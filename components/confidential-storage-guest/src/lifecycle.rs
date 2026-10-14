// SPDX-License-Identifier: Apache-2.0
//! Serialized lifecycle for a guest-owned mount. The backend must implement
//! idempotent teardown of *this activation only*, without lazy/forced unmount.
use crate::receipt::VerifiedGrant;
use async_trait::async_trait;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

#[derive(Clone, Debug, thiserror::Error)]
#[error("{0}")]
pub struct BackendError(pub &'static str);
pub type BackendResult = std::result::Result<(), BackendError>;

#[async_trait]
pub trait Backend: Send + Sync + 'static {
    /// Authenticate the exact manifest/header/profile BEFORE parsing or opening
    /// untrusted disk metadata. Fetch keys through attested CDH, never the host.
    /// Use the activation ID for deterministic mapping names. No formatting.
    async fn open(&self, grant: &VerifiedGrant, device_id: &str) -> BackendResult;
    async fn mount(&self, grant: &VerifiedGrant, mount_path: &str) -> BackendResult;
    /// Success means all application bind mounts and the guest mount are gone.
    /// EBUSY is an error. Already absent must succeed. No MNT_DETACH or force.
    async fn unmount(&self, grant: &VerifiedGrant, mount_path: &str) -> BackendResult;
    /// Success means every mapping for this activation is absent, including a
    /// partially created stack. Must safely handle retries after partial close.
    async fn close_mapping(&self, grant: &VerifiedGrant) -> BackendResult;
    /// Confirm teardown to the authority only after the preceding steps succeed.
    async fn release(&self, grant: &VerifiedGrant) -> BackendResult;
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid or expired activation binding")]
    Binding,
    #[error("volume, device or activation is already owned")]
    Conflict,
    #[error("activation requires cleanup; reopening is forbidden")]
    NeedsCleanup,
    #[error("activation is closed and cannot be replayed")]
    Closed,
    #[error("unknown activation")]
    Unknown,
    #[error("guest activation registry is full")]
    Capacity,
    #[error("backend {0} failed: {1}")]
    Backend(&'static str, BackendError),
    #[error("lifecycle worker stopped unexpectedly; retained state requires cleanup")]
    Worker,
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Reserved,
    NeedsClose,
    NeedsUnmount,
    Mounted,
    NeedsRelease,
    Closed,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mounted {
    pub activation_id: String,
    pub mount_path: String,
}
struct Record {
    grant: VerifiedGrant,
    device_id: String,
    mount_path: String,
    phase: Phase,
}
#[derive(Default)]
struct Registry {
    records: HashMap<String, Arc<Mutex<Record>>>,
    volumes: HashMap<String, String>,
    devices: HashMap<String, String>,
}

pub struct Controller<B: Backend> {
    backend: Arc<B>,
    session_sha256: String,
    registry: Mutex<Registry>,
    capacity: usize,
}
impl<B: Backend> Controller<B> {
    /// Session identity must come from the guest's attested channel context.
    /// Keep one controller per guest service. Closed tombstones are never evicted;
    /// a new controller requires a fresh attested session, not reuse of an old ID.
    pub fn new(backend: Arc<B>, session_sha256: String, capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            backend,
            session_sha256,
            registry: Mutex::new(Registry::default()),
            capacity,
        })
    }
    pub async fn activate(
        self: &Arc<Self>,
        grant: VerifiedGrant,
        device_id: String,
    ) -> Result<Mounted> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Binding)?
            .as_secs();
        self.activate_at(grant, device_id, now).await
    }
    /// Reserve ownership without opening/mounting anything. The trusted runtime
    /// can create a paused namespace after admission and before plaintext exists.
    /// After success the caller must eventually activate or close this record.
    pub async fn reserve(self: &Arc<Self>, grant: VerifiedGrant, device_id: String) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Binding)?
            .as_secs();
        self.reserve_at(&grant, &device_id, now).await.map(|_| ())
    }
    async fn reserve_at(
        &self,
        grant: &VerifiedGrant,
        device_id: &str,
        now: u64,
    ) -> Result<Arc<Mutex<Record>>> {
        grant.check_time(now).map_err(|_| Error::Binding)?;
        let c = grant.claims();
        if c.session_sha256 != self.session_sha256 || !device_id_valid(device_id) {
            return Err(Error::Binding);
        }
        let id = c.activation_id.clone();
        let record = {
            let mut registry = self.registry.lock().await;
            if let Some(record) = registry.records.get(&id) {
                record.clone()
            } else {
                if registry.volumes.contains_key(&c.volume_id)
                    || registry.devices.contains_key(device_id)
                {
                    return Err(Error::Conflict);
                }
                if registry.records.len() >= self.capacity {
                    return Err(Error::Capacity);
                }
                let record = Arc::new(Mutex::new(Record {
                    grant: grant.clone(),
                    device_id: device_id.to_owned(),
                    mount_path: format!("/run/coco/storage/{id}"),
                    phase: Phase::Reserved,
                }));
                registry.volumes.insert(c.volume_id.clone(), id.clone());
                registry.devices.insert(device_id.to_owned(), id.clone());
                registry.records.insert(id.clone(), record.clone());
                record
            }
        };

        {
            let r = record.lock().await;
            if !r.grant.same_activation(grant) || r.device_id != device_id {
                return Err(Error::Conflict);
            }
            match r.phase {
                Phase::Reserved | Phase::Mounted => (),
                Phase::Closed => return Err(Error::Closed),
                _ => return Err(Error::NeedsCleanup),
            }
        }
        Ok(record)
    }
    async fn activate_at(
        self: &Arc<Self>,
        grant: VerifiedGrant,
        device_id: String,
        now: u64,
    ) -> Result<Mounted> {
        grant.check_time(now).map_err(|_| Error::Binding)?;
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(grant.claims().exp - now);
        let id = grant.claims().activation_id.clone();
        let record = self.reserve_at(&grant, &device_id, now).await?;
        let this = self.clone();
        // A lost RPC waiter must not drop a future halfway through disk effects.
        // The service-owned task finishes; retry/close finds the retained record.
        tokio::spawn(async move {
            let mut record = record.lock().await;
            if !record.grant.same_activation(&grant) || record.device_id != device_id {
                return Err(Error::Conflict);
            }
            match record.phase {
                Phase::Mounted => {
                    return Ok(Mounted {
                        activation_id: id,
                        mount_path: record.mount_path.clone(),
                    })
                }
                Phase::Closed => return Err(Error::Closed),
                Phase::Reserved => (),
                _ => return Err(Error::NeedsCleanup),
            }
            if tokio::time::Instant::now() >= deadline {
                // A queued worker may outlive the receipt's admission window.
                // No disk effects have started, but durable ownership must close.
                let _ = this.cleanup(&mut record).await;
                return Err(Error::Binding);
            }
            // Register possible effects BEFORE calling a backend that may fail,
            // panic, or finish after its caller has stopped waiting.
            record.phase = Phase::NeedsClose;
            if let Err(e) = this.backend.open(&record.grant, &record.device_id).await {
                let error = Error::Backend("open", e);
                // On cleanup failure retain the precise failed phase for retry.
                let _ = this.cleanup(&mut record).await;
                return Err(error);
            }
            record.phase = Phase::NeedsUnmount;
            if let Err(e) = this.backend.mount(&record.grant, &record.mount_path).await {
                let error = Error::Backend("mount", e);
                let _ = this.cleanup(&mut record).await;
                return Err(error);
            }
            record.phase = Phase::Mounted;
            Ok(Mounted {
                activation_id: id,
                mount_path: record.mount_path.clone(),
            })
        })
        .await
        .map_err(|_| Error::Worker)?
    }
    pub async fn close(self: &Arc<Self>, activation_id: &str) -> Result<()> {
        let record = self
            .registry
            .lock()
            .await
            .records
            .get(activation_id)
            .cloned()
            .ok_or(Error::Unknown)?;
        let this = self.clone();
        tokio::spawn(async move {
            let mut record = record.lock().await;
            this.cleanup(&mut record).await
        })
        .await
        .map_err(|_| Error::Worker)?
    }
    async fn cleanup(&self, record: &mut Record) -> Result<()> {
        if record.phase == Phase::Closed {
            return Ok(());
        }
        if record.phase == Phase::Reserved {
            record.phase = Phase::NeedsRelease;
        }
        if matches!(record.phase, Phase::Mounted | Phase::NeedsUnmount) {
            record.phase = Phase::NeedsUnmount;
            self.backend
                .unmount(&record.grant, &record.mount_path)
                .await
                .map_err(|e| Error::Backend("unmount", e))?;
            record.phase = Phase::NeedsClose;
        }
        if record.phase == Phase::NeedsClose {
            self.backend
                .close_mapping(&record.grant)
                .await
                .map_err(|e| Error::Backend("close", e))?;
            record.phase = Phase::NeedsRelease;
        }
        if record.phase == Phase::NeedsRelease {
            self.backend
                .release(&record.grant)
                .await
                .map_err(|e| Error::Backend("release", e))?;
            record.phase = Phase::Closed;
            let mut registry = self.registry.lock().await;
            registry.volumes.remove(&record.grant.claims().volume_id);
            registry.devices.remove(&record.device_id);
        }
        Ok(())
    }
    /// Waits for any in-progress backend step; contains no key or mapper path.
    pub async fn phase(&self, activation_id: &str) -> Result<Phase> {
        let record = self
            .registry
            .lock()
            .await
            .records
            .get(activation_id)
            .cloned()
            .ok_or(Error::Unknown)?;
        let phase = record.lock().await.phase;
        Ok(phase)
    }
}
fn device_id_valid(value: &str) -> bool {
    let parts: Vec<_> = value.split(':').collect();
    parts.len() == 2
        && parts
            .iter()
            .all(|v| v.parse::<u32>().is_ok_and(|n| n.to_string() == *v))
}

#[cfg(test)]
mod tests;

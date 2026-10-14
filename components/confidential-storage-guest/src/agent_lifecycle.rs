// SPDX-License-Identifier: Apache-2.0
//! Trusted-agent start/teardown barrier. This is not a host RPC or a Kata adapter.
//! The runtime implementation must own all create/start/exec/remove entry points.
use crate::{
    lifecycle::{Backend, BackendError, BackendResult, Controller},
    receipt::VerifiedGrant,
};
use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub container_id: String,
    pub container_name: String,
    pub activation_id: String,
}
#[async_trait]
pub trait Runtime: Send + Sync + 'static {
    type Consumer: Send + 'static;
    /// Create a private namespace/root and retain the init process behind a start
    /// barrier. No application, exec, hooks or untrusted code may run. Obtain the
    /// handles from this exact runtime object, never host-provided PIDs/paths.
    /// Failure may leave effects, which quiesce/destroy must be able to recover.
    async fn prepare(
        &self,
        identity: &Identity,
    ) -> std::result::Result<Self::Consumer, BackendError>;
    /// Release the same process's start barrier once. Error/panic is ambiguous:
    /// cleanup will quiesce; this method is never retried for this container ID.
    async fn start(&self, identity: &Identity) -> BackendResult;
    /// Idempotently stop all application activity and prevent any new process or
    /// namespace mutation. Preserve the root/namespace until storage is removed.
    /// Must also succeed if prepare had no effects, and wait for actual quiescence.
    async fn quiesce(&self, identity: &Identity) -> BackendResult;
    /// Only after storage cleanup and release. Remove the retained runtime object.
    /// Idempotent, including partial prepare and retries after a lost response.
    async fn destroy(&self, identity: &Identity) -> BackendResult;
}
#[async_trait]
pub trait ConsumerBackend<C>: Backend {
    async fn attach(&self, grant: &VerifiedGrant, consumer: C) -> BackendResult;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Preparing,
    Ready,
    Starting,
    Running,
    NeedsQuiesce,
    NeedsStorageClose,
    NeedsDestroy,
    Closed,
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid runtime container ID")]
    Identity,
    #[error("container binding conflict or another consumer still owns this guest")]
    Conflict,
    #[error("unknown container")]
    Unknown,
    #[error("container state forbids this operation")]
    State,
    #[error("storage: {0}")]
    Storage(#[from] crate::lifecycle::Error),
    #[error("runtime/consumer {0}: {1}")]
    Step(&'static str, BackendError),
    #[error("agent worker failed; retained state requires explicit cleanup")]
    Worker,
}
type Result<T> = std::result::Result<T, Error>;
struct Record {
    identity: Identity,
    grant: VerifiedGrant,
    device: String,
    phase: Phase,
}
/// One coordinator for the entire guest. This MVP admits only ONE non-closed
/// confidential container at a time to prevent a new namespace inheriting another
/// container's plaintext staging. Ordinary container creation must also be gated
/// by the trusted agent while confidential storage exists. No mutable backend or
/// controller is exposed; callers must not retain alternative access to them.
pub struct Agent<B: Backend, R: Runtime> {
    backend: Arc<B>,
    controller: Arc<Controller<B>>,
    runtime: R,
    records: Mutex<HashMap<String, Record>>,
}
impl<B, R> Agent<B, R>
where
    R: Runtime,
    B: ConsumerBackend<R::Consumer>,
{
    pub fn new(backend: B, runtime: R, session: String, capacity: usize) -> Arc<Self> {
        let backend = Arc::new(backend);
        Arc::new(Self {
            controller: Controller::new(backend.clone(), session, capacity),
            backend,
            runtime,
            records: Mutex::new(HashMap::new()),
        })
    }
    /// An exact create retry returns the retained state; it never recreates the
    /// namespace or reattaches storage. Only Ready/Running count as success.
    pub async fn prepare(
        self: &Arc<Self>,
        cid: String,
        grant: VerifiedGrant,
        device: String,
    ) -> Result<Phase> {
        if cid.is_empty()
            || cid.len() > 128
            || !cid
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err(Error::Identity);
        }
        let this = self.clone();
        tokio::spawn(async move {
            let mut records = this.records.lock().await;
            if let Some(r) = records.get(&cid) {
                if !r.grant.same_activation(&grant) || r.device != device {
                    return Err(Error::Conflict);
                }
                return match r.phase {
                    Phase::Ready | Phase::Running => Ok(r.phase),
                    _ => Err(Error::State),
                };
            }
            if records.values().any(|r| {
                r.phase != Phase::Closed
                    || r.grant.claims().activation_id == grant.claims().activation_id
            }) {
                return Err(Error::Conflict);
            }
            // No runtime effects before the controller records our ownership.
            this.controller
                .reserve(grant.clone(), device.clone())
                .await?;
            records.insert(
                cid.clone(),
                Record {
                    identity: Identity {
                        container_id: cid.clone(),
                        container_name: grant.claims().container_name.clone(),
                        activation_id: grant.claims().activation_id.clone(),
                    },
                    grant,
                    device,
                    phase: Phase::Preparing,
                },
            );
            let r = records.get_mut(&cid).unwrap();
            let result = this.prepare_inner(r).await;
            if result.is_err() {
                let _ = this.cleanup(r).await;
            }
            result
        })
        .await
        .map_err(|_| Error::Worker)?
    }
    async fn prepare_inner(&self, r: &mut Record) -> Result<Phase> {
        let consumer = self
            .runtime
            .prepare(&r.identity)
            .await
            .map_err(|e| Error::Step("prepare", e))?;
        self.controller
            .activate(r.grant.clone(), r.device.clone())
            .await?;
        self.backend
            .attach(&r.grant, consumer)
            .await
            .map_err(|e| Error::Step("attach", e))?;
        r.phase = Phase::Ready;
        Ok(r.phase)
    }
    pub async fn start(self: &Arc<Self>, cid: &str) -> Result<()> {
        let this = self.clone();
        let cid = cid.to_owned();
        tokio::spawn(async move {
            let mut records = this.records.lock().await;
            let r = records.get_mut(&cid).ok_or(Error::Unknown)?;
            if r.phase == Phase::Running {
                return Ok(());
            }
            if r.phase != Phase::Ready {
                return Err(Error::State);
            }
            r.phase = Phase::Starting; // Retain uncertainty before releasing FIFO.
            if let Err(e) = this.runtime.start(&r.identity).await {
                let _ = this.cleanup(r).await;
                return Err(Error::Step("start", e));
            }
            r.phase = Phase::Running;
            Ok(())
        })
        .await
        .map_err(|_| Error::Worker)?
    }
    pub async fn close(self: &Arc<Self>, cid: &str) -> Result<()> {
        let this = self.clone();
        let cid = cid.to_owned();
        tokio::spawn(async move {
            let mut records = this.records.lock().await;
            let r = records.get_mut(&cid).ok_or(Error::Unknown)?;
            this.cleanup(r).await
        })
        .await
        .map_err(|_| Error::Worker)?
    }
    async fn cleanup(&self, r: &mut Record) -> Result<()> {
        if r.phase == Phase::Closed {
            return Ok(());
        }
        if !matches!(r.phase, Phase::NeedsStorageClose | Phase::NeedsDestroy) {
            r.phase = Phase::NeedsQuiesce;
            self.runtime
                .quiesce(&r.identity)
                .await
                .map_err(|e| Error::Step("quiesce", e))?;
            r.phase = Phase::NeedsStorageClose;
        }
        if r.phase == Phase::NeedsStorageClose {
            self.controller.close(&r.identity.activation_id).await?;
            r.phase = Phase::NeedsDestroy;
        }
        self.runtime
            .destroy(&r.identity)
            .await
            .map_err(|e| Error::Step("destroy", e))?;
        r.phase = Phase::Closed;
        Ok(())
    }
    pub async fn phase(&self, cid: &str) -> Result<Phase> {
        self.records
            .lock()
            .await
            .get(cid)
            .map(|r| r.phase)
            .ok_or(Error::Unknown)
    }
}

#[cfg(test)]
mod tests;

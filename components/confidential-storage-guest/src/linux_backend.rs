// SPDX-License-Identifier: Apache-2.0
//! Lifecycle adapter for guest-private staging only. Trusted providers are
//! injected; there is no production resolver, attested CDH client or RPC here.
use crate::{
    consumer::Consumer,
    guest_mount::{GuestMount, MountRoot},
    lifecycle::{Backend, BackendError, BackendResult},
    opener::{BlockDevice, Opener, Phase},
    receipt::VerifiedGrant,
    ro_opener::RoOpener,
};
use async_trait::async_trait;
use std::{
    collections::HashMap,
    fs::File,
    sync::{Arc, Mutex},
};

pub struct Resolved {
    pub file: File,
    pub major: u32,
    pub minor: u32,
    pub manifest: Vec<u8>,
}
/// Providers must run inside the trusted guest service. Neither an application
/// nor an untrusted host can implement this boundary in the deployed artifact.
pub trait Providers: Send + Sync + 'static {
    fn resolve(&self, grant: &VerifiedGrant, device_id: &str) -> Result<Resolved, BackendError>;
    /// Called only after exact manifest/header/profile authentication. A real
    /// implementation must bind CDH delivery to this attested session and grant.
    fn key(&self, grant: &VerifiedGrant, credential_uri: &str) -> Result<Secret, BackendError>;
    /// Idempotently stop/quiesce the application before bind removal. Failure
    /// retains all mounts and ownership. The agent must prevent concurrent
    /// startup/namespace mutation; the backend detaches its registered bind.
    fn quiesce_consumers(&self, grant: &VerifiedGrant) -> BackendResult;
    /// Must be an idempotent acknowledgement on the attested authority channel.
    fn release(&self, grant: &VerifiedGrant) -> BackendResult;
}
/// No Debug/Clone. Wipes this owned buffer on drop; providers must also erase any
/// temporary copies. Service-wide dump/swap/tracing hardening is still required.
pub struct Secret([u8; 32]);
impl Secret {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}
impl Drop for Secret {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            // SAFETY: valid unique writable byte; volatile prevents dead-store removal.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}
enum Mapping {
    Rw(Box<Opener>),
    Ro(Box<RoOpener>),
}
impl Mapping {
    fn prepare(
        g: VerifiedGrant,
        manifest: &[u8],
        device: BlockDevice,
    ) -> Result<Self, crate::opener::Error> {
        match g.claims().access.as_str() {
            "rw" => Opener::prepare(g, manifest, device).map(|o| Self::Rw(Box::new(o))),
            "ro" => RoOpener::prepare(g, manifest, device).map(|o| Self::Ro(Box::new(o))),
            _ => Err(crate::opener::Error::Authorization),
        }
    }
    fn credential_uri(&self) -> &str {
        match self {
            Self::Rw(o) => o.credential_uri(),
            Self::Ro(o) => o.credential_uri(),
        }
    }
    fn open(&mut self, key: &[u8; 32]) -> Result<(), crate::opener::Error> {
        match self {
            Self::Rw(o) => o.open(key),
            Self::Ro(o) => o.open(key),
        }
    }
    fn close(&mut self) -> Result<(), crate::opener::Error> {
        match self {
            Self::Rw(o) => o.close(),
            Self::Ro(o) => o.close(),
        }
    }
    fn phase(&self) -> Phase {
        match self {
            Self::Rw(o) => o.phase(),
            Self::Ro(o) => o.phase(),
        }
    }
    fn mapping_path(&self) -> Result<std::path::PathBuf, crate::opener::Error> {
        match self {
            Self::Rw(o) => o.mapping_path(),
            Self::Ro(o) => o.mapping_path(),
        }
    }
}
struct Record {
    grant: VerifiedGrant,
    opener: Option<Mapping>,
    mount: Option<GuestMount>,
    mount_attempted: bool,
    consumer: Option<Consumer>,
    consumer_attempted: bool,
    closing: bool,
    released: bool,
}
struct Inner<P: Providers> {
    providers: P,
    root: MountRoot,
    records: HashMap<String, Record>,
}
/// Use exclusively behind one lifecycle Controller. It owns reservation limits,
/// device exclusivity, replay tombstones and service-owned RPC workers.
pub struct LinuxBackend<P: Providers> {
    inner: Arc<Mutex<Inner<P>>>,
}
impl<P: Providers> LinuxBackend<P> {
    pub fn new(providers: P) -> Result<Self, BackendError> {
        let root = MountRoot::open().map_err(|_| BackendError("invalid private mount root"))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                providers,
                root,
                records: HashMap::new(),
            })),
        })
    }
    /// Trusted agent only, before app startup. The agent must pin a paused
    /// container's namespace and root fds and bind its identity to measured policy.
    /// Call controller.close after any failure; never start the app on failure.
    pub async fn attach_consumer(
        &self,
        g: &VerifiedGrant,
        namespace: File,
        root: File,
        container: &str,
    ) -> BackendResult {
        let g = g.clone();
        let container = container.to_owned();
        self.work(move |i| {
            let r = bound(&mut i.records, &g)?;
            if r.consumer_attempted || r.closing {
                return Err(BackendError(
                    "consumer cannot be replayed or attached during cleanup",
                ));
            }
            let source = r
                .mount
                .as_ref()
                .ok_or(BackendError("guest mount absent"))?
                .verified_source()
                .map_err(|_| BackendError("guest mount not verified"))?;
            // Construction validates caller binding/descriptors, with no effects.
            let consumer = Consumer::new(&g, namespace, root, &container)
                .map_err(|_| BackendError("invalid consumer identity or namespace"))?;
            r.consumer_attempted = true;
            r.consumer = Some(consumer);
            r.consumer
                .as_mut()
                .unwrap()
                .attach(source)
                .map_err(|_| BackendError("consumer attach failed; cleanup required"))
        })
        .await
    }
    async fn work(
        &self,
        f: impl FnOnce(&mut Inner<P>) -> BackendResult + Send + 'static,
    ) -> BackendResult {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = inner
                .lock()
                .map_err(|_| BackendError("backend poisoned; recovery required"))?;
            f(&mut guard)
        })
        .await
        .map_err(|_| BackendError("backend worker failed; recovery required"))?
    }
}
fn bound<'a>(
    records: &'a mut HashMap<String, Record>,
    g: &VerifiedGrant,
) -> Result<&'a mut Record, BackendError> {
    let r = records
        .get_mut(&g.claims().activation_id)
        .ok_or(BackendError("unknown backend activation"))?;
    if !r.grant.same_activation(g) || r.released {
        return Err(BackendError("backend activation conflict"));
    }
    Ok(r)
}
fn target(g: &VerifiedGrant, path: &str) -> BackendResult {
    if path != format!("/run/coco/storage/{}", g.claims().activation_id) {
        return Err(BackendError("unexpected guest mount path"));
    }
    Ok(())
}
#[async_trait]
impl<P: Providers> Backend for LinuxBackend<P> {
    async fn open(&self, g: &VerifiedGrant, device_id: &str) -> BackendResult {
        let g = g.clone();
        let device_id = device_id.to_owned();
        self.work(move |i| {
            let id = g.claims().activation_id.clone();
            if i.records.contains_key(&id) {
                return Err(BackendError("backend open cannot be replayed"));
            }
            i.records.insert(
                id.clone(),
                Record {
                    grant: g.clone(),
                    opener: None,
                    mount: None,
                    mount_attempted: false,
                    consumer: None,
                    consumer_attempted: false,
                    closing: false,
                    released: false,
                },
            );
            let resolved = i.providers.resolve(&g, &device_id)?;
            if device_id != format!("{}:{}", resolved.major, resolved.minor) {
                return Err(BackendError("resolved device mismatch"));
            }
            let device = BlockDevice::from_file(resolved.file, resolved.major, resolved.minor)
                .map_err(|_| BackendError("invalid resolved device"))?;
            let opener = Mapping::prepare(g.clone(), &resolved.manifest, device)
                .map_err(|_| BackendError("header preparation failed"))?;
            let r = i.records.get_mut(&id).unwrap();
            r.opener = Some(opener); // Retain before key fetch or any kernel effects.
            let opener = r.opener.as_mut().unwrap();
            let key = i.providers.key(&g, opener.credential_uri())?;
            opener
                .open(&key.0)
                .map_err(|_| BackendError("mapping open failed"))
        })
        .await
    }
    async fn mount(&self, g: &VerifiedGrant, path: &str) -> BackendResult {
        target(g, path)?;
        let g = g.clone();
        self.work(move |i| {
            let r = bound(&mut i.records, &g)?;
            if r.mount_attempted {
                return Err(BackendError("mount cannot be replayed"));
            }
            let source = r
                .opener
                .as_ref()
                .ok_or(BackendError("mapping absent"))?
                .mapping_path()
                .map_err(|_| BackendError("mapping not open"))?;
            r.mount_attempted = true;
            r.mount = Some(
                i.root
                    .reserve(&g.claims().activation_id)
                    .map_err(|_| BackendError("mount target reservation failed"))?,
            );
            let mount = r.mount.as_mut().unwrap();
            let result = if g.claims().access == "ro" {
                mount.mount_readonly(&source)
            } else {
                mount.mount(&source)
            };
            result.map_err(|_| BackendError("guest mount failed"))
        })
        .await
    }
    async fn unmount(&self, g: &VerifiedGrant, path: &str) -> BackendResult {
        target(g, path)?;
        let g = g.clone();
        self.work(move |i| {
            let r = bound(&mut i.records, &g)?;
            r.closing = true;
            if r.mount_attempted && r.mount.is_none() {
                return Err(BackendError(
                    "uncertain target reservation; recovery required",
                ));
            }
            i.providers.quiesce_consumers(&g)?;
            if let Some(consumer) = &mut r.consumer {
                consumer
                    .detach()
                    .map_err(|_| BackendError("consumer busy or replaced; ownership retained"))?;
            }
            r.consumer = None; // Release namespace/root fds before mapper cleanup.
            if let Some(mount) = &mut r.mount {
                mount
                    .unmount()
                    .map_err(|_| BackendError("guest unmount failed; ownership retained"))?;
            }
            Ok(())
        })
        .await
    }
    async fn close_mapping(&self, g: &VerifiedGrant) -> BackendResult {
        let g = g.clone();
        self.work(move |i| {
            let r = bound(&mut i.records, &g)?;
            if (r.mount_attempted && r.mount.is_none())
                || r.mount.as_ref().is_some_and(|m| !m.removed())
                || r.consumer.is_some()
            {
                return Err(BackendError("mount cleanup pending"));
            }
            if let Some(opener) = &mut r.opener {
                opener
                    .close()
                    .map_err(|_| BackendError("mapping cleanup failed; ownership retained"))?;
            }
            // Drop the retained raw-device fd and sealed header before authority
            // release. Closed tombstones must not pin storage or 16 MiB headers.
            r.opener = None;
            Ok(())
        })
        .await
    }
    async fn release(&self, g: &VerifiedGrant) -> BackendResult {
        let g = g.clone();
        self.work(move |i| {
            // A queued expired admission may release without ever calling open.
            let r = i
                .records
                .entry(g.claims().activation_id.clone())
                .or_insert_with(|| Record {
                    grant: g.clone(),
                    opener: None,
                    mount: None,
                    mount_attempted: false,
                    consumer: None,
                    consumer_attempted: false,
                    closing: true,
                    released: false,
                });
            if !r.grant.same_activation(&g) {
                return Err(BackendError("release binding mismatch"));
            }
            if r.released {
                return Ok(());
            }
            if (r.mount_attempted && r.mount.is_none())
                || r.mount.as_ref().is_some_and(|m| !m.removed())
                || r.consumer.is_some()
                || r.opener
                    .as_ref()
                    .is_some_and(|o| o.phase() != Phase::Closed)
            {
                return Err(BackendError("storage effects remain; release denied"));
            }
            i.providers.release(&g)?;
            r.released = true;
            Ok(())
        })
        .await
    }
}

/// Passed only by a trusted runtime while the container is held before startup.
pub struct ConsumerHandles {
    pub namespace: File,
    pub root: File,
    pub container_name: String,
}
#[async_trait]
impl<P: Providers> crate::agent_lifecycle::ConsumerBackend<ConsumerHandles> for LinuxBackend<P> {
    async fn attach(&self, grant: &VerifiedGrant, consumer: ConsumerHandles) -> BackendResult {
        self.attach_consumer(
            grant,
            consumer.namespace,
            consumer.root,
            &consumer.container_name,
        )
        .await
    }
}

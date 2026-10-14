// SPDX-License-Identifier: Apache-2.0
//! Synthetic lab providers only: never ship these with a production guest.
use super::*;
use confidential_storage_guest::{
    guest_mount::MountRoot,
    lifecycle::{Backend, BackendError, BackendResult, Controller, Phase as LifecyclePhase},
    linux_backend::{LinuxBackend, Providers, Resolved, Secret},
};
use std::{
    os::unix::fs::PermissionsExt,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

#[derive(Clone)]
struct LabProviders {
    manifest: Vec<u8>,
    wrong_key: bool,
    fail_release_once: bool,
    keys: Arc<AtomicUsize>,
    releases: Arc<AtomicUsize>,
    detach_failures: Arc<AtomicUsize>,
    block_fds_before: usize,
}
impl LabProviders {
    fn new(manifest: Vec<u8>) -> Self {
        Self {
            manifest,
            wrong_key: false,
            fail_release_once: false,
            keys: Arc::new(AtomicUsize::new(0)),
            releases: Arc::new(AtomicUsize::new(0)),
            detach_failures: Arc::new(AtomicUsize::new(0)),
            block_fds_before: block_fds(),
        }
    }
}
impl Providers for LabProviders {
    fn resolve(&self, _: &VerifiedGrant, device_id: &str) -> Result<Resolved, BackendError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/vda")
            .unwrap();
        let m = file.metadata().unwrap();
        let (major, minor) = (libc::major(m.rdev()), libc::minor(m.rdev()));
        assert_eq!(device_id, format!("{major}:{minor}"));
        Ok(Resolved {
            file,
            major,
            minor,
            manifest: self.manifest.clone(),
        })
    }
    fn key(&self, g: &VerifiedGrant, uri: &str) -> Result<Secret, BackendError> {
        assert_eq!(uri, g.claims().credential_uri);
        self.keys.fetch_add(1, Ordering::SeqCst);
        let mut key = [0; 32];
        File::open("/test-key")
            .unwrap()
            .read_exact(&mut key)
            .unwrap();
        if self.wrong_key {
            key[0] ^= 1;
        }
        let result = Secret::new(key);
        key.fill(0);
        Ok(result)
    }
    fn quiesce_consumers(&self, _: &VerifiedGrant) -> BackendResult {
        // Lab quiescence/failure hook. The registered bind itself is detached
        // by the real Consumer manager after this callback succeeds.
        if self.detach_failures.swap(0, Ordering::SeqCst) != 0 {
            return Err(BackendError("synthetic application detach failure"));
        }
        Ok(())
    }
    fn release(&self, g: &VerifiedGrant) -> BackendResult {
        assert_eq!(
            block_fds(),
            self.block_fds_before,
            "raw device descriptor retained at release"
        );
        assert!(
            !std::path::Path::new(&format!("/run/coco/storage/{}", g.claims().activation_id))
                .exists()
        );
        let names = Command::new("/usr/sbin/dmsetup")
            .args(["info", "-c", "--noheadings", "-o", "name"])
            .output()
            .unwrap();
        assert!(!String::from_utf8(names.stdout).unwrap().contains("coco-"));
        let attempt = self.releases.fetch_add(1, Ordering::SeqCst);
        if self.fail_release_once && attempt == 0 {
            return Err(BackendError("synthetic acknowledgement lost"));
        }
        Ok(())
    }
}
fn block_fds() -> usize {
    fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|e| fs::read_link(e.path()).ok())
        .filter(|p| p == std::path::Path::new("/dev/vda"))
        .count()
}
fn namespace_holder(marker: &str) -> std::process::Child {
    let mut child = Command::new("/bin/unshare")
        .args([
            "-m",
            "/bin/sh",
            "-c",
            "set -eu; mount --make-rprivate /; echo ready > \"$1\"; exec sleep 600",
            "lab",
            marker,
        ])
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if std::path::Path::new(marker).exists() {
            return child;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("namespace holder did not become ready");
}
pub fn run(header: &[u8]) {
    fs::create_dir_all("/run/coco/storage").unwrap();
    fs::set_permissions("/run/coco/storage", fs::Permissions::from_mode(0o777)).unwrap();
    assert!(MountRoot::open().is_err());
    fs::set_permissions("/run/coco/storage", fs::Permissions::from_mode(0o700)).unwrap();
    let root = MountRoot::open().unwrap();
    std::os::unix::fs::symlink("/data", "/run/coco/storage/foreign").unwrap();
    assert!(root.reserve("foreign").is_err());
    assert!(fs::symlink_metadata("/run/coco/storage/foreign")
        .unwrap()
        .file_type()
        .is_symlink());
    fs::remove_file("/run/coco/storage/foreign").unwrap();
    let mut slot = root.reserve("reserved-test").unwrap();
    assert!(root.reserve("reserved-test").is_err());
    slot.unmount().unwrap();
    slot.unmount().unwrap();
    // Propagation out of the guest-private staging mount must be refused.
    super::run("/bin/mount", &["--make-shared", "/run"]);
    assert!(MountRoot::open().is_err());
    super::run("/bin/mount", &["--make-private", "/run"]);
    println!("COCO_TEST_PASS:private-root-permissions-collision-propagation");

    let stat = fs::metadata("/dev/vda").unwrap();
    let device = format!("{}:{}", libc::major(stat.rdev()), libc::minor(stat.rdev()));
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let (g, mut manifest) = grant_named(header, "mount-bad-manifest");
        manifest[0] ^= 1;
        let providers = LabProviders::new(manifest);
        let backend = Arc::new(LinuxBackend::new(providers.clone()).unwrap());
        let controller = Controller::new(backend, g.claims().session_sha256.clone(), 8);
        assert!(controller
            .activate(g.clone(), device.clone())
            .await
            .is_err());
        assert_eq!(providers.keys.load(Ordering::SeqCst), 0);
        assert_eq!(providers.releases.load(Ordering::SeqCst), 1);
        assert_eq!(
            controller.phase(&g.claims().activation_id).await.unwrap(),
            LifecyclePhase::Closed
        );
        println!("COCO_TEST_PASS:backend-authenticates-before-key");

        let (g, manifest) = grant_named(header, "mount-wrong-key");
        let mut providers = LabProviders::new(manifest);
        providers.wrong_key = true;
        let backend = Arc::new(LinuxBackend::new(providers.clone()).unwrap());
        let controller = Controller::new(backend, g.claims().session_sha256.clone(), 8);
        assert!(controller
            .activate(g.clone(), device.clone())
            .await
            .is_err());
        assert_eq!(
            controller.phase(&g.claims().activation_id).await.unwrap(),
            LifecyclePhase::Closed
        );
        assert_eq!(providers.releases.load(Ordering::SeqCst), 1);
        assert!(controller.activate(g, device.clone()).await.is_err());
        println!("COCO_TEST_PASS:backend-failed-open-cleanup-tombstone");

        let (g, manifest) = grant_named(header, "inherited-staging");
        let providers = LabProviders::new(manifest);
        let backend = Arc::new(LinuxBackend::new(providers.clone()).unwrap());
        let controller = Controller::new(backend.clone(), g.claims().session_sha256.clone(), 8);
        let mounted = controller
            .activate(g.clone(), device.clone())
            .await
            .unwrap();
        let mut inherited = namespace_holder("/run/inherited-ready");
        let inherited_file = File::open(format!(
            "/proc/{}/root{}/probe",
            inherited.id(),
            mounted.mount_path
        ))
        .unwrap();
        assert!(backend
            .attach_consumer(
                &g,
                File::open(format!("/proc/{}/ns/mnt", inherited.id())).unwrap(),
                File::open(format!("/proc/{}/root", inherited.id())).unwrap(),
                &g.claims().container_name
            )
            .await
            .is_err());
        assert!(controller.close(&mounted.activation_id).await.is_err());
        assert_eq!(
            controller.phase(&mounted.activation_id).await.unwrap(),
            LifecyclePhase::NeedsClose
        );
        assert_eq!(providers.releases.load(Ordering::SeqCst), 0);
        inherited.kill().unwrap();
        inherited.wait().unwrap();
        drop(inherited_file);
        controller.close(&mounted.activation_id).await.unwrap();
        assert_eq!(providers.releases.load(Ordering::SeqCst), 1);
        println!("COCO_TEST_PASS:consumer-rejects-inherited-staging-retains-release");

        // Create the namespace BEFORE opening storage; no inherited plaintext.
        let mut holder = namespace_holder("/run/consumer-ready");
        let ns_path = format!("/proc/{}/ns/mnt", holder.id());
        let root_path = format!("/proc/{}/root", holder.id());
        let ns_option = format!("--mount={ns_path}");
        let own_ns = fs::metadata("/proc/thread-self/ns/mnt").unwrap().ino();
        let (g, manifest) = grant_named(header, "mount-success");
        let mut providers = LabProviders::new(manifest);
        providers.fail_release_once = true;
        let backend = Arc::new(LinuxBackend::new(providers.clone()).unwrap());
        let controller = Controller::new(backend.clone(), g.claims().session_sha256.clone(), 8);
        let mounted = controller
            .activate(g.clone(), device.clone())
            .await
            .unwrap();
        assert_eq!(
            controller
                .activate(g.clone(), device.clone())
                .await
                .unwrap(),
            mounted
        );
        assert_eq!(providers.keys.load(Ordering::SeqCst), 1);
        assert!(backend.release(&g).await.is_err());
        assert!(backend.close_mapping(&g).await.is_err());
        assert!(backend.unmount(&g, "/data").await.is_err());
        assert_eq!(providers.releases.load(Ordering::SeqCst), 0);
        let names = Command::new("/usr/sbin/dmsetup")
            .args(["info", "-c", "--noheadings", "-o", "name"])
            .output()
            .unwrap();
        let names = String::from_utf8(names.stdout).unwrap();
        let name = names
            .lines()
            .map(str::trim)
            .find(|s| s.starts_with("coco-") && !s.ends_with("_dif"))
            .unwrap();
        let container = g.claims().container_name.clone();
        assert!(backend
            .attach_consumer(
                &g,
                File::open(&ns_path).unwrap(),
                File::open(&root_path).unwrap(),
                "wrong-container"
            )
            .await
            .is_err());
        assert!(backend
            .attach_consumer(
                &g,
                File::open("/proc/thread-self/ns/mnt").unwrap(),
                File::open("/").unwrap(),
                &container
            )
            .await
            .is_err());
        assert!(backend
            .attach_consumer(
                &g,
                File::open("/dev/null").unwrap(),
                File::open(&root_path).unwrap(),
                &container
            )
            .await
            .is_err());
        backend
            .attach_consumer(
                &g,
                File::open(&ns_path).unwrap(),
                File::open(&root_path).unwrap(),
                &container,
            )
            .await
            .unwrap();
        assert!(backend
            .attach_consumer(
                &g,
                File::open(&ns_path).unwrap(),
                File::open(&root_path).unwrap(),
                &container
            )
            .await
            .is_err());
        assert_eq!(
            fs::metadata("/proc/thread-self/ns/mnt").unwrap().ino(),
            own_ns
        );
        assert!(!std::path::Path::new("/data/probe").exists());
        println!("COCO_TEST_PASS:consumer-identity-namespace-replay-guards");
        // This command runs only the application. The Rust manager owns the bind.
        assert!(Command::new("/bin/nsenter")
            .args([
                ns_option.as_str(),
                "/usr/bin/setpriv",
                "--reuid=1000",
                "--regid=1000",
                "--clear-groups",
                "--bounding-set=-all",
                "--no-new-privs",
                "/bin/sh",
                "/app-test",
                "initialize"
            ])
            .env("COCO_TEST_MAPPER", format!("/dev/mapper/{name}"))
            .env("COCO_TEST_PRIVATE_ROOT", &mounted.mount_path)
            .status()
            .unwrap()
            .success());
        println!("COCO_TEST_PASS:backend-unprivileged-namespace-consumer");
        providers.detach_failures.store(1, Ordering::SeqCst);
        assert!(controller.close(&mounted.activation_id).await.is_err());
        assert_eq!(
            controller.phase(&mounted.activation_id).await.unwrap(),
            LifecyclePhase::NeedsUnmount
        );
        assert!(std::path::Path::new(&format!("{}/probe", mounted.mount_path)).exists());
        assert_eq!(providers.releases.load(Ordering::SeqCst), 0);
        println!("COCO_TEST_PASS:backend-detach-failure-retains-staging");
        // An unrelated overmount must not be mistaken for our bind or removed.
        super::run(
            "/bin/nsenter",
            &[
                ns_option.as_str(),
                "/bin/mount",
                "-t",
                "tmpfs",
                "tmpfs",
                "/data",
            ],
        );
        assert!(controller.close(&mounted.activation_id).await.is_err());
        assert_eq!(providers.releases.load(Ordering::SeqCst), 0);
        assert!(!std::path::Path::new(&format!("{root_path}/data/probe")).exists());
        super::run(
            "/bin/nsenter",
            &[ns_option.as_str(), "/bin/umount", "/data"],
        );
        println!("COCO_TEST_PASS:consumer-refuses-replaced-mount");
        let busy = File::open(format!("{root_path}/data/probe")).unwrap();
        assert!(controller.close(&mounted.activation_id).await.is_err());
        assert_eq!(
            controller.phase(&mounted.activation_id).await.unwrap(),
            LifecyclePhase::NeedsUnmount
        );
        assert_eq!(providers.releases.load(Ordering::SeqCst), 0);
        assert!(controller
            .activate(g.clone(), device.clone())
            .await
            .is_err());
        assert!(busy.metadata().is_ok());
        drop(busy);
        println!("COCO_TEST_PASS:backend-busy-unmount-retains-ownership");
        // First release loses its acknowledgement, after real unmount and close.
        assert!(controller.close(&mounted.activation_id).await.is_err());
        assert_eq!(
            controller.phase(&mounted.activation_id).await.unwrap(),
            LifecyclePhase::NeedsRelease
        );
        assert_eq!(providers.releases.load(Ordering::SeqCst), 1);
        controller.close(&mounted.activation_id).await.unwrap();
        controller.close(&mounted.activation_id).await.unwrap();
        assert_eq!(
            controller.phase(&mounted.activation_id).await.unwrap(),
            LifecyclePhase::Closed
        );
        assert_eq!(providers.releases.load(Ordering::SeqCst), 2);
        assert!(controller.activate(g, device.clone()).await.is_err());
        assert!(!std::path::Path::new(&format!("{root_path}/data/probe")).exists());
        assert_eq!(
            fs::metadata("/proc/thread-self/ns/mnt").unwrap().ino(),
            own_ns
        );
        holder.kill().unwrap();
        holder.wait().unwrap();
        println!("COCO_TEST_PASS:backend-release-after-teardown-retry-tombstone");
        println!("COCO_TEST_PASS:consumer-detached-before-staging-release");
        agent_lab(header, &device).await;
    });
    assert_eq!(fs::read_dir("/run/coco/storage").unwrap().count(), 0);
}

/// Lab runtime owns the namespace holder and runs a synchronous unprivileged
/// application. This tests the real storage adapter, not Kata's FIFO/cgroup code.
struct LabRuntime {
    holder: std::sync::Mutex<Option<std::process::Child>>,
    releases: Arc<AtomicUsize>,
    starts: Arc<AtomicUsize>,
}
#[async_trait::async_trait]
impl confidential_storage_guest::agent_lifecycle::Runtime for LabRuntime {
    type Consumer = confidential_storage_guest::linux_backend::ConsumerHandles;
    async fn prepare(
        &self,
        id: &confidential_storage_guest::agent_lifecycle::Identity,
    ) -> Result<Self::Consumer, BackendError> {
        assert_eq!(fs::read_dir("/run/coco/storage").unwrap().count(), 0);
        let child = namespace_holder("/run/agent-holder-ready");
        let pid = child.id();
        *self.holder.lock().unwrap() = Some(child);
        Ok(Self::Consumer {
            namespace: File::open(format!("/proc/{pid}/ns/mnt")).unwrap(),
            root: File::open(format!("/proc/{pid}/root")).unwrap(),
            container_name: id.container_name.clone(),
        })
    }
    async fn start(
        &self,
        id: &confidential_storage_guest::agent_lifecycle::Identity,
    ) -> BackendResult {
        let pid = self.holder.lock().unwrap().as_ref().unwrap().id();
        let names = Command::new("/usr/sbin/dmsetup")
            .args(["info", "-c", "--noheadings", "-o", "name"])
            .output()
            .unwrap();
        let names = String::from_utf8(names.stdout).unwrap();
        let name = names
            .lines()
            .map(str::trim)
            .find(|s| s.starts_with("coco-") && !s.ends_with("_dif"))
            .unwrap();
        assert!(Command::new("/bin/nsenter")
            .arg(format!("--mount=/proc/{pid}/ns/mnt"))
            .args([
                "/usr/bin/setpriv",
                "--reuid=1000",
                "--regid=1000",
                "--clear-groups",
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                "--no-new-privs",
                "/app-test",
                "initialize"
            ])
            .env("COCO_TEST_MAPPER", format!("/dev/mapper/{name}"))
            .env(
                "COCO_TEST_PRIVATE_ROOT",
                format!("/run/coco/storage/{}", id.activation_id)
            )
            .status()
            .unwrap()
            .success());
        self.starts.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn quiesce(
        &self,
        _: &confidential_storage_guest::agent_lifecycle::Identity,
    ) -> BackendResult {
        // start waits for the sole lab application; only the inert sleep holder
        // remains. Keep it alive until the backend has detached its bind.
        assert!(self
            .holder
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .try_wait()
            .unwrap()
            .is_none());
        Ok(())
    }
    async fn destroy(
        &self,
        _: &confidential_storage_guest::agent_lifecycle::Identity,
    ) -> BackendResult {
        assert_eq!(self.releases.load(Ordering::SeqCst), 1);
        assert_eq!(fs::read_dir("/run/coco/storage").unwrap().count(), 0);
        if let Some(mut child) = self.holder.lock().unwrap().take() {
            assert!(
                !std::path::Path::new(&format!("/proc/{}/root/data/probe", child.id())).exists()
            );
            child.kill().unwrap();
            child.wait().unwrap();
        }
        Ok(())
    }
}
async fn agent_lab(header: &[u8], device: &str) {
    use confidential_storage_guest::agent_lifecycle::{Agent, Phase};
    let (g, manifest) = grant_named(header, "agent-lab");
    let providers = LabProviders::new(manifest);
    let starts = Arc::new(AtomicUsize::new(0));
    let runtime = LabRuntime {
        holder: std::sync::Mutex::new(None),
        releases: providers.releases.clone(),
        starts: starts.clone(),
    };
    let agent = Agent::new(
        LinuxBackend::new(providers.clone()).unwrap(),
        runtime,
        g.claims().session_sha256.clone(),
        8,
    );
    assert!(agent.start("app-runtime-id").await.is_err());
    agent
        .prepare("app-runtime-id".into(), g.clone(), device.into())
        .await
        .unwrap();
    assert_eq!(starts.load(Ordering::SeqCst), 0);
    assert_eq!(agent.phase("app-runtime-id").await.unwrap(), Phase::Ready);
    agent
        .prepare("app-runtime-id".into(), g.clone(), device.into())
        .await
        .unwrap();
    agent.start("app-runtime-id").await.unwrap();
    agent.start("app-runtime-id").await.unwrap();
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    agent.close("app-runtime-id").await.unwrap();
    agent.close("app-runtime-id").await.unwrap();
    assert_eq!(agent.phase("app-runtime-id").await.unwrap(), Phase::Closed);
    assert!(agent.start("app-runtime-id").await.is_err());
    assert!(agent
        .prepare("app-runtime-id".into(), g, device.into())
        .await
        .is_err());
    assert_eq!(providers.releases.load(Ordering::SeqCst), 1);
    println!("COCO_TEST_PASS:agent-start-barrier-real-storage-cleanup");
}

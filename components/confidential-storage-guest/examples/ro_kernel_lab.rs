// SPDX-License-Identifier: Apache-2.0
//! NON-TEE lab: ephemeral signature, synthetic providers, isolated scratch VM.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use confidential_storage_guest::{
    lifecycle::{BackendError, BackendResult, Controller},
    linux_backend::{LinuxBackend, Providers, Resolved, Secret},
    opener::{BlockDevice, Phase},
    receipt::{Claims, Expected, VerifiedGrant, Verifier},
    ro_opener::RoOpener,
};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{FileExt, MetadataExt, PermissionsExt},
    process::Command,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn grant(activation: &str) -> (VerifiedGrant, Vec<u8>) {
    let f: Value = serde_json::from_str(include_str!("../tests/ro-receipt-fixture.json")).unwrap();
    let mut c: Claims = serde_json::from_slice(
        &B64.decode(f["token"].as_str().unwrap().split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    c.iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    c.exp = c.iat + 60;
    c.activation_id = activation.into();
    let key = Ed25519KeyPair::from_pkcs8(
        Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .unwrap()
            .as_ref(),
    )
    .unwrap();
    let input = format!(
        "{}.{}",
        B64.encode(
            serde_json::to_vec(
                &json!({"alg":"Ed25519","typ":"confidential-storage-grant+jwt","kid":"lab"})
            )
            .unwrap()
        ),
        B64.encode(serde_json::to_vec(&c).unwrap())
    );
    let token = format!(
        "{input}.{}",
        B64.encode(key.sign(input.as_bytes()).as_ref())
    );
    let expected: Expected = serde_json::from_value(f["expected"].clone()).unwrap();
    let verified = Verifier::new(
        key.public_key().as_ref().try_into().unwrap(),
        c.iss,
        "lab".into(),
    )
    .verify(&token, &expected, c.iat)
    .unwrap();
    (
        verified,
        f["manifest"].as_str().unwrap().as_bytes().to_vec(),
    )
}
fn device() -> BlockDevice {
    let file = File::open("/dev/vda").unwrap();
    let s = file.metadata().unwrap();
    BlockDevice::from_file(file, libc::major(s.rdev()), libc::minor(s.rdev())).unwrap()
}
fn key() -> [u8; 32] {
    let mut key = [0; 32];
    File::open("/test-key")
        .unwrap()
        .read_exact(&mut key)
        .unwrap();
    key
}
struct LabProviders {
    manifest: Vec<u8>,
    released: Arc<AtomicUsize>,
}
impl Providers for LabProviders {
    fn resolve(&self, _: &VerifiedGrant, id: &str) -> Result<Resolved, BackendError> {
        let file = File::open("/dev/vda").unwrap();
        let m = file.metadata().unwrap();
        let (major, minor) = (libc::major(m.rdev()), libc::minor(m.rdev()));
        assert_eq!(id, format!("{major}:{minor}"));
        Ok(Resolved {
            file,
            major,
            minor,
            manifest: self.manifest.clone(),
        })
    }
    fn key(&self, g: &VerifiedGrant, uri: &str) -> Result<Secret, BackendError> {
        assert_eq!(uri, g.claims().credential_uri);
        let mut k = key();
        let s = Secret::new(k);
        k.fill(0);
        Ok(s)
    }
    fn quiesce_consumers(&self, _: &VerifiedGrant) -> BackendResult {
        Ok(())
    }
    fn release(&self, _: &VerifiedGrant) -> BackendResult {
        let out = Command::new("/usr/sbin/dmsetup")
            .args(["info", "-c", "--noheadings", "-o", "name"])
            .output()
            .unwrap();
        assert!(!String::from_utf8(out.stdout).unwrap().contains("coco-ro-"));
        assert_eq!(fs::read_dir("/run/coco/storage").unwrap().count(), 0);
        self.released.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
fn main() {
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap();
    assert!(cmdline.split_whitespace().any(|s| s == "coco.ro.lab=1"));
    assert_eq!(
        fs::read_to_string("/sys/block/vda/serial").unwrap().trim(),
        "coco-ro-snapshot"
    );
    assert_eq!(
        fs::read_to_string("/sys/block/vda/size").unwrap().trim(),
        "4194304"
    );
    let mut k = key();
    if cmdline.split_whitespace().any(|s| s == "coco.corrupt=1") {
        // QEMU uses a disposable snapshot overlay; original published disk is RO.
        let raw = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/vda")
            .unwrap();
        let offset = 64 * 1024 * 1024;
        let mut b = [0];
        raw.read_exact_at(&mut b, offset).unwrap();
        b[0] ^= 1;
        raw.write_all_at(&b, offset).unwrap();
        raw.sync_all().unwrap();
        let (g, m) = grant("ro-corrupt");
        let mut o = RoOpener::prepare(g, &m, device()).unwrap();
        o.open(&k).unwrap();
        let plain = File::open(o.mapping_path().unwrap()).unwrap();
        let mut block = [0; 4096];
        assert_eq!(
            plain
                .read_exact_at(&mut block, offset - 16777216)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EIO)
        );
        drop(plain);
        o.close().unwrap();
        k.fill(0);
        println!("COCO_TEST_PASS:ro-ciphertext-corruption-eio");
        return;
    }
    let (g, m) = grant("ro-wrong-key");
    let mut o = RoOpener::prepare(g, &m, device()).unwrap();
    let mut bad = k;
    bad[0] ^= 1;
    assert!(o.open(&bad).is_err());
    assert_eq!(o.phase(), Phase::NeedsClose);
    o.close().unwrap();
    bad.fill(0);
    k.fill(0);
    println!("COCO_TEST_PASS:ro-wrong-key-cleanup");
    fs::create_dir_all("/run/coco/storage").unwrap();
    fs::set_permissions("/run/coco/storage", fs::Permissions::from_mode(0o700)).unwrap();
    // Namespace exists before plaintext staging, with private propagation.
    let mut holder = Command::new("/bin/unshare")
        .args([
            "-m",
            "/bin/sh",
            "-c",
            "set -eu; mount --make-rprivate /; echo ready > /run/ro-holder; exec sleep 600",
        ])
        .spawn()
        .unwrap();
    for _ in 0..200 {
        if std::path::Path::new("/run/ro-holder").exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(std::path::Path::new("/run/ro-holder").exists());
    let (g, m) = grant("ro-consumer");
    let manifest: Value = serde_json::from_slice(&m).unwrap();
    let sums = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            format!(
                "{}  {}\n",
                f["sha256"].as_str().unwrap(),
                f["path"].as_str().unwrap()
            )
        })
        .collect::<String>();
    fs::write("/model-checksums", sums).unwrap();
    fs::set_permissions("/model-checksums", fs::Permissions::from_mode(0o444)).unwrap();
    let released = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(
        LinuxBackend::new(LabProviders {
            manifest: m,
            released: released.clone(),
        })
        .unwrap(),
    );
    let controller = Controller::new(backend.clone(), g.claims().session_sha256.clone(), 4);
    let stat = fs::metadata("/dev/vda").unwrap();
    let id = format!("{}:{}", libc::major(stat.rdev()), libc::minor(stat.rdev()));
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let mounted = controller.activate(g.clone(), id).await.unwrap();
        let pid = holder.id();
        let ns = format!("/proc/{pid}/ns/mnt");
        let root = format!("/proc/{pid}/root");
        backend
            .attach_consumer(
                &g,
                File::open(&ns).unwrap(),
                File::open(&root).unwrap(),
                &g.claims().container_name,
            )
            .await
            .unwrap();
        assert!(!std::path::Path::new("/models/config.json").exists());
        assert!(Command::new("/bin/nsenter")
            .arg(format!("--mount={ns}"))
            .args([
                "/usr/bin/setpriv",
                "--reuid=1000",
                "--regid=1000",
                "--clear-groups",
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                "--no-new-privs",
                "/bin/sh",
                "/ro-app-test"
            ])
            .status()
            .unwrap()
            .success());
        let busy = File::open(format!("{root}/models/config.json")).unwrap();
        assert!(controller.close(&mounted.activation_id).await.is_err());
        assert_eq!(released.load(Ordering::SeqCst), 0);
        drop(busy);
        controller.close(&mounted.activation_id).await.unwrap();
        assert_eq!(released.load(Ordering::SeqCst), 1);
        assert!(!std::path::Path::new(&format!("{root}/models/config.json")).exists());
        println!("COCO_TEST_PASS:ro-unprivileged-consumer-and-busy-teardown");
    });
    holder.kill().unwrap();
    holder.wait().unwrap();
}

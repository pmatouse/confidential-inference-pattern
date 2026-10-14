// SPDX-License-Identifier: Apache-2.0
//! Disposable kernel-lab ONLY. Generates synthetic grants, never attestation.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use confidential_storage_guest::{
    opener::{BlockDevice, Opener, Phase},
    profile::{profile_sha256, HEADER_BYTES},
    receipt::{Claims, Expected, VerifiedGrant, Verifier},
};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{FileExt, MetadataExt},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn sha(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn grant(header: &[u8]) -> (VerifiedGrant, Vec<u8>) {
    grant_named(header, "opener-lab")
}
fn grant_named(header: &[u8], activation: &str) -> (VerifiedGrant, Vec<u8>) {
    let fixture: Value =
        serde_json::from_str(include_str!("../tests/receipt-fixture.json")).unwrap();
    let mut claims: Claims = serde_json::from_slice(
        &B64.decode(
            fixture["valid"]
                .as_str()
                .unwrap()
                .split('.')
                .nth(1)
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let manifest = serde_json::to_vec(&json!({"schemaVersion":1,"volumeId":claims.volume_id,"generation":claims.generation,"profileSha256":profile_sha256(),"credentialUri":claims.credential_uri,"luksUuid":"01234567-89ab-4cde-8123-456789abcdef","deviceBytes":134217728,"headerSha256":sha(header),"headerBytes":HEADER_BYTES,"dataOffsetBytes":HEADER_BYTES,"filesystem":"ext4"})).unwrap();
    claims.profile_sha256 = profile_sha256();
    claims.header_sha256 = sha(header);
    claims.manifest_sha256 = sha(&manifest);
    claims.iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    claims.exp = claims.iat + 60;
    claims.activation_id = activation.to_owned();
    let mut expected: Expected = serde_json::from_value(fixture["expected"].clone()).unwrap();
    expected.profile_sha256 = profile_sha256();
    let key = Ed25519KeyPair::from_pkcs8(
        Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .unwrap()
            .as_ref(),
    )
    .unwrap();
    let h = json!({"alg":"Ed25519","typ":"confidential-storage-grant+jwt","kid":"lab"});
    let input = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&h).unwrap()),
        B64.encode(serde_json::to_vec(&claims).unwrap())
    );
    let token = format!(
        "{input}.{}",
        B64.encode(key.sign(input.as_bytes()).as_ref())
    );
    (
        Verifier::new(
            key.public_key().as_ref().try_into().unwrap(),
            claims.iss,
            "lab".into(),
        )
        .verify(&token, &expected, claims.iat)
        .unwrap(),
        manifest,
    )
}
fn device() -> BlockDevice {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/vda")
        .unwrap();
    let stat = file.metadata().unwrap();
    BlockDevice::from_file(file, libc::major(stat.rdev()), libc::minor(stat.rdev())).unwrap()
}
fn run(tool: &str, args: &[&str]) {
    assert!(
        Command::new(tool).args(args).status().unwrap().success(),
        "lab command failed"
    );
}
fn main() {
    assert!(fs::read_to_string("/proc/cmdline")
        .unwrap()
        .split_whitespace()
        .any(|s| s == "coco.storage.lab=1"));
    assert_eq!(
        fs::read_to_string("/sys/block/vda/serial").unwrap().trim(),
        "coco-scratch-only"
    );
    assert_eq!(
        fs::read_to_string("/sys/block/vda/size").unwrap().trim(),
        "262144"
    );
    let source = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/vda")
        .unwrap();
    let mut header = vec![0; HEADER_BYTES];
    source.read_exact_at(&mut header, 0).unwrap();
    let mut key = [0u8; 32];
    File::open("/test-key")
        .unwrap()
        .read_exact(&mut key)
        .unwrap();
    let (g, m) = grant(&header);
    let mut wrong = Opener::prepare(g, &m, device()).unwrap();
    let mut bad = key;
    bad[0] ^= 1;
    assert!(wrong.open(&bad).is_err());
    assert_eq!(wrong.phase(), Phase::NeedsClose);
    assert!(wrong.open(&key).is_err());
    wrong.close().unwrap();
    assert_eq!(wrong.phase(), Phase::Closed);
    println!("COCO_TEST_PASS:rust-wrong-key-no-retry");

    let (g, m) = grant(&header);
    let mut opener = Opener::prepare(g.clone(), &m, device()).unwrap();
    assert_eq!(opener.credential_uri(), g.claims().credential_uri);
    // Change an ACTIVE encrypted keyslot byte after the sealed copy exists.
    source.write_all_at(&[header[32768] ^ 1], 32768).unwrap();
    source.sync_all().unwrap();
    assert!(Opener::prepare(g, &m, device()).is_err());
    if let Err(error) = opener.open(&key) {
        // Diagnostics expose only UUID/name, never a crypt table or a key.
        run(
            "/usr/sbin/dmsetup",
            &["info", "-c", "--noheadings", "-o", "name,uuid"],
        );
        panic!("sealed descriptor open failed: {error}");
    }
    println!("COCO_TEST_PASS:rust-sealed-header-survives-source-change");
    source.write_all_at(&[header[32768]], 32768).unwrap();
    source.sync_all().unwrap();
    let (g, m) = grant(&header);
    let mut collision = Opener::prepare(g, &m, device()).unwrap();
    assert!(collision.open(&key).is_err());
    assert!(collision.close().is_err());
    assert_eq!(collision.phase(), Phase::Prepared);
    println!("COCO_TEST_PASS:rust-collision-retains-existing-mapping");
    let path = opener.mapping_path().unwrap();
    let path = path.to_str().unwrap();
    run(
        "/bin/mount",
        &["-t", "ext4", "-o", "nodev,nosuid,noexec", path, "/data"],
    );
    run("/bin/chown", &["1000:1000", "/data"]);
    assert!(Command::new("/usr/bin/setpriv")
        .args([
            "--reuid=1000",
            "--regid=1000",
            "--clear-groups",
            "--bounding-set=-all",
            "--no-new-privs",
            "/bin/sh",
            "/app-test",
            "initialize"
        ])
        .env("COCO_TEST_MAPPER", path)
        .status()
        .unwrap()
        .success());
    assert!(opener.close().is_err());
    assert_eq!(opener.phase(), Phase::NeedsClose);
    assert!(opener.mapping_path().is_err());
    println!("COCO_TEST_PASS:rust-busy-close-retains-state");
    run("/bin/umount", &["/data"]);
    opener.close().unwrap();
    opener.close().unwrap();
    collision.close().unwrap();
    assert_eq!(opener.phase(), Phase::Closed);
    assert!(opener.open(&key).is_err());
    println!("COCO_TEST_PASS:rust-close-removes-both-mappings");
    lifecycle_lab::run(&header);
    key.fill(0);
    bad.fill(0);
}

#[path = "kernel_opener_lab/lifecycle_lab.rs"]
mod lifecycle_lab;

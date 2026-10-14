// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::receipt::{Claims, Expected, Verifier};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as URL64;
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use serde_json::{json, Value};

fn metadata() -> Value {
    let salt = B64.encode([7; 32]);
    json!({
        "keyslots":{"0":{"type":"luks2","key_size":96,
            "area":{"type":"raw","offset":"32768","size":"385024","encryption":"aes-xts-plain64","key_size":64},
            "kdf":{"type":"argon2id","time":4,"memory":65536,"cpus":1,"salt":salt},
            "af":{"type":"luks1","stripes":4000,"hash":"sha256"}}},
        "tokens":{},
        "segments":{"0":{"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0","encryption":"aes-xts-plain64","sector_size":4096,
            "integrity":{"type":"hmac(sha256)","journal_encryption":"none","journal_integrity":"none"}}},
        "digests":{"0":{"type":"pbkdf2","keyslots":["0"],"segments":["0"],"hash":"sha256","iterations":100000,"salt":salt,"digest":salt}},
        "config":{"json_size":"12288","keyslots_size":"16744448"}
    })
}
const UUID: &str = "01234567-89ab-4cde-8123-456789abcdef";
#[test]
fn read_only_header_profile_cannot_downgrade_rw_integrity() {
    let mut ro = metadata();
    ro["keyslots"]["0"]["key_size"] = json!(64);
    ro["keyslots"]["0"]["area"]["size"] = json!("258048");
    ro["segments"]["0"]
        .as_object_mut()
        .unwrap()
        .remove("integrity");
    let h = header(&serde_json::to_vec(&ro).unwrap());
    validate_ro_header(&h, UUID).unwrap();
    assert!(validate_header(&h, UUID).is_err());
    let rw = header(&serde_json::to_vec(&metadata()).unwrap());
    assert!(validate_ro_header(&rw, UUID).is_err());
    for (key, value) in [("key_size", json!(96)), ("key_size", json!(32))] {
        let mut altered = ro.clone();
        altered["keyslots"]["0"][key] = value;
        assert!(validate_ro_header(&header(&serde_json::to_vec(&altered).unwrap()), UUID).is_err());
    }
}
fn header(metadata: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; HEADER_BYTES];
    for (offset, magic) in [(0, b"LUKS\xba\xbe"), (METADATA_BYTES, b"SKUL\xba\xbe")] {
        let h = &mut bytes[offset..offset + METADATA_BYTES];
        h[..6].copy_from_slice(magic);
        h[6..8].copy_from_slice(&2u16.to_be_bytes());
        h[8..16].copy_from_slice(&(METADATA_BYTES as u64).to_be_bytes());
        h[16..24].copy_from_slice(&1u64.to_be_bytes());
        h[72..78].copy_from_slice(b"sha256");
        h[168..204].copy_from_slice(UUID.as_bytes());
        h[256..264].copy_from_slice(&(offset as u64).to_be_bytes());
        h[4096..4096 + metadata.len()].copy_from_slice(metadata);
        let sum = ring::digest::digest(&ring::digest::SHA256, h);
        h[448..480].copy_from_slice(sum.as_ref());
    }
    bytes
}
fn grant(manifest: &[u8], header: &[u8]) -> VerifiedGrant {
    let fixture: Value =
        serde_json::from_str(include_str!("../../tests/receipt-fixture.json")).unwrap();
    let token = fixture["valid"].as_str().unwrap();
    let mut claims: Claims =
        serde_json::from_slice(&URL64.decode(token.split('.').nth(1).unwrap()).unwrap()).unwrap();
    claims.manifest_sha256 = sha256(manifest);
    claims.header_sha256 = sha256(header);
    claims.profile_sha256 = profile_sha256();
    let mut expected: Expected = serde_json::from_value(fixture["expected"].clone()).unwrap();
    expected.profile_sha256 = profile_sha256();
    let key = Ed25519KeyPair::from_pkcs8(
        Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .unwrap()
            .as_ref(),
    )
    .unwrap();
    let header = json!({"alg":"Ed25519","typ":"confidential-storage-grant+jwt","kid":fixture["key_id"].as_str().unwrap()});
    let input = format!(
        "{}.{}",
        URL64.encode(serde_json::to_vec(&header).unwrap()),
        URL64.encode(serde_json::to_vec(&claims).unwrap())
    );
    let token = format!(
        "{input}.{}",
        URL64.encode(key.sign(input.as_bytes()).as_ref())
    );
    Verifier::new(
        key.public_key().as_ref().try_into().unwrap(),
        claims.iss.clone(),
        fixture["key_id"].as_str().unwrap().into(),
    )
    .verify(&token, &expected, claims.iat)
    .unwrap()
}
fn manifest(header: &[u8]) -> Vec<u8> {
    let f: Value = serde_json::from_str(include_str!("../../tests/receipt-fixture.json")).unwrap();
    let claims: Claims = serde_json::from_slice(
        &URL64
            .decode(f["valid"].as_str().unwrap().split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    serde_json::to_vec(&json!({"schemaVersion":1,"volumeId":claims.volume_id,"generation":claims.generation,"profileSha256":profile_sha256(),"credentialUri":claims.credential_uri,"luksUuid":UUID,"deviceBytes":67108864,"headerSha256":sha256(header),"headerBytes":HEADER_BYTES,"dataOffsetBytes":HEADER_BYTES,"filesystem":"ext4"})).unwrap()
}
#[test]
#[cfg(target_os = "linux")]
#[ignore = "requires the disposable kernel lab's locally generated scratch image"]
fn kernel_generated_integrity_header_matches_profile() {
    use std::io::Read;
    let path = std::env::var("COCO_TEST_KERNEL_LAB_DISK").expect("explicit lab image required");
    let mut source = std::fs::File::open(path).unwrap();
    assert!(source.metadata().unwrap().is_file());
    assert_eq!(source.metadata().unwrap().len(), 128 * 1024 * 1024);
    let mut bytes = vec![0; HEADER_BYTES];
    source.read_exact(&mut bytes).unwrap();
    // Synthetic local signing identity exercises validation, not attestation.
    let mut m: Value = serde_json::from_slice(&manifest(&bytes)).unwrap();
    m["deviceBytes"] = json!(128 * 1024 * 1024);
    let m = serde_json::to_vec(&m).unwrap();
    let g = grant(&m, &bytes);
    let prepared =
        crate::sealed_header::PreparedHeader::prepare(&g, &m, &source, 128 * 1024 * 1024).unwrap();
    assert_eq!(prepared.manifest().device_bytes(), 128 * 1024 * 1024);
    bytes[500000] ^= 1;
    assert!(matches!(
        prepared.manifest().validate_header(&g, &bytes),
        Err(Error::Authentication)
    ));
}
#[test]
fn accepts_only_the_complete_authenticated_rw_profile() {
    let h = header(&serde_json::to_vec(&metadata()).unwrap());
    let m = manifest(&h);
    let g = grant(&m, &h);
    let validated = RwManifest::verify(&g, &m, 67108864).unwrap();
    validated.validate_header(&g, &h).unwrap();
    assert_eq!(validated.credential_uri(), g.claims().credential_uri);
    assert!(RwManifest::verify(&g, b"changed", 67108864).is_err());
    assert!(RwManifest::verify(&g, &m, 67112960).is_err());
    let mut bad = h.clone();
    bad[500000] ^= 1;
    assert!(matches!(
        validated.validate_header(&g, &bad),
        Err(Error::Authentication)
    ));
}
#[test]
fn rejects_reauthorized_manifest_binding_and_layout_changes() {
    let h = header(&serde_json::to_vec(&metadata()).unwrap());
    let original: Value = serde_json::from_slice(&manifest(&h)).unwrap();
    for (field, value) in [
        ("schemaVersion", json!(2)),
        ("volumeId", json!("other")),
        ("generation", json!(99)),
        ("profileSha256", json!("0".repeat(64))),
        ("credentialUri", json!("kbs:///other/key/v1")),
        ("headerSha256", json!("0".repeat(64))),
        ("headerBytes", json!(4096)),
        ("dataOffsetBytes", json!(0)),
        ("deviceBytes", json!(67112960)),
        ("filesystem", json!("xfs")),
        ("luksUuid", json!("../unsafe")),
        ("extra", json!(true)),
    ] {
        let mut m = original.clone();
        m[field] = value;
        let m = serde_json::to_vec(&m).unwrap();
        let g = grant(&m, &h);
        assert!(RwManifest::verify(&g, &m, 67108864).is_err(), "{field}");
    }
}
#[test]
fn rejects_crypto_downgrade_and_unbounded_kdf_even_if_header_is_authorized() {
    let cases = [
        ("/segments/0/type", json!("linear")),
        ("/segments/0/encryption", json!("cipher_null")),
        ("/segments/0/offset", json!("0")),
        ("/segments/0/size", json!("4096")),
        ("/segments/0/sector_size", json!(512)),
        ("/segments/0/iv_tweak", json!("1")),
        ("/segments/0/integrity/type", json!("crc32c")),
        ("/segments/0/integrity/key_size", json!(0)),
        ("/segments/0/flags", json!(["in-reencryption"])),
        ("/config/flags", json!(["integrity-no-journal"])),
        (
            "/config/requirements",
            json!({"mandatory":["online-reencrypt-v2"]}),
        ),
        ("/keyslots/0/key_size", json!(64)),
        ("/keyslots/0/area/key_size", json!(32)),
        ("/keyslots/0/area/offset", json!("0")),
        ("/keyslots/0/area/size", json!("18446744073709551615")),
        ("/keyslots/0/kdf/memory", json!(u64::MAX)),
        ("/keyslots/0/kdf/time", json!(0)),
        ("/keyslots/0/kdf/cpus", json!(100)),
        ("/keyslots/0/af/stripes", json!(1)),
        ("/digests/0/iterations", json!(u64::MAX)),
        ("/digests/0/segments", json!([])),
        ("/tokens/0", json!({"type":"external"})),
        ("/segments/1", metadata()["segments"]["0"].clone()),
        ("/keyslots/1", metadata()["keyslots"]["0"].clone()),
    ];
    for (pointer, value) in cases {
        let mut m = metadata();
        let mut path: Vec<_> = pointer[1..].split('/').collect();
        let key = path.pop().unwrap();
        let mut parent = &mut m;
        for part in path {
            parent = &mut parent[part];
        }
        parent[key] = value;
        let h = header(&serde_json::to_vec(&m).unwrap());
        let m = manifest(&h);
        let g = grant(&m, &h);
        assert!(
            RwManifest::verify(&g, &m, 67108864)
                .unwrap()
                .validate_header(&g, &h)
                .is_err(),
            "{pointer}"
        );
    }
}
#[test]
fn rejects_duplicate_and_unknown_json_fields() {
    let m = serde_json::to_string(&metadata()).unwrap();
    for bad in [
        m.replacen("\"key_size\":96", "\"key_size\":64,\"key_size\":96", 1),
        m.replacen("\"tokens\":{}", "\"tokens\":{},\"tokens\":{}", 1),
        m.replacen("\"json_size\"", "\"unknown\":0,\"json_size\"", 1),
        m.replacen("\"segments\":{", "\"segments\":{\"0\":{},", 1),
    ] {
        assert!(validate_metadata(bad.as_bytes()).is_err());
    }
}
#[test]
fn rejects_corrupt_or_divergent_binary_headers_even_with_new_authority_digest() {
    let good = header(&serde_json::to_vec(&metadata()).unwrap());
    for offset in [
        0,
        6,
        8,
        16,
        72,
        168,
        208,
        256,
        264,
        448,
        480,
        4096,
        METADATA_BYTES,
        METADATA_BYTES + 16,
        METADATA_BYTES + 4096,
    ] {
        let mut h = good.clone();
        h[offset] ^= 1;
        let m = manifest(&h);
        let g = grant(&m, &h);
        assert!(
            RwManifest::verify(&g, &m, 67108864)
                .unwrap()
                .validate_header(&g, &h)
                .is_err(),
            "{offset}"
        );
    }
    // Rechecksum a different valid JSON secondary copy: divergence still fails.
    let mut other = metadata();
    other["keyslots"]["0"]["kdf"]["time"] = json!(5);
    let different = header(&serde_json::to_vec(&other).unwrap());
    let mut h = good;
    h[METADATA_BYTES..METADATA_BYTES * 2]
        .copy_from_slice(&different[METADATA_BYTES..METADATA_BYTES * 2]);
    assert!(validate_header(&h, UUID).is_err());
}
#[cfg(target_os = "linux")]
#[test]
fn prepared_copy_survives_source_replacement_and_rejects_short_source() {
    use std::{
        fs::OpenOptions,
        os::{fd::AsRawFd, unix::fs::FileExt},
    };
    let h = header(&serde_json::to_vec(&metadata()).unwrap());
    let m = manifest(&h);
    let g = grant(&m, &h);
    let path = std::env::temp_dir().join(format!("coco-header-{}", g.claims().activation_id));
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    f.write_all_at(&h, 0).unwrap();
    let prepared = crate::sealed_header::PreparedHeader::prepare(&g, &m, &f, 67108864).unwrap();
    f.write_all_at(b"corrupt", 0).unwrap();
    let copy = std::fs::read(format!("/proc/self/fd/{}", prepared.as_fd().as_raw_fd())).unwrap();
    assert_eq!(copy, h);
    assert!(crate::sealed_header::PreparedHeader::prepare(&g, &m, &f, 67108864).is_err());
    f.set_len(1).unwrap();
    assert!(crate::sealed_header::PreparedHeader::prepare(&g, &m, &f, 67108864).is_err());
}
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires explicitly supplied cryptsetup executable; real userspace header parsing only"]
fn cryptsetup_parses_sealed_synthetic_header_and_real_plain_luks_is_rejected() {
    use std::os::fd::AsRawFd;
    let tool = std::env::var("COCO_TEST_CRYPTSETUP").expect("set COCO_TEST_CRYPTSETUP");
    let real =
        std::env::var("COCO_TEST_PLAIN_LUKS_HEADER").expect("set COCO_TEST_PLAIN_LUKS_HEADER");
    let h = header(&serde_json::to_vec(&metadata()).unwrap());
    let m = manifest(&h);
    let g = grant(&m, &h);
    let path = std::env::temp_dir().join(format!("coco-interop-{}", std::process::id()));
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::FileExt::write_all_at(&f, &h, 0).unwrap();
    let prepared = crate::sealed_header::PreparedHeader::prepare(&g, &m, &f, 67108864).unwrap();
    let fd_path = format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        prepared.as_fd().as_raw_fd()
    );
    let output = std::process::Command::new(&tool)
        .args([
            "luksDump",
            "--dump-json-metadata",
            "--disable-locks",
            &fd_path,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cryptsetup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        metadata()
    );
    let plain = std::fs::read(real).unwrap();
    let m = manifest(&plain);
    let g = grant(&m, &plain);
    assert!(RwManifest::verify(&g, &m, 67108864)
        .unwrap()
        .validate_header(&g, &plain)
        .is_err());
}

// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::receipt::{Claims, Expected, Verifier};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use serde_json::{json, Value};

fn fixture() -> Value {
    serde_json::from_str(include_str!("../../tests/ro-receipt-fixture.json")).unwrap()
}
fn verified() -> (VerifiedGrant, Vec<u8>) {
    let f = fixture();
    let key = f["public_key_hex"].as_str().unwrap();
    let bytes: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&key[i..i + 2], 16).unwrap())
        .collect();
    let grant = Verifier::new(
        bytes.try_into().unwrap(),
        "storage-test".into(),
        "fixture-v1".into(),
    )
    .verify(
        f["token"].as_str().unwrap(),
        &serde_json::from_value(f["expected"].clone()).unwrap(),
        f["now"].as_u64().unwrap(),
    )
    .unwrap();
    (grant, f["manifest"].as_str().unwrap().as_bytes().to_vec())
}
fn signed_changed(raw: &[u8]) -> VerifiedGrant {
    let f = fixture();
    let mut c: Claims = serde_json::from_slice(
        &B64.decode(f["token"].as_str().unwrap().split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    c.manifest_sha256 = sha256(raw);
    let key = Ed25519KeyPair::from_pkcs8(
        Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .unwrap()
            .as_ref(),
    )
    .unwrap();
    let header = json!({"alg":"Ed25519","typ":"confidential-storage-grant+jwt","kid":"fixture-v1"});
    let input = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&header).unwrap()),
        B64.encode(serde_json::to_vec(&c).unwrap())
    );
    let token = format!(
        "{input}.{}",
        B64.encode(key.sign(input.as_bytes()).as_ref())
    );
    let expected: Expected = serde_json::from_value(f["expected"].clone()).unwrap();
    Verifier::new(
        key.public_key().as_ref().try_into().unwrap(),
        c.iss.clone(),
        "fixture-v1".into(),
    )
    .verify(&token, &expected, c.iat)
    .unwrap()
}
#[test]
fn python_approved_manifest_has_exact_geometry_and_receipt_binding() {
    let (grant, raw) = verified();
    let m = RoManifest::verify(&grant, &raw, 2147483648).unwrap();
    assert_eq!(m.luks_uuid(), "17933d68-6bc5-4df6-97a7-99fff275817f");
    assert_eq!(m.verity().data_bytes(), 2113929216);
    assert_eq!(
        m.verity().root(),
        "83a4d3d9c170836bacedfa171f3e20f540cd3e98344cf33a2f5cba80caa5ab63"
    );
    assert!(RoManifest::verify(&grant, &raw, 2147487744).is_err());
    let mut changed = raw.clone();
    changed.push(b' ');
    assert!(RoManifest::verify(&grant, &changed, 2147483648).is_err());
    assert!(m.validate_header(&grant, &vec![0; HEADER_BYTES]).is_err());
}
#[test]
fn reauthorized_invalid_model_geometry_and_files_are_rejected() {
    let (_, raw) = verified();
    let original: Value = serde_json::from_slice(&raw).unwrap();
    for (field, value) in [
        ("filesystem", json!("xfs")),
        ("deviceBytes", json!(false)),
        ("headerBytes", json!(4096)),
        ("dataOffsetBytes", json!(0)),
        ("profileSha256", json!("f".repeat(64))),
        ("luksUuid", json!("../escape")),
    ] {
        let mut m = original.clone();
        m[field] = value;
        let raw = serde_json::to_vec(&m).unwrap();
        assert!(
            RoManifest::verify(&signed_changed(&raw), &raw, 2147483648).is_err(),
            "{field}"
        );
    }
    for (field, value) in [
        ("root", json!("invalid")),
        ("hashAlgorithm", json!("sha1")),
        ("hashOffsetBytes", json!(0)),
        ("blockBytes", json!(512)),
    ] {
        let mut m = original.clone();
        m["verity"][field] = value;
        let raw = serde_json::to_vec(&m).unwrap();
        assert!(
            RoManifest::verify(&signed_changed(&raw), &raw, 2147483648).is_err(),
            "{field}"
        );
    }
    let mut m = original.clone();
    m["verity"]["dataBytes"] = json!(2147483648u64 - 4096);
    m["verity"]["hashOffsetBytes"] = m["verity"]["dataBytes"].clone();
    let raw = serde_json::to_vec(&m).unwrap();
    assert!(RoManifest::verify(&signed_changed(&raw), &raw, 2147483648).is_err());
    for path in ["/model", "../model", "a//model"] {
        let mut m = original.clone();
        m["files"][0]["path"] = json!(path);
        let raw = serde_json::to_vec(&m).unwrap();
        assert!(RoManifest::verify(&signed_changed(&raw), &raw, 2147483648).is_err());
    }
}
#[test]
#[cfg(target_os = "linux")]
#[ignore = "requires the real published ciphertext disk retained in the isolated compiler"]
fn real_published_luks_header_matches_authenticated_ro_profile() {
    use std::io::Read;
    let path = std::env::var("COCO_TEST_RO_DISK").expect("explicit published disk required");
    let mut file = std::fs::File::open(path).unwrap();
    assert!(file.metadata().unwrap().is_file());
    let (grant, raw) = verified();
    let prepared = crate::sealed_header::PreparedRoHeader::prepare(
        &grant,
        &raw,
        &file,
        file.metadata().unwrap().len(),
    )
    .unwrap();
    assert_eq!(
        prepared.manifest().verity().root(),
        "83a4d3d9c170836bacedfa171f3e20f540cd3e98344cf33a2f5cba80caa5ab63"
    );
    let m = RoManifest::verify(&grant, &raw, file.metadata().unwrap().len()).unwrap();
    let mut bytes = vec![0; HEADER_BYTES];
    file.read_exact(&mut bytes).unwrap();
    m.validate_header(&grant, &bytes).unwrap();
    bytes[500000] ^= 1;
    assert!(m.validate_header(&grant, &bytes).is_err());
}

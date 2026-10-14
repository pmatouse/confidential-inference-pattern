// SPDX-License-Identifier: Apache-2.0
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use confidential_storage_guest::receipt::{Expected, Verifier};
use serde::Deserialize;
#[derive(Deserialize)]
struct Invalid {
    name: String,
    token: String,
}
#[derive(Deserialize)]
struct Fixture {
    public_key: String,
    issuer: String,
    key_id: String,
    now: u64,
    expected: Expected,
    valid: String,
    invalid: Vec<Invalid>,
    manifest: String,
    copied_header: String,
}
fn fixture() -> Fixture {
    serde_json::from_str(include_str!("receipt-fixture.json")).unwrap()
}
#[test]
fn verifies_real_python_authority_signature() {
    let f = fixture();
    let key: [u8; 32] = B64.decode(f.public_key).unwrap().try_into().unwrap();
    let v = Verifier::new(key, f.issuer, f.key_id);
    let grant = v.verify(&f.valid, &f.expected, f.now).unwrap();
    let manifest = B64.decode(f.manifest).unwrap();
    let header = B64.decode(f.copied_header).unwrap();
    assert_eq!(
        grant.authenticate_manifest(&manifest).unwrap().as_bytes(),
        manifest
    );
    assert_eq!(
        grant.authenticate_header(&header).unwrap().as_bytes(),
        header
    );
    assert!(grant.authenticate_manifest(b"substituted").is_err());
    assert!(grant.authenticate_header(b"substituted").is_err());
    assert!(grant.authenticate_header(&[]).is_err());
    assert!(grant.authenticate_manifest(&vec![0; 65537]).is_err());
    for bad in f.invalid {
        assert!(
            v.verify(&bad.token, &f.expected, f.now).is_err(),
            "{}",
            bad.name
        )
    }
}
#[test]
fn requires_pinned_key_and_exact_local_request() {
    let f = fixture();
    let key: [u8; 32] = B64.decode(&f.public_key).unwrap().try_into().unwrap();
    assert!(Verifier::new([0; 32], f.issuer.clone(), f.key_id.clone())
        .verify(&f.valid, &f.expected, f.now)
        .is_err());
    let v = Verifier::new(key, f.issuer, f.key_id);
    for field in [
        "volume_id",
        "policy_sha256",
        "profile_sha256",
        "session_sha256",
        "operation_id",
        "nonce",
        "manifest_uri",
        "container_name",
        "destination",
        "access",
    ] {
        let mut expected = serde_json::to_value(&f.expected).unwrap();
        expected[field] = "substituted".into();
        assert!(
            v.verify(&f.valid, &serde_json::from_value(expected).unwrap(), f.now)
                .is_err(),
            "{field}"
        );
    }
    assert!(v.verify(&f.valid, &f.expected, f.now + 60).is_err());
    assert!(v
        .verify(&(f.valid.clone() + "."), &f.expected, f.now)
        .is_err());
    assert!(v.verify(&"a".repeat(16385), &f.expected, f.now).is_err());
}

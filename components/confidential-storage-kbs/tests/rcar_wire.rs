// SPDX-License-Identifier: Apache-2.0
//! Wire compatibility only; synthetic evidence is not a hardware attestation.
#[test]
fn dedicated_signing_key_and_composite_envelope_round_trip_pinned_kbs_types() {
    let wire = serde_json::json!({
        "init-data":{"format":"toml","body":"version = \"0.1.0\""},
        "runtime-data":{"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "tee-pubkey":{"kty":"EC","crv":"P-256","alg":"ES256","x":"synthetic","y":"synthetic"}},
        "tee-evidence":{"primary_evidence":{"synthetic":true},"additional_evidence":"{\"nvidia\":{}}"}
    });
    let parsed: kbs_types::Attestation = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), wire);
}

// SPDX-License-Identifier: Apache-2.0
//! Test-only synthetic evidence, actual authority signatures and KBS crypto.
//! Never install or approve this example as a confidential guest executable.
use confidential_storage_client::{
    initialization::{Operation, Request},
    AuthorityClient, Config, Evidence,
};
use confidential_storage_kbs::{Config as KbsConfig, SnpCpuKbs};
use kbs_protocol::evidence_provider::EvidenceProvider;
use serde_json::{json, Value};
use std::fs;
struct Synthetic;
impl Evidence for Synthetic {
    fn collect(&self, d: [u8; 32]) -> confidential_storage_client::Result<Vec<u8>> {
        Ok(serde_json::to_vec(&json!({"SYNTHETIC_TEST_RUNTIME_DIGEST":hex(&d)})).unwrap())
    }
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
#[async_trait::async_trait]
impl EvidenceProvider for Synthetic {
    async fn primary_evidence(&self, d: Vec<u8>) -> kbs_protocol::Result<Value> {
        Ok(json!({"SYNTHETIC_KBS_RUNTIME_DIGEST":hex(&d)}))
    }
    async fn get_additional_evidence(&self, _d: Vec<u8>) -> kbs_protocol::Result<String> {
        Ok(String::new())
    }
    async fn get_tee_type(&self) -> kbs_protocol::Result<kbs_types::Tee> {
        Ok(kbs_types::Tee::Snp)
    }
}
fn main() {
    let v: Value =
        serde_json::from_slice(&fs::read(std::env::args().nth(1).unwrap()).unwrap()).unwrap();
    let authority = AuthorityClient::new(
        Config {
            audience: v["audience"].as_str().unwrap().into(),
            certificate_der: fs::read(v["certificate_der"].as_str().unwrap()).unwrap(),
            address: Some(v["address"].as_str().unwrap().parse().unwrap()),
            policy_sha256: v["policy_sha256"].as_str().unwrap().into(),
            init_data: v["init_data"].as_str().unwrap().into(),
            receipt_public_key: serde_json::from_value(v["receipt_public_key"].clone()).unwrap(),
            receipt_issuer: v["receipt_issuer"].as_str().unwrap().into(),
            receipt_key_id: v["receipt_key_id"].as_str().unwrap().into(),
        },
        Synthetic,
    )
    .unwrap();
    let mut expected: confidential_storage_guest::receipt::Expected =
        serde_json::from_value(v["expected"].clone()).unwrap();
    expected.session_sha256 = authority.session_sha256().into();
    let request = if v["mode"] == "readonly" {
        None
    } else {
        let request = Request {
            expected: expected.clone(),
            plan_sha256: v["plan_sha256"].as_str().unwrap().into(),
        };
        assert!(authority.authorize_initialization_key(&request).is_err());
        authority
            .initialization(&request, Operation::Begin)
            .unwrap();
        Some(request)
    };
    let obtain = || match &request {
        Some(request) => authority.authorize_initialization_key(request).unwrap(),
        None => authority.authorize_reopen_key(&expected).unwrap().1,
    };
    let permit = obtain();
    let k = &v["kbs"];
    let provider = SnpCpuKbs::new(
        &authority,
        KbsConfig {
            origin: k["origin"].as_str().unwrap().into(),
            certificate_der: fs::read(k["certificate_der"].as_str().unwrap()).unwrap(),
            address: Some(k["address"].as_str().unwrap().parse().unwrap()),
            init_data_toml: k["init_data_toml"].as_str().unwrap().into(),
            allowed_resources: serde_json::from_value(k["allowed_resources"].clone()).unwrap(),
            require_gpu: k["require_gpu"] == true,
        },
    );
    if v["deny_configuration"] == true {
        assert!(provider.is_err());
        println!("PASS configuration rejected");
        return;
    }
    let provider = provider.unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime.block_on(provider.retrieve_fixture(permit, Box::new(Synthetic)));
    if v["deny"] == true {
        assert!(result.is_err());
        println!("PASS key retrieval rejected");
        return;
    }
    let key = result.unwrap();
    assert_eq!(
        hex(ring::digest::digest(&ring::digest::SHA256, key.as_bytes()).as_ref()),
        v["expected_key_sha256"].as_str().unwrap()
    );
    drop(key);
    // A second retrieval must perform fresh attestation with a new TEE key.
    let permit = obtain();
    let key = runtime
        .block_on(provider.retrieve_fixture(permit, Box::new(Synthetic)))
        .unwrap();
    assert_eq!(key.as_bytes().len(), 32);
    drop(key);
    println!("PASS bound private key retrieval, fresh RCAR, encrypted KBS response");
}

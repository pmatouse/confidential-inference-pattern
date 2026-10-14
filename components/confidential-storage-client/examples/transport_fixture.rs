// SPDX-License-Identifier: Apache-2.0
//! Synthetic evidence for cross-language TLS tests ONLY; not a guest executable.
use confidential_storage_client::{AuthorityClient, Config, Evidence, Result};
use confidential_storage_guest::receipt::Expected;
use serde_json::{json, Value};
use std::{fs, net::SocketAddr};
struct FixtureEvidence;
impl Evidence for FixtureEvidence {
    fn collect(&self, digest: [u8; 32]) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&json!({"SYNTHETIC_TEST_RUNTIME_DIGEST":digest.iter().map(|b|format!("{b:02x}")).collect::<String>()})).unwrap())
    }
}
fn main() {
    let input = std::env::args()
        .nth(1)
        .expect("explicit temporary fixture configuration");
    let v: Value = serde_json::from_slice(&fs::read(input).unwrap()).unwrap();
    let c = Config {
        audience: v["audience"].as_str().unwrap().into(),
        certificate_der: fs::read(v["certificate_der"].as_str().unwrap()).unwrap(),
        address: Some(
            v["address"]
                .as_str()
                .unwrap()
                .parse::<SocketAddr>()
                .unwrap(),
        ),
        policy_sha256: v["policy_sha256"].as_str().unwrap().into(),
        init_data: v["init_data"].as_str().unwrap().into(),
        receipt_public_key: serde_json::from_value(v["receipt_public_key"].clone()).unwrap(),
        receipt_issuer: v["receipt_issuer"].as_str().unwrap().into(),
        receipt_key_id: v["receipt_key_id"].as_str().unwrap().into(),
    };
    let client = AuthorityClient::new(c, FixtureEvidence).unwrap();
    let mut expected: Expected = serde_json::from_value(v["expected"].clone()).unwrap();
    expected.session_sha256 = client.session_sha256().into();
    if v["mode"] == "initialize" {
        initialize(&client, expected, &v);
        return;
    }
    match client.reopen(&expected) {
        Err(_) if v["deny"] == true => {
            println!("PASS denied fixture request");
        }
        Ok(grant) if v["deny"] != true => {
            let retry = client.reopen(&expected).unwrap();
            assert_eq!(grant.claims().activation_id, retry.claims().activation_id);
            client.close(&grant).unwrap();
            client.close(&grant).unwrap();
            assert!(client.reopen(&expected).is_err());
            println!(
                "PASS TLS receipt verification, stable-session retry, close, durable replay denial"
            );
        }
        _ => panic!("unexpected fixture authorization result"),
    }
}

// No disk I/O: this exercises the signed protocol and journal only.
fn initialize(client: &AuthorityClient<FixtureEvidence>, expected: Expected, v: &Value) {
    use confidential_storage_client::initialization::{
        Completion, Decision, Operation, Request, State, Step, StepDecision,
    };
    use ring::digest::{digest, SHA256};
    let request = Request {
        expected,
        plan_sha256: v["plan_sha256"].as_str().unwrap().into(),
    };
    let plan = client.initialization(&request, Operation::Plan);
    if v["deny"] == true {
        assert!(plan.is_err());
        println!("PASS denied initialization fixture request");
        return;
    }
    assert!(matches!(plan.unwrap(), Decision::Plan(r) if *r.state() == State::Uninitialized));
    let record = match client.initialization(&request, Operation::Begin).unwrap() {
        Decision::Begin {
            fresh: true,
            record,
        } => record,
        _ => panic!("expected fresh initialization"),
    };
    let activation = record.activation_id().unwrap().to_owned();
    for step in [
        Step::LuksFormat,
        Step::IntegrityInitialize,
        Step::FilesystemCreate,
        Step::DurabilityBarrier,
    ] {
        let start = || Operation::Step {
            activation_id: activation.clone(),
            step,
        };
        let permit = match client.initialization(&request, start()).unwrap() {
            Decision::Step(StepDecision::Execute(p)) => p,
            _ => panic!("expected single execution permit"),
        };
        assert!(matches!(
            client.initialization(&request, start()).unwrap(),
            Decision::Step(StepDecision::Reconcile)
        ));
        if v["stop_started"] == true {
            drop(permit); // Simulate loss before any disk operation.
            assert!(matches!(
                client.initialization(&request, start()).unwrap(),
                Decision::Step(StepDecision::Reconcile)
            ));
            println!("PASS lost execute decision never reissued");
            return;
        }
        let execution = permit.consume().unwrap();
        let raw_manifest = record.manifest(&"d".repeat(64)).unwrap();
        let manifest_hash: String = digest(&SHA256, &raw_manifest)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let result = Completion {
            header_sha256: "d".repeat(64),
            stack_sha256: (step == Step::IntegrityInitialize).then(|| "9".repeat(64)),
            filesystem_uuid: (step == Step::FilesystemCreate)
                .then(|| "01234567-89ab-4cde-8123-456789abcdef".into()),
            manifest_sha256: (step == Step::DurabilityBarrier).then_some(manifest_hash),
        };
        assert!(matches!(
            client
                .initialization(
                    &request,
                    Operation::Complete {
                        activation_id: execution.activation_id().into(),
                        step,
                        step_id: execution.step_id().into(),
                        result,
                        evidence_sha256: "8".repeat(64),
                    }
                )
                .unwrap(),
            Decision::Completed
        ));
        assert!(matches!(
            client.initialization(&request, start()).unwrap(),
            Decision::Step(StepDecision::Complete)
        ));
    }
    let ready = match client
        .initialization(
            &request,
            Operation::Ready {
                activation_id: activation.clone(),
                header_sha256: "d".repeat(64),
            },
        )
        .unwrap()
    {
        Decision::Ready(r) => r,
        _ => panic!("expected Ready"),
    };
    assert!(client
        .initialization(
            &request,
            Operation::Step {
                activation_id: activation,
                step: Step::LuksFormat
            }
        )
        .is_err());
    assert_eq!(
        ready.ready_manifest().unwrap(),
        ready.manifest(&"d".repeat(64)).unwrap()
    );
    client.close_initialization(&ready).unwrap();
    let mut reopen = request.expected.clone();
    reopen.operation_id = "rust-after-init".into();
    assert!(client.authorize_initialization_key(&request).is_err());
    let (grant, permit) = client.authorize_reopen_key(&reopen).unwrap();
    assert!(permit
        .check(
            client.session_sha256(),
            client.policy_sha256(),
            &["kbs:///storage-test/keys/scratch-v1".into()]
        )
        .is_ok());
    client.close(&grant).unwrap();
    println!("PASS signed initialization, one-shot steps, Ready, close and reopen");
}

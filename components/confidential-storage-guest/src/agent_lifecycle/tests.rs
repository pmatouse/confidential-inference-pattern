// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::receipt::{Claims, Expected, Verifier};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use tokio::sync::Semaphore;
fn grant(volume: &str, id: &str, operation: &str) -> VerifiedGrant {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let key = Ed25519KeyPair::from_pkcs8(
        Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .unwrap()
            .as_ref(),
    )
    .unwrap();
    let claims = Claims {
        schema_version: 1,
        iss: "issuer".into(),
        aud: "confidential-storage-guest/v1".into(),
        iat: now,
        exp: now + 60,
        volume_id: volume.into(),
        generation: 1,
        policy_sha256: "a".repeat(64),
        profile_sha256: "c".repeat(64),
        manifest_sha256: "e".repeat(64),
        header_sha256: "d".repeat(64),
        credential_uri: "kbs:///test/keys/key-v1".into(),
        session_sha256: "b".repeat(64),
        operation_id: operation.into(),
        operation: "reopen".into(),
        nonce: "f".repeat(64),
        activation_id: id.into(),
        manifest_uri: "kbs:///test/records/record-v1".into(),
        container_name: "app".into(),
        destination: "/data".into(),
        access: "rw".into(),
    };
    let expected = Expected {
        volume_id: claims.volume_id.clone(),
        generation: 1,
        policy_sha256: claims.policy_sha256.clone(),
        profile_sha256: claims.profile_sha256.clone(),
        session_sha256: claims.session_sha256.clone(),
        operation_id: claims.operation_id.clone(),
        nonce: claims.nonce.clone(),
        manifest_uri: claims.manifest_uri.clone(),
        container_name: "app".into(),
        destination: "/data".into(),
        access: "rw".into(),
    };
    let header =
        B64.encode(br#"{"alg":"Ed25519","typ":"confidential-storage-grant+jwt","kid":"key-1"}"#);
    let payload = B64.encode(serde_json::to_vec(&claims).unwrap());
    let signed = format!("{header}.{payload}");
    let token = format!(
        "{signed}.{}",
        B64.encode(key.sign(signed.as_bytes()).as_ref())
    );
    Verifier::new(
        key.public_key().as_ref().try_into().unwrap(),
        "issuer".into(),
        "key-1".into(),
    )
    .verify(&token, &expected, now)
    .unwrap()
}
struct Gate {
    step: &'static str,
    entered: Semaphore,
    release: Semaphore,
}
#[derive(Default)]
struct State {
    calls: Mutex<Vec<&'static str>>,
    fail: Mutex<Option<&'static str>>,
    panic: Mutex<Option<&'static str>>,
    gate: Option<Gate>,
}
#[derive(Clone, Default)]
struct Mock(Arc<State>);
impl Mock {
    async fn step(&self, name: &'static str) -> BackendResult {
        self.0.calls.lock().await.push(name);
        let mut fail = self.0.fail.lock().await;
        if *fail == Some(name) {
            *fail = None;
            return Err(BackendError("injected"));
        }
        drop(fail);
        let mut panic = self.0.panic.lock().await;
        if *panic == Some(name) {
            *panic = None;
            panic!("injected callback panic");
        }
        drop(panic);
        if let Some(g) = &self.0.gate {
            if g.step == name {
                g.entered.add_permits(1);
                g.release.acquire().await.unwrap().forget();
            }
        }
        Ok(())
    }
    async fn calls(&self) -> Vec<&'static str> {
        self.0.calls.lock().await.clone()
    }
}
#[async_trait]
impl Backend for Mock {
    async fn open(&self, _: &VerifiedGrant, _: &str) -> BackendResult {
        self.step("open").await
    }
    async fn mount(&self, _: &VerifiedGrant, _: &str) -> BackendResult {
        self.step("mount").await
    }
    async fn unmount(&self, _: &VerifiedGrant, _: &str) -> BackendResult {
        self.step("unmount").await
    }
    async fn close_mapping(&self, _: &VerifiedGrant) -> BackendResult {
        self.step("close-mapping").await
    }
    async fn release(&self, _: &VerifiedGrant) -> BackendResult {
        self.step("release").await
    }
}
#[async_trait]
impl Runtime for Mock {
    type Consumer = Identity;
    async fn prepare(&self, id: &Identity) -> std::result::Result<Identity, BackendError> {
        self.step("prepare").await?;
        Ok(id.clone())
    }
    async fn start(&self, _: &Identity) -> BackendResult {
        self.step("start").await
    }
    async fn quiesce(&self, _: &Identity) -> BackendResult {
        self.step("quiesce").await
    }
    async fn destroy(&self, _: &Identity) -> BackendResult {
        self.step("destroy").await
    }
}
#[async_trait]
impl ConsumerBackend<Identity> for Mock {
    async fn attach(&self, g: &VerifiedGrant, id: Identity) -> BackendResult {
        assert_eq!(id.activation_id, g.claims().activation_id);
        assert_eq!(id.container_name, g.claims().container_name);
        self.step("attach").await
    }
}
fn setup() -> (Mock, Arc<Agent<Mock, Mock>>, VerifiedGrant) {
    let m = Mock::default();
    let a = Agent::new(m.clone(), m.clone(), "b".repeat(64), 8);
    (m, a, grant("volume", "activation", "operation"))
}
async fn prepare(a: &Arc<Agent<Mock, Mock>>, g: VerifiedGrant) -> Result<Phase> {
    a.prepare("container".into(), g, "8:1".into()).await
}
#[tokio::test]
async fn exact_retry_start_barrier_and_ordered_teardown() {
    let (m, a, g) = setup();
    assert!(matches!(a.start("container").await, Err(Error::Unknown)));
    assert_eq!(prepare(&a, g.clone()).await.unwrap(), Phase::Ready);
    prepare(&a, g.clone()).await.unwrap();
    assert_eq!(m.calls().await, ["prepare", "open", "mount", "attach"]);
    a.start("container").await.unwrap();
    a.start("container").await.unwrap();
    assert_eq!(prepare(&a, g.clone()).await.unwrap(), Phase::Running);
    a.close("container").await.unwrap();
    a.close("container").await.unwrap();
    assert_eq!(
        m.calls().await,
        [
            "prepare",
            "open",
            "mount",
            "attach",
            "start",
            "quiesce",
            "unmount",
            "close-mapping",
            "release",
            "destroy"
        ]
    );
    assert!(a.start("container").await.is_err());
    assert!(prepare(&a, g.clone()).await.is_err());
    assert!(a.prepare("alias".into(), g, "8:1".into()).await.is_err());
}
#[tokio::test]
async fn admission_and_conflicts_have_no_runtime_effects() {
    let (m, a, g) = setup();
    assert!(a
        .prepare("../bad".into(), g.clone(), "8:1".into())
        .await
        .is_err());
    assert!(a
        .prepare("container".into(), g.clone(), "/dev/vda".into())
        .await
        .is_err());
    assert!(m.calls().await.is_empty());
    prepare(&a, g.clone()).await.unwrap();
    let before = m.calls().await;
    assert!(a
        .prepare(
            "other".into(),
            grant("other", "other", "other"),
            "8:2".into()
        )
        .await
        .is_err());
    assert!(a
        .prepare("container".into(), g, "8:2".into())
        .await
        .is_err());
    assert_eq!(m.calls().await, before);
    a.close("container").await.unwrap();
    a.prepare(
        "other".into(),
        grant("other", "other", "other"),
        "8:2".into(),
    )
    .await
    .unwrap();
}
#[tokio::test]
async fn prepare_and_attach_errors_never_start_application() {
    for step in ["prepare", "open", "mount", "attach"] {
        let (m, a, g) = setup();
        *m.0.fail.lock().await = Some(step);
        assert!(prepare(&a, g).await.is_err());
        assert_eq!(a.phase("container").await.unwrap(), Phase::Closed);
        let calls = m.calls().await;
        assert!(!calls.contains(&"start"));
        assert_eq!(calls.last(), Some(&"destroy"));
        if step == "prepare" {
            assert_eq!(calls, ["prepare", "quiesce", "release", "destroy"]);
        }
    }
}
#[tokio::test]
async fn cleanup_failures_retain_precise_phase_and_block_start() {
    for (step, phase) in [
        ("quiesce", Phase::NeedsQuiesce),
        ("unmount", Phase::NeedsStorageClose),
        ("close-mapping", Phase::NeedsStorageClose),
        ("release", Phase::NeedsStorageClose),
        ("destroy", Phase::NeedsDestroy),
    ] {
        let (m, a, g) = setup();
        prepare(&a, g).await.unwrap();
        a.start("container").await.unwrap();
        *m.0.fail.lock().await = Some(step);
        assert!(a.close("container").await.is_err());
        assert_eq!(a.phase("container").await.unwrap(), phase);
        let before = m.calls().await;
        assert!(a.start("container").await.is_err());
        assert_eq!(m.calls().await, before);
        if step != "destroy" {
            assert!(!before.contains(&"destroy"));
        }
        if ["quiesce", "unmount", "close-mapping"].contains(&step) {
            assert!(!before.contains(&"release"));
        }
        a.close("container").await.unwrap();
        assert_eq!(a.phase("container").await.unwrap(), Phase::Closed);
    }
}
#[tokio::test]
async fn ambiguous_start_failure_is_quiesced_never_retried() {
    let (m, a, g) = setup();
    prepare(&a, g).await.unwrap();
    *m.0.fail.lock().await = Some("start");
    assert!(a.start("container").await.is_err());
    assert!(a.start("container").await.is_err());
    assert_eq!(a.phase("container").await.unwrap(), Phase::Closed);
    assert_eq!(m.calls().await.iter().filter(|s| **s == "start").count(), 1);
}
#[tokio::test]
async fn panic_retains_record_for_explicit_cleanup() {
    for (step, phase) in [
        ("prepare", Phase::Preparing),
        ("attach", Phase::Preparing),
        ("start", Phase::Starting),
    ] {
        let (m, a, g) = setup();
        *m.0.panic.lock().await = Some(step);
        let result = if step == "start" {
            prepare(&a, g).await.unwrap();
            a.start("container").await.map(|_| Phase::Running)
        } else {
            prepare(&a, g).await
        };
        assert!(matches!(result, Err(Error::Worker)));
        assert_eq!(a.phase("container").await.unwrap(), phase);
        assert!(a.start("container").await.is_err());
        a.close("container").await.unwrap();
        assert_eq!(a.phase("container").await.unwrap(), Phase::Closed);
    }
}
fn gated(step: &'static str) -> (Mock, Arc<Agent<Mock, Mock>>, VerifiedGrant) {
    let m = Mock(Arc::new(State {
        gate: Some(Gate {
            step,
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
        }),
        ..Default::default()
    }));
    let a = Agent::new(m.clone(), m.clone(), "b".repeat(64), 8);
    (m, a, grant("volume", "activation", "operation"))
}
async fn entered(m: &Mock) {
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        m.0.gate.as_ref().unwrap().entered.acquire(),
    )
    .await
    .unwrap()
    .unwrap()
    .forget();
}
#[tokio::test]
async fn cancelled_prepare_waiter_does_not_abandon_paused_container() {
    let (m, a, g) = gated("attach");
    let outer = tokio::spawn({
        let a = a.clone();
        let g = g.clone();
        async move { prepare(&a, g).await }
    });
    entered(&m).await;
    outer.abort();
    assert!(outer.await.unwrap_err().is_cancelled());
    assert!(!m.calls().await.contains(&"start"));
    m.0.gate.as_ref().unwrap().release.add_permits(1);
    assert_eq!(prepare(&a, g).await.unwrap(), Phase::Ready);
    a.close("container").await.unwrap();
}
#[tokio::test]
async fn close_wins_against_start_and_cancelled_waiter() {
    let (m, a, g) = gated("quiesce");
    prepare(&a, g).await.unwrap();
    let outer = tokio::spawn({
        let a = a.clone();
        async move { a.close("container").await }
    });
    entered(&m).await;
    let start = tokio::spawn({
        let a = a.clone();
        async move { a.start("container").await }
    });
    outer.abort();
    assert!(outer.await.unwrap_err().is_cancelled());
    m.0.gate.as_ref().unwrap().release.add_permits(1);
    assert!(start.await.unwrap().is_err());
    a.close("container").await.unwrap();
    assert!(!m.calls().await.contains(&"start"));
}
#[tokio::test]
async fn in_flight_start_finishes_before_quiescence() {
    let (m, a, g) = gated("start");
    prepare(&a, g).await.unwrap();
    let start = tokio::spawn({
        let a = a.clone();
        async move { a.start("container").await }
    });
    entered(&m).await;
    let close = tokio::spawn({
        let a = a.clone();
        async move { a.close("container").await }
    });
    start.abort();
    assert!(!m.calls().await.contains(&"quiesce"));
    m.0.gate.as_ref().unwrap().release.add_permits(1);
    close.await.unwrap().unwrap();
    assert_eq!(a.phase("container").await.unwrap(), Phase::Closed);
}
#[tokio::test]
async fn bounded_tombstones_do_not_reuse_runtime_identity() {
    let m = Mock::default();
    let a = Agent::new(m.clone(), m.clone(), "b".repeat(64), 1);
    prepare(&a, grant("volume", "activation", "operation"))
        .await
        .unwrap();
    a.close("container").await.unwrap();
    let calls = m.calls().await;
    assert!(a
        .prepare(
            "other".into(),
            grant("other", "other", "other"),
            "8:2".into()
        )
        .await
        .is_err());
    assert_eq!(calls, m.calls().await);
}

// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::receipt::{Claims, Expected, Verifier};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use tokio::sync::Semaphore;
const NOW: u64 = 2000000000;
fn grant(volume: &str, id: &str, operation: &str) -> VerifiedGrant {
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
        iat: NOW,
        exp: NOW + 60,
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
    .verify(&token, &expected, NOW)
    .unwrap()
}
struct Gate {
    step: &'static str,
    entered: Semaphore,
    release: Semaphore,
}
#[derive(Default)]
struct Mock {
    calls: Mutex<Vec<&'static str>>,
    failures: Mutex<HashMap<&'static str, usize>>,
    gate: Option<Arc<Gate>>,
    panic_open: bool,
}
impl Mock {
    async fn step(&self, step: &'static str) -> BackendResult {
        self.calls.lock().await.push(step);
        let mut failures = self.failures.lock().await;
        if let Some(count) = failures.get_mut(step) {
            if *count > 0 {
                *count -= 1;
                return Err(BackendError("injected"));
            }
        }
        drop(failures);
        if self.panic_open && step == "open" {
            panic!("synthetic backend panic")
        }
        if let Some(gate) = &self.gate {
            if gate.step == step {
                gate.entered.add_permits(1);
                gate.release.acquire().await.unwrap().forget();
            }
        }
        Ok(())
    }
    async fn fail(&self, step: &'static str) {
        self.failures.lock().await.insert(step, 1);
    }
    async fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().await.clone()
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
        self.step("close").await
    }
    async fn release(&self, _: &VerifiedGrant) -> BackendResult {
        self.step("release").await
    }
}
fn setup() -> (Arc<Mock>, Arc<Controller<Mock>>, VerifiedGrant) {
    let backend = Arc::new(Mock::default());
    let c = Controller::new(backend.clone(), "b".repeat(64), 32);
    (backend, c, grant("volume-1", "activation-1", "open-1"))
}
async fn activate(c: &Arc<Controller<Mock>>, g: VerifiedGrant) -> Result<Mounted> {
    c.activate_at(g, "8:16".into(), NOW).await
}
#[tokio::test]
async fn idempotent_activation_and_ordered_cleanup() {
    let (b, c, g) = setup();
    let (a, d) = tokio::join!(activate(&c, g.clone()), activate(&c, g.clone()));
    assert_eq!(a.unwrap(), d.unwrap());
    assert_eq!(b.calls().await, vec!["open", "mount"]);
    c.close("activation-1").await.unwrap();
    c.close("activation-1").await.unwrap();
    assert_eq!(
        b.calls().await,
        vec!["open", "mount", "unmount", "close", "release"]
    );
    assert!(matches!(activate(&c, g).await, Err(Error::Closed)));
}
#[tokio::test]
async fn denied_before_backend_on_bad_session_expiry_or_locator() {
    let (b, c, g) = setup();
    assert!(c
        .activate_at(g.clone(), "8:16".into(), NOW + 60)
        .await
        .is_err());
    assert!(c.activate_at(g.clone(), "08:16".into(), NOW).await.is_err());
    assert!(c
        .activate_at(g.clone(), "/dev/sda".into(), NOW)
        .await
        .is_err());
    let other = Controller::new(b.clone(), "1".repeat(64), 32);
    assert!(activate(&other, g).await.is_err());
    assert!(b.calls().await.is_empty());
}
#[tokio::test]
async fn rejects_another_owner_or_alias_of_device() {
    let (b, c, g) = setup();
    activate(&c, g.clone()).await.unwrap();
    assert!(matches!(
        activate(&c, grant("volume-1", "activation-2", "open-2")).await,
        Err(Error::Conflict)
    ));
    assert!(matches!(
        activate(&c, grant("volume-2", "activation-2", "open-2")).await,
        Err(Error::Conflict)
    ));
    assert!(matches!(
        c.activate_at(g, "8:17".into(), NOW).await,
        Err(Error::Conflict)
    ));
    assert_eq!(b.calls().await, vec!["open", "mount"]);
}
#[tokio::test]
async fn open_failure_closes_partial_mapping_before_release() {
    let (b, c, g) = setup();
    b.fail("open").await;
    assert!(activate(&c, g).await.is_err());
    assert_eq!(b.calls().await, vec!["open", "close", "release"]);
    assert_eq!(c.phase("activation-1").await.unwrap(), Phase::Closed);
}
#[tokio::test]
async fn partial_mount_failure_unmounts_before_mapping_close() {
    let (b, c, g) = setup();
    b.fail("mount").await;
    assert!(activate(&c, g).await.is_err());
    assert_eq!(
        b.calls().await,
        vec!["open", "mount", "unmount", "close", "release"]
    );
}
#[tokio::test]
async fn busy_mount_retains_owner_and_retries_unmount() {
    let (b, c, g) = setup();
    activate(&c, g.clone()).await.unwrap();
    b.fail("unmount").await;
    assert!(c.close("activation-1").await.is_err());
    assert_eq!(c.phase("activation-1").await.unwrap(), Phase::NeedsUnmount);
    assert_eq!(b.calls().await, vec!["open", "mount", "unmount"]);
    assert!(matches!(
        activate(&c, grant("volume-1", "activation-2", "open-2")).await,
        Err(Error::Conflict)
    ));
    assert!(matches!(activate(&c, g).await, Err(Error::NeedsCleanup)));
    c.close("activation-1").await.unwrap();
    assert_eq!(
        b.calls().await,
        vec!["open", "mount", "unmount", "unmount", "close", "release"]
    );
}
#[tokio::test]
async fn close_failure_retains_state_without_repeating_unmount() {
    let (b, c, g) = setup();
    activate(&c, g).await.unwrap();
    b.fail("close").await;
    assert!(c.close("activation-1").await.is_err());
    assert_eq!(c.phase("activation-1").await.unwrap(), Phase::NeedsClose);
    assert!(!b.calls().await.contains(&"release"));
    c.close("activation-1").await.unwrap();
    assert_eq!(
        b.calls().await,
        vec!["open", "mount", "unmount", "close", "close", "release"]
    );
}
#[tokio::test]
async fn release_failure_retries_only_release() {
    let (b, c, g) = setup();
    activate(&c, g).await.unwrap();
    b.fail("release").await;
    assert!(c.close("activation-1").await.is_err());
    assert_eq!(c.phase("activation-1").await.unwrap(), Phase::NeedsRelease);
    assert!(matches!(
        activate(&c, grant("volume-1", "activation-2", "open-2")).await,
        Err(Error::Conflict)
    ));
    c.close("activation-1").await.unwrap();
    assert_eq!(
        b.calls().await,
        vec!["open", "mount", "unmount", "close", "release", "release"]
    );
}
#[tokio::test]
async fn failed_open_and_failed_cleanup_never_reopens_implicitly() {
    let (b, c, g) = setup();
    b.fail("open").await;
    b.fail("close").await;
    assert!(activate(&c, g.clone()).await.is_err());
    assert_eq!(c.phase("activation-1").await.unwrap(), Phase::NeedsClose);
    assert!(matches!(activate(&c, g).await, Err(Error::NeedsCleanup)));
    c.close("activation-1").await.unwrap();
    assert_eq!(b.calls().await, vec!["open", "close", "close", "release"]);
}
#[tokio::test]
async fn cancelled_activation_waiter_keeps_service_owned_worker() {
    let gate = Arc::new(Gate {
        step: "open",
        entered: Semaphore::new(0),
        release: Semaphore::new(0),
    });
    let b = Arc::new(Mock {
        gate: Some(gate.clone()),
        ..Default::default()
    });
    let c = Controller::new(b.clone(), "b".repeat(64), 32);
    let g = grant("volume-1", "activation-1", "open-1");
    let outer = tokio::spawn({
        let c = c.clone();
        let g = g.clone();
        async move { activate(&c, g).await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), gate.entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    outer.abort();
    assert!(outer.await.unwrap_err().is_cancelled());
    gate.release.add_permits(1);
    tokio::time::timeout(std::time::Duration::from_secs(2), activate(&c, g))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(b.calls().await, vec!["open", "mount"]);
    c.close("activation-1").await.unwrap();
}
#[tokio::test]
async fn cancelled_close_waiter_finishes_without_releasing_early() {
    let gate = Arc::new(Gate {
        step: "unmount",
        entered: Semaphore::new(0),
        release: Semaphore::new(0),
    });
    let b = Arc::new(Mock {
        gate: Some(gate.clone()),
        ..Default::default()
    });
    let c = Controller::new(b.clone(), "b".repeat(64), 32);
    activate(&c, grant("volume-1", "activation-1", "open-1"))
        .await
        .unwrap();
    let outer = tokio::spawn({
        let c = c.clone();
        async move { c.close("activation-1").await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), gate.entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    outer.abort();
    assert!(outer.await.unwrap_err().is_cancelled());
    assert!(!b.calls().await.contains(&"release"));
    gate.release.add_permits(1);
    tokio::time::timeout(std::time::Duration::from_secs(2), c.close("activation-1"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        b.calls().await,
        vec!["open", "mount", "unmount", "close", "release"]
    );
}
#[tokio::test]
async fn backend_panic_leaves_cleanup_record() {
    let b = Arc::new(Mock {
        panic_open: true,
        ..Default::default()
    });
    let c = Controller::new(b.clone(), "b".repeat(64), 32);
    assert!(matches!(
        activate(&c, grant("volume-1", "activation-1", "open-1")).await,
        Err(Error::Worker)
    ));
    assert_eq!(c.phase("activation-1").await.unwrap(), Phase::NeedsClose);
    c.close("activation-1").await.unwrap();
    assert_eq!(b.calls().await, vec!["open", "close", "release"]);
}
#[tokio::test]
async fn closed_tombstone_cannot_release_new_owner_and_is_not_evicted() {
    let (b, c, g) = setup();
    activate(&c, g.clone()).await.unwrap();
    c.close("activation-1").await.unwrap();
    activate(&c, grant("volume-1", "activation-2", "open-2"))
        .await
        .unwrap();
    let before = b.calls().await;
    c.close("activation-1").await.unwrap();
    assert_eq!(b.calls().await, before);
    assert!(matches!(activate(&c, g).await, Err(Error::Closed)));
    assert_eq!(c.phase("activation-2").await.unwrap(), Phase::Mounted);
}
#[tokio::test]
async fn bounded_registry_fails_closed_instead_of_dropping_tombstones() {
    let b = Arc::new(Mock::default());
    let c = Controller::new(b.clone(), "b".repeat(64), 1);
    activate(&c, grant("volume-1", "activation-1", "open-1"))
        .await
        .unwrap();
    c.close("activation-1").await.unwrap();
    assert!(matches!(
        activate(&c, grant("volume-1", "activation-2", "open-2")).await,
        Err(Error::Capacity)
    ));
    assert_eq!(c.phase("activation-1").await.unwrap(), Phase::Closed);
    assert!(matches!(c.close("unknown").await, Err(Error::Unknown)));
}

#[tokio::test(start_paused = true)]
async fn queued_worker_rechecks_deadline_before_disk_effects() {
    let (b, c, g) = setup();
    tokio::select! {
        biased;
        _=activate(&c,g)=>panic!("worker completed synchronously"),
        _=std::future::ready(())=>(),
    }
    tokio::time::advance(std::time::Duration::from_secs(60)).await;
    assert_eq!(c.phase("activation-1").await.unwrap(), Phase::Closed);
    assert_eq!(b.calls().await, vec!["release"]);
}

#[tokio::test]
async fn reservation_has_no_disk_effects_and_closes_without_open() {
    let (b, c, g) = setup();
    c.reserve_at(&g, "8:1", NOW).await.unwrap();
    assert_eq!(c.phase("activation-1").await.unwrap(), Phase::Reserved);
    assert!(b.calls().await.is_empty());
    assert!(matches!(
        c.reserve_at(&g, "8:2", NOW).await,
        Err(Error::Conflict)
    ));
    c.close("activation-1").await.unwrap();
    assert_eq!(b.calls().await, ["release"]);
    assert!(matches!(
        c.reserve_at(&g, "8:1", NOW).await,
        Err(Error::Closed)
    ));
}

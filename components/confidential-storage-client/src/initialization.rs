// SPDX-License-Identifier: Apache-2.0
//! Bound, signed first-use journal responses. No formatter or decryption key API.
//! ExecutePermit is consumed before a future trusted disk executor starts work.
use crate::{canonical, digest, now, sha, AuthorityClient, Error, Evidence, Result, B64};
use base64::Engine;
use confidential_storage_guest::receipt::Expected;
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use serde_json::{json, value::RawValue};

#[derive(Clone)]
pub struct Request {
    pub expected: Expected,
    pub plan_sha256: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Step {
    LuksFormat,
    IntegrityInitialize,
    FilesystemCreate,
    DurabilityBarrier,
}
const STEPS: [Step; 4] = [
    Step::LuksFormat,
    Step::IntegrityInitialize,
    Step::FilesystemCreate,
    Step::DurabilityBarrier,
];
#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Completion {
    pub header_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filesystem_uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_sha256: Option<String>,
}
impl Completion {
    fn check(&self, step: Step) -> Result<()> {
        if !digest(&self.header_sha256)
            || self.stack_sha256.is_some() != (step == Step::IntegrityInitialize)
            || self.filesystem_uuid.is_some() != (step == Step::FilesystemCreate)
            || self.manifest_sha256.is_some() != (step == Step::DurabilityBarrier)
            || self.stack_sha256.as_ref().is_some_and(|s| !digest(s))
            || self.manifest_sha256.as_ref().is_some_and(|s| !digest(s))
            || self.filesystem_uuid.as_ref().is_some_and(|s| !uuid(s))
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
}
pub enum Operation {
    Plan,
    Begin,
    Step {
        activation_id: String,
        step: Step,
    },
    Complete {
        activation_id: String,
        step: Step,
        step_id: String,
        result: Completion,
        evidence_sha256: String,
    },
    Ready {
        activation_id: String,
        header_sha256: String,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    schema_version: u32,
    iss: String,
    aud: String,
    iat: u64,
    exp: u64,
    action: String,
    session_sha256: String,
    policy_sha256: String,
    challenge: String,
    request_sha256: String,
    result: Box<RawValue>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    decision: String,
}
#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub manifest_uri: String,
    pub container_name: String,
    pub destination: String,
    pub access: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema_version: u32,
    pub new_volume: bool,
    pub provisioning_id: String,
    pub device_bytes: u64,
    pub luks_uuid: String,
    pub filesystem: String,
    pub header_bytes: u64,
    pub data_offset_bytes: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    plan: Plan,
    plan_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    session_sha256: String,
    operation_id: String,
    operation: String,
    activation_id: String,
    request_sha256: String,
}
#[derive(Deserialize, PartialEq, Eq)]
pub enum State {
    Uninitialized,
    Initializing,
    Ready,
}
#[derive(Deserialize, PartialEq, Eq)]
enum Status {
    Started,
    Complete,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalStep {
    step: Step,
    step_id: String,
    status: Status,
    result: Option<Completion>,
    evidence_sha256: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordData {
    volume_id: String,
    generation: u64,
    policy_sha256: String,
    initialization_policy_sha256: Option<String>,
    profile_sha256: String,
    credential_uri: String,
    mount_binding: Binding,
    initialization_approval: Approval,
    initialization_steps: Vec<JournalStep>,
    state: State,
    owner: Option<Owner>,
    manifest: Option<String>,
}
/// Metadata accepted only after signature and exact request-binding validation.
/// It cannot be constructed or deserialized by a caller.
pub struct Record(RecordData, u64);
impl Record {
    /// Manifest accepted only after the signed Ready journal was verified.
    pub fn ready_manifest(&self) -> Result<Vec<u8>> {
        if self.0.state != State::Ready {
            return Err(Error::Binding);
        }
        self.0
            .manifest
            .as_ref()
            .map(|s| s.as_bytes().to_vec())
            .ok_or(Error::Binding)
    }
    pub fn state(&self) -> &State {
        &self.0.state
    }
    pub fn plan(&self) -> &Plan {
        self.0.plan()
    }
    pub fn credential_uri(&self) -> &str {
        &self.0.credential_uri
    }
    pub fn activation_id(&self) -> Option<&str> {
        self.0.activation_id()
    }
    pub fn manifest(&self, header: &str) -> Result<Vec<u8>> {
        self.0.manifest(header)
    }
}
impl RecordData {
    pub fn plan(&self) -> &Plan {
        &self.initialization_approval.plan
    }
    pub fn activation_id(&self) -> Option<&str> {
        self.owner.as_ref().map(|o| o.activation_id.as_str())
    }
    /// Public metadata, independently derived by the guest before the barrier.
    pub fn manifest(&self, header: &str) -> Result<Vec<u8>> {
        if !digest(header) {
            return Err(Error::Binding);
        }
        let p = self.plan();
        canonical(
            &json!({"schemaVersion":1,"volumeId":self.volume_id,"generation":self.generation,"profileSha256":self.profile_sha256,
            "credentialUri":self.credential_uri,"luksUuid":p.luks_uuid,"deviceBytes":p.device_bytes,"headerSha256":header,
            "headerBytes":p.header_bytes,"dataOffsetBytes":p.data_offset_bytes,"filesystem":p.filesystem}),
        )
    }
    fn check(&self, request: &Request, session: &str, identity: &str) -> Result<()> {
        let e = &request.expected;
        let p = self.plan();
        if self.volume_id != e.volume_id
            || self.generation != e.generation
            || self.policy_sha256 != e.policy_sha256
            || self.profile_sha256 != e.profile_sha256
            || self.mount_binding != binding(e)
            || self.initialization_approval.plan_sha256 != request.plan_sha256
            || p.schema_version != 1
            || !p.new_volume
            || !uuid(&p.provisioning_id)
            || !uuid(&p.luks_uuid)
            || p.device_bytes < 64 * 1024 * 1024
            || p.device_bytes >= 1u64 << 63
            || !p.device_bytes.is_multiple_of(4096)
            || p.header_bytes != 16777216
            || p.data_offset_bytes != 16777216
            || p.filesystem != "ext4"
        {
            return Err(Error::Binding);
        }
        // A completed disk retains its original formatting intent after an
        // administrator upgrades the active workload. Both identities arrive
        // in the signed, request-bound authority response. Never allow this
        // distinction to authorize formatting an uninitialized disk.
        let initialization_policy = match &self.initialization_policy_sha256 {
            Some(policy) if self.state == State::Ready && digest(policy) => policy,
            Some(_) => return Err(Error::Binding),
            None => &self.policy_sha256,
        };
        let intent = json!({"plan":p,"volume_id":self.volume_id,"generation":self.generation,"policy_sha256":initialization_policy,
            "profile_sha256":self.profile_sha256,"credential_uri":self.credential_uri,"mount_binding":self.mount_binding});
        if sha(&canonical(&intent)?) != request.plan_sha256 {
            return Err(Error::Binding);
        }
        if let Some(o) = &self.owner {
            owner(o, request, session, identity, None)?;
        }
        if (self.state == State::Uninitialized
            && (self.owner.is_some() || !self.initialization_steps.is_empty()))
            || (self.state == State::Initializing && self.owner.is_none())
            || self.initialization_steps.len() > 4
        {
            return Err(Error::Binding);
        }
        let mut header = None;
        for (i, s) in self.initialization_steps.iter().enumerate() {
            s.check(STEPS[i])?;
            if s.status == Status::Started && i + 1 != self.initialization_steps.len() {
                return Err(Error::Binding);
            }
            if let Some(r) = &s.result {
                if header.as_ref().is_some_and(|h| h != &r.header_sha256) {
                    return Err(Error::Binding);
                }
                header = Some(r.header_sha256.clone());
            }
        }
        if self.state == State::Ready {
            if self.initialization_steps.len() != 4
                || self
                    .initialization_steps
                    .iter()
                    .any(|s| s.status != Status::Complete)
            {
                return Err(Error::Binding);
            }
            let raw = self.manifest(header.as_deref().ok_or(Error::Binding)?)?;
            if self.manifest.as_deref().map(str::as_bytes) != Some(raw.as_slice())
                || self.initialization_steps[3]
                    .result
                    .as_ref()
                    .and_then(|r| r.manifest_sha256.as_ref())
                    != Some(&sha(&raw))
            {
                return Err(Error::Binding);
            }
        } else if self.manifest.is_some() {
            return Err(Error::Binding);
        }
        Ok(())
    }
}
impl JournalStep {
    fn check(&self, expected: Step) -> Result<()> {
        if self.step != expected || !uuid(&self.step_id) {
            return Err(Error::Binding);
        }
        match self.status {
            Status::Started if self.result.is_none() && self.evidence_sha256.is_none() => Ok(()),
            Status::Complete if self.evidence_sha256.as_ref().is_some_and(|s| digest(s)) => {
                self.result.as_ref().ok_or(Error::Binding)?.check(self.step)
            }
            _ => Err(Error::Binding),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordResult {
    record: RecordData,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BeginResult {
    action: String,
    record: RecordData,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StepResult {
    decision: String,
    volume_id: String,
    generation: u64,
    owner: Owner,
    plan_sha256: String,
    step: Step,
    step_id: String,
    status: Status,
    result: Option<Completion>,
    evidence_sha256: Option<String>,
}

pub enum Decision {
    Plan(Record),
    Begin { fresh: bool, record: Record },
    Step(StepDecision),
    Completed,
    Ready(Record),
}
pub enum StepDecision {
    Execute(ExecutePermit),
    Reconcile,
    Complete,
}
/// Neither Clone nor Deserialize. Consuming it checks its admission deadline.
/// Re-requesting a Started step yields Reconcile, not a replacement permit.
pub struct ExecutePermit {
    activation_id: String,
    step_id: String,
    step: Step,
    expires: u64,
}
pub struct Execution {
    activation_id: String,
    step_id: String,
    step: Step,
}
impl Execution {
    pub fn activation_id(&self) -> &str {
        &self.activation_id
    }
    pub fn step_id(&self) -> &str {
        &self.step_id
    }
    pub fn step(&self) -> Step {
        self.step
    }
}
impl ExecutePermit {
    pub fn consume(self) -> Result<Execution> {
        if now()? >= self.expires {
            return Err(Error::Binding);
        }
        Ok(Execution {
            activation_id: self.activation_id,
            step_id: self.step_id,
            step: self.step,
        })
    }
}

impl<E: Evidence> AuthorityClient<E> {
    pub fn initialization(&self, request: &Request, operation: Operation) -> Result<Decision> {
        let e = &request.expected;
        if e.session_sha256 != self.session
            || e.policy_sha256 != self.config.policy_sha256
            || !confidential_storage_guest::profile::supports_binding(
                &e.profile_sha256,
                &e.destination,
            )
            || e.access != "rw"
            || !digest(&e.nonce)
            || !digest(&request.plan_sha256)
        {
            return Err(Error::Binding);
        }
        let mut body = json!({"volume_id":e.volume_id,"operation_id":e.operation_id,"generation":e.generation,
            "nonce":e.nonce,"profile_sha256":e.profile_sha256,"plan_sha256":request.plan_sha256,"binding":binding(e)});
        let identity = sha(&canonical(&body)?);
        let action = match &operation {
            Operation::Plan => "initialization-plan",
            Operation::Begin => "initialization-begin",
            Operation::Step {
                activation_id,
                step,
            } => {
                body["activation_id"] = json!(activation_id);
                body["step"] = json!(step);
                "initialization-step"
            }
            Operation::Complete {
                activation_id,
                step,
                step_id,
                result,
                evidence_sha256,
            } => {
                result.check(*step)?;
                body["activation_id"] = json!(activation_id);
                body["step"] = json!(step);
                body["step_id"] = json!(step_id);
                body["result"] = json!(result);
                body["evidence_sha256"] = json!(evidence_sha256);
                "initialization-complete"
            }
            Operation::Ready {
                activation_id,
                header_sha256,
            } => {
                body["activation_id"] = json!(activation_id);
                body["header_sha256"] = json!(header_sha256);
                "initialization-ready"
            }
        };
        body["action"] = json!(action);
        let raw = canonical(&body)?;
        let (wire, challenge): (Wire, _) = self.exchange(&raw)?;
        let claims = verify(
            &wire.decision,
            &self.config.receipt_public_key,
            &self.config.receipt_issuer,
            &self.config.receipt_key_id,
        )
        .map_err(|e| {
            eprintln!("STORAGE_INITIALIZATION receipt_rejected");
            e
        })?;
        if claims.session_sha256 != self.session
            || claims.policy_sha256 != self.config.policy_sha256
            || claims.action != action
            || claims.challenge != challenge.nonce
            || claims.request_sha256 != sha(&raw)
        {
            eprintln!("STORAGE_INITIALIZATION request_binding_rejected");
            return Err(Error::Binding);
        }
        let parse = |raw: &str| {
            serde_json::from_str::<RecordResult>(raw).map_err(|_| {
                eprintln!("STORAGE_INITIALIZATION record_schema_rejected");
                Error::Binding
            })
        };
        match operation {
            Operation::Plan => {
                let r = parse(claims.result.get())?.record;
                r.check(request, &self.session, &identity).map_err(|e| {
                    eprintln!("STORAGE_INITIALIZATION record_binding_rejected");
                    e
                })?;
                Ok(Decision::Plan(Record(r, claims.exp)))
            }
            Operation::Begin => {
                let r: BeginResult =
                    serde_json::from_str(claims.result.get()).map_err(|_| Error::Binding)?;
                r.record.check(request, &self.session, &identity)?;
                let fresh = r.action == "plan-initialization";
                if r.record.owner.is_none()
                    || !matches!(
                        (r.action.as_str(), &r.record.state),
                        (
                            "plan-initialization" | "resume-initialization",
                            State::Initializing
                        ) | ("open", State::Ready)
                    )
                {
                    return Err(Error::Binding);
                }
                Ok(Decision::Begin {
                    fresh,
                    record: Record(r.record, claims.exp),
                })
            }
            Operation::Step {
                activation_id,
                step,
            } => {
                let r: StepResult =
                    serde_json::from_str(claims.result.get()).map_err(|_| Error::Binding)?;
                owner(
                    &r.owner,
                    request,
                    &self.session,
                    &identity,
                    Some(&activation_id),
                )?;
                if r.volume_id != e.volume_id
                    || r.generation != e.generation
                    || r.plan_sha256 != request.plan_sha256
                {
                    return Err(Error::Binding);
                }
                let journal = JournalStep {
                    step: r.step,
                    step_id: r.step_id,
                    status: r.status,
                    result: r.result,
                    evidence_sha256: r.evidence_sha256,
                };
                journal.check(step)?;
                let result = match (r.decision.as_str(), journal.status) {
                    ("execute", Status::Started) => StepDecision::Execute(ExecutePermit {
                        activation_id,
                        step_id: journal.step_id,
                        step,
                        expires: claims.exp,
                    }),
                    ("reconcile", Status::Started) => StepDecision::Reconcile,
                    ("complete", Status::Complete) => StepDecision::Complete,
                    _ => return Err(Error::Binding),
                };
                Ok(Decision::Step(result))
            }
            Operation::Complete {
                step,
                step_id,
                result,
                evidence_sha256,
                ..
            } => {
                let r: JournalStep =
                    serde_json::from_str(claims.result.get()).map_err(|_| Error::Binding)?;
                r.check(step)?;
                if r.step_id != step_id
                    || r.status != Status::Complete
                    || r.result.as_ref() != Some(&result)
                    || r.evidence_sha256.as_ref() != Some(&evidence_sha256)
                {
                    return Err(Error::Binding);
                }
                Ok(Decision::Completed)
            }
            Operation::Ready {
                activation_id,
                header_sha256,
            } => {
                let r = parse(claims.result.get())?.record;
                r.check(request, &self.session, &identity)?;
                if r.state != State::Ready
                    || r.activation_id() != Some(activation_id.as_str())
                    || r.initialization_steps[0]
                        .result
                        .as_ref()
                        .unwrap()
                        .header_sha256
                        != header_sha256
                {
                    return Err(Error::Binding);
                }
                Ok(Decision::Ready(Record(r, claims.exp)))
            }
        }
    }
    /// Fetch fresh approved metadata for an already owned initialization. This
    /// permits key retrieval, never formatting; disk effects need a Step permit.
    pub fn authorize_initialization_key(
        &self,
        request: &Request,
    ) -> Result<crate::keys::KeyPermit> {
        let Decision::Plan(record) = self.initialization(request, Operation::Plan)? else {
            return Err(Error::Binding);
        };
        if record.0.state != State::Initializing || record.0.owner.is_none() {
            return Err(Error::Binding);
        }
        crate::keys::KeyPermit::new(
            self.session.clone(),
            self.config.policy_sha256.clone(),
            record.0.credential_uri,
            record.1,
        )
    }
    /// Only after initialization's mappings are proven closed. Ready metadata is
    /// not a reopen grant and cannot be fed to the filesystem opener.
    pub fn close_initialization(&self, record: &Record) -> Result<()> {
        let record = &record.0;
        let o = record.owner.as_ref().ok_or(Error::Binding)?;
        if record.state != State::Ready
            || o.session_sha256 != self.session
            || record.policy_sha256 != self.config.policy_sha256
        {
            return Err(Error::Binding);
        }
        let result: crate::Closed = self.execute(&canonical(
            &json!({"action":"close","volume_id":record.volume_id,"activation_id":o.activation_id}),
        )?)?;
        if !result.closed || result.activation_id != o.activation_id {
            return Err(Error::Binding);
        }
        Ok(())
    }
}
fn owner(
    o: &Owner,
    r: &Request,
    session: &str,
    identity: &str,
    activation: Option<&str>,
) -> Result<()> {
    if o.session_sha256 != session
        || o.operation != "initialize"
        || o.operation_id != r.expected.operation_id
        || o.request_sha256 != identity
        || !uuid(&o.activation_id)
        || activation.is_some_and(|a| a != o.activation_id)
    {
        return Err(Error::Binding);
    }
    Ok(())
}
fn binding(e: &Expected) -> Binding {
    Binding {
        manifest_uri: e.manifest_uri.clone(),
        container_name: e.container_name.clone(),
        destination: e.destination.clone(),
        access: e.access.clone(),
    }
}
fn uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                crate::hex(b)
            }
        })
}
fn decode(s: &str) -> Result<Vec<u8>> {
    let b = B64.decode(s).map_err(|_| Error::Binding)?;
    if B64.encode(&b) != s {
        return Err(Error::Binding);
    }
    Ok(b)
}
fn verify(token: &str, key: &[u8; 32], issuer: &str, kid: &str) -> Result<Claims> {
    if token.len() > 32768 {
        return Err(Error::Binding);
    }
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 || parts[0].len() > 2048 {
        return Err(Error::Binding);
    }
    let header: Header = serde_json::from_slice(&decode(parts[0])?).map_err(|_| Error::Binding)?;
    if header.alg != "Ed25519"
        || header.typ != "confidential-storage-initialization+jwt"
        || header.kid != kid
    {
        eprintln!("STORAGE_INITIALIZATION receipt_header_rejected");
        return Err(Error::Binding);
    }
    let signed = format!("{}.{}", parts[0], parts[1]);
    UnparsedPublicKey::new(&ED25519, key)
        .verify(signed.as_bytes(), &decode(parts[2])?)
        .map_err(|_| {
            eprintln!("STORAGE_INITIALIZATION receipt_signature_rejected");
            Error::Binding
        })?;
    let c: Claims = serde_json::from_slice(&decode(parts[1])?).map_err(|_| Error::Binding)?;
    let mut clock = now()?;
    // A fast local request may cross a whole-second boundary while the freshly
    // booted guest clock trails the authority. Do not widen token validity:
    // wait at most two seconds, then re-read the clock and apply strict checks.
    if c.iat > clock && c.iat - clock <= 2 && c.exp > c.iat && c.exp - c.iat <= 60 {
        eprintln!("STORAGE_INITIALIZATION receipt_clock_wait");
        std::thread::sleep(std::time::Duration::from_secs(c.iat - clock));
        clock = now()?;
    }
    if c.schema_version != 1
        || c.iss != issuer
        || c.aud != "confidential-storage-guest/v1"
        || c.iat > clock
        || c.exp <= clock
        || c.exp.saturating_sub(c.iat) > 60
    {
        eprintln!("STORAGE_INITIALIZATION receipt_time_or_identity_rejected");
        return Err(Error::Binding);
    }
    Ok(c)
}

#[cfg(test)]
mod policy_upgrade_tests {
    use super::*;
    fn fixture() -> (RecordData, Request) {
        let record: RecordData =
            serde_json::from_str(include_str!("../fixtures/ready-policy-upgrade.json")).unwrap();
        let request = Request {
            expected: Expected {
                volume_id: record.volume_id.clone(),
                generation: record.generation,
                policy_sha256: record.policy_sha256.clone(),
                profile_sha256: record.profile_sha256.clone(),
                session_sha256: "1".repeat(64),
                operation_id: "reopen-1".into(),
                nonce: "2".repeat(64),
                manifest_uri: record.mount_binding.manifest_uri.clone(),
                container_name: record.mount_binding.container_name.clone(),
                destination: record.mount_binding.destination.clone(),
                access: "rw".into(),
            },
            plan_sha256: record.initialization_approval.plan_sha256.clone(),
        };
        (record, request)
    }
    #[test]
    fn completed_journal_retains_original_approval_after_workload_upgrade() {
        let (record, request) = fixture();
        record
            .check(&request, &"1".repeat(64), &"2".repeat(64))
            .unwrap();
    }
    #[test]
    fn original_policy_cannot_replace_active_policy_or_approve_new_format() {
        let (mut record, mut request) = fixture();
        request.expected.policy_sha256 = "a".repeat(64);
        assert!(record
            .check(&request, &"1".repeat(64), &"2".repeat(64))
            .is_err());
        request.expected.policy_sha256 = "f".repeat(64);
        record.state = State::Uninitialized;
        record.initialization_steps.clear();
        record.manifest = None;
        assert!(record
            .check(&request, &"1".repeat(64), &"2".repeat(64))
            .is_err());
    }
    #[test]
    fn altered_initial_policy_or_incomplete_journal_is_rejected() {
        let (mut record, request) = fixture();
        record.initialization_policy_sha256 = Some("9".repeat(64));
        assert!(record
            .check(&request, &"1".repeat(64), &"2".repeat(64))
            .is_err());
        record.initialization_policy_sha256 = Some("a".repeat(64));
        record.initialization_steps.pop();
        assert!(record
            .check(&request, &"1".repeat(64), &"2".repeat(64))
            .is_err());
    }
}

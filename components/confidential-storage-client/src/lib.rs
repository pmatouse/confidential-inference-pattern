// SPDX-License-Identifier: Apache-2.0
//! Trusted guest-only authority client. No host RPC, storage effects or key API.
//! The caller supplies measured configuration and retains operation/nonce context.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use confidential_storage_guest::receipt::{Expected, VerifiedGrant, Verifier};
use reqwest::{blocking::Client, header, redirect, tls, Certificate, Url};
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING},
};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use std::{
    io::Read,
    net::SocketAddr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub mod initialization;
pub mod keys;
#[cfg(target_os = "linux")]
pub mod private_aa;
#[cfg(all(target_os = "linux", feature = "private-rcar-aa"))]
mod private_rcar_aa;
const PROTOCOL: &str = "confidential-storage-request/v1";
const MAX_REQUEST: usize = 8192;
const MAX_RESPONSE: usize = 280 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid measured authority configuration")]
    Configuration,
    #[error("authority transport or response rejected")]
    Transport,
    #[error("authority request or receipt binding rejected")]
    Binding,
    #[error("private guest attestation failed")]
    Attestation,
    #[error("signed storage receipt rejected: {0}")]
    Receipt(#[source] confidential_storage_guest::receipt::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

/// Implementations run inside the measured guest service. Applications must not
/// be able to call this trait or choose its runtime data. No public-AA fallback.
pub trait Evidence {
    /// SNP report_data contains this SHA-256 padded to 64 bytes, not double-hashed.
    fn collect(&self, runtime_sha256: [u8; 32]) -> Result<Vec<u8>>;
    /// Composite evidence using standard KBS SHA-384 runtime binding. Providers
    /// without this capability fail closed; never fall back to CPU-only quotes.
    fn collect_rcar(&self, _nonce: &str, _key: &Value) -> Result<Vec<u8>> {
        Err(Error::Attestation)
    }
}

/// Pin only this dedicated TLS CA, AS configuration binding and receipt signer.
/// The audience is the exact HTTPS origin + /v1. Optional static resolution is
/// trusted configuration; TLS still verifies the URL hostname, never the IP alias.
pub struct Config {
    pub audience: String,
    pub certificate_der: Vec<u8>,
    pub address: Option<SocketAddr>,
    pub policy_sha256: String,
    pub init_data: String,
    pub receipt_public_key: [u8; 32],
    pub receipt_issuer: String,
    pub receipt_key_id: String,
}

pub struct AuthorityClient<E: Evidence> {
    http: Client,
    config: Config,
    key: EcdsaKeyPair,
    public_key: Value,
    session: String,
    evidence: E,
    trustee_rcar: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    audience: String,
    nonce: String,
    request_sha256: String,
    expires_in: u64,
    #[serde(default)]
    attestation: Option<RcarChallenge>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RcarChallenge {
    kind: String,
    nonce: String,
    hash_algorithm: String,
}
fn rcar_nonce(nonce: &str) -> bool {
    use base64::engine::general_purpose::STANDARD;
    nonce.len() == 44
        && STANDARD
            .decode(nonce)
            .is_ok_and(|v| v.len() == 32 && STANDARD.encode(v) == nonce)
}
fn select_challenge(mode: bool, challenge: &Option<RcarChallenge>) -> Result<Option<&str>> {
    match (mode, challenge) {
        (false, None) => Ok(None),
        (true, Some(c))
            if c.kind == "trustee-rcar-v1"
                && c.hash_algorithm == "sha384"
                && rcar_nonce(&c.nonce) =>
        {
            Ok(Some(&c.nonce))
        }
        _ => Err(Error::Binding),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Attested {
    token: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reopened {
    receipt: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Closed {
    closed: bool,
    activation_id: String,
}

impl<E: Evidence> AuthorityClient<E> {
    /// Select explicitly in measured configuration, never from a server hint.
    pub fn new_rcar(config: Config, evidence: E) -> Result<Self> {
        let mut client = Self::new(config, evidence)?;
        client.trustee_rcar = true;
        Ok(client)
    }
    pub fn new(config: Config, evidence: E) -> Result<Self> {
        let url = Url::parse(&config.audience).map_err(|_| Error::Configuration)?;
        if !config.audience.is_ascii()
            || url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/v1"
            || url.as_str() != config.audience
            || !digest(&config.policy_sha256)
            || ![64, 96, 128].contains(&config.init_data.len())
            || !config.init_data.bytes().all(hex)
            || config.receipt_issuer.is_empty()
            || config.receipt_key_id.is_empty()
            || config.certificate_der.len() > 16384
        {
            return Err(Error::Configuration);
        }
        let certificate =
            Certificate::from_der(&config.certificate_der).map_err(|_| Error::Configuration)?;
        let mut builder = Client::builder()
            .tls_certs_only([certificate])
            .min_tls_version(tls::Version::TLS_1_3)
            .max_tls_version(tls::Version::TLS_1_3)
            .https_only(true)
            .http1_only()
            .no_proxy()
            .redirect(redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10));
        if let Some(address) = config.address {
            builder = builder.resolve(url.host_str().unwrap(), address);
        }
        let http = builder.build().map_err(|_| Error::Configuration)?;
        let random = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random)
            .map_err(|_| Error::Attestation)?;
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &random)
                .map_err(|_| Error::Attestation)?;
        let point = key.public_key().as_ref();
        if point.len() != 65 || point[0] != 4 {
            return Err(Error::Attestation);
        }
        let public_key = json!({"kty":"EC","crv":"P-256","x":B64.encode(&point[1..33]),"y":B64.encode(&point[33..])});
        let session = sha(&canonical(
            &json!({"protocol":PROTOCOL,"audience":config.audience,"key":public_key,"policy_sha256":config.policy_sha256,"init_data":config.init_data}),
        )?);
        Ok(Self {
            http,
            config,
            key,
            public_key,
            session,
            evidence,
            trustee_rcar: false,
        })
    }
    pub fn policy_sha256(&self) -> &str {
        &self.config.policy_sha256
    }
    pub fn init_data_digest(&self) -> &str {
        &self.config.init_data
    }
    pub fn session_sha256(&self) -> &str {
        &self.session
    }
    /// No automatic retry: the caller must retain this exact request and nonce
    /// after an ambiguous response. A new client/key does not recover old ownership.
    pub fn reopen(&self, expected: &Expected) -> Result<VerifiedGrant> {
        if expected.session_sha256 != self.session
            || expected.policy_sha256 != self.config.policy_sha256
        {
            return Err(Error::Binding);
        }
        let request = canonical(
            &json!({"action":"reopen","volume_id":expected.volume_id,"operation_id":expected.operation_id,
            "generation":expected.generation,"nonce":expected.nonce,"profile_sha256":expected.profile_sha256,
            "binding":{"manifest_uri":expected.manifest_uri,"container_name":expected.container_name,"destination":expected.destination,"access":expected.access}}),
        )?;
        let response: Reopened = self.execute(&request)?;
        let verifier = Verifier::new(
            self.config.receipt_public_key,
            self.config.receipt_issuer.clone(),
            self.config.receipt_key_id.clone(),
        );
        // A guest RTC can lag the authority across a one-second boundary.
        // Never accept a future receipt or extend expiry. Wait only after all
        // signature/shape/binding checks passed, then reverify the same receipt.
        // A monotonic deadline bounds this even if the wall clock moves back.
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match verifier.verify(&response.receipt, expected, now()?) {
                Err(confidential_storage_guest::receipt::Error::NotYetValid)
                    if Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(25));
                }
                result => return result.map_err(Error::Receipt),
            }
        }
    }
    /// Only call after proven application quiescence and all owned mounts/mappers
    /// are gone. The client cannot observe storage teardown itself.
    pub fn close(&self, grant: &VerifiedGrant) -> Result<()> {
        let c = grant.claims();
        if c.session_sha256 != self.session || c.policy_sha256 != self.config.policy_sha256 {
            return Err(Error::Binding);
        }
        let response: Closed = self.execute(&canonical(
            &json!({"action":"close","volume_id":c.volume_id,"activation_id":c.activation_id}),
        )?)?;
        if !response.closed || response.activation_id != c.activation_id {
            return Err(Error::Binding);
        }
        Ok(())
    }
    fn execute<T: DeserializeOwned>(&self, request: &[u8]) -> Result<T> {
        Ok(self.exchange(request)?.0)
    }
    fn exchange<T: DeserializeOwned>(&self, request: &[u8]) -> Result<(T, Challenge)> {
        if request.is_empty() || request.len() > MAX_REQUEST {
            return Err(Error::Binding);
        }
        let challenge: Challenge = self.post("challenge", request)?;
        let request_hash = sha(request);
        if challenge.audience != self.config.audience
            || challenge.request_sha256 != request_hash
            || !digest(&challenge.nonce)
            || challenge.expires_in != 60
        {
            return Err(Error::Binding);
        }
        let evidence = match select_challenge(self.trustee_rcar, &challenge.attestation)? {
            None => {
                let runtime = canonical(
                    &json!({"storage-binding":{"protocol":PROTOCOL,"audience":self.config.audience,
                    "nonce":challenge.nonce,"request_sha256":request_hash,"key":self.public_key}}),
                )?;
                self.evidence.collect(
                    ring::digest::digest(&ring::digest::SHA256, &runtime)
                        .as_ref()
                        .try_into()
                        .unwrap(),
                )?
            }
            Some(nonce) => self.evidence.collect_rcar(nonce, &self.public_key)?,
        };
        if evidence.is_empty() || evidence.len() > 144 * 1024 {
            return Err(Error::Attestation);
        }
        let response: Attested = self.post("attest", &canonical(&json!({"nonce":challenge.nonce,"key":self.public_key,"evidence":B64.encode(evidence)}))?)?;
        if response.token.is_empty()
            || response.token.len() > 256 * 1024
            || !response.token.is_ascii()
        {
            return Err(Error::Attestation);
        }
        let message = canonical(
            &json!({"protocol":PROTOCOL,"audience":self.config.audience,"nonce":challenge.nonce,
            "request_sha256":request_hash,"attestation_sha256":sha(response.token.as_bytes())}),
        )?;
        let proof = self
            .key
            .sign(&SystemRandom::new(), &message)
            .map_err(|_| Error::Attestation)?;
        let result = self.post("execute", &canonical(&json!({"nonce":challenge.nonce,"request":B64.encode(request),"token":response.token,"proof":B64.encode(proof.as_ref())}))?)?;
        Ok((result, challenge))
    }
    fn post<T: DeserializeOwned>(&self, route: &str, body: &[u8]) -> Result<T> {
        let response = self
            .http
            .post(format!("{}/{route}", self.config.audience))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .body(body.to_vec())
            .send()
            .map_err(|_| Error::Transport)?;
        if response.status() != reqwest::StatusCode::OK
            || response
                .content_length()
                .is_none_or(|n| n == 0 || n > MAX_RESPONSE as u64)
            || response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                != Some("application/json")
            || response.headers().contains_key(header::CONTENT_ENCODING)
            || response.headers().contains_key(header::TRANSFER_ENCODING)
        {
            return Err(Error::Transport);
        }
        let length = response.content_length().unwrap() as usize;
        let mut data = Vec::new();
        response
            .take((MAX_RESPONSE + 1) as u64)
            .read_to_end(&mut data)
            .map_err(|_| Error::Transport)?;
        if data.len() != length {
            return Err(Error::Transport);
        }
        serde_json::from_slice(&data).map_err(|_| Error::Transport)
    }
}
fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Binding)?
        .as_secs())
}
fn canonical(value: &Value) -> Result<Vec<u8>> {
    // Explicit sorting survives workspace feature unification enabling
    // serde_json/preserve_order. Runtime/session hashes must match Trustee.
    fn write(value: &Value, out: &mut Vec<u8>) -> Result<()> {
        match value {
            Value::Object(map) => {
                out.push(b'{');
                let sorted: std::collections::BTreeMap<_, _> = map.iter().collect();
                for (index, (key, value)) in sorted.into_iter().enumerate() {
                    if index != 0 {
                        out.push(b',');
                    }
                    out.extend(serde_json::to_vec(key).map_err(|_| Error::Binding)?);
                    out.push(b':');
                    write(value, out)?;
                }
                out.push(b'}');
            }
            Value::Array(values) => {
                out.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        out.push(b',');
                    }
                    write(value, out)?;
                }
                out.push(b']');
            }
            _ => out.extend(serde_json::to_vec(value).map_err(|_| Error::Binding)?),
        }
        Ok(())
    }
    let mut out = Vec::new();
    write(value, &mut out)?;
    Ok(out)
}
fn hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}
fn digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(hex)
}
fn sha(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mode_is_explicit_and_cannot_fall_back_or_negotiate_weaker_hashes() {
        assert!(select_challenge(false, &None).unwrap().is_none());
        assert!(select_challenge(true, &None).is_err());
        let mut c = Some(RcarChallenge {
            kind: "trustee-rcar-v1".into(),
            hash_algorithm: "sha384".into(),
            nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        });
        assert!(select_challenge(true, &c).unwrap().is_some());
        assert!(select_challenge(false, &c).is_err());
        c.as_mut().unwrap().hash_algorithm = "sha256".into();
        assert!(select_challenge(true, &c).is_err());
        c.as_mut().unwrap().hash_algorithm = "sha384".into();
        c.as_mut().unwrap().nonce = "replayed".into();
        assert!(select_challenge(true, &c).is_err());
    }
    #[test]
    fn runtime_canonicalization_is_recursive_and_whitespace_free() {
        let v = json!({"z":[{"y":2,"a":"key"}],"a":true});
        assert_eq!(
            canonical(&v).unwrap(),
            br#"{"a":true,"z":[{"a":"key","y":2}]}"#
        );
    }
}

// SPDX-License-Identifier: Apache-2.0
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid signed storage receipt")]
    Invalid,
    #[error("storage receipt does not match guest request")]
    Binding,
    #[error("storage receipt is expired or not yet valid")]
    Freshness,
    #[error("authenticated storage receipt is not yet valid")]
    NotYetValid,
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expected {
    pub volume_id: String,
    pub generation: u64,
    pub policy_sha256: String,
    pub profile_sha256: String,
    pub session_sha256: String,
    pub operation_id: String,
    pub nonce: String,
    pub manifest_uri: String,
    pub container_name: String,
    pub destination: String,
    pub access: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub schema_version: u32,
    pub iss: String,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    pub volume_id: String,
    pub generation: u64,
    pub policy_sha256: String,
    pub profile_sha256: String,
    pub manifest_sha256: String,
    pub header_sha256: String,
    pub credential_uri: String,
    pub session_sha256: String,
    pub operation_id: String,
    pub operation: String,
    pub nonce: String,
    pub activation_id: String,
    pub manifest_uri: String,
    pub container_name: String,
    pub destination: String,
    pub access: String,
}

/// Construction is restricted to signature and binding verification. This
/// receipt is not a substitute for Trustee verifying the guest's attestation.
#[derive(Clone, Debug)]
pub struct VerifiedGrant(Claims);
impl VerifiedGrant {
    pub fn claims(&self) -> &Claims {
        &self.0
    }
    pub fn check_time(&self, now: u64) -> Result<()> {
        if now < self.0.iat {
            return Err(Error::NotYetValid);
        }
        if now >= self.0.exp {
            return Err(Error::Freshness);
        }
        Ok(())
    }
    /// Check the exact authenticated bytes before a backend parses a manifest.
    pub fn authenticate_manifest<'a>(&self, bytes: &'a [u8]) -> Result<AuthenticatedBytes<'a>> {
        authenticate(bytes, &self.0.manifest_sha256, 64 * 1024)
    }
    /// Authenticate the copied header; the backend must pass this same copy to
    /// cryptsetup. A hash does not itself validate the crypto/integrity profile.
    pub fn authenticate_header<'a>(&self, bytes: &'a [u8]) -> Result<AuthenticatedBytes<'a>> {
        authenticate(bytes, &self.0.header_sha256, 64 * 1024 * 1024)
    }
    pub(crate) fn same_activation(&self, other: &Self) -> bool {
        let mut a = self.0.clone();
        let mut b = other.0.clone();
        // A retry may obtain a newly signed receipt for the same durable owner.
        a.iat = 0;
        a.exp = 0;
        b.iat = 0;
        b.exp = 0;
        a == b
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

pub struct Verifier {
    key: [u8; 32],
    issuer: String,
    key_id: String,
}
impl Verifier {
    /// Values come from guest measured configuration, never JWS jwk/jku/x5u.
    pub fn new(key: [u8; 32], issuer: String, key_id: String) -> Self {
        Self {
            key,
            issuer,
            key_id,
        }
    }
    pub fn verify(&self, token: &str, expected: &Expected, now: u64) -> Result<VerifiedGrant> {
        if token.len() > 16384 {
            return Err(Error::Invalid);
        }
        let parts: Vec<_> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::Invalid);
        }
        let header: Header =
            serde_json::from_slice(&decode(parts[0])?).map_err(|_| Error::Invalid)?;
        if header.alg != "Ed25519"
            || header.typ != "confidential-storage-grant+jwt"
            || header.kid != self.key_id
        {
            return Err(Error::Invalid);
        }
        let signed = format!("{}.{}", parts[0], parts[1]);
        UnparsedPublicKey::new(&ED25519, self.key)
            .verify(signed.as_bytes(), &decode(parts[2])?)
            .map_err(|_| Error::Invalid)?;
        let claims: Claims =
            serde_json::from_slice(&decode(parts[1])?).map_err(|_| Error::Invalid)?;
        if claims.schema_version != 1
            || claims.iss != self.issuer
            || claims.aud != "confidential-storage-guest/v1"
            || claims.operation != "reopen"
        {
            return Err(Error::Invalid);
        }
        if claims.exp <= claims.iat || claims.exp - claims.iat > 60 {
            return Err(Error::Freshness);
        }
        for value in [
            &claims.policy_sha256,
            &claims.profile_sha256,
            &claims.manifest_sha256,
            &claims.header_sha256,
            &claims.session_sha256,
            &claims.nonce,
        ] {
            if !hex_digest(value) {
                return Err(Error::Invalid);
            }
        }
        for value in [
            &claims.volume_id,
            &claims.operation_id,
            &claims.activation_id,
            &claims.container_name,
        ] {
            if !identifier(value) {
                return Err(Error::Invalid);
            }
        }
        if !kbs_uri(&claims.manifest_uri)
            || !kbs_uri(&claims.credential_uri)
            || claims.generation == 0
        {
            return Err(Error::Invalid);
        }
        if !matches!(claims.access.as_str(), "rw" | "ro")
            || !crate::binding::destination(&claims.destination)
        {
            return Err(Error::Invalid);
        }
        let actual = Expected {
            volume_id: claims.volume_id.clone(),
            generation: claims.generation,
            policy_sha256: claims.policy_sha256.clone(),
            profile_sha256: claims.profile_sha256.clone(),
            session_sha256: claims.session_sha256.clone(),
            operation_id: claims.operation_id.clone(),
            nonce: claims.nonce.clone(),
            manifest_uri: claims.manifest_uri.clone(),
            container_name: claims.container_name.clone(),
            destination: claims.destination.clone(),
            access: claims.access.clone(),
        };
        if actual != *expected {
            return Err(Error::Binding);
        }
        let verified = VerifiedGrant(claims);
        verified.check_time(now)?;
        Ok(verified)
    }
}
fn decode(value: &str) -> Result<Vec<u8>> {
    let bytes = B64.decode(value).map_err(|_| Error::Invalid)?;
    if B64.encode(&bytes) != value {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}
fn hex_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        && s != "."
        && s != ".."
}
fn kbs_uri(s: &str) -> bool {
    s.strip_prefix("kbs:///").is_some_and(|s| {
        let parts: Vec<_> = s.split('/').collect();
        parts.len() == 3 && parts.iter().all(|p| identifier(p))
    })
}

/// Bytes authenticated by an authority-pinned digest. No disk parser has run yet.
pub struct AuthenticatedBytes<'a>(&'a [u8]);
impl<'a> AuthenticatedBytes<'a> {
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}
fn authenticate<'a>(
    bytes: &'a [u8],
    expected: &str,
    limit: usize,
) -> Result<AuthenticatedBytes<'a>> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(Error::Invalid);
    }
    let hash = ring::digest::digest(&ring::digest::SHA256, bytes);
    let actual: String = hash.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    if actual != expected {
        return Err(Error::Binding);
    }
    Ok(AuthenticatedBytes(bytes))
}

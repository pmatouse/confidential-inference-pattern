// SPDX-License-Identifier: Apache-2.0
//! A deliberately narrow, versioned RW profile. Header acceptance is not proof
//! that dm-integrity is active: the eventual opener must inspect the kernel stack.
use crate::receipt::VerifiedGrant;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;

pub const PROFILE: &[u8] = include_bytes!("../profiles/rw-luks2-v1.json");
pub const PROFILE_V2: &[u8] = include_bytes!("../profiles/rw-luks2-v2.json");
pub fn supports_binding(digest: &str, destination: &str) -> bool {
    (digest == profile_sha256() && destination == "/data")
        || (digest == sha256(PROFILE_V2) && crate::binding::destination(destination))
}
pub fn filesystem_owner(digest: &str) -> Option<(u32, u32)> {
    if digest == profile_sha256() {
        Some((1000, 1000))
    } else if digest == sha256(PROFILE_V2) {
        Some((1001, 1001))
    } else {
        None
    }
}
pub const HEADER_BYTES: usize = 16 * 1024 * 1024;
const METADATA_BYTES: usize = 16384;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("manifest authentication or binding failed")]
    Manifest,
    #[error("unsupported authenticated storage profile")]
    Profile,
    #[error("header authentication failed")]
    Authentication,
    #[error("unsupported or inconsistent LUKS2 header")]
    Header,
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Manifest {
    schema_version: u32,
    volume_id: String,
    generation: u64,
    profile_sha256: String,
    credential_uri: String,
    luks_uuid: String,
    device_bytes: u64,
    header_sha256: String,
    header_bytes: u64,
    data_offset_bytes: u64,
    filesystem: String,
}
/// Constructed only by authenticating a manifest against a verified receipt.
/// Does not grant formatting permission or attest the supplied device length.
pub struct RwManifest(Manifest);
impl RwManifest {
    pub fn verify(grant: &VerifiedGrant, bytes: &[u8], device_bytes: u64) -> Result<Self> {
        let authenticated = grant
            .authenticate_manifest(bytes)
            .map_err(|_| Error::Manifest)?;
        let m: Manifest =
            serde_json::from_slice(authenticated.as_bytes()).map_err(|_| Error::Manifest)?;
        let c = grant.claims();
        if m.schema_version != 1
            || m.volume_id != c.volume_id
            || m.generation != c.generation
            || m.profile_sha256 != c.profile_sha256
            || m.credential_uri != c.credential_uri
            || m.header_sha256 != c.header_sha256
        {
            return Err(Error::Manifest);
        }
        if c.access != "rw"
            || !supports_binding(&m.profile_sha256, &c.destination)
            || m.filesystem != "ext4"
            || m.header_bytes != HEADER_BYTES as u64
            || m.data_offset_bytes != HEADER_BYTES as u64
            || m.device_bytes != device_bytes
            || device_bytes < 64 * 1024 * 1024
            || !device_bytes.is_multiple_of(4096)
            || !uuid(&m.luks_uuid)
        {
            return Err(Error::Profile);
        }
        Ok(Self(m))
    }
    pub fn credential_uri(&self) -> &str {
        &self.0.credential_uri
    }
    pub fn device_bytes(&self) -> u64 {
        self.0.device_bytes
    }
    pub fn luks_uuid(&self) -> &str {
        &self.0.luks_uuid
    }
    /// Authenticate the entire fixed header, including both metadata copies and
    /// keyslot area, BEFORE inspecting any binary fields or JSON. No recovery.
    pub(crate) fn validate_header(&self, grant: &VerifiedGrant, bytes: &[u8]) -> Result<()> {
        if grant.claims().header_sha256 != self.0.header_sha256 || bytes.len() != HEADER_BYTES {
            return Err(Error::Authentication);
        }
        let checked = grant
            .authenticate_header(bytes)
            .map_err(|_| Error::Authentication)?;
        validate_header(checked.as_bytes(), &self.0.luks_uuid)
    }
}
pub fn profile_sha256() -> String {
    sha256(PROFILE)
}
fn sha256(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect()
}
fn uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn cstring(bytes: &[u8], expected: &[u8]) -> bool {
    bytes.starts_with(expected) && bytes[expected.len()..].iter().all(|b| *b == 0)
}
pub(crate) fn validate_header(bytes: &[u8], uuid: &str) -> Result<()> {
    validate_header_as(bytes, uuid, false)
}
pub(crate) fn validate_ro_header(bytes: &[u8], uuid: &str) -> Result<()> {
    validate_header_as(bytes, uuid, true)
}
fn validate_header_as(bytes: &[u8], uuid: &str, readonly: bool) -> Result<()> {
    if bytes.len() != HEADER_BYTES {
        return Err(Error::Header);
    }
    for (offset, magic) in [(0usize, b"LUKS\xba\xbe"), (METADATA_BYTES, b"SKUL\xba\xbe")] {
        let h = &bytes[offset..offset + METADATA_BYTES];
        if &h[..6] != magic
            || h[6..8] != [0, 2]
            || h[8..16] != (METADATA_BYTES as u64).to_be_bytes()
            || h[256..264] != (offset as u64).to_be_bytes()
            || !cstring(&h[72..104], b"sha256")
            || !cstring(&h[168..208], uuid.as_bytes())
            || h[24..72]
                .iter()
                .chain(&h[208..256])
                .chain(&h[264..448])
                .chain(&h[480..4096])
                .any(|b| *b != 0)
        {
            return Err(Error::Header);
        }
        let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
        digest.update(&h[..448]);
        digest.update(&[0; 64]);
        digest.update(&h[512..]);
        if digest.finish().as_ref() != &h[448..480] {
            return Err(Error::Header);
        }
    }
    if bytes[16..24] == [0; 8]
        || bytes[16..24] != bytes[METADATA_BYTES + 16..METADATA_BYTES + 24]
        || bytes[4096..METADATA_BYTES] != bytes[METADATA_BYTES + 4096..METADATA_BYTES * 2]
    {
        return Err(Error::Header);
    }
    let padded = &bytes[4096..METADATA_BYTES];
    let end = padded.iter().position(|b| *b == 0).ok_or(Error::Header)?;
    if padded[end..].iter().any(|b| *b != 0) {
        return Err(Error::Header);
    }
    if readonly {
        validate_metadata_as(&padded[..end], true)
    } else {
        validate_metadata(&padded[..end])
    }
}

// A fixed slot "0" rejects extra slots AND duplicate JSON names. Generic maps
// and serde_json::Value would silently keep the last duplicate map entry.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Single<T> {
    #[serde(rename = "0")]
    item: T,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    keyslots: Single<Keyslot>,
    tokens: Empty,
    segments: Single<Segment>,
    digests: Single<Digest>,
    config: Config,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Keyslot {
    #[serde(rename = "type")]
    kind: String,
    key_size: u64,
    area: Area,
    kdf: Kdf,
    af: Af,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Area {
    #[serde(rename = "type")]
    kind: String,
    offset: String,
    size: String,
    encryption: String,
    key_size: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Kdf {
    #[serde(rename = "type")]
    kind: String,
    time: u64,
    memory: u64,
    cpus: u64,
    salt: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Af {
    #[serde(rename = "type")]
    kind: String,
    stripes: u64,
    hash: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Segment {
    #[serde(rename = "type")]
    kind: String,
    offset: String,
    size: String,
    iv_tweak: String,
    encryption: String,
    sector_size: u64,
    #[serde(default)]
    integrity: Option<Integrity>,
    #[serde(default)]
    flags: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Integrity {
    #[serde(rename = "type")]
    kind: String,
    journal_encryption: String,
    journal_integrity: String,
    #[serde(default = "default_integrity_key_size")]
    key_size: u64,
}
fn default_integrity_key_size() -> u64 {
    32
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Digest {
    #[serde(rename = "type")]
    kind: String,
    keyslots: Vec<String>,
    segments: Vec<String>,
    hash: String,
    iterations: u64,
    salt: String,
    digest: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    json_size: String,
    keyslots_size: String,
    #[serde(default)]
    flags: Vec<String>,
}
fn base64_32(s: &str) -> bool {
    B64.decode(s)
        .is_ok_and(|v| v.len() == 32 && B64.encode(v) == s)
}
fn validate_metadata(bytes: &[u8]) -> Result<()> {
    validate_metadata_as(bytes, false)
}
fn validate_metadata_as(bytes: &[u8], readonly: bool) -> Result<()> {
    let m: Metadata = serde_json::from_slice(bytes).map_err(|_| Error::Header)?;
    let _ = m.tokens;
    let k = m.keyslots.item;
    let s = m.segments.item;
    let d = m.digests.item;
    let c = m.config;
    match (&s.integrity, readonly) {
        (None, true) => {}
        (Some(i), false)
            if i.kind == "hmac(sha256)"
                && i.key_size == 32
                && i.journal_encryption == "none"
                && i.journal_integrity == "none" => {}
        _ => return Err(Error::Header),
    }
    if k.kind != "luks2"
        || k.key_size != if readonly { 64 } else { 96 }
        || k.area.kind != "raw"
        || k.area.offset != "32768"
        || k.area.size != if readonly { "258048" } else { "385024" }
        || k.area.encryption != "aes-xts-plain64"
        || k.area.key_size != 64
        || k.af.kind != "luks1"
        || k.af.stripes != 4000
        || k.af.hash != "sha256"
        || k.kdf.kind != "argon2id"
        || !(4..=10).contains(&k.kdf.time)
        || !(65536..=1048576).contains(&k.kdf.memory)
        || !(1..=4).contains(&k.kdf.cpus)
        || !base64_32(&k.kdf.salt)
        || s.kind != "crypt"
        || s.offset != "16777216"
        || s.size != "dynamic"
        || s.iv_tweak != "0"
        || s.encryption != "aes-xts-plain64"
        || s.sector_size != 4096
        || !s.flags.is_empty()
        || d.kind != "pbkdf2"
        || d.hash != "sha256"
        || d.keyslots != ["0"]
        || d.segments != ["0"]
        || !(1000..=10_000_000).contains(&d.iterations)
        || !base64_32(&d.salt)
        || !base64_32(&d.digest)
        || c.json_size != "12288"
        || c.keyslots_size != "16744448"
        || !c.flags.is_empty()
    {
        return Err(Error::Header);
    }
    Ok(())
}
#[cfg(test)]
mod tests;

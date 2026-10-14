// SPDX-License-Identifier: Apache-2.0
//! Authenticated immutable model geometry, before any key retrieval/disk effect.
use crate::{
    profile::{Error, Result, HEADER_BYTES},
    receipt::VerifiedGrant,
};
use serde::Deserialize;
use std::collections::BTreeSet;

pub const PROFILE: &[u8] = include_bytes!("../profiles/ro-luks2-verity-v1.json");
pub const PROFILE_V2: &[u8] = include_bytes!("../profiles/ro-luks2-verity-v2.json");
pub fn supports_binding(digest: &str, destination: &str) -> bool {
    (digest == profile_sha256() && destination == "/models")
        || (digest == sha256(PROFILE_V2) && crate::binding::destination(destination))
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
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
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
    verity: Verity,
    source: Source,
    files: Vec<ModelFile>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Source {
    repository: String,
    manifest_digest: String,
    disk_digest: String,
    disk_bytes: u64,
    format: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Verity {
    root: String,
    salt: String,
    hash_algorithm: String,
    hash_offset_bytes: u64,
    data_bytes: u64,
    block_bytes: u64,
}
impl Verity {
    pub fn root(&self) -> &str {
        &self.root
    }
    pub fn salt(&self) -> &str {
        &self.salt
    }
    pub fn hash_offset_bytes(&self) -> u64 {
        self.hash_offset_bytes
    }
    pub fn data_bytes(&self) -> u64 {
        self.data_bytes
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelFile {
    path: String,
    bytes: u64,
    sha256: String,
}

/// No formatting authority. Construction requires a valid fresh receipt first.
pub struct RoManifest(Manifest);
impl RoManifest {
    pub fn verify(grant: &VerifiedGrant, bytes: &[u8], device_bytes: u64) -> Result<Self> {
        let checked = grant
            .authenticate_manifest(bytes)
            .map_err(|_| Error::Manifest)?;
        let m: Manifest =
            serde_json::from_slice(checked.as_bytes()).map_err(|_| Error::Manifest)?;
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
        if c.access != "ro"
            || !supports_binding(&m.profile_sha256, &c.destination)
            || m.filesystem != "ext4"
            || m.header_bytes != HEADER_BYTES as u64
            || m.data_offset_bytes != HEADER_BYTES as u64
            || m.device_bytes != device_bytes
            || !(64 * 1024 * 1024..=64 * 1024 * 1024 * 1024).contains(&device_bytes)
            || !device_bytes.is_multiple_of(4096)
            || !uuid(&m.luks_uuid)
        {
            return Err(Error::Profile);
        }
        let v = &m.verity;
        if !digest(&v.root)
            || !digest(&v.salt)
            || v.hash_algorithm != "sha256"
            || v.block_bytes != 4096
            || v.data_bytes <= HEADER_BYTES as u64
            || v.data_bytes >= device_bytes
            || !v.data_bytes.is_multiple_of(4096)
            || v.hash_offset_bytes != v.data_bytes
        {
            return Err(Error::Profile);
        }
        let mut blocks = v.data_bytes / 4096;
        let mut tree_blocks = 0;
        while blocks > 1 {
            blocks = blocks.div_ceil(128);
            tree_blocks += blocks;
        }
        if v.hash_offset_bytes + tree_blocks * 4096 > device_bytes {
            return Err(Error::Profile);
        }
        let s = &m.source;
        if s.format != "luks-verity-v1"
            || s.disk_bytes != device_bytes
            || !oci_digest(&s.disk_digest)
            || !oci_digest(&s.manifest_digest)
            || !repository(&s.repository)
        {
            return Err(Error::Profile);
        }
        let mut paths = BTreeSet::new();
        let mut total = 0u64;
        if m.files.is_empty() || m.files.len() > 256 {
            return Err(Error::Profile);
        }
        for f in &m.files {
            if f.path.is_empty()
                || f.path.len() > 512
                || !f
                    .path
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
                || f.path.split('/').any(|s| matches!(s, "" | "." | ".."))
                || !paths.insert(&f.path)
                || !digest(&f.sha256)
                || f.bytes > device_bytes
            {
                return Err(Error::Profile);
            }
            total = total.checked_add(f.bytes).ok_or(Error::Profile)?;
        }
        if total > v.data_bytes - HEADER_BYTES as u64 {
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
    pub fn verity(&self) -> &Verity {
        &self.0.verity
    }
    pub fn validate_header(&self, grant: &VerifiedGrant, bytes: &[u8]) -> Result<()> {
        if grant.claims().header_sha256 != self.0.header_sha256 || bytes.len() != HEADER_BYTES {
            return Err(Error::Authentication);
        }
        let checked = grant
            .authenticate_header(bytes)
            .map_err(|_| Error::Authentication)?;
        crate::profile::validate_ro_header(checked.as_bytes(), &self.0.luks_uuid)
    }
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
fn oci_digest(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(digest)
}
fn repository(s: &str) -> bool {
    let Some((ns, name)) = s.split_once('/') else {
        return false;
    };
    let start = |v: &str| {
        v.as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
    };
    ns.len() <= 63
        && name.len() <= 128
        && start(ns)
        && start(name)
        && ns
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}
#[cfg(test)]
mod tests;

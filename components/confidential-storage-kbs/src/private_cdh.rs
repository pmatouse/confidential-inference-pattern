// SPDX-License-Identifier: Apache-2.0
//! Private adapter to the existing GPU guest's CDH; no new evidence collector.
//!
//! CDH/AA, its measured KBC configuration and the standard Trustee resource
//! policy own composite attestation. This adapter does not manufacture or
//! independently appraise GPU evidence. It preserves local grant enforcement.
//! Do not enable this feature in a guest before those components and resource
//! policies have been approved together. The ordinary CDH session may be reused
//! until its upstream expiry; a GetResource call is not proof of fresh evidence.

use crate::{Error, KeyMaterial, Result};
use confidential_storage_client::{keys::resource_uri, keys::KeyPermit, AuthorityClient, Evidence};
use protos::ttrpc::cdh::{api::GetResourceRequest, api_ttrpc::GetResourceServiceClient};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt},
    time::Duration,
};
use zeroize::Zeroizing;

const DIRECTORY: &str = "/run/confidential-containers";
const SOCKET: &str = "/run/confidential-containers/cdh.sock";
const URI: &str = "unix:///run/confidential-containers/cdh.sock";
const TIMEOUT_SECONDS: i64 = 25;

/// Chosen in measured configuration for each resource; never auto-detected.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Raw32,
    LowerHex64,
}

/// Resource entries and session/policy bindings come only from the trusted
/// service's measured configuration and authenticated authority client.
pub struct PrivateCdh {
    resources: BTreeMap<String, Encoding>,
    allowed: Vec<String>,
    session: String,
    policy: String,
}

fn resources_valid(resources: &BTreeMap<String, Encoding>) -> bool {
    !resources.is_empty() && resources.len() <= 16 && resources.keys().all(|r| resource_uri(r))
}

fn private_socket() -> Result<()> {
    let directory = fs::symlink_metadata(DIRECTORY).map_err(|_| Error::Configuration)?;
    let socket = fs::symlink_metadata(SOCKET).map_err(|_| Error::Configuration)?;
    // The root-only parent is essential: CDH's socket mode alone is not an
    // application access boundary. No pathname or endpoint comes from a caller.
    if unsafe { libc::geteuid() } != 0
        || !directory.is_dir()
        || directory.uid() != 0
        || directory.mode() & 0o777 != 0o700
        || !socket.file_type().is_socket()
        || socket.uid() != 0
    {
        return Err(Error::Configuration);
    }
    Ok(())
}

fn decode(bytes: Vec<u8>, encoding: Encoding) -> Result<KeyMaterial> {
    let bytes = Zeroizing::new(bytes);
    match encoding {
        Encoding::Raw32 if bytes.len() == 32 => Ok(KeyMaterial(bytes)),
        Encoding::LowerHex64 if bytes.len() == 64 => {
            fn digit(b: u8) -> Result<u8> {
                match b {
                    b'0'..=b'9' => Ok(b - b'0'),
                    b'a'..=b'f' => Ok(b - b'a' + 10),
                    _ => Err(Error::Retrieval),
                }
            }
            let mut decoded = Zeroizing::new(vec![0u8; 32]);
            for (index, pair) in bytes.chunks_exact(2).enumerate() {
                decoded[index] = digit(pair[0])? * 16 + digit(pair[1])?;
            }
            Ok(KeyMaterial(decoded))
        }
        _ => Err(Error::Retrieval),
    }
}

impl PrivateCdh {
    pub fn new<E: Evidence>(
        authority: &AuthorityClient<E>,
        resources: BTreeMap<String, Encoding>,
    ) -> Result<Self> {
        if !resources_valid(&resources) {
            return Err(Error::Configuration);
        }
        private_socket()?;
        Ok(Self {
            allowed: resources.keys().cloned().collect(),
            resources,
            session: authority.session_sha256().into(),
            policy: authority.policy_sha256().into(),
        })
    }

    /// Consume an opaque authority-derived permit. There is no string-only
    /// public key-fetch method, no alternate socket and no application listener.
    pub async fn retrieve(&self, permit: KeyPermit) -> Result<KeyMaterial> {
        permit
            .check(&self.session, &self.policy, &self.allowed)
            .map_err(|_| Error::Authorization)?;
        private_socket()?;
        let encoding = *self
            .resources
            .get(permit.credential_uri())
            .ok_or(Error::Authorization)?;
        let request = GetResourceRequest {
            ResourcePath: permit.credential_uri().to_owned(),
            ..Default::default()
        };
        // Bound connection plus RPC, suppress remote errors (which can include
        // token/evidence details), and retain no key/token cache in this adapter.
        let operation = async {
            let inner = ttrpc::asynchronous::Client::connect(URI)
                .await
                .map_err(|_| Error::Retrieval)?;
            let client = GetResourceServiceClient::new(inner);
            let mut response = client
                .get_resource(
                    ttrpc::context::with_timeout(TIMEOUT_SECONDS * 1_000_000_000),
                    &request,
                )
                .await
                .map_err(|_| Error::Retrieval)?;
            decode(std::mem::take(&mut response.Resource), encoding)
        };
        let key = tokio::time::timeout(Duration::from_secs(TIMEOUT_SECONDS as u64), operation)
            .await
            .map_err(|_| Error::Retrieval)??;
        // A response completing after its authority permit expired cannot be
        // used to activate a mapping. KeyMaterial wipes its bytes on this error.
        permit
            .check(&self.session, &self.policy, &self.allowed)
            .map_err(|_| Error::Authorization)?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoding_is_explicit_and_never_falls_back_or_trims() {
        assert_eq!(
            decode(vec![7; 32], Encoding::Raw32).unwrap().as_bytes(),
            &[7; 32]
        );
        assert_eq!(
            decode(b"ab".repeat(32), Encoding::LowerHex64)
                .unwrap()
                .as_bytes(),
            &[0xab; 32]
        );
        for bytes in [vec![], vec![7; 31], vec![7; 33], b"ab".repeat(32)] {
            assert!(decode(bytes, Encoding::Raw32).is_err());
        }
        for bytes in [
            vec![7; 32],
            b"AB".repeat(32),
            b"gg".repeat(32),
            b"ab".repeat(31),
            [b"ab".repeat(32), b"\n".to_vec()].concat(),
        ] {
            assert!(decode(bytes, Encoding::LowerHex64).is_err());
        }
    }

    #[test]
    fn configuration_cannot_select_a_remote_host_or_unbounded_resources() {
        assert!(!resources_valid(&BTreeMap::new()));
        assert!(resources_valid(&BTreeMap::from([(
            "kbs:///default/keys/data-v1".into(),
            Encoding::Raw32
        )])));
        for uri in [
            "https://host/key",
            "kbs://host/a/b/c",
            "kbs:///a/b/../c",
            "kbs:///a/b/c?token=x",
        ] {
            assert!(!resources_valid(&BTreeMap::from([(
                uri.into(),
                Encoding::Raw32
            )])));
        }
        assert!(!resources_valid(
            &(0..17)
                .map(|n| (format!("kbs:///a/b/key-{n}"), Encoding::Raw32))
                .collect()
        ));
    }
}

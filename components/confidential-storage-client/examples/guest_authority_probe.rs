// SPDX-License-Identifier: Apache-2.0
//! No-key guest diagnostic: real private AA, fresh TLS authority requests.
//! This executable has no disk, mount, KBS or key-delivery operation.
use confidential_storage_client::{private_aa::PrivateAa, AuthorityClient, Config};
use confidential_storage_guest::receipt::Expected;
use serde::Deserialize;
use std::{fs, net::SocketAddr, os::unix::fs::MetadataExt};

const CONFIG: &str = "/etc/storage-authority-probe.json";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Probe {
    purpose: String,
    audience: String,
    certificate_der: Vec<u8>,
    address: SocketAddr,
    policy_sha256: String,
    init_data: String,
    receipt_public_key: [u8; 32],
    receipt_issuer: String,
    receipt_key_id: String,
    expected: Expected,
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let info = fs::symlink_metadata(CONFIG)?;
    if !info.is_file() || info.uid() != 0 || info.mode() & 0o777 != 0o600 || info.len() > 32768 {
        return Err("invalid fixed probe configuration".into());
    }
    let probe: Probe = serde_json::from_slice(&fs::read(CONFIG)?)?;
    if probe.purpose != "no-key-live-authority-probe"
        || probe.audience != "https://storage-authority.invalid:8443/v1"
        || probe.expected.volume_id != "diagnostic-qwen"
        || probe.expected.access != "ro"
    {
        return Err("not the isolated diagnostic".into());
    }
    let client = AuthorityClient::new(
        Config {
            audience: probe.audience,
            certificate_der: probe.certificate_der,
            address: Some(probe.address),
            policy_sha256: probe.policy_sha256,
            init_data: probe.init_data,
            receipt_public_key: probe.receipt_public_key,
            receipt_issuer: probe.receipt_issuer,
            receipt_key_id: probe.receipt_key_id,
        },
        PrivateAa,
    )?;
    let mut expected = probe.expected;
    expected.session_sha256 = client.session_sha256().into();
    let grant = client.reopen(&expected)?;
    println!("STORAGE_AUTHORITY_PROBE receipt_verified");
    let retry = client.reopen(&expected)?;
    if retry.claims().activation_id != grant.claims().activation_id {
        return Err("authority changed retained activation".into());
    }
    println!("STORAGE_AUTHORITY_PROBE fresh_attestation_retry_verified");
    // This diagnostic never mounts/opens a volume, so there are no consumers
    // or effects to quiesce. Never copy this unconditional close into an opener.
    client.close(&grant)?;
    client.close(&grant)?;
    if client.reopen(&expected).is_ok() {
        return Err("closed operation was replayed".into());
    }
    println!("STORAGE_AUTHORITY_PROBE close_and_replay_denial_verified");
    println!("STORAGE_AUTHORITY_PROBE PASS no_keys_no_storage_effects");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("STORAGE_AUTHORITY_PROBE FAILED {error}");
        if let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            eprintln!("STORAGE_AUTHORITY_PROBE guest_unix_time={}", now.as_secs());
        }
        std::process::exit(1);
    }
}

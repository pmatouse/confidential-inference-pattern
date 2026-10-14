// SPDX-License-Identifier: Apache-2.0
//! Reuse the measured guest's AA through its existing root-private ttRPC API.
use crate::{canonical, rcar_nonce, Error, Result};
use protos::ttrpc::aa::{
    attestation_agent::{GetAdditionalEvidenceRequest, GetEvidenceRequest, GetTeeTypeRequest},
    attestation_agent_ttrpc::AttestationAgentServiceClient,
};
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt},
    time::Duration,
};
const DIRECTORY: &str = "/run/confidential-containers/attestation-agent";
const SOCKET: &str = "/run/confidential-containers/attestation-agent/attestation-agent.sock";
const URI: &str = "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";

fn digest(value: &Value) -> Result<Vec<u8>> {
    Ok(
        ring::digest::digest(&ring::digest::SHA384, &canonical(value)?)
            .as_ref()
            .to_vec(),
    )
}
fn runtime(nonce: &str, key: &Value) -> Result<Value> {
    let object = key.as_object().ok_or(Error::Binding)?;
    if !rcar_nonce(nonce)
        || object.len() != 4
        || key["kty"] != "EC"
        || key["crv"] != "P-256"
        || !key["x"].is_string()
        || !key["y"].is_string()
    {
        return Err(Error::Binding);
    }
    let mut key = object.clone();
    key.insert("alg".into(), json!("ES256"));
    Ok(json!({"nonce":nonce,"tee-pubkey":key}))
}
fn composite_runtime(device_runtime: &Value, additional: &str) -> Result<Value> {
    if additional.len() > 128 * 1024 {
        return Err(Error::Attestation);
    }
    let value: Value = serde_json::from_str(additional).map_err(|_| Error::Attestation)?;
    if !value
        .as_object()
        .is_some_and(|v| v.len() == 1 && v.get("nvidia").is_some_and(Value::is_object))
    {
        return Err(Error::Attestation);
    }
    let mut primary = device_runtime.clone();
    primary["additional-evidence"] = json!(additional);
    Ok(primary)
}
pub fn collect(nonce: &str, key: &Value) -> Result<Vec<u8>> {
    let device_runtime = runtime(nonce, key)?;
    for path in ["/run/confidential-containers", DIRECTORY] {
        let m = fs::symlink_metadata(path).map_err(|_| Error::Attestation)?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o777 != 0o700 {
            return Err(Error::Attestation);
        }
    }
    let m = fs::symlink_metadata(SOCKET).map_err(|_| Error::Attestation)?;
    if unsafe { libc::geteuid() } != 0 || !m.file_type().is_socket() || m.uid() != 0 {
        return Err(Error::Attestation);
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Error::Attestation)?;
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(20), async {
            let inner = ttrpc::asynchronous::Client::connect(URI)
                .await
                .map_err(|_| Error::Attestation)?;
            let client = AttestationAgentServiceClient::new(inner);
            let context = || ttrpc::context::with_timeout(8_000_000_000);
            let tee = client
                .get_tee_type(context(), &GetTeeTypeRequest::default())
                .await
                .map_err(|_| Error::Attestation)?;
            if tee.tee != "snp" {
                return Err(Error::Attestation);
            }
            let additional = client
                .get_additional_evidence(
                    context(),
                    &GetAdditionalEvidenceRequest {
                        RuntimeData: digest(&device_runtime)?,
                        ..Default::default()
                    },
                )
                .await
                .map_err(|_| Error::Attestation)?;
            let additional =
                String::from_utf8(additional.Evidence).map_err(|_| Error::Attestation)?;
            let primary_runtime = composite_runtime(&device_runtime, &additional)?;
            let primary = client
                .get_evidence(
                    context(),
                    &GetEvidenceRequest {
                        RuntimeData: digest(&primary_runtime)?,
                        ..Default::default()
                    },
                )
                .await
                .map_err(|_| Error::Attestation)?;
            if primary.Evidence.len() > 144 * 1024 {
                return Err(Error::Attestation);
            }
            let primary: Value =
                serde_json::from_slice(&primary.Evidence).map_err(|_| Error::Attestation)?;
            if !primary.is_object() {
                return Err(Error::Attestation);
            }
            let result =
                canonical(&json!({"primary_evidence":primary,"additional_evidence":additional}))?;
            if result.len() > 144 * 1024 {
                return Err(Error::Attestation);
            }
            Ok(result)
        })
        .await
        .map_err(|_| Error::Attestation)?
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn composite_digest_binds_gpu_bytes_and_uses_separate_signing_key() {
        let nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let key = json!({"kty":"EC","crv":"P-256","x":"x","y":"y"});
        let device = runtime(nonce, &key).unwrap();
        assert_eq!(device["tee-pubkey"]["alg"], "ES256");
        assert!(key.get("alg").is_none());
        let a = composite_runtime(&device, r#"{"nvidia":{"fixture":1}}"#).unwrap();
        let b = composite_runtime(&device, r#"{"nvidia":{"fixture":2}}"#).unwrap();
        assert_eq!(digest(&a).unwrap().len(), 48);
        assert_ne!(digest(&a).unwrap(), digest(&b).unwrap());
        assert_ne!(digest(&device).unwrap(), digest(&a).unwrap());
        for bad in ["", "{}", r#"{"snp":{}}"#, r#"{"nvidia":null}"#] {
            assert!(composite_runtime(&device, bad).is_err());
        }
        assert!(runtime("host-selected", &key).is_err());
    }
}

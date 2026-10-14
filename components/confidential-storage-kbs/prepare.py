#!/usr/bin/env python3
"""Stage the pinned KBS library and local guest libraries; never modify upstream.

Usage: prepare.py --upstream /path/to/pinned/checkout --output /new/build/directory
Run cargo from output/components/confidential-storage-kbs. A checked-in Cargo.lock
is used when present; the initial dependency resolution must be reviewed/pinned.
"""

import argparse
import hashlib
import io
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

PIN = "0ab1fb1be6e46293f29600085f929ae035ca3739"
UPSTREAM_LOCK = "88ba3f0378dbb6031b19ffe1a29172ebea42871c16c2ae7f8822c90b78658299"
HERE = Path(__file__).resolve().parent


def prepare(source, destination, with_test_fixtures=False, with_service=False):
    if destination.exists():
        raise ValueError("output must be a new directory")
    head = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    if head != PIN:
        raise ValueError("unexpected upstream revision")
    archive = subprocess.check_output(
        ["git", "-C", str(source), "archive", "--format=tar", PIN]
    )
    upstream = destination / "upstream"
    upstream.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for member in tar.getmembers():
            if (
                member.name.startswith("/")
                or ".." in Path(member.name).parts
                or not (member.isfile() or member.isdir())
            ):
                raise ValueError("unsupported upstream archive entry")
            target = upstream / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(tar.extractfile(member).read())
                target.chmod(member.mode & 0o777)
    if (
        hashlib.sha256((upstream / "Cargo.lock").read_bytes()).hexdigest()
        != UPSTREAM_LOCK
    ):
        raise ValueError("unexpected upstream dependency lock")

    # Only the private storage wrapper injects a restrictive HTTPS client. Other
    # upstream users retain their existing builder behavior in this staged tree.
    path = upstream / "attestation-agent/kbs_protocol/src/builder.rs"
    text = path.read_text()
    text = text.replace(
        "    provider: T,",
        "    provider: T,\n    http_client_override: Option<reqwest::Client>,",
        1,
    )
    for provider in ("evidence_provider", "token_provider"):
        old = "            provider: " + provider + ","
        assert old in text
        text = text.replace(old, "            http_client_override: None,\n" + old)
    text = text.replace(
        "impl<T> KbsClientBuilder<T> {",
        """impl<T> KbsClientBuilder<T> {
    pub fn with_http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client_override = Some(client);
        self
    }
""",
    )
    old = """http_client: http_client_builder
                .build()
                .context("Build KBS http client")?,"""
    assert old in text
    text = text.replace(
        old,
        """http_client: match self.http_client_override {
                Some(client) => client,
                None => http_client_builder.build().context("Build KBS http client")?,
            },""",
    )
    path.write_text(text)

    # Bound all RCAR JSON/error response bodies before parsing. reqwest's total
    # timeout and the wrapper's operation deadline apply as well.
    path = upstream / "attestation-agent/kbs_protocol/src/client/rcar_client.rs"
    text = path.read_text()
    text, count = re.subn(
        r"(\w+)\s*\.json::<([^>]+)>\(\)\s*\.await",
        r"bounded_json::<\2>(\1).await",
        text,
    )
    assert count == 8, count
    text, count = re.subn(r"(\w+)\.text\(\)\.await", r"bounded_text(\1).await", text)
    assert count == 2, count
    old = "                    let payload_data = self"
    assert text.count(old) == 1
    text = text.replace(
        old,
        """                    // This staged client serves only 32-byte storage credentials.
                    // Reject malformed wrapping lengths before upstream unwrap.
                    if response.protected.alg != "ECDH-ES+A256KW"
                        || response.protected.enc != "A256GCM"
                        || response.encrypted_key.len() != 40
                        || response.iv.len() != 12 || response.tag.len() != 16
                        || response.ciphertext.len() != 32 || response.aad.is_some()
                        || !storage_epk(&response.protected) {
                        return Err(Error::KbsResponseDeserializationFailed("invalid storage key envelope".into()));
                    }
"""
        + old,
    )
    text += """
fn storage_epk(header: &kbs_types::ProtectedHeader) -> bool {
    use base64::Engine;
    let Some(epk) = header.other_fields.get("epk").and_then(|v| v.as_object()) else { return false; };
    if header.other_fields.len() != 1 || epk.len() != 4
        || epk.get("crv").and_then(|v| v.as_str()) != Some("P-256")
        || epk.get("kty").and_then(|v| v.as_str()) != Some("EC") { return false; }
    ["x", "y"].iter().all(|name| {
        let Some(text) = epk.get(*name).and_then(|v| v.as_str()) else { return false; };
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        engine.decode(text).is_ok_and(|bytes| bytes.len() == 32 && engine.encode(bytes) == text)
    })
}
async fn bounded_body(mut response: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    const LIMIT: usize = 256 * 1024;
    if response.content_length().is_some_and(|n| n > LIMIT as u64) {
        anyhow::bail!("KBS response too large");
    }
    let mut data = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > LIMIT - data.len() { anyhow::bail!("KBS response too large"); }
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}
async fn bounded_json<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> anyhow::Result<T> {
    Ok(serde_json::from_slice(&bounded_body(response).await?)?)
}
async fn bounded_text(response: reqwest::Response) -> anyhow::Result<String> {
    Ok(String::from_utf8(bounded_body(response).await?)?)
}
"""
    path.write_text(text)
    for name in (
        "confidential-storage-client",
        "confidential-storage-guest",
        "confidential-storage-kbs",
    ):
        shutil.copytree(
            HERE.parent / name,
            destination / "components" / name,
            ignore=shutil.ignore_patterns("target", "__pycache__", "._*", ".DS_Store"),
        )
    if with_service:
        shutil.copytree(
            HERE.parent / "confidential-storage-service",
            destination / "components/confidential-storage-service",
            ignore=shutil.ignore_patterns("target", "__pycache__", "._*", ".DS_Store"),
        )
    if with_test_fixtures:
        shutil.copytree(
            HERE.parent / "confidential-storage-authority",
            destination / "components/confidential-storage-authority",
            ignore=shutil.ignore_patterns("__pycache__", "._*", ".DS_Store"),
        )
        relative = Path(
            "tests/confidential-storage/evidence/2026-10-13/model-populator"
        )
        target = destination / relative
        target.mkdir(parents=True)
        for name in ("source.json", "guest-manifest.unsigned.json"):
            shutil.copyfile(HERE.parents[1] / relative / name, target / name)
    print(destination / "components/confidential-storage-kbs")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--with-test-fixtures", action="store_true")
    parser.add_argument("--with-service", action="store_true")
    args = parser.parse_args()
    prepare(
        args.upstream.resolve(),
        args.output.resolve(),
        args.with_test_fixtures,
        args.with_service,
    )

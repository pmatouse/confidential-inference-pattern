// SPDX-License-Identifier: Apache-2.0
//! Fixed private AA collector. No URL, socket path or executable from a request.
use crate::{sha, Error, Evidence, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{
    fs,
    io::Read,
    os::unix::{
        fs::{FileTypeExt, MetadataExt},
        process::CommandExt,
    },
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const CLIENT: &str = "/usr/bin/storage-aa-client";
const CLIENT_SHA256: &str = "1a9ea738602ccaebf7141e9e01ced3adfb3125e05a63b1332b930898a86509e5";
const DIRECTORY: &str = "/run/confidential-containers/attestation-agent";
const SOCKET: &str = "/run/confidential-containers/attestation-agent/attestation-agent.sock";
const LIMIT: usize = 144 * 1024;

/// The initrd must install the pinned client root:root 0700 and create the AA
/// socket directory root:root 0700. No permissive fallback if that is missing.
pub struct PrivateAa;
impl Evidence for PrivateAa {
    fn collect(&self, runtime_sha256: [u8; 32]) -> Result<Vec<u8>> {
        self.collect_digest(&runtime_sha256)
    }
    #[cfg(feature = "private-rcar-aa")]
    fn collect_rcar(&self, nonce: &str, key: &serde_json::Value) -> Result<Vec<u8>> {
        crate::private_rcar_aa::collect(nonce, key)
    }
}
impl PrivateAa {
    /// KBS negotiates SHA-256/384/512; pass the digest directly to private AA.
    pub fn collect_digest(&self, runtime_digest: &[u8]) -> Result<Vec<u8>> {
        if ![32, 48, 64].contains(&runtime_digest.len()) {
            return Err(Error::Attestation);
        }
        let directory = fs::symlink_metadata(DIRECTORY).map_err(|_| Error::Attestation)?;
        let socket = fs::symlink_metadata(SOCKET).map_err(|_| Error::Attestation)?;
        let client = fs::symlink_metadata(CLIENT).map_err(|_| Error::Attestation)?;
        if !directory.is_dir()
            || directory.uid() != 0
            || directory.mode() & 0o777 != 0o700
            || !socket.file_type().is_socket()
            || socket.uid() != 0
            || !client.is_file()
            || client.uid() != 0
            || client.mode() & 0o777 != 0o700
            || client.len() > 4 * 1024 * 1024
        {
            return Err(Error::Attestation);
        }
        if sha(&fs::read(CLIENT).map_err(|_| Error::Attestation)?) != CLIENT_SHA256 {
            return Err(Error::Attestation);
        }
        let mut command = Command::new(CLIENT);
        command
            .args([
                "--attestation_sock",
                concat!(
                    "unix://",
                    "/run/confidential-containers/attestation-agent/attestation-agent.sock"
                ),
                "get-evidence",
                "--runtime-data",
                &STANDARD.encode(runtime_digest),
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // SAFETY: child-only async-signal-safe syscalls, fixed arguments.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &limit) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().map_err(|_| Error::Attestation)?;
        let output = child.stdout.take().ok_or(Error::Attestation)?;
        let reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            output
                .take((LIMIT + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| Error::Attestation)?;
            if bytes.is_empty() || bytes.len() > LIMIT {
                return Err(Error::Attestation);
            }
            Ok(bytes)
        });
        let deadline = Instant::now() + Duration::from_secs(8);
        let success = loop {
            match child.try_wait() {
                Ok(Some(status)) if reader.is_finished() => break status.success(),
                Ok(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                _ => {
                    // SAFETY: the owned collector starts a private process group.
                    unsafe {
                        libc::kill(-(child.id() as i32), libc::SIGKILL);
                    }
                    let _ = child.wait();
                    break false;
                }
            }
        };
        let evidence = reader.join().map_err(|_| Error::Attestation)??;
        if !success {
            return Err(Error::Attestation);
        }
        // AS performs strict evidence parsing and hardware verification. Never
        // manufacture evidence here or fall back to a public HTTP quote endpoint.
        Ok(evidence)
    }
}

// SPDX-License-Identifier: Apache-2.0
//! Linux reopen primitive for the guest service. No formatting, mounting, key
//! retrieval, attestation transport or authority release. Keep failed handles
//! until explicit close succeeds; dropping a handle never proves teardown.
use crate::{receipt::VerifiedGrant, sealed_header::PreparedHeader};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, RawFd},
        unix::{
            fs::{FileTypeExt, MetadataExt},
            process::CommandExt,
        },
    },
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid or expired storage authorization")]
    Authorization,
    #[error("invalid resolved block device")]
    Device,
    #[error("mapping name is already owned or has an unexpected identity")]
    Conflict,
    #[error("opener has been consumed; cleanup required")]
    State,
    #[error("storage command failed or timed out")]
    Command,
    #[error("effective storage stack does not match the fixed profile")]
    Stack,
}
type Result<T> = std::result::Result<T, Error>;

/// Supplied by a trusted guest device resolver. The major/minor expectation must
/// come from that resolver, not from a host claim of authorization.
pub struct BlockDevice {
    pub(crate) file: File,
    pub(crate) id: String,
    pub(crate) bytes: u64,
}
impl BlockDevice {
    pub fn from_file(file: File, major: u32, minor: u32) -> Result<Self> {
        let metadata = file.metadata().map_err(|_| Error::Device)?;
        if !metadata.file_type().is_block_device()
            || libc::major(metadata.rdev()) != major
            || libc::minor(metadata.rdev()) != minor
        {
            return Err(Error::Device);
        }
        let mut bytes = 0u64;
        // SAFETY: live fd and a writable u64 for Linux BLKGETSIZE64.
        if unsafe { libc::ioctl(file.as_raw_fd(), 0x80081272, &mut bytes) } != 0
            || bytes < 64 * 1024 * 1024
            || !bytes.is_multiple_of(4096)
        {
            return Err(Error::Device);
        }
        Ok(Self {
            file,
            id: format!("{major}:{minor}"),
            bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Prepared,
    NeedsClose,
    Open,
    Closed,
}

pub struct Opener {
    device: BlockDevice,
    header: PreparedHeader,
    grant: VerifiedGrant,
    name: String,
    phase: Phase,
    deadline: Instant,
}
impl Opener {
    pub fn prepare(grant: VerifiedGrant, manifest: &[u8], device: BlockDevice) -> Result<Self> {
        let now = now()?;
        grant.check_time(now).map_err(|_| Error::Authorization)?;
        let deadline = Instant::now() + Duration::from_secs(grant.claims().exp - now);
        let header = PreparedHeader::prepare(&grant, manifest, &device.file, device.bytes)
            .map_err(|_| Error::Authorization)?;
        let identity = format!(
            "{}\0{}\0{}",
            grant.claims().volume_id,
            grant.claims().session_sha256,
            grant.claims().activation_id
        );
        let hash = ring::digest::digest(&ring::digest::SHA256, identity.as_bytes());
        let name = format!(
            "coco-{}",
            hash.as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        Ok(Self {
            device,
            header,
            grant,
            name,
            phase: Phase::Prepared,
            deadline,
        })
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn credential_uri(&self) -> &str {
        self.header.manifest().credential_uri()
    }
    /// Retrieve exactly this credential via the future trusted CDH adapter, only
    /// after prepare succeeds. The provider owns zeroization of its input buffer.
    /// The key is passed through an anonymous stdin pipe, never argv/env/a file.
    pub fn open(&mut self, key: &[u8; 32]) -> Result<()> {
        if self.phase != Phase::Prepared {
            return Err(Error::State);
        }
        self.grant
            .check_time(now()?)
            .map_err(|_| Error::Authorization)?;
        if Instant::now() >= self.deadline {
            return Err(Error::Authorization);
        }
        if lookup(&self.name)?.is_some() || lookup(&self.lower_name())?.is_some() {
            return Err(Error::Conflict);
        }
        // Before any kernel effect, including a partially successful command.
        self.phase = Phase::NeedsClose;
        let header_fd = self.header.as_fd().as_raw_fd();
        let device_fd = self.device.file.as_raw_fd();
        let header = format!("/proc/self/fd/{header_fd}");
        let device = format!("/proc/self/fd/{device_fd}");
        run(
            "/usr/sbin/cryptsetup",
            &[
                "open",
                "--batch-mode",
                "--type",
                "luks2",
                "--disable-external-tokens",
                "--disable-keyring",
                "--header",
                &header,
                "--key-file",
                "-",
                "--keyfile-size",
                "32",
                &device,
                &self.name,
            ],
            &[header_fd, device_fd],
            Some(key),
        )?;
        self.verify_stack()?;
        self.phase = Phase::Open;
        Ok(())
    }
    /// Only the guest service may bind this filesystem into an application.
    pub fn mapping_path(&self) -> Result<PathBuf> {
        if self.phase != Phase::Open {
            return Err(Error::State);
        }
        Ok(PathBuf::from("/dev/mapper").join(&self.name))
    }
    /// No force, lazy unmount, deferred remove or automatic authority release.
    /// EBUSY retains NeedsClose. The caller must remove app/guest mounts first.
    pub fn close(&mut self) -> Result<()> {
        if self.phase == Phase::Closed {
            return Ok(());
        }
        if self.phase == Phase::Prepared {
            // A conflicting/pre-existing mapping is not ours to remove, but its
            // presence also prevents claiming that this activation is torn down.
            if lookup(&self.name)?.is_some() || lookup(&self.lower_name())?.is_some() {
                return Err(Error::Conflict);
            }
            self.phase = Phase::Closed;
            return Ok(());
        }
        self.phase = Phase::NeedsClose;
        // Verify both identities BEFORE removing either one, including partial open.
        let top = self.owned(false)?;
        let lower = self.owned(true)?;
        if top.is_some() {
            run("/usr/sbin/cryptsetup", &["close", &self.name], &[], None)?;
        }
        if lower.is_some() && self.owned(true)?.is_some() {
            run(
                "/usr/sbin/cryptsetup",
                &["close", &self.lower_name()],
                &[],
                None,
            )?;
        }
        if lookup(&self.name)?.is_some() || lookup(&self.lower_name())?.is_some() {
            return Err(Error::Conflict);
        }
        self.phase = Phase::Closed;
        Ok(())
    }
    fn lower_name(&self) -> String {
        format!("{}_dif", self.name)
    }
    fn owned(&self, lower: bool) -> Result<Option<PathBuf>> {
        owned_mapping(&self.name, self.header.manifest().luks_uuid(), lower)
    }
    fn verify_stack(&self) -> Result<()> {
        verify_mapping_stack(
            &self.name,
            self.header.manifest().luks_uuid(),
            &self.device.id,
            self.device.bytes,
        )
    }
}
pub(crate) fn owned_mapping(base: &str, uuid: &str, lower: bool) -> Result<Option<PathBuf>> {
    let name = if lower {
        format!("{base}_dif")
    } else {
        base.to_owned()
    };
    let Some(path) = lookup(&name)? else {
        return Ok(None);
    };
    let kind = if lower { "INTEGRITY" } else { "LUKS2" };
    let expected = format!("CRYPT-{kind}-{}-{name}", uuid.replace('-', ""));
    if read(path.join("dm/uuid"))? != expected {
        return Err(Error::Conflict);
    }
    Ok(Some(path))
}
pub(crate) fn verify_mapping_stack(
    name: &str,
    uuid: &str,
    device_id: &str,
    device_bytes: u64,
) -> Result<()> {
    let top = owned_mapping(name, uuid, false)?.ok_or(Error::Stack)?;
    let lower = owned_mapping(name, uuid, true)?.ok_or(Error::Stack)?;
    for (path, name) in [(&top, name.to_owned()), (&lower, format!("{name}_dif"))] {
        if read(path.join("dm/suspended"))? != "0" {
            return Err(Error::Stack);
        }
        let segments = run(
            "/usr/sbin/dmsetup",
            &["info", "-c", "--noheadings", "-o", "segments", &name],
            &[],
            None,
        )?;
        if segments.trim() != "1" {
            return Err(Error::Stack);
        }
    }
    if slaves(&top)? != BTreeSet::from([read(lower.join("dev"))?])
        || slaves(&lower)? != BTreeSet::from([device_id.to_owned()])
    {
        return Err(Error::Stack);
    }
    let table = run(
        "/usr/sbin/dmsetup",
        &["table", "--target", "integrity", &format!("{name}_dif")],
        &[],
        None,
    )?;
    let sectors = integrity_table(&table, device_id, device_bytes)?;
    let status = run("/usr/sbin/cryptsetup", &["status", name], &[], None)?;
    crypt_status(&status, name, sectors, device_id.starts_with("7:"))?;
    // Never query a dm-crypt table or use --showkeys.
    Ok(())
}

pub(crate) fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Authorization)?
        .as_secs())
}
pub(crate) fn read(path: PathBuf) -> Result<String> {
    let bytes = fs::read(path).map_err(|_| Error::Stack)?;
    if bytes.len() > 4096 {
        return Err(Error::Stack);
    }
    Ok(String::from_utf8(bytes)
        .map_err(|_| Error::Stack)?
        .trim()
        .to_owned())
}
pub(crate) fn lookup(name: &str) -> Result<Option<PathBuf>> {
    let mut found = None;
    for entry in fs::read_dir("/sys/class/block").map_err(|_| Error::Stack)? {
        let path = entry.map_err(|_| Error::Stack)?.path();
        match fs::read_to_string(path.join("dm/name")) {
            Ok(value) if value.trim() == name => {
                if found.is_some() {
                    return Err(Error::Conflict);
                }
                found = Some(path);
            }
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(Error::Stack),
        }
    }
    Ok(found)
}
pub(crate) fn slaves(path: &std::path::Path) -> Result<BTreeSet<String>> {
    fs::read_dir(path.join("slaves"))
        .map_err(|_| Error::Stack)?
        .map(|e| read(e.map_err(|_| Error::Stack)?.path().join("dev")))
        .collect()
}
fn integrity_table(text: &str, device: &str, bytes: u64) -> Result<u64> {
    // Fixed, kernel-validated geometries. The kernel chooses a larger default
    // journal for the 1 GiB PVC than for the original 128 MiB loop fixture.
    // Other sizes require explicit validation, not an arbitrary journal value.
    let journal = match bytes {
        134217728 => "journal_sectors:1848",
        1073741824 => "journal_sectors:16368",
        _ => return Err(Error::Stack),
    };
    let v: Vec<_> = text.split_whitespace().collect();
    if v.len() != 15
        || v[0] != "0"
        || v[2] != "integrity"
        || v[3] != device
        || v[4..8] != ["32768", "32", "J", "7"]
    {
        return Err(Error::Stack);
    }
    let sectors: u64 = v[1].parse().map_err(|_| Error::Stack)?;
    if sectors == 0 || !sectors.is_multiple_of(8) || sectors >= bytes.saturating_sub(16777216) / 512
    {
        return Err(Error::Stack);
    }
    let options: BTreeSet<_> = v[8..].iter().copied().collect();
    if options
        != BTreeSet::from([
            "block_size:4096",
            journal,
            "interleave_sectors:32768",
            "buffer_sectors:128",
            "journal_watermark:50",
            "commit_time:10000",
            "fix_padding",
        ])
    {
        return Err(Error::Stack);
    }
    Ok(sectors)
}
fn crypt_status(text: &str, name: &str, sectors: u64, is_loop: bool) -> Result<()> {
    let mut lines = text.lines();
    if lines.next() != Some(format!("/dev/mapper/{name} is active.").as_str()) {
        return Err(Error::Stack);
    }
    let mut fields = BTreeMap::new();
    for line in lines {
        let (key, value) = line.split_once(':').ok_or(Error::Stack)?;
        if fields.insert(key.trim(), value.trim()).is_some() {
            return Err(Error::Stack);
        }
    }
    // cryptsetup emits this informational path only for loop devices. Device
    // identity is independently pinned by the retained fd and kernel slaves.
    if is_loop && fields.remove("loop").is_none() {
        return Err(Error::Stack);
    }
    let required = [
        ("type", "LUKS2"),
        ("cipher", "aes-xts-plain64"),
        ("keysize", "768 bits"),
        ("key location", "dm-crypt"),
        ("integrity", "hmac(sha256)"),
        ("integrity keysize", "256 bits"),
        ("sector size", "4096"),
        ("offset", "0 sectors"),
        ("mode", "read/write"),
    ];
    if fields.len() != required.len() + 2
        || required.iter().any(|(k, v)| fields.get(k) != Some(v))
        || fields.get("size") != Some(&format!("{sectors} sectors").as_str())
        || !fields.contains_key("device")
    {
        return Err(Error::Stack);
    }
    Ok(()) // Device identity is checked from actual kernel dependency links above.
}

/// Fixed trusted executables only. Suppress stderr; never return tool output in
/// public errors. The bounded stdout is used solely by strict stack parsers.
pub(crate) fn run(
    tool: &str,
    args: &[&str],
    inherited: &[RawFd],
    key: Option<&[u8; 32]>,
) -> Result<String> {
    run_bounded(tool, args, inherited, key, Duration::from_secs(30))
}
pub(crate) fn run_bounded(
    tool: &str,
    args: &[&str],
    inherited: &[RawFd],
    key: Option<&[u8; 32]>,
    timeout: Duration,
) -> Result<String> {
    let mut command = Command::new(tool);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(if key.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let fds = inherited.to_vec();
    // SAFETY: child-only async-signal-safe syscalls, no allocation or locks in hook.
    unsafe {
        command.pre_exec(move || {
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
            for fd in &fds {
                let flags = libc::fcntl(*fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(*fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|_| Error::Command)?;
    let stdout = child.stdout.take().ok_or(Error::Command)?;
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(16385)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Command)?;
        if bytes.len() > 16384 {
            return Err(Error::Command);
        }
        String::from_utf8(bytes).map_err(|_| Error::Command)
    });
    let written = key.map_or(Ok(()), |key| {
        child
            .stdin
            .take()
            .ok_or(Error::Command)?
            .write_all(key)
            .map_err(|_| Error::Command)
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success() && written.is_ok(),
            Ok(None) if Instant::now() < deadline && written.is_ok() => {
                thread::sleep(Duration::from_millis(20))
            }
            _ => {
                // SAFETY: child created a private process group; only owned tools.
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                let _ = child.wait();
                break false;
            }
        }
    };
    let output = reader.join().map_err(|_| Error::Command)??;
    if !status {
        return Err(Error::Command);
    }
    Ok(output)
}

#[cfg(test)]
mod tests;

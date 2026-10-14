// SPDX-License-Identifier: Apache-2.0
//! Trusted guest-only first-use disk executor. No RPC, key lookup or authority.
//! The service must consume a fresh signed step permit BEFORE each mutating call.
//! This object is deliberately non-resumable: any failure retains an uncertain
//! phase and can only be cleaned up, never used to repeat destructive work.
use crate::{
    opener::{self, BlockDevice},
    profile, sealed_header,
};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{FileExt, OpenOptionsExt},
    },
    path::PathBuf,
    time::Duration,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Fresh,
    Formatting,
    Formatted,
    Opening,
    Integrity,
    CreatingFilesystem,
    Filesystem,
    Closing,
    Closed,
}

/// Construct only from an attestation-verified administrator first-use plan.
/// The approved PVC/provisioning identity is checked by the service's journal.
pub struct Initializer {
    device: BlockDevice,
    uuid: String,
    name: String,
    header: Option<File>,
    digest: Option<String>,
    phase: Phase,
    filesystem_owner: (u32, u32),
}
fn invalid() -> std::io::Error {
    std::io::Error::other("trusted storage initialization rejected")
}
fn sha(data: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect()
}
fn uuid_bytes(value: &str) -> Result<[u8; 16]> {
    if value.len() != 36
        || !value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
    {
        return Err(invalid().into());
    }
    let compact = value.replace('-', "");
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&compact[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}
impl Initializer {
    pub fn check_blank(device: &BlockDevice, expected_bytes: u64) -> Result<()> {
        if device.bytes != expected_bytes {
            return Err(invalid().into());
        }
        // Full zero scan is an extra guard, NEVER the source of format authority.
        let mut bytes = vec![0; 1024 * 1024];
        let mut offset = 0;
        while offset < device.bytes {
            let n = std::cmp::min(bytes.len() as u64, device.bytes - offset) as usize;
            device.file.read_exact_at(&mut bytes[..n], offset)?;
            if bytes[..n].iter().any(|v| *v != 0) {
                return Err(invalid().into());
            }
            offset += n as u64;
        }
        Ok(())
    }
    pub fn preflight(
        device: BlockDevice,
        expected_bytes: u64,
        uuid: &str,
        activation: &str,
    ) -> Result<Self> {
        Self::preflight_profile(
            device,
            expected_bytes,
            uuid,
            activation,
            &crate::profile::profile_sha256(),
        )
    }
    pub fn preflight_profile(
        device: BlockDevice,
        expected_bytes: u64,
        uuid: &str,
        activation: &str,
        profile_sha256: &str,
    ) -> Result<Self> {
        let filesystem_owner =
            crate::profile::filesystem_owner(profile_sha256).ok_or_else(invalid)?;
        uuid_bytes(uuid)?;
        uuid_bytes(activation)?;
        if device.bytes != expected_bytes {
            return Err(invalid().into());
        }
        Self::check_blank(&device, expected_bytes)?;
        let name = format!("coco-init-{}", activation);
        if opener::lookup(&name)?.is_some() || opener::lookup(&format!("{name}_dif"))?.is_some() {
            return Err(invalid().into());
        }
        Ok(Self {
            device,
            uuid: uuid.into(),
            name,
            header: None,
            digest: None,
            phase: Phase::Fresh,
            filesystem_owner,
        })
    }
    pub fn header_sha256(&self) -> Result<&str> {
        self.digest.as_deref().ok_or_else(|| invalid().into())
    }
    pub fn format(&mut self, key: &[u8; 32]) -> Result<()> {
        if self.phase != Phase::Fresh {
            return Err(invalid().into());
        }
        self.phase = Phase::Formatting;
        // Generate metadata in private guest memory. The untrusted disk never
        // supplies the header parsed by cryptsetup during first-use activation.
        let fd = unsafe { libc::memfd_create(c"coco-new-header".as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let header = unsafe { File::from_raw_fd(fd) };
        header.set_len(profile::HEADER_BYTES as u64)?;
        let hp = format!("/proc/self/fd/{fd}");
        let dp = format!("/proc/self/fd/{}", self.device.file.as_raw_fd());
        opener::run_bounded(
            "/usr/sbin/cryptsetup",
            &[
                "luksFormat",
                "--batch-mode",
                "--type",
                "luks2",
                "--cipher",
                "aes-xts-plain64",
                "--key-size",
                "512",
                "--integrity",
                "hmac-sha256",
                "--sector-size",
                "4096",
                "--uuid",
                &self.uuid,
                "--pbkdf",
                "argon2id",
                "--pbkdf-memory",
                "65536",
                "--pbkdf-parallel",
                "1",
                "--pbkdf-force-iterations",
                "4",
                "--luks2-metadata-size",
                "16k",
                "--luks2-keyslots-size",
                "16744448",
                "--offset",
                "32768",
                "--header",
                &hp,
                "--key-file",
                "-",
                "--keyfile-size",
                "32",
                &dp,
            ],
            &[fd, self.device.file.as_raw_fd()],
            Some(key),
            Duration::from_secs(180),
        )?;
        if header.metadata()?.len() != profile::HEADER_BYTES as u64 {
            return Err(invalid().into());
        }
        let mut bytes = vec![0; profile::HEADER_BYTES];
        header.read_exact_at(&mut bytes, 0)?;
        profile::validate_header(&bytes, &self.uuid)?;
        let sealed = sealed_header::seal(&bytes)?;
        self.device.file.write_all_at(&bytes, 0)?;
        self.device.file.sync_all()?;
        self.digest = Some(sha(&bytes));
        self.header = Some(sealed);
        self.phase = Phase::Formatted;
        Ok(())
    }
    pub fn initialize_integrity(&mut self, key: &[u8; 32]) -> Result<String> {
        if self.phase != Phase::Formatted {
            return Err(invalid().into());
        }
        self.phase = Phase::Opening;
        let fd = self.header.as_ref().ok_or_else(invalid)?.as_raw_fd();
        let hp = format!("/proc/self/fd/{fd}");
        let dp = format!("/proc/self/fd/{}", self.device.file.as_raw_fd());
        opener::run(
            "/usr/sbin/cryptsetup",
            &[
                "open",
                "--batch-mode",
                "--type",
                "luks2",
                "--disable-external-tokens",
                "--disable-keyring",
                "--header",
                &hp,
                "--key-file",
                "-",
                "--keyfile-size",
                "32",
                &dp,
                &self.name,
            ],
            &[fd, self.device.file.as_raw_fd()],
            Some(key),
        )?;
        opener::verify_mapping_stack(&self.name, &self.uuid, &self.device.id, self.device.bytes)?;
        let mut mapping = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(self.mapping())?;
        // Verify the full initialized HMAC-protected payload before filesystem creation.
        let mut buffer = vec![0; 1024 * 1024];
        while mapping.read(&mut buffer)? != 0 {}
        mapping.flush()?;
        mapping.sync_all()?;
        let table = opener::run(
            "/usr/sbin/dmsetup",
            &[
                "table",
                "--target",
                "integrity",
                &format!("{}_dif", self.name),
            ],
            &[],
            None,
        )?;
        self.phase = Phase::Integrity;
        Ok(sha(table.as_bytes()))
    }
    pub fn create_filesystem(&mut self) -> Result<String> {
        if self.phase != Phase::Integrity {
            return Err(invalid().into());
        }
        // Consume before command; failure cannot be retried on this instance.
        self.phase = Phase::CreatingFilesystem;
        let mapping = self.mapping();
        let text = mapping.to_str().ok_or_else(invalid)?;
        let filesystem_options = format!(
            "lazy_itable_init=0,lazy_journal_init=0,root_owner={}:{}",
            self.filesystem_owner.0, self.filesystem_owner.1
        );
        opener::run_bounded(
            "/usr/sbin/mkfs.ext4",
            &[
                "-q",
                "-F",
                "-U",
                &self.uuid,
                "-E",
                &filesystem_options,
                text,
            ],
            &[],
            None,
            Duration::from_secs(90),
        )?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(mapping)?;
        let mut superblock = [0u8; 1024];
        file.read_exact_at(&mut superblock, 1024)?;
        if superblock[56..58] != [0x53, 0xef] || superblock[104..120] != uuid_bytes(&self.uuid)? {
            return Err(invalid().into());
        }
        file.sync_all()?;
        self.phase = Phase::Filesystem;
        Ok(self.uuid.clone())
    }
    pub fn barrier(&mut self) -> Result<()> {
        if self.phase != Phase::Filesystem {
            return Err(invalid().into());
        }
        self.close_mappings()?;
        self.device.file.sync_all()?;
        let mut bytes = vec![0; profile::HEADER_BYTES];
        self.device.file.read_exact_at(&mut bytes, 0)?;
        if sha(&bytes) != self.header_sha256()? {
            return Err(invalid().into());
        }
        Ok(())
    }
    fn mapping(&self) -> PathBuf {
        PathBuf::from("/dev/mapper").join(&self.name)
    }
    pub fn close_mappings(&mut self) -> Result<()> {
        if self.phase == Phase::Closed {
            return Ok(());
        }
        self.phase = Phase::Closing;
        let top = opener::owned_mapping(&self.name, &self.uuid, false)?;
        let lower = opener::owned_mapping(&self.name, &self.uuid, true)?;
        if top.is_some() {
            opener::run("/usr/sbin/cryptsetup", &["close", &self.name], &[], None)?;
        }
        if lower.is_some() && opener::owned_mapping(&self.name, &self.uuid, true)?.is_some() {
            opener::run(
                "/usr/sbin/cryptsetup",
                &["close", &format!("{}_dif", self.name)],
                &[],
                None,
            )?;
        }
        if opener::lookup(&self.name)?.is_some()
            || opener::lookup(&format!("{}_dif", self.name))?.is_some()
        {
            return Err(invalid().into());
        }
        self.phase = Phase::Closed;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn device() -> BlockDevice {
        let fd = unsafe { libc::memfd_create(c"initializer-fixture".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0);
        let file = unsafe { File::from_raw_fd(fd) };
        file.set_len(64 * 1024 * 1024).unwrap();
        // Synthetic file only; production BlockDevice::from_file rejects it.
        BlockDevice {
            file,
            id: "7:0".into(),
            bytes: 64 * 1024 * 1024,
        }
    }
    #[test]
    fn scans_entire_device_and_rejects_geometry_mismatch() {
        let d = device();
        Initializer::check_blank(&d, d.bytes).unwrap();
        assert!(Initializer::check_blank(&d, d.bytes - 4096).is_err());
        d.file.write_all_at(&[1], d.bytes - 1).unwrap();
        assert!(Initializer::check_blank(&d, d.bytes).is_err());
    }
    #[test]
    fn uncertain_steps_cannot_be_reexecuted_or_skipped() {
        let mut x = Initializer {
            filesystem_owner: (1000, 1000),
            device: device(),
            uuid: "be000000-1111-4222-8333-444444444444".into(),
            name: "not-used-by-tests".into(),
            header: None,
            digest: None,
            phase: Phase::Fresh,
        };
        assert!(x.initialize_integrity(&[0; 32]).is_err());
        assert!(x.create_filesystem().is_err());
        assert!(x.barrier().is_err());
        x.phase = Phase::Formatting;
        assert!(x.format(&[0; 32]).is_err());
        x.phase = Phase::Opening;
        assert!(x.initialize_integrity(&[0; 32]).is_err());
        x.phase = Phase::CreatingFilesystem;
        assert!(x.create_filesystem().is_err());
        assert!(x.barrier().is_err());
        x.phase = Phase::Closed;
        assert!(x.format(&[0; 32]).is_err());
    }
    #[test]
    fn mapping_identity_rejects_noncanonical_uuid_or_path() {
        for bad in [
            "../../dev/sda",
            "BE000000-1111-4222-8333-444444444444",
            "be0000001111-4222-8333-444444444444",
            "",
        ] {
            assert!(uuid_bytes(bad).is_err());
        }
        assert_eq!(
            uuid_bytes("be000000-1111-4222-8333-444444444444").unwrap()[0],
            0xbe
        );
    }
}

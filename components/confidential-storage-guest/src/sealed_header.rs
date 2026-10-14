// SPDX-License-Identifier: Apache-2.0
//! Linux-only immutable, anonymous copy of an authenticated LUKS2 header.
use crate::{
    profile::{RwManifest, HEADER_BYTES},
    receipt::VerifiedGrant,
};
use std::{
    fs::File,
    io::Write,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd},
        unix::fs::FileExt,
    },
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Validation(#[from] crate::profile::Error),
    #[error("failed to copy or seal authenticated header")]
    Io,
}
/// Not a mounted volume. This object neither fetches a key nor opens a mapping.
/// Keep it alive through cryptsetup open; never reread the host-controlled header.
pub struct PreparedHeader {
    manifest: RwManifest,
    header: File,
}
/// Read-only model header, authenticated before parsing and sealed before open.
pub struct PreparedRoHeader {
    manifest: crate::ro_profile::RoManifest,
    header: File,
}
impl PreparedRoHeader {
    pub fn prepare(
        grant: &VerifiedGrant,
        manifest: &[u8],
        source: &File,
        device_bytes: u64,
    ) -> Result<Self, Error> {
        let manifest = crate::ro_profile::RoManifest::verify(grant, manifest, device_bytes)?;
        let mut bytes = vec![0; HEADER_BYTES];
        source.read_exact_at(&mut bytes, 0).map_err(|_| Error::Io)?;
        manifest.validate_header(grant, &bytes)?;
        Ok(Self {
            manifest,
            header: seal(&bytes)?,
        })
    }
    pub fn manifest(&self) -> &crate::ro_profile::RoManifest {
        &self.manifest
    }
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.header.as_fd()
    }
}
impl PreparedHeader {
    /// `source` must be the retained descriptor from the guest's device resolver;
    /// `device_bytes` must be obtained from that same descriptor, not host JSON.
    /// File input also permits privilege-free header tests with ordinary files.
    pub fn prepare(
        grant: &VerifiedGrant,
        manifest: &[u8],
        source: &File,
        device_bytes: u64,
    ) -> Result<Self, Error> {
        let manifest = RwManifest::verify(grant, manifest, device_bytes)?;
        let mut bytes = vec![0; HEADER_BYTES];
        source.read_exact_at(&mut bytes, 0).map_err(|_| Error::Io)?;
        manifest.validate_header(grant, &bytes)?;
        let header = seal(&bytes)?;
        Ok(Self { manifest, header })
    }
    pub fn manifest(&self) -> &RwManifest {
        &self.manifest
    }
    /// The fd references a sealed memfd. It contains the authenticated encrypted
    /// keyslot/header bytes, not a Trustee key. The service must not export it.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.header.as_fd()
    }
}
pub(crate) fn seal(bytes: &[u8]) -> Result<File, Error> {
    // SAFETY: NUL-terminated static name, supported flags, no borrowed pointer
    // retained by the syscall. A successful fd is immediately owned by File.
    let fd = unsafe {
        libc::memfd_create(
            c"coco-luks-header".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(Error::Io);
    }
    // SAFETY: fresh uniquely owned descriptor from successful memfd_create.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes).map_err(|_| Error::Io)?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    // SAFETY: live owned fd and the integer mask expected by F_ADD_SEALS.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
        return Err(Error::Io);
    }
    // SAFETY: live owned fd; F_GET_SEALS takes no additional argument.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) } != seals {
        return Err(Error::Io);
    }
    Ok(file)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};
    #[test]
    fn kernel_seals_reject_write_truncate_and_growth() {
        let mut f = seal(b"authenticated ciphertext header").unwrap();
        assert!(f.write_at(b"changed", 0).is_err());
        assert!(f.set_len(0).is_err());
        assert!(f.set_len(1024).is_err());
        // SAFETY: no fixed address, live fd, valid page length; a writable shared
        // mapping must fail because F_SEAL_WRITE is already installed.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                f.as_raw_fd(),
                0,
            )
        };
        assert_eq!(mapping, libc::MAP_FAILED);
        f.seek(SeekFrom::Start(0)).unwrap();
        let mut content = String::new();
        f.read_to_string(&mut content).unwrap();
        assert_eq!(content, "authenticated ciphertext header");
        // FD_CLOEXEC prevents unrelated exec children inheriting the header.
        assert_eq!(
            unsafe { libc::fcntl(f.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            libc::FD_CLOEXEC
        );
    }
}

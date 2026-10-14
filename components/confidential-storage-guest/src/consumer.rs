// SPDX-License-Identifier: Apache-2.0
//! Agent-internal filesystem consumer. FDs must come from the trusted runtime,
//! before application startup, never from a host RPC or application PID string.
use crate::{
    guest_mount::{directory_at, mount_id, mount_info, secure_options_mode},
    receipt::VerifiedGrant,
};
use std::{
    ffi::CString,
    fs::{self, File},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
};

#[derive(Debug, thiserror::Error)]
#[error("consumer namespace, binding or mount operation failed")]
pub struct Error;
type Result<T> = std::result::Result<T, Error>;
type Identity = (u64, u64, u64);

enum State {
    Prepared,
    NeedsDetach { before: Identity, mount: u64 },
    Attached { before: Identity, mount: u64 },
    Detached,
}
pub(crate) struct Consumer {
    namespace: File,
    root: File,
    state: State,
    readonly: bool,
    destination: &'static str,
}
impl Consumer {
    pub(crate) fn new(
        g: &VerifiedGrant,
        namespace: File,
        root: File,
        container: &str,
    ) -> Result<Self> {
        binding(g, container)?;
        require_cloexec(&namespace)?;
        require_cloexec(&root)?;
        // SAFETY: read-only namespace-type ioctl on an owned fd (linux/nsfs.h).
        if unsafe { libc::ioctl(namespace.as_raw_fd(), 0xb703) } != libc::CLONE_NEWNS {
            return Err(Error);
        }
        let own = File::open("/proc/thread-self/ns/mnt").map_err(|_| Error)?;
        if object(&namespace)? == object(&own)? {
            return Err(Error);
        }
        trusted_directory(&root)?;
        Ok(Self {
            namespace,
            root,
            state: State::Prepared,
            readonly: g.claims().access == "ro",
            destination: if g.claims().access == "ro" {
                "models"
            } else {
                "data"
            },
        })
    }
    pub(crate) fn attach(&mut self, source: File) -> Result<()> {
        if !matches!(self.state, State::Prepared) {
            return Err(Error);
        }
        // A dedicated short-lived thread gets private FS state before setns.
        // No Tokio/runtime thread enters an application namespace.
        std::thread::scope(|scope| {
            scope
                .spawn(|| self.attach_worker(source))
                .join()
                .map_err(|_| Error)?
        })
    }
    fn attach_worker(&mut self, source: File) -> Result<()> {
        let source_identity = object(&source)?;
        // SAFETY: live directory fd, empty string, fixed non-recursive clone flags.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_open_tree,
                source.as_raw_fd(),
                c"".as_ptr(),
                1u32 | libc::O_CLOEXEC as u32 | libc::AT_EMPTY_PATH as u32,
            )
        };
        if fd < 0 {
            return Err(Error);
        }
        // SAFETY: fresh owned descriptor returned by open_tree.
        let tree = unsafe { File::from_raw_fd(fd as i32) };
        #[repr(C)]
        struct Attr {
            set: u64,
            clear: u64,
            propagation: u64,
            userns: u64,
        }
        let attr = Attr {
            set: 2 | 4 | 8 | if self.readonly { 1 } else { 0 },
            clear: 0,
            propagation: libc::MS_PRIVATE,
            userns: 0,
        };
        // SAFETY: fixed Linux mount_attr v0 layout and valid live descriptor.
        if unsafe {
            libc::syscall(
                libc::SYS_mount_setattr,
                tree.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH,
                &attr,
                std::mem::size_of::<Attr>(),
            )
        } != 0
        {
            return Err(Error);
        }
        self.enter()?;
        // A namespace cloned after activation may already contain plaintext
        // staging aliases. Never silently admit that namespace as a consumer.
        let device = format!(
            "{}:{}",
            libc::major(source_identity.0),
            libc::minor(source_identity.0)
        );
        let mounts = fs::read_to_string("/proc/thread-self/mountinfo").map_err(|_| Error)?;
        if mounts
            .lines()
            .any(|line| line.split_whitespace().nth(2) == Some(device.as_str()))
        {
            return Err(Error);
        }
        // Root fd must refer to a private mount present in this exact namespace.
        if !mount_info(mount_id(&self.root).map_err(|_| Error)?)
            .map_err(|_| Error)?
            .private
        {
            return Err(Error);
        }
        let target = directory_at(&self.root, self.destination).map_err(|_| Error)?;
        trusted_directory(&target)?;
        let before = identity(&target)?;
        if before.2 != mount_id(&self.root).map_err(|_| Error)? {
            return Err(Error);
        }
        let entries = fs::read_dir(format!("/proc/thread-self/fd/{}", target.as_raw_fd()))
            .map_err(|_| Error)?;
        if entries.count() != 0 {
            return Err(Error);
        }
        let mount = mount_id(&tree).map_err(|_| Error)?;
        self.state = State::NeedsDetach { before, mount };
        // SAFETY: both owned descriptors; only the detached filesystem is moved.
        if unsafe {
            libc::syscall(
                libc::SYS_move_mount,
                tree.as_raw_fd(),
                c"".as_ptr(),
                target.as_raw_fd(),
                c"".as_ptr(),
                0x4u32 | 0x40u32,
            )
        } != 0
        {
            return Err(Error);
        }
        let visible = directory_at(&self.root, self.destination).map_err(|_| Error)?;
        let info = mount_info(mount).map_err(|_| Error)?;
        if mount_id(&visible).map_err(|_| Error)? != mount
            || object(&visible)? != source_identity
            || info.fs != "ext4"
            || !info.private
            || !secure_options_mode(&info.options, self.readonly)
        {
            return Err(Error);
        }
        self.state = State::Attached { before, mount };
        Ok(())
    }
    pub(crate) fn detach(&mut self) -> Result<()> {
        if matches!(self.state, State::Detached) {
            return Ok(());
        }
        if matches!(self.state, State::Prepared) {
            self.state = State::Detached;
            return Ok(());
        }
        std::thread::scope(|scope| {
            scope
                .spawn(|| self.detach_worker())
                .join()
                .map_err(|_| Error)?
        })
    }
    fn detach_worker(&mut self) -> Result<()> {
        self.enter()?;
        let (before, mount) = match self.state {
            State::NeedsDetach { before, mount } | State::Attached { before, mount } => {
                (before, mount)
            }
            _ => return Err(Error),
        };
        self.state = State::NeedsDetach { before, mount };
        let current = directory_at(&self.root, self.destination).map_err(|_| Error)?;
        if identity(&current)? == before {
            // A failed move may have left only the original target. Require the
            // recorded mount ID to be absent everywhere in this namespace.
            if mount_present(mount)? {
                return Err(Error);
            }
        } else {
            if mount_id(&current).map_err(|_| Error)? != mount {
                return Err(Error);
            }
            drop(current);
            let target = CString::new(format!(
                "/proc/thread-self/fd/{}/{}",
                self.root.as_raw_fd(),
                self.destination
            ))
            .unwrap();
            // SAFETY: exact mount ID and retained root; no lazy/force flags.
            if unsafe { libc::umount2(target.as_ptr(), 0) } != 0 {
                return Err(Error);
            }
            let current = directory_at(&self.root, self.destination).map_err(|_| Error)?;
            if identity(&current)? != before || mount_present(mount)? {
                return Err(Error);
            }
        }
        self.state = State::Detached;
        Ok(())
    }
    fn enter(&self) -> Result<()> {
        // SAFETY: runs only on a dedicated thread. Private FS state prevents
        // namespace/root/cwd changes from affecting the service's other threads.
        if unsafe { libc::unshare(libc::CLONE_FS) } != 0
            || unsafe { libc::setns(self.namespace.as_raw_fd(), libc::CLONE_NEWNS) } != 0
        {
            return Err(Error);
        }
        Ok(())
    }
}
fn binding(g: &VerifiedGrant, container: &str) -> Result<()> {
    if g.claims().container_name != container
        || !matches!(
            (g.claims().access.as_str(), g.claims().destination.as_str()),
            ("rw", "/data") | ("ro", "/models")
        )
    {
        return Err(Error);
    }
    Ok(())
}
fn require_cloexec(file: &File) -> Result<()> {
    // SAFETY: query only on an owned live descriptor. Never pass inheritable
    // runtime descriptors into a manager that may coexist with app exec.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
        return Err(Error);
    }
    Ok(())
}
fn object(f: &File) -> Result<(u64, u64)> {
    let m = f.metadata().map_err(|_| Error)?;
    Ok((m.dev(), m.ino()))
}
fn identity(f: &File) -> Result<Identity> {
    let (dev, ino) = object(f)?;
    Ok((dev, ino, mount_id(f).map_err(|_| Error)?))
}
fn trusted_directory(f: &File) -> Result<()> {
    let m = f.metadata().map_err(|_| Error)?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err(Error);
    }
    Ok(())
}
fn mount_present(id: u64) -> Result<bool> {
    let text = fs::read_to_string("/proc/thread-self/mountinfo").map_err(|_| Error)?;
    Ok(text.lines().any(|s| {
        s.split_whitespace()
            .next()
            .and_then(|v| v.parse::<u64>().ok())
            == Some(id)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inherited_runtime_descriptors_are_rejected() {
        let file = File::open("/dev/null").unwrap();
        require_cloexec(&file).unwrap();
        // SAFETY: change only this disposable /dev/null descriptor's exec flag.
        assert_eq!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) },
            0
        );
        assert!(require_cloexec(&file).is_err());
    }
}

// SPDX-License-Identifier: Apache-2.0
//! Private guest staging mounts only. No application namespace entry or format.
use std::{
    ffi::CString,
    fs::{self, File},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{FileTypeExt, MetadataExt},
    },
    path::Path,
    sync::Arc,
};

#[derive(Debug, thiserror::Error)]
#[error("private guest mount operation or identity check failed")]
pub struct Error;
type Result<T> = std::result::Result<T, Error>;

/// Bootstrap must create /run/coco/storage, root-owned mode 0700, on private tmpfs.
/// Keep one trusted mount manager in this namespace; never give its paths to apps.
pub struct MountRoot(Arc<File>);
impl MountRoot {
    pub fn open() -> Result<Self> {
        let mut dir = File::open("/").map_err(|_| Error)?;
        for component in ["run", "coco", "storage"] {
            dir = directory_at(&dir, component)?;
            let m = dir.metadata().map_err(|_| Error)?;
            if m.uid() != 0 || m.mode() & 0o022 != 0 {
                return Err(Error);
            }
        }
        if dir.metadata().map_err(|_| Error)?.mode() & 0o777 != 0o700 {
            return Err(Error);
        }
        let info = mount_info(mount_id(&dir)?)?;
        if info.fs != "tmpfs" || !info.private {
            return Err(Error);
        }
        Ok(Self(Arc::new(dir)))
    }
    pub fn reserve(&self, id: &str) -> Result<GuestMount> {
        if !identifier(id) {
            return Err(Error);
        }
        let name = CString::new(id).map_err(|_| Error)?;
        // SAFETY: owned directory fd and NUL-terminated single path component.
        if unsafe { libc::mkdirat(self.0.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(Error); // Existing targets are never adopted or mounted over.
        }
        let before = directory_at(&self.0, id)?;
        if mount_id(&before)? != mount_id(&self.0)? {
            return Err(Error);
        }
        Ok(GuestMount {
            root: self.0.clone(),
            name,
            before,
            state: State::Empty,
            readonly: false,
        })
    }
}

#[derive(Clone, Copy)]
enum State {
    Empty,
    Uncertain,
    Mounted(u64),
    Removed,
}
pub struct GuestMount {
    root: Arc<File>,
    name: CString,
    before: File,
    state: State,
    readonly: bool,
}
impl GuestMount {
    pub(crate) fn verified_source(&self) -> Result<File> {
        let State::Mounted(id) = self.state else {
            return Err(Error);
        };
        let file = self.current()?;
        if mount_id(&file)? != id {
            return Err(Error);
        }
        let info = mount_info(id)?;
        if info.fs != "ext4" || !info.private || !secure_options_mode(&info.options, self.readonly)
        {
            return Err(Error);
        }
        Ok(file)
    }
    fn target(&self) -> CString {
        CString::new(format!(
            "/proc/self/fd/{}/{}",
            self.root.as_raw_fd(),
            self.name.to_str().unwrap()
        ))
        .unwrap()
    }
    fn current(&self) -> Result<File> {
        directory_at(&self.root, self.name.to_str().map_err(|_| Error)?)
    }
    fn is_original(&self, file: &File) -> Result<bool> {
        let a = file.metadata().map_err(|_| Error)?;
        let b = self.before.metadata().map_err(|_| Error)?;
        Ok(a.dev() == b.dev() && a.ino() == b.ino() && mount_id(file)? == mount_id(&self.before)?)
    }
    pub fn mount(&mut self, source: &Path) -> Result<()> {
        self.mount_mode(source, false)
    }
    pub fn mount_readonly(&mut self, source: &Path) -> Result<()> {
        self.mount_mode(source, true)
    }
    fn mount_mode(&mut self, source: &Path, readonly: bool) -> Result<()> {
        if !matches!(self.state, State::Empty) || !self.is_original(&self.current()?)? {
            return Err(Error);
        }
        // Source comes only from a successfully verified Opener in this guest.
        let source = File::open(source).map_err(|_| Error)?;
        let meta = source.metadata().map_err(|_| Error)?;
        if !meta.file_type().is_block_device() {
            return Err(Error);
        }
        let src = CString::new(format!("/proc/self/fd/{}", source.as_raw_fd())).unwrap();
        let target = self.target();
        self.readonly = readonly;
        self.state = State::Uncertain;
        // SAFETY: live descriptors, valid strings, fixed ext4 type/options.
        let rc = unsafe {
            libc::mount(
                src.as_ptr(),
                target.as_ptr(),
                c"ext4".as_ptr(),
                libc::MS_NODEV
                    | libc::MS_NOSUID
                    | libc::MS_NOEXEC
                    | if readonly { libc::MS_RDONLY } else { 0 },
                if readonly {
                    c"noload".as_ptr().cast()
                } else {
                    std::ptr::null()
                },
            )
        };
        let current = self.current()?;
        if self.is_original(&current)? {
            self.state = State::Empty;
            return Err(Error);
        }
        let id = mount_id(&current)?;
        // Record the new mount before post-validation so cleanup owns the effect.
        self.state = State::Mounted(id);
        let info = mount_info(id)?;
        if rc != 0
            || current.metadata().map_err(|_| Error)?.dev() != meta.rdev()
            || info.fs != "ext4"
            || !info.private
            || !secure_options_mode(&info.options, self.readonly)
        {
            return Err(Error);
        }
        Ok(())
    }
    /// No lazy/forced unmount. Busy or replaced targets retain ownership.
    pub fn unmount(&mut self) -> Result<()> {
        if matches!(self.state, State::Removed) {
            return Ok(());
        }
        let current = self.current()?;
        match self.state {
            State::Mounted(id) => {
                if mount_id(&current)? != id {
                    return Err(Error);
                }
                drop(current); // A live fd into the filesystem would keep it busy.
                let target = self.target();
                // SAFETY: validated owned target; flags 0 means ordinary unmount.
                if unsafe { libc::umount2(target.as_ptr(), 0) } != 0 {
                    return Err(Error);
                }
                self.state = State::Empty;
            }
            State::Empty | State::Uncertain => {
                if !self.is_original(&current)? {
                    return Err(Error);
                }
                self.state = State::Empty;
            }
            State::Removed => unreachable!(),
        }
        if !self.is_original(&self.current()?)? {
            return Err(Error);
        }
        // SAFETY: exact reserved directory; no recursive deletion.
        if unsafe {
            libc::unlinkat(
                self.root.as_raw_fd(),
                self.name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } != 0
        {
            return Err(Error);
        }
        self.state = State::Removed;
        Ok(())
    }
    pub fn removed(&self) -> bool {
        matches!(self.state, State::Removed)
    }
}

fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
pub(crate) fn directory_at(parent: &File, name: &str) -> Result<File> {
    let name = CString::new(name).map_err(|_| Error)?;
    // SAFETY: owned fd, valid string. Symlinks are refused at every component.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(Error);
    }
    // SAFETY: fresh owned descriptor from openat.
    Ok(unsafe { File::from_raw_fd(fd) })
}
pub(crate) fn mount_id(file: &File) -> Result<u64> {
    let text = fs::read_to_string(format!("/proc/thread-self/fdinfo/{}", file.as_raw_fd()))
        .map_err(|_| Error)?;
    let ids: Vec<_> = text
        .lines()
        .filter_map(|s| s.strip_prefix("mnt_id:"))
        .collect();
    if ids.len() != 1 {
        return Err(Error);
    }
    ids[0].trim().parse().map_err(|_| Error)
}
pub(crate) struct MountInfo {
    pub(crate) fs: String,
    pub(crate) options: String,
    pub(crate) private: bool,
}
fn parse_mount_info(text: &str, id: u64) -> Result<MountInfo> {
    let mut found = None;
    for line in text.lines() {
        let v: Vec<_> = line.split_whitespace().collect();
        if v.first().and_then(|s| s.parse::<u64>().ok()) != Some(id) {
            continue;
        }
        if found.is_some() || v.len() < 10 {
            return Err(Error);
        }
        let separator = v.iter().position(|s| *s == "-").ok_or(Error)?;
        if separator < 6 || separator + 4 != v.len() {
            return Err(Error);
        }
        found = Some(MountInfo {
            fs: v[separator + 1].into(),
            options: v[5].into(),
            private: separator == 6,
        }); // Reject shared/slave and unknown propagation fields.
    }
    found.ok_or(Error)
}
pub(crate) fn mount_info(id: u64) -> Result<MountInfo> {
    parse_mount_info(
        &fs::read_to_string("/proc/thread-self/mountinfo").map_err(|_| Error)?,
        id,
    )
}
#[cfg(test)]
fn secure_options(s: &str) -> bool {
    secure_options_mode(s, false)
}
pub(crate) fn secure_options_mode(s: &str, readonly: bool) -> bool {
    let options: std::collections::BTreeSet<_> = s.split(',').collect();
    [
        if readonly { "ro" } else { "rw" },
        "nodev",
        "nosuid",
        "noexec",
    ]
    .iter()
    .all(|s| options.contains(s))
        && !options.contains(if readonly { "rw" } else { "ro" })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn readonly_and_writable_mount_profiles_are_distinct() {
        assert!(secure_options_mode("ro,nodev,nosuid,noexec,relatime", true));
        assert!(!secure_options_mode("rw,nodev,nosuid,noexec", true));
        assert!(!secure_options_mode("ro,nodev,nosuid,noexec", false));
        assert!(!secure_options_mode("ro,rw,nodev,nosuid,noexec", true));
        for missing in ["nodev", "nosuid", "noexec"] {
            assert!(!secure_options_mode(
                &"ro,nodev,nosuid,noexec".replace(missing, ""),
                true
            ));
        }
    }
    #[test]
    fn mount_info_rejects_ambiguous_and_propagated_mounts() {
        let line = "42 1 254:1 / /private rw,nosuid,nodev,noexec - ext4 /dev/dm-0 rw";
        let info = parse_mount_info(line, 42).unwrap();
        assert!(info.private && secure_options(&info.options));
        assert!(
            !parse_mount_info(&line.replace(" - ", " shared:7 - "), 42)
                .unwrap()
                .private
        );
        assert!(
            !parse_mount_info(&line.replace(" - ", " master:7 - "), 42)
                .unwrap()
                .private
        );
        assert!(parse_mount_info(&format!("{line}\n{line}"), 42).is_err());
        assert!(parse_mount_info(line, 43).is_err());
        assert!(parse_mount_info("42 malformed", 42).is_err());
        for option in ["nodev", "nosuid", "noexec", "rw"] {
            assert!(!secure_options(&info.options.replace(option, "")));
        }
    }
    #[test]
    fn target_names_cannot_escape_root() {
        for name in ["", ".", "..", "../escape", "/data", "a/b", "a\0b"] {
            assert!(!identifier(name));
        }
        assert!(identifier("activation-1"));
        assert!(!identifier(&"a".repeat(129)));
    }
}

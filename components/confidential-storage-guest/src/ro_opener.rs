// SPDX-License-Identifier: Apache-2.0
//! Immutable ciphertext verity -> read-only LUKS mapping. Guest service only.
//! No formatting, key retrieval or authority release. Failed handles retain
//! ownership until ordinary close succeeds, including partially created stacks.
use crate::{
    opener::{lookup, now, read, run, slaves, BlockDevice, Error, Phase},
    receipt::VerifiedGrant,
    sealed_header::PreparedRoHeader,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    os::fd::AsRawFd,
    path::PathBuf,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Error>;

pub struct RoOpener {
    device: BlockDevice,
    header: PreparedRoHeader,
    grant: VerifiedGrant,
    name: String,
    phase: Phase,
    deadline: Instant,
}
impl RoOpener {
    pub fn prepare(grant: VerifiedGrant, manifest: &[u8], device: BlockDevice) -> Result<Self> {
        let now = now()?;
        grant.check_time(now).map_err(|_| Error::Authorization)?;
        let deadline = Instant::now() + Duration::from_secs(grant.claims().exp - now);
        let header = PreparedRoHeader::prepare(&grant, manifest, &device.file, device.bytes)
            .map_err(|_| Error::Authorization)?;
        let identity = format!(
            "{}\0{}\0{}",
            grant.claims().volume_id,
            grant.claims().session_sha256,
            grant.claims().activation_id
        );
        let hash = ring::digest::digest(&ring::digest::SHA256, identity.as_bytes());
        let name = format!(
            "coco-ro-{}",
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
    fn lower_name(&self) -> String {
        format!("{}-verity", self.name)
    }
    fn lower_uuid(&self) -> String {
        format!("COCO-VERITY-{}", self.name)
    }
    fn table(&self) -> String {
        let v = self.header.manifest().verity();
        format!(
            "0 {} verity 1 {} {} 4096 4096 {} {} sha256 {} {}",
            v.data_bytes() / 512,
            self.device.id,
            self.device.id,
            v.data_bytes() / 4096,
            v.hash_offset_bytes() / 4096,
            v.root(),
            v.salt()
        )
    }
    /// The trusted provider supplies this exact grant-bound credential. No key
    /// is written to a pathname, argv, environment, log or persistent keyring.
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
        self.phase = Phase::NeedsClose;
        // All table values come from the authenticated fixed profile and retained
        // block fd. No corruption-bypass, check-once, discard or recovery options.
        run(
            "/usr/sbin/dmsetup",
            &[
                "create",
                &self.lower_name(),
                "--uuid",
                &self.lower_uuid(),
                "--readonly",
                "--table",
                &self.table(),
            ],
            &[],
            None,
        )?;
        run(
            "/usr/sbin/dmsetup",
            &["mknodes", &self.lower_name()],
            &[],
            None,
        )?;
        self.verify_lower()?;
        let header_fd = self.header.as_fd().as_raw_fd();
        let header = format!("/proc/self/fd/{header_fd}");
        let lower = format!("/dev/mapper/{}", self.lower_name());
        run(
            "/usr/sbin/cryptsetup",
            &[
                "open",
                "--batch-mode",
                "--type",
                "luks2",
                "--readonly",
                "--disable-external-tokens",
                "--disable-keyring",
                "--header",
                &header,
                "--key-file",
                "-",
                "--keyfile-size",
                "32",
                &lower,
                &self.name,
            ],
            &[header_fd],
            Some(key),
        )?;
        self.verify_stack()?;
        self.phase = Phase::Open;
        Ok(())
    }
    pub fn mapping_path(&self) -> Result<PathBuf> {
        if self.phase != Phase::Open {
            return Err(Error::State);
        }
        Ok(PathBuf::from("/dev/mapper").join(&self.name))
    }
    pub fn close(&mut self) -> Result<()> {
        if self.phase == Phase::Closed {
            return Ok(());
        }
        if self.phase == Phase::Prepared {
            if lookup(&self.name)?.is_some() || lookup(&self.lower_name())?.is_some() {
                return Err(Error::Conflict);
            }
            self.phase = Phase::Closed;
            return Ok(());
        }
        self.phase = Phase::NeedsClose;
        // Validate both identities before removing either, including partial open.
        let top = self.owned(false)?;
        let lower = self.owned(true)?;
        if top.is_some() {
            run("/usr/sbin/cryptsetup", &["close", &self.name], &[], None)?;
        }
        if lower.is_some() && self.owned(true)?.is_some() {
            run(
                "/usr/sbin/dmsetup",
                &["remove", &self.lower_name()],
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
    fn owned(&self, lower: bool) -> Result<Option<PathBuf>> {
        let name = if lower {
            self.lower_name()
        } else {
            self.name.clone()
        };
        let Some(path) = lookup(&name)? else {
            return Ok(None);
        };
        let expected = if lower {
            self.lower_uuid()
        } else {
            format!(
                "CRYPT-LUKS2-{}-{name}",
                self.header.manifest().luks_uuid().replace('-', "")
            )
        };
        if read(path.join("dm/uuid"))? != expected {
            return Err(Error::Conflict);
        }
        Ok(Some(path))
    }
    fn verify_mapping(&self, lower: bool) -> Result<PathBuf> {
        let path = self.owned(lower)?.ok_or(Error::Stack)?;
        let name = if lower {
            self.lower_name()
        } else {
            self.name.clone()
        };
        if read(path.join("dm/suspended"))? != "0"
            || read(path.join("ro"))? != "1"
            || run(
                "/usr/sbin/dmsetup",
                &["info", "-c", "--noheadings", "-o", "segments", &name],
                &[],
                None,
            )?
            .trim()
                != "1"
        {
            return Err(Error::Stack);
        }
        Ok(path)
    }
    fn verify_lower(&self) -> Result<PathBuf> {
        let lower = self.verify_mapping(true)?;
        let actual = run(
            "/usr/sbin/dmsetup",
            &["table", "--target", "verity", &self.lower_name()],
            &[],
            None,
        )?;
        if actual.split_whitespace().collect::<Vec<_>>()
            != self.table().split_whitespace().collect::<Vec<_>>()
            || slaves(&lower)? != BTreeSet::from([self.device.id.clone()])
        {
            return Err(Error::Stack);
        }
        Ok(lower)
    }
    fn verify_stack(&self) -> Result<()> {
        let lower = self.verify_lower()?;
        let top = self.verify_mapping(false)?;
        if slaves(&top)? != BTreeSet::from([read(lower.join("dev"))?]) {
            return Err(Error::Stack);
        }
        let sectors = (self.header.manifest().verity().data_bytes()
            - crate::profile::HEADER_BYTES as u64)
            / 512;
        let status = run("/usr/sbin/cryptsetup", &["status", &self.name], &[], None)?;
        crypt_status(&status, &self.name, sectors)
        // Never query a dm-crypt table or --showkeys.
    }
}
fn crypt_status(text: &str, name: &str, sectors: u64) -> Result<()> {
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
    let required = [
        ("type", "LUKS2"),
        ("cipher", "aes-xts-plain64"),
        ("keysize", "512 bits"),
        ("key location", "dm-crypt"),
        ("sector size", "4096"),
        ("offset", "32768 sectors"),
        ("mode", "readonly"),
    ];
    if fields.len() != required.len() + 2
        || required.iter().any(|(k, v)| fields.get(k) != Some(v))
        || fields.get("size") != Some(&format!("{sectors} sectors").as_str())
        || !fields.contains_key("device")
    {
        return Err(Error::Stack);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn status_rejects_writable_or_wrong_geometry_stack() {
        let good = "/dev/mapper/test is active.\n type: LUKS2\n cipher: aes-xts-plain64\n keysize: 512 bits\n key location: dm-crypt\n sector size: 4096\n offset: 32768 sectors\n mode: readonly\n size: 4096 sectors\n device: /dev/mapper/test-verity\n";
        crypt_status(good, "test", 4096).unwrap();
        for (before, after) in [
            ("readonly", "read/write"),
            ("32768", "0"),
            ("512 bits", "768 bits"),
            ("4096 sectors", "8192 sectors"),
            ("LUKS2", "PLAIN"),
        ] {
            assert!(crypt_status(&good.replace(before, after), "test", 4096).is_err());
        }
        assert!(crypt_status(&format!("{good} flags: allow_discards\n"), "test", 4096).is_err());
        assert!(crypt_status(&format!("{good} mode: readonly\n"), "test", 4096).is_err());
    }
}

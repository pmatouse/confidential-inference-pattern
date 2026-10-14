// SPDX-License-Identifier: Apache-2.0
//! Root-private agent/service protocol. It carries no key or arbitrary command.
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

pub mod group;

pub const SOCKET: &str = "/run/coco/storage-service/agent.sock";
pub const CONFIG: &str = "/etc/confidential-storage/service.json";
pub const MAX_FRAME: usize = 16384;
pub const MAX_VOLUMES: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Attachment {
    pub binding_id: String,
    pub device_path: String,
    pub major: u32,
    pub minor: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MountedVolume {
    pub binding_id: String,
    pub source: String,
    pub destination: String,
    pub readonly: bool,
}
pub fn binding_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    ActivateMany {
        container_id: String,
        devices: Vec<Attachment>,
    },
    Activate {
        container_id: String,
        device_path: String,
        major: u32,
        minor: u32,
    },
    Close {
        container_id: String,
    },
}
impl Request {
    pub fn container(&self) -> &str {
        match self {
            Self::Activate { container_id, .. }
            | Self::ActivateMany { container_id, .. }
            | Self::Close { container_id } => container_id,
        }
    }
    pub fn validate(&self) -> io::Result<()> {
        let id = self.container();
        if id.len() != 64
            || !id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(invalid());
        }
        if let Self::Activate {
            device_path, major, ..
        } = self
        {
            let Some(suffix) = device_path.strip_prefix("/dev/sd") else {
                return Err(invalid());
            };
            if suffix.is_empty()
                || suffix.len() > 3
                || !suffix.bytes().all(|b| b.is_ascii_lowercase())
                || *major == 0
            {
                return Err(invalid());
            }
        }
        if let Self::ActivateMany {
            devices,
            container_id,
        } = self
        {
            if devices.is_empty() || devices.len() > MAX_VOLUMES {
                return Err(invalid());
            }
            let mut ids = std::collections::BTreeSet::new();
            let mut paths = std::collections::BTreeSet::new();
            let mut numbers = std::collections::BTreeSet::new();
            for device in devices {
                if !binding_id(&device.binding_id)
                    || !ids.insert(&device.binding_id)
                    || !paths.insert(&device.device_path)
                    || !numbers.insert((device.major, device.minor))
                {
                    return Err(invalid());
                }
                Self::Activate {
                    container_id: container_id.clone(),
                    device_path: device.device_path.clone(),
                    major: device.major,
                    minor: device.minor,
                }
                .validate()?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "result", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Response {
    MountedMany {
        mounts: Vec<MountedVolume>,
    },
    Mounted {
        source: String,
        destination: String,
        readonly: bool,
    },
    Closed,
    Denied,
}
pub fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "private storage protocol rejected",
    )
}
pub fn read_frame<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut size = [0; 4];
    reader.read_exact(&mut size)?;
    let n = u32::from_be_bytes(size) as usize;
    if n == 0 || n > MAX_FRAME {
        return Err(invalid());
    }
    let mut bytes = vec![0; n];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}
pub fn write_frame<W: Write>(writer: &mut W, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(invalid());
    }
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()
}

/// One immutable caller reservation for this guest lifetime. Validation and
/// retries never allow another container/device to inherit an uncertain effect.
#[derive(Default)]
pub struct Reservation {
    request: Option<Request>,
    closed: bool,
}
impl Reservation {
    pub fn reserve(&mut self, request: &Request) -> io::Result<()> {
        request.validate()?;
        if !matches!(
            request,
            Request::Activate { .. } | Request::ActivateMany { .. }
        ) || self.closed
        {
            return Err(invalid());
        }
        match &self.request {
            Some(old) if old != request => Err(invalid()),
            Some(_) => Ok(()),
            None => {
                self.request = Some(request.clone());
                Ok(())
            }
        }
    }
    pub fn check_close(&self, request: &Request) -> io::Result<()> {
        request.validate()?;
        if !matches!(request, Request::Close { .. })
            || self
                .request
                .as_ref()
                .is_none_or(|r| r.container() != request.container())
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn mark_closed(&mut self) {
        self.closed = true;
    }
    pub fn closed(&self) -> bool {
        self.closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn activate() -> Request {
        Request::Activate {
            container_id: "a".repeat(64),
            device_path: "/dev/sda".into(),
            major: 8,
            minor: 0,
        }
    }
    #[test]
    fn reservation_retains_failed_attempt_and_closed_tombstone() {
        let mut r = Reservation::default();
        let a = activate();
        r.reserve(&a).unwrap();
        r.reserve(&a).unwrap();
        let mut other = a.clone();
        if let Request::Activate { device_path, .. } = &mut other {
            *device_path = "/dev/sdb".into();
        }
        assert!(r.reserve(&other).is_err());
        assert!(r
            .check_close(&Request::Close {
                container_id: "b".repeat(64)
            })
            .is_err());
        let close = Request::Close {
            container_id: "a".repeat(64),
        };
        r.check_close(&close).unwrap();
        r.mark_closed();
        r.check_close(&close).unwrap();
        assert!(r.reserve(&a).is_err());
    }
    #[test]
    fn path_and_schema_cannot_select_arbitrary_files_or_commands() {
        for path in [
            "/dev/sda1",
            "/dev/mapper/x",
            "/dev/sda/../x",
            "/dev/sd",
            "/etc/shadow",
        ] {
            let mut a = activate();
            if let Request::Activate { device_path, .. } = &mut a {
                *device_path = path.into();
            }
            assert!(a.validate().is_err());
        }
        assert!(serde_json::from_str::<Request>(
            r#"{"action":"close","container_id":"x","command":"format"}"#
        )
        .is_err());
    }
    #[test]
    fn batch_protocol_rejects_duplicate_devices_ids_and_excess_count() {
        let base = vec![
            Attachment {
                binding_id: "a".into(),
                device_path: "/dev/sda".into(),
                major: 8,
                minor: 0,
            },
            Attachment {
                binding_id: "b".into(),
                device_path: "/dev/sdb".into(),
                major: 8,
                minor: 16,
            },
        ];
        let request = |devices| Request::ActivateMany {
            container_id: "a".repeat(64),
            devices,
        };
        request(base.clone()).validate().unwrap();
        assert!(request(vec![]).validate().is_err());
        assert!(request(vec![base[0].clone(); 9]).validate().is_err());
        for kind in 0..4 {
            let mut changed = base.clone();
            match kind {
                0 => changed[1].binding_id = changed[0].binding_id.clone(),
                1 => changed[1].device_path = changed[0].device_path.clone(),
                2 => changed[1].minor = changed[0].minor,
                _ => changed[1].device_path = "/dev/mapper/x".into(),
            }
            assert!(request(changed).validate().is_err());
        }
    }
    #[test]
    fn frames_are_bounded_and_truncation_rejected() {
        let mut v = Vec::new();
        write_frame(&mut v, b"test").unwrap();
        assert_eq!(read_frame(&mut v.as_slice()).unwrap(), b"test");
        assert!(read_frame(&mut &v[..v.len() - 1]).is_err());
        assert!(read_frame(&mut (MAX_FRAME as u32 + 1).to_be_bytes().as_slice()).is_err());
    }
}

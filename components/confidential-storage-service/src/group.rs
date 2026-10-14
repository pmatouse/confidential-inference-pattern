// SPDX-License-Identifier: Apache-2.0
//! All requested volumes must be mounted before any application bind is returned.
//! Cleanup is deliberately not rollback: uncertain initialization stays owned.
use crate::{invalid, MountedVolume, Request, Reservation, Response, MAX_VOLUMES};
use std::{collections::BTreeMap, io};

pub trait Backend {
    fn reserve(&mut self, request: &Request) -> io::Result<()>;
    fn activate(&mut self, request: &Request) -> io::Result<Response>;
    fn close(&mut self, request: &Request) -> io::Result<Response>;
}

pub struct Group<B> {
    backends: BTreeMap<String, B>,
    reservation: Reservation,
    closing: bool,
}
impl<B: Backend> Group<B> {
    pub fn new(backends: BTreeMap<String, B>) -> io::Result<Self> {
        if backends.is_empty()
            || backends.len() > MAX_VOLUMES
            || backends.keys().any(|id| !crate::binding_id(id))
        {
            return Err(invalid());
        }
        Ok(Self {
            backends,
            reservation: Reservation::default(),
            closing: false,
        })
    }
    pub fn handle(&mut self, request: &Request) -> io::Result<Response> {
        request.validate()?;
        match request {
            Request::ActivateMany {
                container_id,
                devices,
            } => {
                if self.closing
                    || devices.len() != self.backends.len()
                    || devices
                        .iter()
                        .any(|d| !self.backends.contains_key(&d.binding_id))
                {
                    return Err(invalid());
                }
                // Canonical order makes retries independent of JSON list order.
                let mut devices = devices.clone();
                devices.sort_by(|a, b| a.binding_id.cmp(&b.binding_id));
                self.reservation.reserve(&Request::ActivateMany {
                    container_id: container_id.clone(),
                    devices: devices.clone(),
                })?;
                let requests: Vec<_> = devices
                    .iter()
                    .map(|d| {
                        (
                            d.binding_id.clone(),
                            Request::Activate {
                                container_id: container_id.clone(),
                                device_path: d.device_path.clone(),
                                major: d.major,
                                minor: d.minor,
                            },
                        )
                    })
                    .collect();
                // No authority operation, key retrieval or disk effect until
                // every child has reserved its immutable container/device tuple.
                for (id, child) in &requests {
                    self.backends.get_mut(id).unwrap().reserve(child)?;
                }
                let mut mounts = Vec::new();
                for (id, child) in &requests {
                    let Response::Mounted {
                        source,
                        destination,
                        readonly,
                    } = self.backends.get_mut(id).unwrap().activate(child)?
                    else {
                        return Err(invalid());
                    };
                    mounts.push(MountedVolume {
                        binding_id: id.clone(),
                        source,
                        destination,
                        readonly,
                    });
                }
                Ok(Response::MountedMany { mounts })
            }
            Request::Close { .. } => {
                self.reservation.check_close(request)?;
                self.closing = true;
                if self.reservation.closed() {
                    return Ok(Response::Closed);
                }
                // Try every child even if one has uncertain state or busy mounts.
                // Never release that child's owner merely because peers closed.
                let mut failed = false;
                for backend in self.backends.values_mut().rev() {
                    if !matches!(backend.close(request), Ok(Response::Closed)) {
                        failed = true;
                    }
                }
                if failed {
                    return Err(invalid());
                }
                self.reservation.mark_closed();
                Ok(Response::Closed)
            }
            Request::Activate { .. } => Err(invalid()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Attachment;
    use std::{cell::RefCell, rc::Rc};
    struct Fake {
        id: String,
        events: Rc<RefCell<Vec<String>>>,
        fail_open: bool,
        fail_close: bool,
    }
    impl Backend for Fake {
        fn reserve(&mut self, _: &Request) -> io::Result<()> {
            self.events
                .borrow_mut()
                .push(format!("reserve:{}", self.id));
            Ok(())
        }
        fn activate(&mut self, _: &Request) -> io::Result<Response> {
            self.events.borrow_mut().push(format!("open:{}", self.id));
            if self.fail_open {
                return Err(invalid());
            }
            Ok(Response::Mounted {
                source: format!("/run/coco/storage/{}", self.id),
                destination: format!("/models/{}", self.id),
                readonly: true,
            })
        }
        fn close(&mut self, _: &Request) -> io::Result<Response> {
            self.events.borrow_mut().push(format!("close:{}", self.id));
            if self.fail_close {
                return Err(invalid());
            }
            Ok(Response::Closed)
        }
    }
    fn setup(
        fail_open: bool,
        fail_close: bool,
    ) -> (Group<Fake>, Request, Rc<RefCell<Vec<String>>>) {
        let events = Rc::new(RefCell::new(Vec::new()));
        let backends = ["a", "b"]
            .into_iter()
            .map(|id| {
                (
                    id.into(),
                    Fake {
                        id: id.into(),
                        events: events.clone(),
                        fail_open: fail_open && id == "b",
                        fail_close: fail_close && id == "b",
                    },
                )
            })
            .collect();
        let devices = ["a", "b"]
            .into_iter()
            .enumerate()
            .map(|(n, id)| Attachment {
                binding_id: id.into(),
                device_path: format!("/dev/sd{id}"),
                major: 8,
                minor: n as u32 * 16,
            })
            .collect();
        (
            Group::new(backends).unwrap(),
            Request::ActivateMany {
                container_id: "a".repeat(64),
                devices,
            },
            events,
        )
    }
    #[test]
    fn all_reserved_before_effects_and_no_partial_success() {
        let (mut g, r, e) = setup(true, false);
        assert!(g.handle(&r).is_err());
        assert_eq!(*e.borrow(), ["reserve:a", "reserve:b", "open:a", "open:b"]);
        assert_eq!(
            g.handle(&Request::Close {
                container_id: r.container().into()
            })
            .unwrap(),
            Response::Closed
        );
        assert!(g.handle(&r).is_err());
    }
    #[test]
    fn exact_set_device_binding_and_order_independent_retry() {
        let (mut g, r, e) = setup(false, false);
        let mut short = r.clone();
        if let Request::ActivateMany { devices, .. } = &mut short {
            devices.pop();
        }
        assert!(g.handle(&short).is_err());
        assert!(e.borrow().is_empty());
        let first = g.handle(&r).unwrap();
        let mut reordered = r.clone();
        if let Request::ActivateMany { devices, .. } = &mut reordered {
            devices.reverse();
        }
        assert_eq!(g.handle(&reordered).unwrap(), first);
        if let Request::ActivateMany { devices, .. } = &mut reordered {
            devices[0].minor += 1;
        }
        assert!(g.handle(&reordered).is_err());
    }
    #[test]
    fn cleanup_attempts_every_child_but_never_reopens_after_failure() {
        let (mut g, r, e) = setup(false, true);
        g.handle(&r).unwrap();
        assert!(g
            .handle(&Request::Close {
                container_id: "b".repeat(64)
            })
            .is_err());
        let close = Request::Close {
            container_id: r.container().into(),
        };
        assert!(g.handle(&close).is_err());
        assert!(e.borrow().ends_with(&["close:b".into(), "close:a".into()]));
        assert!(g.handle(&r).is_err());
        assert!(g.handle(&close).is_err());
    }
}

#![forbid(unsafe_code)]
//! Bounded, untrusted BlueZ device-claim reconciliation.
//!
//! This is an epoch-local projection, not camera authentication or a coverage
//! witness. The owner must bind it to a live, independently admitted watch and
//! call `mark_gap` when that watch is interrupted, retired or replaced.

use super::bluez_bus::{ChangeFrame, DeviceClaim, WatchInventory};
use fss_packet::{
    dbus_bluez_signal::{self, Event},
    dbus_handshake,
    dbus_object_manager::ServiceChange,
};
use std::fmt;

const MAX_DEVICES: usize = 128;
const MAX_SERVICES: usize = 32;

/// Refusal; a failed event application permanently marks the epoch as gapped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The caller supplied invalid or inconsistent epoch inputs.
    Configuration,
    /// Changes overlapped the snapshot and require reconciliation first.
    SnapshotOverlap,
    /// The bounded registry or an allocation was exhausted.
    Limit,
    /// A change cannot be reconciled with the current projection.
    Inconsistent,
    /// The frame was not valid for the independently supplied bus owner.
    Signal(dbus_bluez_signal::Error),
    /// The projection is already gapped and requires a fresh snapshot.
    Gap,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlueZ registry refused: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Interpretation of a service-list observation, never an identity decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Assessment {
    /// A present device claimed one of the configured candidate services.
    CandidateClaim,
    /// The observed list did not contain a configured service.
    NonmatchingClaim,
    /// No usable service-list observation exists.
    Unknown,
    /// A Device1 removal was observed; this is not proof of physical absence.
    RemovedClaim,
    /// Continuity was lost; no current interpretation is available.
    Gap,
}

#[derive(Clone, Copy)]
enum Services {
    Unknown,
    Candidate,
    Nonmatching,
}
struct Entry {
    path: String,
    present: bool,
    services: Services,
}

/// One in-memory, bounded view of one adapter in one owner epoch.
pub struct Registry {
    owner: String,
    adapter: String,
    services: Vec<String>,
    entries: Vec<Entry>,
    gapped: bool,
}
impl fmt::Debug for Registry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registry")
            .field("entries", &self.entries.len())
            .field("gapped", &self.gapped)
            .finish_non_exhaustive()
    }
}

fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, byte)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}
fn adapter_path(value: &str) -> bool {
    value.strip_prefix("/org/bluez/hci").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.len() <= 8 && suffix.bytes().all(|b| b.is_ascii_digit())
    })
}
fn device_path(adapter: &str, path: &str) -> bool {
    path.strip_prefix(adapter)
        .and_then(|tail| tail.strip_prefix("/dev_"))
        .is_some_and(|tail| {
            tail.len() == 17
                && tail.bytes().enumerate().all(|(i, byte)| {
                    if matches!(i, 2 | 5 | 8 | 11 | 14) {
                        byte == b'_'
                    } else {
                        byte.is_ascii_hexdigit()
                    }
                })
        })
}
fn under_adapter(adapter: &str, path: &str) -> bool {
    path.strip_prefix(adapter)
        .is_some_and(|tail| tail.starts_with('/'))
}
fn owned(value: &str) -> Result<String, Error> {
    let mut result = String::new();
    result
        .try_reserve_exact(value.len())
        .map_err(|_| Error::Limit)?;
    result.push_str(value);
    Ok(result)
}

impl Registry {
    /// Start with one no-overlap snapshot from an independently admitted watch.
    /// Candidate UUIDs are caller policy, not a complete UniFi model catalog.
    pub fn new(
        owner: &str,
        adapter: &str,
        snapshot: WatchInventory,
        candidate_services: &[&str],
    ) -> Result<Self, Error> {
        if snapshot.overlapping_changes != 0 {
            return Err(Error::SnapshotOverlap);
        }
        if dbus_handshake::bluez_managed_objects_for_owner(1, owner).is_err()
            || !adapter_path(adapter)
            || !snapshot.adapter_paths.iter().any(|path| path == adapter)
            || candidate_services.is_empty()
            || candidate_services.len() > MAX_SERVICES
            || candidate_services.iter().any(|service| !uuid(service))
            || candidate_services.iter().enumerate().any(|(i, service)| {
                candidate_services[..i]
                    .iter()
                    .any(|old| old.eq_ignore_ascii_case(service))
            })
            || snapshot.device_paths.len() != snapshot.device_claims.len()
        {
            return Err(Error::Configuration);
        }
        let mut services = Vec::new();
        services
            .try_reserve_exact(candidate_services.len())
            .map_err(|_| Error::Limit)?;
        for service in candidate_services {
            services.push(owned(service)?);
        }
        let mut result = Self {
            owner: owned(owner)?,
            adapter: owned(adapter)?,
            services,
            entries: Vec::new(),
            gapped: false,
        };
        for (path, claim) in snapshot.device_paths.iter().zip(snapshot.device_claims) {
            if path != &claim.path {
                return Err(Error::Configuration);
            }
            if device_path(adapter, path) {
                result.add_snapshot(claim)?;
            } else if under_adapter(adapter, path) {
                return Err(Error::Configuration);
            }
        }
        Ok(result)
    }

    fn classify<'a>(&self, values: impl IntoIterator<Item = &'a str>) -> Services {
        if values.into_iter().any(|value| {
            self.services
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(value))
        }) {
            Services::Candidate
        } else {
            Services::Nonmatching
        }
    }
    fn add_snapshot(&mut self, claim: DeviceClaim) -> Result<(), Error> {
        if self.entries.len() == MAX_DEVICES {
            return Err(Error::Limit);
        }
        if self.entries.iter().any(|entry| entry.path == claim.path) {
            return Err(Error::Configuration);
        }
        let services = match &claim.service_uuids {
            Some(values) => self.classify(values.iter().map(String::as_str)),
            None => Services::Unknown,
        };
        self.entries.try_reserve(1).map_err(|_| Error::Limit)?;
        self.entries.push(Entry {
            path: claim.path,
            present: true,
            services,
        });
        Ok(())
    }

    /// Permanently invalidate the projection after session or coverage loss.
    pub fn mark_gap(&mut self) {
        self.gapped = true;
    }

    /// Number of path claims retained, including observed removals.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// Whether no path claims are retained; this never proves device absence.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Whether the caller must obtain a fresh snapshot before using claims.
    pub fn is_gapped(&self) -> bool {
        self.gapped
    }
    /// The claimed path at an index; it is sensitive and not an identity proof.
    pub fn path(&self, index: usize) -> Option<&str> {
        self.entries.get(index).map(|e| e.path.as_str())
    }
    /// Interpret a retained claim without turning unknown or gaps into negatives.
    pub fn assess(&self, index: usize) -> Option<Assessment> {
        let entry = self.entries.get(index)?;
        Some(if self.gapped {
            Assessment::Gap
        } else if !entry.present {
            Assessment::RemovedClaim
        } else {
            match entry.services {
                Services::Unknown => Assessment::Unknown,
                Services::Candidate => Assessment::CandidateClaim,
                Services::Nonmatching => Assessment::NonmatchingClaim,
            }
        })
    }

    /// Apply one already received frame after revalidating its sender and scope.
    /// Any refusal invalidates the entire projection until a new snapshot.
    pub fn apply(&mut self, frame: &ChangeFrame) -> Result<(), Error> {
        if self.gapped {
            return Err(Error::Gap);
        }
        let result = frame
            .decode(&self.owner)
            .map_err(Error::Signal)
            .and_then(|event| self.apply_event(event));
        if result.is_err() {
            self.gapped = true;
        }
        result
    }

    fn apply_event(&mut self, event: Event<'_>) -> Result<(), Error> {
        match event {
            Event::Added(added) => {
                let Some(claim) = added.device else {
                    return Ok(());
                };
                if !under_adapter(&self.adapter, added.path) {
                    return Ok(());
                }
                if !device_path(&self.adapter, added.path) {
                    return Err(Error::Inconsistent);
                }
                let values = claim.service_uuids();
                let services = match values {
                    Some(values) => self.classify(values.iter().copied()),
                    None => Services::Unknown,
                };
                if let Some(entry) = self
                    .entries
                    .iter_mut()
                    .find(|entry| entry.path == added.path)
                {
                    if entry.present {
                        return Err(Error::Inconsistent);
                    }
                    entry.present = true;
                    entry.services = services;
                } else {
                    if self.entries.len() == MAX_DEVICES {
                        return Err(Error::Limit);
                    }
                    let path = owned(added.path)?;
                    self.entries.try_reserve(1).map_err(|_| Error::Limit)?;
                    self.entries.push(Entry {
                        path,
                        present: true,
                        services,
                    });
                }
            }
            Event::Removed(removed) => {
                if !removed.interfaces().contains(&"org.bluez.Device1")
                    || !under_adapter(&self.adapter, removed.path)
                {
                    return Ok(());
                }
                if !device_path(&self.adapter, removed.path) {
                    return Err(Error::Inconsistent);
                }
                let entry = self
                    .entries
                    .iter_mut()
                    .find(|entry| entry.path == removed.path && entry.present)
                    .ok_or(Error::Inconsistent)?;
                entry.present = false;
                entry.services = Services::Unknown;
            }
            Event::Properties { path, change } => {
                if change.interface != "org.bluez.Device1" || !under_adapter(&self.adapter, path) {
                    return Ok(());
                }
                if !device_path(&self.adapter, path) {
                    return Err(Error::Inconsistent);
                }
                let replacement = match change.services {
                    ServiceChange::Unchanged => None,
                    ServiceChange::Invalidated => Some(Services::Unknown),
                    ServiceChange::Present(values) => Some(self.classify(values)),
                };
                let entry = self
                    .entries
                    .iter_mut()
                    .find(|entry| entry.path == path && entry.present)
                    .ok_or(Error::Inconsistent)?;
                if let Some(services) = replacement {
                    entry.services = services;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unifi_direct::bluez_bus::test_change_frame;
    use fss_packet::dbus_object_manager::PropertiesChanged;

    const SERVICE: &str = "0c430d0c-00ef-4367-bc6f-ca7c51e6b61f";
    const DEVICE: &str = "/org/bluez/hci1/dev_AA_BB_CC_DD_EE_FF";

    fn snapshot(services: Option<Vec<String>>, overlapping_changes: usize) -> WatchInventory {
        WatchInventory {
            adapter_paths: vec!["/org/bluez/hci1".into()],
            device_paths: vec![DEVICE.into()],
            device_claims: vec![DeviceClaim {
                path: DEVICE.into(),
                service_uuids: services,
            }],
            objects: 2,
            overlapping_changes,
        }
    }
    fn changed<'a>(path: &'a str, services: ServiceChange<'a>) -> Event<'a> {
        Event::Properties {
            path,
            change: PropertiesChanged {
                interface: "org.bluez.Device1",
                services,
            },
        }
    }

    struct Writer(Vec<u8>);
    impl Writer {
        fn pad(&mut self, alignment: usize) {
            while self.0.len() % alignment != 0 {
                self.0.push(0);
            }
        }
        fn number(&mut self, value: u32) {
            self.pad(4);
            self.0.extend_from_slice(&value.to_le_bytes());
        }
        fn string(&mut self, value: &str) {
            self.number(value.len() as u32);
            self.0.extend_from_slice(value.as_bytes());
            self.0.push(0);
        }
        fn array(&mut self, alignment: usize) -> (usize, usize) {
            self.pad(4);
            let start = self.0.len();
            self.number(0);
            self.pad(alignment);
            (start, self.0.len())
        }
        fn finish(&mut self, (at, start): (usize, usize)) {
            let len = (self.0.len() - start) as u32;
            self.0[at..at + 4].copy_from_slice(&len.to_le_bytes());
        }
        fn field(&mut self, code: u8, kind: u8, value: &str) {
            self.pad(8);
            self.0.extend_from_slice(&[code, 1, kind, 0]);
            self.string(value);
        }
    }
    fn frame(
        sender: &str,
        path: &str,
        interface: &str,
        member: &str,
        signature: &str,
        body: &[u8],
    ) -> ChangeFrame {
        let mut w = Writer(b"l\x04\x00\x01".to_vec());
        w.number(body.len() as u32);
        w.number(23);
        w.number(0);
        w.field(1, b'o', path);
        w.field(2, b's', interface);
        w.field(3, b's', member);
        w.field(7, b's', sender);
        w.pad(8);
        w.0.extend_from_slice(&[8, 1, b'g', 0, signature.len() as u8]);
        w.0.extend_from_slice(signature.as_bytes());
        w.0.push(0);
        let fields = (w.0.len() - 16) as u32;
        w.0[12..16].copy_from_slice(&fields.to_le_bytes());
        w.pad(8);
        w.0.extend_from_slice(body);
        test_change_frame(w.0)
    }
    fn add_frame(sender: &str) -> ChangeFrame {
        let mut body = Writer(Vec::new());
        body.string(DEVICE);
        let interfaces = body.array(8);
        body.pad(8);
        body.string("org.bluez.Device1");
        let properties = body.array(8);
        body.finish(properties);
        body.finish(interfaces);
        frame(
            sender,
            "/",
            "org.freedesktop.DBus.ObjectManager",
            "InterfacesAdded",
            "oa{sa{sv}}",
            &body.0,
        )
    }
    fn remove_frame() -> ChangeFrame {
        let mut body = Writer(Vec::new());
        body.string(DEVICE);
        let interfaces = body.array(4);
        body.string("org.bluez.Device1");
        body.finish(interfaces);
        frame(
            ":1.42",
            "/",
            "org.freedesktop.DBus.ObjectManager",
            "InterfacesRemoved",
            "oas",
            &body.0,
        )
    }
    fn service_frame() -> ChangeFrame {
        service_frame_for(DEVICE)
    }
    fn service_frame_for(path: &str) -> ChangeFrame {
        let mut body = Writer(Vec::new());
        body.string("org.bluez.Device1");
        let properties = body.array(8);
        body.pad(8);
        body.string("UUIDs");
        body.0.extend_from_slice(&[2, b'a', b's', 0]);
        let values = body.array(4);
        body.string(SERVICE);
        body.finish(values);
        body.finish(properties);
        let invalidated = body.array(4);
        body.finish(invalidated);
        frame(
            ":1.42",
            path,
            "org.freedesktop.DBus.Properties",
            "PropertiesChanged",
            "sa{sv}as",
            &body.0,
        )
    }

    #[test]
    fn scoped_wire_events_reconcile_and_wrong_owner_invalidates() -> Result<(), Error> {
        let empty = WatchInventory {
            adapter_paths: vec!["/org/bluez/hci1".into()],
            device_paths: vec![],
            device_claims: vec![],
            objects: 1,
            overlapping_changes: 0,
        };
        let mut registry = Registry::new(":1.42", "/org/bluez/hci1", empty, &[SERVICE])?;
        registry.apply(&add_frame(":1.42"))?;
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.assess(0), Some(Assessment::Unknown));
        registry.apply(&service_frame())?;
        assert_eq!(registry.assess(0), Some(Assessment::CandidateClaim));
        registry.apply(&remove_frame())?;
        assert_eq!(registry.assess(0), Some(Assessment::RemovedClaim));
        registry.apply(&add_frame(":1.42"))?;
        assert_eq!(registry.assess(0), Some(Assessment::Unknown));
        assert!(matches!(
            registry.apply(&add_frame(":1.99")),
            Err(Error::Signal(dbus_bluez_signal::Error::OutsideScope))
        ));
        assert_eq!(registry.assess(0), Some(Assessment::Gap));
        assert_eq!(registry.apply(&service_frame()), Err(Error::Gap));
        let mut other = Registry::new(":1.42", "/org/bluez/hci1", snapshot(None, 0), &[SERVICE])?;
        assert_eq!(
            other.apply(&service_frame_for("/org/bluez/hci1/dev_bad")),
            Err(Error::Inconsistent)
        );
        assert_eq!(other.assess(0), Some(Assessment::Gap));
        Ok(())
    }

    #[test]
    fn observed_service_changes_preserve_unknown_and_gap() -> Result<(), Error> {
        let mut registry =
            Registry::new(":1.42", "/org/bluez/hci1", snapshot(None, 0), &[SERVICE])?;
        assert_eq!(registry.assess(0), Some(Assessment::Unknown));
        registry.apply_event(changed(
            DEVICE,
            ServiceChange::Present(vec!["0C430D0C-00EF-4367-BC6F-CA7C51E6B61F"]),
        ))?;
        assert_eq!(registry.assess(0), Some(Assessment::CandidateClaim));
        registry.apply_event(changed(DEVICE, ServiceChange::Unchanged))?;
        assert_eq!(registry.assess(0), Some(Assessment::CandidateClaim));
        registry.apply_event(changed(DEVICE, ServiceChange::Invalidated))?;
        assert_eq!(registry.assess(0), Some(Assessment::Unknown));
        registry.apply_event(changed(DEVICE, ServiceChange::Present(Vec::new())))?;
        assert_eq!(registry.assess(0), Some(Assessment::NonmatchingClaim));
        registry.mark_gap();
        assert_eq!(registry.assess(0), Some(Assessment::Gap));
        assert!(!format!("{registry:?}").contains("AA_BB"));
        Ok(())
    }

    #[test]
    fn overlapping_or_untrusted_inputs_do_not_create_a_current_projection() -> Result<(), Error> {
        let mut malformed = snapshot(None, 0);
        malformed.device_paths[0] = "/org/bluez/hci1/dev_bad".into();
        malformed.device_claims[0].path = malformed.device_paths[0].clone();
        assert!(matches!(
            Registry::new(":1.42", "/org/bluez/hci1", malformed, &[SERVICE]),
            Err(Error::Configuration)
        ));
        assert!(matches!(
            Registry::new(":1.42", "/org/bluez/hci1", snapshot(None, 1), &[SERVICE]),
            Err(Error::SnapshotOverlap)
        ));
        assert!(matches!(
            Registry::new(
                "org.bluez",
                "/org/bluez/hci1",
                snapshot(None, 0),
                &[SERVICE]
            ),
            Err(Error::Configuration)
        ));
        assert!(matches!(
            Registry::new(":1.42", "/org/bluez/hci1", snapshot(None, 0), &["bad"]),
            Err(Error::Configuration)
        ));
        assert!(matches!(
            Registry::new(
                ":1.42",
                "/org/bluez/hci1",
                snapshot(None, 0),
                &[SERVICE, SERVICE]
            ),
            Err(Error::Configuration)
        ));
        let registry = Registry::new(
            ":1.42",
            "/org/bluez/hci1",
            snapshot(Some(vec![SERVICE.into()]), 0),
            &[SERVICE],
        )?;
        assert_eq!(registry.assess(0), Some(Assessment::CandidateClaim));
        assert_eq!(registry.path(0), Some(DEVICE));
        assert_eq!(registry.assess(1), None);
        Ok(())
    }
}

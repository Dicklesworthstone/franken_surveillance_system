#![forbid(unsafe_code)]
//! Scoped, sans-I/O decoding of untrusted BlueZ change signals.
//!
//! A caller must independently establish the bus and current unique BlueZ owner,
//! install and supervise its subscription, and preserve any coverage gaps. This
//! module neither opens a bus session nor proves camera identity or reachability.

use crate::{dbus_handshake as wire, dbus_object_manager as objects};
use std::fmt;

const MAX_SCOPE: usize = 1024;

/// Payload-free refusal. No variant implies that a device is absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Expected sender or path scope is invalid.
    InvalidScope,
    /// The frame is incomplete or contains trailing bytes.
    FrameBoundary,
    /// The restricted signal framing profile rejected the frame.
    Frame(wire::Error),
    /// Sender or path does not match the independently supplied scope.
    OutsideScope,
    /// The signal or its claimed signature is outside this exact profile.
    Unsupported,
    /// The selected signal body is malformed or exceeds a bound.
    Body(objects::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlueZ signal refused: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Current, independently admitted unique sender and object namespace.
/// These fields are caller authority, not established by this parser.
pub struct Scope<'a> {
    /// Expected D-Bus unique owner, such as a separately resolved `:1.42`.
    pub owner: &'a str,
    /// Allowed BlueZ object subtree, as a complete object path.
    pub namespace: &'a str,
    /// Exact ObjectManager signal path, typically the manager root.
    pub manager_path: &'a str,
}

/// One structurally validated, scoped change claim; it is not a coverage proof.
pub enum Event<'a> {
    /// One or more interfaces were reported added to an object.
    Added(objects::InterfacesAdded<'a>),
    /// One or more interfaces were reported removed from an object.
    Removed(objects::InterfacesRemoved<'a>),
    /// Properties were reported changed on the signal header's object.
    Properties {
        /// Scoped object path from the signal header.
        path: &'a str,
        /// Bounded property changes from the signal body.
        change: objects::PropertiesChanged<'a>,
    },
}
impl fmt::Debug for Event<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Added(value) => f.debug_tuple("Added").field(value).finish(),
            Self::Removed(value) => f.debug_tuple("Removed").field(value).finish(),
            Self::Properties { change, .. } => f
                .debug_struct("Properties")
                .field("change", change)
                .finish_non_exhaustive(),
        }
    }
}
fn object_path(path: &str) -> bool {
    path == "/"
        || (path.starts_with('/')
            && !path.ends_with('/')
            && path[1..].split('/').all(|part| {
                !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            }))
}
fn unique_name(name: &str) -> bool {
    name.strip_prefix(':').is_some_and(|rest| {
        rest.contains('.')
            && rest.split('.').all(|part| {
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            })
    })
}
fn within(path: &str, namespace: &str) -> bool {
    namespace == "/"
        || path == namespace
        || path
            .strip_prefix(namespace)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Decode one exact frame under the caller's independently verified scope.
/// Unexpected or out-of-scope frames are returned as refusals, never silently
/// discarded; the owner decides whether its observation coverage has a gap.
pub fn parse<'a>(frame: &'a [u8], scope: &Scope<'_>) -> Result<Event<'a>, Error> {
    if scope.owner.len() > MAX_SCOPE
        || scope.namespace.len() > MAX_SCOPE
        || scope.manager_path.len() > MAX_SCOPE
        || !unique_name(scope.owner)
        || !object_path(scope.namespace)
        || !object_path(scope.manager_path)
    {
        return Err(Error::InvalidScope);
    }
    let signal = wire::parse_signal(frame)
        .map_err(Error::Frame)?
        .ok_or(Error::FrameBoundary)?;
    if signal.consumed != frame.len() {
        return Err(Error::FrameBoundary);
    }
    if signal.sender != scope.owner {
        return Err(Error::OutsideScope);
    }
    let endian = if signal.little_endian {
        objects::Endian::Little
    } else {
        objects::Endian::Big
    };
    match (signal.interface, signal.member, signal.signature) {
        ("org.freedesktop.DBus.ObjectManager", "InterfacesAdded", b"oa{sa{sv}}") => {
            if signal.path != scope.manager_path {
                return Err(Error::OutsideScope);
            }
            let event =
                objects::parse_interfaces_added(signal.body, endian).map_err(Error::Body)?;
            if !within(event.path, scope.namespace) {
                return Err(Error::OutsideScope);
            }
            Ok(Event::Added(event))
        }
        ("org.freedesktop.DBus.ObjectManager", "InterfacesRemoved", b"oas") => {
            if signal.path != scope.manager_path {
                return Err(Error::OutsideScope);
            }
            let event =
                objects::parse_interfaces_removed(signal.body, endian).map_err(Error::Body)?;
            if !within(event.path, scope.namespace) {
                return Err(Error::OutsideScope);
            }
            Ok(Event::Removed(event))
        }
        ("org.freedesktop.DBus.Properties", "PropertiesChanged", b"sa{sv}as") => {
            if !within(signal.path, scope.namespace) {
                return Err(Error::OutsideScope);
            }
            let change =
                objects::parse_properties_changed(signal.body, endian).map_err(Error::Body)?;
            Ok(Event::Properties {
                path: signal.path,
                change,
            })
        }
        _ => Err(Error::Unsupported),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Writer(Vec<u8>);
    impl Writer {
        fn new() -> Self {
            Self(Vec::new())
        }
        fn pad(&mut self, n: usize) {
            while self.0.len() % n != 0 {
                self.0.push(0);
            }
        }
        fn number(&mut self, n: u32) {
            self.pad(4);
            self.0.extend_from_slice(&n.to_le_bytes());
        }
        fn string(&mut self, s: &str) {
            self.number(s.len() as u32);
            self.0.extend_from_slice(s.as_bytes());
            self.0.push(0);
        }
        fn sig(&mut self, s: &str) {
            self.0.push(s.len() as u8);
            self.0.extend_from_slice(s.as_bytes());
            self.0.push(0);
        }
        fn array(&mut self, n: usize) -> (usize, usize) {
            self.pad(4);
            let at = self.0.len();
            self.number(0);
            self.pad(n);
            (at, self.0.len())
        }
        fn finish(&mut self, mark: (usize, usize)) {
            let len = (self.0.len() - mark.1) as u32;
            self.0[mark.0..mark.0 + 4].copy_from_slice(&len.to_le_bytes());
        }
        fn field(&mut self, code: u8, kind: u8, s: &str) {
            self.pad(8);
            self.0.extend_from_slice(&[code, 1, kind, 0]);
            self.string(s);
        }
    }
    fn frame(
        path: &str,
        iface: &str,
        member: &str,
        sig: &str,
        body: &[u8],
        sender: &str,
    ) -> Vec<u8> {
        let mut w = Writer::new();
        w.0.extend_from_slice(b"l\x04\x00\x01");
        w.number(body.len() as u32);
        w.number(7);
        w.number(0);
        w.field(1, b'o', path);
        w.field(2, b's', iface);
        w.field(3, b's', member);
        w.field(7, b's', sender);
        w.pad(8);
        w.0.extend_from_slice(&[8, 1, b'g', 0]);
        w.sig(sig);
        let fields = (w.0.len() - 16) as u32;
        w.0[12..16].copy_from_slice(&fields.to_le_bytes());
        w.pad(8);
        w.0.extend_from_slice(body);
        w.0
    }
    fn added(path: &str) -> Vec<u8> {
        let mut w = Writer::new();
        w.string(path);
        let interfaces = w.array(8);
        w.pad(8);
        w.string("org.bluez.Device1");
        let properties = w.array(8);
        w.pad(8);
        w.string("UUIDs");
        w.sig("as");
        let values = w.array(4);
        w.string("camera-service");
        w.finish(values);
        w.finish(properties);
        w.finish(interfaces);
        w.0
    }
    fn removed(path: &str) -> Vec<u8> {
        let mut w = Writer::new();
        w.string(path);
        let interfaces = w.array(4);
        w.string("org.bluez.Device1");
        w.finish(interfaces);
        w.0
    }
    fn changed() -> Vec<u8> {
        let mut w = Writer::new();
        w.string("org.bluez.Device1");
        let changed = w.array(8);
        w.finish(changed);
        let invalidated = w.array(4);
        w.string("UUIDs");
        w.finish(invalidated);
        w.0
    }
    fn scope() -> Scope<'static> {
        Scope {
            owner: ":1.42",
            namespace: "/org/bluez",
            manager_path: "/",
        }
    }

    #[test]
    fn scoped_signals_preserve_partial_claim_and_invalidation() -> Result<(), Error> {
        let f = frame(
            "/",
            "org.freedesktop.DBus.ObjectManager",
            "InterfacesAdded",
            "oa{sa{sv}}",
            &added("/org/bluez/hci0/dev_AA"),
            ":1.42",
        );
        match parse(&f, &scope())? {
            Event::Added(event) => assert_eq!(
                event
                    .device
                    .as_ref()
                    .and_then(|d| d.claims_service("CAMERA-SERVICE")),
                Some(true)
            ),
            _ => return Err(Error::Unsupported),
        }
        let f = frame(
            "/",
            "org.freedesktop.DBus.ObjectManager",
            "InterfacesRemoved",
            "oas",
            &removed("/org/bluez/hci0/dev_AA"),
            ":1.42",
        );
        match parse(&f, &scope())? {
            Event::Removed(event) => assert_eq!(event.interfaces(), &["org.bluez.Device1"]),
            _ => return Err(Error::Unsupported),
        }
        let f = frame(
            "/org/bluez/hci0/dev_AA",
            "org.freedesktop.DBus.Properties",
            "PropertiesChanged",
            "sa{sv}as",
            &changed(),
            ":1.42",
        );
        let event = parse(&f, &scope())?;
        assert!(!format!("{event:?}").contains("dev_AA"));
        match event {
            Event::Properties { change, .. } => assert!(matches!(
                change.services,
                objects::ServiceChange::Invalidated
            )),
            _ => return Err(Error::Unsupported),
        }
        Ok(())
    }
    #[test]
    fn wrong_sender_scope_signature_and_truncation_never_become_events() {
        let body = added("/org/bluez/hci0/dev_AA");
        let valid = frame(
            "/",
            "org.freedesktop.DBus.ObjectManager",
            "InterfacesAdded",
            "oa{sa{sv}}",
            &body,
            ":1.42",
        );
        for n in 0..valid.len() {
            assert!(parse(&valid[..n], &scope()).is_err());
        }
        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(matches!(
            parse(&trailing, &scope()),
            Err(Error::FrameBoundary)
        ));
        let bad_sender = frame(
            "/",
            "org.freedesktop.DBus.ObjectManager",
            "InterfacesAdded",
            "oa{sa{sv}}",
            &body,
            ":1.43",
        );
        assert!(matches!(
            parse(&bad_sender, &scope()),
            Err(Error::OutsideScope)
        ));
        let sibling = frame(
            "/",
            "org.freedesktop.DBus.ObjectManager",
            "InterfacesAdded",
            "oa{sa{sv}}",
            &added("/org/bluez2/hci0"),
            ":1.42",
        );
        assert!(matches!(
            parse(&sibling, &scope()),
            Err(Error::OutsideScope)
        ));
        let wrong_manager = frame(
            "/org/bluez",
            "org.freedesktop.DBus.ObjectManager",
            "InterfacesAdded",
            "oa{sa{sv}}",
            &body,
            ":1.42",
        );
        assert!(matches!(
            parse(&wrong_manager, &scope()),
            Err(Error::OutsideScope)
        ));
        let wrong_signature = frame(
            "/",
            "org.freedesktop.DBus.ObjectManager",
            "InterfacesAdded",
            "oas",
            &body,
            ":1.42",
        );
        assert!(matches!(
            parse(&wrong_signature, &scope()),
            Err(Error::Unsupported)
        ));
        let bad_scope = Scope {
            owner: "org.bluez",
            ..scope()
        };
        assert!(matches!(
            parse(&valid, &bad_scope),
            Err(Error::InvalidScope)
        ));
    }

    #[test]
    fn single_byte_corruptions_never_escape_scope_or_panic() {
        let body = added("/org/bluez/hci0/dev_AA");
        let valid = frame(
            "/",
            "org.freedesktop.DBus.ObjectManager",
            "InterfacesAdded",
            "oa{sa{sv}}",
            &body,
            ":1.42",
        );
        for offset in 0..valid.len() {
            for byte in [0_u8, 0x7f, 0xff] {
                let mut mutated = valid.clone();
                mutated[offset] = byte;
                if let Ok(event) = parse(&mutated, &scope()) {
                    match event {
                        Event::Added(added) => assert!(within(added.path, "/org/bluez")),
                        Event::Removed(removed) => assert!(within(removed.path, "/org/bluez")),
                        Event::Properties { path, .. } => assert!(within(path, "/org/bluez")),
                    }
                }
            }
        }
    }
}

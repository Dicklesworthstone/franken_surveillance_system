#![forbid(unsafe_code)]
//! Isolated registry-test fixture, not a BlueZ bus or camera integration test.
//!
//! The registry and D-Bus parser are the actual project sources. Only the
//! small bus-facing data types and frame wrapper are supplied by this fixture;
//! production watch ownership, I/O, cancellation and admission are not tested.

extern crate fss_packet;

pub(crate) mod bluez_bus {
    use fss_packet::dbus_bluez_signal::{self as signals, Event};

    pub struct DeviceClaim {
        pub path: String,
        pub service_uuids: Option<Vec<String>>,
    }

    pub struct WatchInventory {
        pub adapter_paths: Vec<String>,
        pub device_paths: Vec<String>,
        pub device_claims: Vec<DeviceClaim>,
        pub objects: usize,
        pub overlapping_changes: usize,
    }

    pub struct ChangeFrame(Vec<u8>);

    pub(crate) fn test_change_frame(bytes: Vec<u8>) -> ChangeFrame {
        ChangeFrame(bytes)
    }

    impl ChangeFrame {
        pub fn decode<'a>(&'a self, owner: &str) -> Result<Event<'a>, signals::Error> {
            signals::parse(
                &self.0,
                &signals::Scope {
                    owner,
                    namespace: "/org/bluez",
                    manager_path: "/",
                },
            )
        }
    }
}

mod unifi_direct {
    pub(crate) use crate::bluez_bus;
}

#[path = "../../crates/fss-reference/src/unifi_direct/bluez_registry.rs"]
mod bluez_registry;

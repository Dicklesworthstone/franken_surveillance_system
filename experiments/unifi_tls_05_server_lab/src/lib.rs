#![forbid(unsafe_code)]
//! Experimental Asupersync 0.5 + rustls server transport; not production TLS.
//! Provider admission, entropy authority and camera identity are unresolved.

pub mod camera_tls;
#[path = "../../unifi_https_snapshot_lab/src/client.rs"]
pub mod camera_tls_client;
pub mod server;
pub mod setup_upgrade;

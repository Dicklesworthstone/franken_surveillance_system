#![forbid(unsafe_code)]
//! Scoped-entropy TLS research; not admitted for production.
pub mod camera_tls;
pub mod camera_tls_client;
#[cfg(target_os = "linux")]
pub mod client_handshake;
#[cfg(target_os = "linux")]
pub mod fleet_transport;
#[cfg(target_os = "linux")]
pub mod owned;
pub mod server;

#[cfg(target_os = "linux")]
pub mod camera_tls_owned;

#[cfg(target_os = "linux")]
pub mod fleet_leased;

#[cfg(target_os = "linux")]
pub mod camera_setup;

#[cfg(target_os = "linux")]
pub mod prepared_setup;

#[cfg(target_os = "linux")]
pub mod prepared_camera;

#[cfg(target_os = "linux")]
pub mod camera_factory;

#[cfg(target_os = "linux")]
pub mod setup_upgrade;

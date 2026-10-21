#![forbid(unsafe_code)]
//! Bounded, owner-authorized ONVIF Media1 onboarding (FSS-043, FSS-044).
//!
//! Discovery advertisements are candidate observations, never network or credential grants.
//! This subset reads capabilities, profiles, and a selected stream URI through explicitly
//! pinned HTTP routes. The caller owns time, cancellation, credentials, entropy, and budgets.
//! Stream capture remains the separately approved native RTSP acquisition path.
//!
//! This is not a Profile T/Media2 implementation or a device-conformance claim. HTTPS,
//! WS-Security, imaging changes, events, PTZ, and device provisioning are not implemented here.

pub mod client;
pub mod http;
pub mod wire;

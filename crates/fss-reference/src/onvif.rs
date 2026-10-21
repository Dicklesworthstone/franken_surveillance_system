#![forbid(unsafe_code)]
//! Bounded, owner-authorized ONVIF Media1/Media2 onboarding (FSS-043, FSS-044).
//!
//! Discovery advertisements are candidate observations, never network or credential grants.
//! This subset reads service discovery, profiles, and a selected stream URI through explicitly
//! pinned HTTP routes. The caller owns time, cancellation, credentials, entropy, and budgets.
//! Stream capture remains the separately approved native RTSP acquisition path.
//!
//! These read-only Media1/Media2 lanes do not establish Profile T or device conformance. The
//! explicit UsernameToken lane uses camera UTC only for authentication freshness. HTTPS,
//! imaging changes, events, PTZ, and device provisioning are not implemented here.

pub mod authentication;
pub mod client;
pub mod http;
pub mod wire;

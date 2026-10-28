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
//! imaging changes, PTZ, and device provisioning are not implemented here.
//! A separately approved bounded PullPoint lane owns transient subscriptions. Both native event
//! responses and owner-supplied XML can be retained and verified through the metadata module.

pub mod authentication;
pub mod client;
/// Durable subscription intent, exact responses and restart discovery under fresh authority.
pub mod control;
pub mod http;
/// Immutable owner-attributed vendor-event imports and independent retained-source verification.
pub mod metadata;
/// Bounded native event subscriptions under explicit lifecycle and transport authority.
pub mod pullpoint;
pub mod snapshot;
pub mod wire;

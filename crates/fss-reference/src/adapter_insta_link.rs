#![forbid(unsafe_code)]
//! Typed registry-row realization for `ADP-INSTA-LINK-001` (bead fss-x4a.30.89.4):
//! the Insta360 Link via UVC/UAC adapter. Standards UVC/UAC path for the Insta360 Link tuple; no
//! vendor SDK or app automation. Researched but unimplemented — the identity
//! exists so the registry row is machine-realized ahead of the driver.
//!
//! Isolation/credentials/capabilities are declared to match the row's normative
//! state ("researched, unimplemented") and NEG-002; see the sibling rows (`adapter_aosu`,
//! `adapter_wyze`) for the pattern. The row ID is stable and never renumbered;
//! supersession requires an explicit tombstone plus migration/consumer audit.

use fss_core::{
    AdapterCapabilities, AdapterGeneration, AdapterId, AdapterIdentity, AdapterKind, ContractError,
    CredentialMethod, IsolationMode,
};

/// Row identifier in `registries/DEVICE_ADAPTERS.md`.
pub const ADP_INSTA_LINK_ROW_ID: &str = "ADP-INSTA-LINK-001";

/// Surface name for the adapter.
pub const ADP_INSTA_LINK_SURFACE: &str = "Insta360 Link via UVC/UAC";

/// Device adapter tier.
pub const ADP_INSTA_LINK_TIER: &str = "T1";

/// Current qualification lifecycle state.
pub const ADP_INSTA_LINK_CURRENT_STATE: &str = "researched, unimplemented";

/// Promotion gate requirement.
pub const ADP_INSTA_LINK_PROMOTION_GATE: &str = "GATE-020";

/// Pinned adapter generation identifier.
pub const ADP_INSTA_LINK_GENERATION: &str = "gen:fss1:adapters-v1";

/// Protocol profile (specification/gate-cited per NEG-002 rule 2).
pub const ADP_INSTA_LINK_PROTOCOL_PROFILE: &str = "uvc:1.5;gate-020;insta360-link-tuple";

/// Lab bandwidth ceiling.
pub const ADP_INSTA_LINK_MAX_BANDWIDTH_BYTES_PER_SEC: u64 = 32 * 1024 * 1024;

/// Lab ring-buffer frame depth.
pub const ADP_INSTA_LINK_MAX_BUFFER_FRAMES: u32 = 256;

/// Lab request timeout in nanoseconds.
pub const ADP_INSTA_LINK_REQUEST_TIMEOUT_NS: u64 = 10_000_000_000;

/// The declared capability set. The Insta360 Link tuple over standard UVC/UAC: streaming, snapshot, and PTZ-class gimbal control (researched, unimplemented).
pub const ADP_INSTA_LINK_CAPABILITIES: AdapterCapabilities = AdapterCapabilities::STREAMING.union(AdapterCapabilities::SNAPSHOT).union(AdapterCapabilities::PTZ_CONTROL);

/// Constructs the typed identity for the row, fully verified: structural
/// invariants (`verify`) and NEG-002 standards compliance must both pass.
pub fn adapter_identity() -> Result<AdapterIdentity, ContractError> {
    let identity = AdapterIdentity {
        adapter_id: AdapterId::parse(ADP_INSTA_LINK_ROW_ID)?,
        generation: AdapterGeneration::parse(ADP_INSTA_LINK_GENERATION)?,
        adapter_kind: AdapterKind::Uvc,
        protocol_profile: ADP_INSTA_LINK_PROTOCOL_PROFILE.to_string(),
        isolation_mode: IsolationMode::NativePureRust,
        credential_method: CredentialMethod::None,
        capabilities: ADP_INSTA_LINK_CAPABILITIES,
        max_bandwidth_bytes_per_sec: ADP_INSTA_LINK_MAX_BANDWIDTH_BYTES_PER_SEC,
        max_buffer_frames: ADP_INSTA_LINK_MAX_BUFFER_FRAMES,
        request_timeout_ns: ADP_INSTA_LINK_REQUEST_TIMEOUT_NS,
    };
    identity.verify()?;
    identity
        .verify_standards_compliance()
        .map_err(|_| ContractError::InvalidIdentifier)?;
    Ok(identity)
}

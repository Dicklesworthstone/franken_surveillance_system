#![forbid(unsafe_code)]
//! Typed registry-row realization for `ADP-UVC-001` (bead fss-x4a.30.89.3):
//! the UVC/UAC adapter. Standards path (USB Video Class / Audio Class); no vendor
//! secret material. Implementation is specified but not yet landed — the
//! identity exists so the registry row is machine-realized ahead of it.
//!
//! Isolation/credentials/capabilities are declared to match the row's normative
//! state ("specified") and NEG-002; see the sibling rows (`adapter_aosu`,
//! `adapter_wyze`) for the pattern. The row ID is stable and never renumbered;
//! supersession requires an explicit tombstone plus migration/consumer audit.

use fss_core::{
    AdapterCapabilities, AdapterGeneration, AdapterId, AdapterIdentity, AdapterKind, ContractError,
    CredentialMethod, IsolationMode,
};

/// Row identifier in `registries/DEVICE_ADAPTERS.md`.
pub const ADP_UVC_ROW_ID: &str = "ADP-UVC-001";

/// Surface name for the adapter.
pub const ADP_UVC_SURFACE: &str = "UVC/UAC";

/// Device adapter tier.
pub const ADP_UVC_TIER: &str = "T1";

/// Current qualification lifecycle state.
pub const ADP_UVC_CURRENT_STATE: &str = "specified";

/// Promotion gate requirement.
pub const ADP_UVC_PROMOTION_GATE: &str = "GATE-020";

/// Pinned adapter generation identifier.
pub const ADP_UVC_GENERATION: &str = "gen:fss1:adapters-v1";

/// Protocol profile (specification/gate-cited per NEG-002 rule 2).
pub const ADP_UVC_PROTOCOL_PROFILE: &str = "uvc:1.5;uac:1.0;gate-020";

/// Lab bandwidth ceiling.
pub const ADP_UVC_MAX_BANDWIDTH_BYTES_PER_SEC: u64 = 32 * 1024 * 1024;

/// Lab ring-buffer frame depth.
pub const ADP_UVC_MAX_BUFFER_FRAMES: u32 = 256;

/// Lab request timeout in nanoseconds.
pub const ADP_UVC_REQUEST_TIMEOUT_NS: u64 = 10_000_000_000;

/// The declared capability set. The UVC/UAC contract: streaming plus snapshot (specified; implementation pending).
pub const ADP_UVC_CAPABILITIES: AdapterCapabilities = AdapterCapabilities::STREAMING.union(AdapterCapabilities::SNAPSHOT);

/// Constructs the typed identity for the row, fully verified: structural
/// invariants (`verify`) and NEG-002 standards compliance must both pass.
pub fn adapter_identity() -> Result<AdapterIdentity, ContractError> {
    let identity = AdapterIdentity {
        adapter_id: AdapterId::parse(ADP_UVC_ROW_ID)?,
        generation: AdapterGeneration::parse(ADP_UVC_GENERATION)?,
        adapter_kind: AdapterKind::Uvc,
        protocol_profile: ADP_UVC_PROTOCOL_PROFILE.to_string(),
        isolation_mode: IsolationMode::NativePureRust,
        credential_method: CredentialMethod::None,
        capabilities: ADP_UVC_CAPABILITIES,
        max_bandwidth_bytes_per_sec: ADP_UVC_MAX_BANDWIDTH_BYTES_PER_SEC,
        max_buffer_frames: ADP_UVC_MAX_BUFFER_FRAMES,
        request_timeout_ns: ADP_UVC_REQUEST_TIMEOUT_NS,
    };
    identity.verify()?;
    identity
        .verify_standards_compliance()
        .map_err(|_| ContractError::InvalidIdentifier)?;
    Ok(identity)
}

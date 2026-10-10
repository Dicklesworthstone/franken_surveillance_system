#![forbid(unsafe_code)]
//! Typed registry-row realization for `ADP-DJI-FLIP-LAB-001` (bead fss-x4a.30.89.10):
//! the DJI Flip manual capture/import lab (NEG-001 non-SDK) adapter. Manual owner capture and bounded file import only: no SDK
//! claim, no autonomous mission claim, no unsupported control reverse
//! engineering (NEG-001). Sealed lab isolation is forced by NEG-002 rule 3
//! (proprietary/vendor lab row).
//!
//! Isolation/credentials/capabilities are declared to match the row's normative
//! state ("research target") and NEG-002; see the sibling rows (`adapter_aosu`,
//! `adapter_wyze`) for the pattern. The row ID is stable and never renumbered;
//! supersession requires an explicit tombstone plus migration/consumer audit.

use fss_core::{
    AdapterCapabilities, AdapterGeneration, AdapterId, AdapterIdentity, AdapterKind, ContractError,
    CredentialMethod, IsolationMode,
};

/// Row identifier in `registries/DEVICE_ADAPTERS.md`.
pub const ADP_DJI_FLIP_ROW_ID: &str = "ADP-DJI-FLIP-LAB-001";

/// Surface name for the adapter.
pub const ADP_DJI_FLIP_SURFACE: &str = "DJI Flip manual capture/import lab (NEG-001 non-SDK)";

/// Device adapter tier.
pub const ADP_DJI_FLIP_TIER: &str = "T3/T4";

/// Current qualification lifecycle state.
pub const ADP_DJI_FLIP_CURRENT_STATE: &str = "research target";

/// Promotion gate requirement.
pub const ADP_DJI_FLIP_PROMOTION_GATE: &str = "GATE-100";

/// Pinned adapter generation identifier.
pub const ADP_DJI_FLIP_GENERATION: &str = "gen:fss1:adapters-v1";

/// Protocol profile (specification/gate-cited per NEG-002 rule 2).
pub const ADP_DJI_FLIP_PROTOCOL_PROFILE: &str = "dji-flip:manual-import;gate-100";

/// Lab bandwidth ceiling.
pub const ADP_DJI_FLIP_MAX_BANDWIDTH_BYTES_PER_SEC: u64 = 16 * 1024 * 1024;

/// Lab ring-buffer frame depth.
pub const ADP_DJI_FLIP_MAX_BUFFER_FRAMES: u32 = 64;

/// Lab request timeout in nanoseconds.
pub const ADP_DJI_FLIP_REQUEST_TIMEOUT_NS: u64 = 10_000_000_000;

/// The declared capability set. Manual owner capture + bounded file import only — no device-link capability is claimed (NEG-001).
pub const ADP_DJI_FLIP_CAPABILITIES: AdapterCapabilities = AdapterCapabilities::NONE;

/// Constructs the typed identity for the row, fully verified: structural
/// invariants (`verify`) and NEG-002 standards compliance must both pass.
pub fn adapter_identity() -> Result<AdapterIdentity, ContractError> {
    let identity = AdapterIdentity {
        adapter_id: AdapterId::parse(ADP_DJI_FLIP_ROW_ID)?,
        generation: AdapterGeneration::parse(ADP_DJI_FLIP_GENERATION)?,
        adapter_kind: AdapterKind::FileArchive,
        protocol_profile: ADP_DJI_FLIP_PROTOCOL_PROFILE.to_string(),
        isolation_mode: IsolationMode::SealedLaboratoryProcess,
        credential_method: CredentialMethod::None,
        capabilities: ADP_DJI_FLIP_CAPABILITIES,
        max_bandwidth_bytes_per_sec: ADP_DJI_FLIP_MAX_BANDWIDTH_BYTES_PER_SEC,
        max_buffer_frames: ADP_DJI_FLIP_MAX_BUFFER_FRAMES,
        request_timeout_ns: ADP_DJI_FLIP_REQUEST_TIMEOUT_NS,
    };
    identity.verify()?;
    identity
        .verify_standards_compliance()
        .map_err(|_| ContractError::InvalidIdentifier)?;
    Ok(identity)
}

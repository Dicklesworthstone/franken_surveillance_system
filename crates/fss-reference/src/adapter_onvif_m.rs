#![forbid(unsafe_code)]
//! Typed registry-row realization for `ADP-ONVIF-M-001` (bead fss-x4a.30.89.7):
//! the ONVIF Profile M metadata adapter. Standards path (ONVIF Profile M metadata/analytics).
//! Specified; no implementation landed yet.
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
pub const ADP_ONVIF_M_ROW_ID: &str = "ADP-ONVIF-M-001";

/// Runtime adapter identifier in the canonical `adapter:` grammar, derived
/// from the registry row (lowercased, hyphen-preserved). The row ID above is
/// the normative registry namespace; this is the runtime identity the
/// acquisition path validates.
pub const ADP_ONVIF_M_RUNTIME_ID: &str = "adapter:adp-onvif-m-001";

/// Surface name for the adapter.
pub const ADP_ONVIF_M_SURFACE: &str = "ONVIF Profile M metadata";

/// Device adapter tier.
pub const ADP_ONVIF_M_TIER: &str = "T1";

/// Current qualification lifecycle state.
pub const ADP_ONVIF_M_CURRENT_STATE: &str = "specified";

/// Promotion gate requirement.
pub const ADP_ONVIF_M_PROMOTION_GATE: &str = "GATE-030";

/// Pinned adapter generation identifier.
pub const ADP_ONVIF_M_GENERATION: &str = "gen:fss1:adapters-v1";

/// Protocol profile (specification/gate-cited per NEG-002 rule 2).
pub const ADP_ONVIF_M_PROTOCOL_PROFILE: &str = "onvif:profile-m;gate-030";

/// Lab bandwidth ceiling.
pub const ADP_ONVIF_M_MAX_BANDWIDTH_BYTES_PER_SEC: u64 = 1024 * 1024;

/// Lab ring-buffer frame depth.
pub const ADP_ONVIF_M_MAX_BUFFER_FRAMES: u32 = 64;

/// Lab request timeout in nanoseconds.
pub const ADP_ONVIF_M_REQUEST_TIMEOUT_NS: u64 = 10_000_000_000;

/// The declared capability set. Profile M is metadata/analytics — telemetry only, no media streaming claim.
pub const ADP_ONVIF_M_CAPABILITIES: AdapterCapabilities = AdapterCapabilities::TELEMETRY;

/// Constructs the typed identity for the row, fully verified: structural
/// invariants (`verify`) and NEG-002 standards compliance must both pass.
pub fn adapter_identity() -> Result<AdapterIdentity, ContractError> {
    let identity = AdapterIdentity {
        adapter_id: AdapterId::parse(ADP_ONVIF_M_RUNTIME_ID)?,
        generation: AdapterGeneration::parse(ADP_ONVIF_M_GENERATION)?,
        adapter_kind: AdapterKind::OnvifProfileM,
        protocol_profile: ADP_ONVIF_M_PROTOCOL_PROFILE.to_string(),
        isolation_mode: IsolationMode::NativePureRust,
        credential_method: CredentialMethod::DigestAuth,
        capabilities: ADP_ONVIF_M_CAPABILITIES,
        max_bandwidth_bytes_per_sec: ADP_ONVIF_M_MAX_BANDWIDTH_BYTES_PER_SEC,
        max_buffer_frames: ADP_ONVIF_M_MAX_BUFFER_FRAMES,
        request_timeout_ns: ADP_ONVIF_M_REQUEST_TIMEOUT_NS,
    };
    identity.verify()?;
    identity
        .verify_standards_compliance()
        .map_err(|_| ContractError::InvalidIdentifier)?;
    Ok(identity)
}

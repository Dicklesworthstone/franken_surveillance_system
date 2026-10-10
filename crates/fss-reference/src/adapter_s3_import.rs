#![forbid(unsafe_code)]
//! Typed registry-row realization for `ADP-S3-IMPORT-001` (bead fss-x4a.30.89.11):
//! the S3-compatible import adapter. S3-compatible bounded object import. Credentials are
//! explicitly scoped presigned/token forms; the profile and id carry no
//! ambient/global scoping (NEG-002 rule 4 — which also forces sealed process
//! isolation for token-authenticated vendor endpoints).
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
pub const ADP_S3_ROW_ID: &str = "ADP-S3-IMPORT-001";

/// Surface name for the adapter.
pub const ADP_S3_SURFACE: &str = "S3-compatible import";

/// Device adapter tier.
pub const ADP_S3_TIER: &str = "T4";

/// Current qualification lifecycle state.
pub const ADP_S3_CURRENT_STATE: &str = "specified";

/// Promotion gate requirement.
pub const ADP_S3_PROMOTION_GATE: &str = "GATE-040";

/// Pinned adapter generation identifier.
pub const ADP_S3_GENERATION: &str = "gen:fss1:adapters-v1";

/// Protocol profile (specification/gate-cited per NEG-002 rule 2).
pub const ADP_S3_PROTOCOL_PROFILE: &str = "s3:object-import;gate-040";

/// Lab bandwidth ceiling.
pub const ADP_S3_MAX_BANDWIDTH_BYTES_PER_SEC: u64 = 64 * 1024 * 1024;

/// Lab ring-buffer frame depth.
pub const ADP_S3_MAX_BUFFER_FRAMES: u32 = 64;

/// Lab request timeout in nanoseconds.
pub const ADP_S3_REQUEST_TIMEOUT_NS: u64 = 30_000_000_000;

/// The declared capability set. Bounded object import; no streaming-type capabilities (import lane).
pub const ADP_S3_CAPABILITIES: AdapterCapabilities = AdapterCapabilities::NONE;

/// Constructs the typed identity for the row, fully verified: structural
/// invariants (`verify`) and NEG-002 standards compliance must both pass.
pub fn adapter_identity() -> Result<AdapterIdentity, ContractError> {
    let identity = AdapterIdentity {
        adapter_id: AdapterId::parse(ADP_S3_ROW_ID)?,
        generation: AdapterGeneration::parse(ADP_S3_GENERATION)?,
        adapter_kind: AdapterKind::FileArchive,
        protocol_profile: ADP_S3_PROTOCOL_PROFILE.to_string(),
        isolation_mode: IsolationMode::SealedLaboratoryProcess,
        credential_method: CredentialMethod::Token,
        capabilities: ADP_S3_CAPABILITIES,
        max_bandwidth_bytes_per_sec: ADP_S3_MAX_BANDWIDTH_BYTES_PER_SEC,
        max_buffer_frames: ADP_S3_MAX_BUFFER_FRAMES,
        request_timeout_ns: ADP_S3_REQUEST_TIMEOUT_NS,
    };
    identity.verify()?;
    identity
        .verify_standards_compliance()
        .map_err(|_| ContractError::InvalidIdentifier)?;
    Ok(identity)
}

#![forbid(unsafe_code)]
//! Typed registry-row realization for `ADP-RTSP-001` (bead fss-x4a.30.89.5):
//! the RTSP/RTP adapter. Owning implementation: `crate::rtsp` (sans-IO RTSP/1.0 client,
//! AVC/HEVC receivers, recording capture/collectors, credential-redacting wire
//! parsing, bounded Digest authentication). Authority plane only.
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
pub const ADP_RTSP_ROW_ID: &str = "ADP-RTSP-001";

/// Runtime adapter identifier in the canonical `adapter:` grammar, derived
/// from the registry row (lowercased, hyphen-preserved). The row ID above is
/// the normative registry namespace; this is the runtime identity the
/// acquisition path validates.
pub const ADP_RTSP_RUNTIME_ID: &str = "adapter:adp-rtsp-001";

/// Surface name for the adapter.
pub const ADP_RTSP_SURFACE: &str = "RTSP/RTP";

/// Device adapter tier.
pub const ADP_RTSP_TIER: &str = "T1";

/// Current qualification lifecycle state.
pub const ADP_RTSP_CURRENT_STATE: &str = "specified";

/// Promotion gate requirement.
pub const ADP_RTSP_PROMOTION_GATE: &str = "GATE-030";

/// Pinned adapter generation identifier.
pub const ADP_RTSP_GENERATION: &str = "gen:fss1:adapters-v1";

/// Protocol profile (specification/gate-cited per NEG-002 rule 2).
pub const ADP_RTSP_PROTOCOL_PROFILE: &str = "rtsp:rfc2326;rtp:rfc3550;gate-030";

/// Lab bandwidth ceiling.
pub const ADP_RTSP_MAX_BANDWIDTH_BYTES_PER_SEC: u64 = 16 * 1024 * 1024;

/// Lab ring-buffer frame depth.
pub const ADP_RTSP_MAX_BUFFER_FRAMES: u32 = 256;

/// Lab request timeout in nanoseconds.
pub const ADP_RTSP_REQUEST_TIMEOUT_NS: u64 = 10_000_000_000;

/// The declared capability set. Streaming (AVC+HEVC clients, recording collectors) plus discovery.
pub const ADP_RTSP_CAPABILITIES: AdapterCapabilities = AdapterCapabilities::STREAMING.union(AdapterCapabilities::DEVICE_DISCOVERY);

/// Constructs the typed identity for the row, fully verified: structural
/// invariants (`verify`) and NEG-002 standards compliance must both pass.
pub fn adapter_identity() -> Result<AdapterIdentity, ContractError> {
    let identity = AdapterIdentity {
        adapter_id: AdapterId::parse(ADP_RTSP_RUNTIME_ID)?,
        generation: AdapterGeneration::parse(ADP_RTSP_GENERATION)?,
        adapter_kind: AdapterKind::Rtsp,
        protocol_profile: ADP_RTSP_PROTOCOL_PROFILE.to_string(),
        isolation_mode: IsolationMode::NativePureRust,
        credential_method: CredentialMethod::DigestAuth,
        capabilities: ADP_RTSP_CAPABILITIES,
        max_bandwidth_bytes_per_sec: ADP_RTSP_MAX_BANDWIDTH_BYTES_PER_SEC,
        max_buffer_frames: ADP_RTSP_MAX_BUFFER_FRAMES,
        request_timeout_ns: ADP_RTSP_REQUEST_TIMEOUT_NS,
    };
    identity.verify()?;
    identity
        .verify_standards_compliance()
        .map_err(|_| ContractError::InvalidIdentifier)?;
    Ok(identity)
}

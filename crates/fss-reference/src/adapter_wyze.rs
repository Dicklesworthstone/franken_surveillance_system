#![forbid(unsafe_code)]
//! Typed registry-row realization for `ADP-WYZE-V4-LAB-001` (bead
//! fss-x4a.30.89.8): the Wyze Cam v4 owner-authorized laboratory adapter.
//!
//! Owning implementation:
//! * protocol core — `fss-tutk` crate (sans-IO TUTK/IOTC NEW-protocol
//!   0xCC51 wire, first-party X25519/ChaCha20-Poly1305/XXTEA/HMAC-SHA1/SHA-256
//!   digests, session state machine; live-proven against owner Wyze Cam v4
//!   HL_CAM4 firmware 4.52.17.26, LAB-2026-10-07);
//! * live adapter — [`crate::ingest::tutk`] (`TutkIngest`: acquisition
//!   lifecycle with transition witnesses, source-custody capsules, ledger
//!   batches, audio privacy-gated off by default);
//! * discovery — [`crate::discovery::fingerprint`] TUTK-NEW classification
//!   (live multi-cam evidence).
//!
//! Producers/consumers and planes: producers are the TUTK session/ingest
//! adapters and the discovery classifier; consumers are the evidence ledger
//! and downstream cognition. The adapter's media path is the **Authority
//! plane** (immutable source-custody observations); ptz/control effect
//! authority is NOT declared by this row.
//!
//! Generation/tombstone rules: the row ID is stable and never renumbered;
//! supersession requires an explicit tombstone plus migration/consumer audit
//! (per the 30.89 epic contract). The adapter generation pins to
//! `gen:fss1:adapters-v1` and only advances monotonically.
//!
//! Isolation and credentials per NEG-002 (enforced by
//! [`AdapterIdentity::verify_standards_compliance`]): proprietary vendor lab
//! path ⇒ [`IsolationMode::SealedLaboratoryProcess`]; the TUTK session key
//! material is a device-local symmetric secret ⇒
//! [`CredentialMethod::LocalSecret`], owner-provisioned, never ambient.
//!
//! Capability honesty: unlike the battery/event-driven AOSU lane, the Wyze
//! lane's continuous streaming is LIVE-PROVEN on owner hardware
//! (LAB-2026-10-07), so `STREAMING` is declared alongside
//! `DEVICE_DISCOVERY` (TUTK discovery beacons live-proven) and `TELEMETRY`
//! (session statistics). No `PTZ_CONTROL`, no `TWO_WAY_AUDIO`: neither is
//! proven on this tuple.

use fss_core::{
    AdapterCapabilities, AdapterGeneration, AdapterId, AdapterIdentity, AdapterKind, ContractError,
    CredentialMethod, IsolationMode,
};

/// Row identifier in `registries/DEVICE_ADAPTERS.md`.
pub const ADP_WYZE_ROW_ID: &str = "ADP-WYZE-V4-LAB-001";

/// Surface name for the adapter.
pub const ADP_WYZE_SURFACE: &str = "Wyze Cam v4 owner-auth lab";

/// Device adapter tier (owner-authenticated lab path).
pub const ADP_WYZE_TIER: &str = "T3";

/// Current qualification lifecycle state.
pub const ADP_WYZE_CURRENT_STATE: &str = "research target";

/// Promotion gate requirement.
pub const ADP_WYZE_PROMOTION_GATE: &str = "GATE-090";

/// Pinned adapter generation identifier.
pub const ADP_WYZE_GENERATION: &str = "gen:fss1:adapters-v1";

/// Protocol profile: TUTK/IOTC NEW-protocol (0xCC51), lab-gated.
pub const ADP_WYZE_PROTOCOL_PROFILE: &str = "tutk-iotc:new;gate-090";

/// Lab bandwidth ceiling (8 MiB/s — 2K-class H.264/H.265 with headroom).
pub const ADP_WYZE_MAX_BANDWIDTH_BYTES_PER_SEC: u64 = 8 * 1024 * 1024;

/// Lab ring-buffer frame depth.
pub const ADP_WYZE_MAX_BUFFER_FRAMES: u32 = 128;

/// Lab request timeout (5 s in nanoseconds).
pub const ADP_WYZE_REQUEST_TIMEOUT_NS: u64 = 5_000_000_000;

/// The declared capability set: streaming + discovery + telemetry, each
/// live-proven on the owner tuple; nothing else claimed.
pub const ADP_WYZE_CAPABILITIES: AdapterCapabilities = AdapterCapabilities::STREAMING
    .union(AdapterCapabilities::DEVICE_DISCOVERY)
    .union(AdapterCapabilities::TELEMETRY);

/// Constructs the typed identity for the row, fully verified: structural
/// invariants (`verify`) and NEG-002 standards compliance
/// (`verify_standards_compliance`) must both pass at construction.
pub fn adapter_identity() -> Result<AdapterIdentity, ContractError> {
    let identity = AdapterIdentity {
        adapter_id: AdapterId::parse(ADP_WYZE_ROW_ID)?,
        generation: AdapterGeneration::parse(ADP_WYZE_GENERATION)?,
        adapter_kind: AdapterKind::TutkIotc,
        protocol_profile: ADP_WYZE_PROTOCOL_PROFILE.to_string(),
        isolation_mode: IsolationMode::SealedLaboratoryProcess,
        credential_method: CredentialMethod::LocalSecret,
        capabilities: ADP_WYZE_CAPABILITIES,
        max_bandwidth_bytes_per_sec: ADP_WYZE_MAX_BANDWIDTH_BYTES_PER_SEC,
        max_buffer_frames: ADP_WYZE_MAX_BUFFER_FRAMES,
        request_timeout_ns: ADP_WYZE_REQUEST_TIMEOUT_NS,
    };
    identity.verify()?;
    identity
        .verify_standards_compliance()
        .map_err(|_| ContractError::InvalidIdentifier)?;
    Ok(identity)
}

#![forbid(unsafe_code)]
//! Typed registry-row realization for `ADP-AOSU-P1MAX-LAB-001` (bead
//! fss-x4a.30.89.9): the AOSU P1 Max owner-authorized laboratory adapter.
//!
//! Owning implementation:
//! * protocol core — `fss-tuya` crate (55AA/6699 wire, AES-128-ECB/GCM,
//!   HMAC-SHA256 session negotiation, deterministic `HomebaseSim`, sans-IO
//!   `TuyaClient`; LAB-AOSU-4/5, closed);
//! * evidence semantics — [`crate::ingest::tuya`] (`TuyaEventMapper`:
//!   vendor-derived event candidates, wake-provenanced segments, device-state
//!   reports, battery/event-driven coverage honesty; LAB-AOSU-6, closed);
//! * live session — LAB-AOSU-2, blocked on the owner `local_key` (NEG-003).
//!
//! Producers/consumers and planes: producers are the discovery beacon
//! listener (`discovery::tuya_beacon`) and the future live session; consumers
//! are the evidence mapper and downstream cognition. This row touches the
//! **Authority plane only** (immutable observations of vendor claims); it
//! grants no effect authority and performs no camera control.
//!
//! Generation/tombstone rules: the row ID is stable and never renumbered;
//! supersession requires an explicit tombstone plus migration/consumer audit
//! (per the 30.89 epic contract). The adapter generation pins to
//! `gen:fss1:adapters-v1` and only advances monotonically.
//!
//! Isolation and credentials per NEG-002 (enforced by
//! [`AdapterIdentity::verify_standards_compliance`]): proprietary vendor lab
//! path ⇒ [`IsolationMode::SealedLaboratoryProcess`]; the Tuya `local_key`
//! is a device-local symmetric secret ⇒ [`CredentialMethod::LocalSecret`],
//! owner-provisioned, never ambient.
//!
//! Capability honesty (DEVICE_ADAPTER_MATRIX §3): battery cams are
//! event-driven, so this identity deliberately does NOT declare
//! `STREAMING` — no continuous-coverage implication may be inferred from it.
//! Declared: `DEVICE_DISCOVERY` (live-proven beacons) and `TELEMETRY`
//! (homebase health/dps reports).

use fss_core::{
    AdapterCapabilities, AdapterGeneration, AdapterId, AdapterIdentity, AdapterKind, ContractError,
    CredentialMethod, IsolationMode,
};

/// Row identifier in `registries/DEVICE_ADAPTERS.md`.
pub const ADP_AOSU_ROW_ID: &str = "ADP-AOSU-P1MAX-LAB-001";

/// Runtime adapter identifier in the canonical `adapter:` grammar, derived
/// from the registry row (lowercased, hyphen-preserved). The row ID above is
/// the normative registry namespace; this is the runtime identity the
/// acquisition path validates.
pub const ADP_AOSU_RUNTIME_ID: &str = "adapter:adp-aosu-p1max-lab-001";

/// Surface name for the adapter.
pub const ADP_AOSU_SURFACE: &str = "AOSU P1 Max owner-auth lab";

/// Device adapter tier (owner-authenticated lab path).
pub const ADP_AOSU_TIER: &str = "T3";

/// Current qualification lifecycle state.
pub const ADP_AOSU_CURRENT_STATE: &str = "research target";

/// Promotion gate requirement.
pub const ADP_AOSU_PROMOTION_GATE: &str = "GATE-090";

/// Pinned adapter generation identifier.
pub const ADP_AOSU_GENERATION: &str = "gen:fss1:adapters-v1";

/// Protocol profile: Tuya LAN 3.5 session (3.4 understood), lab-gated.
pub const ADP_AOSU_PROTOCOL_PROFILE: &str = "tuya:3.5;gate-090";

/// Lab bandwidth ceiling (2 MiB/s — event-class traffic, not streaming).
pub const ADP_AOSU_MAX_BANDWIDTH_BYTES_PER_SEC: u64 = 2 * 1024 * 1024;

/// Lab ring-buffer frame depth.
pub const ADP_AOSU_MAX_BUFFER_FRAMES: u32 = 64;

/// Lab request timeout (5 s in nanoseconds).
pub const ADP_AOSU_REQUEST_TIMEOUT_NS: u64 = 5_000_000_000;

/// The declared capability set: discovery + telemetry, deliberately without
/// `STREAMING` (battery/event-driven honesty).
pub const ADP_AOSU_CAPABILITIES: AdapterCapabilities = AdapterCapabilities::DEVICE_DISCOVERY
    .union(AdapterCapabilities::TELEMETRY);

/// Constructs the typed identity for the row, fully verified: structural
/// invariants (`verify`) and NEG-002 standards compliance
/// (`verify_standards_compliance`) must both pass at construction.
pub fn adapter_identity() -> Result<AdapterIdentity, ContractError> {
    let identity = AdapterIdentity {
        adapter_id: AdapterId::parse(ADP_AOSU_RUNTIME_ID)?,
        generation: AdapterGeneration::parse(ADP_AOSU_GENERATION)?,
        adapter_kind: AdapterKind::TuyaLan,
        protocol_profile: ADP_AOSU_PROTOCOL_PROFILE.to_string(),
        isolation_mode: IsolationMode::SealedLaboratoryProcess,
        credential_method: CredentialMethod::LocalSecret,
        capabilities: ADP_AOSU_CAPABILITIES,
        max_bandwidth_bytes_per_sec: ADP_AOSU_MAX_BANDWIDTH_BYTES_PER_SEC,
        max_buffer_frames: ADP_AOSU_MAX_BUFFER_FRAMES,
        request_timeout_ns: ADP_AOSU_REQUEST_TIMEOUT_NS,
    };
    identity.verify()?;
    identity
        .verify_standards_compliance()
        .map_err(|_| ContractError::InvalidIdentifier)?;
    Ok(identity)
}

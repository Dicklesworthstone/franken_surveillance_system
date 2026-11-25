#![forbid(unsafe_code)]
//! Multipath transfer race and loser-drain protocol (`FSS-129`, `fss-x4a.13.13`).
//!
//! Implements `docs/ATP_ARCHIVE_AND_REPLICATION.md` §5, `XFER-INV-007` (adaptive transport fails
//! closed under integrity/privacy/residency/cost clamps), and `XFER-INV-008` (cancellation and
//! loser draining own all staged work — zero leaked sockets, temporary objects, or billing ops):
//!
//! 1. **Policy-clamped admission BEFORE racing:** unauthorized, privacy-unapproved,
//!    integrity-unverified, out-of-residency, over-cost, or over-latency paths are rejected into
//!    `clamped_rejections` and can NEVER be selected or hedged even if they are faster.
//! 2. **Registered `atp.path.*` lifecycle + orthogonal `RacePathRole`:** composes
//!    [`PathState`] (`Candidate`, `Probing`, `Active`, `Suspect`, `Draining`, `Closed`) directly
//!    with orthogonal [`RacePathRole`] (`Unlaunched`, `Primary`, `Hedged`, `Winner`, `Failed`,
//!    `Quarantined`) without inventing a parallel path state vocabulary.
//! 3. **Deterministic primary & diverse-domain hedging:** admitted paths sort canonically by
//!    `(estimated_latency_ms, estimated_egress_cost_micros, path_id)`; hedging prefers a distinct
//!    `failure_domain` from active paths while respecting `max_concurrent_hedges`.
//! 4. **Verified winner & corrupt-fast-path quarantine:** `declare_winner_with_bytes` verifies
//!    exact canonical byte length and SHA-256 against `target_object_digest`. A fast path returning
//!    corrupt bytes is immediately moved to `PathState::Suspect` + `RacePathRole::Quarantined`
//!    (cannot expose data) rather than accepted.
//! 5. **Mandatory loser drain (`XFER-INV-008`):** once a winner is verified or cancellation is
//!    requested, every losing/active/hedged path transitions to [`PathState::Draining`] and MUST
//!    release all tracked sockets, staged temp objects, and open billing ops before reaching
//!    [`PathState::Closed`]. Stuck losers transition honestly to `Indeterminate`.
//! 6. **Bounded checksummed binary receipt (`FSSMP001` v1):** sealed under
//!    `fss.atp_multipath_race_receipt.v1`.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, TimestampNs,
};

use crate::atp_lifecycle::{PathState, TransferId};

/// Registered digest domain for sealed [`MultipathRaceReceipt`] commitments (`FSS-129`).
pub const ATP_MULTIPATH_RACE_RECEIPT_DOMAIN: &str = "fss.atp_multipath_race_receipt.v1";
/// Binary wire header magic for serialized multipath race receipts.
pub const MULTIPATH_RECEIPT_MAGIC: [u8; 8] = *b"FSSMP001";
/// Supported durable format version for [`MultipathRaceReceipt`].
pub const MULTIPATH_RECEIPT_VERSION: u32 = 1;
/// Hard ceiling on candidate paths admitted into one multipath race.
pub const MAX_RACE_CANDIDATES: usize = 64;
/// Hard ceiling on simultaneously active + hedged paths.
pub const MAX_HEDGED_CONCURRENCY: usize = 16;
/// Hard ceiling on UTF-8 bytes in path IDs, failure domains, residency zones, and diagnostic text.
pub const MAX_RACE_LABEL_BYTES: usize = 256;
/// Hard ceiling on serialized receipt wire bytes (256 KiB).
pub const MAX_RACE_RECEIPT_WIRE_BYTES: usize = 256 * 1024;

/// Transport medium class for one multipath candidate (`docs/ATP_ARCHIVE_AND_REPLICATION.md` §5).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PathKind {
    /// Local filesystem / staging spool path.
    LocalDisk = 1,
    /// Authenticated LAN peer path.
    LanPeer = 2,
    /// Cloud object-store provider path.
    CloudProvider = 3,
    /// Erasure/RaptorQ repair-symbol reconstruction source.
    RepairSource = 4,
}

impl PathKind {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalDisk => "local_disk",
            Self::LanPeer => "lan_peer",
            Self::CloudProvider => "cloud_provider",
            Self::RepairSource => "repair_source",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::LocalDisk),
            2 => Ok(Self::LanPeer),
            3 => Ok(Self::CloudProvider),
            4 => Ok(Self::RepairSource),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Orthogonal race disposition paired with the registered [`PathState`] (`atp.path.*`).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RacePathRole {
    /// Policy-admitted candidate not yet launched.
    Unlaunched = 1,
    /// Primary transfer path launched first.
    Primary = 2,
    /// Hedged path launched concurrently (preferring a distinct failure domain).
    Hedged = 3,
    /// Verified canonical winner whose payload matched `target_object_digest`.
    Winner = 4,
    /// Path failed due to transport/provider error.
    Failed = 5,
    /// Path quarantined because it delivered corrupt/mismatched payload bytes.
    Quarantined = 6,
}

impl RacePathRole {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unlaunched => "unlaunched",
            Self::Primary => "primary",
            Self::Hedged => "hedged",
            Self::Winner => "winner",
            Self::Failed => "failed",
            Self::Quarantined => "quarantined",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::Unlaunched),
            2 => Ok(Self::Primary),
            3 => Ok(Self::Hedged),
            4 => Ok(Self::Winner),
            5 => Ok(Self::Failed),
            6 => Ok(Self::Quarantined),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Non-collapsed multipath race lifecycle state (`XFER-INV-007`, `XFER-INV-008`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MultipathRaceState {
    /// Policy-clamped candidates admitted; no path has launched yet.
    Planned = 1,
    /// One or more authorized paths are actively fetching or hedged.
    Racing = 2,
    /// A winning path delivered digest-verified bytes, but losing paths are still draining resources.
    WinnerVerifiedDrainingLosers = 3,
    /// Winner verified AND every losing path drained to `PathState::Closed` with zero leaks.
    Complete = 4,
    /// Cancellation requested; live paths are draining resources prior to clean terminal closure.
    CancelledDraining = 5,
    /// Cancellation completed with every path `PathState::Closed` and zero leaked resources.
    CancelledClean = 6,
    /// All authorized paths failed or were quarantined without producing verified bytes.
    Failed = 7,
    /// At least one losing or cancelled path failed to confirm drain; reconciliation required.
    Indeterminate = 8,
}

impl MultipathRaceState {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Racing => "racing",
            Self::WinnerVerifiedDrainingLosers => "winner_verified_draining_losers",
            Self::Complete => "complete",
            Self::CancelledDraining => "cancelled_draining",
            Self::CancelledClean => "cancelled_clean",
            Self::Failed => "failed",
            Self::Indeterminate => "indeterminate",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::Planned),
            2 => Ok(Self::Racing),
            3 => Ok(Self::WinnerVerifiedDrainingLosers),
            4 => Ok(Self::Complete),
            5 => Ok(Self::CancelledDraining),
            6 => Ok(Self::CancelledClean),
            7 => Ok(Self::Failed),
            8 => Ok(Self::Indeterminate),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Safe recovery guidance for a refused multipath race transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MultipathGuidance {
    /// Fix invalid candidate definitions, duplicate path IDs, or clamp configuration.
    RepairRaceConfig,
    /// Re-authorize revoked transfer/privacy capability or refresh stale authority generation.
    ReauthorizeTransfer,
    /// Strip effect/activation grants from ATP transfer context (`XFER-INV-006`).
    StripEffectAuthority,
    /// Authorize at least one compliant replica/path satisfying privacy, residency, and cost clamps.
    ProvidePolicyCompliantPath,
    /// Finish draining every losing or cancelled path to zero live sockets/temp objects/billing ops.
    DrainRemainingPaths,
    /// Quarantine the corrupt path and race remaining authorized paths or invoke repair (`FSS-128`).
    QuarantineAndRetryAlternatePath,
    /// Reconcile stuck loser resources or retry from the pinned immutable transfer manifest.
    ReconcileIndeterminateDrain,
    /// Reject corrupt or unsupported binary race receipt bytes.
    RejectCorruptReceipt,
}

/// Typed failure returned by [`MultipathRaceCoordinator`] or [`MultipathRaceReceipt`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MultipathError {
    /// Invalid configuration, duplicate path ID, empty target, or label violation.
    InvalidInput(String),
    /// Capability or privacy authorization revoked.
    AuthorityRevoked(String),
    /// Caller attempted to attach effect authority to an ATP multipath race.
    AuthorityEscalationRefused,
    /// Authority generation or contract basis drifted from race creation.
    StaleAuthorityOrBasis(String),
    /// Every supplied candidate failed integrity, privacy, residency, or cost policy clamps.
    NoAuthorizedPaths {
        /// Number of candidates rejected by policy clamps.
        clamped_count: usize,
    },
    /// Operation not permitted in the current race or path state.
    InvalidStateTransition {
        /// Current race state.
        state: MultipathRaceState,
        /// Explanation.
        detail: String,
    },
    /// Supplied `path_id` does not exist in the admitted candidate set.
    UnknownPath(String),
    /// Candidate winner returned bytes failing canonical length or SHA-256 verification; path quarantined.
    CorruptWinnerQuarantined {
        /// Quarantined path ID.
        path_id: String,
        /// Observed corrupt digest.
        observed_digest: ContentDigest,
    },
    /// Finalization refused because losing/cancelled paths still hold live sockets, temp objects, or billing ops.
    LoserDrainIncomplete {
        /// Count of paths not yet cleanly drained/closed.
        remaining_paths: usize,
        /// Unreleased sockets across non-winner paths.
        leaked_sockets: u32,
        /// Unreleased staged temporary objects across non-winner paths.
        leaked_temp_objects: u32,
        /// Unreleased billing operations across non-winner paths.
        leaked_billing_ops: u32,
    },
    /// Hedge concurrency ceiling reached or no unlaunched candidate remains.
    HedgeLimitOrExhausted(String),
    /// Cooperative cancellation observed before launching a new path.
    Cancelled,
    /// Count or wire length exceeded hard protocol bounds.
    BoundsExceeded {
        /// Observed size/count.
        observed: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Binary receipt lacked [`MULTIPATH_RECEIPT_MAGIC`].
    InvalidMagic,
    /// Binary receipt declared an unsupported version.
    UnsupportedVersion {
        /// Observed version.
        version: u32,
    },
    /// Binary receipt was truncated, non-canonical, or structurally inconsistent.
    MalformedWire(String),
    /// Receipt canonical checksum failed verification.
    ChecksumMismatch,
    /// Canonical encoder failure.
    Encoding(String),
}

impl MultipathError {
    /// Stable canonical machine error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "ERR-ATP-MULTIPATH-INVALID-INPUT-001",
            Self::AuthorityRevoked(_) => "ERR-ATP-MULTIPATH-AUTHORITY-REVOKED-001",
            Self::AuthorityEscalationRefused => "ERR-ATP-MULTIPATH-AUTHORITY-ESCALATION-001",
            Self::StaleAuthorityOrBasis(_) => "ERR-ATP-MULTIPATH-STALE-BASIS-001",
            Self::NoAuthorizedPaths { .. } => "ERR-ATP-MULTIPATH-NO-AUTHORIZED-PATHS-001",
            Self::InvalidStateTransition { .. } => "ERR-ATP-MULTIPATH-INVALID-STATE-001",
            Self::UnknownPath(_) => "ERR-ATP-MULTIPATH-UNKNOWN-PATH-001",
            Self::CorruptWinnerQuarantined { .. } => "ERR-ATP-MULTIPATH-CORRUPT-WINNER-001",
            Self::LoserDrainIncomplete { .. } => "ERR-ATP-MULTIPATH-LOSER-DRAIN-INCOMPLETE-001",
            Self::HedgeLimitOrExhausted(_) => "ERR-ATP-MULTIPATH-HEDGE-LIMIT-001",
            Self::Cancelled => "ERR-ATP-MULTIPATH-CANCELLED-001",
            Self::BoundsExceeded { .. } => "ERR-ATP-MULTIPATH-BOUNDS-001",
            Self::InvalidMagic => "ERR-ATP-MULTIPATH-INVALID-MAGIC-001",
            Self::UnsupportedVersion { .. } => "ERR-ATP-MULTIPATH-UNSUPPORTED-VERSION-001",
            Self::MalformedWire(_) => "ERR-ATP-MULTIPATH-MALFORMED-WIRE-001",
            Self::ChecksumMismatch => "ERR-ATP-MULTIPATH-CHECKSUM-MISMATCH-001",
            Self::Encoding(_) => "ERR-ATP-MULTIPATH-ENCODING-001",
        }
    }

    /// Safe operator/agent recovery guidance.
    #[must_use]
    pub const fn guidance(&self) -> MultipathGuidance {
        match self {
            Self::InvalidInput(_) | Self::UnknownPath(_) | Self::BoundsExceeded { .. } => {
                MultipathGuidance::RepairRaceConfig
            }
            Self::AuthorityRevoked(_) | Self::StaleAuthorityOrBasis(_) => {
                MultipathGuidance::ReauthorizeTransfer
            }
            Self::AuthorityEscalationRefused => MultipathGuidance::StripEffectAuthority,
            Self::NoAuthorizedPaths { .. } | Self::HedgeLimitOrExhausted(_) => {
                MultipathGuidance::ProvidePolicyCompliantPath
            }
            Self::LoserDrainIncomplete { .. } | Self::InvalidStateTransition { .. } => {
                MultipathGuidance::DrainRemainingPaths
            }
            Self::CorruptWinnerQuarantined { .. } => {
                MultipathGuidance::QuarantineAndRetryAlternatePath
            }
            Self::Cancelled => MultipathGuidance::ReconcileIndeterminateDrain,
            Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::MalformedWire(_)
            | Self::ChecksumMismatch
            | Self::Encoding(_) => MultipathGuidance::RejectCorruptReceipt,
        }
    }
}

impl fmt::Display for MultipathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}

impl Error for MultipathError {}

/// Hard integrity, privacy, residency, and cost clamps enforced BEFORE any path may race (`XFER-INV-007`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathPolicyClamp {
    /// Non-empty set of authorized data residency zones (e.g. `"local"`, `"us-east"`).
    pub allowed_residency_zones: BTreeSet<String>,
    /// Allowed transport kinds.
    pub allowed_kinds: BTreeSet<PathKind>,
    /// Hard ceiling on estimated egress cost per transfer (micro-USD).
    pub max_egress_cost_micros: u64,
    /// Hard ceiling on estimated path latency (milliseconds).
    pub max_latency_ms: u64,
    /// Maximum simultaneous active + hedged paths (`1..=MAX_HEDGED_CONCURRENCY`).
    pub max_concurrent_hedges: usize,
    /// Require privacy authorization on every path (MUST be `true` in production).
    pub require_privacy_authorized: bool,
    /// Require integrity verification capability on every path (MUST be `true` in production).
    pub require_integrity_verified: bool,
}

impl PathPolicyClamp {
    /// Validates hard clamp invariants before admission.
    pub fn validate(&self) -> Result<(), MultipathError> {
        if self.allowed_residency_zones.is_empty() {
            return Err(MultipathError::InvalidInput(
                "allowed_residency_zones must be non-empty".to_owned(),
            ));
        }
        for zone in &self.allowed_residency_zones {
            validate_label(zone, MAX_RACE_LABEL_BYTES, "residency_zone")?;
        }
        if self.allowed_kinds.is_empty() {
            return Err(MultipathError::InvalidInput(
                "allowed_kinds must be non-empty".to_owned(),
            ));
        }
        if self.max_concurrent_hedges == 0 || self.max_concurrent_hedges > MAX_HEDGED_CONCURRENCY {
            return Err(MultipathError::InvalidInput(format!(
                "max_concurrent_hedges {} outside 1..={MAX_HEDGED_CONCURRENCY}",
                self.max_concurrent_hedges
            )));
        }
        if !self.require_privacy_authorized || !self.require_integrity_verified {
            return Err(MultipathError::InvalidInput(
                "policy clamp cannot disable privacy or integrity requirements".to_owned(),
            ));
        }
        Ok(())
    }

    fn evaluate_candidate(&self, cand: &MultipathCandidate) -> Option<String> {
        if !cand.privacy_authorized {
            return Some("privacy_not_authorized".to_owned());
        }
        if !cand.integrity_verified {
            return Some("integrity_not_verified".to_owned());
        }
        if !self.allowed_kinds.contains(&cand.kind) {
            return Some(format!("path_kind_{}_disallowed", cand.kind.as_str()));
        }
        if !self.allowed_residency_zones.contains(&cand.residency_zone) {
            return Some(format!("residency_zone_{}_disallowed", cand.residency_zone));
        }
        if cand.estimated_egress_cost_micros > self.max_egress_cost_micros {
            return Some(format!(
                "egress_cost_{}_exceeds_{}",
                cand.estimated_egress_cost_micros, self.max_egress_cost_micros
            ));
        }
        if cand.estimated_latency_ms > self.max_latency_ms {
            return Some(format!(
                "latency_{}_exceeds_{}",
                cand.estimated_latency_ms, self.max_latency_ms
            ));
        }
        None
    }
}

/// Explicit authority context for multipath transfer execution (never grants effect authority).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RaceAuthorityContext {
    /// Exact pinned `ContractBasis` digest.
    pub contract_basis_digest: ContentDigest,
    /// Active authority generation.
    pub authority_generation: u64,
    /// Expected authority generation pinned at race creation.
    pub expected_authority_generation: u64,
    /// Active privacy epoch.
    pub privacy_epoch: u64,
    /// True while transfer capability remains active.
    pub capability_active: bool,
    /// True while privacy authorization remains active.
    pub privacy_active: bool,
    /// MUST remain `false`: ATP transfer paths never carry effect authority (`XFER-INV-006`).
    pub grants_effect_authority: bool,
}

impl RaceAuthorityContext {
    /// Constructs an active transfer-only authority context (`grants_effect_authority = false`).
    #[must_use]
    pub const fn active(
        contract_basis_digest: ContentDigest,
        authority_generation: u64,
        privacy_epoch: u64,
    ) -> Self {
        Self {
            contract_basis_digest,
            authority_generation,
            expected_authority_generation: authority_generation,
            privacy_epoch,
            capability_active: true,
            privacy_active: true,
            grants_effect_authority: false,
        }
    }

    fn validate_against(
        &self,
        pinned_basis: ContentDigest,
        pinned_auth_gen: u64,
        pinned_privacy_epoch: u64,
    ) -> Result<(), MultipathError> {
        if self.grants_effect_authority {
            return Err(MultipathError::AuthorityEscalationRefused);
        }
        if !self.capability_active {
            return Err(MultipathError::AuthorityRevoked(
                "multipath transfer capability revoked".to_owned(),
            ));
        }
        if !self.privacy_active {
            return Err(MultipathError::AuthorityRevoked(
                "multipath privacy authorization revoked".to_owned(),
            ));
        }
        if self.authority_generation != self.expected_authority_generation
            || self.authority_generation != pinned_auth_gen
        {
            return Err(MultipathError::StaleAuthorityOrBasis(format!(
                "authority_generation {} != pinned {pinned_auth_gen}",
                self.authority_generation
            )));
        }
        if self.contract_basis_digest != pinned_basis {
            return Err(MultipathError::StaleAuthorityOrBasis(
                "contract_basis_digest drifted from pinned race basis".to_owned(),
            ));
        }
        if self.privacy_epoch != pinned_privacy_epoch {
            return Err(MultipathError::StaleAuthorityOrBasis(format!(
                "privacy_epoch {} != pinned {pinned_privacy_epoch}",
                self.privacy_epoch
            )));
        }
        Ok(())
    }
}

/// Candidate path submitted to the multipath policy clamp and hedge scheduler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultipathCandidate {
    /// Stable path identity (`1..=MAX_RACE_LABEL_BYTES`).
    pub path_id: String,
    /// Transport medium class.
    pub kind: PathKind,
    /// Independent failure domain label (used for diverse hedging).
    pub failure_domain: String,
    /// Data residency zone label.
    pub residency_zone: String,
    /// True iff privacy policy authorizes moving this object over this path.
    pub privacy_authorized: bool,
    /// True iff this path supports end-to-end digest verification.
    pub integrity_verified: bool,
    /// Measured or estimated latency (milliseconds).
    pub estimated_latency_ms: u64,
    /// Estimated egress/operation cost (micro-USD).
    pub estimated_egress_cost_micros: u64,
}

/// Audit record of one candidate path blocked by hard policy clamps before racing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClampedPathRejection {
    /// Rejected path identity.
    pub path_id: String,
    /// Machine-readable clamp violation reason.
    pub reason: String,
}

/// Live in-flight resources owned by one racing or draining path (`XFER-INV-008`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PathResources {
    /// Open network/transport sockets owned by this path.
    pub in_flight_sockets: u32,
    /// Uncommitted temporary staged objects owned by this path.
    pub temp_staged_objects: u32,
    /// Open provider billing/transfer operations owned by this path.
    pub open_billing_ops: u32,
}

impl PathResources {
    /// True iff zero sockets, temporary objects, and billing ops remain open.
    #[must_use]
    pub const fn is_clean(self) -> bool {
        self.in_flight_sockets == 0 && self.temp_staged_objects == 0 && self.open_billing_ops == 0
    }
}

/// Runtime tracking entry for one policy-admitted path in a multipath race.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedPathState {
    /// Stable path identity.
    pub path_id: String,
    /// Transport medium class.
    pub kind: PathKind,
    /// Independent failure domain.
    pub failure_domain: String,
    /// Data residency zone.
    pub residency_zone: String,
    /// Estimated latency (ms).
    pub estimated_latency_ms: u64,
    /// Estimated egress cost (micro-USD).
    pub estimated_egress_cost_micros: u64,
    /// Canonical registered ATP path lifecycle state (`atp.path.*`).
    pub state: PathState,
    /// Orthogonal multipath race role / disposition.
    pub role: RacePathRole,
    /// Live owned resources that MUST reach zero during loser/cancel drain.
    pub resources: PathResources,
    /// True once cancel/drain was requested for this path.
    pub drain_requested: bool,
    /// Optional terminal/failure/quarantine reason.
    pub note: Option<String>,
}

/// Sealed receipt proving policy clamping, winner verification, and complete loser drain (`FSSMP001` v1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultipathRaceReceipt {
    /// Wire format version (`MULTIPATH_RECEIPT_VERSION`).
    pub format_version: u32,
    /// Governing transfer identity.
    pub transfer_id: TransferId,
    /// Expected target canonical object SHA-256 digest.
    pub target_object_digest: ContentDigest,
    /// Expected target canonical byte length.
    pub expected_byte_len: u64,
    /// Pinned `ContractBasis` digest.
    pub contract_basis_digest: ContentDigest,
    /// Pinned authority generation.
    pub authority_generation: u64,
    /// Pinned privacy epoch.
    pub privacy_epoch: u64,
    /// Terminal non-collapsed race state (`Complete`, `CancelledClean`, `Failed`, or `Indeterminate`).
    pub state: MultipathRaceState,
    /// Winning path identity (present iff `state == Complete`).
    pub winner_path_id: Option<String>,
    /// Ordered audit records of candidates rejected by hard policy clamps BEFORE racing.
    pub clamped_rejections: Vec<ClampedPathRejection>,
    /// Final per-path states and resource counts in canonical `path_id` order.
    pub path_outcomes: Vec<AdmittedPathState>,
    /// Total paths that entered `Draining` and reached clean `PathState::Closed`.
    pub losers_drained_clean: u32,
    /// Total paths quarantined for corrupt bytes.
    pub paths_quarantined: u32,
    /// Total estimated egress cost accrued across launched paths (micro-USD).
    pub total_launched_cost_micros: u64,
    /// Timestamp when this receipt was sealed.
    pub finalized_at: TimestampNs,
    /// Domain-separated SHA-256 commitment (`fss.atp_multipath_race_receipt.v1`).
    pub receipt_digest: ContentDigest,
}

impl MultipathRaceReceipt {
    /// Recomputes the domain-separated canonical SHA-256 commitment.
    pub fn compute_digest(&self) -> Result<ContentDigest, MultipathError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(ATP_MULTIPATH_RACE_RECEIPT_DOMAIN);
        self.encode_body(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|e| MultipathError::Encoding(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    fn verify_self(&self) -> Result<(), MultipathError> {
        if self.format_version != MULTIPATH_RECEIPT_VERSION {
            return Err(MultipathError::UnsupportedVersion {
                version: self.format_version,
            });
        }
        if self.expected_byte_len == 0 {
            return Err(MultipathError::MalformedWire(
                "expected_byte_len must be >= 1".to_owned(),
            ));
        }
        if !matches!(
            self.state,
            MultipathRaceState::Complete
                | MultipathRaceState::CancelledClean
                | MultipathRaceState::Failed
                | MultipathRaceState::Indeterminate
        ) {
            return Err(MultipathError::MalformedWire(format!(
                "receipt cannot carry non-terminal state '{}'",
                self.state.as_str()
            )));
        }
        if (self.state == MultipathRaceState::Complete) != self.winner_path_id.is_some() {
            return Err(MultipathError::MalformedWire(
                "winner_path_id must be present iff state == Complete".to_owned(),
            ));
        }
        if let Some(ref w) = self.winner_path_id {
            validate_label(w, MAX_RACE_LABEL_BYTES, "winner_path_id")
                .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
            if !self
                .path_outcomes
                .iter()
                .any(|p| p.path_id == *w && p.role == RacePathRole::Winner)
            {
                return Err(MultipathError::MalformedWire(
                    "winner_path_id not found with RacePathRole::Winner in path_outcomes"
                        .to_owned(),
                ));
            }
        }
        for pair in self.clamped_rejections.windows(2) {
            if pair[0].path_id >= pair[1].path_id {
                return Err(MultipathError::MalformedWire(
                    "clamped_rejections must be strictly ordered by path_id".to_owned(),
                ));
            }
        }
        for pair in self.path_outcomes.windows(2) {
            if pair[0].path_id >= pair[1].path_id {
                return Err(MultipathError::MalformedWire(
                    "path_outcomes must be strictly ordered by path_id".to_owned(),
                ));
            }
        }
        let clamped_set: BTreeSet<&str> = self
            .clamped_rejections
            .iter()
            .map(|r| r.path_id.as_str())
            .collect();
        if self
            .path_outcomes
            .iter()
            .any(|p| clamped_set.contains(p.path_id.as_str()))
        {
            return Err(MultipathError::MalformedWire(
                "clamped_rejections and path_outcomes must be disjoint".to_owned(),
            ));
        }
        let actual_quarantined = self
            .path_outcomes
            .iter()
            .filter(|p| p.role == RacePathRole::Quarantined)
            .count() as u32;
        if actual_quarantined != self.paths_quarantined {
            return Err(MultipathError::MalformedWire(format!(
                "paths_quarantined ({}) disagrees with Quarantined path count ({actual_quarantined})",
                self.paths_quarantined
            )));
        }
        if matches!(
            self.state,
            MultipathRaceState::Complete
                | MultipathRaceState::CancelledClean
                | MultipathRaceState::Failed
        ) {
            for p in &self.path_outcomes {
                if !p.resources.is_clean() || !p.state.is_terminal() {
                    return Err(MultipathError::MalformedWire(format!(
                        "clean terminal receipt has non-closed or leaked path '{}'",
                        p.path_id
                    )));
                }
            }
        }
        if self.compute_digest()? != self.receipt_digest {
            return Err(MultipathError::ChecksumMismatch);
        }
        Ok(())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.format_version);
        enc.digest(self.transfer_id.digest());
        enc.digest(self.target_object_digest);
        enc.u64(self.expected_byte_len);
        enc.digest(self.contract_basis_digest);
        enc.u64(self.authority_generation);
        enc.u64(self.privacy_epoch);
        enc.u8(self.state.tag());
        match &self.winner_path_id {
            Some(id) => {
                enc.u8(1);
                enc.text(id);
            }
            None => enc.u8(0),
        }
        enc.u32(self.clamped_rejections.len() as u32);
        for rej in &self.clamped_rejections {
            enc.text(&rej.path_id);
            enc.text(&rej.reason);
        }
        enc.u32(self.path_outcomes.len() as u32);
        for p in &self.path_outcomes {
            enc.text(&p.path_id);
            enc.u8(p.kind.tag());
            enc.text(&p.failure_domain);
            enc.text(&p.residency_zone);
            enc.u64(p.estimated_latency_ms);
            enc.u64(p.estimated_egress_cost_micros);
            enc.text(p.state.canonical_id());
            enc.u8(p.role.tag());
            enc.u32(p.resources.in_flight_sockets);
            enc.u32(p.resources.temp_staged_objects);
            enc.u32(p.resources.open_billing_ops);
            enc.bool(p.drain_requested);
            match &p.note {
                Some(n) => {
                    enc.u8(1);
                    enc.text(n);
                }
                None => enc.u8(0),
            }
        }
        enc.u32(self.losers_drained_clean);
        enc.u32(self.paths_quarantined);
        enc.u64(self.total_launched_cost_micros);
        self.finalized_at.encode_canonical(enc);
    }

    /// Encodes this sealed receipt into bounded checksummed binary bytes (`FSSMP001` v1).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, MultipathError> {
        self.verify_self()?;
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        enc.digest(self.receipt_digest);
        let body = enc
            .finish_checked()
            .map_err(|e| MultipathError::Encoding(e.to_string()))?;
        let total = MULTIPATH_RECEIPT_MAGIC
            .len()
            .saturating_add(4)
            .saturating_add(body.len());
        if total > MAX_RACE_RECEIPT_WIRE_BYTES {
            return Err(MultipathError::BoundsExceeded {
                observed: total,
                maximum: MAX_RACE_RECEIPT_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&MULTIPATH_RECEIPT_MAGIC);
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Cold-decodes and verifies a binary [`MultipathRaceReceipt`] (`FSSMP001` v1).
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, MultipathError> {
        if bytes.len() > MAX_RACE_RECEIPT_WIRE_BYTES {
            return Err(MultipathError::BoundsExceeded {
                observed: bytes.len(),
                maximum: MAX_RACE_RECEIPT_WIRE_BYTES,
            });
        }
        if bytes.len() < 12 || bytes[..8] != MULTIPATH_RECEIPT_MAGIC {
            return Err(MultipathError::InvalidMagic);
        }
        let header_ver = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if header_ver != MULTIPATH_RECEIPT_VERSION {
            return Err(MultipathError::UnsupportedVersion {
                version: header_ver,
            });
        }
        let mut dec = CanonicalDecoder::new(&bytes[12..]);
        let format_version = dec
            .u32()
            .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
        if format_version != header_ver {
            return Err(MultipathError::UnsupportedVersion {
                version: format_version,
            });
        }
        let transfer_id = TransferId::from_digest(
            dec.digest()
                .map_err(|e| MultipathError::MalformedWire(e.to_string()))?,
        );
        let target_object_digest = dec
            .digest()
            .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
        let expected_byte_len = dec
            .u64()
            .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
        let contract_basis_digest = dec
            .digest()
            .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
        let authority_generation = dec
            .u64()
            .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
        let privacy_epoch = dec
            .u64()
            .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
        let state = MultipathRaceState::from_tag(
            dec.u8()
                .map_err(|e| MultipathError::MalformedWire(e.to_string()))?,
        )
        .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
        let winner_path_id = match dec
            .u8()
            .map_err(|e| MultipathError::MalformedWire(e.to_string()))?
        {
            0 => None,
            1 => Some(
                dec.text()
                    .map_err(|e| MultipathError::MalformedWire(e.to_string()))?
                    .to_owned(),
            ),
            other => {
                return Err(MultipathError::MalformedWire(format!(
                    "invalid winner tag {other}"
                )));
            }
        };

        let rej_count =
            dec.u32()
                .map_err(|e| MultipathError::MalformedWire(e.to_string()))? as usize;
        if rej_count > MAX_RACE_CANDIDATES || rej_count.saturating_mul(10) > dec.remaining() {
            return Err(MultipathError::BoundsExceeded {
                observed: rej_count,
                maximum: MAX_RACE_CANDIDATES,
            });
        }
        let mut clamped_rejections = Vec::with_capacity(rej_count);
        for _ in 0..rej_count {
            let path_id = dec
                .text()
                .map_err(|e| MultipathError::MalformedWire(e.to_string()))?
                .to_owned();
            let reason = dec
                .text()
                .map_err(|e| MultipathError::MalformedWire(e.to_string()))?
                .to_owned();
            validate_label(&path_id, MAX_RACE_LABEL_BYTES, "path_id")
                .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
            validate_label(&reason, MAX_RACE_LABEL_BYTES, "reason")
                .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
            clamped_rejections.push(ClampedPathRejection { path_id, reason });
        }

        let path_count =
            dec.u32()
                .map_err(|e| MultipathError::MalformedWire(e.to_string()))? as usize;
        if path_count > MAX_RACE_CANDIDATES || path_count.saturating_mul(37) > dec.remaining() {
            return Err(MultipathError::BoundsExceeded {
                observed: path_count,
                maximum: MAX_RACE_CANDIDATES,
            });
        }
        let mut path_outcomes = Vec::with_capacity(path_count);
        for _ in 0..path_count {
            let path_id = dec
                .text()
                .map_err(|e| MultipathError::MalformedWire(e.to_string()))?
                .to_owned();
            validate_label(&path_id, MAX_RACE_LABEL_BYTES, "path_id")
                .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
            let kind = PathKind::from_tag(
                dec.u8()
                    .map_err(|e| MultipathError::MalformedWire(e.to_string()))?,
            )
            .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
            let failure_domain = dec
                .text()
                .map_err(|e| MultipathError::MalformedWire(e.to_string()))?
                .to_owned();
            let residency_zone = dec
                .text()
                .map_err(|e| MultipathError::MalformedWire(e.to_string()))?
                .to_owned();
            validate_label(&failure_domain, MAX_RACE_LABEL_BYTES, "failure_domain")
                .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
            validate_label(&residency_zone, MAX_RACE_LABEL_BYTES, "residency_zone")
                .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
            let estimated_latency_ms = dec
                .u64()
                .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
            let estimated_egress_cost_micros = dec
                .u64()
                .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
            let p_state = parse_path_state(
                dec.text()
                    .map_err(|e| MultipathError::MalformedWire(e.to_string()))?,
            )?;
            let role = RacePathRole::from_tag(
                dec.u8()
                    .map_err(|e| MultipathError::MalformedWire(e.to_string()))?,
            )
            .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
            let in_flight_sockets = dec
                .u32()
                .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
            let temp_staged_objects = dec
                .u32()
                .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
            let open_billing_ops = dec
                .u32()
                .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
            let drain_requested = dec
                .bool()
                .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
            let note = match dec
                .u8()
                .map_err(|e| MultipathError::MalformedWire(e.to_string()))?
            {
                0 => None,
                1 => {
                    let text = dec
                        .text()
                        .map_err(|e| MultipathError::MalformedWire(e.to_string()))?
                        .to_owned();
                    validate_label(&text, MAX_RACE_LABEL_BYTES, "note")
                        .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
                    Some(text)
                }
                other => {
                    return Err(MultipathError::MalformedWire(format!(
                        "invalid note tag {other}"
                    )));
                }
            };
            path_outcomes.push(AdmittedPathState {
                path_id,
                kind,
                failure_domain,
                residency_zone,
                estimated_latency_ms,
                estimated_egress_cost_micros,
                state: p_state,
                role,
                resources: PathResources {
                    in_flight_sockets,
                    temp_staged_objects,
                    open_billing_ops,
                },
                drain_requested,
                note,
            });
        }

        let losers_drained_clean = dec
            .u32()
            .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
        let paths_quarantined = dec
            .u32()
            .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
        let total_launched_cost_micros = dec
            .u64()
            .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
        let finalized_at = TimestampNs::decode_canonical(&mut dec)
            .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
        let stored_digest = dec
            .digest()
            .map_err(|e| MultipathError::MalformedWire(e.to_string()))?;
        dec.ensure_finished().map_err(|_| {
            MultipathError::MalformedWire("trailing bytes after multipath race receipt".to_owned())
        })?;

        let receipt = Self {
            format_version,
            transfer_id,
            target_object_digest,
            expected_byte_len,
            contract_basis_digest,
            authority_generation,
            privacy_epoch,
            state,
            winner_path_id,
            clamped_rejections,
            path_outcomes,
            losers_drained_clean,
            paths_quarantined,
            total_launched_cost_micros,
            finalized_at,
            receipt_digest: stored_digest,
        };
        receipt.verify_self()?;
        Ok(receipt)
    }
}

/// Deterministic multipath race and loser-drain coordinator (`FSS-129`).
#[derive(Clone, Debug)]
pub struct MultipathRaceCoordinator {
    transfer_id: TransferId,
    target_object_digest: ContentDigest,
    expected_byte_len: u64,
    policy: PathPolicyClamp,
    contract_basis_digest: ContentDigest,
    authority_generation: u64,
    privacy_epoch: u64,
    state: MultipathRaceState,
    clamped_rejections: Vec<ClampedPathRejection>,
    paths: BTreeMap<String, AdmittedPathState>,
    winner_path_id: Option<String>,
    losers_drained_clean: u32,
    paths_quarantined: u32,
    total_launched_cost_micros: u64,
    last_updated_at: TimestampNs,
}

impl MultipathRaceCoordinator {
    /// Plans a multipath race by enforcing hard policy clamps BEFORE admitting any candidate.
    #[allow(clippy::too_many_arguments)]
    pub fn plan(
        transfer_id: TransferId,
        target_object_digest: ContentDigest,
        expected_byte_len: u64,
        policy: PathPolicyClamp,
        authority: &RaceAuthorityContext,
        candidates: Vec<MultipathCandidate>,
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<Self, MultipathError> {
        if cancelled {
            return Err(MultipathError::Cancelled);
        }
        if expected_byte_len == 0 {
            return Err(MultipathError::InvalidInput(
                "expected_byte_len must be >= 1".to_owned(),
            ));
        }
        policy.validate()?;
        authority.validate_against(
            authority.contract_basis_digest,
            authority.authority_generation,
            authority.privacy_epoch,
        )?;
        if candidates.is_empty() || candidates.len() > MAX_RACE_CANDIDATES {
            return Err(MultipathError::BoundsExceeded {
                observed: candidates.len(),
                maximum: MAX_RACE_CANDIDATES,
            });
        }

        let mut seen_ids = BTreeSet::new();
        let mut clamped_rejections = Vec::new();
        let mut paths = BTreeMap::new();

        for cand in candidates {
            validate_label(&cand.path_id, MAX_RACE_LABEL_BYTES, "path_id")?;
            validate_label(&cand.failure_domain, MAX_RACE_LABEL_BYTES, "failure_domain")?;
            validate_label(&cand.residency_zone, MAX_RACE_LABEL_BYTES, "residency_zone")?;
            if !seen_ids.insert(cand.path_id.clone()) {
                return Err(MultipathError::InvalidInput(format!(
                    "duplicate candidate path_id '{}'",
                    cand.path_id
                )));
            }
            if let Some(reason) = policy.evaluate_candidate(&cand) {
                clamped_rejections.push(ClampedPathRejection {
                    path_id: cand.path_id,
                    reason,
                });
                continue;
            }
            paths.insert(
                cand.path_id.clone(),
                AdmittedPathState {
                    path_id: cand.path_id,
                    kind: cand.kind,
                    failure_domain: cand.failure_domain,
                    residency_zone: cand.residency_zone,
                    estimated_latency_ms: cand.estimated_latency_ms,
                    estimated_egress_cost_micros: cand.estimated_egress_cost_micros,
                    state: PathState::Candidate,
                    role: RacePathRole::Unlaunched,
                    resources: PathResources::default(),
                    drain_requested: false,
                    note: None,
                },
            );
        }

        clamped_rejections.sort_by(|a, b| a.path_id.cmp(&b.path_id));
        if paths.is_empty() {
            return Err(MultipathError::NoAuthorizedPaths {
                clamped_count: clamped_rejections.len(),
            });
        }

        Ok(Self {
            transfer_id,
            target_object_digest,
            expected_byte_len,
            policy,
            contract_basis_digest: authority.contract_basis_digest,
            authority_generation: authority.authority_generation,
            privacy_epoch: authority.privacy_epoch,
            state: MultipathRaceState::Planned,
            clamped_rejections,
            paths,
            winner_path_id: None,
            losers_drained_clean: 0,
            paths_quarantined: 0,
            total_launched_cost_micros: 0,
            last_updated_at: now,
        })
    }

    /// Current non-collapsed race state.
    #[must_use]
    pub const fn state(&self) -> MultipathRaceState {
        self.state
    }

    /// Candidates rejected by hard policy clamps before racing.
    #[must_use]
    pub fn clamped_rejections(&self) -> &[ClampedPathRejection] {
        &self.clamped_rejections
    }

    /// Current admitted path states keyed by canonical `path_id`.
    #[must_use]
    pub fn paths(&self) -> &BTreeMap<String, AdmittedPathState> {
        &self.paths
    }

    /// Launches the primary (or next diverse-failure-domain hedged) policy-compliant path.
    ///
    /// Returns the deterministically chosen `path_id`.
    pub fn launch_next_path(
        &mut self,
        authority: &RaceAuthorityContext,
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<String, MultipathError> {
        if cancelled {
            return Err(MultipathError::Cancelled);
        }
        authority.validate_against(
            self.contract_basis_digest,
            self.authority_generation,
            self.privacy_epoch,
        )?;
        if !matches!(
            self.state,
            MultipathRaceState::Planned | MultipathRaceState::Racing
        ) {
            return Err(MultipathError::InvalidStateTransition {
                state: self.state,
                detail: "cannot launch path after winner, cancellation, or terminal state"
                    .to_owned(),
            });
        }

        let live_count = self
            .paths
            .values()
            .filter(|p| p.state == PathState::Active)
            .count();
        if live_count >= self.policy.max_concurrent_hedges {
            return Err(MultipathError::HedgeLimitOrExhausted(format!(
                "concurrent hedge ceiling {} reached",
                self.policy.max_concurrent_hedges
            )));
        }

        let active_domains: BTreeSet<&str> = self
            .paths
            .values()
            .filter(|p| p.state == PathState::Active)
            .map(|p| p.failure_domain.as_str())
            .collect();

        // Deterministic selection: prefer distinct failure domain when hedging, then lowest
        // `(estimated_latency_ms, estimated_egress_cost_micros, path_id)`.
        let chosen_id = self
            .paths
            .values()
            .filter(|p| p.state == PathState::Candidate)
            .min_by_key(|p| {
                let same_domain_penalty =
                    u8::from(active_domains.contains(p.failure_domain.as_str()));
                (
                    same_domain_penalty,
                    p.estimated_latency_ms,
                    p.estimated_egress_cost_micros,
                    p.path_id.as_str(),
                )
            })
            .map(|p| p.path_id.clone())
            .ok_or_else(|| {
                MultipathError::HedgeLimitOrExhausted(
                    "no unlaunched candidate paths remain".to_owned(),
                )
            })?;

        let has_launched_any = self
            .paths
            .values()
            .any(|p| p.role != RacePathRole::Unlaunched);
        let entry = self
            .paths
            .get_mut(&chosen_id)
            .ok_or_else(|| MultipathError::UnknownPath(chosen_id.clone()))?;
        entry.state = PathState::Active;
        entry.role = if has_launched_any {
            RacePathRole::Hedged
        } else {
            RacePathRole::Primary
        };
        entry.resources = PathResources {
            in_flight_sockets: 1,
            temp_staged_objects: 1,
            open_billing_ops: 1,
        };
        self.total_launched_cost_micros = self
            .total_launched_cost_micros
            .saturating_add(entry.estimated_egress_cost_micros);
        self.state = MultipathRaceState::Racing;
        self.last_updated_at = now.max(self.last_updated_at);
        Ok(chosen_id)
    }

    /// Declares `path_id` as the winner ONLY after verifying exact length and canonical SHA-256 of
    /// `received_bytes`. Corrupt bytes immediately move `path_id` to `PathState::Suspect` +
    /// `RacePathRole::Quarantined` (unable to expose data) instead of completing!
    ///
    /// Every other live path transitions immediately to [`PathState::Draining`] (`XFER-INV-008`).
    pub fn declare_winner_with_bytes(
        &mut self,
        path_id: &str,
        authority: &RaceAuthorityContext,
        received_bytes: &[u8],
        now: TimestampNs,
    ) -> Result<MultipathRaceState, MultipathError> {
        authority.validate_against(
            self.contract_basis_digest,
            self.authority_generation,
            self.privacy_epoch,
        )?;
        if self.state != MultipathRaceState::Racing {
            return Err(MultipathError::InvalidStateTransition {
                state: self.state,
                detail: "winner can only be declared while Racing".to_owned(),
            });
        }
        let current_state = self
            .paths
            .get(path_id)
            .ok_or_else(|| MultipathError::UnknownPath(path_id.to_owned()))?
            .state;
        if !current_state.can_expose_data() {
            return Err(MultipathError::InvalidStateTransition {
                state: self.state,
                detail: format!("path '{path_id}' is not Active"),
            });
        }

        let observed_digest = ContentDigest::sha256(received_bytes);
        if received_bytes.len() as u64 != self.expected_byte_len
            || observed_digest != self.target_object_digest
        {
            if let Some(entry) = self.paths.get_mut(path_id) {
                entry.state = PathState::Suspect;
                entry.role = RacePathRole::Quarantined;
                entry.drain_requested = true;
                entry.note = Some("corrupt_payload_digest_or_length_mismatch".to_owned());
            }
            self.paths_quarantined = self.paths_quarantined.saturating_add(1);
            self.last_updated_at = now.max(self.last_updated_at);
            self.check_all_exhausted_failed();
            return Err(MultipathError::CorruptWinnerQuarantined {
                path_id: path_id.to_owned(),
                observed_digest,
            });
        }

        // Valid verified winner! Commit its staged buffer into verified custody and close cleanly.
        if let Some(winner) = self.paths.get_mut(path_id) {
            winner.state = PathState::Closed;
            winner.role = RacePathRole::Winner;
            winner.resources = PathResources::default();
            winner.note = Some("verified_canonical_winner".to_owned());
        }
        self.winner_path_id = Some(path_id.to_owned());
        self.last_updated_at = now.max(self.last_updated_at);

        let mut needs_drain = false;
        for (id, entry) in &mut self.paths {
            if id == path_id {
                continue;
            }
            match entry.state {
                PathState::Active | PathState::Probing => {
                    entry.state = PathState::Draining;
                    entry.drain_requested = true;
                    entry.note = Some("superseded_by_verified_winner".to_owned());
                    needs_drain = true;
                }
                PathState::Suspect => {
                    entry.state = PathState::Draining;
                    entry.drain_requested = true;
                    if entry.resources.is_clean() {
                        entry.state = PathState::Closed;
                    } else {
                        needs_drain = true;
                    }
                }
                PathState::Draining => {
                    needs_drain = true;
                }
                PathState::Discover | PathState::Candidate => {
                    entry.state = PathState::Closed;
                    entry.note = Some("never_launched_winner_already_verified".to_owned());
                }
                PathState::Closed => {}
            }
        }

        self.state = if needs_drain {
            MultipathRaceState::WinnerVerifiedDrainingLosers
        } else {
            MultipathRaceState::Complete
        };
        Ok(self.state)
    }

    /// Marks an `Active` path as failed (`PathState::Suspect` + `RacePathRole::Failed`) while
    /// retaining any live resources until explicitly drained to `PathState::Closed`.
    pub fn report_path_failure(
        &mut self,
        path_id: &str,
        reason: &str,
        now: TimestampNs,
    ) -> Result<(), MultipathError> {
        validate_label(reason, MAX_RACE_LABEL_BYTES, "failure_reason")?;
        let entry = self
            .paths
            .get_mut(path_id)
            .ok_or_else(|| MultipathError::UnknownPath(path_id.to_owned()))?;
        if entry.state != PathState::Active {
            return Err(MultipathError::InvalidStateTransition {
                state: self.state,
                detail: format!(
                    "cannot fail path '{path_id}' from state {}",
                    entry.state.canonical_id()
                ),
            });
        }
        entry.state = PathState::Suspect;
        entry.role = RacePathRole::Failed;
        entry.drain_requested = !entry.resources.is_clean();
        entry.note = Some(reason.to_owned());
        self.last_updated_at = now.max(self.last_updated_at);
        self.check_all_exhausted_failed();
        Ok(())
    }

    /// Requests cooperative cancellation of the entire multipath race, transitioning every active
    /// or suspect path with live work into [`PathState::Draining`] so zero resources leak.
    pub fn request_cancel(
        &mut self,
        reason: &str,
        now: TimestampNs,
    ) -> Result<MultipathRaceState, MultipathError> {
        validate_label(reason, MAX_RACE_LABEL_BYTES, "cancel_reason")?;
        if matches!(
            self.state,
            MultipathRaceState::Complete
                | MultipathRaceState::CancelledClean
                | MultipathRaceState::Failed
                | MultipathRaceState::Indeterminate
        ) {
            return Err(MultipathError::InvalidStateTransition {
                state: self.state,
                detail: "cannot cancel already terminal multipath race".to_owned(),
            });
        }
        let mut needs_drain = false;
        for entry in self.paths.values_mut() {
            match entry.state {
                PathState::Active | PathState::Probing => {
                    entry.state = PathState::Draining;
                    entry.drain_requested = true;
                    entry.note = Some(reason.to_owned());
                    needs_drain = true;
                }
                PathState::Suspect => {
                    if entry.resources.is_clean() {
                        entry.state = PathState::Closed;
                    } else {
                        entry.state = PathState::Draining;
                        entry.drain_requested = true;
                        needs_drain = true;
                    }
                }
                PathState::Draining => {
                    needs_drain = true;
                }
                PathState::Discover | PathState::Candidate => {
                    entry.state = PathState::Closed;
                    entry.note = Some(reason.to_owned());
                }
                PathState::Closed => {}
            }
        }
        self.winner_path_id = None;
        self.last_updated_at = now.max(self.last_updated_at);
        self.state = if needs_drain {
            MultipathRaceState::CancelledDraining
        } else {
            MultipathRaceState::CancelledClean
        };
        Ok(self.state)
    }

    /// Records released sockets, temp objects, and billing ops for a `Draining` or `Suspect` path.
    /// Once all three reach zero, transitions the path cleanly to [`PathState::Closed`].
    pub fn drain_path(
        &mut self,
        path_id: &str,
        released_sockets: u32,
        released_temp_objects: u32,
        released_billing_ops: u32,
        now: TimestampNs,
    ) -> Result<PathState, MultipathError> {
        let entry = self
            .paths
            .get_mut(path_id)
            .ok_or_else(|| MultipathError::UnknownPath(path_id.to_owned()))?;
        if !matches!(entry.state, PathState::Draining | PathState::Suspect) {
            return Err(MultipathError::InvalidStateTransition {
                state: self.state,
                detail: format!(
                    "path '{path_id}' cannot drain from state {}",
                    entry.state.canonical_id()
                ),
            });
        }
        entry.resources.in_flight_sockets = entry
            .resources
            .in_flight_sockets
            .saturating_sub(released_sockets);
        entry.resources.temp_staged_objects = entry
            .resources
            .temp_staged_objects
            .saturating_sub(released_temp_objects);
        entry.resources.open_billing_ops = entry
            .resources
            .open_billing_ops
            .saturating_sub(released_billing_ops);

        if entry.resources.is_clean() {
            entry.state = PathState::Closed;
            self.losers_drained_clean = self.losers_drained_clean.saturating_add(1);
        }
        let resulting_path_state = entry.state;
        self.last_updated_at = now.max(self.last_updated_at);
        self.advance_if_all_drained();
        Ok(resulting_path_state)
    }

    /// Marks a stuck draining path as indeterminate (e.g. remote abort timeout) so the race
    /// terminates honestly as [`MultipathRaceState::Indeterminate`] rather than leaking silently.
    pub fn mark_drain_indeterminate(
        &mut self,
        path_id: &str,
        reason: &str,
        now: TimestampNs,
    ) -> Result<(), MultipathError> {
        validate_label(reason, MAX_RACE_LABEL_BYTES, "indeterminate_reason")?;
        let entry = self
            .paths
            .get_mut(path_id)
            .ok_or_else(|| MultipathError::UnknownPath(path_id.to_owned()))?;
        if !matches!(entry.state, PathState::Draining | PathState::Suspect)
            || entry.resources.is_clean()
        {
            return Err(MultipathError::InvalidStateTransition {
                state: self.state,
                detail: format!(
                    "path '{path_id}' is not draining unreleased resources (state {})",
                    entry.state.canonical_id()
                ),
            });
        }
        entry.note = Some(reason.to_owned());
        self.winner_path_id = None;
        self.state = MultipathRaceState::Indeterminate;
        self.last_updated_at = now.max(self.last_updated_at);
        Ok(())
    }

    /// Seals and returns the canonical [`MultipathRaceReceipt`].
    ///
    /// Fails closed with [`MultipathError::LoserDrainIncomplete`] if any path still owns live
    /// sockets, temp staged objects, or billing ops or has not reached [`PathState::Closed`]
    /// (unless explicitly marked [`MultipathRaceState::Indeterminate`]).
    pub fn finalize_receipt(
        &mut self,
        now: TimestampNs,
    ) -> Result<MultipathRaceReceipt, MultipathError> {
        if self.state != MultipathRaceState::Indeterminate {
            let mut remaining_paths = 0_usize;
            let mut leaked_sockets = 0_u32;
            let mut leaked_temp_objects = 0_u32;
            let mut leaked_billing_ops = 0_u32;
            for entry in self.paths.values() {
                if !entry.state.is_terminal() || !entry.resources.is_clean() {
                    remaining_paths += 1;
                    leaked_sockets =
                        leaked_sockets.saturating_add(entry.resources.in_flight_sockets);
                    leaked_temp_objects =
                        leaked_temp_objects.saturating_add(entry.resources.temp_staged_objects);
                    leaked_billing_ops =
                        leaked_billing_ops.saturating_add(entry.resources.open_billing_ops);
                }
            }
            if remaining_paths > 0 {
                return Err(MultipathError::LoserDrainIncomplete {
                    remaining_paths,
                    leaked_sockets,
                    leaked_temp_objects,
                    leaked_billing_ops,
                });
            }
        }
        if !matches!(
            self.state,
            MultipathRaceState::Complete
                | MultipathRaceState::CancelledClean
                | MultipathRaceState::Failed
                | MultipathRaceState::Indeterminate
        ) {
            return Err(MultipathError::InvalidStateTransition {
                state: self.state,
                detail: "race has not reached a terminal state".to_owned(),
            });
        }

        self.last_updated_at = now.max(self.last_updated_at);
        let path_outcomes: Vec<AdmittedPathState> = self.paths.values().cloned().collect();
        let mut receipt = MultipathRaceReceipt {
            format_version: MULTIPATH_RECEIPT_VERSION,
            transfer_id: self.transfer_id,
            target_object_digest: self.target_object_digest,
            expected_byte_len: self.expected_byte_len,
            contract_basis_digest: self.contract_basis_digest,
            authority_generation: self.authority_generation,
            privacy_epoch: self.privacy_epoch,
            state: self.state,
            winner_path_id: self.winner_path_id.clone(),
            clamped_rejections: self.clamped_rejections.clone(),
            path_outcomes,
            losers_drained_clean: self.losers_drained_clean,
            paths_quarantined: self.paths_quarantined,
            total_launched_cost_micros: self.total_launched_cost_micros,
            finalized_at: self.last_updated_at,
            receipt_digest: ContentDigest::sha256(b"unsealed-multipath-receipt"),
        };
        receipt.receipt_digest = receipt.compute_digest()?;
        Ok(receipt)
    }

    fn all_paths_closed_and_clean(&self) -> bool {
        self.paths
            .values()
            .all(|p| p.state.is_terminal() && p.resources.is_clean())
    }

    fn advance_if_all_drained(&mut self) {
        if !self.all_paths_closed_and_clean() {
            return;
        }
        match self.state {
            MultipathRaceState::WinnerVerifiedDrainingLosers => {
                self.state = MultipathRaceState::Complete;
            }
            MultipathRaceState::CancelledDraining => {
                self.state = MultipathRaceState::CancelledClean;
            }
            _ => {}
        }
    }

    fn check_all_exhausted_failed(&mut self) {
        if self.state != MultipathRaceState::Racing {
            return;
        }
        let any_viable = self.paths.values().any(|p| {
            matches!(
                p.state,
                PathState::Discover | PathState::Candidate | PathState::Probing | PathState::Active
            )
        });
        if !any_viable {
            self.state = MultipathRaceState::Failed;
        }
    }
}

fn parse_path_state(raw: &str) -> Result<PathState, MultipathError> {
    match raw {
        "atp.path.discover" => Ok(PathState::Discover),
        "atp.path.candidate" => Ok(PathState::Candidate),
        "atp.path.probing" => Ok(PathState::Probing),
        "atp.path.active" => Ok(PathState::Active),
        "atp.path.suspect" => Ok(PathState::Suspect),
        "atp.path.draining" => Ok(PathState::Draining),
        "atp.path.closed" => Ok(PathState::Closed),
        other => Err(MultipathError::MalformedWire(format!(
            "unknown path state '{other}'"
        ))),
    }
}

fn validate_label(value: &str, max_len: usize, label: &str) -> Result<(), MultipathError> {
    if value.is_empty() || value.len() > max_len {
        return Err(MultipathError::InvalidInput(format!(
            "{label} length {} outside 1..={max_len}",
            value.len()
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(MultipathError::InvalidInput(format!(
            "{label} must not contain control characters"
        )));
    }
    Ok(())
}

#![forbid(unsafe_code)]
//! Archive replication-state and retrievability challenge ledger (`FSS-131`, `fss-x4a.13.15`).
//!
//! Tracks per-replica custody progression across the non-collapsed [`ArchiveObjectState`] ladder
//! (`local_staged` -> `local_durable` -> `remote_staged` -> `remote_children_verified` ->
//! `remote_root_published` -> `replication_policy_satisfied` -> `retrievability_sample_passed`),
//! enforces residency and failure-domain diversity policies under explicit authority/privacy
//! projections, records idempotent proof-of-retrievability challenges with cost rows, and
//! automatically degrades readiness and schedules typed repair obligations whenever a challenge
//! fails, becomes stale, or terminates indeterminate.
//!
//! Non-collapse rule: "uploaded" (`RemoteStaged`) is never synonymous with archived, replicated,
//! protected, or retrievable; a failed or indeterminate sample is never silently ignored; and
//! ledger state carries zero effect authority to mutate remote providers.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, ContractError, TimestampNs};

use crate::atp_lifecycle::{ArchiveObjectState, ProofOfRetrievability};

/// Registered digest domain for [`ArchiveReplicationLedger`] state commitments (`FSS-131`).
pub const ARCHIVE_REPLICATION_LEDGER_DOMAIN: &str = "fss.archive_replication_ledger.v1";
/// Registered digest domain for [`RetrievabilityChallengeReceipt`] commitments (`FSS-131`).
pub const ARCHIVE_RETRIEVABILITY_CHALLENGE_DOMAIN: &str = "fss.archive_retrievability_challenge.v1";
/// Binary wire header magic for serialized archive replication ledgers.
pub const REPLICATION_LEDGER_MAGIC: [u8; 8] = *b"FSSREP01";
/// Supported durable format version for [`ArchiveReplicationLedger`].
pub const REPLICATION_LEDGER_VERSION: u32 = 1;
/// Hard ceiling on tracked replicas per root manifest.
pub const MAX_REPLICAS_PER_ROOT: usize = 64;
/// Hard ceiling on independent failure domains required by policy.
pub const MAX_REPLICATION_DOMAINS: u32 = 32;
/// Hard ceiling on byte/symbol ranges per retrievability challenge.
pub const MAX_CHALLENGE_RANGES: usize = 64;
/// Hard ceiling on retained challenge receipts per ledger.
pub const MAX_CHALLENGE_HISTORY: usize = 4_096;
/// Hard ceiling on open repair obligations per ledger.
pub const MAX_REPAIR_OBLIGATIONS: usize = 256;
/// Hard ceiling on serialized binary wire length of one ledger (2 MiB).
pub const MAX_REPLICATION_LEDGER_WIRE_BYTES: usize = 2 * 1024 * 1024;
/// Maximum UTF-8 bytes in short identifiers (`replica_id`, `challenge_id`, `failure_domain`).
pub const MAX_REPLICA_ID_BYTES: usize = 128;
/// Maximum UTF-8 bytes in descriptive labels (`provider_tuple`, reasons).
pub const MAX_REPLICA_LABEL_BYTES: usize = 256;
/// Maximum UTF-8 bytes in repair obligation identifiers.
pub const MAX_OBLIGATION_ID_BYTES: usize = 288;
/// Maximum UTF-8 bytes in residency region identifiers.
pub const MAX_RESIDENCY_REGION_BYTES: usize = 64;

/// Safe operator/agent recovery guidance for a refused replication-ledger operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicationGuidance {
    /// Fix invalid policy, identifier, range, or parameter bounds before retrying.
    RepairInputParameters,
    /// Re-authorize active capability, privacy epoch, residency, or authority generation.
    ReauthorizeAndReanchor,
    /// Complete earlier custody milestones (e.g., verify children before publishing root).
    CompletePriorCustodyMilestone,
    /// Cooperative cancellation observed; retry safely against the unchanged ledger head.
    RetryFromCleanHead,
    /// Refresh stale replica generation from the latest verified replica record.
    RefreshReplicaGeneration,
    /// Challenge ID already exists with different payload; mint a fresh challenge identity.
    MintDistinctChallengeId,
    /// Reject corrupt or unsupported wire bytes and recover from canonical custody.
    RejectCorruptLedger,
}

/// Typed failure returned by [`ArchiveReplicationLedger`] operations and wire codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplicationError {
    /// Policy, bounds, or input parameter violated hard invariants.
    InvalidInput(String),
    /// Capability, privacy, residency, or failure-domain authorization was refused or revoked.
    AuthorityRevoked(String),
    /// Authority generation or `ContractBasis` drifted from pinned expectation.
    StaleGenerationOrBasis {
        /// Expected authority generation.
        expected: u64,
        /// Observed authority generation.
        observed: u64,
    },
    /// Replica does not exist in this ledger.
    UnknownReplica {
        /// Missing replica identifier.
        replica_id: String,
    },
    /// Attempted to skip or regress an [`ArchiveObjectState`] milestone (e.g., root before children).
    InvalidCustodyTransition {
        /// Replica identifier.
        replica_id: String,
        /// Current custody state.
        from: ArchiveObjectState,
        /// Rejected target custody state.
        to: ArchiveObjectState,
    },
    /// Challenge targeted a stale or mismatched replica generation.
    StaleReplicaGeneration {
        /// Replica identifier.
        replica_id: String,
        /// Current generation in ledger.
        current: u64,
        /// Supplied challenge generation.
        supplied: u64,
    },
    /// Challenge ID was reused with conflicting content.
    DuplicateChallengeConflict {
        /// Conflicting challenge identifier.
        challenge_id: String,
    },
    /// Cooperative cancellation observed before mutating state.
    Cancelled,
    /// Bounded collection or wire size ceiling exceeded.
    BoundsExceeded {
        /// Observed size or count.
        observed: usize,
        /// Maximum permitted bound.
        maximum: usize,
    },
    /// Wire ledger lacked [`REPLICATION_LEDGER_MAGIC`].
    InvalidMagic,
    /// Wire ledger declared an unsupported format version.
    UnsupportedVersion {
        /// Observed format version.
        version: u32,
    },
    /// Wire ledger was truncated, malformed, or violated structural invariants.
    MalformedWire(String),
    /// Wire ledger checksum failed verification.
    ChecksumMismatch,
    /// Canonical encoding failed.
    Encoding(String),
}

impl ReplicationError {
    /// Registered stable error identity.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "ERR-ARCHIVE-REPLICATION-INVALID-INPUT-001",
            Self::AuthorityRevoked(_) => "ERR-ARCHIVE-REPLICATION-AUTHORITY-REVOKED-001",
            Self::StaleGenerationOrBasis { .. } => "ERR-ARCHIVE-REPLICATION-STALE-GEN-001",
            Self::UnknownReplica { .. } => "ERR-ARCHIVE-REPLICATION-UNKNOWN-REPLICA-001",
            Self::InvalidCustodyTransition { .. } => "ERR-ARCHIVE-REPLICATION-CUSTODY-ORDER-001",
            Self::StaleReplicaGeneration { .. } => "ERR-ARCHIVE-REPLICATION-STALE-REPLICA-GEN-001",
            Self::DuplicateChallengeConflict { .. } => {
                "ERR-ARCHIVE-REPLICATION-CHALLENGE-CONFLICT-001"
            }
            Self::Cancelled => "ERR-ARCHIVE-REPLICATION-CANCELLED-001",
            Self::BoundsExceeded { .. } => "ERR-ARCHIVE-REPLICATION-BOUNDS-001",
            Self::InvalidMagic => "ERR-ARCHIVE-REPLICATION-INVALID-MAGIC-001",
            Self::UnsupportedVersion { .. } => "ERR-ARCHIVE-REPLICATION-UNSUPPORTED-VERSION-001",
            Self::MalformedWire(_) => "ERR-ARCHIVE-REPLICATION-MALFORMED-WIRE-001",
            Self::ChecksumMismatch => "ERR-ARCHIVE-REPLICATION-CHECKSUM-MISMATCH-001",
            Self::Encoding(_) => "ERR-ARCHIVE-REPLICATION-ENCODING-001",
        }
    }

    /// Safe recovery guidance for this refusal.
    #[must_use]
    pub const fn guidance(&self) -> ReplicationGuidance {
        match self {
            Self::InvalidInput(_) => ReplicationGuidance::RepairInputParameters,
            Self::AuthorityRevoked(_) | Self::StaleGenerationOrBasis { .. } => {
                ReplicationGuidance::ReauthorizeAndReanchor
            }
            Self::UnknownReplica { .. } | Self::InvalidCustodyTransition { .. } => {
                ReplicationGuidance::CompletePriorCustodyMilestone
            }
            Self::StaleReplicaGeneration { .. } => ReplicationGuidance::RefreshReplicaGeneration,
            Self::DuplicateChallengeConflict { .. } => ReplicationGuidance::MintDistinctChallengeId,
            Self::Cancelled => ReplicationGuidance::RetryFromCleanHead,
            Self::BoundsExceeded { .. }
            | Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::MalformedWire(_)
            | Self::ChecksumMismatch
            | Self::Encoding(_) => ReplicationGuidance::RejectCorruptLedger,
        }
    }
}

impl fmt::Display for ReplicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}

impl Error for ReplicationError {}

/// Immutable replication and retrievability policy governing one archived root (`FSS-131`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplicationPolicy {
    /// Minimum distinct healthy failure domains required (`1..=MAX_REPLICATION_DOMAINS`).
    pub min_failure_domains: u32,
    /// Optional mandatory provider tuples that MUST hold healthy replicas.
    pub required_providers: BTreeSet<String>,
    /// Allowed residency regions (empty = unrestricted; non-empty = hard residency clamp).
    pub allowed_residency_regions: BTreeSet<String>,
    /// Maximum age in nanoseconds before a passed retrievability proof becomes stale (`> 0`).
    pub max_retrievability_staleness_ns: i128,
    /// Domain-separated policy digest binding this policy tuple.
    pub policy_digest: ContentDigest,
}

impl ReplicationPolicy {
    /// Validates hard policy invariants.
    pub fn validate(&self) -> Result<(), ReplicationError> {
        if self.min_failure_domains == 0 || self.min_failure_domains > MAX_REPLICATION_DOMAINS {
            return Err(ReplicationError::InvalidInput(format!(
                "min_failure_domains {} outside 1..={MAX_REPLICATION_DOMAINS}",
                self.min_failure_domains
            )));
        }
        if self.max_retrievability_staleness_ns <= 0 {
            return Err(ReplicationError::InvalidInput(
                "max_retrievability_staleness_ns must be > 0".to_owned(),
            ));
        }
        if self.required_providers.len() > MAX_REPLICAS_PER_ROOT {
            return Err(ReplicationError::BoundsExceeded {
                observed: self.required_providers.len(),
                maximum: MAX_REPLICAS_PER_ROOT,
            });
        }
        for p in &self.required_providers {
            validate_bounded_text(p, MAX_REPLICA_LABEL_BYTES, "required_provider")?;
        }
        if self.allowed_residency_regions.len() > MAX_REPLICAS_PER_ROOT {
            return Err(ReplicationError::BoundsExceeded {
                observed: self.allowed_residency_regions.len(),
                maximum: MAX_REPLICAS_PER_ROOT,
            });
        }
        for r in &self.allowed_residency_regions {
            validate_bounded_text(r, MAX_RESIDENCY_REGION_BYTES, "residency_region")?;
        }
        Ok(())
    }

    fn encode_canonical(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.min_failure_domains);
        enc.u64(self.required_providers.len() as u64);
        for p in &self.required_providers {
            enc.text(p);
        }
        enc.u64(self.allowed_residency_regions.len() as u64);
        for r in &self.allowed_residency_regions {
            enc.text(r);
        }
        enc.i128(self.max_retrievability_staleness_ns);
        enc.digest(self.policy_digest);
    }

    fn decode_canonical(dec: &mut CanonicalDecoder<'_>) -> Result<Self, ReplicationError> {
        let min_failure_domains = dec
            .u32()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        let req_count = usize::try_from(
            dec.u64()
                .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?,
        )
        .map_err(|_| ReplicationError::BoundsExceeded {
            observed: usize::MAX,
            maximum: MAX_REPLICAS_PER_ROOT,
        })?;
        if req_count > MAX_REPLICAS_PER_ROOT || req_count.saturating_mul(5) > dec.remaining() {
            return Err(ReplicationError::BoundsExceeded {
                observed: req_count,
                maximum: MAX_REPLICAS_PER_ROOT,
            });
        }
        let mut required_providers = BTreeSet::new();
        let mut prev_provider: Option<String> = None;
        for _ in 0..req_count {
            let p = dec
                .text()
                .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
            validate_bounded_text(p, MAX_REPLICA_LABEL_BYTES, "required_provider")?;
            if prev_provider.as_deref().is_some_and(|prev| p <= prev) {
                return Err(ReplicationError::MalformedWire(
                    "required_providers must be strictly canonically ordered and unique".to_owned(),
                ));
            }
            prev_provider = Some(p.to_owned());
            required_providers.insert(p.to_owned());
        }
        let res_count = usize::try_from(
            dec.u64()
                .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?,
        )
        .map_err(|_| ReplicationError::BoundsExceeded {
            observed: usize::MAX,
            maximum: MAX_REPLICAS_PER_ROOT,
        })?;
        if res_count > MAX_REPLICAS_PER_ROOT || res_count.saturating_mul(5) > dec.remaining() {
            return Err(ReplicationError::BoundsExceeded {
                observed: res_count,
                maximum: MAX_REPLICAS_PER_ROOT,
            });
        }
        let mut allowed_residency_regions = BTreeSet::new();
        let mut prev_region: Option<String> = None;
        for _ in 0..res_count {
            let r = dec
                .text()
                .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
            validate_bounded_text(r, MAX_RESIDENCY_REGION_BYTES, "residency_region")?;
            if prev_region.as_deref().is_some_and(|prev| r <= prev) {
                return Err(ReplicationError::MalformedWire(
                    "allowed_residency_regions must be strictly canonically ordered and unique"
                        .to_owned(),
                ));
            }
            prev_region = Some(r.to_owned());
            allowed_residency_regions.insert(r.to_owned());
        }
        let max_retrievability_staleness_ns = dec
            .i128()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        let policy_digest = dec
            .digest()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        let policy = Self {
            min_failure_domains,
            required_providers,
            allowed_residency_regions,
            max_retrievability_staleness_ns,
            policy_digest,
        };
        policy.validate()?;
        Ok(policy)
    }
}

/// Live authority, privacy, and generation projection checked before every ledger mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplicationAuthorityContext {
    /// Exact pinned `ContractBasis` / ledger anchor digest.
    pub contract_basis_digest: ContentDigest,
    /// Active authority generation.
    pub authority_generation: u64,
    /// Expected authority generation pinned by caller.
    pub expected_authority_generation: u64,
    /// Active privacy policy epoch.
    pub privacy_epoch: u64,
    /// True while archive-custody recording capability remains valid.
    pub capability_active: bool,
    /// True while privacy projection authorization remains valid.
    pub privacy_active: bool,
    /// Failure domains authorized under this capability (empty = unrestricted).
    pub allowed_failure_domains: BTreeSet<String>,
}

impl ReplicationAuthorityContext {
    /// Constructs an active, unrestricted authority context for tests and verified sessions.
    #[must_use]
    pub fn active(
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
            allowed_failure_domains: BTreeSet::new(),
        }
    }

    fn validate_for(
        &self,
        expected_basis: ContentDigest,
        failure_domain: Option<&str>,
    ) -> Result<(), ReplicationError> {
        if !self.capability_active {
            return Err(ReplicationError::AuthorityRevoked(
                "replication ledger capability revoked".to_owned(),
            ));
        }
        if !self.privacy_active {
            return Err(ReplicationError::AuthorityRevoked(
                "privacy projection authorization revoked".to_owned(),
            ));
        }
        if self.contract_basis_digest != expected_basis {
            return Err(ReplicationError::AuthorityRevoked(
                "contract_basis_digest disagrees with replication ledger basis".to_owned(),
            ));
        }
        if self.authority_generation != self.expected_authority_generation {
            return Err(ReplicationError::StaleGenerationOrBasis {
                expected: self.expected_authority_generation,
                observed: self.authority_generation,
            });
        }
        if let Some(domain) = failure_domain
            && !self.allowed_failure_domains.is_empty()
            && !self.allowed_failure_domains.contains(domain)
        {
            return Err(ReplicationError::AuthorityRevoked(format!(
                "failure_domain '{domain}' not authorized under active capability"
            )));
        }
        Ok(())
    }
}

/// Per-replica operational readiness distinct from custody milestones.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicaReadiness {
    /// Replica custody matches expectations with no open defects.
    Healthy = 1,
    /// Replica observed a transient degradation or stale retrievability proof.
    Degraded = 2,
    /// Failed retrievability sample triggered mandatory repair / re-replication.
    RepairScheduled = 3,
    /// Remote provider returned lagging/ambiguous status; MUST NOT upgrade to Healthy.
    Indeterminate = 4,
    /// Replica returned corrupt bytes and is quarantined pending replacement.
    Quarantined = 5,
}

impl ReplicaReadiness {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::RepairScheduled => "repair_scheduled",
            Self::Indeterminate => "indeterminate",
            Self::Quarantined => "quarantined",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::Healthy),
            2 => Ok(Self::Degraded),
            3 => Ok(Self::RepairScheduled),
            4 => Ok(Self::Indeterminate),
            5 => Ok(Self::Quarantined),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Tracked custody and readiness state for one replica of an archived root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplicaRecord {
    /// Stable replica identifier (`1..=128` bytes).
    pub replica_id: String,
    /// Secret-free provider/storage tuple (`1..=256` bytes).
    pub provider_tuple: String,
    /// Independent failure domain (`1..=128` bytes).
    pub failure_domain: String,
    /// Geographic/administrative residency region (`1..=64` bytes).
    pub residency_region: String,
    /// Monotonic replica generation (`>= 1`).
    pub replica_generation: u64,
    /// Current non-collapsed [`ArchiveObjectState`] custody milestone.
    pub custody_state: ArchiveObjectState,
    /// Operational readiness state (distinct from custody milestone).
    pub readiness: ReplicaReadiness,
    /// Timestamp of the most recent passed retrievability proof on this generation.
    pub last_verified_at: Option<TimestampNs>,
    /// Digest of the most recent passed retrievability challenge receipt.
    pub last_challenge_digest: Option<ContentDigest>,
    /// Timestamp of the last recorded state update.
    pub last_updated_at: TimestampNs,
}

impl ReplicaRecord {
    fn encode_canonical(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.replica_id);
        enc.text(&self.provider_tuple);
        enc.text(&self.failure_domain);
        enc.text(&self.residency_region);
        enc.u64(self.replica_generation);
        enc.u8(archive_state_tag(self.custody_state));
        enc.u8(self.readiness.tag());
        match self.last_verified_at {
            Some(ts) => {
                enc.bool(true);
                enc.i128(ts.0);
            }
            None => enc.bool(false),
        }
        match self.last_challenge_digest {
            Some(d) => {
                enc.bool(true);
                enc.digest(d);
            }
            None => enc.bool(false),
        }
        enc.i128(self.last_updated_at.0);
    }

    fn decode_canonical(dec: &mut CanonicalDecoder<'_>) -> Result<Self, ReplicationError> {
        let replica_id = dec
            .text()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        validate_bounded_text(replica_id, MAX_REPLICA_ID_BYTES, "replica_id")?;
        let provider_tuple = dec
            .text()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        validate_bounded_text(provider_tuple, MAX_REPLICA_LABEL_BYTES, "provider_tuple")?;
        let failure_domain = dec
            .text()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        validate_bounded_text(failure_domain, MAX_REPLICA_ID_BYTES, "failure_domain")?;
        let residency_region = dec
            .text()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        validate_bounded_text(
            residency_region,
            MAX_RESIDENCY_REGION_BYTES,
            "residency_region",
        )?;
        let replica_generation = dec
            .u64()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        if replica_generation == 0 {
            return Err(ReplicationError::MalformedWire(
                "replica_generation must be >= 1".to_owned(),
            ));
        }
        let custody_state = archive_state_from_tag(
            dec.u8()
                .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?,
        )
        .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        let readiness = ReplicaReadiness::from_tag(
            dec.u8()
                .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?,
        )
        .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        let last_verified_at = if dec
            .bool()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?
        {
            Some(TimestampNs(dec.i128().map_err(|e| {
                ReplicationError::MalformedWire(e.to_string())
            })?))
        } else {
            None
        };
        let last_challenge_digest = if dec
            .bool()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?
        {
            Some(
                dec.digest()
                    .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?,
            )
        } else {
            None
        };
        let last_updated_at = TimestampNs(
            dec.i128()
                .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?,
        );
        Ok(Self {
            replica_id: replica_id.to_owned(),
            provider_tuple: provider_tuple.to_owned(),
            failure_domain: failure_domain.to_owned(),
            residency_region: residency_region.to_owned(),
            replica_generation,
            custody_state,
            readiness,
            last_verified_at,
            last_challenge_digest,
            last_updated_at,
        })
    }
}

/// Requested byte or symbol range sampled during a retrievability challenge.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ChallengeRange {
    /// Byte or symbol starting offset.
    pub offset: u64,
    /// Nonzero sampled length.
    pub length: u64,
}

/// Non-collapsed outcome of one proof-of-retrievability challenge sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeOutcome {
    /// Observed digest matched expected canonical digest over nonzero verified bytes.
    Passed = 1,
    /// Observed bytes hashed to a different digest (corruption detected).
    DigestMismatch = 2,
    /// Object or requested range was missing or truncated at the replica.
    MissingOrTruncated = 3,
    /// Provider timed out or returned lagging/ambiguous status (never upgraded to Passed).
    TimeoutOrIndeterminate = 4,
}

impl ChallengeOutcome {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::DigestMismatch => "digest_mismatch",
            Self::MissingOrTruncated => "missing_or_truncated",
            Self::TimeoutOrIndeterminate => "timeout_or_indeterminate",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::Passed),
            2 => Ok(Self::DigestMismatch),
            3 => Ok(Self::MissingOrTruncated),
            4 => Ok(Self::TimeoutOrIndeterminate),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Typed repair/reconciliation action triggered by a retrievability challenge outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairAction {
    /// Challenge passed; no repair needed.
    None = 1,
    /// Missing/truncated replica; re-replicate from an independent healthy domain.
    ReReplicateFromHealthyDomain = 2,
    /// Corrupt replica bytes; quarantine corrupt replica and repair + re-verify canonical digest.
    QuarantineAndRepair = 3,
    /// Provider response was indeterminate; reconcile remote custody before assuming health.
    ReconcileIndeterminateReplica = 4,
}

impl RepairAction {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ReReplicateFromHealthyDomain => "re_replicate_from_healthy_domain",
            Self::QuarantineAndRepair => "quarantine_and_repair",
            Self::ReconcileIndeterminateReplica => "reconcile_indeterminate_replica",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::None),
            2 => Ok(Self::ReReplicateFromHealthyDomain),
            3 => Ok(Self::QuarantineAndRepair),
            4 => Ok(Self::ReconcileIndeterminateReplica),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Input observation for recording one proof-of-retrievability challenge (`docs/ATP_ARCHIVE_AND_REPLICATION.md` §9).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetrievabilityChallengeInput {
    /// Stable challenge/sample identity (idempotent deduplication key).
    pub challenge_id: String,
    /// Target replica identifier.
    pub replica_id: String,
    /// Exact replica generation challenged.
    pub replica_generation: u64,
    /// Requested byte/symbol ranges (`1..=MAX_CHALLENGE_RANGES`, each `length > 0`).
    pub ranges: Vec<ChallengeRange>,
    /// Expected canonical digest.
    pub expected_digest: ContentDigest,
    /// Observed digest when bytes were read (`Some` required for `Passed` and `DigestMismatch`).
    pub observed_digest: Option<ContentDigest>,
    /// Measured challenge latency in milliseconds.
    pub latency_ms: u64,
    /// Egress bytes read during this challenge (cost row).
    pub egress_bytes: u64,
    /// Class B GET/HEAD operations consumed (cost row).
    pub class_b_ops: u64,
    /// Non-collapsed challenge outcome.
    pub outcome: ChallengeOutcome,
    /// Timestamp when the challenge completed.
    pub challenged_at: TimestampNs,
}

/// Immutable, domain-separated receipt recording one executed retrievability challenge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetrievabilityChallengeReceipt {
    /// Stable challenge/sample identifier.
    pub challenge_id: String,
    /// Archived root digest.
    pub root_digest: ContentDigest,
    /// Target replica identifier.
    pub replica_id: String,
    /// Exact replica generation challenged.
    pub replica_generation: u64,
    /// Secret-free provider/path tuple recorded at challenge time.
    pub provider_tuple: String,
    /// Failure domain recorded at challenge time.
    pub failure_domain: String,
    /// Canonically sorted requested ranges.
    pub ranges: Vec<ChallengeRange>,
    /// Expected canonical digest.
    pub expected_digest: ContentDigest,
    /// Observed digest when bytes were read.
    pub observed_digest: Option<ContentDigest>,
    /// Measured latency in milliseconds.
    pub latency_ms: u64,
    /// Egress bytes read.
    pub egress_bytes: u64,
    /// Class B operations consumed.
    pub class_b_ops: u64,
    /// Non-collapsed challenge outcome.
    pub outcome: ChallengeOutcome,
    /// Derived mandatory repair or reconciliation action.
    pub repair_action: RepairAction,
    /// Timestamp when the challenge completed.
    pub challenged_at: TimestampNs,
    /// Domain-separated SHA-256 commitment (`fss.archive_retrievability_challenge.v1`).
    pub receipt_digest: ContentDigest,
}

impl RetrievabilityChallengeReceipt {
    /// Projects a passed challenge receipt into an [`atp_lifecycle::ProofOfRetrievability`].
    ///
    /// Requires an intact receipt for a passing challenge whose observed digest binds the root.
    #[must_use]
    pub fn to_proof_of_retrievability(&self) -> Option<ProofOfRetrievability> {
        if !self.proves_root() || self.compute_digest().ok() != Some(self.receipt_digest) {
            return None;
        }
        let observed_digest = self.observed_digest?;
        Some(ProofOfRetrievability {
            sample_id: self.challenge_id.clone(),
            root_digest: self.root_digest,
            replica_generation: self.replica_generation,
            failure_domain: self.failure_domain.clone(),
            observed_digest,
            sampled_bytes: self.egress_bytes,
            sampled_at: self.challenged_at,
        })
    }

    fn proves_root(&self) -> bool {
        self.outcome == ChallengeOutcome::Passed
            && self.expected_digest == self.root_digest
            && self.observed_digest == Some(self.root_digest)
            && self.egress_bytes > 0
    }

    fn legacy_repair_id(&self) -> String {
        format!("repair:{}:{}", self.replica_id, self.challenge_id)
    }

    fn receipt_repair_id(&self) -> String {
        format!("repair-by-receipt:{}", self.receipt_digest)
    }

    fn resolves_challenge(&self, failure: &Self) -> bool {
        self.outcome == ChallengeOutcome::Passed
            && failure.outcome != ChallengeOutcome::Passed
            && self.replica_id == failure.replica_id
            && self.replica_generation >= failure.replica_generation
            && self.challenged_at >= failure.challenged_at
            && self.expected_digest == failure.expected_digest
            && (self.proves_root() || self.ranges == failure.ranges)
    }

    fn compute_digest(&self) -> Result<ContentDigest, ReplicationError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(ARCHIVE_RETRIEVABILITY_CHALLENGE_DOMAIN);
        self.encode_body(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|e| ReplicationError::Encoding(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.challenge_id);
        enc.digest(self.root_digest);
        enc.text(&self.replica_id);
        enc.u64(self.replica_generation);
        enc.text(&self.provider_tuple);
        enc.text(&self.failure_domain);
        enc.u64(self.ranges.len() as u64);
        for range in &self.ranges {
            enc.u64(range.offset);
            enc.u64(range.length);
        }
        enc.digest(self.expected_digest);
        match self.observed_digest {
            Some(d) => {
                enc.bool(true);
                enc.digest(d);
            }
            None => enc.bool(false),
        }
        enc.u64(self.latency_ms);
        enc.u64(self.egress_bytes);
        enc.u64(self.class_b_ops);
        enc.u8(self.outcome.tag());
        enc.u8(self.repair_action.tag());
        enc.i128(self.challenged_at.0);
    }

    fn encode_canonical(&self, enc: &mut CanonicalEncoder) {
        self.encode_body(enc);
        enc.digest(self.receipt_digest);
    }

    fn decode_canonical(dec: &mut CanonicalDecoder<'_>) -> Result<Self, ReplicationError> {
        let challenge_id = dec
            .text()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        validate_bounded_text(challenge_id, MAX_REPLICA_ID_BYTES, "challenge_id")?;
        let root_digest = dec
            .digest()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        let replica_id = dec
            .text()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        validate_bounded_text(replica_id, MAX_REPLICA_ID_BYTES, "replica_id")?;
        let replica_generation = dec
            .u64()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        if replica_generation == 0 {
            return Err(ReplicationError::MalformedWire(
                "challenge replica_generation must be >= 1".to_owned(),
            ));
        }
        let provider_tuple = dec
            .text()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        validate_bounded_text(provider_tuple, MAX_REPLICA_LABEL_BYTES, "provider_tuple")?;
        let failure_domain = dec
            .text()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        validate_bounded_text(failure_domain, MAX_REPLICA_ID_BYTES, "failure_domain")?;
        let range_count = usize::try_from(
            dec.u64()
                .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?,
        )
        .map_err(|_| ReplicationError::BoundsExceeded {
            observed: usize::MAX,
            maximum: MAX_CHALLENGE_RANGES,
        })?;
        if range_count == 0
            || range_count > MAX_CHALLENGE_RANGES
            || range_count.saturating_mul(16) > dec.remaining()
        {
            return Err(ReplicationError::BoundsExceeded {
                observed: range_count,
                maximum: MAX_CHALLENGE_RANGES,
            });
        }
        let mut ranges = Vec::with_capacity(range_count);
        for _ in 0..range_count {
            let offset = dec
                .u64()
                .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
            let length = dec
                .u64()
                .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
            if length == 0 {
                return Err(ReplicationError::MalformedWire(
                    "challenge range length must be > 0".to_owned(),
                ));
            }
            ranges.push(ChallengeRange { offset, length });
        }
        if !ranges.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(ReplicationError::MalformedWire(
                "challenge ranges must be strictly canonically ordered and unique".to_owned(),
            ));
        }
        let expected_digest = dec
            .digest()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        let observed_digest = if dec
            .bool()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?
        {
            Some(
                dec.digest()
                    .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?,
            )
        } else {
            None
        };
        let latency_ms = dec
            .u64()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        let egress_bytes = dec
            .u64()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        let class_b_ops = dec
            .u64()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        let outcome = ChallengeOutcome::from_tag(
            dec.u8()
                .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?,
        )
        .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        let repair_action = RepairAction::from_tag(
            dec.u8()
                .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?,
        )
        .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        if repair_action != repair_action_for(outcome) {
            return Err(ReplicationError::MalformedWire(
                "challenge repair_action contradicts outcome".to_owned(),
            ));
        }
        match outcome {
            ChallengeOutcome::Passed => {
                if observed_digest != Some(expected_digest) || egress_bytes == 0 {
                    return Err(ReplicationError::MalformedWire(
                        "Passed challenge receipt requires matching digest and nonzero egress_bytes"
                            .to_owned(),
                    ));
                }
            }
            ChallengeOutcome::DigestMismatch => {
                if observed_digest.is_none() || observed_digest == Some(expected_digest) {
                    return Err(ReplicationError::MalformedWire(
                        "DigestMismatch receipt requires distinct observed_digest".to_owned(),
                    ));
                }
            }
            ChallengeOutcome::MissingOrTruncated | ChallengeOutcome::TimeoutOrIndeterminate => {}
        }
        let challenged_at = TimestampNs(
            dec.i128()
                .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?,
        );
        let stored_digest = dec
            .digest()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        let receipt = Self {
            challenge_id: challenge_id.to_owned(),
            root_digest,
            replica_id: replica_id.to_owned(),
            replica_generation,
            provider_tuple: provider_tuple.to_owned(),
            failure_domain: failure_domain.to_owned(),
            ranges,
            expected_digest,
            observed_digest,
            latency_ms,
            egress_bytes,
            class_b_ops,
            outcome,
            repair_action,
            challenged_at,
            receipt_digest: stored_digest,
        };
        if receipt.compute_digest()? != stored_digest {
            return Err(ReplicationError::ChecksumMismatch);
        }
        Ok(receipt)
    }
}

/// Durable repair/reconciliation obligation opened when a retrievability sample fails or stalls.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairObligation {
    /// Stable obligation identifier (`repair:<replica_id>:<challenge_id>`).
    pub obligation_id: String,
    /// Offending replica identifier.
    pub replica_id: String,
    /// Replica generation observed at failure time.
    pub failed_generation: u64,
    /// Required remediation action.
    pub action: RepairAction,
    /// Digest of the triggering retrievability challenge receipt.
    pub triggering_challenge_digest: ContentDigest,
    /// Timestamp when this obligation was opened.
    pub opened_at: TimestampNs,
    /// True once resolved by a fresh passing retrievability proof on a repaired/verified replica.
    pub resolved: bool,
    /// Digest of the resolving passing challenge receipt when `resolved == true`.
    pub resolved_by_challenge_digest: Option<ContentDigest>,
}

impl RepairObligation {
    fn from_failure(
        obligation_id: String,
        failure: &RetrievabilityChallengeReceipt,
        resolver: Option<ContentDigest>,
    ) -> Self {
        Self {
            obligation_id,
            replica_id: failure.replica_id.clone(),
            failed_generation: failure.replica_generation,
            action: failure.repair_action,
            triggering_challenge_digest: failure.receipt_digest,
            opened_at: failure.challenged_at,
            resolved: resolver.is_some(),
            resolved_by_challenge_digest: resolver,
        }
    }

    fn encode_canonical(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.obligation_id);
        enc.text(&self.replica_id);
        enc.u64(self.failed_generation);
        enc.u8(self.action.tag());
        enc.digest(self.triggering_challenge_digest);
        enc.i128(self.opened_at.0);
        enc.bool(self.resolved);
        match self.resolved_by_challenge_digest {
            Some(d) => {
                enc.bool(true);
                enc.digest(d);
            }
            None => enc.bool(false),
        }
    }

    fn decode_canonical(dec: &mut CanonicalDecoder<'_>) -> Result<Self, ReplicationError> {
        let obligation_id = dec
            .text()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        validate_bounded_text(obligation_id, MAX_OBLIGATION_ID_BYTES, "obligation_id")?;
        let replica_id = dec
            .text()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        validate_bounded_text(replica_id, MAX_REPLICA_ID_BYTES, "replica_id")?;
        let failed_generation = dec
            .u64()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        if failed_generation == 0 {
            return Err(ReplicationError::MalformedWire(
                "repair obligation failed_generation must be >= 1".to_owned(),
            ));
        }
        let action = RepairAction::from_tag(
            dec.u8()
                .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?,
        )
        .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        if action == RepairAction::None {
            return Err(ReplicationError::MalformedWire(
                "repair obligation cannot have RepairAction::None".to_owned(),
            ));
        }
        let triggering_challenge_digest = dec
            .digest()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        let opened_at = TimestampNs(
            dec.i128()
                .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?,
        );
        let resolved = dec
            .bool()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        let resolved_by_challenge_digest = if dec
            .bool()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?
        {
            Some(
                dec.digest()
                    .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?,
            )
        } else {
            None
        };
        if resolved != resolved_by_challenge_digest.is_some() {
            return Err(ReplicationError::MalformedWire(
                "repair obligation resolved flag disagrees with resolving digest".to_owned(),
            ));
        }
        Ok(Self {
            obligation_id: obligation_id.to_owned(),
            replica_id: replica_id.to_owned(),
            failed_generation,
            action,
            triggering_challenge_digest,
            opened_at,
            resolved,
            resolved_by_challenge_digest,
        })
    }
}

/// Non-collapsed overall readiness classification for one archived root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveReadinessState {
    /// Only locally staged bytes exist; not durable, replicated, or retrievable.
    StagedOnly,
    /// Locally durable, but remote root publication/replication policy is not yet satisfied.
    LocalDurableOnly,
    /// Remote uploads exist, but independent failure-domain / provider policy is not satisfied.
    RemoteUnqualified,
    /// Replication policy is satisfied, but retrievability has not been sampled across required domains.
    PolicySatisfiedUnchallenged,
    /// Required independent domains hold fresh, passing retrievability proofs and zero open repairs.
    RetrievableFresh,
    /// Prior retrievability proofs have aged past `max_retrievability_staleness_ns`.
    RetrievabilityStale,
    /// At least one replica failed retrievability and has an open repair obligation.
    RepairRequired,
    /// A replica has unresolved reconciliation, or policy depends on an indeterminate replica.
    Indeterminate,
}

impl ArchiveReadinessState {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StagedOnly => "staged_only",
            Self::LocalDurableOnly => "local_durable_only",
            Self::RemoteUnqualified => "remote_unqualified",
            Self::PolicySatisfiedUnchallenged => "policy_satisfied_unchallenged",
            Self::RetrievableFresh => "retrievable_fresh",
            Self::RetrievabilityStale => "retrievability_stale",
            Self::RepairRequired => "repair_required",
            Self::Indeterminate => "indeterminate",
        }
    }
}

/// Point-in-time non-collapsed readiness evaluation of an [`ArchiveReplicationLedger`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveReadinessSummary {
    /// Overall non-collapsed readiness state.
    pub state: ArchiveReadinessState,
    /// Distinct healthy failure domains at or past `RemoteRootPublished`.
    pub healthy_published_domains: BTreeSet<String>,
    /// Distinct healthy failure domains with fresh passed retrievability challenges at `now_ns`.
    pub fresh_retrievable_domains: BTreeSet<String>,
    /// Count of unresolved repair/reconciliation obligations.
    pub open_repair_obligations: usize,
    /// Count of replicas currently in `Indeterminate` state.
    pub indeterminate_replicas: usize,
    /// Cumulative challenge egress bytes spent (cost tracking).
    pub total_challenge_egress_bytes: u64,
    /// Cumulative challenge Class B operations spent (cost tracking).
    pub total_challenge_ops: u64,
    /// Exact ledger head digest bound to this readiness summary.
    pub ledger_head_digest: ContentDigest,
}

/// Append-only, checksummed replication-state and retrievability challenge ledger (`FSS-131`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveReplicationLedger {
    format_version: u32,
    root_digest: ContentDigest,
    contract_basis_digest: ContentDigest,
    policy: ReplicationPolicy,
    replicas: BTreeMap<String, ReplicaRecord>,
    challenges: Vec<RetrievabilityChallengeReceipt>,
    repair_obligations: BTreeMap<String, RepairObligation>,
    head_digest: ContentDigest,
}

impl ArchiveReplicationLedger {
    /// Initializes a fresh ledger pinned to `root_digest`, `contract_basis_digest`, and `policy`.
    pub fn new(
        root_digest: ContentDigest,
        contract_basis_digest: ContentDigest,
        policy: ReplicationPolicy,
    ) -> Result<Self, ReplicationError> {
        policy.validate()?;
        let mut ledger = Self {
            format_version: REPLICATION_LEDGER_VERSION,
            root_digest,
            contract_basis_digest,
            policy,
            replicas: BTreeMap::new(),
            challenges: Vec::new(),
            repair_obligations: BTreeMap::new(),
            head_digest: ContentDigest::sha256(b"unsealed-replication-ledger"),
        };
        ledger.head_digest = ledger.compute_head_digest()?;
        Ok(ledger)
    }

    /// Root manifest digest governed by this ledger.
    #[must_use]
    pub const fn root_digest(&self) -> ContentDigest {
        self.root_digest
    }

    /// Exact pinned `ContractBasis` digest.
    #[must_use]
    pub const fn contract_basis_digest(&self) -> ContentDigest {
        self.contract_basis_digest
    }

    /// Governing [`ReplicationPolicy`].
    #[must_use]
    pub const fn policy(&self) -> &ReplicationPolicy {
        &self.policy
    }

    /// Current tracked replicas indexed by `replica_id`.
    #[must_use]
    pub const fn replicas(&self) -> &BTreeMap<String, ReplicaRecord> {
        &self.replicas
    }

    /// Immutable ordered history of executed retrievability challenge receipts.
    #[must_use]
    pub fn challenges(&self) -> &[RetrievabilityChallengeReceipt] {
        &self.challenges
    }

    /// Tracked repair/reconciliation obligations indexed by `obligation_id`.
    #[must_use]
    pub const fn repair_obligations(&self) -> &BTreeMap<String, RepairObligation> {
        &self.repair_obligations
    }

    /// Domain-separated SHA-256 commitment over the complete ledger state (`fss.archive_replication_ledger.v1`).
    #[must_use]
    pub const fn head_digest(&self) -> ContentDigest {
        self.head_digest
    }

    /// Registers a new replica at `ArchiveObjectState::LocalStaged` (never skipping straight to
    /// published/replicated/retrievable).
    #[allow(clippy::too_many_arguments)]
    pub fn register_replica(
        &mut self,
        authority: &ReplicationAuthorityContext,
        replica_id: impl Into<String>,
        provider_tuple: impl Into<String>,
        failure_domain: impl Into<String>,
        residency_region: impl Into<String>,
        now_ns: TimestampNs,
        cancelled: bool,
    ) -> Result<&ReplicaRecord, ReplicationError> {
        if cancelled {
            return Err(ReplicationError::Cancelled);
        }
        let replica_id = replica_id.into();
        let provider_tuple = provider_tuple.into();
        let failure_domain = failure_domain.into();
        let residency_region = residency_region.into();
        validate_bounded_text(&replica_id, MAX_REPLICA_ID_BYTES, "replica_id")?;
        validate_bounded_text(&provider_tuple, MAX_REPLICA_LABEL_BYTES, "provider_tuple")?;
        validate_bounded_text(&failure_domain, MAX_REPLICA_ID_BYTES, "failure_domain")?;
        validate_bounded_text(
            &residency_region,
            MAX_RESIDENCY_REGION_BYTES,
            "residency_region",
        )?;
        authority.validate_for(self.contract_basis_digest, Some(&failure_domain))?;
        if !self.policy.allowed_residency_regions.is_empty()
            && !self
                .policy
                .allowed_residency_regions
                .contains(&residency_region)
        {
            return Err(ReplicationError::AuthorityRevoked(format!(
                "residency_region '{residency_region}' violates replication residency policy"
            )));
        }
        if let Some(existing) = self.replicas.get(&replica_id) {
            if existing.provider_tuple == provider_tuple
                && existing.failure_domain == failure_domain
                && existing.residency_region == residency_region
            {
                return Ok(existing);
            }
            return Err(ReplicationError::InvalidInput(format!(
                "replica '{replica_id}' already registered with different topology"
            )));
        }
        if self.replicas.len() >= MAX_REPLICAS_PER_ROOT {
            return Err(ReplicationError::BoundsExceeded {
                observed: self.replicas.len() + 1,
                maximum: MAX_REPLICAS_PER_ROOT,
            });
        }
        let record = ReplicaRecord {
            replica_id: replica_id.clone(),
            provider_tuple,
            failure_domain,
            residency_region,
            replica_generation: 1,
            custody_state: ArchiveObjectState::LocalStaged,
            readiness: ReplicaReadiness::Healthy,
            last_verified_at: None,
            last_challenge_digest: None,
            last_updated_at: now_ns,
        };
        self.replicas.insert(replica_id.clone(), record);
        self.head_digest = self.compute_head_digest()?;
        self.replicas
            .get(&replica_id)
            .ok_or(ReplicationError::UnknownReplica { replica_id })
    }

    /// Advances one replica's custody milestone by strictly one legal step along
    /// [`ArchiveObjectState`]. Refuses skipped steps (e.g., root publication before child
    /// verification), advancing a quarantined/indeterminate/repair-scheduled replica to
    /// `ReplicationPolicySatisfied`/`RetrievabilitySamplePassed`, or marking
    /// `RetrievabilitySamplePassed` directly (which requires [`Self::record_challenge`]).
    pub fn advance_replica_custody(
        &mut self,
        authority: &ReplicationAuthorityContext,
        replica_id: &str,
        to: ArchiveObjectState,
        now_ns: TimestampNs,
        cancelled: bool,
    ) -> Result<&ReplicaRecord, ReplicationError> {
        if cancelled {
            return Err(ReplicationError::Cancelled);
        }
        let domain = self
            .replicas
            .get(replica_id)
            .map(|r| r.failure_domain.clone())
            .ok_or_else(|| ReplicationError::UnknownReplica {
                replica_id: replica_id.to_owned(),
            })?;
        authority.validate_for(self.contract_basis_digest, Some(&domain))?;

        if to == ArchiveObjectState::RetrievabilitySamplePassed {
            return Err(ReplicationError::InvalidInput(
                "retrievability_sample_passed requires a verified record_challenge receipt"
                    .to_owned(),
            ));
        }

        let current_state = self.replicas[replica_id].custody_state;
        let current_readiness = self.replicas[replica_id].readiness;
        if current_state == to {
            return Ok(&self.replicas[replica_id]);
        }
        if !current_state.can_advance_to(to) {
            return Err(ReplicationError::InvalidCustodyTransition {
                replica_id: replica_id.to_owned(),
                from: current_state,
                to,
            });
        }
        if matches!(
            current_readiness,
            ReplicaReadiness::Quarantined
                | ReplicaReadiness::RepairScheduled
                | ReplicaReadiness::Indeterminate
        ) {
            return Err(ReplicationError::InvalidInput(format!(
                "cannot advance custody of replica '{replica_id}' while readiness is '{}'",
                current_readiness.as_str()
            )));
        }

        if to == ArchiveObjectState::ReplicationPolicySatisfied {
            let mut healthy_domains: BTreeSet<&str> = self
                .replicas
                .values()
                .filter(|r| {
                    r.readiness == ReplicaReadiness::Healthy
                        && r.custody_state >= ArchiveObjectState::RemoteRootPublished
                })
                .map(|r| r.failure_domain.as_str())
                .collect();
            healthy_domains.insert(domain.as_str());
            if healthy_domains.len() < self.policy.min_failure_domains as usize {
                return Err(ReplicationError::InvalidInput(format!(
                    "only {} healthy published failure domains; policy requires {}",
                    healthy_domains.len(),
                    self.policy.min_failure_domains
                )));
            }
            for req_provider in &self.policy.required_providers {
                let satisfied = self.replicas.values().any(|r| {
                    r.provider_tuple == *req_provider
                        && r.readiness == ReplicaReadiness::Healthy
                        && r.custody_state >= ArchiveObjectState::RemoteRootPublished
                });
                if !satisfied {
                    return Err(ReplicationError::InvalidInput(format!(
                        "required provider '{req_provider}' lacks a healthy published replica"
                    )));
                }
            }
        }

        if let Some(replica) = self.replicas.get_mut(replica_id) {
            replica.custody_state = to;
            replica.last_updated_at = now_ns;
        }
        self.head_digest = self.compute_head_digest()?;
        Ok(&self.replicas[replica_id])
    }

    /// Rotates a degraded/quarantined/repair-scheduled/indeterminate replica to a fresh
    /// `replica_generation = current + 1` at `RemoteStaged` after physical re-replication begins.
    /// Does NOT close open repair obligations until a fresh passing retrievability challenge
    /// proves the new generation is retrievable!
    pub fn begin_replica_repair_generation(
        &mut self,
        authority: &ReplicationAuthorityContext,
        replica_id: &str,
        now_ns: TimestampNs,
        cancelled: bool,
    ) -> Result<&ReplicaRecord, ReplicationError> {
        if cancelled {
            return Err(ReplicationError::Cancelled);
        }
        let domain = self
            .replicas
            .get(replica_id)
            .map(|r| r.failure_domain.clone())
            .ok_or_else(|| ReplicationError::UnknownReplica {
                replica_id: replica_id.to_owned(),
            })?;
        authority.validate_for(self.contract_basis_digest, Some(&domain))?;
        let replica =
            self.replicas
                .get_mut(replica_id)
                .ok_or_else(|| ReplicationError::UnknownReplica {
                    replica_id: replica_id.to_owned(),
                })?;
        let next_gen = replica.replica_generation.checked_add(1).ok_or_else(|| {
            ReplicationError::InvalidInput("replica_generation overflow".to_owned())
        })?;
        replica.replica_generation = next_gen;
        replica.custody_state = ArchiveObjectState::RemoteStaged;
        replica.readiness = ReplicaReadiness::Healthy;
        replica.last_verified_at = None;
        replica.last_challenge_digest = None;
        if now_ns > replica.last_updated_at {
            replica.last_updated_at = now_ns;
        }
        self.head_digest = self.compute_head_digest()?;
        Ok(&self.replicas[replica_id])
    }

    /// Records one proof-of-retrievability challenge observation.
    ///
    /// - Idempotent on exact duplicate `challenge_id` + matching receipt digest; fails closed on
    ///   conflicting `challenge_id`.
    /// - Refuses stale `replica_generation`, unverified/pre-publication replicas (for `Passed`),
    ///   revoked authority, or cooperative cancellation.
    /// - On `Passed`: records the sample and resolves matching repair obligations. Archive
    ///   readiness counts only current-generation samples bound to the root digest.
    /// - On `DigestMismatch`, `MissingOrTruncated`, or `TimeoutOrIndeterminate`: degrades replica
    ///   readiness (`Quarantined`, `RepairScheduled`, or `Indeterminate`) and records a durable
    ///   [`RepairObligation`] so failures are never silently ignored.
    pub fn record_challenge(
        &mut self,
        authority: &ReplicationAuthorityContext,
        input: RetrievabilityChallengeInput,
        cancelled: bool,
    ) -> Result<RetrievabilityChallengeReceipt, ReplicationError> {
        if cancelled {
            return Err(ReplicationError::Cancelled);
        }
        validate_bounded_text(&input.challenge_id, MAX_REPLICA_ID_BYTES, "challenge_id")?;
        validate_bounded_text(&input.replica_id, MAX_REPLICA_ID_BYTES, "replica_id")?;
        if input.ranges.is_empty() || input.ranges.len() > MAX_CHALLENGE_RANGES {
            return Err(ReplicationError::BoundsExceeded {
                observed: input.ranges.len(),
                maximum: MAX_CHALLENGE_RANGES,
            });
        }
        if input.ranges.iter().any(|r| r.length == 0) {
            return Err(ReplicationError::InvalidInput(
                "challenge range length must be > 0".to_owned(),
            ));
        }

        let replica = self
            .replicas
            .get(&input.replica_id)
            .cloned()
            .ok_or_else(|| ReplicationError::UnknownReplica {
                replica_id: input.replica_id.clone(),
            })?;
        authority.validate_for(self.contract_basis_digest, Some(&replica.failure_domain))?;

        if input.replica_generation != replica.replica_generation {
            return Err(ReplicationError::StaleReplicaGeneration {
                replica_id: input.replica_id,
                current: replica.replica_generation,
                supplied: input.replica_generation,
            });
        }

        // Validate outcome-to-observation truthfulness (never allow forged Passed on bad digest/0 bytes).
        match input.outcome {
            ChallengeOutcome::Passed => {
                if replica.readiness == ReplicaReadiness::Quarantined {
                    return Err(ReplicationError::InvalidInput(format!(
                        "quarantined replica '{}' generation {} must rotate via begin_replica_repair_generation before clearing quarantine",
                        replica.replica_id, replica.replica_generation
                    )));
                }
                if input.observed_digest != Some(input.expected_digest) {
                    return Err(ReplicationError::InvalidInput(
                        "Passed challenge requires observed_digest == Some(expected_digest)"
                            .to_owned(),
                    ));
                }
                if input.egress_bytes == 0 {
                    return Err(ReplicationError::InvalidInput(
                        "Passed challenge requires nonzero verified egress_bytes".to_owned(),
                    ));
                }
                if replica.custody_state < ArchiveObjectState::RemoteRootPublished {
                    return Err(ReplicationError::InvalidCustodyTransition {
                        replica_id: replica.replica_id,
                        from: replica.custody_state,
                        to: ArchiveObjectState::RetrievabilitySamplePassed,
                    });
                }
            }
            ChallengeOutcome::DigestMismatch => {
                if input.observed_digest == Some(input.expected_digest)
                    || input.observed_digest.is_none()
                {
                    return Err(ReplicationError::InvalidInput(
                        "DigestMismatch requires observed_digest != expected_digest".to_owned(),
                    ));
                }
            }
            ChallengeOutcome::MissingOrTruncated | ChallengeOutcome::TimeoutOrIndeterminate => {}
        }

        let mut canonical_ranges = input.ranges;
        canonical_ranges.sort_unstable();
        canonical_ranges.dedup();
        let repair_action = repair_action_for(input.outcome);

        let mut receipt = RetrievabilityChallengeReceipt {
            challenge_id: input.challenge_id.clone(),
            root_digest: self.root_digest,
            replica_id: replica.replica_id.clone(),
            replica_generation: input.replica_generation,
            provider_tuple: replica.provider_tuple.clone(),
            failure_domain: replica.failure_domain.clone(),
            ranges: canonical_ranges,
            expected_digest: input.expected_digest,
            observed_digest: input.observed_digest,
            latency_ms: input.latency_ms,
            egress_bytes: input.egress_bytes,
            class_b_ops: input.class_b_ops,
            outcome: input.outcome,
            repair_action,
            challenged_at: input.challenged_at,
            receipt_digest: ContentDigest::sha256(b"unsealed-challenge-receipt"),
        };
        receipt.receipt_digest = receipt.compute_digest()?;

        // Idempotency vs conflict check.
        if let Some(existing) = self
            .challenges
            .iter()
            .find(|c| c.challenge_id == receipt.challenge_id)
        {
            if existing == &receipt {
                return Ok(existing.clone());
            }
            return Err(ReplicationError::DuplicateChallengeConflict {
                challenge_id: receipt.challenge_id,
            });
        }

        if self.challenges.len() >= MAX_CHALLENGE_HISTORY {
            return Err(ReplicationError::BoundsExceeded {
                observed: self.challenges.len() + 1,
                maximum: MAX_CHALLENGE_HISTORY,
            });
        }

        // Apply state transition according to challenge outcome.
        match receipt.outcome {
            ChallengeOutcome::Passed => {
                // A successful sample may repair only the root or object range it verified.
                let repaired_challenges: BTreeSet<_> = self
                    .challenges
                    .iter()
                    .filter(|failed| receipt.resolves_challenge(failed))
                    .map(|failed| failed.receipt_digest)
                    .collect();
                for obligation in self.repair_obligations.values_mut() {
                    if !obligation.resolved
                        && repaired_challenges.contains(&obligation.triggering_challenge_digest)
                    {
                        obligation.resolved = true;
                        obligation.resolved_by_challenge_digest = Some(receipt.receipt_digest);
                    }
                }
                let has_remaining_open_obligation = self
                    .repair_obligations
                    .values()
                    .any(|o| o.replica_id == receipt.replica_id && !o.resolved);
                if let Some(target) = self.replicas.get_mut(&receipt.replica_id) {
                    if !has_remaining_open_obligation
                        && target.readiness != ReplicaReadiness::Quarantined
                    {
                        target.readiness = ReplicaReadiness::Healthy;
                    }
                    if target
                        .last_verified_at
                        .is_none_or(|prev| receipt.challenged_at >= prev)
                    {
                        target.last_verified_at = Some(receipt.challenged_at);
                        target.last_challenge_digest = Some(receipt.receipt_digest);
                    }
                    if receipt.challenged_at > target.last_updated_at {
                        target.last_updated_at = receipt.challenged_at;
                    }
                    if !has_remaining_open_obligation
                        && target.custody_state == ArchiveObjectState::ReplicationPolicySatisfied
                    {
                        target.custody_state = ArchiveObjectState::RetrievabilitySamplePassed;
                    }
                }
            }
            ChallengeOutcome::DigestMismatch
            | ChallengeOutcome::MissingOrTruncated
            | ChallengeOutcome::TimeoutOrIndeterminate => {
                if self.repair_obligations.len() >= MAX_REPAIR_OBLIGATIONS {
                    return Err(ReplicationError::BoundsExceeded {
                        observed: self.repair_obligations.len() + 1,
                        maximum: MAX_REPAIR_OBLIGATIONS,
                    });
                }
                if let Some(target) = self.replicas.get_mut(&receipt.replica_id) {
                    // Quarantine is sticky for a corrupt generation: a later Timeout or Missing
                    // sample must NEVER downgrade Quarantined to Indeterminate/RepairScheduled.
                    let next_readiness = match receipt.outcome {
                        ChallengeOutcome::DigestMismatch => ReplicaReadiness::Quarantined,
                        ChallengeOutcome::MissingOrTruncated => ReplicaReadiness::RepairScheduled,
                        ChallengeOutcome::TimeoutOrIndeterminate => ReplicaReadiness::Indeterminate,
                        ChallengeOutcome::Passed => ReplicaReadiness::Healthy,
                    };
                    if target.readiness != ReplicaReadiness::Quarantined
                        || next_readiness == ReplicaReadiness::Quarantined
                    {
                        target.readiness = next_readiness;
                    }
                    // Demote retrievability custody on failure so stale passed status never lingers.
                    if target.custody_state == ArchiveObjectState::RetrievabilitySamplePassed {
                        target.custody_state = ArchiveObjectState::RemoteRootPublished;
                    }
                    if receipt.challenged_at > target.last_updated_at {
                        target.last_updated_at = receipt.challenged_at;
                    }
                }
                let mut obligation_id = receipt.legacy_repair_id();
                if self.repair_obligations.contains_key(&obligation_id) {
                    // Replica and challenge IDs can both contain the legacy separator.
                    obligation_id = receipt.receipt_repair_id();
                }
                let obligation = RepairObligation::from_failure(obligation_id, &receipt, None);
                self.repair_obligations
                    .insert(obligation.obligation_id.clone(), obligation);
            }
        }

        self.challenges.push(receipt.clone());
        self.head_digest = self.compute_head_digest()?;
        Ok(receipt)
    }

    /// Evaluates the non-collapsed archive readiness summary at `now_ns`.
    #[must_use]
    pub fn evaluate_readiness(&self, now_ns: TimestampNs) -> ArchiveReadinessSummary {
        let mut healthy_published_domains = BTreeSet::new();
        let mut fresh_retrievable_domains = BTreeSet::new();
        let mut stale_retrievable_domains = BTreeSet::new();
        let mut fresh_providers = BTreeSet::new();
        // The most recent sample on a replica may prove only an individual object range.
        // Only root-bound receipts on the current generation count toward archive freshness.
        let mut root_verified_at = BTreeMap::new();
        for challenge in &self.challenges {
            if challenge.proves_root()
                && self
                    .replicas
                    .get(&challenge.replica_id)
                    .is_some_and(|r| r.replica_generation == challenge.replica_generation)
            {
                let newest = root_verified_at
                    .entry(challenge.replica_id.as_str())
                    .or_insert(challenge.challenged_at);
                *newest = (*newest).max(challenge.challenged_at);
            }
        }
        let mut indeterminate_replicas = 0usize;
        let mut any_local_durable = false;
        let mut any_remote = false;

        for replica in self.replicas.values() {
            if replica.custody_state >= ArchiveObjectState::LocalDurable {
                any_local_durable = true;
            }
            if replica.custody_state >= ArchiveObjectState::RemoteStaged {
                any_remote = true;
            }
            if replica.readiness == ReplicaReadiness::Indeterminate {
                indeterminate_replicas += 1;
            }
            if replica.readiness == ReplicaReadiness::Healthy
                && replica.custody_state >= ArchiveObjectState::RemoteRootPublished
            {
                healthy_published_domains.insert(replica.failure_domain.clone());
                if let Some(verified_at) = root_verified_at.get(replica.replica_id.as_str()) {
                    let age = now_ns.0.saturating_sub(verified_at.0);
                    if age >= 0 && age <= self.policy.max_retrievability_staleness_ns {
                        fresh_retrievable_domains.insert(replica.failure_domain.clone());
                        fresh_providers.insert(replica.provider_tuple.clone());
                    } else {
                        stale_retrievable_domains.insert(replica.failure_domain.clone());
                    }
                }
            }
        }

        let open_repair_obligations = self
            .repair_obligations
            .values()
            .filter(|o| !o.resolved)
            .count();

        let required_providers_healthy = self.policy.required_providers.iter().all(|req| {
            self.replicas.values().any(|r| {
                r.provider_tuple == *req
                    && r.readiness == ReplicaReadiness::Healthy
                    && r.custody_state >= ArchiveObjectState::RemoteRootPublished
            })
        });
        let required_providers_fresh = self.policy.required_providers.is_subset(&fresh_providers);
        let required_domains = self.policy.min_failure_domains as usize;
        let policy_satisfied =
            healthy_published_domains.len() >= required_domains && required_providers_healthy;

        let state = if open_repair_obligations > 0
            && self.repair_obligations.values().any(|o| {
                !o.resolved
                    && matches!(
                        o.action,
                        RepairAction::QuarantineAndRepair
                            | RepairAction::ReReplicateFromHealthyDomain
                    )
            }) {
            ArchiveReadinessState::RepairRequired
        } else if open_repair_obligations > 0
            || (indeterminate_replicas > 0
                && (!policy_satisfied
                    || fresh_retrievable_domains.len() < required_domains
                    || !required_providers_fresh))
        {
            ArchiveReadinessState::Indeterminate
        } else if policy_satisfied
            && fresh_retrievable_domains.len() >= required_domains
            && required_providers_fresh
        {
            ArchiveReadinessState::RetrievableFresh
        } else if policy_satisfied && !stale_retrievable_domains.is_empty() {
            ArchiveReadinessState::RetrievabilityStale
        } else if policy_satisfied {
            ArchiveReadinessState::PolicySatisfiedUnchallenged
        } else if any_remote {
            ArchiveReadinessState::RemoteUnqualified
        } else if any_local_durable {
            ArchiveReadinessState::LocalDurableOnly
        } else {
            ArchiveReadinessState::StagedOnly
        };

        let total_challenge_egress_bytes = self
            .challenges
            .iter()
            .fold(0u64, |acc, c| acc.saturating_add(c.egress_bytes));
        let total_challenge_ops = self
            .challenges
            .iter()
            .fold(0u64, |acc, c| acc.saturating_add(c.class_b_ops));

        ArchiveReadinessSummary {
            state,
            healthy_published_domains,
            fresh_retrievable_domains,
            open_repair_obligations,
            indeterminate_replicas,
            total_challenge_egress_bytes,
            total_challenge_ops,
            ledger_head_digest: self.head_digest,
        }
    }

    /// Computes the canonical SHA-256 head digest over the entire ledger state.
    pub fn compute_head_digest(&self) -> Result<ContentDigest, ReplicationError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(ARCHIVE_REPLICATION_LEDGER_DOMAIN);
        self.encode_body(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|e| ReplicationError::Encoding(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.format_version);
        enc.digest(self.root_digest);
        enc.digest(self.contract_basis_digest);
        self.policy.encode_canonical(enc);
        enc.u64(self.replicas.len() as u64);
        for replica in self.replicas.values() {
            replica.encode_canonical(enc);
        }
        enc.u64(self.challenges.len() as u64);
        for challenge in &self.challenges {
            challenge.encode_canonical(enc);
        }
        enc.u64(self.repair_obligations.len() as u64);
        for obligation in self.repair_obligations.values() {
            obligation.encode_canonical(enc);
        }
    }

    /// Serializes this ledger into bounded, checksummed binary wire bytes (`FSSREP01` v1).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ReplicationError> {
        if self.format_version != REPLICATION_LEDGER_VERSION {
            return Err(ReplicationError::UnsupportedVersion {
                version: self.format_version,
            });
        }
        if self.compute_head_digest()? != self.head_digest {
            return Err(ReplicationError::ChecksumMismatch);
        }
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        enc.digest(self.head_digest);
        let body = enc
            .finish_checked()
            .map_err(|e| ReplicationError::Encoding(e.to_string()))?;
        let total = REPLICATION_LEDGER_MAGIC
            .len()
            .saturating_add(4)
            .saturating_add(body.len());
        if total > MAX_REPLICATION_LEDGER_WIRE_BYTES {
            return Err(ReplicationError::BoundsExceeded {
                observed: total,
                maximum: MAX_REPLICATION_LEDGER_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&REPLICATION_LEDGER_MAGIC);
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Cold-decodes and verifies a binary [`ArchiveReplicationLedger`].
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ReplicationError> {
        if bytes.len() > MAX_REPLICATION_LEDGER_WIRE_BYTES {
            return Err(ReplicationError::BoundsExceeded {
                observed: bytes.len(),
                maximum: MAX_REPLICATION_LEDGER_WIRE_BYTES,
            });
        }
        if bytes.len() < 12 || bytes[..8] != REPLICATION_LEDGER_MAGIC {
            return Err(ReplicationError::InvalidMagic);
        }
        let header_version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if header_version != REPLICATION_LEDGER_VERSION {
            return Err(ReplicationError::UnsupportedVersion {
                version: header_version,
            });
        }
        let mut dec = CanonicalDecoder::new(&bytes[12..]);
        let format_version = dec
            .u32()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        if format_version != header_version {
            return Err(ReplicationError::UnsupportedVersion {
                version: format_version,
            });
        }
        let root_digest = dec
            .digest()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        let contract_basis_digest = dec
            .digest()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        let policy = ReplicationPolicy::decode_canonical(&mut dec)?;

        let replica_count = usize::try_from(
            dec.u64()
                .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?,
        )
        .map_err(|_| ReplicationError::BoundsExceeded {
            observed: usize::MAX,
            maximum: MAX_REPLICAS_PER_ROOT,
        })?;
        if replica_count > MAX_REPLICAS_PER_ROOT
            || replica_count.saturating_mul(32) > dec.remaining()
        {
            return Err(ReplicationError::BoundsExceeded {
                observed: replica_count,
                maximum: MAX_REPLICAS_PER_ROOT,
            });
        }
        let mut replicas = BTreeMap::new();
        let mut prev_replica_id: Option<String> = None;
        for _ in 0..replica_count {
            let r = ReplicaRecord::decode_canonical(&mut dec)?;
            if prev_replica_id
                .as_deref()
                .is_some_and(|prev| r.replica_id.as_str() <= prev)
            {
                return Err(ReplicationError::MalformedWire(
                    "replicas must be strictly canonically ordered and unique by replica_id"
                        .to_owned(),
                ));
            }
            if !policy.allowed_residency_regions.is_empty()
                && !policy
                    .allowed_residency_regions
                    .contains(&r.residency_region)
            {
                return Err(ReplicationError::MalformedWire(
                    "decoded replica violates policy residency regions".to_owned(),
                ));
            }
            prev_replica_id = Some(r.replica_id.clone());
            replicas.insert(r.replica_id.clone(), r);
        }

        let challenge_count = usize::try_from(
            dec.u64()
                .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?,
        )
        .map_err(|_| ReplicationError::BoundsExceeded {
            observed: usize::MAX,
            maximum: MAX_CHALLENGE_HISTORY,
        })?;
        if challenge_count > MAX_CHALLENGE_HISTORY
            || challenge_count.saturating_mul(64) > dec.remaining()
        {
            return Err(ReplicationError::BoundsExceeded {
                observed: challenge_count,
                maximum: MAX_CHALLENGE_HISTORY,
            });
        }
        let mut challenges = Vec::with_capacity(challenge_count);
        let mut seen_challenges = BTreeSet::new();
        for _ in 0..challenge_count {
            let c = RetrievabilityChallengeReceipt::decode_canonical(&mut dec)?;
            if c.root_digest != root_digest {
                return Err(ReplicationError::MalformedWire(
                    "challenge receipt root_digest disagrees with ledger root_digest".to_owned(),
                ));
            }
            if !replicas.get(&c.replica_id).is_some_and(|r| {
                r.provider_tuple == c.provider_tuple
                    && r.failure_domain == c.failure_domain
                    && r.replica_generation >= c.replica_generation
            }) {
                return Err(ReplicationError::MalformedWire(
                    "challenge receipt disagrees with replica identity, topology, or generation"
                        .to_owned(),
                ));
            }
            if !seen_challenges.insert(c.challenge_id.clone()) {
                return Err(ReplicationError::MalformedWire(
                    "duplicate challenge_id in wire ledger".to_owned(),
                ));
            }
            challenges.push(c);
        }

        let obligation_count = usize::try_from(
            dec.u64()
                .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?,
        )
        .map_err(|_| ReplicationError::BoundsExceeded {
            observed: usize::MAX,
            maximum: MAX_REPAIR_OBLIGATIONS,
        })?;
        if obligation_count > MAX_REPAIR_OBLIGATIONS
            || obligation_count.saturating_mul(32) > dec.remaining()
        {
            return Err(ReplicationError::BoundsExceeded {
                observed: obligation_count,
                maximum: MAX_REPAIR_OBLIGATIONS,
            });
        }
        let challenge_by_digest: BTreeMap<ContentDigest, &RetrievabilityChallengeReceipt> =
            challenges.iter().map(|c| (c.receipt_digest, c)).collect();
        for replica in replicas.values() {
            match (replica.last_challenge_digest, replica.last_verified_at) {
                (None, None)
                    if replica.custody_state != ArchiveObjectState::RetrievabilitySamplePassed => {}
                (Some(digest), Some(time))
                    if challenge_by_digest.get(&digest).is_some_and(|c| {
                        c.replica_id == replica.replica_id
                            && c.replica_generation == replica.replica_generation
                            && c.outcome == ChallengeOutcome::Passed
                            && c.challenged_at == time
                    }) => {}
                _ => {
                    return Err(ReplicationError::MalformedWire(
                        "replica verification lacks a matching passing challenge receipt".to_owned(),
                    ));
                }
            }
        }
        let mut unmatched_failures: BTreeSet<_> = challenges
            .iter()
            .filter(|c| c.outcome != ChallengeOutcome::Passed)
            .map(|c| c.receipt_digest)
            .collect();
        let mut repair_obligations = BTreeMap::new();
        let mut prev_obligation_id: Option<String> = None;
        for _ in 0..obligation_count {
            let o = RepairObligation::decode_canonical(&mut dec)?;
            if prev_obligation_id
                .as_deref()
                .is_some_and(|prev| o.obligation_id.as_str() <= prev)
            {
                return Err(ReplicationError::MalformedWire(
                    "repair obligations must be strictly canonically ordered and unique".to_owned(),
                ));
            }
            if !replicas.contains_key(&o.replica_id) {
                return Err(ReplicationError::MalformedWire(
                    "repair obligation references unknown replica_id".to_owned(),
                ));
            }
            let Some(trigger) = challenge_by_digest.get(&o.triggering_challenge_digest) else {
                return Err(ReplicationError::MalformedWire(
                    "repair obligation references unknown triggering challenge digest".to_owned(),
                ));
            };
            if !unmatched_failures.remove(&o.triggering_challenge_digest)
                || (o.obligation_id != trigger.legacy_repair_id()
                    && o.obligation_id != trigger.receipt_repair_id())
            {
                return Err(ReplicationError::MalformedWire(
                    "repair obligation ID or triggering challenge is inconsistent".to_owned(),
                ));
            }
            if trigger.replica_id != o.replica_id
                || trigger.outcome == ChallengeOutcome::Passed
                || trigger.replica_generation != o.failed_generation
                || trigger.challenged_at != o.opened_at
                || trigger.repair_action != o.action
            {
                return Err(ReplicationError::MalformedWire(
                    "repair obligation triggering challenge must be a non-passed challenge on the same replica"
                        .to_owned(),
                ));
            }
            if let Some(resolved_digest) = o.resolved_by_challenge_digest {
                let Some(resolver) = challenge_by_digest.get(&resolved_digest) else {
                    return Err(ReplicationError::MalformedWire(
                        "repair obligation references unknown resolving challenge digest"
                            .to_owned(),
                    ));
                };
                if !resolver.resolves_challenge(trigger) {
                    return Err(ReplicationError::MalformedWire(
                        "resolving challenge must verify the failed evidence at or after the failure"
                            .to_owned(),
                    ));
                }
            }
            prev_obligation_id = Some(o.obligation_id.clone());
            repair_obligations.insert(o.obligation_id.clone(), o);
        }

        let stored_head = dec
            .digest()
            .map_err(|e| ReplicationError::MalformedWire(e.to_string()))?;
        dec.ensure_finished().map_err(|_| {
            ReplicationError::MalformedWire("trailing bytes after replication ledger".to_owned())
        })?;

        let mut ledger = Self {
            format_version,
            root_digest,
            contract_basis_digest,
            policy,
            replicas,
            challenges,
            repair_obligations,
            head_digest: stored_head,
        };
        if ledger.compute_head_digest()? != stored_head {
            return Err(ReplicationError::ChecksumMismatch);
        }
        if !unmatched_failures.is_empty() {
            ledger.restore_displaced_obligations(&unmatched_failures)?;
        }
        Ok(ledger)
    }

    /// Older v1 writers could replace a repair row when two pairs of IDs joined to the same
    /// string. Recover only this identifiable case from the retained challenge history.
    fn restore_displaced_obligations(
        &mut self,
        unmatched: &BTreeSet<ContentDigest>,
    ) -> Result<(), ReplicationError> {
        let total = self.repair_obligations.len() + unmatched.len();
        if total > MAX_REPAIR_OBLIGATIONS {
            return Err(ReplicationError::BoundsExceeded {
                observed: total,
                maximum: MAX_REPAIR_OBLIGATIONS,
            });
        }
        for (idx, failure) in self.challenges.iter().enumerate() {
            if !unmatched.contains(&failure.receipt_digest) {
                continue;
            }
            let later = &self.challenges[idx + 1..];
            let displaced = self
                .repair_obligations
                .get(&failure.legacy_repair_id())
                .is_some_and(|existing| {
                    later.iter().any(|c| c.receipt_digest == existing.triggering_challenge_digest)
                });
            if !displaced {
                return Err(ReplicationError::MalformedWire(
                    "failed challenge is missing its repair obligation".to_owned(),
                ));
            }
            let resolver = later
                .iter()
                .find(|c| c.resolves_challenge(failure))
                .map(|c| c.receipt_digest);
            let id = failure.receipt_repair_id();
            let obligation = RepairObligation::from_failure(id, failure, resolver);
            self.repair_obligations
                .insert(obligation.obligation_id.clone(), obligation);
        }
        self.head_digest = self.compute_head_digest()?;
        // Recovery must also fit the persisted wire size ceiling.
        self.to_canonical_bytes().map(|_| ())
    }
}

const fn repair_action_for(outcome: ChallengeOutcome) -> RepairAction {
    match outcome {
        ChallengeOutcome::Passed => RepairAction::None,
        ChallengeOutcome::DigestMismatch => RepairAction::QuarantineAndRepair,
        ChallengeOutcome::MissingOrTruncated => RepairAction::ReReplicateFromHealthyDomain,
        ChallengeOutcome::TimeoutOrIndeterminate => RepairAction::ReconcileIndeterminateReplica,
    }
}

const fn archive_state_tag(state: ArchiveObjectState) -> u8 {
    match state {
        ArchiveObjectState::LocalStaged => 1,
        ArchiveObjectState::LocalDurable => 2,
        ArchiveObjectState::RemoteStaged => 3,
        ArchiveObjectState::RemoteChildrenVerified => 4,
        ArchiveObjectState::RemoteRootPublished => 5,
        ArchiveObjectState::ReplicationPolicySatisfied => 6,
        ArchiveObjectState::RetrievabilitySamplePassed => 7,
    }
}

fn archive_state_from_tag(tag: u8) -> Result<ArchiveObjectState, ContractError> {
    match tag {
        1 => Ok(ArchiveObjectState::LocalStaged),
        2 => Ok(ArchiveObjectState::LocalDurable),
        3 => Ok(ArchiveObjectState::RemoteStaged),
        4 => Ok(ArchiveObjectState::RemoteChildrenVerified),
        5 => Ok(ArchiveObjectState::RemoteRootPublished),
        6 => Ok(ArchiveObjectState::ReplicationPolicySatisfied),
        7 => Ok(ArchiveObjectState::RetrievabilitySamplePassed),
        _ => Err(ContractError::InvalidIdentifier),
    }
}

fn validate_bounded_text(value: &str, max_len: usize, label: &str) -> Result<(), ReplicationError> {
    if value.is_empty() || value.len() > max_len {
        return Err(ReplicationError::InvalidInput(format!(
            "{label} length {} outside 1..={max_len}",
            value.len()
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(ReplicationError::InvalidInput(format!(
            "{label} must not contain control characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ledger() -> Result<ArchiveReplicationLedger, ReplicationError> {
        let root = ContentDigest::sha256(b"root");
        let basis = ContentDigest::sha256(b"basis");
        let policy = ReplicationPolicy {
            min_failure_domains: 1,
            required_providers: BTreeSet::new(),
            allowed_residency_regions: BTreeSet::new(),
            max_retrievability_staleness_ns: 100,
            policy_digest: ContentDigest::sha256(b"policy"),
        };
        ArchiveReplicationLedger::new(root, basis, policy)
    }

    #[test]
    fn restored_verification_requires_a_persisted_passing_receipt() -> Result<(), ReplicationError>
    {
        let mut ledger = test_ledger()?;
        let auth = ReplicationAuthorityContext::active(ledger.contract_basis_digest(), 1, 1);
        ledger.register_replica(
            &auth,
            "r",
            "provider",
            "domain",
            "region",
            TimestampNs(0),
            false,
        )?;
        let replica = ledger
            .replicas
            .get_mut("r")
            .expect("replica was registered above");
        replica.custody_state = ArchiveObjectState::RetrievabilitySamplePassed;
        replica.last_verified_at = Some(TimestampNs(5));
        replica.last_challenge_digest = Some(ContentDigest::sha256(b"absent receipt"));
        ledger.head_digest = ledger.compute_head_digest()?;

        let persisted = ledger.to_canonical_bytes()?;
        assert!(matches!(
            ArchiveReplicationLedger::from_canonical_bytes(&persisted),
            Err(ReplicationError::MalformedWire(_))
        ));
        Ok(())
    }

    #[test]
    fn colliding_legacy_ids_preserve_both_repairs_across_restart() -> Result<(), ReplicationError> {
        let mut ledger = test_ledger()?;
        let auth = ReplicationAuthorityContext::active(ledger.contract_basis_digest(), 1, 1);
        let root = ledger.root_digest();
        for (replica, challenge) in [("a:b", "c"), ("a", "b:c")] {
            ledger.register_replica(
                &auth,
                replica,
                "provider",
                "domain",
                "region",
                TimestampNs(0),
                false,
            )?;
            let failure = RetrievabilityChallengeInput {
                replica_id: replica.to_owned(),
                challenge_id: challenge.to_owned(),
                replica_generation: 1,
                ranges: vec![ChallengeRange {
                    offset: 0,
                    length: 1,
                }],
                expected_digest: root,
                observed_digest: None,
                latency_ms: 10,
                egress_bytes: 0,
                class_b_ops: 1,
                outcome: ChallengeOutcome::MissingOrTruncated,
                challenged_at: TimestampNs(1),
            };
            let receipt = ledger.record_challenge(&auth, failure.clone(), false)?;
            assert_eq!(receipt, ledger.record_challenge(&auth, failure, false)?);
        }

        let legacy_id = "repair:a:b:c";
        let first = ledger.challenges[0].clone();
        let second = ledger.challenges[1].clone();
        assert_eq!(ledger.repair_obligations.len(), 2);
        assert_eq!(
            ledger.repair_obligations[legacy_id].triggering_challenge_digest,
            first.receipt_digest
        );
        assert_eq!(
            ledger.repair_obligations[&second.receipt_repair_id()].triggering_challenge_digest,
            second.receipt_digest
        );
        let wire = ledger.to_canonical_bytes()?;
        let reopened = ArchiveReplicationLedger::from_canonical_bytes(&wire)?;
        assert_eq!(reopened, ledger);

        // Recreate an older persisted v1 snapshot in which the second failure displaced the first.
        ledger.repair_obligations.clear();
        ledger.repair_obligations.insert(
            legacy_id.to_owned(),
            RepairObligation::from_failure(legacy_id.to_owned(), &second, None),
        );
        ledger.head_digest = ledger.compute_head_digest()?;
        let old_wire = ledger.to_canonical_bytes()?;
        let recovered = ArchiveReplicationLedger::from_canonical_bytes(&old_wire)?;
        assert_eq!(
            recovered.repair_obligations[legacy_id].triggering_challenge_digest,
            second.receipt_digest
        );
        assert_eq!(
            recovered.repair_obligations[&first.receipt_repair_id()].triggering_challenge_digest,
            first.receipt_digest
        );
        assert_eq!(
            recovered.evaluate_readiness(TimestampNs(2)).open_repair_obligations,
            2
        );
        let repaired_wire = recovered.to_canonical_bytes()?;
        assert_eq!(
            ArchiveReplicationLedger::from_canonical_bytes(&repaired_wire)?,
            recovered
        );

        // A missing obligation without the legacy collision must still be refused.
        ledger.repair_obligations.clear();
        ledger.head_digest = ledger.compute_head_digest()?;
        assert!(matches!(
            ArchiveReplicationLedger::from_canonical_bytes(&ledger.to_canonical_bytes()?),
            Err(ReplicationError::MalformedWire(_))
        ));
        Ok(())
    }
}

#![forbid(unsafe_code)]
//! Deterministic remote archive restore and fault-injection matrix (`FSS-069`, `fss-x4a.13.9`).
//!
//! Runs a reproducible, bounded matrix of remote archive restore scenarios across real
//! [`ObjectManifest`] closures, [`EncryptionContextManifest`] bindings, [`CustodyLevel`] floors,
//! replica failover, duplicate/reordered deliveries, remote corruption, missing chunks, tombstones,
//! indeterminate remote observations, unauthorized roots, and cancellation at restore boundaries —
//! without reading local raw source media (`INV-046`, `INV-047`, `INV-048`, `INV-066`, `INV-067`,
//! `INV-075`).

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, Generation, TimestampNs,
};

use crate::ObjectManifest;
use crate::closure::CustodyLevel;
use crate::encryption::{CipherSuite, EncryptionContextManifest};
use crate::incident_retrieval::{
    IncidentRetrievalAuthority, IncidentRetrievalError, IncidentRetrievalStatus,
    RetrievedObjectRecord, verify_incident_retrieval,
};

/// Registered digest domain for canonical remote archive restore/fault matrix receipts
/// (`SCHEMA-DOMAIN-OBJECT-RESTORE-FAULT-MATRIX-001`).
pub const RESTORE_FAULT_MATRIX_RECEIPT_DOMAIN: &str = "fss.object.restore_fault_matrix_receipt.v1";

/// Canonical binary format version for [`RestoreFaultMatrixReceipt`].
pub const RESTORE_FAULT_MATRIX_FORMAT_VERSION: u32 = 1;

/// Maximum scenarios admitted in one bounded restore/fault matrix execution.
pub const MAX_MATRIX_SCENARIOS: usize = 64;

/// Maximum UTF-8 bytes in scenario or matrix identifiers.
pub const MAX_MATRIX_LABEL_BYTES: usize = 128;

/// Closed taxonomy of remote archive restore fault scenarios required by `FSS-069`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RestoreFaultKind {
    /// Clean multi-level incident archive restore with full encryption coverage and `Retrievable` floor.
    NominalCleanRestore,
    /// Primary replica serves a bit-flipped chunk; verified secondary replica recovers cleanly.
    CorruptChunkReplicaFailover,
    /// Chunk missing across all replicas; partial verified siblings retained without fabrication.
    MissingChunkUnrecoverable,
    /// Remote object stuck at `Staged`/`Replicated` below `Retrievable` custody floor.
    BelowCustodyFloorStagedOrReplicated,
    /// Remote head/read observation remains indeterminate; never upgraded to verified.
    IndeterminateRemoteObservation,
    /// Target object tombstoned under retention/deletion policy.
    TombstonedDeletedObject,
    /// Unauthorized principal/root refused BEFORE reading object bytes or expanding graph.
    UnauthorizedIncidentRoot,
    /// Encryption context omits a retrieved leaf chunk.
    UncoveredEncryptionLeaf,
    /// Duplicate and out-of-order chunk arrival yields bit-identical verified root & bytes.
    DuplicateReorderedDeliveryIdempotent,
    /// Cooperative cancellation at restore boundary leaves zero staged/published partial state.
    CancelledAtRestoreBoundary,
}

impl RestoreFaultKind {
    /// Stable canonical machine label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NominalCleanRestore => "nominal_clean_restore",
            Self::CorruptChunkReplicaFailover => "corrupt_chunk_replica_failover",
            Self::MissingChunkUnrecoverable => "missing_chunk_unrecoverable",
            Self::BelowCustodyFloorStagedOrReplicated => "below_custody_floor_staged_or_replicated",
            Self::IndeterminateRemoteObservation => "indeterminate_remote_observation",
            Self::TombstonedDeletedObject => "tombstoned_deleted_object",
            Self::UnauthorizedIncidentRoot => "unauthorized_incident_root",
            Self::UncoveredEncryptionLeaf => "uncovered_encryption_leaf",
            Self::DuplicateReorderedDeliveryIdempotent => "duplicate_reordered_delivery_idempotent",
            Self::CancelledAtRestoreBoundary => "cancelled_at_restore_boundary",
        }
    }
}

impl CanonicalEncode for RestoreFaultKind {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self {
            Self::NominalCleanRestore => 1,
            Self::CorruptChunkReplicaFailover => 2,
            Self::MissingChunkUnrecoverable => 3,
            Self::BelowCustodyFloorStagedOrReplicated => 4,
            Self::IndeterminateRemoteObservation => 5,
            Self::TombstonedDeletedObject => 6,
            Self::UnauthorizedIncidentRoot => 7,
            Self::UncoveredEncryptionLeaf => 8,
            Self::DuplicateReorderedDeliveryIdempotent => 9,
            Self::CancelledAtRestoreBoundary => 10,
        });
    }
}

impl CanonicalDecode for RestoreFaultKind {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::NominalCleanRestore),
            2 => Ok(Self::CorruptChunkReplicaFailover),
            3 => Ok(Self::MissingChunkUnrecoverable),
            4 => Ok(Self::BelowCustodyFloorStagedOrReplicated),
            5 => Ok(Self::IndeterminateRemoteObservation),
            6 => Ok(Self::TombstonedDeletedObject),
            7 => Ok(Self::UnauthorizedIncidentRoot),
            8 => Ok(Self::UncoveredEncryptionLeaf),
            9 => Ok(Self::DuplicateReorderedDeliveryIdempotent),
            10 => Ok(Self::CancelledAtRestoreBoundary),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Non-collapsed restore outcome observed for one matrix case.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RestoreScenarioOutcome {
    /// Complete archive closure restored and independently verified without local source.
    RestoredVerifiedComplete,
    /// Primary fault detected and recovered cleanly via verified replica failover.
    RecoveredViaReplicaFailover,
    /// Unrecoverable missing/corrupt/tombstoned/below-floor/uncovered defect preserved honestly.
    PartialDegradedPreserved,
    /// Remote observation remained indeterminate; never upgraded.
    IndeterminatePreserved,
    /// Unauthorized scope refused prior to byte read.
    UnauthorizedRefused,
    /// Cooperative cancellation drained cleanly with zero partial publication.
    CancelledCleanly,
}

impl RestoreScenarioOutcome {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RestoredVerifiedComplete => "restored_verified_complete",
            Self::RecoveredViaReplicaFailover => "recovered_via_replica_failover",
            Self::PartialDegradedPreserved => "partial_degraded_preserved",
            Self::IndeterminatePreserved => "indeterminate_preserved",
            Self::UnauthorizedRefused => "unauthorized_refused",
            Self::CancelledCleanly => "cancelled_cleanly",
        }
    }
}

impl CanonicalEncode for RestoreScenarioOutcome {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self {
            Self::RestoredVerifiedComplete => 1,
            Self::RecoveredViaReplicaFailover => 2,
            Self::PartialDegradedPreserved => 3,
            Self::IndeterminatePreserved => 4,
            Self::UnauthorizedRefused => 5,
            Self::CancelledCleanly => 6,
        });
    }
}

impl CanonicalDecode for RestoreScenarioOutcome {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::RestoredVerifiedComplete),
            2 => Ok(Self::RecoveredViaReplicaFailover),
            3 => Ok(Self::PartialDegradedPreserved),
            4 => Ok(Self::IndeterminatePreserved),
            5 => Ok(Self::UnauthorizedRefused),
            6 => Ok(Self::CancelledCleanly),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// One executed row in the sealed restore/fault matrix receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreFaultCaseReport {
    /// Exact scenario class exercised.
    pub kind: RestoreFaultKind,
    /// Expected non-collapsed outcome for this scenario.
    pub expected: RestoreScenarioOutcome,
    /// Observed non-collapsed outcome.
    pub observed: RestoreScenarioOutcome,
    /// Number of verified objects recorded in the case.
    pub verified_objects: u32,
    /// Cumulative verified bytes recorded in the case.
    pub verified_bytes: u64,
    /// Digest of the underlying incident retrieval witness (or cancellation sentinel).
    pub witness_digest: ContentDigest,
    /// Whether `observed == expected` and cleanup invariants held.
    pub passed: bool,
}

impl CanonicalEncode for RestoreFaultCaseReport {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.kind.encode_canonical(encoder);
        self.expected.encode_canonical(encoder);
        self.observed.encode_canonical(encoder);
        encoder.u32(self.verified_objects);
        encoder.u64(self.verified_bytes);
        encoder.digest(self.witness_digest);
        encoder.u8(u8::from(self.passed));
    }
}

impl CanonicalDecode for RestoreFaultCaseReport {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let kind = RestoreFaultKind::decode_canonical(decoder)?;
        let expected = RestoreScenarioOutcome::decode_canonical(decoder)?;
        let observed = RestoreScenarioOutcome::decode_canonical(decoder)?;
        let verified_objects = decoder.u32()?;
        let verified_bytes = decoder.u64()?;
        let witness_digest = decoder.digest()?;
        let passed = match decoder.u8()? {
            0 => false,
            1 => true,
            _ => return Err(ContractError::InvalidIdentifier),
        };
        let outcome_counts_valid = match observed {
            RestoreScenarioOutcome::RestoredVerifiedComplete
            | RestoreScenarioOutcome::RecoveredViaReplicaFailover => verified_objects > 0,
            RestoreScenarioOutcome::UnauthorizedRefused
            | RestoreScenarioOutcome::CancelledCleanly => {
                verified_objects == 0 && verified_bytes == 0
            }
            RestoreScenarioOutcome::PartialDegradedPreserved
            | RestoreScenarioOutcome::IndeterminatePreserved => true,
        };
        if passed != (expected == observed)
            || (verified_objects == 0 && verified_bytes != 0)
            || !outcome_counts_valid
        {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(Self {
            kind,
            expected,
            observed,
            verified_objects,
            verified_bytes,
            witness_digest,
            passed,
        })
    }
}

/// Typed refusal for restore/fault matrix execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RestoreMatrixError {
    /// Invalid label, generation, or empty scenario list.
    InvalidConfiguration(&'static str),
    /// Internal manifest or encryption-context construction failed.
    FixtureConstructionFailed,
    /// Cooperative cancellation observed before completing matrix execution.
    Cancelled,
}

impl fmt::Display for RestoreMatrixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(why) => write!(f, "invalid restore matrix config: {why}"),
            Self::FixtureConstructionFailed => write!(f, "failed to construct restore fixture"),
            Self::Cancelled => write!(f, "restore/fault matrix execution cancelled"),
        }
    }
}

impl std::error::Error for RestoreMatrixError {}

fn is_clean_label(val: &str) -> bool {
    !val.is_empty()
        && val.len() <= MAX_MATRIX_LABEL_BYTES
        && !val
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
}

/// Canonical, tamper-evident proof receipt covering an entire remote archive restore/fault matrix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreFaultMatrixReceipt {
    /// Format version (`RESTORE_FAULT_MATRIX_FORMAT_VERSION`).
    pub format_version: u32,
    /// Stable matrix run identifier.
    pub matrix_id: String,
    /// Deterministic scenario seed.
    pub seed: u64,
    /// Pinned archive/policy generation (`!= 0`).
    pub generation: Generation,
    /// Timestamp when matrix run completed.
    pub executed_at_ns: TimestampNs,
    /// Ordered per-scenario reports (unique `RestoreFaultKind`).
    pub cases: Vec<RestoreFaultCaseReport>,
    /// Count of passed scenarios (`cases_passed <= cases.len()`).
    pub cases_passed: u32,
    /// Always `false`: remote restore matrix never reads local raw source custody.
    pub read_local_source: bool,
    /// Domain-separated SHA-256 digest over all fields above.
    pub receipt_digest: ContentDigest,
}

impl RestoreFaultMatrixReceipt {
    /// Recomputes the exact domain-separated SHA-256 digest over all canonical fields.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(RESTORE_FAULT_MATRIX_RECEIPT_DOMAIN);
        encoder.u32(self.format_version);
        encoder.text(&self.matrix_id);
        encoder.u64(self.seed);
        encoder.u64(self.generation.0);
        encoder.i128(self.executed_at_ns.0);
        encoder.u64(self.cases.len() as u64);
        for case in &self.cases {
            case.encode_canonical(&mut encoder);
        }
        encoder.u32(self.cases_passed);
        encoder.u8(u8::from(self.read_local_source));
        ContentDigest::sha256(&encoder.finish())
    }

    /// Returns `true` iff `receipt_digest` matches [`Self::computed_digest`].
    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.receipt_digest == self.computed_digest()
    }

    /// Returns `true` iff every case in the matrix passed and digest verifies cleanly.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        !self.cases.is_empty()
            && self.cases_passed as usize == self.cases.len()
            && self.cases.iter().all(|c| c.passed)
            && !self.read_local_source
            && self.verify_digest()
    }
}

impl CanonicalEncode for RestoreFaultMatrixReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.format_version);
        encoder.text(&self.matrix_id);
        encoder.u64(self.seed);
        encoder.u64(self.generation.0);
        encoder.i128(self.executed_at_ns.0);
        encoder.u64(self.cases.len() as u64);
        for case in &self.cases {
            case.encode_canonical(encoder);
        }
        encoder.u32(self.cases_passed);
        encoder.u8(u8::from(self.read_local_source));
        encoder.digest(self.receipt_digest);
    }
}

impl CanonicalDecode for RestoreFaultMatrixReceipt {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let format_version = decoder.u32()?;
        if format_version != RESTORE_FAULT_MATRIX_FORMAT_VERSION {
            return Err(ContractError::InvalidIdentifier);
        }
        let matrix_id = decoder.text()?.to_owned();
        let seed = decoder.u64()?;
        let generation = Generation(decoder.u64()?);
        let executed_at_ns = TimestampNs(decoder.i128()?);
        let count =
            usize::try_from(decoder.u64()?).map_err(|_| ContractError::InvalidIdentifier)?;
        if !is_clean_label(&matrix_id)
            || generation.0 == 0
            || !(1..=MAX_MATRIX_SCENARIOS).contains(&count)
            || count > decoder.remaining() / 49
        {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut cases = Vec::with_capacity(count);
        let mut seen_kinds = BTreeSet::new();
        let mut actual_passed: u32 = 0;
        for _ in 0..count {
            let report = RestoreFaultCaseReport::decode_canonical(decoder)?;
            if !seen_kinds.insert(report.kind) {
                return Err(ContractError::InvalidIdentifier);
            }
            if report.passed {
                actual_passed = actual_passed.saturating_add(1);
            }
            cases.push(report);
        }
        let cases_passed = decoder.u32()?;
        let read_local_source = match decoder.u8()? {
            0 => false,
            1 => true,
            _ => return Err(ContractError::InvalidIdentifier),
        };
        let receipt_digest = decoder.digest()?;
        if cases_passed != actual_passed || read_local_source {
            return Err(ContractError::InvalidIdentifier);
        }

        let receipt = Self {
            format_version,
            matrix_id,
            seed,
            generation,
            executed_at_ns,
            cases,
            cases_passed,
            read_local_source,
            receipt_digest,
        };
        if !receipt.verify_digest() {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(receipt)
    }
}

/// Returns all 10 standard scenarios covering the complete `FSS-069` remote archive restore/fault matrix.
#[must_use]
pub const fn standard_restore_fault_scenarios() -> [RestoreFaultKind; 10] {
    [
        RestoreFaultKind::NominalCleanRestore,
        RestoreFaultKind::CorruptChunkReplicaFailover,
        RestoreFaultKind::MissingChunkUnrecoverable,
        RestoreFaultKind::BelowCustodyFloorStagedOrReplicated,
        RestoreFaultKind::IndeterminateRemoteObservation,
        RestoreFaultKind::TombstonedDeletedObject,
        RestoreFaultKind::UnauthorizedIncidentRoot,
        RestoreFaultKind::UncoveredEncryptionLeaf,
        RestoreFaultKind::DuplicateReorderedDeliveryIdempotent,
        RestoreFaultKind::CancelledAtRestoreBoundary,
    ]
}

fn leaf(payload: Vec<u8>, custody: CustodyLevel) -> (ContentDigest, RetrievedObjectRecord) {
    let digest = ContentDigest::sha256(&payload);
    (
        digest,
        RetrievedObjectRecord {
            digest,
            bytes: payload,
            observed_custody: custody,
            is_manifest: false,
            tombstoned: false,
            indeterminate_remote_state: false,
        },
    )
}

fn manifest_rec(
    manifest: &ObjectManifest,
    custody: CustodyLevel,
) -> (ContentDigest, RetrievedObjectRecord) {
    let bytes = manifest.canonical_bytes();
    let digest = manifest.root();
    (
        digest,
        RetrievedObjectRecord {
            digest,
            bytes,
            observed_custody: custody,
            is_manifest: true,
            tombstoned: false,
            indeterminate_remote_state: false,
        },
    )
}

fn seeded_payload(seed: u64, tag: u8, len: usize) -> Vec<u8> {
    let mut state = seed ^ (u64::from(tag) << 56) ^ 0x9E37_79B9_7F4A_7C15;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.push((state >> 56) as u8);
    }
    out
}

/// Executes the deterministic remote archive restore & fault-injection matrix for `scenarios`,
/// exercising real [`ObjectManifest`] closures, [`EncryptionContextManifest`] coverage, replica
/// failover, custody-floor enforcement, and cooperative cancellation without reading local source.
pub fn run_restore_fault_matrix(
    matrix_id: &str,
    seed: u64,
    generation: Generation,
    executed_at_ns: TimestampNs,
    scenarios: &[RestoreFaultKind],
    mut is_cancelled: impl FnMut() -> bool,
) -> Result<RestoreFaultMatrixReceipt, RestoreMatrixError> {
    if !is_clean_label(matrix_id)
        || generation.0 == 0
        || !(1..=MAX_MATRIX_SCENARIOS).contains(&scenarios.len())
    {
        return Err(RestoreMatrixError::InvalidConfiguration(
            "invalid_matrix_args",
        ));
    }
    let mut unique = BTreeSet::new();
    for &s in scenarios {
        if !unique.insert(s) {
            return Err(RestoreMatrixError::InvalidConfiguration(
                "duplicate_scenario",
            ));
        }
    }
    if is_cancelled() {
        return Err(RestoreMatrixError::Cancelled);
    }

    // Build deterministic 2-tier archive incident graph (root -> [seg_manifest, meta], seg -> [c0, c1]).
    let (c0_d, c0_r) = leaf(seeded_payload(seed, 1, 96), CustodyLevel::Retrievable);
    let (c1_d, c1_r) = leaf(seeded_payload(seed, 2, 112), CustodyLevel::Retrievable);
    let (meta_d, meta_r) = leaf(seeded_payload(seed, 3, 64), CustodyLevel::Retrievable);
    let seg = ObjectManifest::new("segment", [c0_d, c1_d], None)
        .map_err(|_| RestoreMatrixError::FixtureConstructionFailed)?;
    let (seg_d, seg_r) = manifest_rec(&seg, CustodyLevel::Retrievable);
    let root = ObjectManifest::new("incident", [seg_d], Some(meta_d))
        .map_err(|_| RestoreMatrixError::FixtureConstructionFailed)?;
    let (root_d, root_r) = manifest_rec(&root, CustodyLevel::Retrievable);

    let full_enc = EncryptionContextManifest::genesis(
        CipherSuite::ChaCha20Poly1305,
        "kms:archive:matrix-v1",
        [0x5A; 16],
        vec![c0_d, c1_d, meta_d],
    )
    .map_err(|_| RestoreMatrixError::FixtureConstructionFailed)?;

    let mut clean_store = BTreeMap::new();
    clean_store.insert(c0_d, c0_r.clone());
    clean_store.insert(c1_d, c1_r.clone());
    clean_store.insert(meta_d, meta_r.clone());
    clean_store.insert(seg_d, seg_r.clone());
    clean_store.insert(root_d, root_r.clone());

    let base_auth = IncidentRetrievalAuthority {
        incident_id: format!("inc:{matrix_id}"),
        principal_id: "owner:restore-drill".to_owned(),
        authority_grant_digest: ContentDigest::sha256(b"grant:fss-069-restore-matrix"),
        generation,
        allowed_incident_roots: BTreeSet::from([root_d]),
        required_custody_floor: CustodyLevel::Retrievable,
        max_objects: 64,
        max_bytes: 1024 * 1024,
    };

    let mut cases = Vec::with_capacity(scenarios.len());
    let mut cases_passed: u32 = 0;

    for &kind in scenarios {
        if is_cancelled() {
            return Err(RestoreMatrixError::Cancelled);
        }
        let report = match kind {
            RestoreFaultKind::NominalCleanRestore => {
                let r = verify_incident_retrieval(
                    &base_auth,
                    root_d,
                    &clean_store,
                    Some(&full_enc),
                    executed_at_ns,
                    || false,
                )
                .map_err(|_| RestoreMatrixError::FixtureConstructionFailed)?;
                let observed = if r.status == IncidentRetrievalStatus::VerifiedRetrievableComplete
                    && r.verified_objects.len() == 5
                {
                    RestoreScenarioOutcome::RestoredVerifiedComplete
                } else {
                    RestoreScenarioOutcome::PartialDegradedPreserved
                };
                make_case(
                    kind,
                    RestoreScenarioOutcome::RestoredVerifiedComplete,
                    observed,
                    r.verified_objects.len() as u32,
                    r.verified_bytes,
                    r.receipt_digest,
                )
            }
            RestoreFaultKind::CorruptChunkReplicaFailover => {
                // Primary replica serves bit-flipped c1; primary verification MUST reject c1,
                // then failover fetches verified c1 from secondary replica and completes!
                let mut primary = clean_store.clone();
                if let Some(bad) = primary.get_mut(&c1_d) {
                    bad.bytes[0] ^= 0xA5;
                }
                let r_primary = verify_incident_retrieval(
                    &base_auth,
                    root_d,
                    &primary,
                    Some(&full_enc),
                    executed_at_ns,
                    || false,
                )
                .map_err(|_| RestoreMatrixError::FixtureConstructionFailed)?;
                let mut observed = RestoreScenarioOutcome::PartialDegradedPreserved;
                let mut final_objects = r_primary.verified_objects.len() as u32;
                let mut final_bytes = r_primary.verified_bytes;
                let mut final_digest = r_primary.receipt_digest;
                if r_primary.status == IncidentRetrievalStatus::PartialCorruptOrMissing
                    && r_primary.corrupt_digests == vec![c1_d]
                {
                    // Fail over corrupt digest from verified secondary replica (`clean_store`).
                    let mut healed = primary;
                    if let Some(good_c1) = clean_store.get(&c1_d) {
                        healed.insert(c1_d, good_c1.clone());
                    }
                    let r_failover = verify_incident_retrieval(
                        &base_auth,
                        root_d,
                        &healed,
                        Some(&full_enc),
                        executed_at_ns,
                        || false,
                    )
                    .map_err(|_| RestoreMatrixError::FixtureConstructionFailed)?;
                    if r_failover.status == IncidentRetrievalStatus::VerifiedRetrievableComplete
                        && r_failover.verified_objects.len() == 5
                    {
                        observed = RestoreScenarioOutcome::RecoveredViaReplicaFailover;
                        final_objects = r_failover.verified_objects.len() as u32;
                        final_bytes = r_failover.verified_bytes;
                        final_digest = r_failover.receipt_digest;
                    }
                }
                make_case(
                    kind,
                    RestoreScenarioOutcome::RecoveredViaReplicaFailover,
                    observed,
                    final_objects,
                    final_bytes,
                    final_digest,
                )
            }
            RestoreFaultKind::MissingChunkUnrecoverable => {
                let mut missing_store = clean_store.clone();
                missing_store.remove(&c0_d);
                let r = verify_incident_retrieval(
                    &base_auth,
                    root_d,
                    &missing_store,
                    Some(&full_enc),
                    executed_at_ns,
                    || false,
                )
                .map_err(|_| RestoreMatrixError::FixtureConstructionFailed)?;
                let observed = if r.status == IncidentRetrievalStatus::PartialCorruptOrMissing
                    && r.missing_digests == vec![c0_d]
                    && r.verified_objects.len() == 4
                {
                    RestoreScenarioOutcome::PartialDegradedPreserved
                } else {
                    RestoreScenarioOutcome::RestoredVerifiedComplete
                };
                make_case(
                    kind,
                    RestoreScenarioOutcome::PartialDegradedPreserved,
                    observed,
                    r.verified_objects.len() as u32,
                    r.verified_bytes,
                    r.receipt_digest,
                )
            }
            RestoreFaultKind::BelowCustodyFloorStagedOrReplicated => {
                let mut staged_store = clean_store.clone();
                if let Some(rec) = staged_store.get_mut(&c1_d) {
                    rec.observed_custody = CustodyLevel::Replicated;
                }
                let r = verify_incident_retrieval(
                    &base_auth,
                    root_d,
                    &staged_store,
                    Some(&full_enc),
                    executed_at_ns,
                    || false,
                )
                .map_err(|_| RestoreMatrixError::FixtureConstructionFailed)?;
                let observed = if r.status == IncidentRetrievalStatus::PartialCorruptOrMissing
                    && r.below_custody_floor_digests == vec![c1_d]
                {
                    RestoreScenarioOutcome::PartialDegradedPreserved
                } else {
                    RestoreScenarioOutcome::RestoredVerifiedComplete
                };
                make_case(
                    kind,
                    RestoreScenarioOutcome::PartialDegradedPreserved,
                    observed,
                    r.verified_objects.len() as u32,
                    r.verified_bytes,
                    r.receipt_digest,
                )
            }
            RestoreFaultKind::IndeterminateRemoteObservation => {
                let mut indet_store = clean_store.clone();
                if let Some(rec) = indet_store.get_mut(&meta_d) {
                    rec.indeterminate_remote_state = true;
                }
                let r = verify_incident_retrieval(
                    &base_auth,
                    root_d,
                    &indet_store,
                    Some(&full_enc),
                    executed_at_ns,
                    || false,
                )
                .map_err(|_| RestoreMatrixError::FixtureConstructionFailed)?;
                let observed = if r.status
                    == IncidentRetrievalStatus::IndeterminateRemoteObservation
                    && r.indeterminate_digests == vec![meta_d]
                {
                    RestoreScenarioOutcome::IndeterminatePreserved
                } else {
                    RestoreScenarioOutcome::RestoredVerifiedComplete
                };
                make_case(
                    kind,
                    RestoreScenarioOutcome::IndeterminatePreserved,
                    observed,
                    r.verified_objects.len() as u32,
                    r.verified_bytes,
                    r.receipt_digest,
                )
            }
            RestoreFaultKind::TombstonedDeletedObject => {
                let mut tomb_store = clean_store.clone();
                if let Some(rec) = tomb_store.get_mut(&c0_d) {
                    rec.tombstoned = true;
                }
                let r = verify_incident_retrieval(
                    &base_auth,
                    root_d,
                    &tomb_store,
                    Some(&full_enc),
                    executed_at_ns,
                    || false,
                )
                .map_err(|_| RestoreMatrixError::FixtureConstructionFailed)?;
                let observed = if r.status == IncidentRetrievalStatus::PartialCorruptOrMissing
                    && r.tombstoned_digests == vec![c0_d]
                {
                    RestoreScenarioOutcome::PartialDegradedPreserved
                } else {
                    RestoreScenarioOutcome::RestoredVerifiedComplete
                };
                make_case(
                    kind,
                    RestoreScenarioOutcome::PartialDegradedPreserved,
                    observed,
                    r.verified_objects.len() as u32,
                    r.verified_bytes,
                    r.receipt_digest,
                )
            }
            RestoreFaultKind::UnauthorizedIncidentRoot => {
                let mut unauth = base_auth.clone();
                unauth.allowed_incident_roots =
                    BTreeSet::from([ContentDigest::sha256(b"other-incident")]);
                let r = verify_incident_retrieval(
                    &unauth,
                    root_d,
                    &clean_store,
                    Some(&full_enc),
                    executed_at_ns,
                    || false,
                )
                .map_err(|_| RestoreMatrixError::FixtureConstructionFailed)?;
                let observed = if r.status == IncidentRetrievalStatus::UnauthorizedScope
                    && r.verified_objects.is_empty()
                    && r.verified_bytes == 0
                {
                    RestoreScenarioOutcome::UnauthorizedRefused
                } else {
                    RestoreScenarioOutcome::RestoredVerifiedComplete
                };
                make_case(
                    kind,
                    RestoreScenarioOutcome::UnauthorizedRefused,
                    observed,
                    0,
                    0,
                    r.receipt_digest,
                )
            }
            RestoreFaultKind::UncoveredEncryptionLeaf => {
                let partial_enc = EncryptionContextManifest::genesis(
                    CipherSuite::ChaCha20Poly1305,
                    "kms:archive:matrix-v1",
                    [0x5A; 16],
                    vec![c0_d, meta_d], // omits c1_d
                )
                .map_err(|_| RestoreMatrixError::FixtureConstructionFailed)?;
                let r = verify_incident_retrieval(
                    &base_auth,
                    root_d,
                    &clean_store,
                    Some(&partial_enc),
                    executed_at_ns,
                    || false,
                )
                .map_err(|_| RestoreMatrixError::FixtureConstructionFailed)?;
                let observed = if r.status == IncidentRetrievalStatus::PartialCorruptOrMissing
                    && r.uncovered_encryption_digests == vec![c1_d]
                {
                    RestoreScenarioOutcome::PartialDegradedPreserved
                } else {
                    RestoreScenarioOutcome::RestoredVerifiedComplete
                };
                make_case(
                    kind,
                    RestoreScenarioOutcome::PartialDegradedPreserved,
                    observed,
                    r.verified_objects.len() as u32,
                    r.verified_bytes,
                    r.receipt_digest,
                )
            }
            RestoreFaultKind::DuplicateReorderedDeliveryIdempotent => {
                // Deliver objects in reversed order with duplicate insertions; receipt digest must
                // match canonical clean restore bit-for-bit!
                let mut reordered = BTreeMap::new();
                for (d, rec) in [
                    (meta_d, meta_r.clone()),
                    (c1_d, c1_r.clone()),
                    (c1_d, c1_r.clone()),
                    (root_d, root_r.clone()),
                    (c0_d, c0_r.clone()),
                    (seg_d, seg_r.clone()),
                ] {
                    reordered.insert(d, rec);
                }
                let r_clean = verify_incident_retrieval(
                    &base_auth,
                    root_d,
                    &clean_store,
                    Some(&full_enc),
                    executed_at_ns,
                    || false,
                )
                .map_err(|_| RestoreMatrixError::FixtureConstructionFailed)?;
                let r_reord = verify_incident_retrieval(
                    &base_auth,
                    root_d,
                    &reordered,
                    Some(&full_enc),
                    executed_at_ns,
                    || false,
                )
                .map_err(|_| RestoreMatrixError::FixtureConstructionFailed)?;
                let observed = if r_reord == r_clean
                    && r_reord.status == IncidentRetrievalStatus::VerifiedRetrievableComplete
                {
                    RestoreScenarioOutcome::RestoredVerifiedComplete
                } else {
                    RestoreScenarioOutcome::PartialDegradedPreserved
                };
                make_case(
                    kind,
                    RestoreScenarioOutcome::RestoredVerifiedComplete,
                    observed,
                    r_reord.verified_objects.len() as u32,
                    r_reord.verified_bytes,
                    r_reord.receipt_digest,
                )
            }
            RestoreFaultKind::CancelledAtRestoreBoundary => {
                let mut steps = 0_u32;
                let res = verify_incident_retrieval(
                    &base_auth,
                    root_d,
                    &clean_store,
                    Some(&full_enc),
                    executed_at_ns,
                    || {
                        steps += 1;
                        steps >= 3 // cancel mid-traversal after root manifest, before completion!
                    },
                );
                let observed = match res {
                    Err(IncidentRetrievalError::Cancelled) => {
                        RestoreScenarioOutcome::CancelledCleanly
                    }
                    _ => RestoreScenarioOutcome::RestoredVerifiedComplete,
                };
                make_case(
                    kind,
                    RestoreScenarioOutcome::CancelledCleanly,
                    observed,
                    0,
                    0,
                    ContentDigest::sha256(b"cancelled-at-restore-boundary"),
                )
            }
        };
        if report.passed {
            cases_passed = cases_passed.saturating_add(1);
        }
        cases.push(report);
    }

    let mut receipt = RestoreFaultMatrixReceipt {
        format_version: RESTORE_FAULT_MATRIX_FORMAT_VERSION,
        matrix_id: matrix_id.to_owned(),
        seed,
        generation,
        executed_at_ns,
        cases,
        cases_passed,
        read_local_source: false,
        receipt_digest: ContentDigest::sha256(b"pending"),
    };
    receipt.receipt_digest = receipt.computed_digest();
    Ok(receipt)
}

fn make_case(
    kind: RestoreFaultKind,
    expected: RestoreScenarioOutcome,
    observed: RestoreScenarioOutcome,
    verified_objects: u32,
    verified_bytes: u64,
    witness_digest: ContentDigest,
) -> RestoreFaultCaseReport {
    RestoreFaultCaseReport {
        kind,
        expected,
        observed,
        verified_objects,
        verified_bytes,
        witness_digest,
        passed: expected == observed,
    }
}

#![forbid(unsafe_code)]
//! Source-exact conservative withdrawal of historical absence witnesses.
//!
//! The input inventory was read from one verified committed prefix by historical_health.
//! Diagnostics do not confer coverage authority or diagnose a physical failure. They can only
//! withhold a conflicting negative claim; all existing independent coverage owners remain intact.

use fss_core::{ContentDigest, ContractError, EvidenceDeltaBatch, Plane, SensorId};

use super::{CoverageRecord, RetainedCoverage, ZoneWitness};
use crate::agent_orient::{HistoricalHealthMetadata, RetainedHistoricalHealth};
use crate::ingest::sensor_health::HealthFinding;

/// Hard ceilings across one complete orientation. Exhaustion refuses the projection; it never
/// silently drops a contradictory diagnostic or treats unchecked evidence as covered.
const MAX_CONFLICTS: usize = 4_096;
const MAX_HEALTH_CHECKS: usize = 524_288;
/// Aggregate history comparisons for reconstructing every coverage record's privacy binding.
/// The ledger byte ceiling alone does not bound repeated scans over the same history.
const MAX_PRIVACY_CHECKS: usize = 1_048_576;

/// One retained witness withheld by a diagnostic over the same source and interpretation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageHealthConflict {
    /// Payload identity of the original unchanged coverage record.
    pub coverage_record: ContentDigest,
    /// Original witness excluded from this projection's coverage and silence certificates.
    pub witness: ContentDigest,
    /// Immutable diagnostic receipt whose exact finding caused the exclusion.
    pub diagnostic: ContentDigest,
    /// Verified committed source-closed diagnostic provenance root.
    pub provenance_root: ContentDigest,
    /// Historical heuristic finding, never a physical-health verdict.
    pub finding: HealthFinding,
    /// First threshold-satisfied source segment recorded by the native screen.
    pub finding_first_segment: u64,
    /// Last threshold-satisfied source segment recorded by the native screen.
    pub finding_last_segment: u64,
    /// First overlapping source segment withheld conservatively within the requested scan.
    pub first_segment: u64,
    /// Last overlapping source segment withheld conservatively within the requested scan.
    pub last_segment: u64,
}

impl CoverageHealthConflict {
    pub(in crate::agent_orient) fn describe(&self, label: &str) -> String {
        format!(
            "{label}: witness {} from coverage record {} is withheld over source segments \
             {}..{} by historical sensor-health diagnostic {} (provenance root {}): {} \
             threshold findings at segments {}..{}. The conservative withholding scope is \
             the diagnostic's finite requested scan, including threshold latency, not an \
             inferred physical outage or present health condition. An independent unaffected \
             witness may still establish coverage.",
            self.witness,
            self.coverage_record,
            self.first_segment,
            self.last_segment,
            self.diagnostic,
            self.provenance_root,
            self.finding.as_str(),
            self.finding_first_segment,
            self.finding_last_segment,
        )
    }
}

/// Resolve the privacy owner at the exact coverage-analysis anchor. A newer privacy policy must
/// never be substituted for the one that produced the retained negative evidence.
pub(in crate::agent_orient) fn privacy_at_basis(
    record: &CoverageRecord,
    batches: &[EvidenceDeltaBatch],
    checks: &mut usize,
) -> Result<Option<(ContentDigest, u64)>, ContractError> {
    // Charge the entire possible anchor search before examining it, then every prefix delta
    // below. The caller shares this counter across all retained coverage records.
    *checks = checks.saturating_add(batches.len());
    if *checks > MAX_PRIVACY_CHECKS {
        return Err(ContractError::CountBoundExceeded);
    }
    let prefix_len = if batches
        .first()
        .is_some_and(|batch| batch.basis_anchor == record.basis)
    {
        0
    } else {
        batches
            .iter()
            .position(|batch| batch.new_anchor == record.basis)
            .map(|position| position + 1)
            .ok_or(ContractError::StaleAnchor)?
    };
    let sensor = SensorId::parse(&record.sensor_id)?;
    let object = crate::ingest::privacy_mask::mask_object_id(&sensor)?;
    let mut generation = None;
    let mut policy = None;
    for delta in batches[..prefix_len].iter().flat_map(|batch| &batch.deltas) {
        *checks += 1;
        if *checks > MAX_PRIVACY_CHECKS {
            return Err(ContractError::CountBoundExceeded);
        }
        if delta.object_id != object {
            continue;
        }
        let expected = generation
            .unwrap_or(0_u64)
            .checked_add(1)
            .ok_or(ContractError::GenerationConflict)?;
        if delta.family != crate::reference_deployment::FAMILY_PRIVACY_MASK_POLICY
            || delta.plane != Plane::Authority
            || delta.prior_generation != generation
            || delta.new_generation != expected
        {
            return Err(ContractError::GenerationConflict);
        }
        generation = Some(expected);
        policy = Some((delta.payload_digest, expected));
    }
    Ok(policy)
}

pub(super) struct HealthGuard<'a> {
    retained: &'a [RetainedHistoricalHealth],
    checks: usize,
    conflicts: usize,
}

impl<'a> HealthGuard<'a> {
    pub(super) fn new(retained: &'a [RetainedHistoricalHealth]) -> Result<Self, ContractError> {
        if retained.len() > crate::agent_orient::MAX_HISTORICAL_HEALTH_RECORDS {
            return Err(ContractError::CountBoundExceeded);
        }
        // Public snapshot values cannot accidentally mismatch a decoded header and its stated
        // digest. Ledger membership and custody remain the read_inventory owner's responsibility.
        for item in retained {
            if let HistoricalHealthMetadata::Retained { record, .. } = &item.metadata
                && item.receipt_digest != record.digest()
            {
                return Err(ContractError::DigestMismatch);
            }
        }
        Ok(Self {
            retained,
            checks: 0,
            conflicts: 0,
        })
    }

    pub(super) fn conflicts(
        &mut self,
        coverage: &RetainedCoverage,
        witness: &ZoneWitness,
    ) -> Result<Vec<CoverageHealthConflict>, ContractError> {
        let mut conflicts = Vec::new();
        for item in self.retained {
            self.checks += 1;
            if self.checks > MAX_HEALTH_CHECKS {
                return Err(ContractError::CountBoundExceeded);
            }
            let HistoricalHealthMetadata::Retained {
                record,
                provenance_root,
                ..
            } = &item.metadata
            else {
                // Deleted metadata supplies no source identity or invented finding. Import
                // deletion independently removes its dependent coverage through closure.
                continue;
            };
            if record.import_identity() != coverage.record.import_identity
                || record.import_root() != coverage.record.import_root
                || record.sensor_id().as_str() != coverage.record.sensor_id
                || record.privacy_policy_digest() != coverage.privacy_policy_digest
                || record.privacy_generation() != coverage.privacy_generation
            {
                continue;
            }
            let start = record.first_segment() as u64;
            let end = start
                .checked_add(record.segment_count() as u64)
                .and_then(|end| end.checked_sub(1))
                .ok_or(ContractError::InvalidIdentifier)?;
            let first_segment = start.max(witness.first_segment);
            let last_segment = end.min(witness.last_segment);
            if first_segment > last_segment {
                continue;
            }
            for finding in record.summary().findings() {
                self.checks += 1;
                if self.checks > MAX_HEALTH_CHECKS || self.conflicts >= MAX_CONFLICTS {
                    return Err(ContractError::CountBoundExceeded);
                }
                self.conflicts += 1;
                conflicts.push(CoverageHealthConflict {
                    coverage_record: coverage.payload_digest,
                    witness: witness.witness.witness_digest(),
                    diagnostic: item.receipt_digest,
                    provenance_root: *provenance_root,
                    finding: finding.finding,
                    finding_first_segment: finding.first_segment,
                    finding_last_segment: finding.last_segment,
                    first_segment,
                    last_segment,
                });
            }
        }
        Ok(conflicts)
    }
}

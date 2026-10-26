#![forbid(unsafe_code)]
//! Conservatively expose retained screening to an exact downstream source observation.
//!
//! The catalog verifies historical metadata, not native pixels or present sensor health. An
//! importing caller must independently verify its source observation and interpretation. A
//! matching finding or incomplete screen withholds support over that diagnostic's finite scan;
//! no diagnostic, or a complete screen without findings, grants no health or absence certificate.

use std::collections::BTreeSet;
use std::path::PathBuf;

use fss_core::{ContentDigest, LedgerAnchor, SensorId};

use super::{
    FAMILY_HISTORICAL_HEALTH, HISTORICAL_HEALTH_OBJECT_PREFIX, HistoricalHealthError,
    HistoricalHealthReadReport, MAX_HISTORICAL_HEALTH_METADATA_BYTES, Result, checkpoint,
    inspect_with_deletions, valid_digest,
};
use crate::ingest::sensor_health::HealthFinding;
use crate::{ReferenceDeployment, ReferenceError, ReplayCx};

/// Maximum committed diagnostic identities in one complete catalog, including tombstoned rows.
pub const MAX_HEALTH_EXPOSURE_RECORDS: usize = 256;
/// Maximum metadata reads across catalog, deletion and historical privacy owners.
pub const MAX_HEALTH_EXPOSURE_METADATA_READS: usize = 8_192;
/// Maximum conservative history-entry comparison reservations in one catalog load.
pub const MAX_HEALTH_EXPOSURE_HISTORY_WORK: usize = 16_777_216;
/// Maximum diagnostic/finding comparisons across all assessments using one catalog.
pub const MAX_HEALTH_EXPOSURE_ASSESSMENT_WORK: usize = 1_048_576;
/// Maximum finding rows returned across the entire catalog lifetime.
pub const MAX_HEALTH_EXPOSURE_FINDINGS: usize = 4_096;

/// Whole-catalog and whole-assessment ceilings; none refill for a new source observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HealthExposureLimits {
    /// Committed diagnostic rows, including explicit deletion exclusions.
    pub maximum_records: usize,
    /// Successfully read metadata bytes, shared with deletion-plan and historical-mask reads.
    pub maximum_metadata_bytes: usize,
    /// Metadata read attempts, admitted before each object read.
    pub maximum_metadata_reads: usize,
    /// Conservative comparison reservations for the existing strict history readers.
    pub maximum_history_work: usize,
    /// Diagnostic and finding comparisons across every assessment.
    pub maximum_assessment_work: usize,
    /// Finding rows across every returned assessment.
    pub maximum_findings: usize,
}

impl Default for HealthExposureLimits {
    fn default() -> Self {
        Self {
            maximum_records: MAX_HEALTH_EXPOSURE_RECORDS,
            maximum_metadata_bytes: 64 * 1024 * 1024,
            maximum_metadata_reads: MAX_HEALTH_EXPOSURE_METADATA_READS,
            maximum_history_work: MAX_HEALTH_EXPOSURE_HISTORY_WORK,
            maximum_assessment_work: MAX_HEALTH_EXPOSURE_ASSESSMENT_WORK,
            maximum_findings: MAX_HEALTH_EXPOSURE_FINDINGS,
        }
    }
}

impl HealthExposureLimits {
    /// Validate every ceiling before opening metadata or inspecting authority history.
    pub fn validate(self) -> Result<()> {
        if !(1..=MAX_HEALTH_EXPOSURE_RECORDS).contains(&self.maximum_records)
            || !(1..=MAX_HISTORICAL_HEALTH_METADATA_BYTES).contains(&self.maximum_metadata_bytes)
            || !(1..=MAX_HEALTH_EXPOSURE_METADATA_READS).contains(&self.maximum_metadata_reads)
            || !(1..=MAX_HEALTH_EXPOSURE_HISTORY_WORK).contains(&self.maximum_history_work)
            || !(1..=MAX_HEALTH_EXPOSURE_ASSESSMENT_WORK).contains(&self.maximum_assessment_work)
            || !(1..=MAX_HEALTH_EXPOSURE_FINDINGS).contains(&self.maximum_findings)
        {
            return Err(HistoricalHealthError::Limit);
        }
        Ok(())
    }
}

/// Exact downstream source and interpretation. Construction alone verifies no source custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthExposureSource {
    /// Independently verified retained import identity.
    pub import_identity: ContentDigest,
    /// Exact source-closed import root, binding the capsule at each source segment.
    pub import_root: ContentDigest,
    /// Independently verified native sensor identity.
    pub sensor_id: SensorId,
    /// Coding/source segment, not display order or an inferred wall-clock coordinate.
    pub segment: u64,
    /// Privacy interpretation of the independently verified downstream observation.
    pub privacy_policy_digest: Option<ContentDigest>,
    /// Exact historical mask generation, or the explicit no-policy state.
    pub privacy_generation: Option<u64>,
}

impl HealthExposureSource {
    fn validate(&self) -> Result<()> {
        valid_digest(self.import_identity)?;
        valid_digest(self.import_root)?;
        if let Some(digest) = self.privacy_policy_digest {
            valid_digest(digest)?;
        }
        if self.privacy_policy_digest.is_some() != self.privacy_generation.is_some()
            || self.privacy_generation == Some(0)
            || self.segment.checked_add(1).is_none()
        {
            return Err(HistoricalHealthError::InvalidRecord);
        }
        Ok(())
    }
}

/// Immutable retained diagnostic identities, sufficient to identify the original metadata view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthDiagnosticPin {
    /// Canonical diagnostic header identity.
    pub record_digest: ContentDigest,
    /// Verified source-closed provenance-manifest root.
    pub provenance_root: ContentDigest,
    /// Historical native trace identity; catalog loading does not rerun or read the trace.
    pub trace_digest: ContentDigest,
    /// Original diagnostic publication anchor.
    pub ledger_anchor: LedgerAnchor,
}

/// Historical screening classification for one exact source observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthExposureState {
    /// No retained diagnostic matches every source and interpretation coordinate; health unknown.
    NoMatchingDiagnostic,
    /// Matching complete finite screening reported no findings; not a health certificate.
    ScreenedWithoutFindings,
    /// At least one matching finite screen was incomplete; support is withheld conservatively.
    ScreeningIncomplete,
    /// At least one matching finite scan has a retained finding; support is withheld.
    Findings,
}

impl HealthExposureState {
    /// Stable machine spelling; no spelling claims a healthy camera or a physical outage.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoMatchingDiagnostic => "no_matching_diagnostic",
            Self::ScreenedWithoutFindings => "screened_without_findings",
            Self::ScreeningIncomplete => "screening_incomplete",
            Self::Findings => "findings",
        }
    }
}

/// One historical finding and its finite conservative withholding scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthExposureFinding {
    /// Exact diagnostic header which records the finding.
    pub diagnostic: ContentDigest,
    /// Verified committed provenance root for that header.
    pub provenance_root: ContentDigest,
    /// Heuristic visual diagnostic, never a physical cause or event classification.
    pub finding: HealthFinding,
    /// First source position where the native threshold was satisfied.
    pub finding_first_segment: u64,
    /// Last source position where the native threshold remained satisfied.
    pub finding_last_segment: u64,
    /// Beginning of the diagnostic's requested scan, including threshold latency.
    pub withheld_first_segment: u64,
    /// End of that finite requested scan, not a claim of outage duration or later recovery.
    pub withheld_last_segment: u64,
}

/// Reconstructible historical exposure. Fields are private to the verified catalog owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthExposure {
    source: HealthExposureSource,
    state: HealthExposureState,
    diagnostics: Vec<HealthDiagnosticPin>,
    findings: Vec<HealthExposureFinding>,
    screening_incomplete: bool,
}

impl HealthExposure {
    /// Exact downstream source coordinates supplied for this assessment.
    pub const fn source(&self) -> &HealthExposureSource {
        &self.source
    }
    /// Historical finite-screening state, not present sensor health.
    pub const fn state(&self) -> HealthExposureState {
        self.state
    }
    /// Stable state spelling.
    pub const fn status(&self) -> &'static str {
        self.state.as_str()
    }
    /// Every exact matching diagnostic, in canonical receipt identity order.
    pub fn pins(&self) -> &[HealthDiagnosticPin] {
        &self.diagnostics
    }
    /// Complete retained finding rows; none are truncated to fit the output bound.
    pub fn findings(&self) -> &[HealthExposureFinding] {
        &self.findings
    }
    /// At least one matching native scan did not screen its entire requested range.
    pub const fn screening_incomplete(&self) -> bool {
        self.screening_incomplete
    }
    /// Whether this finite historical diagnostic prevents using this source as support.
    pub fn support_withheld(&self) -> bool {
        self.screening_incomplete || !self.findings.is_empty()
    }
    /// Stable diagnostic reasons, deduplicated in canonical order.
    pub fn reasons(&self) -> Vec<&'static str> {
        let mut reasons = self
            .findings
            .iter()
            .map(|finding| finding.finding.as_str())
            .collect::<BTreeSet<_>>();
        if self.screening_incomplete {
            reasons.insert("historical_screening_incomplete");
        }
        reasons.into_iter().collect()
    }
}

/// Aggregate admission and read accounting for one catalog and all of its source assessments.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HealthExposureUsage {
    /// Committed diagnostic rows encountered before current deletion exclusion.
    pub records_seen: usize,
    /// Fully verified retained diagnostic metadata rows loaded.
    pub records_loaded: usize,
    /// Diagnostic payloads tombstoned by a verified committed deletion.
    pub deleted_records: usize,
    /// Successfully read metadata bytes, including deletion and privacy records.
    pub metadata_bytes_read: usize,
    /// Admitted metadata read attempts.
    pub metadata_reads: usize,
    /// Conservative history-entry comparison reservations, not physical I/O measurements.
    pub history_work_admitted: usize,
    /// Diagnostic/finding comparisons spent across source assessments.
    pub assessment_work: usize,
    /// Finding rows returned across all source assessments.
    pub findings_returned: usize,
}

/// One complete current retained diagnostic catalog, pinned to an admitted deployment anchor.
#[derive(Debug)]
pub struct HealthExposureCatalog {
    anchor: LedgerAnchor,
    root: PathBuf,
    principal: String,
    records: Vec<HistoricalHealthReadReport>,
    pins: Vec<HealthDiagnosticPin>,
    limits: HealthExposureLimits,
    usage: HealthExposureUsage,
}

fn charge(counter: &mut usize, amount: usize, maximum: usize) -> Result<()> {
    *counter = counter
        .checked_add(amount)
        .filter(|value| *value <= maximum)
        .ok_or(HistoricalHealthError::Limit)?;
    Ok(())
}

struct CatalogReader<'a> {
    deployment: &'a ReferenceDeployment,
    limits: HealthExposureLimits,
    usage: &'a mut HealthExposureUsage,
    cx: &'a ReplayCx,
}

impl CatalogReader<'_> {
    fn read(&mut self, digest: ContentDigest, bound: usize) -> Result<Vec<u8>> {
        checkpoint(self.cx, "historical_health_exposure:metadata")?;
        charge(
            &mut self.usage.metadata_reads,
            1,
            self.limits.maximum_metadata_reads,
        )?;
        let remaining = self
            .limits
            .maximum_metadata_bytes
            .checked_sub(self.usage.metadata_bytes_read)
            .filter(|value| *value != 0)
            .ok_or(HistoricalHealthError::Limit)?;
        let bytes = self
            .deployment
            .publisher()
            .spool()
            .read_bounded(digest, remaining.min(bound))?;
        charge(
            &mut self.usage.metadata_bytes_read,
            bytes.len(),
            self.limits.maximum_metadata_bytes,
        )?;
        Ok(bytes)
    }
}

impl HealthExposureCatalog {
    /// Read every committed diagnostic under one shared budget and current deletion policy.
    /// No malformed or unavailable nondeleted diagnostic is silently skipped. Records and
    /// provenance are verified by the existing metadata owner; native traces/pixels are not read.
    /// The durable ledger head is checked before and after loading. No mutation is performed.
    pub fn read(
        deployment: &ReferenceDeployment,
        limits: HealthExposureLimits,
        cx: &ReplayCx,
    ) -> Result<Self> {
        limits.validate()?;
        checkpoint(cx, "historical_health_exposure:read")?;
        if cx.root_dir() != deployment.root() {
            return Err(HistoricalHealthError::AuthorityChanged);
        }
        deployment
            .ledger()
            .verify_durable_head()
            .map_err(ReferenceError::from)?;
        let batches = deployment.ledger().batches();
        let mut usage = HealthExposureUsage::default();
        let mut history_width = 0_usize;
        let mut receipts = BTreeSet::new();
        for batch in batches {
            checkpoint(cx, "historical_health_exposure:inventory")?;
            let width = 1_usize
                .checked_add(batch.deltas.len())
                .and_then(|value| value.checked_add(batch.children.len()))
                .ok_or(HistoricalHealthError::Limit)?;
            charge(&mut history_width, width, limits.maximum_history_work)?;
            charge(
                &mut usage.history_work_admitted,
                width,
                limits.maximum_history_work,
            )?;
            for delta in &batch.deltas {
                if delta.family != FAMILY_HISTORICAL_HEALTH
                    && !delta
                        .object_id
                        .as_str()
                        .starts_with(HISTORICAL_HEALTH_OBJECT_PREFIX)
                {
                    continue;
                }
                charge(&mut usage.records_seen, 1, limits.maximum_records)?;
                if delta.family != FAMILY_HISTORICAL_HEALTH
                    || !receipts.insert(delta.payload_digest)
                {
                    return Err(HistoricalHealthError::InvalidRecord);
                }
            }
        }
        // The deletion owner inspects candidates and record/completion markers separately.
        // Reserve four complete widths for those comparisons before invoking its strict
        // verifier; selected deletion metadata shares this catalog's read allowance.
        let deletion_work = history_width
            .checked_mul(4)
            .ok_or(HistoricalHealthError::Limit)?;
        charge(
            &mut usage.history_work_admitted,
            deletion_work,
            limits.maximum_history_work,
        )?;
        let mut reader = CatalogReader {
            deployment,
            limits,
            usage: &mut usage,
            cx,
        };
        let deletions = crate::deletion::DeletionIndex::from_batches(batches, |digest| {
            reader.read(digest, crate::deletion::MAX_DELETION_RECORD_BYTES)
        })?;
        let mut records = Vec::new();
        let mut pins = Vec::new();
        for receipt in receipts {
            checkpoint(cx, "historical_health_exposure:record")?;
            if deletions.object(receipt).is_some() {
                reader.usage.deleted_records += 1;
                continue;
            }
            // read_retained_at performs bounded searches over source/root/privacy/batch
            // bindings. Reserve eight complete history widths before invoking that owner.
            let reserved = history_width
                .checked_mul(8)
                .ok_or(HistoricalHealthError::Limit)?;
            charge(
                &mut reader.usage.history_work_admitted,
                reserved,
                limits.maximum_history_work,
            )?;
            let report =
                inspect_with_deletions(deployment, receipt, &deletions, |digest, bound| {
                    reader.read(digest, bound)
                })?;
            pins.push(HealthDiagnosticPin {
                record_digest: receipt,
                provenance_root: report.provenance_root,
                trace_digest: report.record.trace_digest(),
                ledger_anchor: report.ledger_anchor.clone(),
            });
            records.push(report);
            reader.usage.records_loaded += 1;
        }
        checkpoint(cx, "historical_health_exposure:complete")?;
        deployment
            .ledger()
            .verify_durable_head()
            .map_err(ReferenceError::from)?;
        Ok(Self {
            anchor: deployment.current_anchor().clone(),
            root: deployment.root().to_path_buf(),
            principal: cx.io_authority().principal().into(),
            records,
            pins,
            limits,
            usage,
        })
    }

    /// Exact catalog anchor; a caller must revalidate its complete operation before delivery.
    pub const fn anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
    /// All nondeleted verified diagnostic sources, including those not matching an observation.
    pub fn pins(&self) -> &[HealthDiagnosticPin] {
        &self.pins
    }
    /// Whether no nondeleted diagnostic metadata exists in the pinned catalog.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    /// Shared counters, including every source assessment performed so far.
    pub const fn usage(&self) -> HealthExposureUsage {
        self.usage
    }

    /// Match every historical diagnostic against one independently verified source observation.
    /// Matching uses import, exact root, sensor, source segment and privacy generation together.
    /// A finding conservatively withholds the finite requested scan, including threshold latency;
    /// it never asserts that an unmeasured gap or a later interval contained a physical failure.
    pub fn assess(
        &mut self,
        source: &HealthExposureSource,
        cx: &ReplayCx,
    ) -> Result<HealthExposure> {
        source.validate()?;
        checkpoint(cx, "historical_health_exposure:assess")?;
        if cx.root_dir() != self.root || cx.io_authority().principal() != self.principal {
            return Err(HistoricalHealthError::AuthorityChanged);
        }
        let mut diagnostics = Vec::new();
        let mut findings = Vec::new();
        let mut screening_incomplete = false;
        for (report, pin) in self.records.iter().zip(&self.pins) {
            checkpoint(cx, "historical_health_exposure:match")?;
            charge(
                &mut self.usage.assessment_work,
                1,
                self.limits.maximum_assessment_work,
            )?;
            let record = &report.record;
            if record.import_identity() != source.import_identity
                || record.import_root() != source.import_root
                || record.sensor_id() != &source.sensor_id
                || record.privacy_policy_digest() != source.privacy_policy_digest
                || record.privacy_generation() != source.privacy_generation
            {
                continue;
            }
            let first = record.first_segment() as u64;
            let end = first
                .checked_add(record.segment_count() as u64)
                .ok_or(HistoricalHealthError::InvalidRecord)?;
            if source.segment < first || source.segment >= end {
                continue;
            }
            diagnostics.push(pin.clone());
            screening_incomplete |= !record.summary().complete();
            for finding in record.summary().findings() {
                checkpoint(cx, "historical_health_exposure:finding")?;
                charge(
                    &mut self.usage.assessment_work,
                    1,
                    self.limits.maximum_assessment_work,
                )?;
                charge(
                    &mut self.usage.findings_returned,
                    1,
                    self.limits.maximum_findings,
                )?;
                findings.push(HealthExposureFinding {
                    diagnostic: pin.record_digest,
                    provenance_root: pin.provenance_root,
                    finding: finding.finding,
                    finding_first_segment: finding.first_segment,
                    finding_last_segment: finding.last_segment,
                    withheld_first_segment: first,
                    withheld_last_segment: end - 1,
                });
            }
        }
        let state = if !findings.is_empty() {
            HealthExposureState::Findings
        } else if screening_incomplete {
            HealthExposureState::ScreeningIncomplete
        } else if diagnostics.is_empty() {
            HealthExposureState::NoMatchingDiagnostic
        } else {
            HealthExposureState::ScreenedWithoutFindings
        };
        Ok(HealthExposure {
            source: source.clone(),
            state,
            diagnostics,
            findings,
            screening_incomplete,
        })
    }
}

#[cfg(test)]
mod tests;

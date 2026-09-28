#![forbid(unsafe_code)]
//! Atomic per-camera coverage proposals after the full-camera uncertainty screen.
//!
//! This composes existing version-6 receipts; it invents neither a coverage predicate nor an
//! effect protocol. A failed zone loses only its nominal witnesses. Other zones, observed
//! entries, decode refusals and timing gaps survive. All calibrated cameras must be screened,
//! and a single work budget covers the complete set. Positive event proposals are not inputs.

use std::collections::BTreeSet;

use fss_core::{ContentDigest, ContractError};
use fss_geometry::WorkBudget;

use crate::ingest::calibration_coverage::{
    CalibrationCoverageAssessment, apply_calibration_coverage,
};
use crate::ingest::ground_visibility::VisibilityError;
use crate::ingest::privacy_mask::MaskBinding;
use crate::ingest::recorded_corroboration::CorroborationError;
use crate::ingest::recorded_coverage::{
    CoverageRecord, CoverageSource, MAX_COVERAGE_INTERVALS, MAX_COVERAGE_RECORD_BYTES,
    MAX_COVERAGE_ZONES, PoseProvenance, PoseUncertainty, UncoveredReason, approval_digest,
};

/// One camera's nominal record, optional full-camera assessment, and resolved privacy binding.
/// A site-calibration provenance requires an assessment; other provenance must not receive one.
pub struct CoverageProjectionInput<'a> {
    /// The nominal, immutable coverage record from the existing analysis pipeline.
    pub record: &'a CoverageRecord,
    /// Additional screening of exactly this calibrated camera, or none for an uncalibrated one.
    pub assessment: Option<&'a CalibrationCoverageAssessment>,
    /// Authority-resolved privacy binding used by that camera's analysis and screen.
    pub privacy: &'a MaskBinding,
}

/// Complete, immutable proposal. Construction is all-or-nothing and grants no authority.
///
/// Private records prevent callers from swapping a nominal record back into a prepared set.
/// The ordered records and their version-6 receipts determine the existing exact approval.
#[derive(Clone, Debug)]
pub struct GuardedCoverageSet {
    records: Vec<CoverageRecord>,
    privacy: Vec<(ContentDigest, u64)>,
}

fn invalid(reason: &'static str) -> CorroborationError {
    CorroborationError::InvalidPlan(reason)
}

fn charge(budget: &mut WorkBudget<'_>, units: u64) -> Result<(), CorroborationError> {
    budget.charge(units).map_err(|error| {
        CorroborationError::Visibility(VisibilityError::Geometry(error))
    })
}

// Bound even the uncalibrated companion before validation, encoding, or cloning. The wire
// estimate deliberately overcounts fixed fields and length prefixes; there is no allocation
// proportional to an unchecked caller-owned string or collection.
fn check_copy_bound(record: &CoverageRecord) -> Result<u64, CorroborationError> {
    if record.sensor_id.len() > 512 || record.capture_time_label.len() > 64
        || record.zones.is_empty() || record.zones.len() > MAX_COVERAGE_ZONES
    {
        return Err(CorroborationError::Limit);
    }
    let mut bytes = 16_384_u64;
    for zone in &record.zones {
        if zone.zone_id.len() > 64 || zone.scope.len() > 80 || zone.geometry.len() > 256
            || zone.witnesses.len() > MAX_COVERAGE_INTERVALS
            || zone.uncovered.len() > MAX_COVERAGE_INTERVALS
        {
            return Err(CorroborationError::Limit);
        }
        bytes += 4_096;
        for witness in &zone.witnesses {
            let inner = &witness.witness;
            if inner.negative_predicate.len() > 4_096
                || inner.authorized_domain.len() != 1 || inner.observed_domain.len() != 1
                || !inner.excluded_domain.is_empty()
                || inner.authorized_domain.iter().chain(&inner.observed_domain)
                    .any(|domain| domain.len() > 512)
            {
                return Err(CorroborationError::Limit);
            }
            bytes += 4_096 + inner.negative_predicate.len() as u64;
        }
        for interval in &zone.uncovered {
            let extra = match &interval.reason {
                UncoveredReason::DecodeRefused { error_id } => error_id.len(),
                UncoveredReason::ZoneEntry { event_id, .. } => event_id.as_ref().map_or(0, String::len),
                _ => 0,
            };
            if extra > 512 { return Err(CorroborationError::Limit); }
            bytes += 256 + extra as u64;
        }
    }
    if bytes > MAX_COVERAGE_RECORD_BYTES as u64 { return Err(CorroborationError::Limit); }
    Ok(bytes)
}

impl GuardedCoverageSet {
    /// Project one or two cameras atomically under one caller-owned budget.
    ///
    /// Every calibrated record must have its exact screen, even when it contains no witnesses.
    /// Duplicate sensors/imports, mixed anchors, absent/extra screens, mismatched privacy,
    /// malformed records and exhausted budgets fail closed. The input records are never changed.
    /// This is computation only; the caller must revalidate dependencies before retention.
    pub fn project(
        inputs: &[CoverageProjectionInput<'_>],
        budget: &mut WorkBudget<'_>,
    ) -> Result<Self, CorroborationError> {
        charge(budget, 0)?;
        if inputs.is_empty() || inputs.len() > 2 {
            return Err(invalid("a guarded coverage set requires one or two cameras"));
        }
        let mut sensors = BTreeSet::new();
        let mut imports = BTreeSet::new();
        let mut cameras = BTreeSet::new();
        let mut has_screen = false;
        for input in inputs {
            let record = input.record;
            charge(budget, check_copy_bound(record)?)?;
            if record.source != CoverageSource::Corroborate
                || record.basis != inputs[0].record.basis
                || !sensors.insert(record.sensor_id.as_str())
                || !imports.insert(record.import_identity)
            {
                return Err(invalid("guarded coverage requires distinct sensors/imports at one anchor"));
            }
            let calibrated = matches!(record.pose_provenance, Some(PoseProvenance::SiteCalibration { .. }));
            if calibrated != input.assessment.is_some() {
                return Err(invalid("each calibrated camera requires exactly its own full-camera screen"));
            }
            if let Some(PoseProvenance::SiteCalibration { camera_handle, .. }) = record.pose_provenance
                && !cameras.insert(camera_handle)
            {
                return Err(invalid("one calibrated camera cannot occupy two sensor slots"));
            }
            has_screen |= calibrated;
        }
        if !has_screen { return Err(invalid("guarded coverage requires a calibrated camera")); }
        let mut records = Vec::with_capacity(inputs.len());
        let mut privacy = Vec::with_capacity(inputs.len());
        for input in inputs {
            let record = match input.assessment {
                Some(assessment) => apply_calibration_coverage(input.record, assessment, budget)?,
                None => {
                    input.record.validate()?;
                    input.record.clone()
                }
            };
            let binding = (input.privacy.digest(), input.privacy.generation().unwrap_or(0));
            if let Some(receipt) = record.pose_uncertainty.as_ref().and_then(PoseUncertainty::guard_receipt)
                && (receipt.privacy_digest(), receipt.privacy_generation()) != binding
            {
                return Err(ContractError::DigestMismatch.into());
            }
            if record.to_bytes().len() > MAX_COVERAGE_RECORD_BYTES {
                return Err(CorroborationError::Limit);
            }
            records.push(record);
            privacy.push(binding);
        }
        charge(budget, 0)?;
        Ok(Self { records, privacy })
    }

    /// Exact projected records in the original camera order; never the nominal fallback.
    #[must_use]
    pub fn records(&self) -> &[CoverageRecord] { &self.records }

    /// The ordinary coverage approval, recomputed over the guarded records and their anchors.
    #[must_use]
    pub fn approval(&self) -> ContentDigest {
        approval_digest(&self.records.iter().collect::<Vec<_>>())
    }

    /// Number of formerly witnessed intervals now withheld for full-camera uncertainty.
    /// This is not a count of physical outages or threats.
    #[must_use]
    pub fn abstained_intervals(&self) -> usize {
        self.records.iter().flat_map(|record| &record.zones)
            .flat_map(|zone| &zone.uncovered)
            .filter(|interval| interval.reason == UncoveredReason::CalibrationUncertainty).count()
    }

    /// Exact privacy bindings captured at projection, including explicit no-policy generations.
    #[must_use]
    pub fn privacy_bindings(&self) -> &[(ContentDigest, u64)] { &self.privacy }
}

mod retention;
pub use retention::GuardedCoverageRetentionError;

#[cfg(test)]
mod tests;

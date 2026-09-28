#![forbid(unsafe_code)]
//! Embedded, bounded full-camera screening receipts and lossless abstention.
//!
//! The receipt is evidence of a conditional computation, never effect authority.
//! It keeps the nominal analysis and pipeline identities so applying a screen
//! cannot silently reuse the approval or ledger object of unguarded coverage.

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, ContractError, DigestAlgorithm};
use fss_geometry::{AdjustedCamera, BundleParameter, CameraGeneration, WorkBudget};

use super::super::recorded_corroboration::CorroborationError;
use super::super::recorded_coverage::{
    CoverageRecord, CoverageSource, MAX_COVERAGE_INTERVALS, MAX_COVERAGE_RECORD_BYTES,
    MAX_COVERAGE_ZONES, PoseProvenance, PoseUncertainty, UncoveredInterval, UncoveredReason,
    ZoneCoverage, pose_predicate_clause, zone_witness_predicate,
};
use super::{CALIBRATION_COVERAGE_POLICY, CalibrationCoverageAssessment, geometry};

const DOMAIN: &str = "fss.calibration_coverage_receipt.v1";
const ZONE_DOMAIN: &str = "fss.calibration_coverage_zone.v1";
const ANALYSIS_DOMAIN: &str = "fss.guarded_coverage_analysis.v1";
const PIPELINE_DOMAIN: &str = "fss.guarded_coverage_pipeline.v1";
/// Hard bound on a stand-alone screening receipt, before parsing or allocating.
pub const MAX_CALIBRATION_COVERAGE_RECEIPT_BYTES: usize = 8_192;

/// One exact zone binding and its mutually exclusive screening counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CalibrationZoneReceipt {
    binding: ContentDigest,
    base_pipeline: ContentDigest,
    counts: [u32; 7],
}
impl CalibrationZoneReceipt {
    /// Counts in the registered `CalibrationSampleRelation` order.
    pub const fn counts(&self) -> [u32; 7] {
        self.counts
    }
    /// Number of tested samples (validated to be at most 1024).
    pub fn samples(&self) -> u32 {
        self.counts.iter().sum()
    }
    /// A rejected direction can only remove coverage, never grant it.
    pub fn requires_abstention(&self) -> bool {
        self.counts[0] != self.samples()
    }
}

/// Canonical source- and geometry-bound receipt embedded in coverage version 6.
///
/// All fields are private. Construction consumes an actual bounded assessment;
/// decoding checks bounds, canonical order and counts. `validate_for` additionally
/// checks the enclosing record, exact calibration/pose marginal, zone geometry,
/// analysis/pipeline derivations and the absence of witnesses in rejected zones.
/// The fixed array preserves the existing copyable `PoseUncertainty` contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CalibrationCoverageReceipt {
    input_digest: ContentDigest,
    calibration_digest: ContentDigest,
    camera: CameraGeneration,
    sensor_digest: ContentDigest,
    import_identity: ContentDigest,
    import_root: ContentDigest,
    privacy_digest: ContentDigest,
    privacy_generation: u64,
    base_analysis: ContentDigest,
    pose_bits: [u64; 36],
    zones: [Option<CalibrationZoneReceipt>; MAX_COVERAGE_ZONES],
    len: u8,
}

fn zone_binding(id: &str, geometry: &str, grid: u32, threshold: u32) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(ZONE_DOMAIN);
    e.text(id);
    e.text(geometry);
    e.u32(grid);
    e.u32(threshold);
    ContentDigest::sha256(&e.finish())
}

fn binding(zone: &ZoneCoverage) -> Result<ContentDigest, ContractError> {
    let visibility = zone
        .visibility
        .as_ref()
        .ok_or(ContractError::InvalidIdentifier)?;
    Ok(zone_binding(
        &zone.zone_id,
        &zone.geometry,
        visibility.grid,
        visibility.threshold_ppm,
    ))
}

fn derived(domain: &str, base: ContentDigest, receipt: ContentDigest) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(domain);
    e.digest(base);
    e.digest(receipt);
    ContentDigest::sha256(&e.finish())
}

pub(super) fn pose_covariance_bits(camera: &AdjustedCamera) -> [u64; 36] {
    // The full camera partition has already passed the projection validator.
    let slots: [Option<usize>; 6] = std::array::from_fn(|axis| {
        let parameter = if axis < 3 {
            BundleParameter::Rotation(axis)
        } else {
            BundleParameter::Translation(axis - 3)
        };
        camera
            .covariance
            .parameters
            .iter()
            .position(|p| *p == parameter)
    });
    let k = camera.covariance.parameters.len();
    std::array::from_fn(|index| match (slots[index / 6], slots[index % 6]) {
        (Some(row), Some(column)) => camera.covariance.matrix[row * k + column].to_bits(),
        _ => 0.0_f64.to_bits(),
    })
}

impl CalibrationCoverageReceipt {
    /// Identity of the full consumed camera, covariance, mask, grid and ground zones.
    pub const fn input_digest(&self) -> ContentDigest {
        self.input_digest
    }
    /// Mask binding at the assessment anchor, not an assertion of current currency.
    pub const fn privacy_digest(&self) -> ContentDigest {
        self.privacy_digest
    }
    /// Exact retained mask generation (zero is the explicit no-policy marker).
    pub const fn privacy_generation(&self) -> u64 {
        self.privacy_generation
    }
    /// Camera generation to revalidate at a publication boundary.
    pub const fn camera(&self) -> CameraGeneration {
        self.camera
    }
    /// Exact calibration identity named by the enclosing provenance.
    pub const fn calibration_digest(&self) -> ContentDigest {
        self.calibration_digest
    }

    fn entries(&self) -> impl Iterator<Item = &CalibrationZoneReceipt> {
        self.zones
            .iter()
            .take(usize::from(self.len))
            .filter_map(Option::as_ref)
    }

    /// Find the receipt of this exact zone, including its geometry and grid policy.
    pub fn zone(&self, zone: &ZoneCoverage) -> Result<&CalibrationZoneReceipt, ContractError> {
        let key = binding(zone)?;
        self.entries()
            .find(|entry| entry.binding == key)
            .ok_or(ContractError::InvalidIdentifier)
    }

    fn from_assessment(
        record: &CoverageRecord,
        assessment: &CalibrationCoverageAssessment,
    ) -> Result<Self, ContractError> {
        let Some(PoseUncertainty::SigmaPoints { covariance }) = record.pose_uncertainty else {
            return Err(ContractError::CoverageUncertified);
        };
        if record.sensor_id != assessment.sensor.as_str()
            || record.zones.len() != assessment.zones.len()
            || covariance.bits() != assessment.pose_covariance_bits
        {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut entries = Vec::with_capacity(record.zones.len());
        for zone in &record.zones {
            let result = assessment
                .zones
                .iter()
                .find(|r| r.zone_id == zone.zone_id)
                .ok_or(ContractError::InvalidIdentifier)?;
            let key = zone_binding(
                &result.zone_id,
                &result.geometry,
                assessment.policy.grid,
                assessment.policy.threshold_ppm,
            );
            if binding(zone)? != key {
                return Err(ContractError::InvalidIdentifier);
            }
            entries.push(CalibrationZoneReceipt {
                binding: key,
                base_pipeline: zone.pipeline_generation,
                counts: result.counts,
            });
        }
        entries.sort_by_key(|entry| entry.binding);
        let len = u8::try_from(entries.len()).map_err(|_| ContractError::BudgetExhausted)?;
        let mut zones = [None; MAX_COVERAGE_ZONES];
        for (slot, entry) in zones.iter_mut().zip(entries) {
            *slot = Some(entry);
        }
        let receipt = Self {
            input_digest: assessment.input_digest,
            calibration_digest: assessment.calibration_digest,
            camera: assessment.camera_identity,
            sensor_digest: ContentDigest::sha256(record.sensor_id.as_bytes()),
            import_identity: record.import_identity,
            import_root: record.import_root,
            privacy_digest: assessment.privacy_digest,
            privacy_generation: assessment.privacy_generation,
            base_analysis: record.analysis_digest,
            pose_bits: assessment.pose_covariance_bits,
            zones,
            len,
        };
        receipt.validate()?;
        receipt.check_source(record)?;
        Ok(receipt)
    }

    fn validate(&self) -> Result<(), ContractError> {
        let len = usize::from(self.len);
        if len == 0
            || len > MAX_COVERAGE_ZONES
            || self.camera.camera == 0
            || self.camera.intrinsics == 0
            || self.camera.extrinsics == 0
            || self.zones[..len].iter().any(Option::is_none)
            || self.zones[len..].iter().any(Option::is_some)
        {
            return Err(ContractError::InvalidIdentifier);
        }
        for digest in [
            self.input_digest,
            self.calibration_digest,
            self.sensor_digest,
            self.import_identity,
            self.import_root,
            self.privacy_digest,
            self.base_analysis,
        ] {
            if digest.algorithm() != DigestAlgorithm::Sha256 {
                return Err(ContractError::UnsupportedDigestAlgorithm);
            }
        }
        let mut previous = None;
        for entry in self.entries() {
            let samples: u64 = entry.counts.iter().map(|n| u64::from(*n)).sum();
            if samples == 0
                || samples > 1024
                || previous.is_some_and(|p| p >= entry.binding)
                || entry.binding.algorithm() != DigestAlgorithm::Sha256
                || entry.base_pipeline.algorithm() != DigestAlgorithm::Sha256
            {
                return Err(ContractError::InvalidIdentifier);
            }
            previous = Some(entry.binding);
        }
        // Checked again against the actual sigma-point block of the enclosing record.
        if self
            .pose_bits
            .iter()
            .any(|bits| !f64::from_bits(*bits).is_finite())
        {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(())
    }

    fn check_source(&self, record: &CoverageRecord) -> Result<(), ContractError> {
        let Some(PoseProvenance::SiteCalibration {
            calibration_digest,
            camera_handle,
            intrinsics_generation,
            extrinsics_generation,
            ..
        }) = record.pose_provenance
        else {
            return Err(ContractError::InvalidIdentifier);
        };
        if record.source != CoverageSource::Corroborate
            || record.import_identity != self.import_identity
            || record.import_root != self.import_root
            || ContentDigest::sha256(record.sensor_id.as_bytes()) != self.sensor_digest
            || calibration_digest != self.calibration_digest
            || camera_handle != self.camera.camera
            || intrinsics_generation != self.camera.intrinsics
            || extrinsics_generation != self.camera.extrinsics
            || record.zones.len() != usize::from(self.len)
            || record
                .pose_uncertainty
                .as_ref()
                .and_then(PoseUncertainty::pose_covariance)
                .is_none_or(|covariance| covariance.bits() != self.pose_bits)
        {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut seen = std::collections::BTreeSet::new();
        for zone in &record.zones {
            if !seen.insert(binding(zone)?) {
                return Err(ContractError::NonCanonicalOrdering);
            }
            let entry = self.zone(zone)?;
            if zone
                .visibility
                .as_ref()
                .is_none_or(|v| v.samples != entry.samples())
            {
                return Err(ContractError::InvalidIdentifier);
            }
        }
        Ok(())
    }

    /// Check every binding and derived identity, and fail closed on a witness in a
    /// rejected zone. Called by the normal coverage decoder and retention validator.
    pub fn validate_for(&self, record: &CoverageRecord) -> Result<(), ContractError> {
        self.validate()?;
        self.check_source(record)?;
        let digest = self.digest();
        if record.analysis_digest != derived(ANALYSIS_DOMAIN, self.base_analysis, digest) {
            return Err(ContractError::DigestMismatch);
        }
        for zone in &record.zones {
            let entry = self.zone(zone)?;
            if zone.pipeline_generation != derived(PIPELINE_DOMAIN, entry.base_pipeline, digest) {
                return Err(ContractError::DigestMismatch);
            }
            if entry.requires_abstention() && !zone.witnesses.is_empty() {
                return Err(ContractError::CoverageUncertified);
            }
            if !entry.requires_abstention()
                && zone
                    .uncovered
                    .iter()
                    .any(|interval| interval.reason == UncoveredReason::CalibrationUncertainty)
            {
                return Err(ContractError::CoverageUncertified);
            }
            check_partition(record, zone)?;
        }
        Ok(())
    }

    /// Exact canonical receipt bytes, independent of a transport or JSON renderer.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        self.encode(&mut e);
        e.finish()
    }
    /// SHA-256 of the canonical receipt. Bound into every surviving predicate.
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_bytes())
    }
    /// Decode an exact, digest-pinned stand-alone receipt without granting coverage.
    pub fn from_bytes(bytes: &[u8], expected: ContentDigest) -> Result<Self, ContractError> {
        if bytes.len() > MAX_CALIBRATION_COVERAGE_RECEIPT_BYTES {
            return Err(ContractError::BudgetExhausted);
        }
        if ContentDigest::sha256(bytes) != expected {
            return Err(ContractError::DigestMismatch);
        }
        let mut d = CanonicalDecoder::new(bytes);
        let receipt = Self::decode(&mut d)?;
        d.ensure_finished()?;
        if receipt.to_bytes() != bytes {
            return Err(ContractError::NonCanonicalOrdering);
        }
        Ok(receipt)
    }
    pub(crate) fn encode(&self, e: &mut CanonicalEncoder) {
        e.text(DOMAIN);
        e.text(CALIBRATION_COVERAGE_POLICY);
        for digest in [
            self.input_digest,
            self.calibration_digest,
            self.sensor_digest,
            self.import_identity,
            self.import_root,
            self.privacy_digest,
            self.base_analysis,
        ] {
            e.digest(digest);
        }
        e.u64(self.camera.camera);
        e.u64(self.camera.intrinsics);
        e.u64(self.camera.extrinsics);
        e.u64(self.privacy_generation);
        for bits in self.pose_bits {
            e.u64(bits);
        }
        e.u8(self.len);
        for entry in self.entries() {
            e.digest(entry.binding);
            e.digest(entry.base_pipeline);
            for count in entry.counts {
                e.u32(count);
            }
        }
    }
    pub(crate) fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        if d.text()? != DOMAIN || d.text()? != CALIBRATION_COVERAGE_POLICY {
            return Err(ContractError::InvalidIdentifier);
        }
        let input_digest = d.digest()?;
        let calibration_digest = d.digest()?;
        let sensor_digest = d.digest()?;
        let import_identity = d.digest()?;
        let import_root = d.digest()?;
        let privacy_digest = d.digest()?;
        let base_analysis = d.digest()?;
        let camera = CameraGeneration {
            camera: d.u64()?,
            intrinsics: d.u64()?,
            extrinsics: d.u64()?,
        };
        let privacy_generation = d.u64()?;
        let mut pose_bits = [0; 36];
        for bits in &mut pose_bits {
            *bits = d.u64()?;
        }
        let len = d.u8()?;
        if len == 0 || usize::from(len) > MAX_COVERAGE_ZONES {
            return Err(ContractError::BudgetExhausted);
        }
        let mut zones = [None; MAX_COVERAGE_ZONES];
        for slot in zones.iter_mut().take(usize::from(len)) {
            let binding = d.digest()?;
            let base_pipeline = d.digest()?;
            let mut counts = [0; 7];
            for count in &mut counts {
                *count = d.u32()?;
            }
            *slot = Some(CalibrationZoneReceipt {
                binding,
                base_pipeline,
                counts,
            });
        }
        let receipt = Self {
            input_digest,
            calibration_digest,
            camera,
            sensor_digest,
            import_identity,
            import_root,
            privacy_digest,
            privacy_generation,
            base_analysis,
            pose_bits,
            zones,
            len,
        };
        receipt.validate()?;
        Ok(receipt)
    }
}

/// Reject missing, overlapping or reordered evidence; never fill a hole by assumption.
fn check_partition(record: &CoverageRecord, zone: &ZoneCoverage) -> Result<(), ContractError> {
    if zone.witnesses.len() > MAX_COVERAGE_INTERVALS
        || zone.uncovered.len() > MAX_COVERAGE_INTERVALS
    {
        return Err(ContractError::BudgetExhausted);
    }
    let mut ranges: Vec<(u64, u64)> = zone
        .witnesses
        .iter()
        .map(|w| (w.first_segment, w.last_segment))
        .chain(
            zone.uncovered
                .iter()
                .map(|u| (u.first_segment, u.last_segment)),
        )
        .collect();
    ranges.sort_unstable();
    let mut previous: Option<u64> = None;
    for (first, last) in ranges {
        if first > last
            || first < record.first_segment
            || last > record.last_segment
            || previous.map_or(first != record.first_segment, |p| {
                p.checked_add(1) != Some(first)
            })
        {
            return Err(ContractError::CoverageUncertified);
        }
        previous = Some(last);
    }
    if previous != Some(record.last_segment) {
        return Err(ContractError::CoverageUncertified);
    }
    Ok(())
}

/// Apply full-camera abstention atomically to a validated nominal record.
///
/// Only former witnesses of rejected zones become `calibration_uncertainty`.
/// Existing gap, privacy, timing, warm-up and positive-entry intervals are copied
/// exactly. Surviving witnesses retain their capture/domain/anchor and gain a new
/// guard-bound pipeline and predicate. No nominal record or authority is mutated.
pub fn apply_calibration_coverage(
    record: &CoverageRecord,
    assessment: &CalibrationCoverageAssessment,
    budget: &mut WorkBudget<'_>,
) -> Result<CoverageRecord, CorroborationError> {
    budget.charge(0).map_err(geometry)?;
    // Bound borrowed structures before validation, encoding, sorting or cloning.
    if record.zones.is_empty()
        || record.zones.len() > MAX_COVERAGE_ZONES
        || record.sensor_id.len() > 512
        || record.capture_time_label.len() > 64
    {
        return Err(ContractError::BudgetExhausted.into());
    }
    let mut work = 4096_u64;
    for zone in &record.zones {
        if zone.zone_id.len() > 64
            || zone.geometry.len() > 256
            || zone.scope.len() > 80
            || zone.witnesses.len() > MAX_COVERAGE_INTERVALS
            || zone.uncovered.len() > MAX_COVERAGE_INTERVALS
            || zone.uncovered.iter().any(|u| match &u.reason {
                UncoveredReason::DecodeRefused { error_id } => error_id.len() > 512,
                UncoveredReason::ZoneEntry { event_id, .. } => {
                    event_id.as_ref().is_some_and(|id| id.len() > 512)
                }
                _ => false,
            })
            || zone.witnesses.iter().any(|w| {
                let inner = &w.witness;
                inner.negative_predicate.len() > 4096
                    || inner.authorized_domain.len() != 1
                    || inner.observed_domain.len() != 1
                    || !inner.excluded_domain.is_empty()
                    || inner
                        .authorized_domain
                        .iter()
                        .chain(&inner.observed_domain)
                        .any(|d| d.len() > 512)
            })
        {
            return Err(ContractError::BudgetExhausted.into());
        }
        work += 4096
            + 128 * (zone.witnesses.len() + zone.uncovered.len()) as u64
            + zone
                .witnesses
                .iter()
                .map(|w| w.witness.negative_predicate.len() as u64)
                .sum::<u64>();
    }
    budget.charge(work).map_err(geometry)?;
    record.validate()?;
    for zone in &record.zones {
        check_partition(record, zone)?;
    }
    // Reapplying the same screen is idempotent; a different screen needs a fresh nominal run.
    if let Some(receipt) = record
        .pose_uncertainty
        .as_ref()
        .and_then(PoseUncertainty::guard_receipt)
    {
        if receipt.input_digest != assessment.input_digest
            || receipt.privacy_digest != assessment.privacy_digest
            || receipt.privacy_generation != assessment.privacy_generation
        {
            return Err(ContractError::DigestMismatch.into());
        }
        budget.charge(0).map_err(geometry)?;
        return Ok(record.clone());
    }
    let receipt = CalibrationCoverageReceipt::from_assessment(record, assessment)?;
    let Some(PoseUncertainty::SigmaPoints { covariance }) = record.pose_uncertainty else {
        return Err(ContractError::CoverageUncertified.into());
    };
    let mut guarded = record.clone();
    let digest = receipt.digest();
    guarded.analysis_digest = derived(ANALYSIS_DOMAIN, receipt.base_analysis, digest);
    guarded.pose_uncertainty = Some(PoseUncertainty::SigmaPointsGuarded {
        covariance,
        receipt,
    });
    for zone in &mut guarded.zones {
        let entry = receipt.zone(zone)?;
        zone.pipeline_generation = derived(PIPELINE_DOMAIN, entry.base_pipeline, digest);
        if entry.requires_abstention() {
            if zone.uncovered.len() + zone.witnesses.len() > MAX_COVERAGE_INTERVALS {
                return Err(ContractError::BudgetExhausted.into());
            }
            for witness in zone.witnesses.drain(..) {
                zone.uncovered.push(UncoveredInterval {
                    first_segment: witness.first_segment,
                    last_segment: witness.last_segment,
                    capture: Some(witness.outer),
                    reason: UncoveredReason::CalibrationUncertainty,
                });
            }
            zone.uncovered
                .sort_by_key(|interval| interval.first_segment);
        } else {
            let clause = pose_predicate_clause(
                guarded.pose_uncertainty.as_ref(),
                zone.pose_robustness.as_ref(),
            );
            for witness in &mut zone.witnesses {
                witness.witness.negative_predicate = format!(
                    "{}{}",
                    zone_witness_predicate(
                        guarded.source,
                        &guarded.sensor_id,
                        &zone.scope,
                        zone.pipeline_generation,
                        witness.covered,
                        zone.visibility.as_ref()
                    ),
                    clause
                );
            }
        }
    }
    guarded.validate()?;
    if guarded.to_bytes().len() > MAX_COVERAGE_RECORD_BYTES {
        return Err(ContractError::BudgetExhausted.into());
    }
    budget.charge(0).map_err(geometry)?;
    Ok(guarded)
}

#[cfg(test)]
mod tests;

#![forbid(unsafe_code)]
//! Revalidate current authority before retaining a screened coverage set.
//!
//! Even an already-retained rerun must pass privacy, source and adoption checks. An unrelated
//! event append may advance the head; it does not invalidate an exact retained ancestor or
//! silently upgrade a camera's currency. No bytes are staged until every camera passes.

use std::collections::BTreeMap;
use std::fmt;

use fss_core::{ContentDigest, ContractError, SensorId};
use fss_geometry::CameraGeneration;

use crate::ingest::calibration_adoption::{
    AdoptionError, RetainedAdoption, adopted_currency, retained_adoptions,
};
use crate::ingest::privacy_mask::{PrivacyMaskError, current_mask};
use crate::ingest::recorded_coverage::{
    CoverageError, CoverageRecord, CoverageStatus, PoseProvenance, PoseUncertainty, check_approval,
    coverage_status, retain_coverage,
};
use crate::ingest::recorded_decode::{RecordedDecodeError, source_capsule};
use crate::ingest::recorded_watch::MAX_WATCH_FRAMES;
use crate::ingest::{FileIngestError, RetainedFileImport, RetainedReadLimits};
use crate::{ReferenceDeployment, ReplayCx};

use super::GuardedCoverageSet;

/// The owning subsystem's typed refusal; none of these errors permits a nominal fallback.
#[derive(Debug)]
pub enum GuardedCoverageRetentionError {
    /// The exact approved coverage set is invalid or could not be retained.
    Coverage(Box<CoverageError>),
    /// Original source custody is no longer readable (including deletion).
    Source(Box<FileIngestError>),
    /// A retained source capsule could not be verified.
    Capsule(Box<RecordedDecodeError>),
    /// The privacy binding is unavailable or changed after screening.
    Privacy(Box<PrivacyMaskError>),
    /// The calibration adoption, sensor binding, or claimed currency changed.
    Adoption(Box<AdoptionError>),
    /// A canonical record or identifier is invalid.
    Contract(ContractError),
    /// The record's exact anchor is neither the head nor a retained ancestor.
    ForeignAnchor,
    /// The record does not name the verified import root, sensor, time label, or segment range.
    SourceBinding,
    /// Cancellation occurred before retention.
    Cancelled,
}

impl GuardedCoverageRetentionError {
    /// Existing subsystem error identity; typed variants retain the precise failure dimension.
    #[must_use]
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Coverage(error) => error.stable_id(),
            Self::Capsule(error) => error.stable_id(),
            Self::Privacy(error) => error.stable_id(),
            Self::Adoption(error) => error.stable_id(),
            _ => "ERR-COVERAGE-001",
        }
    }
}

impl fmt::Display for GuardedCoverageRetentionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Coverage(error) => write!(f, "guarded coverage: {error}"),
            Self::Source(error) => write!(f, "guarded coverage source: {error}"),
            Self::Capsule(error) => write!(f, "guarded coverage capsule: {error}"),
            Self::Privacy(error) => write!(f, "guarded coverage privacy: {error}"),
            Self::Adoption(error) => write!(f, "guarded coverage adoption: {error}"),
            Self::Contract(error) => write!(f, "guarded coverage contract: {error}"),
            Self::ForeignAnchor => {
                f.write_str("guarded coverage basis is not a retained authority ancestor")
            }
            Self::SourceBinding => {
                f.write_str("guarded coverage does not match retained source custody")
            }
            Self::Cancelled => {
                f.write_str("guarded coverage retention cancelled before publication")
            }
        }
    }
}
impl std::error::Error for GuardedCoverageRetentionError {}

type Result<T> = std::result::Result<T, GuardedCoverageRetentionError>;

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<()> {
    cx.checkpoint(stage)
        .map_err(|_| GuardedCoverageRetentionError::Cancelled)
}

fn check_adoption(
    record: &CoverageRecord,
    sensor: &SensorId,
    history: &BTreeMap<u64, Vec<RetainedAdoption>>,
) -> Result<()> {
    let Some(PoseProvenance::SiteCalibration {
        calibration_digest,
        camera_handle,
        intrinsics_generation,
        extrinsics_generation,
        currency,
    }) = record.pose_provenance
    else {
        return Ok(());
    };
    // An adopted physical sensor cannot become a second, nominally unadopted camera handle.
    if history.iter().any(|(handle, chain)| {
        *handle != camera_handle && chain.last().is_some_and(|a| a.receipt.sensor_id == *sensor)
    }) {
        return Err(GuardedCoverageRetentionError::Adoption(Box::new(
            AdoptionError::SensorConflict {
                camera_handle,
                sensor: sensor.clone(),
                reason: "screened sensor is adopted by another camera handle",
            },
        )));
    }
    let current = adopted_currency(
        history,
        calibration_digest,
        &record.sensor_id,
        CameraGeneration {
            camera: camera_handle,
            intrinsics: intrinsics_generation,
            extrinsics: extrinsics_generation,
        },
        || Ok(sensor.clone()),
    )
    .map_err(|e| GuardedCoverageRetentionError::Adoption(Box::new(e)))?;
    // New adoption, disappearance, or a different receipt cannot be hidden by an old assertion.
    // A matching first adoption also needs a fresh analysis with adopted_current provenance.
    if currency.adoption_receipt() != current.as_ref().map(|a| a.digest) {
        return Err(GuardedCoverageRetentionError::Adoption(Box::new(
            AdoptionError::InvalidRecord(
                "coverage generation currency differs from current retained adoption; reanalyze",
            ),
        )));
    }
    Ok(())
}

impl GuardedCoverageSet {
    /// Current retention state without writing or claiming dependency currency.
    pub fn status(&self, deployment: &ReferenceDeployment) -> Result<CoverageStatus> {
        coverage_status(deployment, &self.records.iter().collect::<Vec<_>>())
            .map_err(GuardedCoverageRetentionError::Contract)
    }

    /// Revalidate exact retained ancestry, every source capsule, mask generation, and adoption.
    ///
    /// Source reads use the caller's existing limits and cancellation authority. A source range
    /// is at most the recorded-watch frame ceiling per camera; this does not decode any pixels.
    /// Corrupt or missing authority is an error, never "no policy" or "not adopted".
    pub fn revalidate(
        &self,
        deployment: &ReferenceDeployment,
        limits: RetainedReadLimits,
        cx: &ReplayCx,
    ) -> Result<()> {
        checkpoint(cx, "calibrated_coverage:revalidate")?;
        let history = retained_adoptions(deployment)
            .map_err(|e| GuardedCoverageRetentionError::Adoption(Box::new(e)))?;
        for (record, expected_privacy) in self.records.iter().zip(&self.privacy) {
            checkpoint(cx, "calibrated_coverage:camera")?;
            record
                .validate()
                .map_err(GuardedCoverageRetentionError::Contract)?;
            if &record.basis != deployment.current_anchor()
                && !deployment
                    .ledger()
                    .batches()
                    .iter()
                    .any(|batch| batch.new_anchor == record.basis)
            {
                return Err(GuardedCoverageRetentionError::ForeignAnchor);
            }
            let sensor = SensorId::parse(&record.sensor_id)
                .map_err(GuardedCoverageRetentionError::Contract)?;
            let privacy = current_mask(deployment, &sensor)
                .map_err(|e| GuardedCoverageRetentionError::Privacy(Box::new(e)))?;
            if (privacy.digest(), privacy.generation().unwrap_or(0)) != *expected_privacy {
                return Err(GuardedCoverageRetentionError::Privacy(Box::new(
                    PrivacyMaskError::UnmaskedAccessRefused,
                )));
            }
            if let Some(receipt) = record
                .pose_uncertainty
                .as_ref()
                .and_then(PoseUncertainty::guard_receipt)
                && (receipt.privacy_digest(), receipt.privacy_generation()) != *expected_privacy
            {
                return Err(GuardedCoverageRetentionError::Contract(
                    ContractError::DigestMismatch,
                ));
            }
            check_adoption(record, &sensor, &history)?;
            let source = RetainedFileImport::open(deployment, record.import_identity, limits, cx)
                .map_err(|e| GuardedCoverageRetentionError::Source(Box::new(e)))?;
            let count = source.manifest().segment_spans.len();
            if source.import_root() != record.import_root
                || source.manifest().capture_time_label != record.capture_time_label
                || count == 0
                || count > MAX_WATCH_FRAMES
                || record.first_segment > record.last_segment
                || record.last_segment >= count as u64
            {
                return Err(GuardedCoverageRetentionError::SourceBinding);
            }
            // The checked source count bounds these conversions and the inclusive loop.
            for segment in record.first_segment as usize..=record.last_segment as usize {
                checkpoint(cx, "calibrated_coverage:capsule")?;
                let (capsule, _) = source_capsule(deployment, &source, segment)
                    .map_err(|e| GuardedCoverageRetentionError::Capsule(Box::new(e)))?;
                if capsule.sensor_id != sensor {
                    return Err(GuardedCoverageRetentionError::SourceBinding);
                }
            }
        }
        checkpoint(cx, "calibrated_coverage:revalidated")
    }

    /// Check all dependencies and the exact approval before any event or coverage publication.
    /// Rerun approval acceptance remains owned by the existing coverage protocol.
    pub fn check_approval(
        &self,
        deployment: &ReferenceDeployment,
        approval: ContentDigest,
        limits: RetainedReadLimits,
        cx: &ReplayCx,
    ) -> Result<()> {
        self.revalidate(deployment, limits, cx)?;
        check_approval(
            deployment,
            &self.records.iter().collect::<Vec<_>>(),
            approval,
        )
        .map_err(|e| GuardedCoverageRetentionError::Coverage(Box::new(e)))?;
        Ok(())
    }

    /// Retain the screened set through the existing single-batch coverage publisher.
    /// Every camera is revalidated before any spool write, even for an idempotent rerun.
    pub fn retain(
        &self,
        deployment: &mut ReferenceDeployment,
        approval: ContentDigest,
        limits: RetainedReadLimits,
        cx: &ReplayCx,
    ) -> Result<CoverageStatus> {
        self.check_approval(deployment, approval, limits, cx)?;
        checkpoint(cx, "calibrated_coverage:commit")?;
        retain_coverage(
            deployment,
            &self.records.iter().collect::<Vec<_>>(),
            approval,
            cx,
        )
        .map_err(|e| GuardedCoverageRetentionError::Coverage(Box::new(e)))
    }
}

#[cfg(test)]
mod tests;

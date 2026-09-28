#![forbid(unsafe_code)]
//! Full-camera screening composed with the actual corroboration and retention APIs.
//!
//! The screen is subtractive: only former witnesses of rejected zones become explicit
//! calibration-uncertainty intervals. It never changes positive event proposals, repairs a
//! source gap, grants a witness, or claims physical calibration currency. All camera screens
//! and record transformations share the caller's budget, including post-publication reanalysis.

use fss_cli::agent_json::{array, object, string};
use fss_core::{ContentDigest, SensorId};
use fss_geometry::WorkBudget;
use fss_reference::ingest::calibration_coverage::{
    CalibrationCoverageAssessment, CalibrationCoverageInput,
    assess_calibration_coverage, calibrated_camera_model,
};
use fss_reference::ingest::privacy_mask::current_mask;
use fss_reference::ingest::recorded_corroboration::{CorroborationError, CorroborationReport};
use fss_reference::calibrated_coverage::{CoverageProjectionInput, GuardedCoverageSet};
use fss_reference::ingest::RetainedReadLimits;
use fss_reference::ingest::recorded_coverage::{CoverageStatus, PoseProvenance};
use fss_reference::ingest::recorded_decode::RecordedDecodeError;
use fss_reference::ingest::site_calibration::SiteCalibration;
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::{CorroborateAction, RunResult};

/// Owned candidate records: nominal event analysis is never mutated by the coverage screen.
pub(super) struct CoverageGuard {
    assessments: Vec<CalibrationCoverageAssessment>,
    guarded: GuardedCoverageSet,
    read_limits: RetainedReadLimits,
    status: CoverageStatus,
    work_units: u64,
    work_units_total: u64,
    work_units_remaining: u64,
}

impl CoverageGuard {
    /// Validate the actual guarded records, source custody, ancestry, privacy and adoption
    /// before either coverage or event publication.
    pub(super) fn check_retention(
        &self,
        deployment: &ReferenceDeployment,
        approval: ContentDigest,
        cx: &ReplayCx,
    ) -> RunResult<()> {
        self.guarded.check_approval(deployment, approval, self.read_limits, cx)?;
        Ok(())
    }

    /// The ordinary authority owner commits both records in one batch, with its own recheck.
    pub(super) fn retain(
        &mut self,
        deployment: &mut ReferenceDeployment,
        approval: ContentDigest,
        cx: &ReplayCx,
    ) -> RunResult<()> {
        cx.checkpoint("calibration_coverage:retain")
            .map_err(|_| RecordedDecodeError::Cancelled)?;
        self.status = self.guarded.retain(deployment, approval, self.read_limits, cx)?;
        Ok(())
    }

    /// The ordinary coverage renderer emits version-6 receipts and the *guarded* approval.
    pub(super) fn coverage_json(&self, rerun: &str) -> String {
        let records: Vec<_> = self.guarded.records().iter().collect();
        super::super::coverage::render(
            &records,
            self.status,
            self.guarded.approval(),
            rerun,
        )
    }

    pub(super) fn to_json(&self) -> String {
        let assessments: Vec<_> = self.assessments.iter().map(|a| a.to_json()).collect();
        object(&[
            ("format", string("fss.calibration_coverage_proposal.v1")),
            ("mode", string("lossless_per_zone_abstention")),
            ("assessments", array(&assessments)),
            ("work_units", self.work_units.to_string()),
            ("work_units_total", self.work_units_total.to_string()),
            ("work_units_remaining", self.work_units_remaining.to_string()),
            ("absence_claim_authorized", "false".to_owned()),
            ("positive_event_approvals_changed", "false".to_owned()),
            ("existing_coverage_retracted", "false".to_owned()),
            ("effect_authority", "false".to_owned()),
            (
                "claim",
                string("conditional_linearized_screen_not_coverage_or_physical_currency"),
            ),
        ])
    }
}

fn invalid() -> CorroborationError {
    CorroborationError::InvalidPlan("calibration screen does not match the analysed camera set")
}

/// Construct all guarded records before exposing any of them. Matching is by both camera
/// name and source identities, never by calibration-file order. Uncalibrated cameras keep
/// their exact records. A malformed binding, exhausted budget, or cancellation returns no set.
pub(super) fn assess(
    action: &CorroborateAction,
    calibration: Option<&SiteCalibration>,
    calibration_digest: Option<ContentDigest>,
    deployment: &ReferenceDeployment,
    report: &CorroborationReport,
    cx: &ReplayCx,
    budget: &mut WorkBudget<'_>,
) -> RunResult<Option<CoverageGuard>> {
    let (calibration, calibration_digest) = match (calibration, calibration_digest) {
        (None, None) => return Ok(None),
        (Some(calibration), Some(digest)) => (calibration, digest),
        _ => return Err(invalid().into()),
    };
    if report.cameras().len() != action.plan.cameras.len()
        || report.coverage().len() != action.plan.cameras.len()
    {
        return Err(invalid().into());
    }
    let start = budget.used();
    let mut assessments = Vec::with_capacity(report.coverage().len());
    let mut privacy = Vec::with_capacity(report.coverage().len());
    for ((planned, camera), record) in action
        .plan
        .cameras
        .iter()
        .zip(report.cameras())
        .zip(report.coverage())
    {
        cx.checkpoint("calibration_coverage:screen")
            .map_err(|_| RecordedDecodeError::Cancelled)?;
        if planned.name != camera.name
            || planned.import_identity != camera.import_identity
            || record.import_identity != camera.import_identity
            || record.import_root != camera.import_root
            || record.sensor_id != camera.sensor_id
        {
            return Err(invalid().into());
        }
        let sensor = SensorId::parse(&camera.sensor_id)?;
        let mask = current_mask(deployment, &sensor)?;
        let Some(calibrated) = calibration.camera(&planned.name) else {
            // An unmatched owner pose may coexist with a calibrated camera; do not reinterpret it.
            if matches!(record.pose_provenance, Some(PoseProvenance::SiteCalibration { .. })) {
                return Err(invalid().into());
            }
            assessments.push(None);
            privacy.push(mask);
            continue;
        };
        let model = calibrated_camera_model(calibrated)?;
        let assessment = assess_calibration_coverage(
            CalibrationCoverageInput {
                camera_name: &planned.name,
                camera: &model,
                calibration_digest,
                sensor: &sensor,
                privacy: &mask,
                zones: &action.plan.zones,
                policy: action.policy,
            },
            budget,
        )?;
        assessments.push(Some(assessment));
        privacy.push(mask);
    }
    // Reuse the new shared owner rather than duplicating its mixed-anchor, duplicate-camera,
    // companion-copy bounds, privacy bindings or immutable prepared-set semantics in the CLI.
    let guarded = {
        let inputs: Vec<_> = report.coverage().iter().zip(&assessments).zip(&privacy)
            .map(|((record, assessment), privacy)| CoverageProjectionInput {
                record, assessment: assessment.as_ref(), privacy,
            }).collect();
        GuardedCoverageSet::project(&inputs, budget)?
    };
    cx.checkpoint("calibration_coverage:screened")
        .map_err(|_| RecordedDecodeError::Cancelled)?;
    let status = guarded.status(deployment)?;
    Ok(Some(CoverageGuard {
        assessments: assessments.into_iter().flatten().collect(),
        guarded,
        read_limits: action.limits.read_limits,
        status,
        work_units: budget.used() - start,
        work_units_total: budget.used(),
        work_units_remaining: budget.remaining(),
    }))
}

#[cfg(test)]
#[path = "calibration_coverage/tests.rs"]
mod tests;

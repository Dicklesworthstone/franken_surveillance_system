#![forbid(unsafe_code)]
//! Command-boundary interlock: do not offer/retain a nominal absence proposal
//! rejected by the full camera covariance screen. Positive event proposals remain
//! independent. No old ledger record is rewritten or silently retracted.

use super::{
    CorroborateAction, CorroborationError, CorroborationReport, ReferenceDeployment, ReplayCx,
    RunResult, SiteCalibration,
};
use fss_core::{ContentDigest, SensorId};
use fss_geometry::WorkBudget;
use fss_reference::ingest::calibration_coverage::{
    CalibrationCoverageAssessment, CalibrationCoverageInput, MAX_CALIBRATION_COVERAGE_WORK,
    assess_calibration_coverage, calibrated_camera_model,
};
use fss_reference::ingest::privacy_mask::current_mask;
use fss_reference::ingest::recorded_decode::RecordedDecodeError;

/// Diagnostics plus an additional denial, never authority to publish coverage.
pub(super) struct CoverageGuard {
    assessments: Vec<CalibrationCoverageAssessment>,
    blocked: bool,
}
impl CoverageGuard {
    pub(super) fn blocked(&self) -> bool {
        self.blocked
    }

    /// Must run before candidate publication as well as before coverage retention,
    /// so a mixed request cannot partially commit after its coverage was refused.
    pub(super) fn check_retention(&self, requested: bool) -> RunResult<()> {
        if requested && self.blocked {
            return Err(CorroborationError::InvalidPose {
                camera: "calibration-coverage".to_owned(),
                reason: "coverage withheld: full camera uncertainty reaches an image/privacy boundary or camera plane; preview without --retain-coverage and inspect calibration_uncertainty_guard",
            }.into());
        }
        Ok(())
    }

    pub(super) fn to_json(&self) -> String {
        let cameras = self
            .assessments
            .iter()
            .map(CalibrationCoverageAssessment::to_json)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            concat!(
                "{{\"format\":\"fss.calibration_coverage_guard.v1\",\"coverage_withheld\":{},",
                "\"absence_claim_authorized\":false,\"existing_coverage_retracted\":false,",
                "\"positive_event_approvals_changed\":false,\"cameras\":[{}]}}"
            ),
            self.blocked, cameras
        )
    }

    /// Alternate, explicit refusal format. No nominal records, approval digest or
    /// rerun command can accidentally escape through a normal proposal renderer.
    pub(super) fn withheld_coverage_json(&self) -> String {
        format!(
            concat!(
                "{{\"format\":\"fss.calibration_coverage_refusal.v1\",\"status\":\"blocked\",",
                "\"knowledge_state\":\"not_observable\",\"reason\":\"calibration_uncertainty\",",
                "\"approval_digest\":null,\"approve_command\":null,\"records\":[],",
                "\"existing_coverage_retracted\":false,\"guard\":{}}}"
            ),
            self.to_json()
        )
    }
}

fn blocks_nominal_witness(
    assessment: &CalibrationCoverageAssessment,
    has_witness: impl Fn(&str) -> bool,
) -> bool {
    assessment
        .zones()
        .iter()
        .any(|zone| zone.requires_abstention() && has_witness(zone.zone_id()))
}

/// Uses the same already-verified calibration object as pose resolution (no
/// second file read), and resolves masks from the current deployment authority.
/// The check is additive; it cannot turn a pre-existing uncovered zone into a witness.
pub(super) fn assess(
    action: &CorroborateAction,
    calibration: Option<&SiteCalibration>,
    digest: Option<ContentDigest>,
    deployment: &ReferenceDeployment,
    report: &CorroborationReport,
    cx: &ReplayCx,
) -> RunResult<Option<CoverageGuard>> {
    let (calibration, digest) = match (calibration, digest) {
        (None, None) => return Ok(None),
        (Some(calibration), Some(digest)) => (calibration, digest),
        _ => {
            return Err(
                CorroborationError::InvalidPlan("calibration guard identity mismatch").into(),
            );
        }
    };
    let mut budget = WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK);
    let mut assessments = Vec::with_capacity(action.plan.cameras.len());
    let mut blocked = false;
    for camera in &action.plan.cameras {
        cx.checkpoint("corroborate:calibration-coverage")
            .map_err(|_| CorroborationError::from(RecordedDecodeError::Cancelled))?;
        let Some(candidate) = calibration.camera(&camera.name) else {
            continue;
        };
        let record = report
            .coverage()
            .iter()
            .find(|record| record.import_identity == camera.import_identity)
            .ok_or(CorroborationError::InvalidPlan(
                "calibration guard recording mismatch",
            ))?;
        let sensor = SensorId::parse(&record.sensor_id)?;
        let privacy = current_mask(deployment, &sensor)?;
        let model = calibrated_camera_model(candidate)?;
        let assessment = assess_calibration_coverage(
            CalibrationCoverageInput {
                camera_name: &camera.name,
                camera: &model,
                calibration_digest: digest,
                sensor: &sensor,
                privacy: &privacy,
                zones: &action.plan.zones,
                policy: action.policy,
            },
            &mut budget,
        )?;
        blocked |= blocks_nominal_witness(&assessment, |zone_id| {
            record
                .zones
                .iter()
                .any(|zone| zone.zone_id == zone_id && !zone.witnesses.is_empty())
        });
        assessments.push(assessment);
    }
    cx.checkpoint("corroborate:calibration-coverage-complete")
        .map_err(|_| CorroborationError::from(RecordedDecodeError::Cancelled))?;
    Ok(Some(CoverageGuard {
        assessments,
        blocked,
    }))
}

#[cfg(test)]
#[path = "calibration_coverage/tests.rs"]
mod tests;

#![forbid(unsafe_code)]
//! Fail-closed bridge from a current calibration monitor result to world projection and handoff modeling.

use fss_geometry::{HandoffCamera, WorkBudget};
use crate::{ContactObservation, ContactProjection, ProjectionOptions, PropertyTwin, TrackingCamera,
    TwinError, project_contact};
use crate::calibration_monitor::{CalibrationDisposition, CalibrationMonitorReport};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CalibrationGateBasis {
    pub calibration_digest: [u8; 32],
    pub camera: u64,
    pub calibration: u64,
    pub image_domain: u64,
    pub image_domain_digest: [u8; 32],
    pub clock: u64,
    pub checked_capture: [u64; 2],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationGateError {
    InvalidInput,
    BasisMismatch,
    Invalidated,
    Indeterminate,
    Twin(TwinError),
}
impl From<TwinError> for CalibrationGateError { fn from(value: TwinError) -> Self { Self::Twin(value) } }
impl std::fmt::Display for CalibrationGateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid calibration gate input",
            Self::BasisMismatch => "calibration gate basis mismatch",
            Self::Invalidated => "camera calibration invalidated by current monitor evidence",
            Self::Indeterminate => "camera calibration not currently observable enough for world projection",
            Self::Twin(_) => "guarded world projection failed",
        })
    }
}
impl std::error::Error for CalibrationGateError {}

pub struct MonitoredTrackingCamera {
    camera: TrackingCamera,
    basis: CalibrationGateBasis,
}
impl std::fmt::Debug for MonitoredTrackingCamera {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MonitoredTrackingCamera").field("camera", &self.basis.camera)
            .field("calibration", &self.basis.calibration).field("checked_capture", &self.basis.checked_capture)
            .finish_non_exhaustive()
    }
}
impl MonitoredTrackingCamera {
    pub fn basis(&self) -> CalibrationGateBasis { self.basis }

    pub fn project_contact(&self, twin: &PropertyTwin, observation: ContactObservation,
        options: ProjectionOptions, budget: &mut WorkBudget<'_>)
        -> Result<ContactProjection, CalibrationGateError> {
        if !contains(self.basis.checked_capture, observation.capture) {
            return Err(CalibrationGateError::BasisMismatch);
        }
        Ok(project_contact(twin, self.camera, observation, options, budget)?)
    }

    /// Verify that one modeled handoff view is exactly the admitted camera snapshot and
    /// that the source observation used to launch the forecast was covered by the current
    /// calibration check. This does not extend the camera's future validity interval.
    pub fn check_handoff_camera(&self, view: HandoffCamera<'_>, source_capture: [u64;2])
        -> Result<(), CalibrationGateError> {
        if !contains(self.basis.checked_capture, source_capture)
            || view.id != self.camera.camera || view.geometry != self.camera.geometry
            || view.clock != self.camera.clock || view.image_mode != self.camera.image_domain
            || view.pose != self.camera.pose || view.intrinsics != self.camera.intrinsics
            || view.valid.earliest() < self.camera.validity[0]
            || view.valid.latest() > self.camera.validity[1] {
            return Err(CalibrationGateError::BasisMismatch);
        }
        Ok(())
    }
}

pub fn admit_tracking_camera(camera: TrackingCamera, report: &CalibrationMonitorReport,
    basis: CalibrationGateBasis) -> Result<MonitoredTrackingCamera, CalibrationGateError> {
    if basis.calibration_digest == [0;32] || basis.image_domain_digest == [0;32]
        || basis.camera == 0 || basis.calibration == 0 || basis.image_domain == 0 || basis.clock == 0
        || basis.checked_capture[0] > basis.checked_capture[1] {
        return Err(CalibrationGateError::InvalidInput);
    }
    if report.calibration != basis.calibration_digest
        || report.matches.query.image_domain != basis.image_domain_digest
        || camera.camera != basis.camera || camera.calibration != basis.calibration
        || camera.image_domain != basis.image_domain || camera.clock != basis.clock
        || basis.checked_capture[0] < camera.validity[0] || basis.checked_capture[1] > camera.validity[1]
        || report.matches.query.dimensions != camera.intrinsics.dimensions() {
        return Err(CalibrationGateError::BasisMismatch);
    }
    match report.disposition {
        CalibrationDisposition::ValidUnderPolicy => Ok(MonitoredTrackingCamera { camera, basis }),
        CalibrationDisposition::Invalidate => Err(CalibrationGateError::Invalidated),
        CalibrationDisposition::Indeterminate => Err(CalibrationGateError::Indeterminate),
    }
}

fn contains(outer:[u64;2], inner:[u64;2])->bool {
    inner[0] <= inner[1] && outer[0] <= inner[0] && inner[1] <= outer[1]
}

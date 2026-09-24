#![forbid(unsafe_code)]
//! Calibration-gated wrapper for observation-driven next-camera forecasts.

use crate::calibration_gate::{CalibrationGateError, MonitoredTrackingCamera};
use crate::observed_handoff::{
    DestinationHypothesis, ObservedForecastError, ObservedForecastOptions, ObservedHandoffForecast,
    forecast_to_feature,
};
use crate::stream::TrackSnapshot;
use crate::{PropertyTwin, SupportNetwork};
use fss_geometry::{HandoffCamera, WorkBudget};

/// One candidate view coupled to the exact currently monitored tracking snapshot.
pub struct MonitoredHandoffCamera<'view, 'monitor> {
    /// Candidate view to project the track into.
    pub view: HandoffCamera<'view>,
    /// Calibration monitor that must currently admit `view`.
    pub monitor: &'monitor MonitoredTrackingCamera,
}

/// Failure modes of the calibration-gated monitored forecast.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonitoredForecastError {
    /// A candidate view lacks a current admitted calibration receipt.
    Calibration(CalibrationGateError),
    /// The underlying observed forecast failed.
    Forecast(ObservedForecastError),
    /// The candidate camera list was empty or exceeded the 64-camera limit.
    Limit,
}
impl From<CalibrationGateError> for MonitoredForecastError {
    fn from(value: CalibrationGateError) -> Self {
        Self::Calibration(value)
    }
}
impl From<ObservedForecastError> for MonitoredForecastError {
    fn from(value: ObservedForecastError) -> Self {
        Self::Forecast(value)
    }
}
impl std::fmt::Display for MonitoredForecastError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Calibration(_) => "handoff camera lacks current admitted calibration",
            Self::Forecast(_) => "monitored handoff forecast failed",
            Self::Limit => "monitored handoff camera limit exceeded",
        })
    }
}
impl std::error::Error for MonitoredForecastError {}

/// Run the existing route/handoff model only after every candidate view has a current
/// calibration monitor receipt covering the latest source observation. The monitor does
/// not extend future validity: `forecast_to_feature` still clips each view to the frozen
/// TrackingCamera validity already owned by the track snapshot.
pub fn forecast_to_feature_monitored(
    twin: &PropertyTwin,
    network: &SupportNetwork,
    snapshot: TrackSnapshot<'_>,
    destination: DestinationHypothesis<'_>,
    cameras: &[MonitoredHandoffCamera<'_, '_>],
    options: ObservedForecastOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<ObservedHandoffForecast, MonitoredForecastError> {
    budget
        .charge(0)
        .map_err(|e| MonitoredForecastError::Forecast(e.into()))?;
    if cameras.is_empty() || cameras.len() > 64 {
        return Err(MonitoredForecastError::Limit);
    }
    let source_capture = snapshot.projection().observation().capture;
    let mut views = Vec::new();
    views
        .try_reserve_exact(cameras.len())
        .map_err(|_| MonitoredForecastError::Limit)?;
    for candidate in cameras {
        budget
            .charge(1)
            .map_err(|e| MonitoredForecastError::Forecast(e.into()))?;
        candidate
            .monitor
            .check_handoff_camera(candidate.view, source_capture)?;
        views.push(candidate.view);
    }
    Ok(forecast_to_feature(
        twin,
        network,
        snapshot,
        destination,
        &views,
        options,
        budget,
    )?)
}

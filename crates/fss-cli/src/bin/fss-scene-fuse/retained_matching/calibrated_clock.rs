#![forbid(unsafe_code)]
//! Bind original clock-query replay to the exact, currently adopted calibration.
//!
//! The calibration owner authenticates geometry and sensor adoption. The clock owner replays
//! declared search/validation observations, whose source custody remains unverified. Neither
//! operation activates a clock or upgrades the retained source clock basis.

use std::path::Path;

use fss_cli::clock_alignment::MAX_INPUT_BYTES;
use fss_cli::scene_rig::SceneRig;
use fss_geometry::WorkBudget;
use fss_reference::ingest::scene_calibration::RetainedSceneCalibration;
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::calibrated_input::MatchingQuery;
use super::images::PreparedImage;
use super::{Result, SOURCE_BYTES, input, input_error, read_input, temporal_clock, temporal_input};

pub(super) struct Replay {
    pub ready: temporal_clock::Ready,
    pub input_bytes: usize,
}

/// Authenticate every selected sensor without interpreting its original time as common time.
/// Legacy queries retain their existing additive-alignment preflight unchanged.
pub(super) fn preflight_sources(
    query: &MatchingQuery,
    deployment: &ReferenceDeployment,
    cx: &ReplayCx,
) -> Result<()> {
    if query.clock_validation().is_some() {
        super::preflight_views_with_clock(
            deployment,
            query.views(),
            cx,
            input::validate_capsule_identity,
        )
        .map(|_| ())
    } else {
        super::preflight_views(deployment, query.views(), cx)
    }
}

/// Reuse the native finite clock owner under the caller's work/cancellation account. All
/// source intervals and downstream time limits are checked before decoding any selected image.
pub(super) fn replay(
    query: &MatchingQuery,
    calibration: &RetainedSceneCalibration,
    rig: &SceneRig,
    images: &[PreparedImage],
    deployment: &ReferenceDeployment,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<Option<Replay>> {
    let MatchingQuery::Temporal(query) = query else {
        return Ok(None);
    };
    let Some(spec) = &query.clock_validation else {
        return Ok(None);
    };
    for binding in &spec.bindings {
        let camera = calibration
            .camera(binding.camera)
            .ok_or_else(|| input_error("clock camera is absent from the adopted calibration"))?;
        if binding.calibration_digest != calibration.calibration_identity()
            || binding.calibration_digest != camera.adoption().receipt.calibration_digest
            || binding.sensor != camera.adoption().receipt.sensor_id.as_str()
        {
            return Err(input_error(
                "clock camera calibration digest or sensor differs from the exact current adoption",
            ));
        }
    }
    let bytes = read_input(Path::new(&spec.path), MAX_INPUT_BYTES, cx)?;
    let ready = spec.replay(&bytes, &query.views, rig, images, work)?;
    let captures =
        super::preflight_views_with_clock(deployment, &query.views, cx, |view, capsule| {
            ready.capture(view, capsule)
        })?;
    temporal_input::validate_capture_policy(query, &captures, rig)?;
    Ok(Some(Replay {
        ready,
        input_bytes: bytes.len(),
    }))
}

/// Reserve the complete sidecar maximum from the existing aggregate source-read authority.
/// Source extraction and final revalidation share the same reduced, nonrenewable account.
pub(super) fn source_allowance(replayed: bool) -> u64 {
    if replayed {
        SOURCE_BYTES - MAX_INPUT_BYTES as u64
    } else {
        SOURCE_BYTES
    }
}

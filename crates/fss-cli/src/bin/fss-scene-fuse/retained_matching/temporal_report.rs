#![forbid(unsafe_code)]
//! Complete descriptor and moving-geometry diagnostics without source-owner authority.

use fss_cli::json_output::{array, object, string};
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_geometry::{GeometryError, WorkBudget};
use fss_twin::feature_association::DescriptorDecision;
use fss_twin::multiview_motion::{FusedSceneMotion, MotionFusionError};
use fss_twin::temporal_feature_association::{
    TemporalComponentOutcome, TemporalFeatureAssociation, TemporalFeatureComponent,
    TemporalFeatureDisposition, TemporalPairReference,
};

use crate::{Failure, Result, fail};

pub(super) struct GeometryReport {
    pub(super) json: String,
    pub(super) reconstructed: bool,
}

fn digest(value: [u8; 32]) -> String {
    string(&ContentDigest::new(DigestAlgorithm::Sha256, value).to_text())
}
fn time(value: u64) -> String {
    string(&value.to_string())
}
fn capture(value: [u64; 2]) -> String {
    array(&value.map(time))
}
fn vector<const N: usize>(value: [f64; N]) -> String {
    array(&value.map(|n| n.to_string()))
}
fn matrix<const N: usize>(value: [[f64; N]; N]) -> String {
    array(&value.map(vector))
}
fn reference(value: &TemporalPairReference) -> String {
    object(&[
        ("pair", value.pair.to_string()),
        ("decision", value.decision.to_string()),
    ])
}
fn references(values: &[TemporalPairReference]) -> String {
    array(&values.iter().map(reference).collect::<Vec<_>>())
}
fn distance(value: Option<u16>, missing: &str) -> String {
    match value {
        Some(value) => object(&[("state", string("available")), ("value", value.to_string())]),
        None => object(&[
            ("state", string("unavailable")),
            ("reason", string(missing)),
        ]),
    }
}
fn visibility(value: Option<bool>) -> String {
    string(match value {
        Some(true) => "nominal_segment_occluded",
        Some(false) => "nominal_segment_clear",
        None => "outside_image_or_range",
    })
}
fn trajectory(value: &FusedSceneMotion) -> String {
    let estimate = value.estimate();
    let views = estimate
        .residuals
        .iter()
        .zip(value.visibility())
        .map(|(residual, view)| {
            object(&[
                ("camera", time(view.camera)),
                ("exposure", time(view.exposure)),
                ("evidence_digest", digest(view.evidence)),
                ("capture_ns", capture(view.capture)),
                (
                    "nominal_capture_time_ns",
                    time(view.nominal_capture_time_ns),
                ),
                ("residual_pixels", residual.pixels.to_string()),
                ("visibility", visibility(view.nominal_occluded)),
            ])
        })
        .collect::<Vec<_>>();
    object(&[
        ("state", string("estimated")),
        ("kind", string("constant_velocity_trajectory")),
        ("reference_time_ns", time(value.request().reference_time_ns)),
        ("position", vector(estimate.position)),
        ("velocity_per_second", vector(estimate.velocity_per_second)),
        (
            "pixel_noise_covariance",
            matrix(estimate.pixel_noise_covariance),
        ),
        (
            "covariance_coordinates",
            string("x_y_z_vx_vy_vz_in_source_units_and_seconds"),
        ),
        (
            "normalized_condition_number",
            estimate.normalized_condition_number.to_string(),
        ),
        (
            "rms_reprojection_pixels",
            estimate.rms_reprojection_pixels.to_string(),
        ),
        (
            "observed_nominal_time_range_ns",
            array(
                &estimate
                    .observed_time_range_ns
                    .map(|n| string(&n.to_string())),
            ),
        ),
        ("capture_hull_ns", capture(value.capture_hull())),
        ("extrapolation", string("not_supported")),
        (
            "nominal_occlusion_conflict",
            value.has_nominal_occlusion_conflict().to_string(),
        ),
        ("views", array(&views)),
    ])
}

fn component(index: usize, value: &TemporalFeatureComponent) -> String {
    let members = value
        .members()
        .iter()
        .map(|member| {
            object(&[
                ("view", member.view.to_string()),
                ("camera", time(member.camera)),
                ("feature", time(member.feature)),
            ])
        })
        .collect::<Vec<_>>();
    let outcome = match value.outcome() {
        TemporalComponentOutcome::Unmatched => object(&[("state", string("unmatched"))]),
        TemporalComponentOutcome::ExposureConflict { views } => object(&[
            ("state", string("exposure_conflict")),
            (
                "views",
                array(&views.iter().map(usize::to_string).collect::<Vec<_>>()),
            ),
        ]),
        TemporalComponentOutcome::IncompletePairSupport { pairs } => object(&[
            ("state", string("incomplete_pair_support")),
            ("missing_pairs", references(pairs)),
        ]),
        TemporalComponentOutcome::InsufficientObservations => {
            object(&[("state", string("insufficient_observations"))])
        }
        TemporalComponentOutcome::InsufficientCameras => {
            object(&[("state", string("insufficient_cameras"))])
        }
        TemporalComponentOutcome::Fused(value) => trajectory(value),
        TemporalComponentOutcome::Refused(error) => {
            let reason = match error {
                MotionFusionError::Triangulation(inner) => format!("{error}: {inner}"),
                MotionFusionError::Twin(inner) => format!("{error}: {inner}"),
                _ => error.to_string(),
            };
            object(&[("state", string("refused")), ("reason", string(&reason))])
        }
    };
    object(&[
        ("index", index.to_string()),
        ("members", array(&members)),
        ("links", references(value.links())),
        ("evidence_digest", digest(value.evidence())),
        (
            "requested_scene_time_ns",
            time(value.requested_scene_time_ns()),
        ),
        ("capture_hull_ns", capture(value.capture_hull())),
        (
            "nominal_time_range_ns",
            capture(value.nominal_time_range_ns()),
        ),
        ("outcome", outcome),
    ])
}

fn work_failure(error: GeometryError) -> Failure {
    fail(
        if error == GeometryError::Cancelled {
            "ERR-SCENE-FUSION-CANCELLED-001"
        } else {
            "ERR-SCENE-FUSION-LIMIT-001"
        },
        error.to_string(),
    )
}

/// Render the complete bounded inventory; a small byte/work allowance never returns a prefix.
/// No pairwise static geometry is substituted for a motion fit at each observation's own time.
pub(super) fn compute(
    association: &TemporalFeatureAssociation,
    max_bytes: usize,
    work: &mut WorkBudget<'_>,
) -> Result<GeometryReport> {
    let pair_rows = association
        .pairs()
        .iter()
        .map(|p| p.pairs().len())
        .sum::<usize>();
    let pair_features = association
        .pairs()
        .iter()
        .map(|p| p.features().len())
        .sum::<usize>();
    let members = association
        .components()
        .iter()
        .map(|c| c.members().len())
        .sum::<usize>();
    let links = association
        .components()
        .iter()
        .map(|c| c.links().len())
        .sum::<usize>();
    let missing_links = association
        .components()
        .iter()
        .map(|c| match c.outcome() {
            TemporalComponentOutcome::IncompletePairSupport { pairs } => pairs.len(),
            _ => 0,
        })
        .sum::<usize>();
    // Native limits bound exposures<=16, inventory<=256, rows<=30,720 and each pair's
    // nearest ties<=128. Reserve long finite floats, all 6x6 covariances, residuals,
    // escaped strings and JSON construction copies independently of output capacity.
    work.charge(
        65_536
            + association.pairs().len() as u64 * 4096
            + pair_rows as u64 * 1024
            + pair_features as u64 * 8192
            + association.components().len() as u64 * 4096
            + members as u64 * 32_768
            + (links + missing_links) as u64 * 128,
    )
    .map_err(work_failure)?;

    let mut pairs = Vec::with_capacity(association.pairs().len());
    for (index, pair) in association.pairs().iter().enumerate() {
        work.charge(0).map_err(work_failure)?;
        let rows = pair
            .pairs()
            .iter()
            .map(|row| {
                object(&[
                    ("features", array(&row.features.map(time))),
                    ("hamming_distance", row.hamming_distance.to_string()),
                    (
                        "descriptor",
                        string(match row.descriptor {
                            DescriptorDecision::TooDistant => "too_distant",
                            DescriptorDecision::Ambiguous => "ambiguous",
                            DescriptorDecision::NonMutual => "non_mutual",
                            DescriptorDecision::Candidate => "candidate",
                        }),
                    ),
                ])
            })
            .collect::<Vec<_>>();
        let features = pair
            .features()
            .iter()
            .map(|row| {
                object(&[
                    ("view", row.view.to_string()),
                    ("feature", time(row.feature)),
                    (
                        "nearest_features",
                        array(
                            &row.nearest_features
                                .iter()
                                .copied()
                                .map(time)
                                .collect::<Vec<_>>(),
                        ),
                    ),
                    (
                        "best_hamming_distance",
                        distance(row.best_distance, "no_counterpart"),
                    ),
                    (
                        "runner_up_hamming_distance",
                        distance(row.runner_up_distance, "no_runner_up"),
                    ),
                    (
                        "disposition",
                        string(match row.disposition {
                            TemporalFeatureDisposition::NoCounterpart => "no_counterpart",
                            TemporalFeatureDisposition::TooDistant => "too_distant",
                            TemporalFeatureDisposition::Ambiguous => "ambiguous",
                            TemporalFeatureDisposition::NonMutual => "non_mutual",
                            TemporalFeatureDisposition::Selected => "selected",
                        }),
                    ),
                    (
                        "selected_pair",
                        match row.selected_pair {
                            Some(index) => object(&[
                                ("state", string("selected")),
                                ("decision", index.to_string()),
                            ]),
                            None => object(&[("state", string("not_selected"))]),
                        },
                    ),
                ])
            })
            .collect::<Vec<_>>();
        pairs.push(object(&[
            ("index", index.to_string()),
            ("views", array(&pair.views().map(|n| n.to_string()))),
            ("evidence_digest", digest(pair.evidence())),
            ("pairs", array(&rows)),
            ("feature_outcomes", array(&features)),
        ]));
    }
    let mut solved = 0;
    let mut unmatched = 0;
    let mut exposure_conflicts = 0;
    let mut incomplete_support = 0;
    let mut insufficient_observations = 0;
    let mut insufficient_cameras = 0;
    let mut refused = 0;
    let mut occlusion_conflicts = 0;
    let mut components = Vec::with_capacity(association.components().len());
    for (index, value) in association.components().iter().enumerate() {
        work.charge(0).map_err(work_failure)?;
        match value.outcome() {
            TemporalComponentOutcome::Unmatched => unmatched += 1,
            TemporalComponentOutcome::ExposureConflict { .. } => exposure_conflicts += 1,
            TemporalComponentOutcome::IncompletePairSupport { .. } => incomplete_support += 1,
            TemporalComponentOutcome::InsufficientObservations => insufficient_observations += 1,
            TemporalComponentOutcome::InsufficientCameras => insufficient_cameras += 1,
            TemporalComponentOutcome::Fused(value) => {
                solved += 1;
                occlusion_conflicts += usize::from(value.has_nominal_occlusion_conflict());
            }
            TemporalComponentOutcome::Refused(_) => refused += 1,
        }
        components.push(component(index, value));
    }
    let unresolved = exposure_conflicts
        + incomplete_support
        + insufficient_observations
        + insufficient_cameras
        + refused
        + occlusion_conflicts;
    let reconstructed = solved > 0 && unresolved == 0;
    let outcome = if solved == 0 {
        "no_reconstruction"
    } else if reconstructed {
        "reconstructed"
    } else {
        "reconstructed_with_refusals"
    };
    let cameras = association
        .views()
        .iter()
        .map(|v| v.camera.camera)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let json = object(&[
        ("outcome", string(outcome)),
        ("scene_evidence", digest(association.evidence())),
        (
            "requested_scene_time_ns",
            time(association.options().reference_time_ns),
        ),
        ("capture_hull_ns", capture(association.capture_hull())),
        (
            "time_policy",
            string("exact_requested_scene_time_within_each_fitted_component_nominal_support"),
        ),
        (
            "pair_geometry",
            string("not_applied_to_staggered_moving_observations"),
        ),
        ("exposure_pairs", array(&pairs)),
        ("components", array(&components)),
        (
            "counts",
            object(&[
                ("cameras", cameras.to_string()),
                ("exposures", association.views().len().to_string()),
                ("exposure_pairs", pairs.len().to_string()),
                ("features", members.to_string()),
                ("pair_rows", pair_rows.to_string()),
                ("pair_feature_outcomes", pair_features.to_string()),
                ("components", components.len().to_string()),
                ("links", links.to_string()),
                ("missing_links", missing_links.to_string()),
                ("solved", solved.to_string()),
                ("unmatched", unmatched.to_string()),
                ("exposure_conflicts", exposure_conflicts.to_string()),
                ("incomplete_support", incomplete_support.to_string()),
                (
                    "insufficient_observations",
                    insufficient_observations.to_string(),
                ),
                ("insufficient_cameras", insufficient_cameras.to_string()),
                ("refused", refused.to_string()),
                (
                    "nominal_occlusion_conflicts",
                    occlusion_conflicts.to_string(),
                ),
                ("unresolved", unresolved.to_string()),
            ]),
        ),
    ]);
    work.charge(0).map_err(work_failure)?;
    if json.len().checked_add(1).is_none_or(|n| n > max_bytes) {
        return Err(fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "complete temporal geometry exceeds output allowance",
        ));
    }
    Ok(GeometryReport {
        json,
        reconstructed,
    })
}

pub(super) fn assumptions() -> String {
    assumptions_with_clock(false)
}

pub(super) fn assumptions_with_clock(replayed: bool) -> String {
    array(
        &[
            "source_to_rig_mapping_and_raw_lens_parameters_are_operator_declarations",
            "native_rectification_preserves_original_exposure_and_source_mask_support",
            "camera_rig_is_authored_nominal_not_activated_or_physically_validated",
            "one_fixed_camera_mode_per_sensor_over_the_complete_capture_hull",
            if replayed { "replayed_frozen_clock_inventory_preserves_all_hypotheses_and_original_capture_intervals_without_activation" }
            else { "additive_clock_alignment_preserves_full_original_capture_intervals" },
            "constant_world_velocity_is_a_conditional_model_over_each_component",
            "descriptor_correspondence_is_a_hypothesis_not_physical_identity",
            "full_descriptor_competition_precedes_geometry_without_static_epipolar_gating",
            "complete_direct_pair_support_and_one_feature_per_exposure_are_required",
            "repeated_camera_observations_share_camera_calibration_and_failure_domains",
            "requested_scene_time_is_not_clamped_or_extrapolated",
            "all_component_observations_are_retained_without_outlier_removal",
            "pixel_covariance_excludes_interpolation_correlations_and_lens_parameter_error",
            "pixel_covariance_excludes_map_camera_clock_acceleration_and_correspondence_errors",
            "nominal_mesh_visibility_is_not_physical_coverage_or_evidence_of_absence",
            "current_privacy_and_original_source_custody_revalidate_after_complete_analysis",
        ]
        .map(string),
    )
}

#[cfg(test)]
#[path = "temporal_report_tests.rs"]
mod tests;

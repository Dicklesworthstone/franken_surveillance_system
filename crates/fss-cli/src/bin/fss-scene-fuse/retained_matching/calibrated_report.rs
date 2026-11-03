#![forbid(unsafe_code)]
//! Complete adopted-camera lineage and existing native geometry, without publication or I/O.

#[path = "calibrated_geometry.rs"]
mod native;

use fss_cli::json_output::{array, object, string};
use fss_cli::retained_continuity_query::authority_anchor_json;
use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_geometry::WorkBudget;
use fss_reference::ingest::scene_calibration::RetainedSceneCalibration;
use fss_reference::ingest::site_calibration::{CalibrationInput, FramePolicy, parameter_label};
use fss_twin::PropertyTwin;
use fss_twin::feature_association::FeatureView;
use fss_twin::localization::ImageIdentity;
use fss_twin::reconstruction_atlas::Reconstruction;

use super::calibrated_input::MatchingQuery;
use super::{Result, atlas_report, multiview, temporal_report};
use native::{GeometryPolicy, NativeGeometry, work_failure};

pub(super) struct GeometryReport {
    pub json: String,
    pub views: Vec<FeatureView>,
    pub reconstructed: bool,
    pub reference_time_ns: u64,
    pub capture_hull: [u64; 2],
    pub solved: usize,
    pub unresolved: usize,
    pub occlusion_conflicts: usize,
    // Keep the original immutable association for the native atlas producer. Serialized
    // coordinates or descriptors never become a replacement reconstruction input.
    association: NativeGeometry,
}

impl GeometryReport {
    /// Borrow exactly the native static result that produced this complete report.
    /// Constant-velocity fits cannot be promoted into enduring static landmarks.
    pub(super) fn static_reconstruction(&self) -> Result<Reconstruction<'_>> {
        match &self.association {
            NativeGeometry::Pair(value) => Ok(Reconstruction::Pair(value)),
            NativeGeometry::Multi(value) => Ok(Reconstruction::Multiview(value)),
            NativeGeometry::Temporal(_) => Err(super::input_error(
                "a moving-feature reconstruction cannot supply a static localization atlas",
            )),
        }
    }
}

fn digest(value: ContentDigest) -> String {
    string(&value.to_text())
}
fn raw_digest(value: [u8; 32]) -> String {
    digest(ContentDigest::new(DigestAlgorithm::Sha256, value))
}
fn count(value: u64) -> String {
    string(&value.to_string())
}
fn vector<const N: usize>(values: [f64; N]) -> String {
    array(&values.map(|value| value.to_string()))
}
fn matrix<const N: usize>(values: [[f64; N]; N]) -> String {
    array(&values.map(vector))
}
fn identity(value: ImageIdentity) -> String {
    object(&[
        ("exposure_digest", raw_digest(value.exposure)),
        ("pixel_digest", raw_digest(value.pixels)),
        ("image_domain_digest", raw_digest(value.image_domain)),
        (
            "dimensions",
            array(&value.dimensions.map(|value| value.to_string())),
        ),
    ])
}
fn interpretation(value: ComponentInterpretation) -> &'static str {
    match value {
        ComponentInterpretation::Grayscale => "grayscale",
        ComponentInterpretation::YCbCr => "ycbcr",
    }
}

/// Preserve every established native diagnostic while applying one explicit strict outcome.
pub(super) fn geometry(
    query: &MatchingQuery,
    twin: &PropertyTwin,
    views: &[FeatureView],
    maximum_bytes: usize,
    work: &mut WorkBudget<'_>,
) -> Result<GeometryReport> {
    let policy = match query {
        MatchingQuery::Pair(query) => GeometryPolicy::Pair(query.matching),
        MatchingQuery::Multi(query) => GeometryPolicy::Multi(query.matching),
        MatchingQuery::Temporal(query) => GeometryPolicy::Temporal(query.matching),
    };
    let analysis = native::analyze(policy, twin, views, work)?;
    let diagnostics = match &analysis.association {
        NativeGeometry::Pair(value) => {
            atlas_report::geometry(Reconstruction::Pair(value), maximum_bytes, work)
        }
        NativeGeometry::Multi(value) => {
            multiview::report::compute(value, maximum_bytes, work).map(|report| report.json)
        }
        NativeGeometry::Temporal(value) => {
            temporal_report::compute(value, maximum_bytes, work).map(|report| report.json)
        }
    };
    // Legacy static renderers classify all work refusals as limits. This command's
    // persistent deadline/cancellation probe retains its distinct refusal category.
    work.charge(0).map_err(work_failure)?;
    let diagnostics = diagnostics?;
    let json = native::envelope(query.kind(), &analysis, diagnostics, maximum_bytes, work)?;
    Ok(GeometryReport {
        json,
        views: analysis.views,
        reconstructed: analysis.reconstructed,
        reference_time_ns: analysis.reference_time_ns,
        capture_hull: analysis.capture_hull,
        solved: analysis.solved,
        unresolved: analysis.unresolved,
        occlusion_conflicts: analysis.occlusion_conflicts,
        association: analysis.association,
    })
}

fn frame_policy(value: Option<FramePolicy>) -> String {
    match value {
        None => "null".into(),
        Some(value) => object(&[
            ("decoder_digest", raw_digest(value.decoder)),
            (
                "extraction",
                object(&[
                    ("threshold", value.extraction.threshold.to_string()),
                    (
                        "maximum_features",
                        value.extraction.maximum_features.to_string(),
                    ),
                    ("separation", value.extraction.separation.to_string()),
                ]),
            ),
            ("tie_max_distance", value.tie_max_distance.to_string()),
            ("tie_ratio_percent", value.tie_ratio_percent.to_string()),
            ("tie_gate_px", value.tie_gate_px.to_string()),
        ]),
    }
}

/// Render the selected sealed current adoptions and their full candidate-calibration lineage.
/// Local covariance is retained verbatim and is never interpreted as an absolute error bound.
pub(super) fn calibration(
    owner: &RetainedSceneCalibration,
    work: &mut WorkBudget<'_>,
) -> Result<String> {
    let record = owner.record();
    let points =
        record.control_points.len() + record.tie_points.len() + record.excluded_points.len();
    // The sealed owner admits <=16 cameras and canonical candidate lists <=65,536 each.
    // Covariance blocks have <=13 parameters; the per-camera allowance covers every finite
    // decimal, complete parameter/fixed partition, original input, pose and adoption receipt.
    work.charge(65_536 + owner.cameras().len() as u64 * 262_144 + points as u64 * 128)
        .map_err(work_failure)?;
    let mut cameras = Vec::with_capacity(owner.cameras().len());
    for camera in owner.cameras() {
        work.charge(0).map_err(work_failure)?;
        let value = camera.record();
        let basis = camera.image_basis();
        let input = match value.input {
            CalibrationInput::Correspondences => object(&[
                ("kind", string("correspondences")),
                ("observation_file_digest", digest(value.observations)),
            ]),
            CalibrationInput::Frame(frame) => object(&[
                ("kind", string("jpeg_frame")),
                ("jpeg_digest", digest(value.observations)),
                ("metadata_digest", digest(frame.metadata)),
                ("luma_digest", digest(frame.luma)),
                (
                    "component_interpretation",
                    string(interpretation(frame.interpretation)),
                ),
                ("extracted_features", count(frame.extracted_features)),
                ("atlas_matches", count(frame.atlas_matches)),
                ("tie_observations", count(frame.tie_observations)),
            ]),
        };
        let covariance = if value.covariance_parameters.is_empty() {
            array(&[])
        } else {
            array(
                &value
                    .covariance
                    .chunks(value.covariance_parameters.len())
                    .map(|row| array(&row.iter().map(f64::to_string).collect::<Vec<_>>()))
                    .collect::<Vec<_>>(),
            )
        };
        cameras.push(object(&[
            ("camera", count(value.identity.camera)),
            ("camera_name", string(&value.name)),
            (
                "generation",
                object(&[
                    ("camera", count(value.identity.camera)),
                    ("intrinsics", count(value.identity.intrinsics)),
                    ("extrinsics", count(value.identity.extrinsics)),
                ]),
            ),
            (
                "sensor_id",
                string(camera.adoption().receipt.sensor_id.as_str()),
            ),
            ("status", string("adopted_current")),
            (
                "adoption",
                object(&[
                    ("receipt", camera.adoption().receipt.to_json()),
                    (
                        "committed_sequence",
                        count(camera.adoption().committed_sequence),
                    ),
                    ("effective_withdrawal", "null".into()),
                ]),
            ),
            (
                "original_image_basis",
                object(&[
                    ("image", identity(basis.image)),
                    ("input_digest", digest(basis.input_digest)),
                    (
                        "encoded_frame_digest",
                        basis.encoded_frame.map_or_else(|| "null".into(), digest),
                    ),
                    (
                        "component_interpretation",
                        basis
                            .interpretation
                            .map_or_else(|| "null".into(), |v| string(interpretation(v))),
                    ),
                ]),
            ),
            ("calibration_input", input),
            (
                "dimensions",
                array(&value.dimensions.map(|value| value.to_string())),
            ),
            ("intrinsics", vector(value.intrinsics)),
            ("radial_distortion", vector(value.distortion)),
            (
                "world_to_camera",
                object(&[
                    ("rotation", matrix(value.rotation)),
                    ("translation", vector(value.translation)),
                ]),
            ),
            (
                "absolute_calibration_error",
                object(&[("state", string("unknown"))]),
            ),
            (
                "local_covariance",
                object(&[
                    (
                        "scope",
                        string("conditional_camera_marginal_without_cross_camera_blocks"),
                    ),
                    (
                        "parameters",
                        array(
                            &value
                                .covariance_parameters
                                .iter()
                                .map(|p| string(parameter_label(*p)))
                                .collect::<Vec<_>>(),
                        ),
                    ),
                    ("matrix", covariance),
                    (
                        "fixed_parameters",
                        array(
                            &value
                                .fixed_parameters
                                .iter()
                                .map(|p| string(parameter_label(*p)))
                                .collect::<Vec<_>>(),
                        ),
                    ),
                ]),
            ),
            (
                "seed",
                object(&[
                    ("mode", string(value.mode.as_str())),
                    (
                        "sample",
                        value.seed_sample.map_or_else(|| "null".into(), count),
                    ),
                    ("candidate", count(value.seed_candidate)),
                    ("alternatives", count(value.seed_alternatives)),
                    ("inliers", count(value.seed_inliers)),
                    ("fit_rms_px", value.seed_fit_rms_px.to_string()),
                    ("intrinsics", vector(value.seed_intrinsics)),
                    ("rotation", matrix(value.seed_rotation)),
                    ("translation", vector(value.seed_translation)),
                ]),
            ),
            ("seed_rms_px", value.seed_rms_px.to_string()),
            ("refined_rms_px", value.refined_rms_px.to_string()),
            ("control_observations", count(value.control_observations)),
            ("free_observations", count(value.free_observations)),
        ]));
    }
    let point_ids = |values: &[u64]| array(&values.iter().copied().map(count).collect::<Vec<_>>());
    let json = object(&[
        ("resolution_digest", digest(owner.digest())),
        ("calibration_digest", digest(owner.calibration_identity())),
        (
            "calibration_file_digest",
            digest(owner.calibration_file_digest()),
        ),
        (
            "authority_anchor_at_resolution",
            authority_anchor_json(owner.anchor()),
        ),
        ("twin_package_digest", digest(owner.twin_package())),
        ("twin_source_digest", digest(owner.twin_source())),
        ("atlas_package_digest", digest(record.atlas_package)),
        ("atlas_fingerprint", raw_digest(record.atlas_fingerprint)),
        ("atlas_provenance_digest", digest(record.atlas_provenance)),
        (
            "descriptor_domain_digest",
            raw_digest(record.descriptor_domain),
        ),
        (
            "control_policy",
            match record.control_error_bound {
                None => object(&[("kind", string("all_used_atlas_landmarks_held_exact"))]),
                Some(bound) => object(&[
                    ("kind", string("declared_error_at_most")),
                    ("bound", bound.to_string()),
                ]),
            },
        ),
        ("initial_rms_px", record.initial_rms_px.to_string()),
        ("final_rms_px", record.final_rms_px.to_string()),
        ("iterations", count(record.iterations)),
        ("accepted_steps", count(record.accepted_steps)),
        ("convergence", string(&record.convergence)),
        (
            "observation_sigma_px",
            record.observation_sigma_px.to_string(),
        ),
        ("sigma_estimated", record.sigma_estimated.to_string()),
        ("control_points", point_ids(&record.control_points)),
        ("tie_points", point_ids(&record.tie_points)),
        ("excluded_points", point_ids(&record.excluded_points)),
        ("frame_policy", frame_policy(record.frame_policy)),
        (
            "joint_calibration_camera_generations",
            array(
                &record
                    .cameras
                    .iter()
                    .map(|camera| {
                        object(&[
                            ("camera", count(camera.identity.camera)),
                            ("intrinsics", count(camera.identity.intrinsics)),
                            ("extrinsics", count(camera.identity.extrinsics)),
                        ])
                    })
                    .collect::<Vec<_>>(),
            ),
        ),
        ("selected_cameras", array(&cameras)),
    ]);
    work.charge(0).map_err(work_failure)?;
    Ok(json)
}

pub(super) fn assumptions(kind: &str) -> String {
    let mut values = vec![
        "retained_adoption_is_owner_authority_not_a_physical_measurement_of_camera_currency",
        "current_calibration_adoption_and_withdrawal_are_revalidated_before_report_release",
        "all_original_source_ranges_and_current_privacy_are_revalidated_before_report_release",
        "camera_sensor_binding_and_both_calibration_generations_are_exact_retained_dependencies",
        "direct_pinhole_pixels_must_match_the_exact_original_calibration_image_domain_and_grid",
        "source_object_binding_clock_alignment_privacy_namespace_and_validity_interval_are_owner_declarations",
        "camera_absolute_error_is_unknown_and_never_inferred_from_fit_rms_or_covariance",
        "calibration_covariance_is_a_conditional_local_marginal_without_cross_camera_blocks",
        "scene_covariance_covers_declared_pixel_noise_not_calibration_map_lens_clock_or_motion_model_error",
        "shared_calibration_and_camera_errors_are_not_cancelled_or_counted_as_independent_evidence",
        "appearance_correspondences_are_conditional_hypotheses_not_physical_identity",
        "nominal_mesh_occlusion_conflicts_are_preserved_and_preclude_strict_success",
        "unmatched_isolated_features_remain_diagnostics_and_all_nontrivial_alternatives_remain_visible",
        "no_calibration_world_revision_event_identity_or_effect_is_activated_by_this_report",
    ];
    if kind == "temporal" {
        values.extend([
            "motion_is_constant_velocity_over_the_complete_capture_hull",
            "nominal_exposure_times_are_interval_midpoints_without_clock_or_rolling_shutter_estimation",
            "every_fitted_component_uses_the_requested_global_scene_time_and_must_bracket_it",
            "repeated_source_bytes_across_distinct_exposures_do_not_establish_independent_sensors",
        ]);
    } else {
        values.push("selected_features_are_stationary_over_the_complete_capture_hull");
        if kind == "static_multiview" {
            values.push("each_static_subset_solve_time_is_explicitly_clamped_to_its_capture_hull_under_the_full_hull_stationarity_assumption");
        }
    }
    array(&values.into_iter().map(string).collect::<Vec<_>>())
}

/// Explicit adopted-radial profile; the original pinhole assumption bytes remain unchanged.
pub(super) fn rectified_assumptions(kind: &str) -> String {
    let mut values = vec![
        "retained_adoption_is_owner_authority_not_a_physical_measurement_of_camera_currency",
        "current_calibration_adoption_and_withdrawal_are_revalidated_before_report_release",
        "all_original_source_ranges_and_current_privacy_are_revalidated_before_report_release",
        "camera_sensor_binding_and_both_calibration_generations_are_exact_retained_dependencies",
        "source_domain_refined_intrinsics_and_two_term_radial_model_come_only_from_the_exact_current_calibration",
        "native_rectification_target_is_the_exact_refined_original_camera_grid_without_crop_zoom_or_rotation_override",
        "nonzero_radial_sources_require_native_rectification_and_zero_radial_direct_sources_preserve_the_original_domain",
        "rectified_views_use_declared_radius_and_luma_transfer_not_calibration_measurements",
        "every_requested_lens_plan_is_admitted_before_source_decode_and_full_model_map_mask_and_image_receipts_are_preserved",
        "native_rectification_preserves_original_exposure_and_requires_all_positive_weight_privacy_taps_and_descriptor_support",
        "sigma_pixels_is_declared_on_the_actual_output_grid_and_excludes_interpolation_correlations_and_lens_parameter_error",
        "source_object_binding_clock_alignment_privacy_namespace_and_validity_interval_are_owner_declarations",
        "camera_absolute_error_is_unknown_and_never_inferred_from_fit_rms_or_covariance",
        "calibration_covariance_is_a_conditional_local_marginal_without_cross_camera_blocks",
        "scene_covariance_covers_declared_pixel_noise_not_calibration_map_lens_clock_or_motion_model_error",
        "shared_calibration_and_camera_errors_are_not_cancelled_or_counted_as_independent_evidence",
        "appearance_correspondences_are_conditional_hypotheses_not_physical_identity",
        "nominal_mesh_occlusion_conflicts_are_preserved_and_preclude_strict_success",
        "unmatched_isolated_features_remain_diagnostics_and_all_nontrivial_alternatives_remain_visible",
        "no_calibration_world_revision_event_identity_or_effect_is_activated_by_this_report",
    ];
    if kind == "temporal" {
        values.extend([
            "motion_is_constant_velocity_over_the_complete_capture_hull",
            "nominal_exposure_times_are_interval_midpoints_without_clock_or_rolling_shutter_estimation",
            "every_fitted_component_uses_the_requested_global_scene_time_and_must_bracket_it",
            "repeated_source_bytes_across_distinct_exposures_do_not_establish_independent_sensors",
        ]);
    } else {
        values.push("selected_features_are_stationary_over_the_complete_capture_hull");
        if kind == "static_multiview" {
            values.push("each_static_subset_solve_time_is_explicitly_clamped_to_its_capture_hull_under_the_full_hull_stationarity_assumption");
        }
    }
    array(&values.into_iter().map(string).collect::<Vec<_>>())
}

#![forbid(unsafe_code)]
//! Complete deterministic reports over the native geometry owners.

use fss_cli::{
    agent_json::{array, object, string},
    scene_rig::SceneRig,
};
use fss_core::ContentDigest;
use fss_geometry::{
    GeometryError, WorkBudget,
    temporal_triangulation::TemporalTriangulationError,
    triangulation::{TriangulationError, TriangulationOptions},
};
use fss_reference::ReplayCx;
use fss_twin::{
    PropertyTwin, ScaleEvidence, TwinError,
    multiview::{CommonPointMotion, FusedScenePoint, FusionError, FusionRequest, fuse_scene_point},
    multiview_motion::{
        FusedSceneMotion, MotionFusionError, MotionFusionRequest, fuse_scene_motion,
    },
};

use super::{
    Failure, Result, checkpoint,
    input::{Hypothesis, Motion, Observation, Query},
};

#[derive(Debug)]
pub(super) struct Report {
    pub json: String,
    pub all_solved: bool,
}
fn number(v: f64) -> String {
    v.to_string()
}
fn vector<const N: usize>(v: [f64; N]) -> String {
    array(&v.map(number))
}
fn matrix<const N: usize>(v: [[f64; N]; N]) -> String {
    array(&v.map(vector))
}
fn digest(v: [u8; 32]) -> String {
    let mut text = String::from("sha256:");
    use std::fmt::Write;
    for byte in v {
        let _ = write!(text, "{byte:02x}");
    }
    string(&text)
}
fn time(v: u64) -> String {
    string(&v.to_string())
}
fn capture(v: [u64; 2]) -> String {
    array(&v.map(time))
}
fn optional_number(value: Option<f64>, unknown: &str) -> String {
    match value {
        Some(value) => object(&[("state", string("declared")), ("value", number(value))]),
        None => object(&[("state", string("unknown")), ("reason", string(unknown))]),
    }
}
fn scale(value: ScaleEvidence) -> String {
    let (kind, factor, error) = match value {
        ScaleEvidence::Relative => ("relative", None, None),
        ScaleEvidence::Estimated {
            metres_per_unit,
            error,
        } => ("estimated", Some(metres_per_unit), error),
        ScaleEvidence::MeasuredAnchor {
            metres_per_unit,
            error,
        } => ("measured_anchor", Some(metres_per_unit), error),
    };
    object(&[
        ("kind", string(kind)),
        (
            "metres_per_unit",
            optional_number(factor, "relative world units"),
        ),
        (
            "error",
            optional_number(error, "scale error not quantified"),
        ),
        ("coordinates", string("source_world_units_unchanged")),
    ])
}
fn visibility(value: Option<bool>) -> String {
    object(&[
        (
            "state",
            string(match value {
                Some(true) => "nominally_occluded",
                Some(false) => "nominal_segment_clear",
                None => "projection_unavailable",
            }),
        ),
        ("scope", string("exact_imported_static_mesh_only")),
    ])
}
fn point_options(o: TriangulationOptions) -> String {
    object(&[
        ("min_views", o.min_views.to_string()),
        ("max_outliers", o.max_outliers.to_string()),
        ("max_reprojection_pixels", number(o.max_reprojection_pixels)),
        ("min_ray_angle_radians", number(o.min_ray_angle_radians)),
        ("max_distance", number(o.max_distance)),
        ("max_condition_number", number(o.max_condition_number)),
        ("max_iterations", o.max_iterations.to_string()),
    ])
}
fn motion(h: &Hypothesis) -> String {
    match h.motion {
        Motion::Static(o) => object(&[
            ("kind", string("static")),
            ("basis", string("caller_asserted_stationary_feature")),
            ("triangulation", point_options(o)),
        ]),
        Motion::Linear {
            velocity,
            evidence,
            options,
        } => object(&[
            ("kind", string("linear")),
            ("basis", string("externally_supplied_constant_velocity")),
            ("velocity_per_second", vector(velocity)),
            ("evidence", string(&evidence.to_text())),
            ("triangulation", point_options(options)),
        ]),
        Motion::InferLinear {
            max_capture_uncertainty_ns,
            options: o,
        } => object(&[
            ("kind", string("infer_linear")),
            (
                "basis",
                string("fit_constant_velocity_at_nominal_capture_midpoints"),
            ),
            (
                "max_capture_uncertainty_ns",
                time(max_capture_uncertainty_ns),
            ),
            (
                "triangulation",
                object(&[
                    ("max_reprojection_pixels", number(o.max_reprojection_pixels)),
                    ("max_distance", number(o.max_distance)),
                    ("max_speed", number(o.max_speed)),
                    ("max_condition_number", number(o.max_condition_number)),
                    ("max_iterations", o.max_iterations.to_string()),
                ]),
            ),
        ]),
    }
}
fn observation(row: &Observation) -> String {
    let input = row.input;
    let o = input.observation;
    object(&[
        ("source_digest", string(&row.source_digest.to_text())),
        ("evidence_digest", digest(o.evidence)),
        ("camera", time(o.camera)),
        ("track", time(o.track)),
        ("exposure", time(o.exposure)),
        ("image_domain", time(o.image_domain)),
        ("clock", time(o.clock)),
        ("calibration", time(input.camera.calibration)),
        ("privacy_domain", time(input.privacy_domain)),
        ("capture_ns", capture(o.capture)),
        ("pixel_min", vector(o.pixel_min)),
        ("pixel_max", vector(o.pixel_max)),
        ("visible_contact", o.visible_contact.to_string()),
        ("sigma_pixels", number(input.sigma_pixels)),
    ])
}
fn point(value: &FusedScenePoint) -> String {
    let e = value.estimate();
    let views: Vec<_> = e
        .residuals
        .iter()
        .zip(value.visibility())
        .zip(value.inputs())
        .map(|((r, v), input)| {
            object(&[
                ("camera", time(r.camera)),
                ("exposure", time(input.observation.exposure)),
                ("evidence_digest", digest(input.observation.evidence)),
                ("capture_ns", capture(input.observation.capture)),
                ("inlier", r.inlier.to_string()),
                (
                    "residual",
                    match r.pixels {
                        Some(pixels) => {
                            object(&[("state", string("projected")), ("pixels", number(pixels))])
                        }
                        None => object(&[
                            ("state", string("projection_unavailable")),
                            ("reason", string("behind_camera_or_outside_distance_bound")),
                        ]),
                    },
                ),
                ("visibility", visibility(v.nominal_occluded)),
            ])
        })
        .collect();
    object(&[
        ("state", string("estimated")),
        ("kind", string("point")),
        ("reference_time_ns", time(value.request().reference_time_ns)),
        ("position", vector(e.position)),
        ("pixel_noise_covariance", matrix(e.pixel_noise_covariance)),
        (
            "covariance_coordinates",
            string("x_y_z_in_source_world_units"),
        ),
        ("condition_number", number(e.condition_number)),
        ("rms_reprojection_pixels", number(e.rms_reprojection_pixels)),
        ("max_ray_angle_radians", number(e.max_ray_angle_radians)),
        ("capture_hull_ns", capture(value.capture_hull())),
        (
            "nominal_occlusion_conflict",
            value.has_nominal_occlusion_conflict().to_string(),
        ),
        ("views", array(&views)),
    ])
}
fn trajectory(value: &FusedSceneMotion) -> String {
    let e = value.estimate();
    let views: Vec<_> = e
        .residuals
        .iter()
        .zip(value.visibility())
        .map(|(r, v)| {
            object(&[
                ("camera", time(v.camera)),
                ("exposure", time(v.exposure)),
                ("evidence_digest", digest(v.evidence)),
                ("capture_ns", capture(v.capture)),
                (
                    "nominal_capture_time_ns",
                    string(&r.capture_time_ns.to_string()),
                ),
                ("inlier", "true".into()),
                (
                    "residual",
                    object(&[("state", string("projected")), ("pixels", number(r.pixels))]),
                ),
                ("visibility", visibility(v.nominal_occluded)),
            ])
        })
        .collect();
    object(&[
        ("state", string("estimated")),
        ("kind", string("constant_velocity_trajectory")),
        (
            "reference_time_ns",
            string(&e.reference_time_ns.to_string()),
        ),
        ("position", vector(e.position)),
        ("velocity_per_second", vector(e.velocity_per_second)),
        ("pixel_noise_covariance", matrix(e.pixel_noise_covariance)),
        (
            "covariance_coordinates",
            string("x_y_z_vx_vy_vz_in_source_units_and_seconds"),
        ),
        (
            "normalized_condition_number",
            number(e.normalized_condition_number),
        ),
        ("rms_reprojection_pixels", number(e.rms_reprojection_pixels)),
        (
            "observed_nominal_time_range_ns",
            array(&e.observed_time_range_ns.map(|n| string(&n.to_string()))),
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

pub(super) fn compute(
    twin: &PropertyTwin,
    rig: &SceneRig,
    query: &Query,
    rig_digest: ContentDigest,
    observations_digest: ContentDigest,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<Report> {
    let total_work = work.used() + work.remaining();
    let mut results = Vec::new();
    let mut solved = 0;
    for hypothesis in &query.hypotheses {
        checkpoint(cx, "scene_fusion:hypothesis")?;
        let inputs: Vec<_> = hypothesis.observations.iter().map(|r| r.input).collect();
        let before = work.used();
        let estimate = match hypothesis.motion {
            Motion::InferLinear {
                max_capture_uncertainty_ns,
                options,
            } => fuse_scene_motion(
                twin,
                &inputs,
                MotionFusionRequest {
                    association_evidence: hypothesis.association_evidence.bytes(),
                    privacy_domain: query.privacy_domain,
                    reference_time_ns: query.reference_time_ns,
                    max_capture_span_ns: hypothesis.max_capture_span_ns,
                    max_capture_uncertainty_ns,
                    triangulation: options,
                },
                work,
            )
            .map(|v| (trajectory(&v), v.has_nominal_occlusion_conflict()))
            .map_err(motion_failure),
            Motion::Static(options) | Motion::Linear { options, .. } => {
                let motion = match hypothesis.motion {
                    Motion::Linear {
                        velocity, evidence, ..
                    } => CommonPointMotion::Linear {
                        velocity,
                        evidence: evidence.bytes(),
                    },
                    _ => CommonPointMotion::Static,
                };
                fuse_scene_point(
                    twin,
                    &inputs,
                    FusionRequest {
                        association_evidence: hypothesis.association_evidence.bytes(),
                        privacy_domain: query.privacy_domain,
                        reference_time_ns: query.reference_time_ns,
                        max_capture_span_ns: hypothesis.max_capture_span_ns,
                        motion,
                        triangulation: options,
                    },
                    work,
                )
                .map(|v| (point(&v), v.has_nominal_occlusion_conflict()))
                .map_err(point_failure)
            }
        };
        let (outcome, knowledge, estimate) = match estimate {
            Ok((estimate, conflict)) => {
                solved += 1;
                (
                    "solved",
                    if conflict { "conflicted" } else { "estimated" },
                    estimate,
                )
            }
            Err(failure) => (
                "refused",
                "unknown",
                object(&[
                    ("state", string("unavailable")),
                    ("code", string(failure.code)),
                    ("reason", string(&failure.detail)),
                    (
                        "next_step",
                        string(
                            "review the retained observations, timing and geometric constraints; refine or split the hypothesis",
                        ),
                    ),
                ]),
            ),
        };
        results.push(object(&[
            ("id", string(&hypothesis.id)),
            ("outcome", string(outcome)),
            ("knowledge", string(knowledge)),
            (
                "association_evidence",
                string(&hypothesis.association_evidence.to_text()),
            ),
            ("motion", motion(hypothesis)),
            ("max_capture_span_ns", time(hypothesis.max_capture_span_ns)),
            (
                "observations",
                array(
                    &hypothesis
                        .observations
                        .iter()
                        .map(observation)
                        .collect::<Vec<_>>(),
                ),
            ),
            ("estimate", estimate),
            ("work_units", (work.used() - before).to_string()),
        ]));
    }
    let used_cameras: std::collections::BTreeSet<_> = query
        .hypotheses
        .iter()
        .flat_map(|h| h.observations.iter().map(|o| o.input.camera.camera))
        .collect();
    let cameras: Vec<_> = rig
        .cameras()
        .iter()
        .filter(|row| used_cameras.contains(&row.camera.camera))
        .map(|row| {
            let c = row.camera;
            let [width, height] = c.intrinsics.dimensions();
            let [fx, fy] = c.intrinsics.focal_lengths();
            let [cx, cy] = c.intrinsics.principal_point();
            object(&[
                ("camera", time(c.camera)),
                ("source_object_id", string(&row.source_object_id)),
                ("calibration", time(c.calibration)),
                ("image_domain", time(c.image_domain)),
                ("clock", time(c.clock)),
                ("privacy_domain", time(row.privacy_domain)),
                ("validity_ns", capture(c.validity)),
                ("status", string("authored_nominal")),
                ("calibration_error", object(&[("state", string("unknown"))])),
                (
                    "world_to_camera",
                    object(&[
                        ("rotation", matrix(c.pose.rotation())),
                        ("translation", vector(c.pose.translation())),
                    ]),
                ),
                (
                    "intrinsics",
                    object(&[
                        ("width", width.to_string()),
                        ("height", height.to_string()),
                        ("fx", number(fx)),
                        ("fy", number(fy)),
                        ("cx", number(cx)),
                        ("cy", number(cy)),
                        ("image_model", string("undistorted_pinhole")),
                    ]),
                ),
            ])
        })
        .collect();
    let (property, revision) = rig.geometry_basis();
    let all_solved = solved == results.len();
    let body = object(&[
        ("schema", string("fss.scene_fusion_report.v1")),
        (
            "outcome",
            string(if all_solved {
                "complete"
            } else {
                "complete_with_refusals"
            }),
        ),
        ("reference_time_ns", time(query.reference_time_ns)),
        ("clock", time(query.clock)),
        ("clock_evidence", string(&query.clock_evidence.to_text())),
        ("privacy_domain", time(query.privacy_domain)),
        (
            "basis",
            object(&[
                ("twin_digest", digest(twin.digest())),
                ("source_scene_digest", digest(twin.source_scene_digest())),
                ("camera_rig_digest", string(&rig_digest.to_text())),
                (
                    "camera_rig_semantic_digest",
                    string(&rig.digest().to_text()),
                ),
                (
                    "observations_digest",
                    string(&observations_digest.to_text()),
                ),
                (
                    "geometry_basis",
                    object(&[("property", time(property)), ("revision", time(revision))]),
                ),
                ("coordinate_frame", string("RH_Z_UP")),
                ("evaluation_scope", string(twin.evaluation_scope())),
                ("observation_epoch", string(twin.observation_epoch())),
                ("scale", scale(twin.scale())),
                (
                    "map_error",
                    optional_number(twin.geometry_error(), "map error not quantified"),
                ),
            ]),
        ),
        (
            "assumptions",
            object(&[
                (
                    "source_custody",
                    string("caller_supplied_handles_not_fetched_or_authenticated"),
                ),
                (
                    "correspondence",
                    string("caller_supplied_common_feature_hypotheses_not_person_identity"),
                ),
                (
                    "calibration",
                    string("authored_nominal_camera_rig_not_activated_or_physically_validated"),
                ),
                (
                    "time",
                    string("caller_supplied_capture_clock_mapping_and_intervals_not_receive_times"),
                ),
                (
                    "covariance_scope",
                    string("conditional_independent_isotropic_pixel_noise_only"),
                ),
                (
                    "covariance_excludes",
                    array(
                        &[
                            "camera_pose",
                            "intrinsics",
                            "clock",
                            "pixel_rectangle",
                            "correspondence",
                            "motion_model",
                            "rolling_shutter",
                            "shared_failure_modes",
                            "map_error",
                        ]
                        .map(string),
                    ),
                ),
                (
                    "scene_claim",
                    string(
                        "derived_hypotheses_in_one_frame_and_reference_time_no_world_publication",
                    ),
                ),
            ]),
        ),
        ("cameras", array(&cameras)),
        ("hypotheses", array(&results)),
        (
            "counts",
            object(&[
                ("total", results.len().to_string()),
                ("solved", solved.to_string()),
                ("refused", (results.len() - solved).to_string()),
            ]),
        ),
        (
            "work",
            object(&[
                ("limit", total_work.to_string()),
                ("used", work.used().to_string()),
                ("remaining", work.remaining().to_string()),
            ]),
        ),
    ]);
    let report_digest = ContentDigest::sha256(body.as_bytes());
    // The digest covers the complete deterministic report member, without self-reference.
    let json = object(&[
        ("report_digest", string(&report_digest.to_text())),
        ("report", body),
    ]);
    Ok(Report { json, all_solved })
}

fn geometry(error: GeometryError) -> &'static str {
    match error {
        GeometryError::BudgetExhausted => "work_budget_exhausted",
        GeometryError::Cancelled => "cancelled",
        GeometryError::LimitExceeded => "geometry_limit_exceeded",
        GeometryError::NonFinite => "nonfinite_geometry",
        GeometryError::OutOfRange => "geometry_out_of_range",
        GeometryError::InvalidSolverOptions => "invalid_solver_options",
        _ => "invalid_or_unavailable_geometry",
    }
}
fn twin(error: TwinError) -> &'static str {
    match error {
        TwinError::Geometry(e) => geometry(e),
        TwinError::Limit => "twin_limit_exceeded",
        TwinError::Basis => "twin_basis_mismatch",
        TwinError::Numeric => "invalid_numeric_input",
        TwinError::Unobservable => "unobservable",
        TwinError::Format => "invalid_twin_format",
        TwinError::Digest => "twin_digest_mismatch",
        TwinError::Reference => "invalid_twin_reference",
    }
}
fn point_failure(error: FusionError) -> Failure {
    let reason = match error {
        FusionError::Twin(e) => twin(e),
        FusionError::Basis => "camera_basis_or_validity_mismatch",
        FusionError::Observation => "invalid_observation",
        FusionError::DuplicateEvidence => "duplicate_source_evidence",
        FusionError::PrivacyDomain => "privacy_domain_mismatch",
        FusionError::CaptureWindow => "inadmissible_capture_window",
        FusionError::Motion => "invalid_motion_assumption",
        FusionError::ContactUnknown => "common_feature_not_visible",
        FusionError::Triangulation(e) => match e {
            TriangulationError::Geometry(e) => geometry(e),
            TriangulationError::InsufficientViews => "insufficient_views",
            TriangulationError::InvalidView => "invalid_view",
            TriangulationError::DuplicateCamera => "duplicate_camera",
            TriangulationError::WeakGeometry => "weak_geometry",
            TriangulationError::NoConsensus => "no_consensus",
            TriangulationError::AmbiguousConsensus => "ambiguous_consensus",
            TriangulationError::UnstableConsensus => "unstable_consensus",
            TriangulationError::NotConverged => "not_converged",
        },
    };
    super::fail("ERR-SCENE-FUSION-POINT-001", reason)
}
fn motion_failure(error: MotionFusionError) -> Failure {
    let reason = match error {
        MotionFusionError::Twin(e) => twin(e),
        MotionFusionError::Basis => "camera_basis_or_validity_mismatch",
        MotionFusionError::Observation => "invalid_observation",
        MotionFusionError::DuplicateEvidence => "duplicate_source_evidence",
        MotionFusionError::DuplicateExposure => "duplicate_camera_exposure",
        MotionFusionError::PrivacyDomain => "privacy_domain_mismatch",
        MotionFusionError::CaptureWindow => "inadmissible_capture_window_or_uncertainty",
        MotionFusionError::ContactUnknown => "common_feature_not_visible",
        MotionFusionError::Triangulation(e) => match e {
            TemporalTriangulationError::Geometry(e) => geometry(e),
            TemporalTriangulationError::InsufficientObservations => "insufficient_observations",
            TemporalTriangulationError::InsufficientCameras => "insufficient_cameras",
            TemporalTriangulationError::InvalidObservation => "invalid_observation",
            TemporalTriangulationError::DuplicateObservation => "duplicate_camera_time",
            TemporalTriangulationError::InvalidOptions => "invalid_solver_options",
            TemporalTriangulationError::InvalidTimeSpan => "invalid_time_span",
            TemporalTriangulationError::UnobservableMotion => "unobservable_motion",
            TemporalTriangulationError::NoConsensus => "no_consensus",
            TemporalTriangulationError::SpeedLimit => "speed_limit",
            TemporalTriangulationError::NotConverged => "not_converged",
        },
    };
    super::fail("ERR-SCENE-FUSION-MOTION-001", reason)
}

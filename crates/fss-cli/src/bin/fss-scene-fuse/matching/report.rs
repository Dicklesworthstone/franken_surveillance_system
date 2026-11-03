#![forbid(unsafe_code)]
//! Complete source-linked diagnostics, including every candidate and geometric refusal.

use fss_cli::json_output::{array, object, string};
use fss_cli::scene_rig::SceneRig;
use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_twin::feature_association::{
    DescriptorDecision, EpipolarDecision, FeatureAssociation, FeatureDisposition,
    FeatureHypothesisOutcome,
};
use fss_twin::multiview::FusedScenePoint;
use fss_twin::{PropertyTwin, ScaleEvidence};

use super::super::{Result, fail};
use super::input::Query;
use super::pipeline::Analysis;

pub(super) struct Report {
    pub json: String,
    pub reconstructed: bool,
}

fn digest(bytes: [u8; 32]) -> String {
    use std::fmt::Write;
    let mut text = String::from("sha256:");
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    string(&text)
}
fn time(value: u64) -> String {
    string(&value.to_string())
}
fn vector<const N: usize>(value: [f64; N]) -> String {
    array(&value.map(|n| n.to_string()))
}
fn matrix<const N: usize>(value: [[f64; N]; N]) -> String {
    array(&value.map(vector))
}
fn capture(value: [u64; 2]) -> String {
    array(&value.map(time))
}
fn metric(value: Option<f64>, missing: &str) -> String {
    match value {
        Some(value) => object(&[("state", string("available")), ("value", value.to_string())]),
        None => object(&[
            ("state", string("unavailable")),
            ("reason", string(missing)),
        ]),
    }
}
fn hypothesis(value: Option<usize>) -> String {
    match value {
        Some(value) => object(&[("state", string("attempted")), ("index", value.to_string())]),
        None => object(&[("state", string("not_selected"))]),
    }
}
pub(crate) fn point(value: &FusedScenePoint) -> String {
    let estimate = value.estimate();
    let views: Vec<_> = estimate
        .residuals
        .iter()
        .zip(value.visibility())
        .zip(value.inputs())
        .map(|((residual, visibility), input)| {
            object(&[
                ("camera", time(residual.camera)),
                ("evidence_digest", digest(input.observation.evidence)),
                ("capture_ns", capture(input.observation.capture)),
                ("pixel_min", vector(input.observation.pixel_min)),
                ("pixel_max", vector(input.observation.pixel_max)),
                ("inlier", residual.inlier.to_string()),
                (
                    "residual_pixels",
                    metric(residual.pixels, "projection_unavailable"),
                ),
                (
                    "visibility",
                    string(match visibility.nominal_occluded {
                        Some(true) => "nominally_occluded",
                        Some(false) => "nominal_segment_clear",
                        None => "projection_unavailable",
                    }),
                ),
            ])
        })
        .collect();
    object(&[
        ("state", string("estimated")),
        ("position", vector(estimate.position)),
        ("reference_time_ns", time(value.request().reference_time_ns)),
        (
            "pixel_noise_covariance",
            matrix(estimate.pixel_noise_covariance),
        ),
        (
            "covariance_coordinates",
            string("x_y_z_in_source_world_units"),
        ),
        ("condition_number", estimate.condition_number.to_string()),
        (
            "rms_reprojection_pixels",
            estimate.rms_reprojection_pixels.to_string(),
        ),
        (
            "max_ray_angle_radians",
            estimate.max_ray_angle_radians.to_string(),
        ),
        ("capture_hull_ns", capture(value.capture_hull())),
        (
            "nominal_occlusion_conflict",
            value.has_nominal_occlusion_conflict().to_string(),
        ),
        ("views", array(&views)),
    ])
}
pub(crate) fn scale(value: ScaleEvidence) -> String {
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
        ("metres_per_unit", metric(factor, "relative_world_units")),
        ("error", metric(error, "scale_error_not_quantified")),
        ("coordinates", string("source_world_units_unchanged")),
    ])
}

/// Complete shared association inventory. Callers reserve its bounded serialization work
/// before construction; no source authority is inferred by these rendering helpers.
pub(crate) struct AssociationRows {
    pub hypotheses: Vec<String>,
    pub pairs: Vec<String>,
    pub features: Vec<String>,
    pub solved: usize,
}

pub(crate) fn association_rows(association: &FeatureAssociation) -> AssociationRows {
    let mut solved = 0_usize;
    let hypotheses: Vec<_> = association
        .hypotheses()
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let outcome = match &row.outcome {
                FeatureHypothesisOutcome::Fused(value) => {
                    solved += 1;
                    point(value)
                }
                FeatureHypothesisOutcome::Refused(error) => object(&[
                    ("state", string("refused")),
                    ("reason", string(&error.to_string())),
                ]),
            };
            object(&[
                ("index", index.to_string()),
                ("features", array(&row.features.map(time))),
                ("evidence_digest", digest(row.evidence)),
                ("estimate", outcome),
            ])
        })
        .collect();
    let pairs: Vec<_> = association
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
                (
                    "epipolar",
                    string(match row.epipolar {
                        EpipolarDecision::Passed => "passed",
                        EpipolarDecision::OutsideGate => "outside_gate",
                        EpipolarDecision::Unobservable => "unobservable",
                    }),
                ),
                (
                    "epipolar_distance_pixels",
                    match row.epipolar_distance_pixels {
                        Some(distance) => {
                            object(&[("state", string("available")), ("values", vector(distance))])
                        }
                        None => object(&[("state", string("unobservable"))]),
                    },
                ),
                ("hypothesis", hypothesis(row.hypothesis)),
            ])
        })
        .collect();
    let features: Vec<_> = association
        .features()
        .iter()
        .map(|row| {
            object(&[
                ("camera", time(row.camera)),
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
                    metric(row.best_distance.map(f64::from), "no_counterpart"),
                ),
                (
                    "runner_up_hamming_distance",
                    metric(row.runner_up_distance.map(f64::from), "no_runner_up"),
                ),
                (
                    "disposition",
                    string(match row.disposition {
                        FeatureDisposition::NoCounterpart => "no_counterpart",
                        FeatureDisposition::TooDistant => "too_distant",
                        FeatureDisposition::Ambiguous => "ambiguous",
                        FeatureDisposition::NonMutual => "non_mutual",
                        FeatureDisposition::EpipolarRejected => "epipolar_rejected",
                        FeatureDisposition::EpipolarUnobservable => "epipolar_unobservable",
                        FeatureDisposition::Selected => "selected",
                    }),
                ),
                ("hypothesis", hypothesis(row.hypothesis)),
            ])
        })
        .collect();
    AssociationRows {
        hypotheses,
        pairs,
        features,
        solved,
    }
}

pub(super) fn compute(
    twin: &PropertyTwin,
    rig: &SceneRig,
    query: &Query,
    query_digest: ContentDigest,
    analysis: &Analysis,
    max_bytes: usize,
    work: &mut WorkBudget<'_>,
) -> Result<Report> {
    // Reserve the complete inventory's conservative serialization cost before
    // constructing it, independently of a caller's smaller output byte limit.
    // Pair rows are bounded; per-feature nearest lists can retain all128 peers.
    // This also covers an oversized report that must be refused in its entirety.
    let report_work = 65_536_u64
        + query.declarations.len() as u64 * 4
        + analysis.association.pairs().len() as u64 * 1024
        + analysis.association.features().len() as u64 * 8192
        + analysis.association.hypotheses().len() as u64 * 16_384;
    work.charge(report_work)
        .map_err(|e| fail("ERR-SCENE-FUSION-LIMIT-001", e.to_string()))?;
    let association = &analysis.association;
    let AssociationRows {
        hypotheses,
        pairs,
        features,
        solved,
    } = association_rows(association);
    let views: Vec<_> = association
        .views()
        .iter()
        .zip(analysis.diagnostics.iter())
        .map(|(view, diag)| {
            let camera = view.camera;
            let [width, height] = camera.intrinsics.dimensions();
            let [fx, fy] = camera.intrinsics.focal_lengths();
            let [cx, cy] = camera.intrinsics.principal_point();
            let selection = diag.selection;
            let receipt = diag.decode;
            let features: Vec<_> = view
                .frame
                .features()
                .iter()
                .map(|feature| {
                    let descriptor: Vec<_> = feature
                        .descriptor
                        .0
                        .iter()
                        .flat_map(|word| word.to_le_bytes())
                        .collect();
                    object(&[
                        ("feature", time(feature.id)),
                        ("pixel", vector(feature.pixel)),
                        (
                            "descriptor_digest",
                            string(&ContentDigest::sha256(&descriptor).to_text()),
                        ),
                    ])
                })
                .collect();
            object(&[
                ("camera", time(camera.camera)),
                (
                    "source_object_id",
                    string(
                        &rig.camera(camera.camera)
                            .map_or("", |row| row.source_object_id.as_str()),
                    ),
                ),
                ("calibration", time(camera.calibration)),
                ("image_domain", time(camera.image_domain)),
                ("clock", time(camera.clock)),
                ("privacy_domain", time(view.privacy_domain)),
                ("validity_ns", capture(camera.validity)),
                ("capture_ns", capture(view.capture)),
                ("sigma_pixels", view.sigma_pixels.to_string()),
                ("status", string("authored_nominal")),
                ("calibration_error", object(&[("state", string("unknown"))])),
                (
                    "world_to_camera",
                    object(&[
                        ("rotation", matrix(camera.pose.rotation())),
                        ("translation", vector(camera.pose.translation())),
                    ]),
                ),
                (
                    "intrinsics",
                    object(&[
                        ("width", width.to_string()),
                        ("height", height.to_string()),
                        ("fx", fx.to_string()),
                        ("fy", fy.to_string()),
                        ("cx", cx.to_string()),
                        ("cy", cy.to_string()),
                        ("image_model", string("undistorted_pinhole")),
                    ]),
                ),
                ("source_digest", digest(view.source_digest)),
                ("pixel_digest", digest(receipt.luma_sha256)),
                ("image_domain_digest", digest(view.image_domain_digest)),
                ("mapping_basis", digest(view.mapping_basis)),
                ("allowed_mask_digest", digest(view.allowed_mask_digest)),
                ("descriptor_domain", digest(view.frame.descriptor_domain())),
                (
                    "decoder",
                    object(&[
                        ("identity", digest(receipt.decoder)),
                        (
                            "component_interpretation",
                            string(match receipt.interpretation {
                                ComponentInterpretation::Grayscale => "grayscale",
                                ComponentInterpretation::YCbCr => "ycbcr",
                            }),
                        ),
                        ("mcus", receipt.mcus.to_string()),
                        ("entropy_blocks", receipt.entropy_blocks.to_string()),
                        ("restarts", receipt.restarts.to_string()),
                        ("metadata_segments", receipt.metadata_segments.to_string()),
                        ("metadata_bytes", receipt.metadata_bytes.to_string()),
                    ]),
                ),
                (
                    "selection",
                    object(&[
                        ("threshold", selection.threshold.to_string()),
                        ("maximum_features", selection.maximum_features.to_string()),
                        ("separation", selection.separation.to_string()),
                        ("tested_centers", selection.tested_centers.to_string()),
                        ("local_maxima", selection.local_maxima.to_string()),
                        ("selected", selection.selected.to_string()),
                        ("omitted", selection.omitted.to_string()),
                    ]),
                ),
                ("features", array(&features)),
            ])
        })
        .collect();
    let reconstructed = solved > 0 && solved == hypotheses.len();
    let options = association.options();
    let (property, revision) = rig.geometry_basis();
    let body = object(&[
        ("schema", string("fss.scene_feature_match_report.v1")),
        ("authority", string("derived_cognition_no_effect_authority")),
        ("physical_identity_established", "false".into()),
        (
            "outcome",
            string(if solved == 0 {
                "no_reconstruction"
            } else if reconstructed {
                "reconstructed"
            } else {
                "reconstructed_with_refusals"
            }),
        ),
        ("query_digest", string(&query_digest.to_text())),
        ("association_evidence", digest(association.evidence())),
        ("reference_time_ns", time(options.reference_time_ns)),
        ("capture_hull_ns", capture(association.capture_hull())),
        ("clock", time(options.clock)),
        ("clock_evidence", digest(options.clock_evidence)),
        ("privacy_domain", time(options.privacy_domain)),
        (
            "basis",
            object(&[
                ("twin_digest", digest(twin.digest())),
                ("source_scene_digest", digest(twin.source_scene_digest())),
                ("camera_rig_digest", digest(options.camera_rig_digest)),
                (
                    "camera_rig_semantic_digest",
                    string(&rig.digest().to_text()),
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
                    metric(twin.geometry_error(), "map_error_not_quantified"),
                ),
            ]),
        ),
        ("declarations", query.declarations.clone()),
        (
            "assumptions",
            object(&[
                (
                    "source_custody",
                    string("exact_local_jpeg_bytes_not_retained_deployment_custody"),
                ),
                (
                    "image_domain",
                    string("caller_declared_undistorted_pixels_orientation_and_rig_mapping"),
                ),
                (
                    "calibration",
                    string("authored_nominal_rig_not_activated_or_physically_validated"),
                ),
                (
                    "time",
                    string("caller_declared_common_capture_clock_not_packet_arrival"),
                ),
                (
                    "motion",
                    string("common_features_stationary_over_full_capture_hull"),
                ),
                (
                    "correspondence",
                    string("conditional_appearance_and_epipolar_hypotheses_not_physical_identity"),
                ),
                (
                    "privacy",
                    string("explicit_input_mask_policy_not_an_access_grant"),
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
                            "correspondence",
                            "motion",
                            "rolling_shutter",
                            "shared_failure_modes",
                            "map_error",
                        ]
                        .map(string),
                    ),
                ),
                (
                    "scene_claim",
                    string("derived_static_feature_points_no_world_publication"),
                ),
            ]),
        ),
        ("views", array(&views)),
        ("pairs", array(&pairs)),
        ("feature_outcomes", array(&features)),
        ("hypotheses", array(&hypotheses)),
        (
            "counts",
            object(&[
                ("features", features.len().to_string()),
                ("pairs", pairs.len().to_string()),
                ("selected", hypotheses.len().to_string()),
                ("solved", solved.to_string()),
                ("refused", (hypotheses.len() - solved).to_string()),
            ]),
        ),
        (
            "work",
            object(&[
                ("allowance", time(work.used() + work.remaining())),
                ("used", time(work.used())),
            ]),
        ),
    ]);
    let json = object(&[
        ("schema", string("fss.scene_feature_match.v1")),
        (
            "report_digest",
            string(&ContentDigest::sha256(body.as_bytes()).to_text()),
        ),
        ("report", body),
    ]);
    work.charge(0)
        .map_err(|e| fail("ERR-SCENE-FUSION-LIMIT-001", e.to_string()))?;
    if json.len().saturating_add(1) > max_bytes {
        return Err(fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "complete feature-match report exceeds output allowance",
        ));
    }
    Ok(Report {
        json,
        reconstructed,
    })
}

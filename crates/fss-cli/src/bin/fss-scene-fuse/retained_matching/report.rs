#![forbid(unsafe_code)]
//! Complete retained-source matching report, with final read costs outside its immutable analysis.

use fss_cli::json_output::{array, object, string};
use fss_cli::retained_continuity_query::{anchor_digest, authority_anchor_json};
use fss_cli::scene_rig::SceneRig;
use fss_core::{ContentDigest, LedgerAnchor};
use fss_geometry::WorkBudget;
use fss_reference::ingest::recorded_decode::video_budget::{
    RecordedVideoDecodeBudget, VIDEO_DECODE_SEPARATE_AXIS_POLICY, VIDEO_DECODE_WORK_MODEL,
};
use fss_reference::ingest::twin_localization::features::RecordedFeatures;
use fss_twin::PropertyTwin;
use fss_twin::feature_association::{FeatureAssociation, FeatureView};

use super::super::matching::report::{AssociationRows, association_rows, scale};
use super::super::{Result, fail};
use super::input::Query;

pub(super) struct Draft {
    analysis: String,
    reconstructed: bool,
}
pub(super) struct Report {
    pub json: String,
    pub reconstructed: bool,
}

fn digest(value: [u8; 32]) -> String {
    string(&ContentDigest::new(fss_core::DigestAlgorithm::Sha256, value).to_text())
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
fn interval(value: [u64; 2]) -> String {
    array(&value.map(time))
}
fn optional_digest(value: Option<ContentDigest>, missing: &str) -> String {
    match value {
        Some(value) => object(&[
            ("state", string("available")),
            ("digest", string(&value.to_text())),
        ]),
        None => object(&[("state", string(missing))]),
    }
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut result = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

fn view_json(view: &FeatureView, owner: &RecordedFeatures, rig: &SceneRig) -> String {
    let camera = view.camera;
    let [width, height] = camera.intrinsics.dimensions();
    let [fx, fy] = camera.intrinsics.focal_lengths();
    let [cx, cy] = camera.intrinsics.principal_point();
    let source = owner.source();
    let capsule = owner.capsule();
    let selection = owner.selection();
    let features: Vec<_> = view
        .frame
        .features()
        .iter()
        .map(|feature| {
            let descriptor: Vec<_> = feature
                .descriptor
                .0
                .iter()
                .flat_map(|w| w.to_le_bytes())
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
                rig.camera(camera.camera)
                    .map_or("", |r| r.source_object_id.as_str()),
            ),
        ),
        ("calibration", time(camera.calibration)),
        ("image_domain", time(camera.image_domain)),
        ("clock", time(camera.clock)),
        ("privacy_domain", time(view.privacy_domain)),
        ("validity_ns", interval(camera.validity)),
        ("capture_ns", interval(view.capture)),
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
        ("image_domain_digest", digest(view.image_domain_digest)),
        ("mapping_basis", digest(view.mapping_basis)),
        ("descriptor_domain", digest(view.frame.descriptor_domain())),
        ("allowed_mask_digest", digest(view.allowed_mask_digest)),
        ("feature_owner_digest", string(&owner.digest().to_text())),
        (
            "source",
            object(&[
                ("import_identity", string(&source.import_identity.to_text())),
                ("import_root", string(&source.import_root.to_text())),
                ("manifest_digest", string(&source.manifest.to_text())),
                (
                    "completion_anchor",
                    authority_anchor_json(&source.source_anchor),
                ),
                ("capsule_digest", string(&source.capsule.to_text())),
                (
                    "encoded_source_digest",
                    string(&source.encoded_source.to_text()),
                ),
                ("exposure_digest", string(&source.exposure.to_text())),
                ("pixel_digest", string(&source.luma.to_text())),
                ("segment", time(source.segment)),
                ("range_start", time(source.range_start)),
                ("range_count", time(source.range_count)),
                ("codec", string(source.codec)),
                (
                    "dimensions",
                    array(&source.dimensions.map(|n| n.to_string())),
                ),
                (
                    "capsule",
                    object(&[
                        ("capsule_id", string(capsule.capsule_id.as_str())),
                        ("sensor_id", string(capsule.sensor_id.as_str())),
                        ("stream_id", string(capsule.stream_id.as_str())),
                        ("sequence", time(capsule.sequence)),
                        (
                            "capture_ns",
                            array(&[
                                string(&capsule.capture.earliest.0.to_string()),
                                string(&capsule.capture.latest.0.to_string()),
                            ]),
                        ),
                        (
                            "receive_time_ns",
                            string(&capsule.receive_time.0.to_string()),
                        ),
                        ("clock_basis", string(capsule.clock_basis.as_str())),
                        ("source_bytes", time(capsule.source_bytes)),
                        ("frame_count", capsule.frame_count.to_string()),
                        ("gap_before", capsule.gap_before.to_string()),
                    ]),
                ),
                (
                    "decode_receipt_digest",
                    string(&source.decode_receipt.to_text()),
                ),
                (
                    "decode_publication_root",
                    optional_digest(source.decode_root, "not_published"),
                ),
                ("native_receipt_hex", string(&hex(owner.native_receipt()))),
                (
                    "mask_binding_digest",
                    string(&source.mask_binding.to_text()),
                ),
                (
                    "mask_policy",
                    optional_digest(source.mask_policy, "no_current_policy"),
                ),
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
}

pub(super) struct ReportInput<'a> {
    pub twin: &'a PropertyTwin,
    pub rig: &'a SceneRig,
    pub query: &'a Query,
    pub query_digest: ContentDigest,
    pub association: &'a FeatureAssociation,
    pub owners: &'a [RecordedFeatures; 2],
    pub entry_anchor: &'a LedgerAnchor,
    pub final_anchor: &'a LedgerAnchor,
}

pub(super) fn compute(
    input: ReportInput<'_>,
    max_bytes: usize,
    work: &mut WorkBudget<'_>,
) -> Result<Draft> {
    let ReportInput {
        twin,
        rig,
        query,
        query_digest,
        association,
        owners,
        entry_anchor,
        final_anchor,
    } = input;
    if owners
        .iter()
        .any(|owner| owner.native_receipt().len() > 16_384)
    {
        return Err(fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "native source receipt exceeds complete report bound",
        ));
    }
    let receipt_bytes = owners
        .iter()
        .map(|owner| owner.native_receipt().len() as u64)
        .sum::<u64>();
    work.charge(
        69_632
            + query.declarations.len() as u64 * 4
            + receipt_bytes * 8
            + association.pairs().len() as u64 * 1024
            + association.features().len() as u64 * 8192
            + association.hypotheses().len() as u64 * 16_384,
    )
    .map_err(|e| fail("ERR-SCENE-FUSION-LIMIT-001", e.to_string()))?;
    let AssociationRows {
        hypotheses,
        pairs,
        features,
        solved,
    } = association_rows(association);
    let reconstructed = solved > 0 && solved == hypotheses.len();
    let mut views = Vec::with_capacity(2);
    for view in association.views() {
        let index = query
            .views
            .iter()
            .position(|q| q.camera == view.camera.camera)
            .ok_or_else(|| {
                fail(
                    "ERR-SCENE-FUSION-INPUT-001",
                    "association camera has no source owner",
                )
            })?;
        views.push(view_json(view, &owners[index], rig));
    }
    let (property, revision) = rig.geometry_basis();
    let analysis = object(&[
        ("outcome", string(if solved == 0 { "no_reconstruction" } else if reconstructed {
            "reconstructed" } else { "reconstructed_with_refusals" })),
        ("authority", string("derived_cognition_no_effect_authority")),
        ("source_provenance", string("verified_retained_native_frames")),
        ("physical_identity_established", "false".into()),
        ("query_digest", string(&query_digest.to_text())),
        ("association_evidence", digest(association.evidence())),
        ("entry_anchor_digest", string(&anchor_digest(entry_anchor).to_text())),
        ("entry_anchor", authority_anchor_json(entry_anchor)),
        ("anchor_digest", string(&anchor_digest(final_anchor).to_text())),
        ("anchor", authority_anchor_json(final_anchor)),
        ("reference_time_ns", time(query.matching.reference_time_ns)),
        ("capture_hull_ns", interval(association.capture_hull())),
        ("clock", time(query.matching.clock)),
        ("clock_evidence", digest(query.matching.clock_evidence)),
        ("privacy_domain", time(query.matching.privacy_domain)),
        ("basis", object(&[
            ("twin_digest", digest(twin.digest())),
            ("source_scene_digest", digest(twin.source_scene_digest())),
            ("camera_rig_digest", digest(query.matching.camera_rig_digest)),
            ("camera_rig_semantic_digest", string(&rig.digest().to_text())),
            ("geometry_basis", object(&[("property", time(property)), ("revision", time(revision))])),
            ("coordinate_frame", string("RH_Z_UP")),
            ("evaluation_scope", string(twin.evaluation_scope())),
            ("observation_epoch", string(twin.observation_epoch())),
            ("scale", scale(twin.scale())),
            ("map_error", match twin.geometry_error() {
                Some(value) => object(&[("state", string("available")), ("value", value.to_string())]),
                None => object(&[("state", string("unavailable")), ("reason", string("map_error_not_quantified"))]),
            }),
        ])),
        ("declarations", query.declarations.clone()),
        ("assumptions", array(&[
            "source_to_rig_mapping_and_undistorted_pixel_domain_are_operator_declarations",
            "camera_rig_is_authored_nominal_not_activated_or_physically_validated",
            "additive_clock_alignment_is_declared_and_preserves_full_source_uncertainty",
            "common_scene_features_are_stationary_over_the_full_capture_hull",
            "appearance_and_epipolar_correspondences_are_hypotheses_not_physical_identity",
            "current_deployment_privacy_masks_exclude_full_descriptor_footprints",
            "pixel_noise_covariance_excludes_camera_map_clock_motion_and_correspondence_error",
            "retained_custody_does_not_establish_live_coverage_or_calibration_quality",
        ].map(string))),
        ("views", array(&views)), ("pairs", array(&pairs)),
        ("feature_outcomes", array(&features)), ("hypotheses", array(&hypotheses)),
        ("counts", object(&[("features", features.len().to_string()), ("pairs", pairs.len().to_string()),
            ("selected", hypotheses.len().to_string()), ("solved", solved.to_string()),
            ("refused", (hypotheses.len() - solved).to_string())])),
    ]);
    if analysis.len().checked_add(1).is_none_or(|n| n > max_bytes) {
        return Err(fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "complete retained matching analysis exceeds output allowance",
        ));
    }
    Ok(Draft {
        analysis,
        reconstructed,
    })
}

pub(super) fn finish(
    draft: Draft,
    work: &WorkBudget<'_>,
    source_bytes: u64,
    jpeg_work: u64,
    video: &RecordedVideoDecodeBudget,
    max_bytes: usize,
) -> Result<Report> {
    let body = object(&[
        (
            "schema",
            string("fss.scene_feature_match_retained_report.v1"),
        ),
        ("analysis", draft.analysis),
        (
            "cost",
            object(&[
                (
                    "geometry_work",
                    object(&[
                        ("allowance", time(work.used() + work.remaining())),
                        ("used", time(work.used())),
                    ]),
                ),
                (
                    "source_bytes",
                    object(&[
                        ("allowance", time(super::SOURCE_BYTES)),
                        ("used", time(source_bytes)),
                        ("includes_final_revalidation", "true".into()),
                    ]),
                ),
                (
                    "jpeg_work",
                    object(&[
                        ("allowance", time(super::JPEG_WORK)),
                        ("used", time(jpeg_work)),
                    ]),
                ),
                (
                    "video_admission",
                    object(&[
                        ("model", string(VIDEO_DECODE_WORK_MODEL)),
                        ("axis_policy", string(VIDEO_DECODE_SEPARATE_AXIS_POLICY)),
                        ("encoded_bytes_allowance", time(super::VIDEO_BYTES)),
                        ("encoded_bytes_used", time(video.encoded_bytes())),
                        ("coded_luma_allowance", time(super::VIDEO_LUMA)),
                        ("coded_luma_used", time(video.coded_luma_capacity())),
                    ]),
                ),
                (
                    "unmeasured",
                    array(&["cpu_time", "energy", "peak_memory"].map(string)),
                ),
            ]),
        ),
    ]);
    let json = object(&[
        ("schema", string("fss.scene_feature_match_retained.v1")),
        (
            "report_digest",
            string(&ContentDigest::sha256(body.as_bytes()).to_text()),
        ),
        ("report", body),
    ]);
    if json.len().checked_add(1).is_none_or(|n| n > max_bytes) {
        return Err(fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "complete retained matching report exceeds output allowance",
        ));
    }
    Ok(Report {
        json,
        reconstructed: draft.reconstructed,
    })
}

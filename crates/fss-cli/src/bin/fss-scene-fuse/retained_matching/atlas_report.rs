#![forbid(unsafe_code)]
//! Complete native atlas admission and reconstruction provenance; no source custody or I/O.

use fss_cli::json_output::{array, object, string};
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_geometry::WorkBudget;
use fss_twin::localization::ImageIdentity;
use fss_twin::multiview_feature_association::SceneFeature;
use fss_twin::reconstruction_atlas::{
    AtlasBuildReceipt, AtlasCandidateDisposition, LandmarkSelection, Reconstruction,
    ReconstructionKind,
};

use super::super::matching::report::{AssociationRows, association_rows};
use super::{Result, fail};

pub(super) fn digest(value: [u8; 32]) -> String {
    string(&ContentDigest::new(DigestAlgorithm::Sha256, value).to_text())
}
pub(super) fn count(value: u64) -> String {
    string(&value.to_string())
}
fn vector<const N: usize>(values: [f64; N]) -> String {
    array(&values.map(|v| v.to_string()))
}
fn interval(values: [u64; 2]) -> String {
    array(&values.map(count))
}
fn members(values: &[SceneFeature]) -> String {
    array(
        &values
            .iter()
            .map(|v| object(&[("camera", count(v.camera)), ("feature", count(v.feature))]))
            .collect::<Vec<_>>(),
    )
}
fn identity(value: ImageIdentity) -> String {
    object(&[
        ("exposure_digest", digest(value.exposure)),
        ("pixel_digest", digest(value.pixels)),
        ("image_domain_digest", digest(value.image_domain)),
        (
            "dimensions",
            array(&value.dimensions.map(|v| v.to_string())),
        ),
    ])
}
fn selection(value: LandmarkSelection) -> String {
    object(&[
        ("hypothesis", digest(value.hypothesis)),
        ("landmark", count(value.landmark)),
        ("physical_group", count(value.physical_group)),
        ("feature", value.feature.to_string()),
        ("enduring_static_basis", digest(value.enduring_static_basis)),
    ])
}

/// Every admitted and unselected candidate is retained, independently of archive membership.
pub(super) fn receipt(value: &AtlasBuildReceipt, work: &mut WorkBudget<'_>) -> Result<String> {
    work.charge(
        65_536
            + value.sources.len() as u64 * 4096
            + value.candidates.len() as u64 * 8192
            + value.landmarks.len() as u64 * 65_536,
    )
    .map_err(|e| fail("ERR-SCENE-FUSION-LIMIT-001", e.to_string()))?;
    let sources = value
        .sources
        .iter()
        .map(|v| {
            object(&[
                ("camera", count(v.camera)),
                ("source_record_digest", digest(v.source_record)),
                ("encoded_source_digest", digest(v.source_digest)),
                ("frame", identity(v.frame)),
                ("descriptor_domain_digest", digest(v.descriptor_domain)),
                ("allowed_mask_digest", digest(v.allowed_mask)),
                ("feature_count", v.feature_count.to_string()),
                ("included_in_archive", v.included.to_string()),
            ])
        })
        .collect::<Vec<_>>();
    let candidates = value
        .candidates
        .iter()
        .map(|v| {
            object(&[
                ("hypothesis", digest(v.hypothesis)),
                ("members", members(&v.members)),
                ("capture_hull_ns", interval(v.capture_hull)),
                ("solve_time_ns", count(v.solve_time_ns)),
                (
                    "disposition",
                    string(match v.disposition {
                        AtlasCandidateDisposition::Eligible => "eligible",
                        AtlasCandidateDisposition::Refused => "refused",
                        AtlasCandidateDisposition::Unmatched => "unmatched",
                        AtlasCandidateDisposition::CameraConflict => "camera_conflict",
                        AtlasCandidateDisposition::IncompleteCycleSupport => {
                            "incomplete_cycle_support"
                        }
                        AtlasCandidateDisposition::NominalOcclusionConflict => {
                            "nominal_occlusion_conflict"
                        }
                    }),
                ),
                (
                    "selection",
                    match v.selected_landmark {
                        Some(id) => {
                            object(&[("state", string("selected")), ("landmark", count(id))])
                        }
                        None => object(&[("state", string("not_selected"))]),
                    },
                ),
            ])
        })
        .collect::<Vec<_>>();
    let landmarks = value
        .landmarks
        .iter()
        .map(|v| {
            let residuals = v
                .residuals
                .iter()
                .map(|r| {
                    object(&[
                        ("camera", count(r.camera)),
                        ("inlier", r.inlier.to_string()),
                        (
                            "pixels",
                            match r.pixels {
                                Some(p) => object(&[
                                    ("state", string("available")),
                                    ("value", p.to_string()),
                                ]),
                                None => object(&[("state", string("unavailable"))]),
                            },
                        ),
                    ])
                })
                .collect::<Vec<_>>();
            object(&[
                ("selection", selection(v.selection)),
                ("landmark_evidence", digest(v.evidence)),
                ("members", members(&v.members)),
                ("position", vector(v.position)),
                ("absolute_error", object(&[("state", string("unknown"))])),
                (
                    "pixel_noise_covariance",
                    array(&v.pixel_noise_covariance.map(vector)),
                ),
                ("condition_number", v.condition_number.to_string()),
                (
                    "rms_reprojection_pixels",
                    v.rms_reprojection_pixels.to_string(),
                ),
                ("max_ray_angle_radians", v.max_ray_angle_radians.to_string()),
                ("residuals", array(&residuals)),
                ("capture_hull_ns", interval(v.capture_hull)),
                ("solve_time_ns", count(v.solve_time_ns)),
            ])
        })
        .collect::<Vec<_>>();
    let result = object(&[
        ("receipt_digest", digest(value.digest())),
        (
            "kind",
            string(match value.kind {
                ReconstructionKind::Pair => "pair",
                ReconstructionKind::Multiview => "multiview",
            }),
        ),
        ("twin_digest", digest(value.twin_digest)),
        ("association_evidence", digest(value.association_evidence)),
        (
            "requested_scene_time_ns",
            count(value.requested_scene_time_ns),
        ),
        ("capture_hull_ns", interval(value.capture_hull)),
        ("sources", array(&sources)),
        ("candidates", array(&candidates)),
        ("landmarks", array(&landmarks)),
        ("atlas_digest", digest(value.atlas_digest)),
    ]);
    work.charge(0)
        .map_err(|e| fail("ERR-SCENE-FUSION-LIMIT-001", e.to_string()))?;
    Ok(result)
}

/// Reuse the exact complete pair/component serializers, preserving unselected alternatives.
pub(super) fn geometry(
    reconstruction: Reconstruction<'_>,
    maximum_bytes: usize,
    work: &mut WorkBudget<'_>,
) -> Result<String> {
    match reconstruction {
        Reconstruction::Multiview(value) => {
            super::multiview::report::compute(value, maximum_bytes, work).map(|r| r.json)
        }
        Reconstruction::Pair(value) => {
            work.charge(
                65_536
                    + value.pairs().len() as u64 * 1024
                    + value.features().len() as u64 * 8192
                    + value.hypotheses().len() as u64 * 65_536,
            )
            .map_err(|e| fail("ERR-SCENE-FUSION-LIMIT-001", e.to_string()))?;
            let AssociationRows {
                hypotheses,
                pairs,
                features,
                solved,
            } = association_rows(value);
            let json = object(&[
                ("scene_evidence", digest(value.evidence())),
                (
                    "requested_scene_time_ns",
                    count(value.options().reference_time_ns),
                ),
                ("capture_hull_ns", interval(value.capture_hull())),
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
            ]);
            work.charge(0)
                .map_err(|e| fail("ERR-SCENE-FUSION-LIMIT-001", e.to_string()))?;
            if json.len().checked_add(1).is_none_or(|n| n > maximum_bytes) {
                return Err(fail(
                    "ERR-SCENE-FUSION-LIMIT-001",
                    "complete atlas geometry exceeds output allowance",
                ));
            }
            Ok(json)
        }
    }
}

pub(super) fn assumptions() -> String {
    array(&[
        "atlas_is_a_derived_candidate_and_does_not_activate_calibration",
        "enduring_static_eligibility_and_twin_feature_assignments_are_explicit_owner_declarations",
        "physical_groups_are_declared_alias_groups_not_authenticated_object_identity",
        "all_selected_landmark_member_views_and_actual_native_descriptors_are_preserved",
        "capture_window_stationarity_does_not_establish_enduring_landmark_stability",
        "source_camera_poses_and_image_models_remain_the_original_rig_declarations",
        "absolute_landmark_error_remains_unknown_and_is_not_derived_from_pixel_covariance",
        "reconstruction_pixel_covariance_excludes_shared_camera_map_lens_clock_and_correspondence_error",
        "archive_checksums_do_not_grant_source_access_or_establish_future_source_privacy",
        "reference_exposures_are_not_independent_localization_validation_observations",
        "coordinates_remain_in_the_exact_twin_source_units_and_scale_basis",
    ].map(string))
}

#[cfg(test)]
#[path = "atlas_report_tests.rs"]
mod tests;

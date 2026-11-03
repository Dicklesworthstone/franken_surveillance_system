#![forbid(unsafe_code)]
//! Exact original and derived image coordinates for versioned retained scene reports.

use fss_cli::json_output::{array, object, string};
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_geometry::PinholeIntrinsics;
use fss_twin::localization::ImageIdentity;
use fss_twin::rectification::{LensDistortion, LumaRange, RectificationReceipt, RectificationSpec};

/// Conservative complete serialization/copy allowance for one finite model and receipt.
pub(super) const VIEW_WORK: u64 = 65_536;

fn digest(value: [u8; 32]) -> String {
    string(&ContentDigest::new(DigestAlgorithm::Sha256, value).to_text())
}
fn vector<const N: usize>(values: [f64; N]) -> String {
    array(&values.map(|v| v.to_string()))
}
fn dimensions(values: [u32; 2]) -> String {
    array(&values.map(|v| v.to_string()))
}
fn range(value: LumaRange) -> String {
    string(match value {
        LumaRange::Full => "full",
        LumaRange::Video => "video",
    })
}
fn intrinsics(value: PinholeIntrinsics) -> String {
    let [width, height] = value.dimensions();
    let [fx, fy] = value.focal_lengths();
    let [cx, cy] = value.principal_point();
    object(&[
        ("width", width.to_string()),
        ("height", height.to_string()),
        ("fx", fx.to_string()),
        ("fy", fy.to_string()),
        ("cx", cx.to_string()),
        ("cy", cy.to_string()),
    ])
}
fn lens(value: LensDistortion) -> String {
    match value {
        LensDistortion::Pinhole => object(&[("kind", string("pinhole"))]),
        LensDistortion::BrownConrady { radial, tangential } => object(&[
            ("kind", string("brown_conrady")),
            ("radial", vector(radial)),
            ("tangential", vector(tangential)),
        ]),
        LensDistortion::Fisheye { coefficients } => object(&[
            ("kind", string("fisheye")),
            ("coefficients", vector(coefficients)),
        ]),
    }
}
fn identity(value: ImageIdentity) -> String {
    object(&[
        ("exposure_digest", digest(value.exposure)),
        ("pixel_digest", digest(value.pixels)),
        ("image_domain_digest", digest(value.image_domain)),
        ("dimensions", dimensions(value.dimensions)),
    ])
}

/// Render the complete immutable derivation after the source binder has verified both grids.
/// The original native codec receipt remains in the enclosing view's source object.
pub(super) fn processing(
    output: ImageIdentity,
    allowed_mask: [u8; 32],
    rectification: Option<(RectificationSpec, RectificationReceipt)>,
) -> String {
    let Some((spec, receipt)) = rectification else {
        return object(&[
            ("kind", string("native_pinhole")),
            ("output", identity(output)),
            ("allowed_mask_digest", digest(allowed_mask)),
        ]);
    };
    let source = receipt.source;
    object(&[
        ("kind", string("native_rectified")),
        (
            "model",
            object(&[
                ("source_intrinsics", intrinsics(spec.source)),
                ("target_intrinsics", intrinsics(spec.target)),
                ("source_domain_digest", digest(spec.source_domain)),
                ("lens_basis", digest(spec.calibration)),
                ("distortion", lens(spec.distortion)),
                ("maximum_radius", spec.maximum_radius.to_string()),
                ("luma_range", range(spec.range)),
            ]),
        ),
        (
            "source",
            object(&[
                ("exposure_digest", digest(source.exposure)),
                ("storage_digest", digest(source.storage)),
                ("allowed_mask_digest", digest(source.allowed_mask)),
                ("image_domain_digest", digest(source.image_domain)),
                ("lens_basis", digest(source.calibration)),
                ("dimensions", dimensions(source.dimensions)),
                ("row_stride", source.row_stride.to_string()),
                ("luma_range", range(source.range)),
            ]),
        ),
        ("output", identity(output)),
        ("map_digest", digest(receipt.map_digest)),
        ("allowed_mask_digest", digest(allowed_mask)),
        (
            "coverage",
            object(&[
                ("mapped", receipt.coverage.mapped.to_string()),
                (
                    "outside_lens_domain",
                    receipt.coverage.outside_lens_domain.to_string(),
                ),
                (
                    "outside_source",
                    receipt.coverage.outside_source.to_string(),
                ),
                ("allowed_pixels", receipt.allowed_pixels.to_string()),
                ("privacy_rejected", receipt.privacy_rejected.to_string()),
            ]),
        ),
        (
            "sampling",
            string("native_backward_q16_bilinear_q32_half_up"),
        ),
        ("range_expansion", string("before_interpolation")),
        ("output_luma_range", string("full")),
        ("source_exposure_preserved", "true".into()),
        ("calibration_established", "false".into()),
    ])
}

pub(super) fn assumptions(multiview: bool) -> String {
    let mut values = vec![
        "source_to_rig_mapping_and_image_models_are_operator_declarations",
        "lens_basis_and_luma_transfer_do_not_establish_measured_calibration",
        "rectified_target_intrinsics_come_from_the_exact_camera_rig",
        "native_rectification_derives_output_domain_and_preserves_original_exposure",
        "all_positive_weight_source_privacy_taps_and_full_descriptor_footprints_are_required",
        "camera_rig_is_authored_nominal_not_activated_or_physically_validated",
        "additive_clock_alignment_is_declared_and_preserves_full_source_uncertainty",
        "common_scene_features_are_stationary_over_the_full_capture_hull",
        "appearance_and_epipolar_correspondences_are_hypotheses_not_physical_identity",
    ];
    if multiview {
        values.extend([
            "subset_solve_time_is_requested_scene_time_clamped_to_subset_capture_hull",
            "complete_direct_pair_support_is_required_for_joint_components",
            "unresolved_components_preserve_pair_alternatives_without_identity_assignment",
            "all_participating_component_views_are_required_with_no_outlier_removal",
        ]);
    }
    values.extend([
        "sigma_pixels_is_declared_on_the_actual_output_grid",
        "pixel_noise_covariance_excludes_interpolation_correlations_and_lens_parameter_error",
        "pixel_noise_covariance_excludes_camera_map_clock_motion_and_correspondence_error",
        "retained_custody_does_not_establish_live_coverage_or_calibration_quality",
    ]);
    array(&values.into_iter().map(string).collect::<Vec<_>>())
}

#[cfg(test)]
#[path = "image_report_tests.rs"]
mod tests;

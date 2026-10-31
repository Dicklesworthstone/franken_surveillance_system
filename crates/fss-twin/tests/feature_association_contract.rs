#![forbid(unsafe_code)]
//! Independent stereo geometry, native image extraction and refusal controls.
mod common;

use fss_core::ContentDigest;
use fss_geometry::triangulation::{TriangulationError, TriangulationOptions};
use fss_geometry::{GeometryBasis, GeometryError, PinholeIntrinsics, RigidPose, WorkBudget};
use fss_twin::feature_association::*;
use fss_twin::localization::native::{ExtractionOptions, GrayImage, extract_gray};
use fss_twin::localization::{BinaryDescriptor, FeatureFrame, ImageFeature, ImageIdentity};
use fss_twin::multiview::FusionError;
use fss_twin::{ProjectionError, PropertyTwin, TrackingCamera};
use std::error::Error;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

type Test = Result<(), Box<dyn Error>>;
const WORK: u64 = 100_000_000;
const WIDTH: u32 = 192;
const HEIGHT: u32 = 128;
const ROTATION: [[f64; 3]; 3] = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];

fn options() -> AssociationOptions {
    AssociationOptions {
        association_basis: [9; 32],
        camera_rig_digest: [10; 32],
        privacy_domain: 2,
        clock: 1,
        clock_evidence: [8; 32],
        reference_time_ns: 100,
        max_capture_span_ns: 20,
        maximum_hamming_distance: 64,
        ratio_percent: 80,
        maximum_epipolar_distance_pixels: 0.25,
        triangulation: TriangulationOptions::default(),
    }
}
fn frame(camera: u8, features: Vec<ImageFeature>) -> Result<FeatureFrame, Box<dyn Error>> {
    Ok(FeatureFrame::new(
        ImageIdentity {
            exposure: [camera; 32],
            pixels: [camera + 10; 32],
            image_domain: [camera + 20; 32],
            dimensions: [WIDTH, HEIGHT],
        },
        [77; 32],
        features,
        &mut WorkBudget::new(WORK),
    )?)
}
fn feature(id: u64, pixel: [f64; 2], descriptor: [u64; 4]) -> ImageFeature {
    ImageFeature {
        id,
        pixel,
        descriptor: BinaryDescriptor(descriptor),
    }
}
fn view(
    twin: &PropertyTwin,
    camera: u8,
    frame: FeatureFrame,
) -> Result<FeatureView, Box<dyn Error>> {
    Ok(FeatureView {
        image_domain_digest: frame.identity().image_domain,
        frame,
        camera: TrackingCamera {
            geometry: twin.basis(),
            camera: u64::from(camera),
            calibration: 1,
            image_domain: u64::from(camera) + 20,
            clock: 1,
            validity: [0, 1000],
            pose: RigidPose::from_center(ROTATION, [f64::from(camera) - 1.0, 0.0, 0.0])?,
            intrinsics: PinholeIntrinsics::new(WIDTH, HEIGHT, 120.0, 120.0, 96.0, 64.0)?,
            error: Some(ProjectionError::EXACT),
        },
        source_digest: [camera + 30; 32],
        allowed_mask_digest: [camera + 40; 32],
        mapping_basis: [camera + 50; 32],
        privacy_domain: 2,
        clock_evidence: [8; 32],
        capture: [90, 110],
        sigma_pixels: 0.5,
    })
}
fn basic_views(twin: &PropertyTwin) -> Result<[FeatureView; 2], Box<dyn Error>> {
    Ok([
        view(
            twin,
            1,
            frame(
                1,
                vec![
                    feature(11, [96.0, 64.0], [0; 4]),
                    feature(22, [120.0, 80.0], [u64::MAX; 4]),
                ],
            )?,
        )?,
        view(
            twin,
            2,
            frame(
                2,
                vec![
                    feature(31, [84.0, 64.0], [0; 4]),
                    feature(42, [108.0, 80.0], [u64::MAX; 4]),
                ],
            )?,
        )?,
    ])
}
fn run(
    twin: &PropertyTwin,
    views: &[FeatureView; 2],
) -> Result<FeatureAssociation, AssociationError> {
    associate_features(
        twin,
        [&views[0], &views[1]],
        options(),
        &mut WorkBudget::new(WORK),
    )
}
fn replace_features(view: &mut FeatureView, features: Vec<ImageFeature>) -> Test {
    view.frame = FeatureFrame::new(
        view.frame.identity(),
        view.frame.descriptor_domain(),
        features,
        &mut WorkBudget::new(WORK),
    )?;
    Ok(())
}
fn replace_identity(view: &mut FeatureView, identity: ImageIdentity) -> Test {
    view.frame = FeatureFrame::new(
        identity,
        view.frame.descriptor_domain(),
        view.frame.features().to_vec(),
        &mut WorkBudget::new(WORK),
    )?;
    Ok(())
}
fn fused_positions(report: &FeatureAssociation) -> Vec<[f64; 3]> {
    report
        .hypotheses()
        .iter()
        .filter_map(|h| match &h.outcome {
            FeatureHypothesisOutcome::Fused(point) => Some(point.estimate().position),
            FeatureHypothesisOutcome::Refused(_) => None,
        })
        .collect()
}

#[test]
fn automatic_pair_selection_recovers_independent_stereo_positions_and_full_inventory() -> Test {
    let twin = common::twin(&[-20.0], Some(0.0))?;
    let views = basic_views(&twin)?;
    let report = run(&twin, &views)?;
    assert_eq!(report.pairs().len(), 4);
    assert_eq!(report.features().len(), 4);
    assert_eq!(report.hypotheses().len(), 2);
    assert_eq!(report.capture_hull(), [90, 110]);
    assert_eq!(report.options(), options());
    assert!(
        report
            .features()
            .iter()
            .all(|f| f.disposition == FeatureDisposition::Selected)
    );
    let positions = fused_positions(&report);
    assert_eq!(positions.len(), 2);
    // Independent rectified-stereo formula: z = focal*baseline/disparity,
    // x = (u-cx)*z/focal, y = (v-cy)*z/focal. No production projection is used.
    for (actual, expected) in positions
        .iter()
        .zip([[0.0, 0.0, 10.0], [2.0, 4.0 / 3.0, 10.0]])
    {
        for axis in 0..3 {
            assert!((actual[axis] - expected[axis]).abs() < 1e-9);
        }
    }
    for hypothesis in report.hypotheses() {
        let FeatureHypothesisOutcome::Fused(point) = &hypothesis.outcome else {
            return Err("expected fitted hypothesis".into());
        };
        assert_eq!(point.twin_digest(), twin.digest());
        assert_eq!(point.capture_hull(), [90, 110]);
        assert_eq!(point.request().association_evidence, hypothesis.evidence);
        assert_eq!(point.inputs().len(), 2);
        assert_eq!(point.visibility().len(), 2);
        assert!(!point.has_nominal_occlusion_conflict());
        assert!(
            point
                .estimate()
                .pixel_noise_covariance
                .iter()
                .flatten()
                .all(|x| x.is_finite())
        );
    }
    assert_eq!(report.pairs()[1].descriptor, DescriptorDecision::TooDistant);
    assert_eq!(report.pairs()[2].descriptor, DescriptorDecision::TooDistant);
    Ok(())
}

#[test]
fn rotated_oblique_camera_and_distinct_intrinsics_follow_independent_projection_oracle() -> Test {
    let twin = common::twin(&[-20.0], None)?;
    let mut views = basic_views(&twin)?;
    let (sine, cosine) = 0.2_f64.sin_cos();
    views[1].camera.pose = RigidPose::from_center(
        [[cosine, 0.0, sine], [0.0, 1.0, 0.0], [-sine, 0.0, cosine]],
        [1.0, 1.0, 0.5],
    )?;
    views[1].camera.intrinsics = PinholeIntrinsics::new(WIDTH, HEIGHT, 150.0, 90.0, 80.0, 50.0)?;
    // Independent pinhole formulas for this yaw and translated center, without
    // production project(), ray(), matrix operations or epipolar implementation.
    let project = |world: [f64; 3]| {
        let [x, y, z] = [world[0] - 1.0, world[1] - 1.0, world[2] - 0.5];
        let horizontal = cosine * x + sine * z;
        let depth = -sine * x + cosine * z;
        [150.0 * horizontal / depth + 80.0, 90.0 * y / depth + 50.0]
    };
    replace_features(
        &mut views[1],
        vec![
            feature(31, project([0.0, 0.0, 10.0]), [0; 4]),
            feature(42, project([2.0, 4.0 / 3.0, 10.0]), [u64::MAX; 4]),
        ],
    )?;
    let report = associate_features(
        &twin,
        [&views[0], &views[1]],
        AssociationOptions {
            maximum_epipolar_distance_pixels: 1e-9,
            ..options()
        },
        &mut WorkBudget::new(WORK),
    )?;
    let positions = fused_positions(&report);
    assert_eq!(positions.len(), 2);
    for (actual, expected) in positions
        .iter()
        .zip([[0.0, 0.0, 10.0], [2.0, 4.0 / 3.0, 10.0]])
    {
        for axis in 0..3 {
            assert!((actual[axis] - expected[axis]).abs() < 1e-8);
        }
    }
    for pair in report.pairs().iter().filter(|p| p.hypothesis.is_some()) {
        assert!(
            pair.epipolar_distance_pixels
                .ok_or("missing epipolar residual")?
                .iter()
                .all(|d| *d < 1e-10)
        );
    }
    Ok(())
}

#[test]
fn selected_feature_points_preserve_nominal_mesh_occlusion_conflicts() -> Test {
    let twin = common::twin(&[4.0], None)?;
    let views = basic_views(&twin)?;
    let report = run(&twin, &views)?;
    assert_eq!(report.hypotheses().len(), 2);
    let FeatureHypothesisOutcome::Fused(point) = &report.hypotheses()[1].outcome else {
        return Err("expected geometric point with mesh contradiction".into());
    };
    assert!(point.has_nominal_occlusion_conflict());
    assert!(
        point
            .visibility()
            .iter()
            .all(|v| v.inlier && v.nominal_occluded == Some(true))
    );
    assert_eq!(point.inputs().len(), 2);
    assert_eq!(report.pairs().len(), 4);
    Ok(())
}

fn stereo_texture() -> [Vec<u8>; 2] {
    let stride = WIDTH as usize + 12;
    let mut state = 1973_u32;
    let source: Vec<_> = (0..stride * HEIGHT as usize)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            20 + ((state >> 16) % 180) as u8
        })
        .collect();
    std::array::from_fn(|camera| {
        (0..HEIGHT as usize)
            .flat_map(|y| {
                let source = &source;
                (0..WIDTH as usize).map(move |x| source[y * stride + x + 12 * camera])
            })
            .collect()
    })
}
fn extracted_view(
    twin: &PropertyTwin,
    camera: u8,
    pixels: &[u8],
    mask: &[u8],
) -> Result<FeatureView, Box<dyn Error>> {
    let identity = ImageIdentity {
        exposure: [camera; 32],
        pixels: ContentDigest::sha256(pixels).bytes(),
        image_domain: [camera + 20; 32],
        dimensions: [WIDTH, HEIGHT],
    };
    let mut budget = WorkBudget::new(WORK);
    let image = GrayImage::new(identity, pixels, mask, &mut budget)?;
    let extracted = extract_gray(
        &image,
        ExtractionOptions {
            maximum_features: 128,
            ..ExtractionOptions::default()
        },
        &mut budget,
    )?;
    let mut result = view(twin, camera, extracted.frame)?;
    result.source_digest = ContentDigest::sha256(pixels).bytes();
    result.allowed_mask_digest = ContentDigest::sha256(mask).bytes();
    Ok(result)
}

#[test]
fn native_extracted_shifted_texture_produces_depth_without_supplied_correspondences() -> Test {
    let twin = common::twin(&[-20.0], None)?;
    let pixels = stereo_texture();
    let mask = vec![1; (WIDTH * HEIGHT) as usize];
    let views = [
        extracted_view(&twin, 1, &pixels[0], &mask)?,
        extracted_view(&twin, 2, &pixels[1], &mask)?,
    ];
    let report = associate_features(
        &twin,
        [&views[0], &views[1]],
        AssociationOptions {
            maximum_hamming_distance: 0,
            maximum_epipolar_distance_pixels: 1e-9,
            ..options()
        },
        &mut WorkBudget::new(WORK),
    )?;
    assert!(
        report.hypotheses().len() >= 20,
        "native matched count {}",
        report.hypotheses().len()
    );
    assert_eq!(
        report.pairs().len(),
        views[0].frame.features().len() * views[1].frame.features().len()
    );
    for hypothesis in report.hypotheses() {
        let FeatureHypothesisOutcome::Fused(point) = &hypothesis.outcome else {
            return Err("native texture pair did not triangulate".into());
        };
        let a = views[0]
            .frame
            .features()
            .iter()
            .find(|f| f.id == hypothesis.features[0])
            .ok_or("missing left feature")?;
        let b = views[1]
            .frame
            .features()
            .iter()
            .find(|f| f.id == hypothesis.features[1])
            .ok_or("missing right feature")?;
        assert_eq!(a.pixel[0] - b.pixel[0], 12.0);
        assert_eq!(a.pixel[1], b.pixel[1]);
        let expected = [(a.pixel[0] - 96.0) / 12.0, (a.pixel[1] - 64.0) / 12.0, 10.0];
        for (actual, expected) in point.estimate().position.iter().zip(expected) {
            assert!((*actual - expected).abs() < 1e-8);
        }
        assert_eq!(point.map_error(), None);
    }
    Ok(())
}

#[test]
fn repeated_descriptors_retain_all_ties_without_camera_or_feature_id_choice() -> Test {
    let twin = common::twin(&[-20.0], None)?;
    let mut views = basic_views(&twin)?;
    replace_features(
        &mut views[0],
        vec![
            feature(11, [96.0, 64.0], [0; 4]),
            feature(22, [120.0, 80.0], [0; 4]),
        ],
    )?;
    let report = run(&twin, &views)?;
    assert!(report.hypotheses().is_empty());
    assert_eq!(report.pairs()[0].descriptor, DescriptorDecision::Ambiguous);
    assert_eq!(report.pairs()[2].descriptor, DescriptorDecision::Ambiguous);
    let tied = report
        .features()
        .iter()
        .find(|f| f.camera == 2 && f.feature == 31)
        .ok_or("missing tied feature")?;
    assert_eq!(tied.nearest_features, vec![11, 22]);
    assert_eq!(tied.best_distance, Some(0));
    assert_eq!(tied.runner_up_distance, Some(0));
    assert_eq!(tied.disposition, FeatureDisposition::Ambiguous);
    // One competing tie lies outside the epipolar gate. It still prevents a unique
    // descriptor assertion; nominal geometry never removes the ambiguity.
    assert_eq!(report.pairs()[0].epipolar, EpipolarDecision::Passed);
    assert_eq!(report.pairs()[2].epipolar, EpipolarDecision::OutsideGate);
    Ok(())
}

#[test]
fn ratio_is_strict_and_symmetric_including_weak_reverse_runner_up() -> Test {
    let twin = common::twin(&[-20.0], None)?;
    let mut views = basic_views(&twin)?;
    replace_features(
        &mut views[0],
        vec![
            feature(11, [96.0, 64.0], [0; 4]),
            feature(22, [120.0, 80.0], [511, 0, 0, 0]),
        ],
    )?;
    replace_features(
        &mut views[1],
        vec![
            feature(31, [84.0, 64.0], [15, 0, 0, 0]),
            feature(42, [108.0, 80.0], [u64::MAX; 4]),
        ],
    )?;
    let report = run(&twin, &views)?;
    // Left->right ratio 4/256 passes. Right->left 4/5 equals 80%, and MUST fail.
    assert_eq!(report.pairs()[0].hamming_distance, 4);
    assert_eq!(report.pairs()[0].descriptor, DescriptorDecision::Ambiguous);
    assert!(report.hypotheses().is_empty());
    let relaxed = associate_features(
        &twin,
        [&views[0], &views[1]],
        AssociationOptions {
            ratio_percent: 81,
            ..options()
        },
        &mut WorkBudget::new(WORK),
    )?;
    assert_eq!(relaxed.hypotheses().len(), 1);
    assert_eq!(relaxed.pairs()[0].descriptor, DescriptorDecision::Candidate);
    assert_ne!(report.evidence(), relaxed.evidence());
    Ok(())
}

#[test]
fn nonmutual_feature_is_not_greedily_assigned_to_an_alternative() -> Test {
    let twin = common::twin(&[-20.0], None)?;
    let mut views = basic_views(&twin)?;
    replace_features(
        &mut views[0],
        vec![
            feature(11, [96.0, 64.0], [0; 4]),
            feature(22, [120.0, 80.0], [1, 0, 0, 0]),
        ],
    )?;
    let report = run(&twin, &views)?;
    assert_eq!(report.hypotheses().len(), 1);
    assert_eq!(report.pairs()[2].descriptor, DescriptorDecision::NonMutual);
    assert_eq!(
        report.features()[1].disposition,
        FeatureDisposition::NonMutual
    );
    assert_eq!(report.features()[1].nearest_features, vec![31]);
    assert_eq!(
        report.features()[3].disposition,
        FeatureDisposition::TooDistant
    );
    Ok(())
}

#[test]
fn genuine_descriptor_match_off_epipolar_line_keeps_diagnostics_and_other_success() -> Test {
    let twin = common::twin(&[-20.0], None)?;
    let mut views = basic_views(&twin)?;
    replace_features(
        &mut views[1],
        vec![
            feature(31, [84.0, 74.0], [0; 4]),
            feature(42, [108.0, 80.0], [u64::MAX; 4]),
        ],
    )?;
    let report = run(&twin, &views)?;
    assert_eq!(report.pairs().len(), 4);
    assert_eq!(report.hypotheses().len(), 1);
    assert_eq!(report.pairs()[0].descriptor, DescriptorDecision::Candidate);
    assert_eq!(report.pairs()[0].epipolar, EpipolarDecision::OutsideGate);
    let errors = report.pairs()[0]
        .epipolar_distance_pixels
        .ok_or("missing epipolar residual")?;
    for error in errors {
        assert!((error - 10.0).abs() < 1e-12);
    }
    assert_eq!(
        report.features()[0].disposition,
        FeatureDisposition::EpipolarRejected
    );
    assert_eq!(
        report.features()[2].disposition,
        FeatureDisposition::EpipolarRejected
    );
    assert_eq!(report.hypotheses()[0].features, [22, 42]);
    Ok(())
}

#[test]
fn coincident_cameras_and_epipoles_are_unobservable_not_zero_error() -> Test {
    let twin = common::twin(&[-20.0], None)?;
    let mut views = basic_views(&twin)?;
    views[1].camera.pose = views[0].camera.pose;
    let report = run(&twin, &views)?;
    assert!(report.hypotheses().is_empty());
    assert!(
        report
            .pairs()
            .iter()
            .all(|p| p.epipolar == EpipolarDecision::Unobservable
                && p.epipolar_distance_pixels.is_none())
    );
    assert!(
        report
            .features()
            .iter()
            .all(|f| f.disposition == FeatureDisposition::EpipolarUnobservable)
    );
    // Translation along the optical axis puts the center pixel at the epipole.
    views[1].camera.pose = RigidPose::from_center(ROTATION, [0.0, 0.0, 1.0])?;
    let report = run(&twin, &views)?;
    assert_eq!(report.pairs()[0].epipolar, EpipolarDecision::Unobservable);
    assert_eq!(report.pairs()[0].epipolar_distance_pixels, None);
    Ok(())
}

#[test]
fn parallel_and_behind_camera_pairs_preserve_native_refusals_without_points() -> Test {
    let twin = common::twin(&[-20.0], None)?;
    for disparity in [0.0, -12.0] {
        let mut views = basic_views(&twin)?;
        replace_features(
            &mut views[1],
            vec![
                feature(31, [96.0 - disparity, 64.0], [0; 4]),
                feature(42, [120.0 - disparity, 80.0], [u64::MAX; 4]),
            ],
        )?;
        let report = run(&twin, &views)?;
        assert_eq!(report.hypotheses().len(), 2);
        assert!(fused_positions(&report).is_empty());
        for h in report.hypotheses() {
            assert!(matches!(
                h.outcome,
                FeatureHypothesisOutcome::Refused(FusionError::Triangulation(
                    TriangulationError::WeakGeometry | TriangulationError::NoConsensus
                ))
            ));
        }
        assert!(
            report
                .features()
                .iter()
                .all(|f| f.disposition == FeatureDisposition::Selected)
        );
    }
    Ok(())
}

#[test]
fn zero_features_and_missing_runner_up_are_explicit_no_support() -> Test {
    let twin = common::twin(&[-20.0], None)?;
    let mut views = basic_views(&twin)?;
    for v in &mut views {
        replace_features(v, v.frame.features()[..1].to_vec())?;
    }
    let single = run(&twin, &views)?;
    assert_eq!(single.pairs().len(), 1);
    assert_eq!(single.pairs()[0].descriptor, DescriptorDecision::Ambiguous);
    assert!(single.hypotheses().is_empty());
    assert!(
        single
            .features()
            .iter()
            .all(|f| f.runner_up_distance.is_none())
    );
    replace_features(&mut views[1], vec![])?;
    let empty = run(&twin, &views)?;
    assert!(empty.pairs().is_empty());
    assert!(empty.hypotheses().is_empty());
    assert_eq!(empty.features().len(), 1);
    assert_eq!(
        empty.features()[0].disposition,
        FeatureDisposition::NoCounterpart
    );
    assert!(empty.features()[0].nearest_features.is_empty());
    assert_eq!(empty.features()[0].best_distance, None);
    replace_features(&mut views[0], vec![])?;
    assert!(run(&twin, &views)?.features().is_empty());
    Ok(())
}

#[test]
fn masked_native_extraction_never_uses_forbidden_patch_pixels() -> Test {
    let twin = common::twin(&[-20.0], None)?;
    let pixels = stereo_texture();
    let mut masks = [
        vec![1; (WIDTH * HEIGHT) as usize],
        vec![1; (WIDTH * HEIGHT) as usize],
    ];
    // A forbidden image stripe excludes every descriptor footprint touching it.
    for mask in &mut masks {
        for y in 0..HEIGHT as usize {
            mask[y * WIDTH as usize + 96] = 0;
        }
    }
    let views = [
        extracted_view(&twin, 1, &pixels[0], &masks[0])?,
        extracted_view(&twin, 2, &pixels[1], &masks[1])?,
    ];
    for v in &views {
        for f in v.frame.features() {
            assert!((f.pixel[0] as usize).abs_diff(96) > 16);
        }
    }
    let report = run(&twin, &views)?;
    assert_eq!(
        report.views()[0].allowed_mask_digest,
        ContentDigest::sha256(&masks[0]).bytes()
    );
    masks[1].fill(0);
    let denied = extracted_view(&twin, 2, &pixels[1], &masks[1])?;
    assert!(denied.frame.features().is_empty());
    let report = associate_features(
        &twin,
        [&views[0], &denied],
        options(),
        &mut WorkBudget::new(WORK),
    )?;
    assert!(report.hypotheses().is_empty());
    assert!(
        report
            .features()
            .iter()
            .all(|f| f.disposition == FeatureDisposition::NoCounterpart)
    );
    Ok(())
}

#[test]
fn source_domain_clock_privacy_and_exposure_mismatches_fail_before_matching() -> Test {
    let twin = common::twin(&[-20.0], None)?;
    let base = basic_views(&twin)?;
    let mut altered = base.clone();
    altered[1].privacy_domain = 3;
    assert_eq!(
        run(&twin, &altered).err(),
        Some(AssociationError::PrivacyDomain)
    );
    altered = base.clone();
    altered[1].camera.clock = 2;
    assert_eq!(run(&twin, &altered).err(), Some(AssociationError::Basis));
    altered = base.clone();
    altered[1].clock_evidence = [88; 32];
    assert_eq!(run(&twin, &altered).err(), Some(AssociationError::Basis));
    altered = base.clone();
    altered[1].camera.geometry = GeometryBasis::new(2, 1)?;
    assert_eq!(run(&twin, &altered).err(), Some(AssociationError::Basis));
    altered = base.clone();
    altered[1].image_domain_digest = [66; 32];
    assert_eq!(
        run(&twin, &altered).err(),
        Some(AssociationError::ImageDomain)
    );
    altered = base.clone();
    altered[1].camera.intrinsics =
        PinholeIntrinsics::new(WIDTH + 1, HEIGHT, 120.0, 120.0, 96.0, 64.0)?;
    assert_eq!(
        run(&twin, &altered).err(),
        Some(AssociationError::ImageDomain)
    );
    altered = base.clone();
    altered[1].camera.camera = 1;
    assert_eq!(
        run(&twin, &altered).err(),
        Some(AssociationError::DuplicateCamera)
    );
    altered = base.clone();
    let identity = ImageIdentity {
        exposure: altered[0].frame.identity().exposure,
        ..altered[1].frame.identity()
    };
    replace_identity(&mut altered[1], identity)?;
    assert_eq!(
        run(&twin, &altered).err(),
        Some(AssociationError::DuplicateExposure)
    );
    altered = base.clone();
    altered[1].mapping_basis = [0; 32];
    assert_eq!(
        run(&twin, &altered).err(),
        Some(AssociationError::InvalidInput)
    );
    altered = base.clone();
    altered[1].source_digest = [0; 32];
    assert_eq!(
        run(&twin, &altered).err(),
        Some(AssociationError::InvalidInput)
    );
    altered = base.clone();
    altered[1].allowed_mask_digest = [0; 32];
    assert_eq!(
        run(&twin, &altered).err(),
        Some(AssociationError::InvalidInput)
    );
    altered = base;
    altered[1].frame = FeatureFrame::new(
        altered[1].frame.identity(),
        [78; 32],
        altered[1].frame.features().to_vec(),
        &mut WorkBudget::new(WORK),
    )?;
    assert_eq!(run(&twin, &altered).err(), Some(AssociationError::Basis));
    Ok(())
}

#[test]
fn complete_capture_uncertainty_and_validity_gate_even_overlapping_intervals() -> Test {
    let twin = common::twin(&[-20.0], None)?;
    let base = basic_views(&twin)?;
    for capture in [[80, 120], [110, 90], [1001, 1002], [u64::MAX - 1, u64::MAX]] {
        let mut altered = base.clone();
        altered[1].capture = capture;
        assert_eq!(
            run(&twin, &altered).err(),
            Some(AssociationError::CaptureWindow)
        );
    }
    let mut altered = base.clone();
    altered[1].camera.validity = [91, 110];
    assert_eq!(
        run(&twin, &altered).err(),
        Some(AssociationError::CaptureWindow)
    );
    altered[1].camera.validity = [100, 99];
    assert_eq!(
        run(&twin, &altered).err(),
        Some(AssociationError::CaptureWindow)
    );
    assert_eq!(
        associate_features(
            &twin,
            [&base[0], &base[1]],
            AssociationOptions {
                reference_time_ns: 89,
                ..options()
            },
            &mut WorkBudget::new(WORK)
        )
        .err(),
        Some(AssociationError::CaptureWindow)
    );
    // Near-u64::MAX clocks preserve a 20ns hull without floating-point timestamp rounding.
    let mut high = base;
    for v in &mut high {
        v.capture = [u64::MAX - 20, u64::MAX];
        v.camera.validity = v.capture;
    }
    let report = associate_features(
        &twin,
        [&high[0], &high[1]],
        AssociationOptions {
            reference_time_ns: u64::MAX - 10,
            ..options()
        },
        &mut WorkBudget::new(WORK),
    )?;
    assert_eq!(report.capture_hull(), [u64::MAX - 20, u64::MAX]);
    assert_eq!(fused_positions(&report).len(), 2);
    Ok(())
}

#[test]
fn canonical_order_and_exact_evidence_pins_survive_input_permutations() -> Test {
    let twin = common::twin(&[-20.0], None)?;
    let base = basic_views(&twin)?;
    let original = run(&twin, &base)?;
    let mut reordered = base.clone();
    for v in &mut reordered {
        let mut features = v.frame.features().to_vec();
        features.reverse();
        replace_features(v, features)?;
    }
    let reversed = associate_features(
        &twin,
        [&reordered[1], &reordered[0]],
        options(),
        &mut WorkBudget::new(WORK),
    )?;
    assert_eq!(original.evidence(), reversed.evidence());
    assert_eq!(original.pairs(), reversed.pairs());
    assert_eq!(original.features(), reversed.features());
    assert_eq!(fused_positions(&original), fused_positions(&reversed));
    for pin in 0..8 {
        let mut changed = base.clone();
        match pin {
            0 => changed[0].source_digest[0] ^= 1,
            1 => changed[0].allowed_mask_digest[0] ^= 1,
            2 => changed[0].mapping_basis[0] ^= 1,
            3 => changed[0].camera.calibration += 1,
            4 => changed[0].camera.error = None,
            5 => changed[0].sigma_pixels *= 2.0,
            6 => {
                let mut identity = changed[0].frame.identity();
                identity.pixels[0] ^= 1;
                replace_identity(&mut changed[0], identity)?;
            }
            _ => changed[0].capture = [91, 109],
        }
        let report = run(&twin, &changed)?;
        assert_ne!(report.evidence(), original.evidence());
        assert_ne!(
            report.hypotheses()[0].evidence,
            original.hypotheses()[0].evidence
        );
    }
    Ok(())
}

#[test]
fn invalid_policy_and_hard_feature_limit_refuse_instead_of_truncating() -> Test {
    let twin = common::twin(&[-20.0], None)?;
    let mut views = basic_views(&twin)?;
    for variant in 0..9 {
        let mut policy = options();
        match variant {
            0 => policy.maximum_hamming_distance = 257,
            1 => policy.ratio_percent = 0,
            2 => policy.ratio_percent = 100,
            3 => policy.maximum_epipolar_distance_pixels = f64::NAN,
            4 => policy.camera_rig_digest = [0; 32],
            5 => policy.max_capture_span_ns = 1_000_000_001,
            6 => policy.triangulation.min_views = 3,
            7 => policy.triangulation.max_outliers = 1,
            _ => policy.triangulation.max_iterations = 0,
        }
        assert_eq!(
            associate_features(
                &twin,
                [&views[0], &views[1]],
                policy,
                &mut WorkBudget::new(WORK)
            )
            .err(),
            Some(AssociationError::InvalidOptions)
        );
    }
    let many = (0..129)
        .map(|n| feature(n + 1, [n as f64 + 0.5, 64.0], [n; 4]))
        .collect();
    replace_features(&mut views[0], many)?;
    assert_eq!(run(&twin, &views).err(), Some(AssociationError::Limit));
    replace_features(&mut views[0], vec![])?;
    replace_features(&mut views[1], vec![])?;
    assert_eq!(
        associate_features(
            &twin,
            [&views[0], &views[1]],
            AssociationOptions {
                triangulation: TriangulationOptions {
                    max_iterations: 0,
                    ..TriangulationOptions::default()
                },
                ..options()
            },
            &mut WorkBudget::new(WORK)
        )
        .err(),
        Some(AssociationError::InvalidOptions)
    );
    Ok(())
}

#[test]
fn work_exhaustion_and_late_cancellation_never_return_partial_associations() -> Test {
    let twin = common::twin(&[-20.0], None)?;
    let views = basic_views(&twin)?;
    let mut budget = WorkBudget::new(WORK);
    let complete = associate_features(&twin, [&views[0], &views[1]], options(), &mut budget)?;
    let used = WORK - budget.remaining();
    assert!(used > 1);
    for limit in [0, 1, used - 1] {
        assert_eq!(
            associate_features(
                &twin,
                [&views[0], &views[1]],
                options(),
                &mut WorkBudget::new(limit)
            )
            .err(),
            Some(AssociationError::Geometry(GeometryError::BudgetExhausted))
        );
    }
    let stop = AtomicBool::new(true);
    assert_eq!(
        associate_features(
            &twin,
            [&views[0], &views[1]],
            options(),
            &mut WorkBudget::cancellable(WORK, &stop)
        )
        .err(),
        Some(AssociationError::Geometry(GeometryError::Cancelled))
    );
    let calls = AtomicUsize::new(0);
    let probe = || {
        calls.fetch_add(1, Ordering::Relaxed);
        false
    };
    associate_features(
        &twin,
        [&views[0], &views[1]],
        options(),
        &mut WorkBudget::with_cancellation_probe(WORK, &probe),
    )?;
    let late = calls.load(Ordering::Relaxed) - 2;
    assert!(late > 20);
    calls.store(0, Ordering::Relaxed);
    let probe = || calls.fetch_add(1, Ordering::Relaxed) >= late;
    assert_eq!(
        associate_features(
            &twin,
            [&views[0], &views[1]],
            options(),
            &mut WorkBudget::with_cancellation_probe(WORK, &probe)
        )
        .err(),
        Some(AssociationError::Geometry(GeometryError::Cancelled))
    );
    let replay = run(&twin, &views)?;
    assert_eq!(complete.evidence(), replay.evidence());
    assert_eq!(complete.pairs(), replay.pairs());
    assert_eq!(fused_positions(&complete), fused_positions(&replay));
    Ok(())
}

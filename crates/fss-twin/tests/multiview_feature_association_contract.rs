#![forbid(unsafe_code)]
//! Independent projected points and native pixels -> complete multi-camera graphs.
//! Authored cameras/texture are numerical fixtures, not field-calibration evidence.
mod common;

use std::error::Error;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fss_core::ContentDigest;
use fss_geometry::triangulation::{TriangulationError, TriangulationOptions};
use fss_geometry::{GeometryBasis, GeometryError, PinholeIntrinsics, RigidPose, WorkBudget};
use fss_twin::feature_association::{
    AssociationError, AssociationOptions, DescriptorDecision, EpipolarDecision, FeatureDisposition,
    FeatureHypothesisOutcome, FeatureView, associate_features,
};
use fss_twin::localization::native::{ExtractionOptions, GrayImage, extract_gray};
use fss_twin::localization::{BinaryDescriptor, FeatureFrame, ImageFeature, ImageIdentity};
use fss_twin::multiview::FusionError;
use fss_twin::multiview_feature_association::{
    ComponentOutcome, FeatureComponent, MAX_MULTIVIEW_PAIR_ROWS, MultiFeatureAssociation,
    PairReference, SceneFeature, associate_multiview_features,
};
use fss_twin::{ProjectionError, PropertyTwin, ScaleEvidence, TrackingCamera};

type Test<T = ()> = Result<T, Box<dyn Error>>;
const WORK: u64 = 100_000_000;
const WIDTH: u32 = 192;
const HEIGHT: u32 = 128;
const IDENTITY: [[f64; 3]; 3] = [[1., 0., 0.], [0., 1., 0.], [0., 0., 1.]];
const POINTS: [[f64; 3]; 2] = [[0.2, 0.3, 10.], [2., 1.5, 12.]];

fn options() -> AssociationOptions {
    AssociationOptions {
        association_basis: [90; 32],
        camera_rig_digest: [91; 32],
        privacy_domain: 2,
        clock: 1,
        clock_evidence: [92; 32],
        reference_time_ns: 100,
        max_capture_span_ns: 20,
        maximum_hamming_distance: 64,
        ratio_percent: 80,
        maximum_epipolar_distance_pixels: 0.01,
        triangulation: TriangulationOptions::default(),
    }
}
fn feature(id: u64, pixel: [f64; 2], descriptor: [u64; 4]) -> ImageFeature {
    ImageFeature {
        id,
        pixel,
        descriptor: BinaryDescriptor(descriptor),
    }
}
fn frame(camera: u8, features: Vec<ImageFeature>) -> Test<FeatureFrame> {
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
fn view(twin: &PropertyTwin, camera: u8, center: [f64; 3]) -> Test<FeatureView> {
    let features = POINTS
        .iter()
        .enumerate()
        .map(|(i, p)| {
            // Independent pinhole projection: no production project/ray/matrix helper.
            let depth = p[2] - center[2];
            feature(
                u64::from(camera) * 10 + i as u64 + 1,
                [
                    120. * (p[0] - center[0]) / depth + 96.,
                    120. * (p[1] - center[1]) / depth + 64.,
                ],
                if i == 0 { [0; 4] } else { [u64::MAX; 4] },
            )
        })
        .collect();
    let frame = frame(camera, features)?;
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
            pose: RigidPose::from_center(IDENTITY, center)?,
            intrinsics: PinholeIntrinsics::new(WIDTH, HEIGHT, 120., 120., 96., 64.)?,
            error: Some(ProjectionError::EXACT),
        },
        source_digest: [camera + 30; 32],
        allowed_mask_digest: [camera + 40; 32],
        mapping_basis: [camera + 50; 32],
        privacy_domain: 2,
        clock_evidence: [92; 32],
        capture: [90, 110],
        sigma_pixels: 0.5,
    })
}
fn views(twin: &PropertyTwin, count: usize) -> Test<Vec<FeatureView>> {
    let centers = [
        [0., 0., 0.],
        [1., 0., 0.],
        [0.5, 1., 0.],
        [1.5, -0.5, 0.2],
        [-1., 0.5, 0.],
        [-1.5, -0.5, 0.1],
        [0.2, -1., -0.2],
        [1., 1.5, 0.3],
        [2., 2., 0.],
    ];
    centers[..count]
        .iter()
        .enumerate()
        .map(|(i, &c)| view(twin, i as u8 + 1, c))
        .collect()
}
fn horizontal(twin: &PropertyTwin) -> Test<Vec<FeatureView>> {
    (0..3)
        .map(|i| view(twin, i + 1, [f64::from(i), 0., 0.]))
        .collect()
}
fn run(
    twin: &PropertyTwin,
    views: &[FeatureView],
) -> Result<MultiFeatureAssociation, AssociationError> {
    associate_multiview_features(twin, views, options(), &mut WorkBudget::new(WORK))
}
fn position(component: &FeatureComponent) -> Test<[f64; 3]> {
    match component.outcome() {
        ComponentOutcome::Fused(point) => Ok(point.estimate().position),
        outcome => Err(format!("expected joint point, got {outcome:?}").into()),
    }
}
fn close(actual: [f64; 3], expected: [f64; 3], tolerance: f64) {
    for (a, e) in actual.into_iter().zip(expected) {
        assert!((a - e).abs() < tolerance, "{actual:?} != {expected:?}");
    }
}
fn check_native_equivalence(
    left: &MultiFeatureAssociation,
    right: &MultiFeatureAssociation,
) -> Test {
    assert_eq!(left.evidence(), right.evidence());
    assert_eq!(left.capture_hull(), right.capture_hull());
    assert_eq!(left.options(), right.options());
    assert_eq!(left.pairs().len(), right.pairs().len());
    for (a, b) in left.pairs().iter().zip(right.pairs()) {
        assert_eq!(a.cameras(), b.cameras());
        assert_eq!(a.report().evidence(), b.report().evidence());
        assert_eq!(a.report().pairs(), b.report().pairs());
        assert_eq!(a.report().features(), b.report().features());
    }
    assert_eq!(left.components().len(), right.components().len());
    for (a, b) in left.components().iter().zip(right.components()) {
        assert_eq!(a.evidence(), b.evidence());
        assert_eq!(a.members(), b.members());
        assert_eq!(a.links(), b.links());
        assert_eq!(a.solve_time_ns(), b.solve_time_ns());
        match (a.outcome(), b.outcome()) {
            (ComponentOutcome::Fused(x), ComponentOutcome::Fused(y)) => {
                assert_eq!(x.estimate(), y.estimate());
            }
            (ComponentOutcome::Unmatched, ComponentOutcome::Unmatched) => {}
            (ComponentOutcome::Refused(x), ComponentOutcome::Refused(y)) => assert_eq!(x, y),
            _ => return Err("unexpected comparison outcomes".into()),
        }
    }
    Ok(())
}

#[test]
fn three_camera_closure_produces_one_joint_point_per_feature_and_complete_diagnostics() -> Test {
    let twin = common::twin(&[-20.], Some(0.))?;
    let sources = views(&twin, 3)?;
    let report = run(&twin, &sources)?;
    assert_eq!(report.views().len(), 3);
    assert_eq!(report.pairs().len(), 3);
    assert_eq!(
        report
            .pairs()
            .iter()
            .map(|p| p.report().pairs().len())
            .sum::<usize>(),
        12
    );
    assert_eq!(report.components().len(), 2);
    for (component, expected) in report.components().iter().zip(POINTS) {
        assert_eq!(component.members().len(), 3);
        assert_eq!(component.links().len(), 3);
        close(position(component)?, expected, 1e-9);
        let ComponentOutcome::Fused(point) = component.outcome() else {
            return Err("missing joint point".into());
        };
        assert_eq!(point.inputs().len(), 3);
        assert_eq!(point.visibility().len(), 3);
        assert!(point.visibility().iter().all(|v| v.inlier));
        assert_eq!(point.request().triangulation.min_views, 3);
        assert_eq!(point.request().triangulation.max_outliers, 0);
        assert_eq!(point.request().association_evidence, component.evidence());
        assert_eq!(point.request().reference_time_ns, component.solve_time_ns());
        assert_eq!(point.capture_hull(), [90, 110]);
        assert_eq!(point.twin_digest(), twin.digest());
        assert!(
            point
                .inputs()
                .iter()
                .all(|i| i.observation.evidence != component.evidence())
        );
    }
    Ok(())
}

#[test]
fn four_and_eight_cameras_retain_the_unchanged_pair_owner_and_jointly_use_every_view() -> Test {
    let twin = common::twin(&[-20.], None)?;
    for count in [4, 8] {
        let sources = views(&twin, count)?;
        let report = run(&twin, &sources)?;
        assert_eq!(report.pairs().len(), count * (count - 1) / 2);
        assert_eq!(report.components().len(), 2);
        for (component, expected) in report.components().iter().zip(POINTS) {
            close(position(component)?, expected, 1e-8);
            assert_eq!(component.members().len(), count);
            assert_eq!(component.links().len(), count * (count - 1) / 2);
        }
        for pair in report.pairs() {
            let [a, b] = pair.cameras().map(|c| &sources[c as usize - 1]);
            let old = associate_features(&twin, [a, b], options(), &mut WorkBudget::new(WORK))?;
            assert_eq!(pair.report().evidence(), old.evidence());
            assert_eq!(pair.report().pairs(), old.pairs());
            assert_eq!(pair.report().features(), old.features());
            assert_eq!(pair.report().hypotheses().len(), old.hypotheses().len());
        }
    }
    Ok(())
}

#[test]
fn native_extracted_four_view_texture_reconstructs_shared_independent_plane_depth() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let stride = WIDTH as usize + 24;
    let mut seed = 0x52a1_u32;
    let texture: Vec<_> = (0..stride * HEIGHT as usize)
        .map(|_| {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            (seed >> 24) as u8
        })
        .collect();
    let allowed = vec![1; WIDTH as usize * HEIGHT as usize];
    let mut sources = Vec::new();
    for camera in 0..4_usize {
        let pixels: Vec<_> = (0..HEIGHT as usize)
            .flat_map(|y| {
                let texture = &texture;
                (0..WIDTH as usize).map(move |x| texture[y * stride + x + camera * 8])
            })
            .collect();
        let mut source = view(&twin, camera as u8 + 1, [camera as f64, 0., 0.])?;
        let mut work = WorkBudget::new(WORK);
        let image = GrayImage::new(
            ImageIdentity {
                pixels: ContentDigest::sha256(&pixels).bytes(),
                ..source.frame.identity()
            },
            &pixels,
            &allowed,
            &mut work,
        )?;
        let extracted = extract_gray(
            &image,
            ExtractionOptions {
                threshold: 30,
                maximum_features: 64,
                separation: 5,
            },
            &mut work,
        )?;
        source.frame = extracted.frame;
        source.source_digest = ContentDigest::sha256(&pixels).bytes();
        source.allowed_mask_digest = extracted.selection.mask_digest;
        assert!(!source.frame.features().is_empty());
        sources.push(source);
    }
    let report = run(&twin, &sources)?;
    let mut shared = 0;
    for component in report.components() {
        if let ComponentOutcome::Fused(point) = component.outcome() {
            if component.members().len() >= 3 {
                shared += 1;
            }
            let member = component.members()[0];
            let source = &sources[member.camera as usize - 1];
            let pixel = source
                .frame
                .features()
                .iter()
                .find(|f| f.id == member.feature)
                .ok_or("missing source feature")?
                .pixel;
            // Eight pixels of disparity per one source unit with focal=120 implies z=15.
            let expected = [
                (pixel[0] - 96.) / 120. * 15. + member.camera as f64 - 1.,
                (pixel[1] - 64.) / 120. * 15.,
                15.,
            ];
            close(point.estimate().position, expected, 1e-7);
        }
    }
    assert!(
        shared >= 8,
        "only {shared} components shared by at least three views"
    );
    Ok(())
}

#[test]
fn camera_conflicting_cycles_retain_every_member_and_link_without_greedy_resolution() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let mut sources = horizontal(&twin)?;
    for (source, entries) in sources.iter_mut().zip([
        vec![
            feature(11, [100., 64.], [0; 4]),
            feature(12, [104., 64.], [7, 0, 0, 0]),
        ],
        vec![
            feature(21, [88., 64.], [1, 0, 0, 0]),
            feature(22, [115., 80.], [u64::MAX; 4]),
        ],
        vec![
            feature(31, [76., 64.], [3, 0, 0, 0]),
            feature(32, [103., 80.], [u64::MAX; 4]),
        ],
    ]) {
        replace_features(source, entries)?;
    }
    let report = associate_multiview_features(
        &twin,
        &sources,
        AssociationOptions {
            maximum_hamming_distance: 1,
            ..options()
        },
        &mut WorkBudget::new(WORK),
    )?;
    let component = &report.components()[0];
    assert_eq!(
        component.members(),
        [
            SceneFeature {
                camera: 1,
                feature: 11
            },
            SceneFeature {
                camera: 1,
                feature: 12
            },
            SceneFeature {
                camera: 2,
                feature: 21
            },
            SceneFeature {
                camera: 3,
                feature: 31
            },
        ]
    );
    assert_eq!(component.links().len(), 3);
    assert!(
        matches!(component.outcome(), ComponentOutcome::CameraConflict { cameras } if cameras == &[1])
    );
    assert_eq!(
        report
            .components()
            .iter()
            .map(|c| c.members().len())
            .sum::<usize>(),
        6
    );
    assert_eq!(
        report
            .pairs()
            .iter()
            .map(|p| p.report().pairs().len())
            .sum::<usize>(),
        12
    );
    assert!(
        report
            .pairs()
            .iter()
            .all(|p| !p.report().hypotheses().is_empty())
    );
    Ok(())
}

#[test]
fn an_open_chain_is_not_promoted_to_transitive_correspondence_and_keeps_its_pair_points() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let mut sources = horizontal(&twin)?;
    for (source, descriptor) in sources.iter_mut().zip([0, 1, 3]) {
        let mut features = source.frame.features().to_vec();
        features[0].descriptor = BinaryDescriptor([descriptor, 0, 0, 0]);
        replace_features(source, features)?;
    }
    let report = associate_multiview_features(
        &twin,
        &sources,
        AssociationOptions {
            maximum_hamming_distance: 1,
            ..options()
        },
        &mut WorkBudget::new(WORK),
    )?;
    let component = &report.components()[0];
    assert_eq!(component.members().len(), 3);
    assert_eq!(component.links().len(), 2);
    let ComponentOutcome::IncompleteCycleSupport { pairs } = component.outcome() else {
        return Err("open chain was merged".into());
    };
    assert_eq!(
        pairs,
        &[PairReference {
            pair: 1,
            decision: 0
        }]
    );
    let absent = &report.pairs()[pairs[0].pair].report().pairs()[pairs[0].decision];
    assert_eq!(absent.descriptor, DescriptorDecision::TooDistant);
    assert_eq!(absent.epipolar, EpipolarDecision::Passed);
    for i in [0, 2] {
        assert!(matches!(
            report.pairs()[i].report().hypotheses()[0].outcome,
            FeatureHypothesisOutcome::Fused(_)
        ));
    }
    assert!(matches!(
        report.components()[1].outcome(),
        ComponentOutcome::Fused(_)
    ));
    Ok(())
}

#[test]
fn tied_descriptors_keep_all_alternatives_and_missing_runner_up_never_selects_a_feature() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let mut sources = views(&twin, 3)?;
    for source in &mut sources {
        let mut features = source.frame.features().to_vec();
        for feature in &mut features {
            feature.descriptor = BinaryDescriptor([0; 4]);
        }
        replace_features(source, features)?;
    }
    let report = run(&twin, &sources)?;
    assert_eq!(report.components().len(), 6);
    assert!(
        report
            .components()
            .iter()
            .all(|c| matches!(c.outcome(), ComponentOutcome::Unmatched))
    );
    for pair in report.pairs() {
        assert!(
            pair.report()
                .pairs()
                .iter()
                .all(|p| p.descriptor == DescriptorDecision::Ambiguous)
        );
        assert!(
            pair.report()
                .features()
                .iter()
                .all(|f| f.nearest_features.len() == 2)
        );
    }
    let mut sources = views(&twin, 3)?;
    let only = vec![sources[2].frame.features()[0]];
    replace_features(&mut sources[2], only)?;
    let report = run(&twin, &sources)?;
    assert_eq!(report.components().len(), 3);
    assert!(report.components().iter().all(|c| c.members().len() < 3));
    assert!(
        report.pairs()[1]
            .report()
            .features()
            .iter()
            .any(|f| f.disposition == FeatureDisposition::Ambiguous)
    );
    Ok(())
}

#[test]
fn weak_pair_refusals_remain_visible_when_a_third_baseline_enables_joint_depth() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let sources = vec![
        view(&twin, 1, [0., 0., 0.])?,
        view(&twin, 2, [1e-4, 0., 0.])?,
        view(&twin, 3, [1., 0., 0.])?,
    ];
    let report = run(&twin, &sources)?;
    let weak = report.pairs()[0].report();
    assert_eq!(weak.hypotheses().len(), 2);
    assert!(weak.hypotheses().iter().all(|h| matches!(
        h.outcome,
        FeatureHypothesisOutcome::Refused(FusionError::Triangulation(
            TriangulationError::WeakGeometry
        ))
    )));
    for (component, expected) in report.components().iter().zip(POINTS) {
        assert_eq!(component.links().len(), 3);
        assert_eq!(component.members().len(), 3);
        close(position(component)?, expected, 1e-7);
    }
    Ok(())
}

#[test]
fn individually_plausible_pair_points_cannot_override_inconsistent_joint_geometry() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let mut sources = horizontal(&twin)?;
    let mut features = sources[2].frame.features().to_vec();
    features[0].pixel[0] += 3.;
    replace_features(&mut sources[2], features)?;
    let report = associate_multiview_features(
        &twin,
        &sources,
        AssociationOptions {
            triangulation: TriangulationOptions {
                max_reprojection_pixels: 0.01,
                ..TriangulationOptions::default()
            },
            ..options()
        },
        &mut WorkBudget::new(WORK),
    )?;
    let inconsistent = &report.components()[0];
    assert_eq!(inconsistent.links().len(), 3);
    assert!(matches!(
        inconsistent.outcome(),
        ComponentOutcome::Refused(FusionError::Triangulation(TriangulationError::NoConsensus))
    ));
    assert!(report.pairs().iter().all(|p| matches!(
        p.report().hypotheses()[0].outcome,
        FeatureHypothesisOutcome::Fused(_)
    )));
    close(position(&report.components()[1])?, POINTS[1], 1e-8);
    Ok(())
}

#[test]
fn complete_descriptor_and_epipolar_support_still_refuses_behind_camera_points() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let mut sources = horizontal(&twin)?;
    for (i, source) in sources.iter_mut().enumerate() {
        replace_features(
            source,
            vec![
                feature(i as u64 * 10 + 1, [90. + i as f64 * 12., 64.], [0; 4]),
                feature(
                    i as u64 * 10 + 2,
                    [100. + i as f64 * 12., 80.],
                    [u64::MAX; 4],
                ),
            ],
        )?;
    }
    let report = run(&twin, &sources)?;
    assert_eq!(report.components().len(), 2);
    for component in report.components() {
        assert_eq!(component.links().len(), 3);
        assert!(matches!(
            component.outcome(),
            ComponentOutcome::Refused(FusionError::Triangulation(TriangulationError::NoConsensus))
        ));
    }
    Ok(())
}

#[test]
fn empty_views_remain_in_inventory_and_do_not_erase_supported_two_view_components() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let mut sources = views(&twin, 3)?;
    replace_features(&mut sources[2], vec![])?;
    let report = run(&twin, &sources)?;
    assert_eq!(report.views().len(), 3);
    assert_eq!(report.pairs().len(), 3);
    assert_eq!(report.components().len(), 2);
    for (component, expected) in report.components().iter().zip(POINTS) {
        assert_eq!(component.members().len(), 2);
        close(position(component)?, expected, 1e-8);
    }
    for pair in &report.pairs()[1..] {
        assert!(pair.report().pairs().is_empty());
        assert_eq!(pair.report().features().len(), 2);
        assert!(
            pair.report()
                .features()
                .iter()
                .all(|f| f.disposition == FeatureDisposition::NoCounterpart)
        );
    }
    for source in &mut sources {
        replace_features(source, vec![])?;
    }
    let empty = run(&twin, &sources)?;
    assert_eq!(empty.views().len(), 3);
    assert_eq!(empty.pairs().len(), 3);
    assert!(empty.components().is_empty());
    Ok(())
}

#[test]
fn empty_source_views_still_enforce_every_basis_privacy_clock_identity_and_validity_gate() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let mut base = views(&twin, 3)?;
    for source in &mut base {
        replace_features(source, vec![])?;
    }
    for variant in 0..13 {
        let mut sources = base.clone();
        let expected = match variant {
            0 => {
                sources[2].privacy_domain += 1;
                AssociationError::PrivacyDomain
            }
            1 => {
                sources[2].camera.clock += 1;
                AssociationError::Basis
            }
            2 => {
                sources[2].clock_evidence[0] ^= 1;
                AssociationError::Basis
            }
            3 => {
                sources[2].camera.geometry = GeometryBasis::new(1, 2)?;
                AssociationError::Basis
            }
            4 => {
                sources[2].camera.validity = [95, 105];
                AssociationError::CaptureWindow
            }
            5 => {
                sources[2].capture = [110, 90];
                AssociationError::CaptureWindow
            }
            6 => {
                let identity = ImageIdentity {
                    exposure: sources[0].frame.identity().exposure,
                    ..sources[2].frame.identity()
                };
                replace_identity(&mut sources[2], identity)?;
                AssociationError::DuplicateExposure
            }
            7 => {
                sources[2].frame = FeatureFrame::new(
                    sources[2].frame.identity(),
                    [78; 32],
                    vec![],
                    &mut WorkBudget::new(WORK),
                )?;
                AssociationError::Basis
            }
            8 => {
                sources[2].source_digest = [0; 32];
                AssociationError::InvalidInput
            }
            9 => {
                sources[2].image_domain_digest[0] ^= 1;
                AssociationError::ImageDomain
            }
            10 => {
                let identity = ImageIdentity {
                    dimensions: [WIDTH + 1, HEIGHT],
                    ..sources[2].frame.identity()
                };
                replace_identity(&mut sources[2], identity)?;
                AssociationError::ImageDomain
            }
            11 => {
                sources[2].camera.camera = sources[0].camera.camera;
                AssociationError::DuplicateCamera
            }
            _ => {
                sources[2].sigma_pixels = f64::NAN;
                AssociationError::InvalidInput
            }
        };
        assert_eq!(
            run(&twin, &sources).err(),
            Some(expected),
            "variant {variant}"
        );
    }
    for variant in 0..5 {
        let mut policy = options();
        match variant {
            0 => policy.ratio_percent = 0,
            1 => policy.triangulation.min_views = 3,
            2 => policy.triangulation.max_outliers = 1,
            3 => policy.triangulation.max_iterations = 0,
            _ => policy.association_basis = [0; 32],
        }
        assert_eq!(
            associate_multiview_features(&twin, &base, policy, &mut WorkBudget::new(WORK)).err(),
            Some(AssociationError::InvalidOptions)
        );
    }
    Ok(())
}

#[test]
fn staggered_subset_solve_times_are_explicit_and_never_replace_the_hashed_scene_request() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let mut sources = views(&twin, 3)?;
    for (source, capture) in sources.iter_mut().zip([[10, 20], [30, 40], [90, 100]]) {
        source.capture = capture;
    }
    replace_features(&mut sources[2], vec![])?;
    let policy = AssociationOptions {
        reference_time_ns: 95,
        max_capture_span_ns: 90,
        ..options()
    };
    let report = associate_multiview_features(&twin, &sources, policy, &mut WorkBudget::new(WORK))?;
    assert_eq!(report.capture_hull(), [10, 100]);
    assert_eq!(report.options().reference_time_ns, 95);
    assert_eq!(
        report
            .pairs()
            .iter()
            .map(|p| p.solve_time_ns())
            .collect::<Vec<_>>(),
        [40, 95, 95]
    );
    for pair in report.pairs() {
        assert_eq!(pair.requested_scene_time_ns(), 95);
        assert_eq!(
            pair.report().options().reference_time_ns,
            pair.solve_time_ns()
        );
    }
    for component in report.components() {
        assert_eq!(component.capture_hull(), [10, 40]);
        assert_eq!(component.requested_scene_time_ns(), 95);
        assert_eq!(component.solve_time_ns(), 40);
        let ComponentOutcome::Fused(point) = component.outcome() else {
            return Err("subset did not reconstruct".into());
        };
        assert_eq!(point.request().reference_time_ns, 40);
    }
    let later = associate_multiview_features(
        &twin,
        &sources,
        AssociationOptions {
            reference_time_ns: 96,
            ..policy
        },
        &mut WorkBudget::new(WORK),
    )?;
    assert_eq!(
        report.pairs()[0].report().evidence(),
        later.pairs()[0].report().evidence()
    );
    assert_ne!(report.evidence(), later.evidence());
    assert_ne!(
        report.components()[0].evidence(),
        later.components()[0].evidence()
    );
    for changed in [
        AssociationOptions {
            reference_time_ns: 9,
            ..policy
        },
        AssociationOptions {
            max_capture_span_ns: 89,
            ..policy
        },
    ] {
        assert_eq!(
            associate_multiview_features(&twin, &sources, changed, &mut WorkBudget::new(WORK))
                .err(),
            Some(AssociationError::CaptureWindow)
        );
    }
    for source in &mut sources {
        source.capture = source.capture.map(|n| u64::MAX - 100 + n);
        source.camera.validity = [u64::MAX - 100, u64::MAX];
    }
    let high = associate_multiview_features(
        &twin,
        &sources,
        AssociationOptions {
            reference_time_ns: u64::MAX - 5,
            ..policy
        },
        &mut WorkBudget::new(WORK),
    )?;
    assert_eq!(high.capture_hull(), [u64::MAX - 90, u64::MAX]);
    assert_eq!(high.components()[0].solve_time_ns(), u64::MAX - 60);
    close(position(&high.components()[0])?, POINTS[0], 1e-8);
    Ok(())
}

#[test]
fn canonical_graph_and_joint_results_are_invariant_to_view_and_feature_input_permutations() -> Test
{
    let twin = common::twin(&[-20.], None)?;
    let base = views(&twin, 8)?;
    let original = run(&twin, &base)?;
    for shift in 0..8 {
        let mut reordered = base.clone();
        reordered.rotate_left(shift);
        if shift % 2 == 0 {
            reordered.reverse();
        }
        for view in &mut reordered {
            let mut features = view.frame.features().to_vec();
            features.reverse();
            replace_features(view, features)?;
        }
        check_native_equivalence(&original, &run(&twin, &reordered)?)?;
    }
    Ok(())
}

#[test]
fn every_source_pin_and_global_assumption_changes_scene_and_component_evidence() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let base = views(&twin, 3)?;
    let original = run(&twin, &base)?;
    for variant in 0..12 {
        let mut sources = base.clone();
        let mut policy = options();
        match variant {
            0 => sources[2].source_digest[0] ^= 1,
            1 => sources[2].allowed_mask_digest[0] ^= 1,
            2 => sources[2].mapping_basis[0] ^= 1,
            3 => sources[2].camera.calibration += 1,
            4 => sources[2].camera.error = None,
            5 => sources[2].sigma_pixels *= 2.,
            6 => {
                let mut identity = sources[2].frame.identity();
                identity.pixels[0] ^= 1;
                replace_identity(&mut sources[2], identity)?;
            }
            7 => sources[2].capture = [91, 109],
            8 => policy.association_basis[0] ^= 1,
            9 => policy.camera_rig_digest[0] ^= 1,
            10 => policy.reference_time_ns += 1,
            _ => {
                policy.clock_evidence[0] ^= 1;
                for v in &mut sources {
                    v.clock_evidence = policy.clock_evidence;
                }
            }
        }
        let changed =
            associate_multiview_features(&twin, &sources, policy, &mut WorkBudget::new(WORK))?;
        assert_ne!(original.evidence(), changed.evidence(), "pin {variant}");
        assert_ne!(
            original.components()[0].evidence(),
            changed.components()[0].evidence(),
            "pin {variant}"
        );
    }
    Ok(())
}

#[test]
fn complete_maximum_inventory_and_hard_limits_never_silently_drop_features_or_pair_rows() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let mut sources = views(&twin, 8)?;
    for source in &mut sources {
        replace_features(
            source,
            (0..32)
                .map(|n| feature(n + 1, [20. + n as f64 * 4., 64.], [0; 4]))
                .collect(),
        )?;
    }
    let report = run(&twin, &sources)?;
    assert_eq!(report.pairs().len(), 28);
    assert_eq!(
        report
            .pairs()
            .iter()
            .map(|p| p.report().pairs().len())
            .sum::<usize>(),
        MAX_MULTIVIEW_PAIR_ROWS
    );
    assert_eq!(report.components().len(), 256);
    assert!(
        report
            .components()
            .iter()
            .all(|c| matches!(c.outcome(), ComponentOutcome::Unmatched))
    );
    assert!(
        report
            .pairs()
            .iter()
            .flat_map(|p| p.report().features())
            .all(|f| f.nearest_features.len() == 32)
    );
    let mut too_many = sources.clone();
    let mut features = too_many[0].frame.features().to_vec();
    features.push(feature(33, [152., 64.], [0; 4]));
    replace_features(&mut too_many[0], features)?;
    assert_eq!(run(&twin, &too_many).err(), Some(AssociationError::Limit));
    let mut per_view = views(&twin, 3)?;
    replace_features(
        &mut per_view[0],
        (0..129)
            .map(|n| feature(n + 1, [n as f64 + 0.5, 64.], [0; 4]))
            .collect(),
    )?;
    assert_eq!(run(&twin, &per_view).err(), Some(AssociationError::Limit));
    assert_eq!(
        run(&twin, &views(&twin, 9)?).err(),
        Some(AssociationError::Limit)
    );
    assert_eq!(
        run(&twin, &sources[..2]).err(),
        Some(AssociationError::InvalidInput)
    );
    Ok(())
}

#[test]
fn cumulative_work_and_early_middle_final_cancellation_are_atomic_across_all_pairs_and_components()
-> Test {
    let twin = common::twin(&[-20.], None)?;
    let sources = views(&twin, 4)?;
    let mut work = WorkBudget::new(WORK);
    let full = associate_multiview_features(&twin, &sources, options(), &mut work)?;
    let used = work.used();
    let mut exact = WorkBudget::new(used);
    check_native_equivalence(
        &full,
        &associate_multiview_features(&twin, &sources, options(), &mut exact)?,
    )?;
    assert_eq!(exact.remaining(), 0);
    for limit in [0, 1, used / 2, used - 1] {
        assert_eq!(
            associate_multiview_features(&twin, &sources, options(), &mut WorkBudget::new(limit))
                .err(),
            Some(AssociationError::Geometry(GeometryError::BudgetExhausted))
        );
    }
    let stopped = AtomicBool::new(true);
    assert_eq!(
        associate_multiview_features(
            &twin,
            &sources,
            options(),
            &mut WorkBudget::cancellable(WORK, &stopped)
        )
        .err(),
        Some(AssociationError::Geometry(GeometryError::Cancelled))
    );
    let calls = AtomicUsize::new(0);
    let probe = || {
        calls.fetch_add(1, Ordering::Relaxed);
        false
    };
    associate_multiview_features(
        &twin,
        &sources,
        options(),
        &mut WorkBudget::with_cancellation_probe(WORK, &probe),
    )?;
    let count = calls.load(Ordering::Relaxed);
    assert!(count > 100);
    for cutoff in [1, count / 2, count - 1] {
        calls.store(0, Ordering::Relaxed);
        let probe = || calls.fetch_add(1, Ordering::Relaxed) >= cutoff;
        assert_eq!(
            associate_multiview_features(
                &twin,
                &sources,
                options(),
                &mut WorkBudget::with_cancellation_probe(WORK, &probe)
            )
            .err(),
            Some(AssociationError::Geometry(GeometryError::Cancelled))
        );
    }
    check_native_equivalence(&full, &run(&twin, &sources)?)?;
    Ok(())
}

#[test]
fn joint_points_retain_unknown_calibration_map_scale_and_nominal_mesh_conflicts() -> Test {
    let twin = common::twin(&[4.], None)?;
    let mut sources = horizontal(&twin)?;
    for source in &mut sources {
        source.camera.error = None;
    }
    let report = run(&twin, &sources)?;
    let ComponentOutcome::Fused(point) = report.components()[1].outcome() else {
        return Err("missing conditional point".into());
    };
    assert!(point.has_nominal_occlusion_conflict());
    assert!(
        point
            .visibility()
            .iter()
            .all(|v| v.nominal_occluded == Some(true))
    );
    assert_eq!(point.map_error(), None);
    assert_eq!(point.scale(), ScaleEvidence::Relative);
    assert!(point.inputs().iter().all(|i| i.camera.error.is_none()));
    assert!(
        point
            .estimate()
            .pixel_noise_covariance
            .iter()
            .flatten()
            .all(|v| v.is_finite())
    );
    close(point.estimate().position, POINTS[1], 1e-8);
    Ok(())
}

#![forbid(unsafe_code)]
//! Independently projected trajectories and actual grayscale pixels exercise temporal matching.
//! Numerical scene fixtures do not certify physical calibration, identity, or source custody.
mod common;

use std::collections::BTreeSet;
use std::error::Error;

use fss_core::ContentDigest;
use fss_geometry::temporal_triangulation::TemporalTriangulationOptions;
use fss_geometry::triangulation::TriangulationOptions;
use fss_geometry::{PinholeIntrinsics, RigidPose, WorkBudget};
use fss_twin::feature_association::{
    AssociationOptions, DescriptorDecision, EpipolarDecision, FeatureView, associate_features,
};
use fss_twin::localization::native::{ExtractionOptions, GrayImage, extract_gray};
use fss_twin::localization::{BinaryDescriptor, FeatureFrame, ImageFeature, ImageIdentity};
use fss_twin::multiview_motion::FusedSceneMotion;
use fss_twin::temporal_feature_association::{
    TemporalAssociationOptions, TemporalComponentOutcome, TemporalFeatureAssociation,
    TemporalFeatureComponent, associate_temporal_features,
};
use fss_twin::{PropertyTwin, ScaleEvidence, TrackingCamera};

type Test<T = ()> = Result<T, Box<dyn Error>>;
const WORK: u64 = 1_000_000_000;
const EPOCH: u64 = 2_000_000_000;
const ROTATION: [[f64; 3]; 3] = [[1., 0., 0.], [0., 1., 0.], [0., 0., 1.]];
const CENTERS: [[f64; 3]; 3] = [[0., 0., 0.], [2., 0.3, 0.1], [-1., 0.8, -0.2]];

#[derive(Clone, Copy)]
struct Trajectory {
    position: [f64; 3],
    velocity: [f64; 3],
    acceleration: [f64; 3],
}

const CROSSING: [Trajectory; 2] = [
    Trajectory {
        position: [-0.5, -0.25, 8.],
        velocity: [1., 0.5, 0.1],
        acceleration: [0.; 3],
    },
    Trajectory {
        position: [0.5, 0.25, 8.],
        velocity: [-1., -0.5, 0.1],
        acceleration: [0.; 3],
    },
];

fn options(reference_time_ns: u64) -> TemporalAssociationOptions {
    TemporalAssociationOptions {
        association_basis: [90; 32],
        camera_rig_digest: [91; 32],
        privacy_domain: 5,
        clock: 7,
        clock_evidence: [92; 32],
        reference_time_ns,
        max_capture_span_ns: 3_000_000_000,
        max_capture_uncertainty_ns: 20_000_000,
        maximum_hamming_distance: 0,
        ratio_percent: 80,
        triangulation: TemporalTriangulationOptions {
            max_reprojection_pixels: 0.001,
            ..TemporalTriangulationOptions::default()
        },
    }
}

fn descriptor(point: usize) -> BinaryDescriptor {
    let bytes = ContentDigest::sha256(&(point as u64 + 101).to_le_bytes()).bytes();
    BinaryDescriptor(std::array::from_fn(|word| {
        u64::from_le_bytes(std::array::from_fn(|byte| bytes[word * 8 + byte]))
    }))
}

fn intrinsics() -> Test<PinholeIntrinsics> {
    Ok(PinholeIntrinsics::new(384, 256, 160., 155., 192., 128.)?)
}

fn source_view(
    twin: &PropertyTwin,
    camera: u8,
    capture: [u64; 2],
    frame: FeatureFrame,
    intrinsics: PinholeIntrinsics,
    center: [f64; 3],
) -> Test<FeatureView> {
    Ok(FeatureView {
        image_domain_digest: frame.identity().image_domain,
        source_digest: frame.identity().pixels,
        frame,
        camera: TrackingCamera {
            geometry: twin.basis(),
            camera: u64::from(camera),
            calibration: u64::from(camera) + 10,
            image_domain: u64::from(camera) + 20,
            clock: 7,
            validity: [0, u64::MAX],
            pose: RigidPose::from_center(ROTATION, center)?,
            intrinsics,
            error: None,
        },
        allowed_mask_digest: [camera + 70; 32],
        mapping_basis: [camera + 80; 32],
        privacy_domain: 5,
        clock_evidence: [92; 32],
        capture,
        sigma_pixels: 0.5,
    })
}

fn sources(
    twin: &PropertyTwin,
    cameras: usize,
    offsets: &[i128],
    epoch: u64,
    uncertainty: u64,
    trajectories: &[Trajectory],
) -> Test<Vec<FeatureView>> {
    let mut result = Vec::new();
    for (camera_index, center) in CENTERS[..cameras].iter().copied().enumerate() {
        let camera = camera_index as u8 + 1;
        for &offset in offsets {
            let offset = offset + camera_index as i128 * 75_000_000;
            let capture = u64::try_from(i128::from(epoch) + offset)?;
            let dt = offset as f64 * 1e-9;
            let exposure = result.len() as u8 + 1;
            let features = trajectories
                .iter()
                .enumerate()
                .map(|(index, trajectory)| {
                    let point: [f64; 3] = std::array::from_fn(|axis| {
                        trajectory.position[axis]
                            + trajectory.velocity[axis] * dt
                            + 0.5 * trajectory.acceleration[axis] * dt * dt
                    });
                    // Frame-local IDs deliberately reverse their physical-point order in
                    // alternate exposures, while descriptors preserve the correspondence.
                    let local = if exposure.is_multiple_of(2) {
                        trajectories.len() - index
                    } else {
                        index + 1
                    };
                    ImageFeature {
                        id: u64::from(exposure) * 100 + local as u64,
                        // Independent scalar projection. No production project/ray helper.
                        pixel: [
                            160. * (point[0] - center[0]) / (point[2] - center[2]) + 192.,
                            155. * (point[1] - center[1]) / (point[2] - center[2]) + 128.,
                        ],
                        descriptor: descriptor(index),
                    }
                })
                .collect();
            let frame = FeatureFrame::new(
                ImageIdentity {
                    exposure: [exposure; 32],
                    pixels: [exposure + 30; 32],
                    image_domain: [camera + 60; 32],
                    dimensions: [384, 256],
                },
                [77; 32],
                features,
                &mut WorkBudget::new(WORK),
            )?;
            result.push(source_view(
                twin,
                camera,
                [capture - uncertainty, capture + uncertainty],
                frame,
                intrinsics()?,
                center,
            )?);
        }
    }
    Ok(result)
}

fn analyze(
    twin: &PropertyTwin,
    sources: &[FeatureView],
    reference: u64,
) -> Test<TemporalFeatureAssociation> {
    Ok(associate_temporal_features(
        twin,
        sources,
        options(reference),
        &mut WorkBudget::new(WORK),
    )?)
}

fn point_index(
    report: &TemporalFeatureAssociation,
    component: &TemporalFeatureComponent,
) -> Test<usize> {
    let member = component
        .members()
        .first()
        .ok_or("empty motion component")?;
    let feature = report.views()[member.view]
        .frame
        .features()
        .iter()
        .find(|feature| feature.id == member.feature)
        .ok_or("missing original motion feature")?;
    (0..2)
        .find(|index| feature.descriptor == descriptor(*index))
        .ok_or("unexpected motion descriptor".into())
}

fn motion(component: &TemporalFeatureComponent) -> Test<&FusedSceneMotion> {
    match component.outcome() {
        TemporalComponentOutcome::Fused(value) => Ok(value),
        other => Err(format!("expected actual joint motion, got {other:?}").into()),
    }
}

fn close(actual: [f64; 3], expected: [f64; 3], tolerance: f64) {
    for (actual_axis, expected_axis) in actual.into_iter().zip(expected) {
        assert!(
            (actual_axis - expected_axis).abs() < tolerance,
            "{actual:?} != {expected:?}"
        );
    }
}

#[test]
fn staggered_two_and_three_camera_exposures_recover_crossing_points_at_one_scene_time() -> Test {
    let twin = common::twin(&[-20.], Some(0.25))?;
    for cameras in [2, 3] {
        let inputs = sources(
            &twin,
            cameras,
            &[-700_000_000, 650_000_000],
            EPOCH,
            3_000_000,
            &CROSSING,
        )?;
        let report = analyze(&twin, &inputs, EPOCH)?;
        assert_eq!(report.views().len(), cameras * 2);
        assert_eq!(report.pairs().len(), inputs.len() * (inputs.len() - 1) / 2);
        assert_eq!(report.components().len(), 2);
        assert!(
            report
                .pairs()
                .iter()
                .all(|pair| pair.pairs().len() == 4 && pair.features().len() == 4)
        );
        for component in report.components() {
            let point = point_index(&report, component)?;
            let fitted = motion(component)?;
            close(fitted.estimate().position, CROSSING[point].position, 1e-8);
            close(
                fitted.estimate().velocity_per_second,
                CROSSING[point].velocity,
                1e-8,
            );
            assert_eq!(fitted.estimate().reference_time_ns, i128::from(EPOCH));
            assert_eq!(component.requested_scene_time_ns(), EPOCH);
            assert_eq!(fitted.request().reference_time_ns, EPOCH);
            assert_eq!(fitted.request().association_evidence, component.evidence());
            assert_eq!(fitted.inputs().len(), inputs.len());
            assert_eq!(fitted.visibility().len(), inputs.len());
            assert_eq!(fitted.estimate().residuals.len(), inputs.len());
            assert_eq!(component.members().len(), inputs.len());
            assert_eq!(
                component.links().len(),
                inputs.len() * (inputs.len() - 1) / 2
            );
            assert_eq!(
                fitted
                    .inputs()
                    .iter()
                    .map(|input| input.camera.camera)
                    .collect::<BTreeSet<_>>()
                    .len(),
                cameras
            );
            assert_eq!(fitted.map_error(), Some(0.25));
            assert_eq!(fitted.scale(), ScaleEvidence::Relative);
            assert!(
                fitted
                    .inputs()
                    .iter()
                    .all(|input| input.camera.error.is_none())
            );
            assert!(fitted.estimate().rms_reprojection_pixels < 1e-8);
            assert!(!fitted.has_nominal_occlusion_conflict());
            for member in component.members() {
                let source = &report.views()[member.view];
                assert_eq!(member.camera, source.camera.camera);
                let feature = source
                    .frame
                    .features()
                    .iter()
                    .find(|feature| feature.id == member.feature)
                    .ok_or("missing source feature")?;
                assert_eq!(feature.descriptor, descriptor(point));
                assert!(
                    fitted
                        .inputs()
                        .iter()
                        .any(|input| input.camera.camera == member.camera
                            && input.observation.capture == source.capture
                            && input.observation.pixel_min == feature.pixel
                            && input.observation.pixel_max == feature.pixel)
                );
            }
        }
        // These are genuinely crossing trajectories between the original exposures;
        // frame-local feature order is not a motion identity or association oracle.
        assert!(CROSSING[0].position[0] < CROSSING[1].position[0]);
        assert!(
            CROSSING[0].position[0] + CROSSING[0].velocity[0] * 0.65
                > CROSSING[1].position[0] + CROSSING[1].velocity[0] * 0.65
        );
    }
    Ok(())
}

#[test]
fn reference_time_propagates_full_state_covariance_without_losing_large_epoch_nanoseconds() -> Test
{
    let twin = common::twin(&[-20.], None)?;
    let inputs = sources(&twin, 3, &[-700_000_000, 650_000_000], EPOCH, 7, &CROSSING)?;
    let initial = analyze(&twin, &inputs, EPOCH)?;
    let later = analyze(&twin, &inputs, EPOCH + 300_000_000)?;
    for component in initial.components() {
        let index = point_index(&initial, component)?;
        let original = motion(component)?.estimate();
        let corresponding = later
            .components()
            .iter()
            .find(|other| point_index(&later, other).ok() == Some(index))
            .ok_or("missing later trajectory")?;
        let moved = motion(corresponding)?.estimate();
        close(
            moved.position,
            std::array::from_fn(|axis| {
                CROSSING[index].position[axis] + CROSSING[index].velocity[axis] * 0.3
            }),
            1e-8,
        );
        close(
            moved.velocity_per_second,
            original.velocity_per_second,
            1e-9,
        );
        assert_eq!(moved.reference_time_ns, i128::from(EPOCH + 300_000_000));
        for row in 0..6 {
            for column in 0..6 {
                let mut expected = original.pixel_noise_covariance[row][column];
                if row < 3 {
                    expected += 0.3 * original.pixel_noise_covariance[row + 3][column];
                }
                if column < 3 {
                    expected += 0.3 * original.pixel_noise_covariance[row][column + 3];
                }
                if row < 3 && column < 3 {
                    expected += 0.09 * original.pixel_noise_covariance[row + 3][column + 3];
                }
                assert!((moved.pixel_noise_covariance[row][column] - expected).abs() < 1e-11);
            }
        }
    }
    let high_epoch = u64::MAX - 5_000_000_000;
    let high_sources = sources(
        &twin,
        3,
        &[-700_000_000, 650_000_000],
        high_epoch,
        7,
        &CROSSING,
    )?;
    let high = analyze(&twin, &high_sources, high_epoch)?;
    for component in high.components() {
        let index = point_index(&high, component)?;
        let fitted = motion(component)?;
        close(fitted.estimate().position, CROSSING[index].position, 1e-8);
        close(
            fitted.estimate().velocity_per_second,
            CROSSING[index].velocity,
            1e-8,
        );
        assert_eq!(fitted.estimate().reference_time_ns, i128::from(high_epoch));
        assert_eq!(component.requested_scene_time_ns(), high_epoch);
        assert!(
            fitted
                .inputs()
                .iter()
                .all(|input| input.observation.capture[1] - input.observation.capture[0] == 14)
        );
        assert_eq!(
            fitted.capture_hull(),
            [high_epoch - 700_000_007, high_epoch + 800_000_007]
        );
    }
    Ok(())
}

#[test]
fn duplicated_descriptors_in_one_exposure_cannot_add_motion_support_or_silently_pick_an_alias()
-> Test {
    let twin = common::twin(&[-20.], None)?;
    let mut inputs = sources(&twin, 3, &[-700_000_000, 650_000_000], EPOCH, 0, &CROSSING)?;
    let duplicate_exposure = inputs[0].frame.identity().exposure;
    let mut features = inputs[0].frame.features().to_vec();
    for feature in &mut features {
        feature.descriptor = descriptor(0);
    }
    inputs[0].frame = FeatureFrame::new(
        inputs[0].frame.identity(),
        inputs[0].frame.descriptor_domain(),
        features,
        &mut WorkBudget::new(WORK),
    )?;
    let report = analyze(&twin, &inputs, EPOCH)?;
    let mut fused = 0;
    let mut unmatched = 0;
    for component in report.components() {
        match component.outcome() {
            TemporalComponentOutcome::Fused(result) => {
                fused += 1;
                assert_eq!(component.members().len(), 5);
                assert_eq!(result.inputs().len(), 5);
                assert!(component.members().iter().all(|member| {
                    report.views()[member.view].frame.identity().exposure != duplicate_exposure
                }));
                let index = point_index(&report, component)?;
                close(result.estimate().position, CROSSING[index].position, 1e-8);
                close(
                    result.estimate().velocity_per_second,
                    CROSSING[index].velocity,
                    1e-8,
                );
            }
            TemporalComponentOutcome::Unmatched => {
                unmatched += 1;
                assert_eq!(component.members().len(), 1);
                assert_eq!(
                    report.views()[component.members()[0].view]
                        .frame
                        .identity()
                        .exposure,
                    duplicate_exposure
                );
            }
            other => return Err(format!("unexpected alias outcome: {other:?}").into()),
        }
    }
    assert_eq!((fused, unmatched), (2, 2));
    assert_eq!(
        report
            .components()
            .iter()
            .map(|component| component.members().len())
            .sum::<usize>(),
        12
    );
    Ok(())
}

#[test]
fn incompatible_acceleration_refuses_the_whole_component_and_preserves_the_linear_control() -> Test
{
    let twin = common::twin(&[-20.], None)?;
    let mut paths = CROSSING;
    paths[0].acceleration = [0.3, 1.2, 0.4];
    let inputs = sources(
        &twin,
        3,
        &[-800_000_000, -250_000_000, 400_000_000, 950_000_000],
        EPOCH,
        0,
        &paths,
    )?;
    let report = analyze(&twin, &inputs, EPOCH)?;
    assert_eq!(report.components().len(), 2);
    for component in report.components() {
        let index = point_index(&report, component)?;
        assert_eq!(component.members().len(), 12);
        assert_eq!(component.links().len(), 66);
        if index == 0 {
            assert!(
                matches!(component.outcome(), TemporalComponentOutcome::Refused(_)),
                "accelerating feature was accepted under constant velocity"
            );
        } else {
            let fitted = motion(component)?;
            assert_eq!(fitted.inputs().len(), 12);
            close(fitted.estimate().position, paths[1].position, 1e-8);
            close(
                fitted.estimate().velocity_per_second,
                paths[1].velocity,
                1e-8,
            );
        }
    }
    Ok(())
}

#[test]
fn four_actual_grayscale_exposures_recover_plane_motion_that_static_epipolar_matching_rejects()
-> Test {
    let twin = common::twin(&[-20.], None)?;
    let width = 256_usize;
    let height = 192_usize;
    let stride = width + 96;
    let mut seed = 0x7135_u32;
    let texture: Vec<_> = (0..stride * (height + 64))
        .map(|_| {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (seed >> 24) as u8
        })
        .collect();
    let mask = vec![1; width * height];
    let mut inputs = Vec::new();
    for quarter in 0..4_usize {
        let camera_index = quarter % 2;
        let camera = camera_index as u8 + 1;
        // Plane z10, focal160, baseline2: camera disparity32px. Motion [1,.5,0]
        // gives [+4,+2] image pixels per quarter second; inverse texture lookup
        // supplies the actual source bytes independently of projection/geometry code.
        let horizontal = 32 + camera_index * 32 - quarter * 4;
        let vertical = 32 - quarter * 2;
        let pixels: Vec<_> = (0..height)
            .flat_map(|row| {
                let texture = &texture;
                (0..width)
                    .map(move |column| texture[(row + vertical) * stride + column + horizontal])
            })
            .collect();
        let capture = 1_000_000_000 + quarter as u64 * 250_000_000;
        let identity = ImageIdentity {
            exposure: [quarter as u8 + 1; 32],
            pixels: ContentDigest::sha256(&pixels).bytes(),
            image_domain: [camera + 60; 32],
            dimensions: [width as u32, height as u32],
        };
        let mut work = WorkBudget::new(WORK);
        let image = GrayImage::new(identity, &pixels, &mask, &mut work)?;
        let extracted = extract_gray(
            &image,
            ExtractionOptions {
                threshold: 30,
                maximum_features: 64,
                separation: 5,
            },
            &mut work,
        )?;
        assert_eq!(extracted.frame.features().len(), 64);
        let mut source = source_view(
            &twin,
            camera,
            [capture; 2],
            extracted.frame,
            PinholeIntrinsics::new(width as u32, height as u32, 160., 160., 128., 96.)?,
            [camera_index as f64 * 2., 0., 0.],
        )?;
        source.allowed_mask_digest = extracted.selection.mask_digest;
        inputs.push(source);
    }
    let reference = 1_375_000_000;
    let report = analyze(&twin, &inputs, reference)?;
    assert_eq!(report.views().len(), 4);
    assert_eq!(report.pairs().len(), 6);
    assert_eq!(
        report
            .pairs()
            .iter()
            .map(|pair| pair.pairs().len())
            .sum::<usize>(),
        24_576
    );
    let mut solved = 0;
    for component in report.components() {
        if let TemporalComponentOutcome::Fused(fitted) = component.outcome() {
            solved += 1;
            assert_eq!(component.members().len(), 4);
            assert_eq!(fitted.inputs().len(), 4);
            assert_eq!(fitted.estimate().reference_time_ns, i128::from(reference));
            close(fitted.estimate().velocity_per_second, [1., 0.5, 0.], 1e-7);
            let first = component
                .members()
                .iter()
                .find(|member| report.views()[member.view].capture[0] == 1_000_000_000)
                .ok_or("complete native component lost its first capture")?;
            let feature = report.views()[first.view]
                .frame
                .features()
                .iter()
                .find(|feature| feature.id == first.feature)
                .ok_or("native first feature missing")?;
            close(
                fitted.estimate().position,
                [
                    (feature.pixel[0] - 128.) / 160. * 10. + 0.375,
                    (feature.pixel[1] - 96.) / 160. * 10. + 0.1875,
                    10.,
                ],
                1e-7,
            );
            assert!(fitted.estimate().rms_reprojection_pixels < 1e-7);
        }
    }
    assert!(
        solved >= 12,
        "only {solved} complete native moving features reconstructed"
    );
    let static_report = associate_features(
        &twin,
        [&inputs[0], &inputs[1]],
        AssociationOptions {
            association_basis: [90; 32],
            camera_rig_digest: [91; 32],
            privacy_domain: 5,
            clock: 7,
            clock_evidence: [92; 32],
            reference_time_ns: 1_125_000_000,
            max_capture_span_ns: 250_000_000,
            maximum_hamming_distance: 0,
            ratio_percent: 80,
            maximum_epipolar_distance_pixels: 0.01,
            triangulation: TriangulationOptions::default(),
        },
        &mut WorkBudget::new(WORK),
    )?;
    let candidates: Vec<_> = static_report
        .pairs()
        .iter()
        .filter(|pair| pair.descriptor == DescriptorDecision::Candidate)
        .collect();
    assert!(candidates.len() >= 12);
    assert!(
        candidates
            .iter()
            .all(|pair| pair.epipolar == EpipolarDecision::OutsideGate)
    );
    assert!(static_report.hypotheses().is_empty());
    Ok(())
}

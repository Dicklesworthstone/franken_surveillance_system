#![forbid(unsafe_code)]
//! Native reconstruction -> portable atlas -> genuinely fresh image localization.
//! The numerical oracles are authored independently of production projection helpers.
//! Source custody, field calibration, and enduring-static support are not inferred here.
mod common;

use std::collections::BTreeSet;
use std::error::Error;

use fss_core::ContentDigest;
use fss_geometry::triangulation::TriangulationOptions;
use fss_geometry::{PinholeIntrinsics, PoseSolverOptions, RigidPose, WorkBudget};
use fss_twin::atlas_archive::{ArchiveExpectation, ArchivedAtlas, decode_atlas, encode_atlas};
use fss_twin::feature_association::{
    AssociationOptions, FeatureHypothesisOutcome, FeatureView, associate_features,
};
use fss_twin::localization::native::{
    ExtractionOptions, GrayImage, ImageLocalizationOptions, extract_gray, localize_gray_frame,
};
use fss_twin::localization::{
    BinaryDescriptor, FeatureFrame, ImageFeature, ImageIdentity, LocalizationCamera,
    LocalizationError, LocalizationOutcome, MatchOptions, MatchRejection,
};
use fss_twin::multiview_feature_association::{ComponentOutcome, associate_multiview_features};
use fss_twin::reconstruction_atlas::{
    AtlasBuildRequest, LandmarkSelection, ReconstructedAtlas, Reconstruction, ReferenceSource,
    build_reconstruction_atlas,
};
use fss_twin::{ProjectionError, PropertyTwin, TrackingCamera};

type Test<T = ()> = Result<T, Box<dyn Error>>;
const WORK: u64 = 1_000_000_000;
const IDENTITY: [[f64; 3]; 3] = [[1., 0., 0.], [0., 1., 0.], [0., 0., 1.]];
const DIMENSIONS: [u32; 2] = [800, 600];
const POINTS: [[f64; 3]; 12] = [
    [-2.1, -1.2, 6.1],
    [-0.8, -1.6, 8.7],
    [0.6, -1.0, 7.3],
    [2.2, -0.8, 9.4],
    [-2.0, 0.2, 9.1],
    [-0.4, 0.5, 6.8],
    [0.9, 0.3, 10.2],
    [2.4, 0.7, 7.6],
    [-1.5, 1.5, 7.9],
    [-0.2, 1.9, 10.1],
    [1.3, 1.4, 6.5],
    [2.8, 1.6, 9.8],
];

fn budget() -> WorkBudget<'static> {
    WorkBudget::new(WORK)
}

fn descriptor(id: u64) -> BinaryDescriptor {
    let bytes = ContentDigest::sha256(&id.to_le_bytes()).bytes();
    BinaryDescriptor(std::array::from_fn(|word| {
        let offset = word * 8;
        u64::from_le_bytes(std::array::from_fn(|byte| bytes[offset + byte]))
    }))
}

fn intrinsics() -> Test<PinholeIntrinsics> {
    Ok(PinholeIntrinsics::new(800, 600, 420., 445., 390., 280.)?)
}

fn association_options() -> AssociationOptions {
    AssociationOptions {
        association_basis: [90; 32],
        camera_rig_digest: [91; 32],
        privacy_domain: 2,
        clock: 1,
        clock_evidence: [92; 32],
        reference_time_ns: 100,
        max_capture_span_ns: 20,
        maximum_hamming_distance: 0,
        ratio_percent: 80,
        maximum_epipolar_distance_pixels: 0.001,
        triangulation: TriangulationOptions::default(),
    }
}

fn pose_options() -> PoseSolverOptions {
    PoseSolverOptions {
        ransac_trials: 0,
        inlier_threshold_px: 0.01,
        minimum_inliers: 8,
        minimum_inlier_fraction: 0.99,
        ..PoseSolverOptions::default()
    }
}

fn exact_matching() -> MatchOptions {
    MatchOptions {
        maximum_distance: 0,
        ..MatchOptions::default()
    }
}

fn identity(camera: u8, dimensions: [u32; 2]) -> ImageIdentity {
    ImageIdentity {
        exposure: [camera; 32],
        pixels: [camera + 20; 32],
        image_domain: [camera + 40; 32],
        dimensions,
    }
}

fn source_view(
    twin: &PropertyTwin,
    camera: u8,
    center: [f64; 3],
    intrinsics: PinholeIntrinsics,
    frame: FeatureFrame,
) -> Test<FeatureView> {
    Ok(FeatureView {
        image_domain_digest: frame.identity().image_domain,
        frame,
        camera: TrackingCamera {
            geometry: twin.basis(),
            camera: u64::from(camera),
            calibration: 1,
            image_domain: u64::from(camera) + 40,
            clock: 1,
            validity: [0, 1000],
            pose: RigidPose::from_center(IDENTITY, center)?,
            intrinsics,
            error: Some(ProjectionError::EXACT),
        },
        source_digest: [camera + 60; 32],
        allowed_mask_digest: [camera + 80; 32],
        mapping_basis: [camera + 100; 32],
        privacy_domain: 2,
        clock_evidence: [92; 32],
        capture: [90, 110],
        sigma_pixels: 0.5,
    })
}

fn nonplanar_sources(twin: &PropertyTwin, cameras: usize) -> Test<Vec<FeatureView>> {
    let centers = [[-1.2, 0.1, 0.2], [1.4, -0.35, -0.1], [0.3, 1.2, 0.4]];
    centers[..cameras]
        .iter()
        .enumerate()
        .map(|(index, &center)| {
            let camera = index as u8 + 1;
            let mut features: Vec<_> = POINTS
                .iter()
                .enumerate()
                .map(|(index, point)| ImageFeature {
                    id: u64::from(camera) * 100 + index as u64 + 1,
                    // Independent scalar pinhole formula, not RigidPose::project/ray.
                    pixel: [
                        420. * (point[0] - center[0]) / (point[2] - center[2]) + 390.,
                        445. * (point[1] - center[1]) / (point[2] - center[2]) + 280.,
                    ],
                    descriptor: descriptor(index as u64 + 1),
                })
                .collect();
            // Keep a real unbound image feature in each copied frame. It must not be
            // silently pruned when only the twelve reconstructed points are admitted.
            features.push(ImageFeature {
                id: u64::from(camera) * 100 + 99,
                pixel: [42., 41.],
                descriptor: descriptor(1000 + u64::from(camera)),
            });
            source_view(
                twin,
                camera,
                center,
                intrinsics()?,
                FeatureFrame::new(
                    identity(camera, DIMENSIONS),
                    [77; 32],
                    features,
                    &mut budget(),
                )?,
            )
        })
        .collect()
}

fn reference_sources(views: &[FeatureView]) -> Vec<ReferenceSource> {
    views
        .iter()
        .map(|view| ReferenceSource {
            camera: view.camera.camera,
            source_record: ContentDigest::sha256(
                format!("authored-atlas-source-recipe/{}", view.camera.camera).as_bytes(),
            )
            .bytes(),
        })
        .collect()
}

fn selections(pins: impl Iterator<Item = [u8; 32]>) -> Vec<LandmarkSelection> {
    pins.enumerate()
        .map(|(index, hypothesis)| LandmarkSelection {
            hypothesis,
            landmark: index as u64 + 1,
            physical_group: index as u64 + 1001,
            feature: 0,
            enduring_static_basis: [120; 32],
        })
        .collect()
}

fn reconstruct(twin: &PropertyTwin, views: &[FeatureView]) -> Test<ReconstructedAtlas> {
    let references = reference_sources(views);
    if views.len() == 2 {
        let association = associate_features(
            twin,
            [&views[0], &views[1]],
            association_options(),
            &mut budget(),
        )?;
        let selected = selections(association.hypotheses().iter().filter_map(|hypothesis| {
            matches!(hypothesis.outcome, FeatureHypothesisOutcome::Fused(_))
                .then_some(hypothesis.evidence)
        }));
        Ok(build_reconstruction_atlas(
            twin,
            &AtlasBuildRequest {
                association_evidence: association.evidence(),
                selections: &selected,
                references: &references,
            },
            Reconstruction::Pair(&association),
            &mut budget(),
        )?)
    } else {
        let association =
            associate_multiview_features(twin, views, association_options(), &mut budget())?;
        let selected = selections(association.components().iter().filter_map(|component| {
            matches!(component.outcome(), ComponentOutcome::Fused(_))
                .then_some(component.evidence())
        }));
        Ok(build_reconstruction_atlas(
            twin,
            &AtlasBuildRequest {
                association_evidence: association.evidence(),
                selections: &selected,
                references: &references,
            },
            Reconstruction::Multiview(&association),
            &mut budget(),
        )?)
    }
}

fn roundtrip(twin: &PropertyTwin, built: &ReconstructedAtlas) -> Test<ArchivedAtlas> {
    let provenance = built.receipt().digest();
    let bytes = encode_atlas(built.atlas(), provenance, built.references(), &mut budget())?;
    assert_eq!(&bytes[..8], b"FSATLAS1");
    let first = built
        .atlas()
        .references()
        .first()
        .ok_or("missing atlas reference")?;
    let loaded = decode_atlas(
        &bytes,
        twin,
        ArchiveExpectation {
            package: ContentDigest::sha256(&bytes).bytes(),
            provenance,
            descriptor: first.frame.descriptor_domain(),
        },
        &mut budget(),
    )?;
    assert_eq!(loaded.atlas().digest(), built.atlas().digest());
    assert_eq!(loaded.provenance(), provenance);
    assert_eq!(loaded.references(), built.references());
    assert_eq!(
        encode_atlas(
            loaded.atlas(),
            provenance,
            loaded.references(),
            &mut budget()
        )?,
        bytes
    );
    Ok(loaded)
}

fn assert_lineage(built: &ReconstructedAtlas, loaded: &ArchivedAtlas, sources: &[FeatureView]) {
    assert_eq!(loaded.atlas().references().len(), sources.len());
    assert_eq!(built.receipt().sources.len(), sources.len());
    let source_records = reference_sources(sources);
    for (((reference, provenance), receipt), (source, record)) in loaded
        .atlas()
        .references()
        .iter()
        .zip(loaded.references())
        .zip(&built.receipt().sources)
        .zip(sources.iter().zip(source_records))
    {
        assert_eq!(reference.id, source.camera.camera);
        assert_eq!(reference.frame.identity(), source.frame.identity());
        assert_eq!(reference.frame.features(), source.frame.features());
        assert_eq!(
            reference.frame.descriptor_domain(),
            source.frame.descriptor_domain()
        );
        assert_eq!(provenance.reference, source.camera.camera);
        assert_eq!(provenance.source_record, record.source_record);
        assert_eq!(provenance.allowed_mask, source.allowed_mask_digest);
        assert_eq!(receipt.camera, source.camera.camera);
        assert_eq!(receipt.source_record, record.source_record);
        assert_eq!(receipt.source_digest, source.source_digest);
        assert_eq!(receipt.frame, source.frame.identity());
        assert_eq!(receipt.descriptor_domain, source.frame.descriptor_domain());
        assert_eq!(receipt.allowed_mask, source.allowed_mask_digest);
        assert_eq!(receipt.feature_count, source.frame.features().len());
        assert!(receipt.included);
    }
    assert!(
        loaded
            .atlas()
            .landmarks()
            .iter()
            .all(|point| point.error.is_none())
    );
}

fn fresh_query() -> Test<(FeatureFrame, RigidPose)> {
    let (sy, cy) = 0.13_f64.sin_cos();
    let (sp, cp) = (-0.07_f64).sin_cos();
    let rotation = [
        [cy, 0., sy],
        [sp * sy, cp, -sp * cy],
        [-cp * sy, sp, cp * cy],
    ];
    let center = [0.45, -0.35, -0.4];
    let features = POINTS
        .iter()
        .enumerate()
        .map(|(index, point)| {
            let x = point[0] - center[0];
            let y = point[1] - center[1];
            let z = point[2] - center[2];
            // Direct yaw then pitch; these pixels do not use the pose being tested.
            let yaw_x = cy * x + sy * z;
            let yaw_z = -sy * x + cy * z;
            let camera_y = cp * y - sp * yaw_z;
            let depth = sp * y + cp * yaw_z;
            ImageFeature {
                id: index as u64 + 501,
                pixel: [420. * yaw_x / depth + 390., 445. * camera_y / depth + 280.],
                descriptor: descriptor(index as u64 + 1),
            }
        })
        .collect();
    Ok((
        FeatureFrame::new(identity(150, DIMENSIONS), [77; 32], features, &mut budget())?,
        RigidPose::from_center(rotation, center)?,
    ))
}

fn close(actual: [f64; 3], expected: [f64; 3], tolerance: f64) {
    for (actual_axis, expected_axis) in actual.into_iter().zip(expected) {
        assert!(
            (actual_axis - expected_axis).abs() < tolerance,
            "{actual:?} != {expected:?}"
        );
    }
}

fn assert_nonplanar_localization(cameras: usize) -> Test {
    let twin = common::twin(&[-20.], None)?;
    let sources = nonplanar_sources(&twin, cameras)?;
    let built = reconstruct(&twin, &sources)?;
    assert_eq!(built.atlas().landmarks().len(), POINTS.len());
    assert_eq!(built.atlas().bindings().len(), POINTS.len() * cameras);
    for (landmark, expected) in built.atlas().landmarks().iter().zip(POINTS) {
        close(landmark.world, expected, 1e-8);
    }
    let loaded = roundtrip(&twin, &built)?;
    assert_lineage(&built, &loaded, &sources);
    assert!(
        loaded
            .atlas()
            .references()
            .iter()
            .all(|view| view.frame.features().len() == 13)
    );
    let (query, expected) = fresh_query()?;
    let result = loaded.atlas().localize(
        &twin,
        &query,
        LocalizationCamera {
            intrinsics: intrinsics()?,
            image_domain: query.identity().image_domain,
        },
        exact_matching(),
        pose_options(),
        &mut budget(),
    )?;
    assert_eq!(result.matches.correspondences.len(), POINTS.len());
    assert_eq!(result.matches.decisions.len(), POINTS.len());
    assert!(
        result
            .matches
            .decisions
            .iter()
            .all(|decision| decision.distance == 0 && decision.rejection.is_none())
    );
    let physical_support: BTreeSet<_> = result
        .matches
        .correspondences
        .iter()
        .map(|point| point.physical_group)
        .collect();
    assert_eq!(physical_support.len(), POINTS.len());
    let LocalizationOutcome::Candidates(search) = result.outcome else {
        return Err("reconstructed atlas did not recover the fresh nonplanar camera pose".into());
    };
    assert!(search.planar_support().is_none());
    assert_eq!(search.candidates().len(), 1);
    let candidate = &search.candidates()[0];
    assert_eq!(candidate.inlier_landmarks().len(), POINTS.len());
    assert!(candidate.rms_px() < 1e-7);
    close(candidate.pose().center(), expected.center(), 1e-7);
    for (actual, expected) in candidate
        .pose()
        .rotation()
        .into_iter()
        .zip(expected.rotation())
    {
        close(actual, expected, 1e-8);
    }
    Ok(())
}

#[test]
fn stereo_reconstruction_roundtrips_into_a_fresh_nonplanar_pose() -> Test {
    assert_nonplanar_localization(2)
}

#[test]
fn joint_reconstruction_preserves_all_three_views_without_inflating_physical_support() -> Test {
    assert_nonplanar_localization(3)
}

#[test]
fn archived_reference_exposure_cannot_be_reused_through_a_different_pixel_or_domain_wrapper() -> Test
{
    let twin = common::twin(&[-20.], None)?;
    let sources = nonplanar_sources(&twin, 3)?;
    let loaded = roundtrip(&twin, &reconstruct(&twin, &sources)?)?;
    let (fresh, _) = fresh_query()?;
    for source in &sources {
        let replayed = FeatureFrame::new(
            ImageIdentity {
                exposure: source.frame.identity().exposure,
                ..fresh.identity()
            },
            fresh.descriptor_domain(),
            fresh.features().to_vec(),
            &mut budget(),
        )?;
        assert_ne!(replayed.identity().pixels, source.frame.identity().pixels);
        assert_ne!(
            replayed.identity().image_domain,
            source.frame.identity().image_domain
        );
        assert!(matches!(
            loaded.atlas().localize(
                &twin,
                &replayed,
                LocalizationCamera {
                    intrinsics: intrinsics()?,
                    image_domain: replayed.identity().image_domain
                },
                exact_matching(),
                pose_options(),
                &mut budget(),
            ),
            Err(LocalizationError::ReferenceExposure)
        ));
    }
    Ok(())
}

#[test]
fn query_descriptor_aliases_do_not_gain_support_from_multiple_archived_references() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let sources = nonplanar_sources(&twin, 3)?;
    let loaded = roundtrip(&twin, &reconstruct(&twin, &sources)?)?;
    let (fresh, _) = fresh_query()?;
    let mut features = fresh.features().to_vec();
    features.push(ImageFeature {
        id: 999,
        pixel: [40., 45.],
        descriptor: features[0].descriptor,
    });
    let aliased = FeatureFrame::new(
        fresh.identity(),
        fresh.descriptor_domain(),
        features,
        &mut budget(),
    )?;
    let report = loaded
        .atlas()
        .match_frame(&twin, &aliased, exact_matching(), &mut budget())?;
    assert_eq!(loaded.atlas().bindings().len(), 36);
    assert_eq!(report.correspondences.len(), 11);
    assert_eq!(report.decisions.len(), 13);
    assert_eq!(
        report
            .decisions
            .iter()
            .filter(|decision| decision.rejection == Some(MatchRejection::NonMutual))
            .count(),
        2
    );
    assert_eq!(
        report
            .correspondences
            .iter()
            .map(|point| point.physical_group)
            .collect::<BTreeSet<_>>()
            .len(),
        11
    );
    Ok(())
}

const TEXTURE_WIDTH: usize = 192;
const TEXTURE_HEIGHT: usize = 128;
const TEXTURE_STRIDE: usize = TEXTURE_WIDTH + 24;

fn texture() -> Vec<u8> {
    let mut seed = 0x52a1_u32;
    (0..TEXTURE_STRIDE * TEXTURE_HEIGHT)
        .map(|_| {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (seed >> 24) as u8
        })
        .collect()
}

fn texture_pixels(texture: &[u8], shift: usize) -> Vec<u8> {
    (0..TEXTURE_HEIGHT)
        .flat_map(|row| {
            (0..TEXTURE_WIDTH).map(move |column| texture[row * TEXTURE_STRIDE + column + shift])
        })
        .collect()
}

fn extraction_options() -> ExtractionOptions {
    ExtractionOptions {
        threshold: 30,
        maximum_features: 64,
        separation: 5,
    }
}

fn texture_intrinsics() -> Test<PinholeIntrinsics> {
    Ok(PinholeIntrinsics::new(192, 128, 120., 120., 96., 64.)?)
}

fn native_sources(twin: &PropertyTwin, texture: &[u8], cameras: usize) -> Test<Vec<FeatureView>> {
    (0..cameras)
        .map(|index| {
            let camera = index as u8 + 1;
            let pixels = texture_pixels(texture, index * 12);
            let mut allowed = vec![1; pixels.len()];
            // Deny a real interior pixel, so native detection/description must exclude
            // its complete 33x33 support footprint. Masks differ across source views.
            let denied_column = 96 + index * 3;
            allowed[64 * TEXTURE_WIDTH + denied_column] = 0;
            let image_identity = ImageIdentity {
                pixels: ContentDigest::sha256(&pixels).bytes(),
                ..identity(camera, [192, 128])
            };
            let image = GrayImage::new(image_identity, &pixels, &allowed, &mut budget())?;
            let extracted = extract_gray(&image, extraction_options(), &mut budget())?;
            assert!(extracted.frame.features().len() >= 32);
            assert_eq!(
                extracted.selection.mask_digest,
                ContentDigest::sha256(&allowed).bytes()
            );
            for feature in extracted.frame.features() {
                assert!(
                    (feature.pixel[0] - denied_column as f64).abs() > 16.
                        || (feature.pixel[1] - 64.).abs() > 16.
                );
            }
            let mut source = source_view(
                twin,
                camera,
                [index as f64, 0., 0.],
                texture_intrinsics()?,
                extracted.frame,
            )?;
            source.source_digest = ContentDigest::sha256(&pixels).bytes();
            source.allowed_mask_digest = extracted.selection.mask_digest;
            Ok(source)
        })
        .collect()
}

#[test]
fn native_masked_pixels_produce_archivable_landmarks_and_localize_a_later_camera_capture() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let texture = texture();
    for cameras in [2, 3] {
        let sources = native_sources(&twin, &texture, cameras)?;
        let built = reconstruct(&twin, &sources)?;
        assert!(built.atlas().landmarks().len() >= 16);
        assert!(built.atlas().bindings().len() >= 2 * built.atlas().landmarks().len());
        for landmark in built.atlas().landmarks() {
            // Independent rectified stereo: z = 120 * 1 / 12 = 10.
            assert!((landmark.world[2] - 10.).abs() < 1e-8);
        }
        let loaded = roundtrip(&twin, &built)?;
        assert_lineage(&built, &loaded, &sources);
        assert!(
            loaded
                .atlas()
                .references()
                .iter()
                .all(|reference| reference.frame.features().len() == 64)
        );
        assert_ne!(
            loaded.references()[0].allowed_mask,
            loaded.references()[1].allowed_mask
        );

        // A six-pixel translation is a new camera center at x=0.5. No query
        // descriptors, feature coordinates, or 2D-to-3D matches are supplied.
        let pixels = texture_pixels(&texture, 6);
        let allowed = vec![1; pixels.len()];
        let image_identity = ImageIdentity {
            pixels: ContentDigest::sha256(&pixels).bytes(),
            ..identity(150, [192, 128])
        };
        let image = GrayImage::new(image_identity, &pixels, &allowed, &mut budget())?;
        let output = localize_gray_frame(
            loaded.atlas(),
            &twin,
            &image,
            LocalizationCamera {
                intrinsics: texture_intrinsics()?,
                image_domain: image_identity.image_domain,
            },
            ImageLocalizationOptions {
                extraction: extraction_options(),
                matching: exact_matching(),
                solving: pose_options(),
            },
            &mut budget(),
        )?;
        assert!(output.localization.matches.correspondences.len() >= 12);
        assert!(
            output.localization.matches.correspondences.len() <= loaded.atlas().landmarks().len()
        );
        let LocalizationOutcome::Candidates(search) = output.localization.outcome else {
            return Err("native planar pixels failed to reach pose candidates".into());
        };
        assert!(search.planar_support().is_some());
        // Planar alternatives remain explicit; this test never claims unique 3D support.
        let known_pose = search
            .candidates()
            .iter()
            .find(|candidate| {
                candidate
                    .pose()
                    .center()
                    .into_iter()
                    .zip([0.5, 0., 0.])
                    .all(|(actual, expected)| (actual - expected).abs() < 1e-5)
            })
            .ok_or("known planar camera pose is missing")?;
        assert!(known_pose.rms_px() < 1e-7);
        for (actual, expected) in known_pose.pose().rotation().into_iter().zip(IDENTITY) {
            close(actual, expected, 1e-7);
        }
    }
    Ok(())
}

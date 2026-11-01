#![forbid(unsafe_code)]
//! Complete source/matching/motion contracts using independently projected moving points.
mod common;

use std::error::Error;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fss_geometry::temporal_triangulation::TemporalTriangulationOptions;
use fss_geometry::{GeometryError, PinholeIntrinsics, RigidPose, WorkBudget};
use fss_twin::feature_association::{DescriptorDecision, FeatureView};
use fss_twin::localization::{BinaryDescriptor, FeatureFrame, ImageFeature, ImageIdentity};
use fss_twin::multiview_motion::MotionFusionError;
use fss_twin::temporal_feature_association::{
    MAX_TEMPORAL_PAIR_ROWS, TemporalAssociationError, TemporalAssociationOptions,
    TemporalComponentOutcome, TemporalFeatureAssociation, TemporalFeatureDisposition,
    associate_temporal_features,
};
use fss_twin::{ProjectionError, PropertyTwin, TrackingCamera};

type Test<T = ()> = Result<T, Box<dyn Error>>;
const WORK: u64 = 100_000_000;
const IDENTITY: [[f64; 3]; 3] = [[1., 0., 0.], [0., 1., 0.], [0., 0., 1.]];
const POINTS: [[f64; 3]; 2] = [[0.2, 0.3, 10.], [2., 1.5, 12.]];
const VELOCITIES: [[f64; 3]; 2] = [[0.7, 0.4, 0.2], [-0.3, 0.2, -0.1]];

fn options() -> TemporalAssociationOptions {
    TemporalAssociationOptions {
        association_basis: [90; 32],
        camera_rig_digest: [91; 32],
        privacy_domain: 2,
        clock: 1,
        clock_evidence: [92; 32],
        reference_time_ns: 500_000_000,
        max_capture_span_ns: 60_000_000_000,
        max_capture_uncertainty_ns: 20,
        maximum_hamming_distance: 64,
        ratio_percent: 80,
        triangulation: TemporalTriangulationOptions {
            max_reprojection_pixels: 0.001,
            ..TemporalTriangulationOptions::default()
        },
    }
}
fn feature(id: u64, pixel: [f64; 2], descriptor: [u64; 4]) -> ImageFeature {
    ImageFeature {
        id,
        pixel,
        descriptor: BinaryDescriptor(descriptor),
    }
}
fn view(twin: &PropertyTwin, camera: u8, exposure: u8, time: u64) -> Test<FeatureView> {
    let center = [f64::from(camera) - 1., 0., 0.];
    let seconds = time as f64 * 1e-9;
    let features = POINTS
        .iter()
        .zip(VELOCITIES)
        .enumerate()
        .map(|(i, (p, v))| {
            let moving: [f64; 3] = std::array::from_fn(|axis| p[axis] + v[axis] * seconds);
            // Independent scalar pinhole projection; no production project/ray helper.
            feature(
                i as u64 + 1,
                [
                    120. * (moving[0] - center[0]) / moving[2] + 96.,
                    120. * moving[1] / moving[2] + 64.,
                ],
                if i == 0 { [0; 4] } else { [u64::MAX; 4] },
            )
        })
        .collect();
    let frame = FeatureFrame::new(
        ImageIdentity {
            exposure: [exposure; 32],
            pixels: [exposure + 20; 32],
            image_domain: [camera + 40; 32],
            dimensions: [192, 128],
        },
        [77; 32],
        features,
        &mut WorkBudget::new(WORK),
    )?;
    Ok(FeatureView {
        image_domain_digest: frame.identity().image_domain,
        frame,
        camera: TrackingCamera {
            geometry: twin.basis(),
            camera: u64::from(camera),
            calibration: 1,
            image_domain: u64::from(camera) + 40,
            clock: 1,
            validity: [0, 60_000_000_000],
            pose: RigidPose::from_center(IDENTITY, center)?,
            intrinsics: PinholeIntrinsics::new(192, 128, 120., 120., 96., 64.)?,
            error: Some(ProjectionError::EXACT),
        },
        source_digest: [camera + 50; 32],
        allowed_mask_digest: [exposure + 60; 32],
        mapping_basis: [camera + 80; 32],
        privacy_domain: 2,
        clock_evidence: [92; 32],
        capture: [time, time],
        sigma_pixels: 0.5,
    })
}
fn views(twin: &PropertyTwin) -> Test<Vec<FeatureView>> {
    // Canonical camera/capture order; different cameras have staggered timestamps.
    [
        (1, 1, 0),
        (1, 2, 1_000_000_000),
        (2, 3, 250_000_000),
        (2, 4, 1_250_000_000),
    ]
    .into_iter()
    .map(|(c, e, t)| view(twin, c, e, t))
    .collect()
}
fn replace(view: &mut FeatureView, features: Vec<ImageFeature>) -> Test {
    view.frame = FeatureFrame::new(
        view.frame.identity(),
        view.frame.descriptor_domain(),
        features,
        &mut WorkBudget::new(WORK),
    )?;
    Ok(())
}
fn identity(view: &mut FeatureView, value: ImageIdentity) -> Test {
    view.frame = FeatureFrame::new(
        value,
        view.frame.descriptor_domain(),
        view.frame.features().to_vec(),
        &mut WorkBudget::new(WORK),
    )?;
    Ok(())
}
fn run(
    twin: &PropertyTwin,
    sources: &[FeatureView],
) -> Result<TemporalFeatureAssociation, TemporalAssociationError> {
    associate_temporal_features(twin, sources, options(), &mut WorkBudget::new(WORK))
}
fn close(actual: [f64; 3], expected: [f64; 3]) {
    for (a, e) in actual.into_iter().zip(expected) {
        assert!((a - e).abs() < 1e-7, "{actual:?} != {expected:?}");
    }
}

#[test]
fn staggered_sources_automatically_reconstruct_motion_with_complete_membership() -> Test {
    let twin = common::twin(&[-20.], Some(0.2))?;
    let sources = views(&twin)?;
    let report = run(&twin, &sources)?;
    assert_eq!(report.pairs().len(), 6);
    assert_eq!(
        report
            .pairs()
            .iter()
            .map(|p| p.pairs().len())
            .sum::<usize>(),
        24
    );
    assert_eq!(
        report
            .pairs()
            .iter()
            .map(|p| p.features().len())
            .sum::<usize>(),
        24
    );
    assert_eq!(report.components().len(), 2);
    assert_eq!(report.capture_hull(), [0, 1_250_000_000]);
    for (i, component) in report.components().iter().enumerate() {
        assert_eq!(component.members().len(), 4);
        assert_eq!(component.links().len(), 6);
        assert_eq!(component.requested_scene_time_ns(), 500_000_000);
        let TemporalComponentOutcome::Fused(motion) = component.outcome() else {
            return Err(format!("{:?}", component.outcome()).into());
        };
        close(
            motion.estimate().position,
            std::array::from_fn(|a| POINTS[i][a] + VELOCITIES[i][a] * 0.5),
        );
        close(motion.estimate().velocity_per_second, VELOCITIES[i]);
        assert_eq!(motion.estimate().reference_time_ns, 500_000_000);
        assert_eq!(motion.map_error(), Some(0.2));
        assert_eq!(motion.inputs().len(), 4);
        assert_eq!(motion.visibility().len(), 4);
        for (member, input) in component.members().iter().zip(motion.inputs()) {
            assert_eq!(input.observation.exposure, member.view as u64 + 1);
            assert_eq!(input.observation.track, i as u64 + 1);
            assert_eq!(input.camera, sources[member.view].camera);
            assert_eq!(input.observation.capture, sources[member.view].capture);
            assert_eq!(
                input.observation.pixel_min,
                sources[member.view].frame.features()[i].pixel
            );
        }
    }
    Ok(())
}

#[test]
fn permutation_preserves_canonical_graph_hashes_and_numeric_results() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let sources = views(&twin)?;
    let expected = run(&twin, &sources)?;
    let mut shuffled = sources.clone();
    shuffled.reverse();
    shuffled.rotate_left(1);
    for source in &mut shuffled {
        let mut features = source.frame.features().to_vec();
        features.reverse();
        replace(source, features)?;
    }
    let actual = run(&twin, &shuffled)?;
    assert_eq!(actual.evidence(), expected.evidence());
    for (a, b) in actual.pairs().iter().zip(expected.pairs()) {
        assert_eq!(a.views(), b.views());
        assert_eq!(a.evidence(), b.evidence());
        assert_eq!(a.pairs(), b.pairs());
        assert_eq!(a.features(), b.features());
    }
    for (a, b) in actual.components().iter().zip(expected.components()) {
        assert_eq!(a.members(), b.members());
        assert_eq!(a.links(), b.links());
        assert_eq!(a.evidence(), b.evidence());
        match (a.outcome(), b.outcome()) {
            (TemporalComponentOutcome::Fused(x), TemporalComponentOutcome::Fused(y)) => {
                assert_eq!(x.estimate(), y.estimate())
            }
            _ => return Err("expected complete motion fits".into()),
        }
    }
    Ok(())
}

#[test]
fn repeated_encoded_bytes_and_pixels_are_allowed_but_original_exposure_reuse_is_refused() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let mut sources = views(&twin)?;
    for source in &mut sources {
        source.source_digest = [33; 32];
        let updated = ImageIdentity {
            pixels: [34; 32],
            ..source.frame.identity()
        };
        identity(source, updated)?;
    }
    assert_eq!(run(&twin, &sources)?.components().len(), 2);
    let duplicate = sources[0].frame.identity().exposure;
    let updated = ImageIdentity {
        exposure: duplicate,
        ..sources[2].frame.identity()
    };
    identity(&mut sources[2], updated)?;
    assert!(matches!(
        run(&twin, &sources),
        Err(TemporalAssociationError::DuplicateExposure)
    ));
    Ok(())
}

#[test]
fn ties_and_missing_runner_up_never_select_a_descriptor_edge() -> Test {
    let twin = common::twin(&[-20.], None)?;
    for singleton in [false, true] {
        let mut sources = views(&twin)?;
        for source in &mut sources {
            let mut entries = source.frame.features().to_vec();
            for entry in &mut entries {
                entry.descriptor = BinaryDescriptor([0; 4]);
            }
            if singleton {
                entries.truncate(1);
            }
            replace(source, entries)?;
        }
        let report = run(&twin, &sources)?;
        assert!(
            report
                .pairs()
                .iter()
                .flat_map(|p| p.pairs())
                .all(|r| r.descriptor == DescriptorDecision::Ambiguous)
        );
        for row in report.pairs().iter().flat_map(|p| p.features()) {
            assert_eq!(row.nearest_features.len(), if singleton { 1 } else { 2 });
            assert_eq!(row.disposition, TemporalFeatureDisposition::Ambiguous);
            assert_eq!(
                row.runner_up_distance,
                if singleton { None } else { Some(0) }
            );
            assert!(row.selected_pair.is_none());
        }
        assert!(
            report
                .components()
                .iter()
                .all(|c| matches!(c.outcome(), TemporalComponentOutcome::Unmatched))
        );
    }
    Ok(())
}

#[test]
fn pair_table_retains_absolute_ratio_and_nonmutual_decisions_independently() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let mut sources = views(&twin)?;
    replace(
        &mut sources[0],
        vec![
            feature(1, [90., 60.], [0; 4]),
            feature(2, [100., 60.], [15, 0, 0, 0]),
        ],
    )?;
    replace(
        &mut sources[1],
        vec![
            feature(1, [90., 60.], [1, 0, 0, 0]),
            feature(2, [100., 60.], [3, 0, 0, 0]),
        ],
    )?;
    let report = associate_temporal_features(
        &twin,
        &sources,
        TemporalAssociationOptions {
            maximum_hamming_distance: 2,
            ..options()
        },
        &mut WorkBudget::new(WORK),
    )?;
    let rows = report.pairs()[0].pairs();
    assert_eq!(
        rows.iter().map(|r| r.hamming_distance).collect::<Vec<_>>(),
        [1, 2, 3, 2]
    );
    assert_eq!(
        rows.iter().map(|r| r.descriptor).collect::<Vec<_>>(),
        [
            DescriptorDecision::Candidate,
            DescriptorDecision::NonMutual,
            DescriptorDecision::TooDistant,
            DescriptorDecision::Ambiguous
        ]
    );
    Ok(())
}

#[test]
fn conflicting_exposure_cycle_keeps_all_members_and_selected_links() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let mut sources = views(&twin)?;
    for (source, entries) in sources.iter_mut().zip([
        vec![
            feature(1, [90., 60.], [0; 4]),
            feature(2, [100., 60.], [7, 0, 0, 0]),
        ],
        vec![
            feature(1, [90., 60.], [1, 0, 0, 0]),
            feature(2, [100., 60.], [u64::MAX; 4]),
        ],
        vec![
            feature(1, [90., 60.], [3, 0, 0, 0]),
            feature(2, [100., 60.], [u64::MAX; 4]),
        ],
        vec![],
    ]) {
        replace(source, entries)?;
    }
    let report = associate_temporal_features(
        &twin,
        &sources,
        TemporalAssociationOptions {
            maximum_hamming_distance: 1,
            ..options()
        },
        &mut WorkBudget::new(WORK),
    )?;
    let component = &report.components()[0];
    assert_eq!(component.members().len(), 4);
    assert_eq!(component.links().len(), 3);
    assert!(
        matches!(component.outcome(), TemporalComponentOutcome::ExposureConflict { views } if views == &[0])
    );
    assert_eq!(
        report
            .components()
            .iter()
            .map(|c| c.members().len())
            .sum::<usize>(),
        6
    );
    assert!(
        report
            .pairs()
            .iter()
            .filter(|p| p.views().contains(&3))
            .all(|p| p.pairs().is_empty())
    );
    Ok(())
}

#[test]
fn an_open_descriptor_chain_retains_every_missing_direct_pair() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let mut sources = views(&twin)?;
    for (source, word) in sources.iter_mut().zip([0, 1, 3, 7]) {
        replace(
            source,
            vec![
                feature(1, [90., 60.], [word, 0, 0, 0]),
                feature(2, [100., 60.], [u64::MAX; 4]),
            ],
        )?;
    }
    let report = associate_temporal_features(
        &twin,
        &sources,
        TemporalAssociationOptions {
            maximum_hamming_distance: 1,
            ..options()
        },
        &mut WorkBudget::new(WORK),
    )?;
    let component = &report.components()[0];
    assert_eq!(component.members().len(), 4);
    assert_eq!(component.links().len(), 3);
    let TemporalComponentOutcome::IncompletePairSupport { pairs } = component.outcome() else {
        return Err("chain was promoted".into());
    };
    assert_eq!(pairs.len(), 3);
    for reference in pairs {
        let row = &report.pairs()[reference.pair].pairs()[reference.decision];
        assert_eq!(row.descriptor, DescriptorDecision::TooDistant);
        assert!(row.hamming_distance > 1);
    }
    Ok(())
}

#[test]
fn insufficient_observation_and_single_camera_components_remain_explicit() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let mut sources = views(&twin)?;
    replace(&mut sources[3], vec![])?;
    let report = run(&twin, &sources)?;
    assert!(report.components().iter().all(|c| matches!(
        c.outcome(),
        TemporalComponentOutcome::InsufficientObservations
    )));
    let mut single = (0..4)
        .map(|i| view(&twin, 1, i + 1, u64::from(i) * 250_000_000))
        .collect::<Test<Vec<_>>>()?;
    let mut empty = view(&twin, 2, 9, 1_000_000_000)?;
    replace(&mut empty, vec![])?;
    single.push(empty);
    assert!(
        run(&twin, &single)?
            .components()
            .iter()
            .all(|c| matches!(c.outcome(), TemporalComponentOutcome::InsufficientCameras))
    );
    Ok(())
}

#[test]
fn empty_late_view_preserves_global_hull_and_does_not_clamp_component_reference() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let mut sources = views(&twin)?;
    let mut late = view(&twin, 1, 5, 3_000_000_000)?;
    replace(&mut late, vec![])?;
    sources.push(late);
    let report = associate_temporal_features(
        &twin,
        &sources,
        TemporalAssociationOptions {
            reference_time_ns: 2_000_000_000,
            ..options()
        },
        &mut WorkBudget::new(WORK),
    )?;
    assert_eq!(report.capture_hull(), [0, 3_000_000_000]);
    for component in report.components() {
        assert_eq!(component.requested_scene_time_ns(), 2_000_000_000);
        assert_eq!(component.nominal_time_range_ns(), [0, 1_250_000_000]);
        assert_eq!(component.capture_hull(), [0, 1_250_000_000]);
        assert!(matches!(
            component.outcome(),
            TemporalComponentOutcome::Refused(MotionFusionError::CaptureWindow)
        ));
    }
    Ok(())
}

#[test]
fn full_capture_intervals_and_uncertainty_are_not_replaced_by_midpoints() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let mut sources = views(&twin)?;
    sources[3].capture = [1_249_999_990, 1_250_000_010];
    let report = run(&twin, &sources)?;
    assert_eq!(report.capture_hull(), [0, 1_250_000_010]);
    for component in report.components() {
        assert_eq!(component.capture_hull(), report.capture_hull());
        let TemporalComponentOutcome::Fused(motion) = component.outcome() else {
            return Err("interval fixture failed".into());
        };
        assert_eq!(motion.inputs()[3].observation.capture, sources[3].capture);
    }
    for policy in [
        TemporalAssociationOptions {
            max_capture_uncertainty_ns: 19,
            ..options()
        },
        TemporalAssociationOptions {
            max_capture_span_ns: 1_250_000_009,
            ..options()
        },
    ] {
        assert!(matches!(
            associate_temporal_features(&twin, &sources, policy, &mut WorkBudget::new(WORK)),
            Err(TemporalAssociationError::CaptureWindow)
        ));
    }
    Ok(())
}

#[test]
fn all_empty_sources_still_enforce_policy_clock_privacy_mapping_and_capture() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let mut sources = views(&twin)?;
    for source in &mut sources {
        replace(source, vec![])?;
    }
    let report = run(&twin, &sources)?;
    assert!(report.components().is_empty());
    assert_eq!(report.pairs().len(), 6);
    assert_eq!(report.views().len(), 4);
    assert_eq!(report.capture_hull(), [0, 1_250_000_000]);
    for kind in 0..6 {
        let mut changed = sources.clone();
        let mut policy = options();
        let expected = match kind {
            0 => {
                policy.triangulation.max_iterations = 0;
                TemporalAssociationError::InvalidOptions
            }
            1 => {
                changed[3].clock_evidence = [99; 32];
                TemporalAssociationError::Basis
            }
            2 => {
                changed[3].privacy_domain += 1;
                TemporalAssociationError::PrivacyDomain
            }
            3 => {
                changed[3].allowed_mask_digest = [0; 32];
                TemporalAssociationError::InvalidInput
            }
            4 => {
                changed[3].capture = [0, 30];
                TemporalAssociationError::CaptureWindow
            }
            _ => {
                changed[3].image_domain_digest = [88; 32];
                TemporalAssociationError::ImageDomain
            }
        };
        assert!(
            matches!(associate_temporal_features(&twin, &changed, policy, &mut WorkBudget::new(WORK)), Err(actual) if actual == expected),
            "case {kind}"
        );
    }
    Ok(())
}

#[test]
fn changed_repeated_camera_snapshot_or_domain_is_refused_without_merging_generations() -> Test {
    let twin = common::twin(&[-20.], None)?;
    for kind in 0..6 {
        let mut sources = views(&twin)?;
        match kind {
            0 => sources[1].camera.calibration += 1,
            1 => sources[1].mapping_basis = [99; 32],
            2 => sources[1].camera.validity[1] -= 1,
            3 => sources[1].camera.pose = RigidPose::from_center(IDENTITY, [0.1, 0., 0.])?,
            4 => sources[1].camera.error = None,
            _ => {
                sources[1].image_domain_digest = [99; 32];
                let updated = ImageIdentity {
                    image_domain: [99; 32],
                    ..sources[1].frame.identity()
                };
                identity(&mut sources[1], updated)?;
            }
        }
        assert!(
            matches!(run(&twin, &sources), Err(TemporalAssociationError::Basis)),
            "case {kind}"
        );
    }
    Ok(())
}

#[test]
fn exact_source_mask_camera_and_policy_assumptions_change_the_evidence() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let sources = views(&twin)?;
    let baseline = run(&twin, &sources)?.evidence();
    for kind in 0..10 {
        let mut changed = sources.clone();
        let mut policy = options();
        match kind {
            0 => changed[0].source_digest = [98; 32],
            1 => changed[0].allowed_mask_digest = [98; 32],
            2 => {
                let updated = ImageIdentity {
                    pixels: [98; 32],
                    ..changed[0].frame.identity()
                };
                identity(&mut changed[0], updated)?;
            }
            3 => {
                let updated = ImageIdentity {
                    exposure: [98; 32],
                    ..changed[0].frame.identity()
                };
                identity(&mut changed[0], updated)?;
            }
            4 => changed[0].sigma_pixels = 0.6,
            5 => policy.association_basis = [98; 32],
            6 => policy.camera_rig_digest = [98; 32],
            7 => policy.max_capture_uncertainty_ns += 1,
            8 => policy.triangulation.max_speed += 1.,
            _ => {
                for source in &mut changed {
                    source.camera.error = None;
                }
            }
        }
        let report =
            associate_temporal_features(&twin, &changed, policy, &mut WorkBudget::new(WORK))?;
        assert_ne!(report.evidence(), baseline, "case {kind}");
        assert!(report.components().iter().all(|c| c.evidence() != [0; 32]));
    }
    Ok(())
}

#[test]
fn per_view_total_and_exposure_ceilings_refuse_instead_of_truncating() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let sources = views(&twin)?;
    assert!(matches!(
        run(&twin, &sources[..3]),
        Err(TemporalAssociationError::InvalidInput)
    ));
    let too_many = (0..17_u8)
        .map(|i| view(&twin, i % 2 + 1, i + 1, u64::from(i) * 100_000_000))
        .collect::<Test<Vec<_>>>()?;
    assert!(matches!(
        run(&twin, &too_many),
        Err(TemporalAssociationError::InvalidInput)
    ));
    for counts in [[129, 0, 0, 0], [65, 64, 64, 64]] {
        let mut changed = sources.clone();
        for (source, count) in changed.iter_mut().zip(counts) {
            replace(
                source,
                (0..count)
                    .map(|i| {
                        feature(
                            i + 1,
                            [20. + (i % 100) as f64, 20. + (i / 100) as f64],
                            [i; 4],
                        )
                    })
                    .collect(),
            )?;
        }
        assert!(matches!(
            run(&twin, &changed),
            Err(TemporalAssociationError::Limit)
        ));
    }
    Ok(())
}

#[test]
fn maximum_sixteen_exposure_inventory_is_complete_including_every_feature_outcome() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let mut sources = Vec::new();
    for index in 0..16_u8 {
        let mut source = view(
            &twin,
            index / 2 + 1,
            index + 1,
            100_000_000 * u64::from(index),
        )?;
        replace(
            &mut source,
            (0..16_u64)
                .map(|i| feature(i + 1, [20. + i as f64, 40. + i as f64], [i; 4]))
                .collect(),
        )?;
        sources.push(source);
    }
    let report = associate_temporal_features(
        &twin,
        &sources,
        TemporalAssociationOptions {
            maximum_hamming_distance: 0,
            ..options()
        },
        &mut WorkBudget::new(WORK),
    )?;
    assert_eq!(report.views().len(), 16);
    assert_eq!(report.pairs().len(), 120);
    assert_eq!(
        report
            .pairs()
            .iter()
            .map(|p| p.pairs().len())
            .sum::<usize>(),
        MAX_TEMPORAL_PAIR_ROWS
    );
    assert_eq!(
        report
            .pairs()
            .iter()
            .map(|p| p.features().len())
            .sum::<usize>(),
        3840
    );
    assert_eq!(
        report
            .pairs()
            .iter()
            .flat_map(|p| p.pairs())
            .filter(|r| r.descriptor == DescriptorDecision::Candidate)
            .count(),
        1920
    );
    assert_eq!(report.components().len(), 16);
    assert!(
        report
            .components()
            .iter()
            .all(|c| c.members().len() == 16 && c.links().len() == 120)
    );
    Ok(())
}

#[test]
fn geometry_refusals_preserve_the_complete_selected_descriptor_graph() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let sources = views(&twin)?;
    let report = associate_temporal_features(
        &twin,
        &sources,
        TemporalAssociationOptions {
            triangulation: TemporalTriangulationOptions {
                max_speed: 0.01,
                ..options().triangulation
            },
            ..options()
        },
        &mut WorkBudget::new(WORK),
    )?;
    assert_eq!(report.components().len(), 2);
    for component in report.components() {
        assert_eq!(component.members().len(), 4);
        assert_eq!(component.links().len(), 6);
        assert!(matches!(
            component.outcome(),
            TemporalComponentOutcome::Refused(_)
        ));
    }
    assert_eq!(
        report
            .pairs()
            .iter()
            .flat_map(|p| p.pairs())
            .filter(|p| p.descriptor == DescriptorDecision::Candidate)
            .count(),
        12
    );
    Ok(())
}

#[test]
fn cumulative_work_exact_allowance_and_early_middle_terminal_cancellation_are_atomic() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let sources = views(&twin)?;
    let mut budget = WorkBudget::new(WORK);
    let baseline = associate_temporal_features(&twin, &sources, options(), &mut budget)?;
    let used = budget.used();
    assert!(used > 10_000);
    assert_eq!(
        associate_temporal_features(&twin, &sources, options(), &mut WorkBudget::new(used))?
            .evidence(),
        baseline.evidence()
    );
    assert!(matches!(
        associate_temporal_features(&twin, &sources, options(), &mut WorkBudget::new(used - 1)),
        Err(TemporalAssociationError::Geometry(
            GeometryError::BudgetExhausted
        ))
    ));
    let stop = AtomicBool::new(true);
    assert!(matches!(
        associate_temporal_features(
            &twin,
            &sources,
            options(),
            &mut WorkBudget::cancellable(WORK, &stop)
        ),
        Err(TemporalAssociationError::Geometry(GeometryError::Cancelled))
    ));
    let calls = AtomicUsize::new(0);
    let probe = || {
        calls.fetch_add(1, Ordering::SeqCst);
        false
    };
    associate_temporal_features(
        &twin,
        &sources,
        options(),
        &mut WorkBudget::with_cancellation_probe(WORK, &probe),
    )?;
    let total = calls.load(Ordering::SeqCst);
    assert!(total > 100);
    for at in [0, total / 2, total - 1] {
        let calls = AtomicUsize::new(0);
        let probe = || calls.fetch_add(1, Ordering::SeqCst) >= at;
        assert!(
            matches!(
                associate_temporal_features(
                    &twin,
                    &sources,
                    options(),
                    &mut WorkBudget::with_cancellation_probe(WORK, &probe)
                ),
                Err(TemporalAssociationError::Geometry(GeometryError::Cancelled))
            ),
            "probe {at}/{total}"
        );
    }
    assert_eq!(run(&twin, &sources)?.evidence(), baseline.evidence());
    assert!(
        TemporalAssociationError::Geometry(GeometryError::Cancelled)
            .to_string()
            .contains("cancelled")
    );
    assert!(
        TemporalAssociationError::Geometry(GeometryError::BudgetExhausted)
            .to_string()
            .contains("budget exhausted")
    );
    Ok(())
}

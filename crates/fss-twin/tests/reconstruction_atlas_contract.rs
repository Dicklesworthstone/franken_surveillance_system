#![forbid(unsafe_code)]
//! Native reconstruction admission, complete lineage and fail-closed producer contracts.
mod common;

use std::error::Error;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fss_geometry::{GeometryError, PinholeIntrinsics, RigidPose, WorkBudget};
use fss_twin::feature_association::{
    AssociationOptions, FeatureAssociation, FeatureHypothesisOutcome, FeatureView,
    associate_features,
};
use fss_twin::localization::{
    BinaryDescriptor, FeatureFrame, ImageFeature, ImageIdentity, LocalizationError,
};
use fss_twin::multiview_feature_association::{
    ComponentOutcome, MultiFeatureAssociation, associate_multiview_features,
};
use fss_twin::reconstruction_atlas::*;
use fss_twin::{ProjectionError, PropertyTwin, TrackingCamera};

type Test<T = ()> = Result<T, Box<dyn Error>>;
const WORK: u64 = 100_000_000;
const ROTATION: [[f64; 3]; 3] = [[1., 0., 0.], [0., 1., 0.], [0., 0., 1.]];
const POINTS: [[f64; 3]; 3] = [[1., 1., 10.], [2., 1.5, 12.], [0.5, 2., 8.]];

fn options() -> AssociationOptions {
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
        triangulation: Default::default(),
    }
}
fn view(twin: &PropertyTwin, camera: u8) -> Test<FeatureView> {
    let center = [f64::from(camera - 1), 0., 0.];
    let frame = FeatureFrame::new(
        ImageIdentity {
            exposure: [camera; 32],
            pixels: [camera + 10; 32],
            image_domain: [camera + 20; 32],
            dimensions: [192, 128],
        },
        [77; 32],
        POINTS
            .iter()
            .enumerate()
            .map(|(index, p)| ImageFeature {
                id: u64::from(camera) * 10 + index as u64 + 1,
                pixel: [
                    120. * (p[0] - center[0]) / p[2] + 96.,
                    120. * p[1] / p[2] + 64.,
                ],
                descriptor: BinaryDescriptor(
                    [[0; 4], [u64::MAX; 4], [0xff00ff00ff00ff00; 4]][index],
                ),
            })
            .collect(),
        &mut WorkBudget::new(WORK),
    )?;
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
            pose: RigidPose::from_center(ROTATION, center)?,
            intrinsics: PinholeIntrinsics::new(192, 128, 120., 120., 96., 64.)?,
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
fn replace(view: &mut FeatureView, features: Vec<ImageFeature>) -> Test {
    view.frame = FeatureFrame::new(
        view.frame.identity(),
        view.frame.descriptor_domain(),
        features,
        &mut WorkBudget::new(WORK),
    )?;
    Ok(())
}
fn pair(twin: &PropertyTwin) -> Test<FeatureAssociation> {
    Ok(associate_features(
        twin,
        [&view(twin, 1)?, &view(twin, 2)?],
        options(),
        &mut WorkBudget::new(WORK),
    )?)
}
fn multi(twin: &PropertyTwin, views: &[FeatureView]) -> Test<MultiFeatureAssociation> {
    Ok(associate_multiview_features(
        twin,
        views,
        options(),
        &mut WorkBudget::new(WORK),
    )?)
}
fn source_records(views: &[FeatureView]) -> Vec<ReferenceSource> {
    views
        .iter()
        .map(|view| ReferenceSource {
            camera: view.camera.camera,
            source_record: [view.camera.camera as u8 + 60; 32],
        })
        .collect()
}
fn selection(hypothesis: [u8; 32], landmark: u64) -> LandmarkSelection {
    LandmarkSelection {
        hypothesis,
        landmark,
        physical_group: landmark + 100,
        feature: 0,
        enduring_static_basis: [99; 32],
    }
}
fn selected(report: &FeatureAssociation) -> Vec<LandmarkSelection> {
    report
        .hypotheses()
        .iter()
        .enumerate()
        .map(|(i, h)| selection(h.evidence, i as u64 + 1))
        .collect()
}
fn build(
    twin: &PropertyTwin,
    report: &FeatureAssociation,
    selections: &[LandmarkSelection],
) -> Result<ReconstructedAtlas, ReconstructionAtlasError> {
    build_reconstruction_atlas(
        twin,
        &AtlasBuildRequest {
            association_evidence: report.evidence(),
            selections,
            references: &source_records(report.views()),
        },
        Reconstruction::Pair(report),
        &mut WorkBudget::new(WORK),
    )
}
fn close(actual: [f64; 3], expected: [f64; 3]) {
    for (a, b) in actual.into_iter().zip(expected) {
        assert!((a - b).abs() < 1e-8, "{a} != {b}");
    }
}

#[test]
fn explicit_pair_selection_copies_real_point_and_complete_reference_frames() -> Test {
    let twin = common::twin(&[-20.], Some(0.4))?;
    let pair = pair(&twin)?;
    let declarations = selected(&pair);
    let result = build(&twin, &pair, &declarations[..1])?;
    assert_eq!(result.atlas().landmarks().len(), 1);
    assert_eq!(result.atlas().bindings().len(), 2);
    assert_eq!(result.receipt().candidates.len(), 3);
    assert_eq!(
        result
            .receipt()
            .candidates
            .iter()
            .filter(|c| c.selected_landmark.is_some())
            .count(),
        1
    );
    assert_eq!(result.receipt().association_evidence, pair.evidence());
    close(result.atlas().landmarks()[0].world, POINTS[0]);
    assert!(result.atlas().landmarks()[0].error.is_none());
    let FeatureHypothesisOutcome::Fused(point) = &pair.hypotheses()[0].outcome else {
        return Err("fixture point was refused".into());
    };
    assert_eq!(point.map_error(), Some(0.4));
    assert!(result.receipt().landmarks[0].pixel_noise_covariance[0][0] > 0.);
    assert_eq!(result.receipt().landmarks[0].residuals.len(), 2);
    for ((reference, source), original) in result
        .atlas()
        .references()
        .iter()
        .zip(result.references())
        .zip(pair.views())
    {
        assert_eq!(reference.id, original.camera.camera);
        assert_eq!(reference.frame.identity(), original.frame.identity());
        assert_eq!(reference.frame.features(), original.frame.features());
        assert_eq!(
            reference.frame.descriptor_domain(),
            original.frame.descriptor_domain()
        );
        assert_eq!(source.allowed_mask, original.allowed_mask_digest);
        assert_eq!(
            reference.frame.features().len(),
            3,
            "unbound observed features remain in the original frame"
        );
    }
    Ok(())
}

#[test]
fn joint_component_preserves_every_member_binding_without_inflating_landmark_count() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let report = multi(&twin, &[view(&twin, 1)?, view(&twin, 2)?, view(&twin, 3)?])?;
    let selections = report
        .components()
        .iter()
        .enumerate()
        .map(|(i, c)| selection(c.evidence(), i as u64 + 1))
        .collect::<Vec<_>>();
    let result = build_reconstruction_atlas(
        &twin,
        &AtlasBuildRequest {
            association_evidence: report.evidence(),
            selections: &selections,
            references: &source_records(report.views()),
        },
        Reconstruction::Multiview(&report),
        &mut WorkBudget::new(WORK),
    )?;
    assert_eq!(result.atlas().landmarks().len(), 3);
    assert_eq!(result.atlas().bindings().len(), 9);
    assert_eq!(result.references().len(), 3);
    for (admission, component) in result.receipt().landmarks.iter().zip(report.components()) {
        assert_eq!(admission.members, component.members());
        assert_eq!(admission.residuals.len(), 3);
        let ComponentOutcome::Fused(point) = component.outcome() else {
            return Err("fixture did not reconstruct".into());
        };
        assert_eq!(admission.position, point.estimate().position);
        assert_eq!(
            admission.pixel_noise_covariance,
            point.estimate().pixel_noise_covariance
        );
    }
    Ok(())
}

#[test]
fn empty_late_view_remains_in_global_receipt_but_does_not_invent_an_archive_binding() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let mut views = vec![view(&twin, 1)?, view(&twin, 2)?, view(&twin, 3)?];
    replace(&mut views[2], vec![])?;
    views[2].capture = [200, 210];
    let report = associate_multiview_features(
        &twin,
        &views,
        AssociationOptions {
            reference_time_ns: 205,
            max_capture_span_ns: 120,
            ..options()
        },
        &mut WorkBudget::new(WORK),
    )?;
    let selections = [selection(report.components()[0].evidence(), 1)];
    let result = build_reconstruction_atlas(
        &twin,
        &AtlasBuildRequest {
            association_evidence: report.evidence(),
            selections: &selections,
            references: &source_records(report.views()),
        },
        Reconstruction::Multiview(&report),
        &mut WorkBudget::new(WORK),
    )?;
    assert_eq!(result.receipt().capture_hull, [90, 210]);
    assert_eq!(result.receipt().requested_scene_time_ns, 205);
    assert_eq!(result.receipt().landmarks[0].capture_hull, [90, 110]);
    assert_eq!(result.receipt().landmarks[0].solve_time_ns, 110);
    assert_eq!(result.receipt().sources.len(), 3);
    assert!(!result.receipt().sources[2].included);
    assert_eq!(result.receipt().sources[2].feature_count, 0);
    assert_eq!(result.references().len(), 2);
    Ok(())
}

#[test]
fn order_changes_do_not_change_atlas_receipt_or_source_order() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let report = pair(&twin)?;
    let mut selections = selected(&report);
    let first = build(&twin, &report, &selections)?;
    selections.reverse();
    let mut sources = source_records(report.views());
    sources.reverse();
    let second = build_reconstruction_atlas(
        &twin,
        &AtlasBuildRequest {
            association_evidence: report.evidence(),
            selections: &selections,
            references: &sources,
        },
        Reconstruction::Pair(&report),
        &mut WorkBudget::new(WORK),
    )?;
    assert_eq!(first.atlas().digest(), second.atlas().digest());
    assert_eq!(first.receipt().digest(), second.receipt().digest());
    assert_eq!(first.references(), second.references());
    assert_eq!(first.receipt().landmarks, second.receipt().landmarks);
    Ok(())
}

#[test]
fn every_static_support_and_physical_group_declaration_changes_the_output_identity() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let report = pair(&twin)?;
    let declarations = selected(&report);
    let first = build(&twin, &report, &declarations)?;
    for variant in 0..3 {
        let mut changed = declarations.clone();
        match variant {
            0 => changed[0].enduring_static_basis[0] ^= 1,
            1 => changed[0].physical_group += 100,
            _ => changed[0].landmark += 100,
        }
        let result = build(&twin, &report, &changed)?;
        assert_ne!(result.atlas().digest(), first.atlas().digest());
        assert_ne!(result.receipt().digest(), first.receipt().digest());
        assert!(result.atlas().landmarks().iter().all(|p| p.error.is_none()));
    }
    Ok(())
}

#[test]
fn source_recipe_changes_are_bound_without_rewriting_native_features() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let report = pair(&twin)?;
    let selections = selected(&report);
    let first = build(&twin, &report, &selections)?;
    let mut sources = source_records(report.views());
    sources[0].source_record[0] ^= 1;
    let second = build_reconstruction_atlas(
        &twin,
        &AtlasBuildRequest {
            association_evidence: report.evidence(),
            selections: &selections,
            references: &sources,
        },
        Reconstruction::Pair(&report),
        &mut WorkBudget::new(WORK),
    )?;
    assert_ne!(first.receipt().digest(), second.receipt().digest());
    assert_ne!(
        first.atlas().landmarks()[0].evidence,
        second.atlas().landmarks()[0].evidence
    );
    assert_eq!(
        first.atlas().references()[0].frame.features(),
        second.atlas().references()[0].frame.features()
    );
    Ok(())
}

#[test]
fn duplicate_candidate_landmark_or_physical_group_never_becomes_independent_support() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let report = pair(&twin)?;
    for variant in 0..3 {
        let mut selections = selected(&report);
        match variant {
            0 => selections[1].hypothesis = selections[0].hypothesis,
            1 => selections[1].landmark = selections[0].landmark,
            _ => selections[1].physical_group = selections[0].physical_group,
        }
        assert!(matches!(
            build(&twin, &report, &selections),
            Err(ReconstructionAtlasError::Alias)
        ));
    }
    Ok(())
}

#[test]
fn missing_or_zero_static_declarations_and_unknown_twin_features_refuse() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let report = pair(&twin)?;
    assert!(matches!(
        build(&twin, &report, &[]),
        Err(ReconstructionAtlasError::InvalidRequest)
    ));
    for variant in 0..5 {
        let mut selections = selected(&report);
        match variant {
            0 => selections[0].enduring_static_basis = [0; 32],
            1 => selections[0].hypothesis = [0; 32],
            2 => selections[0].landmark = 0,
            3 => selections[0].physical_group = 0,
            _ => selections[0].feature = 1,
        }
        assert!(matches!(
            build(&twin, &report, &selections),
            Err(ReconstructionAtlasError::InvalidRequest)
        ));
    }
    let mut selections = selected(&report);
    selections[0].hypothesis = [244; 32];
    assert!(matches!(
        build(&twin, &report, &selections),
        Err(ReconstructionAtlasError::SelectionMismatch)
    ));
    Ok(())
}

#[test]
fn every_source_requires_exact_nonzero_distinct_recipe_and_input_membership() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let report = pair(&twin)?;
    let selections = selected(&report);
    for variant in 0..5 {
        let mut sources = source_records(report.views());
        match variant {
            0 => {
                sources.pop();
            }
            1 => sources[0].source_record = [0; 32],
            2 => sources[1].source_record = sources[0].source_record,
            3 => sources[1].camera = sources[0].camera,
            _ => sources[1].camera = 99,
        }
        assert!(
            build_reconstruction_atlas(
                &twin,
                &AtlasBuildRequest {
                    association_evidence: report.evidence(),
                    selections: &selections,
                    references: &sources
                },
                Reconstruction::Pair(&report),
                &mut WorkBudget::new(WORK)
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn whole_scene_pin_and_exact_twin_are_required_even_for_an_unchanged_selected_point() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let report = pair(&twin)?;
    let selections = selected(&report);
    assert!(matches!(
        build_reconstruction_atlas(
            &twin,
            &AtlasBuildRequest {
                association_evidence: [211; 32],
                selections: &selections,
                references: &source_records(report.views())
            },
            Reconstruction::Pair(&report),
            &mut WorkBudget::new(WORK)
        ),
        Err(ReconstructionAtlasError::BasisMismatch)
    ));
    let changed = common::twin(&[-21.], None)?;
    assert!(matches!(
        build(&changed, &report, &selections),
        Err(ReconstructionAtlasError::BasisMismatch)
    ));
    Ok(())
}

#[test]
fn an_opaque_geometry_conflict_is_visible_and_cannot_be_promoted() -> Test {
    let twin = common::twin(&[5.], None)?;
    let report = pair(&twin)?;
    let FeatureHypothesisOutcome::Fused(point) = &report.hypotheses()[0].outcome else {
        return Err("point missing".into());
    };
    assert!(point.has_nominal_occlusion_conflict());
    assert!(matches!(
        build(&twin, &report, &selected(&report)[..1]),
        Err(ReconstructionAtlasError::OcclusionConflict)
    ));
    Ok(())
}

#[test]
fn refused_pair_geometry_cannot_be_selected_as_a_landmark() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let left = view(&twin, 1)?;
    let mut right = view(&twin, 2)?;
    let mut features = right.frame.features().to_vec();
    for (other, same) in features.iter_mut().zip(left.frame.features()) {
        other.pixel = same.pixel;
    }
    replace(&mut right, features)?;
    let report = associate_features(
        &twin,
        [&left, &right],
        options(),
        &mut WorkBudget::new(WORK),
    )?;
    assert!(matches!(
        report.hypotheses()[0].outcome,
        FeatureHypothesisOutcome::Refused(_)
    ));
    assert!(matches!(
        build(&twin, &report, &selected(&report)[..1]),
        Err(ReconstructionAtlasError::IneligibleSelection)
    ));
    Ok(())
}

#[test]
fn unmatched_and_incomplete_components_stay_explicit_without_automatic_promotion() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let mut sources = vec![view(&twin, 1)?, view(&twin, 2)?, view(&twin, 3)?];
    for (source, descriptor) in sources.iter_mut().zip([0, 1, 3]) {
        let mut features = source.frame.features().to_vec();
        features[0].descriptor = BinaryDescriptor([descriptor, 0, 0, 0]);
        replace(source, features)?;
    }
    let mut features = sources[2].frame.features().to_vec();
    features.push(ImageFeature {
        id: 39,
        pixel: [140., 95.],
        descriptor: BinaryDescriptor([7; 4]),
    });
    replace(&mut sources[2], features)?;
    let report = associate_multiview_features(
        &twin,
        &sources,
        AssociationOptions {
            maximum_hamming_distance: 1,
            ..options()
        },
        &mut WorkBudget::new(WORK),
    )?;
    let valid = report
        .components()
        .iter()
        .find(|c| matches!(c.outcome(), ComponentOutcome::Fused(_)))
        .ok_or("eligible fixture")?;
    let references = source_records(report.views());
    let build_one = |pin| {
        build_reconstruction_atlas(
            &twin,
            &AtlasBuildRequest {
                association_evidence: report.evidence(),
                selections: &[selection(pin, 1)],
                references: &references,
            },
            Reconstruction::Multiview(&report),
            &mut WorkBudget::new(WORK),
        )
    };
    let result = build_one(valid.evidence())?;
    assert_eq!(result.receipt().candidates.len(), report.components().len());
    for disposition in [
        AtlasCandidateDisposition::Unmatched,
        AtlasCandidateDisposition::IncompleteCycleSupport,
    ] {
        let candidate = result
            .receipt()
            .candidates
            .iter()
            .find(|c| c.disposition == disposition)
            .ok_or("missing unresolved fixture")?;
        assert_eq!(candidate.selected_landmark, None);
        assert!(matches!(
            build_one(candidate.hypothesis),
            Err(ReconstructionAtlasError::IneligibleSelection)
        ));
    }
    Ok(())
}

#[test]
fn bounded_work_and_initial_or_terminal_cancellation_return_no_atlas() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let report = pair(&twin)?;
    let selections = selected(&report);
    let sources = source_records(report.views());
    let request = AtlasBuildRequest {
        association_evidence: report.evidence(),
        selections: &selections,
        references: &sources,
    };
    let mut work = WorkBudget::new(WORK);
    let expected =
        build_reconstruction_atlas(&twin, &request, Reconstruction::Pair(&report), &mut work)?;
    let exact = work.used();
    let completed = build_reconstruction_atlas(
        &twin,
        &request,
        Reconstruction::Pair(&report),
        &mut WorkBudget::new(exact),
    )?;
    assert_eq!(completed.receipt().digest(), expected.receipt().digest());
    assert!(matches!(
        build_reconstruction_atlas(
            &twin,
            &request,
            Reconstruction::Pair(&report),
            &mut WorkBudget::new(exact - 1)
        ),
        Err(ReconstructionAtlasError::Localization(
            LocalizationError::Geometry(GeometryError::BudgetExhausted)
        ))
    ));
    let flag = AtomicBool::new(true);
    assert!(matches!(
        build_reconstruction_atlas(
            &twin,
            &request,
            Reconstruction::Pair(&report),
            &mut WorkBudget::cancellable(WORK, &flag)
        ),
        Err(ReconstructionAtlasError::Localization(
            LocalizationError::Geometry(GeometryError::Cancelled)
        ))
    ));
    let calls = AtomicUsize::new(0);
    let never = || {
        calls.fetch_add(1, Ordering::Relaxed);
        false
    };
    let _ = build_reconstruction_atlas(
        &twin,
        &request,
        Reconstruction::Pair(&report),
        &mut WorkBudget::with_cancellation_probe(WORK, &never),
    )?;
    let last = calls.load(Ordering::Relaxed);
    for stop in [last / 2, last - 1] {
        let calls = AtomicUsize::new(0);
        let cancelled = || calls.fetch_add(1, Ordering::Relaxed) >= stop;
        assert!(matches!(
            build_reconstruction_atlas(
                &twin,
                &request,
                Reconstruction::Pair(&report),
                &mut WorkBudget::with_cancellation_probe(WORK, &cancelled)
            ),
            Err(ReconstructionAtlasError::Localization(
                LocalizationError::Geometry(GeometryError::Cancelled)
            ))
        ));
    }
    Ok(())
}

#[test]
fn oversized_selection_scope_is_refused_before_candidate_expansion() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let report = pair(&twin)?;
    let selections = vec![selected(&report)[0]; MAX_RECONSTRUCTED_LANDMARKS + 1];
    assert!(matches!(
        build(&twin, &report, &selections),
        Err(ReconstructionAtlasError::Limit)
    ));
    Ok(())
}

#[test]
fn conflicting_camera_cycles_cannot_supply_a_static_map_point() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let mut sources = vec![view(&twin, 1)?, view(&twin, 2)?, view(&twin, 3)?];
    for (source, rows) in sources.iter_mut().zip([
        [(11, [100., 64.], [0; 4]), (12, [104., 64.], [7, 0, 0, 0])],
        [
            (21, [88., 64.], [1, 0, 0, 0]),
            (22, [115., 80.], [u64::MAX; 4]),
        ],
        [
            (31, [76., 64.], [3, 0, 0, 0]),
            (32, [103., 80.], [u64::MAX; 4]),
        ],
    ]) {
        replace(
            source,
            rows.into_iter()
                .map(|(id, pixel, descriptor)| ImageFeature {
                    id,
                    pixel,
                    descriptor: BinaryDescriptor(descriptor),
                })
                .collect(),
        )?;
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
    let conflict = report
        .components()
        .iter()
        .find(|component| matches!(component.outcome(), ComponentOutcome::CameraConflict { .. }))
        .ok_or("missing conflicting cycle")?;
    assert!(matches!(
        build_reconstruction_atlas(
            &twin,
            &AtlasBuildRequest {
                association_evidence: report.evidence(),
                selections: &[selection(conflict.evidence(), 1)],
                references: &source_records(report.views()),
            },
            Reconstruction::Multiview(&report),
            &mut WorkBudget::new(WORK)
        ),
        Err(ReconstructionAtlasError::IneligibleSelection)
    ));
    Ok(())
}

#![forbid(unsafe_code)]
//! Actual native geometry and strict envelopes; these tests establish no retained custody.

use std::sync::atomic::{AtomicUsize, Ordering};

use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;
use fss_geometry::temporal_triangulation::TemporalTriangulationOptions;
use fss_geometry::triangulation::TriangulationOptions;
use fss_geometry::{GeometryBasis, PinholeIntrinsics, RigidPose};
use fss_twin::localization::{BinaryDescriptor, FeatureFrame, ImageFeature, ImageIdentity};
use fss_twin::{ImportExpectation, ImportLimits, TrackingCamera, import_twin};

use super::*;

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const WORK: u64 = 100_000_000;
const EPOCH: u64 = 1_000_000_000;
const REFERENCE: u64 = EPOCH + 500_000_000;
const POINTS: [[f64; 3]; 2] = [[0.2, 0.3, 10.0], [2.0, 1.5, 12.0]];
const VELOCITIES: [[f64; 3]; 2] = [[0.7, 0.4, 0.2], [-0.3, 0.2, -0.1]];

fn checked<T>(value: crate::Result<T>) -> Test<T> {
    value.map_err(|error| format!("calibrated geometry: {error:?}").into())
}
fn field<'a>(value: &'a Value, path: &[&str]) -> Test<&'a Value> {
    let Some((key, rest)) = path.split_first() else {
        return Ok(value);
    };
    let child = match value {
        Value::Object(values) => values.get(*key),
        Value::Array(values) => values.get(key.parse::<usize>()?),
        _ => None,
    }
    .ok_or("missing report field")?;
    field(child, rest)
}
fn close(actual: [f64; 3], expected: [f64; 3]) {
    for (actual, expected) in actual.into_iter().zip(expected) {
        assert!(
            (actual - expected).abs() < 1e-7,
            "{actual} differs from {expected}"
        );
    }
}
fn twin(occluded: bool) -> Test<PropertyTwin> {
    fn text(bytes: &mut Vec<u8>, value: &str) {
        bytes.extend_from_slice(&(value.len() as u16).to_le_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    let source = ContentDigest::sha256(b"independent calibrated-scene geometry fixture");
    let mut body = source.bytes().to_vec();
    text(&mut body, "calibrated_geometry_fixture");
    text(&mut body, "synthetic_epoch");
    body.push(0);
    for value in [0.0_f64, -1.0, -1.0] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    for value in [1_u32, 1, 3, 1] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    text(&mut body, "wall");
    body.push(5);
    text(&mut body, "wall");
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.extend_from_slice(&[0, u8::from(occluded)]);
    for point in [
        [-20.0_f64, -20.0, 4.0],
        [20.0, -20.0, 4.0],
        [0.0, 20.0, 4.0],
    ] {
        for value in point {
            body.extend_from_slice(&value.to_le_bytes());
        }
    }
    for value in [0_u32, 1, 2, 0] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    let mut bytes = b"FSSTWIN1".to_vec();
    bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
    bytes.extend(body);
    bytes.extend_from_slice(&ContentDigest::sha256(&bytes).bytes());
    Ok(import_twin(
        &bytes,
        ImportExpectation {
            package_sha256: ContentDigest::sha256(&bytes).bytes(),
            source_scene_sha256: source.bytes(),
            basis: GeometryBasis::new(7, 2)?,
        },
        ImportLimits::default(),
        &mut WorkBudget::new(WORK),
    )?)
}
fn static_options() -> AssociationOptions {
    AssociationOptions {
        association_basis: [90; 32],
        camera_rig_digest: [91; 32],
        privacy_domain: 2,
        clock: 1,
        clock_evidence: [92; 32],
        reference_time_ns: REFERENCE,
        max_capture_span_ns: 20,
        maximum_hamming_distance: 64,
        ratio_percent: 80,
        maximum_epipolar_distance_pixels: 0.01,
        triangulation: TriangulationOptions::default(),
    }
}
fn temporal_options() -> TemporalAssociationOptions {
    TemporalAssociationOptions {
        association_basis: [90; 32],
        camera_rig_digest: [91; 32],
        privacy_domain: 2,
        clock: 1,
        clock_evidence: [92; 32],
        reference_time_ns: REFERENCE,
        max_capture_span_ns: 2_000_000_000,
        max_capture_uncertainty_ns: 20,
        maximum_hamming_distance: 64,
        ratio_percent: 80,
        triangulation: TemporalTriangulationOptions {
            max_reprojection_pixels: 0.001,
            ..TemporalTriangulationOptions::default()
        },
    }
}
fn view(
    twin: &PropertyTwin,
    camera: u8,
    exposure: u8,
    when: u64,
    moving: bool,
) -> Test<FeatureView> {
    let center = match camera {
        1 => [-1.0, 0.0, 0.0],
        2 => [1.0, 0.0, 0.0],
        _ => [0.0, 1.0, 0.0],
    };
    let seconds = if moving {
        (when - EPOCH) as f64 * 1e-9
    } else {
        0.0
    };
    let features = POINTS
        .iter()
        .zip(VELOCITIES)
        .enumerate()
        .map(|(index, (point, velocity))| {
            let point: [f64; 3] =
                std::array::from_fn(|axis| point[axis] + seconds * velocity[axis]);
            ImageFeature {
                id: u64::from(exposure) * 10 + index as u64 + 1,
                // Independent scalar projection, without production ray/project helpers.
                pixel: [
                    96.0 + 120.0 * (point[0] - center[0]) / point[2],
                    64.0 + 120.0 * (point[1] - center[1]) / point[2],
                ],
                descriptor: BinaryDescriptor(if index == 0 { [0; 4] } else { [u64::MAX; 4] }),
            }
        })
        .collect();
    Ok(FeatureView {
        frame: FeatureFrame::new(
            ImageIdentity {
                exposure: [exposure; 32],
                pixels: [exposure + 20; 32],
                image_domain: [camera + 40; 32],
                dimensions: [192, 128],
            },
            [77; 32],
            features,
            &mut WorkBudget::new(WORK),
        )?,
        camera: TrackingCamera {
            geometry: twin.basis(),
            camera: u64::from(camera),
            calibration: 7,
            image_domain: u64::from(camera) + 40,
            clock: 1,
            validity: [0, u64::MAX],
            pose: RigidPose::from_center(
                [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]],
                center,
            )?,
            intrinsics: PinholeIntrinsics::new(192, 128, 120.0, 120.0, 96.0, 64.0)?,
            error: None,
        },
        source_digest: [camera + 50; 32],
        allowed_mask_digest: [exposure + 60; 32],
        image_domain_digest: [camera + 40; 32],
        mapping_basis: [camera + 80; 32],
        privacy_domain: 2,
        clock_evidence: [92; 32],
        capture: [when - 5, when + 5],
        sigma_pixels: 0.5,
    })
}
fn fixture(mode: u8, occluded: bool) -> Test<(PropertyTwin, Vec<FeatureView>, GeometryPolicy)> {
    let twin = twin(occluded)?;
    let (sources, policy) = match mode {
        0 => (
            vec![
                view(&twin, 1, 1, REFERENCE, false)?,
                view(&twin, 2, 2, REFERENCE, false)?,
            ],
            GeometryPolicy::Pair(static_options()),
        ),
        1 => (
            vec![
                view(&twin, 1, 1, REFERENCE, false)?,
                view(&twin, 2, 2, REFERENCE, false)?,
                view(&twin, 3, 3, REFERENCE, false)?,
            ],
            GeometryPolicy::Multi(static_options()),
        ),
        _ => (
            vec![
                view(&twin, 1, 1, EPOCH, true)?,
                view(&twin, 1, 2, EPOCH + 1_000_000_000, true)?,
                view(&twin, 2, 3, EPOCH, true)?,
                view(&twin, 2, 4, EPOCH + 1_000_000_000, true)?,
            ],
            GeometryPolicy::Temporal(temporal_options()),
        ),
    };
    Ok((twin, sources, policy))
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
fn evidence(analysis: &Analysis) -> [u8; 32] {
    match &analysis.association {
        NativeGeometry::Pair(v) => v.evidence(),
        NativeGeometry::Multi(v) => v.evidence(),
        NativeGeometry::Temporal(v) => v.evidence(),
    }
}

#[test]
fn static_pair_keeps_complete_candidates_and_independently_known_positions() -> Test {
    let (twin, sources, policy) = fixture(0, false)?;
    let result = checked(analyze(policy, &twin, &sources, &mut WorkBudget::new(WORK)))?;
    assert!(result.reconstructed);
    assert_eq!(
        (result.solved, result.unresolved, result.occlusion_conflicts),
        (2, 0, 0)
    );
    assert_eq!(result.reference_time_ns, REFERENCE);
    assert_eq!(result.capture_hull, [REFERENCE - 5, REFERENCE + 5]);
    let NativeGeometry::Pair(value) = &result.association else {
        return Err("pair result".into());
    };
    assert_eq!(
        (
            value.pairs().len(),
            value.features().len(),
            value.hypotheses().len()
        ),
        (4, 4, 2)
    );
    for (hypothesis, position) in value.hypotheses().iter().zip(POINTS) {
        let FeatureHypothesisOutcome::Fused(point) = &hypothesis.outcome else {
            return Err("expected actual native point".into());
        };
        close(point.estimate().position, position);
        assert!(
            point
                .inputs()
                .iter()
                .all(|input| input.camera.error.is_none())
        );
    }
    Ok(())
}

#[test]
fn three_camera_joint_components_preserve_every_pair_and_actual_source_frame() -> Test {
    let (twin, sources, policy) = fixture(1, false)?;
    let result = checked(analyze(policy, &twin, &sources, &mut WorkBudget::new(WORK)))?;
    assert!(result.reconstructed);
    assert_eq!((result.solved, result.unresolved), (2, 0));
    let NativeGeometry::Multi(value) = &result.association else {
        return Err("multi result".into());
    };
    assert_eq!(value.pairs().len(), 3);
    assert!(
        value
            .pairs()
            .iter()
            .all(|pair| pair.report().pairs().len() == 4)
    );
    assert_eq!(value.components().len(), 2);
    for (component, position) in value.components().iter().zip(POINTS) {
        assert_eq!((component.members().len(), component.links().len()), (3, 3));
        let ComponentOutcome::Fused(point) = component.outcome() else {
            return Err("joint point".into());
        };
        close(point.estimate().position, position);
    }
    for (actual, expected) in result.views.iter().zip(&sources) {
        assert_eq!(actual.frame.identity(), expected.frame.identity());
        assert_eq!(
            actual.frame.descriptor_domain(),
            expected.frame.descriptor_domain()
        );
        assert_eq!(actual.frame.features(), expected.frame.features());
        assert_eq!(actual.allowed_mask_digest, expected.allowed_mask_digest);
        assert_eq!(actual.camera, expected.camera);
    }
    Ok(())
}

#[test]
fn repeated_exposures_fit_known_velocity_at_one_unchanged_global_time() -> Test {
    let (twin, sources, policy) = fixture(2, false)?;
    let result = checked(analyze(policy, &twin, &sources, &mut WorkBudget::new(WORK)))?;
    assert!(result.reconstructed);
    assert_eq!((result.solved, result.unresolved), (2, 0));
    assert_eq!(result.reference_time_ns, REFERENCE);
    assert_eq!(result.capture_hull, [EPOCH - 5, EPOCH + 1_000_000_005]);
    let NativeGeometry::Temporal(value) = &result.association else {
        return Err("temporal result".into());
    };
    assert_eq!(value.pairs().len(), 6);
    assert!(value.pairs().iter().all(|pair| pair.pairs().len() == 4));
    for (index, component) in value.components().iter().enumerate() {
        assert_eq!((component.members().len(), component.links().len()), (4, 6));
        let TemporalComponentOutcome::Fused(motion) = component.outcome() else {
            return Err("native motion".into());
        };
        close(
            motion.estimate().position,
            std::array::from_fn(|axis| POINTS[index][axis] + 0.5 * VELOCITIES[index][axis]),
        );
        close(motion.estimate().velocity_per_second, VELOCITIES[index]);
        assert_eq!(motion.request().reference_time_ns, REFERENCE);
        assert!(
            motion
                .inputs()
                .iter()
                .all(|input| input.camera.error.is_none())
        );
    }
    assert_eq!(result.views[0].source_digest, result.views[1].source_digest);
    assert_ne!(
        result.views[0].frame.identity().exposure,
        result.views[1].frame.identity().exposure
    );
    Ok(())
}

#[test]
fn nominal_occlusion_prevents_strict_success_in_all_three_modes_without_erasing_estimates() -> Test
{
    for mode in 0..3 {
        let (twin, sources, policy) = fixture(mode, true)?;
        let result = checked(analyze(policy, &twin, &sources, &mut WorkBudget::new(WORK)))?;
        assert_eq!(
            (result.solved, result.unresolved, result.occlusion_conflicts),
            (2, 2, 2)
        );
        assert!(!result.reconstructed);
        let json = checked(envelope(
            "fixture",
            &result,
            r#"{"outcome":"reconstructed","all_native_diagnostics":"preserved"}"#.into(),
            1_000_000,
            &mut WorkBudget::new(WORK),
        ))?;
        let parsed = parse(&json)?;
        assert_eq!(
            field(&parsed, &["outcome"])?.text(),
            Some("reconstructed_with_refusals")
        );
        assert_eq!(
            field(&parsed, &["native_diagnostics", "outcome"])?.text(),
            Some("reconstructed")
        );
        assert_eq!(
            field(&parsed, &["counts", "nominal_occlusion_conflicts"])?.integer(),
            Some(2)
        );
    }
    Ok(())
}

#[test]
fn empty_features_are_explicit_and_do_not_skip_any_camera_validation() -> Test {
    for mode in 0..3 {
        let (twin, mut sources, policy) = fixture(mode, false)?;
        for source in &mut sources {
            replace_features(source, Vec::new())?;
        }
        let result = checked(analyze(policy, &twin, &sources, &mut WorkBudget::new(WORK)))?;
        assert_eq!(
            (result.solved, result.unresolved, result.views.len()),
            (0, 0, sources.len())
        );
        assert!(!result.reconstructed);
        let json = checked(envelope(
            "fixture",
            &result,
            "{}".into(),
            1_000_000,
            &mut WorkBudget::new(WORK),
        ))?;
        assert_eq!(
            field(&parse(&json)?, &["outcome"])?.text(),
            Some("no_reconstruction")
        );
        sources[0].clock_evidence = [0; 32];
        assert!(analyze(policy, &twin, &sources, &mut WorkBudget::new(WORK)).is_err());
    }
    Ok(())
}

#[test]
fn isolated_unmatched_feature_is_diagnostic_but_two_exposure_motion_component_is_unresolved() -> Test
{
    for mode in 0..3 {
        let (twin, mut sources, policy) = fixture(mode, false)?;
        let extra = ImageFeature {
            id: 999,
            pixel: [40.0, 40.0],
            descriptor: BinaryDescriptor([0xaaaa_aaaa_aaaa_aaaa; 4]),
        };
        let mut features = sources[0].frame.features().to_vec();
        features.push(extra);
        replace_features(&mut sources[0], features)?;
        let isolated = checked(analyze(policy, &twin, &sources, &mut WorkBudget::new(WORK)))?;
        assert_eq!((isolated.solved, isolated.unresolved), (2, 0));
        assert!(isolated.reconstructed);
        if mode == 2 {
            let mut features = sources[1].frame.features().to_vec();
            features.push(ImageFeature { id: 1000, ..extra });
            replace_features(&mut sources[1], features)?;
            let connected = checked(analyze(policy, &twin, &sources, &mut WorkBudget::new(WORK)))?;
            assert_eq!((connected.solved, connected.unresolved), (2, 1));
            assert!(!connected.reconstructed);
            let NativeGeometry::Temporal(value) = connected.association else {
                return Err("temporal graph".into());
            };
            assert!(value.components().iter().any(|component| matches!(
                component.outcome(),
                TemporalComponentOutcome::InsufficientObservations
            )));
        }
    }
    Ok(())
}

#[test]
fn canonical_native_view_order_and_evidence_are_permutation_invariant() -> Test {
    for mode in 0..3 {
        let (twin, mut sources, policy) = fixture(mode, false)?;
        let first = checked(analyze(policy, &twin, &sources, &mut WorkBudget::new(WORK)))?;
        sources.reverse();
        let second = checked(analyze(policy, &twin, &sources, &mut WorkBudget::new(WORK)))?;
        assert_eq!(evidence(&first), evidence(&second));
        assert_eq!(
            first
                .views
                .iter()
                .map(|v| (v.camera.camera, v.capture, v.frame.identity()))
                .collect::<Vec<_>>(),
            second
                .views
                .iter()
                .map(|v| (v.camera.camera, v.capture, v.frame.identity()))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            (first.solved, first.unresolved),
            (second.solved, second.unresolved)
        );
    }
    Ok(())
}

#[test]
fn native_and_canonical_copy_work_is_exact_and_cancellation_is_failure_atomic() -> Test {
    for mode in 0..3 {
        let (twin, sources, policy) = fixture(mode, false)?;
        let mut measured = WorkBudget::new(WORK);
        checked(analyze(policy, &twin, &sources, &mut measured))?;
        checked(analyze(
            policy,
            &twin,
            &sources,
            &mut WorkBudget::new(measured.used()),
        ))?;
        let error = analyze(
            policy,
            &twin,
            &sources,
            &mut WorkBudget::new(measured.used() - 1),
        )
        .err()
        .ok_or("one less work accepted")?;
        assert_eq!(error.code, "ERR-SCENE-FUSION-LIMIT-001");
        let calls = AtomicUsize::new(0);
        let never = || {
            calls.fetch_add(1, Ordering::Relaxed);
            false
        };
        checked(analyze(
            policy,
            &twin,
            &sources,
            &mut WorkBudget::with_cancellation_probe(WORK, &never),
        ))?;
        let total = calls.load(Ordering::Relaxed);
        for stop in [0, total / 2, total - 1] {
            let calls = AtomicUsize::new(0);
            let cancel = || calls.fetch_add(1, Ordering::Relaxed) >= stop;
            let error = analyze(
                policy,
                &twin,
                &sources,
                &mut WorkBudget::with_cancellation_probe(WORK, &cancel),
            )
            .err()
            .ok_or("cancelled analysis returned a result")?;
            assert_eq!(error.code, "ERR-SCENE-FUSION-CANCELLED-001");
        }
    }
    Ok(())
}

#[test]
fn envelope_keeps_all_payload_bytes_and_charges_full_copy_even_for_tiny_output_allowance() -> Test {
    let (twin, sources, policy) = fixture(0, false)?;
    let analysis = checked(analyze(policy, &twin, &sources, &mut WorkBudget::new(WORK)))?;
    let diagnostics = r#"{"pairs":[{"refused":"weak"},{"ambiguous":[1,2]}],"features":[1,2,3],"hypotheses":[{"value":5}]}"#;
    let mut full_work = WorkBudget::new(WORK);
    let full = checked(envelope(
        "static_pair",
        &analysis,
        diagnostics.into(),
        1_000_000,
        &mut full_work,
    ))?;
    let parsed = parse(&full)?;
    assert_eq!(
        *field(&parsed, &["native_diagnostics"])?,
        parse(diagnostics)?
    );
    assert_eq!(
        field(&parsed, &["reference_time_ns"])?.text(),
        Some(REFERENCE.to_string().as_str())
    );
    assert_eq!(
        checked(envelope(
            "static_pair",
            &analysis,
            diagnostics.into(),
            full.len() + 1,
            &mut WorkBudget::new(full_work.used())
        ))?,
        full
    );
    let mut refused_work = WorkBudget::new(WORK);
    assert!(
        envelope(
            "static_pair",
            &analysis,
            diagnostics.into(),
            1,
            &mut refused_work
        )
        .is_err()
    );
    assert_eq!(refused_work.used(), full_work.used());
    assert!(
        envelope(
            "static_pair",
            &analysis,
            diagnostics.into(),
            full.len(),
            &mut WorkBudget::new(WORK)
        )
        .is_err()
    );
    assert!(
        envelope(
            "static_pair",
            &analysis,
            diagnostics.into(),
            1_000_000,
            &mut WorkBudget::new(full_work.used() - 1)
        )
        .is_err()
    );
    let calls = AtomicUsize::new(0);
    let terminal = || calls.fetch_add(1, Ordering::Relaxed) > 0;
    let error = envelope(
        "static_pair",
        &analysis,
        diagnostics.into(),
        1_000_000,
        &mut WorkBudget::with_cancellation_probe(WORK, &terminal),
    )
    .err()
    .ok_or("cancelled envelope returned JSON")?;
    assert_eq!(error.code, "ERR-SCENE-FUSION-CANCELLED-001");
    Ok(())
}

#[test]
fn declared_geometry_mode_never_silently_truncates_a_source_inventory() -> Test {
    let (twin, sources, _) = fixture(1, false)?;
    for selected in [&sources[..1], &sources[..3]] {
        assert!(
            analyze(
                GeometryPolicy::Pair(static_options()),
                &twin,
                selected,
                &mut WorkBudget::new(WORK)
            )
            .is_err()
        );
    }
    assert!(
        analyze(
            GeometryPolicy::Multi(static_options()),
            &twin,
            &sources[..2],
            &mut WorkBudget::new(WORK)
        )
        .is_err()
    );
    assert!(
        analyze(
            GeometryPolicy::Temporal(temporal_options()),
            &twin,
            &sources,
            &mut WorkBudget::new(WORK)
        )
        .is_err()
    );
    Ok(())
}

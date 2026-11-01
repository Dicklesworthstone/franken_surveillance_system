#![forbid(unsafe_code)]
//! Real native motion associations exercise the complete production JSON serializer.
//! These pure tests make no claim about the retained-source command's I/O or custody.

use std::collections::BTreeSet;
use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_cli::json_input::{Value, parse, parse_reconstruction_atlas_report};
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_geometry::temporal_triangulation::TemporalTriangulationOptions;
use fss_geometry::{GeometryBasis, PinholeIntrinsics, RigidPose, WorkBudget};
use fss_twin::feature_association::{DescriptorDecision, FeatureView};
use fss_twin::localization::{BinaryDescriptor, FeatureFrame, ImageFeature, ImageIdentity};
use fss_twin::temporal_feature_association::{
    TemporalAssociationOptions, TemporalComponentOutcome, TemporalFeatureAssociation,
    associate_temporal_features,
};
use fss_twin::{ImportExpectation, ImportLimits, PropertyTwin, TrackingCamera, import_twin};

use super::{assumptions, compute};

type Test<T = ()> = std::result::Result<T, Box<dyn Error>>;
const WORK: u64 = 1_000_000_000;
const REPORT_BYTES: usize = 32 * 1024 * 1024;
// Decimal JSON strings must preserve nanoseconds above the exact-integer f64 range.
const EPOCH: u64 = u64::MAX - 4_000_000_000;
const POINTS: [[f64; 3]; 2] = [[0.2, 0.3, 10.], [2., 1.5, 12.]];
const VELOCITIES: [[f64; 3]; 2] = [[0.7, 0.4, 0.2], [-0.3, 0.2, -0.1]];

fn checked<T>(result: crate::Result<T>) -> Test<T> {
    result.map_err(|error| format!("temporal report: {error:?}").into())
}

fn field<'a>(value: &'a Value, path: &[&str]) -> Test<&'a Value> {
    if path.is_empty() {
        return Ok(value);
    }
    let next = match value {
        Value::Object(values) => values.get(path[0]),
        Value::Array(values) => values.get(path[0].parse::<usize>()?),
        _ => None,
    }
    .ok_or_else(|| format!("missing temporal report field {path:?}"))?;
    field(next, &path[1..])
}

fn rows<'a>(value: &'a Value, path: &[&str]) -> Test<&'a [Value]> {
    field(value, path)?
        .array()
        .ok_or("expected temporal report array".into())
}

fn number(value: &Value) -> Test<f64> {
    match value {
        Value::Number(text) => Ok(text.parse()?),
        _ => Err("expected JSON number".into()),
    }
}

fn digest(bytes: [u8; 32]) -> String {
    ContentDigest::new(DigestAlgorithm::Sha256, bytes).to_text()
}

fn twin() -> Test<PropertyTwin> {
    fn text(bytes: &mut Vec<u8>, value: &str) {
        bytes.extend_from_slice(&(value.len() as u16).to_le_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    let mut body = vec![1; 32];
    text(&mut body, "temporal-report-fixture/Z-up");
    text(&mut body, "synthetic");
    body.push(0);
    for value in [0_f64, -1., 0.4] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    for value in [1_u32, 1, 4, 2] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    text(&mut body, "walk");
    body.push(1);
    text(&mut body, "ground");
    body.extend_from_slice(&[0, 0, 0, 0, 1, 1]);
    for point in [
        [-4_f64, -4., -20.],
        [4., -4., -20.],
        [4., 4., -20.],
        [-4., 4., -20.],
    ] {
        for value in point {
            body.extend_from_slice(&value.to_le_bytes());
        }
    }
    for value in [0_u32, 1, 2, 0, 0, 2, 3, 0] {
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
            source_scene_sha256: [1; 32],
            basis: GeometryBasis::new(7, 2)?,
        },
        ImportLimits::default(),
        &mut WorkBudget::new(WORK),
    )?)
}

fn options() -> TemporalAssociationOptions {
    TemporalAssociationOptions {
        association_basis: [90; 32],
        camera_rig_digest: [91; 32],
        privacy_domain: 2,
        clock: 1,
        clock_evidence: [92; 32],
        reference_time_ns: EPOCH + 500_000_000,
        max_capture_span_ns: 3_100_000_000,
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

fn view(twin: &PropertyTwin, camera: u8, exposure: u8, offset: u64) -> Test<FeatureView> {
    let center = [f64::from(camera - 1), 0., 0.];
    let seconds = offset as f64 * 1e-9;
    let features = POINTS
        .iter()
        .zip(VELOCITIES)
        .enumerate()
        .map(|(i, (p, v))| {
            let moving: [f64; 3] = std::array::from_fn(|axis| p[axis] + v[axis] * seconds);
            // Independent scalar projection; production ray/project helpers are not used.
            feature(
                u64::from(exposure) * 10 + i as u64 + 1,
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
            validity: [0, u64::MAX],
            pose: RigidPose::from_center([[1., 0., 0.], [0., 1., 0.], [0., 0., 1.]], center)?,
            intrinsics: PinholeIntrinsics::new(192, 128, 120., 120., 96., 64.)?,
            error: None,
        },
        // Repeated encoded/source bytes are not a distinct source/exposure alias.
        source_digest: [camera + 50; 32],
        allowed_mask_digest: [exposure + 60; 32],
        mapping_basis: [camera + 80; 32],
        privacy_domain: 2,
        clock_evidence: [92; 32],
        capture: [EPOCH + offset - 5, EPOCH + offset + 5],
        sigma_pixels: 0.5,
    })
}

fn views(twin: &PropertyTwin) -> Test<Vec<FeatureView>> {
    [
        (1, 1, 0),
        (1, 2, 1_000_000_000),
        (2, 3, 250_000_000),
        (2, 4, 1_250_000_000),
    ]
    .into_iter()
    .map(|(camera, exposure, offset)| view(twin, camera, exposure, offset))
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

fn run(
    twin: &PropertyTwin,
    sources: &[FeatureView],
    policy: TemporalAssociationOptions,
) -> Test<TemporalFeatureAssociation> {
    Ok(associate_temporal_features(
        twin,
        sources,
        policy,
        &mut WorkBudget::new(WORK),
    )?)
}

fn render(
    name: Option<&str>,
    association: &TemporalFeatureAssociation,
) -> Test<(String, Value, bool)> {
    let report = checked(compute(
        association,
        REPORT_BYTES,
        &mut WorkBudget::new(WORK),
    ))?;
    let value = parse_reconstruction_atlas_report(&report.json)?;
    if let Some(name) = name {
        println!("FSS_TEMPORAL_REPORT_FIXTURE|{name}|{}", report.json);
    }
    Ok((report.json, value, report.reconstructed))
}

fn complete_inventory(value: &Value, association: &TemporalFeatureAssociation) -> Test {
    assert_eq!(
        field(value, &["scene_evidence"])?.text(),
        Some(digest(association.evidence()).as_str())
    );
    let pairs = rows(value, &["exposure_pairs"])?;
    assert_eq!(pairs.len(), association.pairs().len());
    for (pair, native) in pairs.iter().zip(association.pairs()) {
        assert_eq!(
            field(pair, &["evidence_digest"])?.text(),
            Some(digest(native.evidence()).as_str())
        );
        for (view, expected) in rows(pair, &["views"])?.iter().zip(native.views()) {
            assert_eq!(view.integer(), Some(expected as i128));
        }
        assert_eq!(
            rows(pair, &["feature_outcomes"])?.len(),
            native.features().len()
        );
        let decisions = rows(pair, &["pairs"])?;
        assert_eq!(decisions.len(), native.pairs().len());
        for (decision, expected) in decisions.iter().zip(native.pairs()) {
            for (feature, id) in rows(decision, &["features"])?.iter().zip(expected.features) {
                assert_eq!(feature.text(), Some(id.to_string().as_str()));
            }
            assert_eq!(
                field(decision, &["hamming_distance"])?.integer(),
                Some(i128::from(expected.hamming_distance))
            );
            assert_eq!(
                field(decision, &["descriptor"])?.text(),
                Some(match expected.descriptor {
                    DescriptorDecision::Candidate => "candidate",
                    DescriptorDecision::Ambiguous => "ambiguous",
                    DescriptorDecision::TooDistant => "too_distant",
                    DescriptorDecision::NonMutual => "non_mutual",
                })
            );
        }
    }
    let components = rows(value, &["components"])?;
    assert_eq!(components.len(), association.components().len());
    for (component, native) in components.iter().zip(association.components()) {
        assert_eq!(
            field(component, &["evidence_digest"])?.text(),
            Some(digest(native.evidence()).as_str())
        );
        assert_eq!(rows(component, &["members"])?.len(), native.members().len());
        assert_eq!(rows(component, &["links"])?.len(), native.links().len());
        for (member, native) in rows(component, &["members"])?.iter().zip(native.members()) {
            assert_eq!(
                field(member, &["view"])?.integer(),
                Some(native.view as i128)
            );
            assert_eq!(
                field(member, &["camera"])?.text(),
                Some(native.camera.to_string().as_str())
            );
            assert_eq!(
                field(member, &["feature"])?.text(),
                Some(native.feature.to_string().as_str())
            );
        }
        for (link, native) in rows(component, &["links"])?.iter().zip(native.links()) {
            assert_eq!(field(link, &["pair"])?.integer(), Some(native.pair as i128));
            assert_eq!(
                field(link, &["decision"])?.integer(),
                Some(native.decision as i128)
            );
        }
    }
    Ok(())
}

#[test]
fn exact_scene_time_complete_pair_graph_and_full_motion_covariance_survive_serialization() -> Test {
    let twin = twin()?;
    let sources = views(&twin)?;
    assert_eq!(sources[0].source_digest, sources[1].source_digest);
    assert_ne!(
        sources[0].frame.identity().exposure,
        sources[1].frame.identity().exposure
    );
    let association = run(&twin, &sources, options())?;
    let (_, value, reconstructed) = render(Some("solved"), &association)?;
    assert!(reconstructed);
    assert_eq!(field(&value, &["outcome"])?.text(), Some("reconstructed"));
    assert_eq!(
        field(&value, &["requested_scene_time_ns"])?.text(),
        Some(options().reference_time_ns.to_string().as_str())
    );
    assert_eq!(
        field(&value, &["pair_geometry"])?.text(),
        Some("not_applied_to_staggered_moving_observations")
    );
    complete_inventory(&value, &association)?;
    for (key, count) in [
        ("cameras", 2),
        ("exposures", 4),
        ("exposure_pairs", 6),
        ("features", 8),
        ("pair_rows", 24),
        ("pair_feature_outcomes", 24),
        ("components", 2),
        ("links", 12),
        ("solved", 2),
        ("unresolved", 0),
    ] {
        assert_eq!(field(&value, &["counts", key])?.integer(), Some(count));
    }
    for (component, native) in rows(&value, &["components"])?
        .iter()
        .zip(association.components())
    {
        let TemporalComponentOutcome::Fused(motion) = native.outcome() else {
            return Err("projected trajectory did not solve".into());
        };
        let outcome = field(component, &["outcome"])?;
        assert_eq!(field(outcome, &["state"])?.text(), Some("estimated"));
        assert_eq!(
            field(outcome, &["reference_time_ns"])?.text(),
            Some(options().reference_time_ns.to_string().as_str())
        );
        for (key, expected) in [
            ("position", motion.estimate().position),
            ("velocity_per_second", motion.estimate().velocity_per_second),
        ] {
            for (number_value, expected) in rows(outcome, &[key])?.iter().zip(expected) {
                assert_eq!(number(number_value)?, expected);
            }
        }
        let covariance = rows(outcome, &["pixel_noise_covariance"])?;
        assert_eq!(covariance.len(), 6);
        for (row, expected) in covariance
            .iter()
            .zip(motion.estimate().pixel_noise_covariance)
        {
            let row = row.array().ok_or("missing covariance row")?;
            assert_eq!(row.len(), 6);
            for (number_value, expected) in row.iter().zip(expected) {
                assert_eq!(number(number_value)?, expected);
            }
        }
        assert_eq!(motion.map_error(), Some(0.4));
        assert!(
            motion
                .inputs()
                .iter()
                .all(|input| input.camera.error.is_none())
        );
        let residuals = rows(outcome, &["views"])?;
        assert_eq!(residuals.len(), 4);
        let mut aliases = BTreeSet::new();
        for residual in residuals {
            let alias: usize = field(residual, &["exposure"])?
                .text()
                .ok_or("missing exposure alias")?
                .parse()?;
            assert!(aliases.insert(alias));
            let source = &association.views()[alias - 1];
            assert_eq!(
                field(residual, &["camera"])?.text(),
                Some(source.camera.camera.to_string().as_str())
            );
            for (bound, expected) in rows(residual, &["capture_ns"])?.iter().zip(source.capture) {
                assert_eq!(bound.text(), Some(expected.to_string().as_str()));
            }
        }
        assert_eq!(aliases, (1..=4).collect());
    }
    let assumptions = parse(&assumptions())?;
    assert!(rows(&assumptions, &[])?.iter().any(|item| item.text()
        == Some(
            "pixel_covariance_excludes_map_camera_clock_acceleration_and_correspondence_errors"
        )));
    Ok(())
}

#[test]
fn refused_and_unsupported_components_keep_all_members_links_and_requested_time() -> Test {
    let twin = twin()?;
    let original = views(&twin)?;
    let mut scenarios = Vec::new();
    let mut short = original.clone();
    replace(&mut short[3], vec![])?;
    scenarios.push(("short", short, options(), "insufficient_observations"));
    let mut single = (0..4)
        .map(|i| view(&twin, 1, i + 1, u64::from(i) * 250_000_000))
        .collect::<Test<Vec<_>>>()?;
    let mut empty = view(&twin, 2, 9, 1_000_000_000)?;
    replace(&mut empty, vec![])?;
    single.push(empty);
    scenarios.push(("single_camera", single, options(), "insufficient_cameras"));
    let mut late = original.clone();
    let mut empty = view(&twin, 1, 5, 3_000_000_000)?;
    replace(&mut empty, vec![])?;
    late.push(empty);
    scenarios.push((
        "outside_component_time",
        late,
        TemporalAssociationOptions {
            reference_time_ns: EPOCH + 2_000_000_000,
            ..options()
        },
        "refused",
    ));
    for (name, sources, policy, state) in scenarios {
        let association = run(&twin, &sources, policy)?;
        let (_, value, reconstructed) = render(Some(name), &association)?;
        assert!(!reconstructed);
        assert_eq!(
            field(&value, &["outcome"])?.text(),
            Some("no_reconstruction")
        );
        assert_eq!(field(&value, &["counts", "solved"])?.integer(), Some(0));
        assert_eq!(field(&value, &["counts", "unresolved"])?.integer(), Some(2));
        complete_inventory(&value, &association)?;
        for component in rows(&value, &["components"])? {
            assert_eq!(field(component, &["outcome", "state"])?.text(), Some(state));
            assert_eq!(
                field(component, &["requested_scene_time_ns"])?.text(),
                Some(policy.reference_time_ns.to_string().as_str())
            );
            if state == "refused" {
                assert!(
                    !field(component, &["outcome", "reason"])?
                        .text()
                        .ok_or("missing refusal reason")?
                        .is_empty()
                );
                assert_eq!(
                    field(component, &["nominal_time_range_ns", "1"])?.text(),
                    Some((EPOCH + 1_250_000_000).to_string().as_str())
                );
            }
        }
    }
    // Exposure-conflicting cycles and incomplete chains remain diagnostic graph components.
    for conflict in [false, true] {
        let mut sources = original.clone();
        let descriptors = if conflict {
            vec![
                vec![[0; 4], [7, 0, 0, 0]],
                vec![[1, 0, 0, 0], [u64::MAX; 4]],
                vec![[3, 0, 0, 0], [u64::MAX; 4]],
                vec![],
            ]
        } else {
            [0, 1, 3, 7]
                .map(|word| vec![[word, 0, 0, 0], [u64::MAX; 4]])
                .to_vec()
        };
        for (source, descriptors) in sources.iter_mut().zip(descriptors) {
            let entries = descriptors
                .into_iter()
                .enumerate()
                .map(|(i, descriptor)| {
                    // Keep one real projected moving control beside the incomplete graph.
                    let pixel = if !conflict && i == 1 {
                        source.frame.features()[1].pixel
                    } else {
                        [90. + i as f64 * 10., 60.]
                    };
                    feature(i as u64 + 1, pixel, descriptor)
                })
                .collect();
            replace(source, entries)?;
        }
        let association = run(
            &twin,
            &sources,
            TemporalAssociationOptions {
                maximum_hamming_distance: 1,
                ..options()
            },
        )?;
        let name = if conflict {
            "exposure_conflict"
        } else {
            "incomplete_pair_support"
        };
        let (_, value, reconstructed) = render(Some(name), &association)?;
        assert!(!reconstructed);
        assert_eq!(
            field(&value, &["outcome"])?.text(),
            Some(if conflict {
                "no_reconstruction"
            } else {
                "reconstructed_with_refusals"
            })
        );
        assert_eq!(
            field(&value, &["counts", "solved"])?.integer(),
            Some(if conflict { 0 } else { 1 })
        );
        complete_inventory(&value, &association)?;
        let component = &rows(&value, &["components"])?[0];
        assert_eq!(field(component, &["outcome", "state"])?.text(), Some(name));
        assert_eq!(rows(component, &["members"])?.len(), 4);
        assert_eq!(rows(component, &["links"])?.len(), 3);
        if conflict {
            assert_eq!(
                field(component, &["outcome", "views", "0"])?.integer(),
                Some(0)
            );
        } else {
            let missing = rows(component, &["outcome", "missing_pairs"])?;
            assert_eq!(missing.len(), 3);
            assert_eq!(
                field(&value, &["counts", "missing_links"])?.integer(),
                Some(3)
            );
            for link in missing {
                let pair =
                    usize::try_from(field(link, &["pair"])?.integer().ok_or("missing pair")?)?;
                let decision = usize::try_from(
                    field(link, &["decision"])?
                        .integer()
                        .ok_or("missing decision")?,
                )?;
                assert_eq!(
                    association.pairs()[pair].pairs()[decision].descriptor,
                    DescriptorDecision::TooDistant
                );
            }
        }
    }
    Ok(())
}

#[test]
fn ties_missing_runner_up_and_asymmetric_competition_are_all_explicit() -> Test {
    let twin = twin()?;
    for singleton in [false, true] {
        let mut sources = views(&twin)?;
        for source in &mut sources {
            replace(
                source,
                if singleton {
                    vec![feature(1, [90., 60.], [0; 4])]
                } else {
                    vec![
                        feature(1, [90., 60.], [0; 4]),
                        feature(2, [100., 60.], [0; 4]),
                    ]
                },
            )?;
        }
        let association = run(&twin, &sources, options())?;
        let (_, value, reconstructed) = render(
            Some(if singleton { "no_runner_up" } else { "ties" }),
            &association,
        )?;
        assert!(!reconstructed);
        complete_inventory(&value, &association)?;
        for pair in rows(&value, &["exposure_pairs"])? {
            for row in rows(pair, &["feature_outcomes"])? {
                assert_eq!(field(row, &["disposition"])?.text(), Some("ambiguous"));
                assert_eq!(
                    field(row, &["selected_pair", "state"])?.text(),
                    Some("not_selected")
                );
                assert_eq!(
                    rows(row, &["nearest_features"])?.len(),
                    if singleton { 1 } else { 2 }
                );
                assert_eq!(
                    field(row, &["runner_up_hamming_distance", "state"])?.text(),
                    Some(if singleton {
                        "unavailable"
                    } else {
                        "available"
                    })
                );
                if singleton {
                    assert_eq!(
                        field(row, &["runner_up_hamming_distance", "reason"])?.text(),
                        Some("no_runner_up")
                    );
                }
            }
        }
        assert!(rows(&value, &["components"])?.iter().all(|component| {
            field(component, &["outcome", "state"])
                .ok()
                .and_then(Value::text)
                == Some("unmatched")
        }));
    }
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
    replace(&mut sources[3], vec![])?;
    let association = run(
        &twin,
        &sources,
        TemporalAssociationOptions {
            maximum_hamming_distance: 2,
            ..options()
        },
    )?;
    let (_, value, _) = render(Some("all_descriptor_dispositions"), &association)?;
    complete_inventory(&value, &association)?;
    let decisions: Vec<_> = rows(&value, &["exposure_pairs", "0", "pairs"])?
        .iter()
        .map(|row| {
            field(row, &["descriptor"])?
                .text()
                .ok_or("missing disposition".into())
        })
        .collect::<Test<_>>()?;
    assert_eq!(
        decisions,
        ["candidate", "non_mutual", "too_distant", "ambiguous"]
    );
    for pair in rows(&value, &["exposure_pairs"])? {
        if rows(pair, &["pairs"])?.is_empty() {
            for row in rows(pair, &["feature_outcomes"])? {
                assert_eq!(field(row, &["disposition"])?.text(), Some("no_counterpart"));
                assert_eq!(
                    field(row, &["best_hamming_distance", "reason"])?.text(),
                    Some("no_counterpart")
                );
            }
        }
    }
    Ok(())
}

#[test]
fn maximum_sixteen_exposure_report_keeps_all_rows_features_and_nearest_ties() -> Test {
    let twin = twin()?;
    let mut sources = Vec::new();
    for camera in 1..=2 {
        for frame in 0..8_u8 {
            let mut source = view(
                &twin,
                camera,
                (camera - 1) * 8 + frame + 1,
                u64::from(frame) * 125_000_000 + u64::from(camera - 1) * 25_000_000,
            )?;
            replace(
                &mut source,
                (0..16)
                    .map(|i| {
                        feature(
                            i + 1,
                            [80. + (i % 8) as f64 * 4., 50. + (i / 8) as f64 * 4.],
                            [0; 4],
                        )
                    })
                    .collect(),
            )?;
            sources.push(source);
        }
    }
    let association = run(&twin, &sources, options())?;
    let (json, value, reconstructed) = render(None, &association)?;
    assert!(!reconstructed);
    assert!(json.len() < REPORT_BYTES);
    complete_inventory(&value, &association)?;
    for (key, count) in [
        ("exposures", 16),
        ("exposure_pairs", 120),
        ("features", 256),
        ("pair_rows", 30_720),
        ("pair_feature_outcomes", 3_840),
        ("components", 256),
        ("unmatched", 256),
        ("links", 0),
        ("solved", 0),
    ] {
        assert_eq!(field(&value, &["counts", key])?.integer(), Some(count));
    }
    let mut nearest_count = 0;
    for pair in rows(&value, &["exposure_pairs"])? {
        assert_eq!(rows(pair, &["pairs"])?.len(), 256);
        for row in rows(pair, &["feature_outcomes"])? {
            let nearest = rows(row, &["nearest_features"])?;
            assert_eq!(nearest.len(), 16);
            nearest_count += nearest.len();
        }
    }
    assert_eq!(nearest_count, 61_440);
    Ok(())
}

#[test]
fn byte_work_and_initial_or_terminal_cancellation_never_return_a_report_prefix() -> Test {
    let twin = twin()?;
    let association = run(&twin, &views(&twin)?, options())?;
    let mut work = WorkBudget::new(WORK);
    let full = checked(compute(&association, REPORT_BYTES, &mut work))?;
    let used = work.used();
    let exact = checked(compute(
        &association,
        full.json.len() + 1,
        &mut WorkBudget::new(used),
    ))?;
    assert_eq!(exact.json, full.json);
    assert_eq!(exact.reconstructed, full.reconstructed);
    for (bytes, units) in [
        (full.json.len(), used),
        (full.json.len() + 1, used - 1),
        (1, WORK),
    ] {
        let failure = compute(&association, bytes, &mut WorkBudget::new(units))
            .err()
            .ok_or("bounded rendering returned JSON")?;
        assert_eq!(failure.code, "ERR-SCENE-FUSION-LIMIT-001");
    }
    let calls = AtomicUsize::new(0);
    let never = || {
        calls.fetch_add(1, Ordering::Relaxed);
        false
    };
    checked(compute(
        &association,
        REPORT_BYTES,
        &mut WorkBudget::with_cancellation_probe(WORK, &never),
    ))?;
    let total = calls.load(Ordering::Relaxed);
    assert!(total >= association.pairs().len() + association.components().len() + 2);
    for stop in [0, total / 2, total - 1] {
        let calls = AtomicUsize::new(0);
        let cancelled = || calls.fetch_add(1, Ordering::Relaxed) >= stop;
        let failure = compute(
            &association,
            REPORT_BYTES,
            &mut WorkBudget::with_cancellation_probe(WORK, &cancelled),
        )
        .err()
        .ok_or("cancelled rendering returned JSON")?;
        assert_eq!(failure.code, "ERR-SCENE-FUSION-CANCELLED-001");
        assert_eq!(calls.load(Ordering::Relaxed), stop + 1);
    }
    Ok(())
}

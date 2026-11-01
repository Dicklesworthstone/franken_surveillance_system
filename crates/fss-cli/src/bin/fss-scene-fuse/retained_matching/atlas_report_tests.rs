#![forbid(unsafe_code)]
//! Actual native association and atlas admission exercise the production pure serializers.
//! These tests do not substitute or claim execution of the retained-source command owner.

use std::collections::BTreeSet;
use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;
use fss_geometry::triangulation::TriangulationOptions;
use fss_geometry::{GeometryBasis, PinholeIntrinsics, RigidPose, WorkBudget};
use fss_twin::feature_association::{
    AssociationOptions, FeatureAssociation, FeatureView, associate_features,
};
use fss_twin::localization::{BinaryDescriptor, FeatureFrame, ImageFeature, ImageIdentity};
use fss_twin::multiview_feature_association::{
    ComponentOutcome, MultiFeatureAssociation, associate_multiview_features,
};
use fss_twin::reconstruction_atlas::{
    AtlasBuildRequest, LandmarkSelection, ReconstructedAtlas, Reconstruction, ReferenceSource,
    build_reconstruction_atlas,
};
use fss_twin::{
    ImportExpectation, ImportLimits, ProjectionError, PropertyTwin, TrackingCamera, import_twin,
};

use super::{assumptions, geometry, receipt};

type Test<T = ()> = std::result::Result<T, Box<dyn Error>>;
const WORK: u64 = 1_000_000_000;
const REPORT_BYTES: usize = 32 * 1024 * 1024;

fn checked<T>(result: crate::Result<T>) -> Test<T> {
    result.map_err(|error| format!("atlas report: {error:?}").into())
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
    .ok_or_else(|| format!("missing atlas report field {path:?}"))?;
    field(next, &path[1..])
}

fn rows<'a>(value: &'a Value, path: &[&str]) -> Test<&'a [Value]> {
    field(value, path)?
        .array()
        .ok_or("expected report array".into())
}

fn number(value: &Value) -> Test<f64> {
    match value {
        Value::Number(text) => Ok(text.parse()?),
        _ => Err("expected JSON number".into()),
    }
}

fn digest(bytes: [u8; 32]) -> String {
    ContentDigest::new(fss_core::DigestAlgorithm::Sha256, bytes).to_text()
}

fn twin(occluder: bool) -> Test<PropertyTwin> {
    fn text(bytes: &mut Vec<u8>, value: &str) {
        bytes.extend_from_slice(&(value.len() as u16).to_le_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    let mut body = vec![1; 32];
    text(&mut body, "atlas-report-fixture/Z-up");
    text(&mut body, "synthetic");
    body.push(0);
    // Even a declared map error must never become a bound on reconstructed landmarks.
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
    let height = if occluder { 5.0_f64 } else { -20. };
    for point in [
        [0., 0., height],
        [4., 0., height],
        [4., 4., height],
        [0., 4., height],
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

fn projected(camera: u8, id: u64, point: [f64; 3], descriptor: [u64; 4]) -> ImageFeature {
    // Independent scalar projection for a unit-spaced horizontal camera rig.
    feature(
        id,
        [
            120. * (point[0] - f64::from(camera - 1)) / point[2] + 96.,
            120. * point[1] / point[2] + 64.,
        ],
        descriptor,
    )
}

fn view(twin: &PropertyTwin, camera: u8, features: Vec<ImageFeature>) -> Test<FeatureView> {
    Ok(FeatureView {
        frame: FeatureFrame::new(
            ImageIdentity {
                exposure: [camera; 32],
                pixels: [camera + 10; 32],
                image_domain: [camera + 20; 32],
                dimensions: [192, 128],
            },
            [77; 32],
            features,
            &mut WorkBudget::new(WORK),
        )?,
        camera: TrackingCamera {
            geometry: twin.basis(),
            camera: u64::from(camera),
            calibration: 1,
            image_domain: u64::from(camera) + 20,
            clock: 1,
            validity: [0, 1000],
            pose: RigidPose::from_center(
                [[1., 0., 0.], [0., 1., 0.], [0., 0., 1.]],
                [f64::from(camera - 1), 0., 0.],
            )?,
            intrinsics: PinholeIntrinsics::new(192, 128, 120., 120., 96., 64.)?,
            error: Some(ProjectionError::EXACT),
        },
        source_digest: [camera + 30; 32],
        allowed_mask_digest: [camera + 40; 32],
        image_domain_digest: [camera + 20; 32],
        mapping_basis: [camera + 50; 32],
        privacy_domain: 2,
        clock_evidence: [92; 32],
        capture: [90, 110],
        sigma_pixels: 0.5,
    })
}

fn build(
    twin: &PropertyTwin,
    reconstruction: Reconstruction<'_>,
    pin: [u8; 32],
    static_basis: [u8; 32],
) -> Test<ReconstructedAtlas> {
    let (evidence, views): (_, &[FeatureView]) = match reconstruction {
        Reconstruction::Pair(value) => (value.evidence(), value.views()),
        Reconstruction::Multiview(value) => (value.evidence(), value.views()),
    };
    let references: Vec<_> = views
        .iter()
        .map(|view| ReferenceSource {
            camera: view.camera.camera,
            source_record: ContentDigest::sha256(&view.camera.camera.to_le_bytes()).bytes(),
        })
        .collect();
    Ok(build_reconstruction_atlas(
        twin,
        &AtlasBuildRequest {
            association_evidence: evidence,
            selections: &[LandmarkSelection {
                hypothesis: pin,
                landmark: 101,
                physical_group: 1001,
                feature: 0,
                enduring_static_basis: static_basis,
            }],
            references: &references,
        },
        reconstruction,
        &mut WorkBudget::new(WORK),
    )?)
}

fn pair_fixture() -> Test<(PropertyTwin, FeatureAssociation, ReconstructedAtlas)> {
    let twin = twin(true)?;
    let sources: Vec<_> = (1..=2)
        .map(|camera| {
            view(
                &twin,
                camera,
                vec![
                    projected(camera, u64::from(camera) * 10 + 1, [-2., -2., 10.], [0; 4]),
                    projected(
                        camera,
                        u64::from(camera) * 10 + 2,
                        [-1., -1., 12.],
                        [u64::MAX; 4],
                    ),
                    projected(
                        camera,
                        u64::from(camera) * 10 + 3,
                        [2., 2., 10.],
                        [0, u64::MAX, 0, u64::MAX],
                    ),
                    // Identical pixels under translated cameras give parallel rays and a real refusal.
                    feature(
                        u64::from(camera) * 10 + 4,
                        [145., 25.],
                        [u64::MAX, 0, u64::MAX, 0],
                    ),
                ],
            )
        })
        .collect::<Test<Vec<_>>>()?;
    let association = associate_features(
        &twin,
        [&sources[0], &sources[1]],
        options(),
        &mut WorkBudget::new(WORK),
    )?;
    let built = build(
        &twin,
        Reconstruction::Pair(&association),
        association.hypotheses()[0].evidence,
        [120; 32],
    )?;
    Ok((twin, association, built))
}

fn multiview_fixture() -> Test<(PropertyTwin, MultiFeatureAssociation, ReconstructedAtlas)> {
    let twin = twin(false)?;
    let mut sources: Vec<_> = (1..=3)
        .map(|camera| {
            view(
                &twin,
                camera,
                vec![
                    projected(camera, u64::from(camera) * 10 + 1, [-2., -2., 10.], [0; 4]),
                    projected(
                        camera,
                        u64::from(camera) * 10 + 2,
                        [2., 1.5, 12.],
                        [u64::MAX; 4],
                    ),
                ],
            )
        })
        .collect::<Test<Vec<_>>>()?;
    let mut unused = view(&twin, 4, Vec::new())?;
    unused.capture = [200, 210];
    sources.push(unused);
    let association = associate_multiview_features(
        &twin,
        &sources,
        AssociationOptions {
            reference_time_ns: 205,
            max_capture_span_ns: 120,
            ..options()
        },
        &mut WorkBudget::new(WORK),
    )?;
    let pin = association
        .components()
        .iter()
        .find(|component| matches!(component.outcome(), ComponentOutcome::Fused(_)))
        .ok_or("missing joint fixture point")?
        .evidence();
    let built = build(
        &twin,
        Reconstruction::Multiview(&association),
        pin,
        [120; 32],
    )?;
    Ok((twin, association, built))
}

fn render(
    name: &str,
    built: &ReconstructedAtlas,
    reconstruction: Reconstruction<'_>,
) -> Test<(Value, Value)> {
    let receipt = checked(receipt(built.receipt(), &mut WorkBudget::new(WORK)))?;
    let geometry = checked(geometry(
        reconstruction,
        REPORT_BYTES,
        &mut WorkBudget::new(WORK),
    ))?;
    // Libtest captures these on normal runs. The exact-source harness retains them
    // as schema-validation fixtures; production rendering remains unmodified.
    println!("FSS_ATLAS_REPORT_FIXTURE|{name}|receipt|{receipt}");
    println!("FSS_ATLAS_REPORT_FIXTURE|{name}|geometry|{geometry}");
    Ok((parse(&receipt)?, parse(&geometry)?))
}

#[test]
fn pair_report_preserves_selected_unselected_occluded_and_refused_candidates_with_unknown_error()
-> Test {
    let (twin, association, built) = pair_fixture()?;
    let (value, geometry) = render("pair_mixed", &built, Reconstruction::Pair(&association))?;
    assert_eq!(field(&value, &["kind"])?.text(), Some("pair"));
    assert_eq!(
        field(&value, &["receipt_digest"])?.text(),
        Some(digest(built.receipt().digest()).as_str())
    );
    assert_eq!(
        field(&value, &["atlas_digest"])?.text(),
        Some(digest(built.atlas().digest()).as_str())
    );
    assert_eq!(
        field(&value, &["twin_digest"])?.text(),
        Some(digest(twin.digest()).as_str())
    );
    assert_eq!(
        field(&value, &["association_evidence"])?.text(),
        Some(digest(association.evidence()).as_str())
    );
    assert_eq!(
        field(&geometry, &["scene_evidence"])?.text(),
        Some(digest(association.evidence()).as_str())
    );
    let candidates = rows(&value, &["candidates"])?;
    assert_eq!(candidates.len(), 4);
    let dispositions = candidates
        .iter()
        .map(|candidate| {
            field(candidate, &["disposition"])?
                .text()
                .ok_or("missing disposition".into())
        })
        .collect::<Test<Vec<_>>>()?;
    assert_eq!(
        dispositions,
        [
            "eligible",
            "eligible",
            "nominal_occlusion_conflict",
            "refused"
        ]
    );
    assert_eq!(
        field(&candidates[0], &["selection", "state"])?.text(),
        Some("selected")
    );
    assert_eq!(
        field(&candidates[0], &["selection", "landmark"])?.text(),
        Some("101")
    );
    for candidate in &candidates[1..] {
        assert_eq!(
            field(candidate, &["selection", "state"])?.text(),
            Some("not_selected")
        );
        assert_eq!(rows(candidate, &["members"])?.len(), 2);
    }
    assert_eq!(rows(&value, &["sources"])?.len(), 2);
    assert_eq!(rows(&value, &["landmarks"])?.len(), 1);
    let landmark = field(&value, &["landmarks", "0"])?;
    assert_eq!(
        field(landmark, &["absolute_error"])?,
        &parse("{\"state\":\"unknown\"}")?
    );
    assert_eq!(
        field(landmark, &["selection", "physical_group"])?.text(),
        Some("1001")
    );
    assert_eq!(
        field(landmark, &["selection", "feature"])?.integer(),
        Some(0)
    );
    assert_eq!(rows(landmark, &["members"])?.len(), 2);
    assert_eq!(rows(landmark, &["residuals"])?.len(), 2);
    for (actual, expected) in rows(landmark, &["position"])?.iter().zip([-2., -2., 10.]) {
        assert!((number(actual)? - expected).abs() < 1e-8);
    }
    for (row, expected) in rows(landmark, &["pixel_noise_covariance"])?
        .iter()
        .zip(built.receipt().landmarks[0].pixel_noise_covariance)
    {
        for (cell, expected) in rows(row, &[])?.iter().zip(expected) {
            assert_eq!(number(cell)?, expected);
        }
    }
    assert!(built.receipt().landmarks[0].pixel_noise_covariance[0][0] > 0.);
    for (key, expected) in [
        ("features", 8),
        ("pairs", 16),
        ("selected", 4),
        ("solved", 3),
        ("refused", 1),
    ] {
        assert_eq!(
            field(&geometry, &["counts", key])?.integer(),
            Some(expected)
        );
    }
    assert_eq!(rows(&geometry, &["pairs"])?.len(), 16);
    assert_eq!(rows(&geometry, &["feature_outcomes"])?.len(), 8);
    assert_eq!(rows(&geometry, &["hypotheses"])?.len(), 4);
    assert_eq!(
        field(
            &geometry,
            &["hypotheses", "2", "estimate", "nominal_occlusion_conflict"]
        )?,
        &Value::Bool(true)
    );
    assert_eq!(
        field(&geometry, &["hypotheses", "3", "estimate", "state"])?.text(),
        Some("refused")
    );
    let changed = build(
        &twin,
        Reconstruction::Pair(&association),
        association.hypotheses()[0].evidence,
        [121; 32],
    )?;
    let changed_json = parse(&checked(receipt(
        changed.receipt(),
        &mut WorkBudget::new(WORK),
    ))?)?;
    assert_ne!(
        field(&value, &["receipt_digest"])?,
        field(&changed_json, &["receipt_digest"])?
    );
    assert_ne!(
        field(&value, &["atlas_digest"])?,
        field(&changed_json, &["atlas_digest"])?
    );
    assert_eq!(
        field(&value, &["landmarks", "0", "position"])?,
        field(&changed_json, &["landmarks", "0", "position"])?
    );
    let assumptions = parse(&assumptions())?;
    assert!(rows(&assumptions, &[])?.iter().any(|value| value.text()
        == Some(
            "absolute_landmark_error_remains_unknown_and_is_not_derived_from_pixel_covariance"
        )));
    Ok(())
}

#[test]
fn multiview_report_keeps_joint_support_full_source_lineage_and_unused_late_views() -> Test {
    let (_, association, built) = multiview_fixture()?;
    let (value, geometry) = render(
        "multiview_unused",
        &built,
        Reconstruction::Multiview(&association),
    )?;
    assert_eq!(field(&value, &["kind"])?.text(), Some("multiview"));
    assert_eq!(
        field(&value, &["requested_scene_time_ns"])?.text(),
        Some("205")
    );
    assert_eq!(
        rows(&value, &["capture_hull_ns"])?,
        &[Value::Text("90".into()), Value::Text("210".into())]
    );
    assert_eq!(
        field(&value, &["landmarks", "0", "solve_time_ns"])?.text(),
        Some("110")
    );
    assert_eq!(
        rows(&value, &["landmarks", "0", "capture_hull_ns"])?,
        &[Value::Text("90".into()), Value::Text("110".into())]
    );
    assert_eq!(rows(&value, &["landmarks", "0", "members"])?.len(), 3);
    assert_eq!(rows(&value, &["landmarks", "0", "residuals"])?.len(), 3);
    assert_eq!(built.atlas().landmarks().len(), 1);
    assert_eq!(built.atlas().bindings().len(), 3);
    assert_eq!(rows(&value, &["candidates"])?.len(), 2);
    assert_eq!(
        field(&value, &["candidates", "1", "selection", "state"])?.text(),
        Some("not_selected")
    );
    let sources = rows(&value, &["sources"])?;
    assert_eq!(sources.len(), 4);
    for ((row, actual), native) in sources
        .iter()
        .zip(&built.receipt().sources)
        .zip(association.views())
    {
        assert_eq!(
            field(row, &["camera"])?.text(),
            Some(actual.camera.to_string().as_str())
        );
        assert_eq!(
            field(row, &["source_record_digest"])?.text(),
            Some(digest(actual.source_record).as_str())
        );
        assert_eq!(
            field(row, &["encoded_source_digest"])?.text(),
            Some(digest(native.source_digest).as_str())
        );
        assert_eq!(
            field(row, &["allowed_mask_digest"])?.text(),
            Some(digest(native.allowed_mask_digest).as_str())
        );
        assert_eq!(
            field(row, &["descriptor_domain_digest"])?.text(),
            Some(digest(native.frame.descriptor_domain()).as_str())
        );
        assert_eq!(
            field(row, &["frame", "exposure_digest"])?.text(),
            Some(digest(native.frame.identity().exposure).as_str())
        );
        assert_eq!(
            field(row, &["frame", "pixel_digest"])?.text(),
            Some(digest(native.frame.identity().pixels).as_str())
        );
        assert_eq!(
            field(row, &["frame", "image_domain_digest"])?.text(),
            Some(digest(native.frame.identity().image_domain).as_str())
        );
        assert_eq!(
            field(row, &["feature_count"])?.integer(),
            Some(native.frame.features().len() as i128)
        );
        assert_eq!(
            field(row, &["included_in_archive"])?,
            &Value::Bool(actual.included)
        );
    }
    assert_eq!(
        field(&sources[3], &["included_in_archive"])?,
        &Value::Bool(false)
    );
    assert_eq!(field(&sources[3], &["feature_count"])?.integer(), Some(0));
    assert_eq!(rows(&geometry, &["camera_pairs"])?.len(), 6);
    assert_eq!(rows(&geometry, &["components"])?.len(), 2);
    for (key, expected) in [
        ("cameras", 4),
        ("camera_pairs", 6),
        ("features", 6),
        ("pair_rows", 12),
        ("components", 2),
        ("solved", 2),
    ] {
        assert_eq!(
            field(&geometry, &["counts", key])?.integer(),
            Some(expected)
        );
    }
    assert_eq!(
        field(&geometry, &["scene_evidence"])?.text(),
        Some(digest(association.evidence()).as_str())
    );
    Ok(())
}

#[test]
fn unresolved_graph_candidates_keep_all_members_and_links_beside_a_valid_selected_landmark() -> Test
{
    let twin = twin(false)?;
    for conflict in [false, true] {
        let mut sources = Vec::new();
        for camera in 1..=3_u8 {
            let mut features = if conflict {
                match camera {
                    1 => vec![
                        feature(11, [100., 64.], [0; 4]),
                        feature(12, [104., 64.], [7, 0, 0, 0]),
                    ],
                    2 => vec![
                        feature(21, [88., 64.], [1, 0, 0, 0]),
                        feature(22, [115., 80.], [u64::MAX; 4]),
                    ],
                    _ => vec![
                        feature(31, [76., 64.], [3, 0, 0, 0]),
                        feature(32, [103., 80.], [u64::MAX; 4]),
                    ],
                }
            } else {
                vec![
                    projected(
                        camera,
                        u64::from(camera) * 10 + 1,
                        [-2., -2., 10.],
                        [[0, 0, 0, 0], [1, 0, 0, 0], [3, 0, 0, 0]][usize::from(camera - 1)],
                    ),
                    projected(
                        camera,
                        u64::from(camera) * 10 + 2,
                        [2., 1.5, 12.],
                        [u64::MAX; 4],
                    ),
                ]
            };
            if !conflict && camera == 3 {
                features.push(feature(39, [140., 95.], [7; 4]));
            }
            sources.push(view(&twin, camera, features)?);
        }
        let association = associate_multiview_features(
            &twin,
            &sources,
            AssociationOptions {
                maximum_hamming_distance: 1,
                ..options()
            },
            &mut WorkBudget::new(WORK),
        )?;
        let selected = association
            .components()
            .iter()
            .find(|component| matches!(component.outcome(), ComponentOutcome::Fused(_)))
            .ok_or("missing valid point beside unresolved graph")?
            .evidence();
        let built = build(
            &twin,
            Reconstruction::Multiview(&association),
            selected,
            [120; 32],
        )?;
        let name = if conflict {
            "multiview_conflict"
        } else {
            "multiview_incomplete"
        };
        let (value, geometry) = render(name, &built, Reconstruction::Multiview(&association))?;
        let candidates = rows(&value, &["candidates"])?;
        assert_eq!(candidates.len(), association.components().len());
        let states = candidates
            .iter()
            .map(|candidate| {
                field(candidate, &["disposition"])?
                    .text()
                    .ok_or("missing disposition".into())
            })
            .collect::<Test<BTreeSet<_>>>()?;
        let expected: BTreeSet<_> = if conflict {
            ["eligible", "camera_conflict"].into_iter().collect()
        } else {
            ["eligible", "incomplete_cycle_support", "unmatched"]
                .into_iter()
                .collect()
        };
        assert_eq!(states, expected);
        for ((candidate, component), native) in candidates
            .iter()
            .zip(rows(&geometry, &["components"])?)
            .zip(association.components())
        {
            assert_eq!(rows(candidate, &["members"])?.len(), native.members().len());
            assert_eq!(rows(component, &["members"])?.len(), native.members().len());
            assert_eq!(rows(component, &["links"])?.len(), native.links().len());
            assert_eq!(
                field(candidate, &["hypothesis"])?.text(),
                Some(digest(native.evidence()).as_str())
            );
            if native.evidence() != selected {
                assert_eq!(
                    field(candidate, &["selection", "state"])?.text(),
                    Some("not_selected")
                );
                assert_ne!(
                    field(component, &["outcome", "state"])?.text(),
                    Some("estimated")
                );
            }
        }
        assert_eq!(rows(&value, &["landmarks"])?.len(), 1);
        assert_eq!(
            field(&geometry, &["outcome"])?.text(),
            Some("reconstructed_with_refusals")
        );
        if conflict {
            assert_eq!(
                field(&value, &["sources", "0", "included_in_archive"])?,
                &Value::Bool(false)
            );
            assert_eq!(
                field(&value, &["sources", "0", "feature_count"])?.integer(),
                Some(2)
            );
            assert_eq!(
                field(&geometry, &["counts", "camera_conflicts"])?.integer(),
                Some(1)
            );
        } else {
            assert_eq!(
                field(&geometry, &["counts", "incomplete_cycles"])?.integer(),
                Some(1)
            );
            assert_eq!(
                field(&geometry, &["counts", "unmatched"])?.integer(),
                Some(1)
            );
            assert_eq!(
                field(&geometry, &["counts", "missing_links"])?.integer(),
                Some(1)
            );
        }
    }
    Ok(())
}

#[test]
fn complete_output_bounds_work_and_initial_or_terminal_cancellation_refuse_without_partial_json()
-> Test {
    let (_, pair, pair_atlas) = pair_fixture()?;
    let (_, multi, multi_atlas) = multiview_fixture()?;
    for (reconstruction, built) in [
        (Reconstruction::Pair(&pair), &pair_atlas),
        (Reconstruction::Multiview(&multi), &multi_atlas),
    ] {
        let mut work = WorkBudget::new(WORK);
        let full = checked(geometry(reconstruction, REPORT_BYTES, &mut work))?;
        let used = work.used();
        assert_eq!(
            checked(geometry(
                reconstruction,
                full.len() + 1,
                &mut WorkBudget::new(used)
            ))?,
            full
        );
        for (bytes, units) in [(full.len(), used), (full.len() + 1, used - 1), (1, WORK)] {
            let failure = geometry(reconstruction, bytes, &mut WorkBudget::new(units))
                .err()
                .ok_or("bounded geometry unexpectedly succeeded")?;
            assert_eq!(failure.code, "ERR-SCENE-FUSION-LIMIT-001");
        }
        let mut work = WorkBudget::new(WORK);
        let full_receipt = checked(receipt(built.receipt(), &mut work))?;
        let used = work.used();
        assert_eq!(
            checked(receipt(built.receipt(), &mut WorkBudget::new(used)))?,
            full_receipt
        );
        let failure = receipt(built.receipt(), &mut WorkBudget::new(used - 1))
            .err()
            .ok_or("underfunded receipt unexpectedly succeeded")?;
        assert_eq!(failure.code, "ERR-SCENE-FUSION-LIMIT-001");
        for render_receipt in [false, true] {
            let calls = AtomicUsize::new(0);
            let never = || {
                calls.fetch_add(1, Ordering::Relaxed);
                false
            };
            let run = |work: &mut WorkBudget<'_>| {
                if render_receipt {
                    receipt(built.receipt(), work)
                } else {
                    geometry(reconstruction, REPORT_BYTES, work)
                }
            };
            checked(run(&mut WorkBudget::with_cancellation_probe(WORK, &never)))?;
            let last = calls.load(Ordering::Relaxed);
            assert!(last >= 2);
            for stop in [0, last - 1] {
                let calls = AtomicUsize::new(0);
                let cancelled = || calls.fetch_add(1, Ordering::Relaxed) >= stop;
                let failure = run(&mut WorkBudget::with_cancellation_probe(WORK, &cancelled))
                    .err()
                    .ok_or("cancelled rendering unexpectedly published JSON")?;
                assert_eq!(failure.code, "ERR-SCENE-FUSION-LIMIT-001");
            }
        }
    }
    Ok(())
}

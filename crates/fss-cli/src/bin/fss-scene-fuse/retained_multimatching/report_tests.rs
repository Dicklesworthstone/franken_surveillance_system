#![forbid(unsafe_code)]
//! Real native graphs and independently projected points exercise the complete JSON renderer.
//! These fixtures establish numerical/report behavior, not retained custody or field accuracy.

use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;
use fss_geometry::triangulation::TriangulationOptions;
use fss_geometry::{GeometryBasis, PinholeIntrinsics, RigidPose, WorkBudget};
use fss_twin::feature_association::{AssociationOptions, FeatureView};
use fss_twin::localization::{BinaryDescriptor, FeatureFrame, ImageFeature, ImageIdentity};
use fss_twin::multiview_feature_association::{
    MultiFeatureAssociation, associate_multiview_features,
};
use fss_twin::{
    ImportExpectation, ImportLimits, ProjectionError, PropertyTwin, TrackingCamera, import_twin,
};

use super::{GeometryReport, compute};

type Test<T = ()> = std::result::Result<T, Box<dyn Error>>;
const WORK: u64 = 300_000_000;
const REPORT_BYTES: usize = 32 * 1024 * 1024;
const POINTS: [[f64; 3]; 2] = [[0.2, 0.3, 10.], [2., 1.5, 12.]];

fn checked<T>(value: crate::Result<T>) -> Test<T> {
    value.map_err(|error| format!("multi-camera report: {error:?}").into())
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
    .ok_or_else(|| format!("missing report field {path:?}"))?;
    field(next, &path[1..])
}
fn rows<'a>(value: &'a Value, path: &[&str]) -> Test<&'a [Value]> {
    field(value, path)?
        .array()
        .ok_or("expected report array".into())
}
fn real(value: &Value) -> Test<f64> {
    match value {
        Value::Number(text) => Ok(text.parse()?),
        _ => Err("expected JSON real number".into()),
    }
}
fn close_position(value: &Value, expected: [f64; 3]) -> Test {
    let actual = rows(value, &["outcome", "position"])?;
    assert_eq!(actual.len(), 3);
    for (actual, expected) in actual.iter().zip(expected) {
        assert!((real(actual)? - expected).abs() < 1e-7);
    }
    Ok(())
}
fn twin() -> Test<PropertyTwin> {
    let package = crate::matching::fixtures::package();
    Ok(import_twin(
        &package,
        ImportExpectation {
            package_sha256: ContentDigest::sha256(&package).bytes(),
            source_scene_sha256: ContentDigest::sha256(b"synthetic native JPEG matching scene")
                .bytes(),
            basis: GeometryBasis::new(7, 2)?,
        },
        ImportLimits::default(),
        &mut WorkBudget::new(WORK),
    )?)
}
fn policy() -> AssociationOptions {
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
fn replace(source: &mut FeatureView, features: Vec<ImageFeature>) -> Test {
    source.frame = FeatureFrame::new(
        source.frame.identity(),
        source.frame.descriptor_domain(),
        features,
        &mut WorkBudget::new(WORK),
    )?;
    Ok(())
}
fn view(twin: &PropertyTwin, camera: u8, center: [f64; 3]) -> Test<FeatureView> {
    let features = POINTS
        .iter()
        .enumerate()
        .map(|(index, position)| {
            // Independent pinhole projection, without production geometry helpers.
            feature(
                u64::from(camera) * 10 + index as u64 + 1,
                [
                    120. * (position[0] - center[0]) / (position[2] - center[2]) + 96.,
                    120. * (position[1] - center[1]) / (position[2] - center[2]) + 64.,
                ],
                if index == 0 { [0; 4] } else { [u64::MAX; 4] },
            )
        })
        .collect();
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
            validity: [0, u64::MAX],
            pose: RigidPose::from_center([[1., 0., 0.], [0., 1., 0.], [0., 0., 1.]], center)?,
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
fn views(twin: &PropertyTwin, count: u8) -> Test<Vec<FeatureView>> {
    (1..=count)
        .map(|camera| view(twin, camera, [f64::from(camera - 1) * 0.25, 0., 0.]))
        .collect()
}
fn horizontal(twin: &PropertyTwin) -> Test<Vec<FeatureView>> {
    (1..=3)
        .map(|camera| view(twin, camera, [f64::from(camera - 1), 0., 0.]))
        .collect()
}
fn analyze(
    twin: &PropertyTwin,
    sources: &[FeatureView],
    options: AssociationOptions,
) -> Test<MultiFeatureAssociation> {
    Ok(associate_multiview_features(
        twin,
        sources,
        options,
        &mut WorkBudget::new(WORK),
    )?)
}
fn render(value: &MultiFeatureAssociation) -> Test<(GeometryReport, Value)> {
    let report = checked(compute(value, REPORT_BYTES, &mut WorkBudget::new(WORK)))?;
    let json = parse(&report.json)?;
    Ok((report, json))
}

#[test]
fn complete_three_and_eight_camera_reports_keep_every_pair_and_joint_view() -> Test {
    let twin = twin()?;
    for cameras in [3, 8] {
        let sources = views(&twin, cameras)?;
        let association = analyze(&twin, &sources, policy())?;
        let (report, json) = render(&association)?;
        assert!(report.reconstructed);
        assert_eq!(field(&json, &["outcome"])?.text(), Some("reconstructed"));
        assert_eq!(
            field(&json, &["scene_evidence"])?.text(),
            Some(super::digest(association.evidence()).trim_matches('"'))
        );
        assert_eq!(
            field(&json, &["counts", "features"])?.integer(),
            Some(i128::from(cameras) * 2)
        );
        let pairs = rows(&json, &["camera_pairs"])?;
        let expected_pairs = usize::from(cameras) * usize::from(cameras - 1) / 2;
        assert_eq!(pairs.len(), expected_pairs);
        assert_eq!(
            field(&json, &["counts", "pair_rows"])?.integer(),
            Some((expected_pairs * 4) as i128)
        );
        assert_eq!(
            field(&json, &["counts", "pair_feature_outcomes"])?.integer(),
            Some((expected_pairs * 4) as i128)
        );
        assert_eq!(
            field(&json, &["counts", "pair_hypotheses"])?.integer(),
            Some((expected_pairs * 2) as i128)
        );
        for (index, pair) in pairs.iter().enumerate() {
            assert_eq!(field(pair, &["index"])?.integer(), Some(index as i128));
            assert_eq!(rows(pair, &["pairs"])?.len(), 4);
            assert_eq!(rows(pair, &["feature_outcomes"])?.len(), 4);
            assert_eq!(rows(pair, &["hypotheses"])?.len(), 2);
            assert_eq!(field(pair, &["counts", "refused"])?.integer(), Some(0));
            let camera_ids = rows(pair, &["cameras"])?;
            assert!(camera_ids[0].integer() < camera_ids[1].integer());
            assert_eq!(
                field(pair, &["requested_scene_time_ns"])?.text(),
                Some("100")
            );
            assert_eq!(field(pair, &["solve_time_ns"])?.text(), Some("100"));
        }
        let components = rows(&json, &["components"])?;
        assert_eq!(components.len(), 2);
        for (component, expected) in components.iter().zip(POINTS) {
            assert_eq!(rows(component, &["members"])?.len(), usize::from(cameras));
            assert_eq!(rows(component, &["links"])?.len(), expected_pairs);
            assert_eq!(
                rows(component, &["outcome", "views"])?.len(),
                usize::from(cameras)
            );
            assert_eq!(
                field(component, &["outcome", "state"])?.text(),
                Some("estimated")
            );
            assert_eq!(
                rows(component, &["outcome", "pixel_noise_covariance"])?.len(),
                3
            );
            close_position(component, expected)?;
        }
        assert_eq!(field(&json, &["counts", "solved"])?.integer(), Some(2));
        assert_eq!(field(&json, &["counts", "unresolved"])?.integer(), Some(0));
        assert!(!report.json.contains("verified_retained"));
        assert!(!report.json.contains("capsule"));
    }
    Ok(())
}

#[test]
fn weak_pair_refusals_stay_visible_when_joint_components_reconstruct() -> Test {
    let twin = twin()?;
    let sources = vec![
        view(&twin, 1, [0., 0., 0.])?,
        view(&twin, 2, [1e-4, 0., 0.])?,
        view(&twin, 3, [1., 0., 0.])?,
    ];
    let association = analyze(&twin, &sources, policy())?;
    let (report, json) = render(&association)?;
    assert!(report.reconstructed);
    assert_eq!(
        field(&json, &["counts", "pair_refused"])?.integer(),
        Some(2)
    );
    assert_eq!(field(&json, &["counts", "refused"])?.integer(), Some(0));
    for hypothesis in rows(&json, &["camera_pairs", "0", "hypotheses"])? {
        assert_eq!(
            field(hypothesis, &["estimate", "state"])?.text(),
            Some("refused")
        );
        assert!(
            field(hypothesis, &["estimate", "reason"])?
                .text()
                .is_some_and(|reason| !reason.is_empty())
        );
    }
    for (component, point) in rows(&json, &["components"])?.iter().zip(POINTS) {
        close_position(component, point)?;
    }
    Ok(())
}

#[test]
fn open_cycle_retains_its_missing_pair_and_all_independent_pair_points() -> Test {
    let twin = twin()?;
    let mut sources = horizontal(&twin)?;
    for (source, descriptor) in sources.iter_mut().zip([0, 1, 3]) {
        let mut features = source.frame.features().to_vec();
        features[0].descriptor = BinaryDescriptor([descriptor, 0, 0, 0]);
        replace(source, features)?;
    }
    let association = analyze(
        &twin,
        &sources,
        AssociationOptions {
            maximum_hamming_distance: 1,
            ..policy()
        },
    )?;
    let (report, json) = render(&association)?;
    assert!(!report.reconstructed);
    assert_eq!(
        field(&json, &["outcome"])?.text(),
        Some("reconstructed_with_refusals")
    );
    let component = field(&json, &["components", "0"])?;
    assert_eq!(
        field(component, &["outcome", "state"])?.text(),
        Some("incomplete_cycle_support")
    );
    assert_eq!(rows(component, &["members"])?.len(), 3);
    assert_eq!(rows(component, &["links"])?.len(), 2);
    let missing = rows(component, &["outcome", "missing_pairs"])?;
    assert_eq!(missing.len(), 1);
    assert_eq!(field(&missing[0], &["pair"])?.integer(), Some(1));
    assert_eq!(field(&missing[0], &["decision"])?.integer(), Some(0));
    assert_eq!(
        field(&json, &["camera_pairs", "1", "pairs", "0", "descriptor"])?.text(),
        Some("too_distant")
    );
    for pair in ["0", "2"] {
        assert_eq!(
            field(
                &json,
                &["camera_pairs", pair, "hypotheses", "0", "estimate", "state"]
            )?
            .text(),
            Some("estimated")
        );
    }
    close_position(field(&json, &["components", "1"])?, POINTS[1])?;
    assert_eq!(
        field(&json, &["counts", "incomplete_cycles"])?.integer(),
        Some(1)
    );
    assert_eq!(
        field(&json, &["counts", "missing_links"])?.integer(),
        Some(1)
    );
    assert_eq!(field(&json, &["counts", "solved"])?.integer(), Some(1));
    Ok(())
}

#[test]
fn conflicting_cycle_keeps_both_same_camera_features_and_every_link() -> Test {
    let twin = twin()?;
    let mut sources = horizontal(&twin)?;
    for (source, features) in sources.iter_mut().zip([
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
        replace(source, features)?;
    }
    let association = analyze(
        &twin,
        &sources,
        AssociationOptions {
            maximum_hamming_distance: 1,
            ..policy()
        },
    )?;
    let (report, json) = render(&association)?;
    assert!(!report.reconstructed);
    let component = field(&json, &["components", "0"])?;
    assert_eq!(
        field(component, &["outcome", "state"])?.text(),
        Some("camera_conflict")
    );
    assert_eq!(
        rows(component, &["outcome", "cameras"])?,
        &[Value::Text("1".into())]
    );
    let members = rows(component, &["members"])?;
    assert_eq!(members.len(), 4);
    assert_eq!(field(&members[0], &["camera"])?.text(), Some("1"));
    assert_eq!(field(&members[1], &["camera"])?.text(), Some("1"));
    assert_eq!(field(&members[0], &["feature"])?.text(), Some("11"));
    assert_eq!(field(&members[1], &["feature"])?.text(), Some("12"));
    assert_eq!(rows(component, &["links"])?.len(), 3);
    assert_eq!(
        field(&json, &["counts", "camera_conflicts"])?.integer(),
        Some(1)
    );
    assert_eq!(field(&json, &["counts", "features"])?.integer(), Some(6));
    assert_eq!(field(&json, &["counts", "pair_rows"])?.integer(), Some(12));
    Ok(())
}

#[test]
fn joint_refusal_remains_explicit_even_when_each_two_view_point_exists() -> Test {
    let twin = twin()?;
    let mut sources = horizontal(&twin)?;
    let mut features = sources[2].frame.features().to_vec();
    features[0].pixel[0] += 3.;
    replace(&mut sources[2], features)?;
    let association = analyze(
        &twin,
        &sources,
        AssociationOptions {
            triangulation: TriangulationOptions {
                max_reprojection_pixels: 0.01,
                ..TriangulationOptions::default()
            },
            ..policy()
        },
    )?;
    let (report, json) = render(&association)?;
    assert!(!report.reconstructed);
    assert_eq!(
        field(&json, &["components", "0", "outcome", "state"])?.text(),
        Some("refused")
    );
    assert!(
        field(&json, &["components", "0", "outcome", "reason"])?
            .text()
            .is_some_and(|reason| !reason.is_empty())
    );
    for pair in rows(&json, &["camera_pairs"])? {
        assert_eq!(
            field(pair, &["hypotheses", "0", "estimate", "state"])?.text(),
            Some("estimated")
        );
    }
    close_position(field(&json, &["components", "1"])?, POINTS[1])?;
    assert_eq!(
        field(&json, &["counts", "pair_refused"])?.integer(),
        Some(0)
    );
    assert_eq!(field(&json, &["counts", "refused"])?.integer(), Some(1));
    assert_eq!(field(&json, &["counts", "unresolved"])?.integer(), Some(1));
    Ok(())
}

#[test]
fn isolated_unmatched_features_do_not_erase_other_joint_points() -> Test {
    let twin = twin()?;
    let mut sources = views(&twin, 3)?;
    let mut features = sources[2].frame.features().to_vec();
    features.push(feature(39, [110., 90.], [u64::MAX, u64::MAX, 0, 0]));
    replace(&mut sources[2], features)?;
    let association = analyze(&twin, &sources, policy())?;
    let (report, json) = render(&association)?;
    assert!(report.reconstructed);
    assert_eq!(field(&json, &["counts", "solved"])?.integer(), Some(2));
    assert_eq!(field(&json, &["counts", "unmatched"])?.integer(), Some(1));
    assert_eq!(field(&json, &["counts", "unresolved"])?.integer(), Some(0));
    assert_eq!(
        field(&json, &["components", "2", "outcome", "state"])?.text(),
        Some("unmatched")
    );
    assert_eq!(
        field(&json, &["components", "2", "members", "0", "feature"])?.text(),
        Some("39")
    );
    Ok(())
}

#[test]
fn ambiguity_and_empty_views_keep_complete_zero_reconstruction_diagnostics() -> Test {
    let twin = twin()?;
    let mut sources = views(&twin, 3)?;
    for source in &mut sources {
        let mut features = source.frame.features().to_vec();
        for feature in &mut features {
            feature.descriptor = BinaryDescriptor([0; 4]);
        }
        replace(source, features)?;
    }
    let (report, json) = render(&analyze(&twin, &sources, policy())?)?;
    assert!(!report.reconstructed);
    assert_eq!(
        field(&json, &["outcome"])?.text(),
        Some("no_reconstruction")
    );
    assert_eq!(field(&json, &["counts", "unmatched"])?.integer(), Some(6));
    assert_eq!(field(&json, &["counts", "pair_rows"])?.integer(), Some(12));
    for pair in rows(&json, &["camera_pairs"])? {
        for row in rows(pair, &["pairs"])? {
            assert_eq!(field(row, &["descriptor"])?.text(), Some("ambiguous"));
        }
        for feature in rows(pair, &["feature_outcomes"])? {
            assert_eq!(rows(feature, &["nearest_features"])?.len(), 2);
        }
    }
    for source in &mut sources {
        replace(source, vec![])?;
    }
    let (report, json) = render(&analyze(&twin, &sources, policy())?)?;
    assert!(!report.reconstructed);
    assert_eq!(field(&json, &["counts", "cameras"])?.integer(), Some(3));
    assert_eq!(rows(&json, &["camera_pairs"])?.len(), 3);
    assert!(rows(&json, &["components"])?.is_empty());
    for pair in rows(&json, &["camera_pairs"])? {
        assert!(rows(pair, &["pairs"])?.is_empty());
        assert!(rows(pair, &["feature_outcomes"])?.is_empty());
        assert!(rows(pair, &["hypotheses"])?.is_empty());
    }
    Ok(())
}

#[test]
fn staggered_subset_times_preserve_full_precision_and_original_scene_request() -> Test {
    let twin = twin()?;
    let mut sources = views(&twin, 3)?;
    let base = u64::MAX - 100;
    for (source, capture) in sources.iter_mut().zip([
        [base, base + 10],
        [base + 20, base + 30],
        [base + 80, u64::MAX],
    ]) {
        source.capture = capture;
    }
    replace(&mut sources[2], vec![])?;
    let requested = u64::MAX - 5;
    let association = analyze(
        &twin,
        &sources,
        AssociationOptions {
            reference_time_ns: requested,
            max_capture_span_ns: 100,
            ..policy()
        },
    )?;
    let (report, json) = render(&association)?;
    assert!(report.reconstructed);
    assert_eq!(
        field(&json, &["requested_scene_time_ns"])?.text(),
        Some(requested.to_string().as_str())
    );
    assert_eq!(
        rows(&json, &["capture_hull_ns"])?,
        &[
            Value::Text(base.to_string()),
            Value::Text(u64::MAX.to_string())
        ]
    );
    for (pair, solve) in
        rows(&json, &["camera_pairs"])?
            .iter()
            .zip([base + 30, requested, requested])
    {
        assert_eq!(
            field(pair, &["requested_scene_time_ns"])?.text(),
            Some(requested.to_string().as_str())
        );
        assert_eq!(
            field(pair, &["solve_time_ns"])?.text(),
            Some(solve.to_string().as_str())
        );
    }
    for component in rows(&json, &["components"])? {
        assert_eq!(
            field(component, &["requested_scene_time_ns"])?.text(),
            Some(requested.to_string().as_str())
        );
        assert_eq!(
            field(component, &["solve_time_ns"])?.text(),
            Some((base + 30).to_string().as_str())
        );
        assert_eq!(
            field(component, &["outcome", "reference_time_ns"])?.text(),
            Some((base + 30).to_string().as_str())
        );
        assert_eq!(rows(component, &["members"])?.len(), 2);
    }
    assert!(
        field(&json, &["subset_time_policy"])?
            .text()
            .is_some_and(|text| text.contains("static_assumption"))
    );
    Ok(())
}

#[test]
fn canonical_source_order_gives_identical_complete_json_and_work() -> Test {
    let twin = twin()?;
    let sources = views(&twin, 4)?;
    let original = analyze(&twin, &sources, policy())?;
    let mut permuted = sources;
    permuted.rotate_left(2);
    for source in &mut permuted {
        let mut features = source.frame.features().to_vec();
        features.reverse();
        replace(source, features)?;
    }
    let reordered = analyze(&twin, &permuted, policy())?;
    let mut a = WorkBudget::new(WORK);
    let mut b = WorkBudget::new(WORK);
    let first = checked(compute(&original, REPORT_BYTES, &mut a))?;
    let second = checked(compute(&reordered, REPORT_BYTES, &mut b))?;
    assert_eq!(first.json, second.json);
    assert_eq!(first.reconstructed, second.reconstructed);
    assert_eq!(a.used(), b.used());
    Ok(())
}

#[test]
fn byte_limits_exact_work_and_early_mid_final_cancellation_never_return_partial_reports() -> Test {
    let twin = twin()?;
    let association = analyze(&twin, &views(&twin, 3)?, policy())?;
    let polls = AtomicUsize::new(0);
    let probe = || {
        polls.fetch_add(1, Ordering::SeqCst);
        false
    };
    let mut work = WorkBudget::with_cancellation_probe(WORK, &probe);
    let complete = checked(compute(&association, REPORT_BYTES, &mut work))?;
    let used = work.used();
    let total_polls = polls.load(Ordering::SeqCst);
    assert!(used > complete.json.len() as u64);
    assert!(total_polls >= association.pairs().len() + association.components().len() + 2);
    let exact = checked(compute(
        &association,
        complete.json.len() + 1,
        &mut WorkBudget::new(used),
    ))?;
    assert_eq!(exact.json, complete.json);
    assert!(compute(&association, REPORT_BYTES, &mut WorkBudget::new(used - 1)).is_err());
    for bytes in [0, 1, complete.json.len()] {
        let mut limited = WorkBudget::new(WORK);
        assert!(compute(&association, bytes, &mut limited).is_err());
        assert_eq!(
            limited.used(),
            used,
            "small byte allowances cannot undercharge serialization"
        );
    }
    for cut in [1, 2, total_polls] {
        let observed = AtomicUsize::new(0);
        let cancel = || observed.fetch_add(1, Ordering::SeqCst) + 1 >= cut;
        let mut work = WorkBudget::with_cancellation_probe(WORK, &cancel);
        assert!(
            compute(&association, REPORT_BYTES, &mut work).is_err(),
            "cancellation boundary {cut}"
        );
        assert_eq!(observed.load(Ordering::SeqCst), cut);
    }
    Ok(())
}

#[test]
fn maximum_eight_camera_inventory_keeps_all_pair_rows_and_all_nearest_ties() -> Test {
    let twin = twin()?;
    let mut sources = views(&twin, 8)?;
    for source in &mut sources {
        let camera = source.camera.camera;
        replace(
            source,
            (0..32)
                .map(|index| {
                    feature(
                        camera * 100 + index + 1,
                        [
                            32. + (index % 8) as f64 * 12.,
                            24. + (index / 8) as f64 * 16.,
                        ],
                        [0; 4],
                    )
                })
                .collect(),
        )?;
    }
    let association = analyze(&twin, &sources, policy())?;
    let mut work = WorkBudget::new(WORK);
    let report = checked(compute(&association, REPORT_BYTES, &mut work))?;
    assert!(!report.reconstructed);
    assert_eq!(report.json.matches("\"hamming_distance\":").count(), 28_672);
    assert_eq!(report.json.matches("\"nearest_features\":").count(), 1792);
    assert_eq!(report.json.matches("\"state\":\"unmatched\"").count(), 256);
    assert!(report.json.contains("\"pair_rows\":28672"));
    assert!(report.json.contains("\"pair_feature_outcomes\":1792"));
    assert!(report.json.contains("\"features\":256"));
    assert!(report.json.len() < REPORT_BYTES);
    assert!(work.used() > report.json.len() as u64);
    let mut tiny = WorkBudget::new(WORK);
    assert!(compute(&association, 1024, &mut tiny).is_err());
    assert_eq!(tiny.used(), work.used());
    Ok(())
}

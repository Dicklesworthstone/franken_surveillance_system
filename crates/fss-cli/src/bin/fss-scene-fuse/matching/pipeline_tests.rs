#![forbid(unsafe_code)]
//! Real native JPEG decode/extraction/matching/report tests with an independent stereo oracle.

use fss_cli::json_input::{Value, parse};
use fss_cli::scene_rig::SceneRig;
use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_twin::feature_association::{FeatureDisposition, FeatureHypothesisOutcome};
use std::sync::atomic::{AtomicUsize, Ordering};

use super::super::fixtures::*;
use super::super::{input, report};
use super::{Analysis, Image, analyze, extract};

fn images(masks: [Option<&[u8]>; 2]) -> [Image<'_>; 2] {
    [
        Image {
            bytes: LEFT,
            mask: masks[0],
        },
        Image {
            bytes: RIGHT,
            mask: masks[1],
        },
    ]
}
fn analyze_text(f: &Fixture, document: &str, masks: [Option<&[u8]>; 2]) -> TestResult<Analysis> {
    let query = f.parse_query(document)?;
    ok(analyze(
        &f.twin,
        &f.rig,
        &query,
        images(masks),
        &|| false,
        &mut WorkBudget::new(WORK),
    ))
}
fn report_text(
    f: &Fixture,
    document: &str,
    masks: [Option<&[u8]>; 2],
) -> TestResult<(Analysis, report::Report)> {
    let query = f.parse_query(document)?;
    let mut work = WorkBudget::new(WORK);
    let analysis = ok(analyze(
        &f.twin,
        &f.rig,
        &query,
        images(masks),
        &|| false,
        &mut work,
    ))?;
    let report = ok(report::compute(
        &f.twin,
        &f.rig,
        &query,
        ContentDigest::sha256(document.as_bytes()),
        &analysis,
        REPORT_BYTES,
        &mut work,
    ))?;
    Ok((analysis, report))
}
fn array_at<'a>(value: &'a Value, path: &[&str]) -> TestResult<&'a [Value]> {
    field(value, path)?
        .array()
        .ok_or_else(|| "expected report array".into())
}
fn number(value: &Value) -> TestResult<f64> {
    let Value::Number(text) = value else {
        return Err("expected report number".into());
    };
    Ok(text.parse()?)
}
fn query_changed(f: &Fixture, path: &[&str], value: Value) -> TestResult<input::Query> {
    let mut query = parse(&f.query_document)?;
    replace(&mut query, path, value)?;
    f.parse_query(&json(&query))
}

#[test]
fn independent_jpegs_parse_decode_extract_and_reconstruct_known_plane() -> TestResult {
    let f = Fixture::new()?;
    assert!(LEFT.len() + RIGHT.len() < 3072);
    assert_eq!(
        digest(LEFT),
        "sha256:84ef1792126cbe6426494cb4b177e5affa9876273040be2e9f70a8a43a54f652"
    );
    assert_eq!(
        digest(RIGHT),
        "sha256:e284cf5d0ad54929798a5393ab115e18352e5dc38d80087dd46b228a5c1c6eb8"
    );
    assert_eq!(f.twin.digest(), ContentDigest::sha256(&f.package).bytes());
    let analysis = analyze_text(&f, &f.query_document, [None, None])?;
    let a = &analysis.association;
    assert!(
        a.hypotheses().len() >= 8,
        "matched JPEG hypotheses: {}",
        a.hypotheses().len()
    );
    assert_eq!(a.views().len(), 2);
    assert_eq!(
        a.pairs().len(),
        a.views()[0].frame.features().len() * a.views()[1].frame.features().len()
    );
    assert_eq!(
        a.features().len(),
        a.views()
            .iter()
            .map(|v| v.frame.features().len())
            .sum::<usize>()
    );
    assert_eq!(a.capture_hull(), [1000, 1100]);
    for (index, diag) in analysis.diagnostics.iter().enumerate() {
        assert_eq!(diag.camera, index as u64 + 1);
        assert_eq!(
            diag.decode.interpretation,
            ComponentInterpretation::Grayscale
        );
        assert_eq!(
            diag.decode.encoded_sha256,
            ContentDigest::sha256([LEFT, RIGHT][index]).bytes()
        );
        assert_eq!(
            diag.decode.luma_sha256,
            a.views()[index].frame.identity().pixels
        );
        assert!(diag.decode.entropy_blocks > 0);
        assert!(diag.selection.tested_centers > 0);
        assert!(diag.selection.omitted > 0);
        assert_eq!(
            diag.selection.selected,
            a.views()[index].frame.features().len()
        );
        assert_eq!(
            diag.selection.selected + diag.selection.omitted,
            diag.selection.local_maxima
        );
        assert_eq!(a.views()[index].camera.error, None);
    }
    for hypothesis in a.hypotheses() {
        let FeatureHypothesisOutcome::Fused(point) = &hypothesis.outcome else {
            return Err("synthetic JPEG match failed native geometry".into());
        };
        let left = a.views()[0]
            .frame
            .features()
            .iter()
            .find(|v| v.id == hypothesis.features[0])
            .ok_or("left matched feature absent")?;
        let right = a.views()[1]
            .frame
            .features()
            .iter()
            .find(|v| v.id == hypothesis.features[1])
            .ok_or("right matched feature absent")?;
        // The rendered source plane has disparity16, fx160, baseline1. These
        // independent formulas do not call any production projection/solver.
        assert_eq!(left.pixel[0] - right.pixel[0], 16.0);
        assert_eq!(left.pixel[1], right.pixel[1]);
        let expected = [
            (left.pixel[0] - 96.0) / 16.0,
            (left.pixel[1] - 64.0) / 16.0,
            10.0,
        ];
        for (actual, expected) in point.estimate().position.into_iter().zip(expected) {
            assert!((actual - expected).abs() < 1e-8);
        }
        assert!(!point.has_nominal_occlusion_conflict());
        assert_eq!(point.twin_digest(), f.twin.digest());
    }
    Ok(())
}

#[test]
fn report_is_deterministic_complete_and_binds_original_input_and_report_bytes() -> TestResult {
    let f = Fixture::new()?;
    let (analysis, first) = report_text(&f, &f.query_document, [None, None])?;
    let (_, repeated) = report_text(&f, &f.query_document, [None, None])?;
    assert!(first.reconstructed);
    assert_eq!(first.json, repeated.json);
    let value = parse(&first.json)?;
    assert_eq!(
        field(&value, &["schema"])?.text(),
        Some("fss.scene_feature_match.v1")
    );
    assert_eq!(
        field(&value, &["report", "outcome"])?.text(),
        Some("reconstructed")
    );
    assert_eq!(
        field(&value, &["report", "query_digest"])?.text(),
        Some(digest(f.query_document.as_bytes()).as_str())
    );
    let body = first
        .json
        .split_once("\"report\":")
        .ok_or("report body not found")?
        .1
        .strip_suffix('}')
        .ok_or("report wrapper incomplete")?;
    assert_eq!(
        field(&value, &["report_digest"])?.text(),
        Some(digest(body.as_bytes()).as_str())
    );
    let pair_rows = array_at(&value, &["report", "pairs"])?;
    assert_eq!(pair_rows.len(), analysis.association.pairs().len());
    assert_eq!(
        array_at(&value, &["report", "feature_outcomes"])?.len(),
        analysis.association.features().len()
    );
    assert_eq!(
        array_at(&value, &["report", "hypotheses"])?.len(),
        analysis.association.hypotheses().len()
    );
    assert_eq!(
        field(&value, &["report", "counts", "pairs"])?.integer(),
        Some(pair_rows.len() as i128)
    );
    assert_eq!(
        field(&value, &["report", "counts", "refused"])?.integer(),
        Some(0)
    );
    for (row, original) in pair_rows.iter().zip(analysis.association.pairs()) {
        assert_eq!(
            field(row, &["hamming_distance"])?.integer(),
            Some(i128::from(original.hamming_distance))
        );
        for (printed, original) in array_at(row, &["features"])?.iter().zip(original.features) {
            assert_eq!(printed.text(), Some(original.to_string().as_str()));
        }
    }
    for (index, view) in array_at(&value, &["report", "views"])?.iter().enumerate() {
        assert_eq!(
            field(view, &["source_digest"])?.text(),
            Some(digest([LEFT, RIGHT][index]).as_str())
        );
        assert_eq!(
            array_at(view, &["features"])?.len(),
            analysis.association.views()[index].frame.features().len()
        );
        assert_eq!(
            field(view, &["calibration_error", "state"])?.text(),
            Some("unknown")
        );
    }
    for h in array_at(&value, &["report", "hypotheses"])? {
        assert!((number(&array_at(h, &["estimate", "position"])?[2])? - 10.0).abs() < 1e-8);
    }
    assert_eq!(
        field(&value, &["report", "assumptions", "source_custody"])?.text(),
        Some("exact_local_jpeg_bytes_not_retained_deployment_custody")
    );
    assert_eq!(
        field(&value, &["report", "assumptions", "correspondence"])?.text(),
        Some("conditional_appearance_and_epipolar_hypotheses_not_physical_identity")
    );
    Ok(())
}

#[test]
fn explicit_masks_produce_no_reconstruction_without_hiding_views_or_unmatched_features()
-> TestResult {
    let f = Fixture::new()?;
    let allowed = vec![1; (WIDTH * HEIGHT) as usize];
    let denied = vec![0; allowed.len()];
    let all_document = query_document(&f.rig_document, [Some(&allowed), Some(&allowed)]);
    let all = analyze_text(&f, &all_document, [Some(&allowed), Some(&allowed)])?;
    assert_eq!(
        all.association.evidence(),
        analyze_text(&f, &f.query_document, [None, None])?
            .association
            .evidence()
    );
    for (masks, expected_features) in [
        ([Some(denied.as_slice()), Some(denied.as_slice())], 0),
        (
            [Some(allowed.as_slice()), Some(denied.as_slice())],
            all.association.views()[0].frame.features().len(),
        ),
    ] {
        let document = query_document(&f.rig_document, masks);
        let (analysis, rendered) = report_text(&f, &document, masks)?;
        assert!(!rendered.reconstructed);
        assert!(analysis.association.hypotheses().is_empty());
        assert!(analysis.association.pairs().is_empty());
        assert_eq!(analysis.association.features().len(), expected_features);
        assert!(
            analysis
                .association
                .features()
                .iter()
                .all(|f| f.disposition == FeatureDisposition::NoCounterpart)
        );
        assert_eq!(analysis.association.views().len(), 2);
        let report = parse(&rendered.json)?;
        assert_eq!(
            field(&report, &["report", "outcome"])?.text(),
            Some("no_reconstruction")
        );
        assert_eq!(array_at(&report, &["report", "views"])?.len(), 2);
        assert_eq!(
            array_at(&report, &["report", "feature_outcomes"])?.len(),
            expected_features
        );
        assert_eq!(
            field(&report, &["report", "counts", "solved"])?.integer(),
            Some(0)
        );
        assert_eq!(analysis.diagnostics[1].selection.selected, 0);
        assert_eq!(analysis.diagnostics[1].selection.tested_centers, 0);
        assert_eq!(
            analysis.association.views()[1].allowed_mask_digest,
            ContentDigest::sha256(&denied).bytes()
        );
    }
    Ok(())
}

#[test]
fn source_corruption_wrong_component_and_explicit_mask_failures_never_yield_analysis() -> TestResult
{
    let f = Fixture::new()?;
    let query = f.parse_query(&f.query_document)?;
    let mut corrupt = LEFT.to_vec();
    corrupt[LEFT.len() - 1] ^= 1;
    let result = analyze(
        &f.twin,
        &f.rig,
        &query,
        [
            Image {
                bytes: &corrupt,
                mask: None,
            },
            Image {
                bytes: RIGHT,
                mask: None,
            },
        ],
        &|| false,
        &mut WorkBudget::new(WORK),
    );
    let error = result.err().ok_or("corrupted source yielded analysis")?;
    assert_eq!(error.code, "ERR-SCENE-FUSION-INPUT-001");
    assert!(error.detail.contains("source digest mismatch"));
    let wrong = query_changed(
        &f,
        &["left", "component_interpretation"],
        Value::Text("ycbcr".into()),
    )?;
    assert!(
        analyze(
            &f.twin,
            &f.rig,
            &wrong,
            images([None, None]),
            &|| false,
            &mut WorkBudget::new(WORK)
        )
        .is_err()
    );
    let allowed = vec![1; (WIDTH * HEIGHT) as usize];
    assert!(
        analyze(
            &f.twin,
            &f.rig,
            &query,
            images([Some(&allowed), None]),
            &|| false,
            &mut WorkBudget::new(WORK)
        )
        .is_err()
    );
    let document = query_document(&f.rig_document, [Some(&allowed), None]);
    let pinned = f.parse_query(&document)?;
    assert!(
        analyze(
            &f.twin,
            &f.rig,
            &pinned,
            images([None, None]),
            &|| false,
            &mut WorkBudget::new(WORK)
        )
        .is_err()
    );
    let mut wrong_mask = allowed.clone();
    wrong_mask[0] = 0;
    let error = analyze(
        &f.twin,
        &f.rig,
        &pinned,
        images([Some(&wrong_mask), None]),
        &|| false,
        &mut WorkBudget::new(WORK),
    )
    .err()
    .ok_or("mask digest mismatch accepted")?;
    assert!(error.detail.contains("mask digest differs"));
    let short = &allowed[..allowed.len() - 1];
    let short_document = query_document(&f.rig_document, [Some(short), None]);
    let short_query = f.parse_query(&short_document)?;
    assert!(
        analyze(
            &f.twin,
            &f.rig,
            &short_query,
            images([Some(short), None]),
            &|| false,
            &mut WorkBudget::new(WORK)
        )
        .is_err()
    );
    let mut nonbinary = allowed;
    nonbinary[0] = 2;
    let document = query_document(&f.rig_document, [Some(&nonbinary), None]);
    let invalid = f.parse_query(&document)?;
    assert!(
        analyze(
            &f.twin,
            &f.rig,
            &invalid,
            images([Some(&nonbinary), None]),
            &|| false,
            &mut WorkBudget::new(WORK)
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn decoded_grid_clock_privacy_and_full_capture_hull_are_checked_on_real_sources() -> TestResult {
    let mut f = Fixture::new()?;
    for (path, value) in [
        (["clock"], Value::Number("12".into())),
        (["privacy_domain"], Value::Number("10".into())),
    ] {
        let query = query_changed(&f, &path, value)?;
        let error = analyze(
            &f.twin,
            &f.rig,
            &query,
            images([None, None]),
            &|| false,
            &mut WorkBudget::new(WORK),
        )
        .err()
        .ok_or("camera namespace mismatch accepted")?;
        assert!(error.detail.contains("privacy or clock differs"));
    }
    let query = query_changed(
        &f,
        &["left", "capture_ns"],
        Value::Array(vec![
            Value::Number("0".into()),
            Value::Number("1100".into()),
        ]),
    )?;
    let error = analyze(
        &f.twin,
        &f.rig,
        &query,
        images([None, None]),
        &|| false,
        &mut WorkBudget::new(WORK),
    )
    .err()
    .ok_or("excessive capture hull accepted")?;
    assert!(error.detail.contains("capture_window"));
    let mut document = parse(&f.rig_document)?;
    replace(
        &mut document,
        &["cameras", "0", "intrinsics", "width"],
        Value::Number("200".into()),
    )?;
    f.rig_document = json(&document);
    f.rig = SceneRig::from_document(&document, &f.twin, &mut WorkBudget::new(WORK))?;
    let query = f.parse_query(&query_document(&f.rig_document, [None, None]))?;
    let error = analyze(
        &f.twin,
        &f.rig,
        &query,
        images([None, None]),
        &|| false,
        &mut WorkBudget::new(WORK),
    )
    .err()
    .ok_or("actual decoded grid mismatch accepted")?;
    assert!(error.detail.contains("decoded image dimensions differ"));
    Ok(())
}

#[test]
fn swapping_declared_source_order_preserves_canonical_native_association_and_diagnostics()
-> TestResult {
    let f = Fixture::new()?;
    let original = analyze_text(&f, &f.query_document, [None, None])?;
    let mut value = parse(&f.query_document)?;
    let left = field(&value, &["left"])?.clone();
    let right = field(&value, &["right"])?.clone();
    replace(&mut value, &["left"], right)?;
    replace(&mut value, &["right"], left)?;
    let query = f.parse_query(&json(&value))?;
    let changed = ok(analyze(
        &f.twin,
        &f.rig,
        &query,
        [
            Image {
                bytes: RIGHT,
                mask: None,
            },
            Image {
                bytes: LEFT,
                mask: None,
            },
        ],
        &|| false,
        &mut WorkBudget::new(WORK),
    ))?;
    assert_eq!(
        original.association.evidence(),
        changed.association.evidence()
    );
    assert_eq!(original.association.pairs(), changed.association.pairs());
    assert_eq!(
        original.association.features(),
        changed.association.features()
    );
    for (a, b) in original.diagnostics.iter().zip(changed.diagnostics) {
        assert_eq!(a.camera, b.camera);
        assert_eq!(a.decode, b.decode);
        assert_eq!(a.selection, b.selection);
    }
    Ok(())
}

#[test]
fn decoders_extraction_geometry_and_output_share_one_cumulative_work_allowance() -> TestResult {
    let f = Fixture::new()?;
    let query = f.parse_query(&f.query_document)?;
    let mut individual = [0_u64; 2];
    for (index, (slot, image)) in individual.iter_mut().zip(images([None, None])).enumerate() {
        let mut work = WorkBudget::new(WORK);
        ok(extract(
            &f.rig,
            &query,
            query.views[index],
            image,
            &|| false,
            &mut work,
        ))?;
        *slot = work.used();
    }
    let mut full = WorkBudget::new(WORK);
    let analysis = ok(analyze(
        &f.twin,
        &f.rig,
        &query,
        images([None, None]),
        &|| false,
        &mut full,
    ))?;
    let used = full.used();
    assert!(individual.iter().all(|used| *used > 0));
    assert!(used > individual[0] + individual[1]);
    // Each image alone fits; the same allowance cannot be reset for camera two.
    for limit in [
        individual[0].max(individual[1]),
        individual[0] + individual[1],
        used - 1,
    ] {
        let mut work = WorkBudget::new(limit);
        assert!(
            analyze(
                &f.twin,
                &f.rig,
                &query,
                images([None, None]),
                &|| false,
                &mut work
            )
            .is_err()
        );
        assert!(work.used() <= limit);
        assert!(work.used() >= individual[0]);
    }
    let before = full.used();
    let rendered = ok(report::compute(
        &f.twin,
        &f.rig,
        &query,
        ContentDigest::sha256(f.query_document.as_bytes()),
        &analysis,
        REPORT_BYTES,
        &mut full,
    ))?;
    assert!(rendered.reconstructed);
    assert!(full.used() > before);
    assert_eq!(full.used() + full.remaining(), WORK);
    Ok(())
}

#[test]
fn owner_deadline_probe_interrupts_first_decode_second_view_and_final_geometry_atomically()
-> TestResult {
    let f = Fixture::new()?;
    let query = f.parse_query(&f.query_document)?;
    let checks = AtomicUsize::new(0);
    let always_live = || {
        checks.fetch_add(1, Ordering::Relaxed);
        false
    };
    let mut work = WorkBudget::with_cancellation_probe(WORK, &always_live);
    ok(extract(
        &f.rig,
        &query,
        query.views[0],
        Image {
            bytes: LEFT,
            mask: None,
        },
        &always_live,
        &mut work,
    ))?;
    let first_checks = checks.load(Ordering::Relaxed);
    checks.store(0, Ordering::Relaxed);
    let mut work = WorkBudget::with_cancellation_probe(WORK, &always_live);
    ok(analyze(
        &f.twin,
        &f.rig,
        &query,
        images([None, None]),
        &always_live,
        &mut work,
    ))?;
    let all_checks = checks.load(Ordering::Relaxed);
    assert!(all_checks > first_checks + 10);
    // This deterministic owner probe models expiration at existing checkpoints,
    // without a timer task, sleep, system-time dependency or synthetic pixels.
    for deadline in [0, 8, first_checks + 8, all_checks - 2] {
        checks.store(0, Ordering::Relaxed);
        let expired = || checks.fetch_add(1, Ordering::Relaxed) >= deadline;
        let mut work = WorkBudget::with_cancellation_probe(WORK, &expired);
        let error = analyze(
            &f.twin,
            &f.rig,
            &query,
            images([None, None]),
            &expired,
            &mut work,
        )
        .err()
        .ok_or("expired operation returned partial analysis")?;
        assert!(error.detail.contains("cancel"), "{error:?}");
    }
    let resumed = analyze_text(&f, &f.query_document, [None, None])?;
    assert!(resumed.association.hypotheses().len() >= 8);
    Ok(())
}

#[test]
fn complete_report_refuses_byte_limit_work_exhaustion_and_late_cancellation() -> TestResult {
    let f = Fixture::new()?;
    let query = f.parse_query(&f.query_document)?;
    let analysis = analyze_text(&f, &f.query_document, [None, None])?;
    for limit in [0, 1, 64] {
        let error = report::compute(
            &f.twin,
            &f.rig,
            &query,
            ContentDigest::sha256(f.query_document.as_bytes()),
            &analysis,
            limit,
            &mut WorkBudget::new(WORK),
        )
        .err()
        .ok_or("truncated report accepted")?;
        assert_eq!(error.code, "ERR-SCENE-FUSION-LIMIT-001");
    }
    assert!(
        report::compute(
            &f.twin,
            &f.rig,
            &query,
            ContentDigest::sha256(f.query_document.as_bytes()),
            &analysis,
            REPORT_BYTES,
            &mut WorkBudget::new(0)
        )
        .is_err()
    );
    let checks = AtomicUsize::new(0);
    let expired = || checks.fetch_add(1, Ordering::Relaxed) > 0;
    let error = report::compute(
        &f.twin,
        &f.rig,
        &query,
        ContentDigest::sha256(f.query_document.as_bytes()),
        &analysis,
        REPORT_BYTES,
        &mut WorkBudget::with_cancellation_probe(WORK, &expired),
    )
    .err()
    .ok_or("cancelled report accepted")?;
    assert!(error.detail.contains("cancel"));
    Ok(())
}

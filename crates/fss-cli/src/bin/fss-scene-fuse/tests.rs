#![forbid(unsafe_code)]

#[path = "fixtures.rs"]
mod fixtures;

use super::*;
use fixtures::*;

fn setup(f: &Fixture) -> Options {
    Options {
        twin: f.twin.clone(),
        rig: f.rig.clone(),
        observations: f.query.clone(),
        report_out: None,
        work: DEFAULT_WORK,
    }
}
fn cli_ok<T>(result: Result<T>) -> TestResult<T> {
    result.map_err(|e| format!("CLI analysis: {e:?}").into())
}
fn evaluate(f: &Fixture) -> TestResult<(bool, Value)> {
    let mut bytes = Vec::new();
    let solved = cli_ok(execute(&setup(f), &mut bytes))?;
    Ok((solved, parse(std::str::from_utf8(&bytes)?)?))
}
fn numeric(value: &Value) -> TestResult<f64> {
    match value {
        Value::Number(s) => Ok(s.parse()?),
        _ => Err("expected number".into()),
    }
}
fn array_at<'a>(value: &'a Value, path: &[&str]) -> TestResult<&'a [Value]> {
    field(value, path)?
        .array()
        .ok_or_else(|| "expected array".into())
}
fn unsigned_at(value: &Value, path: &[&str]) -> TestResult<u64> {
    Ok(u64::try_from(
        field(value, path)?
            .integer()
            .ok_or("expected exact integer")?,
    )?)
}

#[test]
fn same_property_and_reference_time_unifies_all_three_motion_profiles() -> TestResult {
    let f = Fixture::new(false, &["infer_linear", "static", "linear"])?;
    let (solved, value) = evaluate(&f)?;
    assert!(solved);
    assert_eq!(
        field(&value, &["report", "counts", "solved"])?.integer(),
        Some(3)
    );
    for row in array_at(&value, &["report", "hypotheses"])? {
        assert_eq!(field(row, &["knowledge"])?.text(), Some("estimated"));
        for (observed, expected) in array_at(row, &["estimate", "position"])?
            .iter()
            .zip(POSITION)
        {
            assert!((numeric(observed)? - expected).abs() < 1e-8);
        }
        assert_eq!(
            field(row, &["estimate", "reference_time_ns"])?.integer(),
            Some(i128::from(REFERENCE_NS))
        );
    }
    let trajectory = field(&value, &["report", "hypotheses", "0", "estimate"])?;
    for (observed, expected) in array_at(trajectory, &["velocity_per_second"])?
        .iter()
        .zip(VELOCITY)
    {
        assert!((numeric(observed)? - expected).abs() < 1e-8);
    }
    assert_eq!(array_at(trajectory, &["pixel_noise_covariance"])?.len(), 6);
    assert_eq!(array_at(trajectory, &["views"])?.len(), 6);
    assert_eq!(
        field(&value, &["report", "basis", "geometry_basis", "property"])?.integer(),
        Some(7)
    );
    assert_eq!(
        field(&value, &["report", "basis", "scale", "kind"])?.text(),
        Some("relative")
    );
    Ok(())
}

#[test]
fn observations_reordered_yield_identical_complete_hypothesis_results() -> TestResult {
    let f = Fixture::new(false, &["infer_linear", "static"])?;
    let (_, before) = evaluate(&f)?;
    let mut query = f.read_query()?;
    let Value::Object(top) = &mut query else {
        return Err("query must be object".into());
    };
    let Some(Value::Array(hypotheses)) = top.get_mut("hypotheses") else {
        return Err("hypotheses must be array".into());
    };
    for hypothesis in hypotheses.iter_mut() {
        let Value::Object(h) = hypothesis else {
            return Err("hypothesis must be object".into());
        };
        let Some(Value::Array(v)) = h.get_mut("observations") else {
            return Err("observations must be array".into());
        };
        v.reverse();
    }
    hypotheses.reverse();
    f.write_query(&query)?;
    let (_, after) = evaluate(&f)?;
    assert_eq!(
        field(&before, &["report", "hypotheses"])?,
        field(&after, &["report", "hypotheses"])?
    );
    assert_ne!(
        field(&before, &["report", "basis", "observations_digest"])?,
        field(&after, &["report", "basis", "observations_digest"])?
    );
    Ok(())
}

#[test]
fn refusal_preserves_bad_hypothesis_and_all_source_handles_beside_good_solution() -> TestResult {
    let f = Fixture::new(false, &["infer_linear", "static"])?;
    let mut query = f.read_query()?;
    replace(
        &mut query,
        &["hypotheses", "0", "observations", "2", "visible_contact"],
        Value::Bool(false),
    )?;
    f.write_query(&query)?;
    let (all, value) = evaluate(&f)?;
    assert!(!all);
    assert_eq!(
        field(&value, &["report", "counts", "refused"])?.integer(),
        Some(1)
    );
    assert_eq!(
        field(&value, &["report", "hypotheses", "0", "estimate", "reason"])?.text(),
        Some("common_feature_not_visible")
    );
    assert_eq!(
        array_at(&value, &["report", "hypotheses", "0", "observations"])?.len(),
        6
    );
    assert_eq!(
        field(&value, &["report", "hypotheses", "1", "outcome"])?.text(),
        Some("solved")
    );
    Ok(())
}

#[test]
fn capture_uncertainty_does_not_become_exact_midpoint_evidence() -> TestResult {
    let f = Fixture::new(false, &["infer_linear"])?;
    let mut query = f.read_query()?;
    replace(
        &mut query,
        &["hypotheses", "0", "observations", "1", "capture_ns"],
        parse("[1199999000,1200001000]")?,
    )?;
    f.write_query(&query)?;
    let (solved, value) = evaluate(&f)?;
    assert!(!solved);
    assert_eq!(
        field(&value, &["report", "hypotheses", "0", "estimate", "reason"])?.text(),
        Some("inadmissible_capture_window_or_uncertainty")
    );
    assert_eq!(
        field(
            &value,
            &[
                "report",
                "hypotheses",
                "0",
                "observations",
                "2",
                "capture_ns"
            ]
        )?,
        &parse(r#"["1199999000","1200001000"]"#)?
    );
    Ok(())
}

#[test]
fn opaque_mesh_conflict_survives_a_perfect_fit() -> TestResult {
    let f = Fixture::new(true, &["infer_linear", "static"])?;
    let (all, value) = evaluate(&f)?;
    assert!(all);
    for row in array_at(&value, &["report", "hypotheses"])? {
        assert_eq!(field(row, &["knowledge"])?.text(), Some("conflicted"));
        assert_eq!(
            field(row, &["estimate", "nominal_occlusion_conflict"])?.boolean(),
            Some(true)
        );
    }
    Ok(())
}

#[test]
fn budget_exhaustion_preserves_solved_and_refused_hypotheses_with_every_source() -> TestResult {
    let f = Fixture::new(false, &["static", "infer_linear", "static"])?;
    let (all, complete) = evaluate(&f)?;
    assert!(all);
    let complete_rows = array_at(&complete, &["report", "hypotheses"])?;
    let fusion_work = complete_rows
        .iter()
        .map(|row| unsigned_at(row, &["work_units"]))
        .collect::<TestResult<Vec<_>>>()?;
    let import_work = unsigned_at(&complete, &["report", "work", "used"])?
        .checked_sub(fusion_work.iter().sum())
        .ok_or("fusion work exceeds complete work")?;
    assert!(import_work > 0);
    let mut options = setup(&f);
    // Fund admission and the first complete point, then exhaust the shared allowance.
    options.work = import_work + fusion_work[0];
    let mut bytes = Vec::new();
    assert!(!cli_ok(execute(&options, &mut bytes))?);
    let limited = parse(std::str::from_utf8(&bytes)?)?;
    assert_eq!(
        field(&limited, &["report", "outcome"])?.text(),
        Some("complete_with_refusals")
    );
    assert_eq!(unsigned_at(&limited, &["report", "counts", "total"])?, 3);
    assert_eq!(unsigned_at(&limited, &["report", "counts", "solved"])?, 1);
    assert_eq!(unsigned_at(&limited, &["report", "counts", "refused"])?, 2);
    let limited_rows = array_at(&limited, &["report", "hypotheses"])?;
    assert_eq!(limited_rows.len(), complete_rows.len());
    for (index, (row, original)) in limited_rows.iter().zip(complete_rows).enumerate() {
        assert_eq!(field(row, &["id"])?, field(original, &["id"])?);
        assert_eq!(
            field(row, &["observations"])?,
            field(original, &["observations"])?
        );
        if index == 0 {
            assert_eq!(field(row, &["outcome"])?.text(), Some("solved"));
            assert_eq!(field(row, &["knowledge"])?.text(), Some("estimated"));
            assert_eq!(field(row, &["estimate"])?, field(original, &["estimate"])?);
        } else {
            assert_eq!(field(row, &["outcome"])?.text(), Some("refused"));
            assert_eq!(field(row, &["knowledge"])?.text(), Some("unknown"));
            assert_eq!(
                field(row, &["estimate", "state"])?.text(),
                Some("unavailable")
            );
            assert_eq!(
                field(row, &["estimate", "reason"])?.text(),
                Some("work_budget_exhausted")
            );
        }
    }
    Ok(())
}

#[test]
fn near_u64_max_capture_times_and_identities_round_trip_without_changing_motion() -> TestResult {
    let f = Fixture::new(false, &["infer_linear"])?;
    let (all, baseline) = evaluate(&f)?;
    assert!(all);
    let mut rig = parse(&fs::read_to_string(&f.rig)?)?;
    let clock = u64::MAX - 3;
    let privacy = u64::MAX - 4;
    let calibration = u64::MAX - 5;
    let image_domain = u64::MAX - 6;
    for index in 0..3 {
        let index_text = index.to_string();
        for (key, value) in [
            ("camera", u64::MAX - 2 + index),
            ("clock", clock),
            ("privacy_domain", privacy),
            ("calibration", calibration),
            ("image_domain", image_domain),
        ] {
            replace(
                &mut rig,
                &["cameras", &index_text, key],
                Value::Number(value.to_string()),
            )?;
        }
    }
    let rig_bytes = json(&rig);
    fs::write(&f.rig, &rig_bytes)?;
    let mut query = f.read_query()?;
    replace(
        &mut query,
        &["camera_rig_digest"],
        Value::Text(ContentDigest::sha256(rig_bytes.as_bytes()).to_text()),
    )?;
    replace(&mut query, &["clock"], Value::Text(clock.to_string()))?;
    replace(
        &mut query,
        &["privacy_domain"],
        Value::Number(privacy.to_string()),
    )?;
    let shift = u64::MAX - 2_000_000_000;
    let reference = shift + REFERENCE_NS;
    replace(
        &mut query,
        &["reference_time_ns"],
        Value::Text(reference.to_string()),
    )?;
    let original_rows = array_at(&query, &["hypotheses", "0", "observations"])?.to_vec();
    let mut expected = Vec::new();
    for (index, observation) in original_rows.iter().enumerate() {
        let camera = u64::MAX - 3 + unsigned_at(observation, &["camera"])?;
        let capture = shift + unsigned_at(observation, &["capture_ns", "0"])?;
        let exposure = u64::MAX - u64::try_from(index)?;
        expected.push((camera, capture, exposure));
        let index_text = index.to_string();
        for (key, value) in [
            ("camera", camera),
            ("image_domain", image_domain),
            ("track", u64::MAX),
            ("exposure", exposure),
        ] {
            replace(
                &mut query,
                &["hypotheses", "0", "observations", &index_text, key],
                Value::Text(value.to_string()),
            )?;
        }
        // Mixed exact JSON-integer and decimal-string representations share the same time.
        replace(
            &mut query,
            &["hypotheses", "0", "observations", &index_text, "capture_ns"],
            Value::Array(vec![
                Value::Number(capture.to_string()),
                Value::Text(capture.to_string()),
            ]),
        )?;
    }
    f.write_query(&query)?;
    let (all, value) = evaluate(&f)?;
    assert!(all);
    assert_eq!(
        field(&value, &["report", "reference_time_ns"])?.text(),
        Some(reference.to_string().as_str())
    );
    assert_eq!(
        field(&value, &["report", "clock"])?.text(),
        Some(clock.to_string().as_str())
    );
    assert_eq!(
        field(&value, &["report", "privacy_domain"])?.text(),
        Some(privacy.to_string().as_str())
    );
    let estimate = field(&value, &["report", "hypotheses", "0", "estimate"])?;
    assert_eq!(
        field(estimate, &["reference_time_ns"])?.text(),
        Some(reference.to_string().as_str())
    );
    for key in ["position", "velocity_per_second", "pixel_noise_covariance"] {
        assert_eq!(
            field(estimate, &[key])?,
            field(&baseline, &["report", "hypotheses", "0", "estimate", key])?
        );
    }
    expected.sort_unstable();
    let report_rows = array_at(&value, &["report", "hypotheses", "0", "observations"])?;
    let views = array_at(estimate, &["views"])?;
    assert_eq!(report_rows.len(), expected.len());
    assert_eq!(views.len(), expected.len());
    for ((row, view), (camera, capture, exposure)) in report_rows.iter().zip(views).zip(expected) {
        for (key, value) in [
            ("camera", camera),
            ("exposure", exposure),
            ("track", u64::MAX),
            ("calibration", calibration),
            ("image_domain", image_domain),
        ] {
            assert_eq!(field(row, &[key])?.text(), Some(value.to_string().as_str()));
        }
        for endpoint in ["0", "1"] {
            assert_eq!(
                field(row, &["capture_ns", endpoint])?.text(),
                Some(capture.to_string().as_str())
            );
        }
        assert_eq!(
            field(view, &["camera"])?.text(),
            Some(camera.to_string().as_str())
        );
        assert_eq!(
            field(view, &["exposure"])?.text(),
            Some(exposure.to_string().as_str())
        );
        assert_eq!(
            field(view, &["nominal_capture_time_ns"])?.text(),
            Some(capture.to_string().as_str())
        );
    }
    assert_eq!(
        field(estimate, &["capture_hull_ns", "1"])?.text(),
        Some(u64::MAX.to_string().as_str())
    );
    Ok(())
}

#[test]
fn stale_rig_wrong_image_domain_and_duplicate_keys_fail_before_output() -> TestResult {
    let f = Fixture::new(false, &["static"])?;
    let original = f.read_query()?;
    for (path, replacement) in [
        (vec!["camera_rig_digest"], Value::Text(digest("stale rig"))),
        (
            vec!["hypotheses", "0", "observations", "0", "image_domain"],
            Value::Number("2".into()),
        ),
        (vec!["privacy_domain"], Value::Number("10".into())),
        (vec!["clock"], Value::Number("12".into())),
    ] {
        let mut query = original.clone();
        replace(&mut query, &path, replacement)?;
        f.write_query(&query)?;
        let mut output = Vec::new();
        assert!(execute(&setup(&f), &mut output).is_err());
        assert!(output.is_empty());
    }
    assert!(document(br#"{"schema":1,"schema":2}"#).is_err());
    Ok(())
}

#[test]
fn exclusive_report_file_and_cancellation_preserve_existing_inputs() -> TestResult {
    let f = Fixture::new(false, &["static"])?;
    let mut opt = setup(&f);
    opt.report_out = Some(f.report.clone());
    let mut stdout = Vec::new();
    assert!(cli_ok(execute(&opt, &mut stdout))?);
    assert_eq!(stdout, fs::read(&f.report)?);
    assert!(execute(&opt, &mut Vec::new()).is_err());
    assert_eq!(stdout, fs::read(&f.report)?);
    let cx = cli_ok(authority())?;
    cx.set_cancel_at_checkpoint("scene_fusion:before_read");
    let error = match analyze(&setup(&f), &cx) {
        Ok(_) => return Err("cancelled analysis returned a report".into()),
        Err(e) => e,
    };
    assert_eq!(error.code, "ERR-SCENE-FUSION-CANCELLED-001");
    assert!(cx.is_drain_completed());
    Ok(())
}

#[test]
fn malformed_or_duplicate_options_and_excessive_budgets_are_rejected() -> TestResult {
    let parse = |args: &[&str]| options(args.iter().map(OsString::from));
    assert!(cli_ok(parse(&["--help"]))?.is_none());
    for args in [
        vec![],
        vec!["--twin"],
        vec!["--unknown", "x"],
        vec!["--twin", "x", "--twin", "x"],
        vec![
            "--twin",
            "x",
            "--rig",
            "x",
            "--observations",
            "x",
            "--work-units",
            "1000000001",
        ],
    ] {
        assert!(parse(&args).is_err());
    }
    Ok(())
}

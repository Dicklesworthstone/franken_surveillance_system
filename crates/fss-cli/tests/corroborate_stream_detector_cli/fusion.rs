#![forbid(unsafe_code)]
//! Real retained 170-frame camera pairs, native model runs and read-only class advice.
//! Synthetic mirrored images exercise wiring and custody, not detection quality.
use super::*;
use fss_cli::event_fusion::{ClassFusionSpec, EventFusionProfile, SensorCalibration};
use fss_fusion::{FusionPolicy, LlrInterval, ScoreCalibration, Severity};
use std::collections::BTreeSet;

fn pin(report: &Value, key: &str) -> Test<ContentDigest> {
    Ok(ContentDigest::parse(text(report, key)?)?)
}
fn profile(native: &Value) -> Test<EventFusionProfile> {
    let cameras = array(native, "cameras")?;
    let roots = cameras
        .iter()
        .map(|camera| pin(camera, "analysis_root"))
        .collect::<Test<Vec<_>>>()?
        .try_into()
        .map_err(|_| "two camera roots")?;
    let calibrations = cameras
        .iter()
        .map(|camera| -> Test<SensorCalibration> {
            Ok(SensorCalibration {
                sensor: text(camera, "sensor_id")?,
                failure_domains: BTreeSet::new(),
                calibration: ScoreCalibration::from_counts(
                    "two-camera-fixture-only",
                    &[0, 500_000],
                    &[(100, 9_900), (9_900, 100)],
                )?,
            })
        })
        .collect::<Test<Vec<_>>>()?;
    Ok(EventFusionProfile::for_long_corroboration(
        ClassFusionSpec {
            plan_digest: pin(native, "analysis_digest")?,
            cascade_digest: pin(member(native, "detector_cascade")?, "recipe_digest")?,
            coverage_digests: BTreeSet::new(),
            class_index: 0,
            prior: LlrInterval::point(-500)?,
            policy: FusionPolicy {
                generation: "policy:two-camera-fixture".into(),
                alert_threshold: 1000,
                retain_threshold: -500,
                reject_threshold: -1500,
                min_independent_support: 2,
                urgent_single_domain_threshold: None,
                max_wait_ns: 10,
                look_penalty_per_doubling: 301,
                operator_confirmation_available: true,
            },
            severity: Severity {
                expected_harm: 1000,
                false_alert_cost: 10,
                delay_cost_per_second: 0,
                reversible: false,
            },
            looks: 1,
            now_ns: 10,
            calibrations,
        },
        roots,
    )?)
}
fn with_profile(
    f: &Fixture,
    args: &[OsString],
    profile: &EventFusionProfile,
    suffix: &str,
) -> Test<Vec<OsString>> {
    let path = f.directory.0.join(format!("fusion-{suffix}.json"));
    let json = profile.to_json()?;
    fs::write(&path, &json)?;
    let mut args = args.to_vec();
    args.extend([
        "--fusion-profile".into(),
        path.into_os_string(),
        "--fusion-digest".into(),
        ContentDigest::sha256(json.as_bytes()).to_text().into(),
    ]);
    Ok(args)
}
// Exercise the newly exposed authoring command before native consumption, not just a
// hand-built profile. The library-built request remains an independent semantic oracle.
fn with_authored_profile(
    f: &Fixture,
    args: &[OsString],
    request: &EventFusionProfile,
) -> Test<Vec<OsString>> {
    use fss_cli::agent_json::{object, string};
    use std::io::Write;
    use std::process::Stdio;

    let bindings = request.spec().calibrations.iter().map(|binding| {
        object(&[
            ("sensor", string(&binding.sensor)),
            ("failure_domains", "[]".into()),
            ("calibration", object(&[
                ("schema", string("fss.score_calibration_counts.v1")),
                ("generation", string("two-camera-fixture-only")),
                ("bins", "[{\"lo_ppm\":0,\"true_positives\":100,\"false_positives\":9900},{\"lo_ppm\":500000,\"true_positives\":9900,\"false_positives\":100}]".into()),
            ])),
        ])
    }).collect::<Vec<_>>();
    let counts = format!(
        r#"{{
      "schema":"fss.event_class_fusion_counts.v1",
      "class_index":0,"prior":[-500,-500],"looks":1,"now_ns":10,
      "policy":{{"generation":"policy:two-camera-fixture","alert_threshold":1000,
        "retain_threshold":-500,"reject_threshold":-1500,"min_independent_support":2,
        "urgent_single_domain_threshold":null,"max_wait_ns":10,
        "look_penalty_per_doubling":301,"operator_confirmation_available":true}},
      "severity":{{"expected_harm":1000,"false_alert_cost":10,
        "delay_cost_per_second":0,"reversible":false}},
      "calibrations":[{}]
    }}"#,
        bindings.join(",")
    );
    let roots = request
        .long_corroboration_analysis_roots()
        .ok_or("paired roots")?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_fss-fusion-profile"))
        .args([
            "--scope",
            "corroborate",
            "--counts-digest",
            &ContentDigest::sha256(counts.as_bytes()).to_text(),
            "--analysis-digest",
            &request.spec().plan_digest.to_text(),
            "--detector-recipe-digest",
            &request.spec().cascade_digest.to_text(),
            "--analysis-roots",
            &format!("{},{}", roots[0], roots[1]),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut input = child.stdin.take().ok_or("authoring stdin")?;
    input.write_all(counts.as_bytes())?;
    drop(input);
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, (request.to_json()? + "\n").as_bytes());
    let file_digest = ContentDigest::sha256(&output.stdout);
    let generated = EventFusionProfile::from_json(&output.stdout, file_digest)?;
    assert_eq!(generated.digest(), request.digest());
    let path = f.directory.0.join("authored paired profile.json");
    fs::write(&path, &output.stdout)?;
    let mut args = args.to_vec();
    args.extend([
        "--fusion-profile".into(),
        path.into_os_string(),
        "--fusion-digest".into(),
        file_digest.to_text().into(),
    ]);
    Ok(args)
}
fn advice(report: &Value) -> Test<&Value> {
    member(report, "calibrated_class_advice")
}
fn read_only(advice: &Value) -> Test {
    assert_eq!(text(advice, "schema")?, "fss.event_class_fusion_report.v3");
    for key in [
        "class_absence_certified",
        "event_policy_changed",
        "published",
        "effect_authority",
        "coverage_witness_supplied",
    ] {
        assert_eq!(member(advice, key)?, &Value::Bool(false), "{key}");
    }
    assert!(array(advice, "coverage_digests")?.is_empty());
    assert_eq!(array(advice, "long_corroboration_analysis_roots")?.len(), 2);
    assert_eq!(
        text(
            member(member(advice, "profile_query_template")?, "coverage")?,
            "state"
        )?,
        "gap"
    );
    Ok(())
}
fn unchanged_native(native: &Value, fused: &Value) -> Test {
    let mut fields = fused.object().ok_or("fused object")?.clone();
    assert!(fields.remove("calibrated_class_advice").is_some());
    assert_eq!(
        &Value::Object(fields),
        native,
        "fusion changed native observations, work accounting, proposals or rerun commands"
    );
    Ok(())
}

#[test]
fn fusion_of_both_complete_late_tracks_preserves_native_work_and_authority() -> Test {
    let f = Fixture::mjpeg("fusion-late", true)?;
    let before = f.snapshot()?;
    let native = good(run(&f.detected(2))?)?;
    let request = profile(&native)?;
    let args = with_authored_profile(&f, &f.detected(2), &request)?;
    let fused = good(run(&args)?)?;
    unchanged_native(&native, &fused)?;
    let derived = advice(&fused)?;
    read_only(derived)?;
    assert_eq!(text(derived, "profile_digest")?, request.digest().to_text());
    assert_eq!(
        text(derived, "analysis_digest")?,
        text(&native, "analysis_digest")?
    );
    for camera in array(&fused, "cameras")? {
        assert_eq!(count(camera, "frames_decoded")?, FRAMES as i128);
    }
    for entry in array(&fused, "entries")? {
        assert!(count(entry, "entry_position")? >= APPEARANCE as i128);
    }
    let pair = candidate(&fused)?;
    let fused_pair = candidate(derived)?;
    assert_eq!(
        text(fused_pair, "native_proposal")?,
        text(pair, "proposal_digest")?
    );
    assert_eq!(
        text(fused_pair, "native_provenance_root")?,
        text(pair, "provenance_root")?
    );
    assert_eq!(array(fused_pair, "scores")?.len(), 2);
    assert_eq!(f.snapshot()?, before);
    let repeated = good(run(&args)?)?;
    assert_eq!(&repeated, &fused);
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn complete_empty_camera_scans_stay_empty_without_class_absence() -> Test {
    let f = Fixture::mjpeg("fusion-empty", false)?;
    let before = f.snapshot()?;
    let native = good(run(&f.detected(2))?)?;
    assert!(array(&native, "candidates")?.is_empty());
    let args = with_profile(&f, &f.detected(2), &profile(&native)?, "empty")?;
    let fused = good(run(&args)?)?;
    unchanged_native(&native, &fused)?;
    read_only(advice(&fused)?)?;
    assert!(array(advice(&fused)?, "candidates")?.is_empty());
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn inference_budget_shortfall_keeps_the_other_camera_explicit() -> Test {
    let f = Fixture::mjpeg("fusion-budget", true)?;
    let before = f.snapshot()?;
    let args = f.detected(1);
    let native = good(run(&args)?)?;
    let args = with_profile(&f, &args, &profile(&native)?, "budget")?;
    let fused = good(run(&args)?)?;
    unchanged_native(&native, &fused)?;
    let cascade = member(&fused, "detector_cascade")?;
    assert_eq!(count(cascade, "inferences_completed")?, 1);
    let pair = candidate(advice(&fused)?)?;
    let scores = array(pair, "scores")?;
    assert_eq!(scores.len(), 2, "second-camera shortfall was dropped");
    assert!(
        scores
            .iter()
            .any(|score| member(score, "score_f32_bits").ok() == Some(&Value::Null))
    );
    assert!(!array(member(pair, "outcome")?, "excluded")?.is_empty());
    assert_ne!(
        text(member(member(pair, "outcome")?, "decision")?, "kind")?,
        "reject"
    );
    read_only(advice(&fused)?)?;
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn swapped_roots_foreign_scope_and_single_camera_profiles_refuse_without_output() -> Test {
    let f = Fixture::mjpeg("fusion-scope", true)?;
    let native = good(run(&f.detected(2))?)?;
    let base = profile(&native)?;
    let before = f.snapshot()?;
    for change in 0..6 {
        let mut spec = base.spec().clone();
        let mut roots = base
            .long_corroboration_analysis_roots()
            .ok_or("two roots")?;
        match change {
            0 => roots.swap(0, 1),
            1 => roots[1] = ContentDigest::sha256(b"another source analysis"),
            2 => spec.plan_digest = pin(&native, "plan_digest")?,
            3 => spec.cascade_digest = ContentDigest::sha256(b"other recipe"),
            4 => spec.calibrations[0].sensor = "sensor:foreign".into(),
            _ => {}
        }
        let request = if change == 5 {
            EventFusionProfile::for_long_watch(spec, roots[0])?
        } else {
            EventFusionProfile::for_long_corroboration(spec, roots)?
        };
        let mut args = with_profile(&f, &f.detected(2), &request, &format!("scope-{change}"))?;
        let export = f.directory.0.join(format!("refused-{change}.json"));
        args.extend(["--report-out".into(), export.clone().into_os_string()]);
        refuses(run(&args)?, "ERR-EVENT-FUSION-SCOPE-001");
        assert!(!export.exists());
        assert_eq!(f.snapshot()?, before);
    }
    Ok(())
}

#[test]
fn paired_advice_cannot_publish_or_retain_even_when_the_model_has_disappeared() -> Test {
    let f = Fixture::mjpeg("fusion-authority", true)?;
    let native = good(run(&f.detected(2))?)?;
    let args = with_profile(&f, &f.detected(2), &profile(&native)?, "authority")?;
    let before = f.snapshot()?;
    fs::remove_file(&f.package)?;
    for flag in ["--approve", "--retain-coverage", "--retain-health"] {
        let mut forbidden = args.clone();
        forbidden.extend([
            flag.into(),
            text(candidate(&native)?, "proposal_digest")?.into(),
        ]);
        refuses(run(&forbidden)?, "calibrated fusion is read-only");
        assert_eq!(f.snapshot()?, before);
    }
    Ok(())
}

#[test]
fn corrupt_profile_is_refused_before_package_loading_or_partial_export() -> Test {
    let f = Fixture::mjpeg("fusion-bytes", false)?;
    let native = good(run(&f.detected(2))?)?;
    let mut args = with_profile(&f, &f.detected(2), &profile(&native)?, "bytes")?;
    let path = f.directory.0.join("fusion-bytes.json");
    let mut bytes = fs::read(&path)?;
    bytes.push(b' ');
    fs::write(path, bytes)?;
    fs::remove_file(&f.package)?;
    let before = f.snapshot()?;
    let export = f.directory.0.join("must-not-exist.json");
    args.extend(["--report-out".into(), export.clone().into_os_string()]);
    refuses(run(&args)?, "ERR-EVENT-FUSION-PROFILE-001");
    assert!(!export.exists());
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#![forbid(unsafe_code)]
//! Completed checkpoints provide native, read-only class advice through real cold processes.

use super::*;

fn checkpoint(args: &[OsString], step: &str) -> Test<Value> {
    let mut args = args.to_vec();
    args.extend(["--dwell-step-frames".into(), step.into()]);
    Ok(parse(&good(run(&args)?)?)?)
}

fn resumed(args: &[OsString], saved: &Value, maximum: &str) -> Test<Vec<OsString>> {
    let mut args = args.to_vec();
    args.extend([
        "--dwell-step-frames".into(),
        "300".into(),
        "--dwell-checkpoint".into(),
        text(saved, "checkpoint_digest")?.into(),
        "--dwell-checkpoint-root".into(),
        text(saved, "checkpoint_root")?.into(),
        "--dwell-restore-max-frames".into(),
        maximum.into(),
    ]);
    Ok(args)
}

// The generated POSIX command contains its own quoting; appended profile/output arguments
// are passed as positional values so paths with spaces remain exact.
fn emitted(command: &str, extra: &[OsString]) -> Test<Output> {
    let arguments = command
        .strip_prefix("fss-event ")
        .ok_or("unexpected continuation executable")?;
    Ok(Command::new("sh")
        .arg("-c")
        .arg(format!(
            "program=$1; shift; exec \"$program\" {arguments} \"$@\""
        ))
        .arg("fss-completed-checkpoint-fusion-test")
        .arg(env!("CARGO_BIN_EXE_fss-event"))
        .args(extra)
        .output()?)
}

// One-shot and checkpoint commands intentionally have different publication/retention hints.
// Compare everything else, including exact diagnostic custody, current authority and advice.
fn without_publish_hints(value: &Value) -> Test<Value> {
    let mut value = value.clone();
    let Value::Object(fields) = &mut value else {
        return Err("native report object".into());
    };
    let Some(Value::Array(candidates)) = fields.get_mut("candidates") else {
        return Err("native episode inventory".into());
    };
    for candidate in candidates {
        let Value::Object(fields) = candidate else {
            return Err("native episode object".into());
        };
        fields.remove("publish_command");
    }
    if let Some(Value::Object(health)) = fields.get_mut("historical_health") {
        health.remove("retain_command");
    }
    Ok(value)
}

#[test]
fn complete_checkpoint_advice_matches_same_basis_native_fusion_without_writes() -> Test {
    let f = Fixture::new("checkpoint-fusion-complete", true, true)?;
    let args = trained(&f)?;
    let saved = checkpoint(&args, "300")?;
    let saved_report = member(&saved, "event_report")?;
    let calibration = profile(saved_report)?;
    let before = f.snapshot()?;

    // Execute the one-shot oracle after checkpoint retention so both native reports and
    // fusion contexts bind exactly the same authority basis, without stripping anchor fields.
    let whole_args = with_profile(&f, &args, &calibration, "whole-at-current-basis")?;
    let whole = parse(&good(run(&whole_args)?)?)?;
    assert_eq!(f.snapshot()?, before);

    let extras = with_profile(&f, &[], &calibration, "completed-checkpoint-profile")?;
    let output_path = f.directory.0.join("completed checkpoint advice.json");
    let mut exported = extras.clone();
    exported.extend(["--report-out".into(), output_path.clone().into_os_string()]);
    let command = text(&saved, "continuation_command")?;
    let output = good(emitted(command, &exported)?)?;
    assert_eq!(fs::read_to_string(&output_path)?, output);
    assert!(output.len() <= fss_cli::event_fusion::MAX_REPORT_BYTES);
    let fused = parse(&output)?;
    assert_eq!(text(&fused, "schema")?, "fss.incremental_dwell_progress.v1");
    assert_eq!(text(&fused, "status")?, "complete");
    assert_eq!(text(&fused, "detector_stage")?, "complete");
    assert_eq!(integer(&fused, "new_source_positions")?, 0);
    assert_eq!(integer(&fused, "remaining_segments")?, 0);
    for key in ["checkpoint_digest", "checkpoint_root", "logical_scan_work"] {
        assert_eq!(member(&fused, key)?, member(&saved, key)?, "changed {key}");
    }
    assert_eq!(
        member(&fused, "cold_restoration_work")?,
        member(&saved, "logical_scan_work")?
    );
    assert_eq!(
        integer(member(&fused, "cold_restoration_work")?, "source_positions")?,
        300
    );
    let native = member(&fused, "event_report")?;
    assert_eq!(
        without_publish_hints(native)?,
        without_publish_hints(&whole)?
    );
    assert_eq!(
        member(native, "candidates")?,
        member(saved_report, "candidates")?
    );
    let advice = member(native, "calibrated_class_advice")?;
    read_only(advice)?;
    assert_eq!(
        member(advice, "continuous_occupancy_certified")?.boolean(),
        Some(false)
    );
    assert_eq!(member(&whole, "calibrated_class_advice")?, advice);
    assert!(!text(&fused, "continuation_command")?.contains("--fusion-"));
    for candidate in items(native, "candidates")? {
        let publish = text(candidate, "publish_command")?;
        assert!(!publish.contains("--fusion-"));
        assert!(publish.contains("--dwell-checkpoint"));
    }
    assert_eq!(f.snapshot()?, before);

    let repeated = parse(&good(emitted(command, &extras)?)?)?;
    assert_eq!(repeated, fused);
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn screened_checkpoint_advice_preserves_native_health_and_cold_work_without_writes() -> Test {
    let f = Fixture::with_changing_background("checkpoint-fusion-screened", true, true, true)?;
    let mut args = trained(&f)?;
    args.extend(["--sensor-health".into(), "conservative-v1".into()]);
    let saved = checkpoint(&args, "300")?;
    let saved_report = member(&saved, "event_report")?;
    let health = member(saved_report, "sensor_health")?;
    assert_eq!(member(health, "complete")?.boolean(), Some(true));
    assert_eq!(
        member(health, "publication_blocked")?.boolean(),
        Some(false)
    );
    assert_eq!(integer(saved_report, "candidate_count")?, 1);
    let calibration = profile(saved_report)?;
    let before = f.snapshot()?;

    // The one-shot oracle runs at the same authority anchor as the cold checkpoint.
    let whole_args = with_profile(&f, &args, &calibration, "screened-whole-profile")?;
    let whole = parse(&good(run(&whole_args)?)?)?;
    let extra = with_profile(&f, &[], &calibration, "screened-checkpoint-profile")?;
    let command = text(&saved, "continuation_command")?;
    assert!(command.contains("--sensor-health conservative-v1"));
    let output_path = f.directory.0.join("screened checkpoint advice.json");
    let mut exported = extra.clone();
    exported.extend(["--report-out".into(), output_path.clone().into_os_string()]);
    let output = good(emitted(command, &exported)?)?;
    assert_eq!(fs::read_to_string(&output_path)?, output);
    let fused = parse(&output)?;
    assert_eq!(text(&fused, "sensor_health_stage")?, "complete");
    assert_eq!(integer(&fused, "new_source_positions")?, 0);
    for key in [
        "checkpoint_digest",
        "checkpoint_root",
        "logical_scan_work",
        "sensor_health_policy",
        "sensor_health_policy_digest",
        "logical_health_scan_work",
    ] {
        assert_eq!(member(&fused, key)?, member(&saved, key)?, "changed {key}");
    }
    let cold_health = member(&fused, "cold_health_restoration_work")?;
    assert_eq!(cold_health, member(&saved, "logical_health_scan_work")?);
    assert_eq!(integer(cold_health, "frames_screened")?, 300);
    assert_eq!(integer(cold_health, "samples_screened")?, 300 * 48 * 32);
    let native = member(&fused, "event_report")?;
    assert_eq!(member(native, "sensor_health")?, health);
    assert_eq!(
        without_publish_hints(native)?,
        without_publish_hints(&whole)?
    );
    read_only(member(native, "calibrated_class_advice")?)?;
    assert_eq!(f.snapshot()?, before);
    assert_eq!(parse(&good(emitted(command, &extra)?)?)?, fused);
    assert_eq!(f.snapshot()?, before);

    // The saved health requirement cannot be stripped to avoid its completed-screen fence.
    let mut without_screen = resumed(&args, &saved, "300")?;
    let at = without_screen
        .iter()
        .position(|arg| arg == "--sensor-health")
        .ok_or("missing health option")?;
    without_screen.drain(at..at + 2);
    let refused = with_profile(&f, &without_screen, &calibration, "screened-mode-change")?;
    refuses(
        run(&refused)?,
        "checkpoint source, dwell rule, privacy or resource recipe changed",
    );
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn frozen_completed_checkpoint_cannot_gain_advice_through_terminal_classification() -> Test {
    let f = Fixture::new("checkpoint-fusion-health-refusal", true, true)?;
    let mut screened = f.args();
    screened.extend(["--sensor-health".into(), "conservative-v1".into()]);
    // Retain the complete diagnostic even when health prevents the terminal classifier.
    let saved = checkpoint(&screened, "300")?;
    assert_eq!(
        member(
            member(member(&saved, "event_report")?, "sensor_health")?,
            "publication_blocked"
        )?
        .boolean(),
        Some(true)
    );
    let mut args = trained(&f)?;
    let unscreened = parse(&good(run(&args)?)?)?;
    let calibration = profile(&unscreened)?;
    args.extend(["--sensor-health".into(), "conservative-v1".into()]);
    let attempted = with_profile(
        &f,
        &resumed(&args, &saved, "300")?,
        &calibration,
        "blocked-screen-profile",
    )?;
    let before = f.snapshot()?;
    // Health blocks the native classifier before the incompatible unscreened profile can
    // be considered. There is no successful JSON prefix, new checkpoint or authority write.
    refuses(
        run(&attempted)?,
        "sensor-health findings or incomplete screening block long-dwell publication",
    );
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn partial_checkpoint_cannot_be_completed_inside_read_only_fusion() -> Test {
    let f = Fixture::new("checkpoint-fusion-partial", true, true)?;
    let args = trained(&f)?;
    let whole = parse(&good(run(&args)?)?)?;
    let calibration = profile(&whole)?;
    let partial = checkpoint(&args, "128")?;
    assert_eq!(text(&partial, "status")?, "checkpointed");
    let before = f.snapshot()?;
    let model_position = args
        .iter()
        .position(|arg| arg == "--detector-package")
        .ok_or("detector path option")?;
    fs::remove_file(PathBuf::from(&args[model_position + 1]))?;
    let mut attempted = with_profile(
        &f,
        &resumed(&args, &partial, "128")?,
        &calibration,
        "partial-checkpoint-profile",
    )?;
    let output_path = f.directory.0.join("must-not-create-partial-advice.json");
    attempted.extend(["--report-out".into(), output_path.clone().into_os_string()]);
    // The admitted step can finish all remaining positions, but the retained prefix cannot
    // produce advice. Its refusal must precede the deliberately missing model and new work.
    refuses(
        run(&attempted)?,
        "calibrated incremental dwell requires an already complete checkpoint",
    );
    assert!(!output_path.exists());
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn empty_completed_checkpoint_still_checks_profile_source_recipe_and_output_admission() -> Test {
    let f = Fixture::new("checkpoint-fusion-empty", true, false)?;
    let args = trained(&f)?;
    let saved = checkpoint(&args, "300")?;
    let native = member(&saved, "event_report")?;
    let calibration = profile(native)?;
    let resume = resumed(&args, &saved, "300")?;
    let before = f.snapshot()?;
    let valid = with_profile(&f, &resume, &calibration, "empty-checkpoint-profile")?;
    let complete = parse(&good(run(&valid)?)?)?;
    let report = member(&complete, "event_report")?;
    let advice = member(report, "calibrated_class_advice")?;
    read_only(advice)?;
    assert!(items(report, "candidates")?.is_empty());
    assert!(items(advice, "candidates")?.is_empty());
    assert_eq!(member(report, "model_invoked")?.boolean(), Some(false));
    assert_eq!(
        integer(
            member(report, "detector_cascade")?,
            "inference_pipeline_attempts"
        )?,
        0
    );
    assert_eq!(f.snapshot()?, before);

    // File digest and temporal scope must be checked before a deliberately invalid source
    // or absent detector. Empty episode inventories do not relax these bindings.
    let wrong = ContentDigest::sha256(b"not the bound checkpoint analysis");
    let mut unopened = resume.clone();
    set(&mut unopened, "--import-id", &wrong.to_text())?;
    set(
        &mut unopened,
        "--detector-package",
        "/nonexistent/completed-checkpoint-model",
    )?;
    let mut digest_refusal = with_profile(&f, &unopened, &calibration, "wrong-profile-digest")?;
    set(&mut digest_refusal, "--fusion-digest", &wrong.to_text())?;
    refuses(run(&digest_refusal)?, "ERR-EVENT-FUSION-PROFILE-001");
    let wrong_scope = EventFusionProfile::for_long_watch(
        calibration.spec().clone(),
        pin(native, "analysis_root")?,
    )?;
    let scoped = with_profile(&f, &unopened, &wrong_scope, "wrong-profile-scope")?;
    refuses(run(&scoped)?, "ERR-EVENT-FUSION-SCOPE-001");

    let mut wrong_analysis = calibration.spec().clone();
    wrong_analysis.plan_digest = wrong;
    let mut wrong_recipe = calibration.spec().clone();
    wrong_recipe.cascade_digest = wrong;
    let mut wrong_sensor = calibration.spec().clone();
    wrong_sensor.calibrations[0].sensor = "sensor:foreign-checkpoint".into();
    for (index, spec, root) in [
        (0, wrong_analysis, pin(native, "analysis_root")?),
        (1, wrong_recipe, pin(native, "analysis_root")?),
        (2, wrong_sensor, pin(native, "analysis_root")?),
        (3, calibration.spec().clone(), wrong),
    ] {
        let profile = EventFusionProfile::for_long_dwell(spec, root)?;
        let changed = with_profile(&f, &resume, &profile, &format!("wrong-empty-pin-{index}"))?;
        refuses(run(&changed)?, "ERR-EVENT-FUSION-SCOPE-001");
        assert_eq!(f.snapshot()?, before);
    }

    let mut under_admitted = valid.clone();
    set(&mut under_admitted, "--dwell-restore-max-frames", "299")?;
    refuses(run(&under_admitted)?, "ERR-WATCH-LIMIT-001");
    let mut changed_rule = valid.clone();
    set(&mut changed_rule, "--dwell-for-ns", "20100000000")?;
    refuses(
        run(&changed_rule)?,
        "checkpoint source, dwell rule, privacy or resource recipe changed",
    );
    let output_path = f.directory.0.join("existing advice.json");
    fs::write(&output_path, b"keep the existing output")?;
    let mut output_refusal = valid;
    output_refusal.extend(["--report-out".into(), output_path.clone().into_os_string()]);
    let refused = run(&output_refusal)?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert_eq!(fs::read(&output_path)?, b"keep the existing output");
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn completed_checkpoint_fusion_needs_pins_and_cannot_grant_authority_before_io() -> Test {
    let directory = Directory::new("checkpoint-fusion-no-io")?;
    let root = directory.0.join("must-not-exist");
    let pin = ContentDigest::sha256(b"unavailable checkpoint").to_text();
    let mut args = base(&root, ContentDigest::sha256(b"unavailable import"));
    args.extend(
        [
            "--stream-dwell",
            "--dwell-for-ns",
            "20000000000",
            "--dwell-max-gap-ns",
            "100000000",
            "--segment-count",
            "300",
            "--dwell-step-frames",
            "300",
            "--detector-package",
            "/unused/model",
            "--detector-digest",
            &pin,
            "--detector-max-inferences",
            "1",
            "--fusion-profile",
            "/unused/profile",
            "--fusion-digest",
            &pin,
        ]
        .into_iter()
        .map(OsString::from),
    );
    refuses(run(&args)?, "incremental dwell is unsupported");
    assert!(!root.exists());
    args.extend([
        "--dwell-checkpoint".into(),
        pin.as_str().into(),
        "--dwell-checkpoint-root".into(),
        pin.as_str().into(),
        "--dwell-restore-max-frames".into(),
        "300".into(),
    ]);
    for flag in ["--approve", "--retain-health", "--retain-coverage"] {
        let mut requested = args.clone();
        requested.extend([flag.into(), pin.as_str().into()]);
        refuses(run(&requested)?, "calibrated fusion is read-only");
        assert!(!root.exists());
    }
    Ok(())
}

#![forbid(unsafe_code)]
//! Real cold CLI continuation preserves visual-degradation findings and their publication fence.

use super::*;

fn screened(fixture: &Fixture) -> Vec<OsString> {
    let mut args = fixture.args();
    args.extend(["--sensor-health".into(), "conservative-v1".into()]);
    args
}

fn health_work(value: &Value, field: &str, frames: i128) -> Test {
    let work = member(value, field)?;
    assert_eq!(integer(work, "frames_screened")?, frames);
    assert_eq!(integer(work, "samples_screened")?, frames * 48 * 32);
    Ok(())
}

#[test]
fn screened_continuations_match_native_findings_and_cannot_publish_frozen_dwell() -> Test {
    let fixture = Fixture::new("incremental-health-frozen", true, true)?;
    let whole = parse(&good(run(&screened(&fixture))?)?)?;
    let original_effects = fixture.snapshot()?.1;
    let mut args = screened(&fixture);
    args.extend(["--dwell-step-frames".into(), "128".into()]);
    let first = parse(&good(run(&args)?)?)?;
    assert_eq!(string(&first, "sensor_health_stage")?, "screening");
    assert_eq!(string(&first, "sensor_health_policy")?, "conservative-v1");
    assert_eq!(
        string(&first, "sensor_health_policy_digest")?,
        fss_reference::ingest::sensor_health::policy_digest().to_text()
    );
    assert!(string(&first, "continuation_command")?.contains("--sensor-health conservative-v1"));
    health_work(&first, "logical_health_scan_work", 128)?;
    health_work(&first, "cold_health_restoration_work", 0)?;
    assert!(
        first
            .object()
            .is_some_and(|object| !object.contains_key("event_report"))
    );

    let second = parse(&good(emitted(string(&first, "continuation_command")?)?)?)?;
    health_work(&second, "logical_health_scan_work", 256)?;
    health_work(&second, "cold_health_restoration_work", 128)?;
    let complete = parse(&good(emitted(string(&second, "continuation_command")?)?)?)?;
    assert_eq!(string(&complete, "sensor_health_stage")?, "complete");
    health_work(&complete, "logical_health_scan_work", 300)?;
    health_work(&complete, "cold_health_restoration_work", 256)?;
    let report = member(&complete, "event_report")?;
    assert_eq!(
        string(report, "analysis_digest")?,
        string(&whole, "analysis_digest")?
    );
    assert_eq!(
        string(report, "analysis_root")?,
        string(&whole, "analysis_root")?
    );
    assert_eq!(
        member(report, "sensor_health")?,
        member(&whole, "sensor_health")?
    );
    assert_eq!(
        member(member(report, "sensor_health")?, "publication_blocked")?.boolean(),
        Some(true)
    );
    assert_eq!(integer(report, "candidate_count")?, 1);
    assert_eq!(
        member(first_candidate(report)?, "publish_command")?,
        &Value::Null
    );
    assert_eq!(fixture.snapshot()?.1, original_effects);

    let after = fixture.snapshot()?;
    let mut approve = resume_args(&fixture, &complete, "300")?;
    approve.extend([
        "--sensor-health".into(),
        "conservative-v1".into(),
        "--approve".into(),
        string(first_candidate(report)?, "proposal_digest")?.into(),
    ]);
    refuses(
        run(&approve)?,
        "sensor-health findings or incomplete screening block long-dwell publication",
    );
    assert_eq!(fixture.snapshot()?, after);

    let mut retry = resume_args(&fixture, &complete, "300")?;
    let output = fixture.directory.0.join("screened progress.json");
    retry.extend([
        "--sensor-health".into(),
        "conservative-v1".into(),
        "--report-out".into(),
        output.as_os_str().to_owned(),
    ]);
    let text = good(run(&retry)?)?;
    assert_eq!(fs::read_to_string(output)?, text);
    let repeated = parse(&text)?;
    assert_eq!(integer(&repeated, "new_source_positions")?, 0);
    health_work(&repeated, "cold_health_restoration_work", 300)?;
    for key in ["checkpoint_digest", "checkpoint_root"] {
        assert_eq!(member(&repeated, key)?, member(&complete, key)?);
    }
    assert_eq!(fixture.snapshot()?, after);
    Ok(())
}

#[test]
fn checkpoint_recipe_cannot_silently_enable_or_disable_sensor_health() -> Test {
    let fixture = Fixture::new("incremental-health-mode", true, true)?;
    let mut args = screened(&fixture);
    args.extend(["--dwell-step-frames".into(), "128".into()]);
    let screened_prefix = parse(&good(run(&args)?)?)?;
    let mut plain = fixture.args();
    plain.extend(["--dwell-step-frames".into(), "128".into()]);
    let plain_prefix = parse(&good(run(&plain)?)?)?;
    assert_ne!(
        member(&screened_prefix, "checkpoint_digest")?,
        member(&plain_prefix, "checkpoint_digest")?
    );
    assert!(
        plain_prefix
            .object()
            .is_some_and(|object| !object.contains_key("sensor_health_stage"))
    );
    let after = fixture.snapshot()?;
    refuses(
        run(&resume_args(&fixture, &screened_prefix, "128")?)?,
        "checkpoint source, dwell rule, privacy or resource recipe changed",
    );
    let mut enabled = resume_args(&fixture, &plain_prefix, "128")?;
    enabled.extend(["--sensor-health".into(), "conservative-v1".into()]);
    refuses(
        run(&enabled)?,
        "checkpoint source, dwell rule, privacy or resource recipe changed",
    );
    assert_eq!(fixture.snapshot()?, after);
    Ok(())
}

#[test]
fn empty_screened_scan_retains_diagnostics_and_partial_classifier_remains_deferred() -> Test {
    let fixture = Fixture::new("incremental-health-empty", true, false)?;
    let mut args = screened(&fixture);
    args.extend(["--dwell-step-frames".into(), "150".into()]);
    let mut deferred = args.clone();
    let missing = fixture.directory.0.join("absent detector package");
    deferred.extend([
        "--detector-package".into(),
        missing.as_os_str().to_owned(),
        "--detector-digest".into(),
        ContentDigest::sha256(b"not opened during partial health scan")
            .to_text()
            .into(),
        "--detector-max-inferences".into(),
        "1".into(),
    ]);
    let partial = parse(&good(run(&deferred)?)?)?;
    assert_eq!(
        string(&partial, "detector_stage")?,
        "deferred_until_complete"
    );
    assert!(!missing.exists());
    health_work(&partial, "logical_health_scan_work", 150)?;

    let first = parse(&good(run(&args)?)?)?;
    assert_eq!(
        member(&first, "checkpoint_digest")?,
        member(&partial, "checkpoint_digest")?
    );
    let complete = parse(&good(emitted(string(&first, "continuation_command")?)?)?)?;
    let report = member(&complete, "event_report")?;
    assert_eq!(integer(report, "candidate_count")?, 0);
    assert_eq!(
        string(member(report, "sensor_health")?, "status")?,
        "suspected_degradation"
    );
    assert_eq!(
        member(member(report, "sensor_health")?, "healthy_proved")?.boolean(),
        Some(false)
    );
    assert_eq!(
        member(&complete, "absence_certifiable")?.boolean(),
        Some(false)
    );
    health_work(&complete, "logical_health_scan_work", 300)?;
    Ok(())
}

#[test]
fn screened_partial_fusion_and_retention_refuse_before_deployment_creation() -> Test {
    let directory = Directory::new("incremental-health-admission")?;
    let root = directory.0.join("never-created");
    let pin = ContentDigest::sha256(b"unavailable exact object").to_text();
    let mut args = base(&root, ContentDigest::sha256(b"unavailable import"));
    args.extend(
        [
            "--stream-dwell",
            "--dwell-for-ns",
            "1",
            "--dwell-max-gap-ns",
            "1",
            "--dwell-step-frames",
            "128",
            "--sensor-health",
            "conservative-v1",
        ]
        .map(OsString::from),
    );
    for extra in [
        vec!["--retain-health", pin.as_str()],
        vec!["--retain-coverage", pin.as_str()],
        vec![
            "--detector-package",
            "/unused/package",
            "--detector-digest",
            &pin,
            "--detector-max-inferences",
            "1",
            "--fusion-profile",
            "/unused/profile",
            "--fusion-digest",
            &pin,
        ],
    ] {
        let mut attempted = args.clone();
        attempted.extend(extra.into_iter().map(OsString::from));
        let output = run(&attempted)?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!root.exists());
    }
    Ok(())
}

#[test]
fn completed_frozen_checkpoint_retains_health_without_events_or_detector_work() -> Test {
    let fixture = Fixture::new("incremental-health-retention", true, false)?;
    let whole = parse(&good(run(&screened(&fixture))?)?)?;
    let mut args = screened(&fixture);
    args.extend(["--dwell-step-frames".into(), "300".into()]);
    let complete = parse(&good(run(&args)?)?)?;
    let native = member(&complete, "event_report")?;
    let diagnostic = member(native, "historical_health")?;
    let original = member(&whole, "historical_health")?;
    assert_eq!(integer(native, "candidate_count")?, 0);
    for key in [
        "record_digest",
        "approval_digest",
        "provenance_root",
        "receipt",
    ] {
        assert_eq!(member(diagnostic, key)?, member(original, key)?, "{key}");
    }
    let command = string(diagnostic, "retain_command")?;
    assert!(command.contains("--dwell-checkpoint "));
    assert!(command.contains("--dwell-restore-max-frames 300"));
    let before = fixture.snapshot()?;
    let mut retained_args = resume_args(&fixture, &complete, "300")?;
    let missing_model = fixture.directory.0.join("never opened detector.fmpk");
    retained_args.extend([
        "--sensor-health".into(),
        "conservative-v1".into(),
        "--detector-package".into(),
        missing_model.as_os_str().to_owned(),
        "--detector-digest".into(),
        ContentDigest::sha256(b"no model work for independent health retention")
            .to_text()
            .into(),
        "--detector-max-inferences".into(),
        "1".into(),
        "--retain-health".into(),
        ContentDigest::sha256(b"not this diagnostic's approval")
            .to_text()
            .into(),
    ]);
    refuses(run(&retained_args)?, "historical_health_approval_mismatch");
    assert_eq!(fixture.snapshot()?, before);
    *retained_args
        .last_mut()
        .ok_or("missing retention approval")? = string(diagnostic, "approval_digest")?.into();
    let retained = parse(&good(run(&retained_args)?)?)?;
    assert_eq!(integer(&retained, "new_source_positions")?, 0);
    assert_eq!(
        string(&retained, "detector_stage")?,
        "not_run_for_health_retention"
    );
    health_work(&retained, "logical_health_scan_work", 300)?;
    health_work(&retained, "cold_health_restoration_work", 300)?;
    let retained_native = member(&retained, "event_report")?;
    assert_eq!(
        member(retained_native, "model_invoked")?.boolean(),
        Some(false)
    );
    assert_eq!(integer(retained_native, "candidate_count")?, 0);
    let receipt = member(retained_native, "historical_health")?;
    assert_eq!(string(receipt, "status")?, "retained");
    assert_eq!(member(receipt, "receipt")?, member(diagnostic, "receipt")?);
    assert!(!missing_model.exists());
    let after = fixture.snapshot()?;
    assert_ne!(after.0, before.0);
    assert_eq!(after.1, before.1);
    let retry = parse(&good(emitted(command)?)?)?;
    assert_eq!(
        string(
            member(member(&retry, "event_report")?, "historical_health")?,
            "status"
        )?,
        "already_retained"
    );
    assert_eq!(fixture.snapshot()?, after);

    // Independent cold read/verification needs only retained source and policy, not a loose
    // source file, the checkpoint owner, or a trained model package.
    let mut verify: Vec<OsString> = vec![
        "health".into(),
        "verify".into(),
        "--root".into(),
        fixture.root.as_os_str().to_owned(),
        "--site".into(),
        SITE.into(),
        "--diagnostic-digest".into(),
        string(diagnostic, "record_digest")?.into(),
        "--expected-provenance-root".into(),
        string(diagnostic, "provenance_root")?.into(),
        "--execute-perception".into(),
        "yes".into(),
    ];
    let verified = parse(&good(run(&verify)?)?)?;
    assert_eq!(string(&verified, "status")?, "native_replay_matched");
    verify[1] = "read".into();
    verify.truncate(8);
    good(run(&verify)?)?;
    assert_eq!(fixture.snapshot()?, after);
    Ok(())
}

#[test]
fn health_retention_cannot_advance_a_partial_checkpoint() -> Test {
    let fixture = Fixture::new("incremental-health-retention-partial", true, false)?;
    let mut args = screened(&fixture);
    args.extend(["--dwell-step-frames".into(), "150".into()]);
    let partial = parse(&good(run(&args)?)?)?;
    let before = fixture.snapshot()?;
    let mut retained_args = resume_args(&fixture, &partial, "150")?;
    retained_args.extend([
        "--sensor-health".into(),
        "conservative-v1".into(),
        "--retain-health".into(),
        ContentDigest::sha256(b"a partial screen has no retention approval")
            .to_text()
            .into(),
    ]);
    refuses(
        run(&retained_args)?,
        "incremental health retention requires an already complete checkpoint",
    );
    assert_eq!(fixture.snapshot()?, before);
    Ok(())
}

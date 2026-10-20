#![forbid(unsafe_code)]
//! Completed temporal checkpoints enter the existing trained stage through real processes.
//! Synthetic footage establishes continuation, budgeting and custody, not detector quality.

use super::*;

const PACKAGE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../models/yolox-nano/yolox_nano.fmpk"
));
const PACKAGE_DIGEST: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";

fn detector_args(path: &std::path::Path) -> Vec<OsString> {
    vec![
        "--detector-package".into(),
        path.as_os_str().to_owned(),
        "--detector-digest".into(),
        PACKAGE_DIGEST.into(),
        "--detector-max-inferences".into(),
        "1".into(),
        "--detector-frames-per-track".into(),
        "3".into(),
        "--detector-min-iou-ppm".into(),
        "100000".into(),
        "--detector-minimum-score-ppm".into(),
        "500000".into(),
    ]
}

fn trained_args(f: &Fixture, path: &std::path::Path) -> Vec<OsString> {
    let mut args = f.args();
    args.extend(detector_args(path));
    args
}

// The checkpoint commits intentionally advance authority, and the incremental publisher's
// command names that completed checkpoint. Every other native field must match one-shot work.
fn native_payload(report: &Value) -> Test<Value> {
    let mut report = report.clone();
    let Value::Object(fields) = &mut report else {
        return Err("native report object".into());
    };
    for key in [
        "analysis_basis_sequence",
        "analysis_basis_root",
        "authority_sequence",
    ] {
        fields.remove(key);
    }
    let Some(Value::Array(candidates)) = fields.get_mut("candidates") else {
        return Err("native candidates".into());
    };
    for candidate in candidates {
        let Value::Object(fields) = candidate else {
            return Err("candidate object".into());
        };
        fields.remove("publish_command");
    }
    Ok(report)
}

fn deferred(progress: &Value, positions: i128) -> Test {
    assert_eq!(
        string(progress, "detector_stage")?,
        "deferred_until_complete"
    );
    assert_eq!(integer(progress, "next_segment")?, positions);
    assert_eq!(
        member(progress, "analysis_complete")?.boolean(),
        Some(false)
    );
    assert!(
        progress
            .object()
            .is_some_and(|fields| !fields.contains_key("event_report"))
    );
    let request = member(progress, "detector_request")?;
    assert_eq!(integer(request, "max_inferences")?, 1);
    assert_eq!(integer(request, "frames_per_track")?, 3);
    assert_eq!(integer(request, "minimum_association_iou_ppm")?, 100000);
    assert_eq!(integer(request, "minimum_score_ppm")?, 500000);
    let command = string(progress, "continuation_command")?;
    for option in [
        "--detector-package",
        "--detector-digest",
        PACKAGE_DIGEST,
        "--detector-max-inferences",
        "--detector-frames-per-track",
        "--detector-min-iou-ppm",
        "--detector-minimum-score-ppm",
    ] {
        assert!(
            command.contains(option),
            "missing exact detector option: {option}"
        );
    }
    Ok(())
}

#[test]
fn deferred_cold_steps_match_whole_classification_and_publish_and_replay_exactly_once() -> Test {
    let f = Fixture::new("incremental-trained", true, true)?;
    let path = f.directory.0.join("trained detector package.fmpk");
    fs::write(&path, PACKAGE)?;
    let whole = parse(&good(run(&trained_args(&f, &path))?)?)?;
    let before = f.snapshot()?;
    // The same explicit path and digest must survive two partial commands without package I/O.
    fs::remove_file(&path)?;
    let mut args = trained_args(&f, &path);
    args.extend(["--dwell-step-frames".into(), "128".into()]);
    let first = parse(&good(run(&args)?)?)?;
    deferred(&first, 128)?;
    assert!(!path.exists());
    let after_first = f.snapshot()?;
    assert_eq!(after_first.1, before.1);

    let mut premature = resume_args(&f, &first, "128")?;
    premature.extend(detector_args(&path));
    premature.extend([
        "--approve".into(),
        string(first_candidate(&whole)?, "proposal_digest")?.into(),
    ]);
    refuses(
        run(&premature)?,
        "incomplete incremental dwell range cannot publish",
    );
    assert_eq!(f.snapshot()?, after_first);

    let second = parse(&good(emitted(string(&first, "continuation_command")?)?)?)?;
    deferred(&second, 256)?;
    assert!(!path.exists());
    fs::write(&path, PACKAGE)?;
    let complete = parse(&good(emitted(string(&second, "continuation_command")?)?)?)?;
    assert_eq!(string(&complete, "detector_stage")?, "complete");
    assert_eq!(integer(&complete, "new_source_positions")?, 44);
    assert_eq!(
        integer(member(&complete, "logical_scan_work")?, "frames_decoded")?,
        300
    );
    assert_eq!(
        integer(
            member(&complete, "cold_restoration_work")?,
            "frames_decoded"
        )?,
        256
    );
    let report = member(&complete, "event_report")?;
    assert_eq!(native_payload(report)?, native_payload(&whole)?);
    assert_eq!(integer(report, "candidate_count")?, 1);
    let cascade = member(report, "detector_cascade")?;
    assert_eq!(
        member(cascade, "inferred_segments")?
            .array()
            .ok_or("inferred segments")?
            .len(),
        1
    );
    assert_eq!(
        member(cascade, "budget_skipped_segments")?
            .array()
            .ok_or("budget skipped segments")?
            .len(),
        2
    );
    assert_eq!(f.snapshot()?.1, before.1);

    let publication = string(first_candidate(report)?, "publish_command")?.to_owned();
    let published = parse(&good(emitted(&publication)?)?)?;
    assert_eq!(integer(&published, "new_source_positions")?, 0);
    assert_eq!(
        integer(
            member(&published, "cold_restoration_work")?,
            "frames_decoded"
        )?,
        300
    );
    assert_eq!(
        string(
            first_candidate(member(&published, "event_report")?)?,
            "status"
        )?,
        "published"
    );
    let after = f.snapshot()?;
    let retry = parse(&good(emitted(&publication)?)?)?;
    assert_eq!(
        string(first_candidate(member(&retry, "event_report")?)?, "status")?,
        "already_published"
    );
    assert_eq!(f.snapshot()?, after);

    // The existing native replay command must use the published archive after the loose
    // package and the original recording are absent.
    let event = string(first_candidate(report)?, "event_id")?;
    fs::remove_file(&path)?;
    let mut replay: Vec<OsString> = vec![
        "inspect".into(),
        "--root".into(),
        f.root.as_os_str().to_owned(),
        "--site".into(),
        SITE.into(),
        "--event-id".into(),
        event.into(),
    ];
    let inspection = parse(&good(
        Command::new(env!("CARGO_BIN_EXE_fss-replay-dwell"))
            .args(&replay)
            .output()?,
    )?)?;
    assert_eq!(
        string(&inspection, "detector_package_digest")?,
        PACKAGE_DIGEST
    );
    replay[0] = "verify".into();
    replay.extend([
        "--expected-event-revision".into(),
        string(&inspection, "event_revision_digest")?.into(),
        "--expected-analysis-root".into(),
        string(&inspection, "analysis_root")?.into(),
        "--execute-perception".into(),
        "yes".into(),
    ]);
    let verified = parse(&good(
        Command::new(env!("CARGO_BIN_EXE_fss-replay-dwell"))
            .args(&replay)
            .output()?,
    )?)?;
    assert_eq!(string(&verified, "status")?, "native_replay_matched");
    assert_eq!(integer(&verified, "frames_replayed")?, 300);
    assert_eq!(f.snapshot()?, after);
    Ok(())
}

#[test]
fn failed_package_pin_keeps_the_completed_temporal_checkpoint_and_rejects_untrained_approval()
-> Test {
    let f = Fixture::new("incremental-trained-refusal", true, true)?;
    let path = f.directory.0.join("trained detector package.fmpk");
    fs::write(
        &path,
        b"an invalid package must fail its exact digest before parsing",
    )?;
    let output_path = f.directory.0.join("classified report.json");
    let mut args = trained_args(&f, &path);
    args.extend([
        "--dwell-step-frames".into(),
        "300".into(),
        "--report-out".into(),
        output_path.as_os_str().to_owned(),
    ]);
    let before = f.snapshot()?;
    refuses(run(&args)?, "ERR-MODEL-PACKAGE-DIGEST-001");
    assert!(!output_path.exists());
    let saved = f.snapshot()?;
    assert_ne!(saved.0, before.0);
    assert_eq!(saved.1, before.1);

    // Returning the same complete checkpoint without classification must be an exact
    // root-last retry, proving that the failed terminal stage retained temporal progress.
    let mut temporal_args = f.args();
    temporal_args.extend(["--dwell-step-frames".into(), "300".into()]);
    let temporal = parse(&good(run(&temporal_args)?)?)?;
    assert_eq!(f.snapshot()?, saved);
    let untrained = string(
        first_candidate(member(&temporal, "event_report")?)?,
        "proposal_digest",
    )?;
    fs::write(&path, PACKAGE)?;
    let mut resume = resume_args(&f, &temporal, "300")?;
    resume.extend(detector_args(&path));
    resume.extend(["--report-out".into(), output_path.as_os_str().to_owned()]);
    let text = good(run(&resume)?)?;
    assert_eq!(fs::read_to_string(&output_path)?, text);
    let classified = parse(&text)?;
    assert_eq!(integer(&classified, "new_source_positions")?, 0);
    assert_eq!(string(&classified, "detector_stage")?, "complete");
    assert_eq!(
        string(&classified, "checkpoint_digest")?,
        string(&temporal, "checkpoint_digest")?
    );
    assert_eq!(
        string(&classified, "checkpoint_root")?,
        string(&temporal, "checkpoint_root")?
    );
    let candidate = first_candidate(member(&classified, "event_report")?)?;
    assert_ne!(string(candidate, "proposal_digest")?, untrained);
    assert_eq!(f.snapshot()?, saved);

    let mut wrong = resume_args(&f, &temporal, "300")?;
    wrong.extend(detector_args(&path));
    wrong.extend(["--approve".into(), untrained.into()]);
    refuses(run(&wrong)?, "ERR-WATCH-APPROVAL-STALE-001");
    assert_eq!(f.snapshot()?, saved);
    Ok(())
}

#[test]
fn terminal_classification_and_cold_retry_share_the_original_pixel_allowance() -> Test {
    let f = Fixture::new("incremental-trained-budget", true, true)?;
    let path = f.directory.0.join("trained detector package.fmpk");
    fs::write(&path, PACKAGE)?;
    // Enough for exactly the 300 native 48x32 temporal frames, with nothing left for the
    // classifier's selected RGB frames. A fresh classifier budget would incorrectly succeed.
    let budget = (FRAMES * 48 * 32).to_string();
    let mut trained = trained_args(&f, &path);
    trained.extend([
        "--dwell-step-frames".into(),
        "300".into(),
        "--dwell-pixel-budget".into(),
        budget.as_str().into(),
    ]);
    refuses(run(&trained)?, "ERR-WATCH-LIMIT-001");
    let saved = f.snapshot()?;
    let mut temporal = f.args();
    temporal.extend([
        "--dwell-step-frames".into(),
        "300".into(),
        "--dwell-pixel-budget".into(),
        budget.as_str().into(),
    ]);
    let completed = parse(&good(run(&temporal)?)?)?;
    assert_eq!(f.snapshot()?, saved);
    assert_eq!(
        integer(
            member(&completed, "event_report")?,
            "pixel_samples_processed"
        )?,
        (FRAMES * 48 * 32) as i128
    );
    let mut retry = resume_args(&f, &completed, "300")?;
    retry.extend(detector_args(&path));
    retry.extend(["--dwell-pixel-budget".into(), budget.as_str().into()]);
    refuses(run(&retry)?, "ERR-WATCH-LIMIT-001");
    assert_eq!(f.snapshot()?, saved);
    set(
        &mut retry,
        "--dwell-pixel-budget",
        &(FRAMES * 48 * 32 + 1).to_string(),
    )?;
    refuses(
        run(&retry)?,
        "checkpoint source, dwell rule, privacy or resource recipe changed",
    );
    assert_eq!(f.snapshot()?, saved);
    Ok(())
}

#[test]
fn completed_zero_episode_stage_is_verified_but_performs_no_native_inference() -> Test {
    let f = Fixture::new("incremental-trained-empty", true, false)?;
    let path = f.directory.0.join("trained detector package.fmpk");
    let mut args = trained_args(&f, &path);
    args.extend(["--dwell-step-frames".into(), "128".into()]);
    let first = parse(&good(run(&args)?)?)?;
    deferred(&first, 128)?;
    assert!(!path.exists());
    fs::write(&path, PACKAGE)?;
    let mut final_args = resume_args(&f, &first, "128")?;
    set(&mut final_args, "--dwell-step-frames", "300")?;
    final_args.extend(detector_args(&path));
    let before = f.snapshot()?;
    let final_report = parse(&good(run(&final_args)?)?)?;
    assert_eq!(string(&final_report, "detector_stage")?, "complete");
    assert_eq!(integer(&final_report, "new_source_positions")?, 172);
    let report = member(&final_report, "event_report")?;
    assert_eq!(integer(report, "candidate_count")?, 0);
    assert_eq!(member(report, "model_invoked")?.boolean(), Some(false));
    let detector = member(report, "detector_cascade")?;
    assert_eq!(integer(detector, "inference_pipeline_attempts")?, 0);
    assert_eq!(integer(detector, "inferences_completed")?, 0);
    assert_eq!(integer(detector, "additional_pixel_samples_processed")?, 0);
    ContentDigest::parse(string(detector, "recipe_digest")?)?;
    assert_eq!(f.snapshot()?.1, before.1);
    Ok(())
}

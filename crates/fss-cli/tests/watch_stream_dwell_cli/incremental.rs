#![forbid(unsafe_code)]
//! Actual operator commands, immutable custody and cold native continuation across processes.

use super::*;

#[path = "incremental/video.rs"]
mod video;
use fss_cli::json_input::{Value, parse};

#[path = "incremental/classifier.rs"]
mod classifier;

#[path = "incremental/health.rs"]
mod health;

fn member<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|object| object.get(key))
        .ok_or("missing JSON field".into())
}
fn integer(value: &Value, key: &str) -> Test<i128> {
    member(value, key)?
        .integer()
        .ok_or("expected JSON integer".into())
}
fn string<'a>(value: &'a Value, key: &str) -> Test<&'a str> {
    member(value, key)?
        .text()
        .ok_or("expected JSON string".into())
}
fn first_candidate(report: &Value) -> Test<&Value> {
    member(report, "candidates")?
        .array()
        .and_then(|items| items.first())
        .ok_or("missing candidate".into())
}

// Execute the exact public POSIX continuation, including the fixture's space-containing path.
// The executable itself is supplied as a positional argument, never reconstructed by quoting.
fn emitted(command: &str) -> Test<Output> {
    let args = command
        .strip_prefix("fss-event ")
        .ok_or("unexpected command executable")?;
    Ok(Command::new("sh")
        .arg("-c")
        .arg(format!("exec \"$1\" {args}"))
        .arg("fss-incremental-test")
        .arg(env!("CARGO_BIN_EXE_fss-event"))
        .output()?)
}

fn resume_args(f: &Fixture, checkpoint: &Value, maximum_prefix: &str) -> Test<Vec<OsString>> {
    let mut args = f.args();
    args.extend([
        "--dwell-step-frames".into(),
        "128".into(),
        "--dwell-checkpoint".into(),
        string(checkpoint, "checkpoint_digest")?.into(),
        "--dwell-checkpoint-root".into(),
        string(checkpoint, "checkpoint_root")?.into(),
        "--dwell-restore-max-frames".into(),
        maximum_prefix.into(),
    ]);
    Ok(args)
}

#[test]
fn emitted_continuations_restore_one_native_episode_and_publish_it_exactly_once() -> Test {
    let f = Fixture::new("incremental-commands", true, true)?;
    let whole_text = good(run(&f.args())?)?;
    let whole = parse(&whole_text)?;
    let before = f.snapshot()?;
    let mut args = f.args();
    args.extend(["--dwell-step-frames".into(), "128".into()]);
    let first_text = good(run(&args)?)?;
    let first = parse(&first_text)?;
    assert_eq!(
        string(&first, "schema")?,
        "fss.incremental_dwell_progress.v1"
    );
    assert_eq!(string(&first, "status")?, "checkpointed");
    assert_eq!(integer(&first, "next_segment")?, 128);
    assert_eq!(integer(&first, "remaining_segments")?, 172);
    assert_eq!(integer(&first, "new_source_positions")?, 128);
    assert_eq!(
        integer(member(&first, "logical_scan_work")?, "frames_decoded")?,
        128
    );
    assert_eq!(
        integer(member(&first, "cold_restoration_work")?, "frames_decoded")?,
        0
    );
    assert!(
        first
            .object()
            .is_some_and(|object| !object.contains_key("event_report"))
    );
    let after_first = f.snapshot()?;
    assert_ne!(after_first.0, before.0);
    assert_eq!(after_first.1, before.1);
    let retry = parse(&good(run(&args)?)?)?;
    assert_eq!(
        string(&retry, "checkpoint_digest")?,
        string(&first, "checkpoint_digest")?
    );
    assert_eq!(
        string(&retry, "checkpoint_root")?,
        string(&first, "checkpoint_root")?
    );
    assert_eq!(f.snapshot()?, after_first);

    let second = parse(&good(emitted(string(&first, "continuation_command")?)?)?)?;
    assert_eq!(integer(&second, "next_segment")?, 256);
    assert_eq!(integer(&second, "new_source_positions")?, 128);
    assert_eq!(
        integer(member(&second, "cold_restoration_work")?, "frames_decoded")?,
        128
    );
    assert_eq!(
        integer(member(&second, "logical_scan_work")?, "frames_decoded")?,
        256
    );
    let complete = parse(&good(emitted(string(&second, "continuation_command")?)?)?)?;
    assert_eq!(string(&complete, "status")?, "complete");
    assert_eq!(integer(&complete, "next_segment")?, 300);
    assert_eq!(integer(&complete, "new_source_positions")?, 44);
    assert_eq!(integer(&complete, "remaining_segments")?, 0);
    assert_eq!(
        integer(
            member(&complete, "cold_restoration_work")?,
            "frames_decoded"
        )?,
        256
    );
    let report = member(&complete, "event_report")?;
    assert_eq!(
        string(report, "analysis_digest")?,
        string(&whole, "analysis_digest")?
    );
    assert_eq!(
        string(report, "analysis_root")?,
        string(&whole, "analysis_root")?
    );
    assert_eq!(integer(report, "candidate_count")?, 1);
    assert_eq!(
        string(first_candidate(report)?, "proposal_digest")?,
        string(first_candidate(&whole)?, "proposal_digest")?
    );
    assert_eq!(integer(first_candidate(report)?, "trigger_segment")?, 205);
    assert_eq!(
        member(&complete, "checkpoint_is_event")?.boolean(),
        Some(false)
    );
    assert_eq!(
        member(&complete, "alert_authorized")?.boolean(),
        Some(false)
    );
    assert_eq!(f.snapshot()?.1, before.1);

    let publication = string(first_candidate(report)?, "publish_command")?;
    let published = parse(&good(emitted(publication)?)?)?;
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
    assert_eq!(after.1, before.1);
    let retry = parse(&good(emitted(publication)?)?)?;
    assert_eq!(
        string(first_candidate(member(&retry, "event_report")?)?, "status")?,
        "already_published"
    );
    assert_eq!(f.snapshot()?, after);
    Ok(())
}

#[test]
fn cold_work_is_separately_admitted_and_changed_recipe_cannot_advance_a_checkpoint() -> Test {
    let f = Fixture::new("incremental-admission", true, true)?;
    let whole = good(run(&f.args())?)?;
    let approval = field(&whole, "proposal_digest")?;
    let mut args = f.args();
    args.extend(["--dwell-step-frames".into(), "128".into()]);
    let output_path = f.directory.0.join("checkpoint report.json");
    args.extend(["--report-out".into(), output_path.as_os_str().to_owned()]);
    let first_text = good(run(&args)?)?;
    assert_eq!(fs::read_to_string(&output_path)?, first_text);
    let first = parse(&first_text)?;
    assert!(!string(&first, "continuation_command")?.contains("--report-out"));
    let after = f.snapshot()?;
    refuses(
        run(&resume_args(&f, &first, "127")?)?,
        "ERR-WATCH-LIMIT-001",
    );
    assert_eq!(f.snapshot()?, after);

    let mut changed = resume_args(&f, &first, "128")?;
    set(&mut changed, "--dwell-for-ns", "20100000000")?;
    refuses(
        run(&changed)?,
        "checkpoint source, dwell rule, privacy or resource recipe changed",
    );
    assert_eq!(f.snapshot()?, after);
    let mut under_admitted = resume_args(&f, &first, "128")?;
    under_admitted.extend(["--dwell-pixel-budget".into(), "268435456".into()]);
    refuses(run(&under_admitted)?, "ERR-WATCH-LIMIT-001");
    assert_eq!(f.snapshot()?, after);
    let mut premature_approval = resume_args(&f, &first, "128")?;
    premature_approval.extend(["--approve".into(), approval.into()]);
    refuses(
        run(&premature_approval)?,
        "incomplete incremental dwell range cannot publish",
    );
    assert_eq!(f.snapshot()?, after);
    Ok(())
}

#[test]
fn incremental_modes_and_missing_resume_admission_refuse_before_deployment_io() -> Test {
    let directory = Directory::new("incremental-parse")?;
    let root = directory.0.join("must-not-exist");
    let mut prefix = base(&root, ContentDigest::sha256(b"unavailable source"));
    prefix.extend(
        [
            "--stream-dwell",
            "--dwell-for-ns",
            "1",
            "--dwell-max-gap-ns",
            "1",
            "--dwell-step-frames",
            "128",
        ]
        .map(OsString::from),
    );
    let pin = ContentDigest::sha256(b"not a retained checkpoint").to_text();
    for extra in [
        vec![
            "--sensor-health",
            "conservative-v1",
            "--retain-health",
            "yes",
        ],
        vec!["--dwell-checkpoint", pin.as_str()],
        vec![
            "--dwell-checkpoint",
            pin.as_str(),
            "--dwell-checkpoint-root",
            pin.as_str(),
        ],
        vec!["--dwell-restore-max-frames", "128"],
        vec!["--detector-max-inferences", "1"],
        vec![
            "--detector-package",
            "/unused/model",
            "--detector-digest",
            pin.as_str(),
            "--detector-max-inferences",
            "1",
            "--fusion-profile",
            "/unused/profile",
            "--fusion-digest",
            pin.as_str(),
        ],
    ] {
        let mut args = prefix.clone();
        args.extend(extra.into_iter().map(OsString::from));
        let result = run(&args)?;
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(!root.exists());
    }
    Ok(())
}

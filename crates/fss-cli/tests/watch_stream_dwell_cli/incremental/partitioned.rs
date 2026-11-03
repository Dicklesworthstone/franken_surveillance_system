#![forbid(unsafe_code)]
//! Actual bounded-step commands over independently retained file publication parts.

use super::*;

// Force the standard deployment's real publication boundary. Only the first 300
// positions are selected for native analysis, keeping pixel work bounded.
const SOURCE_FRAMES: usize = fss_reference::DeploymentLimits::STANDARD_MANIFEST_CHILDREN_MAX + 1;

#[test]
fn multipart_continuations_keep_whole_scan_identity_and_publish_once() -> Test {
    let fixture =
        Fixture::with_source_frames("multipart-incremental", true, true, false, SOURCE_FRAMES)?;
    let whole = parse(&good(run(&fixture.args())?)?)?;
    assert_eq!(integer(&whole, "candidate_count")?, 1);
    let initial = fixture.snapshot()?;
    let mut args = fixture.args();
    args.extend(["--dwell-step-frames".into(), "128".into()]);

    let first = parse(&good(run(&args)?)?)?;
    assert_eq!(string(&first, "status")?, "checkpointed");
    assert_eq!(integer(&first, "next_segment")?, 128);
    assert_eq!(fixture.snapshot()?.1, initial.1);
    let first_snapshot = fixture.snapshot()?;
    let retry = parse(&good(run(&args)?)?)?;
    assert_eq!(
        string(&retry, "checkpoint_digest")?,
        string(&first, "checkpoint_digest")?
    );
    assert_eq!(
        string(&retry, "checkpoint_root")?,
        string(&first, "checkpoint_root")?
    );
    assert_eq!(fixture.snapshot()?, first_snapshot);

    let second = parse(&good(emitted(string(&first, "continuation_command")?)?)?)?;
    assert_eq!(integer(&second, "next_segment")?, 256);
    assert_eq!(
        integer(member(&second, "cold_restoration_work")?, "frames_decoded")?,
        128
    );
    let complete = parse(&good(emitted(string(&second, "continuation_command")?)?)?)?;
    assert_eq!(string(&complete, "status")?, "complete");
    assert_eq!(integer(&complete, "new_source_positions")?, 44);
    let report = member(&complete, "event_report")?;
    assert_eq!(
        string(report, "analysis_digest")?,
        string(&whole, "analysis_digest")?
    );
    assert_eq!(
        string(first_candidate(report)?, "proposal_digest")?,
        string(first_candidate(&whole)?, "proposal_digest")?
    );
    assert_eq!(integer(first_candidate(report)?, "trigger_segment")?, 205);
    assert_eq!(fixture.snapshot()?.1, initial.1);

    let command = string(first_candidate(report)?, "publish_command")?;
    let published = parse(&good(emitted(command)?)?)?;
    assert_eq!(integer(&published, "new_source_positions")?, 0);
    assert_eq!(
        string(
            first_candidate(member(&published, "event_report")?)?,
            "status"
        )?,
        "published"
    );
    let terminal = fixture.snapshot()?;
    let duplicate = parse(&good(emitted(command)?)?)?;
    assert_eq!(
        string(
            first_candidate(member(&duplicate, "event_report")?)?,
            "status"
        )?,
        "already_published"
    );
    assert_eq!(fixture.snapshot()?, terminal);
    Ok(())
}

#[test]
fn multipart_resume_preserves_original_resource_admission_and_recipe() -> Test {
    let fixture =
        Fixture::with_source_frames("multipart-admission", true, true, false, SOURCE_FRAMES)?;
    let mut args = fixture.args();
    args.extend(["--dwell-step-frames".into(), "128".into()]);
    let first = parse(&good(run(&args)?)?)?;
    let saved = fixture.snapshot()?;

    refuses(
        run(&resume_args(&fixture, &first, "127")?)?,
        "ERR-WATCH-LIMIT-001",
    );
    assert_eq!(fixture.snapshot()?, saved);

    let mut changed = resume_args(&fixture, &first, "128")?;
    set(&mut changed, "--dwell-for-ns", "20100000000")?;
    refuses(
        run(&changed)?,
        "checkpoint source, dwell rule, privacy or resource recipe changed",
    );
    assert_eq!(fixture.snapshot()?, saved);
    Ok(())
}

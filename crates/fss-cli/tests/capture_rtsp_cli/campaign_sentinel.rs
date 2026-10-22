#![forbid(unsafe_code)]
//! Native stationary RTSP recordings reach a trained detector without a foreground gate.
//! These process proofs establish sampling, ownership and retained replay, not recognition quality.

use super::*;

const PACKAGE_DIGEST: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";
const INFERENCE_DEADLINE: Duration = Duration::from_secs(180);

fn package(directory: &Directory) -> Test<PathBuf> {
    let path = directory.0.join("operator's pinned model.fmpk");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models/yolox-nano/yolox_nano.fmpk"),
        &path,
    )?;
    assert_eq!(
        ContentDigest::sha256(&fs::read(&path)?).to_text(),
        PACKAGE_DIGEST
    );
    Ok(path)
}

fn requests(
    directory: &Directory,
    root: &Path,
    preview: &Value,
    native: &[Vec<Value>],
) -> Test<Vec<Option<Vec<String>>>> {
    let children = value(preview, "attempts")?
        .array()
        .ok_or("capture children")?;
    native
        .iter()
        .enumerate()
        .map(|(index, rows)| {
            let mut request = watch::request(directory, root, &children[index], rows, index + 1)?;
            if let Some(arguments) = &mut request {
                // The native RGB evidence binding requires the entire capture interval to
                // fit unsigned nanoseconds, including the explicit 1000 ns uncertainty.
                let start = arguments
                    .iter()
                    .position(|argument| argument == "--capture-start-ns")
                    .ok_or("missing explicit capture start")?;
                *arguments
                    .get_mut(start + 1)
                    .ok_or("missing explicit capture start value")? =
                    ((index + 1) as u64 * 1_000_000_000).to_string();
            }
            Ok(request)
        })
        .collect()
}

fn args(
    directory: &Directory,
    root: &Path,
    pin: &Value,
    model: &Path,
    requests: &[Option<Vec<String>>],
) -> Test<Vec<OsString>> {
    Ok([
        (
            "--history-root",
            directory.0.join("history").display().to_string(),
        ),
        ("--history-approval", text(pin, "approval")?.into()),
        ("--history-plan", text(pin, "plan")?.into()),
        ("--history-root-digest", text(pin, "root")?.into()),
        ("--history-records", integer(pin, "records")?.to_string()),
        ("--root", root.display().to_string()),
        ("--site", SITE.into()),
        ("--requests", watch::requests_json(requests)),
        ("--interpretation", "ycbcr".into()),
        ("--package", model.display().to_string()),
        ("--package-digest", PACKAGE_DIGEST.into()),
        ("--read-model", "yes".into()),
        ("--retain-analysis", "yes".into()),
        ("--sentinel-every-frames", "1".into()),
        ("--sentinel-burst-frames", "1".into()),
        ("--sentinel-max-inferences", "2".into()),
        ("--owner-authorized", "yes".into()),
        ("--read-originals", "yes".into()),
        ("--retain-originals", "yes".into()),
        // The independently decoded fixture is160×128. A non-multiple proves cold AVC floor parity.
        ("--max-frame-pixels", "20481".into()),
        ("--timeout-ms", "600000".into()),
    ]
    .into_iter()
    .flat_map(|(key, value): (&str, String)| [key.into(), OsString::from(value)])
    .collect())
}

fn approve(input: &[OsString]) -> Test<Vec<OsString>> {
    let preview = parse(&good(run("sentinel-campaign", input)?)?)?;
    assert_eq!(text(&preview, "kind")?, "plan");
    assert_eq!(text(&preview, "writes")?, "none_until_exact_outer_approval");
    assert!(!boolean(value(&preview, "package")?, "verified")?);
    assert!(boolean(value(&preview, "sampling")?, "motion_independent")?);
    let mut approved = input.to_vec();
    approved.extend([
        "--approve-import".into(),
        text(&preview, "approval_digest")?.into(),
    ]);
    Ok(approved)
}

fn completed(input: &[OsString]) -> Test<Value> {
    Ok(parse(&good(run_with_timeout(
        "sentinel-campaign",
        input,
        INFERENCE_DEADLINE,
    )?)?)?)
}

fn attempts(report: &Value) -> Test<&[Value]> {
    Ok(value(value(report, "report")?, "attempts")?
        .array()
        .ok_or("campaign attempts")?)
}

#[test]
fn stationary_independent_archives_get_round_robin_model_samples_and_exact_cold_replay() -> Test {
    let directory = Directory::new("campaign-sentinel-static")?;
    let camera = listener()?;
    let mut capture = history_args(&directory, camera.local_addr()?);
    set(&mut capture, "--max-attempts", "3");
    let (approved_capture, capture_preview) = campaign_approval(&capture)?;
    let (captured, transcripts) = capture_sessions(
        &camera,
        &approved_capture,
        &[
            Behavior::StaticTarget,
            Behavior::StaticTarget,
            Behavior::AuthenticationRequired,
        ],
    )?;
    assert!(!captured.status.success());
    assert_eq!(transcripts.len(), 3);
    let pins = receipts(&captured)?;
    let pin = pins.last().ok_or("terminal campaign pin")?;
    let (_, native) = campaign_rows(&captured)?;
    let root = directory.0.join("independent detector's deployment");
    let requests = requests(&directory, &root, &capture_preview, &native)?;
    assert!(requests[0].is_some() && requests[1].is_some() && requests[2].is_none());
    for prefix in ["capture", "pins"] {
        let source = epoch_path(&directory, prefix, 3);
        if source.exists() {
            fs::rename(source, directory.0.join(format!("offline-{prefix}-3")))?;
        }
    }
    let model = package(&directory)?;
    let history_before = tree(&directory.0.join("history"))?;
    let pin_bytes = (1..=2)
        .map(|ordinal| fs::read(epoch_path(&directory, "pins", ordinal).join("pins.journal")))
        .collect::<Result<Vec<_>, _>>()?;
    let input = args(&directory, &root, pin, &model, &requests)?;
    let approved = approve(&input)?;
    assert!(!root.exists());
    assert_eq!(tree(&directory.0.join("history"))?, history_before);
    no_connection(&camera)?;

    let first = completed(&approved)?;
    let campaign = value(&first, "report")?;
    assert_eq!(
        text(campaign, "format")?,
        "fss.rtsp_campaign_sentinel_report.v1"
    );
    assert!(boolean(campaign, "campaign_history_verified")?);
    assert!(!boolean(campaign, "foreground_gate_required")?);
    assert!(!boolean(campaign, "latest_history_verified")?);
    assert!(!boolean(campaign, "absence_certifiable")?);
    assert!(!boolean(&first, "event_publication_authorized")?);
    assert_eq!(integer(value(campaign, "usage")?, "inferences")?, 2);
    let rows = attempts(&first)?;
    assert_eq!(rows.len(), 3);
    for row in &rows[..2] {
        assert_eq!(text(row, "status")?, "analyzed");
        assert_eq!(integer(row, "catalogued_pictures")?, 2);
        assert_eq!(integer(row, "decoded_pictures")?, 2);
        assert_eq!(integer(row, "model_sampled_pictures")?, 1);
        assert!(boolean(row, "original_rtp_custody_verified")?);
        assert!(boolean(row, "strict_native_video_range_drained")?);
        assert!(!boolean(row, "quiet_scene_proved")?);
        let allocation = value(row, "allocation")?;
        assert_eq!(integer(allocation, "eligible_bursts")?, 2);
        assert_eq!(integer(allocation, "admitted_inferences")?, 1);
        assert_eq!(integer(allocation, "budget_skipped_bursts")?, 1);
        let report = value(row, "sentinel")?;
        assert_eq!(integer(report, "executed_inferences")?, 1);
        assert!(boolean(value(report, "sampling")?, "motion_independent")?);
        assert_eq!(
            value(report, "unsampled_ranges")?
                .array()
                .ok_or("unsampled")?
                .len(),
            1
        );
        assert!(boolean(
            value(row, "retained")?,
            "cold_native_replay_available"
        )?);
        assert_eq!(
            text(value(row, "retained")?, "package_digest")?,
            PACKAGE_DIGEST
        );
    }
    assert_ne!(
        text(value(&rows[0], "import")?, "identity")?,
        text(value(&rows[1], "import")?, "identity")?
    );
    assert_eq!(text(&rows[2], "status")?, "recorded_no_durable_pictures");
    assert_eq!(integer(&rows[2], "recorded_durable_pictures")?, 0);
    assert_eq!(value(&rows[2], "sentinel")?, &Value::Null);
    assert_eq!(value(&rows[2], "retained")?, &Value::Null);
    assert_eq!(
        text(value(value(&rows[2], "finish")?, "native")?, "error_id")?,
        "ERR-CAPTURE-RTSP-AUTH-UNSUPPORTED-001"
    );
    assert!(!boolean(
        value(value(campaign, "history")?, "terminal")?,
        "complete"
    )?);
    let io = value(&first, "archive_io")?;
    assert!(integer(io, "startup_read_bytes")? > 0);
    assert!(integer(io, "total_read_bytes")? > integer(io, "startup_read_bytes")?);

    let journals = watch::journal_snapshot(&root)?;
    let retried = completed(&approved)?;
    for (original, repeated) in rows[..2].iter().zip(&attempts(&retried)?[..2]) {
        assert!(boolean(value(repeated, "import")?, "reused")?);
        assert_eq!(value(original, "sentinel")?, value(repeated, "sentinel")?);
        assert_eq!(
            text(value(original, "retained")?, "report_digest")?,
            text(value(repeated, "retained")?, "report_digest")?
        );
        assert_eq!(
            text(value(repeated, "retained")?, "status")?,
            "already_retained"
        );
    }
    assert_eq!(
        watch::journal_snapshot(&root)?,
        journals,
        "exact retry appended cognition or effects"
    );

    // The same retained images are quiet under the native foreground detector. The trained
    // invocation count above therefore cannot have come from motion/foreground selection.
    let motion = watch::approve_watch(&watch::watch_args(&directory, &root, pin, &requests)?)?;
    let motion = parse(&good(run("watch-campaign", &motion)?)?)?;
    let motion_rows = attempts(&motion)?;
    for row in &motion_rows[..2] {
        assert_eq!(integer(row, "decoded_pictures")?, 2);
        assert_eq!(
            integer(value(row, "watch")?, "candidate_count")?,
            0,
            "repeated exact native IDR pictures must not require foreground candidates"
        );
    }
    assert_eq!(
        watch::journal_snapshot(&root)?,
        journals,
        "foreground comparison published effects"
    );
    assert_eq!(tree(&directory.0.join("history"))?, history_before);
    for ordinal in 1..=2 {
        assert_eq!(
            fs::read(epoch_path(&directory, "pins", ordinal).join("pins.journal"))?,
            pin_bytes[ordinal - 1]
        );
        fs::rename(
            epoch_path(&directory, "capture", ordinal),
            directory.0.join(format!("offline-capture-{ordinal}")),
        )?;
    }
    fs::rename(&model, directory.0.join("offline-model.fmpk"))?;
    let commands = value(&first, "native_sentinel_reruns")?
        .array()
        .ok_or("rerun commands")?;
    assert_eq!(commands.len(), 3);
    assert_eq!(value(&commands[2], "command")?, &Value::Null);
    for index in 0..2 {
        let words = watch::command_words(text(&commands[index], "command")?, "fss-infer")?;
        let exact = good(run_with_timeout("infer", &words[1..], INFERENCE_DEADLINE)?)?;
        assert_eq!(
            ContentDigest::sha256(exact.as_bytes()).to_text(),
            text(value(&rows[index], "retained")?, "report_digest")?
        );
        assert_eq!(&parse(&exact)?, value(&rows[index], "sentinel")?);
    }
    assert_eq!(
        watch::journal_snapshot(&root)?,
        journals,
        "cold replay appended cognition or effects"
    );
    no_connection(&camera)?;
    Ok(())
}

#[test]
fn short_budget_skipped_and_exact_start_only_rows_do_not_claim_analyzed_or_quiet() -> Test {
    let directory = Directory::new("campaign-sentinel-explicit-states")?;
    let camera = listener()?;
    let (capture, preview) = campaign_approval(&history_args(&directory, camera.local_addr()?))?;
    let (captured, _) = capture_sessions(
        &camera,
        &capture,
        &[Behavior::StaticTarget, Behavior::StaticTarget],
    )?;
    assert!(captured.status.success());
    let pins = receipts(&captured)?;
    let pin = pins.last().ok_or("terminal pin")?;
    let (_, native) = campaign_rows(&captured)?;
    let model = package(&directory)?;
    let history_before = tree(&directory.0.join("history"))?;

    let root = directory.0.join("short burst");
    let selected = requests(&directory, &root, &preview, &native)?;
    let mut input = args(&directory, &root, pin, &model, &selected)?;
    set(&mut input, "--sentinel-every-frames", "3");
    set(&mut input, "--sentinel-burst-frames", "3");
    set(&mut input, "--sentinel-max-inferences", "3");
    let short = completed(&approve(&input)?)?;
    assert_eq!(
        integer(value(value(&short, "report")?, "usage")?, "inferences")?,
        0
    );
    for row in attempts(&short)? {
        assert_eq!(text(row, "status")?, "too_short_for_burst");
        assert_eq!(integer(row, "catalogued_pictures")?, 2);
        assert_eq!(integer(row, "decoded_pictures")?, 0);
        assert_eq!(value(row, "sentinel")?, &Value::Null);
        assert_eq!(value(row, "retained")?, &Value::Null);
        assert!(!boolean(row, "strict_native_video_range_drained")?);
        assert!(!boolean(row, "quiet_scene_proved")?);
        assert_eq!(
            integer(
                &value(row, "unsampled_ranges")?
                    .array()
                    .ok_or("whole unsampled range")?[0],
                "segment_count"
            )?,
            2
        );
    }

    let root = directory.0.join("one global inference");
    let selected = requests(&directory, &root, &preview, &native)?;
    let mut input = args(&directory, &root, pin, &model, &selected)?;
    set(&mut input, "--sentinel-max-inferences", "1");
    set(&mut input, "--retain-analysis", "no");
    let skipped = completed(&approve(&input)?)?;
    let rows = attempts(&skipped)?;
    assert_eq!(text(&rows[0], "status")?, "analyzed");
    assert_eq!(text(&rows[1], "status")?, "budget_skipped");
    assert_eq!(integer(&rows[1], "catalogued_pictures")?, 2);
    assert_eq!(integer(&rows[1], "model_sampled_pictures")?, 0);
    assert_eq!(
        integer(value(&rows[1], "allocation")?, "budget_skipped_bursts")?,
        2
    );
    assert_eq!(value(&rows[1], "sentinel")?, &Value::Null);
    assert!(!boolean(&rows[1], "quiet_scene_proved")?);
    for command in value(&skipped, "native_sentinel_reruns")?
        .array()
        .ok_or("commands")?
    {
        assert_eq!(value(command, "command")?, &Value::Null);
        assert!(!boolean(command, "analysis_retained")?);
    }
    // Give both attempts a model call but only the measured decode allowance for one. The
    // second must refuse rather than receive a renewed per-attempt campaign pixel pool.
    let one_attempt_pixels = integer(
        value(value(&skipped, "report")?, "usage")?,
        "pixel_pool_charged",
    )?;
    assert!(one_attempt_pixels > 0);
    let root = directory.0.join("one shared decode allowance");
    let selected = requests(&directory, &root, &preview, &native)?;
    let mut input = args(&directory, &root, pin, &model, &selected)?;
    set(&mut input, "--retain-analysis", "no");
    set(
        &mut input,
        "--stream-pixel-budget",
        &one_attempt_pixels.to_string(),
    );
    let refused = run_with_timeout("sentinel-campaign", &approve(&input)?, INFERENCE_DEADLINE)?;
    assert!(
        !refused.status.success(),
        "whole-campaign pixel pool was renewed"
    );
    assert!(
        refused.stdout.is_empty(),
        "partial campaign inference report escaped"
    );
    assert!(
        root.exists(),
        "imports should precede strict native analysis"
    );

    for ordinal in 1..=2 {
        for prefix in ["capture", "pins"] {
            fs::rename(
                epoch_path(&directory, prefix, ordinal),
                directory.0.join(format!("offline-{prefix}-{ordinal}")),
            )?;
        }
    }
    let root = directory.0.join("exact earlier start");
    let input = args(&directory, &root, &pins[0], &model, &[None])?;
    let started = completed(&approve(&input)?)?;
    let rows = attempts(&started)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(text(&rows[0], "status")?, "started_without_retained_finish");
    assert_eq!(value(&rows[0], "recorded_durable_pictures")?, &Value::Null);
    assert_eq!(value(&rows[0], "sentinel")?, &Value::Null);
    assert_eq!(value(&rows[0], "retained")?, &Value::Null);
    assert_eq!(
        integer(value(&started, "archive_io")?, "total_read_bytes")?,
        0
    );
    let history = value(value(&started, "report")?, "history")?;
    assert_eq!(integer(history, "records")?, 1);
    assert_eq!(integer(history, "planned_attempts")?, 2);
    assert_eq!(value(history, "terminal")?, &Value::Null);
    assert_eq!(tree(&directory.0.join("history"))?, history_before);
    no_connection(&camera)?;
    Ok(())
}

#[test]
fn model_history_custody_and_owner_refusals_precede_source_recovery_or_destination_creation() -> Test
{
    let directory = Directory::new("campaign-sentinel-admission")?;
    let camera = listener()?;
    let (capture, preview) = campaign_approval(&history_args(&directory, camera.local_addr()?))?;
    let (captured, _) = capture_sessions(
        &camera,
        &capture,
        &[Behavior::StaticTarget, Behavior::StaticTarget],
    )?;
    assert!(captured.status.success());
    let pins = receipts(&captured)?;
    let pin = pins.last().ok_or("terminal pin")?;
    let (_, native) = campaign_rows(&captured)?;
    let model = package(&directory)?;
    let history_before = tree(&directory.0.join("history"))?;
    let source_before = tree(&epoch_path(&directory, "capture", 1))?;
    for case in 0..10 {
        let root = if case == 9 {
            epoch_path(&directory, "pins", 2).join("forbidden-destination")
        } else {
            directory.0.join(format!("never-created-{case}"))
        };
        let mut selected = requests(&directory, &root, &preview, &native)?;
        if (2..=4).contains(&case) {
            let second = selected[1].as_mut().ok_or("second request")?;
            let (key, replacement) = match case {
                2 => (
                    "--archive",
                    epoch_path(&directory, "capture", 1).display().to_string(),
                ),
                3 => ("--anchor", digest("reinterpreted original source scope")),
                _ => (
                    "--catalog-pages",
                    format!("invented-catalog@{}", digest("not the selected saved page")),
                ),
            };
            let at = second
                .iter()
                .position(|part| part == key)
                .ok_or("native option")?;
            second[at + 1] = replacement;
        } else if case == 5 {
            selected[1] = None;
        } else if case == 8 {
            for child in selected.iter_mut().flatten() {
                child.extend(["--principal".into(), "principal:another-operator".into()]);
            }
        }
        let mut input = args(&directory, &root, pin, &model, &selected)?;
        match case {
            1 => set(
                &mut input,
                "--package-digest",
                &digest("wrong expected package"),
            ),
            6 => set(&mut input, "--archive-read-bytes", "1"),
            7 => set(
                &mut input,
                "--history-root-digest",
                &digest("wrong saved prefix"),
            ),
            8 => set(&mut input, "--principal", "principal:another-operator"),
            _ => {}
        }
        let mut approved = approve(&input)?;
        if case == 0 {
            set(
                &mut approved,
                "--approve-import",
                &digest("wrong outer approval"),
            );
        }
        let refused = run_with_timeout("sentinel-campaign", &approved, INFERENCE_DEADLINE)?;
        assert!(!refused.status.success(), "refusal case {case} succeeded");
        assert!(
            refused.stdout.is_empty(),
            "case {case} emitted partial success"
        );
        assert!(
            !root.exists(),
            "case {case} created destination before full admission"
        );
        assert_eq!(tree(&directory.0.join("history"))?, history_before);
        if case <= 5 {
            assert_eq!(
                tree(&epoch_path(&directory, "capture", 1))?,
                source_before,
                "case {case} opened a native source owner before source/model admission"
            );
        }
        no_connection(&camera)?;
    }
    Ok(())
}

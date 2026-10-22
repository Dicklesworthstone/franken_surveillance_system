#![forbid(unsafe_code)]
//! Owned native RTSP camera → saved campaign prefix → independent custody → native watch rerun.

use super::*;
use fss_cli::agent_json::{array, object, string};

fn request(
    directory: &Directory,
    root: &Path,
    child: &Value,
    native: &[Value],
    ordinal: usize,
) -> Test<Option<Vec<String>>> {
    let catalogs = native
        .iter()
        .filter(|row| text(row, "kind").ok() == Some("catalog_published"))
        .map(|row| value(row, "detail"))
        .collect::<Test<Vec<_>>>()?;
    let Some(first) = catalogs.first() else {
        return Ok(None);
    };
    let pages = catalogs
        .iter()
        .map(|catalog| {
            Ok(format!(
                "{}@{}",
                text(catalog, "slot")?,
                text(catalog, "root")?
            ))
        })
        .collect::<Test<Vec<_>>>()?
        .join(",");
    Ok(Some(
        [
            (
                "--archive",
                epoch_path(directory, "capture", ordinal)
                    .display()
                    .to_string(),
            ),
            ("--root", root.display().to_string()),
            ("--site", SITE.into()),
            ("--catalog-pages", pages),
            ("--decode-clock", text(first, "decode_clock")?.into()),
            ("--time-scale", integer(first, "time_scale")?.to_string()),
            ("--codec", "avc".into()),
            ("--sensor-id", SENSOR.into()),
            ("--stream-id", STREAM.into()),
            ("--generation", ordinal.to_string()),
            ("--anchor", digest("capture CLI authority anchor")),
            ("--receive-clock", text(child, "receive_clock")?.into()),
            ("--receive-time-ns", "5000000000".into()),
            (
                "--capture-start-ns",
                ((ordinal - 1) as u64 * 1_000_000_000).to_string(),
            ),
            ("--capture-uncertainty-ns", "1000".into()),
            ("--max-frames", "4".into()),
            ("--max-windows", "4".into()),
            ("--max-pages", "4".into()),
            ("--max-original-bytes", "1048576".into()),
            ("--max-media-bytes", "1048576".into()),
            ("--owner-authorized", "yes".into()),
            ("--read-originals", "yes".into()),
            ("--retain-originals", "yes".into()),
        ]
        .into_iter()
        .flat_map(|(key, value): (&str, String)| [key.to_owned(), value])
        .collect(),
    ))
}

fn requests_json(requests: &[Option<Vec<String>>]) -> String {
    array(
        &requests
            .iter()
            .enumerate()
            .map(|(index, request)| {
                object(&[
                    ("ordinal", (index + 1).to_string()),
                    (
                        "request",
                        request.as_ref().map_or_else(
                            || "null".into(),
                            |args| array(&args.iter().map(|part| string(part)).collect::<Vec<_>>()),
                        ),
                    ),
                ])
            })
            .collect::<Vec<_>>(),
    )
}

fn watch_args(
    directory: &Directory,
    root: &Path,
    pin: &Value,
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
        ("--requests", requests_json(requests)),
        ("--interpretation", "ycbcr".into()),
        ("--zone", "entry:0,0,160,128".into()),
        ("--owner-authorized", "yes".into()),
        ("--read-originals", "yes".into()),
        ("--retain-originals", "yes".into()),
        ("--pixel-threshold", "1".into()),
        ("--threshold-sigma", "1".into()),
        ("--min-region-pixels", "1".into()),
        ("--confirmation-hits", "1".into()),
        // The source is 160×128. A non-multiple checks exact campaign→event AVC budget parity.
        ("--max-pixels", "20481".into()),
        ("--timeout-ms", "600000".into()),
    ]
    .into_iter()
    .flat_map(|(key, value): (&str, String)| [OsString::from(key), OsString::from(value)])
    .collect())
}

fn approve_watch(input: &[OsString]) -> Test<Vec<OsString>> {
    let preview = parse(&good(run("watch-campaign", input)?)?)?;
    assert_eq!(text(&preview, "kind")?, "plan");
    assert_eq!(text(&preview, "writes")?, "none_until_exact_outer_approval");
    let mut approved = input.to_vec();
    approved.extend([
        "--approve-import".into(),
        text(&preview, "approval_digest")?.into(),
    ]);
    Ok(approved)
}

fn report(output: Output) -> Test<Value> {
    Ok(parse(&good(output)?)?)
}
fn attempt_rows(report: &Value) -> Test<&[Value]> {
    Ok(value(value(report, "report")?, "attempts")?
        .array()
        .ok_or("campaign rows")?)
}
fn journal_snapshot(root: &Path) -> Test<(Vec<u8>, Vec<u8>)> {
    Ok((
        fs::read(root.join("ledger/journal.fssj"))?,
        fs::read(root.join("effects/journal.fssj"))?,
    ))
}

// Execute only the native binary; this decodes the small shell-quoted argument format emitted
// by its report without invoking a shell, environment expansion or command substitution.
fn command_words(command: &str) -> Test<Vec<OsString>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    let mut characters = command.chars();
    while let Some(character) = characters.next() {
        match character {
            '\'' => quoted = !quoted,
            '\\' if !quoted => word.push(characters.next().ok_or("dangling escape")?),
            character if character.is_whitespace() && !quoted => {
                if !word.is_empty() {
                    words.push(OsString::from(std::mem::take(&mut word)));
                }
            }
            character => word.push(character),
        }
    }
    if quoted {
        return Err("unterminated emitted quote".into());
    }
    if !word.is_empty() {
        words.push(word.into());
    }
    if words.first().is_none_or(|word| word != "fss-event") {
        return Err("unexpected rerun binary".into());
    }
    Ok(words)
}

#[test]
fn two_native_archives_and_empty_failed_attempt_survive_retry_and_cold_exact_watch_reruns() -> Test
{
    let directory = Directory::new("campaign-watch-native")?;
    let camera = listener()?;
    let mut input = history_args(&directory, camera.local_addr()?);
    set(&mut input, "--max-attempts", "3");
    let (approved, preview) = campaign_approval(&input)?;
    let (captured, transcripts) = capture_sessions(
        &camera,
        &approved,
        &[
            Behavior::Target,
            Behavior::Target,
            Behavior::AuthenticationRequired,
        ],
    )?;
    assert!(!captured.status.success());
    assert_eq!(transcripts.len(), 3);
    let pins = receipts(&captured)?;
    let pin = pins.last().ok_or("terminal pin")?;
    let (_, native) = campaign_rows(&captured)?;
    let children = value(&preview, "attempts")?.array().ok_or("child plans")?;
    let root = directory.0.join("analysis deployment's data");
    let requests = native
        .iter()
        .enumerate()
        .map(|(index, native)| request(&directory, &root, &children[index], native, index + 1))
        .collect::<Test<Vec<_>>>()?;
    assert!(requests[0].is_some() && requests[1].is_some() && requests[2].is_none());
    // No-catalog attempts must not open their archive/pin owner, even if that owner is offline.
    for prefix in ["capture", "pins"] {
        let path = epoch_path(&directory, prefix, 3);
        if path.exists() {
            fs::rename(path, directory.0.join(format!("offline-{prefix}-3")))?;
        }
    }
    let history_before = tree(&directory.0.join("history"))?;
    let pin_bytes = (1..=2)
        .map(|ordinal| fs::read(epoch_path(&directory, "pins", ordinal).join("pins.journal")))
        .collect::<Result<Vec<_>, _>>()?;
    let input = watch_args(&directory, &root, pin, &requests)?;
    let approved = approve_watch(&input)?;
    assert!(!root.exists(), "campaign watch preview created destination");
    assert_eq!(tree(&directory.0.join("history"))?, history_before);
    no_connection(&camera)?;
    let first = report(run("watch-campaign", &approved)?)?;
    let native_report = value(&first, "report")?;
    assert!(boolean(native_report, "campaign_history_verified")?);
    assert!(!boolean(native_report, "latest_history_verified")?);
    assert!(!boolean(
        native_report,
        "tracker_continuity_across_attempts"
    )?);
    assert!(!boolean(native_report, "absence_certifiable")?);
    assert!(!boolean(&first, "event_publication_authorized")?);
    let attempts = attempt_rows(&first)?;
    assert_eq!(attempts.len(), 3);
    for attempt in &attempts[..2] {
        assert_eq!(text(attempt, "status")?, "analyzed");
        assert_eq!(integer(attempt, "catalogued_pictures")?, 2);
        assert_eq!(integer(attempt, "decoded_pictures")?, 2);
        assert_eq!(integer(attempt, "recorded_pictures_without_catalog")?, 0);
        assert!(boolean(attempt, "original_rtp_custody_verified")?);
        assert!(boolean(value(attempt, "finish")?, "settled_success")?);
        let watch = value(attempt, "watch")?;
        assert_eq!(
            integer(watch, "analysis_basis_sequence")?,
            integer(native_report, "analysis_basis_sequence")?
        );
        assert!(
            integer(watch, "candidate_count")? > 0,
            "native changing pixels produced no candidate"
        );
    }
    assert_ne!(
        text(value(&attempts[0], "import")?, "identity")?,
        text(value(&attempts[1], "import")?, "identity")?
    );
    assert_eq!(
        text(&attempts[2], "status")?,
        "recorded_no_durable_pictures"
    );
    assert_eq!(integer(&attempts[2], "recorded_durable_pictures")?, 0);
    assert_eq!(value(&attempts[2], "watch")?, &Value::Null);
    assert_eq!(
        text(value(value(&attempts[2], "finish")?, "native")?, "error_id")?,
        "ERR-CAPTURE-RTSP-AUTH-UNSUPPORTED-001"
    );
    let native_history = value(native_report, "history")?;
    assert!(!boolean(value(native_history, "terminal")?, "complete")?);
    let io = value(&first, "archive_io")?;
    assert!(integer(io, "startup_read_bytes")? > 0);
    assert!(integer(io, "total_read_bytes")? > integer(io, "startup_read_bytes")?);
    let snapshot = journal_snapshot(&root)?;
    let retried = report(run("watch-campaign", &approved)?)?;
    for (old, repeated) in attempts[..2].iter().zip(&attempt_rows(&retried)?[..2]) {
        assert!(boolean(value(repeated, "import")?, "reused")?);
        assert_eq!(
            text(value(old, "watch")?, "analysis_digest")?,
            text(value(repeated, "watch")?, "analysis_digest")?
        );
    }
    assert_eq!(
        journal_snapshot(&root)?,
        snapshot,
        "exact campaign retry changed import/effect journals"
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
    // Original source archives may be offline: rerun consumes only destination custody. The
    // non-multiple max-pixels option must preserve the exact native analysis digest and proposal.
    let commands = value(&first, "native_watch_reruns")?
        .array()
        .ok_or("commands")?;
    assert_eq!(commands.len(), 3);
    assert_eq!(value(&commands[2], "command")?, &Value::Null);
    for index in 0..2 {
        let words = command_words(text(&commands[index], "command")?)?;
        let rerun = report(run("event", &words[1..])?)?;
        let watch = value(&attempts[index], "watch")?;
        assert_eq!(
            text(&rerun, "analysis_digest")?,
            text(watch, "analysis_digest")?
        );
        assert_eq!(
            integer(&rerun, "candidate_count")?,
            integer(watch, "candidate_count")?
        );
        let original_candidates = value(watch, "candidates")?.array().ok_or("candidates")?;
        let rerun_candidates = value(&rerun, "candidates")?
            .array()
            .ok_or("rerun candidates")?;
        for (original, recomputed) in original_candidates.iter().zip(rerun_candidates) {
            assert_eq!(
                text(original, "proposal_digest")?,
                text(recomputed, "proposal_digest")?
            );
        }
    }
    assert_eq!(
        journal_snapshot(&root)?,
        snapshot,
        "read-only native reruns published an event/effect"
    );
    no_connection(&camera)?;
    Ok(())
}

#[test]
fn older_start_only_prefix_stays_unknown_even_when_later_success_exists() -> Test {
    let directory = Directory::new("campaign-watch-prefix")?;
    let camera = listener()?;
    let (approved, _) = campaign_approval(&history_args(&directory, camera.local_addr()?))?;
    let (captured, _) =
        capture_sessions(&camera, &approved, &[Behavior::Target, Behavior::Target])?;
    assert!(captured.status.success());
    let pins = receipts(&captured)?;
    let earliest = pins.first().ok_or("first start pin")?;
    let history_before = tree(&directory.0.join("history"))?;
    for ordinal in 1..=2 {
        for prefix in ["capture", "pins"] {
            fs::rename(
                epoch_path(&directory, prefix, ordinal),
                directory.0.join(format!("offline-{prefix}-{ordinal}")),
            )?;
        }
    }
    let root = directory.0.join("prefix deployment");
    let input = approve_watch(&watch_args(&directory, &root, earliest, &[None])?)?;
    assert!(!root.exists());
    let observed = report(run("watch-campaign", &input)?)?;
    let native = value(&observed, "report")?;
    let history = value(native, "history")?;
    assert_eq!(integer(history, "records")?, 1);
    assert_eq!(integer(history, "selected_started_attempts")?, 1);
    assert_eq!(integer(history, "planned_attempts")?, 2);
    assert_eq!(value(history, "terminal")?, &Value::Null);
    let attempts = attempt_rows(&observed)?;
    assert_eq!(attempts.len(), 1);
    assert_eq!(
        text(&attempts[0], "status")?,
        "started_without_retained_finish"
    );
    assert_eq!(value(&attempts[0], "finish")?, &Value::Null);
    assert_eq!(
        value(&attempts[0], "recorded_durable_pictures")?,
        &Value::Null
    );
    assert_eq!(
        integer(value(&observed, "archive_io")?, "total_read_bytes")?,
        0
    );
    assert_eq!(tree(&directory.0.join("history"))?, history_before);
    no_connection(&camera)?;
    Ok(())
}

#[test]
fn history_scope_path_page_and_budget_refusals_precede_destination_imports() -> Test {
    let directory = Directory::new("campaign-watch-refusals")?;
    let camera = listener()?;
    let (approved, preview) = campaign_approval(&history_args(&directory, camera.local_addr()?))?;
    let (captured, _) =
        capture_sessions(&camera, &approved, &[Behavior::Target, Behavior::Target])?;
    assert!(captured.status.success());
    let pins = receipts(&captured)?;
    let pin = pins.last().ok_or("terminal")?;
    let (_, native) = campaign_rows(&captured)?;
    let children = value(&preview, "attempts")?.array().ok_or("children")?;
    let history_before = tree(&directory.0.join("history"))?;
    for case in 0..11 {
        let root = if case == 10 {
            epoch_path(&directory, "pins", 2).join("must-remain-absent")
        } else {
            directory.0.join(format!("must-remain-absent-{case}"))
        };
        let mut requests = native
            .iter()
            .enumerate()
            .map(|(index, native)| request(&directory, &root, &children[index], native, index + 1))
            .collect::<Test<Vec<_>>>()?;
        if case < 4 {
            let second = requests[1].as_mut().ok_or("second request")?;
            let (key, replacement) = match case {
                0 => (
                    "--archive",
                    epoch_path(&directory, "capture", 1).display().to_string(),
                ),
                1 => (
                    "--anchor",
                    digest("incorrect reinterpreted source authority"),
                ),
                2 => ("--receive-clock", digest("wrong receive clock")),
                _ => (
                    "--catalog-pages",
                    format!("other-page@{}", digest("wrong saved catalog")),
                ),
            };
            let index = second
                .iter()
                .position(|part| part == key)
                .ok_or("child option")?;
            second[index + 1] = replacement;
        } else if case == 4 {
            requests[1] = None;
        } else if case == 9 {
            // Keep child/outer ownership internally consistent so current history authority,
            // rather than the pure parser's same-owner guard, refuses this principal.
            for child in requests.iter_mut().flatten() {
                child.extend(["--principal".into(), "principal:another-operator".into()]);
            }
        }
        let mut input = watch_args(&directory, &root, pin, &requests)?;
        match case {
            5 => set(&mut input, "--max-work", "1"),
            6 => set(&mut input, "--archive-read-bytes", "1"),
            7 => set(
                &mut input,
                "--history-root-digest",
                &digest("wrong independently selected history root"),
            ),
            8 => set(&mut input, "--history-records", "4"),
            9 => set(&mut input, "--principal", "principal:another-operator"),
            _ => {}
        }
        let approved = approve_watch(&input)?;
        let refused = run("watch-campaign", &approved)?;
        assert!(
            !refused.status.success(),
            "refusal case {case} unexpectedly succeeded"
        );
        assert!(
            refused.stdout.is_empty(),
            "case {case}: partial or misleading report"
        );
        assert!(
            !root.exists(),
            "case {case}: destination created before full source admission"
        );
        assert_eq!(tree(&directory.0.join("history"))?, history_before);
        no_connection(&camera)?;
    }
    Ok(())
}

#[test]
fn failed_eof_prefix_is_analyzed_without_promoting_the_campaign_to_success() -> Test {
    let directory = Directory::new("campaign-watch-partial")?;
    let camera = listener()?;
    let (approved, preview) = campaign_approval(&history_args(&directory, camera.local_addr()?))?;
    let (captured, _) = capture_sessions(
        &camera,
        &approved,
        &[Behavior::EofAfterOne, Behavior::Target],
    )?;
    assert!(!captured.status.success());
    let pins = receipts(&captured)?;
    let (_, native) = campaign_rows(&captured)?;
    let children = value(&preview, "attempts")?.array().ok_or("children")?;
    let root = directory.0.join("partial deployment");
    let requests = native
        .iter()
        .enumerate()
        .map(|(index, native)| request(&directory, &root, &children[index], native, index + 1))
        .collect::<Test<Vec<_>>>()?;
    let input = approve_watch(&watch_args(
        &directory,
        &root,
        pins.last().ok_or("terminal")?,
        &requests,
    )?)?;
    let processed = report(run("watch-campaign", &input)?)?;
    let attempts = attempt_rows(&processed)?;
    assert_eq!(attempts.len(), 2);
    assert_eq!(text(&attempts[0], "status")?, "analyzed");
    assert_eq!(integer(&attempts[0], "catalogued_pictures")?, 1);
    assert_eq!(integer(&attempts[0], "decoded_pictures")?, 1);
    let failure = value(&attempts[0], "finish")?;
    assert!(!boolean(failure, "settled_success")?);
    assert_eq!(
        text(value(failure, "native")?, "error_id")?,
        "ERR-CAPTURE-RTSP-SHORTFALL-001"
    );
    assert_eq!(integer(&attempts[1], "decoded_pictures")?, 2);
    assert!(!boolean(
        value(value(value(&processed, "report")?, "history")?, "terminal")?,
        "complete"
    )?);
    no_connection(&camera)?;
    Ok(())
}

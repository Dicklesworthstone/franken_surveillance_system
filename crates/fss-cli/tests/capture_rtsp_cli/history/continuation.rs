#![forbid(unsafe_code)]
//! Kill after an independently delivered native finish, then resume only the unused schedule.

use super::*;
use std::io::{BufRead, BufReader};

fn stop_after_retained_finish(input: &[OsString]) -> Test<Output> {
    const MAX_OUTPUT: u64 = 1024 * 1024;
    let mut child = Command::new(binary("capture")?)
        .args(input)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("stdout")?;
    let stderr = child.stderr.take().ok_or("stderr")?;
    let observed = AtomicBool::new(false);
    let exceeded = AtomicBool::new(false);
    thread::scope(|scope| {
        let observed = &observed;
        let exceeded = &exceeded;
        let stdout = scope.spawn(move || -> Test<Vec<u8>> {
            let mut reader = BufReader::new(stdout.take(MAX_OUTPUT + 1));
            let mut bytes = Vec::new();
            let mut selected_end = None;
            loop {
                let start = bytes.len();
                let count = reader.read_until(b'\n', &mut bytes)?;
                if bytes.len() as u64 > MAX_OUTPUT {
                    exceeded.store(true, Ordering::Release);
                    return Err("bounded output exceeded".into());
                }
                if count == 0 {
                    // Killing may cut a later progress row. Select only the complete receipt
                    // prefix delivered before the kill; no later observation is asserted.
                    if let Some(end) = selected_end {
                        bytes.truncate(end);
                    }
                    return Ok(bytes);
                }
                if bytes.last() != Some(&b'\n') {
                    // A killed child may leave even a UTF-8 codepoint incomplete.
                    continue;
                }
                if let Ok(row) = parse(std::str::from_utf8(&bytes[start..])?)
                    && text(&row, "kind").ok() == Some("history_durable")
                    && value(&row, "detail").is_ok_and(|detail| {
                        text(detail, "transition").ok() == Some("attempt_finished")
                    })
                {
                    selected_end.get_or_insert(bytes.len());
                    observed.store(true, Ordering::Release);
                }
            }
        });
        let stderr = scope.spawn(move || output_bytes(stderr, exceeded));
        let deadline = Instant::now() + Duration::from_secs(20);
        let status = loop {
            if observed.load(Ordering::Acquire)
                || exceeded.load(Ordering::Acquire)
                || Instant::now() >= deadline
            {
                let _ = child.kill();
                break child.wait();
            }
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => thread::sleep(Duration::from_millis(2)),
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(error);
                }
            }
        };
        let output = Output {
            status: status?,
            stdout: stdout.join().map_err(|_| "stdout panicked")??,
            stderr: stderr.join().map_err(|_| "stderr panicked")??,
        };
        assert!(
            observed.load(Ordering::Acquire),
            "missing finish: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(output)
    })
}

fn continuation_args(input: &[OsString], pin: &Value, retry: bool) -> Test<Vec<OsString>> {
    let mut continued = input.to_vec();
    for (option, field) in [
        ("--continue-history-approval", "approval"),
        ("--continue-history-plan", "plan"),
        ("--continue-history-root-digest", "root"),
    ] {
        set(&mut continued, option, text(pin, field)?);
    }
    set(
        &mut continued,
        "--continue-history-records",
        &integer(pin, "records")?.to_string(),
    );
    if retry {
        set(&mut continued, "--continue-retry-history", "yes");
    }
    Ok(continued)
}

#[test]
fn native_failed_prefix_continues_after_restart_without_erasing_failure_or_reusing_an_epoch() -> Test
{
    cold_failed_prefix(true)
}

#[test]
fn native_ordinary_reconnect_continues_after_restart_and_stops_at_first_success() -> Test {
    cold_failed_prefix(false)
}

fn cold_failed_prefix(continue_after_success: bool) -> Test {
    let directory = Directory::new(if continue_after_success {
        "cold-campaign-retry"
    } else {
        "cold-ordinary-retry"
    })?;
    let camera = listener()?;
    let mut input = history_args(&directory, camera.local_addr()?);
    if !continue_after_success {
        let at = input
            .iter()
            .position(|part| part == "--continue-after-success")
            .ok_or("campaign option")?;
        input.drain(at..at + 2);
        // The original third attempt must remain unused once ordinary reconnect succeeds.
        set(&mut input, "--max-attempts", "3");
    }
    // The parent kills only after the exact finish receipt arrives, well inside this pause.
    set(&mut input, "--retry-delay-ms", "5000");
    set(&mut input, "--retry-max-delay-ms", "5000");
    let (approved, original) = campaign_approval(&input)?;
    let output = thread::scope(|scope| -> Test<Output> {
        let listener = camera.try_clone()?;
        let server = scope.spawn(move || serve(listener, Behavior::EofAfterOne));
        let output = stop_after_retained_finish(&approved);
        server.join().map_err(|_| "camera panicked")??;
        output
    })?;
    let pins = receipts(&output)?;
    assert_eq!(pins.len(), 2);
    let finish = &pins[1];
    assert_eq!(integer(finish, "records")?, 2);
    assert!(!epoch_path(&directory, "capture", 2).exists());
    let first_archive = tree(&epoch_path(&directory, "capture", 1))?;
    let first_pins = tree(&epoch_path(&directory, "pins", 1))?;
    let history_before = tree(&directory.0.join("history"))?;

    let success_only = continuation_args(&input, finish, false)?;
    let (success_approved, obsolete_approval) = if continue_after_success {
        let (approved, preview) = campaign_approval(&success_only)?;
        (approved, text(&preview, "approval")?.to_owned())
    } else {
        // Ordinary retry has no settled-success-prefix continuation mode.
        (success_only, text(&original, "approval")?.to_owned())
    };
    let refused = run("capture", &success_approved)?;
    assert!(
        !refused.status.success(),
        "success-only approval adopted a failure"
    );
    assert_eq!(tree(&directory.0.join("history"))?, history_before);
    no_connection(&camera)?;

    let retry = continuation_args(&input, finish, true)?;
    let (retry_approved, retry_preview) = campaign_approval(&retry)?;
    assert_ne!(text(&retry_preview, "approval")?, obsolete_approval);
    assert_eq!(
        value(&retry_preview, "attempts")?,
        value(&original, "attempts")?
    );
    let mut stale_approval = retry.clone();
    set(&mut stale_approval, "--approve", &obsolete_approval);
    assert!(!run("capture", &stale_approval)?.status.success());
    let mut changed_scope = retry.clone();
    set(&mut changed_scope, "--generation", "2");
    assert!(!run("capture", &changed_scope)?.status.success());
    let start_only = continuation_args(&input, &pins[0], true)?;
    assert!(!run("capture", &start_only)?.status.success());
    assert_eq!(tree(&directory.0.join("history"))?, history_before);
    no_connection(&camera)?;

    let (output, transcripts) = capture_sessions(&camera, &retry_approved, &[Behavior::Target])?;
    assert_eq!(
        output.status.success(),
        !continue_after_success,
        "the original ordinary/campaign completion rule changed; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(transcripts.len(), 1);
    let (rows, native) = campaign_rows(&output)?;
    assert_eq!(native.len(), 1);
    let resumed = detail(&rows, "continuation_resumed")?;
    assert_eq!(integer(resumed, "prior_attempts")?, 1);
    assert_eq!(
        integer(resumed, "remaining_original_attempts")?,
        if continue_after_success { 1 } else { 2 }
    );
    assert_eq!(integer(resumed, "durable_pictures_prior_attempts")?, 1);
    assert!(!boolean(resumed, "historical_budget_refunded")?);
    let terminal = detail(&rows, "reconnect_terminal")?;
    assert_eq!(integer(terminal, "attempts_used")?, 2);
    assert_eq!(integer(terminal, "successful_attempts")?, 1);
    assert_eq!(integer(terminal, "unsuccessful_attempts")?, 1);
    assert_eq!(integer(terminal, "first_failed_attempt")?, 1);
    assert_eq!(integer(terminal, "durable_pictures_all_attempts")?, 3);
    assert_eq!(
        text(terminal, "first_error_id")?,
        "ERR-CAPTURE-RTSP-SHORTFALL-001"
    );
    if continue_after_success {
        assert_eq!(
            text(terminal, "error_id")?,
            "ERR-CAPTURE-RTSP-SHORTFALL-001"
        );
        assert!(!boolean(terminal, "complete")?);
    } else {
        assert_eq!(value(terminal, "error_id")?, &Value::Null);
        assert!(boolean(terminal, "complete")?);
        assert!(!boolean(terminal, "attempt_limit_reached")?);
        assert_eq!(
            text(terminal, "completion_scope")?,
            "first_successful_attempt"
        );
        assert!(!epoch_path(&directory, "capture", 3).exists());
        assert!(!epoch_path(&directory, "pins", 3).exists());
    }
    assert!(!boolean(terminal, "continuity_across_attempts")?);
    assert_eq!(tree(&epoch_path(&directory, "capture", 1))?, first_archive);
    assert_eq!(tree(&epoch_path(&directory, "pins", 1))?, first_pins);
    let remaining_pins = receipts(&output)?;
    assert_eq!(integer(&remaining_pins[0], "records")?, 3);
    let terminal_pin = remaining_pins.last().ok_or("terminal pin")?;
    let cold = parse(&good(run(
        "capture",
        &inspect_args(&directory, terminal_pin)?,
    )?)?)?;
    assert_eq!(
        text(&cold, "campaign_completion")?,
        if continue_after_success {
            "observed_failed"
        } else {
            "observed_complete"
        }
    );
    assert_eq!(integer(&cold, "observed_finished_attempts")?, 2);
    let final_history = tree(&directory.0.join("history"))?;
    assert!(
        !run("capture", &retry_approved)?.status.success(),
        "old finish reused a started epoch"
    );
    let exhausted = continuation_args(&input, terminal_pin, true)?;
    assert!(!run("capture", &exhausted)?.status.success());
    assert_eq!(tree(&directory.0.join("history"))?, final_history);
    no_connection(&camera)?;
    Ok(())
}

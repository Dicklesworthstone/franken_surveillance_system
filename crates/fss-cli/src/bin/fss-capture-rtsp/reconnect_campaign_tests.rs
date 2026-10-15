#![forbid(unsafe_code)]
//! Deterministic campaign contracts. No files, credentials, sockets or timers are opened.

use super::*;
use crate::driver::RetryReason;
use std::collections::VecDeque;

fn args() -> Vec<OsString> {
    [
        "--root", "/owner/private/archive",
        "--pins", "/owner/private/pins",
        "--peer", "127.0.0.1:8554",
        "--authority", "camera.test:8554",
        "--presentation", "/camera/main",
        "--control-root", "/camera",
        "--sensor-id", "sensor:camera",
        "--stream-id", "stream:main",
        "--generation", "1",
        "--ingress", "1",
        "--ssrc", "7",
        "--anchor", "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "--receive-clock", "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "--timing-evidence", "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        "--journal-id", "sha256:4444444444444444444444444444444444444444444444444444444444444444",
        "--frame-duration-ticks", "3600",
        "--stop-after-pictures", "2",
        "--owner-authorized", "yes",
        "--plaintext", "yes",
        "--retain-originals", "yes",
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn set(input: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(index) = input.iter().position(|argument| argument == key) {
        input[index + 1] = OsString::from(value);
    } else {
        input.extend([OsString::from(key), OsString::from(value)]);
    }
}

fn approve(input: &[OsString]) -> ReconnectPlan {
    let mut plan = ReconnectPlan::parse(input).expect("valid pure plan");
    plan.approve = Some(plan.digest().expect("outer digest"));
    for attempt in &mut plan.attempts {
        attempt.approve = Some(attempt.digest().expect("child digest"));
    }
    plan
}

fn campaign_args() -> Vec<OsString> {
    let mut input = args();
    set(&mut input, "--continue-after-success", "yes");
    input
}

fn success() -> AttemptOutcome {
    AttemptOutcome {
        result: Ok(()),
        retry: Some(RetryReason::SettledSuccess),
        recovery_required: false,
        durable_pictures: 2,
    }
}

fn shortfall() -> AttemptOutcome {
    // Use the real driver's retry enum rather than a second policy implementation.
    AttemptOutcome {
        result: Err("source_shortfall"),
        retry: Some(RetryReason::SourceEnded),
        recovery_required: false,
        durable_pictures: 1,
    }
}

#[derive(Default)]
struct Script {
    outcomes: VecDeque<Result<AttemptOutcome, &'static str>>,
    generations: Vec<u64>,
    rows: Vec<(String, String)>,
    waits: Vec<u64>,
    cancelled: bool,
    cancel_on_wait: bool,
    fail_row: Option<&'static str>,
}

impl Script {
    fn outcomes(outcomes: impl IntoIterator<Item = AttemptOutcome>) -> Self {
        Self {
            outcomes: outcomes.into_iter().map(Ok).collect(),
            ..Self::default()
        }
    }

    fn terminal(&self) -> &str {
        let mut rows = self.rows.iter().filter(|(kind, _)| kind == "reconnect_terminal");
        let (_, row) = rows.next().expect("one terminal receipt");
        assert!(rows.next().is_none(), "exactly one terminal receipt");
        row.as_str()
    }
}

impl Effects for Script {
    fn checkpoint(&mut self) -> Result<(), &'static str> {
        if self.cancelled {
            Err("cancelled")
        } else {
            Ok(())
        }
    }

    fn emit(&mut self, kind: &str, detail: String) -> Result<(), &'static str> {
        if self.fail_row == Some(kind) {
            return Err("output_failed");
        }
        self.rows.push((kind.into(), detail));
        Ok(())
    }

    fn capture(&mut self, options: &Options) -> Result<AttemptOutcome, &'static str> {
        assert_eq!(options.approve, Some(options.digest().expect("exact child approval")));
        self.generations.push(options.recording_config().scope.generation);
        self.outcomes.pop_front().expect("no unplanned session")
    }

    fn pause(&mut self, milliseconds: u64) -> Result<(), &'static str> {
        self.waits.push(milliseconds);
        if self.cancel_on_wait {
            self.cancelled = true;
        }
        Ok(())
    }
}

#[test]
fn legacy_success_stops_after_one_session() {
    let plan = approve(&args());
    let mut script = Script::outcomes([success()]);
    assert_eq!(run(&plan, &mut script), Ok(()));
    assert_eq!(script.generations, [1]);
    assert!(script.waits.is_empty());
    assert!(!plan.preview().expect("preview").contains("campaign_policy"));
    assert!(!script.terminal().contains("completion_scope"));
}

#[test]
fn campaign_approval_does_not_reuse_legacy_or_child_approval() {
    let legacy = approve(&args());
    let mut campaign = approve(&campaign_args());
    assert_ne!(legacy.digest().expect("legacy"), campaign.digest().expect("campaign"));
    // Repeated capture changes the outer authority, not codec/route/custody or child budgets.
    for (old, new) in legacy.attempts.iter().zip(&campaign.attempts) {
        assert_eq!(old.digest().expect("old child"), new.digest().expect("new child"));
    }
    assert_eq!(legacy.maximum_source_bytes, campaign.maximum_source_bytes);
    assert_eq!(legacy.maximum_storage_bytes, campaign.maximum_storage_bytes);
    assert_eq!(legacy.maximum_report_bytes, campaign.maximum_report_bytes);
    assert_eq!(legacy.maximum_capture_ns, campaign.maximum_capture_ns);
    assert_eq!(legacy.maximum_backoff_ms, campaign.maximum_backoff_ms);
    for approval in [None, legacy.approve, Some(campaign.attempts[0].digest().expect("child"))] {
        campaign.approve = approval;
        let mut script = Script::default();
        assert_eq!(run(&campaign, &mut script), Err("ERR-CAPTURE-RTSP-APPROVAL-001"));
        assert!(script.generations.is_empty());
        assert!(script.rows.is_empty());
    }
}

#[test]
fn legacy_approval_encoding_is_byte_for_byte_unchanged() {
    for supervised in [false, true] {
        let mut input = args();
        if supervised {
            set(&mut input, "--progress-timeout-ms", "5000");
        }
        let plan = ReconnectPlan::parse(&input).expect("legacy plan");
        // Exact pre-campaign encoder from the original owner, not the new digest helper.
        let mut e = CanonicalEncoder::new();
        e.text("fss.rtsp_reconnect_cli_plan.v1");
        e.text(if supervised { SUPERVISED_POLICY } else { POLICY });
        if let Some(timeout) = plan.progress_timeout_ns {
            e.text(driver::Supervision::POLICY);
            e.u64(timeout);
        }
        e.u64(MAX_CONTROL_REPORT_BYTES as u64);
        e.u64(plan.retry_delay_ms);
        e.u64(plan.retry_max_delay_ms);
        e.u64(plan.attempts.len() as u64);
        for attempt in &plan.attempts {
            e.digest(attempt.digest().expect("child"));
        }
        assert_eq!(
            plan.digest().expect("new encoder"),
            ContentDigest::sha256(&e.finish_checked().expect("old encoder"))
        );
    }
}

#[test]
fn campaign_option_is_explicit_bounded_and_duplicate_safe() {
    for value in ["no", "true", "1", "YES", "", "yes "] {
        let mut input = args();
        set(&mut input, "--continue-after-success", value);
        assert!(ReconnectPlan::parse(&input).is_err(), "{value:?}");
    }
    let mut duplicate = campaign_args();
    duplicate.extend([OsString::from("--continue-after-success"), OsString::from("yes")]);
    assert!(ReconnectPlan::parse(&duplicate).is_err());
    for count in ["0", "17", "18446744073709551615"] {
        let mut input = campaign_args();
        set(&mut input, "--max-attempts", count);
        assert!(ReconnectPlan::parse(&input).is_err());
    }
    let mut overflow = campaign_args();
    set(&mut overflow, "--generation", "18446744073709551615");
    assert!(ReconnectPlan::parse(&overflow).is_err());
}

#[test]
fn successful_avc_and_hevc_campaigns_use_fresh_epochs_and_stop_at_the_limit() {
    for codec in ["avc", "hevc"] {
        let mut input = campaign_args();
        set(&mut input, "--codec", codec);
        let plan = approve(&input);
        let preview = plan.preview().expect("pure preview");
        assert!(preview.contains("every_approved_attempt_independent"));
        assert!(preview.contains("all_planned_attempts_settled_successfully"));
        let mut script = Script::outcomes([success(), success(), success()]);
        assert_eq!(run(&plan, &mut script), Ok(()));
        assert_eq!(script.generations, [1, 2, 3]);
        assert_eq!(script.waits, [250, 500]);
        for (index, current) in plan.attempts.iter().enumerate() {
            for previous in &plan.attempts[..index] {
                assert_ne!(current.root, previous.root);
                assert_ne!(current.pins, previous.pins);
                assert_ne!(current.pin_scope().journal_id, previous.pin_scope().journal_id);
                assert_ne!(current.recording_config().scope.receive_clock,
                    previous.recording_config().scope.receive_clock);
                assert_ne!(current.catalog_scope().decode_clock, previous.catalog_scope().decode_clock);
            }
        }
        let terminal = script.terminal();
        for field in [
            "\"complete\":true", "\"attempts_used\":3", "\"successful_attempts\":3",
            "\"unsuccessful_attempts\":0", "\"durable_pictures_all_attempts\":6",
            "\"attempt_limit_reached\":true", "\"first_failed_attempt\":null",
            "\"continuity_across_attempts\":false", "\"absence_certifiable\":false",
        ] {
            assert!(terminal.contains(field), "{field}: {terminal}");
        }
        assert_eq!(script.rows.iter().filter(|(_, row)|
            row.contains("\"continuing_after_success\":true")).count(), 2);
        assert_eq!(script.rows.iter().filter(|(_, row)|
            row.contains("next_independent_session")).count(), 2);
    }
}

#[test]
fn success_does_not_erase_an_earlier_campaign_shortfall() {
    let plan = approve(&campaign_args());
    let mut script = Script::outcomes([shortfall(), success(), success()]);
    assert_eq!(run(&plan, &mut script), Err("source_shortfall"));
    assert_eq!(script.generations, [1, 2, 3]);
    let terminal = script.terminal();
    for field in [
        "\"complete\":false", "\"successful_attempts\":2", "\"unsuccessful_attempts\":1",
        "\"first_failed_attempt\":1", "\"error_id\":\"source_shortfall\"",
        "\"durable_pictures_all_attempts\":5",
    ] {
        assert!(terminal.contains(field), "{field}: {terminal}");
    }
    assert!(script.rows.iter().any(|(_, row)| row.contains("retry_after_failure")));
}

#[test]
fn legacy_reconnect_still_succeeds_after_a_retry() {
    let plan = approve(&args());
    let mut script = Script::outcomes([shortfall(), success()]);
    assert_eq!(run(&plan, &mut script), Ok(()));
    assert_eq!(script.generations, [1, 2]);
    assert!(script.terminal().contains("\"complete\":true"));
}

#[test]
fn nonretryable_failures_stop_even_after_success() {
    for failure in ["authentication_refused", "source_budget_exhausted", "storage_failed"] {
        let plan = approve(&campaign_args());
        let mut failed = shortfall();
        failed.result = Err(failure);
        failed.retry = None;
        let mut script = Script::outcomes([success(), failed]);
        assert_eq!(run(&plan, &mut script), Err(failure));
        assert_eq!(script.generations, [1, 2]);
        assert!(script.terminal().contains("\"attempt_limit_reached\":false"));
        assert!(script.terminal().contains("\"first_failed_attempt\":2"));
    }
}

#[test]
fn current_terminal_failure_takes_precedence_but_preserves_first_failure() {
    let plan = approve(&campaign_args());
    let mut fatal = shortfall();
    fatal.retry = None;
    fatal.result = Err("storage_failed");
    let mut script = Script::outcomes([shortfall(), fatal]);
    assert_eq!(run(&plan, &mut script), Err("storage_failed"));
    assert!(script.terminal().contains("\"first_error_id\":\"source_shortfall\""));
    assert!(script.terminal().contains("\"error_id\":\"storage_failed\""));
}

#[test]
fn recovery_obligations_never_admit_a_later_campaign_session() {
    let plan = approve(&campaign_args());
    let mut pending = shortfall();
    pending.recovery_required = true;
    let mut script = Script::outcomes([success(), pending]);
    assert_eq!(run(&plan, &mut script), Err("source_shortfall"));
    assert_eq!(script.generations, [1, 2]);
    assert!(script.terminal().contains("\"recovery_required\":true"));
    let mut contradictory = success();
    contradictory.recovery_required = true;
    let mut script = Script::outcomes([contradictory]);
    assert_eq!(run(&plan, &mut script), Err("ERR-CAPTURE-RTSP-STATE-001"));
    assert_eq!(script.generations, [1]);
    assert!(script.waits.is_empty());
}

#[test]
fn campaign_does_not_implicitly_enable_stall_retries() {
    for supervised in [false, true] {
        let mut input = campaign_args();
        if supervised {
            set(&mut input, "--progress-timeout-ms", "5000");
        }
        let plan = approve(&input);
        let mut stalled = shortfall();
        stalled.retry = Some(RetryReason::ProgressStalled);
        let mut script = Script::outcomes([stalled, success(), success()]);
        assert_eq!(run(&plan, &mut script), Err("source_shortfall"));
        assert_eq!(script.generations.len(), if supervised { 3 } else { 1 });
    }
}

#[test]
fn cancellation_during_successful_session_backoff_prevents_next_intake() {
    let plan = approve(&campaign_args());
    let mut script = Script::outcomes([success()]);
    script.cancel_on_wait = true;
    assert_eq!(run(&plan, &mut script), Err("cancelled"));
    assert_eq!(script.generations, [1]);
    assert_eq!(script.waits, [250]);
}

#[test]
fn output_failure_never_falls_through_to_another_successful_session() {
    for row in ["attempt_started", "attempt_finished", "backoff"] {
        let plan = approve(&campaign_args());
        let mut script = Script::outcomes([success()]);
        script.fail_row = Some(row);
        assert_eq!(run(&plan, &mut script), Err("output_failed"));
        assert_eq!(script.generations.len(), usize::from(row != "attempt_started"));
        assert!(script.waits.is_empty());
    }
}

#[test]
fn offline_campaign_recovery_cannot_enter_capture_controller() {
    let capture = approve(&campaign_args());
    for mode in ["yes", "index"] {
        let mut input = campaign_args();
        set(&mut input, "--recover", mode);
        let plan = approve(&input);
        // Recovery owns a separate approval over this exact original capture identity.
        assert_eq!(capture.digest().expect("capture"), plan.digest().expect("recovery basis"));
        let mut script = Script::default();
        assert_eq!(run(&plan, &mut script), Err("ERR-CAPTURE-RTSP-STATE-001"));
        assert!(script.generations.is_empty());
        assert!(script.rows.is_empty());
    }
}

#[test]
fn all_sixteen_sessions_and_waits_stay_inside_the_approved_ceilings() {
    let mut input = campaign_args();
    set(&mut input, "--max-attempts", "16");
    set(&mut input, "--retry-max-delay-ms", "1000");
    let plan = approve(&input);
    let mut script = Script::outcomes((0..16).map(|_| success()));
    assert_eq!(run(&plan, &mut script), Ok(()));
    assert_eq!(script.generations.len(), 16);
    assert_eq!(script.waits.len(), 15);
    assert_eq!(script.waits.iter().sum::<u64>(), plan.maximum_backoff_ms);
    assert!(script.waits.iter().all(|wait| *wait <= 1000));
    assert!(script.terminal().contains("\"successful_attempts\":16"));
    assert!(script.terminal().contains("\"durable_pictures_all_attempts\":32"));
}

#[test]
fn one_session_campaign_does_not_wait_or_add_an_attempt() {
    let mut input = campaign_args();
    set(&mut input, "--max-attempts", "1");
    let plan = approve(&input);
    let mut script = Script::outcomes([success()]);
    assert_eq!(run(&plan, &mut script), Ok(()));
    assert_eq!(script.generations, [1]);
    assert!(script.waits.is_empty());
    assert!(script.terminal().contains("\"attempt_limit_reached\":true"));
}

#[test]
fn successful_media_without_native_settlement_cannot_continue_or_complete_a_campaign() {
    for count in ["1", "3"] {
        let mut input = campaign_args();
        set(&mut input, "--max-attempts", count);
        let plan = approve(&input);
        let mut unsettled = success();
        unsettled.retry = None; // Native pending control, missing final snapshot, or partial drain.
        let mut script = Script::outcomes([unsettled]);
        assert_eq!(run(&plan, &mut script), Err("ERR-CAPTURE-RTSP-STATE-001"));
        assert_eq!(script.generations, [1]);
        assert!(script.waits.is_empty());
        assert!(script.terminal().contains("\"complete\":false"));
        assert!(script.terminal().contains("\"successful_attempts\":0"));
        assert!(script.terminal().contains("\"durable_pictures_all_attempts\":2"));
        assert!(script.rows.iter().any(|(kind, row)| kind == "attempt_finished"
            && row.contains("\"complete\":true")
            && row.contains("\"continuation_blocked\":true")));
    }
}

#[test]
fn successful_session_marker_cannot_reclassify_a_failure_as_retryable() {
    let plan = approve(&campaign_args());
    let mut inconsistent = shortfall();
    inconsistent.retry = Some(RetryReason::SettledSuccess);
    let mut script = Script::outcomes([inconsistent]);
    assert_eq!(run(&plan, &mut script), Err("source_shortfall"));
    assert_eq!(script.generations, [1]);
    assert!(script.waits.is_empty());
}

#[test]
fn native_success_admission_is_not_exposed_as_a_legacy_failure_reason() {
    let plan = approve(&args());
    let mut script = Script::outcomes([success()]);
    assert_eq!(run(&plan, &mut script), Ok(()));
    assert_eq!(script.generations, [1]);
    assert!(script.rows.iter().any(|(kind, row)| kind == "attempt_finished"
        && row.contains("\"retry_reason\":null")));
    assert!(!script.rows.iter().any(|(_, row)| row.contains("settled_success")));
}

#[test]
fn settled_marker_cannot_hide_under_or_over_capture_of_the_approved_target() {
    for pictures in [0, 1, 3, u64::MAX] {
        let plan = approve(&campaign_args());
        let mut incorrect = success();
        incorrect.durable_pictures = pictures;
        let mut script = Script::outcomes([incorrect]);
        assert_eq!(run(&plan, &mut script), Err("ERR-CAPTURE-RTSP-STATE-001"));
        assert_eq!(script.generations, [1]);
        assert!(script.waits.is_empty());
        assert!(script.terminal().contains("\"complete\":false"));
        assert!(script.terminal().contains("\"successful_attempts\":0"));
        assert!(script.terminal().contains(&format!(
            "\"durable_pictures_all_attempts\":{pictures}"
        )));
    }
}

#[test]
fn one_underfilled_success_after_a_settled_session_preserves_both_counts() {
    let plan = approve(&campaign_args());
    let mut short = success();
    short.durable_pictures = 1;
    let mut script = Script::outcomes([success(), short]);
    assert_eq!(run(&plan, &mut script), Err("ERR-CAPTURE-RTSP-STATE-001"));
    assert_eq!(script.generations, [1, 2]);
    assert_eq!(script.waits, [250]);
    for field in [
        "\"successful_attempts\":1", "\"unsuccessful_attempts\":1",
        "\"first_failed_attempt\":2", "\"durable_pictures_all_attempts\":3",
    ] {
        assert!(script.terminal().contains(field), "{field}");
    }
}

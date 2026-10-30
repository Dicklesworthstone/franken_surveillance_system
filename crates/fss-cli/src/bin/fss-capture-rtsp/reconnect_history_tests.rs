#![forbid(unsafe_code)]

use super::*;
use std::collections::VecDeque;

fn args() -> Vec<OsString> {
    let mut input: Vec<_> = [
        ("--root", "/owner/private/archive"),
        ("--pins", "/owner/private/pins"),
        ("--peer", "127.0.0.1:8554"),
        ("--authority", "camera.test:8554"),
        ("--presentation", "/camera/main"),
        ("--control-root", "/camera"),
        ("--sensor-id", "sensor:camera"),
        ("--stream-id", "stream:main"),
        ("--generation", "1"),
        ("--ingress", "1"),
        ("--ssrc", "7"),
        ("--frame-duration-ticks", "3600"),
        ("--stop-after-pictures", "2"),
        ("--max-attempts", "2"),
        ("--continue-after-success", "yes"),
        ("--owner-authorized", "yes"),
        ("--plaintext", "yes"),
        ("--retain-originals", "yes"),
    ]
    .into_iter()
    .flat_map(|(key, value)| [key.into(), value.into()])
    .collect();
    for (key, digit) in [
        ("--anchor", "1"),
        ("--receive-clock", "2"),
        ("--timing-evidence", "3"),
        ("--journal-id", "4"),
    ] {
        input.extend([key.into(), format!("sha256:{}", digit.repeat(64)).into()]);
    }
    input
}

fn set(input: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(index) = input.iter().position(|part| part == key) {
        input[index + 1] = value.into();
    } else {
        input.extend([key.into(), value.into()]);
    }
}

fn history_args() -> Vec<OsString> {
    let mut input = args();
    set(&mut input, "--history-root", "/owner/private/history");
    input
}

fn approved() -> ReconnectPlan {
    let mut plan = ReconnectPlan::parse(&history_args()).expect("history plan");
    plan.approve = Some(plan.digest().expect("outer digest"));
    for attempt in &mut plan.attempts {
        attempt.approve = Some(attempt.digest().expect("child digest"));
    }
    plan
}

#[test]
fn history_grant_changes_outer_approval_without_rewriting_any_child() {
    let legacy = ReconnectPlan::parse(&args()).expect("legacy plan");
    let retained = ReconnectPlan::parse(&history_args()).expect("history plan");
    assert!(
        !legacy
            .preview()
            .expect("legacy preview")
            .contains("campaign_history")
    );
    assert!(
        retained
            .preview()
            .expect("history preview")
            .contains("campaign_history")
    );
    assert_ne!(legacy.digest().unwrap(), retained.digest().unwrap());
    for (a, b) in legacy.attempts.iter().zip(&retained.attempts) {
        assert_eq!(a.digest().unwrap(), b.digest().unwrap());
    }
    assert_eq!(
        retained.output_paths().unwrap().last().unwrap(),
        &Path::new("/owner/private/history")
    );
    for (key, value) in [
        ("--history-root", "/owner/private/another-history"),
        ("--history-max-records", "32"),
        ("--history-object-bytes", "131072"),
        ("--history-max-scan-entries", "2048"),
        ("--history-metadata-bytes", "8388608"),
        ("--history-storage-bytes", "16777216"),
        ("--history-work", "9999999999"),
    ] {
        let mut input = history_args();
        set(&mut input, key, value);
        let changed = ReconnectPlan::parse(&input).expect("narrowed history grant");
        assert_ne!(
            changed.digest().unwrap(),
            retained.digest().unwrap(),
            "{key}"
        );
        assert_eq!(
            changed.child_approval(0).unwrap(),
            retained.child_approval(0).unwrap()
        );
    }
}

#[test]
fn history_parser_refuses_partial_overflow_duplicate_and_overlapping_grants() {
    let mut input = args();
    set(&mut input, "--history-work", "10");
    assert!(ReconnectPlan::parse(&input).is_err());
    for (key, value) in [
        ("--history-root", "relative"),
        ("--history-root", "/"),
        ("--history-root", "/owner/private/../history"),
        (
            "--history-root",
            "/owner/private/archive.attempt-0002/inside",
        ),
        ("--history-root", "/owner/private/pins.attempt-0001"),
        ("--history-root", "/owner/private"),
        ("--history-max-records", "4"),
        ("--history-max-records", "34"),
        ("--history-work", "0"),
        ("--history-work", "10000000001"),
        ("--history-work", "18446744073709551616"),
        ("--history-object-bytes", "262145"),
        ("--history-storage-bytes", "33554433"),
    ] {
        let mut input = history_args();
        set(&mut input, key, value);
        assert!(ReconnectPlan::parse(&input).is_err(), "{key} {value}");
    }
    let mut input = history_args();
    input.extend(["--history-root".into(), "/other/history".into()]);
    assert!(ReconnectPlan::parse(&input).is_err());
    let mut input = history_args();
    set(
        &mut input,
        "--credential-file",
        "/owner/private/history/secret",
    );
    set(&mut input, "--auth-realm", "camera");
    assert!(ReconnectPlan::parse(&input).is_err());
    let mut input = history_args();
    set(&mut input, "--source-root", "/owner/private/source");
    set(
        &mut input,
        "--source-retention-evidence",
        &ContentDigest::sha256(b"approved raw datagrams").to_text(),
    );
    set(
        &mut input,
        "--history-root",
        "/owner/private/source.attempt-0002/inside",
    );
    assert!(ReconnectPlan::parse(&input).is_err());
}

#[derive(Default)]
struct Ordered {
    events: Vec<String>,
    outcomes: VecDeque<Result<AttemptOutcome, &'static str>>,
    fail: Option<&'static str>,
    captures: usize,
    finished: Vec<(u32, Option<&'static str>, bool, bool)>,
    reports: Vec<(String, String)>,
    terminal: Option<Result<(), &'static str>>,
}

impl Ordered {
    fn success() -> AttemptOutcome {
        AttemptOutcome {
            result: Ok(()),
            retry: Some(driver::RetryReason::SettledSuccess),
            recovery_required: false,
            durable_pictures: 2,
        }
    }
    fn record(&mut self, event: &str) -> Result<(), &'static str> {
        self.events.push(event.to_owned());
        if self.fail == Some(event) {
            Err("fixture:refused")
        } else {
            Ok(())
        }
    }
}

impl Effects for Ordered {
    fn checkpoint(&mut self) -> Result<(), &'static str> {
        Ok(())
    }
    fn emit(&mut self, kind: &str, detail: String) -> Result<(), &'static str> {
        self.reports.push((kind.to_owned(), detail));
        self.record(kind)
    }
    fn capture(&mut self, _: &Options) -> Result<AttemptOutcome, &'static str> {
        self.record("camera")?;
        self.captures += 1;
        self.outcomes
            .pop_front()
            .unwrap_or_else(|| Ok(Self::success()))
    }
    fn pause(&mut self, _: u64) -> Result<(), &'static str> {
        self.record("pause")
    }
    fn history_start(&mut self, _: u32) -> Result<(), &'static str> {
        self.record("durable_start")
    }
    fn history_finish(
        &mut self,
        ordinal: u32,
        error: Option<&'static str>,
        success: bool,
        next: bool,
    ) -> Result<(), &'static str> {
        self.finished.push((ordinal, error, success, next));
        self.record("durable_finish")
    }
    fn history_terminal(&mut self, result: Result<(), &'static str>) -> Result<(), &'static str> {
        self.terminal = Some(result);
        self.record("durable_terminal")
    }
}

#[test]
fn history_barriers_precede_camera_successor_and_outer_terminal() {
    let mut effects = Ordered::default();
    assert_eq!(run(&approved(), &mut effects), Ok(()));
    assert_eq!(
        effects.events,
        [
            "durable_start",
            "attempt_started",
            "camera",
            "durable_finish",
            "attempt_finished",
            "backoff",
            "pause",
            "durable_start",
            "attempt_started",
            "camera",
            "durable_finish",
            "attempt_finished",
            "durable_terminal",
            "reconnect_terminal",
        ]
    );
    assert_eq!(
        effects.finished,
        [(1, None, true, true), (2, None, true, false)]
    );
}

#[test]
fn history_or_output_failure_never_authorizes_a_successor() {
    for (cut, cameras) in [
        ("durable_start", 0),
        ("attempt_started", 0),
        ("durable_finish", 1),
        ("attempt_finished", 1),
        ("backoff", 1),
    ] {
        let mut effects = Ordered {
            fail: Some(cut),
            ..Ordered::default()
        };
        assert_eq!(
            run(&approved(), &mut effects),
            Err("fixture:refused"),
            "{cut}"
        );
        assert_eq!(effects.captures, cameras, "{cut}");
        assert!(
            !effects
                .events
                .iter()
                .any(|event| event == "reconnect_terminal")
        );
    }
    let mut effects = Ordered {
        fail: Some("durable_terminal"),
        ..Ordered::default()
    };
    assert_eq!(run(&approved(), &mut effects), Err("fixture:refused"));
    assert_eq!(effects.captures, 2);
    assert!(
        !effects
            .events
            .iter()
            .any(|event| event == "reconnect_terminal")
    );
}

#[test]
fn native_boundary_failure_is_retained_as_controller_failure_without_retry() {
    let mut effects = Ordered::default();
    effects
        .outcomes
        .push_back(Err("ERR-CAPTURE-RTSP-OUTPUT-001"));
    assert_eq!(
        run(&approved(), &mut effects),
        Err("ERR-CAPTURE-RTSP-OUTPUT-001")
    );
    assert_eq!(
        effects.finished,
        [(1, Some("ERR-CAPTURE-RTSP-OUTPUT-001"), false, false)]
    );
    assert_eq!(
        effects.events,
        [
            "durable_start",
            "attempt_started",
            "camera",
            "durable_finish",
            "durable_terminal"
        ]
    );
    assert_eq!(effects.captures, 1);
}

#[test]
fn history_native_retry_failure_is_not_mislabeled_controller_failure() {
    let mut effects = Ordered::default();
    effects.outcomes.push_back(Ok(AttemptOutcome {
        result: Err("ERR-CAPTURE-RTSP-SHORTFALL-001"),
        retry: Some(driver::RetryReason::SourceEnded),
        recovery_required: false,
        durable_pictures: 1,
    }));
    assert_eq!(
        run(&approved(), &mut effects),
        Err("ERR-CAPTURE-RTSP-SHORTFALL-001")
    );
    assert_eq!(
        effects.finished,
        [(1, None, false, true), (2, None, true, false)]
    );
}

fn continuation_args() -> Vec<OsString> {
    continuation_args_from(history_args())
}

fn continuation_args_from(mut input: Vec<OsString>) -> Vec<OsString> {
    let base = ReconnectPlan::parse(&input).expect("base history plan");
    let capture = base.digest().expect("capture identity");
    let campaign = base
        .history
        .as_ref()
        .expect("history config")
        .campaign(&base)
        .expect("campaign plan");
    for (key, value) in [
        ("--continue-history-approval", capture.to_text()),
        (
            "--continue-history-plan",
            campaign.digest().expect("campaign digest").to_text(),
        ),
        (
            "--continue-history-root-digest",
            ContentDigest::sha256(b"independently saved finish root").to_text(),
        ),
        ("--continue-history-records", "2".into()),
    ] {
        input.extend([key.into(), value.into()]);
    }
    input
}

fn continued() -> ReconnectPlan {
    let mut plan = ReconnectPlan::parse(&continuation_args()).expect("continuation plan");
    plan.approve = Some(plan.approval_digest().expect("fresh continuation approval"));
    for attempt in &mut plan.attempts {
        attempt.approve = Some(attempt.digest().expect("child digest"));
    }
    plan
}

#[test]
fn cold_continuation_preserves_original_campaign_identity_but_requires_a_fresh_outer_approval() {
    let original = ReconnectPlan::parse(&history_args()).expect("original plan");
    let continued = ReconnectPlan::parse(&continuation_args()).expect("continued plan");
    assert_eq!(continued.digest().unwrap(), original.digest().unwrap());
    assert_ne!(
        continued.approval_digest().unwrap(),
        original.approval_digest().unwrap()
    );
    for (before, after) in original.attempts.iter().zip(&continued.attempts) {
        assert_eq!(before.digest().unwrap(), after.digest().unwrap());
    }
    let preview = continued.preview().unwrap();
    for expected in [
        "\"cold_continuation\"",
        "\"fresh_history_work\":true",
        "\"historical_budget_refunded\":false",
        "\"initial_backoff_repeated\":true",
    ] {
        assert!(preview.contains(expected), "missing {expected}");
    }
}

#[test]
fn continuation_parser_refuses_partial_wrong_mode_and_impossible_finish_coordinates() {
    for key in [
        "--continue-history-approval",
        "--continue-history-plan",
        "--continue-history-root-digest",
        "--continue-history-records",
    ] {
        let mut input = continuation_args();
        let at = input.iter().position(|part| part == key).unwrap();
        input.drain(at..at + 2);
        assert!(ReconnectPlan::parse(&input).is_err(), "missing {key}");
    }
    let mut odd = continuation_args();
    set(&mut odd, "--continue-history-records", "1");
    assert!(ReconnectPlan::parse(&odd).is_err());
    let mut terminal_sized = continuation_args();
    set(&mut terminal_sized, "--continue-history-records", "4");
    assert!(ReconnectPlan::parse(&terminal_sized).is_err());
    let mut recovery = continuation_args();
    recovery.extend(["--recover".into(), "yes".into()]);
    assert!(ReconnectPlan::parse(&recovery).is_err());
    let mut no_campaign = continuation_args();
    let at = no_campaign
        .iter()
        .position(|part| part == "--continue-after-success")
        .unwrap();
    no_campaign.drain(at..at + 2);
    assert!(ReconnectPlan::parse(&no_campaign).is_err());
}

#[test]
fn resumed_controller_skips_prior_capture_and_repeats_backoff_before_next_camera() {
    let plan = continued();
    let mut effects = Ordered::default();
    effects.outcomes.push_back(Ok(Ordered::success()));
    assert_eq!(run_from(&plan, &mut effects, 1, 2, 1, None), Ok(()));
    assert_eq!(effects.captures, 1);
    assert_eq!(
        effects.events,
        [
            "continuation_resumed",
            "backoff",
            "pause",
            "durable_start",
            "attempt_started",
            "camera",
            "durable_finish",
            "attempt_finished",
            "durable_terminal",
            "reconnect_terminal",
        ]
    );
    assert_eq!(effects.finished, [(2, None, true, false)]);
}

#[test]
fn retry_continuation_requires_its_own_approval_without_changing_original_attempts() {
    let success_only = ReconnectPlan::parse(&continuation_args()).unwrap();
    let mut input = continuation_args();
    set(&mut input, "--continue-retry-history", "yes");
    let mut retry = ReconnectPlan::parse(&input).unwrap();
    assert_eq!(retry.digest().unwrap(), success_only.digest().unwrap());
    assert_ne!(
        retry.approval_digest().unwrap(),
        success_only.approval_digest().unwrap()
    );
    for (original, continued) in success_only.attempts.iter().zip(&retry.attempts) {
        assert_eq!(original.digest().unwrap(), continued.digest().unwrap());
    }
    assert!(retry.preview().unwrap().contains(RETRY_CONTINUATION_POLICY));
    retry.approve = Some(success_only.approval_digest().unwrap());
    let mut effects = Ordered::default();
    assert_eq!(
        run_from(
            &retry,
            &mut effects,
            1,
            1,
            0,
            Some((1, "ERR-CAPTURE-RTSP-SHORTFALL-001"))
        ),
        Err("ERR-CAPTURE-RTSP-APPROVAL-001")
    );
    assert!(effects.events.is_empty());

    for value in ["no", "true", "1"] {
        set(&mut input, "--continue-retry-history", value);
        assert!(ReconnectPlan::parse(&input).is_err());
    }
    let mut no_pin = history_args();
    set(&mut no_pin, "--continue-retry-history", "yes");
    assert!(ReconnectPlan::parse(&no_pin).is_err());
}

#[test]
fn cold_retry_keeps_original_failure_and_partial_pictures_after_later_success() {
    let mut input = continuation_args();
    set(&mut input, "--continue-retry-history", "yes");
    let mut plan = ReconnectPlan::parse(&input).unwrap();
    plan.approve = Some(plan.approval_digest().unwrap());
    let failure = "ERR-CAPTURE-RTSP-SHORTFALL-001";
    let mut effects = Ordered::default();
    assert_eq!(
        run_from(&plan, &mut effects, 1, 1, 0, Some((1, failure))),
        Err(failure)
    );
    assert_eq!(effects.captures, 1);
    assert_eq!(effects.finished, [(2, None, true, false)]);
    assert_eq!(effects.terminal, Some(Err(failure)));
    let terminal = &effects
        .reports
        .iter()
        .find(|(kind, _)| kind == "reconnect_terminal")
        .unwrap()
        .1;
    for field in [
        "\"complete\":false",
        "\"attempts_used\":2",
        "\"successful_attempts\":1",
        "\"unsuccessful_attempts\":1",
        "\"first_failed_attempt\":1",
        "\"durable_pictures_all_attempts\":3",
        "\"error_id\":\"ERR-CAPTURE-RTSP-SHORTFALL-001\"",
    ] {
        assert!(terminal.contains(field), "missing {field}: {terminal}");
    }
    let resumed = &effects.reports[0].1;
    assert!(resumed.contains("\"remaining_original_attempts\":1"));
    assert!(resumed.contains("\"historical_budget_refunded\":false"));
    assert!(resumed.contains("\"first_error_id\":\"ERR-CAPTURE-RTSP-SHORTFALL-001\""));
}

#[test]
fn cold_retry_cannot_extend_exhausted_schedule_or_authorize_an_unrecognized_failure() {
    let mut input = continuation_args();
    set(&mut input, "--continue-retry-history", "yes");
    let mut plan = ReconnectPlan::parse(&input).unwrap();
    plan.approve = Some(plan.approval_digest().unwrap());
    let mut effects = Ordered::default();
    assert_eq!(
        run_from(
            &plan,
            &mut effects,
            2,
            3,
            1,
            Some((1, "ERR-CAPTURE-RTSP-SHORTFALL-001"))
        ),
        Err("ERR-CAPTURE-RTSP-STATE-001")
    );
    assert!(effects.events.is_empty());
    for error in [
        "ERR-CAPTURE-RTSP-STORAGE-001",
        "ERR-CAPTURE-RTSP-AUTH-REFUSED-001",
        "arbitrary_failure",
    ] {
        assert_eq!(driver::retained_retry_error(error), None);
    }
    for error in [
        "ERR-CAPTURE-RTSP-CONNECT-001",
        "ERR-CAPTURE-RTSP-SHORTFALL-001",
        "ERR-CAPTURE-RTSP-PROGRESS-001",
        "ERR-CAPTURE-RTSP-SOURCE-001",
    ] {
        assert_eq!(driver::retained_retry_error(error), Some(error));
    }
}

#[test]
fn ordinary_reconnect_cold_retry_stops_at_success_and_retains_original_failed_history() {
    let mut original_args = history_args();
    let at = original_args
        .iter()
        .position(|part| part == "--continue-after-success")
        .unwrap();
    original_args.drain(at..at + 2);
    set(&mut original_args, "--max-attempts", "3");
    let original = ReconnectPlan::parse(&original_args).unwrap();
    let mut input = continuation_args_from(original_args);
    assert!(
        ReconnectPlan::parse(&input).is_err(),
        "legacy settled-success continuation cannot admit ordinary reconnect"
    );
    set(&mut input, "--continue-retry-history", "yes");
    let mut plan = ReconnectPlan::parse(&input).unwrap();
    assert!(!plan.continue_after_success);
    assert_eq!(plan.digest().unwrap(), original.digest().unwrap());
    assert_ne!(plan.approval_digest().unwrap(), original.digest().unwrap());
    for (original, continued) in original.attempts.iter().zip(&plan.attempts) {
        assert_eq!(original.digest().unwrap(), continued.digest().unwrap());
    }
    let failure = "ERR-CAPTURE-RTSP-SHORTFALL-001";
    plan.approve = Some(original.digest().unwrap());
    let mut denied = Ordered::default();
    assert_eq!(
        run_from(&plan, &mut denied, 1, 1, 0, Some((1, failure))),
        Err("ERR-CAPTURE-RTSP-APPROVAL-001")
    );
    assert!(denied.events.is_empty());

    plan.approve = Some(plan.approval_digest().unwrap());
    let mut effects = Ordered::default();
    assert_eq!(
        run_from(&plan, &mut effects, 1, 1, 0, Some((1, failure))),
        Ok(())
    );
    assert_eq!(
        effects.captures, 1,
        "third original attempt must stay unused"
    );
    assert_eq!(effects.finished, [(2, None, true, false)]);
    assert_eq!(effects.terminal, Some(Ok(())));
    let terminal = &effects
        .reports
        .iter()
        .find(|(kind, _)| kind == "reconnect_terminal")
        .unwrap()
        .1;
    for field in [
        "\"complete\":true",
        "\"completion_scope\":\"first_successful_attempt\"",
        "\"planned_attempts\":3",
        "\"attempts_used\":2",
        "\"attempt_limit_reached\":false",
        "\"successful_attempts\":1",
        "\"unsuccessful_attempts\":1",
        "\"first_failed_attempt\":1",
        "\"first_error_id\":\"ERR-CAPTURE-RTSP-SHORTFALL-001\"",
        "\"durable_pictures_all_attempts\":3",
        "\"error_id\":null",
    ] {
        assert!(terminal.contains(field), "missing {field}: {terminal}");
    }
    assert!(
        effects.reports[0]
            .1
            .contains("\"remaining_original_attempts\":2")
    );
}

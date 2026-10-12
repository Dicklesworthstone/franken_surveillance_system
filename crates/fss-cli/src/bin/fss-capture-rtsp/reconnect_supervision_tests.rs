#![forbid(unsafe_code)]

use super::*;
use crate::driver::RetryReason;
use std::collections::VecDeque;

fn args() -> Vec<OsString> {
    [
        "--root",
        "/owner/private/archive",
        "--pins",
        "/owner/private/pins",
        "--peer",
        "127.0.0.1:8554",
        "--authority",
        "camera.test:8554",
        "--presentation",
        "/camera/main",
        "--control-root",
        "/camera",
        "--sensor-id",
        "sensor:camera",
        "--stream-id",
        "stream:main",
        "--generation",
        "1",
        "--ingress",
        "1",
        "--ssrc",
        "7",
        "--anchor",
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "--receive-clock",
        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "--timing-evidence",
        "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        "--journal-id",
        "sha256:4444444444444444444444444444444444444444444444444444444444444444",
        "--frame-duration-ticks",
        "3600",
        "--stop-after-pictures",
        "2",
        "--owner-authorized",
        "yes",
        "--plaintext",
        "yes",
        "--retain-originals",
        "yes",
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}
fn set(args: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(index) = args.iter().position(|arg| arg == key) {
        args[index + 1] = OsString::from(value);
    } else {
        args.extend([OsString::from(key), OsString::from(value)]);
    }
}
fn approved() -> ReconnectPlan {
    let mut plan = ReconnectPlan::parse(&args()).expect("valid plan");
    plan.approve = Some(plan.digest().expect("digest"));
    for attempt in &mut plan.attempts {
        attempt.approve = Some(attempt.digest().expect("child digest"));
    }
    plan
}
fn outcome(result: Result<(), &'static str>, retry: Option<RetryReason>) -> AttemptOutcome {
    AttemptOutcome {
        result,
        retry,
        recovery_required: false,
        durable_pictures: 0,
    }
}
#[derive(Default)]
struct TestEffects {
    outcomes: VecDeque<Result<AttemptOutcome, &'static str>>,
    attempts: Vec<(u64, ContentDigest)>,
    rows: Vec<(String, String)>,
    waits: Vec<u64>,
    cancelled: bool,
    cancel_on_wait: bool,
    fail_row: Option<&'static str>,
}
impl Effects for TestEffects {
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
        assert_eq!(
            options.approve,
            Some(options.digest().expect("exact child approval"))
        );
        self.attempts.push((
            options.recording_config().scope.generation,
            options.pin_scope().journal_id,
        ));
        self.outcomes.pop_front().expect("no unplanned attempt")
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
fn progress_policy_is_opt_in_and_bound_only_by_the_exact_outer_approval() {
    let original = approved();
    assert_eq!(original.progress_timeout_ns, None);
    assert_eq!(original.policy(), POLICY);
    assert!(
        !original
            .preview()
            .expect("preview")
            .contains("progress_timeout_ns")
    );
    for codec in ["avc", "hevc"] {
        let mut input = args();
        set(&mut input, "--codec", codec);
        let plain = ReconnectPlan::parse(&input).expect("plain plan");
        set(&mut input, "--progress-timeout-ms", "5000");
        let watched = ReconnectPlan::parse(&input).expect("supervised plan");
        assert_eq!(watched.progress_timeout_ns, Some(5_000_000_000));
        assert_eq!(watched.policy(), SUPERVISED_POLICY);
        assert_ne!(
            watched.digest().expect("watch approval"),
            plain.digest().expect("plain approval")
        );
        assert_eq!(watched.maximum_source_bytes, plain.maximum_source_bytes);
        assert_eq!(watched.maximum_capture_ns, plain.maximum_capture_ns);
        for (a, b) in watched.attempts.iter().zip(&plain.attempts) {
            assert_eq!(
                a.digest().expect("watch child"),
                b.digest().expect("plain child")
            );
        }
        set(&mut input, "--progress-timeout-ms", "5001");
        let changed = ReconnectPlan::parse(&input).expect("changed timeout");
        assert_ne!(
            changed.digest().expect("changed approval"),
            watched.digest().expect("approval")
        );
        set(
            &mut input,
            "--approve",
            &watched.digest().expect("old approval").to_text(),
        );
        let stale = ReconnectPlan::parse(&input).expect("stale plan");
        let mut effects = TestEffects::default();
        assert_eq!(
            run(&stale, &mut effects),
            Err("ERR-CAPTURE-RTSP-APPROVAL-001")
        );
        assert!(effects.attempts.is_empty());
        assert!(effects.rows.is_empty());
    }
}

#[test]
fn invalid_progress_allowances_and_duplicates_are_pure_refusals() {
    for value in ["0", "600001", "-1", "+1", "1.0", "18446744073709551615"] {
        let mut input = args();
        set(&mut input, "--progress-timeout-ms", value);
        assert!(ReconnectPlan::parse(&input).is_err(), "{value}");
    }
    let mut input = args();
    set(&mut input, "--progress-timeout-ms", "1");
    assert!(ReconnectPlan::parse(&input).is_ok());
    input.extend(["--progress-timeout-ms".into(), "2".into()]);
    assert!(ReconnectPlan::parse(&input).is_err());
}

#[test]
fn legacy_policy_cannot_retry_a_supervised_stall_observation() {
    let plan = approved();
    let mut effects = TestEffects {
        outcomes: [Ok(outcome(
            Err("stalled"),
            Some(RetryReason::ProgressStalled),
        ))]
        .into_iter()
        .collect(),
        ..TestEffects::default()
    };
    assert_eq!(run(&plan, &mut effects), Err("stalled"));
    assert_eq!(effects.attempts.len(), 1);
    assert!(effects.waits.is_empty());
    assert!(
        effects
            .rows
            .last()
            .expect("terminal")
            .1
            .contains("\"attempt_limit_reached\":false")
    );
}

#[test]
fn supervised_stalls_remain_finite_and_cannot_bypass_recovery_or_output_failures() {
    let mut input = args();
    set(&mut input, "--progress-timeout-ms", "500");
    let mut plan = ReconnectPlan::parse(&input).expect("supervised plan");
    plan.approve = Some(plan.digest().expect("approval"));
    for child in &mut plan.attempts {
        child.approve = Some(child.digest().expect("child"));
    }
    let mut effects = TestEffects {
        outcomes: (0..3)
            .map(|_| Ok(outcome(Err("stalled"), Some(RetryReason::ProgressStalled))))
            .collect(),
        ..TestEffects::default()
    };
    assert_eq!(run(&plan, &mut effects), Err("stalled"));
    assert_eq!(effects.attempts.len(), 3);
    assert_eq!(effects.waits, [250, 500]);
    for recovery_required in [false, true] {
        let mut effects = TestEffects {
            outcomes: [Ok(AttemptOutcome {
                recovery_required,
                ..outcome(Err("stalled"), Some(RetryReason::ProgressStalled))
            })]
            .into_iter()
            .collect(),
            fail_row: if recovery_required {
                None
            } else {
                Some("attempt_finished")
            },
            ..TestEffects::default()
        };
        assert!(run(&plan, &mut effects).is_err());
        assert_eq!(effects.attempts.len(), 1);
        assert!(effects.waits.is_empty());
    }
}

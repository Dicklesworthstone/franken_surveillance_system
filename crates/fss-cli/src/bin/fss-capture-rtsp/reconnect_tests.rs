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
fn pure_plans_bind_all_attempts_and_never_merge_clock_or_custody_identity() {
    for codec in ["avc", "hevc"] {
        let mut input = args();
        set(&mut input, "--codec", codec);
        let plan = ReconnectPlan::parse(&input).expect("pure plan");
        let preview = plan.preview().expect("bounded preview");
        assert_eq!(plan.attempts.len(), 3);
        assert!(preview.contains("none-until-exact-outer-approval"));
        assert!(preview.contains("\"continuity_across_attempts\":false"));
        for (index, attempt) in plan.attempts.iter().enumerate() {
            assert!(attempt.approve.is_none());
            assert_eq!(attempt.codec(), codec);
            assert_eq!(attempt.binding().key().ingress, 1);
            assert_eq!(attempt.binding().key().ssrc, 7);
            assert_eq!(
                attempt.recording_config().scope.generation,
                index as u64 + 1
            );
            assert_eq!(
                attempt.root.to_str().expect("root"),
                format!("/owner/private/archive.attempt-{:04}", index + 1)
            );
            for previous in &plan.attempts[..index] {
                assert_ne!(previous.root, attempt.root);
                assert_ne!(previous.pins, attempt.pins);
                assert_ne!(
                    previous.pin_scope().journal_id,
                    attempt.pin_scope().journal_id
                );
                assert_ne!(
                    previous.pin_scope().archive_namespace,
                    attempt.pin_scope().archive_namespace
                );
                assert_ne!(
                    previous.recording_config().scope.receive_clock,
                    attempt.recording_config().scope.receive_clock
                );
                assert_ne!(
                    previous.catalog_scope().decode_clock,
                    attempt.catalog_scope().decode_clock
                );
            }
        }
        assert_eq!(
            plan.maximum_source_bytes,
            plan.attempts[0].max_received_bytes() * 3
        );
        assert_eq!(
            plan.maximum_storage_bytes,
            plan.attempts[0].publication_limits().spool.max_total_bytes * 3
        );
    }
}

#[test]
fn ordering_is_irrelevant_but_every_reconnect_input_changes_outer_approval() {
    let original = ReconnectPlan::parse(&args())
        .expect("plan")
        .digest()
        .expect("digest");
    let reversed = args()
        .chunks_exact(2)
        .rev()
        .flat_map(|pair| pair.iter().cloned())
        .collect::<Vec<_>>();
    assert_eq!(
        ReconnectPlan::parse(&reversed)
            .expect("reordered")
            .digest()
            .expect("digest"),
        original
    );
    for (key, value) in [
        ("--max-attempts", "4"),
        ("--retry-delay-ms", "500"),
        ("--retry-max-delay-ms", "10000"),
        ("--generation", "8"),
        ("--codec", "hevc"),
        ("--peer", "127.0.0.2:8554"),
        ("--root", "/another/archive"),
        ("--pins", "/another/pins"),
        ("--max-source-bytes", "8388608"),
    ] {
        let mut input = args();
        set(&mut input, key, value);
        assert_ne!(
            ReconnectPlan::parse(&input)
                .expect(key)
                .digest()
                .expect("digest"),
            original,
            "{key}"
        );
    }
    let mut input = args();
    set(&mut input, "--approve", &original.to_text());
    assert_eq!(
        ReconnectPlan::parse(&input)
            .expect("approval excluded")
            .digest()
            .expect("digest"),
        original
    );
}

#[test]
fn invalid_or_overflowing_attempts_are_refused_before_effects() {
    for (key, value) in [
        ("--max-attempts", "0"),
        ("--max-attempts", "17"),
        ("--max-attempts", "+3"),
        ("--retry-delay-ms", "0"),
        ("--retry-delay-ms", "60001"),
        ("--retry-delay-ms", "5001"),
        ("--retry-max-delay-ms", "249"),
        ("--generation", "18446744073709551615"),
        ("--codec", "auto"),
        ("--peer", "camera.test:8554"),
    ] {
        let mut input = args();
        set(&mut input, key, value);
        assert!(ReconnectPlan::parse(&input).is_err(), "{key}={value}");
    }
    let mut duplicate = args();
    duplicate.extend([OsString::from("--root"), OsString::from("/other/root")]);
    assert!(ReconnectPlan::parse(&duplicate).is_err());
    let mut last_generation = args();
    set(&mut last_generation, "--max-attempts", "1");
    set(&mut last_generation, "--generation", "18446744073709551615");
    assert!(ReconnectPlan::parse(&last_generation).is_ok());
}

#[test]
fn no_approval_or_child_approval_can_start_a_reconnect_run() {
    let mut plan = ReconnectPlan::parse(&args()).expect("plan");
    for approval in [
        None,
        Some(plan.attempts[0].digest().expect("child")),
        Some(ContentDigest::sha256(b"wrong")),
    ] {
        plan.approve = approval;
        let mut effects = TestEffects::default();
        assert!(run(&plan, &mut effects).is_err());
        assert!(effects.attempts.is_empty());
        assert!(effects.rows.is_empty());
        assert!(effects.waits.is_empty());
    }
}

#[test]
fn a_retry_uses_a_new_epoch_and_success_stops_without_a_third_attempt() {
    let plan = approved();
    let mut effects = TestEffects {
        outcomes: [
            Ok(AttemptOutcome {
                durable_pictures: 1,
                ..outcome(Err("shortfall"), Some(RetryReason::SourceEnded))
            }),
            Ok(AttemptOutcome {
                durable_pictures: 2,
                ..outcome(Ok(()), None)
            }),
        ]
        .into_iter()
        .collect(),
        ..TestEffects::default()
    };
    assert!(run(&plan, &mut effects).is_ok());
    assert_eq!(effects.attempts.len(), 2);
    assert_eq!(effects.attempts[0].0, 1);
    assert_eq!(effects.attempts[1].0, 2);
    assert_ne!(effects.attempts[0].1, effects.attempts[1].1);
    assert_eq!(effects.waits, [250]);
    let terminal = &effects.rows.last().expect("terminal").1;
    assert!(terminal.contains("\"durable_pictures_all_attempts\":3"));
    assert!(terminal.contains("\"continuity_across_attempts\":false"));
}

#[test]
fn retries_remain_finite_and_backoff_is_exponential_then_capped() {
    let mut input = args();
    set(&mut input, "--max-attempts", "8");
    set(&mut input, "--retry-max-delay-ms", "1000");
    let mut plan = ReconnectPlan::parse(&input).expect("plan");
    plan.approve = Some(plan.digest().expect("approval"));
    for attempt in &mut plan.attempts {
        attempt.approve = Some(attempt.digest().expect("child"));
    }
    let mut effects = TestEffects {
        outcomes: (0..8)
            .map(|_| {
                Ok(outcome(
                    Err("connection"),
                    Some(RetryReason::ConnectionUnavailable),
                ))
            })
            .collect(),
        ..TestEffects::default()
    };
    assert_eq!(run(&plan, &mut effects), Err("connection"));
    assert_eq!(effects.attempts.len(), 8);
    assert_eq!(effects.waits, [250, 500, 1000, 1000, 1000, 1000, 1000]);
    assert_eq!(plan.maximum_backoff_ms, effects.waits.iter().sum::<u64>());
    assert!(
        effects
            .rows
            .last()
            .expect("terminal")
            .1
            .contains("\"attempt_limit_reached\":true")
    );
}

#[test]
fn fatal_or_unreported_attempts_never_open_a_successor() {
    let plan = approved();
    for result in [
        Ok(outcome(Err("auth_refused"), None)),
        Err("output_failure"),
    ] {
        let mut effects = TestEffects {
            outcomes: [result].into_iter().collect(),
            ..TestEffects::default()
        };
        assert!(run(&plan, &mut effects).is_err());
        assert_eq!(effects.attempts.len(), 1);
        assert!(effects.waits.is_empty());
    }
}

#[test]
fn output_failure_and_cancelled_backoff_stop_before_next_capture() {
    let plan = approved();
    for row in ["attempt_started", "attempt_finished", "backoff"] {
        let mut effects = TestEffects {
            outcomes: [Ok(outcome(
                Err("shortfall"),
                Some(RetryReason::SourceEnded),
            ))]
            .into_iter()
            .collect(),
            fail_row: Some(row),
            ..TestEffects::default()
        };
        assert_eq!(run(&plan, &mut effects), Err("output_failed"));
        assert_eq!(
            effects.attempts.len(),
            usize::from(row != "attempt_started")
        );
        assert!(effects.waits.is_empty());
    }
    let mut effects = TestEffects {
        outcomes: [Ok(outcome(
            Err("shortfall"),
            Some(RetryReason::SourceEnded),
        ))]
        .into_iter()
        .collect(),
        cancel_on_wait: true,
        ..TestEffects::default()
    };
    assert_eq!(run(&plan, &mut effects), Err("cancelled"));
    assert_eq!(effects.attempts.len(), 1);
}

#[test]
fn unsettled_recovery_vetoes_even_a_contradictory_retry_observation() {
    let plan = approved();
    let mut effects = TestEffects {
        outcomes: [Ok(AttemptOutcome {
            recovery_required: true,
            ..outcome(Err("recovery_required"), Some(RetryReason::SourceEnded))
        })]
        .into_iter()
        .collect(),
        ..TestEffects::default()
    };
    assert_eq!(run(&plan, &mut effects), Err("recovery_required"));
    assert_eq!(effects.attempts.len(), 1);
    assert!(effects.waits.is_empty());
}

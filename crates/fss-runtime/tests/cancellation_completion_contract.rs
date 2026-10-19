#![forbid(unsafe_code)]

//! Primary work completion is distinct from the workers' shutdown obligation.

use fss_runtime::cancellation::{CancelOutcome, CancellationLifecycle, DrainStep};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn natural_completion_requests_drain_and_waits_for_every_worker() -> TestResult {
    let mut lifecycle = CancellationLifecycle::new(
        ["receive-worker".to_string(), "archive-worker".to_string()],
        50,
    );
    lifecycle.work_completed();
    assert!(lifecycle.is_requested());
    assert_eq!(lifecycle.primary_outcome(), Some(&CancelOutcome::Completed));
    assert_eq!(lifecycle.outcome(), None);
    assert_eq!(lifecycle.drive(99), DrainStep::NotDraining);

    lifecycle.begin_drain(100);
    assert_eq!(
        lifecycle.drive(101),
        DrainStep::Pending(vec!["archive-worker".into(), "receive-worker".into()])
    );
    lifecycle.worker_done("receive-worker")?;
    assert_eq!(lifecycle.outcome(), None);
    assert_eq!(
        lifecycle.drive(102),
        DrainStep::Pending(vec!["archive-worker".into()])
    );
    lifecycle.worker_done("archive-worker")?;
    assert_eq!(lifecycle.outcome(), Some(&CancelOutcome::Completed));
    assert_eq!(
        lifecycle.drive(103),
        DrainStep::Finalized(CancelOutcome::Completed)
    );
    Ok(())
}

#[test]
fn failure_before_cancellation_retains_its_reason_until_workers_end() -> TestResult {
    let mut lifecycle = CancellationLifecycle::new(
        ["capture-worker".to_string(), "flush-worker".to_string()],
        100,
    );
    let failure = CancelOutcome::Failed {
        reason: "capture source disconnected".into(),
    };
    lifecycle.work_failed("capture source disconnected");
    assert!(lifecycle.is_requested());
    assert_eq!(lifecycle.primary_outcome(), Some(&failure));
    assert_eq!(lifecycle.outcome(), None);
    lifecycle.begin_drain(20);
    lifecycle.worker_done("capture-worker")?;
    assert_eq!(
        lifecycle.drive(21),
        DrainStep::Pending(vec!["flush-worker".into()])
    );
    assert_eq!(lifecycle.outcome(), None);
    lifecycle.worker_done("flush-worker")?;
    assert_eq!(lifecycle.outcome(), Some(&failure));
    assert_eq!(lifecycle.drive(22), DrainStep::Finalized(failure));
    Ok(())
}

#[test]
fn primary_reports_during_requested_or_active_drain_preserve_their_classification() -> TestResult {
    for already_draining in [false, true] {
        for failed in [false, true] {
            let mut lifecycle = CancellationLifecycle::new(["worker".to_string()], 10);
            lifecycle.request(1);
            if already_draining {
                lifecycle.begin_drain(2);
            }
            let expected = if failed {
                lifecycle.work_failed("primary fault");
                CancelOutcome::Failed {
                    reason: "primary fault".into(),
                }
            } else {
                lifecycle.work_completed();
                CancelOutcome::Completed
            };
            assert_eq!(lifecycle.outcome(), None);
            assert_eq!(lifecycle.primary_outcome(), Some(&expected));
            lifecycle.begin_drain(3);
            assert_eq!(
                lifecycle.drive(4),
                DrainStep::Pending(vec!["worker".into()])
            );
            lifecycle.worker_done("worker")?;
            assert_eq!(lifecycle.outcome(), Some(&expected));
        }
    }
    Ok(())
}

#[test]
fn completion_and_later_faults_cannot_erase_the_first_failure() -> TestResult {
    let mut lifecycle = CancellationLifecycle::new(["worker".to_string()], 10);
    lifecycle.work_failed("primary storage failure");
    lifecycle.begin_drain(10);
    lifecycle.work_completed();
    lifecycle.work_failed("secondary shutdown failure");
    let expected = CancelOutcome::Failed {
        reason: "primary storage failure".into(),
    };
    assert_eq!(lifecycle.primary_outcome(), Some(&expected));
    assert_eq!(lifecycle.outcome(), None);
    lifecycle.worker_done("worker")?;
    assert_eq!(lifecycle.outcome(), Some(&expected));
    lifecycle.work_completed();
    assert_eq!(lifecycle.outcome(), Some(&expected));
    Ok(())
}

#[test]
fn failure_while_completed_work_is_still_draining_prevents_clean_success() -> TestResult {
    let mut lifecycle = CancellationLifecycle::new(["flush-worker".to_string()], 10);
    lifecycle.work_completed();
    lifecycle.begin_drain(10);
    lifecycle.work_failed("archive flush failed");
    assert_eq!(lifecycle.outcome(), None);
    lifecycle.worker_done("flush-worker")?;
    let failure = CancelOutcome::Failed {
        reason: "archive flush failed".into(),
    };
    assert_eq!(lifecycle.outcome(), Some(&failure));
    assert!(
        !lifecycle
            .outcome()
            .is_some_and(CancelOutcome::is_terminal_clean)
    );
    Ok(())
}

#[test]
fn drain_timeout_preserves_primary_result_and_exact_stranded_workers() -> TestResult {
    for failed in [false, true] {
        let mut lifecycle = CancellationLifecycle::new(
            [
                "z-stuck-worker".to_string(),
                "already-ended-worker".to_string(),
                "a-stuck-worker".to_string(),
            ],
            10,
        );
        let primary = if failed {
            lifecycle.work_failed("source failure");
            CancelOutcome::Failed {
                reason: "source failure".into(),
            }
        } else {
            lifecycle.work_completed();
            CancelOutcome::Completed
        };
        lifecycle.begin_drain(100);
        lifecycle.worker_done("already-ended-worker")?;
        assert_eq!(
            lifecycle.drive(109),
            DrainStep::Pending(vec!["a-stuck-worker".into(), "z-stuck-worker".into()])
        );
        let timed_out = lifecycle.drive(110);
        let DrainStep::Finalized(CancelOutcome::Indeterminate { reason }) = &timed_out else {
            return Err(format!("expected worker uncertainty, got {timed_out:?}").into());
        };
        assert!(reason.contains("2 worker(s)"), "{reason}");
        assert!(reason.contains("a-stuck-worker,z-stuck-worker"), "{reason}");
        assert!(!reason.contains("already-ended-worker"), "{reason}");
        assert_eq!(lifecycle.primary_outcome(), Some(&primary));

        // Late acknowledgments and primary reports cannot retroactively turn
        // a timed-out shutdown receipt into a clean terminal outcome.
        lifecycle.worker_done("a-stuck-worker")?;
        lifecycle.worker_done("z-stuck-worker")?;
        lifecycle.work_completed();
        lifecycle.work_failed("late report");
        assert_eq!(lifecycle.drive(111), timed_out);
        assert_eq!(lifecycle.primary_outcome(), Some(&primary));
    }
    Ok(())
}

#[test]
fn repeat_requests_and_primary_reports_cannot_extend_an_existing_drain_window() {
    let mut lifecycle = CancellationLifecycle::new(["worker".to_string()], 10);
    lifecycle.request(10);
    lifecycle.begin_drain(20);
    lifecycle.work_completed();
    lifecycle.request(25);
    lifecycle.begin_drain(26);
    lifecycle.work_completed();
    assert_eq!(
        lifecycle.drive(29),
        DrainStep::Pending(vec!["worker".into()])
    );
    assert!(matches!(
        lifecycle.drive(30),
        DrainStep::Finalized(CancelOutcome::Indeterminate { .. })
    ));
    assert_eq!(lifecycle.primary_outcome(), Some(&CancelOutcome::Completed));
}

#[test]
fn zero_grace_does_not_wait_beyond_the_observed_drain_start() {
    let mut lifecycle = CancellationLifecycle::new(["worker".to_string()], 0);
    lifecycle.work_completed();
    lifecycle.begin_drain(100);
    assert_eq!(
        lifecycle.drive(99),
        DrainStep::Pending(vec!["worker".into()])
    );
    assert!(matches!(
        lifecycle.drive(100),
        DrainStep::Finalized(CancelOutcome::Indeterminate { .. })
    ));
}

#[test]
fn empty_or_already_ended_worker_sets_allow_immediate_primary_settlement() -> TestResult {
    for previously_registered in [false, true] {
        for failed in [false, true] {
            let workers = if previously_registered {
                vec!["worker".to_string()]
            } else {
                Vec::new()
            };
            let mut lifecycle = CancellationLifecycle::new(workers, 10);
            if previously_registered {
                lifecycle.worker_done("worker")?;
            }
            let expected = if failed {
                lifecycle.work_failed("primary fault");
                CancelOutcome::Failed {
                    reason: "primary fault".into(),
                }
            } else {
                lifecycle.work_completed();
                CancelOutcome::Completed
            };
            assert_eq!(lifecycle.outcome(), Some(&expected));
            assert_eq!(lifecycle.drive(1), DrainStep::Finalized(expected));
        }
    }
    Ok(())
}

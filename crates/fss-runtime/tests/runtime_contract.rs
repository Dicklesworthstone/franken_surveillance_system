//! Contract tests for the FSS-021 slice-1 runtime core: cancellation
//! lifecycle (four-valued outcomes incl. Indeterminate on non-cooperative
//! work), budget ledgers, obligation leak oracle, and authority scoping
//! rules (kind legality + no silent budget widening).

use fss_runtime::budget::{Budget, BudgetExhausted, BudgetLedger};
use fss_runtime::cancellation::{CancelOutcome, CancellationLifecycle, DrainStep};
use fss_runtime::obligation::{ObligationError, ObligationRegistry, ObligationTerminal};

// ---------- cancellation ----------

#[test]
fn cooperative_drain_ends_cancelled() {
    let mut lc = CancellationLifecycle::new(["w2".to_string(), "w1".to_string()], 1_000);
    assert!(!lc.is_requested());
    lc.request(10);
    lc.begin_drain(20);
    assert!(lc.is_requested());
    // Deterministic sorted pending list.
    match lc.drive(30) {
        DrainStep::Pending(ids) => assert_eq!(ids, vec!["w1", "w2"]),
        other => panic!("expected pending, got {other:?}"),
    }
    lc.worker_done("w1").expect("w1 done");
    lc.worker_done("w2").expect("w2 done");
    assert_eq!(lc.outcome(), Some(&CancelOutcome::Cancelled));
    assert!(CancelOutcome::Cancelled.is_terminal_clean());
}

#[test]
fn non_cooperative_work_ends_indeterminate_with_stranded_names() {
    let mut lc = CancellationLifecycle::new(["stuck".to_string(), "also-stuck".to_string()], 500);
    lc.request(10);
    lc.begin_drain(100);
    let step = lc.drive(601);
    match step {
        DrainStep::Finalized(CancelOutcome::Indeterminate { reason }) => {
            assert!(reason.contains("stuck"), "{reason}");
            assert!(reason.contains("also-stuck"), "{reason}");
        }
        other => panic!("expected Indeterminate, got {other:?}"),
    }
    // Never silently cancelled, never faked complete.
    assert!(!lc.outcome().expect("final").is_terminal_clean());
}

#[test]
fn duplicate_or_unknown_worker_reports_are_typed_errors() {
    let mut lc = CancellationLifecycle::new(["w1".to_string()], 1_000);
    lc.request(1);
    lc.begin_drain(2);
    assert!(lc.worker_done("ghost").is_err(), "unknown id must refuse");
    lc.worker_done("w1").expect("w1 done");
    assert!(lc.worker_done("w1").is_err(), "duplicate report must refuse");
}

#[test]
fn natural_completion_and_failure_are_distinct_outcomes() {
    let mut a = CancellationLifecycle::new(["w".to_string()], 1_000);
    a.work_completed();
    assert_eq!(a.outcome(), Some(&CancelOutcome::Completed));
    let mut b = CancellationLifecycle::new(["w".to_string()], 1_000);
    b.request(1);
    b.begin_drain(2);
    b.work_failed("sensor fault");
    assert_eq!(
        b.outcome(),
        Some(&CancelOutcome::Failed {
            reason: "sensor fault".to_string()
        })
    );
}

#[test]
fn request_is_idempotent_and_never_rewinds() {
    let mut lc = CancellationLifecycle::new(["w".to_string()], 1_000);
    lc.request(10);
    lc.begin_drain(20);
    lc.request(30); // absorbed: the window must not rewind
    lc.worker_done("w").expect("done");
    assert_eq!(lc.outcome(), Some(&CancelOutcome::Cancelled));
}

// ---------- budget ----------

#[test]
fn budget_spends_and_refuses_typed_overdraft() {
    let mut ledger = BudgetLedger::new(Budget::new(10, 100, 1_000));
    ledger.spend_work(4).expect("spend work");
    ledger.spend_bytes(50).expect("spend bytes");
    ledger.spend_wall(500).expect("spend wall");
    assert_eq!(ledger.remaining(), Budget::new(6, 50, 500));
    assert!(matches!(
        ledger.spend_work(7),
        Err(BudgetExhausted::WorkUnits {
            remaining: 6,
            requested: 7
        })
    ));
    assert!(matches!(
        ledger.spend_bytes(51),
        Err(BudgetExhausted::Bytes { .. })
    ));
    assert!(matches!(
        ledger.spend_wall(501),
        Err(BudgetExhausted::WallNs { .. })
    ));
    // A refused spend never decrements.
    assert_eq!(ledger.remaining(), Budget::new(6, 50, 500));
}

#[test]
fn zero_budget_refuses_any_spend() {
    let mut ledger = BudgetLedger::new(Budget::zero());
    assert!(ledger.spend_work(1).is_err());
    assert!(ledger.remaining().is_exhausted());
}

// ---------- obligations ----------

#[test]
fn obligations_register_terminate_and_leak_oracle_names_the_leak() {
    let mut reg = ObligationRegistry::new();
    reg.register("ob-1", "capture").expect("register");
    reg.register("ob-2", "publish").expect("register");
    assert!(!reg.is_clean());
    let leaks = reg.leaked();
    assert_eq!(leaks.len(), 2);
    reg.terminate("ob-1", ObligationTerminal::Completed).expect("terminate");
    assert!(!reg.is_clean());
    let leaks = reg.leaked();
    assert_eq!(leaks.len(), 1);
    assert_eq!(leaks[0].id, "ob-2");
    reg.terminate("ob-2", ObligationTerminal::Drained).expect("terminate");
    assert!(reg.is_clean());
    assert!(reg.leaked().is_empty());
}

#[test]
fn duplicate_and_unknown_obligations_are_typed_refusals() {
    let mut reg = ObligationRegistry::new();
    reg.register("ob-1", "capture").expect("register");
    assert!(matches!(
        reg.register("ob-1", "capture"),
        Err(ObligationError::Duplicate(_))
    ));
    assert!(matches!(
        reg.terminate("ghost", ObligationTerminal::Completed),
        Err(ObligationError::Unknown(_))
    ));
    reg.terminate("ob-1", ObligationTerminal::Completed).expect("terminate");
    assert!(matches!(
        reg.terminate("ob-1", ObligationTerminal::Drained),
        Err(ObligationError::AlreadyTerminal(_))
    ));
}

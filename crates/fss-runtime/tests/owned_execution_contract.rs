#![forbid(unsafe_code)]
//! Actual execution admission, task ownership, cancellation and terminal custody.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::error::Error;
use std::panic::{AssertUnwindSafe, catch_unwind};

use fss_core::{
    BudgetVector, BudgetVectorSpec, ContentDigest, OperationId, RegionId, RegionKind, RegionState,
    RegionTree, RootAuthoritySpec, RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_runtime::authority::AuthorityCx;
use fss_runtime::execution::{ExecutionError, TaskCompletion, TaskSpec, run_owned};
use fss_runtime::grant::{GrantError, GrantSet};
use fss_runtime::obligation::{ObligationTerminal, new_obligation};

type TestResult = Result<(), Box<dyn Error>>;

fn allowance() -> BudgetVector {
    let mut budget = BudgetVector::ZERO;
    budget.bytes = 100;
    budget.network_bytes = 100;
    budget.storage_operations = 10;
    budget.cpu_millis = 20;
    budget
}

fn spec(name: &str) -> Result<RootAuthoritySpec, Box<dyn Error>> {
    Ok(RootAuthoritySpec {
        trace_id: "trace:owned-task".into(),
        operation_id: OperationId::parse(format!("operation:{name}"))?,
        principal: "principal:owner".into(),
        capabilities: vec!["CAP-ADAPTER-NET-001".into()],
        deadline: Some(TimestampNs(100)),
        priority: 10,
        budgets: allowance(),
        privacy_scope: "privacy:local".into(),
        retention_scope: "retention:approved".into(),
        anchor_universe: ContentDigest::sha256(b"owned execution contract"),
        generation: 1,
    })
}

fn root() -> Result<(AuthorityCx, RegionTree), Box<dyn Error>> {
    Ok(AuthorityCx::root(
        spec("root")?,
        RegionId::new("region:owned-root")?,
        RegionKind::Process,
        allowance(),
        TimestampNs(1),
    )?)
}

fn task(name: &str, started_at: i128) -> Result<TaskSpec, Box<dyn Error>> {
    Ok(TaskSpec {
        task_id: TaskId::new(format!("task:{name}"))?,
        started_at: TimestampNs(started_at),
    })
}

fn completed<T>(output: T, outcome: TaskOutcome, now: i128) -> TaskCompletion<T> {
    TaskCompletion {
        output,
        outcome,
        completed_at: TimestampNs(now),
    }
}

fn close(authority: &AuthorityCx, tree: &mut RegionTree, now: i128) -> TestResult {
    authority.request_cancellation(tree, TimestampNs(now))?;
    authority.begin_drain(tree, TimestampNs(now))?;
    authority.finalize(tree, TimestampNs(now))?;
    Ok(())
}

#[test]
fn resources_drop_before_task_receipt_and_canonical_quiescence() -> TestResult {
    struct Resource<'a>(&'a Cell<bool>);
    impl Drop for Resource<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }
    let dropped = Cell::new(false);
    let (mut authority, mut tree) = root()?;
    let registration = task("capture", 2)?;
    let id = registration.task_id.clone();
    let result = run_owned(&mut authority, &mut tree, registration, |cx| {
        let _socket = Resource(&dropped);
        assert_eq!(cx.task_id(), &id);
        assert_eq!(cx.context().operation_id.as_str(), "operation:root");
        let output = cx.checkpoint(TimestampNs(3), &BudgetVector::ZERO);
        assert!(!dropped.get());
        completed(output, TaskOutcome::Success, 4)
    })?;
    result.output?;
    let receipt = result.receipt?;
    assert!(dropped.get());
    assert_eq!(receipt.task_id, id);
    assert_eq!(receipt.registered_at, TimestampNs(2));
    assert_eq!(receipt.completed_at, TimestampNs(4));
    assert!(tree.get(authority.region())?.active_tasks.is_empty());
    close(&authority, &mut tree, 5)?;
    assert_eq!(
        tree.get(authority.region())?
            .quiescence_proof
            .as_ref()
            .map(|p| p.total_tasks),
        Some(1)
    );
    Ok(())
}

#[test]
fn cloned_tree_and_duplicate_task_never_enter_the_native_closure() -> TestResult {
    let entered = Cell::new(0);
    let (mut authority, mut tree) = root()?;
    let mut snapshot = tree.clone();
    let registration = task("unique", 2)?;
    assert!(
        run_owned(&mut authority, &mut snapshot, registration.clone(), |_| {
            entered.set(entered.get() + 1);
            completed((), TaskOutcome::Success, 3)
        })
        .is_err()
    );
    run_owned(&mut authority, &mut tree, registration.clone(), |_| {
        entered.set(entered.get() + 1);
        completed((), TaskOutcome::Success, 3)
    })?
    .receipt?;
    assert!(
        run_owned(&mut authority, &mut tree, registration, |_| {
            entered.set(entered.get() + 1);
            completed((), TaskOutcome::Success, 4)
        })
        .is_err()
    );
    assert_eq!(entered.get(), 1);
    assert!(snapshot.get(authority.region())?.active_tasks.is_empty());
    assert!(snapshot.get(authority.region())?.completed_tasks.is_empty());
    Ok(())
}

#[test]
fn cancelled_or_expired_admission_never_starts_native_work() -> TestResult {
    let entered = Cell::new(false);
    let (mut authority, mut tree) = root()?;
    let result = run_owned(&mut authority, &mut tree, task("expired", 100)?, |_| {
        entered.set(true);
        completed((), TaskOutcome::Success, 100)
    });
    assert!(matches!(result, Err(ExecutionError::Deadline { .. })));
    authority.request_cancellation(&mut tree, TimestampNs(5))?;
    assert!(
        run_owned(&mut authority, &mut tree, task("cancelled", 6)?, |_| {
            entered.set(true);
            completed((), TaskOutcome::Success, 7)
        })
        .is_err()
    );
    assert!(!entered.get());
    assert!(tree.get(authority.region())?.active_tasks.is_empty());
    assert!(tree.get(authority.region())?.completed_tasks.is_empty());
    Ok(())
}

#[test]
fn a_later_task_cannot_rewind_past_canonical_execution_history() -> TestResult {
    let (mut authority, mut tree) = root()?;
    run_owned(&mut authority, &mut tree, task("first-clock", 2)?, |_| {
        completed((), TaskOutcome::Failed("deadline".into()), 101)
    })?
    .receipt?;
    let entered = Cell::new(false);
    let before = authority.budget().remaining();
    let result = run_owned(&mut authority, &mut tree, task("rewound", 3)?, |_| {
        entered.set(true);
        completed((), TaskOutcome::Success, 4)
    });
    assert!(matches!(
        result,
        Err(ExecutionError::ClockRegression {
            previous: TimestampNs(101),
            observed: TimestampNs(3),
        })
    ));
    assert!(!entered.get());
    assert_eq!(authority.budget().remaining(), before);
    assert_eq!(tree.get(authority.region())?.completed_tasks.len(), 1);

    let (mut authority, mut tree) = root()?;
    tree.register_task(
        authority.region(),
        TaskId::new("task:already-owned")?,
        TimestampNs(20),
    )?;
    assert!(matches!(
        run_owned(
            &mut authority,
            &mut tree,
            task("older-than-active", 19)?,
            |_| {
                entered.set(true);
                completed((), TaskOutcome::Success, 21)
            }
        ),
        Err(ExecutionError::ClockRegression {
            previous: TimestampNs(20),
            ..
        })
    ));
    assert!(!entered.get());
    Ok(())
}

#[test]
fn resource_grants_and_whole_cost_are_checked_before_debit() -> TestResult {
    let (mut authority, mut tree) = root()?;
    let net = RuntimeGrant::from_id("CAP-ADAPTER-NET-001")?;
    authority.narrow_grants(
        authority
            .grants()
            .clone()
            .with_scope(net, BTreeSet::from(["camera:a".to_string()])),
    )?;
    let result = run_owned(&mut authority, &mut tree, task("budgets", 2)?, |cx| {
        let output = (|| -> TestResult {
            let before = cx.remaining_budget()?;
            let mut cost = BudgetVector::ZERO;
            cost.bytes = 40;
            cost.network_bytes = 30;
            assert!(matches!(
                cx.checkpoint_for(net, "camera:b", TimestampNs(3), &cost),
                Err(ExecutionError::Grant(GrantError::OutsideScope { .. }))
            ));
            assert_eq!(cx.remaining_budget()?, before);
            cost.storage_operations = 11;
            assert!(matches!(
                cx.checkpoint_for(net, "camera:a", TimestampNs(4), &cost),
                Err(ExecutionError::Budget(_))
            ));
            assert_eq!(cx.remaining_budget()?, before);
            cost.storage_operations = 2;
            cx.checkpoint_for(net, "camera:a", TimestampNs(5), &cost)?;
            let remaining = cx.remaining_budget()?;
            assert_eq!(remaining.bytes, 60);
            assert_eq!(remaining.network_bytes, 70);
            assert_eq!(remaining.storage_operations, 8);
            Ok(())
        })();
        completed(output, TaskOutcome::Success, 6)
    })?;
    result.output?;
    result.receipt?;
    Ok(())
}

#[test]
fn context_metadata_cannot_restore_a_revoked_runtime_grant() -> TestResult {
    let (mut authority, mut tree) = root()?;
    authority.narrow_grants(GrantSet::empty())?;
    let net = RuntimeGrant::from_id("CAP-ADAPTER-NET-001")?;
    let result = run_owned(&mut authority, &mut tree, task("revoked", 2)?, |cx| {
        assert!(cx.context().has_capability("CAP-ADAPTER-NET-001"));
        assert!(matches!(
            cx.checkpoint_for(net, "camera:a", TimestampNs(3), &BudgetVector::ZERO),
            Err(ExecutionError::Grant(GrantError::MissingGrant { .. }))
        ));
        completed((), TaskOutcome::Failed("grant_revoked".into()), 4)
    })?;
    result.receipt?;
    Ok(())
}

#[test]
fn explicit_cancellation_stops_receiving_but_preserves_bounded_cleanup() -> TestResult {
    let (mut authority, mut tree) = root()?;
    let mut work = BudgetVector::ZERO;
    work.bytes = 20;
    let mut cleanup = BudgetVector::ZERO;
    cleanup.storage_operations = 1;
    let result = run_owned(&mut authority, &mut tree, task("drain", 2)?, |cx| {
        let output = (|| -> TestResult {
            cx.checkpoint(TimestampNs(3), &work)?;
            assert!(matches!(
                cx.cleanup_checkpoint(TimestampNs(4), &cleanup),
                Err(ExecutionError::NotDraining)
            ));
            cx.request_cancellation(TimestampNs(5))?;
            assert!(cx.is_cancel_requested()?);
            assert!(cx.checkpoint(TimestampNs(6), &work).is_err());
            cx.begin_drain(TimestampNs(7))?;
            cx.begin_drain(TimestampNs(7))?;
            cx.cleanup_checkpoint(TimestampNs(8), &cleanup)?;
            assert_eq!(cx.remaining_budget()?.bytes, 80);
            assert_eq!(cx.remaining_budget()?.storage_operations, 9);
            Ok(())
        })();
        completed(output, TaskOutcome::Cancelled, 9)
    })?;
    result.output?;
    assert_eq!(result.receipt?.outcome, TaskOutcome::Cancelled);
    assert_eq!(tree.get(authority.region())?.state, RegionState::Draining);
    assert_eq!(
        authority.finalize(&mut tree, TimestampNs(10))?.total_tasks,
        1
    );
    Ok(())
}

#[test]
fn normal_drain_can_finish_successfully_without_reopening_admission() -> TestResult {
    let (mut authority, mut tree) = root()?;
    let result = run_owned(&mut authority, &mut tree, task("normal-drain", 2)?, |cx| {
        let output = (|| -> TestResult {
            cx.begin_drain(TimestampNs(3))?;
            assert!(cx.checkpoint(TimestampNs(4), &BudgetVector::ZERO).is_err());
            cx.cleanup_checkpoint(TimestampNs(5), &BudgetVector::ZERO)?;
            Ok(())
        })();
        completed(output, TaskOutcome::Success, 6)
    })?;
    result.output?;
    assert_eq!(result.receipt?.outcome, TaskOutcome::Success);
    authority.finalize(&mut tree, TimestampNs(7))?;
    Ok(())
}

#[test]
fn deadline_refusal_is_irreversible_and_does_not_extend_cleanup() -> TestResult {
    let (mut authority, mut tree) = root()?;
    let result = run_owned(&mut authority, &mut tree, task("deadline", 2)?, |cx| {
        let output = (|| -> TestResult {
            cx.begin_drain(TimestampNs(3))?;
            assert!(matches!(
                cx.cleanup_checkpoint(TimestampNs(100), &BudgetVector::ZERO),
                Err(ExecutionError::Deadline { .. })
            ));
            assert!(matches!(
                cx.cleanup_checkpoint(TimestampNs(99), &BudgetVector::ZERO),
                Err(ExecutionError::ClockRegression { .. })
            ));
            Ok(())
        })();
        completed(output, TaskOutcome::Failed("deadline".into()), 101)
    })?;
    result.output?;
    result.receipt?;
    Ok(())
}

#[test]
fn success_after_deadline_without_a_late_checkpoint_keeps_task_active() -> TestResult {
    for completed_at in [100, 101] {
        let (mut authority, mut tree) = root()?;
        let registration = task("late-return", 2)?;
        let id = registration.task_id.clone();
        let result = run_owned(&mut authority, &mut tree, registration, |_| {
            completed(vec![7, 8, 9], TaskOutcome::Success, completed_at)
        })?;
        assert_eq!(result.output, vec![7, 8, 9]);
        assert!(matches!(
            result.receipt,
            Err(ExecutionError::Deadline { .. })
        ));
        assert!(tree.get(authority.region())?.active_tasks.contains_key(&id));
        assert!(tree.get(authority.region())?.completed_tasks.is_empty());
    }
    Ok(())
}

#[test]
fn ordinary_drain_does_not_manufacture_a_cancelled_task_receipt() -> TestResult {
    let (mut authority, mut tree) = root()?;
    let registration = task("not-cancelled", 2)?;
    let id = registration.task_id.clone();
    let result = run_owned(&mut authority, &mut tree, registration, |cx| {
        completed(cx.begin_drain(TimestampNs(3)), TaskOutcome::Cancelled, 4)
    })?;
    result.output?;
    assert!(matches!(
        result.receipt,
        Err(ExecutionError::InvalidCompletion)
    ));
    assert!(tree.get(authority.region())?.active_tasks.contains_key(&id));
    assert!(tree.get(authority.region())?.completed_tasks.is_empty());
    Ok(())
}

#[test]
fn invalid_completion_keeps_native_output_and_active_task_for_recovery() -> TestResult {
    for kind in [0, 1, 2] {
        let (mut authority, mut tree) = root()?;
        let registration = task("invalid", 2)?;
        let id = registration.task_id.clone();
        let result = run_owned(&mut authority, &mut tree, registration, |cx| {
            let observation = match kind {
                0 => cx.request_cancellation(TimestampNs(3)),
                1 => cx.checkpoint(TimestampNs(5), &BudgetVector::ZERO),
                _ => Ok(()),
            };
            completed(
                observation.map(|()| vec![1, 2, 3]),
                if kind == 2 {
                    TaskOutcome::Indeterminate("missing_custody".into())
                } else {
                    TaskOutcome::Success
                },
                4,
            )
        })?;
        assert_eq!(result.output?, vec![1, 2, 3]);
        assert!(result.receipt.is_err());
        assert!(tree.get(authority.region())?.active_tasks.contains_key(&id));
        assert!(tree.get(authority.region())?.completed_tasks.is_empty());
        authority.request_cancellation(&mut tree, TimestampNs(6))?;
        authority.begin_drain(&mut tree, TimestampNs(6))?;
        assert!(authority.finalize(&mut tree, TimestampNs(7)).is_err());
    }
    Ok(())
}

#[test]
fn panic_unwinds_resources_and_leaves_canonical_work_visible() -> TestResult {
    struct Resource<'a>(&'a Cell<bool>);
    impl Drop for Resource<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }
    let (mut authority, mut tree) = root()?;
    let dropped = Cell::new(false);
    let registration = task("unwind", 2)?;
    let id = registration.task_id.clone();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _ = run_owned(
            &mut authority,
            &mut tree,
            registration,
            |_| -> TaskCompletion<()> {
                let _socket = Resource(&dropped);
                std::panic::resume_unwind(Box::new("injected native boundary panic"));
            },
        );
    }));
    assert!(result.is_err());
    assert!(dropped.get());
    assert!(tree.get(authority.region())?.active_tasks.contains_key(&id));
    assert!(tree.get(authority.region())?.completed_tasks.is_empty());
    authority.request_cancellation(&mut tree, TimestampNs(4))?;
    authority.begin_drain(&mut tree, TimestampNs(4))?;
    assert!(authority.finalize(&mut tree, TimestampNs(5)).is_err());
    Ok(())
}

#[test]
fn custody_obligations_outlive_the_task_and_gate_quiescence() -> TestResult {
    let (mut authority, mut tree) = root()?;
    let obligation = new_obligation(
        "obligation:custody",
        OperationId::parse("operation:root")?,
        "source retained or exact recovery pin retained",
    )?;
    let id = obligation.obligation_id.clone();
    let result = run_owned(&mut authority, &mut tree, task("custody", 2)?, |cx| {
        let output = (|| -> TestResult {
            cx.register_obligation(obligation, TimestampNs(3))?;
            cx.begin_drain(TimestampNs(4))?;
            Ok(())
        })();
        completed(
            output,
            TaskOutcome::Indeterminate("publication_recovery_required".into()),
            5,
        )
    })?;
    result.output?;
    result.receipt?;
    assert!(tree.get(authority.region())?.active_tasks.is_empty());
    assert_eq!(authority.finalize_report(&tree)?.len(), 1);
    assert!(authority.finalize(&mut tree, TimestampNs(6)).is_err());
    authority.resolve_obligation(
        &mut tree,
        &id,
        ObligationTerminal::Indeterminate,
        None,
        Some("retained recovery pin: fixture-root"),
    )?;
    let proof = authority.finalize(&mut tree, TimestampNs(7))?;
    assert_eq!(proof.total_tasks, 1);
    assert_eq!(proof.indeterminate_obligations, 1);
    Ok(())
}

#[test]
fn bounded_cleanup_resolves_only_this_operation_and_preserves_terminal_rules() -> TestResult {
    let (mut authority, mut tree) = root()?;
    let own = new_obligation(
        "obligation:own",
        OperationId::parse("operation:root")?,
        "custody observed",
    )?;
    let foreign = new_obligation(
        "obligation:foreign",
        OperationId::parse("operation:other")?,
        "other custody",
    )?;
    let own_id = own.obligation_id.clone();
    let result = run_owned(&mut authority, &mut tree, task("resolve", 2)?, |cx| {
        let output = (|| -> TestResult {
            assert!(matches!(
                cx.register_obligation(foreign, TimestampNs(3)),
                Err(ExecutionError::ObligationOwnerMismatch)
            ));
            cx.register_obligation(own, TimestampNs(4))?;
            cx.begin_drain(TimestampNs(5))?;
            let proof = Some(ContentDigest::sha256(b"retained source root"));
            cx.resolve_obligation(
                &own_id,
                ObligationTerminal::Completed,
                proof,
                None,
                TimestampNs(6),
            )?;
            assert!(
                cx.resolve_obligation(
                    &own_id,
                    ObligationTerminal::Failed,
                    proof,
                    None,
                    TimestampNs(7)
                )
                .is_err()
            );
            Ok(())
        })();
        completed(output, TaskOutcome::Success, 8)
    })?;
    result.output?;
    result.receipt?;
    assert!(authority.finalize_report(&tree)?.is_empty());
    authority.finalize(&mut tree, TimestampNs(9))?;
    Ok(())
}

#[test]
fn unsupported_accounting_does_not_silently_consume_zero() -> TestResult {
    let (mut authority, mut tree) = root()?;
    let cost = BudgetVector::new(BudgetVectorSpec {
        privacy_exposure: 0.25,
        ..BudgetVectorSpec::ZERO
    })?;
    let result = run_owned(&mut authority, &mut tree, task("cost", 2)?, |cx| {
        let output = (|| -> TestResult {
            let before = cx.remaining_budget()?;
            assert!(matches!(
                cx.checkpoint(TimestampNs(3), &cost),
                Err(ExecutionError::UnmeteredCost)
            ));
            assert_eq!(cx.remaining_budget()?, before);
            Ok(())
        })();
        completed(output, TaskOutcome::Failed("unsupported_cost".into()), 4)
    })?;
    result.output?;
    result.receipt?;
    Ok(())
}

#[test]
fn cancellation_stays_with_the_executing_sensor_and_charges_its_parent() -> TestResult {
    let (mut root, mut tree) = root()?;
    let mut property = root.scope_down(
        &mut tree,
        RegionId::new("region:property")?,
        RegionKind::Property,
        allowance(),
        spec("property")?,
        TimestampNs(2),
    )?;
    let mut half = allowance();
    half.bytes = 50;
    half.network_bytes = 50;
    half.cpu_millis = 10;
    half.storage_operations = 5;
    let mut first = property.scope_down(
        &mut tree,
        RegionId::new("region:first")?,
        RegionKind::Sensor,
        half,
        spec("first")?,
        TimestampNs(3),
    )?;
    let mut second = property.scope_down(
        &mut tree,
        RegionId::new("region:second")?,
        RegionKind::Sensor,
        half,
        spec("second")?,
        TimestampNs(3),
    )?;
    let run = run_owned(&mut first, &mut tree, task("first", 4)?, |cx| {
        let mut cost = BudgetVector::ZERO;
        cost.bytes = 10;
        let output = cx
            .checkpoint(TimestampNs(5), &cost)
            .and_then(|()| cx.request_cancellation(TimestampNs(6)))
            .and_then(|()| cx.begin_drain(TimestampNs(6)));
        completed(output, TaskOutcome::Cancelled, 7)
    })?;
    run.output?;
    run.receipt?;
    assert!(!second.is_cancel_requested(&tree)?);
    assert!(!property.is_cancel_requested(&tree)?);
    let run = run_owned(&mut second, &mut tree, task("second", 8)?, |cx| {
        completed(
            cx.checkpoint(TimestampNs(9), &BudgetVector::ZERO),
            TaskOutcome::Success,
            10,
        )
    })?;
    run.output?;
    run.receipt?;
    first.finalize(&mut tree, TimestampNs(11))?;
    property.release_scope_reservation(&tree, &mut first)?;
    assert_eq!(property.budget().remaining().bytes, 40);
    close(&second, &mut tree, 12)?;
    property.release_scope_reservation(&tree, &mut second)?;
    assert_eq!(property.budget().remaining().bytes, 90);
    close(&property, &mut tree, 13)?;
    root.release_scope_reservation(&tree, &mut property)?;
    assert_eq!(root.budget().remaining().bytes, 90);
    close(&root, &mut tree, 14)?;
    assert_eq!(
        tree.get(root.region())?
            .quiescence_proof
            .as_ref()
            .map(|proof| proof.total_tasks),
        Some(2)
    );
    Ok(())
}

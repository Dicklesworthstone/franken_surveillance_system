#![forbid(unsafe_code)]
//! Task-owned effect preparation, permit preservation and obligation tracking.
use asupersync::runtime::RuntimeBuilder;
use fss_core::{
    BudgetVector, ContentDigest, IdempotencyKey, OperationId, RegionId, RegionKind,
    RootAuthoritySpec, RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_runtime::{
    authority::AuthorityCx,
    effect::{CommitApproval, EffectCoordinator, PrepareSpec, PreparedEffect},
    execution::{ExecutionError, TaskCompletion, TaskEffectError, TaskSpec, run_owned_async},
    lease::LeaseRegistry,
};
use std::error::Error;

type Test = Result<(), Box<dyn Error>>;
const RESOURCE: &str = "camera:fixture";
fn setup() -> Result<(AuthorityCx, fss_core::RegionTree, LeaseRegistry, u64), Box<dyn Error>> {
    let budget = BudgetVector::ZERO;
    let (authority, tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:task-effect".into(),
            operation_id: OperationId::parse("operation:task-owner")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::CameraManagementCommit.as_str().into(),
                RuntimeGrant::CameraManagementPrepare.as_str().into(),
            ],
            deadline: Some(TimestampNs(100)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"fixture"),
            generation: 1,
        },
        RegionId::new("region:task-effect")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let mut leases = LeaseRegistry::new();
    let fence = leases
        .acquire(RESOURCE, authority.region().as_str(), None, TimestampNs(2))?
        .fence;
    Ok((authority, tree, leases, fence))
}
fn spec<'a>(op: &'a OperationId, fence: u64) -> Result<PrepareSpec<'a>, Box<dyn Error>> {
    Ok(PrepareSpec {
        operation: op,
        idempotency_key: IdempotencyKey::parse(op.as_str())?,
        request_digest: ContentDigest::sha256(b"message"),
        precondition_digest: ContentDigest::sha256(b"preconditions"),
        resource: RESOURCE,
        fence,
        prepare_grant: RuntimeGrant::CameraManagementPrepare,
        commit_grant: RuntimeGrant::CameraManagementCommit,
        terminal_predicate: "independent management readback",
    })
}
fn approval(prepared: &PreparedEffect) -> CommitApproval {
    CommitApproval {
        prepared_digest: prepared.digest(),
        current_precondition_digest: ContentDigest::sha256(b"preconditions"),
    }
}

#[test]
fn observed_task_can_prepare_and_commit_with_retained_failed_approval() -> Test {
    let (mut authority, mut tree, mut leases, fence) = setup()?;
    let mut effects = EffectCoordinator::new();
    let operation = OperationId::parse("operation:observed-hello")?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:observed-hello")?,
                started_at: TimestampNs(3),
            },
            &cx,
            async |task, cx| {
                let output: Test = async {
                    let prepared = task.prepare_effect(
                        cx,
                        &mut effects,
                        &mut leases,
                        spec(&operation, fence)?,
                        TimestampNs(4),
                    )?;
                    let mut wrong = approval(&prepared);
                    wrong.current_precondition_digest = ContentDigest::sha256(b"wrong");
                    let refused = task
                        .commit_effect(
                            cx,
                            &mut effects,
                            &mut leases,
                            prepared,
                            TimestampNs(5),
                            wrong,
                        )
                        .expect_err("stale approval");
                    assert!(matches!(refused.reason, TaskEffectError::Coordinator(_)));
                    let prepared = refused.into_prepared();
                    let approved = approval(&prepared);
                    let permit = task.commit_effect(
                        cx,
                        &mut effects,
                        &mut leases,
                        prepared,
                        TimestampNs(6),
                        approved,
                    )?;
                    assert!(!permit.journal_backed());
                    assert_eq!(
                        permit.prepared().effect_class(),
                        "EFFECT-CAMERA-MANAGEMENT-001"
                    );
                    drop(permit);
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Indeterminate("fixture effect needs reconciliation".into())
                } else {
                    TaskOutcome::Failed("fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(7),
                }
            },
        )
        .await?;
        result.receipt?;
        result.output
    })?;
    assert_eq!(
        effects
            .journal()
            .operation(&operation)
            .ok_or("missing effect")?
            .state,
        fss_core::EffectState::Committed
    );
    assert!(!authority.finalize_report(&tree)?.is_empty());
    Ok(())
}

#[test]
fn another_task_cannot_claim_or_commit_existing_preparation() -> Test {
    let (mut authority, mut tree, mut leases, fence) = setup()?;
    let mut effects = EffectCoordinator::new();
    let operation = OperationId::parse("operation:other-task")?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    let prepared = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:first")?,
                started_at: TimestampNs(3),
            },
            &cx,
            async |task, cx| {
                let output = task.prepare_effect(
                    cx,
                    &mut effects,
                    &mut leases,
                    spec(&operation, fence).expect("fixture spec"),
                    TimestampNs(4),
                );
                TaskCompletion {
                    output,
                    outcome: TaskOutcome::Success,
                    completed_at: TimestampNs(5),
                }
            },
        )
        .await?;
        result.receipt?;
        Ok::<_, Box<dyn Error>>(result.output?)
    })?;
    let prepared = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:second")?,
                started_at: TimestampNs(6),
            },
            &cx,
            async |task, cx| {
                let output: Result<PreparedEffect, Box<dyn Error>> = (|| {
                    let approved = approval(&prepared);
                    let refused = task
                        .commit_effect(
                            cx,
                            &mut effects,
                            &mut leases,
                            prepared,
                            TimestampNs(7),
                            approved,
                        )
                        .expect_err("foreign commit must fail");
                    assert!(matches!(
                        refused.reason,
                        TaskEffectError::Execution(ExecutionError::ObligationOwnerMismatch)
                    ));
                    let prepared = refused.into_prepared();
                    assert!(matches!(
                        task.prepare_effect(
                            cx,
                            &mut effects,
                            &mut leases,
                            spec(&operation, fence)?,
                            TimestampNs(8)
                        ),
                        Err(TaskEffectError::ForeignPreparation)
                    ));
                    Ok(prepared)
                })();
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("foreign fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(9),
                }
            },
        )
        .await?;
        result.receipt?;
        result.output
    })?;
    effects.cancel_prepared(
        &mut tree,
        &authority,
        prepared,
        ContentDigest::sha256(b"fixture cancel"),
        TimestampNs(10),
    )?;
    assert!(authority.finalize_report(&tree)?.is_empty());
    Ok(())
}

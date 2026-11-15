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
fn owning_task_cancels_prepared_effect_with_caller_evidence() -> Test {
    let (mut authority, mut tree, mut leases, fence) = setup()?;
    let mut effects = EffectCoordinator::new();
    let operation = OperationId::parse("operation:cancel-before-dispatch")?;
    let evidence = ContentDigest::sha256(b"retained fixture cancellation evidence");
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:cancel-before-dispatch")?,
                started_at: TimestampNs(3),
            },
            &cx,
            async |task, cx| {
                let output: Test = (|| {
                    let prepared = task.prepare_effect(
                        cx,
                        &mut effects,
                        &mut leases,
                        spec(&operation, fence)?,
                        TimestampNs(4),
                    )?;
                    task.cancel_prepared_effect(
                        cx,
                        &mut effects,
                        prepared,
                        evidence,
                        TimestampNs(5),
                    )?;
                    Ok(())
                })();
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("cancellation fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(6),
                }
            },
        )
        .await?;
        result.receipt?;
        result.output
    })?;
    let receipt = effects
        .journal()
        .operation(&operation)
        .ok_or("missing effect")?;
    assert_eq!(receipt.state, fss_core::EffectState::Cancelled);
    assert_eq!(
        receipt.result_digest,
        Some(effects.journal().cancellation_proof(&operation, evidence)?)
    );
    assert_eq!(
        effects.journal().cancellation_record_version(&operation),
        Some(fss_core::effect::EffectRecordVersion::V3)
    );
    assert!(authority.finalize_report(&tree)?.is_empty());
    Ok(())
}

#[test]
fn owning_task_verifies_only_the_recorded_observation_and_retains_refused_permit() -> Test {
    let (mut authority, mut tree, mut leases, fence) = setup()?;
    let mut effects = EffectCoordinator::new();
    let operation = OperationId::parse("operation:verify-observed")?;
    let proof = ContentDigest::sha256(b"independently retained observation");
    let wrong = ContentDigest::sha256(b"different observation");
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:verify-observed")?,
                started_at: TimestampNs(3),
            },
            &cx,
            async |task, cx| {
                let output: Test = (|| {
                    let prepared = task.prepare_effect(
                        cx,
                        &mut effects,
                        &mut leases,
                        spec(&operation, fence)?,
                        TimestampNs(4),
                    )?;
                    let approved = approval(&prepared);
                    let effect = task.commit_effect(
                        cx,
                        &mut effects,
                        &mut leases,
                        prepared,
                        TimestampNs(5),
                        approved,
                    )?;
                    let refused = task
                        .verify_effect(cx, &mut effects, effect, proof, TimestampNs(6))
                        .expect_err("an unobserved effect must not be verified");
                    assert!(matches!(refused.reason, TaskEffectError::Coordinator(_)));
                    let mut effect = refused.into_effect();
                    effects.adapter_accepted(&mut effect, None, TimestampNs(7))?;
                    effects.observed(&mut effect, proof, TimestampNs(8))?;
                    let refused = task
                        .verify_effect(cx, &mut effects, effect, wrong, TimestampNs(9))
                        .expect_err("different proof must not settle the effect");
                    assert!(matches!(refused.reason, TaskEffectError::Coordinator(_)));
                    assert_eq!(
                        effects
                            .journal()
                            .operation(&operation)
                            .ok_or("missing effect")?
                            .state,
                        fss_core::EffectState::Observed
                    );
                    task.verify_effect(
                        cx,
                        &mut effects,
                        refused.into_effect(),
                        proof,
                        TimestampNs(10),
                    )?;
                    Ok(())
                })();
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("verification fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(11),
                }
            },
        )
        .await?;
        result.receipt?;
        result.output
    })?;
    let record = effects
        .journal()
        .operation(&operation)
        .ok_or("missing effect")?;
    assert_eq!(record.state, fss_core::EffectState::Verified);
    assert_eq!(record.result_digest, Some(proof));
    assert!(authority.finalize_report(&tree)?.is_empty());
    Ok(())
}

#[test]
fn another_task_cannot_verify_the_committed_effect() -> Test {
    let (mut authority, mut tree, mut leases, fence) = setup()?;
    let mut effects = EffectCoordinator::new();
    let operation = OperationId::parse("operation:foreign-verify")?;
    let proof = ContentDigest::sha256(b"fixture observed outcome");
    let runtime = RuntimeBuilder::current_thread().build()?;
    let effect = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:verification-owner")?,
                started_at: TimestampNs(3),
            },
            &cx,
            async |task, cx| {
                let output = (|| {
                    let prepared = task.prepare_effect(
                        cx,
                        &mut effects,
                        &mut leases,
                        spec(&operation, fence)?,
                        TimestampNs(4),
                    )?;
                    let approved = approval(&prepared);
                    let mut effect = task.commit_effect(
                        cx,
                        &mut effects,
                        &mut leases,
                        prepared,
                        TimestampNs(5),
                        approved,
                    )?;
                    effects.adapter_accepted(&mut effect, None, TimestampNs(6))?;
                    effects.observed(&mut effect, proof, TimestampNs(7))?;
                    Ok::<_, Box<dyn Error>>(effect)
                })();
                TaskCompletion {
                    output,
                    outcome: TaskOutcome::Indeterminate("fixture observation retained".into()),
                    completed_at: TimestampNs(8),
                }
            },
        )
        .await?;
        result.receipt?;
        result.output
    })?;
    let effect = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:foreign-verifier")?,
                started_at: TimestampNs(9),
            },
            &cx,
            async |task, cx| {
                let refused = task
                    .verify_effect(cx, &mut effects, effect, proof, TimestampNs(10))
                    .expect_err("a foreign task must not verify the effect");
                let output = if matches!(
                    refused.reason,
                    TaskEffectError::Execution(ExecutionError::ObligationOwnerMismatch)
                ) {
                    Ok(refused.into_effect())
                } else {
                    Err("unexpected foreign-verification refusal")
                };
                TaskCompletion {
                    output,
                    outcome: TaskOutcome::Success,
                    completed_at: TimestampNs(11),
                }
            },
        )
        .await?;
        result.receipt?;
        result
            .output
            .map_err(|error| -> Box<dyn Error> { error.into() })
    })?;
    assert_eq!(
        effects
            .journal()
            .operation(&operation)
            .ok_or("missing effect")?
            .state,
        fss_core::EffectState::Observed
    );
    effects.verified(&mut tree, &authority, effect, proof, TimestampNs(12))?;
    assert_eq!(
        effects
            .journal()
            .operation(&operation)
            .ok_or("missing effect")?
            .state,
        fss_core::EffectState::Verified
    );
    Ok(())
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
                    let inert = effects.prepared(&operation).ok_or("missing preparation")?;
                    let refusal = task
                        .cancel_prepared_effect(
                            cx,
                            &mut effects,
                            inert,
                            ContentDigest::sha256(b"late cancel"),
                            TimestampNs(7),
                        )
                        .expect_err("committed effect must not be cancelled as prepared");
                    assert!(matches!(refusal.reason, TaskEffectError::Coordinator(_)));
                    assert_eq!(refusal.into_prepared().operation(), &operation);
                    assert_eq!(
                        effects
                            .journal()
                            .operation(&operation)
                            .ok_or("missing effect")?
                            .state,
                        fss_core::EffectState::Committed
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
                    completed_at: TimestampNs(8),
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
                    let refusal = task
                        .cancel_prepared_effect(
                            cx,
                            &mut effects,
                            prepared,
                            ContentDigest::sha256(b"foreign fixture cancellation"),
                            TimestampNs(8),
                        )
                        .expect_err("foreign cancellation must fail");
                    assert!(matches!(
                        refusal.reason,
                        TaskEffectError::Execution(ExecutionError::ObligationOwnerMismatch)
                    ));
                    let prepared = refusal.into_prepared();
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

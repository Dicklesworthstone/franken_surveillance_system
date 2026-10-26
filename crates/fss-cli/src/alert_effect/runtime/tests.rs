#![forbid(unsafe_code)]
//! Scripted owner tests: no socket, clock sleep, file read or detached worker is needed.

use super::*;
use fss_core::{EffectIntent, EffectJournal, IdempotencyKey, OperationId};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const BASE: u64 = 100;
const NETWORK_DEADLINE: u64 = BASE + 5_000_000;
const CLEANUP_DEADLINE: u64 = BASE + 10_000_000;

struct Clock {
    elapsed: Cell<u64>,
    reads: Cell<u64>,
    waits: Cell<u64>,
    wait_ns: Cell<u64>,
}
impl Clock {
    fn new() -> Self {
        Self {
            elapsed: Cell::new(0),
            reads: Cell::new(0),
            waits: Cell::new(0),
            wait_ns: Cell::new(1_000_000),
        }
    }
}
impl DispatchClock for Clock {
    fn elapsed_ns(&self) -> Option<u64> {
        self.reads.set(self.reads.get() + 1);
        Some(self.elapsed.get())
    }
    fn wait_one_ms(&self) {
        self.waits.set(self.waits.get() + 1);
        self.elapsed.set(self.elapsed.get() + self.wait_ns.get());
    }
}

struct Fixture {
    source: ContextAuthority,
    cx: ReplayCx,
    endpoint: WebhookEndpoint,
    prepared: OperationReceipt,
    clock: Clock,
    path: PathBuf,
}
impl Fixture {
    fn new(allowance: BudgetVector, original_deadline: Option<TimestampNs>) -> Test<Self> {
        let source = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:owned-alert-test".into(),
            operation_id: OperationId::parse("operation:owned-alert-test")?,
            principal: "principal:local-operator".into(),
            capabilities: vec!["ADP-REPLAY-001".into(), CAP_ALERT_COMMIT.into()],
            deadline: original_deadline,
            priority: 10,
            budgets: allowance,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"owned-alert-test"),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority_read_only(
            &source,
            PathBuf::from("/owned-alert-test"),
        )?;
        let endpoint = WebhookEndpoint::new(
            "127.0.0.1:9".parse()?,
            "/notify",
            ContentDigest::sha256(b"test plaintext approval"),
        )?;
        let mut journal = EffectJournal::new();
        let operation = OperationId::parse("operation:prepared-alert-test")?;
        journal.prepare(
            EffectIntent::new(
                operation.clone(),
                IdempotencyKey::parse("idempotency:prepared-alert-test")?,
                "alert.dispatch",
                ContentDigest::sha256(b"request"),
                ContentDigest::sha256(b"preconditions"),
            )?,
            ObligationId::parse("obligation:prepared-alert-test")?,
            "independent delivery proof",
            timestamp(1),
        )?;
        let prepared = journal
            .operation(&operation)
            .ok_or("prepared operation")?
            .clone();
        Ok(Self {
            source,
            cx,
            endpoint,
            prepared,
            clock: Clock::new(),
            path: PathBuf::from("/owned-alert-test/effects"),
        })
    }
    fn scope<'a>(&'a self, operation: &'a OperationReceipt) -> WebhookScope<'a> {
        WebhookScope {
            endpoint: &self.endpoint,
            operation,
            effect_journal: &self.path,
        }
    }
    fn committed(&self) -> OperationReceipt {
        let mut operation = self.prepared.clone();
        operation.state = EffectState::Committed;
        operation
    }
    fn run(
        &self,
        work: impl FnOnce(&DispatchOwner<'_, '_, Clock>) -> Test,
    ) -> Test<(BudgetVector, QuiescenceProof)> {
        let allowance = self.source.budgets;
        let mut runtime = RuntimeOwner::new(
            &self.source,
            allowance,
            timestamp(CLEANUP_DEADLINE),
            timestamp(BASE),
        )?;
        let run = run_owned(
            &mut runtime.alert,
            &mut runtime.tree,
            TaskSpec {
                task_id: TaskId::new("task:owned-alert-test")?,
                started_at: timestamp(BASE),
            },
            |task| {
                let owner = DispatchOwner {
                    task,
                    cx: &self.cx,
                    route: self.endpoint.digest(),
                    journal: self.path.clone(),
                    prepared: &self.prepared,
                    clock: &self.clock,
                    base_ns: BASE,
                    network_deadline_ns: NETWORK_DEADLINE,
                    last_ns: Cell::new(BASE),
                    interrupted: Cell::new(None),
                    cancellation_reflected: Cell::new(false),
                    pending_socket: Cell::new(None),
                    network_admissions: Cell::new(0),
                };
                let result = (|| -> Test {
                    task.checkpoint_for(
                        RuntimeGrant::AlertCommit,
                        RESOURCE,
                        timestamp(BASE),
                        &cost(allowance.bytes, allowance.latency_ms, 0, JOURNAL_OPERATIONS),
                    )?;
                    work(&owner)
                })();
                let _ = owner.drain_time();
                TaskCompletion {
                    output: result,
                    outcome: if self.cx.is_cancelled() {
                        TaskOutcome::Cancelled
                    } else {
                        TaskOutcome::Failed("scripted owner test complete".into())
                    },
                    completed_at: timestamp(owner.last_ns.get()),
                }
            },
        )?;
        run.output?;
        run.receipt?;
        let consumed = *runtime.alert.budget().consumed();
        let proof = runtime.finish(timestamp(BASE + self.clock.elapsed.get()))?;
        Ok((consumed, proof))
    }
}
fn allowance() -> BudgetVector {
    cost(65_536, 10, 2 * IO_BYTES, 8)
}

#[test]
fn native_network_deadline_keeps_the_original_ceiling_and_refuses_expiry() -> Test {
    assert_eq!(network_deadline(BASE, 5, None)?, NETWORK_DEADLINE);
    assert_eq!(
        network_deadline(BASE, 5, Some(timestamp(BASE + 2_000_000)))?,
        BASE + 2_000_000
    );
    assert_eq!(
        network_deadline(BASE, 5, Some(timestamp(CLEANUP_DEADLINE)))?,
        NETWORK_DEADLINE
    );
    assert!(network_deadline(BASE, 5, Some(timestamp(BASE))).is_err());
    assert!(network_deadline(BASE, 5, Some(TimestampNs(-1))).is_err());
    Ok(())
}

#[test]
fn socket_admission_is_charged_once_across_source_recheck_and_never_refilled() -> Test {
    let f = Fixture::new(allowance(), None)?;
    let committed = f.committed();
    let (consumed, proof) = f.run(|owner| {
        for boundary in [
            WebhookBoundary::Connect,
            WebhookBoundary::Connect,
            WebhookBoundary::AfterIo,
            WebhookBoundary::Configure,
            WebhookBoundary::AfterIo,
        ] {
            owner
                .checkpoint(f.scope(&committed), boundary, BASE, NETWORK_DEADLINE)
                .map_err(|_| "unexpected socket admission refusal")?;
        }
        assert_eq!(owner.network_admissions.get(), 2);
        assert_eq!(
            owner.checkpoint(
                f.scope(&committed),
                WebhookBoundary::Send,
                BASE,
                NETWORK_DEADLINE
            ),
            Err(WebhookDenial::Budget)
        );
        assert_eq!(
            owner.checkpoint(
                f.scope(&committed),
                WebhookBoundary::Send,
                BASE,
                NETWORK_DEADLINE
            ),
            Err(WebhookDenial::Budget)
        );
        assert_eq!(owner.network_admissions.get(), 2);
        Ok(())
    })?;
    assert_eq!(consumed.network_bytes, 2 * IO_BYTES);
    assert_eq!(proof.total_tasks, 1);
    Ok(())
}

#[test]
fn source_read_admissions_keep_failed_work_and_stop_before_overdraft() -> Test {
    let f = Fixture::new(cost(65_536, 10, IO_BYTES, JOURNAL_OPERATIONS + 2), None)?;
    let (consumed, _) = f.run(|owner| {
        owner.source_read()?;
        owner.after_source_read()?;
        owner.source_read()?; // A subsequent physical read failing cannot refund this admission.
        assert!(owner.source_read().is_err());
        assert!(owner.source_read().is_err());
        Ok(())
    })?;
    assert_eq!(consumed.storage_operations, JOURNAL_OPERATIONS + 2);
    assert_eq!(consumed.bytes, 65_536);
    assert_eq!(consumed.latency_ms, 10);
    Ok(())
}

#[test]
fn network_deadline_leaves_only_prepaid_finite_recording_authority() -> Test {
    let f = Fixture::new(allowance(), None)?;
    let committed = f.committed();
    f.run(|owner| {
        f.clock.elapsed.set(5_000_000);
        assert_eq!(owner.active_time(), Err(WebhookDenial::Deadline));
        assert_eq!(
            owner.checkpoint(
                f.scope(&committed),
                WebhookBoundary::Record,
                NETWORK_DEADLINE,
                NETWORK_DEADLINE
            ),
            Ok(())
        );
        assert_eq!(
            owner.checkpoint(
                f.scope(&committed),
                WebhookBoundary::Connect,
                NETWORK_DEADLINE,
                NETWORK_DEADLINE
            ),
            Err(WebhookDenial::Deadline)
        );
        f.clock.elapsed.set(10_000_000);
        assert_eq!(
            owner.checkpoint(
                f.scope(&committed),
                WebhookBoundary::Record,
                CLEANUP_DEADLINE,
                NETWORK_DEADLINE
            ),
            Err(WebhookDenial::Deadline)
        );
        Ok(())
    })?;
    Ok(())
}

#[test]
fn original_deadline_cannot_be_extended_by_the_cleanup_allowance() -> Test {
    let f = Fixture::new(allowance(), Some(timestamp(BASE + 2_000_000)))?;
    let committed = f.committed();
    f.run(|owner| {
        f.clock.elapsed.set(2_000_000);
        assert_eq!(
            owner.checkpoint(
                f.scope(&committed),
                WebhookBoundary::Record,
                BASE + 2_000_000,
                NETWORK_DEADLINE
            ),
            Err(WebhookDenial::Deadline)
        );
        Ok(())
    })?;
    Ok(())
}

#[test]
fn cancellation_refuses_new_clock_and_source_work_and_revokes_recording_io() -> Test {
    let f = Fixture::new(allowance(), None)?;
    let committed = f.committed();
    f.run(|owner| {
        f.cx.request_cancellation();
        assert_eq!(owner.active_time(), Err(WebhookDenial::Cancelled));
        assert_eq!(
            f.clock.reads.get(),
            0,
            "cancellation must precede the native clock read"
        );
        assert!(owner.source_read().is_err());
        assert_eq!(
            owner.checkpoint(
                f.scope(&committed),
                WebhookBoundary::Record,
                BASE,
                NETWORK_DEADLINE
            ),
            Err(WebhookDenial::Revoked)
        );
        assert_eq!(owner.network_admissions.get(), 0);
        Ok(())
    })?;
    Ok(())
}

#[test]
fn an_overslept_owned_wait_cannot_admit_another_network_operation() -> Test {
    let f = Fixture::new(allowance(), None)?;
    let committed = f.committed();
    f.run(|owner| {
        f.clock.wait_ns.set(6_000_000);
        assert_eq!(owner.wait(), Err(WebhookDenial::Deadline));
        assert_eq!(f.clock.waits.get(), 1);
        assert_eq!(
            owner.checkpoint(
                f.scope(&committed),
                WebhookBoundary::Connect,
                BASE + 6_000_000,
                NETWORK_DEADLINE
            ),
            Err(WebhookDenial::Deadline)
        );
        assert_eq!(owner.network_admissions.get(), 0);
        Ok(())
    })?;
    Ok(())
}

#[test]
fn exact_durable_effect_authority_cannot_be_substituted() -> Test {
    for part in ["principal", "capability", "fence"] {
        let f = Fixture::new(allowance(), None)?;
        let mut operation = f.committed();
        match part {
            "principal" => operation.authority.principal = "principal:other".into(),
            "capability" => operation.authority.capability = "effect:other".into(),
            _ => operation.authority.lease_fence = Some(1),
        }
        f.run(|owner| {
            assert_eq!(
                owner.checkpoint(
                    f.scope(&operation),
                    WebhookBoundary::Connect,
                    BASE,
                    NETWORK_DEADLINE
                ),
                Err(WebhookDenial::Unauthorized)
            );
            assert_eq!(owner.network_admissions.get(), 0);
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn translated_runtime_grants_remain_scoped_to_the_exact_private_dispatch_resource() -> Test {
    let f = Fixture::new(allowance(), None)?;
    f.run(|owner| {
        assert!(
            owner
                .task
                .checkpoint_for(
                    RuntimeGrant::AdapterNet,
                    "other:route",
                    timestamp(BASE),
                    &BudgetVector::ZERO
                )
                .is_err()
        );
        assert!(
            owner
                .task
                .checkpoint_for(
                    RuntimeGrant::AlertCommit,
                    "other:journal",
                    timestamp(BASE),
                    &BudgetVector::ZERO
                )
                .is_err()
        );
        assert_eq!(owner.task.context().principal, f.source.principal);
        assert_eq!(owner.task.context().trace_id, f.source.trace_id);
        assert_eq!(owner.task.context().privacy_scope, f.source.privacy_scope);
        assert_eq!(
            owner.task.context().retention_scope,
            f.source.retention_scope
        );
        assert_eq!(owner.task.context().generation, f.source.generation);
        assert_eq!(
            owner.task.context().anchor_universe,
            f.source.anchor_universe
        );
        Ok(())
    })?;
    Ok(())
}

#![forbid(unsafe_code)]
//! Canonical ownership for one exact-approved synchronous webhook attempt. The original durable
//! effect journal owns delivery; this owner accounts for and retires the actual native resources.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, EffectState, ObligationId, OperationReceipt,
    QuiescenceProof, RegionId, RegionKind, RegionTree, RootAuthoritySpec, RuntimeGrant, TaskId,
    TaskOutcome, TaskReceipt, TimestampNs,
};
use fss_publication::LocalPublicationError;
use fss_reference::webhook::{
    WebhookAttempt, WebhookAuthority, WebhookBoundary, WebhookDenial, WebhookEndpoint,
    WebhookError, WebhookEvidence, WebhookLimits, WebhookOutcome, WebhookProgress, WebhookScope,
};
use fss_reference::{ReferenceAlertPlan, ReferenceDeployment, ReferenceError, ReplayCx};
use fss_runtime::authority::AuthorityCx;
use fss_runtime::execution::{ExecutionError, TaskCompletion, TaskCx, TaskSpec, run_owned};
use fss_runtime::obligation::{ObligationTerminal, new_obligation};

use super::{
    AlertDispatch, AlertEffectError, CAP_ALERT_COMMIT, DISPATCH_CLEANUP_MS, MAX_DEADLINE_MS,
    MAX_DISPATCH_NETWORK_BYTES, MAX_DISPATCH_STORAGE_OPERATIONS, not_eligible, wall_ns,
};

const SOURCE_BYTES: u64 = 64 * 1024 * 1024;
const IO_BYTES: u64 = 4096;
const JOURNAL_OPERATIONS: u64 = 2;
const RESOURCE: &str = "alert-dispatch:approved-operation";
const LOCAL_OBLIGATION: &str = "obligation:alert-dispatch:local-retirement";

/// Execution accounting is independent of relay acknowledgement and human delivery.
/// Byte/latency values are conservative prepaid reservations. Each native socket admission
/// reserves a complete 4096-byte envelope, including failed/blocked calls. Storage counts source
/// admissions and two prepaid journal transitions, not filesystem syscalls. Opening recovery,
/// CPU, allocator peaks and journal serialization bytes are outside these meters.
#[derive(Debug)]
pub struct AlertRuntimeSummary {
    /// Present only after native resources retired and `run_owned` accepted the classification.
    pub task_receipt: Option<TaskReceipt>,
    /// Complete Process → Property → Event → AlertObligation closure, when actually proved.
    pub quiescence: Option<QuiescenceProof>,
    /// Reservations and debits remain spent after failed work.
    pub consumed: BudgetVector,
    /// Remaining owned allowance; zero never means unlimited.
    pub remaining: BudgetVector,
    /// Native socket admissions, distinct from actual calls retained in wire evidence.
    pub network_admissions: u64,
    /// Cumulative spool envelope reservations during this attempt, including failed reads.
    pub source_read_reserved_bytes: u64,
    /// Cumulative source read attempts during this attempt, including failures.
    pub source_read_attempts: u64,
    /// Local recording/retirement requires recovery. False does not settle delivery.
    pub recovery_required: bool,
    /// Why local outcome recording did not complete, if applicable.
    pub recording_error: Option<String>,
    /// Why task retirement or subtree closure could not be proved, if applicable.
    pub runtime_error: Option<String>,
}

fn refusal(reason: impl Into<String>) -> AlertEffectError {
    AlertEffectError::Dispatch(reason.into())
}
fn timestamp(now: u64) -> TimestampNs {
    TimestampNs(i128::from(now))
}
fn network_deadline(
    base: u64,
    requested_ms: u64,
    original: Option<TimestampNs>,
) -> Result<u64, AlertEffectError> {
    let requested = requested_ms
        .checked_mul(1_000_000)
        .and_then(|duration| base.checked_add(duration))
        .ok_or(AlertEffectError::Clock)?;
    let effective = original.map_or(i128::from(requested), |deadline| {
        deadline.0.min(i128::from(requested))
    });
    if effective <= i128::from(base) {
        return Err(refusal("original alert deadline reached"));
    }
    u64::try_from(effective).map_err(|_| AlertEffectError::Clock)
}
fn cost(bytes: u64, latency_ms: u64, network_bytes: u64, storage_operations: u64) -> BudgetVector {
    let mut value = BudgetVector::ZERO;
    value.bytes = bytes;
    value.latency_ms = latency_ms;
    value.network_bytes = network_bytes;
    value.storage_operations = storage_operations;
    value
}
fn denial(error: ExecutionError) -> WebhookDenial {
    match error {
        ExecutionError::Deadline { .. } | ExecutionError::ClockRegression { .. } => {
            WebhookDenial::Deadline
        }
        ExecutionError::Budget(_) | ExecutionError::UnmeteredCost => WebhookDenial::Budget,
        ExecutionError::Grant(_) => WebhookDenial::Unauthorized,
        _ => WebhookDenial::Revoked,
    }
}

/// Host time and pacing are reached only through the owned admission below.
trait DispatchClock {
    fn elapsed_ns(&self) -> Option<u64>;
    fn wait_one_ms(&self);
}
struct NativeClock(Instant);
impl DispatchClock for NativeClock {
    fn elapsed_ns(&self) -> Option<u64> {
        u64::try_from(self.0.elapsed().as_nanos()).ok()
    }
    fn wait_one_ms(&self) {
        std::thread::sleep(Duration::from_millis(1));
    }
}

struct DispatchOwner<'a, 'task, C> {
    task: &'a TaskCx<'task>,
    cx: &'a ReplayCx,
    route: ContentDigest,
    journal: PathBuf,
    prepared: &'a OperationReceipt,
    clock: &'a C,
    base_ns: u64,
    network_deadline_ns: u64,
    last_ns: Cell<u64>,
    interrupted: Cell<Option<WebhookDenial>>,
    cancellation_reflected: Cell<bool>,
    pending_socket: Cell<Option<WebhookBoundary>>,
    network_admissions: Cell<u64>,
}
impl<C: DispatchClock> DispatchOwner<'_, '_, C> {
    fn stop(&self, reason: WebhookDenial) -> WebhookDenial {
        if self.interrupted.get().is_none() {
            self.interrupted.set(Some(reason));
        }
        reason
    }
    fn reflect_cancellation(&self) -> Result<(), WebhookDenial> {
        if self.cx.is_cancelled() && !self.cancellation_reflected.replace(true) {
            self.task
                .request_cancellation(timestamp(self.last_ns.get()))
                .map_err(denial)?;
        }
        Ok(())
    }
    fn active_time(&self) -> Result<u64, WebhookDenial> {
        self.reflect_cancellation()?;
        if self.cx.is_cancelled() {
            return Err(self.stop(WebhookDenial::Cancelled));
        }
        if let Some(reason) = self.interrupted.get() {
            return Err(reason);
        }
        self.task
            .checkpoint(timestamp(self.last_ns.get()), &BudgetVector::ZERO)
            .map_err(|error| self.stop(denial(error)))?;
        let now = self
            .clock
            .elapsed_ns()
            .and_then(|elapsed| self.base_ns.checked_add(elapsed))
            .filter(|now| *now >= self.last_ns.get())
            .ok_or_else(|| self.stop(WebhookDenial::Deadline))?;
        self.last_ns.set(now);
        self.task
            .checkpoint(timestamp(now), &BudgetVector::ZERO)
            .map_err(|error| self.stop(denial(error)))?;
        if now >= self.network_deadline_ns {
            return Err(self.stop(WebhookDenial::Deadline));
        }
        Ok(now)
    }
    /// Metadata-only drain admission owns the final clock read. Journal I/O still requires the
    /// original finite deadline, resource grant, and unrevoked underlying I/O authority.
    fn drain_time(&self) -> Result<u64, ExecutionError> {
        let _ = self.reflect_cancellation();
        self.task.begin_drain(timestamp(self.last_ns.get()))?;
        let now = self
            .clock
            .elapsed_ns()
            .and_then(|elapsed| self.base_ns.checked_add(elapsed))
            .filter(|now| *now >= self.last_ns.get())
            .ok_or(ExecutionError::InvalidCompletion)?;
        self.last_ns.set(now);
        self.task.begin_drain(timestamp(now))?;
        Ok(now)
    }
    fn source_read(&self) -> Result<(), ReferenceError> {
        let now = self
            .active_time()
            .map_err(|_| ReferenceError::InvalidSpec("owned_alert_source_refused"))?;
        self.task
            .checkpoint_for(
                RuntimeGrant::AlertCommit,
                RESOURCE,
                timestamp(now),
                &cost(0, 0, 0, 1),
            )
            .map_err(|error| {
                self.stop(denial(error));
                ReferenceError::InvalidSpec("owned_alert_source_budget_refused")
            })
    }
    fn after_source_read(&self) -> Result<(), ReferenceError> {
        self.active_time()
            .map(|_| ())
            .map_err(|_| ReferenceError::InvalidSpec("owned_alert_source_interrupted"))
    }
    fn wait(&self) -> Result<(), WebhookDenial> {
        let now = self.active_time()?;
        if self.network_deadline_ns.saturating_sub(now) < 1_000_000 {
            return Err(self.stop(WebhookDenial::Deadline));
        }
        self.task
            .checkpoint_for(
                RuntimeGrant::AlertCommit,
                RESOURCE,
                timestamp(now),
                &BudgetVector::ZERO,
            )
            .map_err(|error| self.stop(denial(error)))?;
        // The complete finite wait allowance was prepaid before commitment. Oversleep or a
        // failed/blocked socket cannot refund it or admit another network operation.
        self.clock.wait_one_ms();
        self.active_time().map(|_| ())
    }
}
impl<C: DispatchClock> WebhookAuthority for DispatchOwner<'_, '_, C> {
    fn checkpoint(
        &self,
        scope: WebhookScope<'_>,
        boundary: WebhookBoundary,
        now_ns: u64,
        network_deadline_ns: u64,
    ) -> Result<(), WebhookDenial> {
        if scope.endpoint.digest() != self.route
            || scope.effect_journal != self.journal
            || scope.operation.intent != self.prepared.intent
            || scope.operation.intent.effect_class != "alert.dispatch"
            || scope.operation.authority != self.prepared.authority
            || scope.operation.prepared_at != self.prepared.prepared_at
            || network_deadline_ns != self.network_deadline_ns
            || now_ns < self.base_ns
        {
            return Err(self.stop(WebhookDenial::Unauthorized));
        }
        if !self.cx.io_authority().is_valid() {
            return Err(self.stop(WebhookDenial::Revoked));
        }
        if boundary == WebhookBoundary::Record {
            if !matches!(
                scope.operation.state,
                EffectState::Committed | EffectState::AdapterAccepted | EffectState::Indeterminate
            ) {
                return Err(WebhookDenial::Unauthorized);
            }
            let now = self.drain_time().map_err(denial)?;
            if now_ns > now {
                return Err(WebhookDenial::Deadline);
            }
            return self
                .task
                .cleanup_checkpoint_for(
                    RuntimeGrant::AlertCommit,
                    RESOURCE,
                    timestamp(now),
                    &BudgetVector::ZERO,
                )
                .map_err(denial);
        }
        if (boundary == WebhookBoundary::Commit && scope.operation != self.prepared)
            || (boundary != WebhookBoundary::Commit
                && scope.operation.state != EffectState::Committed)
        {
            return Err(self.stop(WebhookDenial::Unauthorized));
        }
        let now = self.active_time()?;
        if now_ns > now {
            return Err(self.stop(WebhookDenial::Deadline));
        }
        let (grant, charge) = match boundary {
            WebhookBoundary::Connect
            | WebhookBoundary::Configure
            | WebhookBoundary::Send
            | WebhookBoundary::Receive => {
                // Connect/send recheck immediately after source validation. Debit the same
                // pending native call only once; AfterIo retires that admission.
                let first = self.pending_socket.get() != Some(boundary);
                (
                    RuntimeGrant::AdapterNet,
                    cost(0, 0, if first { IO_BYTES } else { 0 }, 0),
                )
            }
            _ => (RuntimeGrant::AlertCommit, BudgetVector::ZERO),
        };
        self.task
            .checkpoint_for(grant, RESOURCE, timestamp(now), &charge)
            .map_err(|error| self.stop(denial(error)))?;
        if charge.network_bytes != 0 {
            self.pending_socket.set(Some(boundary));
            self.network_admissions
                .set(self.network_admissions.get().saturating_add(1));
        }
        if boundary == WebhookBoundary::AfterIo {
            self.pending_socket.set(None);
        }
        Ok(())
    }
}

struct RuntimeOwner {
    process: AuthorityCx,
    property: AuthorityCx,
    event: AuthorityCx,
    alert: AuthorityCx,
    tree: RegionTree,
}
impl RuntimeOwner {
    fn new(
        source: &ContextAuthority,
        allowance: BudgetVector,
        deadline: TimestampNs,
        now: TimestampNs,
    ) -> Result<Self, AlertEffectError> {
        // Private translation of the checked exact dispatch approval, never a reusable public
        // network grant. Both grants are narrowed to this task's resource before any work.
        let spec = RootAuthoritySpec {
            trace_id: source.trace_id.clone(),
            operation_id: source.operation_id.clone(),
            principal: source.principal.clone(),
            capabilities: vec![
                RuntimeGrant::AlertCommit.as_str().to_owned(),
                RuntimeGrant::AdapterNet.as_str().to_owned(),
            ],
            deadline: Some(source.deadline.map_or(deadline, |old| old.min(deadline))),
            priority: source.priority,
            budgets: source.budgets,
            privacy_scope: source.privacy_scope.clone(),
            retention_scope: source.retention_scope.clone(),
            anchor_universe: source.anchor_universe,
            generation: source.generation,
        };
        let id = |suffix: &str| {
            RegionId::new(format!("region:alert-dispatch:{suffix}"))
                .map_err(|error| refusal(error.to_string()))
        };
        let (mut process, mut tree) = AuthorityCx::root(
            spec.clone(),
            id("process")?,
            RegionKind::Process,
            allowance,
            now,
        )
        .map_err(|error| refusal(error.to_string()))?;
        let resources = BTreeSet::from([RESOURCE.to_owned()]);
        let grants = process
            .grants()
            .clone()
            .with_scope(RuntimeGrant::AlertCommit, resources.clone())
            .with_scope(RuntimeGrant::AdapterNet, resources);
        process
            .narrow_grants(grants)
            .map_err(|error| refusal(error.to_string()))?;
        let mut property = process
            .scope_down(
                &mut tree,
                id("property")?,
                RegionKind::Property,
                allowance,
                spec.clone(),
                now,
            )
            .map_err(|error| refusal(error.to_string()))?;
        let mut event = property
            .scope_down(
                &mut tree,
                id("event")?,
                RegionKind::Event,
                allowance,
                spec.clone(),
                now,
            )
            .map_err(|error| refusal(error.to_string()))?;
        let alert = event
            .scope_down(
                &mut tree,
                id("obligation")?,
                RegionKind::AlertObligation,
                allowance,
                spec,
                now,
            )
            .map_err(|error| refusal(error.to_string()))?;
        Ok(Self {
            process,
            property,
            event,
            alert,
            tree,
        })
    }
    fn finish(&mut self, now: TimestampNs) -> Result<QuiescenceProof, String> {
        self.alert
            .finalize(&mut self.tree, now)
            .map_err(|error| error.to_string())?;
        self.event
            .release_scope_reservation(&self.tree, &mut self.alert)
            .map_err(|error| error.to_string())?;
        self.tree
            .request_drain(self.event.region(), Some("alert attempt retired"), now)
            .map_err(|error| error.to_string())?;
        self.event
            .begin_drain(&mut self.tree, now)
            .map_err(|error| error.to_string())?;
        self.event
            .finalize(&mut self.tree, now)
            .map_err(|error| error.to_string())?;
        self.property
            .release_scope_reservation(&self.tree, &mut self.event)
            .map_err(|error| error.to_string())?;
        self.tree
            .request_drain(self.property.region(), Some("alert attempt retired"), now)
            .map_err(|error| error.to_string())?;
        self.property
            .begin_drain(&mut self.tree, now)
            .map_err(|error| error.to_string())?;
        self.property
            .finalize(&mut self.tree, now)
            .map_err(|error| error.to_string())?;
        self.process
            .release_scope_reservation(&self.tree, &mut self.property)
            .map_err(|error| error.to_string())?;
        self.tree
            .request_drain(self.process.region(), Some("alert attempt retired"), now)
            .map_err(|error| error.to_string())?;
        self.process
            .begin_drain(&mut self.tree, now)
            .map_err(|error| error.to_string())?;
        self.process
            .finalize(&mut self.tree, now)
            .map_err(|error| error.to_string())
    }
}

#[allow(clippy::too_many_arguments)]
fn validate(
    deployment: &ReferenceDeployment,
    plan: &ReferenceAlertPlan,
    endpoint: &WebhookEndpoint,
    operation: &OperationReceipt,
    commit_granted: bool,
    deadline_ms: u64,
    source: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<BudgetVector, AlertEffectError> {
    source
        .validate()
        .map_err(|error| refusal(error.to_string()))?;
    if !commit_granted || !source.has_capability(CAP_ALERT_COMMIT) || !source.has_capability("ADP-REPLAY-001")
        || source.principal != cx.io_authority().principal() || cx.io_authority().root_dir() != deployment.root()
        || !cx.io_authority().is_valid() || cx.is_cancelled() || source.cancellation_reason.is_some()
        // RootAuthoritySpec cannot preserve these constraints. Refuse rather than drop them.
        || source.lease_fence.is_some() || source.idempotency_key.is_some() || source.lab_controls.is_some()
    {
        return Err(refusal(
            "original alert dispatch authority absent, cancelled, or unsupported",
        ));
    }
    // Preparation's system:operator/effect:execute authority is distinct from the approving CLI
    // principal. Preserve the entire durable authority; never rewrite it to impersonate caller.
    if !(1..=MAX_DEADLINE_MS).contains(&deadline_ms)
        || operation.state != EffectState::Prepared
        || operation.intent != plan.intent
        || plan.channel != endpoint.channel()
        || deployment.effects().operation(&plan.intent.operation_id) != Some(operation)
    {
        return Err(refusal(
            "exact prepared operation, route, or deadline differs",
        ));
    }
    let allowance = cost(
        source.budgets.bytes.min(SOURCE_BYTES),
        deadline_ms + DISPATCH_CLEANUP_MS,
        source.budgets.network_bytes.min(MAX_DISPATCH_NETWORK_BYTES),
        source
            .budgets
            .storage_operations
            .min(MAX_DISPATCH_STORAGE_OPERATIONS),
    );
    if allowance.bytes == 0
        || allowance.network_bytes < IO_BYTES
        || allowance.storage_operations <= JOURNAL_OPERATIONS
        || source.budgets.latency_ms < allowance.latency_ms
    {
        return Err(refusal(
            "finite source, network, journal, or cleanup allowance insufficient",
        ));
    }
    Ok(allowance)
}

struct NativeResult {
    outcome: WebhookOutcome,
    recorded: OperationReceipt,
    evidence: WebhookEvidence,
    recording_error: Option<String>,
}
struct OwnedResult {
    native: Result<NativeResult, AlertEffectError>,
    finished_ns: u64,
    network_admissions: u64,
    source_bytes: u64,
    source_attempts: u64,
    runtime_error: Option<String>,
}

#[allow(clippy::too_many_arguments)]
fn execute<C: DispatchClock>(
    task: &TaskCx<'_>,
    deployment: &mut ReferenceDeployment,
    plan: &ReferenceAlertPlan,
    endpoint: &WebhookEndpoint,
    prepared: &OperationReceipt,
    cx: &ReplayCx,
    clock: &C,
    base: u64,
    network_deadline: u64,
    allowance: BudgetVector,
) -> TaskCompletion<OwnedResult> {
    let mut runtime_error = None;
    let mut registered: Option<ObligationId> = None;
    let before = deployment.publisher().spool().read_budget_usage();
    let path = deployment.effects().path().to_path_buf();
    let owner = DispatchOwner {
        task,
        cx,
        route: endpoint.digest(),
        journal: path,
        prepared,
        clock,
        base_ns: base,
        network_deadline_ns: network_deadline,
        last_ns: Cell::new(base),
        interrupted: Cell::new(None),
        cancellation_reflected: Cell::new(false),
        pending_socket: Cell::new(None),
        network_admissions: Cell::new(0),
    };
    let native = (|| -> Result<NativeResult, AlertEffectError> {
        let now = owner
            .active_time()
            .map_err(|_| refusal("owned task admission refused"))?;
        task.checkpoint_for(
            RuntimeGrant::AlertCommit,
            RESOURCE,
            timestamp(now),
            &cost(allowance.bytes, allowance.latency_ms, 0, JOURNAL_OPERATIONS),
        )
        .map_err(|error| refusal(error.to_string()))?;
        let obligation = new_obligation(
            LOCAL_OBLIGATION,
            task.context().operation_id.clone(),
            "native alert resources retired and local observation durably recorded",
        )
        .map_err(|error| refusal(error.to_string()))?;
        let obligation_id = obligation.obligation_id.clone();
        task.register_obligation(obligation, timestamp(now))
            .map_err(|error| refusal(error.to_string()))?;
        registered = Some(obligation_id);
        deployment
            .publisher_mut()
            .tighten_read_budget(
                allowance.bytes,
                allowance.storage_operations - JOURNAL_OPERATIONS,
            )
            .map_err(|error| refusal(error.to_string()))?;
        let (journal, ledger, publisher) = deployment.effect_dispatch_parts();
        let limits = WebhookLimits {
            io_calls: 4096,
            io_bytes: IO_BYTES as usize,
            response_bytes: 16384,
            connect_timeout_ns: network_deadline.saturating_sub(base).min(5_000_000_000),
        };
        let read = |digest: ContentDigest| -> Result<Vec<u8>, ReferenceError> {
            owner.source_read()?;
            let result = publisher
                .spool()
                .read(digest)
                .map(|bytes| bytes.to_vec())
                .map_err(|error| ReferenceError::from(LocalPublicationError::Spool(error)));
            owner.after_source_read()?;
            result
        };
        let mut attempt = WebhookAttempt::begin(
            plan,
            endpoint,
            ledger,
            journal,
            limits,
            now,
            network_deadline,
            &owner,
            read,
        )
        .map_err(|error| match error {
            WebhookError::Authority(error) => not_eligible(error),
            other => refusal(other.to_string()),
        })?;
        let outcome = loop {
            let now = owner.active_time().unwrap_or_else(|_| owner.last_ns.get());
            match attempt.poll(now, &owner, read) {
                WebhookProgress::ReadyToRecord(outcome) => break outcome,
                WebhookProgress::Pending => {
                    let _ = owner.wait();
                }
            }
        };
        let recorded_at = owner.drain_time().map_err(|error| error.to_string());
        let result = match recorded_at {
            Ok(now) => attempt
                .record(now, &owner)
                .cloned()
                .map_err(|error| error.to_string()),
            Err(error) => Err(error),
        };
        // The journal never deletes its committed operation. Preserve its actual current
        // receipt even if recording failed, then retire all socket resources before returning.
        let (recorded, recording_error) = match result {
            Ok(receipt) => (Some(receipt), None),
            Err(error) => (attempt.operation().cloned(), Some(error)),
        };
        let evidence = attempt.retire();
        Ok(NativeResult {
            outcome,
            recorded: recorded.ok_or_else(|| refusal("committed operation disappeared"))?,
            evidence,
            recording_error,
        })
    })();
    if let Err(error) = owner.drain_time() {
        runtime_error = Some(error.to_string());
    }
    let finished_ns = owner.last_ns.get();
    let after = deployment.publisher().spool().read_budget_usage();
    let local_deadline_reached = task
        .context()
        .deadline
        .is_some_and(|deadline| timestamp(finished_ns) >= deadline);
    if local_deadline_reached {
        runtime_error.get_or_insert_with(|| "original runtime deadline reached".to_owned());
    }
    let outcome = match &native {
        Ok(value)
            if value.recording_error.is_none()
                && runtime_error.is_none()
                && matches!(value.outcome, WebhookOutcome::ReceiverAccepted(_))
                && !cx.is_cancelled() =>
        {
            TaskOutcome::Success
        }
        Ok(_) => {
            TaskOutcome::Indeterminate("alert effect remains owned by durable journal".to_owned())
        }
        Err(_) if cx.is_cancelled() => TaskOutcome::Cancelled,
        Err(_) => TaskOutcome::Failed("alert refused before network ownership".to_owned()),
    };
    if let Some(obligation_id) = registered {
        let resolution = match &native {
            Ok(value) if value.recording_error.is_none() && runtime_error.is_none() => {
                let terminal = if matches!(outcome, TaskOutcome::Success) {
                    ObligationTerminal::Completed
                } else {
                    ObligationTerminal::Indeterminate
                };
                let note = format!(
                    "durable operation {}; receipt {}; delivery obligation {} requires independent reconciliation",
                    value.recorded.intent.operation_id,
                    value.recorded.receipt_digest(),
                    plan.obligation_id
                );
                task.resolve_obligation(
                    &obligation_id,
                    terminal,
                    Some(value.recorded.receipt_digest()),
                    (terminal == ObligationTerminal::Indeterminate).then_some(note.as_str()),
                    timestamp(finished_ns),
                )
            }
            Ok(_) => Ok(()), // Unrecorded observation stays pending: subtree closure must refuse.
            Err(_) => task.resolve_obligation(
                &obligation_id,
                if matches!(outcome, TaskOutcome::Cancelled) {
                    ObligationTerminal::Drained
                } else {
                    ObligationTerminal::Failed
                },
                None,
                None,
                timestamp(finished_ns),
            ),
        };
        if let Err(error) = resolution {
            runtime_error.get_or_insert_with(|| error.to_string());
        }
    }
    TaskCompletion {
        output: OwnedResult {
            native,
            finished_ns,
            network_admissions: owner.network_admissions.get(),
            source_bytes: after.used_bytes.saturating_sub(before.used_bytes),
            source_attempts: after
                .used_read_attempts
                .saturating_sub(before.used_read_attempts),
            runtime_error,
        },
        outcome,
        completed_at: timestamp(finished_ns),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn dispatch(
    deployment: &mut ReferenceDeployment,
    plan: &ReferenceAlertPlan,
    endpoint: &WebhookEndpoint,
    operation: &OperationReceipt,
    commit_granted: bool,
    deadline_ms: u64,
    source: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<AlertDispatch, AlertEffectError> {
    let allowance = validate(
        deployment,
        plan,
        endpoint,
        operation,
        commit_granted,
        deadline_ms,
        source,
        cx,
    )?;
    // Initial host clock admission is authorized by the fully checked original context above.
    let base = wall_ns()?;
    if i128::from(base) < operation.updated_at.0 {
        return Err(AlertEffectError::Clock);
    }
    let clock = NativeClock(Instant::now());
    // The native connect timeout uses this ceiling as well as the TaskCx checkpoints.
    // A longer requested dispatch window can never replace an earlier original deadline.
    let network_deadline = network_deadline(base, deadline_ms, source.deadline)?;
    let cleanup_deadline = base
        .checked_add(allowance.latency_ms * 1_000_000)
        .ok_or(AlertEffectError::Clock)?;
    let mut owner = RuntimeOwner::new(
        source,
        allowance,
        timestamp(cleanup_deadline),
        timestamp(base),
    )?;
    let task = TaskSpec {
        task_id: TaskId::new("task:alert-dispatch:native")
            .map_err(|error| refusal(error.to_string()))?,
        started_at: timestamp(base),
    };
    let run = run_owned(&mut owner.alert, &mut owner.tree, task, |task| {
        execute(
            task,
            deployment,
            plan,
            endpoint,
            operation,
            cx,
            &clock,
            base,
            network_deadline,
            allowance,
        )
    })
    .map_err(|error| refusal(error.to_string()))?;
    let mut result = run.output;
    let task_receipt = match run.receipt {
        Ok(receipt) => Some(receipt),
        Err(error) => {
            result
                .runtime_error
                .get_or_insert_with(|| error.to_string());
            None
        }
    };
    let consumed = *owner.alert.budget().consumed();
    let remaining = owner.alert.budget().remaining();
    let quiescence = match owner.finish(timestamp(result.finished_ns)) {
        Ok(proof) => Some(proof),
        Err(error) => {
            result.runtime_error.get_or_insert(error);
            None
        }
    };
    let native = result.native?;
    Ok(AlertDispatch {
        outcome: native.outcome,
        recorded: native.recorded,
        evidence: native.evidence,
        runtime: AlertRuntimeSummary {
            task_receipt,
            quiescence,
            consumed,
            remaining,
            network_admissions: result.network_admissions,
            source_read_reserved_bytes: result.source_bytes,
            source_read_attempts: result.source_attempts,
            recovery_required: native.recording_error.is_some() || result.runtime_error.is_some(),
            recording_error: native.recording_error,
            runtime_error: result.runtime_error,
        },
    })
}

#[cfg(test)]
mod tests;

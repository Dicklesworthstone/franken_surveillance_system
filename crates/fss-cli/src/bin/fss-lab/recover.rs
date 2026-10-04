#![forbid(unsafe_code)]
//! `fss-lab recover`: explicit operator recovery of a deployment root (fss-2h5zq.15 refinement
//! rounds 2 and 3).
//!
//! Every action is named by the operator; nothing runs implicitly, and nothing is retried. The
//! supporting API of each action, verified at HEAD:
//!
//! | action | API |
//! |---|---|
//! | `--truncate-incomplete-tail ledger\|effects` | `ReferenceDeployment::open_for_recovery` with `RecoveryAction::TruncateIncomplete{Ledger,Effect}Tail` |
//! | `--plan-{ledger,effects}-repair` | `fss_reference::inspect_deployment` (read-only doctor: bounded read, `fss_ledger::doctor`, sealed plan digest; no lock) |
//! | `--apply-{ledger,effects}-repair <digest>` | `open_for_recovery` with `RecoveryAction::ApplySealed{Ledger,Effect}Repair` (refuses corrupt history and a different digest) |
//! | `--discard-orphaned-temps` | `LocalRootPublisher::discard_orphaned_temps` through a `ReferenceDeployment::reopen` |
//! | `--discard-orphaned-staging` | `ReferenceDeployment::discard_orphaned_staging` -> `LocalRootPublisher::discard_orphaned_staging` -> `StagingSpool::discard_orphaned_staging` (fss-vmau3), through a `ReferenceDeployment::reopen` |
//! | `--reconcile-effects` | `DurableEffectJournal::transition` (`Indeterminate` -> `Observed`) then `reconcile_verified`, or `reconcile_failed`, against the lab's durable simulated provider record only |
//!
//! Mutating actions hold `<root>/objects/LOCK` for their whole duration (`open_for_recovery`
//! and `ReferenceDeployment::reopen` both take it) and run in one fixed order: ledger bytes,
//! effect bytes, a normal `Reject` reopen check, orphan discards (root temps, then staging
//! files), effect reconciliation. A held lock refuses the action (`recover_root_locked`). The
//! first refusal, failure or indeterminate outcome stops the sequence; later actions are reported
//! `skipped`. A rerun of the same command resumes: steps already completed report
//! `nothing_to_do`, and a run whose every step had nothing to do is refused as
//! `recover_nothing_to_do`.
//!
//! A staging discard whose outcome cannot be observed (the spool's `DiscardIndeterminate`, or an
//! accounting overflow) is never reported as applied or as nothing to do: the step is
//! `indeterminate`, the spool and the publisher are poisoned, and the next affordance is a reopen,
//! which reclassifies the staging directory from disk.
//!
//! Reconciliation never guesses: an indeterminate operation with no simulated-provider
//! observation, or with a conflicting one, stays indeterminate. A `Committed` operation is
//! already reclassified to indeterminate by the reopen (`restart_reconciliation_pending_
//! observation`, fss-mc9c4), and dispatch is never retried.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use fss_cli::{
    ERR_LAB_RECOVER_CORRUPT_HISTORY, ERR_LAB_RECOVER_NOTHING_TO_DO, ERR_LAB_RECOVER_PLAN_MISMATCH,
    ERR_LAB_RECOVER_ROOT_LOCKED, RecoverJournal, RecoverRequest,
};
use fss_core::{EffectState, ObligationState, OperationId, TimestampNs};
use fss_object::{DiscardReceipt, SpoolError};
use fss_publication::LocalPublicationError;
use fss_reference::{
    DEPLOYMENT_LAYOUT_FILENAME, DeploymentLayout, DoctorCheck, DoctorValue, RecoveryAction,
    RecoveryReceipt, ReferenceDeployment, ReferenceError, RepairError, ReplayCx,
    inspect_deployment,
};

use crate::scenario::make_named_cx;
use crate::sim_provider::{self, ObservationKind, SIMULATED_LABEL};

/// Output schema of `fss-lab recover`.
pub const RECOVER_REPORT_SCHEMA: &str = "fss.lab.recover_report.v1";

/// What `fss-lab recover` does not prove or touch.
pub const RECOVER_NO_CLAIM: &str = "operator recovery of a laboratory root: effects are reconciled only against the lab's simulated provider record, never a real vendor; nothing is dispatched or retried";

/// A typed refusal, each with a registered error identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// Another holder has `<root>/objects/LOCK`.
    RootLocked,
    /// Every requested action found nothing to recover.
    NothingToDo,
    /// The journal's sealed plan has a different digest than the one given.
    PlanMismatch,
    /// The foreign range holds a structurally valid record.
    CorruptHistory,
}

impl Refusal {
    /// Stable short code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::RootLocked => "recover_root_locked",
            Self::NothingToDo => "recover_nothing_to_do",
            Self::PlanMismatch => "recover_plan_mismatch",
            Self::CorruptHistory => "recover_corrupt_history",
        }
    }

    /// Registered error identity (registries/ERRORS.md).
    #[must_use]
    pub const fn error_id(self) -> &'static str {
        match self {
            Self::RootLocked => ERR_LAB_RECOVER_ROOT_LOCKED,
            Self::NothingToDo => ERR_LAB_RECOVER_NOTHING_TO_DO,
            Self::PlanMismatch => ERR_LAB_RECOVER_PLAN_MISMATCH,
            Self::CorruptHistory => ERR_LAB_RECOVER_CORRUPT_HISTORY,
        }
    }
}

/// Status of one step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StepStatus {
    /// The action changed the root.
    Applied,
    /// A read-only plan was produced.
    Planned,
    /// Indeterminate operations remain and none had an observation; nothing changed.
    Unresolved,
    /// The action found nothing to recover.
    NothingToDo,
    /// The action was refused.
    Refused(Refusal),
    /// The action failed for a reason without a registered refusal.
    Failed(String),
    /// Whether the action took effect durably cannot be observed; the owning store is poisoned
    /// and must be reopened to reconcile. Never reported as applied or as nothing to do.
    Indeterminate(String),
    /// Not run, because an earlier step was refused, failed or was indeterminate.
    Skipped,
    /// The reopen check succeeded (not an action).
    Ok,
}

impl StepStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Applied => "applied",
            Self::Planned => "planned",
            Self::Unresolved => "indeterminate_remains",
            Self::NothingToDo => "nothing_to_do",
            Self::Refused(refusal) => refusal.code(),
            Self::Failed(_) => "failed",
            Self::Indeterminate(_) => "indeterminate",
            Self::Skipped => "skipped",
        }
    }

    const fn stops(&self) -> bool {
        matches!(
            self,
            Self::Refused(_) | Self::Failed(_) | Self::Indeterminate(_)
        )
    }
}

/// One executed (or skipped) action and its typed receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Step {
    /// Action name, as the doctor's affordances spell it.
    pub action: &'static str,
    /// Target journal, if any.
    pub target: Option<&'static str>,
    /// Status.
    pub status: StepStatus,
    /// Receipt fields as `(key, json value)`, in order.
    pub receipt: Vec<(&'static str, String)>,
}

impl Step {
    fn new(action: &'static str, target: Option<&'static str>, status: StepStatus) -> Self {
        Self {
            action,
            target,
            status,
            receipt: Vec::new(),
        }
    }

    fn with(mut self, key: &'static str, value: String) -> Self {
        self.receipt.push((key, value));
        self
    }
}

/// Overall outcome of one invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoverOutcome {
    /// At least one action changed the root.
    Applied,
    /// A read-only plan was printed.
    Planned,
    /// Nothing changed, and indeterminate operations remain without observations.
    IndeterminateRemains,
    /// A typed refusal, `recover_nothing_to_do` included.
    Refused(Refusal),
    /// A failure without a registered refusal.
    Failed(String),
    /// An action's durable outcome cannot be observed; reopen to reconcile.
    Indeterminate(String),
}

impl RecoverOutcome {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Planned => "planned",
            Self::IndeterminateRemains => "indeterminate_remains",
            Self::Refused(refusal) => refusal.code(),
            Self::Failed(_) => "failed",
            Self::Indeterminate(_) => "indeterminate",
        }
    }
}

/// Root state observed by a reopen after the actions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StateAfter {
    /// Temporary root records left on disk.
    pub orphaned_temps: usize,
    /// Staging files left in the spool.
    pub orphaned_staging: usize,
    /// Root records that failed verification.
    pub broken_roots: usize,
    /// Spool objects no admitted root reaches.
    pub unreferenced_objects: usize,
    /// Durable roots the ledger does not name, by slot.
    pub pending_roots: Vec<String>,
    /// Obligations in a terminal state.
    pub terminal: usize,
    /// Obligations explicitly indeterminate.
    pub indeterminate: usize,
    /// Obligations neither terminal nor indeterminate.
    pub pending: usize,
}

impl StateAfter {
    /// Operator next steps no `fss-lab recover` action performs.
    #[must_use]
    pub fn next_affordances(&self) -> Vec<&'static str> {
        let mut next = Vec::new();
        if !self.pending_roots.is_empty() {
            next.push("rerun the producing command: a pending root is committed by its idempotent rerun; commit_root needs a CaptureInterval the pending root does not carry");
        }
        if self.unreferenced_objects > 0 {
            next.push("rerun the producing command: it re-stages unreferenced objects as AlreadyPresent and publishes them; no discard API exists for verified or held objects");
        }
        if self.orphaned_temps > 0 {
            next.push("fss-lab recover --discard-orphaned-temps");
        }
        if self.orphaned_staging > 0 {
            next.push("fss-lab recover --discard-orphaned-staging");
        }
        if self.indeterminate > 0 {
            next.push("wait for a provider observation, then fss-lab recover --reconcile-effects; dispatch is never retried");
        }
        next
    }
}

/// The `fss.lab.recover_report.v1` document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverReport {
    /// Root recovered.
    pub root: PathBuf,
    /// Requested actions as flags, in execution order.
    pub requested: Vec<String>,
    /// Steps in execution order, the reopen check included.
    pub steps: Vec<Step>,
    /// Operations the reopen reclassified `Committed` -> `Indeterminate` (fss-mc9c4).
    pub restart_reclassified: Vec<OperationId>,
    /// State after the actions, when the root reopened.
    pub state_after: Option<StateAfter>,
}

impl RecoverReport {
    /// Overall outcome: the first refusal, failure or indeterminate step; otherwise applied,
    /// planned or indeterminate-remains; `recover_nothing_to_do` when every action had nothing
    /// to do.
    #[must_use]
    pub fn outcome(&self) -> RecoverOutcome {
        let mut applied = false;
        let mut planned = false;
        let mut unresolved = false;
        for step in &self.steps {
            match &step.status {
                StepStatus::Refused(refusal) => return RecoverOutcome::Refused(*refusal),
                StepStatus::Failed(reason) => {
                    return RecoverOutcome::Failed(format!("{}: {reason}", step.action));
                }
                StepStatus::Indeterminate(reason) => {
                    return RecoverOutcome::Indeterminate(format!("{}: {reason}", step.action));
                }
                StepStatus::Applied => applied = true,
                StepStatus::Planned => planned = true,
                StepStatus::Unresolved => unresolved = true,
                StepStatus::Ok | StepStatus::NothingToDo | StepStatus::Skipped => {}
            }
        }
        if planned {
            RecoverOutcome::Planned
        } else if applied {
            RecoverOutcome::Applied
        } else if unresolved {
            RecoverOutcome::IndeterminateRemains
        } else {
            RecoverOutcome::Refused(Refusal::NothingToDo)
        }
    }

    /// Renders the JSON document.
    #[must_use]
    pub fn render_json(&self) -> String {
        let mut out = String::new();
        let _ = write!(out, "{{\"schema\":\"{RECOVER_REPORT_SCHEMA}\",\"root\":");
        push_string(&mut out, &self.root.display().to_string());
        out.push_str(",\"requested\":[");
        for (index, flag) in self.requested.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            push_string(&mut out, flag);
        }
        out.push_str("],\"steps\":[");
        for (index, step) in self.steps.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str("{\"action\":");
            push_string(&mut out, step.action);
            out.push_str(",\"target\":");
            match step.target {
                Some(target) => push_string(&mut out, target),
                None => out.push_str("null"),
            }
            out.push_str(",\"status\":");
            push_string(&mut out, step.status.as_str());
            if let StepStatus::Refused(refusal) = &step.status {
                out.push_str(",\"error_id\":");
                push_string(&mut out, refusal.error_id());
            }
            if let StepStatus::Failed(reason) | StepStatus::Indeterminate(reason) = &step.status {
                out.push_str(",\"reason\":");
                push_string(&mut out, reason);
            }
            out.push_str(",\"receipt\":{");
            for (field, (key, value)) in step.receipt.iter().enumerate() {
                if field > 0 {
                    out.push(',');
                }
                push_string(&mut out, key);
                out.push(':');
                out.push_str(value);
            }
            out.push_str("}}");
        }
        out.push_str("],\"restart_reclassified\":[");
        for (index, operation) in self.restart_reclassified.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            push_string(&mut out, operation.as_str());
        }
        out.push_str("],\"state_after\":");
        match &self.state_after {
            None => out.push_str("null"),
            Some(state) => {
                let _ = write!(
                    out,
                    "{{\"orphaned_temps\":{},\"orphaned_staging\":{},\"broken_roots\":{},\"unreferenced_objects\":{},\"pending_roots\":[",
                    state.orphaned_temps,
                    state.orphaned_staging,
                    state.broken_roots,
                    state.unreferenced_objects
                );
                for (index, slot) in state.pending_roots.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    push_string(&mut out, slot);
                }
                let _ = write!(
                    out,
                    "],\"obligations\":{{\"terminal\":{},\"indeterminate\":{},\"pending\":{}}},\"next_affordances\":[",
                    state.terminal, state.indeterminate, state.pending
                );
                for (index, next) in state.next_affordances().iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    push_string(&mut out, next);
                }
                out.push_str("]}");
            }
        }
        let outcome = self.outcome();
        out.push_str(",\"outcome\":");
        push_string(&mut out, outcome.as_str());
        out.push_str(",\"error_id\":");
        match outcome {
            RecoverOutcome::Refused(refusal) => push_string(&mut out, refusal.error_id()),
            _ => out.push_str("null"),
        }
        out.push_str(",\"simulated_provider\":");
        push_string(&mut out, SIMULATED_LABEL);
        out.push_str(",\"no_claim\":");
        push_string(&mut out, RECOVER_NO_CLAIM);
        out.push('}');
        out
    }

    /// Renders a short human summary.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "fss-lab recover {}", self.root.display());
        for step in &self.steps {
            let _ = writeln!(
                out,
                "  {:<26} {:<8} {}",
                step.action,
                step.target.unwrap_or("-"),
                step.status.as_str()
            );
        }
        if let Some(state) = &self.state_after {
            for next in state.next_affordances() {
                let _ = writeln!(out, "  next: {next}");
            }
        }
        let _ = write!(
            out,
            "outcome: {} ({SIMULATED_LABEL})",
            self.outcome().as_str()
        );
        out
    }
}

/// Runs the requested actions on `root` in the fixed order and returns the report.
#[must_use]
pub fn run(root: &Path, request: &RecoverRequest) -> RecoverReport {
    let mut report = RecoverReport {
        root: root.to_path_buf(),
        requested: request.flags(),
        steps: Vec::new(),
        restart_reclassified: Vec::new(),
        state_after: None,
    };
    if let Some(journal) = request.plan_repair {
        report.steps.push(plan_step(root, journal));
        return report;
    }
    let cx = match make_named_cx("recover") {
        Ok(cx) => cx,
        Err(error) => {
            report.steps.push(Step::new(
                "context",
                None,
                StepStatus::Failed(error.to_string()),
            ));
            return report;
        }
    };
    if !root.join(DEPLOYMENT_LAYOUT_FILENAME).is_file() {
        // Recover never initializes a deployment.
        report.steps.push(Step::new(
            "deployment_check",
            None,
            StepStatus::Failed(format!(
                "not a deployment root (no {DEPLOYMENT_LAYOUT_FILENAME}): {}",
                root.display()
            )),
        ));
        return report;
    }

    // 1. Ledger bytes, 2. effect bytes.
    let mut byte_steps: Vec<RecoveryAction> = Vec::new();
    if request.truncate_incomplete_tail == Some(RecoverJournal::Ledger) {
        byte_steps.push(RecoveryAction::TruncateIncompleteLedgerTail);
    }
    if let Some(plan_digest) = request.apply_ledger_repair {
        byte_steps.push(RecoveryAction::ApplySealedLedgerRepair { plan_digest });
    }
    if request.truncate_incomplete_tail == Some(RecoverJournal::Effects) {
        byte_steps.push(RecoveryAction::TruncateIncompleteEffectTail);
    }
    if let Some(plan_digest) = request.apply_effects_repair {
        byte_steps.push(RecoveryAction::ApplySealedEffectRepair { plan_digest });
    }
    for action in byte_steps {
        let step = byte_step(root, action, &cx);
        let stop = step.status.stops();
        report.steps.push(step);
        if stop {
            skip_remaining(&mut report, request, false);
            return report;
        }
    }

    // 3. Reopen check (normal `Reject` open, under the deployment lock).
    let lineage = match read_lineage(root) {
        Ok(lineage) => lineage,
        Err(reason) => {
            report
                .steps
                .push(Step::new("reopen_check", None, StepStatus::Failed(reason)));
            skip_remaining(&mut report, request, true);
            return report;
        }
    };
    let mut deployment = match ReferenceDeployment::reopen(root, &lineage, &cx) {
        Ok(deployment) => deployment,
        Err(error) => {
            let status = match error {
                ReferenceError::DeploymentLocked { .. } => StepStatus::Refused(Refusal::RootLocked),
                other => StepStatus::Failed(other.to_string()),
            };
            report.steps.push(Step::new("reopen_check", None, status));
            skip_remaining(&mut report, request, true);
            return report;
        }
    };
    report.restart_reclassified = deployment.restart_reclassified().to_vec();
    report
        .steps
        .push(Step::new("reopen_check", None, StepStatus::Ok).with(
            "restart_reclassified",
            deployment.restart_reclassified().len().to_string(),
        ));

    // 4. Orphan discards.
    if request.discard_orphaned_temps {
        let step = match deployment.publisher_mut().discard_orphaned_temps() {
            Ok(0) => Step::new(
                "discard_orphaned_temps",
                Some("objects"),
                StepStatus::NothingToDo,
            ),
            Ok(count) => Step::new(
                "discard_orphaned_temps",
                Some("objects"),
                StepStatus::Applied,
            )
            .with("discarded", count.to_string()),
            Err(error) => Step::new(
                "discard_orphaned_temps",
                Some("objects"),
                StepStatus::Failed(error.to_string()),
            ),
        };
        let stop = step.status.stops();
        report.steps.push(step);
        if stop {
            skip_remaining(&mut report, request, true);
            return report;
        }
    }
    if request.discard_orphaned_staging {
        // Exactly the staging files the spool classified when this reopen took the lock.
        let orphans: Vec<String> = deployment
            .publisher()
            .spool()
            .orphaned_staging()
            .map(|orphan| orphan.path.display().to_string())
            .collect();
        let step = if orphans.is_empty() {
            Step::new(
                "discard_orphaned_staging",
                Some("objects"),
                StepStatus::NothingToDo,
            )
        } else {
            staging_step(deployment.discard_orphaned_staging(), &orphans)
        };
        let stop = step.status.stops();
        report.steps.push(step);
        if stop {
            skip_remaining(&mut report, request, true);
            return report;
        }
    }

    // 5. Effect reconciliation, last.
    if request.reconcile_effects {
        let step = reconcile_step(root, &mut deployment);
        let stop = step.status.stops();
        report.steps.push(step);
        if stop {
            return report;
        }
    }
    drop(deployment);
    report.state_after = observe_state(root, &lineage, &cx).ok();
    report
}

fn skip_remaining(report: &mut RecoverReport, request: &RecoverRequest, after_reopen: bool) {
    let ran: Vec<&'static str> = report.steps.iter().map(|step| step.action).collect();
    let mut remaining: Vec<&'static str> = Vec::new();
    if !after_reopen {
        remaining.push("reopen_check");
    }
    if request.discard_orphaned_temps {
        remaining.push("discard_orphaned_temps");
    }
    if request.discard_orphaned_staging {
        remaining.push("discard_orphaned_staging");
    }
    if request.reconcile_effects {
        remaining.push("reconcile_effects");
    }
    for action in remaining {
        if !ran.contains(&action) {
            report
                .steps
                .push(Step::new(action, None, StepStatus::Skipped));
        }
    }
}

fn read_lineage(root: &Path) -> Result<String, String> {
    let text = fs::read_to_string(root.join(DEPLOYMENT_LAYOUT_FILENAME))
        .map_err(|e| format!("read {DEPLOYMENT_LAYOUT_FILENAME}: {e}"))?;
    DeploymentLayout::parse_canonical_text(&text)
        .map(|layout| layout.site_lineage)
        .map_err(|e| e.to_string())
}

fn action_parts(action: &RecoveryAction) -> (&'static str, &'static str) {
    match action {
        RecoveryAction::TruncateIncompleteLedgerTail => ("truncate_incomplete_tail", "ledger"),
        RecoveryAction::TruncateIncompleteEffectTail => ("truncate_incomplete_tail", "effects"),
        RecoveryAction::ApplySealedLedgerRepair { .. } => ("apply_ledger_repair", "ledger"),
        RecoveryAction::ApplySealedEffectRepair { .. } => ("apply_effects_repair", "effects"),
    }
}

fn byte_step(root: &Path, action: RecoveryAction, cx: &ReplayCx) -> Step {
    let (name, target) = action_parts(&action);
    let requested_digest = match &action {
        RecoveryAction::ApplySealedLedgerRepair { plan_digest }
        | RecoveryAction::ApplySealedEffectRepair { plan_digest } => Some(*plan_digest),
        _ => None,
    };
    match ReferenceDeployment::open_for_recovery(root, action, cx) {
        Ok(
            RecoveryReceipt::TruncatedLedgerTail {
                path,
                committed_len,
                truncated_bytes,
                last_root_before,
                last_root_after,
            }
            | RecoveryReceipt::TruncatedEffectTail {
                path,
                committed_len,
                truncated_bytes,
                last_root_before,
                last_root_after,
            },
        ) => Step::new(name, Some(target), StepStatus::Applied)
            .with("journal", json_string(&relative(root, &path)))
            .with("committed_len", committed_len.to_string())
            .with("truncated_bytes", truncated_bytes.to_string())
            .with(
                "last_root_before",
                json_string(&last_root_before.to_string()),
            )
            .with("last_root_after", json_string(&last_root_after.to_string())),
        Ok(
            RecoveryReceipt::AppliedLedgerRepair(receipt)
            | RecoveryReceipt::AppliedEffectRepair(receipt),
        ) => Step::new(name, Some(target), StepStatus::Applied)
            .with(
                "journal",
                json_string(&relative(root, receipt.journal_path())),
            )
            .with(
                "plan_digest",
                json_string(&receipt.plan_digest().to_string()),
            )
            .with("committed_len", receipt.committed_len().to_string())
            .with("last_root", json_string(&receipt.last_root().to_string()))
            .with(
                "quarantined_offset",
                receipt.quarantined_offset().to_string(),
            )
            .with(
                "quarantined_length",
                receipt.quarantined_length().to_string(),
            )
            .with(
                "quarantined_digest",
                json_string(&receipt.quarantined_digest().to_string()),
            )
            .with(
                "quarantine_path",
                json_string(&relative(root, receipt.quarantine_path())),
            )
            .with("truncated_to", receipt.truncated_to().to_string()),
        Err(ReferenceError::NoIncompleteTail { .. }) => {
            Step::new(name, Some(target), StepStatus::NothingToDo)
        }
        Err(ReferenceError::Repair(error)) if matches!(*error, RepairError::NoForeignBytes) => {
            Step::new(name, Some(target), StepStatus::NothingToDo)
        }
        Err(ReferenceError::DeploymentLocked { .. }) => {
            Step::new(name, Some(target), StepStatus::Refused(Refusal::RootLocked))
        }
        Err(ReferenceError::PlanDigestMismatch { expected, actual }) => Step::new(
            name,
            Some(target),
            StepStatus::Refused(Refusal::PlanMismatch),
        )
        .with("requested_plan_digest", json_string(&expected.to_string()))
        .with("current_plan_digest", json_string(&actual.to_string())),
        Err(ReferenceError::RecoverCorruptHistory { path, offset }) => Step::new(
            name,
            Some(target),
            StepStatus::Refused(Refusal::CorruptHistory),
        )
        .with("journal", json_string(&relative(root, &path)))
        .with("valid_record_offset", offset.to_string()),
        Err(other) => {
            let step = Step::new(name, Some(target), StepStatus::Failed(other.to_string()));
            match requested_digest {
                Some(digest) => {
                    step.with("requested_plan_digest", json_string(&digest.to_string()))
                }
                None => step,
            }
        }
    }
}

/// The `discard_orphaned_staging` step for the discard of `orphans` (spool-relative paths), with
/// the spool's indeterminate and poison outcomes kept typed.
fn staging_step(result: Result<DiscardReceipt, ReferenceError>, orphans: &[String]) -> Step {
    const ACTION: &str = "discard_orphaned_staging";
    let orphan_list = json_list(orphans);
    match result {
        Ok(receipt) if receipt.removed == 0 => {
            Step::new(ACTION, Some("objects"), StepStatus::NothingToDo)
        }
        Ok(receipt) => Step::new(ACTION, Some("objects"), StepStatus::Applied)
            .with("discarded", receipt.removed.to_string())
            .with("released_bytes", receipt.released_bytes.to_string())
            .with("orphans", orphan_list),
        Err(ReferenceError::DeploymentLocked { .. }) => Step::new(
            ACTION,
            Some("objects"),
            StepStatus::Refused(Refusal::RootLocked),
        ),
        Err(ReferenceError::LocalPublication(error)) => {
            let code = json_string(error.code());
            // Exactly the outcomes after which the spool (and so the publisher) is poisoned.
            let indeterminate = matches!(
                *error,
                LocalPublicationError::Poisoned
                    | LocalPublicationError::Spool(
                        SpoolError::DiscardIndeterminate { .. }
                            | SpoolError::AccountingOverflow
                            | SpoolError::Poisoned
                    )
            );
            if !indeterminate {
                return Step::new(
                    ACTION,
                    Some("objects"),
                    StepStatus::Failed(error.to_string()),
                )
                .with("error_code", code);
            }
            let mut step = Step::new(
                ACTION,
                Some("objects"),
                StepStatus::Indeterminate(error.to_string()),
            )
            .with("error_code", code)
            .with("publisher_poisoned", "true".to_owned())
            .with(
                "next",
                json_string(
                    "reopen the root (rerun fss-lab recover --discard-orphaned-staging, or fss doctor --root) to reclassify the staging directory from disk",
                ),
            );
            if let LocalPublicationError::Spool(SpoolError::DiscardIndeterminate {
                path,
                operation,
                kind,
            }) = &*error
            {
                step = step
                    .with("path", json_string(&path.display().to_string()))
                    .with("operation", json_string(&operation.to_string()))
                    .with("io_kind", json_string(&kind.to_string()));
            }
            step.with("orphans", orphan_list)
        }
        Err(other) => Step::new(
            ACTION,
            Some("objects"),
            StepStatus::Failed(other.to_string()),
        ),
    }
}

fn json_list(values: &[String]) -> String {
    let mut out = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_string(&mut out, value);
    }
    out.push(']');
    out
}

/// Read-only plan: the deployment doctor's bounded read of the journal, its classification and
/// the sealed plan digest. No lock, no publisher open, no write.
fn plan_step(root: &Path, journal: RecoverJournal) -> Step {
    let action = match journal {
        RecoverJournal::Ledger => "plan_ledger_repair",
        RecoverJournal::Effects => "plan_effects_repair",
    };
    let target = journal.as_str();
    let doctor = inspect_deployment(root);
    let check_id = format!("{target}.journal");
    let Some(check) = doctor.check(&check_id) else {
        return Step::new(
            action,
            Some(target),
            StepStatus::Failed(format!(
                "the doctor did not classify {check_id}: verdict {}",
                doctor.verdict.as_str()
            )),
        );
    };
    if check
        .findings
        .iter()
        .any(|finding| finding.kind == "corrupt_history")
    {
        return Step::new(
            action,
            Some(target),
            StepStatus::Refused(Refusal::CorruptHistory),
        )
        .with(
            "valid_record_offset",
            field(check, &["valid_record_offset"]),
        );
    }
    if !check.fields.contains_key("foreign_offset") {
        return Step::new(action, Some(target), StepStatus::NothingToDo)
            .with("doctor_status", json_string(&check.status));
    }
    let Some(DoctorValue::String(plan_digest)) = check.fields.get("plan_digest") else {
        return Step::new(
            action,
            Some(target),
            StepStatus::Failed(format!(
                "no sealed plan: {}",
                field(check, &["plan_unavailable_reason"])
            )),
        );
    };
    Step::new(action, Some(target), StepStatus::Planned)
        .with("plan_digest", json_string(plan_digest))
        .with("journal", json_string(&format!("{target}/journal.fssj")))
        .with("committed_len", field(check, &["counts", "committed_len"]))
        .with("last_root", field(check, &["evidence", "last_root"]))
        .with("foreign_offset", field(check, &["foreign_offset"]))
        .with("foreign_length", field(check, &["foreign_length"]))
        .with(
            "foreign_digest",
            field(check, &["evidence", "foreign_digest"]),
        )
        .with("cut_offset", field(check, &["counts", "committed_len"]))
        .with(
            "apply",
            json_string(&format!(
                "fss-lab recover --apply-{target}-repair {plan_digest}"
            )),
        )
}

/// A doctor field as JSON, `null` when absent.
fn field(check: &DoctorCheck, path: &[&str]) -> String {
    let mut value: Option<&DoctorValue> = None;
    for (depth, key) in path.iter().enumerate() {
        value = if depth == 0 {
            check.fields.get(*key)
        } else {
            match value {
                Some(DoctorValue::Object(map)) => map.get(*key),
                _ => None,
            }
        };
    }
    value.map_or_else(|| "null".to_owned(), DoctorValue::to_json)
}

/// One indeterminate operation's reconciliation, rendered in the receipt.
struct Resolution {
    operation_id: String,
    observation: &'static str,
    to: &'static str,
    proof: Option<String>,
}

fn reconcile_step(root: &Path, deployment: &mut ReferenceDeployment) -> Step {
    const ACTION: &str = "reconcile_effects";
    let observations = match sim_provider::load(root) {
        Ok(observations) => observations,
        Err(reason) => {
            return Step::new(ACTION, Some("effects"), StepStatus::Failed(reason));
        }
    };
    let indeterminate: Vec<_> = deployment
        .effects()
        .operations()
        .filter(|operation| operation.state == EffectState::Indeterminate)
        .map(|operation| (operation.intent.clone(), operation.updated_at))
        .collect();
    let mut resolutions = Vec::new();
    let mut changed = false;
    for (intent, updated_at) in indeterminate {
        let operation_id = intent.operation_id.clone();
        let keyed = observations
            .iter()
            .find(|observation| observation.intent.idempotency_key == intent.idempotency_key);
        let Some(observation) = keyed else {
            resolutions.push(Resolution {
                operation_id: operation_id.as_str().to_owned(),
                observation: "none",
                to: "indeterminate",
                proof: None,
            });
            continue;
        };
        if !observation.matches(&intent) {
            // Never guess: a record that is not about exactly this intent resolves nothing.
            resolutions.push(Resolution {
                operation_id: operation_id.as_str().to_owned(),
                observation: "conflicting",
                to: "indeterminate",
                proof: None,
            });
            continue;
        }
        let proof = observation.proof_digest();
        // Transition times derive from the journal alone (no clock authority here), exactly as
        // restart reconciliation does, which keeps the records deterministic.
        let observed_at = TimestampNs(updated_at.0.saturating_add(1));
        let terminal_at = TimestampNs(updated_at.0.saturating_add(2));
        let effects = deployment.effects_mut();
        let result = match observation.kind {
            ObservationKind::Failed => effects
                .reconcile_failed(
                    &operation_id,
                    proof,
                    observed_at,
                    observation.error_code.clone(),
                )
                .map(|_| "failed"),
            // Indeterminate -> Observed -> Verified, exactly as reconcile_alert does: the
            // journal's reconcile_verified requires Observed with the same proof.
            ObservationKind::Delivered | ObservationKind::DeliveredAckLost => match effects
                .transition(
                    &operation_id,
                    EffectState::Observed,
                    observed_at,
                    Some(proof),
                    None,
                )
                .map(|_| ())
            {
                Ok(()) => effects
                    .reconcile_verified(&operation_id, proof, terminal_at)
                    .map(|_| "verified"),
                Err(error) => Err(error),
            },
        };
        match result {
            Ok(to) => {
                changed = true;
                resolutions.push(Resolution {
                    operation_id: operation_id.as_str().to_owned(),
                    observation: observation.kind.as_str(),
                    to,
                    proof: Some(proof.to_string()),
                });
            }
            Err(error) => {
                return Step::new(
                    ACTION,
                    Some("effects"),
                    StepStatus::Failed(format!("{}: {error}", operation_id.as_str())),
                );
            }
        }
    }
    let status = if changed {
        StepStatus::Applied
    } else if resolutions.is_empty() {
        StepStatus::NothingToDo
    } else {
        StepStatus::Unresolved
    };
    let mut operations = String::from("[");
    for (index, resolution) in resolutions.iter().enumerate() {
        if index > 0 {
            operations.push(',');
        }
        operations.push_str("{\"operation_id\":");
        push_string(&mut operations, &resolution.operation_id);
        operations.push_str(",\"from\":\"indeterminate\",\"observation\":");
        push_string(&mut operations, resolution.observation);
        operations.push_str(",\"to\":");
        push_string(&mut operations, resolution.to);
        operations.push_str(",\"proof_digest\":");
        match &resolution.proof {
            Some(proof) => push_string(&mut operations, proof),
            None => operations.push_str("null"),
        }
        operations.push('}');
    }
    operations.push(']');
    Step::new(ACTION, Some("effects"), status)
        .with("simulated_provider", json_string(SIMULATED_LABEL))
        .with("provider_records", observations.len().to_string())
        .with("operations", operations)
}

/// Reopens `root` and observes the state the actions left.
pub fn observe_state(root: &Path, lineage: &str, cx: &ReplayCx) -> Result<StateAfter, String> {
    let mut deployment =
        ReferenceDeployment::reopen(root, lineage, cx).map_err(|e| e.to_string())?;
    let report = deployment.recovery_report();
    let mut state = StateAfter {
        orphaned_temps: report.orphaned_temps.len(),
        orphaned_staging: report.spool.orphaned_staging.len(),
        broken_roots: report.broken_roots.len(),
        unreferenced_objects: report.unreferenced_objects.len(),
        ..StateAfter::default()
    };
    let reconciliation = deployment.reconcile().map_err(|e| e.to_string())?;
    state.pending_roots = reconciliation
        .pending
        .iter()
        .map(|pending| pending.slot.as_str().to_owned())
        .collect();
    for obligation in deployment.effects().obligations() {
        match obligation.state {
            ObligationState::Verified | ObligationState::Failed | ObligationState::Cancelled => {
                state.terminal += 1;
            }
            ObligationState::Indeterminate => state.indeterminate += 1,
            ObligationState::Pending => state.pending += 1,
        }
    }
    Ok(state)
}

fn relative(root: &Path, path: &Path) -> String {
    let canonical_root = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    path.strip_prefix(&canonical_root)
        .or_else(|_| path.strip_prefix(root))
        .unwrap_or(path)
        .display()
        .to_string()
}

fn json_string(value: &str) -> String {
    let mut out = String::new();
    push_string(&mut out, value);
    out
}

fn push_string(out: &mut String, value: &str) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::{RecoverOutcome, RecoverReport, Refusal, StepStatus, run};
    use crate::scenario::{Injection, ScenarioKind, make_cx, run_injected};
    use crate::sim_provider::{self, ObservationKind, ProviderObservation};
    use fss_cli::{LabAction, RecoverJournal, RecoverRequest, parse_lab_args};
    use fss_core::{CanonicalEncode, ContentDigest, EffectState, OperationId};
    use fss_object::{SpoolError, SpoolIoOperation};
    use fss_publication::{LedgerCutPoint, LocalPublicationError, PublishCutPoint};
    use fss_reference::{
        AppendPhase, DoctorAffordance, ReferenceDeployment, ReferenceError, inspect_deployment,
    };
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    type TestResult = Result<(), String>;

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Result<Self, String> {
            for n in 0..100 {
                let dir = std::env::temp_dir()
                    .join(format!("fss-lab-recover-{tag}-{}-{n}", std::process::id()));
                match std::fs::create_dir(&dir) {
                    Ok(()) => return Ok(Self(dir)),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e.to_string()),
                }
            }
            Err("temporary directory capacity".to_owned())
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The intrusion scenario with `injection` armed, in a fresh deployment under `scratch`.
    fn corpus(scratch: &Scratch, name: &str, injection: Injection) -> PathBuf {
        let root = scratch.0.join(name);
        let _ = run_injected(ScenarioKind::Intrusion, &root, injection);
        root
    }

    fn alert_state(root: &Path) -> Result<Option<EffectState>, String> {
        let cx = make_cx(ScenarioKind::Intrusion).map_err(|e| e.to_string())?;
        let deployment =
            ReferenceDeployment::reopen(root, "site:lab", &cx).map_err(|e| e.to_string())?;
        let id = OperationId::parse("op:alert:intrusion:1").map_err(|e| e.to_string())?;
        Ok(deployment.effects().operation(&id).map(|op| op.state))
    }

    fn operation_count(root: &Path) -> Result<usize, String> {
        let cx = make_cx(ScenarioKind::Intrusion).map_err(|e| e.to_string())?;
        let deployment =
            ReferenceDeployment::reopen(root, "site:lab", &cx).map_err(|e| e.to_string())?;
        Ok(deployment.effects().operations().count())
    }

    fn reconcile() -> RecoverRequest {
        RecoverRequest {
            reconcile_effects: true,
            ..RecoverRequest::default()
        }
    }

    fn status_of(report: &RecoverReport, action: &str) -> Option<StepStatus> {
        report
            .steps
            .iter()
            .find(|step| step.action == action)
            .map(|step| step.status.clone())
    }

    #[test]
    fn a_lost_ack_reconciles_to_verified_from_the_durable_record_without_dispatch() -> TestResult {
        let scratch = Scratch::new("lost-ack")?;
        let root = corpus(&scratch, "effect.lost_ack", Injection::CrashAfterLostAck);
        let records = sim_provider::load(&root)?;
        assert_eq!(records.len(), 1);
        assert_eq!(
            records.first().map(|r| r.kind),
            Some(ObservationKind::DeliveredAckLost)
        );
        assert_eq!(alert_state(&root)?, Some(EffectState::Indeterminate));
        let operations = operation_count(&root)?;

        let report = run(&root, &reconcile());
        let json = report.render_json();
        assert_eq!(report.outcome(), RecoverOutcome::Applied, "{json}");
        assert!(
            json.contains("\"observation\":\"delivered_ack_lost\",\"to\":\"verified\""),
            "{json}"
        );
        assert!(json.contains("\"schema\":\"fss.lab.recover_report.v1\""));
        assert!(json.contains("simulated: the lab's deterministic alert provider record"));
        assert_eq!(alert_state(&root)?, Some(EffectState::Verified));
        // Nothing was dispatched: no new operation, and the provider record is unchanged.
        assert_eq!(operation_count(&root)?, operations);
        assert_eq!(sim_provider::load(&root)?, records);
        let state = report.state_after.as_ref().ok_or("state_after")?;
        assert_eq!(state.indeterminate, 0);

        // Resuming the completed command: nothing to do.
        let again = run(&root, &reconcile());
        assert_eq!(
            again.outcome(),
            RecoverOutcome::Refused(Refusal::NothingToDo)
        );
        assert_eq!(alert_state(&root)?, Some(EffectState::Verified));
        Ok(())
    }

    #[test]
    fn an_unobserved_commit_stays_indeterminate_and_a_failure_record_reconciles_failed()
    -> TestResult {
        let scratch = Scratch::new("unobserved")?;
        let root = corpus(
            &scratch,
            "effect.after_commit_before_dispatch",
            Injection::CrashAfterCommitBeforeDispatch,
        );
        // The provider was never called: no record. The reopen reclassified the commit.
        assert!(sim_provider::load(&root)?.is_empty());
        assert_eq!(alert_state(&root)?, Some(EffectState::Indeterminate));

        let report = run(&root, &reconcile());
        assert_eq!(report.outcome(), RecoverOutcome::IndeterminateRemains);
        assert_eq!(
            status_of(&report, "reconcile_effects"),
            Some(StepStatus::Unresolved)
        );
        assert!(
            report
                .render_json()
                .contains("\"observation\":\"none\",\"to\":\"indeterminate\"")
        );
        assert_eq!(alert_state(&root)?, Some(EffectState::Indeterminate));

        let intent = {
            let cx = make_cx(ScenarioKind::Intrusion).map_err(|e| e.to_string())?;
            let deployment =
                ReferenceDeployment::reopen(&root, "site:lab", &cx).map_err(|e| e.to_string())?;
            deployment
                .effects()
                .operations()
                .next()
                .map(|op| op.intent.clone())
                .ok_or("no operation")?
        };

        // A record under the same key that is not about exactly this intent resolves nothing.
        let conflicting = scratch.0.join("conflicting");
        crate::crash_matrix::copy_tree(&root, &conflicting)?;
        let mut other = intent.clone();
        other.request_digest = ContentDigest::sha256(b"another request");
        sim_provider::append(
            &conflicting,
            &ProviderObservation {
                provider_id: "alert:site:lab".to_owned(),
                kind: ObservationKind::Delivered,
                message_digest: other.canonical_digest("fss.effect_proof.v1"),
                intent: other,
                provider_nonce: ContentDigest::sha256(b"nonce"),
                error_code: String::new(),
            },
        )?;
        let report = run(&conflicting, &reconcile());
        assert_eq!(report.outcome(), RecoverOutcome::IndeterminateRemains);
        assert!(
            report
                .render_json()
                .contains("\"observation\":\"conflicting\"")
        );
        assert_eq!(alert_state(&conflicting)?, Some(EffectState::Indeterminate));

        // The provider records a failure for exactly this intent: reconcile_failed.
        sim_provider::append(
            &root,
            &ProviderObservation {
                provider_id: "alert:site:lab".to_owned(),
                kind: ObservationKind::Failed,
                message_digest: intent.canonical_digest("fss.effect_proof.v1"),
                intent,
                provider_nonce: ContentDigest::sha256(b"failure nonce"),
                error_code: "failed_before_delivery".to_owned(),
            },
        )?;
        let report = run(&root, &reconcile());
        assert_eq!(report.outcome(), RecoverOutcome::Applied);
        assert!(
            report
                .render_json()
                .contains("\"observation\":\"failed\",\"to\":\"failed\"")
        );
        assert_eq!(alert_state(&root)?, Some(EffectState::Failed));
        Ok(())
    }

    #[test]
    fn a_torn_ledger_tail_is_truncated_once() -> TestResult {
        let scratch = Scratch::new("tail")?;
        let root = corpus(
            &scratch,
            "append.body_write",
            Injection::LedgerAppendFailure(AppendPhase::BodyWrite),
        );
        let request = RecoverRequest {
            truncate_incomplete_tail: Some(RecoverJournal::Ledger),
            ..RecoverRequest::default()
        };
        let report = run(&root, &request);
        assert_eq!(
            report.outcome(),
            RecoverOutcome::Applied,
            "{}",
            report.render_json()
        );
        assert_eq!(status_of(&report, "reopen_check"), Some(StepStatus::Ok));
        assert!(report.render_json().contains("\"truncated_bytes\":"));
        assert_eq!(
            run(&root, &request).outcome(),
            RecoverOutcome::Refused(Refusal::NothingToDo)
        );
        let effects = RecoverRequest {
            truncate_incomplete_tail: Some(RecoverJournal::Effects),
            ..RecoverRequest::default()
        };
        assert_eq!(
            run(&root, &effects).outcome(),
            RecoverOutcome::Refused(Refusal::NothingToDo)
        );
        Ok(())
    }

    #[test]
    fn a_held_lock_refuses_every_mutating_action_but_not_the_plan() -> TestResult {
        let scratch = Scratch::new("locked")?;
        let root = corpus(
            &scratch,
            "ledger.after_root_durable",
            Injection::LedgerCrash(LedgerCutPoint::AfterRootDurable),
        );
        let cx = make_cx(ScenarioKind::Intrusion).map_err(|e| e.to_string())?;
        let holder =
            ReferenceDeployment::reopen(&root, "site:lab", &cx).map_err(|e| e.to_string())?;
        for request in [
            reconcile(),
            RecoverRequest {
                discard_orphaned_temps: true,
                ..RecoverRequest::default()
            },
            RecoverRequest {
                truncate_incomplete_tail: Some(RecoverJournal::Ledger),
                ..RecoverRequest::default()
            },
            RecoverRequest {
                apply_ledger_repair: Some(ContentDigest::sha256(b"any")),
                ..RecoverRequest::default()
            },
        ] {
            let report = run(&root, &request);
            assert_eq!(
                report.outcome(),
                RecoverOutcome::Refused(Refusal::RootLocked),
                "{}",
                report.render_json()
            );
        }
        // The read-only plan takes no lock.
        let plan = run(
            &root,
            &RecoverRequest {
                plan_repair: Some(RecoverJournal::Ledger),
                ..RecoverRequest::default()
            },
        );
        assert_eq!(
            plan.outcome(),
            RecoverOutcome::Refused(Refusal::NothingToDo)
        );
        drop(holder);
        // Released: the pending root is reported with its operator next step, never committed.
        let report = run(&root, &reconcile());
        assert_eq!(
            report.outcome(),
            RecoverOutcome::Refused(Refusal::NothingToDo)
        );
        let state = report.state_after.as_ref().ok_or("state_after")?;
        assert_eq!(state.pending_roots, vec!["slot-sources".to_owned()]);
        assert!(report.render_json().contains("rerun the producing command"));
        Ok(())
    }

    fn append_bytes(path: &Path, bytes: &[u8]) -> TestResult {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        file.write_all(bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())
    }

    fn plan_digest(report: &RecoverReport) -> Result<ContentDigest, String> {
        let step = report.steps.first().ok_or("no step")?;
        let (_, value) = step
            .receipt
            .iter()
            .find(|(key, _)| *key == "plan_digest")
            .ok_or("no plan digest")?;
        value
            .trim_matches('"')
            .parse::<ContentDigest>()
            .map_err(|e| e.to_string())
    }

    #[test]
    fn the_plan_digest_round_trips_and_only_that_digest_applies() -> TestResult {
        let scratch = Scratch::new("plan")?;
        let root = corpus(&scratch, "clean", Injection::None);
        let journal = root.join("ledger").join("journal.fssj");
        let clean_len = std::fs::metadata(&journal)
            .map_err(|e| e.to_string())?
            .len();
        append_bytes(&journal, b"operator-visible foreign trailing bytes")?;
        let dirty = std::fs::read(&journal).map_err(|e| e.to_string())?;

        let plan_request = RecoverRequest {
            plan_repair: Some(RecoverJournal::Ledger),
            ..RecoverRequest::default()
        };
        let planned = run(&root, &plan_request);
        assert_eq!(
            planned.outcome(),
            RecoverOutcome::Planned,
            "{}",
            planned.render_json()
        );
        let digest = plan_digest(&planned)?;
        // Planning is read-only and repeatable.
        assert_eq!(std::fs::read(&journal).map_err(|e| e.to_string())?, dirty);
        assert_eq!(plan_digest(&run(&root, &plan_request))?, digest);

        // Any other digest is refused and changes nothing.
        let wrong = RecoverRequest {
            apply_ledger_repair: Some(ContentDigest::sha256(b"not the plan")),
            ..RecoverRequest::default()
        };
        let refused = run(&root, &wrong);
        assert_eq!(
            refused.outcome(),
            RecoverOutcome::Refused(Refusal::PlanMismatch)
        );
        assert!(
            refused
                .render_json()
                .contains(&format!("\"current_plan_digest\":\"{digest}\""))
        );
        assert_eq!(std::fs::read(&journal).map_err(|e| e.to_string())?, dirty);

        // The exact digest applies: foreign bytes quarantined, committed history intact.
        let apply = RecoverRequest {
            apply_ledger_repair: Some(digest),
            ..RecoverRequest::default()
        };
        let applied = run(&root, &apply);
        assert_eq!(
            applied.outcome(),
            RecoverOutcome::Applied,
            "{}",
            applied.render_json()
        );
        assert_eq!(
            std::fs::metadata(&journal)
                .map_err(|e| e.to_string())?
                .len(),
            clean_len
        );
        assert!(
            applied
                .render_json()
                .contains(&format!("\"plan_digest\":\"{digest}\""))
        );
        // A rerun after the completed apply has nothing to do; neither has the plan.
        assert_eq!(
            run(&root, &apply).outcome(),
            RecoverOutcome::Refused(Refusal::NothingToDo)
        );
        assert_eq!(
            run(&root, &plan_request).outcome(),
            RecoverOutcome::Refused(Refusal::NothingToDo)
        );
        Ok(())
    }

    #[test]
    fn foreign_bytes_holding_a_valid_record_are_corrupt_history() -> TestResult {
        let scratch = Scratch::new("corrupt")?;
        let root = corpus(&scratch, "clean", Injection::None);
        let journal = root.join("ledger").join("journal.fssj");
        let history = std::fs::read(&journal).map_err(|e| e.to_string())?;
        // Garbage, then a copy of committed records: one foreign range that contains
        // structurally valid records.
        let mut foreign = b"garbage".to_vec();
        foreign.extend_from_slice(&history);
        append_bytes(&journal, &foreign)?;
        let plan = run(
            &root,
            &RecoverRequest {
                plan_repair: Some(RecoverJournal::Ledger),
                ..RecoverRequest::default()
            },
        );
        assert_eq!(
            plan.outcome(),
            RecoverOutcome::Refused(Refusal::CorruptHistory),
            "{}",
            plan.render_json()
        );
        let apply = run(
            &root,
            &RecoverRequest {
                apply_ledger_repair: Some(ContentDigest::sha256(b"any")),
                ..RecoverRequest::default()
            },
        );
        assert_eq!(
            apply.outcome(),
            RecoverOutcome::Refused(Refusal::CorruptHistory),
            "{}",
            apply.render_json()
        );
        assert_eq!(status_of(&apply, "reopen_check"), Some(StepStatus::Skipped));
        Ok(())
    }

    /// The command line the read-only doctor names for `finding` in check `check_id`.
    fn doctor_command(root: &Path, check_id: &str, finding: &str) -> Result<String, String> {
        let report = inspect_deployment(root);
        let check = report
            .check(check_id)
            .ok_or_else(|| format!("no {check_id} check: {}", report.to_json()))?;
        let found = check
            .findings
            .iter()
            .find(|candidate| candidate.kind == finding)
            .ok_or_else(|| format!("no {finding} finding: {}", check.to_json()))?;
        match &found.next_affordance {
            Some(DoctorAffordance::Command { command, .. }) => Ok(command.clone()),
            other => Err(format!("{finding}: not a command: {other:?}")),
        }
    }

    /// Runs a doctor-named `fss-lab recover ...` command line through the `fss-lab` argument
    /// parser and the recover code path, exactly as the binary does.
    fn run_command(command: &str) -> Result<RecoverReport, String> {
        let argv = command
            .strip_prefix("fss-lab ")
            .ok_or_else(|| format!("not an fss-lab command: {command}"))?;
        match parse_lab_args(argv.split(' ').map(OsString::from)) {
            Ok(LabAction::Recover { root, request, .. }) => Ok(run(&root, &request)),
            other => Err(format!("{command}: {other:?}")),
        }
    }

    fn finding_kinds(root: &Path, check_id: &str) -> Vec<String> {
        inspect_deployment(root)
            .check(check_id)
            .map(|check| check.findings.iter().map(|f| f.kind.clone()).collect())
            .unwrap_or_default()
    }

    #[test]
    fn each_doctor_named_command_on_a_crash_matrix_sub_root_clears_its_finding() -> TestResult {
        let scratch = Scratch::new("doctor-commands")?;
        let rows: [(&str, Injection, &str, &str, &str); 3] = [
            (
                "append.body_write",
                Injection::LedgerAppendFailure(AppendPhase::BodyWrite),
                "ledger.journal",
                "incomplete_tail",
                "--truncate-incomplete-tail ledger",
            ),
            (
                "publish.after_root_temp_write",
                Injection::PublishCrash(PublishCutPoint::AfterRootTempWrite),
                "publication.roots",
                "orphaned_root_temps",
                "--discard-orphaned-temps",
            ),
            (
                "effect.lost_ack",
                Injection::CrashAfterLostAck,
                "effects.obligations",
                "indeterminate_obligations",
                "--reconcile-effects",
            ),
        ];
        for (name, injection, check_id, finding, flags) in rows {
            let root = corpus(&scratch, name, injection);
            let command = doctor_command(&root, check_id, finding)?;
            assert_eq!(
                command,
                format!("fss-lab recover --root {} {flags}", root.display()),
                "{name}"
            );
            let report = run_command(&command)?;
            assert_eq!(
                report.outcome(),
                RecoverOutcome::Applied,
                "{name}: {}",
                report.render_json()
            );
            assert!(
                !finding_kinds(&root, check_id).contains(&finding.to_owned()),
                "{name}: the doctor still reports {finding}"
            );
        }

        // Foreign trailing bytes: the doctor names the apply of exactly its sealed plan digest.
        let root = corpus(&scratch, "foreign", Injection::None);
        let journal = root.join("ledger").join("journal.fssj");
        append_bytes(&journal, b"foreign trailing bytes for the doctor")?;
        let planned = run(
            &root,
            &RecoverRequest {
                plan_repair: Some(RecoverJournal::Ledger),
                ..RecoverRequest::default()
            },
        );
        let digest = plan_digest(&planned)?;
        let command = doctor_command(&root, "ledger.journal", "foreign_trailing_bytes")?;
        assert_eq!(
            command,
            format!(
                "fss-lab recover --root {} --apply-ledger-repair {digest}",
                root.display()
            )
        );
        let report = run_command(&command)?;
        assert_eq!(report.outcome(), RecoverOutcome::Applied);
        assert!(finding_kinds(&root, "ledger.journal").is_empty());
        Ok(())
    }

    /// Writes an orphaned staging file as an interrupted ingest of `payload` leaves it.
    fn plant_orphan(root: &Path, payload: &[u8], attempt: u32) -> Result<String, String> {
        let name = format!(
            "{}.{attempt}.tmp",
            ContentDigest::sha256(payload)
                .to_text()
                .trim_start_matches("sha256:")
        );
        std::fs::write(staging_dir(root).join(&name), payload).map_err(|e| e.to_string())?;
        Ok(name)
    }

    fn staging_dir(root: &Path) -> PathBuf {
        root.join("objects").join("spool").join("staging")
    }

    fn staging_names(root: &Path) -> Result<Vec<String>, String> {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(staging_dir(root)).map_err(|e| e.to_string())? {
            names.push(
                entry
                    .map_err(|e| e.to_string())?
                    .file_name()
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        names.sort();
        Ok(names)
    }

    #[test]
    fn orphaned_staging_is_discarded_exactly_and_a_rerun_has_nothing_to_do() -> TestResult {
        let scratch = Scratch::new("staging")?;
        let root = corpus(
            &scratch,
            "cancel.publish_root",
            Injection::CancelAt(crate::scenario::stage::PUBLISH_ROOT),
        );
        let request = RecoverRequest {
            discard_orphaned_staging: true,
            ..RecoverRequest::default()
        };
        // Nothing to discard yet.
        let none = run(&root, &request);
        assert_eq!(
            none.outcome(),
            RecoverOutcome::Refused(Refusal::NothingToDo)
        );
        assert_eq!(
            status_of(&none, "discard_orphaned_staging"),
            Some(StepStatus::NothingToDo)
        );

        let mut orphans = vec![
            plant_orphan(&root, b"interrupted ingest one", 0)?,
            plant_orphan(&root, b"interrupted ingest two!", 2)?,
        ];
        orphans.sort();
        std::fs::write(staging_dir(&root).join("operator-notes"), b"keep")
            .map_err(|e| e.to_string())?;
        let mut before = orphans.clone();
        before.push("operator-notes".to_owned());
        before.sort();
        assert_eq!(staging_names(&root)?, before);

        // The doctor names exactly this command for the finding.
        let command = doctor_command(&root, "publication.staging", "orphaned_staging")?;
        assert_eq!(
            command,
            format!(
                "fss-lab recover --root {} --discard-orphaned-staging",
                root.display()
            )
        );
        let report = run_command(&command)?;
        let json = report.render_json();
        assert_eq!(report.outcome(), RecoverOutcome::Applied, "{json}");
        let orphan_list: Vec<String> = orphans
            .iter()
            .map(|name| format!("\"staging/{name}\""))
            .collect();
        assert!(
            json.contains(&format!(
                "{{\"action\":\"discard_orphaned_staging\",\"target\":\"objects\",\"status\":\"applied\",\"receipt\":{{\"discarded\":2,\"released_bytes\":45,\"orphans\":[{}]}}}}",
                orphan_list.join(",")
            )),
            "{json}"
        );
        assert!(json.contains("\"schema\":\"fss.lab.recover_report.v1\""));
        // Exactly the orphans went; the foreign entry stays; the spool reports clean.
        assert_eq!(staging_names(&root)?, vec!["operator-notes".to_owned()]);
        assert_eq!(
            std::fs::read(staging_dir(&root).join("operator-notes")).map_err(|e| e.to_string())?,
            b"keep"
        );
        let state = report.state_after.as_ref().ok_or("state_after")?;
        assert_eq!(state.orphaned_staging, 0);
        assert!(finding_kinds(&root, "publication.staging").is_empty());

        // The completed command, rerun: nothing to do, nothing touched.
        let again = run(&root, &request);
        assert_eq!(
            again.outcome(),
            RecoverOutcome::Refused(Refusal::NothingToDo)
        );
        assert_eq!(staging_names(&root)?, vec!["operator-notes".to_owned()]);
        Ok(())
    }

    #[test]
    fn an_indeterminate_staging_discard_is_a_typed_failure_never_applied_or_nothing_to_do() {
        let orphans = vec!["staging/a.0.tmp".to_owned()];
        let indeterminate = ReferenceError::from(LocalPublicationError::Spool(
            SpoolError::DiscardIndeterminate {
                path: PathBuf::from("/r/objects/spool/staging"),
                operation: SpoolIoOperation::SyncDirectory,
                kind: std::io::ErrorKind::Other,
            },
        ));
        let step = super::staging_step(Err(indeterminate), &orphans);
        assert!(matches!(step.status, StepStatus::Indeterminate(_)));
        assert!(step.status.stops());
        let report = RecoverReport {
            root: PathBuf::from("/r"),
            requested: vec!["--discard-orphaned-staging".to_owned()],
            steps: vec![step],
            restart_reclassified: Vec::new(),
            state_after: None,
        };
        assert!(matches!(report.outcome(), RecoverOutcome::Indeterminate(_)));
        let json = report.render_json();
        assert!(json.contains("\"status\":\"indeterminate\""), "{json}");
        assert!(
            json.contains("\"error_code\":\"ERR-PUBLICATION-LOCAL-SPOOL-001\""),
            "{json}"
        );
        assert!(json.contains("\"publisher_poisoned\":true"), "{json}");
        assert!(
            json.contains("\"path\":\"/r/objects/spool/staging\""),
            "{json}"
        );
        assert!(json.contains("\"outcome\":\"indeterminate\""), "{json}");

        // A poisoned spool is indeterminate too; a settled failure is an ordinary failure.
        let poisoned = super::staging_step(
            Err(ReferenceError::from(LocalPublicationError::Spool(
                SpoolError::Poisoned,
            ))),
            &orphans,
        );
        assert!(matches!(poisoned.status, StepStatus::Indeterminate(_)));
        let settled = super::staging_step(
            Err(ReferenceError::from(LocalPublicationError::Spool(
                SpoolError::InvalidLayout {
                    path: PathBuf::from("/r/objects/spool/staging/a.0.tmp"),
                },
            ))),
            &orphans,
        );
        assert!(matches!(settled.status, StepStatus::Failed(_)));
        // A receipt that removed nothing is nothing to do, never applied.
        let empty = super::staging_step(
            Ok(fss_object::DiscardReceipt {
                removed: 0,
                released_bytes: 0,
            }),
            &orphans,
        );
        assert_eq!(empty.status, StepStatus::NothingToDo);
    }

    #[test]
    fn uninitialized_roots_are_refused_without_writes() -> TestResult {
        let scratch = Scratch::new("refusals")?;
        let empty = scratch.0.join("empty");
        std::fs::create_dir(&empty).map_err(|e| e.to_string())?;
        let report = run(&empty, &reconcile());
        assert!(matches!(report.outcome(), RecoverOutcome::Failed(_)));
        // Recover never initializes a deployment.
        assert_eq!(
            std::fs::read_dir(&empty)
                .map_err(|e| e.to_string())?
                .count(),
            0
        );
        Ok(())
    }
}

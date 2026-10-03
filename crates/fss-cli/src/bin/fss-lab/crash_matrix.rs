#![forbid(unsafe_code)]
//! `fss-lab crash-matrix`: inject one fault per registered fault point into the intrusion
//! scenario on the real stack, reopen through `ReferenceDeployment`, and record the recovery
//! state against an expected class stated up front (fss-2h5zq.15).
//!
//! # Method
//!
//! For each row of [`fault_table`], in table order:
//!
//! 1. Run the scenario in a fresh sub-root `<root>/<family>.<variant>/` with exactly one fault
//!    armed ([`Injection`]). A fault that fires ends the run there, and dropping every handle is
//!    the in-process stand-in for the process dying.
//! 2. Reopen the sub-root with [`ReferenceDeployment::reopen`]. An incomplete journal tail is
//!    refused by that reopen; it is recorded as the tail state.
//! 3. Copy the sub-root to `<root>/rerun/<family>.<variant>/`, so the crashed sub-root stays on
//!    disk untouched as the doctor's corpus. On the copy, apply the byte recovery the class needs
//!    (`ReferenceDeployment::open_for_recovery` truncation of an incomplete tail), reopen, and
//!    record orphaned staging and root temps, broken roots, unreferenced objects, pending roots
//!    and obligations by state.
//! 4. Apply the remaining explicit recovery action (discard orphaned root temps), then rerun the
//!    scenario with no fault on the copy, and count duplicate effects: a provider call for an
//!    operation the journal had already dispatched, a provider record nothing in the rerun
//!    dispatched, a second operation under one idempotency key, or a second batch under one
//!    batch identity.
//!
//! The observed class is computed from those counts by [`classify`]; the expected class is the
//! table's, written from the owning crates' documented recovery contracts and never from a run.
//!
//! # No-Claim
//!
//! Every fault is injected in process through a seam the owning crate exposes. It is not process
//! death, power loss, or a torn page: unsynced bytes stay in the page cache and are read back by
//! the reopen. Real process death is covered by fss-publication's
//! `tests/process_death_crash_harness.rs` (`process_death_sweep_over_spool_publisher_and_ledger`),
//! which this matrix cites rather than duplicates.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use fss_core::{EffectState, ObligationState, OperationId};
use fss_publication::{LedgerCutPoint, PublishCutPoint};
use fss_reference::{AppendPhase, RecoveryAction, ReferenceDeployment, ReferenceError};

use crate::scenario::{Injection, ScenarioKind, make_cx, run_injected, stage};

/// Output schema of the crash matrix.
pub const CRASH_MATRIX_SCHEMA: &str = "fss.lab.crash_matrix.v1";

/// Explicit statement of what this matrix does not prove.
pub const NO_CLAIM: &str = "in-process fault injection only: not process death, power loss or a torn write; real process death is fss-publication tests/process_death_crash_harness.rs";

/// The scenario every row runs.
pub const MATRIX_SCENARIO: ScenarioKind = ScenarioKind::Intrusion;

/// Recovery classification of a sub-root, in precedence order: the first class whose condition
/// holds is the class. Stated before any run; [`classify`] implements exactly this order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryClass {
    /// The fault point has no injection hook or the scenario never reaches it; nothing ran.
    NotApplicable,
    /// The reopen refused an incomplete journal tail.
    IncompleteTail,
    /// The reopen refused for any other reason.
    ReopenRefused,
    /// A root record failed verification or its visibility is indeterminate.
    BrokenRoot,
    /// An obligation is neither terminal nor indeterminate.
    ObligationPending,
    /// An obligation is explicitly indeterminate.
    EffectIndeterminate,
    /// A durable root the ledger does not name yet (`RootLedgerState::PendingLedger`).
    PendingRoot,
    /// A temporary root record left by an interrupted publication.
    OrphanedRootTemp,
    /// A staging file left by an interrupted spool ingest.
    OrphanedStaging,
    /// Spool objects no admitted root reaches.
    UnreferencedObjects,
    /// Nothing to recover.
    Clean,
}

impl RecoveryClass {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::IncompleteTail => "incomplete_tail",
            Self::ReopenRefused => "reopen_refused",
            Self::BrokenRoot => "broken_root",
            Self::ObligationPending => "obligation_pending",
            Self::EffectIndeterminate => "effect_indeterminate",
            Self::PendingRoot => "pending_root",
            Self::OrphanedRootTemp => "orphaned_root_temp",
            Self::OrphanedStaging => "orphaned_staging",
            Self::UnreferencedObjects => "unreferenced_objects",
            Self::Clean => "clean",
        }
    }
}

/// How a fault point is exercised.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Exercise {
    /// Run the scenario with this fault armed; `interrupts` states up front whether the fault
    /// stops the run.
    Run {
        /// The armed fault.
        injection: Injection,
        /// Whether the documented contract says the fault ends the run early.
        interrupts: bool,
    },
    /// Not run, with the reason.
    NotApplicable(&'static str),
}

/// One fault point with its expected class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultRow {
    /// Stable sub-root slug `<family>.<variant>`.
    pub fault: &'static str,
    /// How the row is exercised.
    pub exercise: Exercise,
    /// Expected recovery class, from the cited contract.
    pub expected: RecoveryClass,
    /// Short citation of the contract the expectation comes from.
    pub contract: &'static str,
}

const fn run(injection: Injection, interrupts: bool) -> Exercise {
    Exercise::Run {
        injection,
        interrupts,
    }
}

const NO_LEDGER_HOOK: &str = "no injection hook in fss-ledger: Journal::append polls fail_after only after BodyWrite, BodySync, CommitWrite and CommitSync (journal.rs maybe_fail); reconcile_pending never does";

/// Slug of an [`AppendPhase`]. Exhaustive, so a new phase fails to compile until it has a row.
#[must_use]
pub const fn append_slug(phase: AppendPhase) -> &'static str {
    match phase {
        AppendPhase::BodyWrite => "append.body_write",
        AppendPhase::BodySync => "append.body_sync",
        AppendPhase::CommitWrite => "append.commit_write",
        AppendPhase::CommitSync => "append.commit_sync",
        AppendPhase::ReconcileRead => "append.reconcile_read",
        AppendPhase::ReconcileTruncate => "append.reconcile_truncate",
        AppendPhase::ReconcileSync => "append.reconcile_sync",
        AppendPhase::ReconcileSeek => "append.reconcile_seek",
    }
}

/// Slug of a [`PublishCutPoint`]. Exhaustive, so a new cut point fails to compile until it has a
/// row.
#[must_use]
pub const fn publish_slug(point: PublishCutPoint) -> &'static str {
    match point {
        PublishCutPoint::AfterChildrenVerified => "publish.after_children_verified",
        PublishCutPoint::AfterManifestBody => "publish.after_manifest_body",
        PublishCutPoint::AfterRootTempWrite => "publish.after_root_temp_write",
        PublishCutPoint::AfterRootRename => "publish.after_root_rename",
    }
}

/// Slug of a [`LedgerCutPoint`]. Exhaustive, so a new cut point fails to compile until it has a
/// row.
#[must_use]
pub const fn ledger_slug(point: LedgerCutPoint) -> &'static str {
    match point {
        LedgerCutPoint::AfterRootDurable => "ledger.after_root_durable",
    }
}

/// The expected-class table, one row per fault point, written before any run.
///
/// Where the intrusion scenario is when each fault fires (from scenario.rs, in order): open;
/// stage every source, capsule and model result with `stage_payload`; evaluate policy; publish
/// the event (one ledger batch); prepare the alert (effect journal); dispatch it through the
/// simulated provider and reconcile it to `Verified`; publish and ledger the `slot-sources` root
/// over every staged object (the last ledger append); compile the situation; seal the handoff.
/// Publication, ledger-linkage and append faults are armed on that final `slot-sources`
/// publication, so the alert is already terminal when they fire.
#[must_use]
pub fn fault_table() -> Vec<FaultRow> {
    use RecoveryClass as C;
    vec![
        // fss-publication local/mod.rs "Protocol": a crash at any cut point before step 5 (the
        // rename) leaves nothing visible; "Reopen": objects no admitted root reaches are reported
        // as unreferenced_objects and nothing is deleted implicitly. No other root exists, so
        // every staged object is unreferenced.
        FaultRow {
            fault: publish_slug(PublishCutPoint::AfterChildrenVerified),
            exercise: run(
                Injection::PublishCrash(PublishCutPoint::AfterChildrenVerified),
                true,
            ),
            expected: C::UnreferencedObjects,
            contract: "fss-publication local/mod.rs Protocol+Reopen: nothing visible before the rename; unreachable objects reported unreferenced",
        },
        // Same contract: the manifest body is staged but no root record names it.
        FaultRow {
            fault: publish_slug(PublishCutPoint::AfterManifestBody),
            exercise: run(
                Injection::PublishCrash(PublishCutPoint::AfterManifestBody),
                true,
            ),
            expected: C::UnreferencedObjects,
            contract: "fss-publication local/mod.rs Protocol+Reopen: nothing visible before the rename; unreachable objects reported unreferenced",
        },
        // local/mod.rs "Reopen": temporary records are reported as orphaned_temps (the reopen
        // deletes a temp only when its target record already exists; here none does).
        FaultRow {
            fault: publish_slug(PublishCutPoint::AfterRootTempWrite),
            exercise: run(
                Injection::PublishCrash(PublishCutPoint::AfterRootTempWrite),
                true,
            ),
            expected: C::OrphanedRootTemp,
            contract: "fss-publication local/mod.rs Reopen: temporary records are reported as orphaned_temps",
        },
        // fss-publication ledger.rs crash table: "after the rename, before the directory fsync |
        // Visible | unchanged | PendingLedger (reopen admits and fsyncs)".
        FaultRow {
            fault: publish_slug(PublishCutPoint::AfterRootRename),
            exercise: run(
                Injection::PublishCrash(PublishCutPoint::AfterRootRename),
                true,
            ),
            expected: C::PendingRoot,
            contract: "fss-publication ledger.rs crash table: after the rename, before the fsync -> PendingLedger",
        },
        // ledger.rs crash table: "after the root is Durable, before the append | Durable |
        // unchanged | PendingLedger".
        FaultRow {
            fault: ledger_slug(LedgerCutPoint::AfterRootDurable),
            exercise: run(
                Injection::LedgerCrash(LedgerCutPoint::AfterRootDurable),
                true,
            ),
            expected: C::PendingRoot,
            contract: "fss-publication ledger.rs crash table: root Durable, before the append -> PendingLedger",
        },
        // fss-ledger journal.rs Journal::append: the body is written before the BodyWrite and
        // BodySync checks and the commit trailer after them, so the record is torn; recovery.rs
        // inspect: "a torn final record is returned as incomplete_tail"; ReferenceDeployment::open
        // rejects an incomplete tail (IncompleteTailPolicy::Reject).
        FaultRow {
            fault: append_slug(AppendPhase::BodyWrite),
            exercise: run(Injection::LedgerAppendFailure(AppendPhase::BodyWrite), true),
            expected: C::IncompleteTail,
            contract: "fss-ledger journal.rs append (trailer not yet written) + recovery.rs torn record = incomplete_tail; ReferenceDeployment::open rejects it",
        },
        FaultRow {
            fault: append_slug(AppendPhase::BodySync),
            exercise: run(Injection::LedgerAppendFailure(AppendPhase::BodySync), true),
            expected: C::IncompleteTail,
            contract: "fss-ledger journal.rs append (trailer not yet written) + recovery.rs torn record = incomplete_tail; ReferenceDeployment::open rejects it",
        },
        // journal.rs Journal::append: the trailer is written before the CommitWrite and
        // CommitSync checks, so the record is complete; recovery.rs replays a complete record as
        // committed, and the caller only saw AppendIndeterminate (ledger.rs crash table "append
        // indeterminate | Durable | committed or not | Ledgered or PendingLedger").
        FaultRow {
            fault: append_slug(AppendPhase::CommitWrite),
            exercise: run(
                Injection::LedgerAppendFailure(AppendPhase::CommitWrite),
                true,
            ),
            expected: C::Clean,
            contract: "fss-ledger journal.rs append (trailer written) + recovery.rs complete record = committed; ledger.rs -> Ledgered",
        },
        FaultRow {
            fault: append_slug(AppendPhase::CommitSync),
            exercise: run(
                Injection::LedgerAppendFailure(AppendPhase::CommitSync),
                true,
            ),
            expected: C::Clean,
            contract: "fss-ledger journal.rs append (trailer written) + recovery.rs complete record = committed; ledger.rs -> Ledgered",
        },
        FaultRow {
            fault: append_slug(AppendPhase::ReconcileRead),
            exercise: Exercise::NotApplicable(NO_LEDGER_HOOK),
            expected: C::NotApplicable,
            contract: "fss-ledger journal.rs: no fault hook in reconcile_pending",
        },
        FaultRow {
            fault: append_slug(AppendPhase::ReconcileTruncate),
            exercise: Exercise::NotApplicable(NO_LEDGER_HOOK),
            expected: C::NotApplicable,
            contract: "fss-ledger journal.rs: no fault hook in reconcile_pending",
        },
        FaultRow {
            fault: append_slug(AppendPhase::ReconcileSync),
            exercise: Exercise::NotApplicable(NO_LEDGER_HOOK),
            expected: C::NotApplicable,
            contract: "fss-ledger journal.rs: no fault hook in reconcile_pending",
        },
        FaultRow {
            fault: append_slug(AppendPhase::ReconcileSeek),
            exercise: Exercise::NotApplicable(NO_LEDGER_HOOK),
            expected: C::NotApplicable,
            contract: "fss-ledger journal.rs: no fault hook in reconcile_pending",
        },
        // fss-reference alert.rs execute_alert_dispatch: a lost acknowledgement is durably marked
        // Indeterminate ("provider_ack_lost") before dispatch returns; durable_effect.rs replays
        // the exact journal state on reopen; plan §29.3 GATE-010: kill points leave terminal or
        // indeterminate obligations.
        FaultRow {
            fault: "effect.lost_ack",
            exercise: run(Injection::CrashAfterLostAck, true),
            expected: C::EffectIndeterminate,
            contract: "fss-reference alert.rs: lost ack -> journaled Indeterminate; durable_effect.rs exact replay; plan 29.3 GATE-010",
        },
        // Plan §29.3 GATE-010: "every injected kill/cancel point yields terminal or indeterminate
        // classified obligations"; plan §8.6: dispatch without a trustworthy result is
        // indeterminate until readback. A kill between commit and the provider call must
        // therefore not leave the obligation pending.
        FaultRow {
            fault: "effect.after_commit_before_dispatch",
            exercise: run(Injection::CrashAfterCommitBeforeDispatch, true),
            expected: C::EffectIndeterminate,
            contract: "plan 29.3 GATE-010: kill points yield terminal or indeterminate obligations; plan 8.6 indeterminate until readback",
        },
        // ReferenceDeployment::open checks cx before creating anything, so nothing is written.
        FaultRow {
            fault: "cancel.deployment_open",
            exercise: run(Injection::CancelAt(stage::DEPLOYMENT_OPEN), true),
            expected: C::Clean,
            contract: "fss-reference reference_deployment.rs open: cancellation checked before any directory or file is created",
        },
        FaultRow {
            fault: "cancel.stage_objects",
            exercise: Exercise::NotApplicable(
                "not reached: the scenario stages through ReferenceDeployment::stage_payload, which has no cancellation checkpoint; stage_objects is polled only by stage_and_publish",
            ),
            expected: C::NotApplicable,
            contract: "fss-reference reference_deployment.rs stage_and_publish",
        },
        FaultRow {
            fault: "cancel.stage_manifest",
            exercise: Exercise::NotApplicable(
                "not reached: stage_manifest is polled only by stage_and_publish, which the scenario never calls",
            ),
            expected: C::NotApplicable,
            contract: "fss-reference reference_deployment.rs stage_and_publish",
        },
        // publish_and_commit: a cancellation before any work leaves disk and ledger unchanged;
        // the staged objects stay unreferenced (local/mod.rs Reopen).
        FaultRow {
            fault: "cancel.publish_root",
            exercise: run(Injection::CancelAt(stage::PUBLISH_ROOT), true),
            expected: C::UnreferencedObjects,
            contract: "fss-reference publish_and_commit: cancelled before any work, ledger unchanged; local/mod.rs Reopen: unreachable objects reported",
        },
        FaultRow {
            fault: "cancel.publish_event",
            exercise: run(Injection::CancelAt(stage::PUBLISH_EVENT), true),
            expected: C::UnreferencedObjects,
            contract: "fss-reference publish_event: cancelled before any work; local/mod.rs Reopen: unreachable objects reported",
        },
        FaultRow {
            fault: "cancel.append_batch",
            exercise: Exercise::NotApplicable(
                "not reached: the scenario never calls ReferenceDeployment::append_batch",
            ),
            expected: C::NotApplicable,
            contract: "fss-reference reference_deployment.rs append_batch",
        },
        FaultRow {
            fault: "cancel.evaluate_policy",
            exercise: run(Injection::CancelAt(stage::EVALUATE_POLICY), true),
            expected: C::UnreferencedObjects,
            contract: "fss-reference evaluate_policy: cancelled before any work; local/mod.rs Reopen: unreachable objects reported",
        },
        // AGENTS.md: cancellation is request -> drain -> finalize with no orphan work, and every
        // obligation is left terminal, delegated or explicitly indeterminate; plan §29.3
        // GATE-010: every cancel point yields terminal or indeterminate obligations. The prepared,
        // never-committed alert drains to a terminal state (DurableEffectJournal::cancel), so the
        // remaining class is the unpublished staged objects.
        FaultRow {
            fault: "cancel.dispatch_alert",
            exercise: run(Injection::CancelAt(stage::DISPATCH_ALERT), true),
            expected: C::UnreferencedObjects,
            contract: "AGENTS.md cancellation request->drain->finalize, obligations terminal or indeterminate; plan 29.3 GATE-010",
        },
        // Nothing durable follows the ledgered slot-sources root: the situation and the handoff
        // are compiled in memory.
        FaultRow {
            fault: "cancel.compile_situation",
            exercise: run(Injection::CancelAt(stage::COMPILE_SITUATION), true),
            expected: C::Clean,
            contract: "fss-reference compile_situation/seal_handoff write nothing; everything before is published and ledgered",
        },
        FaultRow {
            fault: "cancel.seal_handoff",
            exercise: run(Injection::CancelAt(stage::SEAL_HANDOFF), true),
            expected: C::Clean,
            contract: "fss-reference compile_situation/seal_handoff write nothing; everything before is published and ledgered",
        },
        // publish_and_commit: a cancellation at a pre-commit cut point returns
        // CancellationRequested, removes any temporary root record, and leaves the ledger
        // unchanged; local/mod.rs: nothing is visible before the rename.
        FaultRow {
            fault: "cancel.after_children_verified",
            exercise: run(Injection::CancelAt("after_children_verified"), true),
            expected: C::UnreferencedObjects,
            contract: "fss-reference publish_and_commit: pre-commit cancellation removes the temp and leaves the ledger unchanged",
        },
        FaultRow {
            fault: "cancel.after_manifest_body",
            exercise: run(Injection::CancelAt("after_manifest_body"), true),
            expected: C::UnreferencedObjects,
            contract: "fss-reference publish_and_commit: pre-commit cancellation removes the temp and leaves the ledger unchanged",
        },
        FaultRow {
            fault: "cancel.after_root_temp_write",
            exercise: run(Injection::CancelAt("after_root_temp_write"), true),
            expected: C::UnreferencedObjects,
            contract: "fss-reference publish_and_commit: pre-commit cancellation removes the temp and leaves the ledger unchanged",
        },
        // publish_and_commit: "The rename is the commit point: cancellation is never honored
        // after it, so the root becomes durable and is ledgered" (local/mod.rs: "Cancellation is
        // never consulted after the rename"). The run is not interrupted.
        FaultRow {
            fault: "cancel.after_root_rename",
            exercise: run(Injection::CancelAt("after_root_rename"), false),
            expected: C::Clean,
            contract: "fss-reference publish_and_commit + local/mod.rs: cancellation is never consulted after the rename",
        },
    ]
}

/// Recovery state observed for one sub-root.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Observation {
    /// Whether the fault run ended early.
    pub interrupted: bool,
    /// `complete`, `incomplete_ledger`, `incomplete_effects` or `reopen_refused`.
    pub tail_state: &'static str,
    /// Temporary root records left on disk.
    pub orphaned_temps: usize,
    /// Staging files left in the spool.
    pub orphaned_staging: usize,
    /// Root records that failed verification.
    pub broken_roots: usize,
    /// Spool objects no admitted root reaches.
    pub unreferenced_objects: usize,
    /// Durable roots the ledger does not name.
    pub pending_roots: usize,
    /// Obligations in a terminal state.
    pub terminal: usize,
    /// Obligations explicitly indeterminate.
    pub indeterminate: usize,
    /// Obligations neither terminal nor indeterminate.
    pub pending: usize,
    /// Explicit recovery actions applied before the rerun, in order.
    pub recovery_actions: Vec<&'static str>,
    /// Whether the rerun after recovery completed.
    pub rerun_completed: bool,
    /// Duplicate effects counted across the rerun.
    pub duplicate_effects: usize,
}

/// The precedence classifier of [`RecoveryClass`].
#[must_use]
pub fn classify(observation: &Observation) -> RecoveryClass {
    match observation.tail_state {
        "incomplete_ledger" | "incomplete_effects" => return RecoveryClass::IncompleteTail,
        "reopen_refused" => return RecoveryClass::ReopenRefused,
        _ => {}
    }
    if observation.broken_roots > 0 {
        RecoveryClass::BrokenRoot
    } else if observation.pending > 0 {
        RecoveryClass::ObligationPending
    } else if observation.indeterminate > 0 {
        RecoveryClass::EffectIndeterminate
    } else if observation.pending_roots > 0 {
        RecoveryClass::PendingRoot
    } else if observation.orphaned_temps > 0 {
        RecoveryClass::OrphanedRootTemp
    } else if observation.orphaned_staging > 0 {
        RecoveryClass::OrphanedStaging
    } else if observation.unreferenced_objects > 0 {
        RecoveryClass::UnreferencedObjects
    } else {
        RecoveryClass::Clean
    }
}

/// One rendered matrix row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RowResult {
    /// The table row.
    pub row: FaultRow,
    /// Observed class.
    pub observed: RecoveryClass,
    /// Observation, `None` for a not-applicable row.
    pub observation: Option<Observation>,
}

impl RowResult {
    /// Whether the row meets its expectation: observed class equals the expected class, the run
    /// was interrupted exactly when the contract says so, and no effect was duplicated.
    #[must_use]
    pub fn passes(&self) -> bool {
        let interrupts = match self.row.exercise {
            Exercise::Run { interrupts, .. } => Some(interrupts),
            Exercise::NotApplicable(_) => None,
        };
        let observed_interrupt = self.observation.as_ref().map(|o| o.interrupted);
        self.observed == self.row.expected
            && interrupts == observed_interrupt
            && self
                .observation
                .as_ref()
                .is_none_or(|o| o.duplicate_effects == 0)
    }
}

/// Matrix verdict: pass only when every row passes.
#[must_use]
pub fn verdict(rows: &[RowResult]) -> bool {
    rows.iter().all(RowResult::passes)
}

/// Runs every row of [`fault_table`] under `root` and returns the results in table order.
pub fn run_matrix(root: &Path) -> Result<Vec<RowResult>, String> {
    let mut results = Vec::new();
    for row in fault_table() {
        let result = match row.exercise {
            Exercise::NotApplicable(_) => RowResult {
                row,
                observed: RecoveryClass::NotApplicable,
                observation: None,
            },
            Exercise::Run { injection, .. } => {
                let observation = run_row(root, row.fault, injection)?;
                RowResult {
                    row,
                    observed: classify(&observation),
                    observation: Some(observation),
                }
            }
        };
        results.push(result);
    }
    Ok(results)
}

fn run_row(root: &Path, slug: &str, injection: Injection) -> Result<Observation, String> {
    let corpus = root.join(slug);
    let interrupted = run_injected(MATRIX_SCENARIO, &corpus, injection).is_err();

    let cx = make_cx(MATRIX_SCENARIO).map_err(|e| e.to_string())?;
    let tail_state = match ReferenceDeployment::reopen(&corpus, "site:lab", &cx) {
        Ok(_) => "complete",
        Err(ReferenceError::IncompleteJournalTail { path, .. }) => {
            if path.ends_with(Path::new("ledger").join("journal.fssj")) {
                "incomplete_ledger"
            } else {
                "incomplete_effects"
            }
        }
        Err(_) => "reopen_refused",
    };

    let work = root.join("rerun").join(slug);
    copy_tree(&corpus, &work)?;

    let mut observation = Observation {
        interrupted,
        tail_state,
        ..Observation::default()
    };
    let byte_action = match tail_state {
        "incomplete_ledger" => Some((
            RecoveryAction::TruncateIncompleteLedgerTail,
            "truncate_incomplete_ledger_tail",
        )),
        "incomplete_effects" => Some((
            RecoveryAction::TruncateIncompleteEffectTail,
            "truncate_incomplete_effect_tail",
        )),
        _ => None,
    };
    if let Some((action, name)) = byte_action {
        ReferenceDeployment::open_for_recovery(&work, action, &cx)
            .map_err(|e| format!("{slug}: {name} failed: {e}"))?;
        observation.recovery_actions.push(name);
    }

    let Ok(mut deployment) = ReferenceDeployment::reopen(&work, "site:lab", &cx) else {
        // Still refused after the byte recovery: nothing further is safe to measure or rerun.
        return Ok(observation);
    };
    let report = deployment.recovery_report();
    observation.orphaned_temps = report.orphaned_temps.len();
    observation.orphaned_staging = report.spool.orphaned_staging.len();
    observation.broken_roots = report.broken_roots.len();
    observation.unreferenced_objects = report.unreferenced_objects.len();
    let reconciliation = deployment.reconcile().map_err(|e| e.to_string())?;
    observation.pending_roots = reconciliation.pending.len();
    for obligation in deployment.effects().obligations() {
        match obligation.state {
            ObligationState::Verified | ObligationState::Failed | ObligationState::Cancelled => {
                observation.terminal += 1;
            }
            ObligationState::Indeterminate => observation.indeterminate += 1,
            ObligationState::Pending => observation.pending += 1,
        }
    }
    if observation.orphaned_temps > 0 {
        deployment
            .publisher_mut()
            .discard_orphaned_temps()
            .map_err(|e| format!("{slug}: discard_orphaned_temps failed: {e}"))?;
        observation.recovery_actions.push("discard_orphaned_temps");
    }
    drop(deployment);

    let measured = rerun_after_recovery(&work)?;
    observation.rerun_completed = measured.completed;
    observation.duplicate_effects = measured.duplicate_effects;
    Ok(observation)
}

/// What one rerun on a recovered sub-root did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RerunMeasurement {
    /// Whether the rerun completed.
    pub completed: bool,
    /// Duplicate effects (see [`rerun_after_recovery`]).
    pub duplicate_effects: usize,
    /// Ledger batches before the rerun.
    pub ledger_batches_before: usize,
    /// Ledger batches after the rerun.
    pub ledger_batches_after: usize,
    /// Effect operations before the rerun.
    pub operations_before: usize,
    /// Effect operations after the rerun.
    pub operations_after: usize,
}

/// Reruns the scenario with no fault on `work` and counts duplicate effects.
///
/// A duplicate effect is any of: a dispatch the rerun made for an operation the effect journal
/// had already taken past `Prepared` (a blind retry); a record in the rerun's alert provider that
/// no rerun dispatch accounts for (the provider starts empty on every open); a second operation
/// under one idempotency key; a second ledger batch under one batch identity.
pub fn rerun_after_recovery(work: &Path) -> Result<RerunMeasurement, String> {
    let cx = make_cx(MATRIX_SCENARIO).map_err(|e| e.to_string())?;
    let (dispatched_before, ledger_batches_before, operations_before) = {
        let deployment = ReferenceDeployment::reopen(work, "site:lab", &cx)
            .map_err(|e| format!("reopen before rerun failed: {e}"))?;
        let dispatched: BTreeSet<OperationId> = deployment
            .effects()
            .operations()
            .filter(|operation| {
                !matches!(
                    operation.state,
                    EffectState::Prepared | EffectState::Cancelled
                )
            })
            .map(|operation| operation.intent.operation_id.clone())
            .collect();
        (
            dispatched,
            deployment.ledger().batches().len(),
            deployment.effects().operations().count(),
        )
    };

    let mut duplicate_effects = 0;
    let completed = match run_injected(MATRIX_SCENARIO, work, Injection::None) {
        Ok(report) => {
            duplicate_effects += report
                .dispatched_operations
                .iter()
                .filter(|operation| dispatched_before.contains(*operation))
                .count();
            duplicate_effects += report
                .provider_effects
                .saturating_sub(report.dispatched_operations.len());
            true
        }
        Err(_) => false,
    };

    let deployment = ReferenceDeployment::reopen(work, "site:lab", &cx)
        .map_err(|e| format!("reopen after rerun failed: {e}"))?;
    let keys: BTreeSet<_> = deployment
        .effects()
        .operations()
        .map(|operation| operation.intent.idempotency_key.clone())
        .collect();
    let operations_after = deployment.effects().operations().count();
    duplicate_effects += operations_after.saturating_sub(keys.len());
    let batch_ids: BTreeSet<_> = deployment
        .ledger()
        .batches()
        .iter()
        .map(|batch| batch.batch_id.clone())
        .collect();
    let ledger_batches_after = deployment.ledger().batches().len();
    duplicate_effects += ledger_batches_after.saturating_sub(batch_ids.len());

    Ok(RerunMeasurement {
        completed,
        duplicate_effects,
        ledger_batches_before,
        ledger_batches_after,
        operations_before,
        operations_after,
    })
}

/// Copies the directory tree `from` to the new directory `to`. Refuses anything but regular
/// files and directories, and never overwrites.
fn copy_tree(from: &Path, to: &Path) -> Result<(), String> {
    if to.exists() {
        return Err(format!("copy target already exists: {}", to.display()));
    }
    fs::create_dir_all(to).map_err(|e| format!("create {}: {e}", to.display()))?;
    let mut entries: Vec<_> = fs::read_dir(from)
        .map_err(|e| format!("read {}: {e}", from.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("read {}: {e}", from.display()))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let kind = entry
            .file_type()
            .map_err(|e| format!("inspect {}: {e}", entry.path().display()))?;
        let target = to.join(entry.file_name());
        if kind.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), &target)
                .map_err(|e| format!("copy {}: {e}", entry.path().display()))?;
        } else {
            return Err(format!(
                "refusing to copy a non-regular entry: {}",
                entry.path().display()
            ));
        }
    }
    Ok(())
}

/// Renders the `fss.lab.crash_matrix.v1` JSON document.
#[must_use]
pub fn render_json(rows: &[RowResult]) -> String {
    let mut out = String::new();
    out.push('{');
    let _ = write!(
        out,
        "\"schema\":\"{CRASH_MATRIX_SCHEMA}\",\"scenario\":\"{}\",\"injection\":\"in_process\",\"no_claim\":",
        MATRIX_SCENARIO.as_str()
    );
    push_string(&mut out, NO_CLAIM);
    out.push_str(",\"rows\":[");
    for (index, result) in rows.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        render_row(&mut out, result);
    }
    let mismatches = rows.iter().filter(|row| !row.passes()).count();
    let _ = write!(
        out,
        "],\"row_count\":{},\"mismatches\":{mismatches},\"verdict\":\"{}\"}}",
        rows.len(),
        if verdict(rows) { "pass" } else { "fail" }
    );
    out
}

fn render_row(out: &mut String, result: &RowResult) {
    let empty = Observation {
        tail_state: "not_applicable",
        ..Observation::default()
    };
    let observation = result.observation.as_ref().unwrap_or(&empty);
    out.push_str("{\"fault\":");
    push_string(out, result.row.fault);
    out.push_str(",\"expected_class\":");
    push_string(out, result.row.expected.as_str());
    out.push_str(",\"observed_class\":");
    push_string(out, result.observed.as_str());
    out.push_str(",\"pass\":");
    out.push_str(bool_str(result.passes()));
    match result.row.exercise {
        Exercise::Run { interrupts, .. } => {
            out.push_str(",\"expected_interrupted\":");
            out.push_str(bool_str(interrupts));
            out.push_str(",\"interrupted\":");
            out.push_str(bool_str(observation.interrupted));
            out.push_str(",\"reason\":null");
        }
        Exercise::NotApplicable(reason) => {
            out.push_str(",\"expected_interrupted\":null,\"interrupted\":null,\"reason\":");
            push_string(out, reason);
        }
    }
    let _ = write!(
        out,
        ",\"orphaned\":{},\"orphaned_temps\":{},\"orphaned_staging\":{},\"broken_roots\":{},\"unreferenced_objects\":{},\"pending_roots\":{},\"tail_state\":",
        observation.orphaned_temps + observation.orphaned_staging,
        observation.orphaned_temps,
        observation.orphaned_staging,
        observation.broken_roots,
        observation.unreferenced_objects,
        observation.pending_roots,
    );
    push_string(out, observation.tail_state);
    let _ = write!(
        out,
        ",\"obligations\":{{\"terminal\":{},\"indeterminate\":{},\"pending\":{}}},\"recovery_actions\":[",
        observation.terminal, observation.indeterminate, observation.pending
    );
    for (index, action) in observation.recovery_actions.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_string(out, action);
    }
    out.push_str("],\"rerun\":");
    push_string(
        out,
        match (&result.row.exercise, observation.rerun_completed) {
            (Exercise::NotApplicable(_), _) => "not_applicable",
            (_, true) => "completed",
            (_, false) => "refused",
        },
    );
    let _ = write!(
        out,
        ",\"duplicate_effects\":{},\"contract\":",
        observation.duplicate_effects
    );
    push_string(out, result.row.contract);
    out.push('}');
}

/// Renders a fixed-width human table.
#[must_use]
pub fn render_text(rows: &[RowResult]) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "fss-lab crash-matrix ({} scenario; {NO_CLAIM})",
        MATRIX_SCENARIO.as_str()
    );
    let _ = writeln!(
        out,
        "{:<38} {:<22} {:<22} {:>4} {:>4} {:>4} {:<18} {:>4} {:>4} {:>4} {:<9} {:>3}",
        "fault",
        "expected",
        "observed",
        "orph",
        "brkn",
        "unrf",
        "tail",
        "term",
        "ind",
        "pend",
        "rerun",
        "dup"
    );
    for result in rows {
        let empty = Observation {
            tail_state: "not_applicable",
            ..Observation::default()
        };
        let o = result.observation.as_ref().unwrap_or(&empty);
        let rerun = match (&result.row.exercise, o.rerun_completed) {
            (Exercise::NotApplicable(_), _) => "n/a",
            (_, true) => "completed",
            (_, false) => "refused",
        };
        let _ = writeln!(
            out,
            "{:<38} {:<22} {:<22} {:>4} {:>4} {:>4} {:<18} {:>4} {:>4} {:>4} {:<9} {:>3}{}",
            result.row.fault,
            result.row.expected.as_str(),
            result.observed.as_str(),
            o.orphaned_temps + o.orphaned_staging,
            o.broken_roots,
            o.unreferenced_objects,
            o.tail_state,
            o.terminal,
            o.indeterminate,
            o.pending,
            rerun,
            o.duplicate_effects,
            if result.passes() { "" } else { "  MISMATCH" }
        );
    }
    let _ = write!(
        out,
        "verdict: {} ({} rows, {} mismatches)",
        if verdict(rows) { "pass" } else { "fail" },
        rows.len(),
        rows.iter().filter(|row| !row.passes()).count()
    );
    out
}

const fn bool_str(value: bool) -> &'static str {
    if value { "true" } else { "false" }
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
    use super::{
        Exercise, Observation, RecoveryClass, RowResult, append_slug, classify, fault_table,
        ledger_slug, publish_slug, render_json, render_text, rerun_after_recovery, run_matrix,
        verdict,
    };
    use fss_publication::{LedgerCutPoint, PublishCutPoint};
    use fss_reference::{AppendPhase, DEPLOYMENT_CANCEL_STAGES};
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Result<Self, std::io::Error> {
            for n in 0..100 {
                let dir = std::env::temp_dir()
                    .join(format!("fss-lab-crash-{tag}-{}-{n}", std::process::id()));
                match std::fs::create_dir(&dir) {
                    Ok(()) => return Ok(Self(dir)),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e),
                }
            }
            Err(std::io::Error::other("temporary directory capacity"))
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_table_has_exactly_one_row_per_registered_fault_point() {
        let slugs: Vec<&str> = fault_table().iter().map(|row| row.fault).collect();
        let unique: BTreeSet<&str> = slugs.iter().copied().collect();
        assert_eq!(unique.len(), slugs.len(), "duplicate fault slug");

        let mut required: BTreeSet<String> = BTreeSet::new();
        for point in [
            PublishCutPoint::AfterChildrenVerified,
            PublishCutPoint::AfterManifestBody,
            PublishCutPoint::AfterRootTempWrite,
            PublishCutPoint::AfterRootRename,
        ] {
            // The slug spells the publisher's own Display name of the cut point.
            assert_eq!(publish_slug(point), format!("publish.{point}"));
            required.insert(publish_slug(point).to_owned());
        }
        required.insert(ledger_slug(LedgerCutPoint::AfterRootDurable).to_owned());
        assert_eq!(
            ledger_slug(LedgerCutPoint::AfterRootDurable),
            format!("ledger.{}", LedgerCutPoint::AfterRootDurable)
        );
        for phase in [
            AppendPhase::BodyWrite,
            AppendPhase::BodySync,
            AppendPhase::CommitWrite,
            AppendPhase::CommitSync,
            AppendPhase::ReconcileRead,
            AppendPhase::ReconcileTruncate,
            AppendPhase::ReconcileSync,
            AppendPhase::ReconcileSeek,
        ] {
            required.insert(append_slug(phase).to_owned());
        }
        for stage in DEPLOYMENT_CANCEL_STAGES {
            required.insert(format!("cancel.{stage}"));
        }
        required.insert("effect.lost_ack".to_owned());
        required.insert("effect.after_commit_before_dispatch".to_owned());
        assert_eq!(unique, required.iter().map(String::as_str).collect());
    }

    #[test]
    fn every_cancel_injection_names_a_registered_stage() {
        for row in fault_table() {
            if let Exercise::Run {
                injection: crate::scenario::Injection::CancelAt(stage),
                ..
            } = row.exercise
            {
                assert!(DEPLOYMENT_CANCEL_STAGES.contains(&stage), "{stage}");
                assert_eq!(row.fault, format!("cancel.{stage}"));
            }
        }
    }

    #[test]
    fn not_applicable_rows_carry_a_reason_and_the_not_applicable_class() {
        for row in fault_table() {
            match row.exercise {
                Exercise::NotApplicable(reason) => {
                    assert!(!reason.is_empty());
                    assert_eq!(row.expected, RecoveryClass::NotApplicable, "{}", row.fault);
                }
                Exercise::Run { .. } => {
                    assert_ne!(row.expected, RecoveryClass::NotApplicable, "{}", row.fault);
                }
            }
            assert!(!row.contract.is_empty(), "{} cites no contract", row.fault);
        }
    }

    #[test]
    fn classify_follows_the_stated_precedence() {
        let base = Observation {
            tail_state: "complete",
            ..Observation::default()
        };
        assert_eq!(classify(&base), RecoveryClass::Clean);
        let unreferenced = Observation {
            unreferenced_objects: 3,
            ..base.clone()
        };
        assert_eq!(classify(&unreferenced), RecoveryClass::UnreferencedObjects);
        let temp = Observation {
            orphaned_temps: 1,
            ..unreferenced.clone()
        };
        assert_eq!(classify(&temp), RecoveryClass::OrphanedRootTemp);
        let pending_root = Observation {
            pending_roots: 1,
            ..temp.clone()
        };
        assert_eq!(classify(&pending_root), RecoveryClass::PendingRoot);
        let indeterminate = Observation {
            indeterminate: 1,
            ..pending_root.clone()
        };
        assert_eq!(classify(&indeterminate), RecoveryClass::EffectIndeterminate);
        let pending = Observation {
            pending: 1,
            ..indeterminate.clone()
        };
        assert_eq!(classify(&pending), RecoveryClass::ObligationPending);
        let broken = Observation {
            broken_roots: 1,
            ..pending.clone()
        };
        assert_eq!(classify(&broken), RecoveryClass::BrokenRoot);
        let tail = Observation {
            tail_state: "incomplete_ledger",
            ..broken
        };
        assert_eq!(classify(&tail), RecoveryClass::IncompleteTail);
    }

    fn passing_row() -> Result<RowResult, String> {
        let row = fault_table()
            .into_iter()
            .find(|row| row.fault == "publish.after_root_rename")
            .ok_or("publish.after_root_rename row is missing")?;
        Ok(RowResult {
            row,
            observed: row.expected,
            observation: Some(Observation {
                interrupted: true,
                tail_state: "complete",
                ..Observation::default()
            }),
        })
    }

    #[test]
    fn a_planted_class_mismatch_fails_the_verdict() -> Result<(), String> {
        let good = passing_row()?;
        assert!(verdict(std::slice::from_ref(&good)));
        // Planted negative: the observed class differs from the expected one.
        let planted = RowResult {
            observed: RecoveryClass::Clean,
            ..good.clone()
        };
        assert_ne!(planted.observed, planted.row.expected);
        assert!(!verdict(&[good.clone(), planted.clone()]));
        assert!(render_json(&[good, planted]).contains("\"verdict\":\"fail\""));
        Ok(())
    }

    #[test]
    fn a_duplicate_effect_or_an_unexpected_interrupt_fails_the_verdict() -> Result<(), String> {
        let good = passing_row()?;
        let mut duplicated = good.clone();
        if let Some(observation) = duplicated.observation.as_mut() {
            observation.duplicate_effects = 1;
        }
        assert!(!verdict(&[duplicated]));
        let mut not_fired = good;
        if let Some(observation) = not_fired.observation.as_mut() {
            observation.interrupted = false;
        }
        assert!(!verdict(&[not_fired]));
        Ok(())
    }

    #[test]
    fn the_text_table_marks_mismatches_and_states_the_verdict() -> Result<(), String> {
        let good = passing_row()?;
        let text = render_text(std::slice::from_ref(&good));
        assert!(text.contains("publish.after_root_rename"));
        assert!(text.ends_with("verdict: pass (1 rows, 0 mismatches)"));
        assert!(!text.contains("MISMATCH"));
        let planted = RowResult {
            observed: RecoveryClass::Clean,
            ..good
        };
        let text = render_text(&[planted]);
        assert!(text.contains("MISMATCH"));
        assert!(text.ends_with("verdict: fail (1 rows, 1 mismatches)"));
        Ok(())
    }

    /// Runs the full matrix twice in fresh roots: the output is byte-identical, every fault point
    /// has a row, every rerun after recovery completed without a duplicate effect, and a second
    /// rerun on every recovered sub-root changes neither journal and duplicates nothing.
    #[test]
    fn the_matrix_is_deterministic_and_reruns_are_idempotent() -> Result<(), String> {
        let first_root = Scratch::new("a").map_err(|e| e.to_string())?;
        let second_root = Scratch::new("b").map_err(|e| e.to_string())?;
        let first = run_matrix(&first_root.0)?;
        let second = run_matrix(&second_root.0)?;
        let first_json = render_json(&first);
        assert_eq!(first_json, render_json(&second));
        println!("CRASH-MATRIX {first_json}");
        assert_eq!(first.len(), fault_table().len());
        // Every row meets its documented class since fss-51xqy (cooperative cancel at
        // dispatch_alert drains to a terminal cancellation) and fss-mc9c4 (a committed alert with
        // no provider record is indeterminate after restart).
        let failing: Vec<&str> = first
            .iter()
            .filter(|result| !result.passes())
            .map(|result| result.row.fault)
            .collect();
        assert!(verdict(&first), "failing rows: {failing:?}");

        for result in &first {
            let Some(observation) = &result.observation else {
                assert_eq!(result.observed, RecoveryClass::NotApplicable);
                continue;
            };
            assert_eq!(observation.duplicate_effects, 0, "{}", result.row.fault);
            assert!(
                observation.rerun_completed,
                "{}: rerun after recovery did not complete",
                result.row.fault
            );
            // The crashed corpus and its recovered copy both stay on disk.
            assert!(first_root.0.join(result.row.fault).is_dir());
            let work = first_root.0.join("rerun").join(result.row.fault);
            assert!(work.is_dir());
            let again = rerun_after_recovery(&work)?;
            assert!(again.completed, "{}", result.row.fault);
            assert_eq!(again.duplicate_effects, 0, "{}", result.row.fault);
            assert_eq!(
                again.ledger_batches_after, again.ledger_batches_before,
                "{}: a second rerun appended a ledger batch",
                result.row.fault
            );
            assert_eq!(
                again.operations_after, again.operations_before,
                "{}: a second rerun added an effect operation",
                result.row.fault
            );
        }
        Ok(())
    }
}

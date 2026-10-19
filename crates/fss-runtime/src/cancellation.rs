//! The deterministic cancellation state machine: request → drain →
//! finalize, with four-valued terminal outcomes. Built over Asupersync's
//! cancellation substrate (`Cx::cancel_with_reason` / `is_cancelled`), this
//! is the FSS reference behavior for the import record IMP-AS-CANCEL-001:
//! non-cooperative work ends `Indeterminate`, never dropped-as-cancelled or
//! reported-as-complete.
//!
//! Sans-IO and deterministic: the driver is fed worker handles and time by
//! the caller; it never spawns, sleeps, or touches a clock of its own.

use std::collections::BTreeSet;

/// Terminal outcome of a cancellation lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CancelOutcome {
    /// The work finished naturally and every registered worker ended.
    Completed,
    /// The work was cancelled and drained cooperatively.
    Cancelled,
    /// The work failed and every registered worker ended.
    Failed {
        /// Typed reason (never secret-bearing).
        reason: String,
    },
    /// The work did not cooperatively end within the drain window — the
    /// honest indeterminate state (not a silent cancel, not a fake success).
    Indeterminate {
        /// Typed reason (never secret-bearing).
        reason: String,
    },
}

impl CancelOutcome {
    /// Whether the lifecycle completed or cooperatively cancelled with every
    /// worker ended. Failed and indeterminate outcomes remain distinct.
    #[must_use]
    pub const fn is_terminal_clean(&self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled)
    }
}

/// Lifecycle state of one cancellation.
#[derive(Clone, Debug, Eq, PartialEq)]
enum CancelPhase {
    /// Work is running; no request yet.
    Running,
    /// Shutdown requested; drain not yet driven.
    Requested {
        /// Caller time for an explicit request. A primary work report has no
        /// time parameter and leaves this unset until the driver begins drain.
        requested_ns: Option<u64>,
    },
    /// Drain is being driven; workers being awaited.
    Draining {
        /// When drain began.
        drain_start_ns: u64,
    },
    /// Terminal.
    Final(CancelOutcome),
}

/// One cancellation lifecycle with its worker set. Workers are identified by
/// opaque caller-chosen ids (this machine does not own their execution).
pub struct CancellationLifecycle {
    phase: CancelPhase,
    /// The primary work result, retained independently of worker quiescence.
    /// Only Completed and Failed are stored here; cancellation without a
    /// primary result resolves Cancelled once the workers have ended.
    primary_outcome: Option<CancelOutcome>,
    /// Workers still expected to report during drain (sorted for
    /// deterministic iteration).
    outstanding: BTreeSet<String>,
    /// Grace window (ns) after drain start before outstanding workers become
    /// Indeterminate.
    drain_timeout_ns: u64,
}

/// The outcome of one drain step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DrainStep {
    /// The lifecycle is not in a drainable phase.
    NotDraining,
    /// Drain continues; these workers remain outstanding (sorted).
    Pending(Vec<String>),
    /// The lifecycle finalized with this outcome.
    Finalized(CancelOutcome),
}

impl CancellationLifecycle {
    /// A lifecycle tracking the given worker ids, with a drain timeout.
    #[must_use]
    pub fn new(workers: impl IntoIterator<Item = String>, drain_timeout_ns: u64) -> Self {
        Self {
            phase: CancelPhase::Running,
            primary_outcome: None,
            outstanding: workers.into_iter().collect(),
            drain_timeout_ns,
        }
    }

    /// Request cancellation. Idempotent: a second request in Requested/Draining
    /// is absorbed without rewinding the window.
    pub fn request(&mut self, now_ns: u64) {
        if matches!(self.phase, CancelPhase::Running) {
            self.phase = CancelPhase::Requested {
                requested_ns: Some(now_ns),
            };
        }
    }

    /// Whether shutdown has been requested (any phase past Running). A primary
    /// completion or failure also requests drain for any remaining workers.
    #[must_use]
    pub fn is_requested(&self) -> bool {
        !matches!(self.phase, CancelPhase::Running)
    }

    /// Begin the drain (moves Requested → Draining). Completion and failure
    /// reports request this transition too. The grace window starts at caller
    /// time; repeated calls cannot restart it. Calling begin while Running is
    /// a no-op (nothing was requested).
    pub fn begin_drain(&mut self, now_ns: u64) {
        if let CancelPhase::Requested { requested_ns } = self.phase {
            self.phase = CancelPhase::Draining {
                drain_start_ns: requested_ns.map_or(now_ns, |requested| now_ns.max(requested)),
            };
        }
    }

    /// Report one worker cooperatively ended. Unknown ids are rejected (a
    /// worker ending twice, or one never registered, is an error — never a
    /// silent deduction).
    pub fn worker_done(&mut self, worker_id: &str) -> Result<(), CancelError> {
        if !self.outstanding.remove(worker_id) {
            return Err(CancelError::UnknownWorker(worker_id.to_string()));
        }
        if self.outstanding.is_empty()
            && !matches!(self.phase, CancelPhase::Final(_))
            && (self.primary_outcome.is_some()
                || matches!(self.phase, CancelPhase::Draining { .. }))
        {
            self.phase = CancelPhase::Final(self.drained_outcome());
        }
        Ok(())
    }

    /// Report the underlying work completed naturally. Remaining workers must
    /// still drain before Completed is terminal; call `begin_drain` with caller
    /// time to bound that wait. A prior failure cannot be erased by completion.
    pub fn work_completed(&mut self) {
        self.record_primary(CancelOutcome::Completed);
    }

    /// Report the underlying work failed. Its first failure reason remains
    /// available while workers drain, including if the drain times out. A
    /// failure before quiescence supersedes a pending completion report.
    pub fn work_failed(&mut self, reason: impl Into<String>) {
        self.record_primary(CancelOutcome::Failed {
            reason: reason.into(),
        });
    }

    fn record_primary(&mut self, outcome: CancelOutcome) {
        if matches!(self.phase, CancelPhase::Final(_))
            || matches!(self.primary_outcome, Some(CancelOutcome::Failed { .. }))
        {
            return;
        }
        self.primary_outcome = Some(outcome);
        if self.outstanding.is_empty() {
            self.phase = CancelPhase::Final(self.drained_outcome());
        } else if matches!(self.phase, CancelPhase::Running) {
            self.phase = CancelPhase::Requested { requested_ns: None };
        }
    }

    fn drained_outcome(&self) -> CancelOutcome {
        self.primary_outcome
            .clone()
            .unwrap_or(CancelOutcome::Cancelled)
    }

    /// Drive the drain against the current time: outstanding workers within
    /// the window are reported as pending; at the deadline the lifecycle
    /// finalizes Indeterminate with the stranded worker names — the
    /// non-cooperative failure boundary, made explicit.
    pub fn drive(&mut self, now_ns: u64) -> DrainStep {
        match self.phase.clone() {
            CancelPhase::Draining { drain_start_ns } => {
                if self.outstanding.is_empty() {
                    let outcome = self.drained_outcome();
                    self.phase = CancelPhase::Final(outcome.clone());
                    return DrainStep::Finalized(outcome);
                }
                if now_ns >= drain_start_ns
                    && now_ns.saturating_sub(drain_start_ns) >= self.drain_timeout_ns
                {
                    let stranded: Vec<String> = self.outstanding.iter().cloned().collect();
                    let outcome = CancelOutcome::Indeterminate {
                        reason: format!(
                            "{} worker(s) did not drain within the window: {}",
                            stranded.len(),
                            stranded.join(",")
                        ),
                    };
                    self.phase = CancelPhase::Final(outcome.clone());
                    return DrainStep::Finalized(outcome);
                }
                DrainStep::Pending(self.outstanding.iter().cloned().collect())
            }
            CancelPhase::Final(outcome) => DrainStep::Finalized(outcome),
            _ => DrainStep::NotDraining,
        }
    }

    /// The terminal outcome, if finalized.
    #[must_use]
    pub fn outcome(&self) -> Option<&CancelOutcome> {
        match &self.phase {
            CancelPhase::Final(o) => Some(o),
            _ => None,
        }
    }

    /// The primary work result, independent of whether its workers have ended.
    /// A drain timeout reports Indeterminate through `outcome` while retaining
    /// this result and its original failure reason for recovery.
    #[must_use]
    pub fn primary_outcome(&self) -> Option<&CancelOutcome> {
        self.primary_outcome.as_ref()
    }
}

/// Typed cancellation errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CancelError {
    /// A worker id reported done that was never registered (or already done).
    UnknownWorker(String),
}

impl core::fmt::Display for CancelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownWorker(w) => write!(f, "unknown or duplicate worker id: {w}"),
        }
    }
}

impl std::error::Error for CancelError {}

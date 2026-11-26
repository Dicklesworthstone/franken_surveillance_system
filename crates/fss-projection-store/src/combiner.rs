#![forbid(unsafe_code)]
//! Deterministic flat-combining commit coalescer ([`CommitCombiner`]).
//!
//! Concurrent camera/pipeline writer threads submit [`CommitProposal`]s into a bounded queue.
//! A single caller-elected combiner thread drains queued proposals for each round with zero
//! background/detached threads, canonically sorts them by `(sensor_scope, request_digest)`, and
//! executes one atomic group-commit pipeline:
//! 1. 1 `PackStore::append_batch` (1 pack `fsync`)
//! 2. 1 `MerkleEpochLedger::append_batch` (1 epoch `fsync`)
//! 3. 1 `MvccProjectionStore::apply_delta_batch` (atomic MVCC head advance)

mod types;

use std::collections::{BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use fss_core::{BatchId, CanonicalEncoder, ContentDigest, RegionTree};
use fss_runtime::authority::AuthorityCx;

use crate::error::CombinerError;
use crate::schema::PROJECTION_COALESCED_BATCH_DOMAIN;

pub use types::{
    CoalescedCommitReceipt, CommitCombinerConfig, CommitCombinerStats, CommitProposal, CommitSink,
    DEFAULT_MAX_BATCH_PROPOSALS, DEFAULT_MAX_DELTAS_PER_BATCH, DEFAULT_MAX_OBJECTS_PER_BATCH,
    DEFAULT_MAX_PENDING_PROPOSALS, LedgerPackProjectionSink, OwnedPackObject, SinkCommitOutcome,
};

struct PendingSubmission {
    proposal: Mutex<Option<CommitProposal>>,
    cancelled: Option<Arc<AtomicBool>>,
    outcome: Mutex<Option<Result<CoalescedCommitReceipt, CombinerError>>>,
    ready: Condvar,
}

impl PendingSubmission {
    fn new(proposal: CommitProposal, cancelled: Option<Arc<AtomicBool>>) -> Self {
        Self {
            proposal: Mutex::new(Some(proposal)),
            cancelled,
            outcome: Mutex::new(None),
            ready: Condvar::new(),
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire))
    }

    fn complete(&self, res: Result<CoalescedCommitReceipt, CombinerError>) {
        if let Ok(mut guard) = self.outcome.lock() {
            *guard = Some(res);
            self.ready.notify_all();
        }
    }

    fn wait(&self) -> Result<CoalescedCommitReceipt, CombinerError> {
        let mut guard = self
            .outcome
            .lock()
            .map_err(|_| CombinerError::LockPoisoned)?;
        while guard.is_none() {
            guard = self
                .ready
                .wait(guard)
                .map_err(|_| CombinerError::LockPoisoned)?;
        }
        guard.take().unwrap_or(Err(CombinerError::LockPoisoned))
    }
}

struct QueueState {
    combiner_active: bool,
    shutting_down: bool,
    pending: VecDeque<Arc<PendingSubmission>>,
    rounds_executed: u64,
    proposals_committed: u64,
    fsyncs_executed: u64,
}

/// Caller-elected deterministic flat-combining commit coalescer with zero background threads.
pub struct CommitCombiner<S: CommitSink> {
    config: CommitCombinerConfig,
    queue: Mutex<QueueState>,
    queue_idle: Condvar,
    sink: Mutex<S>,
}

impl<S: CommitSink> CommitCombiner<S> {
    /// Creates a new [`CommitCombiner`] owning `sink`.
    pub fn new(sink: S, config: CommitCombinerConfig) -> Result<Self, CombinerError> {
        config.validate()?;
        Ok(Self {
            config,
            queue: Mutex::new(QueueState {
                combiner_active: false,
                shutting_down: false,
                pending: VecDeque::new(),
                rounds_executed: 0,
                proposals_committed: 0,
                fsyncs_executed: 0,
            }),
            queue_idle: Condvar::new(),
            sink: Mutex::new(sink),
        })
    }

    /// Submits `proposal` into the bounded flat-combining collector and waits for its deterministic
    /// [`CoalescedCommitReceipt`].
    pub fn submit(
        &self,
        proposal: CommitProposal,
    ) -> Result<CoalescedCommitReceipt, CombinerError> {
        self.submit_internal(proposal, None)
    }

    /// Submits `proposal` with an explicit cooperative cancellation flag checked before queueing
    /// and before commit execution.
    pub fn submit_with_cancel(
        &self,
        proposal: CommitProposal,
        cancel_flag: Arc<AtomicBool>,
    ) -> Result<CoalescedCommitReceipt, CombinerError> {
        if cancel_flag.load(Ordering::Acquire) {
            return Err(CombinerError::Cancelled);
        }
        self.submit_internal(proposal, Some(cancel_flag))
    }

    /// Submits `proposal` after explicitly verifying that the caller's [`AuthorityCx`] is not
    /// cancelled on `tree`.
    pub fn submit_with_authority(
        &self,
        cx: &AuthorityCx,
        tree: &RegionTree,
        proposal: CommitProposal,
    ) -> Result<CoalescedCommitReceipt, CombinerError> {
        let cancelled = cx
            .is_cancel_requested(tree)
            .map_err(|err| CombinerError::SinkFailure(err.to_string()))?;
        if cancelled {
            return Err(CombinerError::Cancelled);
        }
        self.submit_internal(proposal, None)
    }

    /// Returns cumulative coalescing and fsync amortization telemetry.
    pub fn stats(&self) -> Result<CommitCombinerStats, CombinerError> {
        let state = self.queue.lock().map_err(|_| CombinerError::LockPoisoned)?;
        Ok(build_stats(&state))
    }

    /// Returns the instantaneous count of queued proposals waiting for the next combiner wave.
    pub fn pending_len(&self) -> Result<usize, CombinerError> {
        let state = self.queue.lock().map_err(|_| CombinerError::LockPoisoned)?;
        Ok(state.pending.len())
    }

    /// Transitions the combiner to shutdown, waits cleanly for any active combiner round to drain
    /// all already-admitted proposals, and returns final telemetry with zero orphan threads.
    pub fn shutdown(&self) -> Result<CommitCombinerStats, CombinerError> {
        let mut state = self.queue.lock().map_err(|_| CombinerError::LockPoisoned)?;
        state.shutting_down = true;
        while state.combiner_active || !state.pending.is_empty() {
            state = self
                .queue_idle
                .wait(state)
                .map_err(|_| CombinerError::LockPoisoned)?;
        }
        Ok(build_stats(&state))
    }

    /// Shuts down cleanly and returns ownership of the underlying [`CommitSink`].
    pub fn into_sink(self) -> Result<S, CombinerError> {
        let _ = self.shutdown()?;
        self.sink
            .into_inner()
            .map_err(|_| CombinerError::LockPoisoned)
    }

    fn submit_internal(
        &self,
        proposal: CommitProposal,
        cancel_flag: Option<Arc<AtomicBool>>,
    ) -> Result<CoalescedCommitReceipt, CombinerError> {
        proposal.validate()?;
        if proposal.deltas.len() > self.config.max_deltas_per_batch {
            return Err(CombinerError::InvalidProposal(
                "proposal deltas exceed max_deltas_per_batch",
            ));
        }
        if proposal.objects.len() > self.config.max_objects_per_batch {
            return Err(CombinerError::InvalidProposal(
                "proposal objects exceed max_objects_per_batch",
            ));
        }

        let submission = Arc::new(PendingSubmission::new(proposal, cancel_flag));
        let became_combiner = {
            let mut state = self.queue.lock().map_err(|_| CombinerError::LockPoisoned)?;
            if state.shutting_down {
                return Err(CombinerError::Shutdown);
            }
            if state.pending.len() >= self.config.max_pending_proposals {
                return Err(CombinerError::QueueFull {
                    max_pending: self.config.max_pending_proposals,
                });
            }
            state.pending.push_back(Arc::clone(&submission));
            if !state.combiner_active {
                state.combiner_active = true;
                true
            } else {
                false
            }
        };

        if became_combiner {
            self.run_combiner_loop();
        }
        submission.wait()
    }

    fn run_combiner_loop(&self) {
        loop {
            let drained: Vec<Arc<PendingSubmission>> = {
                let Ok(mut state) = self.queue.lock() else {
                    return;
                };
                if state.pending.is_empty() {
                    state.combiner_active = false;
                    self.queue_idle.notify_all();
                    return;
                }
                let take = state.pending.len().min(self.config.max_batch_proposals);
                state.pending.drain(..take).collect()
            };

            let mut active = Vec::with_capacity(drained.len());
            for entry in drained {
                if entry.is_cancelled() {
                    entry.complete(Err(CombinerError::Cancelled));
                    continue;
                }
                let maybe_prop = entry.proposal.lock().ok().and_then(|mut g| g.take());
                if let Some(prop) = maybe_prop {
                    active.push((entry, prop));
                } else {
                    entry.complete(Err(CombinerError::LockPoisoned));
                }
            }

            if active.is_empty() {
                continue;
            }

            // Deterministic canonical sort independent of thread arrival order.
            active.sort_by(|(_, a), (_, b)| {
                a.sensor_scope
                    .cmp(&b.sensor_scope)
                    .then_with(|| a.request_digest.cmp(&b.request_digest))
                    .then_with(|| a.batch_id_prefix.cmp(&b.batch_id_prefix))
            });

            let mut deferred: Vec<(Arc<PendingSubmission>, CommitProposal)> = Vec::new();
            let mut wave: Vec<(Arc<PendingSubmission>, CommitProposal)> = Vec::new();
            let mut wave_objects_used = BTreeSet::new();
            let mut total_deltas = 0_usize;
            let mut total_objects = 0_usize;

            let round_outcome = {
                let Ok(mut sink) = self.sink.lock() else {
                    for (entry, _) in active {
                        entry.complete(Err(CombinerError::LockPoisoned));
                    }
                    continue;
                };

                for (entry, prop) in active {
                    if let Err(err) = validate_proposal_against_sink(&*sink, &prop) {
                        entry.complete(Err(err));
                        continue;
                    }
                    let collides = prop
                        .deltas
                        .iter()
                        .any(|d| wave_objects_used.contains(&d.object_id));
                    let exceeds_limits = !wave.is_empty()
                        && (total_deltas + prop.deltas.len() > self.config.max_deltas_per_batch
                            || total_objects + prop.objects.len()
                                > self.config.max_objects_per_batch);
                    if collides || exceeds_limits {
                        deferred.push((entry, prop));
                        continue;
                    }
                    for d in &prop.deltas {
                        wave_objects_used.insert(d.object_id.clone());
                    }
                    total_deltas += prop.deltas.len();
                    total_objects += prop.objects.len();
                    wave.push((entry, prop));
                }

                if wave.is_empty() {
                    None
                } else {
                    match derive_coalesced_batch_id(&wave) {
                        Ok(batch_id) => {
                            let mut all_objects = Vec::with_capacity(total_objects);
                            let mut all_deltas = Vec::with_capacity(total_deltas);
                            let mut child_roots = Vec::with_capacity(total_deltas);
                            for (_, prop) in &wave {
                                all_objects.extend(prop.objects.iter().cloned());
                                for d in &prop.deltas {
                                    child_roots.push(d.payload_digest);
                                    all_deltas.push(d.clone());
                                }
                            }
                            Some(sink.commit_coalesced_wave(
                                batch_id,
                                &all_objects,
                                all_deltas,
                                child_roots,
                            ))
                        }
                        Err(err) => {
                            let msg = err.to_string();
                            for (entry, _) in wave.drain(..) {
                                entry.complete(Err(CombinerError::SinkFailure(msg.clone())));
                            }
                            None
                        }
                    }
                }
            };

            if !deferred.is_empty()
                && let Ok(mut state) = self.queue.lock()
            {
                for (entry, prop) in deferred.into_iter().rev() {
                    let stored = match entry.proposal.lock() {
                        Ok(mut slot) => {
                            *slot = Some(prop);
                            true
                        }
                        Err(_) => false,
                    };
                    if stored {
                        state.pending.push_front(entry);
                    } else {
                        entry.complete(Err(CombinerError::LockPoisoned));
                    }
                }
            }

            if let Some(outcome) = round_outcome {
                match outcome {
                    Ok(committed) => {
                        let coalesced_count = wave.len();
                        if let Ok(mut state) = self.queue.lock() {
                            state.rounds_executed = state.rounds_executed.saturating_add(1);
                            state.proposals_committed = state
                                .proposals_committed
                                .saturating_add(coalesced_count as u64);
                            state.fsyncs_executed = state
                                .fsyncs_executed
                                .saturating_add(committed.fsyncs_executed);
                        }
                        for (pos, (entry, _)) in wave.into_iter().enumerate() {
                            entry.complete(Ok(CoalescedCommitReceipt {
                                commit_sequence: committed.commit_sequence,
                                batch_id: committed.batch_id.clone(),
                                authority_root: committed.authority_root,
                                history_root: committed.history_root,
                                batch_digest: committed.batch_digest,
                                coalesced_count,
                                fsyncs_executed: committed.fsyncs_executed,
                                proposal_position: pos,
                                checkpoint_failure: committed.checkpoint_failure.clone(),
                            }));
                        }
                    }
                    Err(CombinerError::CommittedProjectionFailed {
                        receipt,
                        checkpoint_failure,
                        source,
                    }) => {
                        for (entry, _) in wave {
                            entry.complete(Err(CombinerError::CommittedProjectionFailed {
                                receipt: Arc::clone(&receipt),
                                checkpoint_failure: checkpoint_failure.clone(),
                                source: Arc::clone(&source),
                            }));
                        }
                    }
                    Err(err) => {
                        let msg = err.to_string();
                        for (entry, _) in wave {
                            entry.complete(Err(CombinerError::SinkFailure(msg.clone())));
                        }
                    }
                }
            }
        }
    }
}

fn validate_proposal_against_sink<S: CommitSink>(
    sink: &S,
    proposal: &CommitProposal,
) -> Result<(), CombinerError> {
    for delta in &proposal.deltas {
        let committed = sink.current_object_generation(&delta.object_id);
        let valid = match committed {
            None => delta.prior_generation.is_none() && delta.new_generation == 1,
            Some(cur) => {
                delta.prior_generation == Some(cur)
                    && cur.checked_add(1) == Some(delta.new_generation)
            }
        };
        if !valid {
            return Err(CombinerError::GenerationConflict {
                object_id: delta.object_id.clone(),
                committed_generation: committed,
                prior_generation: delta.prior_generation,
                new_generation: delta.new_generation,
            });
        }
    }
    Ok(())
}

fn derive_coalesced_batch_id(
    wave: &[(Arc<PendingSubmission>, CommitProposal)],
) -> Result<BatchId, CombinerError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.canonical.v1");
    encoder.text(PROJECTION_COALESCED_BATCH_DOMAIN);
    encoder.u64(wave.len() as u64);
    for (_, prop) in wave {
        encoder.text(&prop.sensor_scope);
        encoder.digest(prop.request_digest);
        encoder.text(&prop.batch_id_prefix);
    }
    let digest = ContentDigest::sha256(&encoder.finish());
    let text = digest.to_text();
    let hex = text.split_once(':').map_or(text.as_str(), |(_, h)| h);
    let prefix = wave
        .first()
        .map_or("coalesced", |(_, p)| p.batch_id_prefix.as_str());
    let id_str = format!("{prefix}-{}", &hex[..24]);
    BatchId::parse(id_str).map_err(|err| CombinerError::SinkFailure(err.to_string()))
}

fn build_stats(state: &QueueState) -> CommitCombinerStats {
    let coalesced_commits = state
        .proposals_committed
        .saturating_sub(state.rounds_executed);
    let baseline_fsyncs = state.proposals_committed.saturating_mul(2);
    let fsyncs_saved = baseline_fsyncs.saturating_sub(state.fsyncs_executed);
    CommitCombinerStats {
        rounds_executed: state.rounds_executed,
        proposals_committed: state.proposals_committed,
        coalesced_commits,
        fsyncs_executed: state.fsyncs_executed,
        fsyncs_saved,
    }
}

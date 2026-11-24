#![forbid(unsafe_code)]
//! Scaled agent, effect, and learning control-plane indexes backed by segmented checkpointable
//! epoch journals and [`fss_pack::VirtualRootCatalog`].
//!
//! Coordinates three disjoint durable stores under a deployment root:
//! - `<root>/agent/sessions/` — `agent_sessions_idx`, `active_cases_idx`, and active leases
//!   with archival pruning of terminal closed sessions while preserving sealed epoch audit files.
//! - `<root>/effects/` — `effects_obligations_idx` tracking 100,000+ historical completed effects
//!   while guaranteeing 100% of open obligations and `Indeterminate` effects stay O(1)-indexed.
//! - `<root>/agent/publications/` — `learning_proposals_idx` backed by `VirtualRootCatalog`
//!   (zero `max_roots = 128` or `MAX_CAPTURED_LEARNING = 16` wall) with paginated discovery.

pub mod effects;
mod epoch_checkpoint;
mod epoch_codec;
pub mod epoch_journal;
pub mod learning;
mod learning_store;
pub mod sessions;
mod sessions_codec;

use std::cell::Cell;
use std::path::{Path, PathBuf};

use fss_core::{CanonicalDecode, CanonicalEncode, CanonicalEncoder, ContentDigest, TimestampNs};

use crate::error::ProjectionError;

pub use effects::{
    AGENT_EFFECTS_INDEX_DOMAIN, EFFECT_EVENT_RECORD_KIND, EffectJournalEvent, EffectsIndexSummary,
    EffectsObligationsIndex, IndexedEffect, IndexedObligation, is_open_obligation,
    is_terminal_effect,
};
pub use epoch_journal::{
    AGENT_EPOCH_CHECKPOINT_DOMAIN, AGENT_EPOCH_CHECKPOINT_MAGIC, AGENT_EPOCH_FILE_MAGIC,
    AGENT_EPOCH_FORMAT_VERSION, AGENT_EPOCH_HEADER_DOMAIN, AGENT_EPOCH_HEADER_LEN,
    AGENT_EPOCH_RECORD_MAGIC, AGENT_EPOCH_SEAL_DOMAIN, AGENT_EPOCH_SEAL_LEN,
    AGENT_EPOCH_SEAL_MAGIC, AGENT_RECORD_HEADER_LEN, AGENT_RECORD_TRAILER_LEN,
    DEFAULT_AGENT_CHECKPOINT_STRIDE, DEFAULT_MAX_AGENT_EPOCH_BYTES, EpochCheckpointReceipt,
    EpochJournalConfig, EpochJournalRecord, EpochOpenReport, MAX_AGENT_CHECKPOINT_BYTES,
    MAX_AGENT_RECORD_BYTES, MIN_AGENT_EPOCH_BYTES, SegmentedEpochJournal, checkpoint_path,
    epoch_path,
};
pub use learning::{
    AGENT_LEARNING_INDEX_DOMAIN, IndexedLearningProposal, LEARNING_EVENT_RECORD_KIND,
    LearningInventorySummary, LearningJournalEvent, LearningProposalPage, LearningProposalStatus,
    LearningProposalsIndex, LearningPublicationStore,
};
pub use sessions::{
    AGENT_SESSIONS_INDEX_DOMAIN, CaseLifecycle, IndexedCase, IndexedSession,
    SESSION_EVENT_RECORD_KIND, SessionJournalEvent, SessionLifecycle, SessionsIndex,
    SessionsIndexSummary,
};

/// Canonical digest domain for [`AgentStoreIndex::state_digest`].
pub const AGENT_STORE_INDEX_STATE_DOMAIN: &str = "fss.agent_index.store_state.v1";

/// Configuration for opening [`AgentStoreIndex`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AgentStoreIndexConfig {
    /// Epoch size, checkpoint stride, durability, and tail-recovery policy for `agent/sessions/`.
    pub sessions: EpochJournalConfig,
    /// Epoch size, checkpoint stride, durability, and tail-recovery policy for `effects/`.
    pub effects: EpochJournalConfig,
    /// Epoch size, checkpoint stride, durability, and tail-recovery policy for `agent/publications/`.
    pub learning: EpochJournalConfig,
}

impl AgentStoreIndexConfig {
    /// Constructs a uniform configuration sharing one [`EpochJournalConfig`] across all three stores.
    #[must_use]
    pub const fn uniform(journal: EpochJournalConfig) -> Self {
        Self {
            sessions: journal,
            effects: journal,
            learning: journal,
        }
    }
}

/// Combined recovery report returned by [`AgentStoreIndex::open`] or
/// [`AgentStoreIndex::rebuild_from_epochs`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentStoreOpenReport {
    /// Recovery diagnostics for `agent/sessions/`.
    pub sessions: EpochOpenReport,
    /// Recovery diagnostics for `effects/`.
    pub effects: EpochOpenReport,
    /// Recovery diagnostics for `agent/publications/`.
    pub learning: EpochOpenReport,
}

/// Combined `O(1) + O(learning_top_k)` orientation summary across sessions, effects, and learning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentOrientIndexSummary {
    /// Materialized session, lease, and active case counts.
    pub sessions: SessionsIndexSummary,
    /// Materialized effect, open obligation, and indeterminate effect counts.
    pub effects: EffectsIndexSummary,
    /// Bounded learning summary with top-K recent briefs and priced pagination cursor.
    pub learning: LearningInventorySummary,
    /// Composite canonical state digest binding all three materialized indexes.
    pub state_digest: ContentDigest,
}

/// Unified durable facade coordinating segmented epoch journals, verified checkpoints,
/// `VirtualRootCatalog`, and O(1) materialized agent/effect/learning indexes.
pub struct AgentStoreIndex {
    root_dir: PathBuf,
    sessions_journal: SegmentedEpochJournal,
    sessions_index: SessionsIndex,
    effects_journal: SegmentedEpochJournal,
    effects_index: EffectsObligationsIndex,
    learning_store: LearningPublicationStore,
    cached_state_digest: Cell<Option<ContentDigest>>,
}

impl AgentStoreIndex {
    /// Opens or initializes all three scaled agent stores under `root_dir`, loading from the
    /// latest verified checkpoints and replaying only post-checkpoint tails in `O(tail)`.
    pub fn open(
        root_dir: impl AsRef<Path>,
        config: AgentStoreIndexConfig,
    ) -> Result<(Self, AgentStoreOpenReport), ProjectionError> {
        Self::open_inner(root_dir.as_ref().to_path_buf(), config, true)
    }

    /// Rebuilds all three materialized indexes strictly from sealed epoch files (ignoring
    /// checkpoints), proving bit-identical state digests against checkpointed opens.
    pub fn rebuild_from_epochs(
        root_dir: impl AsRef<Path>,
        config: AgentStoreIndexConfig,
    ) -> Result<(Self, AgentStoreOpenReport), ProjectionError> {
        Self::open_inner(root_dir.as_ref().to_path_buf(), config, false)
    }

    fn open_inner(
        root_dir: PathBuf,
        config: AgentStoreIndexConfig,
        use_checkpoints: bool,
    ) -> Result<(Self, AgentStoreOpenReport), ProjectionError> {
        let sessions_dir = root_dir.join("agent").join("sessions");
        let effects_dir = root_dir.join("effects");
        let publications_dir = root_dir.join("agent").join("publications");

        let (sessions_res, effects_res, learning_res) = std::thread::scope(|scope| {
            let s_handle = scope.spawn(move || -> Result<_, ProjectionError> {
                let (journal, report) = if use_checkpoints {
                    SegmentedEpochJournal::open(sessions_dir, config.sessions)?
                } else {
                    SegmentedEpochJournal::open_from_genesis(sessions_dir, config.sessions)?
                };
                let mut index = match &report.checkpoint_payload {
                    Some(bytes) => SessionsIndex::decode_checkpoint_bytes(bytes)?,
                    None => SessionsIndex::new(),
                };
                for rec in &report.tail_records {
                    if rec.kind != SESSION_EVENT_RECORD_KIND {
                        return Err(ProjectionError::CorruptDerivedStore {
                            artifact: "sessions_epoch_journal",
                            detail: format!(
                                "unexpected session record kind {} at seq {}",
                                rec.kind, rec.seq
                            ),
                        });
                    }
                    let ev = SessionJournalEvent::from_canonical_bytes(&rec.body)?;
                    index.apply_event(rec.seq, ev);
                }
                Ok((journal, index, report))
            });
            let e_handle = scope.spawn(move || -> Result<_, ProjectionError> {
                let (journal, report) = if use_checkpoints {
                    SegmentedEpochJournal::open(effects_dir, config.effects)?
                } else {
                    SegmentedEpochJournal::open_from_genesis(effects_dir, config.effects)?
                };
                let mut index = match &report.checkpoint_payload {
                    Some(bytes) => EffectsObligationsIndex::decode_checkpoint_bytes(bytes)?,
                    None => EffectsObligationsIndex::new(),
                };
                for rec in &report.tail_records {
                    if rec.kind != EFFECT_EVENT_RECORD_KIND {
                        return Err(ProjectionError::CorruptDerivedStore {
                            artifact: "effects_epoch_journal",
                            detail: format!(
                                "unexpected effect record kind {} at seq {}",
                                rec.kind, rec.seq
                            ),
                        });
                    }
                    let ev = EffectJournalEvent::from_canonical_bytes(&rec.body)?;
                    index.apply_event(rec.seq, ev);
                }
                Ok((journal, index, report))
            });
            let l_res = if use_checkpoints {
                LearningPublicationStore::open(publications_dir, config.learning)
            } else {
                LearningPublicationStore::open_from_genesis(publications_dir, config.learning)
            };
            let s_res = s_handle.join().map_err(|_| ProjectionError::LockPoisoned);
            let e_res = e_handle.join().map_err(|_| ProjectionError::LockPoisoned);
            (s_res, e_res, l_res)
        });

        let (sessions_journal, sessions_index, sessions_report) = sessions_res??;
        let (effects_journal, effects_index, effects_report) = effects_res??;
        let (learning_store, learning_report) = learning_res?;

        Ok((
            Self {
                root_dir,
                sessions_journal,
                sessions_index,
                effects_journal,
                effects_index,
                learning_store,
                cached_state_digest: Cell::new(None),
            },
            AgentStoreOpenReport {
                sessions: sessions_report,
                effects: effects_report,
                learning: learning_report,
            },
        ))
    }

    /// Appends one session/case event durably into `agent/sessions/` and updates `SessionsIndex`.
    pub fn append_session_event(
        &mut self,
        event: SessionJournalEvent,
    ) -> Result<u64, ProjectionError> {
        let mut seqs = self.append_session_events_batch(&[event])?;
        seqs.pop()
            .ok_or(ProjectionError::ArithmeticOverflow("session_event_seq"))
    }

    /// Group-commits a batch of session/case events into `agent/sessions/`.
    pub fn append_session_events_batch(
        &mut self,
        events: &[SessionJournalEvent],
    ) -> Result<Vec<u64>, ProjectionError> {
        if events.is_empty() {
            return Ok(Vec::new());
        }
        let encoded: Vec<Vec<u8>> = events
            .iter()
            .map(CanonicalEncode::try_canonical_bytes)
            .collect::<Result<_, _>>()?;
        let refs: Vec<(u16, &[u8])> = encoded
            .iter()
            .map(|b| (SESSION_EVENT_RECORD_KIND, b.as_slice()))
            .collect();
        let seqs = self.sessions_journal.append_batch(&refs)?;
        for (ev, &seq) in events.iter().zip(&seqs) {
            self.sessions_index.apply_event(seq, ev.clone());
        }
        self.cached_state_digest.set(None);
        if self.sessions_journal.should_checkpoint() {
            let payload = self.sessions_index.encode_checkpoint_bytes()?;
            let _ = self.sessions_journal.write_checkpoint(&payload)?;
        }
        Ok(seqs)
    }

    /// Appends one effect/obligation event durably into `effects/` and updates `EffectsObligationsIndex`.
    pub fn append_effect_event(
        &mut self,
        event: EffectJournalEvent,
    ) -> Result<u64, ProjectionError> {
        let mut seqs = self.append_effect_events_batch(&[event])?;
        seqs.pop()
            .ok_or(ProjectionError::ArithmeticOverflow("effect_event_seq"))
    }

    /// Group-commits a batch of effect/obligation events into `effects/`.
    pub fn append_effect_events_batch(
        &mut self,
        events: &[EffectJournalEvent],
    ) -> Result<Vec<u64>, ProjectionError> {
        if events.is_empty() {
            return Ok(Vec::new());
        }
        let encoded: Vec<Vec<u8>> = events
            .iter()
            .map(CanonicalEncode::try_canonical_bytes)
            .collect::<Result<_, _>>()?;
        let refs: Vec<(u16, &[u8])> = encoded
            .iter()
            .map(|b| (EFFECT_EVENT_RECORD_KIND, b.as_slice()))
            .collect();
        let seqs = self.effects_journal.append_batch(&refs)?;
        for (ev, &seq) in events.iter().zip(&seqs) {
            self.effects_index.apply_event(seq, ev.clone());
        }
        self.cached_state_digest.set(None);
        if self.effects_journal.should_checkpoint() {
            let payload = self.effects_index.encode_checkpoint_bytes()?;
            let _ = self.effects_journal.write_checkpoint(&payload)?;
        }
        Ok(seqs)
    }

    /// Records one captured learning proposal into `VirtualRootCatalog` + learning epoch journal.
    pub fn record_learning_proposal(
        &mut self,
        proposal: IndexedLearningProposal,
    ) -> Result<u64, ProjectionError> {
        let mut seqs = self.learning_store.record_proposals_batch(&[proposal])?;
        seqs.pop()
            .ok_or(ProjectionError::ArithmeticOverflow("learning_event_seq"))
    }

    /// Group-commits a batch of captured learning proposals into `VirtualRootCatalog` + journal.
    pub fn record_learning_proposals_batch(
        &mut self,
        proposals: &[IndexedLearningProposal],
    ) -> Result<Vec<u64>, ProjectionError> {
        let seqs = self.learning_store.record_proposals_batch(proposals)?;
        self.cached_state_digest.set(None);
        Ok(seqs)
    }

    /// Applies an explicit authority-receipt-backed learning review transition.
    pub fn transition_learning_status(
        &mut self,
        proposal_id: &str,
        status: LearningProposalStatus,
        authority_receipt_digest: ContentDigest,
    ) -> Result<u64, ProjectionError> {
        let seq =
            self.learning_store
                .transition_status(proposal_id, status, authority_receipt_digest)?;
        self.cached_state_digest.set(None);
        Ok(seq)
    }

    /// Emits verified checkpoint snapshots across sessions, effects, and learning stores.
    pub fn checkpoint_all(&mut self) -> Result<(), ProjectionError> {
        let sessions_payload = self.sessions_index.encode_checkpoint_bytes()?;
        let _ = self.sessions_journal.write_checkpoint(&sessions_payload)?;
        let effects_payload = self.effects_index.encode_checkpoint_bytes()?;
        let _ = self.effects_journal.write_checkpoint(&effects_payload)?;
        self.learning_store.checkpoint()?;
        Ok(())
    }

    /// Computes a bounded `O(active + learning_top_k)` orientation summary across all three stores.
    #[must_use]
    pub fn orient_summary(
        &self,
        now: TimestampNs,
        learning_top_k: usize,
    ) -> AgentOrientIndexSummary {
        AgentOrientIndexSummary {
            sessions: self.sessions_index.summary(now),
            effects: self.effects_index.summary(),
            learning: self.learning_store.summary(learning_top_k),
            state_digest: self.state_digest(),
        }
    }

    /// Deterministically paginates all captured learning proposals in ascending `proposal_id` order.
    #[must_use]
    pub fn list_learning_page(&self, cursor: Option<&str>, limit: usize) -> LearningProposalPage {
        self.learning_store.index().list_page(cursor, limit)
    }

    /// Computes the composite SHA-256 state digest binding sessions, effects, and learning indexes.
    #[must_use]
    pub fn state_digest(&self) -> ContentDigest {
        if let Some(cached) = self.cached_state_digest.get() {
            return cached;
        }
        let mut enc = CanonicalEncoder::new();
        enc.text(AGENT_STORE_INDEX_STATE_DOMAIN);
        enc.digest(self.sessions_index.state_digest());
        enc.digest(self.effects_index.state_digest());
        enc.digest(self.learning_store.index().state_digest());
        let digest = ContentDigest::sha256(&enc.finish());
        self.cached_state_digest.set(Some(digest));
        digest
    }

    /// Returns the root directory owning this store.
    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// Returns a reference to the materialized [`SessionsIndex`].
    #[must_use]
    pub const fn sessions(&self) -> &SessionsIndex {
        &self.sessions_index
    }

    /// Returns a reference to the materialized [`EffectsObligationsIndex`].
    #[must_use]
    pub const fn effects(&self) -> &EffectsObligationsIndex {
        &self.effects_index
    }

    /// Returns a reference to the backing [`LearningPublicationStore`].
    #[must_use]
    pub const fn learning(&self) -> &LearningPublicationStore {
        &self.learning_store
    }
}

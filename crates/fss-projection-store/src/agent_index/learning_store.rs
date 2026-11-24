#![forbid(unsafe_code)]
//! Durable learning publication store pairing [`fss_pack::VirtualRootCatalog`] with
//! [`super::epoch_journal::SegmentedEpochJournal`] and [`super::learning::LearningProposalsIndex`].

use std::path::PathBuf;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, TimestampNs,
};
use fss_pack::{CatalogRootEntry, QuotaPolicy, VirtualRootCatalog, VirtualRootRecord};

use super::epoch_journal::{EpochJournalConfig, EpochOpenReport, SegmentedEpochJournal};
use super::learning::{
    IndexedLearningProposal, LEARNING_EVENT_RECORD_KIND, LearningInventorySummary,
    LearningJournalEvent, LearningProposalStatus, LearningProposalsIndex,
};
use crate::error::ProjectionError;

/// Durable publication store pairing [`VirtualRootCatalog`] with [`SegmentedEpochJournal`] and
/// [`LearningProposalsIndex`].
pub struct LearningPublicationStore {
    catalog: VirtualRootCatalog,
    journal: SegmentedEpochJournal,
    index: LearningProposalsIndex,
}

impl LearningPublicationStore {
    /// Opens or initializes the learning store under `publications_dir`, loading from checkpoint.
    pub fn open(
        publications_dir: PathBuf,
        config: EpochJournalConfig,
    ) -> Result<(Self, EpochOpenReport), ProjectionError> {
        Self::open_inner(publications_dir, config, true)
    }

    /// Rebuilds the learning index strictly from sealed epochs while opening [`VirtualRootCatalog`].
    pub fn open_from_genesis(
        publications_dir: PathBuf,
        config: EpochJournalConfig,
    ) -> Result<(Self, EpochOpenReport), ProjectionError> {
        Self::open_inner(publications_dir, config, false)
    }

    fn open_inner(
        publications_dir: PathBuf,
        config: EpochJournalConfig,
        use_checkpoints: bool,
    ) -> Result<(Self, EpochOpenReport), ProjectionError> {
        let roots_dir = publications_dir.join("roots");
        let journal_dir = publications_dir.join("journal");
        let (catalog_res, journal_res) = std::thread::scope(|scope| {
            let cat_handle = scope.spawn(move || {
                VirtualRootCatalog::open(roots_dir, config.durability, QuotaPolicy::default())
            });
            let j_res = if use_checkpoints {
                SegmentedEpochJournal::open(journal_dir, config)
            } else {
                SegmentedEpochJournal::open_from_genesis(journal_dir, config)
            };
            let cat_res = cat_handle.join().map_err(|_| ProjectionError::LockPoisoned);
            (cat_res, j_res)
        });
        let (catalog, _) = catalog_res??;
        let (journal, report) = journal_res?;
        let mut index = match &report.checkpoint_payload {
            Some(bytes) => LearningProposalsIndex::decode_checkpoint_bytes(bytes)?,
            None => LearningProposalsIndex::new(),
        };
        for rec in &report.tail_records {
            if rec.kind != LEARNING_EVENT_RECORD_KIND {
                return Err(ProjectionError::CorruptDerivedStore {
                    artifact: "learning_epoch_journal",
                    detail: format!("unexpected record kind {} at seq {}", rec.kind, rec.seq),
                });
            }
            let ev = LearningJournalEvent::from_canonical_bytes(&rec.body)?;
            index.apply_event(rec.seq, ev);
        }
        Ok((
            Self {
                catalog,
                journal,
                index,
            },
            report,
        ))
    }

    /// Group-commits a batch of newly captured learning proposals into [`VirtualRootCatalog`]
    /// and the segmented epoch journal, automatically checkpointing at `checkpoint_stride`.
    pub fn record_proposals_batch(
        &mut self,
        proposals: &[IndexedLearningProposal],
    ) -> Result<Vec<u64>, ProjectionError> {
        if proposals.is_empty() {
            return Ok(Vec::new());
        }
        let mut root_records = Vec::with_capacity(proposals.len());
        let mut encoded_events = Vec::with_capacity(proposals.len());
        for p in proposals {
            if self.index.get(&p.proposal_id).is_some() {
                return Err(ProjectionError::InvalidRequest(
                    "duplicate learning proposal_id in capture batch",
                ));
            }
            let rec = VirtualRootRecord::new(
                p.root_id.clone(),
                p.publication_root,
                "agent-learning",
                1,
                p.payload_bytes,
                1,
                p.created_at_ns,
                Some(p.experience_digest),
            )?;
            root_records.push(rec);
            encoded_events.push(
                LearningJournalEvent::CaptureProposal(Box::new(p.clone())).try_canonical_bytes()?,
            );
        }
        let _ = self.catalog.publish_roots_batch(&root_records)?;
        let frame_refs: Vec<(u16, &[u8])> = encoded_events
            .iter()
            .map(|b| (LEARNING_EVENT_RECORD_KIND, b.as_slice()))
            .collect();
        let seqs = self.journal.append_batch(&frame_refs)?;
        for (p, &seq) in proposals.iter().zip(&seqs) {
            self.index.apply_event(
                seq,
                LearningJournalEvent::CaptureProposal(Box::new(p.clone())),
            );
        }
        if self.journal.should_checkpoint() {
            self.checkpoint()?;
        }
        Ok(seqs)
    }

    /// Records an explicit authority-receipt-backed review transition (`Promoted` or `Rejected`).
    pub fn transition_status(
        &mut self,
        proposal_id: &str,
        status: LearningProposalStatus,
        authority_receipt_digest: ContentDigest,
    ) -> Result<u64, ProjectionError> {
        let ev = LearningJournalEvent::TransitionStatus {
            proposal_id: proposal_id.to_owned(),
            status,
            authority_receipt_digest,
        };
        let bytes = ev.try_canonical_bytes()?;
        let seq = self.journal.append(LEARNING_EVENT_RECORD_KIND, &bytes)?;
        self.index.apply_event(seq, ev);
        if self.journal.should_checkpoint() {
            self.checkpoint()?;
        }
        Ok(seq)
    }

    /// Compacts both [`VirtualRootCatalog`] (`catalog.snap`) and the learning checkpoint snapshot.
    pub fn checkpoint(&mut self) -> Result<(), ProjectionError> {
        let _ = self.catalog.compact()?;
        let payload = self.index.encode_checkpoint_bytes()?;
        let _ = self.journal.write_checkpoint(&payload)?;
        Ok(())
    }

    /// Returns the materialized [`LearningProposalsIndex`].
    #[must_use]
    pub const fn index(&self) -> &LearningProposalsIndex {
        &self.index
    }

    /// Looks up a virtual root directly in the backing [`VirtualRootCatalog`] in O(1).
    #[must_use]
    pub fn catalog_root(&self, root_id: &str) -> Option<&CatalogRootEntry> {
        self.catalog.get_root(root_id)
    }

    /// Returns the O(K) [`LearningInventorySummary`] including backing catalog root counts.
    #[must_use]
    pub fn summary(&self, top_k: usize) -> LearningInventorySummary {
        self.index.summary(top_k, self.catalog.live_root_count())
    }
}

impl CanonicalEncode for IndexedLearningProposal {
    fn encode_canonical(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.proposal_id);
        enc.text(&self.root_id);
        enc.text(&self.experience_id);
        enc.text(&self.source_episode_id);
        enc.text(&self.session_id);
        enc.text(&self.mission_id);
        enc.text(&self.class_label);
        enc.digest(self.publication_root);
        enc.digest(self.experience_digest);
        enc.digest(self.proposal_digest);
        enc.u64(self.payload_bytes);
        enc.tag(self.status.to_tag());
        match self.transition_receipt_digest {
            Some(d) => {
                enc.bool(true);
                enc.digest(d);
            }
            None => enc.bool(false),
        }
        self.created_at_ns.encode_canonical(enc);
        self.review_after_ns.encode_canonical(enc);
        self.expires_at_ns.encode_canonical(enc);
        enc.u64(self.last_seq);
    }
}

impl CanonicalDecode for IndexedLearningProposal {
    fn decode_canonical(dec: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            proposal_id: dec.text()?.to_owned(),
            root_id: dec.text()?.to_owned(),
            experience_id: dec.text()?.to_owned(),
            source_episode_id: dec.text()?.to_owned(),
            session_id: dec.text()?.to_owned(),
            mission_id: dec.text()?.to_owned(),
            class_label: dec.text()?.to_owned(),
            publication_root: dec.digest()?,
            experience_digest: dec.digest()?,
            proposal_digest: dec.digest()?,
            payload_bytes: dec.u64()?,
            status: LearningProposalStatus::from_tag(dec.tag()?)
                .ok_or(ContractError::InvalidIdentifier)?,
            transition_receipt_digest: if dec.bool()? {
                Some(dec.digest()?)
            } else {
                None
            },
            created_at_ns: TimestampNs::decode_canonical(dec)?,
            review_after_ns: TimestampNs::decode_canonical(dec)?,
            expires_at_ns: TimestampNs::decode_canonical(dec)?,
            last_seq: dec.u64()?,
        })
    }
}

impl CanonicalEncode for LearningJournalEvent {
    fn encode_canonical(&self, enc: &mut CanonicalEncoder) {
        match self {
            Self::CaptureProposal(p) => {
                enc.tag(1);
                p.encode_canonical(enc);
            }
            Self::TransitionStatus {
                proposal_id,
                status,
                authority_receipt_digest,
            } => {
                enc.tag(2);
                enc.text(proposal_id);
                enc.tag(status.to_tag());
                enc.digest(*authority_receipt_digest);
            }
        }
    }
}

impl CanonicalDecode for LearningJournalEvent {
    fn decode_canonical(dec: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match dec.tag()? {
            1 => Ok(Self::CaptureProposal(Box::new(
                IndexedLearningProposal::decode_canonical(dec)?,
            ))),
            2 => Ok(Self::TransitionStatus {
                proposal_id: dec.text()?.to_owned(),
                status: LearningProposalStatus::from_tag(dec.tag()?)
                    .ok_or(ContractError::InvalidIdentifier)?,
                authority_receipt_digest: dec.digest()?,
            }),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

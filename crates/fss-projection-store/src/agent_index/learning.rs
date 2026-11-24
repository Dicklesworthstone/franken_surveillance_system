#![forbid(unsafe_code)]
//! Indexed learning proposal state (`learning_proposals_idx`) with O(1) aggregate counts,
//! O(K) top-K recent briefs, and deterministic cursor-paginated discovery.
//!
//! Paired with [`LearningPublicationStore`] (`fss_pack::VirtualRootCatalog`), eliminating both
//! the `MAX_CAPTURED_LEARNING = 16` wall and the `STANDARD_MAX_ROOTS = 128` root wall.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    DigestAlgorithm, Sha256Hasher, TimestampNs,
};

use crate::error::ProjectionError;

pub use super::learning_store::LearningPublicationStore;

/// Canonical digest domain for [`LearningProposalsIndex::state_digest`].
pub const AGENT_LEARNING_INDEX_DOMAIN: &str = "fss.agent_index.learning_state.v1";

/// Record kind tag for serialized [`LearningJournalEvent`] frames inside `agent/publications/`.
pub const LEARNING_EVENT_RECORD_KIND: u16 = 0x0301;

/// Advisory review status of a captured learning proposal.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LearningProposalStatus {
    /// Captured single-episode advisory history awaiting independent review.
    PendingReview,
    /// Explicitly promoted via a separate evidence-gated authority receipt.
    Promoted,
    /// Explicitly rejected via review authority receipt.
    Rejected,
}

impl LearningProposalStatus {
    pub(super) const fn to_tag(self) -> u8 {
        match self {
            Self::PendingReview => 1,
            Self::Promoted => 2,
            Self::Rejected => 3,
        }
    }

    pub(super) const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::PendingReview),
            2 => Some(Self::Promoted),
            3 => Some(Self::Rejected),
            _ => None,
        }
    }
}

/// Indexed metadata for one immutable captured learning proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedLearningProposal {
    /// Stable immutable proposal identifier (`learning:<hex>`).
    pub proposal_id: String,
    /// Stable virtual root identifier registered in `VirtualRootCatalog`.
    pub root_id: String,
    /// Immutable experience capsule identifier.
    pub experience_id: String,
    /// Originating execution episode identifier.
    pub source_episode_id: String,
    /// Owning session identifier.
    pub session_id: String,
    /// Owning mission identifier.
    pub mission_id: String,
    /// Advisory learning class label (e.g., `"procedure_candidate"`).
    pub class_label: String,
    /// Content digest of the complete learning publication root.
    pub publication_root: ContentDigest,
    /// Content digest of the canonical experience payload.
    pub experience_digest: ContentDigest,
    /// Content digest of the canonical learning proposal payload.
    pub proposal_digest: ContentDigest,
    /// Logical byte size of the complete captured closure for hydration pricing.
    pub payload_bytes: u64,
    /// Current advisory lifecycle status (`PendingReview` upon capture).
    pub status: LearningProposalStatus,
    /// Optional explicit authority receipt digest witnessing a `Promoted`/`Rejected` transition.
    pub transition_receipt_digest: Option<ContentDigest>,
    /// Evidence clock capture timestamp.
    pub created_at_ns: TimestampNs,
    /// Immutable review deadline on the evidence clock.
    pub review_after_ns: TimestampNs,
    /// Immutable expiry deadline on the evidence clock.
    pub expires_at_ns: TimestampNs,
    /// Journal sequence number of the last update.
    pub last_seq: u64,
}

/// Canonical event persisted into the `agent/publications/` learning epoch journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LearningJournalEvent {
    /// Captures a new immutable learning proposal (always initialized `PendingReview`).
    CaptureProposal(Box<IndexedLearningProposal>),
    /// Records an authority-receipt-backed review disposition (`Promoted` or `Rejected`).
    TransitionStatus {
        /// Target proposal identifier.
        proposal_id: String,
        /// Target review status.
        status: LearningProposalStatus,
        /// Explicit authority receipt digest witnessing the review disposition.
        authority_receipt_digest: ContentDigest,
    },
}

/// Bounded O(K) summary of captured learning proposals with priced pagination metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LearningInventorySummary {
    /// Total captured learning proposals retained in the catalog.
    pub total_captured: u64,
    /// Proposals currently in `PendingReview`.
    pub pending_review: u64,
    /// Proposals explicitly promoted via authority receipt.
    pub promoted: u64,
    /// Proposals explicitly rejected via review receipt.
    pub rejected: u64,
    /// Bounded top-K most recent proposal briefs (newest-first, tie-broken by `proposal_id`).
    pub top_recent: Vec<IndexedLearningProposal>,
    /// Number of captured proposals omitted from `top_recent` (discoverable via pagination).
    pub omitted_count: u64,
    /// Cursor to resume full deterministic pagination when `omitted_count > 0`.
    pub next_cursor: Option<String>,
    /// Cumulative logical payload bytes across all captured proposals (for hydration pricing).
    pub total_payload_bytes: u64,
    /// Live root count tracked in the backing `VirtualRootCatalog`.
    pub catalog_live_roots: u64,
}

/// One deterministically ordered page of [`IndexedLearningProposal`] entries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LearningProposalPage {
    /// Entries returned for this page in ascending `proposal_id` order.
    pub entries: Vec<IndexedLearningProposal>,
    /// Total captured proposals across the full inventory.
    pub total_captured: u64,
    /// Opaque pagination cursor (`proposal_id` of the last returned entry) when `has_more` is true.
    pub next_cursor: Option<String>,
    /// True if additional entries follow beyond this page.
    pub has_more: bool,
}

/// Pure materialized state of `learning_proposals_idx`, separate from on-disk I/O handles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LearningProposalsIndex {
    entries: BTreeMap<String, IndexedLearningProposal>,
    recent_order: BTreeSet<(TimestampNs, String)>,
    pending_review: u64,
    promoted: u64,
    rejected: u64,
    total_payload_bytes: u64,
    last_seq: u64,
}

impl Default for LearningProposalsIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl LearningProposalsIndex {
    /// Creates an empty [`LearningProposalsIndex`] at sequence `0`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            recent_order: BTreeSet::new(),
            pending_review: 0,
            promoted: 0,
            rejected: 0,
            total_payload_bytes: 0,
            last_seq: 0,
        }
    }

    /// Applies one committed [`LearningJournalEvent`] at `seq`.
    pub fn apply_event(&mut self, seq: u64, event: LearningJournalEvent) {
        self.last_seq = seq;
        match event {
            LearningJournalEvent::CaptureProposal(mut proposal) => {
                proposal.last_seq = seq;
                proposal.status = LearningProposalStatus::PendingReview;
                proposal.transition_receipt_digest = None;
                if self.entries.contains_key(&proposal.proposal_id) {
                    return;
                }
                self.pending_review = self.pending_review.saturating_add(1);
                self.total_payload_bytes = self
                    .total_payload_bytes
                    .saturating_add(proposal.payload_bytes);
                self.recent_order
                    .insert((proposal.created_at_ns, proposal.proposal_id.clone()));
                self.entries.insert(proposal.proposal_id.clone(), *proposal);
            }
            LearningJournalEvent::TransitionStatus {
                proposal_id,
                status,
                authority_receipt_digest,
            } => {
                let prev_status = {
                    let Some(entry) = self.entries.get_mut(&proposal_id) else {
                        return;
                    };
                    if entry.status == status {
                        return;
                    }
                    let prev = entry.status;
                    entry.status = status;
                    entry.transition_receipt_digest = Some(authority_receipt_digest);
                    entry.last_seq = seq;
                    prev
                };
                self.adjust_status_counter(prev_status, false);
                self.adjust_status_counter(status, true);
            }
        }
    }

    /// Looks up a captured learning proposal by stable `proposal_id` in O(log N).
    #[must_use]
    pub fn get(&self, proposal_id: &str) -> Option<&IndexedLearningProposal> {
        self.entries.get(proposal_id)
    }

    /// Returns total captured proposals in O(1).
    #[must_use]
    pub fn total_captured(&self) -> u64 {
        self.entries.len() as u64
    }

    /// Builds an O(K) summary returning `top_k` most recent briefs + priced pagination cursor.
    #[must_use]
    pub fn summary(&self, top_k: usize, catalog_live_roots: u64) -> LearningInventorySummary {
        let total_captured = self.entries.len() as u64;
        let top_recent: Vec<IndexedLearningProposal> = self
            .recent_order
            .iter()
            .rev()
            .take(top_k)
            .filter_map(|(_, id)| self.entries.get(id).cloned())
            .collect();
        let omitted_count = total_captured.saturating_sub(top_recent.len() as u64);
        let next_cursor = if omitted_count > 0 {
            self.entries.keys().next().cloned()
        } else {
            None
        };
        LearningInventorySummary {
            total_captured,
            pending_review: self.pending_review,
            promoted: self.promoted,
            rejected: self.rejected,
            top_recent,
            omitted_count,
            next_cursor,
            total_payload_bytes: self.total_payload_bytes,
            catalog_live_roots,
        }
    }

    /// Lists captured learning proposals deterministically in ascending `proposal_id` order.
    #[must_use]
    pub fn list_page(&self, cursor: Option<&str>, limit: usize) -> LearningProposalPage {
        let total_captured = self.entries.len() as u64;
        if limit == 0 {
            return LearningProposalPage {
                entries: Vec::new(),
                total_captured,
                next_cursor: None,
                has_more: !self.entries.is_empty(),
            };
        }
        let mut entries = Vec::with_capacity(limit.min(self.entries.len()));
        let mut has_more = false;
        let iter: Box<dyn Iterator<Item = (&String, &IndexedLearningProposal)> + '_> = match cursor
        {
            Some(c) => Box::new(
                self.entries
                    .range::<str, _>((Bound::Excluded(c), Bound::Unbounded)),
            ),
            None => Box::new(self.entries.iter()),
        };
        for (_, item) in iter {
            if entries.len() == limit {
                has_more = true;
                break;
            }
            entries.push(item.clone());
        }
        let next_cursor = if has_more {
            entries.last().map(|e| e.proposal_id.clone())
        } else {
            None
        };
        LearningProposalPage {
            entries,
            total_captured,
            next_cursor,
            has_more,
        }
    }

    /// Serializes this index into compact interned canonical checkpoint payload bytes.
    pub fn encode_checkpoint_bytes(&self) -> Result<Vec<u8>, ProjectionError> {
        let mut dict_ids: BTreeMap<&str, u32> = BTreeMap::new();
        let mut dict: Vec<&str> = Vec::new();
        let mut row_refs = Vec::with_capacity(self.entries.len());
        for p in self.entries.values() {
            let sid = intern_str(&p.session_id, &mut dict_ids, &mut dict)?;
            let mid = intern_str(&p.mission_id, &mut dict_ids, &mut dict)?;
            let cid = intern_str(&p.class_label, &mut dict_ids, &mut dict)?;
            row_refs.push((p, sid, mid, cid));
        }

        let mut enc = CanonicalEncoder::new();
        enc.text(AGENT_LEARNING_INDEX_DOMAIN);
        enc.u64(self.last_seq);
        enc.u64(self.pending_review);
        enc.u64(self.promoted);
        enc.u64(self.rejected);
        enc.u64(self.total_payload_bytes);
        enc.u32(dict.len() as u32);
        for s in &dict {
            enc.text(s);
        }
        enc.u64(row_refs.len() as u64);
        for (p, sid, mid, cid) in row_refs {
            enc.text(&p.proposal_id);
            enc.text(&p.root_id);
            enc.text(&p.experience_id);
            enc.text(&p.source_episode_id);
            enc.u32(sid);
            enc.u32(mid);
            enc.u32(cid);
            enc.digest(p.publication_root);
            enc.digest(p.experience_digest);
            enc.digest(p.proposal_digest);
            enc.u64(p.payload_bytes);
            enc.tag(p.status.to_tag());
            if let Some(d) = p.transition_receipt_digest {
                enc.bool(true);
                enc.digest(d);
            } else {
                enc.bool(false);
            }
            p.created_at_ns.encode_canonical(&mut enc);
            p.review_after_ns.encode_canonical(&mut enc);
            p.expires_at_ns.encode_canonical(&mut enc);
            enc.u64(p.last_seq);
        }
        Ok(enc.finish_checked()?)
    }

    /// Decodes a verified [`LearningProposalsIndex`] from canonical checkpoint payload bytes.
    pub fn decode_checkpoint_bytes(bytes: &[u8]) -> Result<Self, ProjectionError> {
        let mut dec = CanonicalDecoder::new(bytes);
        if dec.text()? != AGENT_LEARNING_INDEX_DOMAIN {
            return Err(ProjectionError::CorruptDerivedStore {
                artifact: "learning_index_checkpoint",
                detail: "invalid learning checkpoint domain".to_owned(),
            });
        }
        let last_seq = dec.u64()?;
        let pending_review = dec.u64()?;
        let promoted = dec.u64()?;
        let rejected = dec.u64()?;
        let total_payload_bytes = dec.u64()?;
        let dict_len = dec.u32()? as usize;
        let mut dict = Vec::with_capacity(dict_len);
        for _ in 0..dict_len {
            dict.push(dec.text()?.to_owned());
        }
        let lookup = |idx: u32| -> Result<String, ProjectionError> {
            dict.get(idx as usize)
                .cloned()
                .ok_or(ProjectionError::CorruptDerivedStore {
                    artifact: "learning_index_checkpoint",
                    detail: "invalid string dictionary index".to_owned(),
                })
        };
        let count = usize::try_from(dec.u64()?)
            .map_err(|_| ProjectionError::ArithmeticOverflow("learning_entries_len"))?;
        let mut entries = BTreeMap::new();
        let mut recent_order = BTreeSet::new();
        for _ in 0..count {
            let proposal_id = dec.text()?.to_owned();
            let root_id = dec.text()?.to_owned();
            let experience_id = dec.text()?.to_owned();
            let source_episode_id = dec.text()?.to_owned();
            let (session_id, mission_id, class_label) = (
                lookup(dec.u32()?)?,
                lookup(dec.u32()?)?,
                lookup(dec.u32()?)?,
            );
            let (publication_root, experience_digest, proposal_digest) =
                (dec.digest()?, dec.digest()?, dec.digest()?);
            let payload_bytes = dec.u64()?;
            let status = LearningProposalStatus::from_tag(dec.tag()?).ok_or(
                ProjectionError::CorruptDerivedStore {
                    artifact: "learning_index_checkpoint",
                    detail: "invalid proposal status tag".to_owned(),
                },
            )?;
            let transition_receipt_digest = if dec.bool()? {
                Some(dec.digest()?)
            } else {
                None
            };
            let created_at_ns = TimestampNs::decode_canonical(&mut dec)?;
            let review_after_ns = TimestampNs::decode_canonical(&mut dec)?;
            let expires_at_ns = TimestampNs::decode_canonical(&mut dec)?;
            let row_seq = dec.u64()?;
            recent_order.insert((created_at_ns, proposal_id.clone()));
            entries.insert(
                proposal_id.clone(),
                IndexedLearningProposal {
                    proposal_id,
                    root_id,
                    experience_id,
                    source_episode_id,
                    session_id,
                    mission_id,
                    class_label,
                    publication_root,
                    experience_digest,
                    proposal_digest,
                    payload_bytes,
                    status,
                    transition_receipt_digest,
                    created_at_ns,
                    review_after_ns,
                    expires_at_ns,
                    last_seq: row_seq,
                },
            );
        }
        dec.ensure_finished()?;
        Ok(Self {
            entries,
            recent_order,
            pending_review,
            promoted,
            rejected,
            total_payload_bytes,
            last_seq,
        })
    }

    /// Computes the deterministic SHA-256 state digest under [`AGENT_LEARNING_INDEX_DOMAIN`]
    /// via zero-allocation streaming hashing.
    #[must_use]
    pub fn state_digest(&self) -> ContentDigest {
        let mut h = Sha256Hasher::new();
        h.update(AGENT_LEARNING_INDEX_DOMAIN.as_bytes());
        h.update(&self.last_seq.to_be_bytes());
        h.update(&self.pending_review.to_be_bytes());
        h.update(&self.promoted.to_be_bytes());
        h.update(&self.rejected.to_be_bytes());
        h.update(&self.total_payload_bytes.to_be_bytes());
        h.update(&(self.entries.len() as u64).to_be_bytes());
        for p in self.entries.values() {
            h.update(&(p.proposal_id.len() as u32).to_be_bytes());
            h.update(p.proposal_id.as_bytes());
            h.update(&p.publication_root.bytes());
            h.update(&p.experience_digest.bytes());
            h.update(&p.proposal_digest.bytes());
            h.update(&[p.status.to_tag()]);
            if let Some(d) = p.transition_receipt_digest {
                h.update(&[1]);
                h.update(&d.bytes());
            } else {
                h.update(&[0]);
            }
            h.update(&p.created_at_ns.0.to_be_bytes());
            h.update(&p.last_seq.to_be_bytes());
        }
        ContentDigest::new(DigestAlgorithm::Sha256, h.finalize().unwrap_or_default())
    }

    fn adjust_status_counter(&mut self, status: LearningProposalStatus, inc: bool) {
        let slot = match status {
            LearningProposalStatus::PendingReview => &mut self.pending_review,
            LearningProposalStatus::Promoted => &mut self.promoted,
            LearningProposalStatus::Rejected => &mut self.rejected,
        };
        *slot = if inc {
            slot.saturating_add(1)
        } else {
            slot.saturating_sub(1)
        };
    }
}

fn intern_str<'a>(
    s: &'a str,
    ids: &mut BTreeMap<&'a str, u32>,
    dict: &mut Vec<&'a str>,
) -> Result<u32, ProjectionError> {
    if let Some(&id) = ids.get(s) {
        return Ok(id);
    }
    let id = u32::try_from(dict.len())
        .map_err(|_| ProjectionError::ArithmeticOverflow("learning_dict_len"))?;
    dict.push(s);
    ids.insert(s, id);
    Ok(id)
}

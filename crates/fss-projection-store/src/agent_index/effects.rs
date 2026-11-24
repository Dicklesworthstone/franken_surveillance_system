#![forbid(unsafe_code)]
//! Materialized `effects_obligations_idx` guaranteeing 100% retention and O(1) visibility of
//! every open obligation (`Pending` / `Indeterminate`) and every `Indeterminate` effect across
//! 100,000+ historical completed effects, checkpoints, and cold restarts.

use std::collections::BTreeMap;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, DigestAlgorithm, EffectState, ObligationState, Sha256Hasher, TimestampNs,
};

use crate::error::ProjectionError;

/// Canonical digest domain for [`EffectsObligationsIndex::state_digest`].
pub const AGENT_EFFECTS_INDEX_DOMAIN: &str = "fss.agent_index.effects_state.v1";

/// Record kind tag for serialized [`EffectJournalEvent`] frames inside `effects/`.
pub const EFFECT_EVENT_RECORD_KIND: u16 = 0x0201;

const fn effect_state_tag(state: EffectState) -> u8 {
    match state {
        EffectState::Prepared => 1,
        EffectState::Committed => 2,
        EffectState::AdapterAccepted => 3,
        EffectState::Observed => 4,
        EffectState::Verified => 5,
        EffectState::Cancelled => 6,
        EffectState::Failed => 7,
        EffectState::Indeterminate => 8,
    }
}

const fn effect_state_from_tag(tag: u8) -> Option<EffectState> {
    match tag {
        1 => Some(EffectState::Prepared),
        2 => Some(EffectState::Committed),
        3 => Some(EffectState::AdapterAccepted),
        4 => Some(EffectState::Observed),
        5 => Some(EffectState::Verified),
        6 => Some(EffectState::Cancelled),
        7 => Some(EffectState::Failed),
        8 => Some(EffectState::Indeterminate),
        _ => None,
    }
}

/// Returns `true` iff `state` is a known terminal effect outcome (`Verified`, `Failed`, `Cancelled`).
#[must_use]
pub const fn is_terminal_effect(state: EffectState) -> bool {
    matches!(
        state,
        EffectState::Verified | EffectState::Failed | EffectState::Cancelled
    )
}

const fn obligation_state_tag(state: ObligationState) -> u8 {
    match state {
        ObligationState::Pending => 1,
        ObligationState::Verified => 2,
        ObligationState::Failed => 3,
        ObligationState::Indeterminate => 4,
        ObligationState::Cancelled => 5,
    }
}

const fn obligation_state_from_tag(tag: u8) -> Option<ObligationState> {
    match tag {
        1 => Some(ObligationState::Pending),
        2 => Some(ObligationState::Verified),
        3 => Some(ObligationState::Failed),
        4 => Some(ObligationState::Indeterminate),
        5 => Some(ObligationState::Cancelled),
        _ => None,
    }
}

/// Returns `true` iff `state` is an open obligation (`Pending` or `Indeterminate`).
#[must_use]
pub const fn is_open_obligation(state: ObligationState) -> bool {
    matches!(
        state,
        ObligationState::Pending | ObligationState::Indeterminate
    )
}

/// Materialized effect row stored in `effects_obligations_idx`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedEffect {
    /// Stable effect operation identifier.
    pub operation_id: String,
    /// Effect class name (e.g., `"alert.webhook"`).
    pub effect_class: String,
    /// Current canonical effect lifecycle state.
    pub state: EffectState,
    /// Content digest of the durable receipt witnessing `state`.
    pub receipt_digest: ContentDigest,
    /// Evidence clock timestamp of the latest transition.
    pub updated_at_ns: TimestampNs,
    /// Monotonic journal sequence number of the latest transition.
    pub last_seq: u64,
}

impl CanonicalEncode for IndexedEffect {
    fn encode_canonical(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.operation_id);
        enc.text(&self.effect_class);
        enc.tag(effect_state_tag(self.state));
        enc.digest(self.receipt_digest);
        self.updated_at_ns.encode_canonical(enc);
        enc.u64(self.last_seq);
    }
}

impl CanonicalDecode for IndexedEffect {
    fn decode_canonical(dec: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            operation_id: dec.text()?.to_owned(),
            effect_class: dec.text()?.to_owned(),
            state: effect_state_from_tag(dec.tag()?).ok_or(ContractError::InvalidIdentifier)?,
            receipt_digest: dec.digest()?,
            updated_at_ns: TimestampNs::decode_canonical(dec)?,
            last_seq: dec.u64()?,
        })
    }
}

/// Materialized durable obligation row stored in `effects_obligations_idx`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedObligation {
    /// Stable obligation identifier.
    pub obligation_id: String,
    /// Owning effect operation identifier.
    pub operation_id: String,
    /// Current canonical obligation state.
    pub state: ObligationState,
    /// Optional proof digest witnessing a terminal state.
    pub proof_digest: Option<ContentDigest>,
    /// Evidence clock timestamp of the latest update.
    pub updated_at_ns: TimestampNs,
    /// Monotonic journal sequence number of the latest update.
    pub last_seq: u64,
}

impl CanonicalEncode for IndexedObligation {
    fn encode_canonical(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.obligation_id);
        enc.text(&self.operation_id);
        enc.tag(obligation_state_tag(self.state));
        match self.proof_digest {
            Some(d) => {
                enc.bool(true);
                enc.digest(d);
            }
            None => enc.bool(false),
        }
        self.updated_at_ns.encode_canonical(enc);
        enc.u64(self.last_seq);
    }
}

impl CanonicalDecode for IndexedObligation {
    fn decode_canonical(dec: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            obligation_id: dec.text()?.to_owned(),
            operation_id: dec.text()?.to_owned(),
            state: obligation_state_from_tag(dec.tag()?).ok_or(ContractError::InvalidIdentifier)?,
            proof_digest: if dec.bool()? {
                Some(dec.digest()?)
            } else {
                None
            },
            updated_at_ns: TimestampNs::decode_canonical(dec)?,
            last_seq: dec.u64()?,
        })
    }
}

/// Canonical event persisted into the `effects/` segmented epoch journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectJournalEvent {
    /// Creates or transitions a tracked effect operation.
    UpsertEffect(IndexedEffect),
    /// Creates or transitions a tracked durable obligation.
    UpsertObligation(IndexedObligation),
}

impl CanonicalEncode for EffectJournalEvent {
    fn encode_canonical(&self, enc: &mut CanonicalEncoder) {
        match self {
            Self::UpsertEffect(effect) => {
                enc.tag(1);
                effect.encode_canonical(enc);
            }
            Self::UpsertObligation(obligation) => {
                enc.tag(2);
                obligation.encode_canonical(enc);
            }
        }
    }
}

impl CanonicalDecode for EffectJournalEvent {
    fn decode_canonical(dec: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match dec.tag()? {
            1 => Ok(Self::UpsertEffect(IndexedEffect::decode_canonical(dec)?)),
            2 => Ok(Self::UpsertObligation(IndexedObligation::decode_canonical(
                dec,
            )?)),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// O(1) orient summary of effect and obligation states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectsIndexSummary {
    /// Cumulative effects ever recorded across all sealed and active epochs.
    pub total_effects_ever: u64,
    /// Completed terminal effects (`Verified + Failed + Cancelled`) archived out of hot maps.
    pub completed_effects_count: u64,
    /// Currently non-terminal effects (`Prepared`, `Committed`, `AdapterAccepted`, `Observed`, `Indeterminate`).
    pub non_terminal_effects: u64,
    /// Currently `Indeterminate` effects (100% retained, never truncated).
    pub indeterminate_effects: u64,
    /// Currently open obligations (`Pending` or `Indeterminate`; 100% retained, never truncated).
    pub open_obligations: u64,
    /// Terminal closed obligations archived out of the hot map.
    pub closed_obligations_count: u64,
    /// Highest applied journal sequence number.
    pub last_seq: u64,
}

/// Materialized `effects_obligations_idx` preserving 100% of open obligations and `Indeterminate`
/// effects while keeping terminal historical effects compact and epoch-verifiable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectsObligationsIndex {
    non_terminal_effects: BTreeMap<String, IndexedEffect>,
    indeterminate_effects: BTreeMap<String, IndexedEffect>,
    open_obligations: BTreeMap<String, IndexedObligation>,
    total_effects_ever: u64,
    completed_effects_count: u64,
    verified_effects: u64,
    failed_effects: u64,
    cancelled_effects: u64,
    closed_obligations_count: u64,
    archived_effects_digest: ContentDigest,
    last_seq: u64,
}

impl Default for EffectsObligationsIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl EffectsObligationsIndex {
    /// Creates an empty [`EffectsObligationsIndex`] at sequence `0`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            non_terminal_effects: BTreeMap::new(),
            indeterminate_effects: BTreeMap::new(),
            open_obligations: BTreeMap::new(),
            total_effects_ever: 0,
            completed_effects_count: 0,
            verified_effects: 0,
            failed_effects: 0,
            cancelled_effects: 0,
            closed_obligations_count: 0,
            archived_effects_digest: ContentDigest::sha256(b"fss.agent_index.effects_archive.v1"),
            last_seq: 0,
        }
    }

    /// Applies one committed [`EffectJournalEvent`] at `seq`, keeping 100% of open obligations
    /// and `Indeterminate` effects permanently resident in their dedicated hot maps.
    pub fn apply_event(&mut self, seq: u64, event: EffectJournalEvent) {
        self.last_seq = seq;
        match event {
            EffectJournalEvent::UpsertEffect(mut effect) => {
                effect.last_seq = seq;
                if !self.non_terminal_effects.contains_key(&effect.operation_id) {
                    self.total_effects_ever = self.total_effects_ever.saturating_add(1);
                }
                if is_terminal_effect(effect.state) {
                    self.non_terminal_effects.remove(&effect.operation_id);
                    self.indeterminate_effects.remove(&effect.operation_id);
                    self.completed_effects_count = self.completed_effects_count.saturating_add(1);
                    match effect.state {
                        EffectState::Verified => {
                            self.verified_effects = self.verified_effects.saturating_add(1);
                        }
                        EffectState::Failed => {
                            self.failed_effects = self.failed_effects.saturating_add(1);
                        }
                        EffectState::Cancelled => {
                            self.cancelled_effects = self.cancelled_effects.saturating_add(1);
                        }
                        _ => {}
                    }
                    self.fold_archived_effect(&effect, seq);
                } else {
                    if effect.state == EffectState::Indeterminate {
                        self.indeterminate_effects
                            .insert(effect.operation_id.clone(), effect.clone());
                    } else {
                        self.indeterminate_effects.remove(&effect.operation_id);
                    }
                    self.non_terminal_effects
                        .insert(effect.operation_id.clone(), effect);
                }
            }
            EffectJournalEvent::UpsertObligation(mut obligation) => {
                obligation.last_seq = seq;
                if is_open_obligation(obligation.state) {
                    self.open_obligations
                        .insert(obligation.obligation_id.clone(), obligation);
                } else {
                    self.open_obligations.remove(&obligation.obligation_id);
                    self.closed_obligations_count = self.closed_obligations_count.saturating_add(1);
                    self.fold_archived_obligation(&obligation, seq);
                }
            }
        }
    }

    /// Looks up a non-terminal effect (including any `Indeterminate` effect) in O(log active).
    #[must_use]
    pub fn get_non_terminal_effect(&self, operation_id: &str) -> Option<&IndexedEffect> {
        self.non_terminal_effects.get(operation_id)
    }

    /// Looks up an `Indeterminate` effect in O(log active).
    #[must_use]
    pub fn get_indeterminate_effect(&self, operation_id: &str) -> Option<&IndexedEffect> {
        self.indeterminate_effects.get(operation_id)
    }

    /// Looks up an open obligation (`Pending` or `Indeterminate`) in O(log active).
    #[must_use]
    pub fn get_open_obligation(&self, obligation_id: &str) -> Option<&IndexedObligation> {
        self.open_obligations.get(obligation_id)
    }

    /// Returns the complete untruncated map of all `Indeterminate` effects.
    #[must_use]
    pub const fn indeterminate_effects(&self) -> &BTreeMap<String, IndexedEffect> {
        &self.indeterminate_effects
    }

    /// Returns the complete untruncated map of all open obligations (`Pending` | `Indeterminate`).
    #[must_use]
    pub const fn open_obligations(&self) -> &BTreeMap<String, IndexedObligation> {
        &self.open_obligations
    }

    /// Returns the complete untruncated map of all non-terminal effects.
    #[must_use]
    pub const fn non_terminal_effects(&self) -> &BTreeMap<String, IndexedEffect> {
        &self.non_terminal_effects
    }

    /// Returns an `O(1)` summary of effect and obligation counts.
    #[must_use]
    pub fn summary(&self) -> EffectsIndexSummary {
        EffectsIndexSummary {
            total_effects_ever: self.total_effects_ever,
            completed_effects_count: self.completed_effects_count,
            non_terminal_effects: self.non_terminal_effects.len() as u64,
            indeterminate_effects: self.indeterminate_effects.len() as u64,
            open_obligations: self.open_obligations.len() as u64,
            closed_obligations_count: self.closed_obligations_count,
            last_seq: self.last_seq,
        }
    }

    /// Serializes this index into canonical checkpoint payload bytes.
    pub fn encode_checkpoint_bytes(&self) -> Result<Vec<u8>, ProjectionError> {
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        Ok(enc.finish_checked()?)
    }

    /// Decodes a verified [`EffectsObligationsIndex`] from canonical checkpoint payload bytes.
    pub fn decode_checkpoint_bytes(bytes: &[u8]) -> Result<Self, ProjectionError> {
        let mut dec = CanonicalDecoder::new(bytes);
        if dec.text()? != AGENT_EFFECTS_INDEX_DOMAIN {
            return Err(ProjectionError::CorruptDerivedStore {
                artifact: "effects_index_checkpoint",
                detail: "invalid effects checkpoint domain".to_owned(),
            });
        }
        let last_seq = dec.u64()?;
        let total_effects_ever = dec.u64()?;
        let completed_effects_count = dec.u64()?;
        let verified_effects = dec.u64()?;
        let failed_effects = dec.u64()?;
        let cancelled_effects = dec.u64()?;
        let closed_obligations_count = dec.u64()?;
        let archived_effects_digest = dec.digest()?;

        let eff_len = usize::try_from(dec.u64()?)
            .map_err(|_| ProjectionError::ArithmeticOverflow("non_terminal_effects_len"))?;
        let mut non_terminal_effects = BTreeMap::new();
        let mut indeterminate_effects = BTreeMap::new();
        for _ in 0..eff_len {
            let eff = IndexedEffect::decode_canonical(&mut dec)?;
            if eff.state == EffectState::Indeterminate {
                indeterminate_effects.insert(eff.operation_id.clone(), eff.clone());
            }
            non_terminal_effects.insert(eff.operation_id.clone(), eff);
        }
        let ob_len = usize::try_from(dec.u64()?)
            .map_err(|_| ProjectionError::ArithmeticOverflow("open_obligations_len"))?;
        let mut open_obligations = BTreeMap::new();
        for _ in 0..ob_len {
            let ob = IndexedObligation::decode_canonical(&mut dec)?;
            open_obligations.insert(ob.obligation_id.clone(), ob);
        }
        dec.ensure_finished()?;
        Ok(Self {
            non_terminal_effects,
            indeterminate_effects,
            open_obligations,
            total_effects_ever,
            completed_effects_count,
            verified_effects,
            failed_effects,
            cancelled_effects,
            closed_obligations_count,
            archived_effects_digest,
            last_seq,
        })
    }

    /// Computes the deterministic SHA-256 state digest under [`AGENT_EFFECTS_INDEX_DOMAIN`].
    #[must_use]
    pub fn state_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        ContentDigest::sha256(&enc.finish())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(AGENT_EFFECTS_INDEX_DOMAIN);
        enc.u64(self.last_seq);
        enc.u64(self.total_effects_ever);
        enc.u64(self.completed_effects_count);
        enc.u64(self.verified_effects);
        enc.u64(self.failed_effects);
        enc.u64(self.cancelled_effects);
        enc.u64(self.closed_obligations_count);
        enc.digest(self.archived_effects_digest);
        enc.u64(self.non_terminal_effects.len() as u64);
        for eff in self.non_terminal_effects.values() {
            eff.encode_canonical(enc);
        }
        enc.u64(self.open_obligations.len() as u64);
        for ob in self.open_obligations.values() {
            ob.encode_canonical(enc);
        }
    }

    fn fold_archived_effect(&mut self, effect: &IndexedEffect, seq: u64) {
        let mut h = Sha256Hasher::new();
        h.update(b"effect-archive:");
        h.update(&self.archived_effects_digest.bytes());
        h.update(&seq.to_be_bytes());
        h.update(&[effect_state_tag(effect.state)]);
        h.update(&effect.receipt_digest.bytes());
        h.update(&effect.updated_at_ns.0.to_be_bytes());
        h.update(effect.operation_id.as_bytes());
        self.archived_effects_digest =
            ContentDigest::new(DigestAlgorithm::Sha256, h.finalize().unwrap_or_default());
    }

    fn fold_archived_obligation(&mut self, obligation: &IndexedObligation, seq: u64) {
        let mut h = Sha256Hasher::new();
        h.update(b"obligation-archive:");
        h.update(&self.archived_effects_digest.bytes());
        h.update(&seq.to_be_bytes());
        h.update(&[obligation_state_tag(obligation.state)]);
        if let Some(d) = obligation.proof_digest {
            h.update(&d.bytes());
        }
        h.update(&obligation.updated_at_ns.0.to_be_bytes());
        h.update(obligation.obligation_id.as_bytes());
        self.archived_effects_digest =
            ContentDigest::new(DigestAlgorithm::Sha256, h.finalize().unwrap_or_default());
    }
}

//! Canonical runtime preparation and transition log. Reopening is evidence-only:
//! live process identities, lease registries and dispatch permits are never restored.

use std::collections::BTreeMap;
use std::sync::Arc;

use fss_core::effect::{EffectAuthority, PreparedEffect as CanonicalPreparedEffect};
use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContextAuthority, EffectJournal, EffectJournalTransition, EffectState, ObligationState,
    OperationId, RegionId, RegionTree, RuntimeGrant, TimestampNs,
};

use super::{
    EffectCoordError, EffectCoordinator, MAX_EFFECT_RESOURCE_LEN, MAX_RETAINED_EFFECTS,
    PREPARATION_DIGEST_DOMAIN, PreparationBinding, PreparedEffect, Reconciliation,
    indeterminate_note, journal_error, registered_effect_class,
};
use crate::authority::AuthorityCx;
use crate::effect_journal::{
    EffectJournalPin, EffectJournalStore, EffectPersistenceError, MAX_EFFECT_HISTORY_RECORDS,
    MAX_EFFECT_RECORD_BYTES,
};
use crate::grant::GrantSet;

const RECORD_DOMAIN: &str = "fss.runtime_effect_record.v1";
// Canonical transition metadata is bounded independently of full preparations.
const MAX_TRANSITION_BYTES: usize = 16 * 1024;

/// Pure immutable recipe; decoding it grants no runtime authority.
#[derive(Clone, Debug)]
pub(super) struct RetainedPreparation {
    pub(super) prepared: CanonicalPreparedEffect,
    pub(super) context: ContextAuthority,
    pub(super) owner: RegionId,
    pub(super) resource: String,
    pub(super) fence: u64,
    pub(super) prepare_grant: RuntimeGrant,
    pub(super) commit_grant: RuntimeGrant,
}

impl RetainedPreparation {
    pub(super) fn from_binding(binding: &PreparationBinding) -> Self {
        Self {
            prepared: binding.prepared.clone(),
            context: binding.context.clone(),
            owner: binding.owner.clone(),
            resource: binding.resource.clone(),
            fence: binding.fence,
            prepare_grant: binding.prepare_grant,
            commit_grant: binding.commit_grant,
        }
    }

    fn validate(&self) -> Result<(), EffectPersistenceError> {
        let invalid = EffectPersistenceError::InvalidHistory;
        self.context.validate().map_err(|_| invalid("authority"))?;
        let grants = GrantSet::from_authority(&self.context)
            .map_err(|_| invalid("unregistered authority grant"))?;
        grants
            .require_grant(self.prepare_grant)
            .map_err(|_| invalid("missing preparation authority"))?;
        if registered_effect_class(self.prepare_grant, self.commit_grant)
            != Some(self.prepared.intent.effect_class.as_str())
            || self.resource.trim().is_empty()
            || self.resource.len() > MAX_EFFECT_RESOURCE_LEN
            || self.fence == 0
            || self.context.cancellation_reason.is_some()
            || self
                .context
                .deadline
                .is_some_and(|end| self.prepared.prepared_at >= end)
            || self.prepared.obligation_id.as_str()
                != format!("obligation:{}:terminal", self.prepared.intent.operation_id)
        {
            return Err(invalid("preparation binding"));
        }
        Ok(())
    }
}

impl CanonicalEncode for RetainedPreparation {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.prepared.encode_canonical(encoder);
        self.context.encode_canonical(encoder);
        self.owner.encode_canonical(encoder);
        encoder.text(&self.resource);
        encoder.u64(self.fence);
        encoder.text(self.prepare_grant.as_str());
        encoder.text(self.commit_grant.as_str());
    }
}

impl CanonicalDecode for RetainedPreparation {
    fn decode_canonical(
        decoder: &mut CanonicalDecoder<'_>,
    ) -> Result<Self, fss_core::ContractError> {
        Ok(Self {
            prepared: CanonicalPreparedEffect::decode_canonical(decoder)?,
            context: ContextAuthority::decode_canonical(decoder)?,
            owner: RegionId::decode_canonical(decoder)?,
            resource: decoder.text()?.to_owned(),
            fence: decoder.u64()?,
            prepare_grant: RuntimeGrant::from_id(decoder.text()?)?,
            commit_grant: RuntimeGrant::from_id(decoder.text()?)?,
        })
    }
}

#[derive(Debug)]
pub(super) enum JournalEvent {
    Prepare(Box<RetainedPreparation>),
    Transition(EffectJournalTransition),
}

impl JournalEvent {
    pub(super) fn reconciliation(
        journal: &EffectJournal,
        operation: &OperationId,
        action: Reconciliation<'_>,
        now: TimestampNs,
    ) -> Result<Self, EffectCoordError> {
        let operation_id = operation.clone();
        Ok(Self::Transition(match action {
            Reconciliation::Observed(proof) => EffectJournalTransition::Transition {
                operation_id,
                next: EffectState::Observed,
                now,
                result_digest: Some(proof),
                error_code: None,
            },
            Reconciliation::Verified(proof_digest) => EffectJournalTransition::ReconcileVerified {
                operation_id,
                proof_digest,
                now,
            },
            Reconciliation::Failed {
                proof: proof_digest,
                reason,
            } => EffectJournalTransition::ReconcileFailed {
                operation_id,
                proof_digest,
                now,
                reason: reason.to_owned(),
            },
            Reconciliation::Indeterminate(note) => EffectJournalTransition::Transition {
                operation_id,
                next: EffectState::Indeterminate,
                now,
                result_digest: None,
                error_code: Some(note.to_owned()),
            },
            Reconciliation::Cancelled(cancel_request_evidence) => EffectJournalTransition::Cancel {
                operation_id,
                now,
                cancel_request_evidence,
                proof_digest: journal
                    .cancellation_proof(operation, cancel_request_evidence)
                    .map_err(|error| journal_error(operation, error))?,
                reason: None,
            },
        }))
    }

    fn encode(
        &self,
        before: ContentDigest,
        after: ContentDigest,
    ) -> Result<Vec<u8>, EffectPersistenceError> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(RECORD_DOMAIN);
        encoder.digest(before);
        encoder.digest(after);
        match self {
            Self::Prepare(record) => {
                encoder.u8(1);
                record.encode_canonical(&mut encoder);
            }
            Self::Transition(record) => {
                encoder.u8(2);
                record.encode_canonical(&mut encoder);
            }
        }
        let bytes = encoder
            .finish_checked()
            .map_err(|_| EffectPersistenceError::InvalidHistory("encoding"))?;
        if bytes.len() > MAX_EFFECT_RECORD_BYTES {
            return Err(EffectPersistenceError::Capacity);
        }
        if matches!(self, Self::Transition(_)) && bytes.len() > MAX_TRANSITION_BYTES {
            return Err(EffectPersistenceError::Capacity);
        }
        Ok(bytes)
    }
}

impl EffectCoordinator {
    /// Attach an empty exclusive journal before preparing any effects. Existing
    /// history must use [`Self::recover`]; it can never be silently overwritten.
    pub fn with_journal(
        store: Box<dyn EffectJournalStore>,
    ) -> Result<Self, EffectPersistenceError> {
        if store.head().is_some() || !store.records().is_empty() {
            return Err(EffectPersistenceError::InvalidHistory(
                "new owner requires an empty journal",
            ));
        }
        let mut owner = Self::new();
        owner.persistence = Some(store);
        Ok(owner)
    }

    /// Replay complete retained history at or after an independent minimum pin.
    /// No grant, lease, dispatch permit or live authority is reconstructed. This
    /// owner admits only adoption and evidence reconciliation, including cancellation
    /// of preparations that never committed. It never admits a new dispatch.
    pub fn recover(
        store: Box<dyn EffectJournalStore>,
        minimum: EffectJournalPin,
    ) -> Result<Self, EffectPersistenceError> {
        if minimum.sequence == 0 || minimum.root.is_laboratory() || !store.contains(minimum) {
            return Err(EffectPersistenceError::PinMismatch);
        }
        let head = store.head().ok_or(EffectPersistenceError::PinMismatch)?;
        if head.sequence < minimum.sequence
            || head.sequence as u128 != store.records().len() as u128
            || store.records().len() > MAX_EFFECT_HISTORY_RECORDS
            || !store.contains(head)
        {
            return Err(EffectPersistenceError::InvalidHistory(
                "incomplete journal chain",
            ));
        }
        let mut journal = EffectJournal::new();
        let mut unbound = BTreeMap::new();
        for bytes in store.records() {
            replay_record(bytes, &mut journal, &mut unbound)?;
        }
        let mut owner = Self::new();
        owner.journal = journal;
        owner.unbound = unbound;
        owner.reconciliation_only = true;
        owner.durable_head = Some(head);
        owner.persistence = Some(store);
        Ok(owner)
    }

    /// Last acknowledged durable head. After an ambiguous append a newer record
    /// may exist; save this pin and cold-reopen instead of retrying the effect.
    #[must_use]
    pub const fn durable_pin(&self) -> Option<EffectJournalPin> {
        self.durable_head
    }

    /// Whether a storage ambiguity requires a fresh verified open.
    #[must_use]
    pub const fn persistence_needs_recovery(&self) -> bool {
        self.persistence_poisoned
    }

    /// Recovered owners never acquire dispatch authority from saved records.
    #[must_use]
    pub const fn is_reconciliation_only(&self) -> bool {
        self.reconciliation_only
    }

    /// The original digest to compare with an independently retained preparation.
    /// This is inspectable metadata, not approval or proof of provider outcome.
    #[must_use]
    pub fn retained_preparation_digest(&self, operation: &OperationId) -> Option<ContentDigest> {
        self.bindings
            .get(operation)
            .map(|binding| binding.canonical_digest(PREPARATION_DIGEST_DOMAIN))
            .or_else(|| {
                self.unbound
                    .get(operation)
                    .map(|record| record.canonical_digest(PREPARATION_DIGEST_DOMAIN))
            })
    }

    /// Attach one recovered obligation to a fresh explicitly supplied owner.
    /// Original principal, operation, region, anchor, generation, privacy and
    /// retention must match; grants, deadline and budgets may only narrow. The
    /// exact original preparation digest is required. Returned handles are inert:
    /// even a recovered `Prepared` operation can only cancel or reconcile.
    pub fn adopt_recovered(
        &mut self,
        authority: &AuthorityCx,
        tree: &mut RegionTree,
        operation: &OperationId,
        expected_preparation: ContentDigest,
        now: TimestampNs,
    ) -> Result<PreparedEffect, EffectCoordError> {
        self.require_persistence_ready(operation)?;
        if !self.reconciliation_only {
            return Err(persistence_error(
                operation,
                EffectPersistenceError::InvalidHistory("owner is not a recovery"),
            ));
        }
        if let Some(binding) = self.bindings.get(operation) {
            let handle = self.handle(binding.clone());
            self.require_scope(&handle, authority, tree)?;
            if handle.digest() != expected_preparation {
                return Err(EffectCoordError::ApprovalMismatch {
                    operation: operation.to_string(),
                    expected: handle.digest(),
                    presented: expected_preparation,
                });
            }
            return Ok(handle);
        }
        let record = self
            .unbound
            .get(operation)
            .ok_or_else(|| journal_error(operation, fss_core::ContractError::NotFound))?;
        let expected = record.canonical_digest(PREPARATION_DIGEST_DOMAIN);
        if expected != expected_preparation {
            return Err(EffectCoordError::ApprovalMismatch {
                operation: operation.to_string(),
                expected,
                presented: expected_preparation,
            });
        }
        authority
            .require_active(tree)
            .map_err(|error| EffectCoordError::Region {
                operation: operation.to_string(),
                detail: error.to_string(),
            })?;
        let node = tree
            .get(authority.region())
            .map_err(|error| EffectCoordError::Region {
                operation: operation.to_string(),
                detail: error.to_string(),
            })?;
        let current = &node.authority;
        if authority.region() != &record.owner
            || current.operation_id != record.context.operation_id
            || current.privacy_scope != record.context.privacy_scope
            || current.retention_scope != record.context.retention_scope
            || current.verify_narrowing_of(&record.context).is_err()
        {
            return Err(EffectCoordError::WrongAuthority {
                operation: operation.to_string(),
            });
        }
        let receipt = self
            .journal
            .operation(operation)
            .ok_or_else(|| journal_error(operation, fss_core::ContractError::NotFound))?;
        if now < receipt.updated_at {
            return Err(journal_error(
                operation,
                fss_core::ContractError::InvertedTimeInterval,
            ));
        }
        if tree.iter().any(|node| {
            node.obligations
                .values()
                .any(|obligation| &obligation.operation_id == operation)
        }) {
            return Err(EffectCoordError::DuplicateOperation {
                operation: operation.to_string(),
            });
        }
        let obligation = self
            .journal
            .obligations()
            .find(|obligation| &obligation.operation_id == operation)
            .ok_or_else(|| journal_error(operation, fss_core::ContractError::NotFound))?
            .clone();
        let note = if obligation.state == ObligationState::Indeterminate {
            Some(indeterminate_note(&self.journal, operation)?.to_owned())
        } else {
            None
        };
        let binding = Arc::new(PreparationBinding {
            prepared: record.prepared.clone(),
            authority: authority.binding().clone(),
            lease_registry: None,
            context: record.context.clone(),
            owner: record.owner.clone(),
            resource: record.resource.clone(),
            fence: record.fence,
            prepare_grant: record.prepare_grant,
            commit_grant: record.commit_grant,
        });
        authority
            .register_obligation(tree, obligation.clone())
            .map_err(|error| EffectCoordError::Region {
                operation: operation.to_string(),
                detail: error.to_string(),
            })?;
        if let Some(note) = note {
            authority
                .resolve_obligation(
                    tree,
                    &obligation.obligation_id,
                    crate::obligation::ObligationTerminal::Indeterminate,
                    obligation.proof_digest,
                    Some(&note),
                )
                .map_err(|error| EffectCoordError::Region {
                    operation: operation.to_string(),
                    detail: error.to_string(),
                })?;
        }
        self.unbound.remove(operation);
        self.bindings.insert(operation.clone(), binding.clone());
        Ok(self.handle(binding))
    }

    pub(super) fn require_persistence_ready(
        &self,
        operation: &OperationId,
    ) -> Result<(), EffectCoordError> {
        if self.persistence_poisoned {
            return Err(persistence_error(
                operation,
                EffectPersistenceError::Poisoned,
            ));
        }
        Ok(())
    }

    pub(super) fn persist_event(
        &mut self,
        operation: &OperationId,
        event: JournalEvent,
        candidate: &EffectJournal,
    ) -> Result<(), EffectCoordError> {
        self.require_persistence_ready(operation)?;
        let Some(store) = self.persistence.as_mut() else {
            return Ok(());
        };
        if candidate == &self.journal {
            return Ok(());
        }
        let before = self.journal.journal_root();
        let bytes = event
            .encode(before, candidate.journal_root())
            .map_err(|error| persistence_error(operation, error))?;
        // Preserve room for *every* outstanding operation, so a later prepare
        // cannot spend another operation's cancellation or reconciliation path.
        // This preflight does not promise that a future filesystem write succeeds.
        let remaining: usize = candidate
            .operations()
            .map(|receipt| match receipt.state {
                EffectState::Prepared | EffectState::Observed => 1,
                EffectState::Verified | EffectState::Failed | EffectState::Cancelled => 0,
                _ => 2,
            })
            .sum();
        let needed_records = remaining + 1;
        if store.records().len().saturating_add(needed_records) > MAX_EFFECT_HISTORY_RECORDS {
            return Err(persistence_error(
                operation,
                EffectPersistenceError::Capacity,
            ));
        }
        store
            .reserve_capacity(needed_records, bytes.len().max(MAX_TRANSITION_BYTES))
            .map_err(|error| persistence_error(operation, error))?;
        match store.append(self.durable_head, &bytes) {
            Ok(pin)
                if pin.sequence == self.durable_head.map_or(1, |old| old.sequence + 1)
                    && store.head() == Some(pin)
                    && store.contains(pin)
                    && pin.sequence as u128 == store.records().len() as u128
                    && store.records().last() == Some(&bytes) =>
            {
                self.durable_head = Some(pin);
                Ok(())
            }
            Ok(_) => {
                self.persistence_poisoned = true;
                Err(persistence_error(
                    operation,
                    EffectPersistenceError::InvalidHistory("append receipt"),
                ))
            }
            Err(error) => {
                self.persistence_poisoned = true;
                Err(persistence_error(operation, error))
            }
        }
    }
}

fn persistence_error(operation: &OperationId, error: EffectPersistenceError) -> EffectCoordError {
    EffectCoordError::Persistence {
        operation: operation.to_string(),
        error,
    }
}

fn replay_record(
    bytes: &[u8],
    journal: &mut EffectJournal,
    bindings: &mut BTreeMap<OperationId, RetainedPreparation>,
) -> Result<(), EffectPersistenceError> {
    let invalid = EffectPersistenceError::InvalidHistory;
    if bytes.len() > MAX_EFFECT_RECORD_BYTES {
        return Err(EffectPersistenceError::Capacity);
    }
    let mut decoder = CanonicalDecoder::new(bytes);
    if decoder.text().map_err(|_| invalid("record domain"))? != RECORD_DOMAIN {
        return Err(invalid("record version"));
    }
    let before = decoder
        .digest()
        .map_err(|_| invalid("previous state root"))?;
    let after = decoder.digest().map_err(|_| invalid("next state root"))?;
    if before != journal.journal_root() || before == after {
        return Err(invalid("state root chain"));
    }
    let event = match decoder.u8().map_err(|_| invalid("record kind"))? {
        1 => {
            let record = RetainedPreparation::decode_canonical(&mut decoder)
                .map_err(|_| invalid("preparation decode"))?;
            record.validate()?;
            let operation = record.prepared.intent.operation_id.clone();
            if bindings.len() >= MAX_RETAINED_EFFECTS {
                return Err(EffectPersistenceError::Capacity);
            }
            if bindings.contains_key(&operation) {
                return Err(invalid("duplicate preparation"));
            }
            let effect_authority = EffectAuthority::new(
                record.context.principal.clone(),
                record.commit_grant.as_str(),
                Some(record.fence),
            )
            .map_err(|_| invalid("effect authority"))?;
            journal
                .prepare_effect(record.prepared.clone(), effect_authority)
                .map_err(|_| invalid("preparation semantics"))?;
            bindings.insert(operation, record.clone());
            JournalEvent::Prepare(Box::new(record))
        }
        2 => {
            let transition = EffectJournalTransition::decode_canonical(&mut decoder)
                .map_err(|_| invalid("transition decode"))?;
            match &transition {
                EffectJournalTransition::Prepare { .. } => {
                    return Err(invalid("unbound preparation"));
                }
                EffectJournalTransition::Transition {
                    operation_id,
                    next,
                    now,
                    ..
                } => {
                    if !matches!(
                        next,
                        EffectState::Committed
                            | EffectState::AdapterAccepted
                            | EffectState::Observed
                            | EffectState::Indeterminate
                    ) {
                        return Err(invalid("unbound terminal transition"));
                    }
                    if *next == EffectState::Committed {
                        let binding = bindings
                            .get(operation_id)
                            .ok_or_else(|| invalid("unknown commit"))?;
                        if !binding
                            .context
                            .has_capability(binding.commit_grant.as_str())
                            || binding.context.deadline.is_some_and(|end| *now >= end)
                        {
                            return Err(invalid("commit authority"));
                        }
                    }
                }
                _ => {}
            }
            journal
                .apply_transition(transition.clone())
                .map_err(|_| invalid("transition semantics"))?;
            JournalEvent::Transition(transition)
        }
        _ => return Err(invalid("unknown record kind")),
    };
    decoder
        .ensure_finished()
        .map_err(|_| invalid("trailing bytes"))?;
    if event.encode(before, after)? != bytes {
        return Err(invalid("noncanonical record"));
    }
    if journal.journal_root() != after {
        return Err(invalid("replayed state root"));
    }
    Ok(())
}

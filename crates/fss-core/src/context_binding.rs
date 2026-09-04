//! Exact descriptor-bound bindings for context-pack expansion slots.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::hydration::{HydrationError, HydrationLevel, SemanticHandle};
use crate::{
    BudgetVector, CanonicalEncode, CanonicalEncoder, ContentDigest, ContractBasis, ContractError,
    LedgerAnchor, RecoveryClass, SemanticCompressionReceipt, SemanticContextPack,
};

const MAX_BINDINGS: usize = 4_096;
const MAX_TEXT_BYTES: usize = 4 * 1_024;

/// Stable failures raised while binding an expansion slot to an exact descriptor revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContextBindingError {
    /// Shared semantic contract failure.
    Contract(ContractError),
    /// Semantic-hydration descriptor failure.
    Hydration(HydrationError),
    /// A pack or receipt expansion slot has no exact descriptor binding.
    MissingSlot(String),
    /// A binding names a slot absent from both the pack and compression receipt.
    UnexpectedSlot(String),
    /// A slot is bound more than once.
    DuplicateSlot(String),
}

impl ContextBindingError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Contract(error) => error.code(),
            Self::Hydration(error) => error.code(),
            Self::MissingSlot(_) => "context_expansion_binding_missing",
            Self::UnexpectedSlot(_) => "context_expansion_binding_unexpected",
            Self::DuplicateSlot(_) => "context_expansion_binding_duplicate",
        }
    }

    /// Returns deterministic recovery guidance.
    #[must_use]
    pub const fn recovery(&self) -> RecoveryClass {
        match self {
            Self::Contract(ContractError::StaleAnchor)
            | Self::Contract(ContractError::GenerationConflict)
            | Self::Contract(ContractError::DigestMismatch)
            | Self::MissingSlot(_)
            | Self::UnexpectedSlot(_) => RecoveryClass::RebaseRequired,
            Self::Hydration(error) => error.recovery(),
            Self::Contract(_) | Self::DuplicateSlot(_) => RecoveryClass::NeverUnchanged,
        }
    }
}

impl fmt::Display for ContextBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSlot(slot) | Self::UnexpectedSlot(slot) | Self::DuplicateSlot(slot) => {
                write!(formatter, "{}:{slot}", self.code())
            }
            Self::Contract(_) | Self::Hydration(_) => formatter.write_str(self.code()),
        }
    }
}

impl std::error::Error for ContextBindingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::Hydration(error) => Some(error),
            Self::MissingSlot(_) | Self::UnexpectedSlot(_) | Self::DuplicateSlot(_) => None,
        }
    }
}

impl From<ContractError> for ContextBindingError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}

impl From<HydrationError> for ContextBindingError {
    fn from(value: HydrationError) -> Self {
        Self::Hydration(value)
    }
}

/// Immutable reference to one exact semantic-handle descriptor and hydration level.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticHandleReference {
    /// Stable immutable-subject handle identity.
    pub handle_id: String,
    /// Exact descriptor revision digest.
    pub descriptor_digest: ContentDigest,
    /// Exact immutable subject digest.
    pub subject_digest: ContentDigest,
    /// Exact semantic-contract basis digest.
    pub contract_basis_digest: ContentDigest,
    /// Authority anchor at which the descriptor revision was published.
    pub descriptor_anchor: LedgerAnchor,
    /// Exact hydration level intended by this reference.
    pub hydration_level: HydrationLevel,
    /// Digest of the descriptor's complete hydration ladder policy.
    pub ladder_policy_digest: ContentDigest,
    /// Digest of this complete reference body.
    pub reference_digest: ContentDigest,
}

impl SemanticHandleReference {
    /// Publishes a reference from a verified exact descriptor revision.
    pub fn publish(
        handle: &SemanticHandle,
        hydration_level: HydrationLevel,
    ) -> Result<Self, ContextBindingError> {
        handle.verify()?;
        if !handle.levels.contains(&hydration_level) {
            return Err(HydrationError::LevelUnavailable.into());
        }
        let mut reference = Self {
            handle_id: handle.handle_id.clone(),
            descriptor_digest: handle.descriptor_digest,
            subject_digest: handle.subject_digest,
            contract_basis_digest: handle.contract_basis.basis_digest(),
            descriptor_anchor: handle.anchor.clone(),
            hydration_level,
            ladder_policy_digest: handle.ladder_policy_digest(),
            reference_digest: ContentDigest::sha256(b"unpublished-semantic-handle-reference"),
        };
        reference.validate_body()?;
        reference.reference_digest = reference.computed_digest();
        Ok(reference)
    }

    /// Recomputes the exact reference digest.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        self.encode_body(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Verifies the self-contained reference identity.
    pub fn verify(&self) -> Result<(), ContextBindingError> {
        self.validate_body()?;
        if self.reference_digest != self.computed_digest() {
            return Err(ContractError::DigestMismatch.into());
        }
        Ok(())
    }

    /// Verifies this reference against the exact descriptor revision it names.
    pub fn validate_for(&self, handle: &SemanticHandle) -> Result<(), ContextBindingError> {
        self.verify()?;
        handle.verify()?;
        if self.handle_id != handle.handle_id
            || self.descriptor_digest != handle.descriptor_digest
            || self.subject_digest != handle.subject_digest
            || self.contract_basis_digest != handle.contract_basis.basis_digest()
            || self.descriptor_anchor != handle.anchor
            || self.ladder_policy_digest != handle.ladder_policy_digest()
        {
            return Err(ContractError::DigestMismatch.into());
        }
        if !handle.levels.contains(&self.hydration_level) {
            return Err(HydrationError::LevelUnavailable.into());
        }
        Ok(())
    }

    fn validate_body(&self) -> Result<(), ContextBindingError> {
        if !valid_text(&self.handle_id) {
            return Err(ContractError::InvalidIdentifier.into());
        }
        Ok(())
    }

    fn encode_body(&self, encoder: &mut CanonicalEncoder) {
        encoder.text("fss.semantic_handle_reference.v1");
        encoder.text(&self.handle_id);
        encoder.digest(self.descriptor_digest);
        encoder.digest(self.subject_digest);
        encoder.digest(self.contract_basis_digest);
        self.descriptor_anchor.encode_canonical(encoder);
        self.hydration_level.encode_canonical(encoder);
        encoder.digest(self.ladder_policy_digest);
    }
}

impl CanonicalEncode for SemanticHandleReference {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.encode_body(encoder);
        encoder.digest(self.reference_digest);
    }
}

/// One expansion slot bound to an exact descriptor revision and descriptor-owned price.
#[derive(Clone, Debug, PartialEq)]
pub struct ContextExpansionBinding {
    /// Stable slot emitted by a v1 context pack or compression receipt.
    pub slot_id: String,
    /// Exact immutable semantic-handle reference.
    pub reference: SemanticHandleReference,
    /// Bounded explanation of what expanding the slot provides.
    pub purpose: String,
    /// Exact conservative descriptor price for the referenced level.
    pub estimated_cost: BudgetVector,
    /// Digest of this complete binding body.
    pub binding_digest: ContentDigest,
}

impl ContextExpansionBinding {
    /// Publishes one binding while deriving price and identity from the exact descriptor.
    pub fn publish(
        slot_id: impl Into<String>,
        handle: &SemanticHandle,
        hydration_level: HydrationLevel,
        purpose: impl Into<String>,
    ) -> Result<Self, ContextBindingError> {
        let reference = SemanticHandleReference::publish(handle, hydration_level)?;
        let estimated_cost = handle
            .estimated_cost(hydration_level)
            .ok_or(HydrationError::LevelUnavailable)?;
        let mut binding = Self {
            slot_id: slot_id.into(),
            reference,
            purpose: purpose.into(),
            estimated_cost,
            binding_digest: ContentDigest::sha256(b"unpublished-context-expansion-binding"),
        };
        binding.validate_body()?;
        binding.binding_digest = binding.computed_digest();
        Ok(binding)
    }

    /// Recomputes the exact binding digest.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        self.encode_body(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Verifies the self-contained binding identity and finite price.
    pub fn verify(&self) -> Result<(), ContextBindingError> {
        self.validate_body()?;
        if self.binding_digest != self.computed_digest() {
            return Err(ContractError::DigestMismatch.into());
        }
        Ok(())
    }

    /// Verifies the binding against the exact descriptor revision and its registered price.
    pub fn validate_for(&self, handle: &SemanticHandle) -> Result<(), ContextBindingError> {
        self.verify()?;
        self.reference.validate_for(handle)?;
        let exact_cost = handle
            .estimated_cost(self.reference.hydration_level)
            .ok_or(HydrationError::LevelUnavailable)?;
        if self.estimated_cost != exact_cost {
            return Err(ContractError::DigestMismatch.into());
        }
        Ok(())
    }

    fn validate_body(&self) -> Result<(), ContextBindingError> {
        self.reference.verify()?;
        if !valid_text(&self.slot_id)
            || !valid_text(&self.purpose)
            || !self.estimated_cost.is_valid()
        {
            return Err(ContractError::EvidenceRequired.into());
        }
        Ok(())
    }

    fn encode_body(&self, encoder: &mut CanonicalEncoder) {
        encoder.text("fss.context_expansion_binding.v1");
        encoder.text(&self.slot_id);
        self.reference.encode_canonical(encoder);
        encoder.text(&self.purpose);
        encode_budget(self.estimated_cost, encoder);
    }
}

impl CanonicalEncode for ContextExpansionBinding {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.encode_body(encoder);
        encoder.digest(self.binding_digest);
    }
}

/// Complete proof that every expansion slot is bound exactly once to a descriptor revision.
#[derive(Clone, Debug, PartialEq)]
pub struct ContextExpansionBindingSet {
    /// Exact semantic contract basis digest.
    pub contract_basis_digest: ContentDigest,
    /// Exact selected context-pack digest.
    pub pack_digest: ContentDigest,
    /// Exact semantic-compression receipt digest.
    pub compression_receipt_digest: ContentDigest,
    /// Canonically ordered one-to-one slot bindings.
    pub bindings: Vec<ContextExpansionBinding>,
    /// Digest of the complete binding-set body.
    pub binding_set_digest: ContentDigest,
}

impl ContextExpansionBindingSet {
    /// Publishes a complete binding set for one exact pack and compression receipt.
    pub fn publish(
        pack: &SemanticContextPack,
        receipt: &SemanticCompressionReceipt,
        mut bindings: Vec<ContextExpansionBinding>,
    ) -> Result<Self, ContextBindingError> {
        pack.verify()?;
        receipt.validate_for(pack)?;
        bindings.sort_by(|left, right| left.slot_id.cmp(&right.slot_id));
        let mut binding_set = Self {
            contract_basis_digest: pack.contract_basis.basis_digest(),
            pack_digest: pack.pack_digest,
            compression_receipt_digest: receipt.receipt_digest(),
            bindings,
            binding_set_digest: ContentDigest::sha256(
                b"unpublished-context-expansion-binding-set",
            ),
        };
        binding_set.validate_body(pack, receipt)?;
        binding_set.binding_set_digest = binding_set.computed_digest();
        Ok(binding_set)
    }

    /// Recomputes the binding-set digest.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        self.encode_body(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Verifies completeness and identity against the exact pack and receipt.
    pub fn validate_for(
        &self,
        pack: &SemanticContextPack,
        receipt: &SemanticCompressionReceipt,
    ) -> Result<(), ContextBindingError> {
        self.validate_body(pack, receipt)?;
        if self.binding_set_digest != self.computed_digest() {
            return Err(ContractError::DigestMismatch.into());
        }
        Ok(())
    }

    /// Verifies every binding against a catalog containing exact descriptor revisions.
    pub fn validate_catalog(
        &self,
        pack: &SemanticContextPack,
        receipt: &SemanticCompressionReceipt,
        handles: &[SemanticHandle],
    ) -> Result<(), ContextBindingError> {
        self.validate_for(pack, receipt)?;
        let mut catalog = BTreeMap::new();
        for handle in handles {
            handle.verify()?;
            let key = (handle.handle_id.clone(), handle.descriptor_digest);
            if catalog.insert(key, handle).is_some() {
                return Err(ContractError::NonCanonicalOrdering.into());
            }
        }
        for binding in &self.bindings {
            let key = (
                binding.reference.handle_id.clone(),
                binding.reference.descriptor_digest,
            );
            let handle = catalog
                .get(&key)
                .copied()
                .ok_or(HydrationError::DescriptorNotFound)?;
            binding.validate_for(handle)?;
        }
        Ok(())
    }

    /// Returns the exact binding for one expansion slot.
    #[must_use]
    pub fn binding_for_slot(&self, slot_id: &str) -> Option<&ContextExpansionBinding> {
        self.bindings
            .binary_search_by(|binding| binding.slot_id.as_str().cmp(slot_id))
            .ok()
            .map(|index| &self.bindings[index])
    }

    /// Returns every expansion slot required by the exact pack and receipt.
    #[must_use]
    pub fn required_slots(
        pack: &SemanticContextPack,
        receipt: &SemanticCompressionReceipt,
    ) -> BTreeSet<String> {
        pack.items
            .iter()
            .flat_map(|item| item.expansion_handles.iter().cloned())
            .chain(
                receipt
                    .expansion_handles
                    .iter()
                    .map(|handle| handle.handle.clone()),
            )
            .collect()
    }

    fn validate_body(
        &self,
        pack: &SemanticContextPack,
        receipt: &SemanticCompressionReceipt,
    ) -> Result<(), ContextBindingError> {
        pack.verify()?;
        receipt.validate_for(pack)?;
        if self.contract_basis_digest != pack.contract_basis.basis_digest()
            || self.pack_digest != pack.pack_digest
            || self.compression_receipt_digest != receipt.receipt_digest()
            || self.bindings.len() > MAX_BINDINGS
        {
            return Err(ContractError::DigestMismatch.into());
        }

        let required = Self::required_slots(pack, receipt);
        let mut actual = BTreeSet::new();
        let mut prior: Option<&str> = None;
        for binding in &self.bindings {
            binding.verify()?;
            if prior.is_some_and(|value| value >= binding.slot_id.as_str()) {
                return Err(ContextBindingError::DuplicateSlot(binding.slot_id.clone()));
            }
            prior = Some(&binding.slot_id);
            if !actual.insert(binding.slot_id.clone()) {
                return Err(ContextBindingError::DuplicateSlot(binding.slot_id.clone()));
            }
            let descriptor_anchor = &binding.reference.descriptor_anchor;
            if binding.reference.contract_basis_digest != self.contract_basis_digest
                || descriptor_anchor.site_lineage != pack.anchor.site_lineage
                || descriptor_anchor.ledger_epoch != pack.anchor.ledger_epoch
            {
                return Err(ContractError::GenerationConflict.into());
            }
            if descriptor_anchor.commit_sequence > pack.anchor.commit_sequence {
                return Err(ContractError::StaleAnchor.into());
            }
        }

        if let Some(slot) = required.difference(&actual).next() {
            return Err(ContextBindingError::MissingSlot(slot.clone()));
        }
        if let Some(slot) = actual.difference(&required).next() {
            return Err(ContextBindingError::UnexpectedSlot(slot.clone()));
        }
        Ok(())
    }

    fn encode_body(&self, encoder: &mut CanonicalEncoder) {
        encoder.text("fss.context_expansion_binding_set.v1");
        encoder.digest(self.contract_basis_digest);
        encoder.digest(self.pack_digest);
        encoder.digest(self.compression_receipt_digest);
        encoder.u64(self.bindings.len() as u64);
        for binding in &self.bindings {
            binding.encode_canonical(encoder);
        }
    }
}

impl CanonicalEncode for ContextExpansionBindingSet {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.encode_body(encoder);
        encoder.digest(self.binding_set_digest);
    }
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn encode_budget(value: BudgetVector, encoder: &mut CanonicalEncoder) {
    encoder.u64(value.latency_ms);
    encoder.u64(value.tokens);
    encoder.u64(value.bytes);
    encoder.u32(value.model_calls);
    encoder.u64(value.cpu_millis);
    encoder.u64(value.accelerator_millis);
    encoder.u64(value.energy_millijoules);
    encoder.u64(value.network_bytes);
    encoder.u64(value.storage_operations);
    encoder.u64(canonical_f64_bits(value.privacy_exposure));
    encoder.u64(canonical_f64_bits(value.operator_attention_seconds));
}

fn canonical_f64_bits(value: f64) -> u64 {
    if value == 0.0 {
        0
    } else if value.is_nan() {
        0x7ff8_0000_0000_0000
    } else {
        value.to_bits()
    }
}

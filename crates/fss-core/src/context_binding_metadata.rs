//! Cross-contract validation for receipt-level expansion metadata.

use crate::{
    ContextBindingError, ContextExpansionBindingSet, ContractError, SemanticCompressionReceipt,
};

impl ContextExpansionBindingSet {
    /// Verifies the exact receipt identity, canonical binding integrity, and descriptor-bound
    /// purpose and full multidimensional price of every receipt-level expansion slot.
    ///
    /// This check does not replace `validate_catalog`: descriptor authenticity and the complete
    /// pack-to-slot correspondence still require the exact pack and descriptor catalog.
    pub fn validate_receipt_metadata(
        &self,
        receipt: &SemanticCompressionReceipt,
    ) -> Result<(), ContextBindingError> {
        receipt.validate()?;
        if self.compression_receipt_digest != receipt.receipt_digest()
            || self.binding_set_digest != self.computed_digest()
        {
            return Err(ContractError::DigestMismatch.into());
        }
        let mut prior: Option<&str> = None;
        let mut actual = std::collections::BTreeSet::new();
        for binding in &self.bindings {
            binding.verify()?;
            if let Some(prior_slot) = prior {
                if prior_slot > binding.slot_id.as_str() {
                    return Err(ContextBindingError::NonCanonicalOrdering(
                        binding.slot_id.clone(),
                    ));
                }
            }
            prior = Some(&binding.slot_id);
            if !actual.insert(binding.slot_id.clone()) {
                return Err(ContextBindingError::DuplicateSlot(binding.slot_id.clone()));
            }
        }
        for expansion in &receipt.expansion_handles {
            let binding = self
                .binding_for_slot(&expansion.handle)
                .ok_or_else(|| ContextBindingError::MissingSlot(expansion.handle.clone()))?;
            if binding.purpose != expansion.purpose
                || binding.estimated_cost != expansion.estimated_cost
            {
                return Err(ContractError::DigestMismatch.into());
            }
        }
        Ok(())
    }
}

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
        for binding in &self.bindings {
            binding.verify()?;
            if prior.is_some_and(|slot| slot >= binding.slot_id.as_str()) {
                return Err(ContextBindingError::DuplicateSlot(binding.slot_id.clone()));
            }
            prior = Some(&binding.slot_id);
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

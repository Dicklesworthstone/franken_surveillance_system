//! Cross-contract validation for receipt-level expansion metadata.

use crate::{
    ContextBindingError, ContextExpansionBindingSet, ContractError, SemanticCompressionReceipt,
};

impl ContextExpansionBindingSet {
    /// Verifies that every receipt-level expansion slot repeats the descriptor-owned purpose and
    /// full multidimensional price exactly.
    pub fn validate_receipt_metadata(
        &self,
        receipt: &SemanticCompressionReceipt,
    ) -> Result<(), ContextBindingError> {
        receipt.validate()?;
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

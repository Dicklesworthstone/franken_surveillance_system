//! Session admission layered over the existing exact hydration protocol.

use fss_core::{HydrationRequest, HydrationResponse, PrincipalId, SessionId, TimestampNs};

use super::{ReferenceSessionError, ReferenceSessionStore, SessionAlias};
use crate::ReferenceHydrationCatalog;

impl ReferenceSessionStore {
    /// Hydrates an exact session symbol through the existing catalog and canonical protocol.
    ///
    /// Request grants must be subsets of the stored authority projection. An alias never grants
    /// capabilities, changes a request digest, permits another session's cursor, or follows the
    /// latest descriptor. H0 admission protects identity; the catalog independently enforces the
    /// selected level, privacy class, full cost vector, H4 purpose, and exact continuation.
    ///
    /// The session's token ceiling is cumulative. Each successful delivery, including another
    /// delivery of the same non-continuation request, consumes its receipt's quoted token cost.
    /// Quotes are not measurements of actual runtime use. Failed requests do not consume tokens.
    pub fn hydrate(
        &mut self,
        principal: &PrincipalId,
        alias: &SessionAlias,
        request: &HydrationRequest,
        catalog: &mut ReferenceHydrationCatalog,
        now: TimestampNs,
    ) -> Result<HydrationResponse, ReferenceSessionError> {
        let resolved = self.resolve(principal, alias, catalog, now)?;
        let entry = self.live_entry(principal, &alias.session_id, now)?;
        request.verify()?;
        if request.session_id != alias.session_id
            || request.handle_id != resolved.handle_id
            || request.expected_descriptor_digest != resolved.descriptor_digest
            || request.expected_subject_digest != resolved.subject_digest
        {
            return Err(ReferenceSessionError::StaleAlias);
        }
        if request.contract_basis != entry.basis
            || request.anchor != entry.session.current_anchor
            || request.issued_at.0 < entry.session.created_at_ns
            || request.issued_at > now
        {
            return Err(ReferenceSessionError::StaleBasis);
        }
        if !request
            .available_capabilities
            .is_subset(&entry.session.capabilities)
            || !request
                .authorized_privacy_classes
                .is_subset(&entry.session.privacy_scope)
        {
            return Err(ReferenceSessionError::GrantEscalation);
        }
        let remaining = entry
            .session
            .token_budget
            .checked_sub(entry.spent_tokens)
            .ok_or(ReferenceSessionError::BudgetExceeded)?;
        if request.budget.tokens > remaining {
            return Err(ReferenceSessionError::BudgetExceeded);
        }

        // All session refusals precede catalog mutation (including cursor issuance/consumption).
        // The catalog checks every delivered cost component against this exact request budget.
        let response = catalog.hydrate(request, now)?;
        entry.spent_tokens = entry
            .spent_tokens
            .checked_add(response.receipt.cost.tokens)
            .filter(|total| *total <= entry.session.token_budget)
            .ok_or(ReferenceSessionError::BudgetExceeded)?;
        Ok(response)
    }

    /// Returns the remaining cumulative token grant without exposing another principal's state.
    ///
    /// Refresh, symbol rotation, and exact open retries never replenish this balance.
    pub fn remaining_token_budget(
        &mut self,
        principal: &PrincipalId,
        session_id: &SessionId,
        now: TimestampNs,
    ) -> Result<u64, ReferenceSessionError> {
        let entry = self.live_entry(principal, session_id, now)?;
        entry
            .session
            .token_budget
            .checked_sub(entry.spent_tokens)
            .ok_or(ReferenceSessionError::BudgetExceeded)
    }
}

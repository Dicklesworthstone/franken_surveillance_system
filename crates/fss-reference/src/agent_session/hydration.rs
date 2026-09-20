//! Session admission layered over the existing exact hydration protocol.

use fss_core::{HydrationRequest, HydrationResponse, PrincipalId, SessionId, TimestampNs};

use super::{ReferenceSessionError, ReferenceSessionStore, SessionAlias};
use crate::{PublishedSourceReader, ReferenceHydrationCatalog, SourceHydrationError};
use fss_object::SpoolIo;
use fss_publication::LocalRootPublisher;

/// Separates session admission/accounting from live source-custody failures.
///
/// A source refusal is not evidence of absence. Display strings deliberately omit paths,
/// object identities and payloads; detailed causes belong only in authorized diagnostics.
#[derive(Debug)]
pub enum SessionSourceHydrationError {
    /// The live session, exact alias, request projection or cumulative budget refused delivery.
    Session(ReferenceSessionError),
    /// The catalog or source owner refused the exact requested evidence.
    Source(SourceHydrationError),
}

impl std::fmt::Display for SessionSourceHydrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Session(_) => "session source hydration admission refused",
            Self::Source(_) => "session source hydration custody refused",
        })
    }
}

impl std::error::Error for SessionSourceHydrationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Session(error) => Some(error),
            Self::Source(error) => Some(error),
        }
    }
}

impl From<ReferenceSessionError> for SessionSourceHydrationError {
    fn from(error: ReferenceSessionError) -> Self { Self::Session(error) }
}

impl From<SourceHydrationError> for SessionSourceHydrationError {
    fn from(error: SourceHydrationError) -> Self { Self::Source(error) }
}

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
        self.hydrate_with(principal, alias, request, catalog, now, |catalog| {
            catalog.hydrate(request, now).map_err(ReferenceSessionError::from)
        })
    }

    /// Delivers original published source evidence under the exact live session projection.
    ///
    /// Admission and the entire requested token allowance are checked BEFORE source I/O. The
    /// existing source reader revalidates root closure/tombstones and the catalog verifies exact
    /// bytes, selected-level grants, full cost, retention and continuation. Source bytes are not
    /// cached: a later request must recheck custody even for an identical request/alias.
    /// The trusted owner supplies both the scoped reader and service time, not the agent.
    pub fn hydrate_from_source(
        &mut self,
        principal: &PrincipalId,
        alias: &SessionAlias,
        request: &HydrationRequest,
        catalog: &mut ReferenceHydrationCatalog,
        reader: &dyn PublishedSourceReader,
        now: TimestampNs,
    ) -> Result<HydrationResponse, SessionSourceHydrationError> {
        self.hydrate_with(principal, alias, request, catalog, now, |catalog| {
            catalog.hydrate_from_source(request, reader, now).map_err(Into::into)
        })
    }

    /// Delivers source from the borrowed, lock-owning local publisher using its scoped I/O.
    ///
    /// No storage inspection occurs before session admission. The publisher is neither opened
    /// nor repaired here; its existing source reader rechecks disk closure around the read.
    /// This reference method does not make session charges or catalog cursors crash-durable.
    #[allow(clippy::too_many_arguments)] // explicit session and custody owners, no ambient authority
    pub fn hydrate_from_local_source(
        &mut self,
        principal: &PrincipalId,
        alias: &SessionAlias,
        request: &HydrationRequest,
        catalog: &mut ReferenceHydrationCatalog,
        publisher: &LocalRootPublisher,
        io: &dyn SpoolIo,
        now: TimestampNs,
    ) -> Result<HydrationResponse, SessionSourceHydrationError> {
        self.hydrate_with(principal, alias, request, catalog, now, |catalog| {
            catalog.hydrate_from_local_source(request, publisher, io, now).map_err(Into::into)
        })
    }

    // One admission/accounting path for cached and source-backed delivery. The callback remains
    // private: it cannot be used by a caller to supply arbitrary receipts or escape grants.
    fn hydrate_with<E: From<ReferenceSessionError>>(
        &mut self,
        principal: &PrincipalId,
        alias: &SessionAlias,
        request: &HydrationRequest,
        catalog: &mut ReferenceHydrationCatalog,
        now: TimestampNs,
        deliver: impl FnOnce(&mut ReferenceHydrationCatalog) -> Result<HydrationResponse, E>,
    ) -> Result<HydrationResponse, E> {
        let resolved = self.resolve(principal, alias, catalog, now)?;
        let entry = self.live_entry(principal, &alias.session_id, now)?;
        request.verify().map_err(ReferenceSessionError::from)?;
        if request.session_id != alias.session_id
            || request.handle_id != resolved.handle_id
            || request.expected_descriptor_digest != resolved.descriptor_digest
            || request.expected_subject_digest != resolved.subject_digest
        {
            return Err(ReferenceSessionError::StaleAlias.into());
        }
        if request.contract_basis != entry.basis
            || request.anchor != entry.session.current_anchor
            || request.issued_at.0 < entry.session.created_at_ns
            || request.issued_at > now
        {
            return Err(ReferenceSessionError::StaleBasis.into());
        }
        if !request
            .available_capabilities
            .is_subset(&entry.session.capabilities)
            || !request
                .authorized_privacy_classes
                .is_subset(&entry.session.privacy_scope)
        {
            return Err(ReferenceSessionError::GrantEscalation.into());
        }
        let remaining = entry
            .session
            .token_budget
            .checked_sub(entry.spent_tokens)
            .ok_or(ReferenceSessionError::BudgetExceeded)?;
        if request.budget.tokens > remaining {
            return Err(ReferenceSessionError::BudgetExceeded.into());
        }

        // All session refusals precede catalog mutation (including cursor issuance/consumption).
        // The catalog checks every delivered cost component against this exact request budget.
        let response = deliver(catalog)?;
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

//! Expand published context slots without reconstructing handles or granting ambient authority.
//!
//! The publication anchor describes the current situation; a slot may name an older, still
//! current descriptor. Its evidence anchor is preserved, not rewritten to the session anchor.
//! A descriptor superseded in the authoritative catalog is never served through an old pack.

use std::fmt;

use fss_core::hydration::{
    HydrationError, HydrationLevel, HydrationPurpose, HydrationRequest, HydrationRequestSpec,
    HydrationResponse,
};
use fss_core::{
    AgentSession, BudgetVector, CanonicalEncoder, ContentDigest, ContextBindingError,
    ContextExpansionBinding, ContinuationCursor, ContractError, PrincipalId, SessionId,
    TimestampNs,
};
use fss_object::SpoolIo;
use fss_publication::LocalRootPublisher;

use super::{ReferenceSessionError, ReferenceSessionStore};
use crate::{
    BoundReferenceSituationPublication, PublishedSourceReader, ReferenceContextBindingError,
    ReferenceHydrationCatalog, SourceHydrationError,
};

/// A read names a published slot, never caller-supplied subject identity or capability grants.
#[derive(Clone, Debug, PartialEq)]
pub struct ContextSlotRead {
    /// Authenticated session that owns the publication.
    pub session_id: SessionId,
    /// Current symbol-table generation, invalidated on rebase or grant changes.
    pub generation: u64,
    /// Exact root the caller inspected, preventing silent publication replacement.
    pub expected_publication_digest: ContentDigest,
    /// Exact expansion slot from the pack or its compression receipt.
    pub slot_id: String,
    /// The quoted level initially, or the next level of an issued continuation.
    pub requested_level: HydrationLevel,
    /// Explicit permission to deliver a lower authorized level within the budget.
    pub allow_lower_level: bool,
    /// Per-read resource ceilings; tokens also consume the cumulative session grant.
    pub budget: BudgetVector,
    /// Evidence purpose, not authority to use laboratory material or cause effects.
    pub purpose: HydrationPurpose,
    /// Optional catalog-issued single-use continuation for the same descriptor.
    pub continuation: Option<ContinuationCursor>,
    /// Request creation time, bounded by the session lease and service clock.
    pub issued_at: TimestampNs,
}

/// Read failures. Missing, unauthorized, and superseded slot targets are indistinguishable.
#[derive(Debug)]
pub enum ContextHydrationError {
    /// Principal, session, generation, budget, or hydration admission failed.
    Session(ReferenceSessionError),
    /// The caller's publication or its binding proofs are invalid.
    Publication(ReferenceContextBindingError),
    /// Live custody failed after admission; this is not evidence of physical absence.
    Source(SourceHydrationError),
    /// No currently authorized exact slot target is available; no raw identity is returned.
    SlotUnavailable,
    /// A fresh read must request the slot's published level, not silently widen the read.
    WrongInitialLevel,
}

impl fmt::Display for ContextHydrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(error) => fmt::Display::fmt(error, formatter),
            Self::Publication(_) => formatter.write_str("invalid context publication"),
            Self::Source(_) => formatter.write_str("context source custody unavailable"),
            Self::SlotUnavailable => formatter.write_str("context slot unavailable"),
            Self::WrongInitialLevel => formatter.write_str("request the published expansion level"),
        }
    }
}

impl std::error::Error for ContextHydrationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Session(error) => Some(error),
            Self::Publication(error) => Some(error),
            Self::Source(error) => Some(error),
            Self::SlotUnavailable | Self::WrongInitialLevel => None,
        }
    }
}

impl From<ReferenceSessionError> for ContextHydrationError {
    fn from(error: ReferenceSessionError) -> Self {
        Self::Session(error)
    }
}

impl From<ReferenceContextBindingError> for ContextHydrationError {
    fn from(error: ReferenceContextBindingError) -> Self {
        Self::Publication(error)
    }
}

impl From<ContextBindingError> for ContextHydrationError {
    fn from(error: ContextBindingError) -> Self {
        Self::Publication(error.into())
    }
}

impl From<HydrationError> for ContextHydrationError {
    fn from(error: HydrationError) -> Self {
        Self::Session(error.into())
    }
}

impl From<SourceHydrationError> for ContextHydrationError {
    fn from(error: SourceHydrationError) -> Self {
        match error {
            SourceHydrationError::Hydration(error) => error.into(),
            error => Self::Source(error),
        }
    }
}

impl From<ContractError> for ContextHydrationError {
    fn from(error: ContractError) -> Self {
        Self::Session(error.into())
    }
}

/// Delivery proof linking a context publication to an exact evidence request and receipt.
///
/// This is a historical, in-memory reference receipt, not a signed capability, production audit
/// journal, or proof of current availability. The full session snapshot is retained separately.
#[derive(Clone, Debug, PartialEq)]
pub struct BoundContextHydration {
    /// Exact situation/context/binding publication root.
    pub publication_digest: ContentDigest,
    /// Slot actually expanded.
    pub slot_id: String,
    /// Exact descriptor-and-price binding used for the read.
    pub binding_digest: ContentDigest,
    /// Session authority snapshot at admission, including grants, anchor, and generation.
    pub session_digest: ContentDigest,
    /// Actual request derived from the descriptor and server-owned session grants.
    pub request: HydrationRequest,
    /// Actual proof-bearing payload or typed unavailability result.
    pub response: HydrationResponse,
    /// Canonical digest of this delivery and all its linked roots.
    pub delivery_digest: ContentDigest,
}

impl BoundContextHydration {
    /// Recomputes the delivery root. Child roots are validated by [`Self::verify_for`].
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.reference_bound_context_hydration.v1");
        encoder.digest(self.publication_digest);
        encoder.text(&self.slot_id);
        encoder.digest(self.binding_digest);
        encoder.digest(self.session_digest);
        encoder.digest(self.request.request_digest);
        encoder.digest(self.response.receipt.receipt_digest);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Verifies historical delivery against the exact publication and admitted session snapshot.
    ///
    /// This does not consult current authority or prove that a continuation remains unconsumed.
    /// Only the live store and catalog authorize subsequent disclosure.
    pub fn verify_for(
        &self,
        publication: &BoundReferenceSituationPublication,
        session: &AgentSession,
    ) -> Result<(), ContextHydrationError> {
        publication.verify()?;
        let capsule = &publication.publication.situation.capsule;
        if self.publication_digest != publication.bound_publication_digest
            || self.session_digest != session.session_digest()
            || self.delivery_digest != self.computed_digest()
            || capsule.principal_id != session.principal_id
            || capsule.session_id != session.session_id
            || capsule.mission_id != session.mission_id
            || capsule.anchor != session.current_anchor
            || self.request.session_id != session.session_id
            || self.request.contract_basis != capsule.contract_basis
            || self.request.available_capabilities != session.capabilities
            || self.request.authorized_privacy_classes != session.privacy_scope
            || self.request.budget.tokens > session.token_budget
            || self.request.issued_at < capsule.created_at
            || self.request.issued_at.0 < session.created_at_ns
            || self.response.receipt.issued_at.0 >= session.expires_at_ns
        {
            return Err(ContractError::DigestMismatch.into());
        }
        let binding = publication
            .expansion_bindings
            .binding_for_slot(&self.slot_id)
            .ok_or(ContextHydrationError::SlotUnavailable)?;
        if self.binding_digest != binding.binding_digest {
            return Err(ContractError::DigestMismatch.into());
        }
        check_initial_level(
            binding,
            self.request.requested_level,
            &self.request.continuation,
        )?;
        let descriptor = publication
            .descriptors
            .iter()
            .find(|descriptor| {
                descriptor.handle_id == binding.reference.handle_id
                    && descriptor.descriptor_digest == binding.reference.descriptor_digest
            })
            .ok_or(ContextHydrationError::SlotUnavailable)?;
        binding.validate_for(descriptor)?;
        let required = descriptor
            .required_capabilities
            .get(&HydrationLevel::H0)
            .ok_or(ContextHydrationError::SlotUnavailable)?;
        if !required.is_subset(&session.capabilities)
            || !session.privacy_scope.contains(&descriptor.privacy_class)
        {
            return Err(ContextHydrationError::SlotUnavailable);
        }
        self.response.validate_for(&self.request, descriptor)?;
        Ok(())
    }
}

impl ReferenceSessionStore {
    /// Delivers a published expansion using current session authority and cumulative accounting.
    ///
    /// No alias is allocated and no session anchor is changed. An older descriptor anchor is
    /// allowed only by the verified pack binding; the descriptor must remain current in the
    /// server catalog. Failed reads do not spend tokens or consume cursors, although the session
    /// still observes the trusted service clock. Each delivery charges descriptor-quoted tokens,
    /// not measured runtime consumption. Typed retention unavailability costs zero.
    pub fn hydrate_context_slot(
        &mut self,
        principal: &PrincipalId,
        publication: &BoundReferenceSituationPublication,
        read: &ContextSlotRead,
        catalog: &mut ReferenceHydrationCatalog,
        now: TimestampNs,
    ) -> Result<BoundContextHydration, ContextHydrationError> {
        self.hydrate_context_slot_with(
            principal,
            publication,
            read,
            catalog,
            now,
            |catalog, request| Ok(catalog.hydrate(request, now)?),
        )
    }

    /// Expands a published slot through live source custody under server-owned session grants.
    ///
    /// Principal, session, generation, publication identity, current descriptor, privacy, and
    /// cumulative token admission all precede source I/O. The supplied reader is owned by the
    /// runtime, never derived from a caller-provided digest. Source delivery rechecks custody
    /// and never caches H3 bytes; failure spends no tokens and leaves continuations unconsumed.
    /// This reuses the ordinary bound delivery proof and allocates no session alias.
    pub fn hydrate_context_slot_from_source(
        &mut self,
        principal: &PrincipalId,
        publication: &BoundReferenceSituationPublication,
        read: &ContextSlotRead,
        catalog: &mut ReferenceHydrationCatalog,
        reader: &dyn PublishedSourceReader,
        now: TimestampNs,
    ) -> Result<BoundContextHydration, ContextHydrationError> {
        self.hydrate_context_slot_with(
            principal,
            publication,
            read,
            catalog,
            now,
            |catalog, request| Ok(catalog.hydrate_from_source(request, reader, now)?),
        )
    }

    /// Reads a bound slot from the lock-owning local publisher and its explicit I/O capability.
    ///
    /// The publisher is borrowed, not reopened or repaired. Session admission precedes disk
    /// inspection; the existing local source reader verifies publication closure around I/O.
    /// Neither token accounting nor cursor consumption is made crash-durable by this helper.
    #[allow(clippy::too_many_arguments)] // explicit session and custody owners, no ambient authority
    pub fn hydrate_context_slot_from_local_source(
        &mut self,
        principal: &PrincipalId,
        publication: &BoundReferenceSituationPublication,
        read: &ContextSlotRead,
        catalog: &mut ReferenceHydrationCatalog,
        publisher: &LocalRootPublisher,
        io: &dyn SpoolIo,
        now: TimestampNs,
    ) -> Result<BoundContextHydration, ContextHydrationError> {
        self.hydrate_context_slot_with(
            principal,
            publication,
            read,
            catalog,
            now,
            |catalog, request| Ok(catalog.hydrate_from_local_source(request, publisher, io, now)?),
        )
    }

    // Private dispatch keeps all transports on one admission and accounting path. A caller
    // cannot inject arbitrary receipts, bypass server grants, or mutate tokens before delivery.
    fn hydrate_context_slot_with(
        &mut self,
        principal: &PrincipalId,
        publication: &BoundReferenceSituationPublication,
        read: &ContextSlotRead,
        catalog: &mut ReferenceHydrationCatalog,
        now: TimestampNs,
        deliver: impl FnOnce(
            &mut ReferenceHydrationCatalog,
            &HydrationRequest,
        ) -> Result<HydrationResponse, ContextHydrationError>,
    ) -> Result<BoundContextHydration, ContextHydrationError> {
        let entry = self.live_entry(principal, &read.session_id, now)?;
        Self::check_generation(entry, read.generation)?;
        if read.slot_id.is_empty()
            || read.slot_id.len() > 4_096
            || read.slot_id.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(ContextHydrationError::SlotUnavailable);
        }
        let capsule = &publication.publication.situation.capsule;
        if capsule.principal_id != entry.session.principal_id
            || capsule.session_id != entry.session.session_id
            || capsule.mission_id != entry.session.mission_id
        {
            return Err(ReferenceSessionError::Unavailable.into());
        }
        if capsule.anchor != entry.session.current_anchor
            || capsule.contract_basis != entry.basis
            || publication.bound_publication_digest != read.expected_publication_digest
            || read.issued_at < capsule.created_at
            || read.issued_at.0 < entry.session.created_at_ns
            || read.issued_at > now
        {
            return Err(ReferenceSessionError::StaleBasis.into());
        }
        let binding = publication
            .expansion_bindings
            .binding_for_slot(&read.slot_id)
            .ok_or(ContextHydrationError::SlotUnavailable)?;
        let descriptor = catalog
            .current_descriptor(&binding.reference.handle_id)
            .filter(|descriptor| {
                descriptor.descriptor_digest == binding.reference.descriptor_digest
                    && descriptor.subject_digest == binding.reference.subject_digest
            })
            .ok_or(ContextHydrationError::SlotUnavailable)?;
        // Current server-owned H0/privacy projection precedes integrity diagnostics. Neither a
        // caller's descriptor copy nor the slot's explanatory purpose can grant authority.
        let required = descriptor
            .required_capabilities
            .get(&HydrationLevel::H0)
            .ok_or(ContextHydrationError::SlotUnavailable)?;
        if !required.is_subset(&entry.session.capabilities)
            || !entry
                .session
                .privacy_scope
                .contains(&descriptor.privacy_class)
        {
            return Err(ContextHydrationError::SlotUnavailable);
        }
        publication.verify()?;
        binding.validate_for(descriptor)?;
        if descriptor.contract_basis != entry.basis || descriptor.published_at > now {
            return Err(ReferenceSessionError::StaleBasis.into());
        }
        check_initial_level(binding, read.requested_level, &read.continuation)?;
        let request = HydrationRequest::publish(HydrationRequestSpec {
            contract_basis: descriptor.contract_basis.clone(),
            session_id: entry.session.session_id.clone(),
            handle_id: descriptor.handle_id.clone(),
            expected_descriptor_digest: descriptor.descriptor_digest,
            expected_subject_digest: descriptor.subject_digest,
            anchor: descriptor.anchor.clone(),
            requested_level: read.requested_level,
            allow_lower_level: read.allow_lower_level,
            available_capabilities: entry.session.capabilities.clone(),
            authorized_privacy_classes: entry.session.privacy_scope.clone(),
            budget: read.budget,
            purpose: read.purpose,
            continuation: read.continuation.clone(),
            issued_at: read.issued_at,
        })?;
        let remaining = entry
            .session
            .token_budget
            .checked_sub(entry.spent_tokens)
            .ok_or(ReferenceSessionError::BudgetExceeded)?;
        if request.budget.tokens > remaining {
            return Err(ReferenceSessionError::BudgetExceeded.into());
        }
        let response = deliver(catalog, &request)?;
        // The catalog validates cost <= request budget <= remaining before committing cursors.
        // No fallible step may follow that commit. This bounded addition therefore cannot wrap.
        entry.spent_tokens += response.receipt.cost.tokens;
        let mut delivery = BoundContextHydration {
            publication_digest: publication.bound_publication_digest,
            slot_id: read.slot_id.clone(),
            binding_digest: binding.binding_digest,
            session_digest: entry.session.session_digest(),
            request,
            response,
            delivery_digest: ContentDigest::sha256(b"unpublished-bound-context-hydration"),
        };
        delivery.delivery_digest = delivery.computed_digest();
        Ok(delivery)
    }
}

fn check_initial_level(
    binding: &ContextExpansionBinding,
    level: HydrationLevel,
    continuation: &Option<ContinuationCursor>,
) -> Result<(), ContextHydrationError> {
    if continuation.is_none() && level != binding.reference.hydration_level {
        return Err(ContextHydrationError::WrongInitialLevel);
    }
    Ok(())
}

impl BoundContextHydration {
    /// Verifies both context/session admission and exact original-source provenance.
    ///
    /// The publication, admitted session snapshot, and source binding must be retained from
    /// trusted authority, not reconstructed from this delivery. Ordinary [`Self::verify_for`]
    /// also admits valid previews and unavailable results; this stronger check requires a
    /// complete, untransformed H3 payload from the exact bound publication root. It rejects a
    /// different source publication even when that publication contains identical source bytes.
    ///
    /// This checks historical consistency, not current custody or authentication. A fresh live
    /// read is still required after expiry, grant changes, deletion, or an authority transition.
    pub fn verify_source_for(
        &self,
        publication: &BoundReferenceSituationPublication,
        session: &AgentSession,
        source: &crate::SourceObjectBinding,
    ) -> Result<(), ContextHydrationError> {
        self.verify_for(publication, session)?;
        let descriptor = publication
            .descriptors
            .iter()
            .find(|descriptor| {
                descriptor.handle_id == self.request.handle_id
                    && descriptor.descriptor_digest == self.request.expected_descriptor_digest
            })
            .ok_or(ContextHydrationError::SlotUnavailable)?;
        source.validate_response(&self.request, descriptor, &self.response)?;
        Ok(())
    }
}

#![forbid(unsafe_code)]
//! Claims, investigations, source registration and disclosure share exactly one journal owner.
//!
//! These are compositions of existing state machines, not alternative claim or case encodings.
//! No mutable session/catalog escape hatch is exposed, and no operation opens a second writer.

use super::{
    ContentDigest, DisclosureError, DurableDisclosureStore, DurableSessionLimits,
    DurableSessionStore, IncompleteTailPolicy, Path, PrincipalId, ReferenceHydrationCatalog,
    SessionId, TimestampNs, WorkClaimLimits, recover_profile,
};
use crate::agent_session::checkpoint::journal::DurableSessionError;
use crate::agent_session::checkpoint::journal::coordination::{
    CoordinationCommand, SessionRecoveryReceipt,
};
use crate::agent_session::checkpoint::journal::coordination::investigations::{
    DurableInvestigationError, InvestigationCommand, InvestigationLimits, InvestigationRevision,
};
use crate::agent_session::work_claims::WorkClaimRevision;

impl DurableDisclosureStore {
    /// Opens an existing coordinated journal and restores its disclosure replay protection.
    ///
    /// The runtime supplies both the independently trusted root and claim ceilings. Stored limits
    /// cannot authorize a larger allocation. Missing descriptors/source may remain absent, but
    /// saved source requirements, session charges, claim fences and cursor tombstones survive.
    /// No coordination or case state is initialized or reset by opening. The caller holds the
    /// same external exclusive namespace lock required by the ordinary disclosure owner.
    pub fn open_existing_with_coordination(
        path: impl AsRef<Path>,
        expected_root: ContentDigest,
        limits: DurableSessionLimits,
        claim_ceilings: WorkClaimLimits,
        catalog: ReferenceHydrationCatalog,
    ) -> Result<Self, DisclosureError> {
        let sessions = DurableSessionStore::open_existing_with_coordination(
            path, expected_root, limits, claim_ceilings,
        )?;
        let mut owner = Self { sessions, catalog };
        owner.synchronize_catalog(None)?;
        Ok(owner)
    }

    /// Cold recovery of a mixed claim/case/disclosure history at an independently trusted root.
    ///
    /// Complete semantic replay, independent claim ceilings and catalog compatibility all precede
    /// any truncation or synchronization. The existing native recovery contract still governs I/O
    /// uncertainty. Committed claims/citations are not retried, charged source is not reread, and
    /// complete newer history cannot be discarded to satisfy an older root. The legacy entry point
    /// continues refusing coordination history without independently supplied claim ceilings.
    pub fn recover_existing_with_coordination(
        path: impl AsRef<Path>,
        expected_root: ContentDigest,
        limits: DurableSessionLimits,
        claim_ceilings: WorkClaimLimits,
        policy: IncompleteTailPolicy,
        catalog: ReferenceHydrationCatalog,
    ) -> Result<(Self, SessionRecoveryReceipt), DisclosureError> {
        recover_profile(
            path.as_ref(), expected_root, limits, Some(claim_ceilings), policy, catalog,
        )
    }

    /// Explicit one-way initialization through the same writer that owns disclosure charges.
    /// This administrative operation does not grant an agent a work capability or change cursors.
    pub fn enable_coordination(&mut self, limits: WorkClaimLimits) -> Result<(), DurableSessionError> {
        self.sessions.enable_coordination(limits)
    }

    /// Executes a session-authorized work claim through the existing canonical coordinator.
    /// Refusal-side clocks and claim fences retain their original durability semantics. An
    /// uncertain append fences source disclosure as well; use this owner's reconcile_pending.
    pub fn coordinate(
        &mut self,
        principal: &PrincipalId,
        session: &SessionId,
        command: CoordinationCommand,
        now: TimestampNs,
    ) -> Result<WorkClaimRevision, DurableSessionError> {
        self.sessions.coordinate(principal, session, command, now)
    }

    /// Initializes the existing bounded case history in this owner's coordinated journal.
    /// Stored case limits remain immutable and subject to the native absolute envelope.
    pub fn enable_investigations(
        &mut self,
        limits: InvestigationLimits,
    ) -> Result<(), DurableInvestigationError> {
        self.sessions.enable_investigations(limits)
    }

    /// Applies an existing case command without giving it source-disclosure or effect authority.
    /// Evidence citations supplied here remain caller-authorized metadata, not fresh custody
    /// proofs. This operation preserves all source commitments and issued/consumed continuations.
    pub fn investigate(
        &mut self,
        principal: &PrincipalId,
        session: &SessionId,
        command: InvestigationCommand,
        now: TimestampNs,
    ) -> Result<InvestigationRevision, DurableInvestigationError> {
        self.sessions.investigate(principal, session, command, now)
    }
}

#[cfg(test)]
mod tests;

#![forbid(unsafe_code)]
//! Admitted read projections of captured session history, without a writable journal handle.

use fss_core::{AgentSession, ContentDigest, PrincipalId, SessionId, TimestampNs};

use super::coordination::investigations::InvestigationRevision;
use super::mission::{DurableMissionError, MissionRevision};
use super::supervision::{DurableSupervisionError, SupervisionInventoryEntry};
use super::workspace::DurableWorkspaceError;
use super::{
    DurableSessionError, DurableSessionLimits, DurableSessionStore, MAX_SESSION_JOURNAL_BYTES,
    ReplayedSessionState, SessionRecoveryState, read_report, recovery_state_from_replayed,
    replay_all,
};
use crate::agent_session::ReferenceSessionError;
use crate::agent_session::work_claims::{WorkClaimLimits, WorkClaimRevision};
use crate::agent_session::workspace::WorkspaceRevision;

/// The same authenticated read facets are available to the live owner and a captured projection.
/// No method grants mutation, renews a lease, acknowledges delivery or advances a clock.
pub(crate) trait SessionProjection {
    fn mission_head_for_projection(
        &self,
        session: &AgentSession,
        now: TimestampNs,
    ) -> Result<Option<MissionRevision>, DurableMissionError>;
    fn supervision_inventory(
        &self,
        session: &AgentSession,
        now: TimestampNs,
    ) -> Result<Vec<SupervisionInventoryEntry>, DurableSupervisionError>;
    /// Exact historical custody for authenticating retained private advisory publications.
    /// Returning these bytes does not make past grants or workspaces current authority.
    fn recovery_state_for_projection(
        &self,
        session: &AgentSession,
        now: TimestampNs,
    ) -> Result<SessionRecoveryState, DurableSessionError>;
    fn investigation_heads(&self) -> Vec<InvestigationRevision>;
    fn work_claim_heads(&self) -> Vec<WorkClaimRevision>;
}

impl SessionProjection for DurableSessionStore {
    fn mission_head_for_projection(
        &self,
        session: &AgentSession,
        now: TimestampNs,
    ) -> Result<Option<MissionRevision>, DurableMissionError> {
        DurableSessionStore::mission_head_for_projection(self, session, now)
    }
    fn supervision_inventory(
        &self,
        session: &AgentSession,
        now: TimestampNs,
    ) -> Result<Vec<SupervisionInventoryEntry>, DurableSupervisionError> {
        DurableSessionStore::supervision_inventory(self, session, now)
    }
    fn recovery_state_for_projection(
        &self,
        session: &AgentSession,
        now: TimestampNs,
    ) -> Result<SessionRecoveryState, DurableSessionError> {
        if self.fenced {
            return Err(DurableSessionError::ReconciliationRequired);
        }
        admit_recovery(&self.memory, session, now)?;
        let report = read_report(self.path(), self.limits)?;
        if report.last_root() != self.committed_root()
            || report.committed_len() != self.journal.committed_len()
            || report.records().len() != self.records
            || report.incomplete_tail().is_some()
        {
            return Err(DurableSessionError::RootMismatch);
        }
        let ceilings = self.coordination.as_ref().map(|state| state.limits);
        let restored = replay_all(&report, self.limits, ceilings)?;
        let recovery = recovery_state_from_replayed(
            &restored,
            self.limits,
            report.last_root(),
            report.records().len(),
            report.committed_len(),
            None,
        )?;
        if recovery.inspection.checkpoint_digest != self.checkpoint_digest {
            return Err(DurableSessionError::InvalidHistory);
        }
        admit_recovery(&restored.memory, session, now)?;
        Ok(recovery)
    }
    fn investigation_heads(&self) -> Vec<InvestigationRevision> {
        DurableSessionStore::investigation_heads(self)
    }
    fn work_claim_heads(&self) -> Vec<WorkClaimRevision> {
        DurableSessionStore::work_claim_heads(self)
    }
}

/// A fully verified immutable prefix captured while the native reader holds the existing lock.
/// Replay grants no authority; every returned session and facet still runs live admission.
pub(crate) struct SessionProjectionSnapshot {
    restored: ReplayedSessionState,
    root: ContentDigest,
    records: usize,
    committed_bytes: u64,
    limits: DurableSessionLimits,
}

impl SessionProjectionSnapshot {
    pub(crate) fn from_bytes(
        bytes: &[u8],
        pinned: ContentDigest,
        limits: DurableSessionLimits,
        claims: WorkClaimLimits,
    ) -> Result<Self, DurableSessionError> {
        if bytes.len() > limits.max_journal_bytes.min(MAX_SESSION_JOURNAL_BYTES) {
            return Err(DurableSessionError::CapacityExceeded);
        }
        let report = fss_ledger::recover_bytes(bytes)?;
        if report.records().len() > limits.max_records {
            return Err(DurableSessionError::CapacityExceeded);
        }
        if let Some(offset) = report.incomplete_tail() {
            return Err(fss_ledger::JournalError::IncompleteTail { offset }.into());
        }
        if report.last_root() != pinned
            && !report
                .records()
                .iter()
                .any(|record| record.root() == pinned)
        {
            return Err(DurableSessionError::RootMismatch);
        }
        Ok(Self {
            restored: replay_all(&report, limits, Some(claims))?,
            root: report.last_root(),
            records: report.records().len(),
            committed_bytes: report.committed_len(),
            limits,
        })
    }

    pub(crate) fn root(&self) -> ContentDigest {
        self.root
    }

    /// Apply the ordinary owner checks to isolated memory. A rejected future read cannot close
    /// the persisted session or consume its symbols, and a successful one cannot rebase it.
    pub(crate) fn session_workspace(
        &self,
        principal: &PrincipalId,
        session_id: &SessionId,
        now: TimestampNs,
    ) -> Result<(AgentSession, WorkspaceRevision, u64), DurableWorkspaceError> {
        let mut memory = self.restored.memory.clone();
        let session = memory
            .session(principal, session_id, now)
            .map_err(DurableSessionError::Session)?;
        if memory
            .sessions
            .get(session_id)
            .is_none_or(|entry| entry.basis != fss_core::reference_contract_basis())
        {
            return Err(DurableSessionError::Session(ReferenceSessionError::StaleBasis).into());
        }
        let workspace = self
            .restored
            .workspaces
            .as_ref()
            .ok_or(DurableWorkspaceError::NotInitialized)?
            .head_for_projection(&mut memory, principal, session_id, now)
            .map_err(DurableWorkspaceError::Refused)?;
        let remaining = memory
            .remaining_token_budget(principal, session_id, now)
            .map_err(DurableSessionError::Session)?;
        Ok((session, workspace.revision, remaining))
    }
}

impl SessionProjection for SessionProjectionSnapshot {
    fn mission_head_for_projection(
        &self,
        session: &AgentSession,
        now: TimestampNs,
    ) -> Result<Option<MissionRevision>, DurableMissionError> {
        super::mission::project_mission_head(&self.restored, session, now)
    }
    fn supervision_inventory(
        &self,
        session: &AgentSession,
        now: TimestampNs,
    ) -> Result<Vec<SupervisionInventoryEntry>, DurableSupervisionError> {
        super::supervision::project_inventory(&self.restored, session, now)
    }
    fn recovery_state_for_projection(
        &self,
        session: &AgentSession,
        now: TimestampNs,
    ) -> Result<SessionRecoveryState, DurableSessionError> {
        admit_recovery(&self.restored.memory, session, now)?;
        recovery_state_from_replayed(
            &self.restored,
            self.limits,
            self.root,
            self.records,
            self.committed_bytes,
            None,
        )
    }
    fn investigation_heads(&self) -> Vec<InvestigationRevision> {
        self.restored
            .coordination
            .as_ref()
            .and_then(|state| state.cases.as_ref())
            .map(|cases| cases.heads().cloned().collect())
            .unwrap_or_default()
    }
    fn work_claim_heads(&self) -> Vec<WorkClaimRevision> {
        self.restored
            .coordination
            .as_ref()
            .map(|state| state.claims.heads().cloned().collect())
            .unwrap_or_default()
    }
}

/// Authenticate the exact live owner and read/privacy grants on an isolated session store.
/// This read neither advances persisted clocks nor uses historical grants as current access.
fn admit_recovery(
    memory: &crate::agent_session::ReferenceSessionStore,
    session: &AgentSession,
    now: TimestampNs,
) -> Result<(), DurableSessionError> {
    let entry = memory
        .sessions
        .get(&session.session_id)
        .filter(|entry| entry.session == *session && !entry.closed)
        .ok_or(DurableSessionError::Session(
            ReferenceSessionError::Unavailable,
        ))?;
    if entry.basis != fss_core::reference_contract_basis() {
        return Err(DurableSessionError::Session(
            ReferenceSessionError::StaleBasis,
        ));
    }
    if !["CAP-AGENT-SESSION-READ-001", "CAP-AGENT-SITUATION-READ-001"]
        .iter()
        .all(|capability| session.capabilities.contains(*capability))
        || !session.privacy_scope.contains("private:property")
    {
        return Err(DurableSessionError::Session(
            ReferenceSessionError::GrantEscalation,
        ));
    }
    memory
        .clone()
        .session(&session.principal_id, &session.session_id, now)
        .map_err(DurableSessionError::Session)?;
    Ok(())
}

#![forbid(unsafe_code)]
//! Admitted read projections of captured session history, without a writable journal handle.

use fss_core::{AgentSession, ContentDigest, PrincipalId, SessionId, TimestampNs};

use super::coordination::investigations::InvestigationRevision;
use super::mission::{DurableMissionError, MissionRevision};
use super::supervision::{DurableSupervisionError, SupervisionInventoryEntry};
use super::workspace::DurableWorkspaceError;
use super::{
    DurableSessionError, DurableSessionLimits, DurableSessionStore, MAX_SESSION_JOURNAL_BYTES,
    ReplayedSessionState, replay_all,
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

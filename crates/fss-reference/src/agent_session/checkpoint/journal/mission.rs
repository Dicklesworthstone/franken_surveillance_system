#![forbid(unsafe_code)]
//! Immutable mission criteria and assessed lifecycle revisions in the shared session journal.
//!
//! Replay re-executes the same admitted state machine against preceding session/workspace state.
//! Stored output states cannot override that derivation. Native custody verification remains a
//! prerequisite; this owner neither reads source media nor creates effect authority.

use std::fmt;

use fss_core::{
    AgentSession, CanonicalDecoder, CanonicalEncoder, ContentDigest, PrincipalId, SessionId,
    TimestampNs,
};

use super::workspace::WorkspaceState;
use super::{
    DurableSessionError, DurableSessionLimits, DurableSessionStore, PendingSession,
    ReferenceSessionStore, read_report, replay_all,
};
use crate::agent_session::mission::{MAX_MISSION_RECORD_BYTES, admit, admit_read, text};
pub use crate::agent_session::mission::{
    MissionAssessmentFacts, MissionClosureFacts, MissionEpisodeFacts, MissionEpisodeOutcome,
    MissionError, MissionObligationFacts, MissionObligationState, MissionOperationFacts,
    MissionOperationState, MissionPlanCriterion, MissionRevision, ReferenceMissionStore,
};

/// Additive private command family. Old readers refuse it rather than losing mission state.
pub const MISSION_COMMAND_RECORD_KIND: u16 = 0x4d53;
const RECORD_DOMAIN: &str = "fss.reference_mission_command.v1";
const MAX_COMMAND_BYTES: usize = MAX_MISSION_RECORD_BYTES + 4096;

#[cfg(test)]
mod tests;

/// Ordinary semantic refusal is distinct from uncertain or invalid persistence.
#[derive(Debug)]
pub enum DurableMissionError {
    /// Live authorization, immutable criteria, terminal-state or predecessor refusal.
    Refused(MissionError),
    /// Shared journal integrity, capacity or append reconciliation failure.
    Durability(DurableSessionError),
}

impl fmt::Display for DurableMissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Refused(_) => "durable mission request refused",
            Self::Durability(_) => "mission persistence requires inspection or reconciliation",
        })
    }
}
impl std::error::Error for DurableMissionError {}
impl From<MissionError> for DurableMissionError {
    fn from(value: MissionError) -> Self {
        Self::Refused(value)
    }
}
impl From<DurableSessionError> for DurableMissionError {
    fn from(value: DurableSessionError) -> Self {
        Self::Durability(value)
    }
}
type Result<T> = std::result::Result<T, DurableMissionError>;

#[derive(Clone, Debug)]
enum Command {
    Register(MissionPlanCriterion),
    Assess {
        mission_record_digest: ContentDigest,
        expected_head: ContentDigest,
        facts: MissionAssessmentFacts,
    },
}

impl Command {
    fn mission_record_digest(&self) -> ContentDigest {
        match self {
            Self::Register(criterion) => criterion.mission_record_digest,
            Self::Assess {
                mission_record_digest,
                ..
            } => *mission_record_digest,
        }
    }
}

impl DurableSessionStore {
    /// Read one already admitted session's current lifecycle for canonical projection.
    /// The supplied session must exactly equal persisted authority. This method checks time
    /// without advancing it and verifies the complete journal; it writes and charges nothing.
    pub fn mission_head_for_projection(
        &self,
        session: &AgentSession,
        now: TimestampNs,
    ) -> Result<Option<MissionRevision>> {
        if self.fenced {
            return Err(DurableSessionError::ReconciliationRequired.into());
        }
        check_projection_session(&self.memory, session, now)?;
        let report = read_report(self.path(), self.limits)?;
        if report.last_root() != self.committed_root()
            || report.committed_len() != self.journal.committed_len()
            || report.incomplete_tail().is_some()
        {
            return Err(DurableSessionError::RootMismatch.into());
        }
        let ceilings = self.coordination.as_ref().map(|state| state.limits);
        let restored = replay_all(&report, self.limits, ceilings)?;
        if restored
            .memory
            .checkpoint(self.limits.max_checkpoint_bytes)
            .map_err(DurableSessionError::from)?
            .digest()
            != self.checkpoint_digest
        {
            return Err(DurableSessionError::InvalidHistory.into());
        }
        check_projection_session(&restored.memory, session, now)?;
        // Legacy readers need no mutation grants or workspace just to establish that their
        // authenticated session has never enrolled an executable profile.
        if !restored.missions.retained().iter().any(|revision| {
            revision.criterion().session_id == session.session_id
                && revision.criterion().principal == session.principal_id
        }) {
            return Ok(None);
        }
        let revisions = restored
            .workspaces
            .as_ref()
            .ok_or(MissionError::ScopeMismatch)?
            .retained_revisions();
        let current = revisions
            .iter()
            .filter(|revision| revision.capsule().session_id == session.session_id)
            .max_by_key(|revision| revision.capsule().revision)
            .ok_or(MissionError::ScopeMismatch)?;
        let mission_record_digest = ContentDigest::parse(&current.capsule().objective_digest)
            .map_err(|_| MissionError::ScopeMismatch)?;
        require_workspace(
            restored.workspaces.as_ref(),
            &session.principal_id,
            &session.session_id,
            mission_record_digest,
        )?;
        let mut memory = restored.memory;
        Ok(restored.missions.head(
            &mut memory,
            &session.principal_id,
            &session.session_id,
            mission_record_digest,
            now,
        )?)
    }

    /// Enroll an explicit immutable PlanOutcomeV1 profile. An exact retry returns its current
    /// head without recreating an initial revision, extending a lease or refilling any budget.
    pub fn register_mission_plan(
        &mut self,
        principal: &PrincipalId,
        criterion: MissionPlanCriterion,
        now: TimestampNs,
    ) -> Result<MissionRevision> {
        let session = criterion.session_id.clone();
        self.mission_command(principal, &session, Command::Register(criterion), now)
    }

    /// Derive and commit one assessment against the exact expected immutable predecessor.
    /// The native caller must first verify every fact and the complete other-work inventory.
    /// No effect is issued; a failed/uncertain append withholds the result and fences this store.
    pub fn assess_mission_plan(
        &mut self,
        principal: &PrincipalId,
        session: &SessionId,
        mission_record_digest: ContentDigest,
        expected_head: ContentDigest,
        facts: MissionAssessmentFacts,
        now: TimestampNs,
    ) -> Result<MissionRevision> {
        self.mission_command(
            principal,
            session,
            Command::Assess {
                mission_record_digest,
                expected_head,
                facts,
            },
            now,
        )
    }

    /// Return the admitted current lifecycle. None is a legacy/prose-only mission, never success.
    pub fn mission_head(
        &mut self,
        principal: &PrincipalId,
        session: &SessionId,
        mission_record_digest: ContentDigest,
        now: TimestampNs,
    ) -> Result<Option<MissionRevision>> {
        Ok(self
            .mission_history(principal, session, mission_record_digest, now)?
            .pop())
    }

    /// Read complete bounded retained mission history under current live authority. Clock and
    /// expiry mutations are persisted before private details or a refusal are returned.
    pub fn mission_history(
        &mut self,
        principal: &PrincipalId,
        session: &SessionId,
        mission_record_digest: ContentDigest,
        now: TimestampNs,
    ) -> Result<Vec<MissionRevision>> {
        self.session(principal, session, now)?;
        // Admission must precede inspection of private workspace or mission metadata.
        admit_read(&mut self.memory.clone(), principal, session, now)?;
        let restored = self.read_mission_history()?;
        require_workspace(
            restored.workspaces.as_ref(),
            principal,
            session,
            mission_record_digest,
        )?;
        let mut memory = self.memory.clone();
        Ok(restored.missions.history(
            &mut memory,
            principal,
            session,
            mission_record_digest,
            now,
        )?)
    }

    fn mission_command(
        &mut self,
        principal: &PrincipalId,
        session: &SessionId,
        command: Command,
        now: TimestampNs,
    ) -> Result<MissionRevision> {
        self.session(principal, session, now)?;
        admit(&mut self.memory.clone(), principal, session, now)?;
        let restored = self.read_mission_history()?;
        require_workspace(
            restored.workspaces.as_ref(),
            principal,
            session,
            command.mission_record_digest(),
        )?;
        let mut state = restored.missions;
        let before_state = state.digest();
        let mut memory = self.memory.clone();
        let result = apply(&mut state, &mut memory, principal, session, &command, now)?;
        let after_state = state.digest();
        if before_state == after_state {
            return Ok(result);
        }
        let checkpoint = memory
            .checkpoint(self.limits.max_checkpoint_bytes)
            .map_err(DurableSessionError::from)?;
        if checkpoint.digest() != self.checkpoint_digest {
            self.fenced = true;
            return Err(DurableSessionError::InvalidHistory.into());
        }
        let payload = encode(&Record {
            principal: principal.clone(),
            session: session.clone(),
            now,
            session_digest: self.checkpoint_digest,
            before_state,
            after_state,
            command,
        })?;
        self.commit_candidate(PendingSession {
            memory,
            checkpoint,
            coordination: None,
            record: Some((MISSION_COMMAND_RECORD_KIND, payload)),
        })?;
        Ok(result)
    }

    fn read_mission_history(&mut self) -> Result<super::ReplayedSessionState> {
        self.preflight()?;
        let report = read_report(self.path(), self.limits)?;
        if report.last_root() != self.committed_root()
            || report.committed_len() != self.journal.committed_len()
            || report.incomplete_tail().is_some()
        {
            self.fenced = true;
            return Err(DurableSessionError::RootMismatch.into());
        }
        let ceilings = self.coordination.as_ref().map(|state| state.limits);
        let restored = match replay_all(&report, self.limits, ceilings) {
            Ok(restored) => restored,
            Err(error) => {
                self.fenced = true;
                return Err(error.into());
            }
        };
        if restored
            .memory
            .checkpoint(self.limits.max_checkpoint_bytes)
            .map_err(DurableSessionError::from)?
            .digest()
            != self.checkpoint_digest
        {
            self.fenced = true;
            return Err(DurableSessionError::InvalidHistory.into());
        }
        Ok(restored)
    }
}

fn check_projection_session(
    memory: &ReferenceSessionStore,
    session: &AgentSession,
    now: TimestampNs,
) -> Result<()> {
    let entry = memory
        .sessions
        .get(&session.session_id)
        .filter(|entry| entry.session.principal_id == session.principal_id && !entry.closed)
        .ok_or(MissionError::Session(
            crate::agent_session::ReferenceSessionError::Unavailable,
        ))?;
    if entry.session != *session {
        return Err(MissionError::ScopeMismatch.into());
    }
    // Reuse live read/clock/expiry predicates on an isolated clone, never renewing or
    // tombstoning the caller's store from a pure projection or requiring mutation grants.
    admit_read(
        &mut memory.clone(),
        &session.principal_id,
        &session.session_id,
        now,
    )?;
    Ok(())
}

fn require_workspace(
    workspaces: Option<&WorkspaceState>,
    principal: &PrincipalId,
    session: &SessionId,
    mission_record_digest: ContentDigest,
) -> Result<()> {
    let revisions = workspaces
        .ok_or(MissionError::ScopeMismatch)?
        .retained_revisions();
    let mut own = revisions
        .iter()
        .filter(|revision| revision.capsule().session_id == *session);
    let first = own.next().ok_or(MissionError::ScopeMismatch)?;
    let last = own.last().unwrap_or(first);
    let expected = mission_record_digest.to_text();
    if first.capsule().revision != 0
        || first.capsule().objective_digest != expected
        || last.capsule().objective_digest != expected
        || first.capsule().principal != principal.as_str()
        || last.capsule().principal != principal.as_str()
    {
        return Err(MissionError::ScopeMismatch.into());
    }
    Ok(())
}

fn apply(
    state: &mut ReferenceMissionStore,
    memory: &mut ReferenceSessionStore,
    principal: &PrincipalId,
    session: &SessionId,
    command: &Command,
    now: TimestampNs,
) -> std::result::Result<MissionRevision, MissionError> {
    match command {
        Command::Register(criterion) => {
            if criterion.session_id != *session {
                return Err(MissionError::ScopeMismatch);
            }
            state.register(memory, principal, criterion.clone(), now)
        }
        Command::Assess {
            mission_record_digest,
            expected_head,
            facts,
        } => state.assess(
            memory,
            principal,
            session,
            *mission_record_digest,
            *expected_head,
            facts.clone(),
            now,
        ),
    }
}

struct Record {
    principal: PrincipalId,
    session: SessionId,
    now: TimestampNs,
    session_digest: ContentDigest,
    before_state: ContentDigest,
    after_state: ContentDigest,
    command: Command,
}

fn encode(record: &Record) -> std::result::Result<Vec<u8>, DurableSessionError> {
    let mut e = CanonicalEncoder::new();
    e.text(RECORD_DOMAIN);
    e.text(record.principal.as_str());
    e.text(record.session.as_str());
    e.i128(record.now.0);
    e.digest(record.session_digest);
    e.digest(record.before_state);
    e.digest(record.after_state);
    match &record.command {
        Command::Register(criterion) => {
            e.tag(0);
            criterion.encode(&mut e);
        }
        Command::Assess {
            mission_record_digest,
            expected_head,
            facts,
        } => {
            e.tag(1);
            e.digest(*mission_record_digest);
            e.digest(*expected_head);
            facts.encode(&mut e);
        }
    }
    let bytes = e.finish_checked()?;
    if bytes.len() > MAX_COMMAND_BYTES {
        return Err(DurableSessionError::CapacityExceeded);
    }
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> std::result::Result<Record, DurableSessionError> {
    if bytes.len() > MAX_COMMAND_BYTES {
        return Err(DurableSessionError::CapacityExceeded);
    }
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != RECORD_DOMAIN {
        return Err(DurableSessionError::InvalidHistory);
    }
    let principal = PrincipalId::parse(text(&mut d)?)?;
    let session = SessionId::parse(text(&mut d)?)?;
    let now = TimestampNs(d.i128()?);
    let session_digest = d.digest()?;
    let before_state = d.digest()?;
    let after_state = d.digest()?;
    let command = match d.tag()? {
        0 => Command::Register(MissionPlanCriterion::decode(&mut d)?),
        1 => Command::Assess {
            mission_record_digest: d.digest()?,
            expected_head: d.digest()?,
            facts: MissionAssessmentFacts::decode(&mut d)?,
        },
        _ => return Err(DurableSessionError::InvalidHistory),
    };
    d.ensure_finished()?;
    let record = Record {
        principal,
        session,
        now,
        session_digest,
        before_state,
        after_state,
        command,
    };
    if encode(&record)? != bytes {
        return Err(DurableSessionError::InvalidHistory);
    }
    Ok(record)
}

pub(super) fn replay_command(
    bytes: &[u8],
    memory: &mut ReferenceSessionStore,
    state: &mut ReferenceMissionStore,
    workspaces: Option<&WorkspaceState>,
    limits: DurableSessionLimits,
) -> std::result::Result<(), DurableSessionError> {
    let record = decode(bytes)?;
    if memory.checkpoint(limits.max_checkpoint_bytes)?.digest() != record.session_digest
        || state.digest() != record.before_state
    {
        return Err(DurableSessionError::InvalidHistory);
    }
    // Authenticate before examining the private mission-record binding, exactly as on writes.
    admit(memory, &record.principal, &record.session, record.now)
        .map_err(|_| DurableSessionError::InvalidHistory)?;
    require_workspace(
        workspaces,
        &record.principal,
        &record.session,
        record.command.mission_record_digest(),
    )
    .map_err(|_| DurableSessionError::InvalidHistory)?;
    apply(
        state,
        memory,
        &record.principal,
        &record.session,
        &record.command,
        record.now,
    )
    .map_err(|_| DurableSessionError::InvalidHistory)?;
    if memory.checkpoint(limits.max_checkpoint_bytes)?.digest() != record.session_digest
        || state.digest() != record.after_state
        || record.before_state == record.after_state
    {
        return Err(DurableSessionError::InvalidHistory);
    }
    Ok(())
}

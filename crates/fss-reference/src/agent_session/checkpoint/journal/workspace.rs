#![forbid(unsafe_code)]
//! Workspace commands in the existing exclusive session journal (FSS-204).
//!
//! A command records one sealed revision and both pre/post state identities. Recovery runs the
//! same workspace admission code against the preceding session and workspace state; snapshots
//! supplied by a writer cannot replace unrelated history. No source/effect authority is created.

use std::fmt;

use fss_core::{
    CanonicalDecoder, CanonicalEncoder, ContentDigest, PrincipalId, SessionId, TimestampNs,
};

use super::{
    DurableSessionError, DurableSessionLimits, DurableSessionStore, PendingSession,
    ReferenceSessionStore, SessionCheckpoint, read_report, replay_all,
};
use crate::agent_session::workspace::checkpoint::{
    MAX_WORKSPACE_CHECKPOINT_BYTES, decode_revision,
};
use crate::agent_session::workspace::{
    MAX_WORKSPACE_REVISION_BYTES, ReferenceWorkspaceStore, WorkspaceError, WorkspaceLimits,
    WorkspaceResume, WorkspaceRevision, WorkspaceWrite, WorkspaceWriteMode,
};

/// Atomic refresh/rebase commands on the same session journal.
pub mod rebase;

/// One-way workspace-store initialization; a second initialization is invalid history.
pub const WORKSPACE_INIT_RECORD_KIND: u16 = 0x5753;
/// A replayable workspace write, atomically advancing the session clock and workspace history.
pub const WORKSPACE_WRITE_RECORD_KIND: u16 = 0x5754;
const INIT_DOMAIN: &str = "fss.reference_workspace_journal_init.v1";
const WRITE_DOMAIN: &str = "fss.reference_workspace_journal_write.v1";
const MAX_RECORD_BYTES: usize = MAX_WORKSPACE_REVISION_BYTES + 1024;

/// Failures distinguish a normal workspace refusal from withheld, possibly committed persistence.
#[derive(Debug)]
pub enum DurableWorkspaceError {
    /// The workspace/session owner refused; any clock or expiry change was committed first.
    Refused(WorkspaceError),
    /// Journal admission, integrity, or uncertain persistence requires recovery before retry.
    Durability(DurableSessionError),
    /// The runtime has not initialized a workspace store in this journal.
    NotInitialized,
    /// Initialized limits cannot be changed or reset by another initialization request.
    LimitsMismatch,
}

impl fmt::Display for DurableWorkspaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Refused(_) => "durable workspace request refused",
            Self::Durability(_) => "workspace persistence requires inspection or reconciliation",
            Self::NotInitialized => "durable workspace store not initialized",
            Self::LimitsMismatch => "durable workspace limits differ from initialization",
        })
    }
}
impl std::error::Error for DurableWorkspaceError {}
impl From<DurableSessionError> for DurableWorkspaceError {
    fn from(error: DurableSessionError) -> Self {
        Self::Durability(error)
    }
}

/// An ordinary workspace result released only after its associated session mutation is durable.
/// The journal root must be pinned independently; none of these digests is a bearer capability.
#[derive(Clone, Debug, PartialEq)]
pub struct JournaledWorkspace<T> {
    /// Existing workspace semantic result; no transport-specific payload dialect.
    pub result: T,
    /// Joint committed journal root, including earlier disclosure/coordination records.
    pub committed_root: ContentDigest,
    /// Complete session checkpoint at that root, including clock watermarks and charges.
    pub session_checkpoint_digest: ContentDigest,
    /// Complete immutable workspace history at that root, not only the returned revision.
    pub workspace_checkpoint_digest: ContentDigest,
}

#[derive(Clone, Debug)]
pub(super) struct WorkspaceState {
    store: ReferenceWorkspaceStore,
    requested_limits: WorkspaceLimits,
    digest: ContentDigest,
}

impl WorkspaceState {
    fn new(limits: WorkspaceLimits) -> Result<Self, DurableSessionError> {
        let store = ReferenceWorkspaceStore::with_limits(limits);
        let digest = checkpoint_digest(&store)?;
        Ok(Self {
            store,
            requested_limits: limits,
            digest,
        })
    }
}

impl DurableSessionStore {
    /// Enables bounded workspace persistence exactly once on this exclusive runtime-owned journal.
    /// Equal requested limits are an idempotent retry; different limits cannot reset history.
    /// The reference workspace owner applies its hard ceilings even to larger requested values.
    pub fn initialize_workspaces(
        &mut self,
        limits: WorkspaceLimits,
    ) -> Result<ContentDigest, DurableWorkspaceError> {
        if let Some(existing) = self.read_workspace_state()? {
            if existing.requested_limits != limits {
                return Err(DurableWorkspaceError::LimitsMismatch);
            }
            return Ok(self.committed_root());
        }
        let state = WorkspaceState::new(limits)?;
        let payload = encode_init(self.checkpoint_digest, limits, state.digest)?;
        let checkpoint = self.workspace_session_checkpoint(&self.memory.clone())?;
        self.commit_candidate(PendingSession {
            memory: self.memory.clone(),
            checkpoint,
            coordination: None,
            record: Some((WORKSPACE_INIT_RECORD_KIND, payload)),
        })?;
        Ok(self.committed_root())
    }

    /// Publishes one immutable revision and its session watermark in one synchronized record.
    /// Exact retries reuse history and never rewind its head. A failed append withholds the
    /// revision and fences the shared session owner, including reads and disclosure operations.
    pub fn publish_workspace(
        &mut self,
        principal: &PrincipalId,
        request: WorkspaceWrite,
        now: TimestampNs,
    ) -> Result<JournaledWorkspace<WorkspaceRevision>, DurableWorkspaceError> {
        let mut state = self
            .read_workspace_state()?
            .ok_or(DurableWorkspaceError::NotInitialized)?;
        let before = state.digest;
        let mode = request.mode;
        let mut memory = self.memory.clone();
        let result = state.store.publish(&mut memory, principal, request, now);
        let checkpoint = self.workspace_session_checkpoint(&memory)?;
        let revision = match result {
            Ok(revision) => revision,
            Err(error) => {
                return self.finish_workspace_read(memory, checkpoint, before, Err(error));
            }
        };
        state.digest = match checkpoint_digest(&state.store) {
            Ok(digest) => digest,
            Err(error) => {
                self.fenced = true;
                return Err(error.into());
            }
        };
        if state.digest == before && checkpoint.digest() == self.checkpoint_digest {
            return Ok(self.workspace_result(revision, state.digest));
        }
        let payload = match encode_write(
            self.checkpoint_digest,
            before,
            checkpoint.digest(),
            state.digest,
            mode,
            now,
            revision.as_bytes(),
        ) {
            Ok(payload) => payload,
            Err(error) => {
                self.fenced = true;
                return Err(error.into());
            }
        };
        self.commit_candidate(PendingSession {
            memory,
            checkpoint,
            coordination: None,
            record: Some((WORKSPACE_WRITE_RECORD_KIND, payload)),
        })?;
        Ok(self.workspace_result(revision, state.digest))
    }

    /// Returns only an exact, currently authorized revision, persisting clock/expiry changes even
    /// on refusal. Supersession and rebase flags remain those of the existing workspace owner.
    pub fn resume_workspace(
        &mut self,
        principal: &PrincipalId,
        session: &SessionId,
        revision: ContentDigest,
        now: TimestampNs,
    ) -> Result<JournaledWorkspace<WorkspaceResume>, DurableWorkspaceError> {
        let state = self
            .read_workspace_state()?
            .ok_or(DurableWorkspaceError::NotInitialized)?;
        let mut memory = self.memory.clone();
        let result = state
            .store
            .resume(&mut memory, principal, session, revision, now);
        let checkpoint = self.workspace_session_checkpoint(&memory)?;
        self.finish_workspace_read(memory, checkpoint, state.digest, result)
    }

    /// Returns the current head revision of `session`, persisting clock/expiry changes even on
    /// refusal, exactly as [`Self::resume_workspace`] does for a named revision.
    pub fn workspace_head(
        &mut self,
        principal: &PrincipalId,
        session: &SessionId,
        now: TimestampNs,
    ) -> Result<JournaledWorkspace<WorkspaceResume>, DurableWorkspaceError> {
        let state = self
            .read_workspace_state()?
            .ok_or(DurableWorkspaceError::NotInitialized)?;
        let mut memory = self.memory.clone();
        let result = state.store.head(&mut memory, principal, session, now);
        let checkpoint = self.workspace_session_checkpoint(&memory)?;
        self.finish_workspace_read(memory, checkpoint, state.digest, result)
    }

    fn workspace_result<T>(
        &self,
        result: T,
        workspace_checkpoint_digest: ContentDigest,
    ) -> JournaledWorkspace<T> {
        JournaledWorkspace {
            result,
            committed_root: self.committed_root(),
            session_checkpoint_digest: self.checkpoint_digest,
            workspace_checkpoint_digest,
        }
    }

    fn finish_workspace_read<T>(
        &mut self,
        memory: ReferenceSessionStore,
        checkpoint: SessionCheckpoint,
        digest: ContentDigest,
        result: Result<T, WorkspaceError>,
    ) -> Result<JournaledWorkspace<T>, DurableWorkspaceError> {
        if checkpoint.digest() != self.checkpoint_digest {
            self.commit_candidate(PendingSession {
                memory,
                checkpoint,
                coordination: None,
                record: None,
            })?;
        }
        result
            .map(|result| self.workspace_result(result, digest))
            .map_err(DurableWorkspaceError::Refused)
    }

    fn workspace_session_checkpoint(
        &mut self,
        memory: &ReferenceSessionStore,
    ) -> Result<SessionCheckpoint, DurableWorkspaceError> {
        match memory.checkpoint(self.limits.max_checkpoint_bytes) {
            Ok(checkpoint) => Ok(checkpoint),
            Err(error) => {
                self.fenced = true;
                Err(DurableSessionError::from(error).into())
            }
        }
    }

    // Rebuild under the same exact journal pin; there is no independent mutable workspace owner.
    // Full bounded replay is deliberate reference behavior, not a production performance claim.
    fn read_workspace_state(&mut self) -> Result<Option<WorkspaceState>, DurableWorkspaceError> {
        self.preflight()?;
        let result = (|| -> Result<_, DurableSessionError> {
            let report = read_report(self.path(), self.limits)?;
            if report.last_root() != self.committed_root()
                || report.incomplete_tail().is_some()
                || report.committed_len() != self.journal.committed_len()
                || report.records().len() != self.records
            {
                return Err(DurableSessionError::RootMismatch);
            }
            let restored = replay_all(
                &report,
                self.limits,
                self.coordination.as_ref().map(|state| state.limits),
            )?;
            if restored
                .memory
                .checkpoint(self.limits.max_checkpoint_bytes)?
                .digest()
                != self.checkpoint_digest
            {
                return Err(DurableSessionError::RootMismatch);
            }
            Ok(restored.workspaces)
        })();
        match result {
            Ok(state) => Ok(state),
            Err(error) => {
                self.fenced = true;
                Err(error.into())
            }
        }
    }
}

fn checkpoint_digest(
    store: &ReferenceWorkspaceStore,
) -> Result<ContentDigest, DurableSessionError> {
    store
        .checkpoint(MAX_WORKSPACE_CHECKPOINT_BYTES)
        .map(|checkpoint| checkpoint.digest())
        .map_err(|_| DurableSessionError::InvalidHistory)
}

fn encode_init(
    before: ContentDigest,
    limits: WorkspaceLimits,
    workspace: ContentDigest,
) -> Result<Vec<u8>, DurableSessionError> {
    let mut e = CanonicalEncoder::new();
    e.text(INIT_DOMAIN);
    e.digest(before);
    for value in [
        limits.max_workspaces,
        limits.max_revisions_per_workspace,
        limits.max_revision_bytes,
        limits.max_history_bytes,
    ] {
        e.u64(u64::try_from(value).map_err(|_| DurableSessionError::CapacityExceeded)?);
    }
    e.digest(workspace);
    Ok(e.finish_checked()?)
}

fn count(d: &mut CanonicalDecoder<'_>) -> Result<usize, DurableSessionError> {
    usize::try_from(d.u64()?).map_err(|_| DurableSessionError::CapacityExceeded)
}

pub(super) fn replay_initialization(
    payload: &[u8],
    sessions: &ReferenceSessionStore,
    history: &mut Option<WorkspaceState>,
    limits: DurableSessionLimits,
) -> Result<(), DurableSessionError> {
    if history.is_some() || payload.len() > 1024 {
        return Err(DurableSessionError::InvalidHistory);
    }
    let mut d = CanonicalDecoder::new(payload);
    if d.text()? != INIT_DOMAIN {
        return Err(DurableSessionError::InvalidHistory);
    }
    let before = d.digest()?;
    let requested = WorkspaceLimits {
        max_workspaces: count(&mut d)?,
        max_revisions_per_workspace: count(&mut d)?,
        max_revision_bytes: count(&mut d)?,
        max_history_bytes: count(&mut d)?,
    };
    let digest = d.digest()?;
    d.ensure_finished()?;
    let state = WorkspaceState::new(requested)?;
    if before != sessions.checkpoint(limits.max_checkpoint_bytes)?.digest()
        || digest != state.digest
        || encode_init(before, requested, digest)? != payload
    {
        return Err(DurableSessionError::InvalidHistory);
    }
    *history = Some(state);
    Ok(())
}

#[allow(clippy::too_many_arguments)] // distinct pre/post commitments are not interchangeable
fn encode_write(
    before_sessions: ContentDigest,
    before_workspaces: ContentDigest,
    after_sessions: ContentDigest,
    after_workspaces: ContentDigest,
    mode: WorkspaceWriteMode,
    now: TimestampNs,
    revision: &[u8],
) -> Result<Vec<u8>, DurableSessionError> {
    if revision.len() > MAX_WORKSPACE_REVISION_BYTES {
        return Err(DurableSessionError::CapacityExceeded);
    }
    let mut e = CanonicalEncoder::new();
    e.text(WRITE_DOMAIN);
    for digest in [
        before_sessions,
        before_workspaces,
        after_sessions,
        after_workspaces,
    ] {
        e.digest(digest);
    }
    e.u8(match mode {
        WorkspaceWriteMode::Advance => 0,
        WorkspaceWriteMode::Rebase => 1,
    });
    e.i128(now.0);
    e.bytes(revision);
    let bytes = e.finish_checked()?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(DurableSessionError::CapacityExceeded);
    }
    Ok(bytes)
}

pub(super) fn replay_write(
    payload: &[u8],
    sessions: &mut ReferenceSessionStore,
    history: &mut Option<WorkspaceState>,
    limits: DurableSessionLimits,
) -> Result<(), DurableSessionError> {
    if rebase::is_record(payload) {
        return rebase::replay_rebase(payload, sessions, history, limits);
    }
    if payload.len() > MAX_RECORD_BYTES {
        return Err(DurableSessionError::CapacityExceeded);
    }
    let state = history
        .as_mut()
        .ok_or(DurableSessionError::InvalidHistory)?;
    let mut d = CanonicalDecoder::new(payload);
    if d.text()? != WRITE_DOMAIN {
        return Err(DurableSessionError::InvalidHistory);
    }
    let before_sessions = d.digest()?;
    let before_workspaces = d.digest()?;
    let after_sessions = d.digest()?;
    let after_workspaces = d.digest()?;
    let mode = match d.u8()? {
        0 => WorkspaceWriteMode::Advance,
        1 => WorkspaceWriteMode::Rebase,
        _ => return Err(DurableSessionError::InvalidHistory),
    };
    let now = TimestampNs(d.i128()?);
    let raw = d.bytes()?;
    d.ensure_finished()?;
    if before_sessions != sessions.checkpoint(limits.max_checkpoint_bytes)?.digest()
        || before_workspaces != state.digest
    {
        return Err(DurableSessionError::InvalidHistory);
    }
    let recorded = decode_revision(raw, state.requested_limits)
        .map_err(|_| DurableSessionError::InvalidHistory)?;
    let principal = PrincipalId::parse(&recorded.capsule().principal)?;
    let revision = state
        .store
        .publish(
            sessions,
            &principal,
            WorkspaceWrite {
                expected_head: recorded.parent_digest(),
                capsule: recorded.capsule().clone(),
                mode,
            },
            now,
        )
        .map_err(|_| DurableSessionError::InvalidHistory)?;
    state.digest = checkpoint_digest(&state.store)?;
    if revision.as_bytes() != raw
        || state.digest != after_workspaces
        || sessions.checkpoint(limits.max_checkpoint_bytes)?.digest() != after_sessions
        || encode_write(
            before_sessions,
            before_workspaces,
            after_sessions,
            after_workspaces,
            mode,
            now,
            raw,
        )? != payload
    {
        return Err(DurableSessionError::InvalidHistory);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

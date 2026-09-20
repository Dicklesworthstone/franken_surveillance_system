#![forbid(unsafe_code)]
//! Workspace lifecycle on the same exclusive owner as evidence disclosure.

use fss_core::{ContentDigest, PrincipalId, SessionId, TimestampNs};

use super::DurableDisclosureStore;
use crate::agent_session::SessionRefresh;
use crate::agent_session::checkpoint::journal::workspace::{DurableWorkspaceError, JournaledWorkspace};
use crate::agent_session::workspace::{WorkspaceLimits, WorkspaceResume, WorkspaceRevision, WorkspaceWrite};

impl DurableDisclosureStore {
    /// Initializes workspace history in this owner's existing journal, without changing cursors.
    /// No second session handle is opened and no mutable session/catalog authority is exposed.
    pub fn initialize_workspaces(&mut self, limits: WorkspaceLimits)
        -> Result<ContentDigest, DurableWorkspaceError>
    {
        self.sessions.initialize_workspaces(limits)
    }

    /// Publishes a workspace revision together with session-clock/expiry state. Existing source
    /// charges and issued/consumed hydration cursors remain in the same verified journal history.
    /// Any uncertain workspace append fences evidence disclosure too, until reconciliation.
    pub fn publish_workspace(&mut self, principal: &PrincipalId, request: WorkspaceWrite, now: TimestampNs)
        -> Result<JournaledWorkspace<WorkspaceRevision>, DurableWorkspaceError>
    {
        self.sessions.publish_workspace(principal, request, now)
    }

    /// Restores an exact authorized workspace without refunding evidence reads or reviving cursors.
    /// Refused reads retain the underlying session owner's durable clock and expiry semantics.
    pub fn resume_workspace(&mut self, principal: &PrincipalId, session: &SessionId,
        revision: ContentDigest, now: TimestampNs)
        -> Result<JournaledWorkspace<WorkspaceResume>, DurableWorkspaceError>
    {
        self.sessions.resume_workspace(principal, session, revision, now)
    }

    /// Atomically refreshes the authority anchor and rebases its workspace, without rebinding
    /// any descriptor or continuation. Old context/alias reads must still pass normal freshness
    /// checks; a rebase cannot turn an old evidence handle into an implicit latest handle.
    pub fn rebase_workspace(&mut self, principal: &PrincipalId, refresh: SessionRefresh,
        request: WorkspaceWrite, now: TimestampNs)
        -> Result<JournaledWorkspace<WorkspaceRevision>, DurableWorkspaceError>
    {
        self.sessions.rebase_workspace(principal, refresh, request, now)
    }
}

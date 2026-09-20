#![forbid(unsafe_code)]
//! All-or-nothing session refresh and workspace rebase, including lost-acknowledgement recovery.
//!
//! Failed rebases keep only the observed session clock/expiry transition. They never leave a
//! changed anchor, narrowed grants, rotated symbols, or a half-published workspace behind.

use std::collections::BTreeSet;

use fss_core::{CanonicalDecode, CanonicalEncode, LedgerAnchor};

use super::*;
use crate::agent_session::SessionRefresh;

const DOMAIN: &str = "fss.reference_workspace_journal_rebase.v1";
const MAX_REBASE_RECORD_BYTES: usize = 2 * MAX_WORKSPACE_REVISION_BYTES + 16 * 1024;
const MAX_REFRESH_GRANTS: usize = 8192;

impl DurableSessionStore {
    /// Moves the live session and its immutable workspace to one new authority anchor atomically.
    ///
    /// The runtime verifies the supplied anchor; this method neither authenticates that authority
    /// nor accepts a capsule as evidence. Existing refresh CAS/grant narrowing and workspace
    /// preservation rules run before persistence. Any semantic refusal leaves the old anchor,
    /// symbol generation, grants, and workspace intact, while retaining clock/expiry observations.
    ///
    /// An exact retry of a committed command recovers its revision under today's live grants. It
    /// does not rerun the old refresh, restore revoked authority, or rewind a newer session/head.
    /// A different refresh paired with the same capsule is not an exact retry.
    pub fn rebase_workspace(
        &mut self,
        principal: &PrincipalId,
        refresh: SessionRefresh,
        request: WorkspaceWrite,
        now: TimestampNs,
    ) -> Result<JournaledWorkspace<WorkspaceRevision>, DurableWorkspaceError> {
        let mut state = self.read_workspace_state()?.ok_or(DurableWorkspaceError::NotInitialized)?;
        let before_workspace = state.digest;
        let mut observed = self.memory.clone();
        let session_id = &request.capsule.session_id;
        let observed_session = match observed.session(principal, session_id, now) {
            Ok(session) => session,
            Err(error) => {
                let checkpoint = self.workspace_session_checkpoint(&observed)?;
                return self.finish_workspace_read(observed, checkpoint, before_workspace, Err(error.into()));
            }
        };
        if request.mode != WorkspaceWriteMode::Rebase {
            let checkpoint = self.workspace_session_checkpoint(&observed)?;
            return self.finish_workspace_read(observed, checkpoint, before_workspace, Err(WorkspaceError::InvalidAnchor));
        }
        // A retry is established by the whole previously committed command, not by a stale CAS
        // exception or a matching revision number. Lookup happens only after live authorization.
        let retry = match self.find_rebase_retry(&state, &refresh, &request) {
            Ok(retry) => retry,
            Err(error) => { self.fenced = true; return Err(error.into()); }
        };
        if let Some(digest) = retry {
            let result = state.store.resume(&mut observed, principal, session_id, digest, now)
                .map(|resumed| resumed.revision);
            let checkpoint = self.workspace_session_checkpoint(&observed)?;
            return self.finish_workspace_read(observed, checkpoint, before_workspace, result);
        }
        if refresh.current_anchor == observed_session.current_anchor
            || request.capsule.current_anchor != refresh.current_anchor
        {
            let checkpoint = self.workspace_session_checkpoint(&observed)?;
            return self.finish_workspace_read(observed, checkpoint, before_workspace, Err(WorkspaceError::InvalidAnchor));
        }
        let mut candidate = observed.clone();
        let outcome = candidate.refresh(principal, session_id, refresh.clone(), now)
            .map_err(WorkspaceError::from)
            .and_then(|_| state.store.publish(&mut candidate, principal, request, now));
        let revision = match outcome {
            Ok(revision) => revision,
            Err(error) => {
                // Discard ALL staged refresh mutations, not only the workspace candidate.
                let checkpoint = self.workspace_session_checkpoint(&observed)?;
                return self.finish_workspace_read(observed, checkpoint, before_workspace, Err(error));
            }
        };
        let checkpoint = self.workspace_session_checkpoint(&candidate)?;
        let prepared = (|| -> Result<_, DurableSessionError> {
            let after_workspace = checkpoint_digest(&state.store)?;
            if after_workspace == before_workspace { return Err(DurableSessionError::InvalidHistory); }
            let record = RebaseRecord {
                before_session: self.checkpoint_digest, before_workspace,
                after_session: checkpoint.digest(), after_workspace,
                refresh, observed_at: now, revision: revision.as_bytes(),
            };
            Ok((record.encode(self.limits)?, after_workspace))
        })();
        let (payload, after_workspace) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => { self.fenced = true; return Err(error.into()); }
        };
        self.commit_candidate(PendingSession {
            memory: candidate, checkpoint, coordination: None,
            record: Some((WORKSPACE_WRITE_RECORD_KIND, payload)),
        })?;
        Ok(self.workspace_result(revision, after_workspace))
    }

    fn find_rebase_retry(&self, state: &WorkspaceState, refresh: &SessionRefresh, request: &WorkspaceWrite)
        -> Result<Option<ContentDigest>, DurableSessionError>
    {
        let report = read_report(self.path(), self.limits)?;
        if report.last_root() != self.committed_root() || report.incomplete_tail().is_some()
            || report.committed_len() != self.journal.committed_len()
        { return Err(DurableSessionError::RootMismatch); }
        for record in report.records() {
            if record.kind() != WORKSPACE_WRITE_RECORD_KIND || !is_record(record.payload()) { continue; }
            let saved = RebaseRecord::decode(record.payload(), self.limits)?;
            if !same_refresh(&saved.refresh, refresh) { continue; }
            let revision = decode_revision(saved.revision, state.requested_limits)
                .map_err(|_| DurableSessionError::InvalidHistory)?;
            if revision.capsule() == &request.capsule && revision.parent_digest() == request.expected_head {
                return Ok(Some(revision.digest()));
            }
        }
        Ok(None)
    }
}

pub(super) fn is_record(payload: &[u8]) -> bool {
    let mut prefix = CanonicalEncoder::new(); prefix.text(DOMAIN);
    payload.starts_with(&prefix.finish())
}

fn same_refresh(left: &SessionRefresh, right: &SessionRefresh) -> bool {
    left.expected_session_digest == right.expected_session_digest
        && left.current_anchor == right.current_anchor
        && left.capabilities == right.capabilities
        && left.privacy_scope == right.privacy_scope
}

struct RebaseRecord<'a> {
    before_session: ContentDigest,
    before_workspace: ContentDigest,
    after_session: ContentDigest,
    after_workspace: ContentDigest,
    refresh: SessionRefresh,
    observed_at: TimestampNs,
    revision: &'a [u8],
}

impl<'a> RebaseRecord<'a> {
    fn encode(&self, limits: DurableSessionLimits) -> Result<Vec<u8>, DurableSessionError> {
        if self.revision.len() > MAX_WORKSPACE_REVISION_BYTES { return Err(DurableSessionError::CapacityExceeded); }
        let count = self.refresh.capabilities.len().checked_add(self.refresh.privacy_scope.len())
            .ok_or(DurableSessionError::CapacityExceeded)?;
        let bytes = self.refresh.capabilities.iter().chain(&self.refresh.privacy_scope)
            .try_fold(0_usize, |sum, grant| sum.checked_add(grant.len()))
            .ok_or(DurableSessionError::CapacityExceeded)?;
        if count > limits.sessions.max_grants_per_session.min(MAX_REFRESH_GRANTS)
            || bytes > limits.sessions.max_grant_bytes_per_session.min(MAX_WORKSPACE_REVISION_BYTES)
        { return Err(DurableSessionError::CapacityExceeded); }
        let mut e = CanonicalEncoder::new(); e.text(DOMAIN);
        for digest in [self.before_session, self.before_workspace, self.after_session, self.after_workspace,
            self.refresh.expected_session_digest] { e.digest(digest); }
        self.refresh.current_anchor.encode_canonical(&mut e);
        for grants in [&self.refresh.capabilities, &self.refresh.privacy_scope] {
            e.u64(u64::try_from(grants.len()).map_err(|_| DurableSessionError::CapacityExceeded)?);
            for grant in grants { e.text(grant); }
        }
        e.i128(self.observed_at.0); e.bytes(self.revision);
        let bytes = e.finish_checked()?;
        if bytes.len() > MAX_REBASE_RECORD_BYTES { return Err(DurableSessionError::CapacityExceeded); }
        Ok(bytes)
    }

    fn decode(payload: &'a [u8], limits: DurableSessionLimits) -> Result<Self, DurableSessionError> {
        if payload.len() > MAX_REBASE_RECORD_BYTES { return Err(DurableSessionError::CapacityExceeded); }
        let mut d = CanonicalDecoder::new(payload);
        if d.text()? != DOMAIN { return Err(DurableSessionError::InvalidHistory); }
        let before_session = d.digest()?; let before_workspace = d.digest()?;
        let after_session = d.digest()?; let after_workspace = d.digest()?;
        let expected_session_digest = d.digest()?;
        let current_anchor = LedgerAnchor::decode_canonical(&mut d)?;
        let mut count = limits.sessions.max_grants_per_session.min(MAX_REFRESH_GRANTS);
        let mut bytes = limits.sessions.max_grant_bytes_per_session.min(MAX_WORKSPACE_REVISION_BYTES);
        let capabilities = grants(&mut d, &mut count, &mut bytes)?;
        let privacy_scope = grants(&mut d, &mut count, &mut bytes)?;
        let observed_at = TimestampNs(d.i128()?); let revision = d.bytes()?; d.ensure_finished()?;
        let record = Self { before_session, before_workspace, after_session, after_workspace,
            refresh: SessionRefresh { expected_session_digest, current_anchor, capabilities, privacy_scope },
            observed_at, revision };
        if record.encode(limits)? != payload { return Err(DurableSessionError::InvalidHistory); }
        Ok(record)
    }
}

fn grants(d: &mut CanonicalDecoder<'_>, remaining_count: &mut usize, remaining_bytes: &mut usize)
    -> Result<BTreeSet<String>, DurableSessionError>
{
    let count = usize::try_from(d.u64()?).map_err(|_| DurableSessionError::CapacityExceeded)?;
    *remaining_count = remaining_count.checked_sub(count).ok_or(DurableSessionError::CapacityExceeded)?;
    let mut result = BTreeSet::new();
    for _ in 0..count {
        let text = d.text()?;
        *remaining_bytes = remaining_bytes.checked_sub(text.len()).ok_or(DurableSessionError::CapacityExceeded)?;
        if result.last().is_some_and(|old: &String| old.as_str() >= text) {
            return Err(DurableSessionError::InvalidHistory);
        }
        result.insert(text.to_owned());
    }
    Ok(result)
}

pub(in crate::agent_session::checkpoint::journal) fn replay_rebase(payload: &[u8], sessions: &mut ReferenceSessionStore,
    history: &mut Option<WorkspaceState>, limits: DurableSessionLimits) -> Result<(), DurableSessionError>
{
    let record = RebaseRecord::decode(payload, limits)?;
    let state = history.as_mut().ok_or(DurableSessionError::InvalidHistory)?;
    if record.before_session != sessions.checkpoint(limits.max_checkpoint_bytes)?.digest()
        || record.before_workspace != state.digest || record.before_workspace == record.after_workspace
    { return Err(DurableSessionError::InvalidHistory); }
    let saved = decode_revision(record.revision, state.requested_limits).map_err(|_| DurableSessionError::InvalidHistory)?;
    let principal = PrincipalId::parse(&saved.capsule().principal)?;
    let observed = sessions.session(&principal, &saved.capsule().session_id, record.observed_at)
        .map_err(|_| DurableSessionError::InvalidHistory)?;
    if observed.current_anchor == record.refresh.current_anchor
        || saved.capsule().current_anchor != record.refresh.current_anchor
    { return Err(DurableSessionError::InvalidHistory); }
    sessions.refresh(&principal, &saved.capsule().session_id, record.refresh, record.observed_at)
        .map_err(|_| DurableSessionError::InvalidHistory)?;
    let result = state.store.publish(sessions, &principal, WorkspaceWrite {
        capsule: saved.capsule().clone(), expected_head: saved.parent_digest(), mode: WorkspaceWriteMode::Rebase,
    }, record.observed_at).map_err(|_| DurableSessionError::InvalidHistory)?;
    state.digest = checkpoint_digest(&state.store)?;
    if result.as_bytes() != record.revision || state.digest != record.after_workspace
        || sessions.checkpoint(limits.max_checkpoint_bytes)?.digest() != record.after_session
    { return Err(DurableSessionError::InvalidHistory); }
    Ok(())
}

#[cfg(test)]
mod tests;

#![forbid(unsafe_code)]
//! Work-claim commands committed in the SAME journal as their session authority.
//!
//! Recovery re-executes the reference coordinator and compares exact response and session-state
//! fingerprints. Serialized owners, fences, and results are never adopted as authority. These
//! private reference records are not another public `fss/1` operation or a canonical world ledger.

use std::path::Path;

use fss_core::{ContentDigest, PrincipalId, SessionId, TimestampNs};

use crate::agent_session::ReferenceSessionStore;
use crate::agent_session::work_claims::{
    ReferenceWorkClaimStore, WorkClaimError, WorkClaimLimits, WorkClaimRecovery, WorkClaimRequest,
    WorkClaimRevision, WorkClaimUpdate,
};
use super::{
    DurableSessionError, DurableSessionLimits, DurableSessionStore, PendingSession,
    SessionJournalInspection,
};

mod codec;
mod recovery;

/// Session-admitted case lifecycle with immutable evidence-preserving revisions.
pub mod investigations;

pub use recovery::SessionRecoveryReceipt;

/// One-way initialization of bounded coordination within an existing session journal.
pub const COORDINATION_INIT_RECORD_KIND: u16 = 0x5749;
/// Replayable coordination command, session-state witnesses, and exact outcome fingerprint.
pub const COORDINATION_COMMAND_RECORD_KIND: u16 = 0x5743;
/// Hard bound on a complete private command record, independent of configured journal capacity.
pub const MAX_COORDINATION_RECORD_BYTES: usize = 1024 * 1024;

/// Typed reference coordination request. Principal, session, and time come from the runtime.
///
/// The digest in a mutation is a precondition, not permission. Domain capability/privacy/basis
/// checks still occur inside the owning reference state machine before a revision is returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoordinationCommand {
    /// Reserve an already compiled, authorized, exact work scope.
    Acquire(WorkClaimRequest),
    /// Inspect the current authorized head without extending its lease.
    Inspect {
        /// Stable claim identity.
        claim_id: String,
    },
    /// Read a retained audit revision, never restore it as the current writer.
    InspectRevision {
        /// Stable claim identity.
        claim_id: String,
        /// Exact historical revision.
        revision: ContentDigest,
    },
    /// Change the live owner's exact current revision.
    Update {
        /// Stable claim identity.
        claim_id: String,
        /// Full revision CAS precondition.
        expected: ContentDigest,
        /// Typed update; cannot supply a replacement owner or fence.
        change: WorkClaimUpdate,
    },
    /// Explicitly expire, transfer, or reclaim through the same authority checks as live work.
    Recover {
        /// Stable claim identity.
        claim_id: String,
        /// Full revision CAS precondition.
        expected: ContentDigest,
        /// Typed recovery request; never settles an external effect obligation.
        recovery: WorkClaimRecovery,
    },
}

#[derive(Debug)]
pub(super) struct CoordinationState {
    pub(super) claims: ReferenceWorkClaimStore,
    pub(super) limits: WorkClaimLimits,
    pub(super) cases: Option<investigations::ReferenceInvestigationStore>,
}

impl CoordinationState {
    fn fork(&self) -> Self {
        Self { claims: self.claims.fork_for_transaction(), limits: self.limits, cases: self.cases.clone() }
    }
}

impl DurableSessionStore {
    /// Enables coordination once and commits its exact ceilings before acknowledging success.
    ///
    /// An identical retry is a no-op; a different limit set or reset is refused. Existing session
    /// checkpoints remain readable, but old session-only readers MUST reject the new record kinds.
    /// Call only through the trusted, exclusive journal owner, not a raw agent transport.
    pub fn enable_coordination(&mut self, limits: WorkClaimLimits) -> Result<(), DurableSessionError> {
        self.preflight()?;
        if let Some(existing) = &self.coordination {
            return if existing.limits == limits { Ok(()) } else { Err(DurableSessionError::InvalidHistory) };
        }
        let checkpoint = self.memory.checkpoint(self.limits.max_checkpoint_bytes)?;
        let payload = codec::encode_initialization(limits, checkpoint.digest())?;
        self.commit_candidate(PendingSession {
            memory: self.memory.clone(), checkpoint,
            coordination: Some(CoordinationState {
                claims: ReferenceWorkClaimStore::with_limits(limits), limits, cases: None,
            }),
            record: Some((COORDINATION_INIT_RECORD_KIND, payload)),
        })
    }

    /// Opens exact existing session AND claim history under independently supplied ceilings.
    ///
    /// Never initializes missing coordination state, repairs a tail, changes stored limits, or
    /// trusts a root found in the same file. The runtime must protect and independently pin roots.
    pub fn open_existing_with_coordination(
        path: impl AsRef<Path>, expected_root: ContentDigest, limits: DurableSessionLimits,
        claim_ceilings: WorkClaimLimits,
    ) -> Result<Self, DurableSessionError> {
        Self::open_with_coordination_ceiling(path.as_ref(), expected_root, limits, Some(claim_ceilings))
    }

    /// Replays the complete bounded prefix without modifying its bytes or adopting a new root.
    pub fn inspect_with_coordination(
        path: impl AsRef<Path>, limits: DurableSessionLimits, claim_ceilings: WorkClaimLimits,
    ) -> Result<SessionJournalInspection, DurableSessionError> {
        Self::inspect_with_coordination_ceiling(path.as_ref(), limits, Some(claim_ceilings))
    }

    /// Commits one coordination command, including refusal-side authority mutations, atomically.
    ///
    /// The result is withheld until its record is synchronized. An uncertain append fences BOTH
    /// session and work operations; `reconcile_pending` never redelivers the withheld response.
    /// Reads are journaled too because they can advance clocks or create expiry tombstones.
    /// Journal capacity is consumed even by a no-op, and exhaustion never discards lease history.
    pub fn coordinate(
        &mut self, principal: &PrincipalId, session_id: &SessionId,
        command: CoordinationCommand, now: TimestampNs,
    ) -> Result<WorkClaimRevision, DurableSessionError> {
        self.preflight()?;
        let request = codec::Request {
            principal: principal.clone(), session: session_id.clone(), command, now,
        };
        // Hard bounds before copying any stores or executing session admission.
        let request_bytes = codec::encode_request(&request)?;
        let mut state = self.coordination.as_ref()
            .ok_or(DurableSessionError::InvalidHistory)?.fork();
        let mut memory = self.memory.clone();
        let result = apply(&request, &mut memory, &mut state.claims);
        let staged = (|| -> Result<PendingSession, DurableSessionError> {
            let checkpoint = memory.checkpoint(self.limits.max_checkpoint_bytes)?;
            let payload = codec::encode_record(
                &request_bytes, self.checkpoint_digest, checkpoint.digest(), codec::outcome_digest(&result)?,
            )?;
            Ok(PendingSession {
                memory, checkpoint, coordination: Some(state),
                record: Some((COORDINATION_COMMAND_RECORD_KIND, payload)),
            })
        })();
        let pending = match staged {
            Ok(pending) => pending,
            Err(error) => { self.fenced = true; return Err(error); }
        };
        self.commit_candidate(pending)?;
        result.map_err(DurableSessionError::WorkClaim)
    }
}

fn apply(
    request: &codec::Request, sessions: &mut ReferenceSessionStore, claims: &mut ReferenceWorkClaimStore,
) -> Result<WorkClaimRevision, WorkClaimError> {
    let codec::Request { principal, session, command, now } = request;
    match command {
        CoordinationCommand::Acquire(input) => claims.acquire(sessions, principal, session, input.clone(), *now),
        CoordinationCommand::Inspect { claim_id } => claims.inspect(sessions, principal, session, claim_id, *now),
        CoordinationCommand::InspectRevision { claim_id, revision } => {
            claims.inspect_revision(sessions, principal, session, claim_id, *revision, *now)
        }
        CoordinationCommand::Update { claim_id, expected, change } => {
            let current = claims.inspect(sessions, principal, session, claim_id, *now)?;
            if current.digest() != *expected { return Err(WorkClaimError::StaleRevision); }
            claims.update(sessions, principal, session, &current, *change, *now)
        }
        CoordinationCommand::Recover { claim_id, expected, recovery } => {
            let current = claims.inspect(sessions, principal, session, claim_id, *now)?;
            if current.digest() != *expected { return Err(WorkClaimError::StaleRevision); }
            claims.recover(sessions, principal, session, &current, recovery.clone(), *now)
        }
    }
}

pub(super) fn restore_initialization(
    payload: &[u8], session_digest: ContentDigest, ceilings: WorkClaimLimits,
) -> Result<CoordinationState, DurableSessionError> {
    let limits = codec::decode_initialization(payload, session_digest, ceilings)?;
    Ok(CoordinationState { claims: ReferenceWorkClaimStore::with_limits(limits), limits, cases: None })
}

pub(super) fn replay_command(
    payload: &[u8], sessions: &mut ReferenceSessionStore, state: &mut CoordinationState,
    limits: DurableSessionLimits,
) -> Result<(), DurableSessionError> {
    if investigations::journal::is_record(payload)? {
        return investigations::journal::replay_record(payload, sessions, state, limits);
    }
    let record = codec::decode_record(payload)?;
    if sessions.checkpoint(limits.max_checkpoint_bytes)?.digest() != record.before {
        return Err(DurableSessionError::InvalidHistory);
    }
    let result = apply(&record.request, sessions, &mut state.claims);
    if codec::outcome_digest(&result)? != record.outcome
        || sessions.checkpoint(limits.max_checkpoint_bytes)?.digest() != record.after
    {
        return Err(DurableSessionError::InvalidHistory);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

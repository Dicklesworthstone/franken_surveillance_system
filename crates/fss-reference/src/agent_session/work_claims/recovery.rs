#![forbid(unsafe_code)]
//! Explicit lease handoff and orphan recovery. No transition settles external obligations.

use fss_core::{PrincipalId, SessionId, TimestampNs, WorkClaimState};

use super::{
    CAPABILITY_WORK_CLAIM, ReferenceSessionError, ReferenceSessionStore, ReferenceWorkClaimStore,
    WorkClaimError, WorkClaimRevision,
};

/// Recovery is explicit and CAS-protected, never an implicit side effect of reading a claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkClaimRecovery {
    /// Record time expiry without deleting the exact work reservation or its progress.
    Expire,
    /// Hand work to another separately admitted session of the same principal and mission.
    /// The remaining lease can only shrink; activation must be explicit after transfer.
    Transfer {
        /// Live recipient, authenticated through the same principal's session owner.
        recipient: SessionId,
    },
    /// Reacquire released, expired, or authoritatively orphaned work under a fresh fence.
    /// For a live lease, a missing owner record is not proof of an orphan and fails closed.
    Reclaim {
        /// New lease, bounded by the requesting session's expiry and configured duration.
        expires_at: TimestampNs,
    },
}

impl ReferenceWorkClaimStore {
    /// Preserves work identity, dependencies, progress, and audit history while transferring or
    /// reclaiming ownership. Completed results are terminal. No grant, plan, dispatch, or external
    /// obligation is transferred, cancelled, verified, or retried by this coordination operation.
    ///
    /// Transfer and reclaim require the recipient's exact original anchor/ContractBasis. World
    /// drift needs separately recompiled work; this method never silently rebases an old question.
    /// Recovery from a lost acknowledgement reads the head instead of repeating a stale mutation.
    pub fn recover(
        &mut self,
        sessions: &mut ReferenceSessionStore,
        principal: &PrincipalId,
        session_id: &SessionId,
        expected: &WorkClaimRevision,
        recovery: WorkClaimRecovery,
        now: TimestampNs,
    ) -> Result<WorkClaimRevision, WorkClaimError> {
        let (session, basis) = self.admit(sessions, principal, session_id, now)?;
        let entry = self
            .claims
            .get(&expected.claim.claim_id)
            .ok_or(WorkClaimError::Unavailable)?;
        Self::visible(&entry.head, &session)?;
        if entry.head.digest() != expected.digest() {
            return Err(WorkClaimError::StaleRevision);
        }
        let mut next = entry.head.clone();
        match recovery {
            WorkClaimRecovery::Expire => {
                if next.claim.state == WorkClaimState::Expired {
                    return Ok(next);
                }
                if !matches!(
                    next.claim.state,
                    WorkClaimState::Claimed | WorkClaimState::Active | WorkClaimState::Blocked
                ) {
                    return Err(WorkClaimError::InvalidTransition);
                }
                if now.0 < next.claim.expires_at_ns {
                    return Err(WorkClaimError::InvalidLease);
                }
                next.claim.state = WorkClaimState::Expired;
            }
            WorkClaimRecovery::Transfer { recipient } => {
                Self::owned(&next, &session, &basis, now)?;
                if recipient == session.session_id {
                    return Err(WorkClaimError::InvalidTransition);
                }
                let (target, target_basis) = self.admit(sessions, principal, &recipient, now)?;
                Self::visible(&next, &target)?;
                if target_basis != next.basis || target.current_anchor != next.claim.basis_anchor {
                    return Err(WorkClaimError::StaleBasis);
                }
                let expires = TimestampNs(next.claim.expires_at_ns.min(target.expires_at_ns));
                self.check_lease(&target, expires, now)?;
                next.claim.lease_incarnation = next
                    .claim
                    .lease_incarnation
                    .checked_add(1)
                    .ok_or(WorkClaimError::CounterExhausted)?;
                next.claim.owner_session_id = recipient.to_string();
                next.claim.expires_at_ns = expires.0;
                next.claim.state = WorkClaimState::Claimed;
            }
            WorkClaimRecovery::Reclaim { expires_at } => {
                if !matches!(
                    next.claim.state,
                    WorkClaimState::Claimed
                        | WorkClaimState::Active
                        | WorkClaimState::Blocked
                        | WorkClaimState::Expired
                        | WorkClaimState::Released
                ) {
                    return Err(WorkClaimError::InvalidTransition);
                }
                if next.basis != basis || next.claim.basis_anchor != session.current_anchor {
                    return Err(WorkClaimError::StaleBasis);
                }
                if next.lease_covers(now) && owner_still_live(sessions, &next, now)? {
                    return Err(WorkClaimError::Conflict);
                }
                self.check_lease(&session, expires_at, now)?;
                next.claim.lease_incarnation = next
                    .claim
                    .lease_incarnation
                    .checked_add(1)
                    .ok_or(WorkClaimError::CounterExhausted)?;
                next.claim.owner_session_id = session_id.to_string();
                next.claim.expires_at_ns = expires_at.0;
                next.claim.state = WorkClaimState::Claimed;
            }
        }
        self.append(next, now)
    }
}

fn owner_still_live(
    sessions: &mut ReferenceSessionStore,
    head: &WorkClaimRevision,
    now: TimestampNs,
) -> Result<bool, WorkClaimError> {
    let owner_id = SessionId::parse(head.claim.owner_session_id.as_str())?;
    // A lost session store must not look like a certified owner closure. Retained tombstones,
    // expiry, or narrowed grants can establish an orphan; a missing record cannot.
    let owner = sessions.sessions.get(&owner_id).ok_or(WorkClaimError::Unavailable)?;
    if owner.session.principal_id != head.principal || owner.session.mission_id != head.mission {
        return Err(WorkClaimError::Unavailable);
    }
    // live_entry deliberately hides closed records before its clock check. Recovery must still
    // reject a future-dated closure rather than using it as authority at an earlier instant.
    if now < owner.last_observed_at {
        return Err(WorkClaimError::ClockRegression);
    }
    match sessions.live_entry(&head.principal, &owner_id, now) {
        Ok(entry) => {
            if entry.session.mission_id != head.mission {
                return Err(WorkClaimError::Unavailable);
            }
            Ok(entry.session.capabilities.contains(CAPABILITY_WORK_CLAIM)
                && entry.session.privacy_scope.contains(&head.privacy_class)
                && entry.session.current_anchor == head.claim.basis_anchor
                && entry.basis == head.basis)
        }
        Err(ReferenceSessionError::Unavailable) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

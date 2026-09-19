#![forbid(unsafe_code)]
//! Bounded, session-authorized coordination for the FSS-226 reference lane.
//!
//! A record is not a lease authority. This single-owner store admits mutations only against its
//! retained head and a live session from the owning runtime. It never dispatches an effect. Work
//! identity is exact: (principal, mission, case, privacy class, work root). Distinct roots are NOT a proof that
//! semantic scopes are disjoint. The caller must compile/authorize those scopes before admission.
//!
//! Revisions and scope reservations are retained, including terminal and expired claims. Capacity
//! exhaustion refuses new revisions rather than forgetting fences. This in-memory reference is
//! not crash-durable, a distributed lock, or a replacement for the canonical ledger publisher.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::{
    AgentSession, CanonicalEncode, CanonicalEncoder, CaseId, ContentDigest, ContractBasis,
    ContractError, MissionId, PrincipalId, SessionId, TimestampNs, WorkClaim, WorkClaimState,
};

use super::{ReferenceSessionError, ReferenceSessionStore};

#[cfg(test)]
mod tests;

/// Registered coordination grant; never substitutes for an effect capability.
pub const CAPABILITY_WORK_CLAIM: &str = "CAP-AGENT-WORK-CLAIM-001";
/// Private reference revision digest domain, not a new public operation or wire schema.
pub const WORK_CLAIM_REVISION_DOMAIN: &str = "fss-reference:work-claim-revision:v1";

/// Explicit ceilings. Zero is zero capacity, never an unlimited sentinel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkClaimLimits {
    /// Includes terminal claim identities and their exact scope reservations.
    pub max_claims: usize,
    /// Total retained revisions across all claims, including their initial revisions.
    pub max_revisions: usize,
    /// Per-claim dependency ceiling, also capped by the registered schema's 4096 limit.
    pub max_dependencies: usize,
    /// Maximum requested lease duration, additionally bounded by session expiry.
    pub max_lease_ns: u64,
}

impl Default for WorkClaimLimits {
    fn default() -> Self {
        Self {
            max_claims: 1_024,
            max_revisions: 16_384,
            max_dependencies: 256,
            max_lease_ns: 300_000_000_000,
        }
    }
}

/// A runtime-authorized, exact unit of work; no caller-selected owner, fence, or lifecycle state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkClaimRequest {
    /// Stable claim identity. Never recycled for different work.
    pub claim_id: String,
    /// Exact case in the authenticated session's mission.
    pub case_id: CaseId,
    /// Content identity of the immutable, already authorized work description.
    pub work_root: ContentDigest,
    /// Required session privacy grant. No implicit public/default class.
    pub privacy_class: String,
    /// Absolute runtime-clock expiry; retries cannot extend it.
    pub expires_at: TimestampNs,
    /// Unique, existing claim identities in the same authorized mission.
    pub dependencies: BTreeSet<String>,
}

/// Immutable, hash-linked reference revision of the existing WorkClaim contract.
#[derive(Clone, Debug, PartialEq)]
pub struct WorkClaimRevision {
    claim: WorkClaim,
    principal: PrincipalId,
    mission: MissionId,
    basis: ContractBasis,
    privacy_class: String,
    work_root: ContentDigest,
    revision: u64,
    predecessor: Option<ContentDigest>,
    changed_at: TimestampNs,
}

impl WorkClaimRevision {
    /// The recorded state, not proof of a currently live lease or of any external effect.
    #[must_use]
    pub const fn claim(&self) -> &WorkClaim {
        &self.claim
    }

    /// Exact revision precondition for a subsequent mutation.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        self.canonical_digest(WORK_CLAIM_REVISION_DOMAIN)
    }

    /// Previous retained revision, absent only for revision one.
    #[must_use]
    pub const fn predecessor(&self) -> Option<ContentDigest> {
        self.predecessor
    }

    /// Monotone revision number; distinct from the lease fencing incarnation.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Whether the recorded lease covers this runtime instant. Session admission is still needed.
    #[must_use]
    pub fn lease_covers(&self, now: TimestampNs) -> bool {
        now >= self.changed_at
            && now.0 < self.claim.expires_at_ns
            && matches!(
                self.claim.state,
                WorkClaimState::Claimed | WorkClaimState::Active | WorkClaimState::Blocked
            )
    }
}

impl CanonicalEncode for WorkClaimRevision {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.claim.encode_canonical(encoder);
        self.principal.encode_canonical(encoder);
        self.mission.encode_canonical(encoder);
        self.basis.encode_canonical(encoder);
        encoder.text(&self.privacy_class);
        encoder.digest(self.work_root);
        encoder.u64(self.revision);
        encoder.bool(self.predecessor.is_some());
        if let Some(previous) = self.predecessor {
            encoder.digest(previous);
        }
        encoder.i128(self.changed_at.0);
    }
}

/// Lifecycle changes supported by the reference owner; none authorizes external work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkClaimUpdate {
    /// Begin/resume work only after every dependency completed at this exact basis.
    Activate,
    /// Preserve an explicit immutable progress artifact while blocked.
    Block(ContentDigest),
    /// Publish progress without changing the active lifecycle state.
    Progress(ContentDigest),
    /// Record a work result, not a verified physical fact or effect outcome.
    Complete(ContentDigest),
    /// Stop coordinating this work. Does not cancel or settle any external obligation.
    Release,
    /// Explicit lease renewal; advances the fence and cannot exceed the session's expiry.
    Renew(TimestampNs),
}

/// Deliberately identity-free refusals; private existence and wrong-principal are indistinguishable.
#[derive(Debug)]
pub enum WorkClaimError {
    /// Missing, cross-principal/mission, or not privacy-authorized.
    Unavailable,
    /// An identity or exact work scope is already reserved.
    Conflict,
    /// The supplied revision or owner no longer holds the retained head.
    StaleRevision,
    /// Session and work no longer have the same exact anchor and contract basis.
    StaleBasis,
    /// Lease is expired, terminal, outside bounds, or would not strictly extend on renewal.
    InvalidLease,
    /// The requested transition is not allowed from the retained state.
    InvalidTransition,
    /// A dependency has not completed at the current exact basis.
    DependencyPending,
    /// A caller or schema resource ceiling was exceeded.
    CapacityExceeded,
    /// A monotone revision/fence cannot advance.
    CounterExhausted,
    /// Runtime time went backwards; the retained watermark never rewinds.
    ClockRegression,
    /// A core identity/record was malformed.
    Contract(ContractError),
    /// The owning session refused admission (including missing coordination grants).
    Session(ReferenceSessionError),
}

impl fmt::Display for WorkClaimError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::Unavailable => "work claim unavailable",
            Self::Conflict => "work identity or scope already reserved",
            Self::StaleRevision => "work claim revision is stale",
            Self::StaleBasis => "work claim basis is stale",
            Self::InvalidLease => "work claim lease is invalid",
            Self::InvalidTransition => "work claim transition refused",
            Self::DependencyPending => "work claim dependency is not ready",
            Self::CapacityExceeded => "work claim capacity exceeded",
            Self::CounterExhausted => "work claim counter exhausted",
            Self::ClockRegression => "work claim clock regressed",
            Self::Contract(_) => "invalid work claim contract",
            Self::Session(_) => "work claim session admission refused",
        })
    }
}

impl std::error::Error for WorkClaimError {}

impl From<ContractError> for WorkClaimError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}

impl From<ReferenceSessionError> for WorkClaimError {
    fn from(value: ReferenceSessionError) -> Self {
        Self::Session(value)
    }
}

#[derive(Debug)]
struct ClaimEntry {
    opening: WorkClaimRequest,
    creator: SessionId,
    head: WorkClaimRevision,
    history: Vec<WorkClaimRevision>,
}

/// One runtime-owned coordination store. Returned snapshots cannot be written back as authority.
///
/// Keep this store together with its session owner. Dropping/reconstructing an empty reference
/// store is NOT recovery; a production owner must persist revisions and fences before acknowledging.
#[derive(Debug)]
pub struct ReferenceWorkClaimStore {
    claims: BTreeMap<String, ClaimEntry>,
    limits: WorkClaimLimits,
    revisions: usize,
    last_observed_at: Option<TimestampNs>,
}

impl Default for ReferenceWorkClaimStore {
    fn default() -> Self {
        Self::with_limits(WorkClaimLimits::default())
    }
}

impl ReferenceWorkClaimStore {
    /// Creates a single-owner in-memory reference with explicit storage and duration bounds.
    #[must_use]
    pub fn with_limits(limits: WorkClaimLimits) -> Self {
        Self { claims: BTreeMap::new(), limits, revisions: 0, last_observed_at: None }
    }

    /// Reserves exact work once. An identical live opening retry returns the CURRENT revision,
    /// never resets progress, and never renews the lease. Existing scope reservations are retained
    /// after expiry/release, so recovery cannot reset a resource's fence using a new claim ID.
    pub fn acquire(
        &mut self,
        sessions: &mut ReferenceSessionStore,
        principal: &PrincipalId,
        session_id: &SessionId,
        request: WorkClaimRequest,
        now: TimestampNs,
    ) -> Result<WorkClaimRevision, WorkClaimError> {
        let (session, basis) = self.admit(sessions, principal, session_id, now)?;
        if !session.privacy_scope.contains(&request.privacy_class) {
            return Err(WorkClaimError::Unavailable);
        }
        if request.claim_id.is_empty() || request.claim_id.len() > 128
            || request.dependencies.len() > self.limits.max_dependencies.min(4_096)
            || request.privacy_class.is_empty() || request.privacy_class.len() > 256
            || request.dependencies.iter().any(|id| id.len() > 128)
        {
            return Err(WorkClaimError::CapacityExceeded);
        }
        if let Some(existing) = self.claims.get(&request.claim_id) {
            Self::visible(&existing.head, &session)?;
            if existing.creator != session.session_id || existing.opening != request {
                return Err(WorkClaimError::Conflict);
            }
            Self::owned(&existing.head, &session, &basis, now)?;
            return Ok(existing.head.clone());
        }
        self.check_lease(&session, request.expires_at, now)?;
        if self.claims.values().any(|entry| {
            let head = &entry.head;
            head.principal == session.principal_id && head.mission == session.mission_id
                && head.claim.case_id.as_deref() == Some(request.case_id.as_str())
                && head.privacy_class == request.privacy_class && head.work_root == request.work_root
        }) {
            return Err(WorkClaimError::Conflict);
        }
        for dependency in &request.dependencies {
            if dependency == &request.claim_id {
                return Err(WorkClaimError::InvalidTransition);
            }
            let prior = self.claims.get(dependency).ok_or(WorkClaimError::Unavailable)?;
            Self::visible(&prior.head, &session)?;
        }
        if self.claims.len() >= self.limits.max_claims {
            return Err(WorkClaimError::CapacityExceeded);
        }
        self.reserve_revision()?;
        let claim = WorkClaim::new(
            request.claim_id.clone(), Some(request.case_id.to_string()), session_id.to_string(),
            format!("{{\"workRoot\":\"{}\"}}", request.work_root), session.current_anchor.clone(),
            1, now.0, request.expires_at.0, WorkClaimState::Claimed,
            request.dependencies.iter().cloned().collect(), "{}", None,
        )?;
        let head = WorkClaimRevision {
            claim, principal: session.principal_id, mission: session.mission_id, basis,
            privacy_class: request.privacy_class.clone(), work_root: request.work_root,
            revision: 1, predecessor: None, changed_at: now,
        };
        self.claims.insert(request.claim_id.clone(), ClaimEntry {
            opening: request, creator: session.session_id, head: head.clone(), history: Vec::new(),
        });
        self.revisions += 1;
        Ok(head)
    }

    /// Reads one authorized head, including expired/terminal work for recovery. It does not renew
    /// the lease or hide stale state. Check `lease_covers(now)` and revalidate before acting.
    pub fn inspect(
        &mut self,
        sessions: &mut ReferenceSessionStore,
        principal: &PrincipalId,
        session_id: &SessionId,
        claim_id: &str,
        now: TimestampNs,
    ) -> Result<WorkClaimRevision, WorkClaimError> {
        let (session, _) = self.admit(sessions, principal, session_id, now)?;
        let entry = self.claims.get(claim_id).ok_or(WorkClaimError::Unavailable)?;
        Self::visible(&entry.head, &session)?;
        Ok(entry.head.clone())
    }

    /// Reads one exact retained historical revision. This is audit data, not permission to resume
    /// a stale writer. Privacy and mission admission precede any historical lookup.
    pub fn inspect_revision(
        &mut self,
        sessions: &mut ReferenceSessionStore,
        principal: &PrincipalId,
        session_id: &SessionId,
        claim_id: &str,
        digest: ContentDigest,
        now: TimestampNs,
    ) -> Result<WorkClaimRevision, WorkClaimError> {
        let head = self.inspect(sessions, principal, session_id, claim_id, now)?;
        if head.digest() == digest {
            return Ok(head);
        }
        self.claims.get(claim_id).and_then(|entry| {
            entry.history.iter().find(|revision| revision.digest() == digest)
        }).cloned().ok_or(WorkClaimError::Unavailable)
    }

    /// Changes only the current owner's live, exact revision. Failed transitions append nothing.
    /// CAS covers the full basis/progress, not merely the lease number. Lost-ACK mutation retries
    /// refresh the head instead of silently overwriting a later update.
    pub fn update(
        &mut self,
        sessions: &mut ReferenceSessionStore,
        principal: &PrincipalId,
        session_id: &SessionId,
        expected: &WorkClaimRevision,
        change: WorkClaimUpdate,
        now: TimestampNs,
    ) -> Result<WorkClaimRevision, WorkClaimError> {
        let (session, basis) = self.admit(sessions, principal, session_id, now)?;
        let entry = self.claims.get(&expected.claim.claim_id).ok_or(WorkClaimError::Unavailable)?;
        Self::visible(&entry.head, &session)?;
        if entry.head.digest() != expected.digest() {
            return Err(WorkClaimError::StaleRevision);
        }
        Self::owned(&entry.head, &session, &basis, now)?;
        let mut next = entry.head.clone();
        match change {
            WorkClaimUpdate::Activate => {
                if !matches!(next.claim.state, WorkClaimState::Claimed | WorkClaimState::Blocked) {
                    return Err(WorkClaimError::InvalidTransition);
                }
                self.dependencies_ready(&next, &session, &basis)?;
                next.claim.state = WorkClaimState::Active;
            }
            WorkClaimUpdate::Block(root) => {
                next.claim.state = WorkClaimState::Blocked;
                next.claim.progress_json = format!("{{\"root\":\"{root}\"}}");
            }
            WorkClaimUpdate::Progress(root) => {
                if next.claim.state != WorkClaimState::Active {
                    return Err(WorkClaimError::InvalidTransition);
                }
                next.claim.progress_json = format!("{{\"root\":\"{root}\"}}");
            }
            WorkClaimUpdate::Complete(root) => {
                if next.claim.state != WorkClaimState::Active {
                    return Err(WorkClaimError::InvalidTransition);
                }
                self.dependencies_ready(&next, &session, &basis)?;
                next.claim.state = WorkClaimState::Completed;
                next.claim.result_root = Some(root.to_string());
            }
            WorkClaimUpdate::Release => next.claim.state = WorkClaimState::Released,
            WorkClaimUpdate::Renew(expires) => {
                self.check_lease(&session, expires, now)?;
                if expires.0 <= next.claim.expires_at_ns {
                    return Err(WorkClaimError::InvalidLease);
                }
                next.claim.lease_incarnation = next.claim.lease_incarnation.checked_add(1)
                    .ok_or(WorkClaimError::CounterExhausted)?;
                next.claim.expires_at_ns = expires.0;
            }
        }
        self.append(next, now)
    }

    fn admit(
        &mut self, sessions: &mut ReferenceSessionStore, principal: &PrincipalId,
        session_id: &SessionId, now: TimestampNs,
    ) -> Result<(AgentSession, ContractBasis), WorkClaimError> {
        let entry = sessions.live_entry(principal, session_id, now)?;
        if !entry.session.capabilities.contains(CAPABILITY_WORK_CLAIM) {
            return Err(ReferenceSessionError::GrantEscalation.into());
        }
        if now.0 < 0 || self.last_observed_at.is_some_and(|last| now < last) {
            return Err(WorkClaimError::ClockRegression);
        }
        self.last_observed_at = Some(now);
        Ok((entry.session.clone(), entry.basis.clone()))
    }

    fn visible(head: &WorkClaimRevision, session: &AgentSession) -> Result<(), WorkClaimError> {
        if head.principal != session.principal_id || head.mission != session.mission_id
            || !session.privacy_scope.contains(&head.privacy_class)
        {
            return Err(WorkClaimError::Unavailable);
        }
        Ok(())
    }

    fn owned(
        head: &WorkClaimRevision, session: &AgentSession, basis: &ContractBasis, now: TimestampNs,
    ) -> Result<(), WorkClaimError> {
        if head.claim.owner_session_id != session.session_id.as_str() {
            return Err(WorkClaimError::StaleRevision);
        }
        if &head.basis != basis || head.claim.basis_anchor != session.current_anchor {
            return Err(WorkClaimError::StaleBasis);
        }
        if !head.lease_covers(now) {
            return Err(WorkClaimError::InvalidLease);
        }
        Ok(())
    }

    fn check_lease(
        &self, session: &AgentSession, expires: TimestampNs, now: TimestampNs,
    ) -> Result<(), WorkClaimError> {
        let duration = expires.0.checked_sub(now.0).ok_or(WorkClaimError::InvalidLease)?;
        if duration <= 0 || duration > i128::from(self.limits.max_lease_ns)
            || expires.0 > session.expires_at_ns
        {
            return Err(WorkClaimError::InvalidLease);
        }
        Ok(())
    }

    fn dependencies_ready(
        &self, head: &WorkClaimRevision, session: &AgentSession, basis: &ContractBasis,
    ) -> Result<(), WorkClaimError> {
        for id in &head.claim.dependencies {
            let dependency = self.claims.get(id).ok_or(WorkClaimError::Unavailable)?;
            Self::visible(&dependency.head, session)?;
            if dependency.head.basis != *basis
                || dependency.head.claim.basis_anchor != session.current_anchor
            {
                return Err(WorkClaimError::StaleBasis);
            }
            if dependency.head.claim.state != WorkClaimState::Completed {
                return Err(WorkClaimError::DependencyPending);
            }
        }
        Ok(())
    }

    fn reserve_revision(&self) -> Result<(), WorkClaimError> {
        if self.revisions >= self.limits.max_revisions || self.revisions == usize::MAX {
            return Err(WorkClaimError::CapacityExceeded);
        }
        Ok(())
    }

    fn append(
        &mut self, mut next: WorkClaimRevision, now: TimestampNs,
    ) -> Result<WorkClaimRevision, WorkClaimError> {
        self.reserve_revision()?;
        // Link to the retained predecessor, not to the unpublished candidate.
        let entry = self.claims.get_mut(&next.claim.claim_id).ok_or(WorkClaimError::Unavailable)?;
        next.predecessor = Some(entry.head.digest());
        next.revision = entry.head.revision.checked_add(1).ok_or(WorkClaimError::CounterExhausted)?;
        next.changed_at = now;
        entry.history.push(entry.head.clone());
        entry.head = next.clone();
        self.revisions += 1;
        Ok(next)
    }
}

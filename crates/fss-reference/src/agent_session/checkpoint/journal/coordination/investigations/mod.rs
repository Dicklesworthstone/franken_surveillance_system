#![forbid(unsafe_code)]
//! Session-admitted immutable investigations over the existing AOP-006 contracts.
//!
//! Records are cognition, not verified physical facts. Evidence digests are citations whose
//! custody and disclosure must be checked by their semantic owner. No command executes a probe,
//! removes an alternative or grants an external effect capability. Explicit rebases invalidate
//! old positive knowledge and citation applicability without discarding the prior revision.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::{
    AgentSession, CanonicalEncode, CanonicalEncoder, CaseId, ContentDigest, ContractBasis,
    HypothesisDisposition, InvestigationCaseState, InvestigationLifecycle, InvestigationState,
    InvestigationStateParams, PrincipalId, SessionId, TimestampNs,
};
use crate::agent_session::{ReferenceSessionError, ReferenceSessionStore};

mod validation;

/// Explicit world-drift invalidation and append-only expansion of a live investigation.
pub mod evolution;
pub(super) mod journal;

pub use journal::DurableInvestigationError;

/// Registered cognition-write grant. It is never an effect grant.
pub const CAPABILITY_INVESTIGATE: &str = "CAP-AGENT-INVESTIGATE-001";
/// Private revision identity; the embedded public record retains its existing schema.
pub const INVESTIGATION_REVISION_DOMAIN: &str = "fss-reference:investigation-revision:v1";
/// Hard bound for a single retained revision or encoded request.
pub const MAX_INVESTIGATION_BYTES: usize = 1024 * 1024;

/// Bounded reference history, including closed identities and all historical revisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvestigationLimits {
    /// Maximum stable case identities; terminal identities are not evicted.
    pub max_cases: usize,
    /// Total retained revisions across cases.
    pub max_revisions: usize,
    /// Sum of retained canonical revision bytes.
    pub max_retained_bytes: usize,
}

impl Default for InvestigationLimits {
    fn default() -> Self {
        Self { max_cases: 256, max_revisions: 4_096, max_retained_bytes: 32 * 1024 * 1024 }
    }
}

impl InvestigationLimits {
    /// Refuses ceilings beyond the deterministic reference's absolute allocation envelope.
    pub fn validate(self) -> Result<(), InvestigationError> {
        if self.max_cases > 1_024 || self.max_revisions > 16_384
            || self.max_retained_bytes > 64 * 1024 * 1024
        {
            return Err(InvestigationError::CapacityExceeded);
        }
        Ok(())
    }
}

/// Typed case mutation, never a caller-supplied replacement revision.
#[derive(Clone, Debug, PartialEq)]
pub enum InvestigationChange {
    /// Start or resume cognition before the decision deadline.
    Activate,
    /// Retain a support/contradiction citation without promoting its epistemic state.
    Cite {
        /// Existing hypothesis; alternatives cannot be silently added or deleted.
        hypothesis: String,
        /// Immutable evidence identity, already authorized by the evidence owner.
        evidence: ContentDigest,
        /// True attaches counterevidence, false attaches support.
        contradicts: bool,
    },
    /// Apply the existing monotone disposition table using an already attached citation.
    Assess {
        /// Existing hypothesis identity.
        hypothesis: String,
        /// Supported/disfavored/refuted, subject to the core transition table.
        disposition: HypothesisDisposition,
        /// Supporting citation for support, counterevidence for disfavor/refutation.
        evidence: ContentDigest,
    },
    /// Pause, explicitly preserve uncertainty, cancel cognition, or close an ended case.
    SetState {
        /// AwaitingEvidence/AwaitingApproval/Blocked/Indeterminate/Cancelled/Closed only.
        state: InvestigationLifecycle,
        /// Immutable reason/assessment artifact; not proof that external work was cancelled.
        reason: ContentDigest,
    },
    /// Conclude cognition only after alternatives and residual unknowns are accounted for.
    Conclude {
        /// True requires every hypothesis refuted; false requires at least one supported.
        refuted: bool,
        /// Exact declared stop rule, not a replacement rule introduced at completion.
        stop_rule: String,
        /// Caller assessment identity. This is not a physical-outcome proof.
        assessment: ContentDigest,
        /// Exact IDs of all retained unknown statements, acknowledged rather than deleted.
        residual_unknowns: BTreeSet<String>,
    },
}

/// Commands shared by live reference execution and durable replay.
#[derive(Clone, Debug, PartialEq)]
pub enum InvestigationCommand {
    /// Open revision one in Draft at the exact live session basis; exact retries are harmless.
    Open {
        /// Existing schema-faithful record. Ownership and revision are not inferred from it.
        record: Box<InvestigationState>,
        /// Exact authorized privacy domain for the complete case.
        privacy_class: String,
    },
    /// Read one current or historical revision. A stale record is never a write grant.
    Inspect {
        /// Stable case identity.
        case_id: String,
        /// None reads current state; Some selects an exact retained revision.
        revision: Option<ContentDigest>,
    },
    /// Apply to exactly the retained head; a stale retry never overwrites a later writer.
    Change {
        /// Stable case identity.
        case_id: String,
        /// Full revision identity including session, privacy, assessment and predecessor.
        expected: ContentDigest,
        /// Typed mutation.
        change: InvestigationChange,
    },
}

/// One immutable case revision, with knowledge and hypothesis disposition kept orthogonal.
#[derive(Clone, Debug, PartialEq)]
pub struct InvestigationRevision {
    record: InvestigationState,
    control: InvestigationCaseState,
    principal: PrincipalId,
    author_session: SessionId,
    privacy_class: String,
    predecessor: Option<ContentDigest>,
    changed_at: TimestampNs,
    assessment: Option<ContentDigest>,
    validity: Option<evolution::InvestigationValidity>,
}

impl InvestigationRevision {
    /// Existing AOP-006 record. It cannot be written back as authoritative store state.
    #[must_use]
    pub const fn record(&self) -> &InvestigationState { &self.record }
    /// Core disposition state, separate from every statement's knowledge state.
    #[must_use]
    pub const fn control(&self) -> &InvestigationCaseState { &self.control }
    /// Previous exact revision, absent only at creation.
    #[must_use]
    pub const fn predecessor(&self) -> Option<ContentDigest> { self.predecessor }
    /// Authenticated session that authored this revision.
    #[must_use]
    pub const fn author_session(&self) -> &SessionId { &self.author_session }
    /// Exact optimistic concurrency and audit identity.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let domain = if self.validity.is_some() { evolution::EVOLVED_REVISION_DOMAIN }
            else { INVESTIGATION_REVISION_DOMAIN };
        self.canonical_digest(domain)
    }
    /// Current-basis invalidation and readmission receipts, absent for never-rebased cases.
    #[must_use]
    pub const fn validity(&self) -> Option<&evolution::InvestigationValidity> {
        self.validity.as_ref()
    }
}

impl CanonicalEncode for InvestigationRevision {
    fn encode_canonical(&self, e: &mut CanonicalEncoder) {
        self.record.encode_canonical(e);
        self.control.encode_canonical(e);
        self.principal.encode_canonical(e);
        self.author_session.encode_canonical(e);
        e.text(&self.privacy_class);
        e.bool(self.predecessor.is_some());
        if let Some(root) = self.predecessor { e.digest(root); }
        e.i128(self.changed_at.0);
        e.bool(self.assessment.is_some());
        if let Some(root) = self.assessment { e.digest(root); }
        // Legacy revisions remain byte-identical. Rebased revisions use a distinct digest domain
        // and a self-identifying extension; this is not a reinterpretation of old journal bytes.
        if let Some(validity) = &self.validity { validity.encode_canonical(e); }
    }
}

/// Identity-free, deterministic refusal classes suitable for exact command replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvestigationError {
    /// Unknown session/case, wrong principal/mission, or unavailable privacy domain.
    Unavailable,
    /// Live session lacks the registered cognition-write grant.
    Denied,
    /// Submitted fields fail the existing contract or strict bounded reference admission.
    InvalidRecord,
    /// Stable identity already belongs to a different opening request.
    Conflict,
    /// Expected revision is not the current head.
    StaleRevision,
    /// Session and case anchor/ContractBasis disagree. No implicit rebase is performed.
    StaleBasis,
    /// Decision deadline has elapsed; only uncertainty/cancellation/closure remains available.
    DeadlineElapsed,
    /// Lifecycle or core disposition transition is not legal.
    InvalidTransition,
    /// Live alternatives or incompatible conclusions prevent a conclusive result.
    UnresolvedAlternatives,
    /// A disposition cites evidence not attached on the required side of the hypothesis.
    EvidenceRequired,
    /// Stop rule or exact residual-unknown acknowledgement is missing.
    ResidualsRequired,
    /// Count or retained-byte capacity exceeded; history is never evicted to proceed.
    CapacityExceeded,
    /// Revision counter cannot advance without wrapping.
    CounterExhausted,
    /// Trusted runtime time regressed. Watermarks are never rewound.
    ClockRegression,
}

impl fmt::Display for InvestigationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "investigation unavailable",
            Self::Denied => "investigation capability denied",
            Self::InvalidRecord => "invalid investigation record",
            Self::Conflict => "investigation identity conflict",
            Self::StaleRevision => "investigation revision is stale",
            Self::StaleBasis => "investigation basis is stale",
            Self::DeadlineElapsed => "investigation decision deadline elapsed",
            Self::InvalidTransition => "investigation transition refused",
            Self::UnresolvedAlternatives => "investigation alternatives remain unresolved",
            Self::EvidenceRequired => "investigation evidence required",
            Self::ResidualsRequired => "investigation residual acknowledgement required",
            Self::CapacityExceeded => "investigation capacity exceeded",
            Self::CounterExhausted => "investigation revision exhausted",
            Self::ClockRegression => "investigation clock regressed",
        })
    }
}
impl std::error::Error for InvestigationError {}

#[derive(Clone, Debug)]
struct Entry {
    opening: ContentDigest,
    head: InvestigationRevision,
    history: Vec<InvestigationRevision>,
}

/// Sole-owner in-memory oracle. Production persistence must commit session and case state together.
#[derive(Clone, Debug)]
pub struct ReferenceInvestigationStore {
    entries: BTreeMap<String, Entry>,
    limits: InvestigationLimits,
    revisions: usize,
    retained_bytes: usize,
    last_observed_at: Option<TimestampNs>,
}

impl ReferenceInvestigationStore {
    /// Constructs a bounded store; zero limits mean no capacity.
    pub fn new(limits: InvestigationLimits) -> Result<Self, InvestigationError> {
        limits.validate()?;
        Ok(Self { entries: BTreeMap::new(), limits, revisions: 0,
            retained_bytes: 0, last_observed_at: None })
    }

    /// Executes using live session authority and a runtime clock, not an agent's claimed grants.
    /// Failed operations may advance clocks or expire a session, but never append a case revision.
    /// All input media/text/citations must already be scoped by their source owner before entry.
    pub fn execute(
        &mut self, sessions: &mut ReferenceSessionStore, principal: &PrincipalId,
        session_id: &SessionId, command: &InvestigationCommand, now: TimestampNs,
    ) -> Result<InvestigationRevision, InvestigationError> {
        validation::command(command)?;
        let entry = sessions.live_entry(principal, session_id, now).map_err(|error| match error {
            ReferenceSessionError::ClockRegression => InvestigationError::ClockRegression,
            _ => InvestigationError::Unavailable,
        })?;
        if !entry.session.capabilities.contains(CAPABILITY_INVESTIGATE) {
            return Err(InvestigationError::Denied);
        }
        if now.0 < 0 || self.last_observed_at.is_some_and(|last| now < last) {
            return Err(InvestigationError::ClockRegression);
        }
        self.last_observed_at = Some(now);
        let session = &entry.session;
        let basis = &entry.basis;
        match command {
            InvestigationCommand::Open { record, privacy_class } => {
                if !session.privacy_scope.contains(privacy_class) {
                    return Err(InvestigationError::Unavailable);
                }
                Self::basis(record, session, basis)?;
                let mut e = CanonicalEncoder::new();
                record.encode_canonical(&mut e);
                e.text(privacy_class);
                let opening = ContentDigest::sha256(&e.finish_checked()
                    .map_err(|_| InvestigationError::InvalidRecord)?);
                if let Some(existing) = self.entries.get(&record.investigation_id) {
                    Self::visible(&existing.head, session)?;
                    if existing.opening != opening { return Err(InvestigationError::Conflict); }
                    return Ok(existing.head.clone());
                }
                if record.state != InvestigationLifecycle::Draft || record.revision != 1 {
                    return Err(InvestigationError::InvalidRecord);
                }
                if record.decision_deadline_ns <= now.0 {
                    return Err(InvestigationError::DeadlineElapsed);
                }
                if self.entries.len() >= self.limits.max_cases {
                    return Err(InvestigationError::CapacityExceeded);
                }
                let control = InvestigationCaseState::create(record.investigation_id.clone(),
                    record.mission_id.clone(), &record.hypotheses.iter()
                        .map(|h| h.hypothesis_id.clone()).collect())
                    .map_err(|_| InvestigationError::InvalidRecord)?;
                let next = InvestigationRevision { record: record.as_ref().clone(), control,
                    principal: principal.clone(), author_session: session_id.clone(),
                    privacy_class: privacy_class.clone(), predecessor: None, changed_at: now,
                    assessment: None, validity: None };
                let bytes = self.reserve(&next)?;
                self.entries.insert(record.investigation_id.clone(), Entry {
                    opening, head: next.clone(), history: Vec::new(),
                });
                self.revisions += 1;
                self.retained_bytes += bytes;
                Ok(next)
            }
            InvestigationCommand::Inspect { case_id, revision } => {
                let current = self.entries.get(case_id).ok_or(InvestigationError::Unavailable)?;
                Self::visible(&current.head, session)?;
                match revision {
                    None => Ok(current.head.clone()),
                    Some(root) if current.head.digest() == *root => Ok(current.head.clone()),
                    Some(root) => current.history.iter().find(|old| old.digest() == *root)
                        .cloned().ok_or(InvestigationError::Unavailable),
                }
            }
            InvestigationCommand::Change { case_id, expected, change } => {
                let current = self.entries.get(case_id).ok_or(InvestigationError::Unavailable)?;
                Self::visible(&current.head, session)?;
                if current.head.digest() != *expected { return Err(InvestigationError::StaleRevision); }
                Self::basis(&current.head.record, session, basis)?;
                let mut next = current.head.clone();
                apply_change(&mut next, change, now)?;
                next.record.revision = next.record.revision.checked_add(1)
                    .ok_or(InvestigationError::CounterExhausted)?;
                next.predecessor = Some(*expected);
                next.author_session = session_id.clone();
                next.changed_at = now;
                let bytes = self.reserve(&next)?;
                let current = self.entries.get_mut(case_id).ok_or(InvestigationError::Unavailable)?;
                current.history.push(current.head.clone());
                current.head = next.clone();
                self.revisions += 1;
                self.retained_bytes += bytes;
                Ok(next)
            }
        }
    }

    fn visible(head: &InvestigationRevision, session: &AgentSession) -> Result<(), InvestigationError> {
        if head.principal != session.principal_id || head.record.mission_id != session.mission_id
            || !session.privacy_scope.contains(&head.privacy_class)
        { return Err(InvestigationError::Unavailable); }
        Ok(())
    }

    fn basis(record: &InvestigationState, session: &AgentSession, basis: &ContractBasis)
        -> Result<(), InvestigationError>
    {
        if record.mission_id != session.mission_id { return Err(InvestigationError::Unavailable); }
        if &record.contract_basis != basis || record.basis_anchor != session.current_anchor {
            return Err(InvestigationError::StaleBasis);
        }
        Ok(())
    }

    fn reserve(&self, next: &InvestigationRevision) -> Result<usize, InvestigationError> {
        let bytes = next.try_canonical_bytes().map_err(|_| InvestigationError::InvalidRecord)?.len();
        if bytes > MAX_INVESTIGATION_BYTES || self.revisions >= self.limits.max_revisions
            || self.retained_bytes.checked_add(bytes)
                .is_none_or(|total| total > self.limits.max_retained_bytes)
        { return Err(InvestigationError::CapacityExceeded); }
        Ok(bytes)
    }
}

fn open_state(state: InvestigationLifecycle) -> bool {
    matches!(state, InvestigationLifecycle::Draft | InvestigationLifecycle::Active
        | InvestigationLifecycle::AwaitingEvidence | InvestigationLifecycle::AwaitingApproval
        | InvestigationLifecycle::Blocked | InvestigationLifecycle::Indeterminate)
}

fn apply_change(next: &mut InvestigationRevision, change: &InvestigationChange, now: TimestampNs)
    -> Result<(), InvestigationError>
{
    use InvestigationLifecycle as L;
    if next.record.state == L::Closed { return Err(InvestigationError::InvalidTransition); }
    let late_allowed = matches!(change, InvestigationChange::SetState {
        state: L::Indeterminate | L::Cancelled | L::Closed, ..
    });
    if now.0 >= next.record.decision_deadline_ns && !late_allowed {
        return Err(InvestigationError::DeadlineElapsed);
    }
    match change {
        InvestigationChange::SetState { state: L::Closed, reason } => {
            if !matches!(next.record.state, L::Resolved | L::Refuted | L::Cancelled | L::Indeterminate) {
                return Err(InvestigationError::InvalidTransition);
            }
            next.record.state = L::Closed;
            next.assessment = Some(*reason);
        }
        _ if !open_state(next.record.state) => return Err(InvestigationError::InvalidTransition),
        InvestigationChange::Activate => {
            if next.record.state == L::Active { return Err(InvestigationError::InvalidTransition); }
            next.record.state = L::Active;
        }
        InvestigationChange::Cite { hypothesis, evidence, contradicts } => {
            let h = next.record.hypotheses.iter_mut().find(|h| &h.hypothesis_id == hypothesis)
                .ok_or(InvestigationError::InvalidRecord)?;
            let (roots, limit) = if *contradicts { (&mut h.contradictions, 128) }
                else { (&mut h.evidence, 256) };
            if !roots.contains(evidence) {
                if roots.len() >= limit { return Err(InvestigationError::CapacityExceeded); }
                roots.push(*evidence);
                roots.sort();
            }
        }
        InvestigationChange::Assess { hypothesis, disposition, evidence } => {
            if next.record.state != L::Active { return Err(InvestigationError::InvalidTransition); }
            let h = next.record.hypotheses.iter().find(|h| &h.hypothesis_id == hypothesis)
                .ok_or(InvestigationError::InvalidRecord)?;
            let valid = match disposition {
                HypothesisDisposition::Supported => h.evidence.contains(evidence),
                HypothesisDisposition::Disfavored | HypothesisDisposition::Refuted => h.contradictions.contains(evidence),
                _ => false,
            };
            if !valid || next.validity.as_ref().is_some_and(|validity| {
                validity.needs_readmission(hypothesis, *evidence,
                    *disposition != HypothesisDisposition::Supported)
            }) { return Err(InvestigationError::EvidenceRequired); }
            next.control.advance_hypothesis(hypothesis, *disposition)
                .map_err(|_| InvestigationError::InvalidTransition)?;
            next.assessment = Some(*evidence);
        }
        InvestigationChange::SetState { state, reason } => {
            if !matches!(state, L::AwaitingEvidence | L::AwaitingApproval | L::Blocked
                | L::Indeterminate | L::Cancelled) || *state == next.record.state
            { return Err(InvestigationError::InvalidTransition); }
            next.record.state = *state;
            next.assessment = Some(*reason);
        }
        InvestigationChange::Conclude { refuted, stop_rule, assessment, residual_unknowns } => {
            if next.record.state != L::Active { return Err(InvestigationError::InvalidTransition); }
            let mut unknowns: BTreeSet<String> = next.record.unknowns.iter()
                .map(|s| s.statement_id.clone()).collect();
            if next.validity.is_some() {
                unknowns.extend(next.record.knowns.iter()
                    .filter(|s| s.epistemic_state == fss_core::KnowledgeState::Stale)
                    .map(|s| s.statement_id.clone()));
            }
            if !next.record.stop_rules.contains(stop_rule) || residual_unknowns != &unknowns {
                return Err(InvestigationError::ResidualsRequired);
            }
            let dispositions = next.control.hypotheses();
            let valid = if *refuted {
                dispositions.values().all(|d| *d == HypothesisDisposition::Refuted)
            } else {
                dispositions.values().any(|d| *d == HypothesisDisposition::Supported)
            };
            if !valid { return Err(InvestigationError::UnresolvedAlternatives); }
            next.control.stop(HypothesisDisposition::Resolved)
                .map_err(|_| InvestigationError::UnresolvedAlternatives)?;
            next.record.state = if *refuted { L::Refuted } else { L::Resolved };
            next.assessment = Some(*assessment);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;

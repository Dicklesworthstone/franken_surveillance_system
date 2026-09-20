#![forbid(unsafe_code)]
//! Immutable, session-authorized workspace revisions (FSS-204).
//!
//! This is a bounded cognition store, not an evidence authority or an effect executor. The
//! runtime authenticates principals and supplies the session store and clock. Capsule references
//! remain references: publishing them does not prove their contents or grant an effect. Revoking
//! any captured capability or privacy grant makes the old revision unavailable until an explicit projection is
//! implemented. Failed session checks may update clock/expiry state and must also be persisted.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, ContractBasis, ContractError, LedgerAnchor,
    MissionId, PrincipalId, SessionCapsule, SessionCapsuleParams, SessionId, TimestampNs,
};

use super::{ReferenceSessionError, ReferenceSessionStore, SessionEntry};

/// Canonical recovery of the complete private workspace revision history.
pub mod checkpoint;

/// Hard ceiling on one serialized revision, including its private authorization projection.
pub const MAX_WORKSPACE_REVISION_BYTES: usize = 1024 * 1024;
/// Hard ceiling on the aggregate serialized revision history.
pub const MAX_WORKSPACE_HISTORY_BYTES: usize = 16 * 1024 * 1024;
const MAX_WORKSPACES: usize = 1024;
const MAX_REVISIONS: usize = 1024;
const MAX_ITEMS: usize = 4096;
const MAX_ITEM_BYTES: usize = 4096;
const REVISION_DOMAIN: &str = "fss.reference_workspace_revision.v2";

/// Finite storage limits. Zero means no capacity, not unlimited storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkspaceLimits {
    /// Maximum distinct session workspaces; histories are never silently evicted.
    pub max_workspaces: usize,
    /// Maximum retained revisions per workspace.
    pub max_revisions_per_workspace: usize,
    /// Maximum canonical bytes per revision.
    pub max_revision_bytes: usize,
    /// Maximum aggregate canonical bytes across all revisions.
    pub max_history_bytes: usize,
}

impl Default for WorkspaceLimits {
    fn default() -> Self {
        Self {
            max_workspaces: 128,
            max_revisions_per_workspace: 64,
            max_revision_bytes: 256 * 1024,
            max_history_bytes: MAX_WORKSPACE_HISTORY_BYTES,
        }
    }
}

impl WorkspaceLimits {
    fn bounded(self) -> Self {
        Self {
            max_workspaces: self.max_workspaces.min(MAX_WORKSPACES),
            max_revisions_per_workspace: self.max_revisions_per_workspace.min(MAX_REVISIONS),
            max_revision_bytes: self.max_revision_bytes.min(MAX_WORKSPACE_REVISION_BYTES),
            max_history_bytes: self.max_history_bytes.min(MAX_WORKSPACE_HISTORY_BYTES),
        }
    }
}

/// An anchor move is never inferred from an ordinary workspace write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceWriteMode {
    /// Create revision zero or append at the same exact authority anchor.
    Advance,
    /// Explicitly move to the live session anchor, retaining uncertainty and invalidating actions.
    Rebase,
}

/// Optimistically fenced cognition write. The predecessor is a revision digest, not a revision
/// number or an implicit latest alias.
#[derive(Clone, Debug)]
pub struct WorkspaceWrite {
    /// None only for the initial revision; otherwise the exact retained predecessor.
    pub expected_head: Option<ContentDigest>,
    /// Exact registered session-capsule payload to retain.
    pub capsule: SessionCapsule,
    /// Explicit ordinary-write or rebase intent.
    pub mode: WorkspaceWriteMode,
}

/// A sealed revision. Fields cannot be mutated independently of the content identity.
#[derive(Clone, Debug, PartialEq)]
pub struct WorkspaceRevision {
    capsule: SessionCapsule,
    basis: ContractBasis,
    mission_id: MissionId,
    capability_scope: BTreeSet<String>,
    privacy_scope: BTreeSet<String>,
    parent: Option<ContentDigest>,
    rebase_from: Option<LedgerAnchor>,
    invalidated_actions: Vec<String>,
    bytes: Vec<u8>,
    digest: ContentDigest,
}

impl WorkspaceRevision {
    /// Archived cognition, not current authority or an executable effect plan.
    #[must_use]
    pub const fn capsule(&self) -> &SessionCapsule {
        &self.capsule
    }

    /// Exact contract basis captured from the authorizing session.
    #[must_use]
    pub const fn contract_basis(&self) -> &ContractBasis {
        &self.basis
    }

    /// Content identity covering payload, authorization projection, predecessor, and rebase.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    /// Exact predecessor, absent only for revision zero.
    #[must_use]
    pub const fn parent_digest(&self) -> Option<ContentDigest> {
        self.parent
    }

    /// Prior actions that a rebase retained as invalidated rather than silently executing.
    #[must_use]
    pub fn invalidated_actions(&self) -> &[String] {
        &self.invalidated_actions
    }

    /// Private canonical bytes for protected custody; not a public response serialization.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Exact-resume result. Old bytes are returned as history with explicit invalidations, never
/// silently substituted by a newer revision or relabeled as current evidence.
#[derive(Clone, Debug, PartialEq)]
pub struct WorkspaceResume {
    /// The exact requested revision.
    pub revision: WorkspaceRevision,
    /// The actual retained head, to use in a deliberate subsequent write.
    pub head_digest: ContentDigest,
    /// A newer workspace revision exists; this result is historical.
    pub superseded: bool,
    /// The live session is at a different anchor; reorientation/rebase is required.
    pub rebase_required: bool,
}

/// Refusals do not disclose principal identities, evidence handles, or private payloads.
#[derive(Debug)]
pub enum WorkspaceError {
    /// Missing, unauthorized, or no longer authorized workspace revision.
    Unavailable,
    /// The expected parent is not the current head, or an identity was reused with different data.
    StaleHead,
    /// A revision skipped, wrapped, or attempted to start other than at zero.
    InvalidRevision,
    /// Ordinary writes cannot move the authority anchor.
    RebaseRequired,
    /// Cross-lineage, cross-epoch, rollback, or equal-sequence fork.
    InvalidAnchor,
    /// A write would drop protected material or retain unreviewed actions across a rebase.
    PreservationRequired,
    /// A finite count or byte limit would be exceeded.
    CapacityExceeded,
    /// A capsule violates its core contract.
    Contract(ContractError),
    /// Live session admission failed, before any private workspace lookup.
    Session(ReferenceSessionError),
}

impl fmt::Display for WorkspaceError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::Unavailable => "workspace unavailable",
            Self::StaleHead => "workspace head changed; resume the exact revision before retrying",
            Self::InvalidRevision => "invalid workspace revision succession",
            Self::RebaseRequired => "workspace requires explicit rebase",
            Self::InvalidAnchor => "workspace anchor is not an admitted successor",
            Self::PreservationRequired => "workspace must preserve protected material and invalidate stale actions",
            Self::CapacityExceeded => "workspace storage capacity exceeded",
            Self::Contract(_) => "invalid workspace capsule",
            Self::Session(_) => "workspace session admission refused",
        })
    }
}

impl std::error::Error for WorkspaceError {}

impl From<ContractError> for WorkspaceError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}

impl From<ReferenceSessionError> for WorkspaceError {
    fn from(value: ReferenceSessionError) -> Self {
        Self::Session(value)
    }
}

/// Bounded immutable workspace histories, with one writer head per session.
#[derive(Clone, Debug)]
pub struct ReferenceWorkspaceStore {
    histories: BTreeMap<SessionId, Vec<WorkspaceRevision>>,
    limits: WorkspaceLimits,
    retained_bytes: usize,
}

impl Default for ReferenceWorkspaceStore {
    fn default() -> Self {
        Self::with_limits(WorkspaceLimits::default())
    }
}

impl ReferenceWorkspaceStore {
    /// Creates a store with requested limits clamped to the format's hard ceilings.
    #[must_use]
    pub fn with_limits(limits: WorkspaceLimits) -> Self {
        Self { histories: BTreeMap::new(), limits: limits.bounded(), retained_bytes: 0 }
    }

    /// Appends atomically in memory. Exact lost-acknowledgement retries return the original
    /// revision without spending capacity or resetting the head. They remain subject to today's
    /// session grants. No identity can be overwritten, recycled, or implicitly rebased.
    pub fn publish(
        &mut self,
        sessions: &mut ReferenceSessionStore,
        principal: &PrincipalId,
        request: WorkspaceWrite,
        now: TimestampNs,
    ) -> Result<WorkspaceRevision, WorkspaceError> {
        let entry = sessions.live_entry(principal, &request.capsule.session_id, now)?;
        validate_capsule(&request.capsule, self.limits.max_revision_bytes)?;
        if request.capsule.principal != principal.as_str()
            || request.capsule.capability_projection.iter().any(|cap| !entry.session.capabilities.contains(cap))
        {
            return Err(WorkspaceError::Unavailable);
        }
        let history = self.histories.get(&request.capsule.session_id);
        if let Some(existing) = history.and_then(|items| items.iter().find(|item| item.capsule.revision == request.capsule.revision)) {
            authorize_revision(entry, existing)?;
            if existing.capsule == request.capsule
                && existing.parent == request.expected_head
                && existing.rebase_from.is_some() == (request.mode == WorkspaceWriteMode::Rebase)
            {
                return Ok(existing.clone());
            }
            return Err(WorkspaceError::StaleHead);
        }
        if request.capsule.current_anchor != entry.session.current_anchor {
            return Err(WorkspaceError::InvalidAnchor);
        }
        let previous = history.and_then(|items| items.last());
        if let Some(previous) = previous {
            authorize_revision(entry, previous)?;
        }
        let rebase_from = validate_successor(previous, &request)?;
        let invalidated_actions = if rebase_from.is_some() {
            previous.map_or_else(Vec::new, |item| item.capsule.next_actions.clone())
        } else {
            Vec::new()
        };
        if entry.session.privacy_scope.len() > MAX_ITEMS
            || entry.session.capabilities.len() > MAX_ITEMS
        {
            return Err(WorkspaceError::CapacityExceeded);
        }
        let mut scope_bytes = 0_usize;
        for scope in entry.session.capabilities.iter().chain(&entry.session.privacy_scope) {
            if scope.len() > MAX_ITEM_BYTES { return Err(WorkspaceError::CapacityExceeded); }
            scope_bytes = scope_bytes.checked_add(scope.len()).and_then(|n| n.checked_add(8))
                .filter(|n| *n <= self.limits.max_revision_bytes)
                .ok_or(WorkspaceError::CapacityExceeded)?;
        }
        let mut revision = WorkspaceRevision {
            capsule: request.capsule,
            basis: entry.basis.clone(),
            mission_id: entry.session.mission_id.clone(),
            capability_scope: entry.session.capabilities.clone(),
            privacy_scope: entry.session.privacy_scope.clone(),
            parent: request.expected_head,
            rebase_from,
            invalidated_actions,
            bytes: Vec::new(),
            digest: ContentDigest::sha256(&[]),
        };
        revision.bytes = encode_revision(&revision)?;
        if revision.bytes.len() > self.limits.max_revision_bytes
            || history.map_or(0, Vec::len) >= self.limits.max_revisions_per_workspace
            || (history.is_none() && self.histories.len() >= self.limits.max_workspaces)
        {
            return Err(WorkspaceError::CapacityExceeded);
        }
        let total = self.retained_bytes.checked_add(revision.bytes.len())
            .filter(|total| *total <= self.limits.max_history_bytes)
            .ok_or(WorkspaceError::CapacityExceeded)?;
        revision.digest = ContentDigest::sha256(&revision.bytes);
        self.histories.entry(revision.capsule.session_id.clone()).or_default().push(revision.clone());
        self.retained_bytes = total;
        Ok(revision)
    }

    /// Resumes only the requested immutable identity, after rechecking live-session authority.
    pub fn resume(
        &self,
        sessions: &mut ReferenceSessionStore,
        principal: &PrincipalId,
        session_id: &SessionId,
        digest: ContentDigest,
        now: TimestampNs,
    ) -> Result<WorkspaceResume, WorkspaceError> {
        let entry = sessions.live_entry(principal, session_id, now)?;
        let history = self.histories.get(session_id).ok_or(WorkspaceError::Unavailable)?;
        let revision = history.iter().find(|item| item.digest == digest).ok_or(WorkspaceError::Unavailable)?;
        authorize_revision(entry, revision)?;
        let head = history.last().ok_or(WorkspaceError::Unavailable)?;
        // A narrowed projection must not disclose even the head identity of a wider revision.
        authorize_revision(entry, head)?;
        Ok(WorkspaceResume {
            revision: revision.clone(),
            head_digest: head.digest,
            superseded: head.digest != digest,
            rebase_required: revision.capsule.current_anchor != entry.session.current_anchor,
        })
    }

    /// Exact retained canonical-byte charge. This is storage accounting, not an effect budget.
    #[must_use]
    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }
}

fn authorize_revision(entry: &SessionEntry, revision: &WorkspaceRevision) -> Result<(), WorkspaceError> {
    if revision.basis != entry.basis
        || revision.mission_id != entry.session.mission_id
        || revision.capsule.principal != entry.session.principal_id.as_str()
        || !revision.capability_scope.is_subset(&entry.session.capabilities)
        || !revision.privacy_scope.is_subset(&entry.session.privacy_scope)
        || revision.capsule.capability_projection.iter().any(|cap| !entry.session.capabilities.contains(cap))
    {
        return Err(WorkspaceError::Unavailable);
    }
    Ok(())
}

fn anchor_successor(old: &LedgerAnchor, new: &LedgerAnchor) -> bool {
    old == new || (old.site_lineage == new.site_lineage
        && old.ledger_epoch == new.ledger_epoch
        && new.commit_sequence > old.commit_sequence
        && new.adapter_registry_epoch >= old.adapter_registry_epoch)
}

fn contains_all<T: Ord>(new: &[T], old: &[T]) -> bool {
    let retained: BTreeSet<_> = new.iter().collect();
    old.iter().all(|item| retained.contains(item))
}

fn validate_successor(previous: Option<&WorkspaceRevision>, request: &WorkspaceWrite) -> Result<Option<LedgerAnchor>, WorkspaceError> {
    let new = &request.capsule;
    let Some(previous) = previous else {
        if request.expected_head.is_some() { return Err(WorkspaceError::StaleHead); }
        if new.revision != 0 { return Err(WorkspaceError::InvalidRevision); }
        if request.mode != WorkspaceWriteMode::Advance || new.base_anchor != new.current_anchor {
            return Err(WorkspaceError::InvalidAnchor);
        }
        return Ok(None);
    };
    let old = &previous.capsule;
    if request.expected_head != Some(previous.digest) { return Err(WorkspaceError::StaleHead); }
    if old.revision.checked_add(1) != Some(new.revision) { return Err(WorkspaceError::InvalidRevision); }
    if old.objective_digest != new.objective_digest || old.base_anchor != new.base_anchor {
        return Err(WorkspaceError::InvalidAnchor);
    }
    for (new, old) in [
        (&new.unknowns, &old.unknowns),
        (&new.not_observable_domains, &old.not_observable_domains),
        (&new.epistemic_debt, &old.epistemic_debt),
        (&new.open_obligations, &old.open_obligations),
        (&new.active_hypotheses, &old.active_hypotheses),
    ] {
        if !contains_all(new, old) { return Err(WorkspaceError::PreservationRequired); }
    }
    if !contains_all(&new.bookmarked_evidence, &old.bookmarked_evidence) {
        return Err(WorkspaceError::PreservationRequired);
    }
    match request.mode {
        WorkspaceWriteMode::Advance => {
            if old.current_anchor != new.current_anchor { return Err(WorkspaceError::RebaseRequired); }
            if !contains_all(&new.next_actions, &old.next_actions) {
                return Err(WorkspaceError::PreservationRequired);
            }
            // Removing an assumption must preserve it explicitly as debt, not erase it.
            let retained: BTreeSet<_> = new.assumptions.iter().chain(&new.epistemic_debt).collect();
            if old.assumptions.iter().any(|item| !retained.contains(item)) {
                return Err(WorkspaceError::PreservationRequired);
            }
            Ok(None)
        }
        WorkspaceWriteMode::Rebase => {
            if old.current_anchor == new.current_anchor || !anchor_successor(&old.current_anchor, &new.current_anchor) {
                return Err(WorkspaceError::InvalidAnchor);
            }
            if old.situation_capsule_digest == new.situation_capsule_digest
                || old.decision_digest == new.decision_digest
                || !new.next_actions.is_empty()
                || !contains_all(&new.epistemic_debt, &old.assumptions)
                || !contains_all(&new.active_hypotheses, &old.active_hypotheses)
            {
                return Err(WorkspaceError::PreservationRequired);
            }
            Ok(Some(old.current_anchor.clone()))
        }
    }
}

fn validate_capsule(value: &SessionCapsule, byte_limit: usize) -> Result<(), WorkspaceError> {
    // Bound input before cloning or invoking the core canonical encoder. No list count is cast
    // until it has been checked against the schema ceiling and the aggregate byte ceiling.
    for text in [
        value.principal.as_str(), value.objective_digest.as_str(),
        value.situation_capsule_digest.as_str(), value.decision_digest.as_str(),
        value.base_anchor.site_lineage.as_str(), value.current_anchor.site_lineage.as_str(),
    ] {
        if text.len() > 256 { return Err(WorkspaceError::CapacityExceeded); }
    }
    let mut bytes = 0_usize;
    for group in [
        &value.capability_projection, &value.active_hypotheses, &value.assumptions,
        &value.unknowns, &value.not_observable_domains, &value.epistemic_debt,
        &value.open_obligations, &value.next_actions,
    ] {
        if group.len() > MAX_ITEMS { return Err(WorkspaceError::CapacityExceeded); }
        for item in group {
            if item.len() > MAX_ITEM_BYTES { return Err(WorkspaceError::CapacityExceeded); }
            bytes = bytes.checked_add(item.len()).and_then(|n| n.checked_add(8))
                .filter(|n| *n <= byte_limit).ok_or(WorkspaceError::CapacityExceeded)?;
        }
    }
    if value.epistemic_debt.len() > 1024 || value.bookmarked_evidence.len() > MAX_ITEMS {
        return Err(WorkspaceError::CapacityExceeded);
    }
    let _ = bytes.checked_add(value.bookmarked_evidence.len() * 33)
        .filter(|n| *n <= byte_limit).ok_or(WorkspaceError::CapacityExceeded)?;
    // The core fields are public. Re-run construction rather than trusting a once-valid value.
    SessionCapsule::new(SessionCapsuleParams {
        session_id: value.session_id.clone(), revision: value.revision, principal: value.principal.clone(),
        capability_projection: value.capability_projection.clone(), objective_digest: value.objective_digest.clone(),
        base_anchor: value.base_anchor.clone(), current_anchor: value.current_anchor.clone(),
        situation_capsule_digest: value.situation_capsule_digest.clone(), active_hypotheses: value.active_hypotheses.clone(),
        assumptions: value.assumptions.clone(), unknowns: value.unknowns.clone(),
        not_observable_domains: value.not_observable_domains.clone(), epistemic_debt: value.epistemic_debt.clone(),
        open_obligations: value.open_obligations.clone(), budget_ledger: value.budget_ledger,
        bookmarked_evidence: value.bookmarked_evidence.clone(), next_actions: value.next_actions.clone(),
        decision_digest: value.decision_digest.clone(),
    })?;
    if !anchor_successor(&value.base_anchor, &value.current_anchor) {
        return Err(WorkspaceError::InvalidAnchor);
    }
    Ok(())
}

fn encode_revision(value: &WorkspaceRevision) -> Result<Vec<u8>, WorkspaceError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(REVISION_DOMAIN);
    value.basis.encode_canonical(&mut encoder);
    value.mission_id.encode_canonical(&mut encoder);
    // Capture actual authority, not just the caller-declared capability projection. Otherwise
    // an empty declaration could make sensitive history readable after capability revocation.
    for scopes in [&value.capability_scope, &value.privacy_scope] {
        encoder.u64(scopes.len() as u64);
        for scope in scopes { encoder.text(scope); }
    }
    encoder.bool(value.parent.is_some());
    if let Some(parent) = value.parent { encoder.digest(parent); }
    encoder.bool(value.rebase_from.is_some());
    if let Some(anchor) = &value.rebase_from { anchor.encode_canonical(&mut encoder); }
    encoder.u64(value.invalidated_actions.len() as u64);
    for action in &value.invalidated_actions { encoder.text(action); }
    value.capsule.encode_canonical(&mut encoder);
    Ok(encoder.finish_checked()?)
}

#[cfg(test)]
mod tests;

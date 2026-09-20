#![forbid(unsafe_code)]
//! Graph-aware expiry over one exclusively owned, bounded reference custody store.
//!
//! This is not a remote deletion service or authentication boundary. The trusted runtime assigns
//! retention rules, declares every derivative dependency, projects grants, and supplies time.
//! There is no mutable escape to custody: an unregistered object cannot bypass graph protection.
//! Only this owner's local graph is covered, never external exports, replicas, or allocator copies.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, ContractError, TimestampNs};
use crate::{InMemoryObjectStore, ObjectError, ObjectLimits, ObjectManifest, ObjectState};

mod execute;
pub use execute::{DeletionReceipt, RetentionAuthorization};

/// Hard ceiling on retained identities, including permanent tombstones.
pub const MAX_RETENTION_ENTRIES: usize = 16_384;
/// Hard ceiling on declared graph edges across all identities.
pub const MAX_RETENTION_EDGES: usize = 65_536;
/// Hard ceiling on retained hold identities, including released holds.
pub const MAX_RETENTION_HOLDS: usize = 4_096;
/// Hard ceiling on completed deletion receipts; receipts are never evicted implicitly.
pub const MAX_RETENTION_RECEIPTS: usize = 4_096;
const MAX_TEXT: usize = 1_024;

/// Finite metadata ceilings, independent of custody's byte and object ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionLimits {
    /// Live entries and permanent deletion tombstones.
    pub max_entries: usize,
    /// Total source and manifest dependency edges.
    pub max_edges: usize,
    /// Active and released hold identities.
    pub max_holds: usize,
    /// Completed deletion invocations retained for exact retry.
    pub max_receipts: usize,
}
impl Default for RetentionLimits {
    fn default() -> Self {
        Self { max_entries: MAX_RETENTION_ENTRIES, max_edges: MAX_RETENTION_EDGES,
            max_holds: MAX_RETENTION_HOLDS, max_receipts: MAX_RETENTION_RECEIPTS }
    }
}

/// Explicit policy-owned deadline and bounded machine-readable reason; no default duration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionRule {
    /// Earliest runtime time at which expiry may be considered.
    pub retain_until: TimestampNs,
    /// Stable policy rule/reason identity, not an authority grant.
    pub reason: String,
}

/// Work limits for one sweep. Partial selection is explicit and dependency-safe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionBudget {
    /// Maximum selected local objects, including manifest objects.
    pub max_objects: usize,
    /// Maximum selected payload bytes to release.
    pub max_deleted_bytes: u64,
    /// Maximum additional payload bytes for the reference transaction's custody clone.
    pub max_staging_bytes: u64,
}

/// Retention failures never report a partially committed deletion as success.
#[derive(Debug)]
pub enum RetentionError {
    /// Existing custody verification, quota, or tombstone failure.
    Custody(ObjectError),
    /// Shared identity, generation, or canonical encoding failure.
    Contract(ContractError),
    /// Invalid bounded text or structurally inconsistent metadata.
    InvalidRecord,
    /// A source dependency or hold subject is not live in this owner's graph.
    UnknownObject,
    /// Same bytes were assigned different dependency, kind, or retention semantics.
    ConflictingRegistration,
    /// An installed hold identity cannot be rewritten or reused after release.
    HoldConflict,
    /// The supplied policy/graph/plan precondition no longer matches.
    StalePlan,
    /// Explicit runtime-projected deletion authority is insufficient or expired.
    Unauthorized,
    /// Trusted runtime time regressed or predates plan preparation.
    ClockRegression,
    /// A hard metadata, receipt, or counter limit was reached.
    CapacityExceeded,
    /// The transaction's additional payload memory would exceed its explicit ceiling.
    StagingBudgetExceeded,
    /// A plan selected no objects; no deletion was attempted.
    NoWork,
}
impl fmt::Display for RetentionError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(match self {
            Self::Custody(_) => "retention custody verification failed",
            Self::Contract(_) | Self::InvalidRecord => "invalid retention record",
            Self::UnknownObject => "retention object unavailable",
            Self::ConflictingRegistration => "retention registration conflict",
            Self::HoldConflict => "retention hold conflict",
            Self::StalePlan => "retention plan is stale",
            Self::Unauthorized => "retention deletion authority refused",
            Self::ClockRegression => "retention clock regressed",
            Self::CapacityExceeded => "retention capacity exceeded",
            Self::StagingBudgetExceeded => "retention staging budget exceeded",
            Self::NoWork => "retention plan selected no objects",
        })
    }
}
impl std::error::Error for RetentionError {}
impl From<ObjectError> for RetentionError {
    fn from(error: ObjectError) -> Self { Self::Custody(error) }
}
impl From<ContractError> for RetentionError {
    fn from(error: ContractError) -> Self { Self::Contract(error) }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Entry {
    rule: RetentionRule,
    dependencies: BTreeSet<ContentDigest>,
    bytes: u64,
    manifest: bool,
    deleted_by: Option<ContentDigest>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Hold {
    subject: ContentDigest,
    witness: ContentDigest,
    released_by: Option<ContentDigest>,
}

/// One bounded, reproducible sweep. Private fields prevent unvalidated caller-edited plans.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionPlan {
    state: ContentDigest,
    policy: ContentDigest,
    prepared_at: TimestampNs,
    budget: RetentionBudget,
    selected: Vec<ContentDigest>,
    selected_bytes: u64,
    blocked_due: BTreeSet<ContentDigest>,
    deferred_due: BTreeSet<ContentDigest>,
    held_roots: BTreeSet<ContentDigest>,
    not_due: BTreeSet<ContentDigest>,
    digest: ContentDigest,
}
impl RetentionPlan {
    /// Exact plan identity; it is a precondition, not authority.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest { self.digest }
    /// Exact metadata state against which the plan was constructed.
    #[must_use]
    pub const fn state_digest(&self) -> ContentDigest { self.state }
    /// Dependents-first deletion order; every prefix preserves retained dependencies.
    #[must_use]
    pub fn selected(&self) -> &[ContentDigest] { &self.selected }
    /// Quoted payload bytes to release locally; not filesystem or provider accounting.
    #[must_use]
    pub const fn selected_bytes(&self) -> u64 { self.selected_bytes }
    /// Expired objects protected by a hold or by a still-retained dependent.
    #[must_use]
    pub fn blocked_due(&self) -> &BTreeSet<ContentDigest> { &self.blocked_due }
    /// Otherwise eligible objects deferred by this batch's limits or a deferred dependent.
    #[must_use]
    pub fn deferred_due(&self) -> &BTreeSet<ContentDigest> { &self.deferred_due }
    /// Active hold subjects and hold witnesses whose dependency closures were preserved.
    #[must_use]
    pub fn held_roots(&self) -> &BTreeSet<ContentDigest> { &self.held_roots }
    /// Objects whose own deadline has not passed; their dependencies are protected too.
    #[must_use]
    pub fn not_due(&self) -> &BTreeSet<ContentDigest> { &self.not_due }

    fn computed_digest(&self) -> Result<ContentDigest, RetentionError> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.reference_retention_plan.v1");
        e.digest(self.state); e.digest(self.policy); e.i128(self.prepared_at.0);
        e.u64(self.budget.max_objects as u64); e.u64(self.budget.max_deleted_bytes);
        e.u64(self.budget.max_staging_bytes); e.u64(self.selected_bytes);
        e.u64(self.selected.len() as u64);
        for digest in &self.selected { e.digest(*digest); }
        for set in [&self.blocked_due, &self.deferred_due, &self.held_roots, &self.not_due] {
            encode_set(set, &mut e);
        }
        Ok(ContentDigest::sha256(&e.finish_checked()?))
    }
}

/// Exclusive in-process custody and retention owner, with bounded metadata and no implicit eviction.
///
/// All object references must be registered here. A source is opaque; a derivative explicitly
/// names its sources; a manifest uses its actual child closure, including metadata. There is no
/// global claim about undeclared derivatives or third-party copies. Source bytes stay solely in
/// custody except for the explicitly budgeted transaction clone during a deletion commit.
#[derive(Debug)]
pub struct RetentionStore {
    custody: InMemoryObjectStore,
    policy: ContentDigest,
    limits: RetentionLimits,
    entries: BTreeMap<ContentDigest, Entry>,
    holds: BTreeMap<String, Hold>,
    receipts: BTreeMap<ContentDigest, DeletionReceipt>,
    revision: u64,
    last_commit_at: Option<TimestampNs>,
}
impl RetentionStore {
    /// Creates a new, empty owner. Existing untracked custody is never silently adopted.
    #[must_use]
    pub fn new(policy: ContentDigest, objects: ObjectLimits, limits: RetentionLimits) -> Self {
        Self { custody: InMemoryObjectStore::new(objects), policy, limits,
            entries: BTreeMap::new(), holds: BTreeMap::new(), receipts: BTreeMap::new(),
            revision: 0, last_commit_at: None }
    }

    /// Read-only custody capability for existing publication and hydration readers.
    /// A digest or this reference does not authenticate an agent or grant disclosure authority.
    #[must_use]
    pub const fn custody(&self) -> &InMemoryObjectStore { &self.custody }

    /// Registers opaque source bytes with an explicit policy rule before exposing their identity.
    pub fn put_source(&mut self, bytes: &[u8], rule: RetentionRule) -> Result<ContentDigest, RetentionError> {
        self.put(bytes, rule, BTreeSet::new(), None)
    }

    /// Registers exact derivative bytes and EVERY controlled source dependency.
    /// A live derivative keeps its entire source closure retained, including shared sources.
    pub fn put_derivative(&mut self, bytes: &[u8], rule: RetentionRule,
        sources: BTreeSet<ContentDigest>) -> Result<ContentDigest, RetentionError>
    {
        if sources.is_empty() { return Err(RetentionError::InvalidRecord); }
        self.put(bytes, rule, sources, None)
    }

    /// Root-last publication assigns retention to the manifest AND registers its real children.
    /// Metadata is already included by `ObjectManifest`; opaque manifest-shaped bytes stay opaque.
    pub fn publish_manifest(&mut self, manifest: ObjectManifest, rule: RetentionRule)
        -> Result<ContentDigest, RetentionError>
    {
        let bytes = manifest.try_canonical_bytes()?;
        let dependencies = manifest.children().iter().copied().collect();
        self.put(&bytes, rule, dependencies, Some(manifest))
    }

    fn put(&mut self, bytes: &[u8], rule: RetentionRule, dependencies: BTreeSet<ContentDigest>,
        manifest: Option<ObjectManifest>) -> Result<ContentDigest, RetentionError>
    {
        if !valid_text(&rule.reason) { return Err(RetentionError::InvalidRecord); }
        let digest = ContentDigest::sha256(bytes);
        let entry = Entry { rule, dependencies, bytes: bytes.len() as u64,
            manifest: manifest.is_some(), deleted_by: None };
        if let Some(existing) = self.entries.get(&digest) {
            if existing != &entry { return Err(RetentionError::ConflictingRegistration); }
            self.custody.read_verified(digest)?;
            return Ok(digest);
        }
        if self.entries.len() >= self.limits.max_entries.min(MAX_RETENTION_ENTRIES) {
            return Err(RetentionError::CapacityExceeded);
        }
        let edges = self.entries.values().try_fold(entry.dependencies.len(), |n, entry|
            n.checked_add(entry.dependencies.len())).ok_or(RetentionError::CapacityExceeded)?;
        if edges > self.limits.max_edges.min(MAX_RETENTION_EDGES) {
            return Err(RetentionError::CapacityExceeded);
        }
        // Dependencies must predate a NEW node. Exact duplicates cannot rewrite edges, so cycles
        // are impossible without corrupting private metadata. Self-reference is explicitly refused.
        for dependency in &entry.dependencies {
            if *dependency == digest { return Err(RetentionError::InvalidRecord); }
            self.live_entry(*dependency)?;
            self.custody.read_verified(*dependency)?;
        }
        let next = self.revision.checked_add(1).ok_or(RetentionError::CapacityExceeded)?;
        match manifest {
            Some(manifest) => { self.custody.publish_manifest(manifest)?; }
            None => { self.custody.put_verified(bytes)?; }
        }
        self.entries.insert(digest, entry);
        self.revision = next;
        Ok(digest)
    }

    /// Installs a runtime-authorized evidence/legal hold with an exact state precondition.
    /// Both the subject closure and witness closure remain pinned until an explicit release.
    pub fn add_hold(&mut self, expected_state: ContentDigest, id: &str, subject: ContentDigest,
        witness: ContentDigest) -> Result<(), RetentionError>
    {
        if !valid_text(id) { return Err(RetentionError::InvalidRecord); }
        if self.state_digest()? != expected_state { return Err(RetentionError::StalePlan); }
        self.live_entry(subject)?; self.live_entry(witness)?;
        self.custody.read_verified(subject)?; self.custody.read_verified(witness)?;
        let hold = Hold { subject, witness, released_by: None };
        if let Some(existing) = self.holds.get(id) {
            return if existing == &hold { Ok(()) } else { Err(RetentionError::HoldConflict) };
        }
        if self.holds.len() >= self.limits.max_holds.min(MAX_RETENTION_HOLDS) {
            return Err(RetentionError::CapacityExceeded);
        }
        let next = self.revision.checked_add(1).ok_or(RetentionError::CapacityExceeded)?;
        self.holds.insert(id.to_owned(), hold); self.revision = next;
        Ok(())
    }

    /// Explicit runtime-authorized hold release. Released hold IDs remain permanent tombstones.
    /// The verified release witness is an audit reference, not cryptographic authentication.
    pub fn release_hold(&mut self, expected_state: ContentDigest, id: &str,
        witness: ContentDigest) -> Result<(), RetentionError>
    {
        if self.state_digest()? != expected_state { return Err(RetentionError::StalePlan); }
        self.live_entry(witness)?; self.custody.read_verified(witness)?;
        let hold = self.holds.get(id).ok_or(RetentionError::HoldConflict)?;
        if let Some(previous) = hold.released_by {
            return if previous == witness { Ok(()) } else { Err(RetentionError::HoldConflict) };
        }
        let next = self.revision.checked_add(1).ok_or(RetentionError::CapacityExceeded)?;
        self.holds.get_mut(id).ok_or(RetentionError::HoldConflict)?.released_by = Some(witness);
        self.revision = next;
        Ok(())
    }

    /// Exact policy/graph/hold/deletion state fingerprint; contains no source payload bytes.
    pub fn state_digest(&self) -> Result<ContentDigest, RetentionError> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.reference_retention_state.v1"); e.digest(self.policy); e.u64(self.revision);
        for limit in [self.limits.max_entries, self.limits.max_edges, self.limits.max_holds,
            self.limits.max_receipts] { e.u64(limit as u64); }
        e.u64(self.custody.limits().max_objects as u64); e.u64(self.custody.limits().max_total_bytes);
        e.bool(self.last_commit_at.is_some());
        if let Some(time) = self.last_commit_at { e.i128(time.0); }
        e.u64(self.entries.len() as u64);
        for (digest, entry) in &self.entries {
            e.digest(*digest); e.i128(entry.rule.retain_until.0); e.text(&entry.rule.reason);
            e.u64(entry.bytes); e.bool(entry.manifest); encode_set(&entry.dependencies, &mut e);
            e.bool(entry.deleted_by.is_some());
            if let Some(plan) = entry.deleted_by { e.digest(plan); }
        }
        e.u64(self.holds.len() as u64);
        for (id, hold) in &self.holds {
            e.text(id); e.digest(hold.subject); e.digest(hold.witness);
            e.bool(hold.released_by.is_some());
            if let Some(witness) = hold.released_by { e.digest(witness); }
        }
        Ok(ContentDigest::sha256(&e.finish_checked()?))
    }

    /// Prepares expiry without mutation. Retention propagates backwards through the full graph.
    /// Eligible objects are selected dependents-first with deterministic digest tie-breaking;
    /// a byte-limited skipped dependent keeps its sources deferred, never dangling.
    /// Work is bounded by the owner's entry/edge ceilings and exact custody payload byte ceiling.
    pub fn prepare_expiry(&self, now: TimestampNs, budget: RetentionBudget)
        -> Result<RetentionPlan, RetentionError>
    {
        if self.last_commit_at.is_some_and(|last| now < last) {
            return Err(RetentionError::ClockRegression);
        }
        self.verify_live_graph()?;
        let live: BTreeSet<_> = self.entries.iter().filter_map(|(digest, entry)|
            entry.deleted_by.is_none().then_some(*digest)).collect();
        let not_due: BTreeSet<_> = live.iter().filter(|digest|
            self.entries.get(*digest).is_some_and(|entry| now < entry.rule.retain_until))
            .copied().collect();
        let held_roots: BTreeSet<_> = self.holds.values().filter(|hold| hold.released_by.is_none())
            .flat_map(|hold| [hold.subject, hold.witness]).collect();
        let mut protected = not_due.clone(); protected.extend(&held_roots);
        let mut pending: Vec<_> = protected.iter().copied().collect();
        while let Some(digest) = pending.pop() {
            for dependency in &self.live_entry(digest)?.dependencies {
                if protected.insert(*dependency) { pending.push(*dependency); }
            }
        }
        let due: BTreeSet<_> = live.difference(&not_due).copied().collect();
        let eligible: BTreeSet<_> = live.difference(&protected).copied().collect();
        let blocked_due = due.intersection(&protected).copied().collect();
        let mut dependents: BTreeMap<_, usize> = eligible.iter().map(|digest| (*digest, 0)).collect();
        for digest in &eligible {
            for dependency in &self.live_entry(*digest)?.dependencies {
                if let Some(count) = dependents.get_mut(dependency) { *count += 1; }
            }
        }
        let mut ready: BTreeSet<_> = dependents.iter().filter_map(|(digest, count)|
            (*count == 0).then_some(*digest)).collect();
        let mut selected = Vec::new(); let mut selected_bytes = 0_u64;
        while let Some(digest) = ready.pop_first() {
            let entry = self.live_entry(digest)?;
            let Some(total) = selected_bytes.checked_add(entry.bytes) else { continue; };
            if selected.len() >= budget.max_objects || total > budget.max_deleted_bytes { continue; }
            selected.push(digest); selected_bytes = total;
            for dependency in &entry.dependencies {
                if let Some(count) = dependents.get_mut(dependency) {
                    *count = count.checked_sub(1).ok_or(RetentionError::InvalidRecord)?;
                    if *count == 0 { ready.insert(*dependency); }
                }
            }
        }
        let selected_set: BTreeSet<_> = selected.iter().copied().collect();
        let deferred_due = eligible.difference(&selected_set).copied().collect();
        let mut plan = RetentionPlan { state: self.state_digest()?, policy: self.policy,
            prepared_at: now, budget, selected, selected_bytes, blocked_due, deferred_due,
            held_roots, not_due, digest: ContentDigest::sha256(b"unpublished-retention-plan") };
        plan.digest = plan.computed_digest()?;
        Ok(plan)
    }

    fn live_entry(&self, digest: ContentDigest) -> Result<&Entry, RetentionError> {
        self.entries.get(&digest).filter(|entry| entry.deleted_by.is_none())
            .ok_or(RetentionError::UnknownObject)
    }

    fn verify_live_graph(&self) -> Result<(), RetentionError> {
        if self.entries.len() != self.custody.object_count() { return Err(RetentionError::InvalidRecord); }
        for (digest, entry) in &self.entries {
            if entry.deleted_by.is_some() {
                if self.custody.state(*digest) != Some(ObjectState::Tombstoned) {
                    return Err(RetentionError::InvalidRecord);
                }
                continue;
            }
            if self.custody.read_verified(*digest)?.len() as u64 != entry.bytes {
                return Err(RetentionError::InvalidRecord);
            }
            for dependency in &entry.dependencies { self.live_entry(*dependency)?; }
            if entry.manifest && self.custody.published_manifest(*digest)?.children()
                .iter().copied().collect::<BTreeSet<_>>() != entry.dependencies
            { return Err(RetentionError::InvalidRecord); }
        }
        Ok(())
    }
}

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT && !value.chars().any(char::is_control)
}
fn encode_set(values: &BTreeSet<ContentDigest>, e: &mut CanonicalEncoder) {
    e.u64(values.len() as u64);
    for value in values { e.digest(*value); }
}

#[cfg(test)]
mod tests;

#![forbid(unsafe_code)]
//! Durable local-root belief verification using native capture and the existing core deriver.
//!
//! This narrow profile admits current ledgered local-root slots. The default entry point refuses
//! deletion-bearing histories; a second entry point accepts only a verifier-owned deletion authority
//! that validates the complete committed deletion history and returns its deny set. It is not a
//! production engine registry or a permission grant. Native read and replay are independently bounded.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use fss_core::belief_verification::{RegisteredBeliefDeriver, BeliefVerificationError};
use fss_core::belief_verification::graph::{
    BeliefEvidenceAncestry, BeliefGraphFailure, BeliefGraphLimits, BeliefGraphRequest,
    BeliefGraphUsage, verify_derived_belief_graph,
};
use fss_core::{
    CanonicalDecode, ContentDigest, ContractError, DerivedBelief, KnowledgeCell, LedgerAnchor,
    Plane, ReferenceLedger,
};
use fss_ledger::{DurableLedgerError, DurableReferenceLedger};
use fss_object::SpoolIo;
use crate::{
    LocalPublicationState, LocalRootPublisher, ROOT_REACHABILITY_FAMILY, ROOT_RETRACTION_FAMILY,
    SlotName, root_reachability_object_id,
};
use super::{CapturedBeliefCustody, CustodyCaptureError, capture_belief_custody};
use super::super::{
    CustodyAuditLimits, CustodyRootBasis, LocalCustodyAudit, MAX_AUDIT_ROOTS,
    MAX_AUDIT_OBJECTS, MAX_AUDIT_READ_BYTES, sha,
};

/// Explicit memory/work ceilings for replay of an already-opened journal.
/// Replay is a deterministic reference adapter, not a direct production MVCC view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableBeliefLimits {
    /// Maximum offered canonical belief bytes, before decoder allocation.
    pub max_encoded_bytes: usize,
    /// Maximum committed batches replayed, including empty batches.
    pub max_batches: usize,
    /// Maximum delta entries plus child references across replayed history.
    pub max_history_entries: usize,
    /// Conservative sum of successor snapshot entries, reserved before replay appends.
    /// This bounds retained reference snapshots, not allocator overhead.
    pub max_replay_snapshot_entries: usize,
    /// Conservative bytes of copied history and snapshot text, including repeated snapshot strings.
    /// Transient canonical encoder buffers and allocator overhead are not this counter.
    pub max_replay_text_bytes: usize,
    /// Cumulative native custody reads, metadata scans and calls.
    pub custody: CustodyAuditLimits,
    /// Maximum exact payload bytes retained in the returned observation.
    pub max_retained_bytes: u64,
    /// Independent graph traversal, ancestry and rederivation input-copy limits.
    pub graph: BeliefGraphLimits,
}
impl Default for DurableBeliefLimits {
    fn default() -> Self {
        Self {
            max_encoded_bytes: 256 * 1024, max_batches: 256,
            max_history_entries: 16_384, max_replay_snapshot_entries: 65_536,
            max_replay_text_bytes: 4 * 1024 * 1024,
            custody: CustodyAuditLimits::default(), max_retained_bytes: 64 * 1024 * 1024,
            graph: BeliefGraphLimits::default(),
        }
    }
}

/// Independently selected scope and cancellation authority, never inferred from a conclusion.
pub struct DurableBeliefRequest<'a, C: Fn() -> bool + Sync> {
    /// Nonempty, strictly ordered local slots the caller is authorized to read.
    pub slots: &'a [SlotName],
    /// Explicit additional denials. These only narrow access; even a supplied map cannot
    /// override this profile's refusal of every deletion-bearing journal.
    pub denied: &'a BTreeMap<ContentDigest, ContentDigest>,
    /// One set of resource ceilings, without retries or implicit refills.
    pub limits: DurableBeliefLimits,
    /// Cooperative cancellation, checked before every phase and native audit call.
    pub cancelled: &'a C,
}

/// Trusted deletion owner used only by the deletion-aware durable entry point.
///
/// The implementation must validate the complete committed deletion transition history represented
/// by the supplied ledger, using exact retained plan/completion bytes owned by the publisher, and
/// return every locally denied object as object-digest to deletion-plan-digest. Returning an
/// incomplete set is a verifier bug: this trait is selected by the application, exactly like the
/// registered derivation engine, and is never supplied by the offered belief. It must not repair,
/// undelete, publish, or widen access.
pub trait DurableBeliefDeletionAuthority {
    /// Validate the complete deletion history and return its exact deny map.
    fn verified_denials(
        &self,
        ledger: &DurableReferenceLedger,
        publisher: &LocalRootPublisher,
    ) -> Result<BTreeMap<ContentDigest, ContentDigest>, DurableBeliefError>;
}

/// Logical replay reservations, distinct from native I/O and derivation-engine CPU cost.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DurableBeliefReplayUsage {
    /// Committed batches replayed, including empty ones.
    pub batches: usize,
    /// History delta and child-reference entries copied.
    pub history_entries: usize,
    /// Conservative cumulative successor snapshot entries reserved.
    pub snapshot_entries: usize,
    /// Conservative copied text bytes, including repeated snapshot copies.
    pub text_bytes: usize,
}

/// No verified result is returned on refusal. Native storage errors stay distinguishable.
#[derive(Debug)]
pub enum DurableBeliefError {
    /// Invalid encoding, anchor or structural belief contract.
    Contract(ContractError),
    /// Native journal verification refused the opened durable head.
    Ledger(DurableLedgerError),
    /// Native custody capture did not establish the complete selected closure.
    Capture(CustodyCaptureError),
    /// Core graph verification/rederivation refusal with its consumed logical work.
    Graph(BeliefGraphFailure),
    /// Noncanonical selection or a slot that is not current and durably ledgered.
    Selection,
    /// No current store identity can be established, or the journal file was replaced.
    StoreIdentity,
    /// A head, anchor, publisher state or selected slot changed.
    AuthorityChanged,
    /// Deletion authority requires the higher-level deletion-owner adapter.
    DeletionAdapterRequired,
    /// The selected deletion owner could not validate a complete canonical deletion history.
    DeletionAuthorityInvalid,
    /// A named intake/replay resource allowance was exhausted.
    Limit(&'static str),
    /// Cooperative cancellation; no partial proof.
    Cancelled,
}
impl fmt::Display for DurableBeliefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(f, "durable belief contract: {error}"),
            Self::Ledger(error) => write!(f, "durable belief ledger: {error}"),
            Self::Capture(error) => write!(f, "durable belief {error}"),
            Self::Graph(error) => write!(f, "durable belief {error}"),
            Self::Selection => f.write_str("belief slots are not an exact current ledgered selection"),
            Self::StoreIdentity => f.write_str("belief authority store identity cannot be established"),
            Self::AuthorityChanged => f.write_str("belief authority changed during the observation"),
            Self::DeletionAdapterRequired => f.write_str("deletion-bearing history requires the deletion-owner belief adapter"),
            Self::DeletionAuthorityInvalid => f.write_str("deletion-owner belief authority could not validate complete deletion history"),
            Self::Limit(dimension) => write!(f, "durable belief {dimension} budget exhausted"),
            Self::Cancelled => f.write_str("durable belief verification cancelled"),
        }
    }
}
impl std::error::Error for DurableBeliefError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error), Self::Ledger(error) => Some(error),
            Self::Capture(error) => Some(error), Self::Graph(error) => Some(error), _ => None,
        }
    }
}
impl From<ContractError> for DurableBeliefError {
    fn from(error: ContractError) -> Self { Self::Contract(error) }
}
impl From<DurableLedgerError> for DurableBeliefError {
    fn from(error: DurableLedgerError) -> Self { Self::Ledger(error) }
}
impl From<CustodyCaptureError> for DurableBeliefError {
    fn from(error: CustodyCaptureError) -> Self { Self::Capture(error) }
}
impl From<BeliefGraphFailure> for DurableBeliefError {
    fn from(error: BeliefGraphFailure) -> Self { Self::Graph(error) }
}

fn checkpoint(cancelled: &impl Fn() -> bool) -> Result<(), DurableBeliefError> {
    if cancelled() { Err(DurableBeliefError::Cancelled) } else { Ok(()) }
}
fn charge(used: &mut usize, count: usize, maximum: usize, name: &'static str) -> Result<(), DurableBeliefError> {
    let next = used.checked_add(count).ok_or(DurableBeliefError::Limit(name))?;
    if next > maximum { return Err(DurableBeliefError::Limit(name)); }
    *used = next;
    Ok(())
}
fn check_head(
    ledger: &DurableReferenceLedger, publisher: &LocalRootPublisher,
    pin: ContentDigest, head: ContentDigest, anchor: &LedgerAnchor,
    cancelled: &impl Fn() -> bool,
) -> Result<(), DurableBeliefError> {
    checkpoint(cancelled)?;
    if ledger.store_pin() != Some(pin) || !ledger.store_pin_is_current() {
        return Err(DurableBeliefError::StoreIdentity);
    }
    ledger.verify_durable_head()?;
    checkpoint(cancelled)?;
    if publisher.is_poisoned() || ledger.journal_root() != head || &ledger.current().anchor != anchor {
        return Err(DurableBeliefError::AuthorityChanged);
    }
    Ok(())
}

/// Rederived cognition bound to an opened journal and exact retained input bytes.
///
/// No decoder or mutable accessor exists. Borrows prevent cooperating ledger/publisher mutation.
/// External filesystem mutation is not excluded; projection rechecks journal identity and head.
/// Evidence copies remain retained here, but no lease on original files is claimed.
pub struct VerifiedDurableBelief<'a> {
    belief: DerivedBelief,
    ledger: &'a DurableReferenceLedger,
    publisher: &'a LocalRootPublisher,
    pin: ContentDigest,
    head: ContentDigest,
    custody: CapturedBeliefCustody,
    usage: BeliefGraphUsage,
    replay_usage: DurableBeliefReplayUsage,
    ancestry: BTreeMap<ContentDigest, Vec<BeliefEvidenceAncestry>>,
}
impl fmt::Debug for VerifiedDurableBelief<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedDurableBelief").field("usage", &self.usage)
            .field("replay_usage", &self.replay_usage)
            .field("retained_bytes", &self.custody.retained_bytes()).finish_non_exhaustive()
    }
}
impl VerifiedDurableBelief<'_> {
    /// Cognition-plane result, not an effect grant or absence certificate.
    #[must_use]
    pub const fn belief(&self) -> &DerivedBelief { &self.belief }
    /// Logical graph work, separate from native custody and bounded ledger-head checks.
    #[must_use]
    pub const fn graph_usage(&self) -> BeliefGraphUsage { self.usage }
    /// Conservative reservations for the independently bounded reference replay.
    #[must_use]
    pub const fn replay_usage(&self) -> DurableBeliefReplayUsage { self.replay_usage }
    /// Native custody observation and complete capture's physical-read accounting.
    #[must_use]
    pub fn custody_audit(&self) -> &LocalCustodyAudit { self.custody.audit() }
    /// Typed ancestry within the independently selected slots.
    #[must_use]
    pub fn ancestry(&self, root: ContentDigest) -> Option<&[BeliefEvidenceAncestry]> {
        self.ancestry.get(&root).map(Vec::as_slice)
    }
    /// Rechecks durable authority before projecting cognition. Native bounded tail checks are
    /// not a full historical scrub and are separate from the custody-audit cost counters.
    pub fn to_knowledge_cell(&self, cancelled: &impl Fn() -> bool) -> Result<KnowledgeCell, DurableBeliefError> {
        check_head(self.ledger, self.publisher, self.pin, self.head, self.belief.anchor(), cancelled)?;
        Ok(self.belief.to_knowledge_cell(&self.ledger.current().anchor)?)
    }
}

/// Verify a saved belief against current ledgered slots and native on-disk custody.
///
/// The caller supplies independently authorized slots, opened publisher/ledger owners, I/O and
/// a trusted registered engine. Unledgered/staged slots, replaced journals, unreconciled heads,
/// missing custody and changed scope refuse. Every deletion-prefixed family, root retraction or
/// reserved deletion batch is refused: an empty deny-set never overrides committed deletion.
/// Local publication tombstones and extra denials independently narrow access.
///
/// The durable ledger is replayed under explicit history and snapshot-copy bounds and compared
/// exactly with its opened current snapshot. This bounded reference adaptation does not promote
/// unverified snapshots or replay into independent durable authority. The head is checked before
/// and after, and on projection. No write, repair, activation or effect occurs.
///
/// Event manifests without slots, deletion-bearing deployments and production engine activation
/// are not supported by this profile. Native capture, replay and graph limits are distinct; graph
/// input copies can coexist with captured payloads. Preflight/capture refusals do not yet carry a
/// unified partial-work receipt; a graph refusal retains its existing logical usage. Physical
/// journal-head checks have fixed bounded reads, separate from the custody I/O meter.
pub fn verify_durable_belief<'a, C: Fn() -> bool + Sync>(
    encoded: &[u8],
    ledger: &'a DurableReferenceLedger,
    publisher: &'a LocalRootPublisher,
    io: &dyn SpoolIo,
    engine: &(impl RegisteredBeliefDeriver + ?Sized),
    request: DurableBeliefRequest<'_, C>,
) -> Result<VerifiedDurableBelief<'a>, DurableBeliefError> {
    verify_durable_belief_inner(encoded, ledger, publisher, io, engine, None, request)
}

/// Verify a saved belief while admitting a deletion-bearing deployment only through a trusted
/// deletion owner that validates the complete committed deletion history.
///
/// The deletion authority can only add denials. Its map is merged with the explicit request deny
/// set, validated, and passed to native custody before any selected payload is copied. The ordinary
/// `verify_durable_belief` remains fail-closed for every deletion marker.
pub fn verify_durable_belief_with_deletion_authority<'a, C: Fn() -> bool + Sync>(
    encoded: &[u8],
    ledger: &'a DurableReferenceLedger,
    publisher: &'a LocalRootPublisher,
    io: &dyn SpoolIo,
    engine: &(impl RegisteredBeliefDeriver + ?Sized),
    deletion_authority: &dyn DurableBeliefDeletionAuthority,
    request: DurableBeliefRequest<'_, C>,
) -> Result<VerifiedDurableBelief<'a>, DurableBeliefError> {
    verify_durable_belief_inner(
        encoded, ledger, publisher, io, engine, Some(deletion_authority), request,
    )
}

fn verify_durable_belief_inner<'a, C: Fn() -> bool + Sync>(
    encoded: &[u8],
    ledger: &'a DurableReferenceLedger,
    publisher: &'a LocalRootPublisher,
    io: &dyn SpoolIo,
    engine: &(impl RegisteredBeliefDeriver + ?Sized),
    deletion_authority: Option<&dyn DurableBeliefDeletionAuthority>,
    request: DurableBeliefRequest<'_, C>,
) -> Result<VerifiedDurableBelief<'a>, DurableBeliefError> {
    checkpoint(request.cancelled)?;
    let limits = request.limits;
    // Count ceilings precede scans of caller-owned collections or any native I/O.
    if request.slots.len() > MAX_AUDIT_ROOTS || request.slots.len() > limits.graph.max_authority_objects
        || request.slots.len() > limits.graph.verification.max_snapshot_objects {
        return Err(DurableBeliefError::Limit("selected slots"));
    }
    if request.slots.is_empty() || !request.slots.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(DurableBeliefError::Selection);
    }
    if request.denied.len() > MAX_AUDIT_OBJECTS || limits.max_retained_bytes > MAX_AUDIT_READ_BYTES {
        return Err(DurableBeliefError::Limit("custody request"));
    }
    if request.denied.iter().any(|(root, proof)| !sha(*root) || !sha(*proof)) {
        return Err(DurableBeliefError::Selection);
    }
    limits.custody.validate().map_err(CustodyCaptureError::from)?;
    if encoded.len() > limits.max_encoded_bytes { return Err(DurableBeliefError::Limit("encoded bytes")); }
    let offered = DerivedBelief::from_canonical_bytes(encoded)?;
    let anchor = &ledger.current().anchor;
    offered.validate_anchor_freshness(anchor)?;
    let graph_failure = |error| DurableBeliefError::Graph(BeliefGraphFailure {
        reason: error, usage: BeliefGraphUsage::default(),
    });
    if offered.derivation_inputs().algorithm_id != engine.algorithm_id() {
        return Err(graph_failure(BeliefVerificationError::AlgorithmMismatch.into()));
    }
    if offered.generation() != engine.generation() {
        return Err(graph_failure(BeliefVerificationError::GenerationMismatch.into()));
    }
    if offered.supporting_evidence().len() + offered.contradictions().len() > limits.graph.verification.max_roots {
        return Err(graph_failure(BeliefVerificationError::RootLimit.into()));
    }
    let pin = ledger.store_pin().ok_or(DurableBeliefError::StoreIdentity)?;
    let head = ledger.journal_root();
    check_head(ledger, publisher, pin, head, anchor, request.cancelled)?;
    if ledger.batches().len() > limits.max_batches { return Err(DurableBeliefError::Limit("replay batches")); }
    let mut replay_usage = DurableBeliefReplayUsage::default();
    let mut deletion_history = false;
    // Complete deletion/history preflight before reading any selected custody payload.
    for batch in ledger.batches() {
        checkpoint(request.cancelled)?;
        if batch.batch_id.as_str().starts_with("batch:deletion:") {
            deletion_history = true;
        }
        charge(&mut replay_usage.history_entries, batch.children.len(), limits.max_history_entries, "history entries")?;
        charge(&mut replay_usage.history_entries, batch.deltas.len(), limits.max_history_entries, "history entries")?;
        // Batch identity is also copied into the replay's idempotency index.
        for text in [batch.batch_id.as_str(), batch.batch_id.as_str(),
            &batch.basis_anchor.site_lineage, &batch.new_anchor.site_lineage] {
            charge(&mut replay_usage.text_bytes, text.len(), limits.max_replay_text_bytes, "replay text")?;
        }
        for delta in &batch.deltas {
            checkpoint(request.cancelled)?;
            if delta.family.starts_with("deletion_") || delta.family == ROOT_RETRACTION_FAMILY {
                deletion_history = true;
            }
            for text in [delta.delta_id.as_str(), delta.family.as_str(), delta.object_id.as_str()] {
                charge(&mut replay_usage.text_bytes, text.len(), limits.max_replay_text_bytes, "replay text")?;
            }
            if let Some(id) = &delta.operation_id {
                charge(&mut replay_usage.text_bytes, id.as_str().len(), limits.max_replay_text_bytes, "replay text")?;
            }
        }
    }
    let mut denied = request.denied.clone();
    if deletion_history {
        let authority = deletion_authority.ok_or(DurableBeliefError::DeletionAdapterRequired)?;
        checkpoint(request.cancelled)?;
        let verified = authority.verified_denials(ledger, publisher)?;
        checkpoint(request.cancelled)?;
        if verified.len() > MAX_AUDIT_OBJECTS
            || denied.len().checked_add(verified.len()).is_none_or(|n| n > MAX_AUDIT_OBJECTS)
            || verified.iter().any(|(root, proof)| !sha(*root) || !sha(*proof))
        {
            return Err(DurableBeliefError::DeletionAuthorityInvalid);
        }
        for (root, proof) in verified {
            if let Some(existing) = denied.get(&root)
                && *existing != proof
            {
                return Err(DurableBeliefError::DeletionAuthorityInvalid);
            }
            denied.insert(root, proof);
        }
        check_head(ledger, publisher, pin, head, anchor, request.cancelled)?;
    }
    let mut selected = Vec::with_capacity(request.slots.len());
    let mut roots = BTreeSet::new();
    for slot in request.slots {
        checkpoint(request.cancelled)?;
        let id = root_reachability_object_id(slot).map_err(|_| DurableBeliefError::Selection)?;
        let revision = ledger.current().objects.get(&id).ok_or(DurableBeliefError::Selection)?;
        let local = publisher.root(slot).ok_or(DurableBeliefError::Selection)?;
        if revision.family != ROOT_REACHABILITY_FAMILY || revision.plane != Plane::Authority
            || revision.generation != 1 || revision.payload_digest != local.root
            || local.state != LocalPublicationState::Durable {
            return Err(DurableBeliefError::Selection);
        }
        selected.push(id);
        roots.insert(revision.payload_digest);
    }
    charge(&mut replay_usage.text_bytes, anchor.site_lineage.len(), limits.max_replay_text_bytes, "replay text")?;
    let mut replay = ReferenceLedger::new(anchor.site_lineage.clone());
    for batch in ledger.batches() {
        checkpoint(request.cancelled)?;
        let upper = replay.current().objects.len().checked_add(batch.deltas.len())
            .ok_or(DurableBeliefError::Limit("replay snapshots"))?;
        charge(&mut replay_usage.snapshot_entries, upper, limits.max_replay_snapshot_entries, "replay snapshots")?;
        // Count overwritten rows and their replacements conservatively before cloning any state.
        charge(&mut replay_usage.text_bytes, batch.new_anchor.site_lineage.len(), limits.max_replay_text_bytes, "replay text")?;
        for (id, revision) in &replay.current().objects {
            checkpoint(request.cancelled)?;
            charge(&mut replay_usage.text_bytes, id.as_str().len(), limits.max_replay_text_bytes, "replay text")?;
            charge(&mut replay_usage.text_bytes, revision.family.len(), limits.max_replay_text_bytes, "replay text")?;
        }
        for delta in &batch.deltas {
            checkpoint(request.cancelled)?;
            charge(&mut replay_usage.text_bytes, delta.object_id.as_str().len(), limits.max_replay_text_bytes, "replay text")?;
            charge(&mut replay_usage.text_bytes, delta.family.len(), limits.max_replay_text_bytes, "replay text")?;
        }
        let _ = replay.append(batch.clone())?;
        replay_usage.batches += 1;
    }
    if replay.current() != ledger.current() { return Err(DurableBeliefError::AuthorityChanged); }
    let roots: Vec<_> = roots.into_iter().collect();
    let custody = capture_belief_custody(io, publisher.root_dir(), &roots, &denied,
        limits.custody, request.cancelled, CustodyRootBasis::LocalPublicationRecords, limits.max_retained_bytes)?;
    // Another slot publishing an equal digest cannot substitute for the exact selected record.
    for slot in request.slots {
        let local = publisher.root(slot).ok_or(DurableBeliefError::AuthorityChanged)?;
        if custody.records.get(slot) != Some(&(local.root, local.child_count as u64, local.record_digest)) {
            return Err(DurableBeliefError::AuthorityChanged);
        }
    }
    let verified = verify_derived_belief_graph(&offered, &replay, &custody, engine, BeliefGraphRequest {
        authority_objects: &selected, limits: limits.graph, cancelled: request.cancelled,
    })?;
    let belief = verified.proof().belief().clone();
    let usage = verified.usage();
    let mut ancestry = BTreeMap::new();
    for root in offered.supporting_evidence().iter().chain(offered.contradictions()) {
        let paths = verified.ancestry(*root).ok_or(DurableBeliefError::AuthorityChanged)?;
        ancestry.insert(*root, paths.to_vec());
    }
    drop(verified);
    check_head(ledger, publisher, pin, head, anchor, request.cancelled)?;
    Ok(VerifiedDurableBelief { belief, ledger, publisher, pin, head, custody, usage, replay_usage, ancestry })
}

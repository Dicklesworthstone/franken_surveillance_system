#![forbid(unsafe_code)]
//! Current-anchor belief verification over complete, explicitly selected immutable object graphs.
//!
//! The graph owner, not a guessed byte signature or the belief, defines published edges. The
//! verifier rehashes every reached object, including unused siblings, before derivation. It retains
//! one deterministic shortest path per selected authority object; this is not an inventory of all
//! possible paths. Direct payload bindings and transitive ancestry remain distinct.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use super::{
    BeliefEvidenceReadError, BeliefRebuildInputs, BeliefVerificationError, BeliefVerificationLimits,
    RegisteredBeliefDeriver, RetainedBeliefEvidence, VerifiedBeliefEvidence, VerifiedDerivedBelief,
};
use crate::{ContentDigest, ContractError, DerivedBelief, ObjectId, ObjectRevision, Plane, ReferenceLedger};

/// Verifier-owned graph format/publication authority. This is not supplied by the offered belief.
///
/// Implementations must decode edges from the supplied, independently rehashed bytes, cross-check
/// their exact publication identity, reject invalidated manifests, and return strictly increasing
/// children. An opaque leaf returns no children even when its bytes resemble a manifest. Check the
/// allowance before allocating an owned edge list. No repair, promotion, or publication is allowed.
pub trait RetainedBeliefGraph: RetainedBeliefEvidence {
    /// Reads only published edges of the exact verified object, or an empty list for an opaque leaf.
    fn belief_children(
        &self,
        digest: ContentDigest,
        verified_bytes: &[u8],
        max_children: usize,
    ) -> Result<Vec<ContentDigest>, BeliefEvidenceReadError>;
}

/// Bounded request-owned traversal, with no recursive walk or implicit whole-store expansion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BeliefGraphLimits {
    /// Existing snapshot, offered-root, per-object and aggregate byte limits. Bytes include parents
    /// and unused siblings, not just the roots supplied to the derivation engine.
    pub verification: BeliefVerificationLimits,
    /// Maximum independently selected authority objects.
    pub max_authority_objects: usize,
    /// Maximum unique objects read from all selected closures together.
    pub max_graph_objects: usize,
    /// Maximum object visits summed across selected authority objects (shared nodes count again).
    pub max_visits: usize,
    /// Maximum edge inspections, including both cycle-check passes and repeated ancestor walks.
    pub max_edge_visits: usize,
    /// Maximum shortest-path edge distance from EACH selected authority object to a reached node.
    pub max_depth: usize,
    /// Maximum digest entries across retained ancestry paths, including their start and end.
    pub max_witness_steps: usize,
}

impl Default for BeliefGraphLimits {
    fn default() -> Self {
        Self {
            verification: BeliefVerificationLimits::default(),
            max_authority_objects: 64,
            max_graph_objects: 16_384,
            max_visits: 65_536,
            max_edge_visits: 262_144,
            max_depth: 64,
            max_witness_steps: 65_536,
        }
    }
}

/// One explicit graph selection and cooperative cancellation boundary.
#[derive(Clone, Copy)]
pub struct BeliefGraphRequest<'a> {
    /// Independently authorized authority-object IDs, nonempty and strictly increasing. Unselected
    /// authority roots confer no transitive membership. This never grants access to an entire store.
    pub authority_objects: &'a [ObjectId],
    /// One cumulative allowance for the whole verification.
    pub limits: BeliefGraphLimits,
    /// Owner-supplied cancellation checkpoint, called before reads, expansion and derivation.
    pub cancelled: &'a dyn Fn() -> bool,
}

/// Logical work actually admitted, retained on success AND refusal. These are not physical I/O,
/// hashing-CPU, or registered engine execution-cost measurements.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BeliefGraphUsage {
    /// Snapshot objects inspected for direct bindings.
    pub snapshot_objects: usize,
    /// Selected authority closures started.
    pub authority_objects: usize,
    /// Unique object read attempts (includes a failed attempt).
    pub read_attempts: usize,
    /// Returned bytes admitted within the byte ceiling, including a corrupt returned payload.
    pub admitted_bytes: usize,
    /// Discovered (selected authority object, reachable digest) pairs.
    pub visits: usize,
    /// Inspected edges, including the cycle check.
    pub edge_visits: usize,
    /// Digest entries admitted to ancestry witnesses.
    pub witness_steps: usize,
    /// Independent derivations started, either zero or one.
    pub derivations: usize,
}

/// A retained root's explicit reachability from one current selected authority object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeliefEvidenceAncestry {
    object_id: ObjectId,
    revision: ObjectRevision,
    path: Vec<ContentDigest>,
}

impl BeliefEvidenceAncestry {
    /// Selected current authority object, NOT an assertion that it directly types the leaf.
    #[must_use]
    pub fn object_id(&self) -> &ObjectId { &self.object_id }
    /// Exact authority revision, including family, validity, generation and starting payload root.
    #[must_use]
    pub fn revision(&self) -> &ObjectRevision { &self.revision }
    /// Start payload through final evidence digest, inclusive; adjacent entries are published edges.
    #[must_use]
    pub fn path(&self) -> &[ContentDigest] { &self.path }
}

/// Precise graph refusal. No partial traversal can produce a verified belief.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BeliefGraphError {
    /// Existing belief, payload, custody or registration refusal.
    Verification(BeliefVerificationError),
    /// Cancellation before completion; no proof or implicit retry.
    Cancelled,
    /// Empty, duplicate or noncanonical authority-object selection.
    InvalidSelection,
    /// Selected object is missing or not in the authority plane at the exact current anchor.
    InvalidAuthorityObject(ObjectId),
    /// A traversal or witness work allowance was exhausted.
    Limit(&'static str),
    /// The graph owner returned noncanonical, inconsistent or cyclic edges.
    InvalidGraph(ContentDigest),
}

impl From<BeliefVerificationError> for BeliefGraphError {
    fn from(error: BeliefVerificationError) -> Self { Self::Verification(error) }
}
impl From<ContractError> for BeliefGraphError {
    fn from(error: ContractError) -> Self { Self::Verification(error.into()) }
}
impl fmt::Display for BeliefGraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verification(error) => write!(f, "{error}"),
            Self::Cancelled => f.write_str("belief graph verification cancelled"),
            Self::InvalidSelection => f.write_str("belief graph authority selection is not canonical"),
            Self::InvalidAuthorityObject(id) => write!(f, "belief graph authority object unavailable: {id}"),
            Self::Limit(dimension) => write!(f, "belief graph {dimension} allowance exhausted"),
            Self::InvalidGraph(root) => write!(f, "belief graph is inconsistent at {root}"),
        }
    }
}
impl std::error::Error for BeliefGraphError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self { Self::Verification(error) => Some(error), _ => None }
    }
}

/// A refused verification with its non-reset cumulative work accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeliefGraphFailure {
    /// Why no proof was returned.
    pub reason: BeliefGraphError,
    /// Work admitted up to the refusal.
    pub usage: BeliefGraphUsage,
}
impl fmt::Display for BeliefGraphFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.reason.fmt(f) }
}
impl std::error::Error for BeliefGraphFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.reason) }
}

/// Verified cognition plus retained, typed ancestry and logical work. No canonical decode exists.
#[derive(Debug)]
pub struct VerifiedBeliefGraph<'a> {
    proof: VerifiedDerivedBelief<'a>,
    usage: BeliefGraphUsage,
    ancestry: BTreeMap<ContentDigest, Vec<BeliefEvidenceAncestry>>,
}
impl<'a> VerifiedBeliefGraph<'a> {
    /// The same private core proof used for current-anchor knowledge-cell projection.
    #[must_use]
    pub const fn proof(&self) -> &VerifiedDerivedBelief<'a> { &self.proof }
    /// Logical work performed across the complete selected closures.
    #[must_use]
    pub const fn usage(&self) -> BeliefGraphUsage { self.usage }
    /// Exact ancestry of an offered supporting or contradicting digest, in authority-object order.
    #[must_use]
    pub fn ancestry(&self, root: ContentDigest) -> Option<&[BeliefEvidenceAncestry]> {
        self.ancestry.get(&root).map(Vec::as_slice)
    }
}

struct GraphObject {
    bytes: Vec<u8>,
    children: Vec<ContentDigest>,
}
struct Scan<'a, 'r, R: ?Sized> {
    reader: &'a R,
    request: BeliefGraphRequest<'r>,
    usage: BeliefGraphUsage,
    objects: BTreeMap<ContentDigest, GraphObject>,
    ancestry: BTreeMap<ContentDigest, Vec<BeliefEvidenceAncestry>>,
}

fn reserve(used: &mut usize, count: usize, maximum: usize, name: &'static str) -> Result<(), BeliefGraphError> {
    let next = used.checked_add(count).ok_or(BeliefGraphError::Limit(name))?;
    if next > maximum { return Err(BeliefGraphError::Limit(name)); }
    *used = next;
    Ok(())
}

impl<R: RetainedBeliefGraph + ?Sized> Scan<'_, '_, R> {
    fn checkpoint(&self) -> Result<(), BeliefGraphError> {
        if (self.request.cancelled)() { Err(BeliefGraphError::Cancelled) } else { Ok(()) }
    }

    fn load(&mut self, root: ContentDigest) -> Result<(), BeliefGraphError> {
        self.checkpoint()?;
        if self.objects.contains_key(&root) { return Ok(()); }
        reserve(&mut self.usage.read_attempts, 1, self.request.limits.max_graph_objects, "objects")?;
        let limits = self.request.limits.verification;
        let allowance = limits.max_root_bytes.min(limits.max_total_bytes - self.usage.admitted_bytes);
        let read_error = |cause| BeliefGraphError::Verification(BeliefVerificationError::Read { digest: root, cause });
        let bytes = self.reader.read_belief_evidence(root, allowance).map_err(read_error)?;
        if bytes.len() > allowance { return Err(read_error(BeliefEvidenceReadError::LimitExceeded)); }
        self.usage.admitted_bytes += bytes.len();
        if ContentDigest::sha256(&bytes) != root {
            return Err(BeliefVerificationError::PayloadDigestMismatch(root).into());
        }
        self.checkpoint()?;
        let remaining_edges = self.request.limits.max_edge_visits - self.usage.edge_visits;
        let children = self.reader.belief_children(root, &bytes, remaining_edges).map_err(read_error)?;
        if children.len() > remaining_edges { return Err(BeliefGraphError::Limit("edges")); }
        if !children.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(BeliefGraphError::InvalidGraph(root));
        }
        self.objects.insert(root, GraphObject { bytes, children });
        Ok(())
    }

    fn walk(&mut self, id: &ObjectId, revision: &ObjectRevision, wanted: &BTreeSet<ContentDigest>) -> Result<(), BeliefGraphError> {
        self.checkpoint()?;
        self.usage.authority_objects += 1;
        reserve(&mut self.usage.visits, 1, self.request.limits.max_visits, "visits")?;
        let mut parents = BTreeMap::from([(revision.payload_digest, None)]);
        let mut pending = VecDeque::from([(revision.payload_digest, 0_usize)]);
        while let Some((root, depth)) = pending.pop_front() {
            self.load(root)?;
            let object = self.objects.get(&root).ok_or(BeliefGraphError::InvalidGraph(root))?;
            reserve(&mut self.usage.edge_visits, object.children.len(), self.request.limits.max_edge_visits, "edges")?;
            for child in &object.children {
                if (self.request.cancelled)() { return Err(BeliefGraphError::Cancelled); }
                if parents.contains_key(child) { continue; }
                let next_depth = depth.checked_add(1).ok_or(BeliefGraphError::Limit("depth"))?;
                if next_depth > self.request.limits.max_depth { return Err(BeliefGraphError::Limit("depth")); }
                reserve(&mut self.usage.visits, 1, self.request.limits.max_visits, "visits")?;
                parents.insert(*child, Some(root));
                pending.push_back((*child, next_depth));
            }
        }
        for root in wanted {
            self.checkpoint()?;
            if !parents.contains_key(root) { continue; }
            let mut path = Vec::new();
            let mut cursor = Some(*root);
            while let Some(node) = cursor {
                self.checkpoint()?;
                reserve(&mut self.usage.witness_steps, 1, self.request.limits.max_witness_steps, "witness steps")?;
                path.push(node);
                cursor = *parents.get(&node).ok_or(BeliefGraphError::InvalidGraph(node))?;
            }
            path.reverse();
            self.ancestry.entry(*root).or_default().push(BeliefEvidenceAncestry {
                object_id: id.clone(), revision: revision.clone(), path,
            });
        }
        Ok(())
    }

    fn require_acyclic(&mut self) -> Result<(), BeliefGraphError> {
        let mut incoming: BTreeMap<_, usize> = self.objects.keys().map(|root| (*root, 0)).collect();
        for (root, object) in &self.objects {
            if (self.request.cancelled)() { return Err(BeliefGraphError::Cancelled); }
            reserve(&mut self.usage.edge_visits, object.children.len(), self.request.limits.max_edge_visits, "edges")?;
            for child in &object.children {
                let count = incoming.get_mut(child).ok_or(BeliefGraphError::InvalidGraph(*root))?;
                *count = count.checked_add(1).ok_or(BeliefGraphError::Limit("edges"))?;
            }
        }
        let mut ready: VecDeque<_> = incoming.iter().filter_map(|(root, n)| (*n == 0).then_some(*root)).collect();
        let mut removed = 0;
        while let Some(root) = ready.pop_front() {
            self.checkpoint()?;
            removed += 1;
            let object = self.objects.get(&root).ok_or(BeliefGraphError::InvalidGraph(root))?;
            reserve(&mut self.usage.edge_visits, object.children.len(), self.request.limits.max_edge_visits, "edges")?;
            for child in &object.children {
                let count = incoming.get_mut(child).ok_or(BeliefGraphError::InvalidGraph(root))?;
                *count = count.checked_sub(1).ok_or(BeliefGraphError::InvalidGraph(root))?;
                if *count == 0 { ready.push_back(*child); }
            }
        }
        if removed != self.objects.len() {
            let root = incoming.iter().find_map(|(root, count)| (*count > 0).then_some(*root))
                .ok_or(BeliefGraphError::InvalidSelection)?;
            return Err(BeliefGraphError::InvalidGraph(root));
        }
        Ok(())
    }

    fn verify<'a>(&mut self, offered: &DerivedBelief, ledger: &'a ReferenceLedger, engine: &'a (impl RegisteredBeliefDeriver + ?Sized)) -> Result<VerifiedDerivedBelief<'a>, BeliefGraphError> {
        self.checkpoint()?;
        offered.validate()?;
        let snapshot = ledger.current();
        offered.validate_anchor_freshness(&snapshot.anchor)?;
        if offered.derivation_inputs().algorithm_id != engine.algorithm_id() { return Err(BeliefVerificationError::AlgorithmMismatch.into()); }
        if offered.generation() != engine.generation() { return Err(BeliefVerificationError::GenerationMismatch.into()); }
        let limits = self.request.limits;
        if offered.supporting_evidence().len() + offered.contradictions().len() > limits.verification.max_roots {
            return Err(BeliefVerificationError::RootLimit.into());
        }
        if snapshot.objects.len() > limits.verification.max_snapshot_objects { return Err(BeliefVerificationError::SnapshotLimit.into()); }
        let selected = self.request.authority_objects;
        if selected.is_empty() || !selected.windows(2).all(|pair| pair[0] < pair[1]) { return Err(BeliefGraphError::InvalidSelection); }
        if selected.len() > limits.max_authority_objects { return Err(BeliefGraphError::Limit("authority objects")); }
        // Validate the ENTIRE selection before the first custody read.
        for id in selected {
            self.checkpoint()?;
            if snapshot.objects.get(id).is_none_or(|revision| revision.plane != Plane::Authority) {
                return Err(BeliefGraphError::InvalidAuthorityObject(id.clone()));
            }
        }
        let wanted: BTreeSet<_> = offered.supporting_evidence().iter().chain(offered.contradictions()).copied().collect();
        let mut bindings: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for (id, revision) in &snapshot.objects {
            self.checkpoint()?;
            self.usage.snapshot_objects += 1;
            if revision.plane == Plane::Authority && wanted.contains(&revision.payload_digest) {
                bindings.entry(revision.payload_digest).or_default().push((id.clone(), revision.clone()));
            }
        }
        for id in selected {
            let revision = snapshot.objects.get(id).ok_or_else(|| BeliefGraphError::InvalidAuthorityObject(id.clone()))?;
            self.walk(id, revision, &wanted)?;
        }
        self.require_acyclic()?;
        // No engine observes a partial set, even if the missing root is a contradiction.
        for root in &wanted {
            if !self.ancestry.contains_key(root) { return Err(BeliefVerificationError::RootNotAnchored(*root).into()); }
        }
        let mut take = |roots: &[ContentDigest]| -> Result<Vec<VerifiedBeliefEvidence>, BeliefGraphError> {
            roots.iter().map(|root| {
                let object = self.objects.remove(root).ok_or(BeliefGraphError::InvalidGraph(*root))?;
                Ok(VerifiedBeliefEvidence {
                    digest: *root, bytes: object.bytes,
                    bindings: bindings.remove(root).unwrap_or_default(),
                    ancestry: self.ancestry.remove(root).ok_or(BeliefGraphError::InvalidGraph(*root))?,
                })
            }).collect()
        };
        let supporting = take(offered.supporting_evidence())?;
        let contradicting = take(offered.contradictions())?;
        self.checkpoint()?;
        self.usage.derivations = 1;
        let rebuilt = engine.derive(&BeliefRebuildInputs {
            belief_id: offered.belief_id(), anchor: &snapshot.anchor,
            supporting: &supporting, contradicting: &contradicting,
        })?;
        self.checkpoint()?;
        rebuilt.validate()?;
        if rebuilt != *offered { return Err(BeliefVerificationError::DerivationMismatch.into()); }
        for evidence in supporting.into_iter().chain(contradicting) {
            self.ancestry.insert(evidence.digest, evidence.ancestry);
        }
        Ok(VerifiedDerivedBelief { belief: rebuilt, ledger })
    }
}

/// Verifies the COMPLETE union of selected closures, then independently re-derives the belief.
///
/// All bindings name the exact current snapshot. Traversal is deterministic breadth-first with
/// canonical child order; shared payloads are read once but visits/edges remain cumulatively priced.
/// Cycles, missing siblings, invalidated graph owners, stale anchors, cancellation and exhausted
/// bounds refuse. The original direct verifier and durable belief encodings are unchanged.
/// The engine must explicitly understand `VerifiedBeliefEvidence::ancestry`; ancestry never fills
/// the direct `bindings()` list. Engine runtime cost remains the engine's independently owned limit.
pub fn verify_derived_belief_graph<'a>(
    offered: &DerivedBelief,
    ledger: &'a ReferenceLedger,
    reader: &'a (impl RetainedBeliefGraph + ?Sized),
    engine: &'a (impl RegisteredBeliefDeriver + ?Sized),
    request: BeliefGraphRequest<'_>,
) -> Result<VerifiedBeliefGraph<'a>, BeliefGraphFailure> {
    let mut scan = Scan { reader, request, usage: BeliefGraphUsage::default(), objects: BTreeMap::new(), ancestry: BTreeMap::new() };
    match scan.verify(offered, ledger, engine) {
        Ok(proof) => Ok(VerifiedBeliefGraph { proof, usage: scan.usage, ancestry: scan.ancestry }),
        Err(reason) => Err(BeliefGraphFailure { reason, usage: scan.usage }),
    }
}

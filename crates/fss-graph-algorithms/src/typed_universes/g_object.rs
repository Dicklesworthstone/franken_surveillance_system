#![forbid(unsafe_code)]
//! Archive object and deletion graph `G_object` (`PROJ-OBJECT-001`, `fss-x4a.23.69.8`).
//!
//! Represents evidence roots, manifests, source chunks, repair symbols, indexes, reports, model
//! receipts, signatures, replicas, legal holds, and cache entries. Typed edges are strictly
//! `contains`, `references`, `repairs`, `supersedes`, `replica-of`, and `retained-by-hold`.
//!
//! Core guarantees:
//! - Distinguishes `Staged`, `Durable`, `Published`, `Replicated`, `Protected`, and `Retrievable`
//!   states for every reachable object;
//! - Enforces root-last publication (a root claiming `Published`/`Retrievable` while any reachable
//!   child is still `Staged` or missing fails closed!);
//! - Traverses holds, hold cycles, caches, indexes, repair symbols, and alternate roots to prove
//!   graph-complete deletion closure or report exact blockers (never mistaking a deleted row or
//!   listed prefix for graph-complete deletion!).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fss_core::{
    CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest, Generation,
    GraphAlgorithmWitness, LedgerAnchor, Plane,
};

use crate::projection::{
    AbsenceBoundary, GraphUniverse, ImmutableGraphProjection, ProjectionAuthorityScope,
    ProjectionEdgeSpec, ProjectionNodeSpec, ProjectionOrientation,
};

use super::{
    CURRENT_UNIVERSE_WIRE_VERSION, LEGACY_UNIVERSE_WIRE_VERSION, MAX_UNIVERSE_ITEMS, OpBudget,
    TypedUniverseError, UniverseMigrationReport, build_universe_witness, hash_domain_tag,
    open_wire_envelope, seal_wire_envelope, validate_clean_label,
};

/// Registered digest domain for `G_object` projections and witnesses
/// (`SCHEMA-DOMAIN-GRAPH-G-OBJECT-001`).
pub const G_OBJECT_DIGEST_DOMAIN: &str = "fss.graph.g_object_projection.v1";
/// Wire magic for durable `G_object` fixtures (`FSSGOB01`).
pub const G_OBJECT_WIRE_MAGIC: [u8; 8] = *b"FSSGOB01";
/// Registered algorithm ID emitted in `G_object` witnesses.
pub const G_OBJECT_ALGORITHM_ID: &str = "ALG-PROJ-OBJECT-001";
/// Implementation generation recorded in `G_object` witnesses.
pub const G_OBJECT_IMPLEMENTATION_ID: &str =
    "fss-graph-algorithms:proj-object-001:g-object-oracle:v2";
/// Policy identity recorded in `G_object` witnesses.
pub const G_OBJECT_POLICY_ID: &str =
    "graph-policy:g-object:root-last-closure:graph-complete-deletion:v2";

/// Closed taxonomy of object-graph artifact kinds in `G_object`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ArchiveObjectKind {
    /// Top-level immutable evidence root.
    EvidenceRoot = 1,
    /// Content-addressed manifest listing children.
    Manifest = 2,
    /// Immutable source chunk / packfile object.
    SourceChunk = 3,
    /// Fountain / GF(256) repair symbol.
    RepairSymbol = 4,
    /// Derived secondary index object.
    Index = 5,
    /// Incident or audit report object.
    Report = 6,
    /// Model execution receipt object.
    ModelReceipt = 7,
    /// Detached cryptographic signature object.
    Signature = 8,
    /// Cross-region or local mirror replica.
    Replica = 9,
    /// Active legal/evidence retention hold.
    Hold = 10,
    /// Cached derived/rehydrated copy.
    CacheEntry = 11,
}

impl ArchiveObjectKind {
    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::EvidenceRoot),
            2 => Ok(Self::Manifest),
            3 => Ok(Self::SourceChunk),
            4 => Ok(Self::RepairSymbol),
            5 => Ok(Self::Index),
            6 => Ok(Self::Report),
            7 => Ok(Self::ModelReceipt),
            8 => Ok(Self::Signature),
            9 => Ok(Self::Replica),
            10 => Ok(Self::Hold),
            11 => Ok(Self::CacheEntry),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown ArchiveObjectKind tag {other}"
            ))),
        }
    }
}

/// Strictly ordered non-collapsed custody/durability progression (`FSS-068` / `XFER-INV`).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObjectCustodyState {
    /// Bytes staged locally/remotely; NOT yet durable or published!
    Staged = 1,
    /// Flushed durably to storage, not yet root-published.
    Durable = 2,
    /// Root-last published and reachable.
    Published = 3,
    /// Replicated to secondary durability tier.
    Replicated = 4,
    /// Protected by object lock / WORM / encryption integrity.
    Protected = 5,
    /// Independently challenged and verified retrievable.
    Retrievable = 6,
}

impl ObjectCustodyState {
    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::Staged),
            2 => Ok(Self::Durable),
            3 => Ok(Self::Published),
            4 => Ok(Self::Replicated),
            5 => Ok(Self::Protected),
            6 => Ok(Self::Retrievable),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown ObjectCustodyState tag {other}"
            ))),
        }
    }
}

/// Exact 6 typed directed edges in `G_object`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObjectEdgeKind {
    /// Container/manifest containment (`parent` contains `child`).
    Contains = 1,
    /// Logical reference (`a` references `b`).
    References = 2,
    /// Repair symbol coverage (`symbol` repairs `chunk`).
    Repairs = 3,
    /// Version supersession (`newer` supersedes `older`).
    Supersedes = 4,
    /// Mirror relationship (`replica` is replica-of `primary`).
    ReplicaOf = 5,
    /// Retention lock (`object` retained-by-hold `hold`).
    RetainedByHold = 6,
}

impl ObjectEdgeKind {
    /// Stable canonical relation name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Contains => "contains",
            Self::References => "references",
            Self::Repairs => "repairs",
            Self::Supersedes => "supersedes",
            Self::ReplicaOf => "replica-of",
            Self::RetainedByHold => "retained-by-hold",
        }
    }

    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::Contains),
            2 => Ok(Self::References),
            3 => Ok(Self::Repairs),
            4 => Ok(Self::Supersedes),
            5 => Ok(Self::ReplicaOf),
            6 => Ok(Self::RetainedByHold),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown ObjectEdgeKind tag {other}"
            ))),
        }
    }
}

/// One typed archive object node in `G_object`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveObjectNode {
    /// Stable unique object ID.
    pub object_id: String,
    /// Artifact kind.
    pub kind: ArchiveObjectKind,
    /// Immutable content digest (duplicate content shares digest, tracked explicitly!).
    pub content_digest: ContentDigest,
    /// Byte size of the immutable object.
    pub byte_len: u64,
    /// Pinned source/repair generation (`>= 1`).
    pub object_generation: Generation,
    /// Non-collapsed custody state.
    pub custody_state: ObjectCustodyState,
    /// True iff this object is missing on remote storage (detected during retrieval challenge!).
    pub missing_on_challenge: bool,
    /// Owning semantic plane.
    pub plane: Plane,
}

impl ArchiveObjectNode {
    /// Validates node invariants fail-closed.
    pub fn validate(&self) -> Result<(), TypedUniverseError> {
        validate_clean_label(&self.object_id, "object_id")?;
        if self.object_generation.0 == 0 {
            return Err(TypedUniverseError::InvalidInput(format!(
                "zero object_generation on '{}'",
                self.object_id
            )));
        }
        Ok(())
    }

    /// Canonical SHA-256 commitment for this object node.
    #[must_use]
    pub fn node_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        hash_domain_tag(G_OBJECT_DIGEST_DOMAIN, 1, &enc.finish())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.object_id);
        enc.u8(self.kind as u8);
        enc.digest(self.content_digest);
        enc.u64(self.byte_len);
        enc.u64(self.object_generation.0);
        enc.u8(self.custody_state as u8);
        enc.u8(u8::from(self.missing_on_challenge));
        self.plane.encode_canonical(enc);
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, TypedUniverseError> {
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let object_id = dec.text().map_err(map_err)?.to_owned();
        let kind = ArchiveObjectKind::from_tag(dec.u8().map_err(map_err)?)?;
        let content_digest = dec.digest().map_err(map_err)?;
        let byte_len = dec.u64().map_err(map_err)?;
        let object_generation = Generation(dec.u64().map_err(map_err)?);
        let custody_state = ObjectCustodyState::from_tag(dec.u8().map_err(map_err)?)?;
        let missing_on_challenge = match dec.u8().map_err(map_err)? {
            0 => false,
            1 => true,
            _ => {
                return Err(TypedUniverseError::MalformedWire(
                    "invalid missing_on_challenge bool".to_owned(),
                ));
            }
        };
        let plane = match dec.text().map_err(map_err)? {
            "authority" => Plane::Authority,
            "cognition" => Plane::Cognition,
            "effect" => Plane::Effect,
            other => {
                return Err(TypedUniverseError::MalformedWire(format!(
                    "unknown plane '{other}'"
                )));
            }
        };
        let node = Self {
            object_id,
            kind,
            content_digest,
            byte_len,
            object_generation,
            custody_state,
            missing_on_challenge,
            plane,
        };
        node.validate()?;
        Ok(node)
    }
}

/// One typed directed archive object edge in `G_object`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ArchiveObjectEdge {
    /// Source object ID.
    pub source_id: String,
    /// Target object ID.
    pub target_id: String,
    /// Typed object relation.
    pub kind: ObjectEdgeKind,
}

impl ArchiveObjectEdge {
    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.source_id);
        enc.text(&self.target_id);
        enc.u8(self.kind as u8);
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, TypedUniverseError> {
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let source_id = dec.text().map_err(map_err)?.to_owned();
        let target_id = dec.text().map_err(map_err)?.to_owned();
        let kind = ObjectEdgeKind::from_tag(dec.u8().map_err(map_err)?)?;
        validate_clean_label(&source_id, "source_id")?;
        validate_clean_label(&target_id, "target_id")?;
        Ok(Self {
            source_id,
            target_id,
            kind,
        })
    }
}

/// Incremental ordered delta applied to `G_object`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObjectGraphDelta {
    /// Upsert an object node.
    UpsertNode(ArchiveObjectNode),
    /// Remove an object node and incident edges.
    RemoveNode(String),
    /// Add a typed object edge.
    AddEdge(ArchiveObjectEdge),
    /// Remove a typed object edge.
    RemoveEdge(ArchiveObjectEdge),
}

/// Non-collapsed verdict for root closure, retrieval challenge, and deletion reachability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObjectClosureVerdict {
    /// Complete root-last closure verified & all reachable objects met required custody floor!
    ClosureVerified,
    /// Root-before-child violation, missing child, stale repair symbol, or replica lag detected!
    ClosureDefective,
    /// Deletion closure permitted (zero active holds, zero alternate roots sharing members!).
    DeletionClosureAdmitted,
    /// Deletion blocked by active holds, hold cycles, or shared alternate root references!
    DeletionBlocked,
}

/// Certified root reconstruction, retrieval challenge, and deletion closure report over `G_object`.
#[derive(Clone, Debug, PartialEq)]
pub struct ObjectClosureAudit {
    /// Audited root object ID.
    pub root_id: String,
    /// Non-collapsed verdict for closure/retrieval.
    pub closure_verdict: ObjectClosureVerdict,
    /// Non-collapsed verdict for deletion eligibility.
    pub deletion_verdict: ObjectClosureVerdict,
    /// All reachable closure members with their exact non-collapsed `ObjectCustodyState`.
    pub member_custody_states: BTreeMap<String, ObjectCustodyState>,
    /// Root-before-child violations (root published while child remained `Staged`).
    pub root_before_child_violations: Vec<String>,
    /// Reachable objects missing during retrieval challenge.
    pub missing_children: Vec<String>,
    /// Repair symbols whose `object_generation` differs from the chunk they repair.
    pub stale_repair_symbols: Vec<String>,
    /// Replicas lagging below `Replicated` custody state.
    pub lagging_replicas: Vec<String>,
    /// Exact deletion blockers (holds, hold cycles, alternate roots sharing reachable objects).
    pub deletion_blockers: Vec<String>,
    /// All secondary artifacts included in deletion closure (indexes, caches, repair symbols, replicas).
    pub deletion_closure_members: Vec<String>,
    /// Always `false`: archive graph inspection never grants deletion or effect authority!
    pub grants_effect_authority: bool,
    /// Certified execution witness.
    pub witness: GraphAlgorithmWitness,
}

/// Anchor-pinned, capability-filtered Archive Object & Deletion Graph (`G_object`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveObjectGraph {
    projection_id: String,
    policy_generation: Generation,
    projection: ImmutableGraphProjection,
    visible_nodes: BTreeMap<String, ArchiveObjectNode>,
    visible_edges: BTreeSet<ArchiveObjectEdge>,
    tombstoned_fields: Vec<String>,
    universe_digest: ContentDigest,
}

impl ArchiveObjectGraph {
    /// Builds `G_object` over `ImmutableGraphProjection` (`GraphUniverse::GObject`).
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        projection_id: impl Into<String>,
        policy_generation: Generation,
        anchor: LedgerAnchor,
        history_root: ContentDigest,
        authority: &ProjectionAuthorityScope,
        nodes: Vec<ArchiveObjectNode>,
        edges: Vec<ArchiveObjectEdge>,
        requested_absence: AbsenceBoundary,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<Self, TypedUniverseError> {
        if is_cancelled() {
            return Err(TypedUniverseError::Cancelled);
        }
        let projection_id = projection_id.into();
        validate_clean_label(&projection_id, "projection_id")?;
        if policy_generation.0 == 0 {
            return Err(TypedUniverseError::InvalidInput(
                "policy_generation must be >= 1".to_owned(),
            ));
        }
        if nodes.len() > MAX_UNIVERSE_ITEMS || edges.len() > MAX_UNIVERSE_ITEMS * 4 {
            return Err(TypedUniverseError::InvalidInput(
                "G_object size exceeds hard ceiling".to_owned(),
            ));
        }

        let mut raw_nodes: BTreeMap<String, ArchiveObjectNode> = BTreeMap::new();
        for node in nodes {
            if is_cancelled() {
                return Err(TypedUniverseError::Cancelled);
            }
            node.validate()?;
            if raw_nodes.contains_key(&node.object_id) {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "duplicate G_object object_id '{}'",
                    node.object_id
                )));
            }
            raw_nodes.insert(node.object_id.clone(), node);
        }

        let mut raw_edges: BTreeSet<ArchiveObjectEdge> = BTreeSet::new();
        for edge in edges {
            validate_clean_label(&edge.source_id, "source_id")?;
            validate_clean_label(&edge.target_id, "target_id")?;
            if !raw_nodes.contains_key(&edge.source_id) || !raw_nodes.contains_key(&edge.target_id)
            {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "unknown G_object edge endpoint '{}' -> '{}'",
                    edge.source_id, edge.target_id
                )));
            }
            raw_edges.insert(edge);
        }

        let proj_nodes: Vec<ProjectionNodeSpec> = raw_nodes
            .values()
            .map(|n| ProjectionNodeSpec {
                node_id: n.object_id.clone(),
                plane: n.plane,
                payload_digest: n.node_digest(),
            })
            .collect();
        let proj_edges: Vec<ProjectionEdgeSpec> = raw_edges
            .iter()
            .map(|e| ProjectionEdgeSpec {
                source_id: e.source_id.clone(),
                target_id: e.target_id.clone(),
                relation: e.kind.as_str().to_owned(),
                weight: u64::from(e.kind as u8),
            })
            .collect();

        let projection = ImmutableGraphProjection::build(
            GraphUniverse::GObject,
            ProjectionOrientation::Directed,
            anchor,
            history_root,
            authority,
            proj_nodes,
            proj_edges,
            requested_absence,
            is_cancelled(),
        )?;

        let visible_nodes: BTreeMap<String, ArchiveObjectNode> = raw_nodes
            .into_iter()
            .filter(|(id, _)| projection.handle_for_node_id(id).is_some())
            .collect();
        let visible_edges: BTreeSet<ArchiveObjectEdge> = raw_edges
            .into_iter()
            .filter(|e| {
                visible_nodes.contains_key(&e.source_id) && visible_nodes.contains_key(&e.target_id)
            })
            .collect();

        let universe_digest = Self::compute_digest(
            &projection_id,
            policy_generation,
            &projection,
            &visible_nodes,
            &visible_edges,
        );
        Ok(Self {
            projection_id,
            policy_generation,
            projection,
            visible_nodes,
            visible_edges,
            tombstoned_fields: Vec::new(),
            universe_digest,
        })
    }

    /// Incrementally applies ordered `ObjectGraphDelta` updates with full-rebuild parity.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_deltas(
        &self,
        new_anchor: LedgerAnchor,
        new_history_root: ContentDigest,
        expected_policy_generation: Generation,
        authority: &ProjectionAuthorityScope,
        deltas: &[ObjectGraphDelta],
        requested_absence: AbsenceBoundary,
        is_cancelled: impl FnMut() -> bool,
    ) -> Result<Self, TypedUniverseError> {
        if expected_policy_generation != self.policy_generation {
            return Err(TypedUniverseError::MixedAnchorOrGeneration(
                "policy generation mismatch".to_owned(),
            ));
        }
        if new_anchor.site_lineage != self.projection.anchor().site_lineage
            || new_anchor.commit_sequence < self.projection.anchor().commit_sequence
        {
            return Err(TypedUniverseError::MixedAnchorOrGeneration(
                "delta anchor must remain on same site_lineage with monotonic sequence".to_owned(),
            ));
        }
        let mut nodes = self.visible_nodes.clone();
        let mut edges = self.visible_edges.clone();
        for delta in deltas {
            match delta {
                ObjectGraphDelta::UpsertNode(n) => {
                    n.validate()?;
                    nodes.insert(n.object_id.clone(), n.clone());
                }
                ObjectGraphDelta::RemoveNode(id) => {
                    nodes.remove(id);
                    edges.retain(|e| e.source_id != *id && e.target_id != *id);
                }
                ObjectGraphDelta::AddEdge(e) => {
                    edges.insert(e.clone());
                }
                ObjectGraphDelta::RemoveEdge(e) => {
                    edges.remove(e);
                }
            }
        }
        Self::build(
            self.projection_id.clone(),
            self.policy_generation,
            new_anchor,
            new_history_root,
            authority,
            nodes.into_values().collect(),
            edges.into_iter().collect(),
            requested_absence,
            is_cancelled,
        )
    }

    /// Underlying capability-filtered `ImmutableGraphProjection`.
    #[must_use]
    pub const fn projection(&self) -> &ImmutableGraphProjection {
        &self.projection
    }

    /// Canonical digest of this `G_object` universe.
    #[must_use]
    pub const fn universe_digest(&self) -> ContentDigest {
        self.universe_digest
    }

    /// Inspecting `G_object` NEVER grants deletion or effect authority.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Audits manifest-rooted closure, root-last durability ordering, retrieval challenge
    /// completeness, repair-symbol generation currency, replica lag, and graph-complete deletion
    /// blockers (holds, hold cycles, caches/indexes/repair symbols, and alternate shared roots)!
    pub fn audit_root_closure_and_deletion(
        &self,
        root_id: &str,
        required_custody_floor: ObjectCustodyState,
        max_operations: u64,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<ObjectClosureAudit, TypedUniverseError> {
        validate_clean_label(root_id, "root_id")?;
        let mut budget = OpBudget::new(max_operations)?;
        let Some(root_node) = self.visible_nodes.get(root_id) else {
            return Err(TypedUniverseError::InvalidInput(format!(
                "root object '{root_id}' not present in G_object"
            )));
        };

        // Traverse forward Contains/References from root_id.
        let mut reachable: BTreeSet<&str> = BTreeSet::new();
        let mut q: VecDeque<&str> = VecDeque::new();
        q.push_back(root_id);
        reachable.insert(root_id);
        while let Some(u) = q.pop_front() {
            budget.charge(1, &mut is_cancelled)?;
            for edge in &self.visible_edges {
                if edge.source_id == u
                    && matches!(
                        edge.kind,
                        ObjectEdgeKind::Contains | ObjectEdgeKind::References
                    )
                    && reachable.insert(edge.target_id.as_str())
                {
                    q.push_back(edge.target_id.as_str());
                }
            }
        }

        // Expand deletion closure to include repair symbols, replicas, indexes, and caches linked
        // to any reachable primary member!
        let mut deletion_closure: BTreeSet<&str> = reachable.clone();
        let mut stale_repair_symbols = BTreeSet::new();
        let mut lagging_replicas = BTreeSet::new();
        let mut deletion_blockers = BTreeSet::new();

        for edge in &self.visible_edges {
            budget.charge(1, &mut is_cancelled)?;
            if edge.kind == ObjectEdgeKind::Repairs && reachable.contains(edge.target_id.as_str()) {
                deletion_closure.insert(edge.source_id.as_str());
                if let (Some(sym), Some(tgt)) = (
                    self.visible_nodes.get(&edge.source_id),
                    self.visible_nodes.get(&edge.target_id),
                ) && sym.object_generation != tgt.object_generation
                {
                    stale_repair_symbols.insert(sym.object_id.clone());
                }
            } else if edge.kind == ObjectEdgeKind::ReplicaOf
                && reachable.contains(edge.target_id.as_str())
            {
                deletion_closure.insert(edge.source_id.as_str());
                if let Some(rep) = self.visible_nodes.get(&edge.source_id)
                    && rep.custody_state < ObjectCustodyState::Replicated
                {
                    lagging_replicas.insert(rep.object_id.clone());
                }
            } else if edge.kind == ObjectEdgeKind::References
                && reachable.contains(edge.target_id.as_str())
                && let Some(src) = self.visible_nodes.get(&edge.source_id)
                && matches!(
                    src.kind,
                    ArchiveObjectKind::Index
                        | ArchiveObjectKind::CacheEntry
                        | ArchiveObjectKind::Report
                )
            {
                deletion_closure.insert(src.object_id.as_str());
            }
        }

        // Check custody states, root-before-child ordering, and missing objects.
        let mut member_custody_states = BTreeMap::new();
        let mut root_before_child_violations = Vec::new();
        let mut missing_children = Vec::new();
        let root_published = root_node.custody_state >= ObjectCustodyState::Published;

        for &id in &reachable {
            budget.charge(1, &mut is_cancelled)?;
            if let Some(node) = self.visible_nodes.get(id) {
                member_custody_states.insert(node.object_id.clone(), node.custody_state);
                if node.missing_on_challenge {
                    missing_children.push(node.object_id.clone());
                }
                if id != root_id
                    && root_published
                    && node.custody_state == ObjectCustodyState::Staged
                {
                    root_before_child_violations.push(node.object_id.clone());
                }
            }
        }

        // Deletion blockers:
        // 1. Any active RetainedByHold edge touching any deletion_closure member (handles hold cycles cleanly!).
        for edge in &self.visible_edges {
            budget.charge(1, &mut is_cancelled)?;
            if edge.kind == ObjectEdgeKind::RetainedByHold
                && deletion_closure.contains(edge.source_id.as_str())
            {
                deletion_blockers.insert(format!("hold:{}:{}", edge.source_id, edge.target_id));
            }
        }
        // 2. Any alternate EvidenceRoot (`alt != root_id`) reaching any shared member of `reachable`!
        for (alt_id, alt_node) in &self.visible_nodes {
            if alt_id == root_id || alt_node.kind != ArchiveObjectKind::EvidenceRoot {
                continue;
            }
            let mut alt_seen: BTreeSet<&str> = BTreeSet::new();
            let mut alt_q: VecDeque<&str> = VecDeque::new();
            alt_q.push_back(alt_id.as_str());
            alt_seen.insert(alt_id.as_str());
            while let Some(u) = alt_q.pop_front() {
                budget.charge(1, &mut is_cancelled)?;
                if u != alt_id && deletion_closure.contains(u) {
                    deletion_blockers.insert(format!("shared_alternate_root:{alt_id}:{u}"));
                }
                for edge in &self.visible_edges {
                    if edge.source_id == u
                        && matches!(
                            edge.kind,
                            ObjectEdgeKind::Contains | ObjectEdgeKind::References
                        )
                        && alt_seen.insert(edge.target_id.as_str())
                    {
                        alt_q.push_back(edge.target_id.as_str());
                    }
                }
            }
        }
        // 3. Uncertified/redacted absence boundary blocks deletion certification!
        if !self.projection.absence_boundary().certifies_absence() {
            deletion_blockers.insert("uncertified_or_redacted_absence_boundary".to_owned());
        }

        let below_floor = member_custody_states
            .values()
            .any(|&st| st < required_custody_floor);
        let closure_verdict = if root_before_child_violations.is_empty()
            && missing_children.is_empty()
            && stale_repair_symbols.is_empty()
            && lagging_replicas.is_empty()
            && !below_floor
            && self.projection.absence_boundary().certifies_absence()
        {
            ObjectClosureVerdict::ClosureVerified
        } else {
            ObjectClosureVerdict::ClosureDefective
        };

        let deletion_verdict = if deletion_blockers.is_empty() {
            ObjectClosureVerdict::DeletionClosureAdmitted
        } else {
            ObjectClosureVerdict::DeletionBlocked
        };

        let stale_repairs_vec: Vec<String> = stale_repair_symbols.into_iter().collect();
        let lagging_vec: Vec<String> = lagging_replicas.into_iter().collect();
        let blockers_vec: Vec<String> = deletion_blockers.into_iter().collect();
        let closure_vec: Vec<String> = deletion_closure.into_iter().map(str::to_owned).collect();

        let mut path_enc = CanonicalEncoder::new();
        path_enc.text(root_id);
        path_enc.u8(u8::from(
            closure_verdict == ObjectClosureVerdict::ClosureVerified,
        ));
        path_enc.u8(u8::from(
            deletion_verdict == ObjectClosureVerdict::DeletionClosureAdmitted,
        ));
        for b in &blockers_vec {
            path_enc.text(b);
        }
        let decision_path_digest = hash_domain_tag(G_OBJECT_DIGEST_DOMAIN, 2, &path_enc.finish());
        let mut out_enc = CanonicalEncoder::new();
        out_enc.digest(self.universe_digest);
        out_enc.digest(decision_path_digest);
        out_enc.u64(closure_vec.len() as u64);
        let output_digest = hash_domain_tag(G_OBJECT_DIGEST_DOMAIN, 3, &out_enc.finish());

        let witness = build_universe_witness(
            G_OBJECT_ALGORITHM_ID,
            G_OBJECT_IMPLEMENTATION_ID,
            GraphUniverse::GObject,
            &self.projection_id,
            self.projection.anchor(),
            self.projection.node_count(),
            self.projection.edge_count(),
            self.universe_digest,
            G_OBJECT_POLICY_ID,
            budget.used(),
            ((self.visible_nodes.len() + self.visible_edges.len() + 1) * 192) as u64,
            decision_path_digest,
            output_digest,
        )?;

        Ok(ObjectClosureAudit {
            root_id: root_id.to_owned(),
            closure_verdict,
            deletion_verdict,
            member_custody_states,
            root_before_child_violations,
            missing_children,
            stale_repair_symbols: stale_repairs_vec,
            lagging_replicas: lagging_vec,
            deletion_blockers: blockers_vec,
            deletion_closure_members: closure_vec,
            grants_effect_authority: false,
            witness,
        })
    }

    /// Serializes `G_object` into its versioned checksummed wire format (`v2`).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, TypedUniverseError> {
        self.encode_versioned(CURRENT_UNIVERSE_WIRE_VERSION, false)
    }

    /// Serializes a compatible legacy `v1` fixture carrying a removed `legacy_row_delete_ok` flag.
    pub fn to_legacy_v1_fixture_bytes(
        &self,
        legacy_row_delete_ok: bool,
    ) -> Result<Vec<u8>, TypedUniverseError> {
        self.encode_versioned(LEGACY_UNIVERSE_WIRE_VERSION, legacy_row_delete_ok)
    }

    fn encode_versioned(
        &self,
        version: u32,
        legacy_row_delete_ok: bool,
    ) -> Result<Vec<u8>, TypedUniverseError> {
        let proj_bytes = self.projection.to_canonical_bytes()?;
        let mut enc = CanonicalEncoder::new();
        enc.text(&self.projection_id);
        enc.u64(self.policy_generation.0);
        enc.bytes(&proj_bytes);
        enc.u64(self.visible_nodes.len() as u64);
        for node in self.visible_nodes.values() {
            node.encode_body(&mut enc);
        }
        enc.u64(self.visible_edges.len() as u64);
        for edge in &self.visible_edges {
            edge.encode_body(&mut enc);
        }
        if version == LEGACY_UNIVERSE_WIRE_VERSION {
            enc.u8(u8::from(legacy_row_delete_ok));
        } else {
            enc.u64(self.tombstoned_fields.len() as u64);
            for t in &self.tombstoned_fields {
                enc.text(t);
            }
        }
        let payload = enc
            .finish_checked()
            .map_err(|e| TypedUniverseError::MalformedWire(e.to_string()))?;
        seal_wire_envelope(
            G_OBJECT_WIRE_MAGIC,
            version,
            G_OBJECT_DIGEST_DOMAIN,
            &payload,
        )
    }

    /// Opens a `v1` (migrating deterministically with tombstones) or `v2` durable `G_object` fixture.
    pub fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<(Self, UniverseMigrationReport), TypedUniverseError> {
        let (version, payload) =
            open_wire_envelope(bytes, G_OBJECT_WIRE_MAGIC, G_OBJECT_DIGEST_DOMAIN)?;
        let mut dec = CanonicalDecoder::new(payload);
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let projection_id = dec.text().map_err(map_err)?.to_owned();
        validate_clean_label(&projection_id, "projection_id")?;
        let policy_generation = Generation(dec.u64().map_err(map_err)?);
        if policy_generation.0 == 0 {
            return Err(TypedUniverseError::MalformedWire(
                "zero policy_generation".to_owned(),
            ));
        }
        let proj_bytes = dec.bytes().map_err(map_err)?;
        let projection = ImmutableGraphProjection::from_canonical_bytes(proj_bytes)?;
        if projection.universe() != GraphUniverse::GObject {
            return Err(TypedUniverseError::MalformedWire(
                "embedded projection universe is not G_object".to_owned(),
            ));
        }
        let n_len = usize::try_from(dec.u64().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("node count overflow".to_owned()))?;
        if n_len > MAX_UNIVERSE_ITEMS || n_len.saturating_mul(48) > dec.remaining() {
            return Err(TypedUniverseError::MalformedWire(
                "node count out of wire bounds".to_owned(),
            ));
        }
        let mut visible_nodes = BTreeMap::new();
        for _ in 0..n_len {
            let node = ArchiveObjectNode::decode_body(&mut dec)?;
            if visible_nodes.contains_key(&node.object_id) {
                return Err(TypedUniverseError::MalformedWire(
                    "duplicate G_object object_id".to_owned(),
                ));
            }
            let Some(handle) = projection.handle_for_node_id(&node.object_id) else {
                return Err(TypedUniverseError::MalformedWire(
                    "wire G_object node missing from embedded projection".to_owned(),
                ));
            };
            if projection.node(handle)?.payload_digest != node.node_digest() {
                return Err(TypedUniverseError::MalformedWire(
                    "wire G_object node digest disagrees with embedded projection".to_owned(),
                ));
            }
            visible_nodes.insert(node.object_id.clone(), node);
        }
        if visible_nodes.len() != projection.node_count() {
            return Err(TypedUniverseError::MalformedWire(
                "wire G_object node count disagrees with embedded projection".to_owned(),
            ));
        }
        let e_len = usize::try_from(dec.u64().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("edge count overflow".to_owned()))?;
        if e_len > MAX_UNIVERSE_ITEMS * 4 || e_len.saturating_mul(9) > dec.remaining() {
            return Err(TypedUniverseError::MalformedWire(
                "edge count out of wire bounds".to_owned(),
            ));
        }
        let mut visible_edges = BTreeSet::new();
        for _ in 0..e_len {
            let edge = ArchiveObjectEdge::decode_body(&mut dec)?;
            if !visible_nodes.contains_key(&edge.source_id)
                || !visible_nodes.contains_key(&edge.target_id)
            {
                return Err(TypedUniverseError::MalformedWire(
                    "wire G_object edge references unknown node".to_owned(),
                ));
            }
            if !visible_edges.insert(edge) {
                return Err(TypedUniverseError::MalformedWire(
                    "duplicate wire G_object edge".to_owned(),
                ));
            }
        }
        if visible_edges.len() != projection.edge_count() {
            return Err(TypedUniverseError::MalformedWire(
                "wire G_object edge count disagrees with embedded projection".to_owned(),
            ));
        }
        let (migrated, tombstoned_fields) = if version == LEGACY_UNIVERSE_WIRE_VERSION {
            let _deprecated_flag = dec.u8().map_err(map_err)?;
            (
                true,
                vec![
                    "v1.legacy_row_delete_ok:tombstoned_graph_complete_closure_required".to_owned(),
                ],
            )
        } else {
            let t_len = usize::try_from(dec.u64().map_err(map_err)?).map_err(|_| {
                TypedUniverseError::MalformedWire("tombstone count overflow".to_owned())
            })?;
            if t_len > 32 || t_len.saturating_mul(4) > dec.remaining() {
                return Err(TypedUniverseError::MalformedWire(
                    "tombstone count exceeds bounds".to_owned(),
                ));
            }
            let mut tombs = Vec::with_capacity(t_len);
            for _ in 0..t_len {
                let t = dec.text().map_err(map_err)?.to_owned();
                validate_clean_label(&t, "tombstone")?;
                tombs.push(t);
            }
            (false, tombs)
        };
        dec.ensure_finished().map_err(map_err)?;

        let universe_digest = Self::compute_digest(
            &projection_id,
            policy_generation,
            &projection,
            &visible_nodes,
            &visible_edges,
        );
        let report = UniverseMigrationReport {
            source_version: version,
            target_version: CURRENT_UNIVERSE_WIRE_VERSION,
            migrated,
            tombstoned_fields: tombstoned_fields.clone(),
            universe_digest,
        };
        Ok((
            Self {
                projection_id,
                policy_generation,
                projection,
                visible_nodes,
                visible_edges,
                tombstoned_fields,
                universe_digest,
            },
            report,
        ))
    }

    fn compute_digest(
        projection_id: &str,
        policy_generation: Generation,
        projection: &ImmutableGraphProjection,
        visible_nodes: &BTreeMap<String, ArchiveObjectNode>,
        visible_edges: &BTreeSet<ArchiveObjectEdge>,
    ) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text(projection_id);
        enc.u64(policy_generation.0);
        enc.digest(projection.generation().projection_digest);
        enc.u64(visible_nodes.len() as u64);
        for node in visible_nodes.values() {
            enc.digest(node.node_digest());
        }
        enc.u64(visible_edges.len() as u64);
        for edge in visible_edges {
            edge.encode_body(&mut enc);
        }
        hash_domain_tag(G_OBJECT_DIGEST_DOMAIN, 0, &enc.finish())
    }
}

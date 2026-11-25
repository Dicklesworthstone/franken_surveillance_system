#![forbid(unsafe_code)]
//! Immutable graph projection and generational-handle core (`FSS-151`, `fss-x4a.23.1`).
//!
//! Provides the shared immutable graph projection container and generational handle mechanism
//! backing the twelve registered FSS graph universes (`G_phys`, `H_vis`, `G_sensor`, `G_time`,
//! `G_assoc`, `G_evidence`, `G_effect`, `G_object`, `G_auth`, `G_memory`, `G_agent`, `G_world`)
//! without collapsing distinct universes into one generic property graph:
//!
//! - **Generational handles (`NodeHandle`, `EdgeHandle`, `ProjectionGeneration`):** every index
//!   lookup, attribute read, or neighbor expansion checks exact generation equality first,
//!   failing closed with [`ProjectionError::StaleHandleGeneration`] on stale, forked, cross-universe,
//!   or cross-privacy-epoch handles.
//! - **Capability and privacy filtering BEFORE expansion:** unauthorized universes, unauthorized
//!   planes, or redacted nodes never expand into the materialized projection; omissions are
//!   preserved explicitly in [`AbsenceBoundary`] rather than collapsed into certified absence.
//! - **Insertion-order invariance (CGSE canonical tie-break):** nodes are indexed in ascending
//!   byte order of stable external IDs; edges are sorted canonically by
//!   `(source_index, target_index, relation, weight)` so identical sets yield byte-identical
//!   compressed adjacency and digests regardless of insertion order.
//! - **Hand-audited durable binary format (`FSSGPR01` v1):** bounded, checksummed wire codec
//!   sealed under `fss.graph.immutable_projection.v1` with allocation-bomb guards.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, LedgerAnchor, Plane,
};

use crate::graph::{GraphBuilder, GraphError, MAX_NODE_ID_LEN, UndirectedGraph};

/// Registered digest domain for [`ImmutableGraphProjection`] commitments (`FSS-151`).
pub const IMMUTABLE_PROJECTION_DOMAIN: &str = "fss.graph.immutable_projection.v1";
/// Binary wire header magic for serialized immutable graph projections.
pub const PROJECTION_WIRE_MAGIC: [u8; 8] = *b"FSSGPR01";
/// Supported durable wire format version for [`ImmutableGraphProjection`].
pub const PROJECTION_WIRE_VERSION: u32 = 1;
/// Hard ceiling on nodes in one immutable graph projection.
pub const MAX_PROJECTION_NODES: usize = 65_536;
/// Hard ceiling on edges in one immutable graph projection.
pub const MAX_PROJECTION_EDGES: usize = 262_144;
/// Hard ceiling on serialized binary wire bytes of one projection (8 MiB).
pub const MAX_PROJECTION_WIRE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum UTF-8 bytes in an edge relation label or omission reason.
pub const MAX_RELATION_LABEL_BYTES: usize = 128;

/// Registered FSS typed graph universe (`GRAPH-PROJECTION-SEMANTICS-001`).
///
/// Distinct universes never silently merge into one untyped property graph.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GraphUniverse {
    /// Physical space / site topology (`G_phys`).
    GPhys = 1,
    /// Visibility / line-of-sight hypergraph (`H_vis`).
    HVis = 2,
    /// Sensor / hardware dependency graph (`G_sensor`).
    GSensor = 3,
    /// Temporal / clock-alignment graph (`G_time`).
    GTime = 4,
    /// Tracklet / identity association graph (`G_assoc`).
    GAssoc = 5,
    /// Evidence / support DAG (`G_evidence`).
    GEvidence = 6,
    /// Effect / obligation dependency graph (`G_effect`).
    GEffect = 7,
    /// Content-addressed object / manifest graph (`G_object`).
    GObject = 8,
    /// Authority / capability delegation graph (`G_auth`).
    GAuth = 9,
    /// Cautious memory / episode graph (`G_memory`).
    GMemory = 10,
    /// Agent session / handoff / workspace graph (`G_agent`).
    GAgent = 11,
    /// Possible-worlds / hypothesis envelope graph (`G_world`).
    GWorld = 12,
}

impl GraphUniverse {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GPhys => "G_phys",
            Self::HVis => "H_vis",
            Self::GSensor => "G_sensor",
            Self::GTime => "G_time",
            Self::GAssoc => "G_assoc",
            Self::GEvidence => "G_evidence",
            Self::GEffect => "G_effect",
            Self::GObject => "G_object",
            Self::GAuth => "G_auth",
            Self::GMemory => "G_memory",
            Self::GAgent => "G_agent",
            Self::GWorld => "G_world",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::GPhys),
            2 => Ok(Self::HVis),
            3 => Ok(Self::GSensor),
            4 => Ok(Self::GTime),
            5 => Ok(Self::GAssoc),
            6 => Ok(Self::GEvidence),
            7 => Ok(Self::GEffect),
            8 => Ok(Self::GObject),
            9 => Ok(Self::GAuth),
            10 => Ok(Self::GMemory),
            11 => Ok(Self::GAgent),
            12 => Ok(Self::GWorld),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Edge orientation contract of one immutable graph projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionOrientation {
    /// Undirected simple edges (`source_idx < target_idx` canonically).
    Undirected = 1,
    /// Directed edges (`source_idx -> target_idx`).
    Directed = 2,
}

impl ProjectionOrientation {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Undirected => "undirected",
            Self::Directed => "directed",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::Undirected),
            2 => Ok(Self::Directed),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Safe operator/agent recovery guidance for a refused projection operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionGuidance {
    /// Repair invalid node/edge input, bounds, self-loop, or duplicate entries.
    RepairInput,
    /// Re-authorize revoked capability, privacy projection, or universe/plane scope.
    ReauthorizeProjection,
    /// Re-acquire handles from the current projection generation before dereferencing.
    ReacquireHandlesForCurrentGeneration,
    /// Cooperative cancellation observed; rebuild cleanly from pinned anchor when ready.
    RetryFromPinnedAnchor,
    /// Reject corrupt or unsupported binary projection bytes and rebuild from canonical ledger.
    RebuildFromCanonicalLedger,
}

/// Typed failure returned by [`ImmutableGraphProjection`] construction, handle access, or codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionError {
    /// Node/edge input violated bounds, uniqueness, or endpoint validity.
    InvalidInput(String),
    /// Capability, privacy, universe, or plane authorization was refused or revoked.
    AuthorityRevoked(String),
    /// Authority generation drifted from pinned expectation.
    StaleAuthorityGeneration {
        /// Expected authority generation.
        expected: u64,
        /// Observed authority generation.
        observed: u64,
    },
    /// Handle belonged to a different projection generation, anchor, universe, or privacy epoch.
    StaleHandleGeneration {
        /// Handle's generation digest.
        handle_digest: ContentDigest,
        /// Active projection's generation digest.
        projection_digest: ContentDigest,
    },
    /// Handle index fell out of bounds (defensive guard).
    HandleOutOfRange {
        /// Supplied index.
        index: u32,
        /// Valid upper bound.
        len: usize,
    },
    /// Cooperative cancellation observed before completing projection construction.
    Cancelled,
    /// Projection count or wire length exceeded hard ceilings.
    BoundsExceeded {
        /// Observed size or count.
        observed: usize,
        /// Maximum allowed bound.
        maximum: usize,
    },
    /// Wire projection lacked [`PROJECTION_WIRE_MAGIC`].
    InvalidMagic,
    /// Wire projection declared an unsupported format version.
    UnsupportedVersion {
        /// Observed format version.
        version: u32,
    },
    /// Wire projection was truncated, non-canonical, or malformed.
    MalformedWire(String),
    /// Wire projection checksum failed verification.
    ChecksumMismatch,
    /// Canonical encoding failed.
    Encoding(String),
}

impl ProjectionError {
    /// Registered stable error identity.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "ERR-GRAPH-PROJECTION-INVALID-INPUT-001",
            Self::AuthorityRevoked(_) => "ERR-GRAPH-PROJECTION-AUTHORITY-REVOKED-001",
            Self::StaleAuthorityGeneration { .. } => "ERR-GRAPH-PROJECTION-STALE-AUTH-GEN-001",
            Self::StaleHandleGeneration { .. } | Self::HandleOutOfRange { .. } => {
                "ERR-GRAPH-PROJECTION-STALE-HANDLE-001"
            }
            Self::Cancelled => "ERR-GRAPH-PROJECTION-CANCELLED-001",
            Self::BoundsExceeded { .. } => "ERR-GRAPH-PROJECTION-BOUNDS-001",
            Self::InvalidMagic => "ERR-GRAPH-PROJECTION-INVALID-MAGIC-001",
            Self::UnsupportedVersion { .. } => "ERR-GRAPH-PROJECTION-UNSUPPORTED-VERSION-001",
            Self::MalformedWire(_) => "ERR-GRAPH-PROJECTION-MALFORMED-WIRE-001",
            Self::ChecksumMismatch => "ERR-GRAPH-PROJECTION-CHECKSUM-MISMATCH-001",
            Self::Encoding(_) => "ERR-GRAPH-PROJECTION-ENCODING-001",
        }
    }

    /// Safe recovery guidance for this refusal.
    #[must_use]
    pub const fn guidance(&self) -> ProjectionGuidance {
        match self {
            Self::InvalidInput(_) | Self::BoundsExceeded { .. } => ProjectionGuidance::RepairInput,
            Self::AuthorityRevoked(_) | Self::StaleAuthorityGeneration { .. } => {
                ProjectionGuidance::ReauthorizeProjection
            }
            Self::StaleHandleGeneration { .. } | Self::HandleOutOfRange { .. } => {
                ProjectionGuidance::ReacquireHandlesForCurrentGeneration
            }
            Self::Cancelled => ProjectionGuidance::RetryFromPinnedAnchor,
            Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::MalformedWire(_)
            | Self::ChecksumMismatch
            | Self::Encoding(_) => ProjectionGuidance::RebuildFromCanonicalLedger,
        }
    }
}

impl fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}

impl Error for ProjectionError {}

/// Explicit capability and privacy projection enforced BEFORE graph node/edge expansion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionAuthorityScope {
    /// Active authority generation.
    pub authority_generation: u64,
    /// Expected authority generation pinned at projection time.
    pub expected_authority_generation: u64,
    /// Active privacy policy epoch.
    pub privacy_epoch: u64,
    /// True while graph projection read capability remains active.
    pub capability_active: bool,
    /// True while privacy projection authorization remains active.
    pub privacy_active: bool,
    /// Graph universes permitted for this projection.
    pub allowed_universes: BTreeSet<GraphUniverse>,
    /// Semantic planes whose nodes may enter this projection.
    pub allowed_planes: BTreeSet<Plane>,
    /// Node identities redacted/restricted under the caller's privacy scope (filtered BEFORE expansion).
    pub redacted_node_ids: BTreeSet<String>,
}

impl ProjectionAuthorityScope {
    /// Constructs an active scope authorizing `universe` and all three semantic planes.
    #[must_use]
    pub fn active_for(
        universe: GraphUniverse,
        authority_generation: u64,
        privacy_epoch: u64,
    ) -> Self {
        let mut allowed_universes = BTreeSet::new();
        allowed_universes.insert(universe);
        let allowed_planes = [Plane::Authority, Plane::Cognition, Plane::Effect]
            .into_iter()
            .collect();
        Self {
            authority_generation,
            expected_authority_generation: authority_generation,
            privacy_epoch,
            capability_active: true,
            privacy_active: true,
            allowed_universes,
            allowed_planes,
            redacted_node_ids: BTreeSet::new(),
        }
    }

    fn validate_for(&self, universe: GraphUniverse) -> Result<(), ProjectionError> {
        if !self.capability_active {
            return Err(ProjectionError::AuthorityRevoked(
                "graph projection capability revoked".to_owned(),
            ));
        }
        if !self.privacy_active {
            return Err(ProjectionError::AuthorityRevoked(
                "graph privacy projection authorization revoked".to_owned(),
            ));
        }
        if self.authority_generation != self.expected_authority_generation {
            return Err(ProjectionError::StaleAuthorityGeneration {
                expected: self.expected_authority_generation,
                observed: self.authority_generation,
            });
        }
        if !self.allowed_universes.contains(&universe) {
            return Err(ProjectionError::AuthorityRevoked(format!(
                "graph universe '{}' not authorized by active capability",
                universe.as_str()
            )));
        }
        Ok(())
    }
}

/// Non-collapsed absence boundary distinguishing certified completeness from redacted/gapped views.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AbsenceBoundary {
    /// Entire universe at the pinned anchor was observed without redactions or source gaps.
    CertifiedComplete {
        /// Digest of the backing `CoverageWitness`.
        coverage_witness_digest: ContentDigest,
    },
    /// Projection excluded redacted/unauthorized nodes or carries an explicit coverage gap;
    /// absence of a node/edge from this projection is NOT certified absence in the world.
    UncertifiedOrRedacted {
        /// Count of nodes filtered out before expansion due to privacy/plane clamps.
        redacted_node_count: u64,
        /// Count of incident edges suppressed because at least one endpoint was filtered.
        suppressed_edge_count: u64,
        /// Machine-readable reason (`privacy_redaction`, `coverage_gap`, `partial_projection`).
        reason: String,
    },
}

impl AbsenceBoundary {
    /// True iff this projection certifies negative absence queries.
    #[must_use]
    pub const fn certifies_absence(&self) -> bool {
        matches!(self, Self::CertifiedComplete { .. })
    }

    pub(crate) fn encode_canonical(&self, enc: &mut CanonicalEncoder) {
        match self {
            Self::CertifiedComplete {
                coverage_witness_digest,
            } => {
                enc.u8(1);
                enc.digest(*coverage_witness_digest);
            }
            Self::UncertifiedOrRedacted {
                redacted_node_count,
                suppressed_edge_count,
                reason,
            } => {
                enc.u8(2);
                enc.u64(*redacted_node_count);
                enc.u64(*suppressed_edge_count);
                enc.text(reason);
            }
        }
    }

    pub(crate) fn decode_canonical(
        dec: &mut CanonicalDecoder<'_>,
    ) -> Result<Self, ProjectionError> {
        match dec
            .u8()
            .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?
        {
            1 => Ok(Self::CertifiedComplete {
                coverage_witness_digest: dec
                    .digest()
                    .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?,
            }),
            2 => {
                let redacted_node_count = dec
                    .u64()
                    .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?;
                let suppressed_edge_count = dec
                    .u64()
                    .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?;
                let reason = dec
                    .text()
                    .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?;
                validate_label(reason, MAX_RELATION_LABEL_BYTES, "absence_reason")?;
                Ok(Self::UncertifiedOrRedacted {
                    redacted_node_count,
                    suppressed_edge_count,
                    reason: reason.to_owned(),
                })
            }
            other => Err(ProjectionError::MalformedWire(format!(
                "unknown absence boundary tag {other}"
            ))),
        }
    }
}

/// Cryptographic generation stamp shared by one [`ImmutableGraphProjection`] and all its handles.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProjectionGeneration {
    /// Typed graph universe.
    pub universe: GraphUniverse,
    /// Exact committed ledger sequence pinned by this projection.
    pub anchor_sequence: u64,
    /// Active authority generation.
    pub authority_generation: u64,
    /// Active privacy policy epoch.
    pub privacy_epoch: u64,
    /// Domain-separated SHA-256 commitment of the complete immutable projection.
    pub projection_digest: ContentDigest,
}

/// Generational handle referencing one canonical node inside an [`ImmutableGraphProjection`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NodeHandle {
    index: u32,
    generation: ProjectionGeneration,
}

impl NodeHandle {
    /// Canonical dense index within the owning projection.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.index
    }

    /// Exact generation stamp of the owning projection.
    #[must_use]
    pub const fn generation(self) -> ProjectionGeneration {
        self.generation
    }
}

/// Generational handle referencing one canonical edge inside an [`ImmutableGraphProjection`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EdgeHandle {
    index: u32,
    generation: ProjectionGeneration,
}

impl EdgeHandle {
    /// Canonical dense index within the owning projection.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.index
    }

    /// Exact generation stamp of the owning projection.
    #[must_use]
    pub const fn generation(self) -> ProjectionGeneration {
        self.generation
    }
}

/// Input specification for one node in a projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionNodeSpec {
    /// Stable external node identity (`1..=MAX_NODE_ID_LEN` non-control UTF-8 bytes).
    pub node_id: String,
    /// Owning semantic plane.
    pub plane: Plane,
    /// Object revision / payload content digest pinned at the anchor.
    pub payload_digest: ContentDigest,
}

/// Input specification for one edge in a projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionEdgeSpec {
    /// Source stable external node identity.
    pub source_id: String,
    /// Target stable external node identity.
    pub target_id: String,
    /// Typed relation label (`1..=MAX_RELATION_LABEL_BYTES`).
    pub relation: String,
    /// Deterministic exact integer weight.
    pub weight: u64,
}

/// Immutable materialized node stored inside [`ImmutableGraphProjection`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionNode {
    /// Stable external node identity.
    pub node_id: String,
    /// Owning semantic plane.
    pub plane: Plane,
    /// Content digest pinned at the projection anchor.
    pub payload_digest: ContentDigest,
}

/// Immutable materialized edge stored inside [`ImmutableGraphProjection`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionEdge {
    /// Canonical dense source node index.
    pub source_index: u32,
    /// Canonical dense target node index.
    pub target_index: u32,
    /// Typed relation label.
    pub relation: String,
    /// Exact integer weight.
    pub weight: u64,
}

/// Anchor-pinned, capability-filtered immutable graph projection with generational handles (`FSS-151`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImmutableGraphProjection {
    format_version: u32,
    universe: GraphUniverse,
    orientation: ProjectionOrientation,
    anchor: LedgerAnchor,
    history_root: ContentDigest,
    authority_generation: u64,
    privacy_epoch: u64,
    absence_boundary: AbsenceBoundary,
    nodes: Vec<ProjectionNode>,
    edges: Vec<ProjectionEdge>,
    /// CSR offsets (`len == nodes.len() + 1`) indexing into `adjacency`.
    offsets: Vec<u32>,
    /// Compressed adjacency `(neighbor_node_index, edge_index)` sorted ascending per node.
    adjacency: Vec<(u32, u32)>,
    projection_digest: ContentDigest,
}

impl ImmutableGraphProjection {
    /// Builds an immutable, capability-filtered, insertion-order-invariant graph projection.
    ///
    /// - Enforces [`ProjectionAuthorityScope`] BEFORE node/edge expansion: unauthorized universes
    ///   fail closed; unauthorized planes or redacted nodes are excluded before edge materialization
    ///   and downgrade [`AbsenceBoundary`] to [`AbsenceBoundary::UncertifiedOrRedacted`].
    /// - Refuses duplicate node IDs, self-loops (for undirected projections), unknown endpoints
    ///   (not in raw node set), parallel identical edges, or cooperative cancellation.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        universe: GraphUniverse,
        orientation: ProjectionOrientation,
        anchor: LedgerAnchor,
        history_root: ContentDigest,
        authority: &ProjectionAuthorityScope,
        raw_nodes: Vec<ProjectionNodeSpec>,
        raw_edges: Vec<ProjectionEdgeSpec>,
        requested_absence: AbsenceBoundary,
        cancelled: bool,
    ) -> Result<Self, ProjectionError> {
        if cancelled {
            return Err(ProjectionError::Cancelled);
        }
        authority.validate_for(universe)?;
        if raw_nodes.len() > MAX_PROJECTION_NODES {
            return Err(ProjectionError::BoundsExceeded {
                observed: raw_nodes.len(),
                maximum: MAX_PROJECTION_NODES,
            });
        }
        if raw_edges.len() > MAX_PROJECTION_EDGES {
            return Err(ProjectionError::BoundsExceeded {
                observed: raw_edges.len(),
                maximum: MAX_PROJECTION_EDGES,
            });
        }
        validate_label(&anchor.site_lineage, MAX_NODE_ID_LEN, "site_lineage")?;
        if let AbsenceBoundary::UncertifiedOrRedacted { ref reason, .. } = requested_absence {
            validate_label(reason, MAX_RELATION_LABEL_BYTES, "absence_reason")?;
        }

        // Canonicalize & validate raw node IDs first, then apply capability/privacy projection BEFORE expansion.
        let mut sorted_raw = raw_nodes;
        sorted_raw.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        for node in &sorted_raw {
            validate_label(&node.node_id, MAX_NODE_ID_LEN, "node_id")?;
        }
        for pair in sorted_raw.windows(2) {
            if pair[0].node_id == pair[1].node_id {
                return Err(ProjectionError::InvalidInput(format!(
                    "duplicate node_id '{}'",
                    pair[0].node_id
                )));
            }
        }

        let all_known_ids: BTreeSet<String> =
            sorted_raw.iter().map(|n| n.node_id.clone()).collect();
        let mut nodes: Vec<ProjectionNode> = Vec::with_capacity(sorted_raw.len());
        let mut redacted_node_count = 0_u64;
        for node in sorted_raw {
            let permitted = authority.allowed_planes.contains(&node.plane)
                && !authority.redacted_node_ids.contains(&node.node_id);
            if permitted {
                nodes.push(ProjectionNode {
                    node_id: node.node_id,
                    plane: node.plane,
                    payload_digest: node.payload_digest,
                });
            } else {
                redacted_node_count = redacted_node_count.saturating_add(1);
            }
        }

        let lookup_visible = |id: &str| -> Option<u32> {
            nodes
                .binary_search_by(|n| n.node_id.as_str().cmp(id))
                .ok()
                .and_then(|idx| u32::try_from(idx).ok())
        };

        let mut edges: Vec<ProjectionEdge> = Vec::with_capacity(raw_edges.len());
        let mut suppressed_edge_count = 0_u64;
        for edge in raw_edges {
            validate_label(&edge.relation, MAX_RELATION_LABEL_BYTES, "relation")?;
            if !all_known_ids.contains(&edge.source_id) {
                return Err(ProjectionError::InvalidInput(format!(
                    "unknown edge source_id '{}'",
                    edge.source_id
                )));
            }
            if !all_known_ids.contains(&edge.target_id) {
                return Err(ProjectionError::InvalidInput(format!(
                    "unknown edge target_id '{}'",
                    edge.target_id
                )));
            }
            let (Some(src), Some(dst)) = (
                lookup_visible(&edge.source_id),
                lookup_visible(&edge.target_id),
            ) else {
                // At least one endpoint was filtered by capability/privacy projection BEFORE expansion!
                suppressed_edge_count = suppressed_edge_count.saturating_add(1);
                continue;
            };
            if orientation == ProjectionOrientation::Undirected && src == dst {
                return Err(ProjectionError::InvalidInput(format!(
                    "self-loop prohibited on undirected projection at '{}'",
                    edge.source_id
                )));
            }
            let (source_index, target_index) = match orientation {
                ProjectionOrientation::Undirected => (src.min(dst), src.max(dst)),
                ProjectionOrientation::Directed => (src, dst),
            };
            edges.push(ProjectionEdge {
                source_index,
                target_index,
                relation: edge.relation,
                weight: edge.weight,
            });
        }

        edges.sort_by(|a, b| {
            (
                a.source_index,
                a.target_index,
                a.relation.as_str(),
                a.weight,
            )
                .cmp(&(
                    b.source_index,
                    b.target_index,
                    b.relation.as_str(),
                    b.weight,
                ))
        });
        for pair in edges.windows(2) {
            if pair[0].source_index == pair[1].source_index
                && pair[0].target_index == pair[1].target_index
                && pair[0].relation == pair[1].relation
            {
                return Err(ProjectionError::InvalidInput(format!(
                    "duplicate edge ({}, {}, '{}')",
                    pair[0].source_index, pair[0].target_index, pair[0].relation
                )));
            }
        }

        // Downgrade absence boundary whenever capability/privacy filtering omitted any node/edge!
        let absence_boundary = if redacted_node_count > 0 || suppressed_edge_count > 0 {
            let (prior_redacted, prior_suppressed, reason) = match requested_absence {
                AbsenceBoundary::CertifiedComplete { .. } => (0, 0, "privacy_or_plane_redaction"),
                AbsenceBoundary::UncertifiedOrRedacted {
                    redacted_node_count: r,
                    suppressed_edge_count: s,
                    ..
                } => (r, s, "privacy_redaction_and_coverage_gap"),
            };
            AbsenceBoundary::UncertifiedOrRedacted {
                redacted_node_count: prior_redacted.saturating_add(redacted_node_count),
                suppressed_edge_count: prior_suppressed.saturating_add(suppressed_edge_count),
                reason: reason.to_owned(),
            }
        } else {
            if let AbsenceBoundary::UncertifiedOrRedacted { ref reason, .. } = requested_absence {
                validate_label(reason, MAX_RELATION_LABEL_BYTES, "absence_reason")?;
            }
            requested_absence
        };

        let (offsets, adjacency) = build_csr(nodes.len(), &edges, orientation)?;
        let mut projection = Self {
            format_version: PROJECTION_WIRE_VERSION,
            universe,
            orientation,
            anchor,
            history_root,
            authority_generation: authority.authority_generation,
            privacy_epoch: authority.privacy_epoch,
            absence_boundary,
            nodes,
            edges,
            offsets,
            adjacency,
            projection_digest: ContentDigest::sha256(b"unsealed-graph-projection"),
        };
        projection.projection_digest = projection.compute_digest()?;
        Ok(projection)
    }

    /// Typed graph universe of this projection.
    #[must_use]
    pub const fn universe(&self) -> GraphUniverse {
        self.universe
    }

    /// Orientation contract of this projection.
    #[must_use]
    pub const fn orientation(&self) -> ProjectionOrientation {
        self.orientation
    }

    /// Exact pinned ledger anchor.
    #[must_use]
    pub const fn anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }

    /// Exact pinned history-chain root.
    #[must_use]
    pub const fn history_root(&self) -> ContentDigest {
        self.history_root
    }

    /// Non-collapsed absence boundary.
    #[must_use]
    pub const fn absence_boundary(&self) -> &AbsenceBoundary {
        &self.absence_boundary
    }

    /// Cryptographic generation stamp bound to every handle issued by this projection.
    #[must_use]
    pub const fn generation(&self) -> ProjectionGeneration {
        ProjectionGeneration {
            universe: self.universe,
            anchor_sequence: self.anchor.commit_sequence,
            authority_generation: self.authority_generation,
            privacy_epoch: self.privacy_epoch,
            projection_digest: self.projection_digest,
        }
    }

    /// Number of visible canonical nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of visible canonical edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Looks up a generational [`NodeHandle`] by stable external `node_id`.
    #[must_use]
    pub fn handle_for_node_id(&self, node_id: &str) -> Option<NodeHandle> {
        let idx = self
            .nodes
            .binary_search_by(|n| n.node_id.as_str().cmp(node_id))
            .ok()?;
        let index = u32::try_from(idx).ok()?;
        Some(NodeHandle {
            index,
            generation: self.generation(),
        })
    }

    /// Returns all canonical [`NodeHandle`]s in ascending stable-identity order.
    #[must_use]
    pub fn node_handles(&self) -> Vec<NodeHandle> {
        let gen_stamp = self.generation();
        (0..self.nodes.len())
            .filter_map(|idx| u32::try_from(idx).ok())
            .map(|index| NodeHandle {
                index,
                generation: gen_stamp,
            })
            .collect()
    }

    /// Returns all canonical [`EdgeHandle`]s in ascending canonical edge order.
    #[must_use]
    pub fn edge_handles(&self) -> Vec<EdgeHandle> {
        let gen_stamp = self.generation();
        (0..self.edges.len())
            .filter_map(|idx| u32::try_from(idx).ok())
            .map(|index| EdgeHandle {
                index,
                generation: gen_stamp,
            })
            .collect()
    }

    /// Dereferences `handle`, failing closed on any generation mismatch or out-of-range index.
    pub fn node(&self, handle: NodeHandle) -> Result<&ProjectionNode, ProjectionError> {
        self.check_generation(handle.generation)?;
        self.nodes
            .get(handle.index as usize)
            .ok_or(ProjectionError::HandleOutOfRange {
                index: handle.index,
                len: self.nodes.len(),
            })
    }

    /// Dereferences `handle`, failing closed on any generation mismatch or out-of-range index.
    pub fn edge(&self, handle: EdgeHandle) -> Result<&ProjectionEdge, ProjectionError> {
        self.check_generation(handle.generation)?;
        self.edges
            .get(handle.index as usize)
            .ok_or(ProjectionError::HandleOutOfRange {
                index: handle.index,
                len: self.edges.len(),
            })
    }

    /// Expands canonical `(neighbor_handle, edge_handle)` pairs for `handle`, failing closed on
    /// stale/cross-projection handles.
    pub fn neighbors(
        &self,
        handle: NodeHandle,
    ) -> Result<Vec<(NodeHandle, EdgeHandle)>, ProjectionError> {
        self.check_generation(handle.generation)?;
        let idx = handle.index as usize;
        if idx >= self.nodes.len() {
            return Err(ProjectionError::HandleOutOfRange {
                index: handle.index,
                len: self.nodes.len(),
            });
        }
        let gen_stamp = self.generation();
        let start = self.offsets[idx] as usize;
        let end = self.offsets[idx + 1] as usize;
        Ok(self.adjacency[start..end]
            .iter()
            .map(|&(nbr, edge)| {
                (
                    NodeHandle {
                        index: nbr,
                        generation: gen_stamp,
                    },
                    EdgeHandle {
                        index: edge,
                        generation: gen_stamp,
                    },
                )
            })
            .collect())
    }

    /// Projects an undirected projection directly into [`UndirectedGraph`] for certified
    /// `fss-graph-algorithms` execution (`bridges`, `flow`, `paths`, etc.).
    pub fn to_undirected_simple_graph(&self) -> Result<UndirectedGraph, GraphError> {
        if self.orientation != ProjectionOrientation::Undirected {
            return Err(GraphError::PreconditionFailed(
                "cannot project a directed ImmutableGraphProjection into UndirectedGraph"
                    .to_owned(),
            ));
        }
        let mut builder = GraphBuilder::new();
        for node in &self.nodes {
            builder.add_node(node.node_id.clone());
        }
        let mut seen_pairs = BTreeSet::new();
        for edge in &self.edges {
            let pair = (edge.source_index, edge.target_index);
            if seen_pairs.insert(pair) {
                builder.add_edge(
                    self.nodes[edge.source_index as usize].node_id.clone(),
                    self.nodes[edge.target_index as usize].node_id.clone(),
                );
            }
        }
        builder.build()
    }

    fn check_generation(&self, supplied: ProjectionGeneration) -> Result<(), ProjectionError> {
        if supplied != self.generation() {
            return Err(ProjectionError::StaleHandleGeneration {
                handle_digest: supplied.projection_digest,
                projection_digest: self.projection_digest,
            });
        }
        Ok(())
    }

    /// Recomputes the domain-separated SHA-256 commitment digest (`fss.graph.immutable_projection.v1`).
    pub fn compute_digest(&self) -> Result<ContentDigest, ProjectionError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(IMMUTABLE_PROJECTION_DOMAIN);
        self.encode_body(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|e| ProjectionError::Encoding(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.format_version);
        enc.u8(self.universe.tag());
        enc.u8(self.orientation.tag());
        self.anchor.encode_canonical(enc);
        enc.digest(self.history_root);
        enc.u64(self.authority_generation);
        enc.u64(self.privacy_epoch);
        self.absence_boundary.encode_canonical(enc);
        enc.u64(self.nodes.len() as u64);
        for node in &self.nodes {
            enc.text(&node.node_id);
            node.plane.encode_canonical(enc);
            enc.digest(node.payload_digest);
        }
        enc.u64(self.edges.len() as u64);
        for edge in &self.edges {
            enc.u32(edge.source_index);
            enc.u32(edge.target_index);
            enc.text(&edge.relation);
            enc.u64(edge.weight);
        }
    }

    /// Encodes this immutable projection into bounded, checksummed binary bytes (`FSSGPR01` v1).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ProjectionError> {
        if self.format_version != PROJECTION_WIRE_VERSION {
            return Err(ProjectionError::UnsupportedVersion {
                version: self.format_version,
            });
        }
        if self.compute_digest()? != self.projection_digest {
            return Err(ProjectionError::ChecksumMismatch);
        }
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        enc.digest(self.projection_digest);
        let body = enc
            .finish_checked()
            .map_err(|e| ProjectionError::Encoding(e.to_string()))?;
        let total = PROJECTION_WIRE_MAGIC
            .len()
            .saturating_add(4)
            .saturating_add(body.len());
        if total > MAX_PROJECTION_WIRE_BYTES {
            return Err(ProjectionError::BoundsExceeded {
                observed: total,
                maximum: MAX_PROJECTION_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&PROJECTION_WIRE_MAGIC);
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Cold-decodes and verifies a binary [`ImmutableGraphProjection`], rebuilding CSR adjacency
    /// deterministically and failing closed on any corruption, non-canonical ordering, or bound breach.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProjectionError> {
        if bytes.len() > MAX_PROJECTION_WIRE_BYTES {
            return Err(ProjectionError::BoundsExceeded {
                observed: bytes.len(),
                maximum: MAX_PROJECTION_WIRE_BYTES,
            });
        }
        if bytes.len() < 12 || bytes[..8] != PROJECTION_WIRE_MAGIC {
            return Err(ProjectionError::InvalidMagic);
        }
        let header_version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if header_version != PROJECTION_WIRE_VERSION {
            return Err(ProjectionError::UnsupportedVersion {
                version: header_version,
            });
        }
        let mut dec = CanonicalDecoder::new(&bytes[12..]);
        let format_version = dec
            .u32()
            .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?;
        if format_version != header_version {
            return Err(ProjectionError::UnsupportedVersion {
                version: format_version,
            });
        }
        let universe = GraphUniverse::from_tag(
            dec.u8()
                .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?,
        )
        .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?;
        let orientation = ProjectionOrientation::from_tag(
            dec.u8()
                .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?,
        )
        .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?;
        let anchor = LedgerAnchor::decode_canonical(&mut dec)
            .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?;
        validate_label(&anchor.site_lineage, MAX_NODE_ID_LEN, "site_lineage")
            .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?;
        let history_root = dec
            .digest()
            .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?;
        let authority_generation = dec
            .u64()
            .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?;
        let privacy_epoch = dec
            .u64()
            .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?;
        let absence_boundary = AbsenceBoundary::decode_canonical(&mut dec)?;

        let node_count = usize::try_from(
            dec.u64()
                .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?,
        )
        .map_err(|_| ProjectionError::BoundsExceeded {
            observed: usize::MAX,
            maximum: MAX_PROJECTION_NODES,
        })?;
        // Each encoded node takes at least 4(id) + 1 + 4(plane) + 1 + 33(digest) = 43 bytes.
        if node_count > MAX_PROJECTION_NODES || node_count.saturating_mul(43) > dec.remaining() {
            return Err(ProjectionError::BoundsExceeded {
                observed: node_count,
                maximum: MAX_PROJECTION_NODES,
            });
        }
        let mut nodes = Vec::with_capacity(node_count);
        for _ in 0..node_count {
            let node_id = dec
                .text()
                .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?;
            validate_label(node_id, MAX_NODE_ID_LEN, "node_id")?;
            let plane = decode_plane(&mut dec)?;
            let payload_digest = dec
                .digest()
                .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?;
            if nodes
                .last()
                .is_some_and(|prev: &ProjectionNode| node_id <= prev.node_id.as_str())
            {
                return Err(ProjectionError::MalformedWire(
                    "projection nodes must be strictly canonically ordered and unique".to_owned(),
                ));
            }
            nodes.push(ProjectionNode {
                node_id: node_id.to_owned(),
                plane,
                payload_digest,
            });
        }

        let edge_count = usize::try_from(
            dec.u64()
                .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?,
        )
        .map_err(|_| ProjectionError::BoundsExceeded {
            observed: usize::MAX,
            maximum: MAX_PROJECTION_EDGES,
        })?;
        // Each encoded edge takes at least 4(src) + 4(dst) + 5(rel) + 8(weight) = 21 bytes.
        if edge_count > MAX_PROJECTION_EDGES || edge_count.saturating_mul(21) > dec.remaining() {
            return Err(ProjectionError::BoundsExceeded {
                observed: edge_count,
                maximum: MAX_PROJECTION_EDGES,
            });
        }
        let mut edges: Vec<ProjectionEdge> = Vec::with_capacity(edge_count);
        for _ in 0..edge_count {
            let source_index = dec
                .u32()
                .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?;
            let target_index = dec
                .u32()
                .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?;
            let relation = dec
                .text()
                .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?;
            validate_label(relation, MAX_RELATION_LABEL_BYTES, "relation")?;
            let weight = dec
                .u64()
                .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?;
            if (source_index as usize) >= nodes.len() || (target_index as usize) >= nodes.len() {
                return Err(ProjectionError::MalformedWire(
                    "edge endpoint index out of bounds".to_owned(),
                ));
            }
            if orientation == ProjectionOrientation::Undirected && source_index >= target_index {
                return Err(ProjectionError::MalformedWire(
                    "undirected edge endpoints must satisfy source_index < target_index".to_owned(),
                ));
            }
            if let Some(prev) = edges.last() {
                let prev_key = (prev.source_index, prev.target_index, prev.relation.as_str());
                let cur_key = (source_index, target_index, relation);
                if cur_key <= prev_key {
                    return Err(ProjectionError::MalformedWire(
                        "projection edges must be strictly canonically ordered and unique"
                            .to_owned(),
                    ));
                }
            }
            edges.push(ProjectionEdge {
                source_index,
                target_index,
                relation: relation.to_owned(),
                weight,
            });
        }

        let stored_digest = dec
            .digest()
            .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?;
        dec.ensure_finished().map_err(|_| {
            ProjectionError::MalformedWire("trailing bytes after graph projection".to_owned())
        })?;

        let (offsets, adjacency) = build_csr(nodes.len(), &edges, orientation)?;
        let projection = Self {
            format_version,
            universe,
            orientation,
            anchor,
            history_root,
            authority_generation,
            privacy_epoch,
            absence_boundary,
            nodes,
            edges,
            offsets,
            adjacency,
            projection_digest: stored_digest,
        };
        if projection.compute_digest()? != stored_digest {
            return Err(ProjectionError::ChecksumMismatch);
        }
        Ok(projection)
    }
}

type CsrAdjacency = (Vec<u32>, Vec<(u32, u32)>);

fn build_csr(
    node_count: usize,
    edges: &[ProjectionEdge],
    orientation: ProjectionOrientation,
) -> Result<CsrAdjacency, ProjectionError> {
    let mut degree = vec![0_u32; node_count + 1];
    for edge in edges {
        degree[edge.source_index as usize + 1] = degree[edge.source_index as usize + 1]
            .checked_add(1)
            .ok_or(ProjectionError::BoundsExceeded {
                observed: usize::MAX,
                maximum: MAX_PROJECTION_EDGES,
            })?;
        if orientation == ProjectionOrientation::Undirected {
            degree[edge.target_index as usize + 1] = degree[edge.target_index as usize + 1]
                .checked_add(1)
                .ok_or(ProjectionError::BoundsExceeded {
                    observed: usize::MAX,
                    maximum: MAX_PROJECTION_EDGES,
                })?;
        }
    }
    let mut running = 0_u32;
    for slot in &mut degree {
        running = running
            .checked_add(*slot)
            .ok_or(ProjectionError::BoundsExceeded {
                observed: usize::MAX,
                maximum: MAX_PROJECTION_EDGES,
            })?;
        *slot = running;
    }
    let offsets = degree;
    let mut fill = offsets[..node_count].to_vec();
    let total_adj = running as usize;
    let mut adjacency = vec![(0_u32, 0_u32); total_adj];
    for (edge_idx, edge) in edges.iter().enumerate() {
        let edge_u32 = u32::try_from(edge_idx).map_err(|_| ProjectionError::BoundsExceeded {
            observed: edge_idx,
            maximum: MAX_PROJECTION_EDGES,
        })?;
        let s = edge.source_index as usize;
        adjacency[fill[s] as usize] = (edge.target_index, edge_u32);
        fill[s] += 1;
        if orientation == ProjectionOrientation::Undirected {
            let t = edge.target_index as usize;
            adjacency[fill[t] as usize] = (edge.source_index, edge_u32);
            fill[t] += 1;
        }
    }
    for window in offsets.windows(2) {
        adjacency[window[0] as usize..window[1] as usize].sort_unstable();
    }
    Ok((offsets, adjacency))
}

fn decode_plane(dec: &mut CanonicalDecoder<'_>) -> Result<Plane, ProjectionError> {
    match dec
        .text()
        .map_err(|e| ProjectionError::MalformedWire(e.to_string()))?
    {
        "authority" => Ok(Plane::Authority),
        "cognition" => Ok(Plane::Cognition),
        "effect" => Ok(Plane::Effect),
        other => Err(ProjectionError::MalformedWire(format!(
            "unknown plane '{other}'"
        ))),
    }
}

fn validate_label(value: &str, max_len: usize, label: &str) -> Result<(), ProjectionError> {
    if value.is_empty() || value.len() > max_len {
        return Err(ProjectionError::InvalidInput(format!(
            "{label} length {} outside 1..={max_len}",
            value.len()
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(ProjectionError::InvalidInput(format!(
            "{label} must not contain control characters"
        )));
    }
    Ok(())
}

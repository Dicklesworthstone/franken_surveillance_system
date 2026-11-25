#![forbid(unsafe_code)]
//! Canonical graph serialization and cryptographic hash verification (`FSS-153`, `fss-x4a.23.3`).
//!
//! Delivers deterministic, insertion-order-invariant, bounded binary serialization and structural
//! Merkle hash verification across BOTH canonical FSS graph representations:
//!
//! 1. [`UndirectedGraph`] (`crate::graph`) — previously lacked a binary wire codec; now serializes
//!    and cold-decodes canonically inside [`CanonicalGraphEnvelope`] (`FSSGCH01` v1) with exact
//!    strict-order, simple-graph, and allocation-bomb enforcement.
//! 2. [`ImmutableGraphProjection`] (`crate::projection`, `FSS-151`) — wraps its canonical
//!    `FSSGPR01` representation with independent structural node/edge Merkle roots and projection
//!    cross-verification, seamlessly compatible with `FSS-152` `ArcSnapshotViewStore`.
//!
//! Every [`CanonicalGraphEnvelope`] commits to:
//! - `graph_digest`: the underlying canonical graph/projection digest;
//! - `nodes_merkle_root`: domain-separated balanced binary SHA-256 Merkle root over ordered nodes;
//! - `edges_merkle_root`: domain-separated balanced binary SHA-256 Merkle root over ordered edges;
//! - `envelope_digest`: domain-separated SHA-256 commitment (`fss.graph.canonical_envelope.v1`).
//!
//! Verification localizes tampering cleanly (envelope checksum vs graph digest vs nodes Merkle
//! root vs edges Merkle root) and proves permutation invariance without ever granting write or
//! effect authority.

use std::error::Error;
use std::fmt;

use fss_core::{CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest, ContractError};

use crate::graph::{
    GraphBuilder, MAX_GRAPH_EDGES, MAX_GRAPH_NODES, MAX_NODE_ID_LEN, UndirectedGraph,
};
use crate::projection::{ImmutableGraphProjection, MAX_PROJECTION_WIRE_BYTES};

/// Registered digest domain for [`CanonicalGraphEnvelope`] commitments (`FSS-153`).
pub const GRAPH_CANONICAL_ENVELOPE_DOMAIN: &str = "fss.graph.canonical_envelope.v1";
/// Registered digest domain for structural graph Merkle node/edge commitments (`FSS-153`).
pub const GRAPH_MERKLE_STRUCTURE_DOMAIN: &str = "fss.graph.merkle_structure.v1";
/// Binary wire header magic for canonical serialized graph envelopes.
pub const CANONICAL_GRAPH_MAGIC: [u8; 8] = *b"FSSGCH01";
/// Supported durable format version for [`CanonicalGraphEnvelope`].
pub const CANONICAL_GRAPH_VERSION: u32 = 1;
/// Hard ceiling on serialized canonical graph envelope wire bytes (8 MiB + header headroom).
pub const MAX_CANONICAL_GRAPH_WIRE_BYTES: usize = MAX_PROJECTION_WIRE_BYTES + 64 * 1024;

/// Graph payload family carried inside one [`CanonicalGraphEnvelope`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GraphPayloadKind {
    /// Canonical undirected simple graph ([`UndirectedGraph`]).
    UndirectedSimple = 1,
    /// Anchor-pinned typed immutable graph projection ([`ImmutableGraphProjection`], `FSS-151`).
    ImmutableProjection = 2,
}

impl GraphPayloadKind {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UndirectedSimple => "undirected_simple",
            Self::ImmutableProjection => "immutable_projection",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::UndirectedSimple),
            2 => Ok(Self::ImmutableProjection),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Typed tamper-localization classification when verifying canonical graph commitments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashMismatchComponent {
    /// Envelope self-checksum disagreed with recomputed commitment.
    EnvelopeChecksum,
    /// Underlying graph/projection digest disagreed with declared `graph_digest`.
    GraphDigest,
    /// Recomputed nodes Merkle root disagreed with declared `nodes_merkle_root`.
    NodesMerkleRoot,
    /// Recomputed edges Merkle root disagreed with declared `edges_merkle_root`.
    EdgesMerkleRoot,
    /// Declared node/edge counts disagreed with decoded graph structure.
    StructureCounts,
    /// Caller's pinned expected digest disagreed with verified envelope/graph digest.
    ExpectedPinMismatch,
}

/// Safe operator/agent recovery guidance for a refused canonical graph codec operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalGraphGuidance {
    /// Reconstruct the graph projection from the pinned canonical ledger anchor.
    RebuildFromCanonicalLedger,
    /// Cooperative cancellation observed; safe to retry cleanly.
    RetryWhenReady,
    /// Quarantine corrupt or unsupported binary graph artifact bytes.
    QuarantineCorruptArtifact,
}

/// Typed error returned by canonical graph serialization or hash verification (`FSS-153`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalGraphError {
    /// Cooperative cancellation observed before completing encoding or verification.
    Cancelled,
    /// Graph or wire length exceeded hard ceilings.
    BoundsExceeded {
        /// Observed size/count.
        observed: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Wire envelope lacked [`CANONICAL_GRAPH_MAGIC`].
    InvalidMagic,
    /// Wire envelope declared an unsupported format version.
    UnsupportedVersion {
        /// Observed version.
        version: u32,
    },
    /// Wire envelope or embedded graph payload was truncated, unsorted, or structurally invalid.
    MalformedWire(String),
    /// Cryptographic digest verification failed on a specific localized component.
    HashMismatch {
        /// Exact component that failed hash verification.
        component: HashMismatchComponent,
    },
    /// Canonical encoding failure.
    Encoding(String),
}

impl CanonicalGraphError {
    /// Stable canonical machine error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Cancelled => "ERR-GRAPH-CODEC-CANCELLED-001",
            Self::BoundsExceeded { .. } => "ERR-GRAPH-CODEC-BOUNDS-001",
            Self::InvalidMagic => "ERR-GRAPH-CODEC-INVALID-MAGIC-001",
            Self::UnsupportedVersion { .. } => "ERR-GRAPH-CODEC-UNSUPPORTED-VERSION-001",
            Self::MalformedWire(_) => "ERR-GRAPH-CODEC-MALFORMED-WIRE-001",
            Self::HashMismatch { .. } => "ERR-GRAPH-CODEC-HASH-MISMATCH-001",
            Self::Encoding(_) => "ERR-GRAPH-CODEC-ENCODING-001",
        }
    }

    /// Safe recovery guidance.
    #[must_use]
    pub const fn guidance(&self) -> CanonicalGraphGuidance {
        match self {
            Self::Cancelled => CanonicalGraphGuidance::RetryWhenReady,
            Self::BoundsExceeded { .. } | Self::Encoding(_) => {
                CanonicalGraphGuidance::RebuildFromCanonicalLedger
            }
            Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::MalformedWire(_)
            | Self::HashMismatch { .. } => CanonicalGraphGuidance::QuarantineCorruptArtifact,
        }
    }
}

impl fmt::Display for CanonicalGraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}

impl Error for CanonicalGraphError {}

/// Structural cryptographic commitments for one canonical graph artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GraphStructuralHashes {
    /// Canonical node count.
    pub node_count: u32,
    /// Canonical edge count.
    pub edge_count: u32,
    /// Underlying graph/projection canonical digest.
    pub graph_digest: ContentDigest,
    /// Balanced binary SHA-256 Merkle root over canonically ordered nodes (`fss.graph.merkle_structure.v1`).
    pub nodes_merkle_root: ContentDigest,
    /// Balanced binary SHA-256 Merkle root over canonically ordered edges (`fss.graph.merkle_structure.v1`).
    pub edges_merkle_root: ContentDigest,
}

/// Decoded canonical graph payload carried by [`CanonicalGraphEnvelope`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalGraphPayload {
    /// Canonical undirected simple graph.
    UndirectedSimple(Box<UndirectedGraph>),
    /// Anchor-pinned typed immutable graph projection (`FSS-151`).
    ImmutableProjection(Box<ImmutableGraphProjection>),
}

/// Sealed, bounded, hash-verified canonical graph serialization envelope (`FSSGCH01` v1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalGraphEnvelope {
    /// Wire format version (`CANONICAL_GRAPH_VERSION`).
    pub format_version: u32,
    /// Payload family tag.
    pub payload_kind: GraphPayloadKind,
    /// Structural counts and Merkle commitments.
    pub hashes: GraphStructuralHashes,
    /// Canonical serialized inner graph bytes.
    pub payload_bytes: Vec<u8>,
    /// Domain-separated SHA-256 envelope commitment (`fss.graph.canonical_envelope.v1`).
    pub envelope_digest: ContentDigest,
}

impl CanonicalGraphEnvelope {
    /// Seals a canonical [`UndirectedGraph`] into a verifiable [`CanonicalGraphEnvelope`].
    pub fn from_undirected(
        graph: &UndirectedGraph,
        cancelled: bool,
    ) -> Result<Self, CanonicalGraphError> {
        if cancelled {
            return Err(CanonicalGraphError::Cancelled);
        }
        let payload_bytes = encode_undirected_canonical(graph)?;
        let hashes = compute_undirected_hashes(graph)?;
        Self::seal(GraphPayloadKind::UndirectedSimple, hashes, payload_bytes)
    }

    /// Seals an [`ImmutableGraphProjection`] (`FSS-151`) into a verifiable [`CanonicalGraphEnvelope`].
    pub fn from_projection(
        projection: &ImmutableGraphProjection,
        cancelled: bool,
    ) -> Result<Self, CanonicalGraphError> {
        if cancelled {
            return Err(CanonicalGraphError::Cancelled);
        }
        let payload_bytes = projection
            .to_canonical_bytes()
            .map_err(|e| CanonicalGraphError::Encoding(e.to_string()))?;
        let hashes = compute_projection_hashes(projection)?;
        Self::seal(GraphPayloadKind::ImmutableProjection, hashes, payload_bytes)
    }

    fn seal(
        payload_kind: GraphPayloadKind,
        hashes: GraphStructuralHashes,
        payload_bytes: Vec<u8>,
    ) -> Result<Self, CanonicalGraphError> {
        if payload_bytes.len() > MAX_PROJECTION_WIRE_BYTES {
            return Err(CanonicalGraphError::BoundsExceeded {
                observed: payload_bytes.len(),
                maximum: MAX_PROJECTION_WIRE_BYTES,
            });
        }
        let mut env = Self {
            format_version: CANONICAL_GRAPH_VERSION,
            payload_kind,
            hashes,
            payload_bytes,
            envelope_digest: ContentDigest::sha256(b"unsealed-canonical-graph-envelope"),
        };
        env.envelope_digest = env.compute_envelope_digest()?;
        Ok(env)
    }

    /// Recomputes the domain-separated SHA-256 commitment (`fss.graph.canonical_envelope.v1`).
    pub fn compute_envelope_digest(&self) -> Result<ContentDigest, CanonicalGraphError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(GRAPH_CANONICAL_ENVELOPE_DOMAIN);
        self.encode_body(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|e| CanonicalGraphError::Encoding(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    /// Decodes the embedded graph payload and performs complete localized cryptographic hash
    /// verification across envelope checksum, graph digest, nodes Merkle root, and edges Merkle root.
    pub fn verify_and_decode(
        &self,
        expected_graph_digest: Option<ContentDigest>,
        expected_envelope_digest: Option<ContentDigest>,
        cancelled: bool,
    ) -> Result<CanonicalGraphPayload, CanonicalGraphError> {
        if cancelled {
            return Err(CanonicalGraphError::Cancelled);
        }
        if self.format_version != CANONICAL_GRAPH_VERSION {
            return Err(CanonicalGraphError::UnsupportedVersion {
                version: self.format_version,
            });
        }
        if self.payload_bytes.len() > MAX_PROJECTION_WIRE_BYTES {
            return Err(CanonicalGraphError::BoundsExceeded {
                observed: self.payload_bytes.len(),
                maximum: MAX_PROJECTION_WIRE_BYTES,
            });
        }
        if self.compute_envelope_digest()? != self.envelope_digest {
            return Err(CanonicalGraphError::HashMismatch {
                component: HashMismatchComponent::EnvelopeChecksum,
            });
        }
        if let Some(exp_env) = expected_envelope_digest
            && self.envelope_digest != exp_env
        {
            return Err(CanonicalGraphError::HashMismatch {
                component: HashMismatchComponent::ExpectedPinMismatch,
            });
        }

        let (payload, recomputed) = match self.payload_kind {
            GraphPayloadKind::UndirectedSimple => {
                let g = decode_undirected_canonical(&self.payload_bytes)?;
                let h = compute_undirected_hashes(&g)?;
                (CanonicalGraphPayload::UndirectedSimple(Box::new(g)), h)
            }
            GraphPayloadKind::ImmutableProjection => {
                let p = ImmutableGraphProjection::from_canonical_bytes(&self.payload_bytes)
                    .map_err(|e| CanonicalGraphError::MalformedWire(e.to_string()))?;
                let h = compute_projection_hashes(&p)?;
                (CanonicalGraphPayload::ImmutableProjection(Box::new(p)), h)
            }
        };

        if recomputed.node_count != self.hashes.node_count
            || recomputed.edge_count != self.hashes.edge_count
        {
            return Err(CanonicalGraphError::HashMismatch {
                component: HashMismatchComponent::StructureCounts,
            });
        }
        if recomputed.graph_digest != self.hashes.graph_digest {
            return Err(CanonicalGraphError::HashMismatch {
                component: HashMismatchComponent::GraphDigest,
            });
        }
        if recomputed.nodes_merkle_root != self.hashes.nodes_merkle_root {
            return Err(CanonicalGraphError::HashMismatch {
                component: HashMismatchComponent::NodesMerkleRoot,
            });
        }
        if recomputed.edges_merkle_root != self.hashes.edges_merkle_root {
            return Err(CanonicalGraphError::HashMismatch {
                component: HashMismatchComponent::EdgesMerkleRoot,
            });
        }
        if let Some(exp_graph) = expected_graph_digest
            && recomputed.graph_digest != exp_graph
        {
            return Err(CanonicalGraphError::HashMismatch {
                component: HashMismatchComponent::ExpectedPinMismatch,
            });
        }

        Ok(payload)
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.format_version);
        enc.u8(self.payload_kind.tag());
        enc.u32(self.hashes.node_count);
        enc.u32(self.hashes.edge_count);
        enc.digest(self.hashes.graph_digest);
        enc.digest(self.hashes.nodes_merkle_root);
        enc.digest(self.hashes.edges_merkle_root);
        enc.bytes(&self.payload_bytes);
    }

    /// Encodes this verified envelope into bounded checksummed binary bytes (`FSSGCH01` v1).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, CanonicalGraphError> {
        let _ = self.verify_and_decode(None, None, false)?;
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        enc.digest(self.envelope_digest);
        let body = enc
            .finish_checked()
            .map_err(|e| CanonicalGraphError::Encoding(e.to_string()))?;
        let total = CANONICAL_GRAPH_MAGIC
            .len()
            .saturating_add(4)
            .saturating_add(body.len());
        if total > MAX_CANONICAL_GRAPH_WIRE_BYTES {
            return Err(CanonicalGraphError::BoundsExceeded {
                observed: total,
                maximum: MAX_CANONICAL_GRAPH_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&CANONICAL_GRAPH_MAGIC);
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Cold-decodes and completely hash-verifies binary [`CanonicalGraphEnvelope`] bytes (`FSSGCH01` v1).
    pub fn from_canonical_bytes(
        bytes: &[u8],
        expected_graph_digest: Option<ContentDigest>,
        expected_envelope_digest: Option<ContentDigest>,
        cancelled: bool,
    ) -> Result<(Self, CanonicalGraphPayload), CanonicalGraphError> {
        if cancelled {
            return Err(CanonicalGraphError::Cancelled);
        }
        if bytes.len() > MAX_CANONICAL_GRAPH_WIRE_BYTES {
            return Err(CanonicalGraphError::BoundsExceeded {
                observed: bytes.len(),
                maximum: MAX_CANONICAL_GRAPH_WIRE_BYTES,
            });
        }
        if bytes.len() < 12 || bytes[..8] != CANONICAL_GRAPH_MAGIC {
            return Err(CanonicalGraphError::InvalidMagic);
        }
        let header_ver = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if header_ver != CANONICAL_GRAPH_VERSION {
            return Err(CanonicalGraphError::UnsupportedVersion {
                version: header_ver,
            });
        }
        let mut dec = CanonicalDecoder::new(&bytes[12..]);
        let format_version = dec
            .u32()
            .map_err(|e| CanonicalGraphError::MalformedWire(e.to_string()))?;
        if format_version != header_ver {
            return Err(CanonicalGraphError::UnsupportedVersion {
                version: format_version,
            });
        }
        let payload_kind = GraphPayloadKind::from_tag(
            dec.u8()
                .map_err(|e| CanonicalGraphError::MalformedWire(e.to_string()))?,
        )
        .map_err(|e| CanonicalGraphError::MalformedWire(e.to_string()))?;
        let node_count = dec
            .u32()
            .map_err(|e| CanonicalGraphError::MalformedWire(e.to_string()))?;
        let edge_count = dec
            .u32()
            .map_err(|e| CanonicalGraphError::MalformedWire(e.to_string()))?;
        let graph_digest = dec
            .digest()
            .map_err(|e| CanonicalGraphError::MalformedWire(e.to_string()))?;
        let nodes_merkle_root = dec
            .digest()
            .map_err(|e| CanonicalGraphError::MalformedWire(e.to_string()))?;
        let edges_merkle_root = dec
            .digest()
            .map_err(|e| CanonicalGraphError::MalformedWire(e.to_string()))?;
        let payload_bytes = dec
            .bytes()
            .map_err(|e| CanonicalGraphError::MalformedWire(e.to_string()))?
            .to_vec();
        let envelope_digest = dec
            .digest()
            .map_err(|e| CanonicalGraphError::MalformedWire(e.to_string()))?;
        dec.ensure_finished().map_err(|_| {
            CanonicalGraphError::MalformedWire(
                "trailing bytes after canonical graph envelope".to_owned(),
            )
        })?;

        let env = Self {
            format_version,
            payload_kind,
            hashes: GraphStructuralHashes {
                node_count,
                edge_count,
                graph_digest,
                nodes_merkle_root,
                edges_merkle_root,
            },
            payload_bytes,
            envelope_digest,
        };
        let payload =
            env.verify_and_decode(expected_graph_digest, expected_envelope_digest, false)?;
        Ok((env, payload))
    }
}

/// Computes structural hashes (graph digest + balanced Merkle roots over nodes and edges) for
/// [`UndirectedGraph`].
pub fn compute_undirected_hashes(
    graph: &UndirectedGraph,
) -> Result<GraphStructuralHashes, CanonicalGraphError> {
    let node_count =
        u32::try_from(graph.node_count()).map_err(|_| CanonicalGraphError::BoundsExceeded {
            observed: graph.node_count(),
            maximum: MAX_GRAPH_NODES,
        })?;
    let edge_count =
        u32::try_from(graph.edge_count()).map_err(|_| CanonicalGraphError::BoundsExceeded {
            observed: graph.edge_count(),
            maximum: MAX_GRAPH_EDGES,
        })?;

    let mut node_leaves = Vec::with_capacity(graph.node_count());
    for (idx, id) in graph.ids().iter().enumerate() {
        let mut enc = CanonicalEncoder::new();
        enc.text(GRAPH_MERKLE_STRUCTURE_DOMAIN);
        enc.text("undirected_node_leaf");
        enc.u32(idx as u32);
        enc.text(id);
        let bytes = enc
            .finish_checked()
            .map_err(|e| CanonicalGraphError::Encoding(e.to_string()))?;
        node_leaves.push(ContentDigest::sha256(&bytes));
    }

    let mut edge_leaves = Vec::with_capacity(graph.edge_count());
    for (idx, &(lo, hi)) in graph.edges().iter().enumerate() {
        let mut enc = CanonicalEncoder::new();
        enc.text(GRAPH_MERKLE_STRUCTURE_DOMAIN);
        enc.text("undirected_edge_leaf");
        enc.u32(idx as u32);
        enc.u32(lo);
        enc.u32(hi);
        let bytes = enc
            .finish_checked()
            .map_err(|e| CanonicalGraphError::Encoding(e.to_string()))?;
        edge_leaves.push(ContentDigest::sha256(&bytes));
    }

    Ok(GraphStructuralHashes {
        node_count,
        edge_count,
        graph_digest: graph.digest(),
        nodes_merkle_root: merkle_root_over("nodes", &node_leaves)?,
        edges_merkle_root: merkle_root_over("edges", &edge_leaves)?,
    })
}

/// Computes structural hashes (projection digest + balanced Merkle roots over nodes and edges)
/// for [`ImmutableGraphProjection`].
pub fn compute_projection_hashes(
    projection: &ImmutableGraphProjection,
) -> Result<GraphStructuralHashes, CanonicalGraphError> {
    let node_handles = projection.node_handles();
    let edge_handles = projection.edge_handles();
    let node_count =
        u32::try_from(node_handles.len()).map_err(|_| CanonicalGraphError::BoundsExceeded {
            observed: node_handles.len(),
            maximum: MAX_GRAPH_NODES,
        })?;
    let edge_count =
        u32::try_from(edge_handles.len()).map_err(|_| CanonicalGraphError::BoundsExceeded {
            observed: edge_handles.len(),
            maximum: MAX_GRAPH_EDGES,
        })?;

    let mut node_leaves = Vec::with_capacity(node_handles.len());
    for (idx, handle) in node_handles.into_iter().enumerate() {
        let node = projection
            .node(handle)
            .map_err(|e| CanonicalGraphError::Encoding(e.to_string()))?;
        let mut enc = CanonicalEncoder::new();
        enc.text(GRAPH_MERKLE_STRUCTURE_DOMAIN);
        enc.text("projection_node_leaf");
        enc.u32(idx as u32);
        enc.text(&node.node_id);
        node.plane.encode_canonical(&mut enc);
        enc.digest(node.payload_digest);
        let bytes = enc
            .finish_checked()
            .map_err(|e| CanonicalGraphError::Encoding(e.to_string()))?;
        node_leaves.push(ContentDigest::sha256(&bytes));
    }

    let mut edge_leaves = Vec::with_capacity(edge_handles.len());
    for (idx, handle) in edge_handles.into_iter().enumerate() {
        let edge = projection
            .edge(handle)
            .map_err(|e| CanonicalGraphError::Encoding(e.to_string()))?;
        let mut enc = CanonicalEncoder::new();
        enc.text(GRAPH_MERKLE_STRUCTURE_DOMAIN);
        enc.text("projection_edge_leaf");
        enc.u32(idx as u32);
        enc.u32(edge.source_index);
        enc.u32(edge.target_index);
        enc.text(&edge.relation);
        enc.u64(edge.weight);
        let bytes = enc
            .finish_checked()
            .map_err(|e| CanonicalGraphError::Encoding(e.to_string()))?;
        edge_leaves.push(ContentDigest::sha256(&bytes));
    }

    Ok(GraphStructuralHashes {
        node_count,
        edge_count,
        graph_digest: projection.generation().projection_digest,
        nodes_merkle_root: merkle_root_over("nodes", &node_leaves)?,
        edges_merkle_root: merkle_root_over("edges", &edge_leaves)?,
    })
}

fn encode_undirected_canonical(graph: &UndirectedGraph) -> Result<Vec<u8>, CanonicalGraphError> {
    let mut enc = CanonicalEncoder::new();
    enc.text("fss.graph.undirected_simple.v1");
    enc.u32(graph.node_count() as u32);
    for id in graph.ids() {
        enc.text(id);
    }
    enc.u32(graph.edge_count() as u32);
    for &(lo, hi) in graph.edges() {
        enc.u32(lo);
        enc.u32(hi);
    }
    enc.finish_checked()
        .map_err(|e| CanonicalGraphError::Encoding(e.to_string()))
}

fn decode_undirected_canonical(bytes: &[u8]) -> Result<UndirectedGraph, CanonicalGraphError> {
    let mut dec = CanonicalDecoder::new(bytes);
    let tag = dec
        .text()
        .map_err(|e| CanonicalGraphError::MalformedWire(e.to_string()))?;
    if tag != "fss.graph.undirected_simple.v1" {
        return Err(CanonicalGraphError::MalformedWire(format!(
            "unexpected undirected payload tag '{tag}'"
        )));
    }
    let node_count =
        dec.u32()
            .map_err(|e| CanonicalGraphError::MalformedWire(e.to_string()))? as usize;
    if node_count > MAX_GRAPH_NODES || node_count.saturating_mul(5) > dec.remaining() {
        return Err(CanonicalGraphError::BoundsExceeded {
            observed: node_count,
            maximum: MAX_GRAPH_NODES,
        });
    }
    let mut ids = Vec::with_capacity(node_count);
    for _ in 0..node_count {
        let id = dec
            .text()
            .map_err(|e| CanonicalGraphError::MalformedWire(e.to_string()))?
            .to_owned();
        if id.is_empty() || id.len() > MAX_NODE_ID_LEN || id.chars().any(char::is_control) {
            return Err(CanonicalGraphError::MalformedWire(format!(
                "invalid node_id '{id}' in canonical undirected payload"
            )));
        }
        if let Some(prev) = ids.last()
            && prev >= &id
        {
            return Err(CanonicalGraphError::MalformedWire(
                "node_ids in canonical undirected payload must be strictly sorted".to_owned(),
            ));
        }
        ids.push(id);
    }

    let edge_count =
        dec.u32()
            .map_err(|e| CanonicalGraphError::MalformedWire(e.to_string()))? as usize;
    if edge_count > MAX_GRAPH_EDGES || edge_count.saturating_mul(8) > dec.remaining() {
        return Err(CanonicalGraphError::BoundsExceeded {
            observed: edge_count,
            maximum: MAX_GRAPH_EDGES,
        });
    }
    let mut edges = Vec::with_capacity(edge_count);
    for _ in 0..edge_count {
        let lo = dec
            .u32()
            .map_err(|e| CanonicalGraphError::MalformedWire(e.to_string()))?;
        let hi = dec
            .u32()
            .map_err(|e| CanonicalGraphError::MalformedWire(e.to_string()))?;
        if (lo as usize) >= node_count || (hi as usize) >= node_count || lo >= hi {
            return Err(CanonicalGraphError::MalformedWire(format!(
                "invalid undirected canonical edge ({lo}, {hi})"
            )));
        }
        if let Some(&(prev_lo, prev_hi)) = edges.last()
            && (prev_lo, prev_hi) >= (lo, hi)
        {
            return Err(CanonicalGraphError::MalformedWire(
                "edges in canonical undirected payload must be strictly sorted".to_owned(),
            ));
        }
        edges.push((lo, hi));
    }
    dec.ensure_finished().map_err(|_| {
        CanonicalGraphError::MalformedWire("trailing bytes in undirected payload".to_owned())
    })?;

    let mut builder = GraphBuilder::new();
    for id in &ids {
        builder.add_node(id.clone());
    }
    for &(lo, hi) in &edges {
        builder.add_edge(ids[lo as usize].clone(), ids[hi as usize].clone());
    }
    builder
        .build()
        .map_err(|e| CanonicalGraphError::MalformedWire(e.to_string()))
}

fn merkle_root_over(
    kind: &str,
    leaves: &[ContentDigest],
) -> Result<ContentDigest, CanonicalGraphError> {
    if leaves.is_empty() {
        let mut enc = CanonicalEncoder::new();
        enc.text(GRAPH_MERKLE_STRUCTURE_DOMAIN);
        enc.text("empty_root");
        enc.text(kind);
        let bytes = enc
            .finish_checked()
            .map_err(|e| CanonicalGraphError::Encoding(e.to_string()))?;
        return Ok(ContentDigest::sha256(&bytes));
    }
    let mut level: Vec<ContentDigest> = leaves.to_vec();
    let mut depth = 0_u32;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let mut enc = CanonicalEncoder::new();
            enc.text(GRAPH_MERKLE_STRUCTURE_DOMAIN);
            enc.text("internal_node");
            enc.text(kind);
            enc.u32(depth);
            enc.u8(pair.len() as u8);
            enc.digest(pair[0]);
            if pair.len() == 2 {
                enc.digest(pair[1]);
            }
            let bytes = enc
                .finish_checked()
                .map_err(|e| CanonicalGraphError::Encoding(e.to_string()))?;
            next.push(ContentDigest::sha256(&bytes));
        }
        level = next;
        depth = depth.saturating_add(1);
    }
    Ok(level[0])
}

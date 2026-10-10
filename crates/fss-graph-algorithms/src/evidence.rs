#![forbid(unsafe_code)]
//! An active-revision `EvidenceClaimGraph` compiled from canonical event records.
//!
//! The directed incidence graph contains `object:<digest>` vertices and one vertex per
//! **Supports** edge. A support is `object -> edge -> revision`; repeated object digests
//! are shared, never counted as independent sources. A synthetic root enters only supporting
//! objects that are not one of the selected revisions. These are UNEXPANDED REFERENCES, not
//! verified observations. Rootedness is not truth, corroboration, custody, or physical absence.
//!
//! All other relations remain in the complete, digest-bound event records, but are never
//! traversed as support. In particular, contradiction, invalidation, tamper, supersession,
//! derivation and temporal order do not provide a positive support path. A previous revision
//! named by evidence but not selected is an explicit unexpanded boundary, not silently replaced
//! by its successor. The caller selects exactly one revision per event from ONE verified
//! snapshot and supplies its anchor when constructing the algorithm witness.
//!
//! This is a structural diagnostic, NOT an AND/OR proof evaluator, independence estimator,
//! absence certificate, or effect authorization. Canonical source bytes are unchanged.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::{
    ContentDigest, ContractError, EventDecodeError, EventHypothesis, GraphAlgorithmWitness,
    LedgerAnchor,
};

use crate::certified::{Budget, CertifiedRun, check_witness};
use crate::dominators::{self, DominanceDirection, DominanceOutput};
use crate::graph::GraphError;
use crate::weighted::{WeightedGraph, WeightedGraphBuilder};

/// Registered graph kind and the exact active-revision selection/traversal policy.
pub const PROJECTION_ID: &str = "EvidenceClaimGraph:active-support-incidence:v1";
/// Synthetic entry point. It is not a source observation or evidence artifact.
pub const FRONTIER_ROOT: &str = "evidence:unexpanded-support-frontier:v1";
/// Maximum selected event revisions; larger deployments need an explicitly scoped query.
pub const MAX_EVENTS: usize = 128;
/// Maximum evidence edges inspected, including every non-supporting relation.
pub const MAX_EVIDENCE_EDGES: usize = 8192;
/// Maximum total canonical event bytes admitted by the compiler.
pub const MAX_CANONICAL_BYTES: usize = 8 * 1024 * 1024;

/// Admission limits apply before graph construction, in addition to algorithm budgets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceProjectionLimits {
    /// Selected event revisions.
    pub max_events: usize,
    /// All evidence edges, not just supports.
    pub max_evidence_edges: usize,
    /// Total canonical versioned event bytes.
    pub max_canonical_bytes: usize,
}

impl Default for EvidenceProjectionLimits {
    fn default() -> Self {
        Self {
            max_events: MAX_EVENTS,
            max_evidence_edges: MAX_EVIDENCE_EDGES,
            max_canonical_bytes: MAX_CANONICAL_BYTES,
        }
    }
}

/// A malformed input, exhausted budget, or invalid anchor yields no partial answer.
#[derive(Clone, Debug, PartialEq)]
pub enum EvidenceProjectionError {
    /// An event record did not satisfy its canonical contract.
    Event(EventDecodeError),
    /// A projection, algorithm budget, or bound was refused.
    Graph(GraphError),
    /// The anchor or registered witness was invalid.
    Contract(ContractError),
}

impl EvidenceProjectionError {
    /// Existing registered error identity; this compiler introduces no parallel error family.
    #[must_use]
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Graph(error) => error.stable_id(),
            Self::Event(_) | Self::Contract(_) => "ERR-GRAPH-INPUT-INVALID-001",
        }
    }
}

impl fmt::Display for EvidenceProjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Event(error) => write!(f, "event projection refused: {error}"),
            Self::Graph(error) => write!(f, "evidence graph refused: {error}"),
            Self::Contract(error) => write!(f, "evidence witness refused: {error}"),
        }
    }
}

impl std::error::Error for EvidenceProjectionError {}

impl From<GraphError> for EvidenceProjectionError {
    fn from(error: GraphError) -> Self {
        Self::Graph(error)
    }
}

/// Canonical vertex identity for an artifact or selected revision.
#[must_use]
pub fn object_node(digest: ContentDigest) -> String {
    format!("object:{digest}")
}

/// One declared edge's identity; its revision digest binds ALL fields of that edge.
#[must_use]
pub fn support_node(revision: ContentDigest, index: usize) -> String {
    format!("support:{revision}:{index:04}")
}

/// Immutable active-revision projection with the full records needed to interpret it.
#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceClaimProjection {
    graph: WeightedGraph,
    events: Vec<EventHypothesis>,
    unexpanded_support: Vec<ContentDigest>,
    unexpanded_evidence: Vec<ContentDigest>,
    canonical_bytes: usize,
    evidence_edges: usize,
}

fn admit(value: usize, limit: usize, dimension: &'static str) -> Result<(), GraphError> {
    if value > limit {
        return Err(GraphError::BudgetExhausted {
            dimension,
            limit: limit as u64,
        });
    }
    Ok(())
}

impl EvidenceClaimProjection {
    /// Compiles one selected revision per event. No selection or truncation is performed here.
    ///
    /// The entire canonical revision digest is a vertex identity, binding uncertainty,
    /// counterevidence, model generations and ordering even when they do not add support arcs.
    /// Insertion order of distinct events cannot change the graph or answer; evidence order is
    /// part of each canonical event's identity and is intentionally not rewritten.
    ///
    /// # Errors
    ///
    /// Invalid records, duplicate event identities, caller limits above the hard ceilings, or
    /// exhausted event/edge/byte limits. No incomplete projection is returned.
    pub fn build(
        events: &[EventHypothesis],
        limits: EvidenceProjectionLimits,
    ) -> Result<Self, EvidenceProjectionError> {
        if limits.max_events > MAX_EVENTS
            || limits.max_evidence_edges > MAX_EVIDENCE_EDGES
            || limits.max_canonical_bytes > MAX_CANONICAL_BYTES
        {
            return Err(GraphError::TooLarge.into());
        }
        admit(events.len(), limits.max_events, "event_revisions")?;
        // Preflight aggregate cardinality before copying or verifying canonical records.
        let evidence_edges = events.iter().try_fold(0_usize, |total, event| {
            total
                .checked_add(event.evidence.len())
                .ok_or(GraphError::TooLarge)
        })?;
        admit(evidence_edges, limits.max_evidence_edges, "evidence_edges")?;
        let mut ordered: Vec<_> = events.iter().collect();
        ordered.sort_unstable_by(|a, b| a.event_id.as_str().cmp(b.event_id.as_str()));
        for pair in ordered.windows(2) {
            if pair[0].event_id == pair[1].event_id {
                return Err(GraphError::DuplicateNode(pair[0].event_id.to_string()).into());
            }
        }
        let mut canonical_bytes = 0_usize;
        let mut revisions = BTreeSet::new();
        for event in &ordered {
            let bytes = event
                .to_versioned_bytes()
                .map_err(EvidenceProjectionError::Event)?;
            canonical_bytes = canonical_bytes
                .checked_add(bytes.len())
                .ok_or(GraphError::TooLarge)?;
            admit(canonical_bytes, limits.max_canonical_bytes, "canonical_event_bytes")?;
            revisions.insert(event.revision_digest());
        }

        // The unit binds the traversal policy into the existing weighted-projection digest.
        // Reference incidence is simple even when several typed edges name the same object.
        let mut builder = WeightedGraphBuilder::directed("active-support-incidence:v1");
        let mut nodes = BTreeSet::from([FRONTIER_ROOT.to_owned()]);
        let mut arcs = BTreeSet::new();
        let mut unexpanded_support = BTreeSet::new();
        let mut unexpanded_evidence = BTreeSet::new();
        for event in &ordered {
            let revision = event.revision_digest();
            let target = object_node(revision);
            nodes.insert(target.clone());
            for (index, edge) in event.evidence.iter().enumerate() {
                if !revisions.contains(&edge.digest) {
                    unexpanded_evidence.insert(edge.digest);
                }
                if !edge.counts_as_support() {
                    continue;
                }
                let source = object_node(edge.digest);
                let incidence = support_node(revision, index);
                nodes.insert(source.clone());
                nodes.insert(incidence.clone());
                arcs.insert((source.clone(), incidence.clone()));
                arcs.insert((incidence, target.clone()));
                if !revisions.contains(&edge.digest) {
                    unexpanded_support.insert(edge.digest);
                    arcs.insert((FRONTIER_ROOT.to_owned(), source));
                }
            }
        }
        for node in nodes {
            builder.add_node(node);
        }
        for (source, target) in arcs {
            builder.add_arc(source, target, 1);
        }
        Ok(Self {
            graph: builder.build()?,
            events: ordered.into_iter().cloned().collect(),
            unexpanded_support: unexpanded_support.into_iter().collect(),
            unexpanded_evidence: unexpanded_evidence.into_iter().collect(),
            canonical_bytes,
            evidence_edges,
        })
    }

    /// Canonical support-incidence graph; no mutable access is exposed.
    #[must_use]
    pub fn graph(&self) -> &WeightedGraph {
        &self.graph
    }

    /// Complete selected records, including ALL non-supporting relations and uncertainty.
    #[must_use]
    pub fn events(&self) -> &[EventHypothesis] {
        &self.events
    }

    /// Supporting object references not expanded as one of the selected revisions.
    /// They are NOT verified source leaves or independent sources.
    #[must_use]
    pub fn unexpanded_support(&self) -> &[ContentDigest] {
        &self.unexpanded_support
    }

    /// All unexpanded evidence references, including contradicting and neutral edges.
    /// Capsule, identity and model receipt references remain explicit in [`Self::events`].
    #[must_use]
    pub fn unexpanded_evidence(&self) -> &[ContentDigest] {
        &self.unexpanded_evidence
    }

    /// Total canonical event bytes admitted, excluding graph and algorithm allocations.
    #[must_use]
    pub const fn canonical_bytes(&self) -> usize {
        self.canonical_bytes
    }

    /// Total inspected edges, including those deliberately excluded from support traversal.
    #[must_use]
    pub const fn evidence_edges(&self) -> usize {
        self.evidence_edges
    }

    /// Computes exact dominators from the declared, unexpanded support frontier.
    ///
    /// # Errors
    ///
    /// Algorithm operation/output budget exhaustion, a failed registered bound, or an invalid
    /// anchor. Unreachable events are reported as unrooted or without declared support, never
    /// as false, absent, rejected, or safe to ignore.
    pub fn analyze(
        &self,
        anchor: LedgerAnchor,
        budget: Budget,
    ) -> Result<EvidenceClaimAnalysis, EvidenceProjectionError> {
        let run = dominators::dominators(
            &self.graph,
            FRONTIER_ROOT,
            DominanceDirection::Dominators,
            budget,
        )?;
        let witness = run
            .witness(PROJECTION_ID, anchor)
            .map_err(EvidenceProjectionError::Contract)?;
        check_witness(
            &witness,
            &dominators::IDENTITY,
            &dominators::bound(run.node_count, run.edge_count),
        )?;
        // Direct lookup only: materializing a whole dominator chain for every event could
        // turn a bounded linear-size output into a quadratic dump.
        let immediate: BTreeMap<_, _> = run.output.immediate_dominators.iter().cloned().collect();
        let claims = self
            .events
            .iter()
            .map(|event| {
                let revision = event.revision_digest();
                let supports = event
                    .evidence
                    .iter()
                    .filter(|edge| edge.counts_as_support())
                    .count();
                let contradictions = event
                    .evidence
                    .iter()
                    .filter(|edge| edge.counts_as_contradiction())
                    .count();
                let immediate_dominator = immediate.get(&object_node(revision)).cloned();
                let reachability = if supports == 0 {
                    SupportReachability::NoDeclaredSupport
                } else if immediate_dominator.is_some() {
                    SupportReachability::RootedInUnexpandedReference
                } else {
                    SupportReachability::Unrooted
                };
                ClaimSupport {
                    event_id: event.event_id.to_string(),
                    revision,
                    supports,
                    contradictions,
                    neutral: event.evidence.len() - supports - contradictions,
                    reachability,
                    immediate_dominator,
                }
            })
            .collect();
        Ok(EvidenceClaimAnalysis { run, witness, claims })
    }
}

/// Structural reachability only, orthogonal to event truth and source availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupportReachability {
    /// No explicit Supports edge exists in the selected revision.
    NoDeclaredSupport,
    /// At least one path reaches an unexpanded reference; no source proof is implied.
    RootedInUnexpandedReference,
    /// Supports exist, but no path reaches this projection's external-reference frontier.
    Unrooted,
}

impl SupportReachability {
    /// Stable machine spelling, explicitly avoiding truth or observability labels.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoDeclaredSupport => "no_declared_support",
            Self::RootedInUnexpandedReference => "rooted_in_unexpanded_reference",
            Self::Unrooted => "unrooted",
        }
    }
}

/// A selected event's support-path diagnostic, not an adjudication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimSupport {
    /// Event identity, in ascending order in the report.
    pub event_id: String,
    /// Exact selected revision identity.
    pub revision: ContentDigest,
    /// Explicit Supports edges, not independent-source count.
    pub supports: usize,
    /// Explicit Contradicts edges.
    pub contradictions: usize,
    /// Every other retained relation (including tamper and invalidation).
    pub neutral: usize,
    /// Exact structural result inside the declared projection.
    pub reachability: SupportReachability,
    /// Immediate dominator node, or None when structurally unreachable.
    pub immediate_dominator: Option<String>,
}

/// Complete certified support-path analysis with its anchor and interpretation records.
#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceClaimAnalysis {
    /// Exact algorithm answer and charged operations. Its digest covers the dominator output.
    pub run: CertifiedRun<DominanceOutput>,
    /// Registered ALG-DOM-001 witness; source truth is not upgraded by this witness.
    pub witness: GraphAlgorithmWitness,
    /// One diagnostic per selected event, rederived from the graph and complete records.
    pub claims: Vec<ClaimSupport>,
}

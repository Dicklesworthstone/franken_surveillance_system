#![forbid(unsafe_code)]
//! Exact historical event references in the registered `EvidenceClaimGraph`.
//!
//! Every input lineage is verified in full before selecting its head and expanding references.
//! Expansion follows the exact digest of every evidence relation, including counterevidence;
//! only explicit Supports edges enter the positive incidence graph. Supersession is never a
//! support edge or a redirect. Catalogue-only ancestors are validated but not bulk-expanded.
//! This is derived structure over caller-supplied, same-snapshot records, not source custody,
//! current truth, independent corroboration, an absence certificate, or effect authority.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{ContentDigest, EventHypothesis, LedgerAnchor};

use crate::certified::{Budget, check_witness};
use crate::dominators::{self, DominanceDirection};
use crate::evidence::{
    ClaimSupport, EvidenceClaimAnalysis, EvidenceProjectionError, FRONTIER_ROOT,
    SupportReachability, object_node, support_node,
};
use crate::graph::GraphError;
use crate::weighted::{WeightedGraph, WeightedGraphBuilder};

/// Additive projection identity; active-only v1 witnesses remain unchanged.
pub const PROJECTION_ID: &str = "EvidenceClaimGraph:retained-history-support-incidence:v1";
/// Canonical graph unit binds the exact-history expansion and traversal policy.
pub const POLICY_UNIT: &str = "retained-history-support-incidence:v1";
/// Maximum independent event lineages, matching the retained deployment reader.
pub const MAX_LINEAGES: usize = 128;
/// Maximum revisions in one complete lineage, matching the retained deployment reader.
pub const MAX_LINEAGE_REVISIONS: usize = 64;
/// Maximum catalogue revisions, including ancestors not selected for expansion.
pub const MAX_REVISIONS: usize = MAX_LINEAGES * MAX_LINEAGE_REVISIONS;
/// Maximum evidence edges inspected across the entire catalogue, not merely support edges.
pub const MAX_EVIDENCE_EDGES: usize = 16_384;
/// Maximum aggregate canonical versioned bytes validated across the catalogue.
pub const MAX_CANONICAL_BYTES: usize = 16 * 1024 * 1024;

/// Preflight compiler limits, separate from the dominator operation and output budgets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryLimits {
    /// Maximum nonempty, unique lineages.
    pub max_lineages: usize,
    /// Maximum revisions across every supplied lineage.
    pub max_revisions: usize,
    /// Maximum evidence edges across every supplied revision.
    pub max_evidence_edges: usize,
    /// Maximum canonical versioned bytes across every supplied revision.
    pub max_canonical_bytes: usize,
}

impl Default for HistoryLimits {
    fn default() -> Self {
        Self {
            max_lineages: MAX_LINEAGES,
            max_revisions: MAX_REVISIONS,
            max_evidence_edges: MAX_EVIDENCE_EDGES,
            max_canonical_bytes: MAX_CANONICAL_BYTES,
        }
    }
}

fn admit(value: usize, limit: usize, dimension: &'static str) -> Result<(), GraphError> {
    if value > limit {
        return Err(GraphError::BudgetExhausted { dimension, limit: limit as u64 });
    }
    Ok(())
}

/// Immutable projection with explicit heads, exact expanded records and unresolved boundaries.
#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceHistoryProjection {
    graph: WeightedGraph,
    heads: BTreeMap<String, ContentDigest>,
    records: Vec<EventHypothesis>,
    unexpanded_support: Vec<ContentDigest>,
    unexpanded_evidence: Vec<ContentDigest>,
    catalogue_revisions: usize,
    catalogue_edges: usize,
    catalogue_bytes: usize,
}

impl EvidenceHistoryProjection {
    /// Verify complete oldest-first lineages and expand exact references from ALL their heads.
    ///
    /// The input order of distinct lineages is irrelevant; order inside a lineage is canonical
    /// and is never repaired. Even unused ancestors must validate. No reference is redirected
    /// to a newer revision, and a referenced unsupported old claim is not a source frontier.
    ///
    /// # Errors
    ///
    /// Empty/duplicate lineages, missing/forked/reordered revisions, invalid canonical records,
    /// invalid limits or exhausted cardinality/byte budgets yield no partial projection.
    pub fn build(
        lineages: &[&[EventHypothesis]],
        limits: HistoryLimits,
    ) -> Result<Self, EvidenceProjectionError> {
        if limits.max_lineages > MAX_LINEAGES
            || limits.max_revisions > MAX_REVISIONS
            || limits.max_evidence_edges > MAX_EVIDENCE_EDGES
            || limits.max_canonical_bytes > MAX_CANONICAL_BYTES
        {
            return Err(GraphError::TooLarge.into());
        }
        admit(lineages.len(), limits.max_lineages, "history_lineages")?;
        let mut catalogue_revisions = 0_usize;
        let mut catalogue_edges = 0_usize;
        // Cardinality admission precedes hashing, verification or copying event records.
        for lineage in lineages {
            if lineage.is_empty() {
                return Err(GraphError::PreconditionFailed("empty event lineage".to_owned()).into());
            }
            admit(lineage.len(), MAX_LINEAGE_REVISIONS, "lineage_revisions")?;
            catalogue_revisions = catalogue_revisions.checked_add(lineage.len())
                .ok_or(GraphError::TooLarge)?;
            admit(catalogue_revisions, limits.max_revisions, "history_revisions")?;
            for record in *lineage {
                catalogue_edges = catalogue_edges.checked_add(record.evidence.len())
                    .ok_or(GraphError::TooLarge)?;
                admit(catalogue_edges, limits.max_evidence_edges, "history_evidence_edges")?;
            }
        }
        let mut ordered = lineages.to_vec();
        ordered.sort_unstable_by(|a, b| a[0].event_id.as_str().cmp(b[0].event_id.as_str()));
        for pair in ordered.windows(2) {
            if pair[0][0].event_id == pair[1][0].event_id {
                return Err(GraphError::DuplicateNode(pair[0][0].event_id.to_string()).into());
            }
        }
        let mut catalogue_bytes = 0_usize;
        let mut catalogue = BTreeMap::new();
        let mut heads = BTreeMap::new();
        for lineage in ordered {
            for record in lineage {
                let bytes = record.to_versioned_bytes().map_err(EvidenceProjectionError::Event)?;
                catalogue_bytes = catalogue_bytes.checked_add(bytes.len())
                    .ok_or(GraphError::TooLarge)?;
                admit(catalogue_bytes, limits.max_canonical_bytes, "history_canonical_bytes")?;
            }
            EventHypothesis::verify_chain(lineage).map_err(EvidenceProjectionError::Event)?;
            for record in lineage {
                let digest = record.revision_digest();
                if catalogue.insert(digest, record).is_some() {
                    return Err(GraphError::DuplicateNode(object_node(digest)).into());
                }
            }
            let head = lineage.last().ok_or_else(|| {
                GraphError::Inconsistent("admitted lineage has no head".to_owned())
            })?;
            heads.insert(head.event_id.to_string(), head.revision_digest());
        }
        let mut pending: BTreeSet<_> = heads.values().copied().collect();
        let mut selected = BTreeSet::new();
        while let Some(digest) = pending.pop_first() {
            if !selected.insert(digest) {
                continue;
            }
            let record = catalogue.get(&digest).ok_or_else(|| {
                GraphError::Inconsistent("selected revision is outside catalogue".to_owned())
            })?;
            for edge in &record.evidence {
                // Preserve historical counterevidence too, without turning it into support.
                if catalogue.contains_key(&edge.digest) && !selected.contains(&edge.digest) {
                    pending.insert(edge.digest);
                }
            }
        }
        let mut records: Vec<_> = selected.iter().filter_map(|digest| catalogue.get(digest).copied())
            .collect();
        if records.len() != selected.len() {
            return Err(GraphError::Inconsistent("incomplete history selection".to_owned()).into());
        }
        records.sort_unstable_by(|a, b| {
            a.event_id.as_str().cmp(b.event_id.as_str()).then(a.revision.cmp(&b.revision))
        });
        let mut nodes = BTreeSet::from([FRONTIER_ROOT.to_owned()]);
        let mut arcs = BTreeSet::new();
        let mut unexpanded_support = BTreeSet::new();
        let mut unexpanded_evidence = BTreeSet::new();
        for record in &records {
            let revision = record.revision_digest();
            let target = object_node(revision);
            nodes.insert(target.clone());
            for (index, edge) in record.evidence.iter().enumerate() {
                if !selected.contains(&edge.digest) {
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
                if !selected.contains(&edge.digest) {
                    unexpanded_support.insert(edge.digest);
                    arcs.insert((FRONTIER_ROOT.to_owned(), source));
                }
            }
        }
        let mut builder = WeightedGraphBuilder::directed(POLICY_UNIT);
        for node in nodes { builder.add_node(node); }
        for (source, target) in arcs { builder.add_arc(source, target, 1); }
        Ok(Self {
            graph: builder.build()?,
            heads,
            records: records.into_iter().cloned().collect(),
            unexpanded_support: unexpanded_support.into_iter().collect(),
            unexpanded_evidence: unexpanded_evidence.into_iter().collect(),
            catalogue_revisions,
            catalogue_edges,
            catalogue_bytes,
        })
    }

    /// Exact support graph; no mutable access is exposed.
    #[must_use]
    pub fn graph(&self) -> &WeightedGraph { &self.graph }
    /// Latest selected revision of every lineage, ordered by event identity.
    #[must_use]
    pub fn heads(&self) -> &BTreeMap<String, ContentDigest> { &self.heads }
    /// Complete expanded records, ordered by event identity then revision number.
    #[must_use]
    pub fn records(&self) -> &[EventHypothesis] { &self.records }
    /// Supporting references not found in the verified event catalogue; NOT verified sources.
    #[must_use]
    pub fn unexpanded_support(&self) -> &[ContentDigest] { &self.unexpanded_support }
    /// All non-event evidence references, including counterevidence and neutral relations.
    #[must_use]
    pub fn unexpanded_evidence(&self) -> &[ContentDigest] { &self.unexpanded_evidence }
    /// Revisions validated, including catalogue-only ancestors not selected for expansion.
    #[must_use]
    pub const fn catalogue_revisions(&self) -> usize { self.catalogue_revisions }
    /// All inspected evidence edges, including unused ancestors and non-supports.
    #[must_use]
    pub const fn catalogue_edges(&self) -> usize { self.catalogue_edges }
    /// All validated canonical versioned bytes; excludes graph allocation and source I/O.
    #[must_use]
    pub const fn catalogue_bytes(&self) -> usize { self.catalogue_bytes }

    /// Exact witnessed dominators over the historical support graph.
    ///
    /// # Errors
    ///
    /// The registered algorithm's budget/bound failures or an invalid anchor. Structurally
    /// unrooted revisions remain explicit, never adjudicated as false or absent.
    pub fn analyze(
        &self,
        anchor: LedgerAnchor,
        budget: Budget,
    ) -> Result<EvidenceClaimAnalysis, EvidenceProjectionError> {
        let run = dominators::dominators(
            &self.graph, FRONTIER_ROOT, DominanceDirection::Dominators, budget,
        )?;
        let witness = run.witness(PROJECTION_ID, anchor).map_err(EvidenceProjectionError::Contract)?;
        check_witness(&witness, &dominators::IDENTITY, &dominators::bound(run.node_count, run.edge_count))?;
        let immediate: BTreeMap<_, _> = run.output.immediate_dominators.iter().cloned().collect();
        let claims = self.records.iter().map(|record| {
            let revision = record.revision_digest();
            let supports = record.evidence.iter().filter(|edge| edge.counts_as_support()).count();
            let contradictions = record.evidence.iter().filter(|edge| edge.counts_as_contradiction()).count();
            let immediate_dominator = immediate.get(&object_node(revision)).cloned();
            let reachability = if supports == 0 {
                SupportReachability::NoDeclaredSupport
            } else if immediate_dominator.is_some() {
                SupportReachability::RootedInUnexpandedReference
            } else {
                SupportReachability::Unrooted
            };
            ClaimSupport {
                event_id: record.event_id.to_string(), revision, supports, contradictions,
                neutral: record.evidence.len() - supports - contradictions,
                reachability, immediate_dominator,
            }
        }).collect();
        Ok(EvidenceClaimAnalysis { run, witness, claims })
    }
}

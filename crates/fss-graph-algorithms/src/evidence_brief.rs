#![forbid(unsafe_code)]
//! Decision-oriented explanations of one current event's exact historical support.
//!
//! Two registered `ALG-DOM-001` runs distinguish all positive-support ancestors from
//! objects on EVERY rooted support path. Their operation and output budgets are shared,
//! not reset between runs. The brief keeps unsupported branches and superseded supporting
//! revisions explicit, even when another branch makes the target structurally reachable.
//! These are statements about declared paths, never truth, source custody or independence.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{ContentDigest, EventHypothesis, EventState, ExplainQuestion, ExplainReceipt,
    GraphAlgorithmWitness, LedgerAnchor};

use crate::certified::{Budget, check_witness};
use crate::dominators::{self, DominanceDirection};
use crate::evidence::{EvidenceProjectionError, FRONTIER_ROOT, SupportReachability, object_node};
use crate::evidence_history::{EvidenceHistoryProjection, PROJECTION_ID};
use crate::graph::GraphError;

/// Maximum identities emitted by a brief. Exhaustion refuses, never truncates.
pub const MAX_BRIEF_ENTRIES: usize = 256;

/// One exact event revision, not an assertion of its physical truth.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportRevision {
    /// Stable lineage identity.
    pub event_id: String,
    /// Exact immutable revision number.
    pub revision: u64,
    /// Exact immutable revision identity.
    pub digest: ContentDigest,
    /// State recorded by that revision.
    pub state: EventState,
}

impl SupportRevision {
    fn of(record: &EventHypothesis) -> Self {
        Self {
            event_id: record.event_id.to_string(),
            revision: record.revision,
            digest: record.revision_digest(),
            state: record.state,
        }
    }
}

/// A positive-support ancestor whose lineage has since acquired another head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupersededSupport {
    /// The revision actually referenced along a support path; never redirected.
    pub referenced: SupportRevision,
    /// The separately retained current head, including its potentially adverse state.
    pub current: SupportRevision,
}

/// A complete bounded structural explanation, with no external effect authority.
#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceSupportBrief {
    /// The requested CURRENT event revision.
    pub target: SupportRevision,
    /// Whether the target has a rooted declared positive-support path.
    pub reachability: SupportReachability,
    /// Direct Supports edges, not a count of independent sources.
    pub direct_support_edges: usize,
    /// Direct explicit Contradicts edges.
    pub direct_contradictions: usize,
    /// Every other direct evidence relation, not traversed as support.
    pub direct_other_relations: usize,
    /// All non-event support ancestors, sorted by digest. Their bytes are unexpanded.
    pub unexpanded_support: Vec<ContentDigest>,
    /// Object vertices on every path from the synthetic frontier to the target,
    /// in root-to-target order, excluding the target itself and incidence vertices.
    /// Empty on an unrooted target; it does NOT then establish redundancy.
    pub bottleneck_objects: Vec<ContentDigest>,
    /// Every positive-support ancestor with no declared Supports edges, including
    /// the target when it has none. Another rooted branch never hides these leaves.
    pub unsupported_revisions: Vec<SupportRevision>,
    /// Every superseded event revision on a positive-support path to this target.
    pub superseded_support: Vec<SupersededSupport>,
    /// Frontier-rooted dominators; certifies the indispensable-path calculation.
    pub rooted_witness: GraphAlgorithmWitness,
    /// Target-rooted post-dominators; certifies reverse reachability (support ancestry).
    pub ancestry_witness: GraphAlgorithmWitness,
    /// Existing AOP-011 receipt binds the exact target and both algorithm witnesses.
    pub receipt: ExplainReceipt,
    /// Sum of operations consumed by BOTH registered runs.
    pub graph_operations: u64,
    /// Sum of output entries consumed by BOTH registered runs (before brief projection).
    pub graph_output_entries: u64,
    /// Identities emitted by the four bounded lists (a superseded pair counts twice).
    pub brief_entries: usize,
}

fn reserve(entries: &mut usize, count: usize, maximum: usize) -> Result<(), GraphError> {
    let next = entries.checked_add(count).ok_or(GraphError::TooLarge)?;
    if next > maximum {
        return Err(GraphError::BudgetExhausted {
            dimension: "evidence_brief_entries",
            limit: maximum as u64,
        });
    }
    *entries = next;
    Ok(())
}

/// Explain one current head without promoting unsupported or superseded evidence.
///
/// The caller supplies a verified, already-authorized same-snapshot history projection.
/// Source/compiler costs remain separately bounded by that projection's owner. The two
/// registered runs share `budget`; the second can spend only the first's remainder.
/// `max_entries` covers every returned identity, including both halves of each historical
/// correction pair. No incomplete list, omitted branch, or unregistered algorithm is used.
/// The witness output digests cover their full registered answers, not this brief wrapper;
/// the brief can be rederived from the pinned records and those answers.
///
/// # Errors
///
/// Unknown current event, invalid entry ceiling, graph budget/bound failure, or a complete
/// brief that exceeds its entry budget. Refusal returns neither a partial brief nor a verdict.
pub fn explain_current_support(
    projection: &EvidenceHistoryProjection,
    event_id: &str,
    anchor: LedgerAnchor,
    budget: Budget,
    max_entries: usize,
) -> Result<EvidenceSupportBrief, EvidenceProjectionError> {
    if max_entries > MAX_BRIEF_ENTRIES {
        return Err(GraphError::TooLarge.into());
    }
    let target_digest = *projection.heads().get(event_id)
        .ok_or_else(|| GraphError::UnknownNode(event_id.to_owned()))?;
    let records: BTreeMap<_, _> = projection.records().iter()
        .map(|record| (record.revision_digest(), record)).collect();
    let target_record = records.get(&target_digest).copied()
        .ok_or_else(|| GraphError::Inconsistent("current head is not expanded".to_owned()))?;
    let target_node = object_node(target_digest);
    let graph = projection.graph();
    let bound = dominators::bound(graph.node_count() as u64, graph.arc_count() as u64);
    let rooted = dominators::dominators(graph, FRONTIER_ROOT,
        DominanceDirection::Dominators, budget)?;
    let remaining = Budget::new(
        budget.max_operations.checked_sub(rooted.operations).ok_or(GraphError::TooLarge)?,
        budget.max_output_entries.checked_sub(rooted.output_entries).ok_or(GraphError::TooLarge)?,
    );
    let ancestry = dominators::dominators(graph, &target_node,
        DominanceDirection::PostDominators, remaining)?;
    let rooted_witness = rooted.witness(PROJECTION_ID, anchor.clone())
        .map_err(EvidenceProjectionError::Contract)?;
    let ancestry_witness = ancestry.witness(PROJECTION_ID, anchor)
        .map_err(EvidenceProjectionError::Contract)?;
    check_witness(&rooted_witness, &dominators::IDENTITY, &bound)?;
    check_witness(&ancestry_witness, &dominators::IDENTITY, &bound)?;

    // Every reachable node except the query root has one immediate post-dominator.
    let mut ancestors: BTreeSet<&str> = ancestry.output.immediate_dominators.iter()
        .map(|(node, _)| node.as_str()).collect();
    ancestors.insert(&target_node);
    let direct_support_edges = target_record.evidence.iter()
        .filter(|edge| edge.counts_as_support()).count();
    let direct_contradictions = target_record.evidence.iter()
        .filter(|edge| edge.counts_as_contradiction()).count();
    let rooted_target = rooted.output.immediate_dominators.binary_search_by(
        |(node, _)| node.as_str().cmp(&target_node)).is_ok();
    let reachability = if direct_support_edges == 0 {
        SupportReachability::NoDeclaredSupport
    } else if rooted_target {
        SupportReachability::RootedInUnexpandedReference
    } else {
        SupportReachability::Unrooted
    };
    let mut entries = 0;
    let mut unexpanded_support = Vec::new();
    for digest in projection.unexpanded_support() {
        if ancestors.contains(object_node(*digest).as_str()) {
            reserve(&mut entries, 1, max_entries)?;
            unexpanded_support.push(*digest);
        }
    }
    let mut unsupported_revisions = Vec::new();
    let mut superseded_support = Vec::new();
    for record in projection.records() {
        let digest = record.revision_digest();
        if !ancestors.contains(object_node(digest).as_str()) { continue; }
        if !record.evidence.iter().any(|edge| edge.counts_as_support()) {
            reserve(&mut entries, 1, max_entries)?;
            unsupported_revisions.push(SupportRevision::of(record));
        }
        let head_digest = projection.heads().get(record.event_id.as_str())
            .ok_or_else(|| GraphError::Inconsistent("support lineage has no current head".to_owned()))?;
        if digest != *head_digest {
            let head = records.get(head_digest).copied()
                .ok_or_else(|| GraphError::Inconsistent("support lineage head is not expanded".to_owned()))?;
            reserve(&mut entries, 2, max_entries)?;
            superseded_support.push(SupersededSupport {
                referenced: SupportRevision::of(record), current: SupportRevision::of(head),
            });
        }
    }
    // Walk one chain only, without materializing all per-event chains or assuming acyclicity.
    let mut bottleneck_objects = Vec::new();
    if rooted_target {
        let mut current = target_node.as_str();
        let mut steps = 0_u64;
        while current != FRONTIER_ROOT {
            steps = steps.checked_add(1).ok_or(GraphError::TooLarge)?;
            if steps > rooted.node_count {
                return Err(GraphError::Inconsistent("dominator chain cycle".to_owned()).into());
            }
            let at = rooted.output.immediate_dominators.binary_search_by(
                |(node, _)| node.as_str().cmp(current)).map_err(|_| {
                    GraphError::Inconsistent("rooted chain lacks its parent".to_owned())
                })?;
            current = &rooted.output.immediate_dominators[at].1;
            if let Some(text) = current.strip_prefix("object:") {
                let digest = ContentDigest::parse(text).map_err(EvidenceProjectionError::Contract)?;
                reserve(&mut entries, 1, max_entries)?;
                bottleneck_objects.push(digest);
            }
        }
        bottleneck_objects.reverse();
    }
    let receipt = ExplainReceipt::compile(ExplainQuestion::Why, target_digest,
        vec![target_digest, rooted_witness.digest(), ancestry_witness.digest()], Vec::new(), 0)
        .map_err(EvidenceProjectionError::Contract)?;
    Ok(EvidenceSupportBrief {
        target: SupportRevision::of(target_record), reachability, direct_support_edges,
        direct_contradictions,
        direct_other_relations: target_record.evidence.len() - direct_support_edges - direct_contradictions,
        unexpanded_support, bottleneck_objects, unsupported_revisions, superseded_support,
        rooted_witness, ancestry_witness, receipt,
        graph_operations: rooted.operations.checked_add(ancestry.operations).ok_or(GraphError::TooLarge)?,
        graph_output_entries: rooted.output_entries.checked_add(ancestry.output_entries).ok_or(GraphError::TooLarge)?,
        brief_entries: entries,
    })
}


/// Availability-conditioned support over the same exact history projection.
pub mod availability {
    #![forbid(unsafe_code)]
    //! Availability-conditioned paths through exact retained event support.
    //!
    //! A verified-reference path is not a proof of the event, an AND/OR evidence
    //! argument, sensor independence, or durable custody. Two registered dominator
    //! runs distinguish paths through rehashed references from paths that still
    //! depend on unchecked references. Known unavailable objects block both views.
    //! All observations must come from the caller's same-request authorized audit.

    use std::collections::BTreeSet;

    use fss_core::{ContentDigest, GraphAlgorithmWitness, LedgerAnchor};

    use crate::certified::{Budget, check_witness};
    use crate::dominators::{self, DominanceDirection};
    use crate::evidence::{EvidenceProjectionError, FRONTIER_ROOT, object_node};
    use crate::evidence_history::EvidenceHistoryProjection;
    use crate::graph::GraphError;
    use crate::weighted::{WeightedGraph, WeightedGraphBuilder};

    /// Maximum unique observations admitted before any graph construction.
    pub const MAX_AVAILABILITY_OBSERVATIONS: usize = 65_536;
    /// Projection identity for paths that may still use unchecked references.
    pub const POSSIBLE_PROJECTION_ID: &str = "EvidenceClaimGraph:possible-reference-support:v1";
    /// Projection identity for paths through checked references only.
    pub const VERIFIED_PROJECTION_ID: &str = "EvidenceClaimGraph:verified-reference-support:v1";

    /// One exact object's observation, never its physical truth or access authority.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum ObjectAvailability {
        /// The authorized audit rehashed these exact bytes successfully.
        Verified,
        /// Bytes are missing, corrupt, invalid for their declared role, or denied.
        Unavailable,
        /// Not checked or not established, including an access/per-object limit.
        Unchecked,
    }

    /// An already authorized, same-observation-scope digest classification.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct AvailabilityObservation {
        /// Exact content identity. No generation, label, root or revision substitution.
        pub digest: ContentDigest,
        /// Observation supplied by the custody owner, not a conclusion from this graph.
        pub availability: ObjectAvailability,
    }

    /// Structural state of one current event's declared positive-support paths.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum AvailableSupport {
        /// At least one path reaches a verified non-event reference through admitted nodes.
        VerifiedReferencePath,
        /// A path remains, but every such path needs at least one unchecked reference.
        UncheckedReferencePath,
        /// No frontier path remains; this includes already unrooted historical branches.
        NoUnblockedReferencePath,
        /// The target declares no positive-support edge. Not an absence conclusion.
        NoDeclaredSupport,
    }

    impl AvailableSupport {
        /// Stable non-durable diagnostic spelling.
        #[must_use]
        pub const fn as_str(self) -> &'static str {
            match self {
                Self::VerifiedReferencePath => "verified_reference_path",
                Self::UncheckedReferencePath => "unchecked_reference_path",
                Self::NoUnblockedReferencePath => "no_unblocked_reference_path",
                Self::NoDeclaredSupport => "no_declared_support",
            }
        }
    }

    /// Both complete registered runs share one allowance; no partial success is returned.
    #[derive(Clone, Debug, PartialEq)]
    pub struct EvidenceAvailabilityAnalysis {
        /// Exact current event revision evaluated, not an external publication root.
        pub target: ContentDigest,
        /// Reachability only; no event state, probability or effect eligibility is modified.
        pub support: AvailableSupport,
        /// Registered witness for the graph excluding known unavailable object vertices.
        pub possible_witness: GraphAlgorithmWitness,
        /// Registered witness for the stricter graph also excluding unchecked vertices.
        pub verified_witness: GraphAlgorithmWitness,
        /// Observations matching object vertices in the WHOLE input support graph.
        pub mapped_observations: usize,
        /// Observations outside that graph, NOT evidence that those objects are irrelevant.
        pub outside_graph_observations: usize,
        /// Unchecked external frontiers across the WHOLE graph, not only the target ancestry.
        pub unchecked_frontier_references: usize,
        /// Sum charged by the two registered runs, excluding separately bounded graph construction.
        pub graph_operations: u64,
        /// Sum of both full registered outputs, not merely the two reachability bits.
        pub graph_output_entries: u64,
    }

    fn filtered(
        graph: &WeightedGraph,
        blocked: &[bool],
        unit: &str,
    ) -> Result<WeightedGraph, GraphError> {
        let mut builder = WeightedGraphBuilder::directed(unit);
        // Preserve even isolated node identities, weights and the selected current head.
        for (index, id) in graph.ids().iter().enumerate() {
            builder.add_weighted_node(id.clone(), graph.node_weight(index as u32));
        }
        for arc in graph.arcs() {
            if !blocked[arc.tail as usize] && !blocked[arc.head as usize] {
                builder.add_arc(graph.id(arc.tail), graph.id(arc.head), arc.weight);
            }
        }
        builder.build()
    }

    /// Analyze the current event's paths under exact custody observations.
    ///
    /// Unobserved external references default to Unchecked, never Verified or Missing.
    /// Canonical event records already validated by `EvidenceHistoryProjection` need
    /// no extra observation to participate as metadata; an explicit Unchecked or
    /// Unavailable observation still restricts that exact vertex. Verified metadata
    /// cannot seed an unsupported event as an external frontier. Supersession and
    /// non-support relations never become paths. Unavailable vertices are removed
    /// simultaneously, so independent losses can jointly exhaust alternate paths.
    ///
    /// The caller must bind the observations, both witnesses and the original history
    /// to the same authorized read/revalidation scope. Witnesses certify the filtered
    /// graph runs, NOT how an observation was obtained. Unmapped faults still belong
    /// in the caller's custody report. These paths do not certify opaque descendants,
    /// source authenticity, semantic sufficiency, physical independence or event truth.
    ///
    /// # Errors
    ///
    /// Unknown current head, duplicate observations (even equal duplicates), input
    /// admission overflow, graph failure, or either run exhausting the shared budget.
    /// Construction is bounded by the original history graph and observation ceiling;
    /// those costs are separate from the registered algorithm work counters.
    pub fn analyze_current_availability(
        projection: &EvidenceHistoryProjection,
        event_id: &str,
        observations: &[AvailabilityObservation],
        anchor: LedgerAnchor,
        budget: Budget,
    ) -> Result<EvidenceAvailabilityAnalysis, EvidenceProjectionError> {
        if observations.len() > MAX_AVAILABILITY_OBSERVATIONS {
            return Err(GraphError::BudgetExhausted {
                dimension: "availability_observations",
                limit: MAX_AVAILABILITY_OBSERVATIONS as u64,
            }.into());
        }
        let target = *projection.heads().get(event_id)
            .ok_or_else(|| GraphError::UnknownNode(event_id.to_owned()))?;
        let record = projection.records().iter().find(|record| record.revision_digest() == target)
            .ok_or_else(|| GraphError::Inconsistent("current head is not expanded".to_owned()))?;
        let graph = projection.graph();
        let mut seen = BTreeSet::new();
        let mut possible_blocked = vec![false; graph.node_count()];
        let mut verified_blocked = vec![false; graph.node_count()];
        for digest in projection.unexpanded_support() {
            let index = graph.require(&object_node(*digest))? as usize;
            verified_blocked[index] = true;
        }
        let mut mapped = 0;
        for observation in observations {
            if !seen.insert(observation.digest) {
                return Err(GraphError::DuplicateNode(object_node(observation.digest)).into());
            }
            if let Some(index) = graph.index_of(&object_node(observation.digest)) {
                mapped += 1;
                let index = index as usize;
                possible_blocked[index] = observation.availability == ObjectAvailability::Unavailable;
                verified_blocked[index] = observation.availability != ObjectAvailability::Verified;
            }
        }
        let unchecked_frontier_references = projection.unexpanded_support().iter()
            .filter(|digest| graph.index_of(&object_node(**digest)).is_some_and(|index| {
                verified_blocked[index as usize] && !possible_blocked[index as usize]
            })).count();
        let possible_graph = filtered(graph, &possible_blocked, "possible-reference-support:v1")?;
        let possible = dominators::dominators(
            &possible_graph, FRONTIER_ROOT, DominanceDirection::Dominators, budget,
        )?;
        let remaining = Budget::new(
            budget.max_operations.checked_sub(possible.operations).ok_or(GraphError::TooLarge)?,
            budget.max_output_entries.checked_sub(possible.output_entries).ok_or(GraphError::TooLarge)?,
        );
        let verified_graph = filtered(graph, &verified_blocked, "verified-reference-support:v1")?;
        let verified = dominators::dominators(
            &verified_graph, FRONTIER_ROOT, DominanceDirection::Dominators, remaining,
        )?;
        let possible_witness = possible.witness(POSSIBLE_PROJECTION_ID, anchor.clone())
            .map_err(EvidenceProjectionError::Contract)?;
        let verified_witness = verified.witness(VERIFIED_PROJECTION_ID, anchor)
            .map_err(EvidenceProjectionError::Contract)?;
        check_witness(&possible_witness, &dominators::IDENTITY,
            &dominators::bound(possible.node_count, possible.edge_count))?;
        check_witness(&verified_witness, &dominators::IDENTITY,
            &dominators::bound(verified.node_count, verified.edge_count))?;
        let target_node = object_node(target);
        let possible_path = possible.output.immediate_dominators.binary_search_by(
            |(node, _)| node.as_str().cmp(&target_node)).is_ok();
        let verified_path = verified.output.immediate_dominators.binary_search_by(
            |(node, _)| node.as_str().cmp(&target_node)).is_ok();
        if verified_path && !possible_path {
            return Err(GraphError::Inconsistent("verified graph is not a possible-graph subset".to_owned()).into());
        }
        let support = if !record.evidence.iter().any(|edge| edge.counts_as_support()) {
            AvailableSupport::NoDeclaredSupport
        } else if verified_path {
            AvailableSupport::VerifiedReferencePath
        } else if possible_path {
            AvailableSupport::UncheckedReferencePath
        } else {
            AvailableSupport::NoUnblockedReferencePath
        };
        Ok(EvidenceAvailabilityAnalysis {
            target, support, possible_witness, verified_witness,
            mapped_observations: mapped,
            outside_graph_observations: observations.len() - mapped,
            unchecked_frontier_references,
            graph_operations: possible.operations.checked_add(verified.operations).ok_or(GraphError::TooLarge)?,
            graph_output_entries: possible.output_entries.checked_add(verified.output_entries).ok_or(GraphError::TooLarge)?,
        })
    }
}

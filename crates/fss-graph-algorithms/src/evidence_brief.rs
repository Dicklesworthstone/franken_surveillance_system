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

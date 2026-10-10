#![forbid(unsafe_code)]
//! AOP-011 support structure inside the existing agent response, not a new transport.
//!
//! The local reference reader already admits event metadata for the whole deployment. We
//! consume that exact snapshot only; no media is read, no permission is inferred from a graph,
//! and no newly computed receipt is advertised as a retained or hydratable source artifact.

use fss_core::{
    AgentCognitiveEnvelope, AgentView, BudgetVector, Completeness, ContentDigest,
    EnvelopeBudget, EnvelopeProposition, ExplainQuestion, ExplainReceipt, KnowledgeState,
    ResponseOutcome, ResponseSafeRetry,
};
use fss_graph_algorithms::GraphError;
use fss_graph_algorithms::certified::Budget;
use fss_graph_algorithms::evidence::{EvidenceProjectionError, SupportReachability};
use fss_graph_algorithms::evidence_brief::{
    EvidenceSupportBrief, MAX_BRIEF_ENTRIES, explain_current_support,
};
use fss_graph_algorithms::evidence_history::{EvidenceHistoryProjection, HistoryLimits};
use fss_reference::agent_orient::{DeploymentOrientation, DeploymentSnapshot, EventExplanation};

use super::{CAPABILITY_EXPLAIN, ResponseParts, agent_json, build_response, read_only_boundary};

/// One shared allowance across both registered runs, not a per-algorithm refill.
const GRAPH_BUDGET: Budget = Budget::new(2_000_000, 65_536);
/// Extra semantic bytes are also bounded before they join the existing explanation.
const MAX_SEMANTIC_BYTES: usize = 8 * 1024;
/// An independent serialization ceiling, including the newline emitted by the CLI.
pub(super) const MAX_RESPONSE_BYTES: usize = 256 * 1024;

const SCOPE: &str = "Declared positive-support structure only: unexpanded artifact references are not source custody or independent-sensor certificates. No event truth, probability, lifecycle state or effect authority is changed.";
const INVALIDATOR: &str = "Recompute support structure after the ledger anchor, any referenced revision or its current head changes. Old references are never redirected to successors.";
const METER_SCOPE: &str = "Graph work units are not CPU milliseconds; graph and catalogue counts are reported separately. Full-output tokenizer, latency and allocator-peak measurements are unavailable.";
const DECLINED_WORK: &str = "Source hydration, custody verification and full graph expansion in the agent payload were not requested.";
const PROOF_SCOPE: &str = "Graph witnesses and explanation receipts are non-durable, recomputable read products. Their digests are derivation proof pointers, not newly retained objects or available hydration handles.";

#[derive(Debug)]
pub(super) struct SupportReview {
    pub(super) propositions: Vec<EnvelopeProposition>,
    pub(super) assumptions: Vec<String>,
    pub(super) invalidators: Vec<String>,
    pub(super) warnings: Vec<String>,
    pub(super) proof_pointers: Vec<String>,
    pub(super) receipt: ExplainReceipt,
    pub(super) requested: BudgetVector,
    pub(super) consumed: BudgetVector,
    pub(super) cost_statement: String,
}

fn inconsistent(message: &str) -> EvidenceProjectionError {
    GraphError::Inconsistent(message.to_owned()).into()
}

fn proposition(
    target: ContentDigest,
    suffix: &str,
    statement: String,
    state: KnowledgeState,
    evidence: Vec<String>,
) -> EnvelopeProposition {
    EnvelopeProposition {
        id: format!("claim:event-support:{target}:{suffix}"),
        statement,
        state,
        provenance: "derived".to_owned(),
        evidence,
    }
}

/// Complete lists become complete propositions; no ranking, take, truncate or fallback.
fn propositions(brief: &EvidenceSupportBrief) -> Vec<EnvelopeProposition> {
    let target = brief.target.digest;
    let rooted = brief.rooted_witness.digest().to_text();
    let ancestry = brief.ancestry_witness.digest().to_text();
    let mut result = vec![proposition(
        target,
        "structure",
        format!(
            "Current revision {} has support reachability {}; direct relations: {} Supports, {} Contradicts, {} other. These are declared edges, not independent observations.",
            brief.target.revision, brief.reachability.as_str(), brief.direct_support_edges,
            brief.direct_contradictions, brief.direct_other_relations,
        ),
        KnowledgeState::Known,
        vec![target.to_text(), rooted.clone(), ancestry.clone()],
    )];
    if !brief.unexpanded_support.is_empty() {
        result.push(proposition(
            target,
            "unexpanded-references",
            format!(
                "All {} non-event references on positive-support paths are listed here. Their payloads were not hydrated; existence of a reference does not establish availability or independent corroboration.",
                brief.unexpanded_support.len(),
            ),
            KnowledgeState::Known,
            brief.unexpanded_support.iter().map(|digest| digest.to_text()).collect(),
        ));
    }
    let bottlenecks = if brief.reachability != SupportReachability::RootedInUnexpandedReference {
        "No rooted support path exists; an empty bottleneck list is NOT evidence of redundancy, falsity or absence.".to_owned()
    } else if brief.bottleneck_objects.is_empty() {
        "No object other than the target lies on EVERY rooted positive-support path. This describes path alternatives, not independent sensors or satisfied AND/OR proof obligations.".to_owned()
    } else {
        format!(
            "Every rooted positive-support path passes through these {} object identities, listed in frontier-to-target order. Losing one removes all such paths; this is not an automatic event retraction or a physical failure-domain certificate.",
            brief.bottleneck_objects.len(),
        )
    };
    result.push(proposition(
        target,
        "bottlenecks",
        bottlenecks,
        KnowledgeState::Known,
        if brief.bottleneck_objects.is_empty() {
            vec![rooted]
        } else {
            brief.bottleneck_objects.iter().map(|digest| digest.to_text()).collect()
        },
    ));
    for revision in &brief.unsupported_revisions {
        result.push(proposition(
            target,
            &format!("unsupported:{}", revision.digest),
            format!(
                "{} revision {} ({}) is on a positive-support branch but has no declared Supports edges. Any alternate rooted branch does not repair this unsupported leaf; its truth remains a separate question.",
                revision.event_id, revision.revision, revision.state.as_str(),
            ),
            KnowledgeState::Known,
            vec![revision.digest.to_text(), ancestry.clone()],
        ));
    }
    for pair in &brief.superseded_support {
        result.push(proposition(
            target,
            &format!("superseded:{}", pair.referenced.digest),
            format!(
                "Support still names {} revision {} ({}); its current head is revision {} ({}). Both exact digests are retained separately in this statement's evidence. Review the correction; neither a redirect nor invalidation of the dependent event was performed.",
                pair.referenced.event_id, pair.referenced.revision, pair.referenced.state.as_str(),
                pair.current.revision, pair.current.state.as_str(),
            ),
            KnowledgeState::Known,
            vec![pair.referenced.digest.to_text(), pair.current.digest.to_text(), ancestry.clone()],
        ));
    }
    result.push(proposition(
        target,
        "custody-and-independence",
        "This structural query does not establish current source availability or physical sensor independence. Resolve those through their own custody and corroboration evidence; graph reachability supplies neither certificate.".to_owned(),
        KnowledgeState::Unknown,
        vec![target.to_text()],
    ));
    result
}

fn semantic_bytes(review: &SupportReview) -> Result<usize, EvidenceProjectionError> {
    let mut total = 0_usize;
    let mut add = |text: &str| -> Result<(), EvidenceProjectionError> {
        total = total.checked_add(text.len()).ok_or(GraphError::TooLarge)?;
        Ok(())
    };
    for proposition in &review.propositions {
        add(&proposition.id)?;
        add(&proposition.statement)?;
        add(proposition.state.as_str())?;
        add(&proposition.provenance)?;
        for evidence in &proposition.evidence { add(evidence)?; }
    }
    for text in review.assumptions.iter().chain(&review.invalidators).chain(&review.warnings).chain(&review.proof_pointers) {
        add(text)?;
    }
    add(&review.cost_statement)?;
    add(METER_SCOPE)?;
    add(DECLINED_WORK)?;
    Ok(total)
}

fn price(review: &mut SupportReview) -> Result<(), EvidenceProjectionError> {
    let bytes = semantic_bytes(review)?;
    let extra_tokens = (bytes as u64).div_ceil(4);
    let maximum = u64::from(AgentView::DecisionDiff.maximum_tokens());
    let next = review.consumed.tokens.checked_add(extra_tokens).ok_or(GraphError::TooLarge)?;
    if bytes > MAX_SEMANTIC_BYTES || next > maximum {
        return Err(GraphError::BudgetExhausted {
            dimension: "agent_explain_semantic_tokens",
            limit: maximum,
        }.into());
    }
    review.requested.tokens = maximum;
    review.consumed.tokens = next;
    Ok(())
}

/// Compose only from the same verified deployment, orientation and exact current event.
pub(super) fn compile(
    snapshot: &DeploymentSnapshot,
    orientation: &DeploymentOrientation,
    explanation: &EventExplanation,
) -> Result<SupportReview, EvidenceProjectionError> {
    if snapshot.anchor != orientation.capsule().anchor {
        return Err(inconsistent("support explanation anchor mismatch"));
    }
    let target = &explanation.event;
    let selected = snapshot.events.iter().find(|retained| retained.event.event_id == target.event.event_id)
        .ok_or_else(|| inconsistent("explanation event is outside the snapshot"))?;
    if selected.event != target.event || selected.event_root != target.event_root
        || selected.revision_digest != target.revision_digest {
        return Err(inconsistent("support explanation current revision mismatch"));
    }
    for retained in &snapshot.events {
        if retained.revisions.last() != Some(&retained.event)
            || retained.revision_digest != retained.event.revision_digest() {
            return Err(inconsistent("support history head is not its committed chain tail"));
        }
    }
    let lineages: Vec<_> = snapshot.events.iter().map(|retained| retained.revisions.as_slice()).collect();
    let projection = EvidenceHistoryProjection::build(&lineages, HistoryLimits::default())?;
    let brief = explain_current_support(&projection, target.event.event_id.as_str(),
        snapshot.anchor.clone(), GRAPH_BUDGET, MAX_BRIEF_ENTRIES)?;
    compose(&projection, &brief, orientation, explanation)
}

fn compose(
    projection: &EvidenceHistoryProjection,
    brief: &EvidenceSupportBrief,
    orientation: &DeploymentOrientation,
    explanation: &EventExplanation,
) -> Result<SupportReview, EvidenceProjectionError> {
    let receipt = ExplainReceipt::compile(
        ExplainQuestion::Why,
        explanation.event.revision_digest,
        vec![explanation.event.event_root, explanation.receipt.receipt_digest(),
            brief.receipt.receipt_digest(), orientation.capsule().anchor.state_root],
        Vec::new(), 0,
    ).map_err(EvidenceProjectionError::Contract)?;
    let mut warnings = vec![PROOF_SCOPE.to_owned()];
    if !brief.unsupported_revisions.is_empty() {
        warnings.push("At least one support branch terminates at an unsupported event revision; a rooted alternative does not erase that uncertainty.".to_owned());
    }
    if !brief.superseded_support.is_empty() {
        warnings.push("Positive support uses superseded revisions. Their separately identified current heads require review; no dependent event was automatically invalidated.".to_owned());
    }
    let cost_statement = format!(
        "Support analysis consumed {} of {} shared graph operations and {} of {} shared algorithm output entries across two ALG-DOM-001 runs. Catalogue: {} revisions, {} evidence edges, {} canonical bytes; brief: {} of {} identities. Compiler/brief work is separately cardinality-bounded, not included in the graph counters. Added semantic tokens use ceil(UTF-8 field bytes/4), not a model tokenizer or full JSON size.",
        brief.graph_operations, GRAPH_BUDGET.max_operations, brief.graph_output_entries,
        GRAPH_BUDGET.max_output_entries, projection.catalogue_revisions(),
        projection.catalogue_edges(), projection.catalogue_bytes(), brief.brief_entries,
        MAX_BRIEF_ENTRIES,
    );
    let mut review = SupportReview {
        propositions: propositions(brief),
        assumptions: vec![SCOPE.to_owned()],
        invalidators: vec![INVALIDATOR.to_owned()],
        warnings,
        proof_pointers: vec![receipt.receipt_digest().to_text(), brief.receipt.receipt_digest().to_text(),
            brief.rooted_witness.digest().to_text(), brief.ancestry_witness.digest().to_text()],
        receipt,
        requested: orientation.requested,
        consumed: orientation.consumed,
        cost_statement,
    };
    price(&mut review)?;
    Ok(review)
}

pub(super) fn budget(review: &SupportReview) -> EnvelopeBudget {
    EnvelopeBudget {
        requested_json: agent_json::budget(&review.requested),
        consumed_json: agent_json::budget(&review.consumed),
        remaining_json: agent_json::remaining(&review.requested, &review.consumed),
        degraded_dimensions: vec![METER_SCOPE.to_owned()],
        marginal_work_declined: vec![DECLINED_WORK.to_owned()],
    }
}

pub(super) fn refusal_id(error: &EvidenceProjectionError) -> &'static str {
    match error {
        EvidenceProjectionError::Graph(GraphError::BudgetExhausted {
            dimension: "agent_explain_semantic_tokens" | "evidence_brief_entries", ..
        }) => super::ERR_AGENT_CONTEXT_INCOMPLETE,
        _ => error.stable_id(),
    }
}

pub(super) fn refusal(
    orientation: &DeploymentOrientation,
    explanation: &EventExplanation,
    request_digest: ContentDigest,
    error_id: &'static str,
) -> Result<String, Box<dyn std::error::Error>> {
    let capsule = orientation.capsule();
    build_response(ResponseParts {
        operation: "explain", request_digest, principal: capsule.principal_id.clone(),
        session_id: Some(capsule.session_id.as_str().to_owned()),
        mission_id: Some(capsule.mission_id.as_str().to_owned()), anchor: capsule.anchor.clone(),
        view: AgentView::DecisionDiff, capability: CAPABILITY_EXPLAIN,
        outcome: ResponseOutcome::Refused, error_id: Some(error_id),
        payload_schema: AgentCognitiveEnvelope::SCHEMA, payload_json: "null".to_owned(),
        epistemic_state: KnowledgeState::Unknown, completeness: Completeness::Partial,
        warnings: vec!["The requested explanation was not returned; no event was changed or adjudicated, and no missing support was interpreted as absence.".to_owned()],
        contradictions: orientation.contradictions.clone(),
        degradation: vec![
            "The complete support explanation exceeded its bounds or failed its input/witness contract. No dependencies, historical corrections or protected alternatives were truncated.".to_owned(),
            "The reported consumed vector accounts for the existing snapshot orientation only; failed graph work is not reported as zero or as a completed witness.".to_owned(),
            "For a larger operator-local graph report, inspect fss-evidence analyze-history under its separate explicit limits. This is not authorization to bypass an agent privacy projection.".to_owned(),
        ],
        budgets_json: agent_json::budget_summary(&orientation.requested, &orientation.consumed),
        proof_pointers: vec![explanation.event.event_root.to_text(), explanation.event.revision_digest.to_text()],
        affordances: Vec::new(), affordance_objects: Vec::new(),
        decision_fingerprint: request_digest, compression_receipt_id: None, continuation: None,
        recovery_class: "never_unchanged", safe_retry: ResponseSafeRetry::No,
        boundary: read_only_boundary("The committed event was read, but no complete support explanation was emitted.".to_owned()),
        created_at_ns: capsule.created_at.0, workspace_revision: None, idempotency_key: None,
    })
}

#[cfg(test)]
#[path = "evidence_tests.rs"]
mod tests;

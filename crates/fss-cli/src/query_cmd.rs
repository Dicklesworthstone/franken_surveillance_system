#![forbid(unsafe_code)]
//! AOP-005 CLI projection of the bounded, verified event-record query engine.
//!
//! The reference engine owns selection, plans, receipts and continuation validation. This
//! module only parses explicit predicates and renders the registered envelopes. It never
//! certifies physical absence, executes an affordance or changes a deployment.

use std::path::PathBuf;

use fss_core::{
    AgentCognitiveEnvelope, AgentView, BudgetVector, CognitiveAnswerClass, Completeness,
    EnvelopeBudget, EnvelopeContinuity, EnvelopeProposition, EventId, EventKind, EventState,
    KnowledgeState, ResponseOutcome, ResponseSafeRetry,
};
use fss_reference::agent_follow::{AnchorToken, snapshot_anchor_token};
use fss_reference::agent_orient::{
    DeploymentOrientation, DeploymentSnapshot, OrientLimits, OrientRequest, orient_deployment,
    read_deployment,
};
use fss_reference::agent_query::{
    CAPABILITY_QUERY, DEFAULT_QUERY_ENTRIES, DeploymentQuery, EventQueryFilter, EventQueryRequest,
    MAX_QUERY_ENTRIES, QueryError, query_deployment,
};

use crate::agent_json;
use crate::error::{CliError, ExitIdentity};
use crate::orient_cmd::{
    ERR_AGENT_CONTEXT_INCOMPLETE, RenderError, ResponseParts, build_response, collect_options,
    contexts, internal_failure, principal, read_only_boundary, read_refusal, rendered,
    request_identity, required_root, take,
};
use crate::token::ArgToken;

/// Maximum complete response size, including context and JSON escaping. This is a byte
/// ceiling, not token metering. An oversized response is refused, never truncated.
pub const MAX_QUERY_OUTPUT_BYTES: usize = 256 * 1024;

/// Options for an exact bounded metadata read; the principal is an audit label.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryArgs {
    /// Existing deployment root; read-only.
    pub root: PathBuf,
    /// Native query request, including any exact anchor and continuation preconditions.
    pub request: EventQueryRequest,
}

fn malformed(option: &str, value: &str, reason: &str, index: usize) -> CliError {
    CliError::MalformedValue {
        option: option.to_owned(),
        value: value.to_owned(),
        reason: reason.to_owned(),
        command: Some("query".to_owned()),
        index,
    }
}

fn number<T: std::str::FromStr + ToString>(
    option: &str,
    value: &str,
    index: usize,
) -> Result<T, CliError> {
    let parsed = value
        .parse::<T>()
        .map_err(|_| malformed(option, value, "expected an integer in range", index))?;
    if parsed.to_string() != value {
        return Err(malformed(
            option,
            value,
            "expected canonical decimal spelling",
            index,
        ));
    }
    Ok(parsed)
}

/// Parses exact conjunctive filters. No natural language, raw offsets, mutation flags or
/// unimplemented query mode is accepted. Time endpoints are independently optional.
pub fn parse_query_args(tokens: &[ArgToken]) -> Result<QueryArgs, CliError> {
    let values = collect_options(
        "query",
        tokens,
        &[
            "--root",
            "--principal",
            "--event-id",
            "--kind",
            "--zone",
            "--state",
            "--from-ns",
            "--through-ns",
            "--max-entries",
            "--anchor",
            "--continuation",
        ],
    )?;
    let event_id = take(&values, "--event-id")
        .map(|(_, value, index)| {
            EventId::parse(value.clone())
                .map_err(|_| malformed("--event-id", value, "invalid event identity", *index))
        })
        .transpose()?;
    let kind = take(&values, "--kind")
        .map(|(_, value, index)| {
            EventKind::parse(value)
                .map_err(|_| malformed("--kind", value, "unknown event kind", *index))
        })
        .transpose()?;
    let state = take(&values, "--state")
        .map(|(_, value, index)| {
            EventState::parse(value)
                .map_err(|_| malformed("--state", value, "unknown lifecycle state", *index))
        })
        .transpose()?;
    let from_ns = take(&values, "--from-ns")
        .map(|(_, value, index)| number::<i128>("--from-ns", value, *index))
        .transpose()?;
    let through_ns = take(&values, "--through-ns")
        .map(|(_, value, index)| number::<i128>("--through-ns", value, *index))
        .transpose()?;
    let max_entries = take(&values, "--max-entries")
        .map(|(_, value, index)| number::<u32>("--max-entries", value, *index))
        .transpose()?
        .unwrap_or(DEFAULT_QUERY_ENTRIES);
    if !(1..=MAX_QUERY_ENTRIES).contains(&max_entries) {
        return Err(malformed(
            "--max-entries",
            &max_entries.to_string(),
            "expected 1..32",
            0,
        ));
    }
    let expected_anchor = take(&values, "--anchor")
        .map(|(_, value, index)| {
            AnchorToken::parse(value).ok_or_else(|| {
                malformed("--anchor", value, "expected an exact anchor token", *index)
            })
        })
        .transpose()?;
    let request = EventQueryRequest {
        filter: EventQueryFilter {
            event_id,
            kind,
            state,
            zone: take(&values, "--zone").map(|(_, value, _)| value.clone()),
            from_ns,
            through_ns,
        },
        principal: principal("query", &values)?,
        max_entries,
        expected_anchor,
        continuation: take(&values, "--continuation").map(|(_, value, _)| value.clone()),
    };
    request
        .validate()
        .map_err(|error| malformed("query", "[redacted]", &error.to_string(), 0))?;
    Ok(QueryArgs {
        root: required_root("query", &values)?,
        request,
    })
}

fn query_response(
    args: &QueryArgs,
    query: &DeploymentQuery,
    orientation: &DeploymentOrientation,
) -> Result<String, Box<dyn std::error::Error>> {
    let request_digest = query.request_digest;
    let text = request_digest.to_text();
    let hex = text.strip_prefix("sha256:").unwrap_or(&text);
    let capsule = orientation.capsule();
    let next = query
        .page
        .next_cursor
        .as_ref()
        .map(|cursor| cursor.token().to_owned());
    let mut epistemic = query.epistemic();
    epistemic.propositions.push(EnvelopeProposition {
        id: "claim:query:anchor".to_owned(),
        statement: format!(
            "Exact authority/effect-history token: {}",
            query.anchor_token
        ),
        state: KnowledgeState::Known,
        provenance: "derived".to_owned(),
        evidence: vec![query.selection_witness.to_text()],
    });
    // Filtering a catalogue must not remove unrelated critical deployment context. Use the
    // existing bounded orientation, including coverage, tamper, contradictions and effects.
    epistemic
        .propositions
        .extend(capsule.frame.knowledge_cells.iter().map(|cell| {
            EnvelopeProposition {
                id: cell.claim_id().to_owned(),
                statement: cell.disclosable_statement().to_owned(),
                state: cell.knowledge_state(),
                provenance: cell.provenance().as_str().to_owned(),
                evidence: cell
                    .evidence_digests()
                    .iter()
                    .map(|digest| digest.to_text())
                    .collect(),
            }
        }));
    let handles: Vec<_> = query
        .events
        .iter()
        .map(|row| agent_json::EvidenceHandle {
            handle_id: format!("fss://proof/{}", row.event_root),
            object_digest: row.event_root,
            kind: "event_manifest".to_owned(),
            hydration: "H0",
            allowed_hydration: vec!["H0"],
            privacy_class: "private:property".to_owned(),
            availability: "available",
            estimated_cost: BudgetVector::default(),
            required_capability: Some(CAPABILITY_QUERY.to_owned()),
        })
        .collect();
    let (_, affordance_context) = contexts(orientation);
    // Context-refresh actions plus explicit per-hit explanations fit the schema's 64-action
    // ceiling (32 hits + 3 context reads). Do not execute or synthesize affordances.
    let action_ids: Vec<String> = capsule
        .affordances
        .iter()
        .filter(|action| {
            matches!(
                action.affordance_id.as_str(),
                "affordance:orient:reorient"
                    | "affordance:orient:doctor"
                    | "affordance:orient:follow"
            ) || query.events.iter().any(|row| {
                action.affordance_id
                    == format!("affordance:explain:{}", row.event.event_id.as_str())
            })
        })
        .map(|action| action.affordance_id.clone())
        .collect();
    let action_objects =
        agent_json::affordance_objects(&action_ids, &capsule.affordances, &affordance_context)
            .ok_or(RenderError("query affordance objects"))?;
    let frame_digest = capsule.frame.frame_digest()?;
    let decision = request_identity("fss.cli.query.context_decision.v1", |encoder| {
        encoder.digest(query.decision_digest);
        encoder.digest(frame_digest);
    });
    let cognitive = AgentCognitiveEnvelope::new(
        capsule.contract_basis.clone(),
        format!("request:query:{hex}"),
        format!("response:query:{hex}"),
        format!("trace:query:{hex}"),
        "query",
        "query",
        AgentView::Case.id(),
        CognitiveAnswerClass::BoundedSummary,
        capsule.anchor.clone(),
        epistemic,
        query.coverage(),
        EnvelopeBudget {
            requested_json: agent_json::budget(&orientation.requested),
            consumed_json: agent_json::budget(&orientation.consumed),
            remaining_json: agent_json::remaining(&orientation.requested, &orientation.consumed),
            degraded_dimensions: vec!["query-cpu-and-output-tokens-not-metered".to_owned()],
            marginal_work_declined: Vec::new(),
        },
        handles
            .iter()
            .map(|handle| handle.handle_id.clone())
            .collect(),
        action_ids.clone(),
        EnvelopeContinuity {
            cursor: next.clone(),
            reanchor_triggers: vec!["Any authority or effect-journal advance.".to_owned()],
            session_capsule_digest: None,
            unresolved_obligations: capsule
                .obligations
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect(),
        },
        decision.to_text(),
    )?;
    let payload = agent_json::cognitive_envelope(&cognitive, &handles, &action_objects)
        .ok_or(RenderError("query cognitive envelope"))?;
    build_response(ResponseParts {
        operation: "query",
        request_digest,
        principal: args.request.principal.clone(),
        session_id: Some(query.session_id.as_str().to_owned()),
        mission_id: Some(query.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(),
        view: AgentView::Case,
        capability: CAPABILITY_QUERY,
        outcome: if next.is_some() { ResponseOutcome::Partial } else { ResponseOutcome::Ok },
        error_id: None,
        payload_schema: AgentCognitiveEnvelope::SCHEMA,
        payload_json: payload,
        epistemic_state: KnowledgeState::Unknown,
        completeness: Completeness::Bounded,
        warnings: vec!["Metadata-only query; no certified physical absence or effect authority.".to_owned()],
        contradictions: orientation.contradictions.clone(),
        degradation: vec!["Query CPU, output tokens and elapsed latency are not metered. The native latency allowance is not a measurement or enforced deadline.".to_owned()],
        budgets_json: agent_json::budget_summary(&orientation.requested, &orientation.consumed),
        proof_pointers: vec![query.plan.plan_digest().to_text(), query.admission.receipt_digest().to_text(),
            query.selection_witness.to_text(), query.page.page_digest.to_text(), frame_digest.to_text()],
        affordances: action_ids,
        affordance_objects: action_objects,
        decision_fingerprint: decision,
        compression_receipt_id: None,
        continuation: next,
        recovery_class: "safe_read_retry",
        safe_retry: ResponseSafeRetry::YesSameRequest,
        boundary: read_only_boundary("Compiled exact filters and read one event-record page with protected deployment context.".to_owned()),
        created_at_ns: capsule.created_at.0,
        workspace_revision: None,
        idempotency_key: None,
    })
}

fn refusal(
    args: &QueryArgs,
    snapshot: &DeploymentSnapshot,
    reason: &str,
    rebase: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let digest = request_identity("fss.cli.query.refusal.v1", |encoder| {
        encoder.text(&args.request.filter.description());
        encoder.text(args.request.principal.as_str());
        encoder.u32(args.request.max_entries);
        encoder.text(
            args.request
                .expected_anchor
                .as_ref()
                .map_or("", AnchorToken::as_str),
        );
        encoder.text(args.request.continuation.as_deref().unwrap_or(""));
        encoder.text(&snapshot_anchor_token(snapshot));
        encoder.text(reason);
    });
    build_response(ResponseParts {
        operation: "query", request_digest: digest, principal: args.request.principal.clone(),
        session_id: None, mission_id: None, anchor: snapshot.anchor.clone(), view: AgentView::Case,
        capability: CAPABILITY_QUERY, outcome: ResponseOutcome::Refused,
        error_id: Some(ERR_AGENT_CONTEXT_INCOMPLETE), payload_schema: AgentCognitiveEnvelope::SCHEMA,
        payload_json: "null".to_owned(), epistemic_state: KnowledgeState::Unknown,
        completeness: Completeness::Partial, warnings: vec![reason.to_owned()], contradictions: Vec::new(),
        degradation: vec!["No query result was delivered; refusal is not an empty match set. Resource use for this refused read is not metered.".to_owned()],
        budgets_json: agent_json::budget_summary(&BudgetVector::default(), &BudgetVector::default()),
        proof_pointers: Vec::new(), affordances: Vec::new(), affordance_objects: Vec::new(),
        decision_fingerprint: digest, compression_receipt_id: None, continuation: None,
        recovery_class: if rebase { "rebase_required" } else { "operator_action_required" },
        safe_retry: ResponseSafeRetry::No,
        boundary: read_only_boundary("Read refused; refresh the anchor or narrow the admitted bound.".to_owned()),
        created_at_ns: snapshot.latest_evidence_time.0, workspace_revision: None, idempotency_key: None,
    })
}

/// Reads one verified snapshot, invokes the native query engine, and renders one complete
/// registered answer. Neither a smaller page nor an empty match set bypasses a scan failure.
#[must_use]
pub fn execute_query(args: &QueryArgs) -> (String, ExitIdentity) {
    let limits = OrientLimits::default();
    let snapshot = match read_deployment(&args.root, &limits) {
        Ok(snapshot) => snapshot,
        Err(error) => return read_refusal("query", &args.root, &error),
    };
    let query = match query_deployment(&snapshot, &args.request) {
        Ok(query) => query,
        Err(error) => {
            return rendered(
                refusal(
                    args,
                    &snapshot,
                    &error.to_string(),
                    matches!(
                        error,
                        QueryError::Continuation(_) | QueryError::AnchorChanged
                    ),
                ),
                ExitIdentity::AGENT_REFUSED,
                "query",
                &args.root,
            );
        }
    };
    let orient_request = OrientRequest {
        view: AgentView::Brief,
        principal: args.request.principal.clone(),
        budget_tokens: None,
    };
    let orientation = match orient_deployment(&snapshot, &orient_request, &limits) {
        Ok(orientation) => orientation,
        Err(error) => {
            return rendered(
                refusal(args, &snapshot, &error.to_string(), false),
                ExitIdentity::AGENT_REFUSED,
                "query",
                &args.root,
            );
        }
    };
    match query_response(args, &query, &orientation) {
        Ok(output) if output.len() <= MAX_QUERY_OUTPUT_BYTES => (output, ExitIdentity::SUCCESS),
        Ok(_) => rendered(
            refusal(
                args,
                &snapshot,
                "Complete query response exceeds 256 KiB; reduce --max-entries. Nothing was truncated.",
                false,
            ),
            ExitIdentity::AGENT_REFUSED,
            "query",
            &args.root,
        ),
        Err(_) => internal_failure("query", &args.root),
    }
}

#[cfg(test)]
mod tests;

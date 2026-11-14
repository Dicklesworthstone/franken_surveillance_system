#![forbid(unsafe_code)]
//! Canonical CLI/MCP discovery of retained source inventory and historical continuity metadata.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use fss_core::{
    AgentCognitiveEnvelope, AgentView, BudgetVector, CanonicalEncode, CognitiveAnswerClass,
    Completeness, ContextAuthority, EnvelopeBudget, EnvelopeContinuity, EnvelopeProposition,
    KnowledgeState, OperationId, ResponseOutcome, ResponseSafeRetry, RootAuthoritySpec,
    SensorId, StreamId, TimestampNs,
};
use fss_reference::ReplayCx;
use fss_reference::agent_follow::AnchorToken;
use fss_reference::agent_orient::{DeploymentOrientation, OrientRequest, orient_deployment};
use fss_reference::agent_query::CAPABILITY_QUERY;
use fss_reference::agent_sources::{
    DEFAULT_SOURCES_QUERY_ENTRIES, DeploymentSourcesQuery, SourcesQueryError,
    SourcesQueryFilter, SourcesQueryLimits, SourcesQueryRequest,
    query_sources,
};

use crate::agent_json;
use crate::error::{CliError, ExitIdentity};
use crate::orient_cmd::{
    ERR_AGENT_CONTEXT_INCOMPLETE, RenderError, ResponseParts, build_sources_response,
    collect_options, contexts, execution_diagnostic, internal_failure, principal,
    read_only_boundary, rendered, request_identity, required_root, take,
};
use crate::query_cmd::MAX_QUERY_OUTPUT_BYTES;
use crate::token::ArgToken;

const READ_DEADLINE: Duration = Duration::from_secs(60);

/// Bounded metadata discovery; no source-read or inference permission is inferred.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourcesQueryArgs {
    /// Exact existing absolute deployment root, never initialized or recovered.
    pub root: PathBuf,
    /// Typed sensor/stream selection and exact native continuation.
    pub request: SourcesQueryRequest,
    /// One aggregate metadata allowance through final revalidation.
    pub limits: SourcesQueryLimits,
}

fn malformed(option: &str, reason: &str, index: usize) -> CliError {
    CliError::MalformedValue {
        option: option.to_owned(),
        value: "[redacted]".to_owned(),
        reason: reason.to_owned(),
        command: Some("query".to_owned()),
        index,
    }
}

fn number<T: std::str::FromStr + ToString>(
    text: &str,
    option: &str,
    index: usize,
) -> Result<T, CliError> {
    text.parse::<T>()
        .ok()
        .filter(|value| value.to_string() == text)
        .ok_or_else(|| {
            malformed(
                option,
                "expected a canonical decimal integer in range",
                index,
            )
        })
}

/// Closed source-inventory grammar. Filters do not bypass the complete-index bounds.
pub fn parse_sources_query_args(
    tokens: &[ArgToken],
) -> Result<SourcesQueryArgs, CliError> {
    let values = collect_options(
        "query",
        tokens,
        &[
            "--target",
            "--root",
            "--principal",
            "--sensor",
            "--stream",
            "--max-entries",
            "--anchor",
            "--continuation",
            "--max-query-read-bytes",
            "--max-query-read-objects",
            "--max-query-results",
        ],
    )?;
    match take(&values, "--target") {
        Some((_, target, _)) if target == "sources" => {}
        Some((_, _, index)) => return Err(malformed("--target", "expected sources", *index)),
        None => {
            return Err(CliError::MissingValue {
                option: "--target".to_owned(),
                command: Some("query".to_owned()),
                expected: "sources for retained source inventory discovery".to_owned(),
            });
        }
    }
    let sensor_id = take(&values, "--sensor")
        .map(|(_, text, index)| SensorId::parse(text.clone()).map_err(|_| malformed("--sensor", "expected an exact sensor identity", *index)))
        .transpose()?;
    let stream_id = take(&values, "--stream")
        .map(|(_, text, index)| StreamId::parse(text.clone()).map_err(|_| malformed("--stream", "expected an exact stream identity", *index)))
        .transpose()?;
    let max_entries = take(&values, "--max-entries")
        .map(|(_, text, index)| number::<u32>(text, "--max-entries", *index))
        .transpose()?
        .unwrap_or(DEFAULT_SOURCES_QUERY_ENTRIES);
    let expected_anchor = take(&values, "--anchor")
        .map(|(_, text, index)| {
            AnchorToken::parse(text).ok_or_else(|| {
                malformed(
                    "--anchor",
                    "expected exact current deployment anchor token",
                    *index,
                )
            })
        })
        .transpose()?;
    let request = SourcesQueryRequest {
        filter: SourcesQueryFilter {
            sensor_id,
            stream_id,
        },
        principal: principal("query", &values)?,
        max_entries,
        expected_anchor,
        continuation: take(&values, "--continuation").map(|(_, text, _)| text.clone()),
    };
    request
        .validate()
        .map_err(|_| malformed("query", "invalid bounded source inventory request", 0))?;
    let mut limits = SourcesQueryLimits::default();
    for (name, value) in [
        ("--max-query-read-bytes", &mut limits.read.max_read_bytes),
        (
            "--max-query-read-objects",
            &mut limits.read.max_read_objects,
        ),
        ("--max-query-results", &mut limits.max_streams),
    ] {
        if let Some((_, text, index)) = take(&values, name) {
            *value = number::<usize>(text, name, *index)?;
        }
    }
    limits
        .validate()
        .map_err(|_| malformed("query", "source inventory allowance outside bounds", 0))?;
    let root = required_root("query", &values)?;
    if !root.is_absolute()
        || root.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(malformed(
            "--root",
            "an exact absolute deployment root is required",
            0,
        ));
    }
    Ok(SourcesQueryArgs {
        root,
        request,
        limits,
    })
}

fn response(
    args: &SourcesQueryArgs,
    query: &DeploymentSourcesQuery,
    orientation: &DeploymentOrientation,
) -> Result<String, Box<dyn std::error::Error>> {
    let request_text = query.request_digest.to_text();
    let hex = request_text
        .strip_prefix("sha256:")
        .unwrap_or(&request_text);
    let capsule = orientation.capsule();
    let next = query
        .page
        .next_cursor
        .as_ref()
        .map(|cursor| cursor.token().to_owned());
    let mut epistemic = query.epistemic();
    epistemic.propositions.push(EnvelopeProposition {
        id: "claim:sources-query:deployment-anchor".to_owned(),
        statement: format!(
            "Exact current authority/effect-history token: {}",
            query.anchor_token
        ),
        state: KnowledgeState::Known,
        provenance: "derived".to_owned(),
        evidence: vec![query.selection_witness.to_text()],
    });
    // A filtered discovery page must retain urgent and uncertain deployment context.
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
    let mut metadata = BTreeMap::new();
    for row in &query.rows {
        for digest in &row.capsule_metadata {
            metadata.insert(*digest, fss_reference::reference_deployment::FAMILY_SENSOR_CAPSULE.to_owned());
        }
    }
    let handles: Vec<_> = metadata
        .into_iter()
        .map(|(digest, kind)| agent_json::EvidenceHandle {
            handle_id: format!("fss://proof/{digest}"),
            object_digest: digest,
            kind,
            hydration: "H0",
            allowed_hydration: vec!["H0"],
            privacy_class: "private:property".to_owned(),
            availability: "available",
            estimated_cost: BudgetVector::default(),
            required_capability: Some(CAPABILITY_QUERY.to_owned()),
        })
        .collect();
    let (_, affordance_context) = contexts(orientation);
    let action_ids: Vec<_> = capsule
        .affordances
        .iter()
        .filter(|action| {
            matches!(
                action.affordance_id.as_str(),
                "affordance:orient:reorient"
                    | "affordance:orient:doctor"
                    | "affordance:orient:follow"
            )
        })
        .map(|action| action.affordance_id.clone())
        .collect();
    let action_objects =
        agent_json::affordance_objects(&action_ids, &capsule.affordances, &affordance_context)
            .ok_or(RenderError("source inventory affordance objects"))?;
    let frame_digest = capsule.frame.frame_digest()?;
    let decision = request_identity(
        "fss.cli.sources_query.context_decision.v1",
        |encoder| {
            encoder.digest(query.decision_digest);
            encoder.digest(frame_digest);
        },
    );
    let allowance = args.limits.allowance()?;
    let mut requested = orientation.requested;
    requested.latency_ms = allowance.latency_ms;
    requested.bytes = allowance.bytes;
    requested.storage_operations = allowance.storage_operations;
    let mut consumed = orientation.consumed;
    consumed.bytes = query.read_usage.read_bytes;
    consumed.storage_operations = query.read_usage.read_objects;
    let cognitive = AgentCognitiveEnvelope::new(
        capsule.contract_basis.clone(), format!("request:query:{hex}"), format!("response:query:{hex}"),
        format!("trace:query:{hex}"), "query", "query", AgentView::Case.id(),
        CognitiveAnswerClass::BoundedSummary, capsule.anchor.clone(), epistemic, query.coverage(),
        EnvelopeBudget {
            requested_json: agent_json::budget(&requested), consumed_json: agent_json::budget(&consumed),
            remaining_json: agent_json::remaining(&requested, &consumed),
            degraded_dimensions: vec!["query-cpu-and-output-tokens-not-metered".to_owned()],
            marginal_work_declined: Vec::new(),
        }, handles.iter().map(|handle| handle.handle_id.clone()).collect(), action_ids.clone(),
        EnvelopeContinuity {
            cursor: next.clone(),
            reanchor_triggers: vec!["Any authority/effect prefix, metadata custody, publication, deletion, query scope or allowance change.".to_owned()],
            session_capsule_digest: None,
            unresolved_obligations: capsule.obligations.iter().map(|id| id.as_str().to_owned()).collect(),
        }, decision.to_text(),
    )?;
    let payload = agent_json::cognitive_envelope(&cognitive, &handles, &action_objects)
        .ok_or(RenderError("source inventory cognitive envelope"))?;
    let mut warnings = orientation.warnings.clone();
    warnings.push("Retained source metadata only. Historical continuity and heuristic diagnostics do not establish present camera health, physical coverage, absence, origin authentication or source-byte availability. Only representative capsule-metadata handles are returned; they grant no ReadMedia authority. Original media and model bytes were not read or disclosed.".to_owned());
    build_sources_response(ResponseParts {
        operation: "query", request_digest: query.request_digest, principal: args.request.principal.clone(),
        session_id: Some(query.session_id.as_str().to_owned()), mission_id: Some(query.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(), view: AgentView::Case, capability: CAPABILITY_QUERY,
        outcome: if next.is_some() { ResponseOutcome::Partial } else { ResponseOutcome::Ok },
        error_id: None, payload_schema: AgentCognitiveEnvelope::SCHEMA, payload_json: payload,
        epistemic_state: KnowledgeState::Unknown, completeness: Completeness::Bounded, warnings,
        contradictions: orientation.contradictions.clone(),
        degradation: vec!["CPU time, full output tokens and elapsed latency are not metered. The 60-second deadline is cooperative. Payload bytes and read attempts share one metadata balance through final revalidation; they are not filesystem syscall counts or an atomic read lease.".to_owned()],
        budgets_json: agent_json::budget_summary(&requested, &consumed),
        proof_pointers: vec![query.plan.plan_digest().to_text(), query.admission.receipt_digest().to_text(), query.selection_witness.to_text(), query.page.page_digest.to_text(), frame_digest.to_text()],
        affordances: action_ids, affordance_objects: action_objects, decision_fingerprint: decision,
        compression_receipt_id: None, continuation: next,
        recovery_class: "safe_read_retry", safe_retry: ResponseSafeRetry::YesSameRequest,
        boundary: read_only_boundary("Verified retained source capsule metadata, historical continuity and protected deployment context under one bounded read allowance, with final cooperative revalidation. No source-media reads, model execution, publisher locks, recovery or writes.".to_owned()),
        created_at_ns: capsule.created_at.0, workspace_revision: None, idempotency_key: None,
    })
}

fn refusal(
    args: &SourcesQueryArgs,
    query: &DeploymentSourcesQuery,
    reason: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let digest = request_identity("fss.cli.sources_query.refusal.v1", |encoder| {
        encoder.digest(query.request_digest);
        encoder.text(reason);
    });
    build_sources_response(ResponseParts {
        operation: "query", request_digest: digest, principal: args.request.principal.clone(), session_id: None, mission_id: None,
        anchor: query.snapshot.anchor.clone(), view: AgentView::Case, capability: CAPABILITY_QUERY,
        outcome: ResponseOutcome::Refused, error_id: Some(ERR_AGENT_CONTEXT_INCOMPLETE),
        payload_schema: AgentCognitiveEnvelope::SCHEMA, payload_json: "null".to_owned(), epistemic_state: KnowledgeState::Unknown,
        completeness: Completeness::Partial, warnings: vec![reason.to_owned()], contradictions: Vec::new(),
        degradation: vec!["No source inventory was delivered. Refusal is not an empty match set; refused-read resource accounting is not reported.".to_owned()],
        budgets_json: agent_json::budget_summary(&BudgetVector::default(), &BudgetVector::default()), proof_pointers: Vec::new(),
        affordances: Vec::new(), affordance_objects: Vec::new(), decision_fingerprint: digest,
        compression_receipt_id: None, continuation: None, recovery_class: "operator_action_required", safe_retry: ResponseSafeRetry::No,
        boundary: read_only_boundary("Source inventory refused without a partial page or media disclosure.".to_owned()),
        created_at_ns: query.snapshot.latest_evidence_time.0, workspace_revision: None, idempotency_key: None,
    })
}

fn diagnostic(args: &SourcesQueryArgs, error: SourcesQueryError) -> (String, ExitIdentity) {
    let (code, exit) = match error {
        SourcesQueryError::InvalidRequest(_) => (
            crate::ERR_CLI_MALFORMED_VALUE,
            ExitIdentity::MALFORMED_VALUE,
        ),
        _ => (ERR_AGENT_CONTEXT_INCOMPLETE, ExitIdentity::AGENT_REFUSED),
    };
    (execution_diagnostic("query", &args.root, code, exit), exit)
}

/// Execute native source inventory for both transports while preserving protected context.
#[must_use]
pub fn execute_sources_query(args: &SourcesQueryArgs) -> (String, ExitIdentity) {
    let allowance = match args.limits.allowance() {
        Ok(value) => value,
        Err(error) => return diagnostic(args, error),
    };
    let input = request_identity(
        "fss.cli.sources_query.metadata_authority.v1",
        |encoder| {
            args.request.principal.encode_canonical(encoder);
            args.request.filter.encode_canonical(encoder);
            encoder.u32(args.request.max_entries);
            encoder.text(args.request.continuation.as_deref().unwrap_or(""));
            encoder.text(
                args.request
                    .expected_anchor
                    .as_ref()
                    .map_or("", AnchorToken::as_str),
            );
            encoder.u64(args.limits.read.max_read_bytes as u64);
            encoder.u64(args.limits.read.max_read_objects as u64);
            encoder.u64(args.limits.max_streams as u64);
        },
    );
    let authority = match OperationId::parse("operation:sources-query")
        .map_err(|_| ())
        .and_then(|operation_id| {
            ContextAuthority::new_root(RootAuthoritySpec {
                trace_id: "trace:sources-query".to_owned(),
                operation_id,
                principal: args.request.principal.as_str().to_owned(),
                capabilities: vec![CAPABILITY_QUERY.to_owned(), "ADP-REPLAY-001".to_owned()],
                deadline: Some(TimestampNs(60_000_000_000)),
                priority: 10,
                budgets: allowance,
                privacy_scope: "privacy:source-metadata".to_owned(),
                retention_scope: "retention:current-deletion-restrictions".to_owned(),
                anchor_universe: input,
                generation: 1,
            })
            .map_err(|_| ())
        }) {
        Ok(authority) => authority,
        Err(()) => return internal_failure("query", &args.root),
    };
    let cx = match ReplayCx::from_context_authority_read_only(&authority, &args.root) {
        Ok(cx) => cx,
        Err(_) => return diagnostic(args, SourcesQueryError::Unauthorized),
    };
    let started = Instant::now();
    let result = query_sources(&args.root, &args.request, args.limits, &cx, &|| {
        authority.cancellation_reason.is_some() || started.elapsed() >= READ_DEADLINE
    });
    cx.drain_and_finalize();
    let query = match result {
        Ok(query) => query,
        Err(error) => return diagnostic(args, error),
    };
    let orientation = match orient_deployment(
        &query.snapshot,
        &OrientRequest {
            view: AgentView::Brief,
            principal: args.request.principal.clone(),
            budget_tokens: None,
        },
        &args.limits.read.snapshot,
    ) {
        Ok(orientation) => orientation,
        Err(error) => {
            return rendered(
                refusal(args, &query, &error.to_string()),
                ExitIdentity::AGENT_REFUSED,
                "query",
                &args.root,
            );
        }
    };
    match response(args, &query, &orientation) {
        Ok(output)
            if output.len() <= MAX_QUERY_OUTPUT_BYTES && started.elapsed() < READ_DEADLINE =>
        {
            (output, ExitIdentity::SUCCESS)
        }
        Ok(_) => rendered(
            refusal(
                args,
                &query,
                "Complete sources-query response exceeded 256 KiB or the cooperative deadline. No result prefix was delivered; reduce --max-entries or the complete-index allowance.",
            ),
            ExitIdentity::AGENT_REFUSED,
            "query",
            &args.root,
        ),
        Err(_) => internal_failure("query", &args.root),
    }
}

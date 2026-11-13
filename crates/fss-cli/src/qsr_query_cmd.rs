#![forbid(unsafe_code)]
//! Canonical CLI/MCP QSR query over exact retained screened detector evidence.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use fss_core::{
    AgentCognitiveEnvelope, AgentView, BudgetVector, CognitiveAnswerClass, Completeness,
    ContentDigest, ContextAuthority, EnvelopeBudget, EnvelopeContinuity, EnvelopeProposition,
    KnowledgeState, OperationId, ResponseOutcome, ResponseSafeRetry, RootAuthoritySpec,
    TimestampNs,
};
use fss_reference::agent_follow::AnchorToken;
use fss_reference::agent_orient::{DeploymentOrientation, OrientRequest, orient_deployment};
use fss_reference::agent_qsr::{
    DeploymentQsrQuery, QsrQueryError, QsrQueryLimits, QsrQueryRequest, QsrSourceReadPermit,
    query_qsr_in_deployment,
};
use fss_reference::agent_query::CAPABILITY_QUERY;
use fss_reference::ingest::qsr_observations::{QsrConfig, QsrZoneBinding, QsrZoneRole};

use crate::agent_json;
use crate::error::{CliError, ExitIdentity};
use crate::json_input::{self, Value};
use crate::orient_cmd::{
    ERR_AGENT_CONTEXT_INCOMPLETE, RenderError, ResponseParts, build_qsr_response, collect_options,
    contexts, execution_diagnostic, internal_failure, principal, read_only_boundary, rendered,
    request_identity, required_root, take,
};
use crate::query_cmd::MAX_QUERY_OUTPUT_BYTES;
use crate::token::ArgToken;

const READ_DEADLINE: Duration = Duration::from_secs(60);

/// Exact QSR read, with a separate local permission for internal source verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QsrQueryArgs {
    /// Existing deployment, inspected without locks, recovery or writes.
    pub root: PathBuf,
    /// Exact screened report and bounded annotations.
    pub request: QsrQueryRequest,
    /// One aggregate payload-read balance including final revalidation.
    pub limits: QsrQueryLimits,
    /// Explicit operator consent, checked again for directly constructed Rust requests.
    pub verify_qsr_source: bool,
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

fn required<'a>(
    values: &'a [(String, String, usize)],
    name: &str,
) -> Result<(&'a str, usize), CliError> {
    take(values, name)
        .map(|(_, value, index)| (value.as_str(), *index))
        .ok_or_else(|| CliError::MissingValue {
            option: name.to_owned(),
            command: Some("query".to_owned()),
            expected: format!("explicit {name} for an exact QSR query"),
        })
}

fn zone(value: Option<&Value>, option: &str, index: usize) -> Result<String, CliError> {
    value
        .and_then(Value::text)
        .filter(|value| {
            (1..=64).contains(&value.len())
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        })
        .map(str::to_owned)
        .ok_or_else(|| {
            malformed(
                option,
                "zone IDs require one to 64 ASCII letters, digits, underscores or hyphens",
                index,
            )
        })
}

fn inline(text: &str, option: &str, index: usize) -> Result<Value, CliError> {
    if text.len() > 16 * 1024 {
        return Err(malformed(option, "inline selector exceeds 16 KiB", index));
    }
    json_input::parse(text).map_err(|_| malformed(option, "invalid bounded inline JSON", index))
}

fn config(values: &[(String, String, usize)]) -> Result<QsrConfig, CliError> {
    let mut config = QsrConfig::default();
    if let Some((_, text, index)) = take(values, "--zone-roles") {
        let input = inline(text, "--zone-roles", *index)?;
        let rows = input
            .array()
            .filter(|rows| rows.len() <= 16)
            .ok_or_else(|| {
                malformed(
                    "--zone-roles",
                    "expected at most 16 zone/role objects",
                    *index,
                )
            })?;
        for row in rows {
            let object = row
                .object()
                .filter(|object| {
                    object.len() == 2 && object.contains_key("zone") && object.contains_key("role")
                })
                .ok_or_else(|| {
                    malformed(
                        "--zone-roles",
                        "each object contains only zone and role",
                        *index,
                    )
                })?;
            let role = match object.get("role").and_then(Value::text) {
                Some("area") => QsrZoneRole::Area,
                Some("queue") => QsrZoneRole::Queue,
                Some("register") => QsrZoneRole::Register,
                _ => {
                    return Err(malformed(
                        "--zone-roles",
                        "expected area, queue or register; lane roles are inferred from lane-stages",
                        *index,
                    ));
                }
            };
            config.zone_roles.push(QsrZoneBinding {
                zone: zone(object.get("zone"), "--zone-roles", *index)?,
                role,
            });
        }
    }
    if let Some((_, text, index)) = take(values, "--lane-stages") {
        let input = inline(text, "--lane-stages", *index)?;
        let rows = input
            .array()
            .filter(|rows| rows.is_empty() || (2..=16).contains(&rows.len()))
            .ok_or_else(|| {
                malformed(
                    "--lane-stages",
                    "expected zero or two to 16 ordered zone IDs",
                    *index,
                )
            })?;
        for row in rows {
            config
                .lane_stages
                .push(zone(Some(row), "--lane-stages", *index)?);
        }
    }
    config
        .validate_shape()
        .map_err(|_| malformed("query", "invalid or conflicting QSR zone annotations", 0))?;
    Ok(config)
}

fn optional_number(
    values: &[(String, String, usize)],
    name: &str,
    default: usize,
) -> Result<usize, CliError> {
    match take(values, name) {
        None => Ok(default),
        Some((_, text, index)) => text
            .parse::<usize>()
            .ok()
            .filter(|n| *n > 0 && n.to_string() == *text)
            .ok_or_else(|| {
                malformed(
                    name,
                    "expected a positive canonical decimal integer",
                    *index,
                )
            }),
    }
}

/// Closed QSR grammar. Report selection is by retained digest, with inline annotations only.
pub fn parse_qsr_query_args(tokens: &[ArgToken]) -> Result<QsrQueryArgs, CliError> {
    let values = collect_options(
        "query",
        tokens,
        &[
            "--target",
            "--root",
            "--principal",
            "--report-digest",
            "--zone-roles",
            "--lane-stages",
            "--verify-qsr-source",
            "--anchor",
            "--max-query-read-bytes",
            "--max-query-read-objects",
        ],
    )?;
    let (target, index) = required(&values, "--target")?;
    if target != "qsr" {
        return Err(malformed("--target", "expected qsr", index));
    }
    let (verification, index) = required(&values, "--verify-qsr-source")?;
    if verification != "yes" {
        return Err(malformed(
            "--verify-qsr-source",
            "explicit yes required for internal source verification",
            index,
        ));
    }
    let (text, index) = required(&values, "--report-digest")?;
    let report_digest = ContentDigest::parse(text).map_err(|_| {
        malformed(
            "--report-digest",
            "expected canonical nonzero SHA-256 digest",
            index,
        )
    })?;
    if report_digest.to_text() != text {
        return Err(malformed("--report-digest", "noncanonical digest", index));
    }
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
    let request = QsrQueryRequest {
        report_digest,
        config: config(&values)?,
        principal: principal("query", &values)?,
        expected_anchor,
    };
    request
        .validate()
        .map_err(|_| malformed("query", "invalid exact QSR request", 0))?;
    let mut limits = QsrQueryLimits::default();
    limits.read.max_read_bytes = optional_number(
        &values,
        "--max-query-read-bytes",
        limits.read.max_read_bytes,
    )?;
    limits.read.max_read_objects = optional_number(
        &values,
        "--max-query-read-objects",
        limits.read.max_read_objects,
    )?;
    limits
        .validate()
        .map_err(|_| malformed("query", "invalid bounded QSR read allowance", 0))?;
    let root = required_root("query", &values)?;
    if !root.is_absolute() {
        return Err(malformed(
            "--root",
            "an absolute deployment root is required",
            0,
        ));
    }
    Ok(QsrQueryArgs {
        root,
        request,
        limits,
        verify_qsr_source: true,
    })
}

fn response(
    args: &QsrQueryArgs,
    query: &DeploymentQsrQuery,
    orientation: &DeploymentOrientation,
) -> Result<String, Box<dyn std::error::Error>> {
    let request_text = query.request_digest.to_text();
    let hex = request_text
        .strip_prefix("sha256:")
        .unwrap_or(&request_text);
    let capsule = orientation.capsule();
    let mut epistemic = query.epistemic.clone();
    epistemic.propositions.push(EnvelopeProposition {
        id: "claim:qsr:deployment-anchor".to_owned(),
        statement: format!("Exact current authority/effect-history token: {}. Historical source and screening anchors remain separate.", query.anchor_token),
        state: KnowledgeState::Known, provenance: "derived".to_owned(), evidence: vec![query.decision_digest.to_text()],
    });
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
    let source = query.report.source();
    let handles: Vec<_> = [
        (
            source.digest(),
            "retained_screened_package_zone_report_metadata",
        ),
        (
            source.provenance_root(),
            "retained_screening_provenance_metadata",
        ),
    ]
    .into_iter()
    .map(|(digest, kind)| agent_json::EvidenceHandle {
        handle_id: format!("fss://proof/{digest}"),
        object_digest: digest,
        kind: kind.to_owned(),
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
            .ok_or(RenderError("QSR query affordance objects"))?;
    let frame_digest = capsule.frame.frame_digest()?;
    let decision = request_identity("fss.cli.qsr_query.context_decision.v1", |encoder| {
        encoder.digest(query.decision_digest);
        encoder.digest(frame_digest);
    });
    let allowance = args.limits.allowance()?;
    let mut requested = orientation.requested;
    requested.latency_ms = allowance.latency_ms;
    requested.bytes = allowance.bytes;
    requested.storage_operations = allowance.storage_operations;
    let mut consumed = orientation.consumed;
    consumed.bytes = query.read_usage.read_bytes;
    consumed.storage_operations = query.read_usage.read_objects;
    let cognitive = AgentCognitiveEnvelope::new(
        capsule.contract_basis.clone(), format!("request:query:{hex}"), format!("response:query:{hex}"), format!("trace:query:{hex}"),
        "query", "query", AgentView::Case.id(), CognitiveAnswerClass::BoundedSummary, capsule.anchor.clone(), epistemic, query.coverage(),
        EnvelopeBudget {
            requested_json: agent_json::budget(&requested), consumed_json: agent_json::budget(&consumed),
            remaining_json: agent_json::remaining(&requested, &consumed),
            degraded_dimensions: vec!["query-cpu-and-output-tokens-not-metered".to_owned()], marginal_work_declined: Vec::new(),
        }, handles.iter().map(|handle| handle.handle_id.clone()).collect(), action_ids.clone(),
        EnvelopeContinuity {
            cursor: None, reanchor_triggers: vec!["Any authority/effect prefix, source custody, deletion, mask, screening, report, annotations or allowance change.".to_owned()],
            session_capsule_digest: None, unresolved_obligations: capsule.obligations.iter().map(|id| id.as_str().to_owned()).collect(),
        }, decision.to_text(),
    )?;
    let payload = agent_json::cognitive_envelope(&cognitive, &handles, &action_objects)
        .ok_or(RenderError("QSR query cognitive envelope"))?;
    let mut warnings = orientation.warnings.clone();
    warnings.push("QSR counts refer to confirmed model tracks at sampled frames. Unknown/masked samples and lane interruptions remain explicit. Physical identity, continuous coverage, absence, measured model accuracy, current camera health and service/wait durations are not established. Original media and model bytes are withheld.".to_owned());
    build_qsr_response(ResponseParts {
        operation: "query", request_digest: query.request_digest, principal: args.request.principal.clone(),
        session_id: Some(query.session_id.as_str().to_owned()), mission_id: Some(query.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(), view: AgentView::Case, capability: CAPABILITY_QUERY, outcome: ResponseOutcome::Ok,
        error_id: None, payload_schema: AgentCognitiveEnvelope::SCHEMA, payload_json: payload,
        epistemic_state: KnowledgeState::Unknown, completeness: Completeness::Bounded, warnings,
        contradictions: orientation.contradictions.clone(),
        degradation: vec!["CPU time, full output tokens and elapsed latency are not metered. The 60-second deadline is cooperative. Byte and object counters share one payload-read balance across history, source verification and final revalidation; they are not filesystem syscall counters.".to_owned()],
        budgets_json: agent_json::budget_summary(&requested, &consumed),
        proof_pointers: vec![query.plan.plan_digest().to_text(), query.admission.receipt_digest().to_text(), query.source_permit_digest.to_text(), query.report.digest().to_text(), query.report.lane_traversals().digest().to_text(), source.digest().to_text(), source.provenance_root().to_text(), frame_digest.to_text()],
        affordances: action_ids, affordance_objects: action_objects, decision_fingerprint: decision,
        compression_receipt_id: None, continuation: None, recovery_class: "safe_read_retry", safe_retry: ResponseSafeRetry::YesSameRequest,
        boundary: read_only_boundary("Verified one retained screened QSR report with an explicit source-read grant and one immutable budget; revalidated source custody, publication, deletion and authority without publisher locks, recovery, model execution, media disclosure or writes.".to_owned()),
        created_at_ns: capsule.created_at.0, workspace_revision: None, idempotency_key: None,
    })
}

fn refusal(
    args: &QsrQueryArgs,
    query: &DeploymentQsrQuery,
    reason: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let digest = request_identity("fss.cli.qsr_query.refusal.v1", |encoder| {
        encoder.digest(query.request_digest);
        encoder.text(reason);
    });
    build_qsr_response(ResponseParts {
        operation: "query", request_digest: digest, principal: args.request.principal.clone(), session_id: None, mission_id: None,
        anchor: query.snapshot.anchor.clone(), view: AgentView::Case, capability: CAPABILITY_QUERY,
        outcome: ResponseOutcome::Refused, error_id: Some(ERR_AGENT_CONTEXT_INCOMPLETE),
        payload_schema: AgentCognitiveEnvelope::SCHEMA, payload_json: "null".to_owned(), epistemic_state: KnowledgeState::Unknown,
        completeness: Completeness::Partial, warnings: vec![reason.to_owned()], contradictions: Vec::new(),
        degradation: vec!["No QSR analysis was delivered. Refusal is not an empty match set; refused-read resource accounting is not reported.".to_owned()],
        budgets_json: agent_json::budget_summary(&BudgetVector::default(), &BudgetVector::default()), proof_pointers: Vec::new(),
        affordances: Vec::new(), affordance_objects: Vec::new(), decision_fingerprint: digest, compression_receipt_id: None,
        continuation: None, recovery_class: "operator_action_required", safe_retry: ResponseSafeRetry::No,
        boundary: read_only_boundary("The QSR query refused without a partial result or media disclosure.".to_owned()),
        created_at_ns: query.snapshot.latest_evidence_time.0, workspace_revision: None, idempotency_key: None,
    })
}

fn diagnostic(args: &QsrQueryArgs, error: QsrQueryError) -> (String, ExitIdentity) {
    let (code, exit) = match error {
        QsrQueryError::InvalidRequest => (
            crate::ERR_CLI_MALFORMED_VALUE,
            ExitIdentity::MALFORMED_VALUE,
        ),
        _ => (ERR_AGENT_CONTEXT_INCOMPLETE, ExitIdentity::AGENT_REFUSED),
    };
    (execution_diagnostic("query", &args.root, code, exit), exit)
}

/// Execute the same admitted native query for CLI and MCP, preserving protected context.
#[must_use]
pub fn execute_qsr_query(args: &QsrQueryArgs) -> (String, ExitIdentity) {
    if !args.verify_qsr_source {
        return diagnostic(args, QsrQueryError::Unauthorized);
    }
    let allowance = match args.limits.allowance() {
        Ok(value) => value,
        Err(error) => return diagnostic(args, error),
    };
    let started = Instant::now();
    let now = || TimestampNs(i128::try_from(started.elapsed().as_nanos()).unwrap_or(i128::MAX));
    let authority = match OperationId::parse("operation:qsr-query")
        .map_err(|_| ())
        .and_then(|operation_id| {
            ContextAuthority::new_root(RootAuthoritySpec {
                trace_id: "trace:qsr-query".to_owned(),
                operation_id,
                principal: args.request.principal.as_str().to_owned(),
                capabilities: vec![
                    CAPABILITY_QUERY.to_owned(),
                    "CAP-READ-MEDIA-001".to_owned(),
                    "ADP-REPLAY-001".to_owned(),
                ],
                deadline: Some(TimestampNs(60_000_000_000)),
                priority: 10,
                budgets: allowance,
                privacy_scope: "privacy:qsr-source-verification".to_owned(),
                retention_scope: "retention:current-deletion-restrictions".to_owned(),
                anchor_universe: args.request.report_digest,
                generation: 1,
            })
            .map_err(|_| ())
        }) {
        Ok(authority) => authority,
        Err(()) => return internal_failure("query", &args.root),
    };
    let permit = match QsrSourceReadPermit::authorize(
        &authority,
        &args.root,
        &args.request,
        args.limits,
        &now,
    ) {
        Ok(permit) => permit,
        Err(error) => return diagnostic(args, error),
    };
    let query = match query_qsr_in_deployment(
        &args.root,
        &args.request,
        args.limits,
        Some(&permit),
        &|| started.elapsed() >= READ_DEADLINE,
    ) {
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
        Ok(value) => value,
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
                "Complete QSR response exceeded 256 KiB or the cooperative deadline. No result prefix was delivered; select a smaller retained report.",
            ),
            ExitIdentity::AGENT_REFUSED,
            "query",
            &args.root,
        ),
        Err(_) => internal_failure("query", &args.root),
    }
}

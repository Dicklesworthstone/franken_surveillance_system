#![forbid(unsafe_code)]
//! Read-only AOP-005 access to retained source-capsule metadata.
//!
//! The native reader owns custody, selection, pagination and current-head revalidation.
//! This projection never opens a writable deployment or returns source-media bytes.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use fss_core::{
    AgentCognitiveEnvelope, AgentView, BudgetVector, CognitiveAnswerClass, Completeness,
    EnvelopeBudget, EnvelopeContinuity, EnvelopeProposition, KnowledgeState, ResponseOutcome,
    ResponseSafeRetry, SensorId, StreamId,
};
use fss_reference::agent_follow::AnchorToken;
use fss_reference::agent_footage::{
    DeploymentFootageQuery, FootageQueryError, FootageQueryFilter, FootageQueryLimits,
    FootageQueryRequest, query_footage,
};
use fss_reference::agent_orient::{
    DeploymentOrientation, DeploymentSnapshot, OrientRequest, orient_deployment,
};
use fss_reference::agent_query::{CAPABILITY_QUERY, DEFAULT_QUERY_ENTRIES, MAX_QUERY_ENTRIES};
use fss_reference::deployment_status::StatusError;

use crate::agent_json;
use crate::error::{CliError, ExitIdentity};
use crate::fss_cmd::FssCommand;
use crate::orient_cmd::{
    ERR_AGENT_CONTEXT_INCOMPLETE, RenderError, ResponseParts, build_footage_response,
    collect_options, contexts, execution_diagnostic, internal_failure, principal,
    read_only_boundary, rendered, request_identity, required_root, take,
};
use crate::query_cmd::MAX_QUERY_OUTPUT_BYTES;
use crate::token::ArgToken;

/// Maximum cooperative read duration. The native reader checks this at bounded I/O stages;
/// this is not a preemptive deadline for a blocking filesystem call.
const READ_DEADLINE: Duration = Duration::from_secs(60);

/// An exact, bounded metadata read of a current committed deployment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FootageQueryArgs {
    /// Existing deployment root, inspected without writes, recovery or locks.
    pub root: PathBuf,
    /// Typed source predicates and exact continuation/precondition.
    pub request: FootageQueryRequest,
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

/// Dispatches a closed query target without weakening either target's grammar.
/// Existing invocations select events. Cross-target predicates are rejected by the
/// selected parser rather than silently ignored or reinterpreted.
pub(crate) fn parse_query_command(tokens: &[ArgToken]) -> Result<FssCommand, CliError> {
    let values = collect_options(
        "query",
        tokens,
        &[
            "--target",
            "--root",
            "--principal",
            "--event-id",
            "--kind",
            "--zone",
            "--state",
            "--sensor",
            "--stream",
            "--from-ns",
            "--through-ns",
            "--max-entries",
            "--anchor",
            "--at",
            "--continuation",
        ],
    )?;
    match take(&values, "--target") {
        None => crate::query_cmd::parse_query_args(tokens).map(FssCommand::Query),
        Some((_, target, _)) if target == "events" => {
            crate::query_cmd::parse_query_args(tokens).map(FssCommand::Query)
        }
        Some((_, target, _)) if target == "footage" => {
            parse_footage_query_args(tokens).map(FssCommand::FootageQuery)
        }
        Some((_, target, index)) => Err(malformed(
            "--target",
            target,
            "expected events or footage",
            *index,
        )),
    }
}

/// Parses exact source identity and source-clock interval predicates. No natural
/// language, media hydration, historical selector, UTC conversion or mutation is admitted.
pub fn parse_footage_query_args(tokens: &[ArgToken]) -> Result<FootageQueryArgs, CliError> {
    let values = collect_options(
        "query",
        tokens,
        &[
            "--target",
            "--root",
            "--principal",
            "--sensor",
            "--stream",
            "--from-ns",
            "--through-ns",
            "--max-entries",
            "--anchor",
            "--continuation",
        ],
    )?;
    match take(&values, "--target") {
        Some((_, target, _)) if target == "footage" => {}
        Some((_, target, index)) => {
            return Err(malformed("--target", target, "expected footage", *index));
        }
        None => {
            return Err(CliError::MissingValue {
                option: "--target".to_owned(),
                command: Some("query".to_owned()),
                expected: "explicit --target footage".to_owned(),
            });
        }
    }
    let sensor = take(&values, "--sensor")
        .map(|(_, value, index)| {
            SensorId::parse(value.clone())
                .map_err(|_| malformed("--sensor", value, "invalid sensor identity", *index))
        })
        .transpose()?;
    let stream = take(&values, "--stream")
        .map(|(_, value, index)| {
            StreamId::parse(value.clone())
                .map_err(|_| malformed("--stream", value, "invalid stream identity", *index))
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
    let request = FootageQueryRequest {
        filter: FootageQueryFilter {
            sensor,
            stream,
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
    Ok(FootageQueryArgs {
        root: required_root("query", &values)?,
        request,
    })
}

fn footage_response(
    args: &FootageQueryArgs,
    query: &DeploymentFootageQuery,
    orientation: &DeploymentOrientation,
    limits: &FootageQueryLimits,
) -> Result<String, Box<dyn std::error::Error>> {
    let text = query.request_digest.to_text();
    let hex = text.strip_prefix("sha256:").unwrap_or(&text);
    let capsule = orientation.capsule();
    let next = query
        .page
        .next_cursor
        .as_ref()
        .map(|cursor| cursor.token().to_owned());
    let mut epistemic = query.epistemic();
    epistemic.propositions.push(EnvelopeProposition {
        id: "claim:query:footage:anchor".to_owned(),
        statement: format!(
            "Exact authority/effect-history token: {}",
            query.anchor_token
        ),
        state: KnowledgeState::Known,
        provenance: "derived".to_owned(),
        evidence: vec![query.selection_witness.to_text()],
    });
    // A filtered source page must still retain urgent and uncertain deployment context.
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
        .rows
        .iter()
        .map(|row| agent_json::EvidenceHandle {
            handle_id: format!("fss://proof/{}", row.capsule_digest),
            object_digest: row.capsule_digest,
            kind: "sensor_capsule".to_owned(),
            hydration: "H0",
            allowed_hydration: vec!["H0"],
            privacy_class: "private:property".to_owned(),
            // This availability refers only to the verified capsule metadata, not its media.
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
            .ok_or(RenderError("footage query affordance objects"))?;
    let frame_digest = capsule.frame.frame_digest()?;
    let decision = request_identity("fss.cli.footage_query.context_decision.v1", |encoder| {
        encoder.digest(query.decision_digest);
        encoder.digest(frame_digest);
    });
    // The native counters already include the snapshot used for orientation. Replacing
    // its read dimensions avoids counting that same I/O twice; context tokens retain
    // their existing metering, distinct from the unmetered footage-output tokens.
    let mut requested = orientation.requested;
    requested.latency_ms = query.admission.cost().latency_ms;
    requested.bytes = u64::try_from(limits.max_metadata_bytes)?;
    requested.storage_operations = u64::try_from(limits.max_metadata_objects)?;
    let mut consumed = orientation.consumed;
    consumed.bytes = query.metadata_bytes_read;
    consumed.storage_operations = query.metadata_objects_read;
    let cognitive = AgentCognitiveEnvelope::new(
        capsule.contract_basis.clone(),
        format!("request:query:{hex}"),
        format!("response:query:{hex}"),
        format!("trace:query:{hex}"),
        "query", "query", AgentView::Case.id(), CognitiveAnswerClass::BoundedSummary,
        capsule.anchor.clone(), epistemic, query.coverage(),
        EnvelopeBudget {
            requested_json: agent_json::budget(&requested),
            consumed_json: agent_json::budget(&consumed),
            remaining_json: agent_json::remaining(&requested, &consumed),
            degraded_dimensions: vec![
                "query-cpu-and-output-tokens-not-metered".to_owned(),
                "metadata-payload-io-excludes-filesystem-and-syscall-overhead".to_owned(),
            ],
            marginal_work_declined: Vec::new(),
        },
        handles.iter().map(|handle| handle.handle_id.clone()).collect(),
        action_ids.clone(),
        EnvelopeContinuity {
            cursor: next.clone(),
            reanchor_triggers: vec![
                "Any authority or effect-journal advance, metadata custody change, or changed query scope.".to_owned(),
            ],
            session_capsule_digest: None,
            unresolved_obligations: capsule.obligations.iter().map(|id| id.as_str().to_owned()).collect(),
        },
        decision.to_text(),
    )?;
    let payload = agent_json::cognitive_envelope(&cognitive, &handles, &action_objects)
        .ok_or(RenderError("footage query cognitive envelope"))?;
    let mut warnings = orientation.warnings.clone();
    warnings.push("Footage metadata only. Source-media availability is unknown; no media bytes, UTC conversion, physical coverage or absence certificate is returned.".to_owned());
    warnings.push("Time predicates compare conservative recorded intervals in their declared clock basis. Estimated or overlapping intervals remain uncertain.".to_owned());
    build_footage_response(ResponseParts {
        operation: "query", request_digest: query.request_digest,
        principal: args.request.principal.clone(),
        session_id: Some(query.session_id.as_str().to_owned()),
        mission_id: Some(query.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(), view: AgentView::Case, capability: CAPABILITY_QUERY,
        outcome: if next.is_some() { ResponseOutcome::Partial } else { ResponseOutcome::Ok },
        error_id: None, payload_schema: AgentCognitiveEnvelope::SCHEMA, payload_json: payload,
        epistemic_state: KnowledgeState::Unknown, completeness: Completeness::Bounded,
        warnings, contradictions: orientation.contradictions.clone(),
        degradation: vec!["Query CPU, full output tokens and elapsed latency are not metered. The 60-second read deadline is cooperative at bounded checkpoints, not a preemptive filesystem timeout. Metadata I/O counts exclude filesystem and syscall overhead.".to_owned()],
        budgets_json: agent_json::budget_summary(&requested, &consumed),
        proof_pointers: vec![query.plan.plan_digest().to_text(), query.admission.receipt_digest().to_text(),
            query.selection_witness.to_text(), query.page.page_digest.to_text(), frame_digest.to_text()],
        affordances: action_ids, affordance_objects: action_objects,
        decision_fingerprint: decision, compression_receipt_id: None, continuation: next,
        recovery_class: "safe_read_retry", safe_retry: ResponseSafeRetry::YesSameRequest,
        boundary: read_only_boundary("Verified committed import/capsule metadata and one exact footage page, then revalidated custody and the authority/effect prefix without recovery.".to_owned()),
        created_at_ns: capsule.created_at.0, workspace_revision: None, idempotency_key: None,
    })
}

fn refusal(
    args: &FootageQueryArgs,
    snapshot: &DeploymentSnapshot,
    reason: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let digest = request_identity("fss.cli.footage_query.refusal.v1", |encoder| {
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
        encoder.text(&fss_reference::agent_follow::snapshot_anchor_token(
            snapshot,
        ));
        encoder.text(reason);
    });
    build_footage_response(ResponseParts {
        operation: "query", request_digest: digest, principal: args.request.principal.clone(),
        session_id: None, mission_id: None, anchor: snapshot.anchor.clone(), view: AgentView::Case,
        capability: CAPABILITY_QUERY, outcome: ResponseOutcome::Refused,
        error_id: Some(ERR_AGENT_CONTEXT_INCOMPLETE), payload_schema: AgentCognitiveEnvelope::SCHEMA,
        payload_json: "null".to_owned(), epistemic_state: KnowledgeState::Unknown,
        completeness: Completeness::Partial, warnings: vec![reason.to_owned()], contradictions: Vec::new(),
        degradation: vec!["No footage result was delivered. A refusal is not an empty match set; refused-read resource accounting is not reported.".to_owned()],
        budgets_json: agent_json::budget_summary(&BudgetVector::default(), &BudgetVector::default()),
        proof_pointers: Vec::new(), affordances: Vec::new(), affordance_objects: Vec::new(),
        decision_fingerprint: digest, compression_receipt_id: None, continuation: None,
        recovery_class: "operator_action_required", safe_retry: ResponseSafeRetry::No,
        boundary: read_only_boundary("Footage read refused; no result page or media payload was delivered.".to_owned()),
        created_at_ns: snapshot.latest_evidence_time.0, workspace_revision: None, idempotency_key: None,
    })
}

fn native_refusal(args: &FootageQueryArgs, error: &FootageQueryError) -> (String, ExitIdentity) {
    // Before a verified snapshot exists, do not invent an authority anchor for an envelope.
    let (code, exit) = match error {
        FootageQueryError::InvalidRequest(_) => (
            crate::ERR_CLI_MALFORMED_VALUE,
            ExitIdentity::MALFORMED_VALUE,
        ),
        FootageQueryError::Read(StatusError::NotADeployment) => (
            crate::error::ERR_DOCTOR_NOT_A_DEPLOYMENT,
            ExitIdentity::DOCTOR_NOT_A_DEPLOYMENT,
        ),
        FootageQueryError::Read(StatusError::Unreadable | StatusError::Corrupt)
        | FootageQueryError::InvalidRecord => (
            crate::ERR_CLI_RUNTIME_FAILURE,
            ExitIdentity::RUNTIME_FAILURE,
        ),
        _ => (ERR_AGENT_CONTEXT_INCOMPLETE, ExitIdentity::AGENT_REFUSED),
    };
    (execution_diagnostic("query", &args.root, code, exit), exit)
}

/// Executes one bounded read through the native custody owner and renders the existing
/// registered query/case envelope. All native failures refuse; none become empty results.
#[must_use]
pub fn execute_footage_query(args: &FootageQueryArgs) -> (String, ExitIdentity) {
    let limits = FootageQueryLimits::default();
    let started = Instant::now();
    let query = match query_footage(&args.root, &args.request, &limits, &mut |_| {
        started.elapsed() < READ_DEADLINE
    }) {
        Ok(query) => query,
        Err(error) => return native_refusal(args, &error),
    };
    let orientation = match orient_deployment(
        &query.snapshot,
        &OrientRequest {
            view: AgentView::Brief,
            principal: args.request.principal.clone(),
            budget_tokens: None,
        },
        &limits.snapshot,
    ) {
        Ok(orientation) => orientation,
        Err(error) => {
            return rendered(
                refusal(args, &query.snapshot, &error.to_string()),
                ExitIdentity::AGENT_REFUSED,
                "query",
                &args.root,
            );
        }
    };
    match footage_response(args, &query, &orientation, &limits) {
        Ok(output) if output.len() <= MAX_QUERY_OUTPUT_BYTES => (output, ExitIdentity::SUCCESS),
        Ok(_) => rendered(
            refusal(
                args,
                &query.snapshot,
                "Complete footage query response exceeds 256 KiB; reduce --max-entries. Nothing was truncated.",
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

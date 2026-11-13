#![forbid(unsafe_code)]
//! Canonical CLI/MCP track observations over exact retained detector evidence.

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
use fss_reference::agent_query::CAPABILITY_QUERY;
use fss_reference::agent_tracks::{DEFAULT_TRACK_QUERY_ENTRIES, MAX_TRACK_QUERY_ENTRIES};
use fss_reference::agent_tracks::{
    DeploymentTrackQuery, TrackQueryError, TrackQueryLimits, TrackQueryRequest,
    TrackSourceReadPermit, query_tracks_in_deployment,
};
use fss_reference::ingest::package_event::PackageTrackingConfig;

use crate::agent_json;
use crate::error::{CliError, ExitIdentity};
use crate::orient_cmd::{
    ERR_AGENT_CONTEXT_INCOMPLETE, RenderError, ResponseParts, build_tracks_response,
    collect_options, contexts, execution_diagnostic, internal_failure, principal,
    read_only_boundary, rendered, request_identity, required_root, take,
};
use crate::query_cmd::MAX_QUERY_OUTPUT_BYTES;
use crate::token::ArgToken;

const READ_DEADLINE: Duration = Duration::from_secs(60);

/// Exact paginated track read, with separate permission for internal source verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TracksQueryArgs {
    /// Existing deployment, inspected without locks, recovery or writes.
    pub root: PathBuf,
    /// Exact retained report, label, tracking recipe and page.
    pub request: TrackQueryRequest,
    /// One aggregate payload-read balance including final revalidation.
    pub limits: TrackQueryLimits,
    /// Explicit operator consent, checked again for directly constructed Rust requests.
    pub verify_tracks_source: bool,
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
            expected: format!("explicit {name} for an exact track query"),
        })
}

fn recipe_number(
    values: &[(String, String, usize)],
    name: &str,
    default: u32,
    minimum: u32,
    maximum: u32,
) -> Result<u32, CliError> {
    match take(values, name) {
        None => Ok(default),
        Some((_, text, index)) => text
            .parse::<u32>()
            .ok()
            .filter(|number| (minimum..=maximum).contains(number) && number.to_string() == *text)
            .ok_or_else(|| malformed(name, "expected a bounded canonical decimal integer", *index)),
    }
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

/// Closed track grammar. A retained digest and exact label select native matched observations.
pub fn parse_tracks_query_args(tokens: &[ArgToken]) -> Result<TracksQueryArgs, CliError> {
    let values = collect_options(
        "query",
        tokens,
        &[
            "--target",
            "--root",
            "--principal",
            "--report-digest",
            "--label",
            "--confirmation-hits",
            "--maximum-missed-frames",
            "--minimum-iou-ppm",
            "--max-entries",
            "--continuation",
            "--verify-tracks-source",
            "--anchor",
            "--max-query-read-bytes",
            "--max-query-read-objects",
        ],
    )?;
    let (target, index) = required(&values, "--target")?;
    if target != "tracks" {
        return Err(malformed("--target", "expected tracks", index));
    }
    let (verification, index) = required(&values, "--verify-tracks-source")?;
    if verification != "yes" {
        return Err(malformed(
            "--verify-tracks-source",
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
    let request = TrackQueryRequest {
        report_digest,
        label: required(&values, "--label")?.0.to_owned(),
        config: PackageTrackingConfig {
            confirmation_hits: recipe_number(&values, "--confirmation-hits", 2, 1, u32::MAX)?,
            maximum_missed_frames: recipe_number(
                &values,
                "--maximum-missed-frames",
                1,
                1,
                u32::MAX,
            )?,
            minimum_iou_ppm: recipe_number(&values, "--minimum-iou-ppm", 100_000, 0, 1_000_000)?,
        },
        max_entries: recipe_number(
            &values,
            "--max-entries",
            DEFAULT_TRACK_QUERY_ENTRIES,
            1,
            MAX_TRACK_QUERY_ENTRIES,
        )?,
        continuation: take(&values, "--continuation").map(|(_, text, _)| text.clone()),
        principal: principal("query", &values)?,
        expected_anchor,
    };
    request
        .validate()
        .map_err(|_| malformed("query", "invalid exact track request", 0))?;
    let mut limits = TrackQueryLimits::default();
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
        .map_err(|_| malformed("query", "invalid bounded track read allowance", 0))?;
    let root = required_root("query", &values)?;
    if !root.is_absolute() {
        return Err(malformed(
            "--root",
            "an absolute deployment root is required",
            0,
        ));
    }
    Ok(TracksQueryArgs {
        root,
        request,
        limits,
        verify_tracks_source: true,
    })
}

fn response(
    args: &TracksQueryArgs,
    query: &DeploymentTrackQuery,
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
    let mut epistemic = query.epistemic.clone();
    epistemic.propositions.push(EnvelopeProposition {
        id: "claim:tracks:deployment-anchor".to_owned(),
        statement: format!("Exact current authority/effect-history token: {}. Historical source anchors remain separate.", query.anchor_token),
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
    let source = query.report.retained();
    let handles: Vec<_> = [
        (
            source.record_digest(),
            "retained_package_detection_record_metadata",
        ),
        (
            source.root(),
            "retained_package_detection_manifest_metadata",
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
            .ok_or(RenderError("track query affordance objects"))?;
    let frame_digest = capsule.frame.frame_digest()?;
    let decision = request_identity("fss.cli.tracks_query.context_decision.v1", |encoder| {
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
            cursor: next.clone(), reanchor_triggers: vec!["Any authority/effect prefix, source custody, deletion, privacy, report, label, tracking recipe, principal, page size or allowance change.".to_owned()],
            session_capsule_digest: None, unresolved_obligations: capsule.obligations.iter().map(|id| id.as_str().to_owned()).collect(),
        }, decision.to_text(),
    )?;
    let payload = agent_json::cognitive_envelope(&cognitive, &handles, &action_objects)
        .ok_or(RenderError("track query cognitive envelope"))?;
    let mut warnings = orientation.warnings.clone();
    warnings.push("Track rows are actual matched native observations. Tentative samples remain tentative even if their track later confirms; source discontinuities reset tracking. Scores are uncalibrated and track identities do not establish physical identity. Predicted-only boxes, missed frames, physical absence, continuous coverage and model accuracy are not established. Original media and model bytes are withheld.".to_owned());
    build_tracks_response(ResponseParts {
        operation: "query", request_digest: query.request_digest, principal: args.request.principal.clone(),
        session_id: Some(query.session_id.as_str().to_owned()), mission_id: Some(query.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(), view: AgentView::Case, capability: CAPABILITY_QUERY, outcome: if next.is_some() { ResponseOutcome::Partial } else { ResponseOutcome::Ok },
        error_id: None, payload_schema: AgentCognitiveEnvelope::SCHEMA, payload_json: payload,
        epistemic_state: KnowledgeState::Unknown, completeness: Completeness::Bounded, warnings,
        contradictions: orientation.contradictions.clone(),
        degradation: vec!["CPU time, full output tokens and elapsed latency are not metered. The 60-second deadline is cooperative. Byte and object counters share one payload-read balance across history, source verification and final revalidation; they are not filesystem syscall counters.".to_owned()],
        budgets_json: agent_json::budget_summary(&requested, &consumed),
        proof_pointers: vec![query.plan.plan_digest().to_text(), query.admission.receipt_digest().to_text(), query.source_permit_digest.to_text(), query.selection_witness.to_text(), query.page.page_digest.to_text(), query.report.digest().to_text(), source.record_digest().to_text(), source.root().to_text(), frame_digest.to_text()],
        affordances: action_ids, affordance_objects: action_objects, decision_fingerprint: decision,
        compression_receipt_id: None, continuation: next, recovery_class: "safe_read_retry", safe_retry: ResponseSafeRetry::YesSameRequest,
        boundary: read_only_boundary("Rebuilt one retained detector label with an explicit tracking recipe and source-read grant, returned one exact matched-observation page, and revalidated source custody, publication, privacy, deletion and authority without publisher locks, recovery, model execution, media disclosure or writes.".to_owned()),
        created_at_ns: capsule.created_at.0, workspace_revision: None, idempotency_key: None,
    })
}

fn refusal(
    args: &TracksQueryArgs,
    query: &DeploymentTrackQuery,
    reason: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let digest = request_identity("fss.cli.tracks_query.refusal.v1", |encoder| {
        encoder.digest(query.request_digest);
        encoder.text(reason);
    });
    build_tracks_response(ResponseParts {
        operation: "query", request_digest: digest, principal: args.request.principal.clone(), session_id: None, mission_id: None,
        anchor: query.snapshot.anchor.clone(), view: AgentView::Case, capability: CAPABILITY_QUERY,
        outcome: ResponseOutcome::Refused, error_id: Some(ERR_AGENT_CONTEXT_INCOMPLETE),
        payload_schema: AgentCognitiveEnvelope::SCHEMA, payload_json: "null".to_owned(), epistemic_state: KnowledgeState::Unknown,
        completeness: Completeness::Partial, warnings: vec![reason.to_owned()], contradictions: Vec::new(),
        degradation: vec!["No track observation page was delivered. Refusal is not an empty match set; refused-read resource accounting is not reported.".to_owned()],
        budgets_json: agent_json::budget_summary(&BudgetVector::default(), &BudgetVector::default()), proof_pointers: Vec::new(),
        affordances: Vec::new(), affordance_objects: Vec::new(), decision_fingerprint: digest, compression_receipt_id: None,
        continuation: None, recovery_class: "operator_action_required", safe_retry: ResponseSafeRetry::No,
        boundary: read_only_boundary("The track query refused without a partial result or media disclosure.".to_owned()),
        created_at_ns: query.snapshot.latest_evidence_time.0, workspace_revision: None, idempotency_key: None,
    })
}

fn diagnostic(args: &TracksQueryArgs, error: TrackQueryError) -> (String, ExitIdentity) {
    let (code, exit) = match error {
        TrackQueryError::InvalidRequest => (
            crate::ERR_CLI_MALFORMED_VALUE,
            ExitIdentity::MALFORMED_VALUE,
        ),
        _ => (ERR_AGENT_CONTEXT_INCOMPLETE, ExitIdentity::AGENT_REFUSED),
    };
    (execution_diagnostic("query", &args.root, code, exit), exit)
}

/// Execute the same admitted native page for CLI and MCP, preserving protected context.
#[must_use]
pub fn execute_tracks_query(args: &TracksQueryArgs) -> (String, ExitIdentity) {
    if !args.verify_tracks_source {
        return diagnostic(args, TrackQueryError::Unauthorized);
    }
    let allowance = match args.limits.allowance() {
        Ok(value) => value,
        Err(error) => return diagnostic(args, error),
    };
    let started = Instant::now();
    let now = || TimestampNs(i128::try_from(started.elapsed().as_nanos()).unwrap_or(i128::MAX));
    let authority = match OperationId::parse("operation:tracks-query")
        .map_err(|_| ())
        .and_then(|operation_id| {
            ContextAuthority::new_root(RootAuthoritySpec {
                trace_id: "trace:tracks-query".to_owned(),
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
                privacy_scope: "privacy:tracks-source-verification".to_owned(),
                retention_scope: "retention:current-deletion-restrictions".to_owned(),
                anchor_universe: args.request.report_digest,
                generation: 1,
            })
            .map_err(|_| ())
        }) {
        Ok(authority) => authority,
        Err(()) => return internal_failure("query", &args.root),
    };
    let permit = match TrackSourceReadPermit::authorize(
        &authority,
        &args.root,
        &args.request,
        args.limits,
        &now,
    ) {
        Ok(permit) => permit,
        Err(error) => return diagnostic(args, error),
    };
    let query = match query_tracks_in_deployment(
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
                "Complete track response exceeded 256 KiB or the cooperative deadline. No result prefix was delivered; start a fresh query with a smaller page or retained report.",
            ),
            ExitIdentity::AGENT_REFUSED,
            "query",
            &args.root,
        ),
        Err(_) => internal_failure("query", &args.root),
    }
}

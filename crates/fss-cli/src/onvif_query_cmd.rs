#![forbid(unsafe_code)]
//! Canonical AOP-005 projection of exact retained ONVIF source analysis.
//!
//! The native reader owns source custody, current deletion checks, source replay,
//! admission and complete-row bounds. CLI and MCP use this same closed parser and
//! response renderer; neither can choose a file or disclosure expansion through JSON.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use fss_core::{
    AgentCognitiveEnvelope, AgentView, BudgetVector, CognitiveAnswerClass, Completeness,
    ContentDigest, EnvelopeBudget, EnvelopeContinuity, EnvelopeProposition, KnowledgeState,
    ResponseOutcome, ResponseSafeRetry,
};
use fss_object::HostSpoolIo;
use fss_reference::agent_follow::AnchorToken;
use fss_reference::agent_onvif::{
    DeploymentOnvifQuery, OnvifAnalysis, OnvifAnalysisResult, OnvifQueryError, OnvifQueryLimits,
    OnvifQueryRequest, query_onvif_in_deployment,
};
use fss_reference::agent_orient::{
    DeploymentOrientation, DeploymentReadError, OrientRequest, orient_deployment,
};
use fss_reference::agent_query::CAPABILITY_QUERY;
use fss_reference::onvif::metadata::tracks::{MAX_TRACK_SOURCES, TrackSourcePin};
use fss_reference::onvif::metadata::zones::contract::{MAX_ZONE_POLICY_BYTES, ZonePolicy};

use crate::agent_json;
use crate::error::{CliError, ExitIdentity};
use crate::json_input::{self, Value};
use crate::orient_cmd::{
    ERR_AGENT_CONTEXT_INCOMPLETE, RenderError, ResponseParts, build_onvif_response,
    collect_options, contexts, execution_diagnostic, internal_failure, principal,
    read_only_boundary, rendered, request_identity, required_root, take,
};
use crate::query_cmd::MAX_QUERY_OUTPUT_BYTES;
use crate::token::ArgToken;

const MAX_SOURCE_SELECTOR_BYTES: usize = 16 * 1024;
const READ_DEADLINE: Duration = Duration::from_secs(60);

/// One read-only current deployment query over exact ordered source pins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnvifQueryArgs {
    /// Existing deployment, never recovered, initialized or locked by this query.
    pub root: PathBuf,
    /// Typed semantic request shared by Rust, CLI and MCP.
    pub request: OnvifQueryRequest,
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
            expected: format!("explicit {name} for an exact ONVIF query"),
        })
}

fn pin_digest(value: Option<&Value>, index: usize) -> Result<ContentDigest, CliError> {
    let text = value.and_then(Value::text).ok_or_else(|| {
        malformed(
            "--sources",
            "source pins require canonical SHA-256 strings",
            index,
        )
    })?;
    let digest = ContentDigest::parse(text)
        .map_err(|_| malformed("--sources", "invalid source digest", index))?;
    if digest.to_text() != text || text == format!("sha256:{}", "0".repeat(64)) {
        return Err(malformed(
            "--sources",
            "source pins require nonzero canonical SHA-256 digests",
            index,
        ));
    }
    Ok(digest)
}

fn sources(text: &str, index: usize) -> Result<Vec<TrackSourcePin>, CliError> {
    if text.len() > MAX_SOURCE_SELECTOR_BYTES {
        return Err(malformed(
            "--sources",
            "source selector exceeds 16 KiB",
            index,
        ));
    }
    let value = json_input::parse(text).map_err(|_| {
        malformed(
            "--sources",
            "invalid or over-budget JSON source selector",
            index,
        )
    })?;
    let values = value
        .array()
        .filter(|values| (1..=MAX_TRACK_SOURCES).contains(&values.len()))
        .ok_or_else(|| malformed("--sources", "expected one to 32 ordered source pins", index))?;
    let mut pins = Vec::with_capacity(values.len());
    for value in values {
        let object = value
            .object()
            .filter(|object| {
                object.len() == 3
                    && ["kind", "identity", "root"]
                        .iter()
                        .all(|key| object.contains_key(*key))
            })
            .ok_or_else(|| {
                malformed(
                    "--sources",
                    "each source contains only kind, identity and root",
                    index,
                )
            })?;
        let identity = pin_digest(object.get("identity"), index)?;
        let root = pin_digest(object.get("root"), index)?;
        let pin = match object.get("kind").and_then(Value::text) {
            Some("xml") => TrackSourcePin::Xml { identity, root },
            Some("rtp") => TrackSourcePin::Rtp { identity, root },
            _ => {
                return Err(malformed(
                    "--sources",
                    "source kind must be xml or rtp",
                    index,
                ));
            }
        };
        if pins
            .iter()
            .any(|existing: &TrackSourcePin| existing.identity() == identity)
        {
            return Err(malformed(
                "--sources",
                "duplicate source identities are not admitted",
                index,
            ));
        }
        pins.push(pin);
    }
    Ok(pins)
}

/// Parse a closed target-specific grammar with inline JSON only. No path or stdin
/// indirection, raw vendor-value option, historical selector or continuation exists.
pub fn parse_onvif_query_args(tokens: &[ArgToken]) -> Result<OnvifQueryArgs, CliError> {
    let values = collect_options(
        "query",
        tokens,
        &[
            "--target",
            "--root",
            "--principal",
            "--analysis",
            "--sources",
            "--zone-policy",
            "--max-entries",
            "--anchor",
        ],
    )?;
    let (target, index) = required(&values, "--target")?;
    if target != "onvif" {
        return Err(malformed("--target", "expected onvif", index));
    }
    let (input, index) = required(&values, "--sources")?;
    let sources = sources(input, index)?;
    let (analysis, index) = required(&values, "--analysis")?;
    let policy = take(&values, "--zone-policy");
    let analysis = match (analysis, policy) {
        ("tracks", None) => OnvifAnalysis::Tracks,
        ("lifecycle", None) => OnvifAnalysis::Lifecycle,
        ("zones", Some((_, text, index))) => {
            if text.len() > MAX_ZONE_POLICY_BYTES {
                return Err(malformed(
                    "--zone-policy",
                    "inline policy exceeds 64 KiB",
                    *index,
                ));
            }
            OnvifAnalysis::Zones(ZonePolicy::parse_json(text).map_err(|_| {
                malformed(
                    "--zone-policy",
                    "invalid bounded raw-coordinate zone policy",
                    *index,
                )
            })?)
        }
        ("zones", None) => {
            return Err(CliError::MissingValue {
                option: "--zone-policy".to_owned(),
                command: Some("query".to_owned()),
                expected: "explicit inline JSON policy for zones".to_owned(),
            });
        }
        ("tracks" | "lifecycle", Some(_)) => {
            return Err(malformed(
                "--zone-policy",
                "zone policy is permitted only for analysis zones",
                index,
            ));
        }
        _ => {
            return Err(malformed(
                "--analysis",
                "expected tracks, lifecycle or zones",
                index,
            ));
        }
    };
    let max_entries = match take(&values, "--max-entries") {
        None => 32,
        Some((_, text, index)) => text
            .parse::<usize>()
            .ok()
            .filter(|value| (1..=32).contains(value) && value.to_string() == *text)
            .ok_or_else(|| {
                malformed(
                    "--max-entries",
                    "expected canonical integer 1..32; excess rows refuse without truncation",
                    *index,
                )
            })?,
    };
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
    let request = OnvifQueryRequest {
        sources,
        analysis,
        max_entries,
        principal: principal("query", &values)?,
        expected_anchor,
    };
    request
        .validate()
        .map_err(|_| malformed("query", "invalid exact ONVIF request", 0))?;
    Ok(OnvifQueryArgs {
        root: required_root("query", &values)?,
        request,
    })
}

fn response(
    args: &OnvifQueryArgs,
    query: &DeploymentOnvifQuery,
    orientation: &DeploymentOrientation,
    limits: OnvifQueryLimits,
) -> Result<String, Box<dyn std::error::Error>> {
    let request_text = query.request_digest.to_text();
    let hex = request_text
        .strip_prefix("sha256:")
        .unwrap_or(&request_text);
    let capsule = orientation.capsule();
    let mut epistemic = query.epistemic(&args.request);
    epistemic.propositions.push(EnvelopeProposition {
        id: "claim:onvif:deployment-anchor".to_owned(),
        statement: format!("Exact current authority/effect-history token: {}. Original source publication anchors remain separate.", query.anchor_token),
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
    let handles: Vec<_> = query
        .native
        .sources
        .iter()
        .map(|source| agent_json::EvidenceHandle {
            handle_id: format!("fss://proof/{}", source.pin.root()),
            object_digest: source.pin.root(),
            kind: "onvif_source_publication_metadata".to_owned(),
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
            .ok_or(RenderError("ONVIF query affordance objects"))?;
    let frame_digest = capsule.frame.frame_digest()?;
    let decision = request_identity("fss.cli.onvif_query.context_decision.v1", |encoder| {
        encoder.digest(query.decision_digest);
        encoder.digest(frame_digest);
    });
    let allowance = limits.allowance()?;
    let mut requested = orientation.requested;
    requested.latency_ms = allowance.latency_ms;
    requested.bytes = allowance.bytes;
    requested.storage_operations = allowance.storage_operations;
    let mut consumed = orientation.consumed;
    consumed.bytes = query
        .deployment_bytes_read
        .checked_add(query.native.read_usage.read_bytes)
        .ok_or(RenderError("ONVIF query byte accounting overflow"))?;
    consumed.storage_operations = query
        .deployment_metadata_reads
        .checked_add(query.native.read_usage.io_calls)
        .ok_or(RenderError("ONVIF query operation accounting overflow"))?;
    let cognitive = AgentCognitiveEnvelope::new(
        capsule.contract_basis.clone(), format!("request:query:{hex}"), format!("response:query:{hex}"), format!("trace:query:{hex}"),
        "query", "query", AgentView::Case.id(), CognitiveAnswerClass::BoundedSummary, capsule.anchor.clone(), epistemic, query.coverage(),
        EnvelopeBudget {
            requested_json: agent_json::budget(&requested), consumed_json: agent_json::budget(&consumed),
            remaining_json: agent_json::remaining(&requested, &consumed),
            degraded_dimensions: vec!["query-cpu-and-output-tokens-not-metered".to_owned(), "deployment-io-counts-payload-reads-source-io-counts-filesystem-calls".to_owned()],
            marginal_work_declined: Vec::new(),
        }, handles.iter().map(|handle| handle.handle_id.clone()).collect(), action_ids.clone(),
        EnvelopeContinuity {
            cursor: None, reanchor_triggers: vec!["Any authority/effect prefix, source/root/closure, deletion, frozen interpretation, policy or request allowance change.".to_owned()],
            session_capsule_digest: None, unresolved_obligations: capsule.obligations.iter().map(|id| id.as_str().to_owned()).collect(),
        }, decision.to_text(),
    )?;
    let payload = agent_json::cognitive_envelope(&cognitive, &handles, &action_objects)
        .ok_or(RenderError("ONVIF query cognitive envelope"))?;
    let mut warnings = orientation.warnings.clone();
    warnings.push("Retained vendor metadata and derived comparisons only. Physical identity, occupancy, coverage, absence, independent corroboration and trustworthy capture time remain unknown. All lexical vendor values and original source bytes are withheld.".to_owned());
    let mut proofs = vec![
        query.plan.plan_digest().to_text(),
        query.admission.receipt_digest().to_text(),
        query.native.request_digest.to_text(),
        query.native.decision_digest.to_text(),
        query.native.tracks.report_digest.to_text(),
        frame_digest.to_text(),
    ];
    match &query.native.analysis {
        OnvifAnalysisResult::Tracks => {}
        OnvifAnalysisResult::Lifecycle {
            report,
            documents_digest,
            ..
        } => {
            proofs.push(report.report_digest.to_text());
            proofs.push(documents_digest.to_text());
        }
        OnvifAnalysisResult::Zones(report) => {
            proofs.push(report.report_digest.to_text());
            proofs.push(report.policy_digest.to_text());
        }
    }
    build_onvif_response(ResponseParts {
        operation: "query", request_digest: query.request_digest, principal: args.request.principal.clone(),
        session_id: Some(query.session_id.as_str().to_owned()), mission_id: Some(query.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(), view: AgentView::Case, capability: CAPABILITY_QUERY, outcome: ResponseOutcome::Ok,
        error_id: None, payload_schema: AgentCognitiveEnvelope::SCHEMA, payload_json: payload,
        epistemic_state: KnowledgeState::Unknown, completeness: Completeness::Bounded, warnings,
        contradictions: orientation.contradictions.clone(),
        degradation: vec![format!("CPU time, full output tokens and elapsed latency are not metered. Conservative source/parser/projection work reservations total {} units. The 60-second deadline is cooperative. Deployment counters measure metadata payload reads/bytes; source counters include metered filesystem calls.", query.native.reserved_work_units)],
        budgets_json: agent_json::budget_summary(&requested, &consumed), proof_pointers: proofs,
        affordances: action_ids, affordance_objects: action_objects, decision_fingerprint: decision,
        compression_receipt_id: None, continuation: None, recovery_class: "safe_read_retry", safe_retry: ResponseSafeRetry::YesSameRequest,
        boundary: read_only_boundary("Verified exact retained ONVIF source closures and complete redacted analysis, then revalidated current authority, effect history and deletion restrictions without recovery, initialization, publisher locks or writes.".to_owned()),
        created_at_ns: capsule.created_at.0, workspace_revision: None, idempotency_key: None,
    })
}

fn refusal(
    args: &OnvifQueryArgs,
    query: &DeploymentOnvifQuery,
    reason: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let digest = request_identity("fss.cli.onvif_query.refusal.v1", |encoder| {
        encoder.digest(query.request_digest);
        encoder.text(reason);
    });
    build_onvif_response(ResponseParts {
        operation: "query", request_digest: digest, principal: args.request.principal.clone(), session_id: None, mission_id: None,
        anchor: query.snapshot.anchor.clone(), view: AgentView::Case, capability: CAPABILITY_QUERY,
        outcome: ResponseOutcome::Refused, error_id: Some(ERR_AGENT_CONTEXT_INCOMPLETE),
        payload_schema: AgentCognitiveEnvelope::SCHEMA, payload_json: "null".to_owned(), epistemic_state: KnowledgeState::Unknown,
        completeness: Completeness::Partial, warnings: vec![reason.to_owned()], contradictions: Vec::new(),
        degradation: vec!["No ONVIF analysis was delivered. Refusal is not an empty match set; refused-read resource accounting is not reported.".to_owned()],
        budgets_json: agent_json::budget_summary(&BudgetVector::default(), &BudgetVector::default()), proof_pointers: Vec::new(),
        affordances: Vec::new(), affordance_objects: Vec::new(), decision_fingerprint: digest, compression_receipt_id: None,
        continuation: None, recovery_class: "operator_action_required", safe_retry: ResponseSafeRetry::No,
        boundary: read_only_boundary("The ONVIF query refused without returning a partial analysis or original source bytes.".to_owned()),
        created_at_ns: query.snapshot.latest_evidence_time.0, workspace_revision: None, idempotency_key: None,
    })
}

/// Execute the registered query/case read and preserve protected deployment context.
#[must_use]
pub fn execute_onvif_query(args: &OnvifQueryArgs) -> (String, ExitIdentity) {
    let limits = OnvifQueryLimits::default();
    let started = Instant::now();
    let query =
        match query_onvif_in_deployment(&HostSpoolIo, &args.root, &args.request, limits, &|| {
            started.elapsed() >= READ_DEADLINE
        }) {
            Ok(query) => query,
            Err(error) => {
                let (code, exit) = match error {
                    OnvifQueryError::InvalidRequest => (
                        crate::ERR_CLI_MALFORMED_VALUE,
                        ExitIdentity::MALFORMED_VALUE,
                    ),
                    OnvifQueryError::Deployment(DeploymentReadError::NotADeployment { .. }) => (
                        crate::error::ERR_DOCTOR_NOT_A_DEPLOYMENT,
                        ExitIdentity::DOCTOR_NOT_A_DEPLOYMENT,
                    ),
                    _ => (ERR_AGENT_CONTEXT_INCOMPLETE, ExitIdentity::AGENT_REFUSED),
                };
                return (execution_diagnostic("query", &args.root, code, exit), exit);
            }
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
                refusal(args, &query, &error.to_string()),
                ExitIdentity::AGENT_REFUSED,
                "query",
                &args.root,
            );
        }
    };
    match response(args, &query, &orientation, limits) {
        Ok(_) if started.elapsed() >= READ_DEADLINE => rendered(
            refusal(
                args,
                &query,
                "The cooperative ONVIF query deadline elapsed before output; no result was delivered.",
            ),
            ExitIdentity::AGENT_REFUSED,
            "query",
            &args.root,
        ),
        Ok(output) if output.len() <= MAX_QUERY_OUTPUT_BYTES => (output, ExitIdentity::SUCCESS),
        Ok(_) => rendered(
            refusal(
                args,
                &query,
                "Complete ONVIF response exceeds 256 KiB; select fewer exact sources or a smaller analysis. Nothing was truncated.",
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

#![forbid(unsafe_code)]
//! Byte-free AOP-005 queries of explicitly pinned native AVC/HEVC recording catalogs.

/// Explicit retained-clock UTC selection, separate from the legacy decode-clock request.
pub mod utc;

/// One shared decode-clock query over explicitly pinned catalogs.
pub mod set;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use fss_core::{
    AgentCognitiveEnvelope, AgentView, BudgetVector, CognitiveAnswerClass, Completeness,
    ContentDigest, EnvelopeBudget, EnvelopeContinuity, EnvelopeCoverage, EnvelopeEpistemic,
    EnvelopeProposition, KnowledgeState, PrincipalId, ResponseOutcome, ResponseSafeRetry, SensorId,
    StreamId,
};
use fss_object::HostSpoolIo;
use fss_publication::SlotName;
use fss_reference::agent_follow::AnchorToken;
use fss_reference::agent_orient::{
    DeploymentOrientation, DeploymentSnapshot, OrientRequest, orient_deployment,
};
use fss_reference::agent_query::CAPABILITY_QUERY;
use fss_reference::agent_recording_context::{
    DeploymentRecordingQuery, RecordingContextError, RecordingContextLimits,
    RecordingContextRequest, query_recordings_in_deployment,
};
use fss_reference::agent_recordings::{RecordingQueryCodec, RecordingQueryRequest};
use fss_reference::rtsp::recording::{MAX_RECORDING_BYTES, RecordingScope};
use fss_reference::rtsp::recording_catalog::CatalogScope;

use crate::agent_json;
use crate::error::{CliError, ExitIdentity};
use crate::orient_cmd::{
    ERR_AGENT_CONTEXT_INCOMPLETE, RenderError, ResponseParts, build_recording_response,
    collect_options, contexts, execution_diagnostic, internal_failure, principal,
    read_only_boundary, rendered, request_identity, required_root, take,
};
use crate::query_cmd::MAX_QUERY_OUTPUT_BYTES;
use crate::token::ArgToken;

/// Current deployment context plus a separately and explicitly selected archive root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingQueryArgs {
    /// Existing deployment; never opened for mutation by this command.
    pub root: PathBuf,
    /// Existing native object/archive root fixed by the operator.
    pub archive_root: PathBuf,
    /// Exact source/catalog pins, bounded interval and current deployment precondition.
    pub request: RecordingContextRequest,
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

fn required<'a>(
    values: &'a [(String, String, usize)],
    name: &str,
) -> Result<(&'a str, usize), CliError> {
    take(values, name)
        .map(|(_, value, index)| (value.as_str(), *index))
        .ok_or_else(|| CliError::MissingValue {
            option: name.to_owned(),
            command: Some("query".to_owned()),
            expected: format!("explicit {name} for a pinned recording query"),
        })
}

fn number<T: std::str::FromStr + ToString>(
    name: &str,
    value: &str,
    index: usize,
) -> Result<T, CliError> {
    let parsed = value
        .parse::<T>()
        .map_err(|_| malformed(name, value, "integer outside range", index))?;
    if parsed.to_string() != value {
        return Err(malformed(
            name,
            value,
            "expected canonical decimal spelling",
            index,
        ));
    }
    Ok(parsed)
}

struct RecordingPins {
    codec: RecordingQueryCodec,
    scope: CatalogScope,
    catalog_slot: SlotName,
    catalog_root: ContentDigest,
    max_windows: usize,
    max_hydration_bytes: u64,
}

fn pin_digest(values: &[(String, String, usize)], name: &str) -> Result<ContentDigest, CliError> {
    let (value, index) = required(values, name)?;
    let parsed =
        ContentDigest::parse(value).map_err(|_| malformed(name, value, "invalid digest", index))?;
    if parsed.to_text() != value {
        return Err(malformed(
            name,
            value,
            "expected canonical digest spelling",
            index,
        ));
    }
    Ok(parsed)
}

fn pin_integer(values: &[(String, String, usize)], name: &str) -> Result<u64, CliError> {
    let (value, index) = required(values, name)?;
    number(name, value, index)
}

fn expected_anchor(values: &[(String, String, usize)]) -> Result<Option<AnchorToken>, CliError> {
    take(values, "--anchor")
        .map(|(_, value, index)| {
            AnchorToken::parse(value).ok_or_else(|| {
                malformed(
                    "--anchor",
                    value,
                    "expected exact deployment anchor token",
                    *index,
                )
            })
        })
        .transpose()
}

fn recording_source_pins(
    values: &[(String, String, usize)],
) -> Result<(RecordingQueryCodec, CatalogScope, usize, u64), CliError> {
    let (target, target_index) = required(values, "--target")?;
    if target != "recordings" {
        return Err(malformed(
            "--target",
            target,
            "expected recordings",
            target_index,
        ));
    }
    let (codec, index) = required(values, "--codec")?;
    let codec = match codec {
        "avc" => RecordingQueryCodec::Avc,
        "hevc" => RecordingQueryCodec::Hevc,
        _ => return Err(malformed("--codec", codec, "expected avc or hevc", index)),
    };
    let (sensor, index) = required(values, "--sensor")?;
    let sensor = SensorId::parse(sensor)
        .map_err(|_| malformed("--sensor", sensor, "invalid sensor identity", index))?;
    let (stream, index) = required(values, "--stream")?;
    let stream = StreamId::parse(stream)
        .map_err(|_| malformed("--stream", stream, "invalid stream identity", index))?;
    let (time_scale, index) = required(values, "--time-scale")?;
    let time_scale = number::<u32>("--time-scale", time_scale, index)?;
    let max_windows = take(values, "--max-windows")
        .map(|(_, value, index)| number::<usize>("--max-windows", value, *index))
        .transpose()?
        .unwrap_or(32);
    if !(1..=32).contains(&max_windows) {
        return Err(malformed(
            "--max-windows",
            &max_windows.to_string(),
            "expected 1..32; overflow refuses without truncation",
            0,
        ));
    }
    let max_hydration_bytes = take(values, "--max-hydration-bytes")
        .map(|(_, value, index)| number::<u64>("--max-hydration-bytes", value, *index))
        .transpose()?
        .unwrap_or((32 * MAX_RECORDING_BYTES) as u64);
    Ok((
        codec,
        CatalogScope {
            recording: RecordingScope {
                sensor,
                stream,
                generation: pin_integer(values, "--generation")?,
                anchor: pin_digest(values, "--source-anchor")?,
                receive_clock: pin_digest(values, "--receive-clock")?,
            },
            decode_clock: pin_digest(values, "--decode-clock")?,
            time_scale,
        },
        max_windows,
        max_hydration_bytes,
    ))
}

fn recording_pins(values: &[(String, String, usize)]) -> Result<RecordingPins, CliError> {
    let (codec, scope, max_windows, max_hydration_bytes) = recording_source_pins(values)?;
    let (slot, index) = required(values, "--catalog-slot")?;
    let catalog_slot = SlotName::parse(slot)
        .map_err(|_| malformed("--catalog-slot", slot, "invalid publication slot", index))?;
    Ok(RecordingPins {
        codec,
        scope,
        catalog_slot,
        catalog_root: pin_digest(values, "--catalog-root")?,
        max_windows,
        max_hydration_bytes,
    })
}

/// Parses a closed grammar. Historical deployment selectors, file-import filters and
/// continuations are not silently reinterpreted as native decode-clock queries.
pub fn parse_recording_query_args(tokens: &[ArgToken]) -> Result<RecordingQueryArgs, CliError> {
    let values = collect_options(
        "query",
        tokens,
        &[
            "--target",
            "--root",
            "--archive-root",
            "--principal",
            "--anchor",
            "--codec",
            "--catalog-slot",
            "--catalog-root",
            "--sensor",
            "--stream",
            "--generation",
            "--source-anchor",
            "--receive-clock",
            "--decode-clock",
            "--time-scale",
            "--start-tick",
            "--end-tick",
            "--max-windows",
            "--max-hydration-bytes",
        ],
    )?;
    let pins = recording_pins(&values)?;
    let recording = RecordingQueryRequest {
        codec: pins.codec,
        scope: pins.scope,
        catalog_slot: pins.catalog_slot,
        catalog_root: pins.catalog_root,
        interval: pin_integer(&values, "--start-tick")?..pin_integer(&values, "--end-tick")?,
        max_windows: pins.max_windows,
        max_hydration_bytes: pins.max_hydration_bytes,
    };
    recording
        .validate()
        .map_err(|error| malformed("query", "[redacted]", &error.to_string(), 0))?;
    let expected_anchor = expected_anchor(&values)?;
    let (archive_root, _) = required(&values, "--archive-root")?;
    Ok(RecordingQueryArgs {
        root: required_root("query", &values)?,
        archive_root: PathBuf::from(archive_root),
        request: RecordingContextRequest {
            recording,
            principal: principal("query", &values)?,
            expected_anchor,
        },
    })
}

// Only the transport projection is shared. Decode-clock and UTC requests retain their own
// native types, verification, canonical identities, clock semantics and refusal domains.
type RecordingResponseBuilder = fn(ResponseParts) -> Result<String, Box<dyn std::error::Error>>;

struct RecordingResponseView<'a> {
    request_digest: ContentDigest,
    decision_digest: ContentDigest,
    principal: PrincipalId,
    anchor_token: &'a str,
    session_id: &'a str,
    mission_id: &'a str,
    epistemic: EnvelopeEpistemic,
    coverage: EnvelopeCoverage,
    allowance: BudgetVector,
    deployment_bytes_read: u64,
    deployment_metadata_reads: u64,
    archive_bytes_read: u64,
    archive_io_calls: u64,
    metadata_handles: Vec<(ContentDigest, &'static str)>,
    proof_pointers: Vec<String>,
    context_decision_domain: &'static str,
    build_response: RecordingResponseBuilder,
    warning: &'static str,
    boundary: &'static str,
}

fn response(
    args: &RecordingQueryArgs,
    query: &DeploymentRecordingQuery,
    orientation: &DeploymentOrientation,
    limits: &RecordingContextLimits,
) -> Result<String, Box<dyn std::error::Error>> {
    render_response(
        RecordingResponseView {
            request_digest: query.request_digest,
            decision_digest: query.decision_digest,
            principal: args.request.principal.clone(),
            anchor_token: &query.anchor_token,
            session_id: query.session_id.as_str(),
            mission_id: query.mission_id.as_str(),
            epistemic: query.epistemic(&args.request.recording),
            coverage: query.coverage(),
            allowance: limits.allowance()?,
            deployment_bytes_read: query.deployment_bytes_read,
            deployment_metadata_reads: query.deployment_metadata_reads,
            archive_bytes_read: query.native.read_usage.read_bytes,
            archive_io_calls: query.native.read_usage.io_calls,
            metadata_handles: std::iter::once((
                query.native.catalog_metadata_digest,
                "recording_catalog_metadata",
            ))
            .chain(
                query
                    .native
                    .rows
                    .iter()
                    .map(|row| (row.entry.root(), "recording_window_metadata")),
            )
            .collect(),
            proof_pointers: vec![
                query.plan.plan_digest().to_text(),
                query.admission.receipt_digest().to_text(),
                query.native.request_digest.to_text(),
                query.native.decision_digest.to_text(),
                query.native.catalog_root.to_text(),
                query.native.catalog_metadata_digest.to_text(),
            ],
            context_decision_domain: "fss.cli.recording_query.context_decision.v1",
            build_response: build_recording_response,
            warning: "Recording metadata only. Payload availability, physical coverage, absence, trusted UTC and gap causes remain unknown. A hydration byte quote grants no hydration authority.",
            boundary: "Verified one exact native recording catalog, member publications and metadata; revalidated archive custody and the bracketed deployment prefix without recovery or source-media reads.",
        },
        orientation,
    )
}

fn render_response(
    mut query: RecordingResponseView<'_>,
    orientation: &DeploymentOrientation,
) -> Result<String, Box<dyn std::error::Error>> {
    let text = query.request_digest.to_text();
    let hex = text.strip_prefix("sha256:").unwrap_or(&text);
    let capsule = orientation.capsule();
    let mut epistemic = query.epistemic;
    epistemic.propositions.push(EnvelopeProposition {
        id: "claim:recordings:deployment-anchor".to_owned(),
        statement: format!("Exact deployment authority/effect-history token: {}. This token is distinct from the historical recording's source anchor.", query.anchor_token),
        state: KnowledgeState::Known,
        provenance: "derived".to_owned(),
        evidence: vec![query.decision_digest.to_text()],
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
        .metadata_handles
        .into_iter()
        .map(|(digest, kind)| agent_json::EvidenceHandle {
            handle_id: format!("fss://proof/{digest}"),
            object_digest: digest,
            kind: kind.to_owned(),
            hydration: "H0",
            allowed_hydration: vec!["H0"],
            privacy_class: "private:property".to_owned(),
            // Availability refers to the verified metadata object alone, never its media.
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
            .ok_or(RenderError("recording query affordance objects"))?;
    let frame_digest = capsule.frame.frame_digest()?;
    let decision = request_identity(query.context_decision_domain, |encoder| {
        encoder.digest(query.decision_digest);
        encoder.digest(frame_digest);
    });
    let allowance = query.allowance;
    let mut requested = orientation.requested;
    requested.latency_ms = allowance.latency_ms;
    requested.bytes = allowance.bytes;
    requested.storage_operations = allowance.storage_operations;
    let mut consumed = orientation.consumed;
    consumed.bytes = query
        .deployment_bytes_read
        .checked_add(query.archive_bytes_read)
        .ok_or(RenderError("recording query byte accounting overflow"))?;
    consumed.storage_operations = query
        .deployment_metadata_reads
        .checked_add(query.archive_io_calls)
        .ok_or(RenderError("recording query operation accounting overflow"))?;
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
        query.coverage,
        EnvelopeBudget {
            requested_json: agent_json::budget(&requested),
            consumed_json: agent_json::budget(&consumed),
            remaining_json: agent_json::remaining(&requested, &consumed),
            degraded_dimensions: vec![
                "query-cpu-and-output-tokens-not-metered".to_owned(),
                "deployment-io-counts-payload-reads-archive-io-counts-filesystem-calls".to_owned(),
            ],
            marginal_work_declined: Vec::new(),
        },
        handles
            .iter()
            .map(|handle| handle.handle_id.clone())
            .collect(),
        action_ids.clone(),
        EnvelopeContinuity {
            cursor: None,
            reanchor_triggers: vec![
                "Any deployment-prefix, catalog, publication, tombstone or exact query-pin change."
                    .to_owned(),
            ],
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
        .ok_or(RenderError("recording query cognitive envelope"))?;
    let mut warnings = orientation.warnings.clone();
    warnings.push(query.warning.to_owned());
    warnings.push("The current deployment and historical archive are independently verified; there is no cross-owner atomic snapshot or inferred source registration.".to_owned());
    query.proof_pointers.push(frame_digest.to_text());
    (query.build_response)(ResponseParts {
        operation: "query",
        request_digest: query.request_digest,
        principal: query.principal,
        session_id: Some(query.session_id.to_owned()),
        mission_id: Some(query.mission_id.to_owned()),
        anchor: capsule.anchor.clone(),
        view: AgentView::Case,
        capability: CAPABILITY_QUERY,
        outcome: ResponseOutcome::Ok,
        error_id: None,
        payload_schema: AgentCognitiveEnvelope::SCHEMA,
        payload_json: payload,
        epistemic_state: KnowledgeState::Unknown,
        completeness: Completeness::Bounded,
        warnings,
        contradictions: orientation.contradictions.clone(),
        degradation: vec!["CPU, full output tokens and elapsed latency are not metered. The 60-second read deadline is cooperative. Deployment counters measure metadata payload reads/bytes; archive counters include metered filesystem calls and framing reads.".to_owned()],
        budgets_json: agent_json::budget_summary(&requested, &consumed),
        proof_pointers: query.proof_pointers,
        affordances: action_ids,
        affordance_objects: action_objects,
        decision_fingerprint: decision,
        compression_receipt_id: None,
        continuation: None,
        recovery_class: "safe_read_retry",
        safe_retry: ResponseSafeRetry::YesSameRequest,
        boundary: read_only_boundary(query.boundary.to_owned()),
        created_at_ns: capsule.created_at.0,
        workspace_revision: None,
        idempotency_key: None,
    })
}

fn refusal(
    args: &RecordingQueryArgs,
    query: &DeploymentRecordingQuery,
    reason: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    render_refusal(
        args.request.principal.clone(),
        &query.snapshot,
        query.request_digest,
        reason,
        "fss.cli.recording_query.refusal.v1",
        build_recording_response,
    )
}

fn render_refusal(
    principal: PrincipalId,
    snapshot: &DeploymentSnapshot,
    request_digest: ContentDigest,
    reason: &str,
    domain: &str,
    build_response: RecordingResponseBuilder,
) -> Result<String, Box<dyn std::error::Error>> {
    let digest = request_identity(domain, |encoder| {
        encoder.digest(request_digest);
        encoder.text(reason);
    });
    build_response(ResponseParts {
        operation: "query",
        request_digest: digest,
        principal,
        session_id: None,
        mission_id: None,
        anchor: snapshot.anchor.clone(),
        view: AgentView::Case,
        capability: CAPABILITY_QUERY,
        outcome: ResponseOutcome::Refused,
        error_id: Some(ERR_AGENT_CONTEXT_INCOMPLETE),
        payload_schema: AgentCognitiveEnvelope::SCHEMA,
        payload_json: "null".to_owned(),
        epistemic_state: KnowledgeState::Unknown,
        completeness: Completeness::Partial,
        warnings: vec![reason.to_owned()],
        contradictions: Vec::new(),
        degradation: vec!["No recording result was delivered. A refusal is not an empty match set; refused-read accounting is not reported.".to_owned()],
        budgets_json: agent_json::budget_summary(&BudgetVector::default(), &BudgetVector::default()),
        proof_pointers: Vec::new(),
        affordances: Vec::new(),
        affordance_objects: Vec::new(),
        decision_fingerprint: digest,
        compression_receipt_id: None,
        continuation: None,
        recovery_class: "operator_action_required",
        safe_retry: ResponseSafeRetry::No,
        boundary: read_only_boundary("Recording metadata query refused without returning media or a result selection.".to_owned()),
        created_at_ns: snapshot.latest_evidence_time.0,
        workspace_revision: None,
        idempotency_key: None,
    })
}

/// Execute the registered query/case read, retaining protected current deployment cells.
#[must_use]
pub fn execute_recording_query(args: &RecordingQueryArgs) -> (String, ExitIdentity) {
    let limits = RecordingContextLimits::default();
    let started = Instant::now();
    let query = match query_recordings_in_deployment(
        &HostSpoolIo,
        &args.root,
        &args.archive_root,
        &args.request,
        &limits,
        &|| started.elapsed() >= Duration::from_secs(60),
    ) {
        Ok(query) => query,
        Err(error) => {
            // No fabricated deployment anchor if the native reader could not establish one.
            let (code, exit) = match error {
                RecordingContextError::InvalidRequest => (
                    crate::ERR_CLI_MALFORMED_VALUE,
                    ExitIdentity::MALFORMED_VALUE,
                ),
                RecordingContextError::Deployment(
                    fss_reference::agent_orient::DeploymentReadError::NotADeployment { .. },
                ) => (
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
    match response(args, &query, &orientation, &limits) {
        Ok(output) if output.len() <= MAX_QUERY_OUTPUT_BYTES => (output, ExitIdentity::SUCCESS),
        Ok(_) => rendered(
            refusal(
                args,
                &query,
                "Complete recording response exceeds 256 KiB; narrow the decode-clock interval. Nothing was truncated.",
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

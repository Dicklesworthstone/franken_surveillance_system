#![forbid(unsafe_code)]
//! UTC candidate metadata across explicitly pinned capture sessions of one sensor and stream.
//! The request never substitutes a UTC interval for decode ticks or source capture time.

use super::*;
use crate::json_input::Value;
use crate::orient_cmd::build_recording_utc_response;
use fss_reference::agent_recording_context::utc_sessions::{
    DeploymentRecordingUtcSessionsQuery, RecordingUtcSessionsContextError,
    RecordingUtcSessionsContextLimits, RecordingUtcSessionsContextRequest,
    query_recordings_utc_sessions_in_deployment,
};
use fss_reference::agent_recordings::set::RecordingCatalogPin;
use fss_reference::agent_recordings::utc_sessions::{
    RecordingUtcSessionPin, RecordingUtcSessionsRequest,
};

/// Existing deployment and archive owners with exact retained UTC interpretation pins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingUtcSessionsQueryArgs {
    /// Current deployment metadata; never opened for mutation.
    pub root: PathBuf,
    /// Explicit existing native archive root.
    pub archive_root: PathBuf,
    /// Exact source/catalog/clock companion, UTC interval and deployment precondition.
    pub request: RecordingUtcSessionsContextRequest,
}

/// Maximum literal session selector, independently bounded before JSON parsing.
pub const MAX_SESSIONS_JSON_BYTES: usize = 64 * 1024;

fn invalid_sessions(index: usize, reason: &str) -> CliError {
    malformed("--sessions", "[redacted]", reason, index)
}

fn session_pin(value: &Value, index: usize) -> Result<RecordingUtcSessionPin, CliError> {
    let fields = value
        .object()
        .ok_or_else(|| invalid_sessions(index, "expected a session object"))?;
    let allowed = [
        "codec",
        "sensor",
        "stream",
        "generation",
        "source_anchor",
        "receive_clock",
        "decode_clock",
        "time_scale",
        "catalogs",
        "clock_slot",
        "clock_root",
    ];
    if fields.len() != allowed.len() || fields.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid_sessions(
            index,
            "each session requires only the eleven exact source/catalog/clock fields",
        ));
    }
    let text = |field: &str, bound: usize| -> Result<&str, CliError> {
        fields
            .get(field)
            .and_then(Value::text)
            .filter(|value| !value.is_empty() && value.len() <= bound)
            .ok_or_else(|| {
                invalid_sessions(
                    index,
                    "expected a bounded source/clock string or exact decimal string",
                )
            })
    };
    let mut values = vec![("--target".to_owned(), "recordings".to_owned(), index)];
    for (field, option, bound) in [
        ("codec", "--codec", 4),
        ("sensor", "--sensor", 128),
        ("stream", "--stream", 128),
        ("generation", "--generation", 20),
        ("source_anchor", "--source-anchor", 71),
        ("receive_clock", "--receive-clock", 71),
        ("decode_clock", "--decode-clock", 71),
        ("clock_slot", "--clock-slot", 128),
        ("clock_root", "--clock-root", 71),
    ] {
        values.push((option.to_owned(), text(field, bound)?.to_owned(), index));
    }
    let Some(Value::Number(time_scale)) = fields.get("time_scale") else {
        return Err(invalid_sessions(
            index,
            "session time_scale requires a positive JSON integer",
        ));
    };
    values.push(("--time-scale".to_owned(), time_scale.clone(), index));
    let (codec, scope, _, _) = recording_source_pins(&values)?;
    let pins = fields
        .get("catalogs")
        .and_then(Value::array)
        .filter(|pins| (1..=8).contains(&pins.len()))
        .ok_or_else(|| {
            invalid_sessions(index, "each session requires one to eight catalog pins")
        })?;
    let mut catalogs = Vec::with_capacity(pins.len());
    for pin in pins {
        let fields = pin
            .object()
            .filter(|fields| fields.len() == 2)
            .ok_or_else(|| invalid_sessions(index, "catalog pins contain only slot and root"))?;
        let slot = fields
            .get("slot")
            .and_then(Value::text)
            .filter(|text| text.len() <= 128)
            .ok_or_else(|| invalid_sessions(index, "expected an exact catalog slot"))?;
        let slot = SlotName::parse(slot)
            .map_err(|_| invalid_sessions(index, "invalid catalog publication slot"))?;
        let root = fields
            .get("root")
            .and_then(Value::text)
            .filter(|text| text.len() == 71)
            .ok_or_else(|| invalid_sessions(index, "expected a canonical SHA-256 catalog root"))?;
        let digest = ContentDigest::parse(root)
            .map_err(|_| invalid_sessions(index, "invalid catalog root"))?;
        if digest.to_text() != root {
            return Err(invalid_sessions(index, "noncanonical catalog root"));
        }
        catalogs.push(RecordingCatalogPin { slot, root: digest });
    }
    let clock_slot = SlotName::parse(text("clock_slot", 128)?)
        .map_err(|_| invalid_sessions(index, "invalid clock publication slot"))?;
    Ok(RecordingUtcSessionPin {
        codec,
        scope,
        catalogs,
        clock_slot,
        clock_root: pin_digest(&values, "--clock-root")?,
    })
}

/// Decode a literal bounded JSON selector; never read paths or infer source identity.
fn session_pins(text: &str, index: usize) -> Result<Vec<RecordingUtcSessionPin>, CliError> {
    if text.len() > MAX_SESSIONS_JSON_BYTES {
        return Err(invalid_sessions(index, "session selector exceeds 64 KiB"));
    }
    let value = crate::json_input::parse(text)
        .map_err(|_| invalid_sessions(index, "expected strict JSON with unique object keys"))?;
    let items = value
        .array()
        .filter(|items| (1..=8).contains(&items.len()))
        .ok_or_else(|| {
            invalid_sessions(index, "expected one to eight explicitly pinned sessions")
        })?;
    items.iter().map(|item| session_pin(item, index)).collect()
}

/// Parse one aggregate UTC interval with a closed per-session source and clock grammar.
/// Legacy singleton/set/discovery fields cannot silently change this request's scope.
pub fn parse_recording_utc_sessions_query_args(
    tokens: &[ArgToken],
) -> Result<RecordingUtcSessionsQueryArgs, CliError> {
    let values = collect_options(
        "query",
        tokens,
        &[
            "--target",
            "--root",
            "--archive-root",
            "--principal",
            "--anchor",
            "--sessions",
            "--start-utc-ns",
            "--end-utc-ns",
            "--max-windows",
            "--max-hydration-bytes",
        ],
    )?;
    let (target, index) = required(&values, "--target")?;
    if target != "recordings" {
        return Err(malformed("--target", target, "expected recordings", index));
    }
    let (text, index) = required(&values, "--sessions")?;
    let sessions = session_pins(text, index)?;
    let max_windows = take(&values, "--max-windows")
        .map(|(_, value, index)| number::<usize>("--max-windows", value, *index))
        .transpose()?
        .unwrap_or(32);
    if !(1..=32).contains(&max_windows) {
        return Err(malformed(
            "--max-windows",
            "[redacted]",
            "expected 1..32; overflow refuses without truncation",
            0,
        ));
    }
    let max_hydration_bytes = take(&values, "--max-hydration-bytes")
        .map(|(_, value, index)| number::<u64>("--max-hydration-bytes", value, *index))
        .transpose()?
        .unwrap_or((32 * MAX_RECORDING_BYTES) as u64);
    let recording = RecordingUtcSessionsRequest {
        sessions,
        interval: pin_integer(&values, "--start-utc-ns")?..pin_integer(&values, "--end-utc-ns")?,
        max_windows,
        max_hydration_bytes,
    };
    recording
        .validate()
        .map_err(|error| malformed("query", "[redacted]", &error.to_string(), 0))?;
    let (archive_root, _) = required(&values, "--archive-root")?;
    Ok(RecordingUtcSessionsQueryArgs {
        root: required_root("query", &values)?,
        archive_root: PathBuf::from(archive_root),
        request: RecordingUtcSessionsContextRequest {
            recording,
            principal: principal("query", &values)?,
            expected_anchor: expected_anchor(&values)?,
        },
    })
}

fn response(
    args: &RecordingUtcSessionsQueryArgs,
    query: &DeploymentRecordingUtcSessionsQuery,
    orientation: &DeploymentOrientation,
    limits: &RecordingUtcSessionsContextLimits,
) -> Result<String, Box<dyn std::error::Error>> {
    let selected_catalogs = query.selected_catalog_indexes();
    let metadata_handles = selected_catalogs
        .iter()
        .map(|(session, catalog)| {
            (
                query.native.sessions[*session].catalogs[*catalog].metadata_digest,
                "recording_catalog_metadata",
            )
        })
        .chain(
            query
                .native
                .sessions
                .iter()
                .map(|session| (session.clock_metadata_digest, "recording_clock_metadata")),
        )
        .chain(
            query
                .native
                .rows
                .iter()
                .map(|row| (row.row.entry.root(), "recording_window_metadata")),
        )
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut proof_pointers = vec![
        query.plan.plan_digest().to_text(),
        query.admission.receipt_digest().to_text(),
        query.native.request_digest.to_text(),
        query.native.decision_digest.to_text(),
    ];
    proof_pointers.extend(query.native.sessions.iter().flat_map(|session| {
        [
            session.session_digest.to_text(),
            session.clock_root.to_text(),
            session.clock_metadata_digest.to_text(),
            session.clock_approval_digest.to_text(),
        ]
    }));
    proof_pointers.extend(selected_catalogs.iter().flat_map(|(session, catalog)| {
        let catalog = &query.native.sessions[*session].catalogs[*catalog];
        [
            catalog.pin.root.to_text(),
            catalog.metadata_digest.to_text(),
        ]
    }));
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
            metadata_handles,
            proof_pointers,
            context_decision_domain: "fss.cli.recording_utc_sessions_query.context_decision.v1",
            build_response: build_recording_utc_response,
            warning: "Each capture session retains its own source generation and reconstructed node-clock evidence. UTC envelopes do not establish clock equivalence or camera exposure time. Unannotated windows remain clock_unavailable and consume the same aggregate output and hydration-quote bounds. Source bytes were not replayed; trusted UTC, physical continuity, absence and payload availability remain unknown.",
            boundary: "Verified every explicitly pinned capture session, catalog and retained clock under one aggregate archive allowance. Preserved per-session conditional gaps and clock provenance, then revalidated every publication/tombstone and the bracketed current deployment prefix without recovery or media reads. Completeness concerns the explicit session union only.",
        },
        orientation,
    )
}

fn refusal(
    args: &RecordingUtcSessionsQueryArgs,
    query: &DeploymentRecordingUtcSessionsQuery,
    reason: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    render_refusal(
        args.request.principal.clone(),
        &query.snapshot,
        query.request_digest,
        reason,
        "fss.cli.recording_utc_sessions_query.refusal.v1",
        build_recording_utc_response,
    )
}

/// Execute the metadata-only UTC query through its independently verified deployment context.
#[must_use]
pub fn execute_recording_utc_sessions_query(
    args: &RecordingUtcSessionsQueryArgs,
) -> (String, ExitIdentity) {
    let limits = RecordingUtcSessionsContextLimits::default();
    let started = Instant::now();
    let query = match query_recordings_utc_sessions_in_deployment(
        &HostSpoolIo,
        &args.root,
        &args.archive_root,
        &args.request,
        &limits,
        &|| started.elapsed() >= Duration::from_secs(60),
    ) {
        Ok(query) => query,
        Err(error) => {
            let (code, exit) = match error {
                RecordingUtcSessionsContextError::InvalidRequest => (
                    crate::ERR_CLI_MALFORMED_VALUE,
                    ExitIdentity::MALFORMED_VALUE,
                ),
                RecordingUtcSessionsContextError::Deployment(
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
                "Complete recording response exceeds 256 KiB. Narrow the UTC interval or explicitly select fewer complete capture sessions; clock-unavailable windows cannot be excluded by UTC. Nothing was truncated.",
            ),
            ExitIdentity::AGENT_REFUSED,
            "query",
            &args.root,
        ),
        Err(_) => internal_failure("query", &args.root),
    }
}

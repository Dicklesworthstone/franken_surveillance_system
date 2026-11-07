#![forbid(unsafe_code)]
//! UTC candidate metadata from an explicitly pinned retained node-clock companion.
//! The request never substitutes a UTC interval for decode ticks or source capture time.

use super::*;
use crate::orient_cmd::build_recording_utc_response;
use fss_reference::agent_recording_context::utc::{
    DeploymentRecordingUtcQuery, RecordingUtcContextError, RecordingUtcContextLimits,
    RecordingUtcContextRequest, query_recordings_utc_in_deployment,
};
use fss_reference::agent_recordings::utc::RecordingUtcQueryRequest;

/// Existing deployment and archive owners with exact retained UTC interpretation pins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingUtcQueryArgs {
    /// Current deployment metadata; never opened for mutation.
    pub root: PathBuf,
    /// Explicit existing native archive root.
    pub archive_root: PathBuf,
    /// Exact source/catalog/clock companion, UTC interval and deployment precondition.
    pub request: RecordingUtcContextRequest,
}

/// Parse UTC nanoseconds losslessly. Clock/source pins are mandatory; decode bounds,
/// capture-time predicates, continuations and effect options cannot enter this mode.
pub fn parse_recording_utc_query_args(
    tokens: &[ArgToken],
) -> Result<RecordingUtcQueryArgs, CliError> {
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
            "--clock-slot",
            "--clock-root",
            "--start-utc-ns",
            "--end-utc-ns",
            "--max-windows",
            "--max-hydration-bytes",
        ],
    )?;
    let pins = recording_pins(&values)?;
    let (slot, index) = required(&values, "--clock-slot")?;
    let clock_slot = SlotName::parse(slot).map_err(|_| {
        malformed(
            "--clock-slot",
            slot,
            "invalid clock publication slot",
            index,
        )
    })?;
    let recording = RecordingUtcQueryRequest {
        codec: pins.codec,
        scope: pins.scope,
        catalog_slot: pins.catalog_slot,
        catalog_root: pins.catalog_root,
        clock_slot,
        clock_root: pin_digest(&values, "--clock-root")?,
        interval: pin_integer(&values, "--start-utc-ns")?..pin_integer(&values, "--end-utc-ns")?,
        max_windows: pins.max_windows,
        max_hydration_bytes: pins.max_hydration_bytes,
    };
    recording
        .validate()
        .map_err(|error| malformed("query", "[redacted]", &error.to_string(), 0))?;
    let (archive_root, _) = required(&values, "--archive-root")?;
    Ok(RecordingUtcQueryArgs {
        root: required_root("query", &values)?,
        archive_root: PathBuf::from(archive_root),
        request: RecordingUtcContextRequest {
            recording,
            principal: principal("query", &values)?,
            expected_anchor: expected_anchor(&values)?,
        },
    })
}

fn response(
    args: &RecordingUtcQueryArgs,
    query: &DeploymentRecordingUtcQuery,
    orientation: &DeploymentOrientation,
    limits: &RecordingUtcContextLimits,
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
            metadata_handles: [
                (
                    query.native.catalog_metadata_digest,
                    "recording_catalog_metadata",
                ),
                (
                    query.native.clock_metadata_digest,
                    "recording_clock_metadata",
                ),
            ]
            .into_iter()
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
                query.native.clock_root.to_text(),
                query.native.clock_metadata_digest.to_text(),
                query.native.clock_approval_digest.to_text(),
            ],
            context_decision_domain: "fss.cli.recording_utc_query.context_decision.v1",
            build_response: build_recording_utc_response,
            warning: "UTC candidates reflect reconstructed retained node-clock metadata, not camera exposure time or newly verified packet-to-clock correspondence. Source payloads were not replayed. Unannotated windows remain clock_unavailable and count against the same output and hydration-quote bounds. Trusted UTC, physical coverage, absence and payload availability remain unknown.",
            boundary: "Verified one exact native recording catalog and retained clock companion, reconstructed declared node observation intervals, and revalidated publication/tombstone metadata and the bracketed deployment prefix without recovery or source-media reads.",
        },
        orientation,
    )
}

fn refusal(
    args: &RecordingUtcQueryArgs,
    query: &DeploymentRecordingUtcQuery,
    reason: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    render_refusal(
        args.request.principal.clone(),
        &query.snapshot,
        query.request_digest,
        reason,
        "fss.cli.recording_utc_query.refusal.v1",
        build_recording_utc_response,
    )
}

/// Execute the metadata-only UTC query through its independently verified deployment context.
#[must_use]
pub fn execute_recording_utc_query(args: &RecordingUtcQueryArgs) -> (String, ExitIdentity) {
    let limits = RecordingUtcContextLimits::default();
    let started = Instant::now();
    let query = match query_recordings_utc_in_deployment(
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
                RecordingUtcContextError::InvalidRequest => (
                    crate::ERR_CLI_MALFORMED_VALUE,
                    ExitIdentity::MALFORMED_VALUE,
                ),
                RecordingUtcContextError::Deployment(
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
                "Complete recording response exceeds 256 KiB. Narrow the UTC interval or use a smaller pinned catalog; clock-unavailable windows cannot be excluded by UTC. Nothing was truncated.",
            ),
            ExitIdentity::AGENT_REFUSED,
            "query",
            &args.root,
        ),
        Err(_) => internal_failure("query", &args.root),
    }
}

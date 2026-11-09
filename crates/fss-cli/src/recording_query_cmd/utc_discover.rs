#![forbid(unsafe_code)]
//! UTC candidate metadata discovered within one explicitly scoped native archive namespace.
//! The request never substitutes a UTC interval for decode ticks or source capture time.

use super::*;
use crate::orient_cmd::build_recording_utc_response;
use fss_reference::agent_recording_context::utc_discover::RecordingUtcDiscoveryContextError;
use fss_reference::agent_recording_context::utc_discover::{
    DeploymentRecordingUtcDiscoveryQuery, RecordingUtcDiscoveryContextLimits,
    RecordingUtcDiscoveryContextRequest, discover_recordings_utc_in_deployment,
};
use fss_reference::agent_recordings::utc_discover::RecordingUtcDiscoveryRequest;

/// Existing deployment and archive owners with exact retained UTC interpretation pins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingUtcDiscoveryQueryArgs {
    /// Current deployment metadata; never opened for mutation.
    pub root: PathBuf,
    /// Explicit existing native archive root.
    pub archive_root: PathBuf,
    /// Exact source namespace, clock companion, UTC interval and deployment precondition.
    pub request: RecordingUtcDiscoveryContextRequest,
}

/// Parse UTC nanoseconds losslessly. Clock/source pins are mandatory; decode bounds,
/// capture-time predicates, continuations and effect options cannot enter this mode.
pub fn parse_recording_utc_discovery_query_args(
    tokens: &[ArgToken],
) -> Result<RecordingUtcDiscoveryQueryArgs, CliError> {
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
            "--discover-catalogs",
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
    let (codec, scope, max_windows, max_hydration_bytes) = recording_source_pins(&values)?;
    let (discovery, index) = required(&values, "--discover-catalogs")?;
    if discovery != "yes" {
        return Err(malformed(
            "--discover-catalogs",
            discovery,
            "expected yes for explicit namespace discovery",
            index,
        ));
    }
    let (slot, index) = required(&values, "--clock-slot")?;
    let clock_slot = SlotName::parse(slot).map_err(|_| {
        malformed(
            "--clock-slot",
            slot,
            "invalid clock publication slot",
            index,
        )
    })?;
    let recording = RecordingUtcDiscoveryRequest {
        codec,
        scope,
        clock_slot,
        clock_root: pin_digest(&values, "--clock-root")?,
        interval: pin_integer(&values, "--start-utc-ns")?..pin_integer(&values, "--end-utc-ns")?,
        max_windows,
        max_hydration_bytes,
    };
    recording
        .validate()
        .map_err(|error| malformed("query", "[redacted]", &error.to_string(), 0))?;
    let (archive_root, _) = required(&values, "--archive-root")?;
    Ok(RecordingUtcDiscoveryQueryArgs {
        root: required_root("query", &values)?,
        archive_root: PathBuf::from(archive_root),
        request: RecordingUtcDiscoveryContextRequest {
            recording,
            principal: principal("query", &values)?,
            expected_anchor: expected_anchor(&values)?,
        },
    })
}

fn response(
    args: &RecordingUtcDiscoveryQueryArgs,
    query: &DeploymentRecordingUtcDiscoveryQuery,
    orientation: &DeploymentOrientation,
    limits: &RecordingUtcDiscoveryContextLimits,
) -> Result<String, Box<dyn std::error::Error>> {
    let selected_catalogs = query.selected_catalog_indexes();
    let metadata_handles = selected_catalogs
        .iter()
        .map(|index| {
            (
                query.native.catalogs[*index].metadata_digest,
                "recording_catalog_metadata",
            )
        })
        .chain(std::iter::once((
            query.native.clock_metadata_digest,
            "recording_clock_metadata",
        )))
        .chain(
            query
                .native
                .rows
                .iter()
                .map(|row| (row.entry.root(), "recording_window_metadata")),
        )
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut proof_pointers = vec![
        query.plan.plan_digest().to_text(),
        query.admission.receipt_digest().to_text(),
        query.native.request_digest.to_text(),
        query.native.decision_digest.to_text(),
        query.native.namespace_digest.to_text(),
        query.native.inventory_digest.to_text(),
        query.native.clock_root.to_text(),
        query.native.clock_metadata_digest.to_text(),
        query.native.clock_approval_digest.to_text(),
    ];
    proof_pointers.extend(selected_catalogs.iter().flat_map(|index| {
        let catalog = &query.native.catalogs[*index];
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
            context_decision_domain: "fss.cli.recording_utc_discovery_query.context_decision.v1",
            build_response: build_recording_utc_response,
            warning: "UTC candidates reflect reconstructed retained node-clock metadata, not camera exposure time or newly verified packet-to-clock correspondence. Source payloads were not replayed. Unannotated windows remain clock_unavailable and count against the same output and hydration-quote bounds. Trusted UTC, physical coverage, absence and payload availability remain unknown.",
            boundary: "Discovered the complete canonical native archive namespace and verified its retained clock companion with one shared archive allowance, reconstructed declared node observation intervals, and revalidated namespace membership and every publication/tombstone plus the bracketed deployment prefix without recovery or source-media reads.",
        },
        orientation,
    )
}

fn refusal(
    args: &RecordingUtcDiscoveryQueryArgs,
    query: &DeploymentRecordingUtcDiscoveryQuery,
    reason: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    render_refusal(
        args.request.principal.clone(),
        &query.snapshot,
        query.request_digest,
        reason,
        "fss.cli.recording_utc_discovery_query.refusal.v1",
        build_recording_utc_response,
    )
}

/// Execute the metadata-only UTC query through its independently verified deployment context.
#[must_use]
pub fn execute_recording_utc_discovery_query(
    args: &RecordingUtcDiscoveryQueryArgs,
) -> (String, ExitIdentity) {
    let limits = RecordingUtcDiscoveryContextLimits::default();
    let started = Instant::now();
    let query = match discover_recordings_utc_in_deployment(
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
                RecordingUtcDiscoveryContextError::InvalidRequest => (
                    crate::ERR_CLI_MALFORMED_VALUE,
                    ExitIdentity::MALFORMED_VALUE,
                ),
                RecordingUtcDiscoveryContextError::Deployment(
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
                "Complete UTC discovery response exceeds 256 KiB. Narrow the UTC interval or use an explicitly scoped catalog-set query; clock-unavailable windows cannot be excluded by UTC. Nothing was truncated.",
            ),
            ExitIdentity::AGENT_REFUSED,
            "query",
            &args.root,
        ),
        Err(_) => internal_failure("query", &args.root),
    }
}

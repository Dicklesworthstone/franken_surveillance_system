#![forbid(unsafe_code)]
//! AOP-005 catalog discovery in one explicit native archive namespace.

use super::*;
use fss_reference::agent_recording_context::discover::{
    DeploymentRecordingDiscoveryQuery, RecordingDiscoveryContextLimits,
    RecordingDiscoveryContextRequest, discover_recordings_in_deployment,
};
use fss_reference::agent_recordings::discover::RecordingDiscoveryRequest;

/// Existing deployment and archive owners with one explicitly scoped namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingDiscoveryQueryArgs {
    /// Existing current deployment metadata root.
    pub root: PathBuf,
    /// Operator-selected existing native archive root.
    pub archive_root: PathBuf,
    /// Exact source namespace, interval and deployment precondition.
    pub request: RecordingDiscoveryContextRequest,
}

/// Parse explicit namespace discovery, excluding manual catalog and UTC pins.
pub fn parse_recording_discovery_query_args(
    tokens: &[ArgToken],
) -> Result<RecordingDiscoveryQueryArgs, CliError> {
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
            "--start-tick",
            "--end-tick",
            "--max-windows",
            "--max-hydration-bytes",
        ],
    )?;
    let (discovery, index) = required(&values, "--discover-catalogs")?;
    if discovery != "yes" {
        return Err(malformed(
            "--discover-catalogs",
            discovery,
            "expected yes for explicit namespace discovery",
            index,
        ));
    }
    let (codec, scope, max_windows, max_hydration_bytes) = recording_source_pins(&values)?;
    let recording = RecordingDiscoveryRequest {
        codec,
        scope,
        interval: pin_integer(&values, "--start-tick")?..pin_integer(&values, "--end-tick")?,
        max_windows,
        max_hydration_bytes,
    };
    recording
        .validate()
        .map_err(|error| malformed("query", "[redacted]", &error.to_string(), 0))?;
    let (archive_root, _) = required(&values, "--archive-root")?;
    Ok(RecordingDiscoveryQueryArgs {
        root: required_root("query", &values)?,
        archive_root: PathBuf::from(archive_root),
        request: RecordingDiscoveryContextRequest {
            recording,
            principal: principal("query", &values)?,
            expected_anchor: expected_anchor(&values)?,
        },
    })
}

fn response(
    args: &RecordingDiscoveryQueryArgs,
    query: &DeploymentRecordingDiscoveryQuery,
    orientation: &DeploymentOrientation,
    limits: &RecordingDiscoveryContextLimits,
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
            context_decision_domain: "fss.cli.recording_discovery_query.context_decision.v1",
            build_response: build_recording_response,
            warning: "Complete selected-namespace metadata only. Other scopes, source payload availability, physical coverage, absence, trusted UTC and gap causes remain unknown. A hydration byte quote grants no media authority.",
            boundary: "Discovered and verified every canonical catalog and window in the selected namespace with one shared allowance and final membership revalidation; bracketed current deployment context without recovery or source-media reads.",
        },
        orientation,
    )
}

fn refusal(
    args: &RecordingDiscoveryQueryArgs,
    query: &DeploymentRecordingDiscoveryQuery,
    reason: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    render_refusal(
        args.request.principal.clone(),
        &query.snapshot,
        query.request_digest,
        reason,
        "fss.cli.recording_discovery_query.refusal.v1",
        build_recording_response,
    )
}

/// Execute the complete query or return a refusal; never emit a successful prefix.
#[must_use]
pub fn execute_recording_discovery_query(
    args: &RecordingDiscoveryQueryArgs,
) -> (String, ExitIdentity) {
    let limits = RecordingDiscoveryContextLimits::default();
    let started = Instant::now();
    let query = match discover_recordings_in_deployment(
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
                "Complete archive-discovery response exceeds 256 KiB; narrow the requested interval. Nothing was truncated.",
            ),
            ExitIdentity::AGENT_REFUSED,
            "query",
            &args.root,
        ),
        Err(_) => internal_failure("query", &args.root),
    }
}

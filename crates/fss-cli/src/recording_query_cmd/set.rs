#![forbid(unsafe_code)]
//! AOP-005 over an explicit bounded catalog set in one native decode-clock scope.

use super::*;
use fss_reference::agent_recording_context::set::{
    DeploymentRecordingSetQuery, RecordingSetContextLimits, RecordingSetContextRequest,
    query_recording_set_in_deployment,
};
use fss_reference::agent_recordings::set::{
    MAX_RECORDING_QUERY_CATALOGS, RecordingCatalogPin, RecordingSetQueryRequest,
};

/// Existing read-only deployment and archive owners with an exact catalog set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingSetQueryArgs {
    /// Existing current deployment metadata root.
    pub root: PathBuf,
    /// Operator-selected existing native archive root.
    pub archive_root: PathBuf,
    /// Exact source/catalog pins and deployment precondition.
    pub request: RecordingSetContextRequest,
}

/// Parse one to eight `slot=sha256:digest` pins without paths, implicit discovery or UTC.
pub fn parse_recording_set_query_args(
    tokens: &[ArgToken],
) -> Result<RecordingSetQueryArgs, CliError> {
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
            "--catalogs",
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
    let (text, index) = required(&values, "--catalogs")?;
    if text.is_empty() || text.len() > MAX_RECORDING_QUERY_CATALOGS * 201 {
        return Err(malformed(
            "--catalogs",
            "[redacted]",
            "expected 1..8 bounded slot=digest pins",
            index,
        ));
    }
    let mut catalogs = Vec::new();
    for token in text.split(',') {
        if catalogs.len() >= MAX_RECORDING_QUERY_CATALOGS {
            return Err(malformed(
                "--catalogs",
                "[redacted]",
                "at most eight catalogs",
                index,
            ));
        }
        let (slot, digest) = token.split_once('=').ok_or_else(|| {
            malformed(
                "--catalogs",
                "[redacted]",
                "expected slot=sha256:digest",
                index,
            )
        })?;
        let slot = SlotName::parse(slot).map_err(|_| {
            malformed(
                "--catalogs",
                "[redacted]",
                "invalid publication slot",
                index,
            )
        })?;
        let root = ContentDigest::parse(digest)
            .map_err(|_| malformed("--catalogs", "[redacted]", "invalid catalog digest", index))?;
        if root.to_text() != digest {
            return Err(malformed(
                "--catalogs",
                "[redacted]",
                "expected canonical digest spelling",
                index,
            ));
        }
        catalogs.push(RecordingCatalogPin { slot, root });
    }
    let (codec, scope, max_windows, max_hydration_bytes) = recording_source_pins(&values)?;
    let recording = RecordingSetQueryRequest {
        codec,
        scope,
        catalogs,
        interval: pin_integer(&values, "--start-tick")?..pin_integer(&values, "--end-tick")?,
        max_windows,
        max_hydration_bytes,
    };
    recording
        .validate()
        .map_err(|error| malformed("query", "[redacted]", &error.to_string(), 0))?;
    let (archive_root, _) = required(&values, "--archive-root")?;
    Ok(RecordingSetQueryArgs {
        root: required_root("query", &values)?,
        archive_root: PathBuf::from(archive_root),
        request: RecordingSetContextRequest {
            recording,
            principal: principal("query", &values)?,
            expected_anchor: expected_anchor(&values)?,
        },
    })
}

fn response(
    args: &RecordingSetQueryArgs,
    query: &DeploymentRecordingSetQuery,
    orientation: &DeploymentOrientation,
    limits: &RecordingSetContextLimits,
) -> Result<String, Box<dyn std::error::Error>> {
    let metadata_handles = query
        .native
        .catalogs
        .iter()
        .map(|catalog| (catalog.metadata_digest, "recording_catalog_metadata"))
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
    ];
    proof_pointers.extend(query.native.catalogs.iter().flat_map(|catalog| {
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
            context_decision_domain: "fss.cli.recording_set_query.context_decision.v1",
            build_response: build_recording_response,
            warning: "Explicit catalog-set metadata only. Source payload availability, physical coverage, absence, trusted UTC and gap causes remain unknown. A hydration byte quote grants no hydration authority.",
            boundary: "Verified the complete explicit catalog set and all member publications with one shared archive allowance and final revalidation; bracketed deployment context without recovery or source-media reads.",
        },
        orientation,
    )
}

fn refusal(
    args: &RecordingSetQueryArgs,
    query: &DeploymentRecordingSetQuery,
    reason: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    render_refusal(
        args.request.principal.clone(),
        &query.snapshot,
        query.request_digest,
        reason,
        "fss.cli.recording_set_query.refusal.v1",
        build_recording_response,
    )
}

/// Execute the complete query or return a refusal; never emit a successful prefix.
#[must_use]
pub fn execute_recording_set_query(args: &RecordingSetQueryArgs) -> (String, ExitIdentity) {
    let limits = RecordingSetContextLimits::default();
    let started = Instant::now();
    let query = match query_recording_set_in_deployment(
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
                "Complete recording-set response exceeds 256 KiB; narrow the interval or selected catalog set. Nothing was truncated.",
            ),
            ExitIdentity::AGENT_REFUSED,
            "query",
            &args.root,
        ),
        Err(_) => internal_failure("query", &args.root),
    }
}

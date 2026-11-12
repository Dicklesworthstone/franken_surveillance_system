#![forbid(unsafe_code)]
//! Canonical recorder UTC after source archive removal, using exact retained import custody.

use super::*;
use crate::orient_cmd::build_retained_recording_replay_response;
use fss_reference::agent_recording_context::replay::retained::{
    DeploymentRetainedReplayQuery, RetainedRecordingReplayLimits, RetainedRecordingReplayRequest,
    RetainedReplaySourceReadPermit, query_retained_recordings_replay_in_deployment,
};

/// Exact destination import and independently selected original recorder interpretation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedRecordingReplayQueryArgs {
    /// Existing destination deployment; no archive directory is required.
    pub root: PathBuf,
    /// Current import completion plus independent native pins.
    pub request: RetainedRecordingReplayRequest,
    /// One aggregate payload-read balance, including all final revalidation.
    pub limits: RetainedRecordingReplayLimits,
    /// Explicit local operator permission, repeated for directly constructed Rust requests.
    pub verify_replay_source: bool,
}

/// Closed imported-source grammar. Archive paths and syscall-count quotas are excluded.
pub fn parse_retained_recording_replay_query_args(
    tokens: &[ArgToken],
) -> Result<RetainedRecordingReplayQueryArgs, CliError> {
    let values = collect_options(
        "query",
        tokens,
        &[
            "--target",
            "--root",
            "--principal",
            "--anchor",
            "--retained-import",
            "--codec",
            "--sensor",
            "--stream",
            "--generation",
            "--source-anchor",
            "--receive-clock",
            "--decode-clock",
            "--time-scale",
            "--replay-root",
            "--replay-request",
            "--ntp-era",
            "--utc-start-ns",
            "--utc-end-ns",
            "--verify-replay-source",
            "--max-query-windows",
            "--max-query-samples",
            "--max-query-packets",
            "--max-query-source-bytes",
            "--max-query-results",
            "--max-query-read-bytes",
            "--max-query-read-objects",
        ],
    )?;
    let replay = parse_replay_request(&values)?;
    let import_identity = pin_digest(&values, "--retained-import")?;
    if import_identity.algorithm() != fss_core::DigestAlgorithm::Sha256
        || import_identity.bytes() == [0; 32]
    {
        return Err(malformed(
            "--retained-import",
            "[redacted]",
            "expected a nonzero SHA-256 completed import identity",
            0,
        ));
    }
    let mut limits = RetainedRecordingReplayLimits::default();
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
    limits.retained.max_source_bytes = replay.replay.limits.max_source_bytes;
    limits.validate().map_err(|_| {
        malformed(
            "query",
            "[redacted]",
            "invalid retained payload-read allowance",
            0,
        )
    })?;
    Ok(RetainedRecordingReplayQueryArgs {
        root: required_root("query", &values)?,
        request: RetainedRecordingReplayRequest {
            import_identity,
            replay,
        },
        limits,
        verify_replay_source: true,
    })
}

fn response(
    args: &RetainedRecordingReplayQueryArgs,
    query: &DeploymentRetainedReplayQuery,
    orientation: &DeploymentOrientation,
) -> Result<String, Box<dyn std::error::Error>> {
    let report = &query.report;
    render_retained_response(
        RecordingResponseView {
            request_digest: query.request_digest,
            decision_digest: query.decision_digest,
            principal: args.request.replay.principal.clone(),
            anchor_token: &query.anchor_token,
            session_id: query.session_id.as_str(),
            mission_id: query.mission_id.as_str(),
            epistemic: query.epistemic(),
            coverage: query.coverage(),
            allowance: args.limits.allowance()?,
            // This owner counts every history/source payload in a single balance. It does
            // not claim that source reads are metadata-only or filesystem syscall counts.
            deployment_bytes_read: query.read_usage.read_bytes,
            deployment_metadata_reads: query.read_usage.read_objects,
            archive_bytes_read: 0,
            archive_io_calls: 0,
            metadata_handles: [
                (query.import_root, "retained_import_publication_metadata"),
                (query.manifest_digest, "retained_import_manifest_metadata"),
                (report.receipt.root(), "replay_receipt_metadata"),
            ]
            .into_iter()
            .chain(
                report
                    .receipt
                    .windows()
                    .iter()
                    .map(|window| (window.root(), "recording_window_metadata")),
            )
            .collect(),
            proof_pointers: vec![
                query.plan.plan_digest().to_text(),
                query.admission.receipt_digest().to_text(),
                query.source_permit_digest.to_text(),
                query.import_identity.to_text(),
                report.query.digest()?.to_text(),
                report.digest.to_text(),
                report.index_digest.to_text(),
            ],
            context_decision_domain: "fss.cli.retained_recording_replay_query.context_decision.v1",
            build_response: build_retained_recording_replay_response,
            warning: "Recorder UTC assertions were reconstructed from original packets in a current retained import. The original archive was not opened. NTP era is caller-supplied; interval uncertainty covers rounding only. Missing, conflicting and source-only evidence remains explicit. Trusted clocks, exposure time, physical coverage and absence remain unknown. No media is disclosed.",
            boundary: "Verified exact completed import, native recorder receipt and original AVC/HEVC custody with one bounded immutable reader and a separate source grant; revalidated authority, publication and deletion without publisher locks, recovery, network, pixel decode or writes.",
        },
        orientation,
    )
}

fn refusal(
    args: &RetainedRecordingReplayQueryArgs,
    query: &DeploymentRetainedReplayQuery,
    reason: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    render_refusal(
        args.request.replay.principal.clone(),
        &query.snapshot,
        query.request_digest,
        reason,
        "fss.cli.retained_recording_replay_query.refusal.v1",
        build_refusal_response,
    )
}

fn build_refusal_response(mut parts: ResponseParts) -> Result<String, Box<dyn std::error::Error>> {
    parts.boundary = read_only_boundary(
        "Imported recorder query refused without returning media or a partial result. Refused read accounting is not reported.".to_owned(),
    );
    build_retained_recording_replay_response(parts)
}

fn diagnostic(
    args: &RetainedRecordingReplayQueryArgs,
    error: RecordingReplayContextError,
) -> (String, ExitIdentity) {
    let (code, exit) = match error {
        RecordingReplayContextError::InvalidRequest => (
            crate::ERR_CLI_MALFORMED_VALUE,
            ExitIdentity::MALFORMED_VALUE,
        ),
        _ => (ERR_AGENT_CONTEXT_INCOMPLETE, ExitIdentity::AGENT_REFUSED),
    };
    (execution_diagnostic("query", &args.root, code, exit), exit)
}

/// Execute under explicit source consent; a typed caller cannot bypass this check.
#[must_use]
pub fn execute_retained_recording_replay_query(
    args: &RetainedRecordingReplayQueryArgs,
) -> (String, ExitIdentity) {
    if !args.verify_replay_source {
        return diagnostic(args, RecordingReplayContextError::Unauthorized);
    }
    let allowance = match args.limits.allowance() {
        Ok(value) => value,
        Err(error) => return diagnostic(args, error),
    };
    let started = Instant::now();
    let now = || TimestampNs(i128::try_from(started.elapsed().as_nanos()).unwrap_or(i128::MAX));
    let scope = &args.request.replay.replay.scope.recording;
    let authority = match OperationId::parse("operation:retained-recording-replay-query")
        .map_err(|_| ())
        .and_then(|operation_id| {
            ContextAuthority::new_root(RootAuthoritySpec {
                trace_id: "trace:retained-recording-replay-query".to_owned(),
                operation_id,
                principal: args.request.replay.principal.as_str().to_owned(),
                capabilities: vec![
                    CAPABILITY_QUERY.to_owned(),
                    "CAP-READ-MEDIA-001".to_owned(),
                    "ADP-REPLAY-001".to_owned(),
                ],
                deadline: Some(TimestampNs(60_000_000_000)),
                priority: 10,
                budgets: allowance,
                privacy_scope: "privacy:recorder-time-source-verification".to_owned(),
                retention_scope: "retention:current-deletion-restrictions".to_owned(),
                anchor_universe: scope.anchor,
                generation: scope.generation,
            })
            .map_err(|_| ())
        }) {
        Ok(authority) => authority,
        Err(()) => return internal_failure("query", &args.root),
    };
    let permit = match RetainedReplaySourceReadPermit::authorize(
        &authority,
        &args.root,
        &args.request,
        args.limits,
        &now,
    ) {
        Ok(permit) => permit,
        Err(error) => return diagnostic(args, error),
    };
    let query = match query_retained_recordings_replay_in_deployment(
        &args.root,
        &args.request,
        args.limits,
        Some(&permit),
        &|| started.elapsed() >= Duration::from_secs(60),
    ) {
        Ok(query) => query,
        Err(error) => return diagnostic(args, error),
    };
    let orientation = match orient_deployment(
        &query.snapshot,
        &OrientRequest {
            view: AgentView::Brief,
            principal: args.request.replay.principal.clone(),
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
            if output.len() <= MAX_QUERY_OUTPUT_BYTES
                && started.elapsed() < Duration::from_secs(60) =>
        {
            (output, ExitIdentity::SUCCESS)
        }
        Ok(_) => rendered(
            refusal(
                args,
                &query,
                "Complete imported recorder response exceeded 256 KiB or the cooperative deadline. No result prefix was delivered; unknown and source-only observations were preserved.",
            ),
            ExitIdentity::AGENT_REFUSED,
            "query",
            &args.root,
        ),
        Err(_) => internal_failure("query", &args.root),
    }
}

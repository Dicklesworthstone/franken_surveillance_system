#![forbid(unsafe_code)]
//! Exact recorder UTC assertions under an explicitly granted, bounded source read.
//!
//! Catalog UTC remains a separate metadata-only request. This mode verifies original packet
//! custody through the native replay owner and discloses only its source-linked assertions.

use super::*;
use crate::orient_cmd::build_recording_replay_response;
use fss_core::{ContextAuthority, OperationId, RootAuthoritySpec, TimestampNs};
use fss_reference::agent_recording_context::replay::{
    DeploymentRecordingReplayQuery, RecordingReplayContextError, RecordingReplayContextLimits,
    RecordingReplayContextRequest, ReplaySourceReadPermit, query_recordings_replay_in_deployment,
};
use fss_reference::rtsp::recording_replay::ReplayCodec;
use fss_reference::rtsp::recording_replay::time::pinned::ReplayTimeReadLimits;
use fss_reference::rtsp::recording_replay::time::{ReplayTimeLimits, ReplayTimeQuery};

/// Presence of any replay-specific input selects this closed grammar, including incomplete
/// requests. No replay pin, consent or work bound can be silently dropped by a metadata mode.
pub(crate) const SELECTORS: &[&str] = &[
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
    "--max-query-io-calls",
];

/// Largest complete result inventory admitted by the canonical response surface.
pub const MAX_REPLAY_QUERY_RESULTS: usize = 128;
/// Default complete result inventory, including unknown samples and source-only groups.
pub const DEFAULT_REPLAY_QUERY_RESULTS: usize = 32;

/// Current deployment and explicitly selected archive, interpretation and source-read allowance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingReplayQueryArgs {
    /// Existing deployment metadata; never opened for publication or recovery.
    pub root: PathBuf,
    /// Operator-selected existing native archive. MCP fixes this at launch.
    pub archive_root: PathBuf,
    /// Complete native replay pins, interval and current deployment precondition.
    pub request: RecordingReplayContextRequest,
    /// Independent metadata/source read budgets, bound by the source-read permit.
    pub limits: RecordingReplayContextLimits,
    /// Explicit local operator grant; execution repeats this gate for typed callers.
    pub verify_replay_source: bool,
}

fn optional_number<T: std::str::FromStr + ToString>(
    values: &[(String, String, usize)],
    name: &str,
    default: T,
) -> Result<T, CliError> {
    take(values, name)
        .map(|(_, value, index)| number(name, value, *index))
        .transpose()
        .map(|value| value.unwrap_or(default))
}

/// Parse independent replay interpretation pins and explicit local source-read consent.
/// Existing catalog/clock selectors, imported footage filters and mutation options are refused.
pub fn parse_recording_replay_query_args(
    tokens: &[ArgToken],
) -> Result<RecordingReplayQueryArgs, CliError> {
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
            "--max-query-io-calls",
        ],
    )?;
    let (target, index) = required(&values, "--target")?;
    if target != "recordings" {
        return Err(malformed("--target", target, "expected recordings", index));
    }
    let (consent, index) = required(&values, "--verify-replay-source")?;
    if consent != "yes" {
        return Err(malformed(
            "--verify-replay-source",
            "[redacted]",
            "explicit yes is required to verify private replay sources without disclosing media",
            index,
        ));
    }
    let (codec, index) = required(&values, "--codec")?;
    let codec = match codec {
        "avc" => ReplayCodec::Avc,
        "hevc" => ReplayCodec::Hevc,
        _ => return Err(malformed("--codec", codec, "expected avc or hevc", index)),
    };
    let (sensor, index) = required(&values, "--sensor")?;
    let sensor = SensorId::parse(sensor)
        .map_err(|_| malformed("--sensor", sensor, "invalid sensor identity", index))?;
    let (stream, index) = required(&values, "--stream")?;
    let stream = StreamId::parse(stream)
        .map_err(|_| malformed("--stream", stream, "invalid stream identity", index))?;
    let defaults = ReplayTimeLimits::default();
    let query_limits = ReplayTimeLimits {
        max_windows: optional_number(&values, "--max-query-windows", defaults.max_windows)?,
        max_samples: optional_number(&values, "--max-query-samples", defaults.max_samples)?,
        max_packets: optional_number(&values, "--max-query-packets", defaults.max_packets)?,
        max_source_bytes: optional_number(
            &values,
            "--max-query-source-bytes",
            defaults.max_source_bytes,
        )?,
        max_results: optional_number(&values, "--max-query-results", DEFAULT_REPLAY_QUERY_RESULTS)?,
    };
    if !(1..=MAX_REPLAY_QUERY_RESULTS).contains(&query_limits.max_results) {
        return Err(malformed(
            "--max-query-results",
            "[redacted]",
            "expected 1..128 complete rows; unknown and source-only rows consume the same bound",
            0,
        ));
    }
    let (time_scale, index) = required(&values, "--time-scale")?;
    let time_scale = number("--time-scale", time_scale, index)?;
    let (era, index) = required(&values, "--ntp-era")?;
    let ntp_era = number("--ntp-era", era, index)?;
    let (start, index) = required(&values, "--utc-start-ns")?;
    let start_ns = number("--utc-start-ns", start, index)?;
    let (end, index) = required(&values, "--utc-end-ns")?;
    let end_ns = number("--utc-end-ns", end, index)?;
    let replay = ReplayTimeQuery {
        codec,
        scope: CatalogScope {
            recording: RecordingScope {
                sensor,
                stream,
                generation: pin_integer(&values, "--generation")?,
                anchor: pin_digest(&values, "--source-anchor")?,
                receive_clock: pin_digest(&values, "--receive-clock")?,
            },
            decode_clock: pin_digest(&values, "--decode-clock")?,
            time_scale,
        },
        receipt_root: pin_digest(&values, "--replay-root")?,
        request: pin_digest(&values, "--replay-request")?,
        ntp_era,
        start_ns,
        end_ns,
        limits: query_limits,
    };
    replay
        .validate()
        .map_err(|error| malformed("query", "[redacted]", error.code(), 0))?;
    let read_bytes = optional_number(&values, "--max-query-read-bytes", 1024_u64 * 1024 * 1024)?;
    let io_calls = optional_number(&values, "--max-query-io-calls", 1_000_000_u64)?;
    if !(1..=4_u64 * 1024 * 1024 * 1024).contains(&read_bytes)
        || !(1..=4_000_000).contains(&io_calls)
    {
        return Err(malformed(
            "query",
            "[redacted]",
            "source verification requires read bytes in 1..4294967296 and I/O calls in 1..4000000",
            0,
        ));
    }
    let mut read_limits = ReplayTimeReadLimits::default();
    let metadata_bytes = (read_bytes / 2).min(read_limits.metadata.max_read_bytes);
    read_limits.metadata.max_read_bytes = metadata_bytes;
    read_limits.originals.max_read_bytes = read_bytes - metadata_bytes;
    let metadata_calls = (io_calls / 2).min(read_limits.metadata.max_io_calls);
    read_limits.metadata.max_io_calls = metadata_calls;
    read_limits.originals.max_io_calls = io_calls - metadata_calls;
    let limits = RecordingReplayContextLimits {
        replay: read_limits,
        ..RecordingReplayContextLimits::default()
    };
    limits
        .allowance()
        .map_err(|_| malformed("query", "[redacted]", "invalid source-read allowance", 0))?;
    let (archive_root, _) = required(&values, "--archive-root")?;
    Ok(RecordingReplayQueryArgs {
        root: required_root("query", &values)?,
        archive_root: PathBuf::from(archive_root),
        request: RecordingReplayContextRequest {
            replay,
            principal: principal("query", &values)?,
            expected_anchor: expected_anchor(&values)?,
        },
        limits,
        verify_replay_source: true,
    })
}

fn response(
    args: &RecordingReplayQueryArgs,
    query: &DeploymentRecordingReplayQuery,
    orientation: &DeploymentOrientation,
) -> Result<String, Box<dyn std::error::Error>> {
    let native = &query.native;
    let report = &native.report;
    let archive_bytes_read = native
        .metadata_usage
        .read_bytes
        .checked_add(native.original_usage.read_bytes)
        .ok_or(RenderError("recorder query byte accounting overflow"))?;
    let archive_io_calls = native
        .metadata_usage
        .io_calls
        .checked_add(native.original_usage.io_calls)
        .ok_or(RenderError("recorder query operation accounting overflow"))?;
    render_response(
        RecordingResponseView {
            request_digest: query.request_digest,
            decision_digest: query.decision_digest,
            principal: args.request.principal.clone(),
            anchor_token: &query.anchor_token,
            session_id: query.session_id.as_str(),
            mission_id: query.mission_id.as_str(),
            epistemic: query.epistemic(),
            coverage: query.coverage(),
            allowance: args.limits.allowance()?,
            deployment_bytes_read: query.deployment_bytes_read,
            deployment_metadata_reads: query.deployment_metadata_reads,
            archive_bytes_read,
            archive_io_calls,
            metadata_handles: std::iter::once((report.receipt.root(), "replay_receipt_metadata"))
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
                report.query.digest()?.to_text(),
                report.digest.to_text(),
                report.index_digest.to_text(),
                report.receipt.root().to_text(),
            ],
            context_decision_domain: "fss.cli.recording_replay_query.context_decision.v1",
            build_response: build_recording_replay_response,
            warning: "Recorder UTC assertions were reconstructed from verified original packets under an explicit source-read grant. NTP era is caller-supplied; interval uncertainty covers rounding only. Missing, conflicting and source-only evidence remains explicit. Device clock error, calibrated exposure time, physical coverage and absence remain unknown. No source media is disclosed.",
            boundary: "Verified exact replay receipt and original AVC/HEVC closures under a separately granted source-read capability, bounded read allowances and current deletion checks; no publisher, recovery, network, pixel decode or media output.",
        },
        orientation,
    )
}

fn refusal(
    args: &RecordingReplayQueryArgs,
    query: &DeploymentRecordingReplayQuery,
    reason: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    render_refusal(
        args.request.principal.clone(),
        &query.snapshot,
        query.request_digest,
        reason,
        "fss.cli.recording_replay_query.refusal.v1",
        build_refusal_response,
    )
}

fn build_refusal_response(mut parts: ResponseParts) -> Result<String, Box<dyn std::error::Error>> {
    parts.boundary = read_only_boundary(
        "Recorder UTC query refused after authorized source verification. No source media or result selection was delivered; refused source-read accounting is not reported.".to_owned(),
    );
    build_recording_replay_response(parts)
}

fn diagnostic(
    args: &RecordingReplayQueryArgs,
    error: RecordingReplayContextError,
) -> (String, ExitIdentity) {
    let (code, exit) = match error {
        RecordingReplayContextError::InvalidRequest => (
            crate::ERR_CLI_MALFORMED_VALUE,
            ExitIdentity::MALFORMED_VALUE,
        ),
        RecordingReplayContextError::Deployment(
            fss_reference::agent_orient::DeploymentReadError::NotADeployment { .. },
        ) => (
            crate::error::ERR_DOCTOR_NOT_A_DEPLOYMENT,
            ExitIdentity::DOCTOR_NOT_A_DEPLOYMENT,
        ),
        _ => (ERR_AGENT_CONTEXT_INCOMPLETE, ExitIdentity::AGENT_REFUSED),
    };
    (execution_diagnostic("query", &args.root, code, exit), exit)
}

/// Execute only after local source-read consent; a typed request cannot bypass this gate.
#[must_use]
pub fn execute_recording_replay_query(args: &RecordingReplayQueryArgs) -> (String, ExitIdentity) {
    if !args.verify_replay_source {
        return (
            execution_diagnostic(
                "query",
                &args.root,
                ERR_AGENT_CONTEXT_INCOMPLETE,
                ExitIdentity::AGENT_REFUSED,
            ),
            ExitIdentity::AGENT_REFUSED,
        );
    }
    let allowance = match args.limits.allowance() {
        Ok(allowance) => allowance,
        Err(error) => return diagnostic(args, error),
    };
    let started = Instant::now();
    let now = || TimestampNs(i128::try_from(started.elapsed().as_nanos()).unwrap_or(i128::MAX));
    let authority = match OperationId::parse("operation:recording-replay-query")
        .map_err(|_| ())
        .and_then(|operation_id| {
            ContextAuthority::new_root(RootAuthoritySpec {
                trace_id: "trace:recording-replay-query".to_owned(),
                operation_id,
                principal: args.request.principal.as_str().to_owned(),
                capabilities: vec![CAPABILITY_QUERY.to_owned(), "CAP-READ-MEDIA-001".to_owned()],
                deadline: Some(TimestampNs(60_000_000_000)),
                priority: 10,
                budgets: allowance,
                privacy_scope: "privacy:recorder-time-source-verification".to_owned(),
                retention_scope: "retention:current-deletion-restrictions".to_owned(),
                anchor_universe: args.request.replay.scope.recording.anchor,
                generation: args.request.replay.scope.recording.generation,
            })
            .map_err(|_| ())
        }) {
        Ok(authority) => authority,
        Err(()) => return internal_failure("query", &args.root),
    };
    let permit = match ReplaySourceReadPermit::authorize(
        &authority,
        &args.request,
        args.limits.replay,
        &now,
    ) {
        Ok(permit) => permit,
        Err(error) => return diagnostic(args, error),
    };
    let query = match query_recordings_replay_in_deployment(
        &HostSpoolIo,
        &args.root,
        &args.archive_root,
        &args.request,
        &args.limits,
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
            principal: args.request.principal.clone(),
            budget_tokens: None,
        },
        &args.limits.snapshot,
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
    if started.elapsed() >= Duration::from_secs(60) {
        return rendered(
            refusal(
                args,
                &query,
                "Recorder UTC read deadline expired before response delivery.",
            ),
            ExitIdentity::AGENT_REFUSED,
            "query",
            &args.root,
        );
    }
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
                "Complete recorder UTC response exceeded its 256 KiB output or cooperative read deadline. No result prefix was delivered; unknown and source-only rows were not dropped.",
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

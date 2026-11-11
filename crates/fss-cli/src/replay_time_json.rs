#![forbid(unsafe_code)]
//! One bounded, lossless operator projection of a native recorder timestamp report.
//! Archive and retained-import queries use the same renderer and native proof identities.

use fss_reference::rtsp::recording_replay::time::{
    ReplaySampleTime, ReplaySourceOnlyTime, ReplayTimeEvidence, ReplayTimeReport,
};

/// Complete projection ceiling, including every matched, unknown and source-only row.
pub const MAX_REPORT_BYTES: usize = 8 * 1024 * 1024;

/// Payload-free rendering or owner-checkpoint refusal.
#[derive(Clone, Copy, Debug)]
pub struct ReplayTimeRenderError {
    /// Existing stable error identity.
    pub code: &'static str,
    /// Static explanation, without paths or original media.
    pub message: &'static str,
}

type Result<T> = std::result::Result<T, ReplayTimeRenderError>;

fn runtime(message: &'static str) -> ReplayTimeRenderError {
    ReplayTimeRenderError {
        code: crate::ERR_CLI_RUNTIME_FAILURE,
        message,
    }
}

fn quoted(value: &str) -> String {
    format!("\"{}\"", crate::escape_json_str(value))
}

fn append(report: &mut String, part: &str) -> Result<()> {
    if part.len() > MAX_REPORT_BYTES.saturating_sub(report.len()) {
        return Err(runtime("recorder-time report byte bound exceeded"));
    }
    report
        .try_reserve(part.len())
        .map_err(|_| runtime("recorder-time report allocation refused"))?;
    report.push_str(part);
    Ok(())
}

fn evidence_json(report: &mut String, evidence: &ReplayTimeEvidence) -> Result<()> {
    append(
        report,
        &format!(
            r#""first_sequence":{},"last_sequence":{},"packet_count":{},"packet_set_digest":{},"proof_digest":{},"header":"#,
            quoted(&evidence.first_sequence.to_string()),
            quoted(&evidence.last_sequence.to_string()),
            evidence.packet_count,
            quoted(&evidence.packet_set_digest.to_text()),
            quoted(&evidence.proof_digest.to_text()),
        ),
    )?;
    if let Some(header) = evidence.header {
        append(
            report,
            &format!(
                r#"{{"ntp_seconds":{},"ntp_fraction":{},"cseq_low":{},"clean_point":{},"end_of_contiguous_section":{},"discontinuity":{},"terminal":{}}}"#,
                header.ntp.seconds,
                header.ntp.fraction,
                header.cseq_low,
                header.clean_point,
                header.end_of_contiguous_section,
                header.discontinuity,
                header.terminal,
            ),
        )?;
    } else {
        append(report, "null")?;
    }
    append(report, r#","recorder_utc_ns":"#)?;
    if let Some(utc) = evidence.utc {
        append(
            report,
            &format!(
                r#"{{"earliest":{},"latest":{}}}"#,
                quoted(&utc.earliest_ns.to_string()),
                quoted(&utc.latest_ns.to_string()),
            ),
        )?;
    } else {
        append(report, "null")?;
    }
    append(report, r#","unknown_reason":"#)?;
    if let Some(reason) = &evidence.unknown {
        append(report, &quoted(reason.as_str()))?;
        append(report, r#","unknown_error_code":"#)?;
        if let Some(code) = reason.error_code() {
            append(report, &quoted(code))?;
        } else {
            append(report, "null")?;
        }
    } else {
        append(report, r#"null,"unknown_error_code":null"#)?;
    }
    Ok(())
}

fn sample_json(report: &mut String, row: &ReplaySampleTime) -> Result<()> {
    append(
        report,
        &format!(
            r#"{{"window":{},"slot":{},"root":{},"sample":{},"decode_time":{},"presentation_time":{},"duration":{},"rtp_timestamp":{},"evidence":{{"#,
            row.window,
            quoted(row.slot.as_str()),
            quoted(&row.root.to_text()),
            row.sample,
            quoted(&row.decode_time.to_string()),
            quoted(&row.presentation_time.to_string()),
            row.duration,
            row.rtp_timestamp,
        ),
    )?;
    evidence_json(report, &row.evidence)?;
    append(report, "}}")
}

fn source_only_json(report: &mut String, row: &ReplaySourceOnlyTime) -> Result<()> {
    append(
        report,
        &format!(
            r#"{{"window":{},"slot":{},"root":{},"rtp_timestamp":{},"sample":null,"evidence":{{"#,
            row.window,
            quoted(row.slot.as_str()),
            quoted(&row.root.to_text()),
            row.rtp_timestamp,
        ),
    )?;
    evidence_json(report, &row.evidence)?;
    append(report, "}}")
}

/// Render the complete native report without truncating rows or inferring capture time.
/// The caller retains current read authority and supplies a cooperative checkpoint.
pub fn render_replay_time_report(
    result: &ReplayTimeReport,
    mut checkpoint: impl FnMut() -> Result<()>,
) -> Result<String> {
    checkpoint()?;
    let receipt = &result.receipt;
    let scope = receipt.scope();
    let request = receipt.request();
    let slot = receipt
        .slot()
        .map_err(|_| runtime("verified replay slot could not be reconstructed"))?;
    let mut report = String::new();
    append(
        &mut report,
        &format!(
            r#"{{"schema":"fss.local_replay_time_operator_report.v1","command":"query-replay-utc","codec":{},"report_digest":{},"index_digest":{},"replay_receipt_root":{},"replay_receipt_slot":{},"replay_request":{},"approval":{},"route":{},"sensor":{},"stream":{},"generation":{},"anchor":{},"receive_clock":{},"decode_clock":{},"time_scale":{},"#,
            quoted(result.query.codec.as_str()),
            quoted(&result.digest.to_text()),
            quoted(&result.index_digest.to_text()),
            quoted(&receipt.root().to_text()),
            quoted(slot.as_str()),
            quoted(&request.digest().to_text()),
            quoted(&receipt.approval().to_text()),
            quoted(&request.route().to_text()),
            quoted(scope.recording.sensor.as_str()),
            quoted(scope.recording.stream.as_str()),
            scope.recording.generation,
            quoted(&scope.recording.anchor.to_text()),
            quoted(&scope.recording.receive_clock.to_text()),
            quoted(&scope.decode_clock.to_text()),
            scope.time_scale,
        ),
    )?;
    if let Some(source) = request.onvif_source() {
        append(
            &mut report,
            &format!(
                r#""onvif_source":{},"#,
                fss_cli::onvif_replay_plan::source_json(source)
            ),
        )?;
    }
    append(
        &mut report,
        &format!(
            r#""requested_range":{},"acknowledged_range":{},"play_cseq":{},"play_cseq_correlation":"low_byte_only","termination":{},"publication_complete":{},"query":{{"ntp_era":{},"start_ns":{},"end_ns":{},"interval":"half_open","selection":"conservative_rounding_overlap","max_windows":{},"max_samples":{},"max_packets":{},"max_source_bytes":{},"max_results":{}}},"scanned_windows":{},"scanned_samples":{},"scanned_packets":{},"source_bytes_reserved":{},"verified_source_bytes":{},"known_samples_outside_query":{},"matched_samples":{},"unknown_samples":{},"source_only_groups":{},"windows":["#,
            quoted(&request.window().to_string()),
            quoted(&receipt.acceptance().acknowledged().to_string()),
            receipt.acceptance().cseq(),
            quoted(receipt.termination().as_str()),
            receipt.publication_complete(),
            result.query.ntp_era,
            quoted(&result.query.start_ns.to_string()),
            quoted(&result.query.end_ns.to_string()),
            result.query.limits.max_windows,
            result.query.limits.max_samples,
            result.query.limits.max_packets,
            result.query.limits.max_source_bytes,
            result.query.limits.max_results,
            result.scanned_windows,
            result.scanned_samples,
            result.scanned_packets,
            result.source_bytes_reserved,
            result.source_bytes,
            result.outside_samples,
            result.matches.len(),
            result.unknown.len(),
            result.source_only.len(),
        ),
    )?;
    for (ordinal, window) in receipt.windows().iter().enumerate() {
        checkpoint()?;
        if ordinal != 0 {
            append(&mut report, ",")?;
        }
        let leaves = window.original_leaf_digests();
        append(
            &mut report,
            &format!(
                r#"{{"ordinal":{ordinal},"slot":{},"root":{},"original_leaf_digests":[{},{},{},{}]}}"#,
                quoted(window.slot().as_str()),
                quoted(&window.root().to_text()),
                quoted(&leaves[0].to_text()),
                quoted(&leaves[1].to_text()),
                quoted(&leaves[2].to_text()),
                quoted(&leaves[3].to_text()),
            ),
        )?;
    }
    append(&mut report, r#"],"matches":["#)?;
    for (ordinal, row) in result.matches.iter().enumerate() {
        checkpoint()?;
        if ordinal != 0 {
            append(&mut report, ",")?;
        }
        sample_json(&mut report, row)?;
    }
    append(&mut report, r#"],"unknown":["#)?;
    for (ordinal, row) in result.unknown.iter().enumerate() {
        checkpoint()?;
        if ordinal != 0 {
            append(&mut report, ",")?;
        }
        sample_json(&mut report, row)?;
    }
    append(&mut report, r#"],"source_only":["#)?;
    for (ordinal, row) in result.source_only.iter().enumerate() {
        checkpoint()?;
        if ordinal != 0 {
            append(&mut report, ",")?;
        }
        source_only_json(&mut report, row)?;
    }
    append(
        &mut report,
        r#"],"original_source_verified":true,"time_basis":"recorder_reported_frame_grabber_ntp","rounding_only_uncertainty":true,"device_clock_error":"unknown","calibrated_capture_time":"unknown","coverage_claim":"not_claimed","absence_claim":"not_claimed","source_bytes_emitted":false,"operation_complete":true}"#,
    )?;
    append(&mut report, "\n")?;
    checkpoint()?;
    Ok(report)
}

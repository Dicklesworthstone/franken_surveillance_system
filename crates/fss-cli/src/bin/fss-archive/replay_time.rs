#![forbid(unsafe_code)]
//! Bounded cold projection of source-verified recorder-reported timestamps.
//! JSON is an operator projection; the native report digest binds its interpretation.

use std::collections::BTreeMap;
use std::ffi::OsStr;

use fss_publication::LocalRootPublisher;
use fss_reference::rtsp::recording_replay::time::{
    REPLAY_TIME_END_EXCLUSIVE_NS, ReplaySampleTime, ReplaySourceOnlyTime, ReplayTimeEvidence,
    ReplayTimeLimits, ReplayTimeQuery, query_replay_time,
};

use super::{Clock, Error, Options, Result, argument, malformed, quoted, runtime};
use fss_cli::{ERR_CLI_INVALID_UNICODE, ERR_CLI_MISSING_VALUE};

pub(super) const HELP: &str = "fss-archive query-replay-utc [options]\n\
  Required: --root EXISTING_DIR --codec avc|hevc --sensor ID --stream ID --generation N\n\
            --anchor sha256:HEX --receive-clock sha256:HEX\n\
            --decode-clock sha256:HEX --time-scale N\n\
            --expected-replay-root sha256:HEX --expected-replay-request sha256:HEX\n\
            --ntp-era N --utc-start-ns I128 --utc-end-ns I128\n\
  Query: half-open Unix-nanosecond interval [start,end), within 1970 through 9999.\n\
         NTP era is an explicit interpretation input; it is never inferred.\n\
  Work bounds: [--max-query-windows N] [--max-query-samples N]\n\
               [--max-query-packets N] [--max-query-source-bytes N]\n\
               [--max-query-results N]\n\
  Defaults: 64 windows, 16384 samples, 262144 packets, 268435456 reserved source\n\
            bytes and 4096 returned sample/lookahead rows. Output is at most 8 MiB.\n\
  Storage: [--timeout-ms N] [--max-scan-roots N] [--max-objects N]\n\
           [--max-object-bytes N] [--max-total-bytes N]\n\
  Each window reserves 32 MiB before native source verification; the default source\n\
  allowance admits eight windows. Raise an explicit bound only after reviewing it.\n\
  Reconstructs ONVIF 0xABAC time from original AVC/HEVC packets. Missing, conflicting\n\
  or unusable timestamps stay explicit. CSeq correlation checks only its low byte.\n\
  Recorder-reported time is not calibrated capture time. No coverage or absence claim.\n\
  Existing owner open takes exclusive locks and may perform normal recovery I/O.\n\
  No network, source payload output, publication, deletion or guessed pins.\n";

pub(super) const OPTIONS: [&str; 8] = [
    "--ntp-era",
    "--utc-start-ns",
    "--utc-end-ns",
    "--max-query-windows",
    "--max-query-samples",
    "--max-query-packets",
    "--max-query-source-bytes",
    "--max-query-results",
];

const MAX_REPORT_BYTES: usize = 8 * 1024 * 1024;

pub(super) struct QueryOptions {
    ntp_era: u32,
    start_ns: i128,
    end_ns: i128,
    limits: ReplayTimeLimits,
}

impl QueryOptions {
    pub(super) fn parse(values: &BTreeMap<&str, &OsStr>) -> Result<Self> {
        let text = |key: &str| -> Result<&str> {
            values
                .get(key)
                .ok_or_else(|| argument(ERR_CLI_MISSING_VALUE, "required time option missing"))?
                .to_str()
                .ok_or_else(|| argument(ERR_CLI_INVALID_UNICODE, "time option must be UTF-8"))
        };
        let unsigned = |key: &str, default: Option<u64>| -> Result<u64> {
            if !values.contains_key(key) {
                return default.ok_or_else(|| {
                    argument(ERR_CLI_MISSING_VALUE, "required time option missing")
                });
            }
            let raw = text(key)?;
            if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(malformed("expected unsigned decimal time bound"));
            }
            raw.parse()
                .map_err(|_| malformed("time bound integer overflow"))
        };
        let signed = |key: &str| -> Result<i128> {
            let raw = text(key)?;
            let digits = raw.strip_prefix('-').unwrap_or(raw);
            if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(malformed("expected signed decimal Unix nanoseconds"));
            }
            raw.parse()
                .map_err(|_| malformed("Unix nanoseconds integer overflow"))
        };
        let size = |key: &str, default: usize| -> Result<usize> {
            usize::try_from(unsigned(key, Some(default as u64))?)
                .map_err(|_| malformed("query work bound integer overflow"))
        };
        let defaults = ReplayTimeLimits::default();
        let limits = ReplayTimeLimits {
            max_windows: size("--max-query-windows", defaults.max_windows)?,
            max_samples: size("--max-query-samples", defaults.max_samples)?,
            max_packets: size("--max-query-packets", defaults.max_packets)?,
            max_source_bytes: unsigned(
                "--max-query-source-bytes",
                Some(defaults.max_source_bytes),
            )?,
            max_results: size("--max-query-results", defaults.max_results)?,
        };
        limits
            .validate()
            .map_err(|_| malformed("query work bound outside supported limits"))?;
        let ntp_era = u32::try_from(unsigned("--ntp-era", None)?)
            .map_err(|_| malformed("NTP era must fit an unsigned 32-bit integer"))?;
        let start_ns = signed("--utc-start-ns")?;
        let end_ns = signed("--utc-end-ns")?;
        if start_ns < 0 || start_ns >= end_ns || end_ns > REPLAY_TIME_END_EXCLUSIVE_NS {
            return Err(malformed(
                "query UTC interval must be nonempty within 1970-9999",
            ));
        }
        Ok(Self {
            ntp_era,
            start_ns,
            end_ns,
            limits,
        })
    }
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

pub(super) fn run(
    publisher: &LocalRootPublisher,
    options: &Options,
    time: &QueryOptions,
    clock: &Clock,
) -> Result<String> {
    let query = ReplayTimeQuery {
        codec: options.codec,
        scope: options.scope.clone(),
        receipt_root: options.receipt,
        request: options.request,
        ntp_era: time.ntp_era,
        start_ns: time.start_ns,
        end_ns: time.end_ns,
        limits: time.limits,
    };
    let result = query_replay_time(publisher, &query, clock).map_err(|error| Error {
        code: error.code(),
        message: "recorder-time query or pinned original source verification refused",
        usage: false,
    })?;
    clock.check()?;
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
            quoted(options.codec.as_str()),
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
            time.ntp_era,
            quoted(&time.start_ns.to_string()),
            quoted(&time.end_ns.to_string()),
            time.limits.max_windows,
            time.limits.max_samples,
            time.limits.max_packets,
            time.limits.max_source_bytes,
            time.limits.max_results,
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
        clock.check()?;
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
        clock.check()?;
        if ordinal != 0 {
            append(&mut report, ",")?;
        }
        sample_json(&mut report, row)?;
    }
    append(&mut report, r#"],"unknown":["#)?;
    for (ordinal, row) in result.unknown.iter().enumerate() {
        clock.check()?;
        if ordinal != 0 {
            append(&mut report, ",")?;
        }
        sample_json(&mut report, row)?;
    }
    append(&mut report, r#"],"source_only":["#)?;
    for (ordinal, row) in result.source_only.iter().enumerate() {
        clock.check()?;
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
    clock.check()?;
    Ok(report)
}

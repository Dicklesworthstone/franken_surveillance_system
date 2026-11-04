#![forbid(unsafe_code)]
//! Bounded, byte-free evidence for one approved native probe session.
//!
//! The completion digest binds canonical receipt claims and native counters, never
//! JSON text. It is an integrity witness, not a signature, source-custody root,
//! authenticated camera identity or proof of scene freshness. A success rendering
//! leaves the native adapter only after the shared owned runtime has finalized.

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_reference::rtsp::tcp::TcpTotals;
use fss_reference::site::live_probe::ProbeAccounting;
use fss_reference::site::probe_observation::{
    MAX_PROBE_PICTURES, MAX_PROBE_RTP_BYTES, MAX_PROBE_RTP_PACKETS,
};
use fss_reference::site::{ProbeCodec, SiteProbeReceipt};

use super::native::Facts;
use super::plan::{ProbePlan, receipt_json};
use crate::error::ExitIdentity;
use crate::json_output::{array, object, string};

const SCHEMA: &str = "fss.site_probe_session.v1";
const ENCODING: &str = "ERR-SITE-PROBE-SESSION-EVIDENCE-001";
const MEASUREMENT_BASIS: &str = "native_rtsp_picture_syntax";
const JPEG_MEASUREMENT_BASIS: &str = "native_rfc2435_whole_frame_reconstruction";
const CUTOFF_POLICY: &str = "minimum_confirmed_prefix_with_explicit_tail_omission";
const RECONCILIATION: &str = "Remote session closure is unconfirmed. Local socket retirement is not a TEARDOWN acknowledgement; no reconnect was attempted.";

fn measurement_basis(codec: ProbeCodec) -> &'static str {
    match codec {
        ProbeCodec::Avc | ProbeCodec::Hevc => MEASUREMENT_BASIS,
        ProbeCodec::Jpeg => JPEG_MEASUREMENT_BASIS,
    }
}

fn optional_cseq(value: Option<u32>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| value.to_string())
}

fn transport(value: TcpTotals) -> String {
    object(&[
        ("received_bytes", value.received_bytes.to_string()),
        ("sent_bytes", value.sent_bytes.to_string()),
        ("read_calls", value.read_calls.to_string()),
        ("write_calls", value.write_calls.to_string()),
        ("last_sent_cseq", optional_cseq(value.last_sent_cseq)),
        ("peer_eof", value.peer_eof.to_string()),
    ])
}

fn accounting(value: ProbeAccounting) -> String {
    object(&[
        ("rtp_packets", value.rtp_packets.to_string()),
        ("rtp_bytes", value.rtp_bytes.to_string()),
        (
            "unverified_nal_bytes_excluded",
            value.unverified_nal_bytes_excluded.to_string(),
        ),
        (
            "unfinished_fragment_bytes_excluded",
            value.unfinished_fragment_bytes_excluded.to_string(),
        ),
        (
            "rtcp_frames_excluded",
            value.rtcp_frames_excluded.to_string(),
        ),
        ("rtcp_bytes_excluded", value.rtcp_bytes_excluded.to_string()),
        (
            "closing_frames_excluded",
            value.closing_frames_excluded.to_string(),
        ),
        (
            "closing_bytes_excluded",
            value.closing_bytes_excluded.to_string(),
        ),
        ("control_responses", value.control_responses.to_string()),
        (
            "discarded_wire_bytes",
            value.discarded_wire_bytes.to_string(),
        ),
    ])
}

/// The receipt and byte accounting must describe one settled native session.
/// A valid receipt alone cannot manufacture close or transport evidence.
pub(super) fn success(
    plan: &ProbePlan<'_>,
    receipt: &SiteProbeReceipt,
    facts: Facts,
) -> Result<String, &'static str> {
    receipt.validate_for(plan.manifest).map_err(|_| ENCODING)?;
    let totals = facts.totals.ok_or(ENCODING)?;
    let measured = facts.accounting.ok_or(ENCODING)?;
    let classified_wire_bytes = measured
        .rtp_bytes
        .checked_add(measured.rtcp_bytes_excluded)
        .and_then(|bytes| bytes.checked_add(measured.closing_bytes_excluded))
        .ok_or(ENCODING)?;
    let io_calls = totals
        .read_calls
        .checked_add(totals.write_calls)
        .ok_or(ENCODING)?;
    if !facts.connection_attempted
        || !facts.teardown_acknowledged
        || facts.remote_session_may_exist
        || facts.pending_cseq.is_some()
        || facts.request_sent_bytes != 0
        || facts.unsent_request_bytes != 0
        || facts.credentials_loaded != facts.credential_access_attempted
        || facts.credentials_loaded
            != plan.manifest.sources[plan.source_index]
                .authentication
                .is_some()
        || receipt.source_id != plan.options.source
        || receipt.codec != plan.options.codec
        || receipt.media_index != plan.options.media_index
        || receipt.rtp_channel != plan.options.rtp_channel
        || plan
            .options
            .payload_type
            .is_some_and(|value| value != receipt.payload_type)
        || receipt.observed_frames < plan.options.observe_frames
        || receipt.observed_frames > MAX_PROBE_PICTURES
        || measured.rtp_packets == 0
        || measured.rtp_bytes == 0
        || measured.rtp_packets > u64::from(MAX_PROBE_RTP_PACKETS)
        || measured.rtp_bytes > MAX_PROBE_RTP_BYTES
        || classified_wire_bytes > totals.received_bytes
        || totals.received_bytes > plan.transport.max_received_bytes
        || totals.sent_bytes > plan.transport.max_sent_bytes
        || io_calls > plan.transport.max_io_calls
        || totals.read_calls == 0
        || totals.write_calls == 0
        || !totals.last_sent_cseq.is_some_and(|cseq| cseq != 0)
        || measured.discarded_wire_bytes != totals.received_bytes
        || totals.sent_bytes == 0
        || facts.last_observed_ns >= plan.options.timeout_ms * 1_000_000
    {
        return Err(ENCODING);
    }
    let receipt_digest = receipt.digest().map_err(|_| ENCODING)?;
    let completion = completion_digest(plan, receipt_digest, facts, totals, measured)?;
    Ok(render(
        plan,
        facts,
        Some((receipt, receipt_digest, completion)),
        None,
        ExitIdentity::SUCCESS,
    ))
}

fn completion_digest(
    plan: &ProbePlan<'_>,
    receipt_digest: ContentDigest,
    facts: Facts,
    totals: TcpTotals,
    measured: ProbeAccounting,
) -> Result<ContentDigest, &'static str> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(SCHEMA);
    encoder.text(measurement_basis(plan.options.codec));
    encoder.text(CUTOFF_POLICY);
    encoder.digest(plan.approval);
    encoder.digest(receipt_digest);
    encoder.bool(facts.connection_attempted);
    encoder.bool(facts.credential_access_attempted);
    encoder.bool(facts.credentials_loaded);
    encoder.bool(facts.teardown_acknowledged);
    encoder.bool(facts.remote_session_may_exist);
    encode_cseq(&mut encoder, facts.pending_cseq);
    encoder.u64(u64::try_from(facts.request_sent_bytes).map_err(|_| ENCODING)?);
    encoder.u64(u64::try_from(facts.unsent_request_bytes).map_err(|_| ENCODING)?);
    encoder.u64(facts.last_observed_ns);
    encoder.u64(totals.received_bytes);
    encoder.u64(totals.sent_bytes);
    encoder.u64(totals.read_calls);
    encoder.u64(totals.write_calls);
    encode_cseq(&mut encoder, totals.last_sent_cseq);
    encoder.bool(totals.peer_eof);
    for value in [
        measured.rtp_packets,
        measured.rtp_bytes,
        measured.unverified_nal_bytes_excluded,
        measured.unfinished_fragment_bytes_excluded,
        measured.rtcp_frames_excluded,
        measured.rtcp_bytes_excluded,
        measured.closing_frames_excluded,
        measured.closing_bytes_excluded,
        measured.control_responses,
        measured.discarded_wire_bytes,
    ] {
        encoder.u64(value);
    }
    Ok(ContentDigest::sha256(
        &encoder.finish_checked().map_err(|_| ENCODING)?,
    ))
}

fn encode_cseq(encoder: &mut CanonicalEncoder, value: Option<u32>) {
    match value {
        None => encoder.tag(0),
        Some(value) => {
            encoder.tag(1);
            encoder.u32(value);
        }
    }
}

/// Preserve observed effects and close uncertainty on every admitted failure.
/// No failure carries a receipt or completion witness, including late runtime
/// finalization failures after the remote peer acknowledged TEARDOWN.
pub(super) fn refusal(
    plan: &ProbePlan<'_>,
    code: &str,
    facts: Facts,
    exit: ExitIdentity,
) -> String {
    render(plan, facts, None, Some(code), exit)
}

fn render(
    plan: &ProbePlan<'_>,
    facts: Facts,
    completed: Option<(&SiteProbeReceipt, ContentDigest, ContentDigest)>,
    error: Option<&str>,
    exit: ExitIdentity,
) -> String {
    let source = &plan.manifest.sources[plan.source_index];
    let (status, receipts, receipt_digest, completion) = match completed {
        Some((receipt, digest, completion)) => (
            "measured",
            array(&[receipt_json(receipt)]),
            string(&digest.to_text()),
            string(&completion.to_text()),
        ),
        None => (
            if facts.remote_session_may_exist {
                "indeterminate"
            } else {
                "refused"
            },
            "[]".to_owned(),
            "null".to_owned(),
            "null".to_owned(),
        ),
    };
    object(&[
        ("schema", string(SCHEMA)),
        ("status", string(status)),
        ("approval", string(&plan.approval.to_text())),
        ("site_id", string(&plan.manifest.site_id)),
        ("source_id", string(&source.source_id)),
        ("source_generation", source.generation.to_string()),
        ("codec", string(plan.options.codec.as_str())),
        (
            "requested_minimum_pictures",
            plan.options.observe_frames.to_string(),
        ),
        (
            "measurement_basis",
            string(measurement_basis(plan.options.codec)),
        ),
        ("cutoff_policy", string(CUTOFF_POLICY)),
        ("receipt_digest", receipt_digest),
        ("completion_digest", completion),
        ("receipts", receipts),
        ("error_id", error.map_or_else(|| "null".to_owned(), string)),
        ("exit_id", string(exit.identifier)),
        ("exit_code", exit.code.to_string()),
        (
            "connection_attempted",
            facts.connection_attempted.to_string(),
        ),
        (
            "credential_access_attempted",
            facts.credential_access_attempted.to_string(),
        ),
        ("credentials_loaded", facts.credentials_loaded.to_string()),
        (
            "teardown_acknowledged",
            facts.teardown_acknowledged.to_string(),
        ),
        (
            "remote_session_may_exist",
            facts.remote_session_may_exist.to_string(),
        ),
        ("pending_cseq", optional_cseq(facts.pending_cseq)),
        ("request_sent_bytes", facts.request_sent_bytes.to_string()),
        (
            "unsent_request_bytes",
            facts.unsent_request_bytes.to_string(),
        ),
        ("last_observed_ns", facts.last_observed_ns.to_string()),
        (
            "transport",
            facts.totals.map_or_else(|| "null".to_owned(), transport),
        ),
        (
            "accounting",
            facts
                .accounting
                .map_or_else(|| "null".to_owned(), accounting),
        ),
        (
            "runtime_allowance",
            crate::agent_json::budget(&plan.allowance),
        ),
        ("receipt_issued", completed.is_some().to_string()),
        ("source_retained", "false".to_owned()),
        ("raw_media_returned", "false".to_owned()),
        ("pixels_decoded", "false".to_owned()),
        ("source_freshness_verified", "false".to_owned()),
        ("source_origin_authenticated", "false".to_owned()),
        ("rights_verdict_verified", "false".to_owned()),
        ("capture_authorized", "false".to_owned()),
        ("retry_automatically", "false".to_owned()),
        (
            "reconciliation",
            if facts.remote_session_may_exist {
                string(RECONCILIATION)
            } else {
                "null".to_owned()
            },
        ),
    ])
}

#[cfg(test)]
#[path = "report_tests.rs"]
mod tests;

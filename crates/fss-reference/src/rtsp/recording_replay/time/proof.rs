#![forbid(unsafe_code)]
//! Canonical query/projection identities; existing replay and recording bytes are unchanged.

use super::super::{ReplayReceiptError, Result};
use super::*;
use fss_core::CanonicalEncoder;

pub(super) fn query_digest(query: &ReplayTimeQuery) -> Result<ContentDigest> {
    let mut out = CanonicalEncoder::new();
    out.text(REPLAY_TIME_QUERY_DOMAIN);
    pins(&mut out, query);
    out.i128(query.start_ns);
    out.i128(query.end_ns);
    count(&mut out, query.limits.max_windows)?;
    count(&mut out, query.limits.max_samples)?;
    count(&mut out, query.limits.max_packets)?;
    out.u64(query.limits.max_source_bytes);
    count(&mut out, query.limits.max_results)?;
    finish(out)
}

pub(super) fn packet_set(
    packet_count: usize,
    values: impl Iterator<Item = (u64, ContentDigest)>,
) -> Result<ContentDigest> {
    let mut out = CanonicalEncoder::new();
    out.text(REPLAY_TIME_PACKETS_DOMAIN);
    count(&mut out, packet_count)?;
    for (sequence, digest) in values {
        out.u64(sequence);
        out.digest(digest);
    }
    finish(out)
}

pub(super) fn sample(query: &ReplayTimeQuery, row: &ReplaySampleTime) -> Result<ContentDigest> {
    let mut out = CanonicalEncoder::new();
    out.text(REPLAY_TIME_SAMPLE_DOMAIN);
    out.text("sample");
    pins(&mut out, query);
    origin(&mut out, row.window, &row.slot, row.root)?;
    count(&mut out, row.sample)?;
    out.u64(row.decode_time);
    out.u64(row.presentation_time);
    out.u32(row.duration);
    out.u32(row.rtp_timestamp);
    evidence(&mut out, &row.evidence)?;
    finish(out)
}

pub(super) fn source_only(
    query: &ReplayTimeQuery,
    ordinal: usize,
    row: &ReplaySourceOnlyTime,
) -> Result<ContentDigest> {
    let mut out = CanonicalEncoder::new();
    out.text(REPLAY_TIME_SAMPLE_DOMAIN);
    out.text("source_only");
    pins(&mut out, query);
    origin(&mut out, row.window, &row.slot, row.root)?;
    count(&mut out, ordinal)?;
    out.u32(row.rtp_timestamp);
    evidence(&mut out, &row.evidence)?;
    finish(out)
}

pub(super) fn index(
    query: &ReplayTimeQuery,
    observations: &[ContentDigest],
) -> Result<ContentDigest> {
    let mut out = CanonicalEncoder::new();
    out.text(REPLAY_TIME_INDEX_DOMAIN);
    pins(&mut out, query);
    count(&mut out, observations.len())?;
    for observation in observations {
        out.digest(*observation);
    }
    finish(out)
}

pub(super) fn report(report: &ReplayTimeReport) -> Result<ContentDigest> {
    let mut out = CanonicalEncoder::new();
    out.text(REPLAY_TIME_REPORT_DOMAIN);
    out.digest(query_digest(&report.query)?);
    out.digest(report.index_digest);
    count(&mut out, report.scanned_windows)?;
    count(&mut out, report.scanned_samples)?;
    count(&mut out, report.scanned_packets)?;
    out.u64(report.source_bytes_reserved);
    out.u64(report.source_bytes);
    count(&mut out, report.outside_samples)?;
    count(&mut out, report.matches.len())?;
    for row in &report.matches {
        out.digest(row.evidence.proof_digest);
    }
    count(&mut out, report.unknown.len())?;
    for row in &report.unknown {
        out.digest(row.evidence.proof_digest);
    }
    count(&mut out, report.source_only.len())?;
    for row in &report.source_only {
        out.digest(row.evidence.proof_digest);
    }
    finish(out)
}

fn pins(out: &mut CanonicalEncoder, query: &ReplayTimeQuery) {
    out.text(query.codec.as_str());
    super::super::wire::encode_scope(out, &query.scope);
    out.digest(query.receipt_root);
    out.digest(query.request);
    out.u32(query.ntp_era);
}

fn origin(
    out: &mut CanonicalEncoder,
    window: usize,
    slot: &SlotName,
    root: ContentDigest,
) -> Result<()> {
    count(out, window)?;
    out.text(slot.as_str());
    out.digest(root);
    Ok(())
}

fn evidence(out: &mut CanonicalEncoder, value: &ReplayTimeEvidence) -> Result<()> {
    out.u64(value.first_sequence);
    out.u64(value.last_sequence);
    count(out, value.packet_count)?;
    out.digest(value.packet_set_digest);
    out.bool(value.header.is_some());
    if let Some(header) = value.header {
        out.u32(header.ntp.seconds);
        out.u32(header.ntp.fraction);
        out.bool(header.clean_point);
        out.bool(header.end_of_contiguous_section);
        out.bool(header.discontinuity);
        out.bool(header.terminal);
        out.u8(header.cseq_low);
    }
    out.bool(value.utc.is_some());
    if let Some(utc) = value.utc {
        out.i128(utc.earliest_ns);
        out.i128(utc.latest_ns);
    }
    out.bool(value.unknown.is_some());
    if let Some(reason) = value.unknown {
        out.text(reason.as_str());
        out.bool(reason.error_code().is_some());
        if let Some(code) = reason.error_code() {
            out.text(code);
        }
    }
    Ok(())
}

fn count(out: &mut CanonicalEncoder, count: usize) -> Result<()> {
    out.u64(u64::try_from(count).map_err(|_| ReplayReceiptError::Limit)?);
    Ok(())
}

fn finish(out: CanonicalEncoder) -> Result<ContentDigest> {
    super::super::digest(
        &out.finish_checked()
            .map_err(|_| ReplayReceiptError::Limit)?,
    )
}

#![forbid(unsafe_code)]
//! Exact bounded canonical metadata; no source-authority inference from stored tags.

use std::net::SocketAddr;

use super::*;
use crate::site::clock::ClockCorrelationPolicy;
use fss_core::{CanonicalDecoder, ContractError, SensorId, StreamId};

const VERSION: u64 = 1;
const CHECKSUM_BYTES: usize = 33;

#[allow(clippy::too_many_arguments)]
pub(super) fn encode(
    scope: &CatalogScope,
    codec: RecordingClockCodec,
    approval: ContentDigest,
    exchange: &LocalNtpExchange,
    terminal: HostClockSample,
    brackets: &[ReceiveClockBracket],
    entries: &[ClockIndexEntry],
) -> Result<Vec<u8>> {
    let mut out = CanonicalEncoder::new();
    out.text(CLOCK_INDEX_DOMAIN);
    out.u64(VERSION);
    out.u8(codec.tag());
    encode_scope(&mut out, scope);
    out.digest(approval);
    encode_exchange(&mut out, exchange);
    encode_sample(&mut out, terminal);
    out.u64(brackets.len() as u64);
    for bracket in brackets {
        out.u64(bracket.admission_ns);
        encode_sample(&mut out, bracket.completed);
    }
    out.u64(entries.len() as u64);
    for entry in entries {
        let window = &entry.window;
        out.text(window.slot.as_str());
        out.digest(window.root());
        out.u64(window.summary.decode_interval.start);
        out.u64(window.summary.decode_interval.end);
        out.u64(window.summary.packets as u64);
        out.u64(window.summary.samples as u64);
        out.u64(window.summary.nals as u64);
        out.u64(window.bytes as u64);
        for leaf in window.leaves {
            out.digest(leaf);
        }
        out.u64(window.admissions.len() as u64);
        for admission in &window.admissions {
            out.u64(*admission);
        }
        out.u64(entry.utc.earliest_ns);
        out.u64(entry.utc.latest_ns);
    }
    let mut bytes = out
        .finish_checked()
        .map_err(|_| RecordingClockError::Limit)?;
    if bytes.len() > MAX_CLOCK_INDEX_BYTES - CHECKSUM_BYTES {
        return Err(RecordingClockError::Limit);
    }
    let checksum = digest(&bytes)?;
    bytes
        .try_reserve_exact(CHECKSUM_BYTES)
        .map_err(|_| RecordingClockError::Limit)?;
    bytes.push(1);
    bytes.extend_from_slice(&checksum.bytes());
    Ok(bytes)
}

pub(super) fn encode_scope(out: &mut CanonicalEncoder, scope: &CatalogScope) {
    out.text(scope.recording.sensor.as_str());
    out.text(scope.recording.stream.as_str());
    out.u64(scope.recording.generation);
    out.digest(scope.recording.anchor);
    out.digest(scope.recording.receive_clock);
    out.digest(scope.decode_clock);
    out.u32(scope.time_scale);
}

fn encode_sample(out: &mut CanonicalEncoder, sample: HostClockSample) {
    out.u64(sample.monotonic_before_ns);
    out.u64(sample.wall_clock_unix_ns);
    out.u64(sample.monotonic_after_ns);
}

fn encode_exchange(out: &mut CanonicalEncoder, exchange: &LocalNtpExchange) {
    out.text(&exchange.peer.to_string());
    out.bytes(&exchange.request);
    out.bytes(&exchange.reply);
    for sample in [
        exchange.sent_before,
        exchange.sent_after,
        exchange.received_before,
        exchange.received_after,
    ] {
        encode_sample(out, sample);
    }
    out.u64(exchange.policy.max_sample_bracket_ns);
    out.u64(exchange.policy.max_drift_ppb);
    out.u64(exchange.policy.max_age_ns);
}

/// Reconstruct every derived interval, compare canonical bytes, and preserve only
/// native-source claims pending the storage layer's actual original replay.
pub(super) fn decode(
    bytes: &[u8],
    expected_scope: &CatalogScope,
    expected_codec: RecordingClockCodec,
) -> Result<RecordingClockIndex> {
    if bytes.len() > MAX_CLOCK_INDEX_BYTES {
        return Err(RecordingClockError::Limit);
    }
    let body_end = bytes
        .len()
        .checked_sub(CHECKSUM_BYTES)
        .ok_or(RecordingClockError::Malformed)?;
    let mut trailer = CanonicalDecoder::new(&bytes[body_end..]);
    if trailer.digest().map_err(bad)? != digest(&bytes[..body_end])? {
        return Err(RecordingClockError::Digest);
    }
    trailer.ensure_finished().map_err(bad)?;
    let mut input = CanonicalDecoder::new(&bytes[..body_end]);
    if input.text().map_err(bad)? != CLOCK_INDEX_DOMAIN || input.u64().map_err(bad)? != VERSION {
        return Err(RecordingClockError::Malformed);
    }
    if input.u8().map_err(bad)? != expected_codec.tag() {
        return Err(RecordingClockError::Scope);
    }
    let scope = decode_scope(&mut input)?;
    if &scope != expected_scope {
        return Err(RecordingClockError::Scope);
    }
    let approval = input.digest().map_err(bad)?;
    let exchange = decode_exchange(&mut input)?;
    let terminal = decode_sample(&mut input)?;
    let bracket_count = count(&mut input, MAX_CLOCK_BRACKETS)?;
    if bracket_count > input.remaining() / 32 {
        return Err(RecordingClockError::Malformed);
    }
    let mut brackets = bounded_vec(bracket_count)?;
    for _ in 0..bracket_count {
        brackets.push(ReceiveClockBracket {
            admission_ns: input.u64().map_err(bad)?,
            completed: decode_sample(&mut input)?,
        });
    }
    let window_count = count(&mut input, MAX_CLOCK_WINDOWS)?;
    let mut windows = bounded_vec(window_count)?;
    for _ in 0..window_count {
        let slot = SlotName::parse(input.text().map_err(bad)?)
            .map_err(|_| RecordingClockError::Malformed)?;
        let root = input.digest().map_err(bad)?;
        let start = input.u64().map_err(bad)?;
        let end = input.u64().map_err(bad)?;
        let packets = count(&mut input, MAX_RECORDING_PACKETS)?;
        let samples = count(&mut input, super::super::recording::MAX_RECORDING_SAMPLES)?;
        let nals = count(&mut input, super::super::recording::MAX_RECORDING_MAPPINGS)?;
        let byte_len = count(&mut input, MAX_RECORDING_BYTES)?;
        let leaves = [
            input.digest().map_err(bad)?,
            input.digest().map_err(bad)?,
            input.digest().map_err(bad)?,
            input.digest().map_err(bad)?,
        ];
        let admission_count = count(&mut input, MAX_RECORDING_PACKETS)?;
        if admission_count > input.remaining() / 8 {
            return Err(RecordingClockError::Malformed);
        }
        let mut admissions = bounded_vec(admission_count)?;
        for _ in 0..admission_count {
            admissions.push(input.u64().map_err(bad)?);
        }
        // These redundant endpoints must equal fresh reconstruction byte-for-byte.
        // They are not trusted merely because the metadata checksum matched.
        input.u64().map_err(bad)?;
        input.u64().map_err(bad)?;
        windows.push(ClockWindow {
            codec: expected_codec,
            slot,
            summary: RecordingSummary {
                root,
                scope: scope.recording.clone(),
                packets,
                samples,
                nals,
                time_scale: scope.time_scale,
                decode_interval: start..end,
            },
            bytes: byte_len,
            leaves,
            admissions,
        });
    }
    input.ensure_finished().map_err(bad)?;
    let index = RecordingClockIndex::prepare(
        scope,
        expected_codec,
        approval,
        exchange,
        terminal,
        &brackets,
        &windows,
    )?;
    if index.index_bytes() != bytes {
        return Err(RecordingClockError::Malformed);
    }
    Ok(index)
}

fn decode_scope(input: &mut CanonicalDecoder<'_>) -> Result<CatalogScope> {
    let sensor = SensorId::parse(input.text().map_err(bad)?).map_err(bad)?;
    let stream = StreamId::parse(input.text().map_err(bad)?).map_err(bad)?;
    Ok(CatalogScope {
        recording: RecordingScope {
            sensor,
            stream,
            generation: input.u64().map_err(bad)?,
            anchor: input.digest().map_err(bad)?,
            receive_clock: input.digest().map_err(bad)?,
        },
        decode_clock: input.digest().map_err(bad)?,
        time_scale: input.u32().map_err(bad)?,
    })
}

fn decode_sample(input: &mut CanonicalDecoder<'_>) -> Result<HostClockSample> {
    Ok(HostClockSample {
        monotonic_before_ns: input.u64().map_err(bad)?,
        wall_clock_unix_ns: input.u64().map_err(bad)?,
        monotonic_after_ns: input.u64().map_err(bad)?,
    })
}

fn decode_exchange(input: &mut CanonicalDecoder<'_>) -> Result<LocalNtpExchange> {
    let peer_text = input.text().map_err(bad)?;
    if peer_text.len() > 64 {
        return Err(RecordingClockError::Malformed);
    }
    let peer: SocketAddr = peer_text
        .parse()
        .map_err(|_| RecordingClockError::Malformed)?;
    if peer.to_string() != peer_text {
        return Err(RecordingClockError::Malformed);
    }
    let request = input
        .bytes()
        .map_err(bad)?
        .try_into()
        .map_err(|_| RecordingClockError::Malformed)?;
    let reply = input
        .bytes()
        .map_err(bad)?
        .try_into()
        .map_err(|_| RecordingClockError::Malformed)?;
    Ok(LocalNtpExchange {
        peer,
        request,
        reply,
        sent_before: decode_sample(input)?,
        sent_after: decode_sample(input)?,
        received_before: decode_sample(input)?,
        received_after: decode_sample(input)?,
        policy: ClockCorrelationPolicy {
            max_sample_bracket_ns: input.u64().map_err(bad)?,
            max_drift_ppb: input.u64().map_err(bad)?,
            max_age_ns: input.u64().map_err(bad)?,
        },
    })
}

fn count(input: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<usize> {
    let value =
        usize::try_from(input.u64().map_err(bad)?).map_err(|_| RecordingClockError::Limit)?;
    if value == 0 || value > maximum {
        return Err(RecordingClockError::Limit);
    }
    Ok(value)
}

fn bad(_: ContractError) -> RecordingClockError {
    RecordingClockError::Malformed
}

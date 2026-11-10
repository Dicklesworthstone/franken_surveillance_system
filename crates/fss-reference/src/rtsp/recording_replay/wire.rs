#![forbid(unsafe_code)]
//! Canonical bounded replay metadata; reconstruct identities and reject aliases.

use super::*;
use fss_core::{CanonicalDecoder, ContractError, SensorId, StreamId};

const VERSION: u64 = 1;
const CHECKSUM_BYTES: usize = 33;
const MAX_RANGE_BYTES: usize = 64;
// Empty slot text would still need its length, root, six counts and four leaves.
const MIN_WINDOW_BYTES: usize = 8 + 33 + 6 * 8 + 4 * 33;

#[allow(clippy::too_many_arguments)]
pub(super) fn encode(
    request: &ReplayRequest,
    scope: &CatalogScope,
    approval: ContentDigest,
    acceptance: ReplayAcceptance,
    windows: &[ReplayWindowProof],
    termination: ReplayTermination,
    publication_complete: bool,
) -> Result<Vec<u8>> {
    let mut out = CanonicalEncoder::new();
    out.text(request.receipt_domain());
    out.u64(VERSION);
    if let Some(source) = request.onvif_source() { source.encode(&mut out); }
    encode_recording_scope(&mut out, request.scope());
    out.digest(request.route());
    out.text(&request.window().to_string());
    out.digest(request.base_decode_clock());
    out.digest(request.digest());
    encode_scope(&mut out, scope);
    out.digest(approval);
    out.u32(acceptance.cseq());
    out.text(&acceptance.acknowledged().to_string());
    out.u8(0); // Rate-Control: no, the only supported replay policy.
    out.u8(termination.tag());
    out.u8(u8::from(publication_complete));
    out.u64(windows.len() as u64);
    for window in windows {
        out.text(window.slot.as_str());
        out.digest(window.root());
        out.u64(window.summary.decode_interval.start);
        out.u64(window.summary.decode_interval.end);
        out.u64(window.summary.packets as u64);
        out.u64(window.summary.samples as u64);
        out.u64(window.summary.nals as u64);
        out.u64(window.bytes as u64);
        for leaf in window.leaves { out.digest(leaf); }
    }
    let mut bytes = out.finish_checked().map_err(|_| ReplayReceiptError::Limit)?;
    if bytes.len() > MAX_REPLAY_RECEIPT_BYTES - CHECKSUM_BYTES {
        return Err(ReplayReceiptError::Limit);
    }
    let checksum = digest(&bytes)?;
    bytes.try_reserve_exact(CHECKSUM_BYTES).map_err(|_| ReplayReceiptError::Limit)?;
    bytes.push(1);
    bytes.extend_from_slice(&checksum.bytes());
    Ok(bytes)
}

pub(super) fn encode_recording_scope(out: &mut CanonicalEncoder, scope: &RecordingScope) {
    out.text(scope.sensor.as_str());
    out.text(scope.stream.as_str());
    out.u64(scope.generation);
    out.digest(scope.anchor);
    out.digest(scope.receive_clock);
}

pub(super) fn encode_scope(out: &mut CanonicalEncoder, scope: &CatalogScope) {
    encode_recording_scope(out, &scope.recording);
    out.digest(scope.decode_clock);
    out.u32(scope.time_scale);
}

pub(super) fn decode(
    bytes: &[u8],
    expected_codec: ReplayCodec,
    expected_scope: &CatalogScope,
    expected_request: ContentDigest,
) -> Result<ReplayReceipt> {
    if bytes.len() > MAX_REPLAY_RECEIPT_BYTES { return Err(ReplayReceiptError::Limit); }
    let body_end = bytes.len().checked_sub(CHECKSUM_BYTES).ok_or(ReplayReceiptError::Malformed)?;
    let mut trailer = CanonicalDecoder::new(&bytes[body_end..]);
    if trailer.digest().map_err(bad)? != digest(&bytes[..body_end])? {
        return Err(ReplayReceiptError::Digest);
    }
    trailer.ensure_finished().map_err(bad)?;
    let mut input = CanonicalDecoder::new(&bytes[..body_end]);
    let domain = input.text().map_err(bad)?;
    let onvif_domain = match expected_codec {
        ReplayCodec::Avc => ONVIF_AVC_REPLAY_RECEIPT_DOMAIN,
        ReplayCodec::Hevc => ONVIF_HEVC_REPLAY_RECEIPT_DOMAIN,
    };
    if (domain != expected_codec.receipt_domain() && domain != onvif_domain)
        || input.u64().map_err(bad)? != VERSION
    {
        return Err(ReplayReceiptError::Malformed);
    }
    let source = if domain == onvif_domain {
        if input.text().map_err(bad)? != ONVIF_REPLAY_SOURCE_DOMAIN {
            return Err(ReplayReceiptError::Malformed);
        }
        Some(OnvifReplaySource::new(
            input.digest().map_err(bad)?, input.digest().map_err(bad)?, input.digest().map_err(bad)?,
            input.digest().map_err(bad)?, input.digest().map_err(bad)?, input.digest().map_err(bad)?,
            input.digest().map_err(bad)?, input.digest().map_err(bad)?, input.digest().map_err(bad)?,
        )?)
    } else { None };
    let recording = decode_recording_scope(&mut input)?;
    let route = input.digest().map_err(bad)?;
    let window = decode_window(&mut input)?;
    let base = input.digest().map_err(bad)?;
    let request = ReplayRequest::for_source(expected_codec, recording, route, window, base, source)?;
    if input.digest().map_err(bad)? != request.digest() || request.digest() != expected_request {
        return Err(ReplayReceiptError::Scope);
    }
    let scope = CatalogScope {
        recording: decode_recording_scope(&mut input)?,
        decode_clock: input.digest().map_err(bad)?,
        time_scale: input.u32().map_err(bad)?,
    };
    if &scope != expected_scope { return Err(ReplayReceiptError::Scope); }
    let approval = input.digest().map_err(bad)?;
    let cseq = input.u32().map_err(bad)?;
    let acknowledged = decode_window(&mut input)?;
    let acceptance = ReplayAcceptance::new(cseq, request.window(), acknowledged)?;
    if input.u8().map_err(bad)? != 0 { return Err(ReplayReceiptError::Malformed); }
    let termination = match input.u8().map_err(bad)? {
        0 => ReplayTermination::RequestedStop, 1 => ReplayTermination::InputEnded,
        2 => ReplayTermination::SourceFailure, 3 => ReplayTermination::Deadline,
        4 => ReplayTermination::Budget, 5 => ReplayTermination::Authority,
        6 => ReplayTermination::Storage, 7 => ReplayTermination::Output,
        8 => ReplayTermination::ProgressStalled, 9 => ReplayTermination::Cancelled,
        10 => ReplayTermination::ProtocolFailure,
        _ => return Err(ReplayReceiptError::Malformed),
    };
    let publication_complete = match input.u8().map_err(bad)? {
        0 => false, 1 => true, _ => return Err(ReplayReceiptError::Malformed),
    };
    let count = count(&mut input, MAX_REPLAY_WINDOWS, true)?;
    if count > input.remaining() / MIN_WINDOW_BYTES { return Err(ReplayReceiptError::Malformed); }
    let mut windows = bounded_vec(count)?;
    for _ in 0..count {
        let slot = SlotName::parse(input.text().map_err(bad)?).map_err(|_| ReplayReceiptError::Malformed)?;
        let root = input.digest().map_err(bad)?;
        let start = input.u64().map_err(bad)?;
        let end = input.u64().map_err(bad)?;
        let packets = self::count(&mut input, MAX_RECORDING_PACKETS, false)?;
        let samples = self::count(&mut input, MAX_RECORDING_SAMPLES, false)?;
        let nals = self::count(&mut input, MAX_RECORDING_MAPPINGS, false)?;
        let bytes = self::count(&mut input, MAX_RECORDING_BYTES, false)?;
        let leaves = [input.digest().map_err(bad)?, input.digest().map_err(bad)?,
            input.digest().map_err(bad)?, input.digest().map_err(bad)?];
        windows.push(ReplayWindowProof {
            codec: expected_codec,
            slot,
            summary: RecordingSummary { root, scope: scope.recording.clone(), packets, samples,
                nals, time_scale: scope.time_scale, decode_interval: start..end },
            bytes,
            leaves,
        });
    }
    input.ensure_finished().map_err(bad)?;
    let receipt = ReplayReceipt::prepare(request, scope, approval, acceptance, windows,
        termination, publication_complete)?;
    if receipt.metadata_bytes() != bytes { return Err(ReplayReceiptError::Malformed); }
    Ok(receipt)
}

fn decode_recording_scope(input: &mut CanonicalDecoder<'_>) -> Result<RecordingScope> {
    Ok(RecordingScope {
        sensor: SensorId::parse(input.text().map_err(bad)?).map_err(bad)?,
        stream: StreamId::parse(input.text().map_err(bad)?).map_err(bad)?,
        generation: input.u64().map_err(bad)?,
        anchor: input.digest().map_err(bad)?,
        receive_clock: input.digest().map_err(bad)?,
    })
}

fn decode_window(input: &mut CanonicalDecoder<'_>) -> Result<ReplayWindow> {
    let text = input.text().map_err(bad)?;
    if text.len() > MAX_RANGE_BYTES { return Err(ReplayReceiptError::Limit); }
    let window = ReplayWindow::parse(text)?;
    if window.to_string() != text { return Err(ReplayReceiptError::Malformed); }
    Ok(window)
}

fn count(input: &mut CanonicalDecoder<'_>, maximum: usize, allow_zero: bool) -> Result<usize> {
    let value = usize::try_from(input.u64().map_err(bad)?).map_err(|_| ReplayReceiptError::Limit)?;
    if (!allow_zero && value == 0) || value > maximum { return Err(ReplayReceiptError::Limit); }
    Ok(value)
}

fn bad(_: ContractError) -> ReplayReceiptError { ReplayReceiptError::Malformed }

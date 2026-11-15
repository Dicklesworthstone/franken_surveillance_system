#![forbid(unsafe_code)]
//! Shared native AVC/HEVC configuration-record interpretation for container prefixes.

use std::ops::Range;

use crate::demux::{DemuxError, VideoCodec, probe_parameter_sets};

use super::{
    ParameterCodec, ParameterError, ParameterLimits, ParameterSource, ParameterTuple,
    TupleMetadata, checkpoint, parse_tuple, save,
};

fn demux_error(error: DemuxError) -> ParameterError {
    match error {
        DemuxError::Limit => ParameterError::Limit,
        DemuxError::Cancelled => ParameterError::Cancelled,
        DemuxError::Unsupported => ParameterError::Unsupported,
        // The enclosing configuration record was present in full: an internal truncation
        // is malformed source metadata, not a request for more bytes after that record.
        _ => ParameterError::Malformed,
    }
}

fn record_consistency(
    body: &[u8],
    parameter_tail: &[u8],
    tuple: &ParameterTuple<'_>,
    metadata: &TupleMetadata,
    cancelled: &mut impl FnMut() -> bool,
) -> Result<(), ParameterError> {
    match tuple.codec {
        ParameterCodec::Avc => {
            if body.get(1..4) != tuple.sps.bytes.get(1..4) {
                return Err(ParameterError::Contradictory);
            }
            // High-profile optional extension fields are declarations too. Native SPS
            // admission here is 8-bit 4:2:0; record metadata cannot contradict it.
            if !parameter_tail.is_empty() {
                if parameter_tail.len() != 4 {
                    return Err(ParameterError::Malformed);
                }
                if parameter_tail[0] & 3 != 1
                    || parameter_tail[1] & 7 != 0
                    || parameter_tail[2] & 7 != 0
                {
                    return Err(ParameterError::Contradictory);
                }
            }
        }
        ParameterCodec::Hevc => {
            if body.len() < 23 {
                return Err(ParameterError::Malformed);
            }
            if body[13] & 0xf0 != 0xf0
                || body[15] & 0xfc != 0xfc
                || body[16] & 0xfc != 0xfc
                || body[17] & 0xf8 != 0xf8
                || body[18] & 0xf8 != 0xf8
            {
                return Err(ParameterError::Malformed);
            }
            if metadata
                .hevc_profile_tier_level
                .as_ref()
                .map(|ptl| &ptl[..])
                != Some(&body[1..13])
                || body[16] & 3 != 1
                || (body[17] & 7) + 8 != metadata.depth
                || (body[18] & 7) + 8 != metadata.depth
            {
                return Err(ParameterError::Contradictory);
            }
            // The native owner already checked the entire array framing. This initialization
            // operation requires no reserved array bit or incomplete VPS/SPS/PPS array.
            let mut at = 23;
            for _ in 0..body[22] {
                checkpoint(cancelled)?;
                let array = body.get(at..at + 3).ok_or(ParameterError::Malformed)?;
                let kind = array[0] & 63;
                if array[0] & 0x40 != 0 {
                    return Err(ParameterError::Malformed);
                }
                if matches!(kind, 32..=34) && array[0] & 0x80 == 0 {
                    return Err(ParameterError::Unsupported);
                }
                let count = u16::from_be_bytes([array[1], array[2]]);
                at += 3;
                for _ in 0..count {
                    checkpoint(cancelled)?;
                    let size = body.get(at..at + 2).ok_or(ParameterError::Malformed)?;
                    at = at
                        .checked_add(2 + usize::from(u16::from_be_bytes([size[0], size[1]])))
                        .filter(|end| *end <= body.len())
                        .ok_or(ParameterError::Malformed)?;
                }
            }
            if at != body.len() {
                return Err(ParameterError::Malformed);
            }
        }
    }
    Ok(())
}

pub(super) fn parse_record<'a>(
    window: &'a [u8],
    codec: ParameterCodec,
    record: Range<usize>,
    limits: ParameterLimits,
    cancelled: &mut impl FnMut() -> bool,
) -> Result<(ParameterTuple<'a>, TupleMetadata, usize), ParameterError> {
    let mut check = || {
        if (cancelled)() {
            Err(DemuxError::Cancelled)
        } else {
            Ok(())
        }
    };
    let (ranges, units) = probe_parameter_sets(
        window,
        match codec {
            ParameterCodec::Avc => VideoCodec::Avc,
            ParameterCodec::Hevc => VideoCodec::Hevc,
        },
        record.clone(),
        limits.max_units,
        &mut check,
    )
    .map_err(demux_error)?;
    let parameter_end = ranges
        .iter()
        .map(|range| range.end)
        .max()
        .ok_or(ParameterError::Malformed)?;
    let parameter_tail = window
        .get(parameter_end..record.end)
        .ok_or(ParameterError::Malformed)?;
    let (mut vps, mut sps, mut pps) = (None, None, None);
    for range in ranges {
        checkpoint(cancelled)?;
        let bytes = window.get(range.clone()).ok_or(ParameterError::Malformed)?;
        let header = *bytes.first().ok_or(ParameterError::Malformed)?;
        let source = ParameterSource { range, bytes };
        match (codec, header & 31, (header >> 1) & 63) {
            (ParameterCodec::Avc, 7, _) | (ParameterCodec::Hevc, _, 33) => save(&mut sps, source)?,
            (ParameterCodec::Avc, 8, _) | (ParameterCodec::Hevc, _, 34) => save(&mut pps, source)?,
            (ParameterCodec::Hevc, _, 32) => save(&mut vps, source)?,
            _ => return Err(ParameterError::Unsupported),
        }
    }
    let tuple = ParameterTuple {
        codec,
        vps,
        sps: sps.ok_or(ParameterError::Malformed)?,
        pps: pps.ok_or(ParameterError::Malformed)?,
    };
    let metadata = parse_tuple(&tuple, limits, cancelled).map_err(|error| {
        if error == ParameterError::Truncated {
            ParameterError::Malformed
        } else {
            error
        }
    })?;
    record_consistency(
        &window[record.clone()],
        parameter_tail,
        &tuple,
        &metadata,
        cancelled,
    )?;
    Ok((tuple, metadata, units))
}

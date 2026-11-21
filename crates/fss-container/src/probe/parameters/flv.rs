#![forbid(unsafe_code)]
//! Strict FLV initialization over an exact prefix, without heuristic boundary recovery.
//!
//! Uses the packet owner's borrowed header/tag views, then the same configuration
//! parser as MP4 and Matroska. The admitted profile requires ordinary unfiltered
//! tags with zero stream IDs and a first video tag carrying an AVC sequence header.
//! Audio and script payloads are skipped without interpreting or decoding them.
//! No media-clock, picture, source-continuity or vendor-extension claim is made.

use fss_packet::extended_flv::{self, Header, Parse, Tag, avc};

use super::{
    ContainerKind, MAX_PROBE_BYTES, ParameterCodec, ParameterError, ParameterLimits,
    VideoParameters, checkpoint,
};

const MAX_TAGS: usize = 128;

fn framing_error(error: extended_flv::Error) -> ParameterError {
    match error {
        extended_flv::Error::PayloadLimit => ParameterError::Limit,
        extended_flv::Error::InvalidTagKind => ParameterError::Unsupported,
        _ => ParameterError::Malformed,
    }
}

pub(super) fn probe<'a>(
    window: &'a [u8],
    incomplete: ParameterError,
    limits: ParameterLimits,
    cancelled: &mut impl FnMut() -> bool,
) -> Result<VideoParameters<'a>, ParameterError> {
    checkpoint(cancelled)?;
    let prefix = window.get(..9).ok_or(incomplete)?;
    if prefix[4] & !5 != 0 {
        return Err(ParameterError::Malformed);
    }
    let offset = u32::from_be_bytes(
        prefix[5..9]
            .try_into()
            .map_err(|_| ParameterError::Malformed)?,
    );
    if offset as u64 + 4 > MAX_PROBE_BYTES as u64 {
        return Err(ParameterError::Limit);
    }
    let framing = extended_flv::Limits {
        max_payload: MAX_PROBE_BYTES,
        max_trailer: 0,
        max_header: MAX_PROBE_BYTES,
    };
    let header = match Header::parse(window, framing).map_err(framing_error)? {
        Parse::Complete(header) => header,
        Parse::NeedMore => return Err(incomplete),
    };
    if header.flags() & 1 == 0 {
        return Err(ParameterError::Unsupported);
    }
    let mut at = header.wire_bytes().len();
    for _ in 0..MAX_TAGS {
        checkpoint(cancelled)?;
        let remaining = window.get(at..).ok_or(ParameterError::Malformed)?;
        let kind = *remaining.first().ok_or(incomplete)?;
        if kind & 0xc0 != 0 {
            return Err(ParameterError::Malformed);
        }
        if kind & 0x20 != 0 || !matches!(kind, 8 | 9 | 18) {
            return Err(ParameterError::Unsupported);
        }
        let tag_header = remaining.get(..11).ok_or(incomplete)?;
        if tag_header[8..11] != [0; 3] {
            return Err(ParameterError::Malformed);
        }
        let tag = match Tag::parse(remaining, framing).map_err(framing_error)? {
            Parse::Complete(tag) => tag,
            Parse::NeedMore => return Err(incomplete),
        };
        let end = at + tag.wire_bytes().len();
        match kind {
            8 if header.flags() & 4 == 0 => return Err(ParameterError::Contradictory),
            9 => {
                let video = avc::VideoTag::parse(tag).map_err(|error| match error {
                    avc::Error::UnsupportedVideo => ParameterError::Unsupported,
                    _ => ParameterError::Malformed,
                })?;
                if video.frame_type() != 1 || video.packet_type() != avc::PacketType::Configuration
                {
                    return Err(ParameterError::Unsupported);
                }
                if video.composition_offset_ms() != 0 {
                    return Err(ParameterError::Malformed);
                }
                let record = video.body_range();
                let (tuple, metadata, units) = super::configuration::parse_record(
                    window,
                    ParameterCodec::Avc,
                    at + record.start..at + record.end,
                    limits,
                    cancelled,
                )?;
                checkpoint(cancelled)?;
                return Ok(tuple.report(metadata, ContainerKind::Flv, None, end, units));
            }
            _ => {}
        }
        at = end;
    }
    Err(ParameterError::Limit)
}

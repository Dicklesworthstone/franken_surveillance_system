#![forbid(unsafe_code)]
//! A bounded configuration-prefix view using the demux owner's EBML and track grammar.

use super::{
    CLUSTER, CRC32, DemuxError, DemuxLimits, EBML, Element, Reader, SEGMENT, TRACKS, VOID,
    VideoCodec, ebml_header, end_of, header, level_one_name, select_track, verify_crc, visit,
};
use std::ops::Range;

pub(crate) struct ConfigurationPrefix {
    pub(crate) codec: VideoCodec,
    pub(crate) number: u64,
    pub(crate) private: Range<usize>,
    pub(crate) inspected_bytes: usize,
}

/// An internal child cannot request bytes beyond its already complete enclosing element.
fn complete_element(error: DemuxError) -> DemuxError {
    match error {
        DemuxError::Truncated => DemuxError::Layout,
        other => other,
    }
}

/// The first complete Tracks closes this result. Segment/media completion and timing remain
/// outside its scope. The public probe owns the caller's narrower prefix and NAL allowances.
pub(crate) fn probe_configuration(
    source: &[u8],
    check: &mut dyn FnMut() -> Result<(), DemuxError>,
) -> Result<ConfigurationPrefix, DemuxError> {
    if source.len() > 4096 {
        return Err(DemuxError::Limit);
    }
    let limits = DemuxLimits {
        maximum_input_bytes: 4096,
        maximum_metadata_bytes: 4096,
        maximum_boxes: 128,
        maximum_tracks: 16,
        ..DemuxLimits::default()
    };
    let mut r = Reader::new(source, limits, check);
    visit(&mut r)?;
    let (id, data, size) = header(source, 0, source.len())?;
    if id != EBML {
        return Err(DemuxError::Unsupported);
    }
    let header_end = end_of(data, size.ok_or(DemuxError::Layout)?, source.len())?;
    ebml_header(&mut r, data..header_end).map_err(complete_element)?;
    visit(&mut r)?;
    let (id, mut at, size) = header(source, header_end, source.len())?;
    if id != SEGMENT {
        return Err(DemuxError::MissingBox(SEGMENT.to_be_bytes()));
    }
    let segment_end = size
        .map(|size| at.checked_add(size).ok_or(DemuxError::Limit))
        .transpose()?;
    let limit = segment_end.unwrap_or(source.len()).min(source.len());
    let complete_segment = segment_end.is_some_and(|end| end <= source.len());
    while at < limit {
        visit(&mut r)?;
        let (id, data, size) = header(source, at, limit).map_err(|error| {
            if complete_segment {
                complete_element(error)
            } else {
                error
            }
        })?;
        // A prefix cannot verify a Segment CRC, whose checksum covers the unread media.
        // Reaching media before Tracks cannot supply an initialization-only result either.
        if matches!(id, CLUSTER | CRC32) || level_one_name(id).is_none() {
            return Err(DemuxError::Unsupported);
        }
        let end = data
            .checked_add(size.ok_or(DemuxError::Unsupported)?)
            .ok_or(DemuxError::Limit)?;
        if segment_end.is_some_and(|outer| end > outer) {
            return Err(DemuxError::Layout);
        }
        if end > source.len() {
            return Err(DemuxError::Truncated);
        }
        let element = Element {
            id,
            start: at,
            data: data..end,
        };
        if id == TRACKS {
            let selected = select_track(&mut r, &element, None).map_err(complete_element)?;
            r.checkpoint()?;
            return Ok(ConfigurationPrefix {
                codec: selected.codec,
                number: selected.number,
                private: selected.private.data,
                inspected_bytes: end,
            });
        }
        // Match full demux admission for an unopened master's leading CRC. No skipped bytes
        // are treated as codec configuration; Void payloads remain uninterpreted.
        if id != VOID && data != end {
            visit(&mut r)?;
            let (child, start, size) = header(source, data, end).map_err(complete_element)?;
            if child == CRC32 {
                let crc_end = end_of(start, size.ok_or(DemuxError::Layout)?, end)
                    .map_err(complete_element)?;
                let crc = Element {
                    id: CRC32,
                    start: data,
                    data: start..crc_end,
                };
                verify_crc(&mut r, &[crc], end)?;
            }
        }
        at = end;
    }
    if complete_segment {
        Err(DemuxError::MissingBox(TRACKS.to_be_bytes()))
    } else {
        Err(DemuxError::Truncated)
    }
}

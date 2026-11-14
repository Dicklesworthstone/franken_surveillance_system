#![forbid(unsafe_code)]
//! Complete initialization metadata within the admitted prefix, without media seeking.

use std::ops::Range;

use crate::demux::{DemuxError, VideoCodec, probe_parameter_sets};

use super::{
    ContainerKind, ParameterCodec, ParameterError, ParameterLimits, ParameterSource,
    ParameterTuple, TupleMetadata, VideoParameters, checkpoint, parse_tuple, save,
};

const MAX_BOXES: usize = 128;
const MAX_TRACKS: usize = 16;

#[derive(Clone)]
struct Atom {
    kind: [u8; 4],
    body: Range<usize>,
}

struct Walker<'a, 'c, F> {
    bytes: &'a [u8],
    end_of_source: bool,
    incomplete: ParameterError,
    boxes: usize,
    cancelled: &'c mut F,
}

impl<'a, F: FnMut() -> bool> Walker<'a, '_, F> {
    fn next(
        &mut self,
        at: &mut usize,
        end: usize,
        top: bool,
    ) -> Result<Option<Atom>, ParameterError> {
        checkpoint(self.cancelled)?;
        if *at == end {
            return Ok(None);
        }
        if self.boxes == MAX_BOXES {
            return Err(ParameterError::Limit);
        }
        self.boxes += 1;
        let failure = if top {
            self.incomplete
        } else {
            ParameterError::Malformed
        };
        let header = self.bytes.get(*at..end).ok_or(ParameterError::Malformed)?;
        let prefix = header.get(..8).ok_or(failure)?;
        let size = u32::from_be_bytes(prefix[..4].try_into().map_err(|_| failure)?);
        let kind = prefix[4..8].try_into().map_err(|_| failure)?;
        let (length, header_length) = match size {
            0 if top && self.end_of_source => (end - *at, 8),
            0 if top => return Err(self.incomplete),
            0 => return Err(ParameterError::Malformed),
            1 => {
                let extended = header.get(8..16).ok_or(failure)?;
                let length = u64::from_be_bytes(extended.try_into().map_err(|_| failure)?);
                (
                    usize::try_from(length).map_err(|_| ParameterError::Limit)?,
                    16,
                )
            }
            length => (length as usize, 8),
        };
        if length < header_length {
            return Err(ParameterError::Malformed);
        }
        let stop = at.checked_add(length).ok_or(ParameterError::Limit)?;
        if stop > end {
            return Err(failure);
        }
        let body = *at + header_length..stop;
        *at = stop;
        Ok(Some(Atom { kind, body }))
    }

    /// Visit every child header once; duplicates of a requested singleton refuse.
    fn children<const N: usize>(
        &mut self,
        range: Range<usize>,
        kinds: [[u8; 4]; N],
    ) -> Result<[Option<Atom>; N], ParameterError> {
        let mut result = std::array::from_fn(|_| None);
        let mut at = range.start;
        while let Some(atom) = self.next(&mut at, range.end, false)? {
            if atom.kind == *b"cmov" {
                return Err(ParameterError::Unsupported);
            }
            if let Some(index) = kinds.iter().position(|kind| *kind == atom.kind) {
                if result[index].is_some() {
                    return Err(ParameterError::Contradictory);
                }
                result[index] = Some(atom);
            }
        }
        Ok(result)
    }

    fn body(&self, atom: &Atom) -> &'a [u8] {
        &self.bytes[atom.body.clone()]
    }

    fn track(&mut self, atom: Atom) -> Result<(u32, Option<Atom>), ParameterError> {
        let [header, media] = self.children(atom.body, [*b"tkhd", *b"mdia"])?;
        let header = header.ok_or(ParameterError::Malformed)?;
        let media = media.ok_or(ParameterError::Malformed)?;
        let id = track_id(self.body(&header))?;
        let [handler, info] = self.children(media.body, [*b"hdlr", *b"minf"])?;
        let handler = handler.ok_or(ParameterError::Malformed)?;
        let handler = self.body(&handler);
        if handler.len() < 24 || handler[..4] != [0; 4] {
            return Err(ParameterError::Malformed);
        }
        if handler[8..12] != *b"vide" {
            return Ok((id, None));
        }
        let info = info.ok_or(ParameterError::Malformed)?;
        let [table] = self.children(info.body, [*b"stbl"])?;
        let table = table.ok_or(ParameterError::Malformed)?;
        let [description] = self.children(table.body, [*b"stsd"])?;
        Ok((id, Some(description.ok_or(ParameterError::Malformed)?)))
    }

    fn movie(&mut self, movie: &Atom) -> Result<(u32, Atom), ParameterError> {
        let mut at = movie.body.start;
        let mut ids = [0_u32; MAX_TRACKS];
        let mut tracks = 0;
        let mut selected = None;
        while let Some(atom) = self.next(&mut at, movie.body.end, false)? {
            if atom.kind == *b"cmov" {
                return Err(ParameterError::Unsupported);
            }
            if atom.kind != *b"trak" {
                continue;
            }
            if tracks == MAX_TRACKS {
                return Err(ParameterError::Limit);
            }
            let (id, description) = self.track(atom)?;
            if ids[..tracks].contains(&id) {
                return Err(ParameterError::Contradictory);
            }
            ids[tracks] = id;
            tracks += 1;
            if let Some(description) = description {
                if selected.is_some() {
                    return Err(ParameterError::Contradictory);
                }
                selected = Some((id, description));
            }
        }
        selected.ok_or(ParameterError::Unsupported)
    }

    fn configuration(
        &mut self,
        description: Atom,
    ) -> Result<(ParameterCodec, Atom), ParameterError> {
        let body = self.body(&description);
        if body.len() < 8 || body[..4] != [0; 4] {
            return Err(ParameterError::Malformed);
        }
        if body[4..8] != [0, 0, 0, 1] {
            return Err(ParameterError::Contradictory);
        }
        let mut at = description.body.start + 8;
        let entry = self
            .next(&mut at, description.body.end, false)?
            .ok_or(ParameterError::Malformed)?;
        if at != description.body.end {
            return Err(ParameterError::Malformed);
        }
        // avc3/hev1 may rely on later in-band configuration. This operation reports only
        // complete initialization; their sample-level generation protocol belongs to demux.
        let codec = match &entry.kind {
            b"avc1" => ParameterCodec::Avc,
            b"hvc1" => ParameterCodec::Hevc,
            _ => return Err(ParameterError::Unsupported),
        };
        let body = self.body(&entry);
        if body.len() < 78 || body[..6] != [0; 6] || body[6..8] != [0, 1] {
            return Err(ParameterError::Malformed);
        }
        if body[24..26] == [0; 2] || body[26..28] == [0; 2] {
            return Err(ParameterError::Malformed);
        }
        let [avc, hevc, protection] = self.children(
            entry.body.start + 78..entry.body.end,
            [*b"avcC", *b"hvcC", *b"sinf"],
        )?;
        if protection.is_some() {
            return Err(ParameterError::Unsupported);
        }
        match (codec, avc, hevc) {
            (ParameterCodec::Avc, Some(record), None)
            | (ParameterCodec::Hevc, None, Some(record)) => Ok((codec, record)),
            (_, Some(_), Some(_)) => Err(ParameterError::Contradictory),
            _ => Err(ParameterError::Malformed),
        }
    }
}

fn track_id(body: &[u8]) -> Result<u32, ParameterError> {
    let version = *body.first().ok_or(ParameterError::Malformed)?;
    let (at, length) = match version {
        0 => (12, 84),
        1 => (20, 96),
        _ => return Err(ParameterError::Unsupported),
    };
    if body.len() != length || body[1..3] != [0; 2] || body[3] & 0xf0 != 0 {
        return Err(ParameterError::Malformed);
    }
    let id = u32::from_be_bytes(
        body[at..at + 4]
            .try_into()
            .map_err(|_| ParameterError::Malformed)?,
    );
    if id == 0 {
        return Err(ParameterError::Malformed);
    }
    Ok(id)
}

fn demux_error(error: DemuxError) -> ParameterError {
    match error {
        DemuxError::Limit => ParameterError::Limit,
        DemuxError::Cancelled => ParameterError::Cancelled,
        DemuxError::Unsupported => ParameterError::Unsupported,
        // The enclosing configuration box was present in full: an internal truncation
        // is malformed source metadata, not a request for more bytes after that box.
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
            // The native owner already checked the entire array framing. Check the hvc1
            // declaration here as well: no reserved array bit or incomplete VPS/SPS/PPS array.
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

pub(super) fn probe<'a>(
    window: &'a [u8],
    end_of_source: bool,
    incomplete: ParameterError,
    limits: ParameterLimits,
    cancelled: &mut impl FnMut() -> bool,
) -> Result<VideoParameters<'a>, ParameterError> {
    let mut walker = Walker {
        bytes: window,
        end_of_source,
        incomplete,
        boxes: 0,
        cancelled,
    };
    let mut at = 0;
    let mut ftyp = false;
    let (movie, id, description) = loop {
        let atom = walker
            .next(&mut at, window.len(), true)?
            .ok_or(incomplete)?;
        match &atom.kind {
            b"ftyp" => {
                if ftyp {
                    return Err(ParameterError::Contradictory);
                }
                let body = walker.body(&atom);
                if body.len() < 8 || !(body.len() - 8).is_multiple_of(4) {
                    return Err(ParameterError::Malformed);
                }
                ftyp = true;
            }
            b"moov" if ftyp => {
                let (id, description) = walker.movie(&atom)?;
                break (atom, id, description);
            }
            b"moof" | b"cmov" => return Err(ParameterError::Unsupported),
            _ => {}
        }
    };
    let (codec, record) = walker.configuration(description)?;
    let mut check = || {
        if (walker.cancelled)() {
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
        record.body.clone(),
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
        .get(parameter_end..record.body.end)
        .ok_or(ParameterError::Malformed)?;
    let (mut vps, mut sps, mut pps) = (None, None, None);
    for range in ranges {
        checkpoint(walker.cancelled)?;
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
    let metadata = parse_tuple(&tuple, limits, walker.cancelled).map_err(|error| {
        if error == ParameterError::Truncated {
            ParameterError::Malformed
        } else {
            error
        }
    })?;
    record_consistency(
        walker.body(&record),
        parameter_tail,
        &tuple,
        &metadata,
        walker.cancelled,
    )?;
    checkpoint(walker.cancelled)?;
    Ok(tuple.report(
        metadata,
        ContainerKind::IsoBmff,
        Some(id),
        movie.body.end,
        units,
    ))
}

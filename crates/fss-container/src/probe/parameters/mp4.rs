#![forbid(unsafe_code)]
//! Complete initialization metadata within the admitted prefix, without media seeking.

use std::ops::Range;

use super::{
    ContainerKind, ParameterCodec, ParameterError, ParameterLimits, VideoParameters, checkpoint,
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
    let (tuple, metadata, units) =
        super::configuration::parse_record(window, codec, record.body, limits, walker.cancelled)?;
    checkpoint(walker.cancelled)?;
    Ok(tuple.report(
        metadata,
        ContainerKind::IsoBmff,
        Some(id),
        movie.body.end,
        units,
    ))
}

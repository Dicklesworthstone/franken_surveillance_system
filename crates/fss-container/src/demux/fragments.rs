#![forbid(unsafe_code)]
//! Fragmented MP4 (ISO/IEC 14496-12 8.8) sample index for the selected video track.
//!
//! `mvex`/`trex` defaults, then every top-level `moof` in file order: `mfhd` sequence numbers
//! must increase, the selected track's `traf` is read through `tfhd`, optional `tfdt` and its
//! `trun` boxes, and every sample range must lie inside one `mdat` body. The result has the same
//! shape as the indexed sample-table join, so NAL validation and custody stay shared.
use super::DemuxError;
use super::reader::{BoxRef, Reader, be32, be64, full, one, optional};
use std::ops::Range;

/// One sample before NAL validation: source range, decode time, duration, composition offset
/// and the container's sync assertion.
pub(super) type FragmentSample = (Range<usize>, u64, u32, i64, bool);

/// `trex` defaults of the selected track.
struct Defaults {
    duration: u32,
    size: u32,
    flags: u32,
}

/// `sample_is_non_sync_sample` in ISO/IEC 14496-12 8.8.3.1 sample flags.
const NON_SYNC: u32 = 0x0001_0000;

fn defaults(r: &mut Reader<'_, '_>, mvex: &BoxRef, track: u32) -> Result<Defaults, DemuxError> {
    let children = r.children(mvex.body.clone(), false)?;
    let mut found = None;
    for trex in children.iter().filter(|b| b.kind == *b"trex") {
        let b = r.body(trex);
        full(b, 0, 0)?;
        if b.len() != 24 {
            return Err(DemuxError::Layout);
        }
        if be32(b, 4)? != track {
            continue;
        }
        if found.is_some() {
            return Err(DemuxError::DuplicateBox(*b"trex"));
        }
        if be32(b, 8)? != 1 {
            return Err(DemuxError::Unsupported);
        }
        found = Some(Defaults {
            duration: be32(b, 12)?,
            size: be32(b, 16)?,
            flags: be32(b, 20)?,
        });
    }
    found.ok_or(DemuxError::MissingBox(*b"trex"))
}

/// Header fields of one `tfhd` (version 0).
struct TrackFragment {
    track: u32,
    base: Option<u64>,
    default_base_is_moof: bool,
    duration: Option<u32>,
    size: Option<u32>,
    flags: Option<u32>,
}

fn track_fragment_header(b: &[u8]) -> Result<TrackFragment, DemuxError> {
    if b.first() != Some(&0) {
        return Err(DemuxError::Unsupported);
    }
    let flags = be32(b, 0)? & 0x00ff_ffff;
    if flags & !0x0003_003b != 0 {
        return Err(DemuxError::Unsupported);
    }
    let mut at = 8;
    let mut field = |present: bool, width: usize| -> Result<Option<u64>, DemuxError> {
        if !present {
            return Ok(None);
        }
        let value = if width == 8 {
            be64(b, at)?
        } else {
            u64::from(be32(b, at)?)
        };
        at += width;
        Ok(Some(value))
    };
    let base = field(flags & 0x1 != 0, 8)?;
    let description = field(flags & 0x2 != 0, 4)?;
    let narrow = |value: Option<u64>| value.map(|v| u32::try_from(v).unwrap_or(u32::MAX));
    let duration = narrow(field(flags & 0x8 != 0, 4)?);
    let size = narrow(field(flags & 0x10 != 0, 4)?);
    let sample_flags = narrow(field(flags & 0x20 != 0, 4)?);
    if at != b.len() {
        return Err(DemuxError::Layout);
    }
    if description.is_some_and(|index| index != 1) {
        return Err(DemuxError::Unsupported);
    }
    Ok(TrackFragment {
        track: be32(b, 4)?,
        base,
        default_base_is_moof: flags & 0x0002_0000 != 0,
        duration,
        size,
        flags: sample_flags,
    })
}

/// The selected track's samples across every movie fragment, in decode (file) order.
pub(super) fn fragments(
    r: &mut Reader<'_, '_>,
    top: &[BoxRef],
    mvex: &BoxRef,
    track: u32,
    media: &[Range<usize>],
) -> Result<Vec<FragmentSample>, DemuxError> {
    let trex = defaults(r, mvex, track)?;
    let mut samples: Vec<FragmentSample> = Vec::new();
    let mut sequence = None;
    let mut next_decode = 0_u64;
    for moof in top.iter().filter(|b| b.kind == *b"moof") {
        r.checkpoint()?;
        let children = r.children(moof.body.clone(), false)?;
        let mfhd = one(&children, b"mfhd")?;
        let b = r.body(&mfhd);
        full(b, 0, 0)?;
        if b.len() != 8 {
            return Err(DemuxError::Layout);
        }
        let number = be32(b, 4)?;
        if sequence.is_some_and(|previous| number <= previous) {
            return Err(DemuxError::Layout);
        }
        sequence = Some(number);
        for (position, traf) in children.iter().filter(|b| b.kind == *b"traf").enumerate() {
            let boxes = r.children(traf.body.clone(), false)?;
            let header = track_fragment_header(r.body(&one(&boxes, b"tfhd")?))?;
            if header.track != track {
                continue;
            }
            // Encryption and sample-group side tables change interpretation; never ignored.
            if boxes.iter().any(|b| {
                matches!(
                    &b.kind,
                    b"senc" | b"saiz" | b"saio" | b"sbgp" | b"sgpd" | b"subs"
                )
            }) {
                return Err(DemuxError::Unsupported);
            }
            let base = match header.base {
                Some(base) => usize::try_from(base).map_err(|_| DemuxError::Layout)?,
                // Without either flag only the first track fragment starts at the moof.
                None if header.default_base_is_moof || position == 0 => moof.start,
                None => return Err(DemuxError::Unsupported),
            };
            if let Some(tfdt) = optional(&boxes, b"tfdt")? {
                let b = r.body(&tfdt);
                let (version, width) = match b.first() {
                    Some(0) => (0, 4),
                    Some(1) => (1, 8),
                    _ => return Err(DemuxError::Unsupported),
                };
                full(b, version, 0)?;
                if b.len() != 4 + width {
                    return Err(DemuxError::Layout);
                }
                let start = if width == 8 {
                    be64(b, 4)?
                } else {
                    u64::from(be32(b, 4)?)
                };
                if start < next_decode {
                    return Err(DemuxError::Timeline);
                }
                next_decode = start;
            }
            let mut at = base;
            for (run_index, trun) in boxes.iter().filter(|b| b.kind == *b"trun").enumerate() {
                r.checkpoint()?;
                let b = r.body(trun);
                let version = *b.first().ok_or(DemuxError::Truncated)?;
                let flags = be32(b, 0)? & 0x00ff_ffff;
                if version > 1 || flags & !0x0f05 != 0 {
                    return Err(DemuxError::Unsupported);
                }
                let count = be32(b, 4)? as usize;
                if count > r.limits.maximum_samples.saturating_sub(samples.len()) {
                    return Err(DemuxError::Limit);
                }
                r.entries(count)?;
                let mut position = 8;
                if flags & 0x1 != 0 {
                    let offset = i64::from(be32(b, position)? as i32);
                    position += 4;
                    at = i64::try_from(base)
                        .ok()
                        .and_then(|base| base.checked_add(offset))
                        .and_then(|start| usize::try_from(start).ok())
                        .ok_or(DemuxError::Layout)?;
                } else if run_index == 0 {
                    at = base;
                }
                let first_flags = if flags & 0x4 != 0 {
                    position += 4;
                    Some(be32(b, position - 4)?)
                } else {
                    None
                };
                let fields = [0x100, 0x200, 0x400, 0x800]
                    .iter()
                    .filter(|bit| flags & **bit != 0)
                    .count();
                let expected = count
                    .checked_mul(fields * 4)
                    .and_then(|n| n.checked_add(position))
                    .ok_or(DemuxError::Limit)?;
                if b.len() != expected {
                    return Err(DemuxError::Layout);
                }
                for index in 0..count {
                    let mut value = |present: bool| -> Result<Option<u32>, DemuxError> {
                        if !present {
                            return Ok(None);
                        }
                        position += 4;
                        be32(b, position - 4).map(Some)
                    };
                    let duration = value(flags & 0x100 != 0)?
                        .or(header.duration)
                        .unwrap_or(trex.duration);
                    let size = value(flags & 0x200 != 0)?
                        .or(header.size)
                        .unwrap_or(trex.size);
                    let listed = value(flags & 0x400 != 0)?;
                    let composition = value(flags & 0x800 != 0)?.map_or(0, |raw| {
                        if version == 1 {
                            i64::from(raw as i32)
                        } else {
                            i64::from(raw)
                        }
                    });
                    let sample_flags = first_flags
                        .filter(|_| index == 0)
                        .or(listed)
                        .or(header.flags)
                        .unwrap_or(trex.flags);
                    if duration == 0 {
                        return Err(DemuxError::Timeline);
                    }
                    if size == 0 {
                        return Err(DemuxError::Layout);
                    }
                    let end = at.checked_add(size as usize).ok_or(DemuxError::Layout)?;
                    let containing = media
                        .partition_point(|m| m.start <= at)
                        .checked_sub(1)
                        .and_then(|i| media.get(i));
                    if containing.is_none_or(|m| end > m.end) {
                        return Err(DemuxError::Layout);
                    }
                    samples.push((
                        at..end,
                        next_decode,
                        duration,
                        composition,
                        sample_flags & NON_SYNC == 0,
                    ));
                    at = end;
                    next_decode = next_decode
                        .checked_add(u64::from(duration))
                        .ok_or(DemuxError::Timeline)?;
                }
            }
        }
    }
    if samples.is_empty() {
        return Err(DemuxError::Layout);
    }
    let mut order: Vec<&Range<usize>> = samples.iter().map(|sample| &sample.0).collect();
    order.sort_by_key(|range| range.start);
    if order.windows(2).any(|pair| pair[0].end > pair[1].start) {
        return Err(DemuxError::Layout);
    }
    Ok(samples)
}

#![forbid(unsafe_code)]
//! The indexed avc1 sample-table join and configuration decoder.
use super::reader::{BoxRef, Reader, be16, be32, be64, exact_table, full, one, optional};
use super::{DemuxError, Mp4Edit};
use std::ops::Range;

pub(super) fn time_header(b: &[u8]) -> Result<(u32, u64), DemuxError> {
    let version = *b.first().ok_or(DemuxError::Truncated)?;
    full(b, version, 0)?;
    let (scale, duration) = match version {
        0 => {
            let n = be32(b, 16)?;
            (
                be32(b, 12)?,
                if n == u32::MAX {
                    u64::MAX
                } else {
                    u64::from(n)
                },
            )
        }
        1 => (be32(b, 20)?, be64(b, 24)?),
        _ => return Err(DemuxError::Unsupported),
    };
    if scale == 0 {
        return Err(DemuxError::Timeline);
    }
    Ok((scale, duration))
}
pub(super) fn track_header(b: &[u8]) -> Result<(u32, [i32; 9]), DemuxError> {
    let version = *b.first().ok_or(DemuxError::Truncated)?;
    if be32(b, 0)? & 0x00ff_fff0 != 0 {
        return Err(DemuxError::Unsupported);
    }
    let (id_at, matrix_at, size) = match version {
        0 => (12, 40, 84),
        1 => (20, 52, 96),
        _ => return Err(DemuxError::Unsupported),
    };
    if b.len() != size {
        return Err(DemuxError::Layout);
    }
    let id = be32(b, id_at)?;
    if id == 0 {
        return Err(DemuxError::TrackSelection);
    }
    let mut matrix = [0; 9];
    for (i, n) in matrix.iter_mut().enumerate() {
        *n = be32(b, matrix_at + i * 4)? as i32;
    }
    Ok((id, matrix))
}
pub(super) fn parse_edits(
    r: &mut Reader<'_, '_>,
    track: &[BoxRef],
) -> Result<Vec<Mp4Edit>, DemuxError> {
    let Some(edts) = optional(track, b"edts")? else {
        return Ok(Vec::new());
    };
    let contents = r.children(edts.body, false)?;
    let elst = one(&contents, b"elst")?;
    if contents.len() != 1 {
        return Err(DemuxError::Unsupported);
    }
    let b = r.body(&elst);
    let version = *b.first().ok_or(DemuxError::Truncated)?;
    full(b, version, 0)?;
    let width = match version {
        0 => 12,
        1 => 20,
        _ => return Err(DemuxError::Unsupported),
    };
    let count = be32(b, 4)? as usize;
    if count > 1024 {
        return Err(DemuxError::Limit);
    }
    exact_table(b, 8, count, width)?;
    r.entries(count)?;
    let mut edits = Vec::with_capacity(count);
    for row in b[8..].chunks_exact(width) {
        let (duration, time, rate_at) = if version == 0 {
            (u64::from(be32(row, 0)?), i64::from(be32(row, 4)? as i32), 8)
        } else {
            (be64(row, 0)?, be64(row, 8)? as i64, 16)
        };
        if duration == 0 || time < -1 || be32(row, rate_at)? != 0x0001_0000 {
            return Err(DemuxError::Unsupported);
        }
        edits.push(Mp4Edit {
            movie_duration: duration,
            media_time: time,
        });
    }
    Ok(edits)
}
pub(super) fn validate_data_reference(
    r: &mut Reader<'_, '_>,
    info: &[BoxRef],
) -> Result<(), DemuxError> {
    let dinf = one(info, b"dinf")?;
    let boxes = r.children(dinf.body, false)?;
    let dref = one(&boxes, b"dref")?;
    let b = r.body(&dref);
    full(b, 0, 0)?;
    if be32(b, 4)? != 1 {
        return Err(DemuxError::Unsupported);
    }
    let entries = r.children(dref.body.start + 8..dref.body.end, false)?;
    if entries.len() != 1 || entries[0].kind != *b"url " {
        return Err(DemuxError::Unsupported);
    }
    let reference = r.body(&entries[0]);
    full(reference, 0, 1)?;
    if reference.len() != 4 {
        return Err(DemuxError::Unsupported);
    }
    Ok(())
}
/// Coded dimensions, NAL length-field bytes and parameter-set byte ranges of one sample entry.
pub(super) type Configuration = ([u16; 2], usize, Vec<Range<usize>>);
pub(super) fn configuration(
    r: &mut Reader<'_, '_>,
    stsd: &BoxRef,
) -> Result<Configuration, DemuxError> {
    let b = r.body(stsd);
    full(b, 0, 0)?;
    if be32(b, 4)? != 1 {
        return Err(DemuxError::Unsupported);
    }
    let entries = r.children(stsd.body.start + 8..stsd.body.end, false)?;
    if entries.len() != 1 || entries[0].kind != *b"avc1" {
        return Err(DemuxError::Unsupported);
    }
    let avc = &entries[0];
    let data = r.body(avc);
    if data.len() < 78 || data[..6] != [0; 6] || be16(data, 6)? != 1 {
        return Err(DemuxError::Unsupported);
    }
    let dimensions = [be16(data, 24)?, be16(data, 26)?];
    if dimensions.contains(&0) {
        return Err(DemuxError::Layout);
    }
    let boxes = r.children(avc.body.start + 78..avc.body.end, false)?;
    if boxes.iter().any(|b| b.kind == *b"sinf") {
        return Err(DemuxError::Unsupported);
    }
    let config = one(&boxes, b"avcC")?;
    let b = r.body(&config);
    if b.len() < 7 || b[0] != 1 || b[4] & 0xfc != 0xfc || b[5] & 0xe0 != 0xe0 {
        return Err(DemuxError::Nal);
    }
    let length = usize::from((b[4] & 3) + 1);
    if length == 3 {
        return Err(DemuxError::Unsupported);
    }
    let mut position = 6;
    let mut parameters = Vec::new();
    let sps = usize::from(b[5] & 31);
    if sps == 0 {
        return Err(DemuxError::Nal);
    }
    config_nals(r, &config, &mut position, sps, 7, &mut parameters)?;
    let pps = usize::from(*b.get(position).ok_or(DemuxError::Truncated)?);
    position += 1;
    if pps == 0 {
        return Err(DemuxError::Nal);
    }
    config_nals(r, &config, &mut position, pps, 8, &mut parameters)?;
    if position < b.len() {
        if !matches!(b[1], 100 | 110 | 122 | 144) {
            return Err(DemuxError::Unsupported);
        }
        let extension = b.get(position..position + 4).ok_or(DemuxError::Truncated)?;
        if extension[0] & 0xfc != 0xfc || extension[1] & 0xf8 != 0xf8 || extension[2] & 0xf8 != 0xf8
        {
            return Err(DemuxError::Nal);
        }
        position += 4;
        config_nals(
            r,
            &config,
            &mut position,
            usize::from(extension[3]),
            13,
            &mut parameters,
        )?;
    }
    if position != b.len() {
        return Err(DemuxError::Layout);
    }
    Ok((dimensions, length, parameters))
}
fn config_nals(
    r: &mut Reader<'_, '_>,
    config: &BoxRef,
    position: &mut usize,
    count: usize,
    kind: u8,
    result: &mut Vec<Range<usize>>,
) -> Result<(), DemuxError> {
    r.entries(count)?;
    let b = r.body(config);
    for _ in 0..count {
        r.checkpoint()?;
        let len = usize::from(be16(b, *position)?);
        *position += 2;
        let end = position
            .checked_add(len)
            .filter(|end| *end <= b.len())
            .ok_or(DemuxError::Truncated)?;
        if nal_kind(&b[*position..end])? != kind {
            return Err(DemuxError::Nal);
        }
        r.nals = r
            .nals
            .checked_add(1)
            .filter(|n| *n <= r.limits.maximum_nals)
            .ok_or(DemuxError::Limit)?;
        result.push(config.body.start + *position..config.body.start + end);
        *position = end;
    }
    Ok(())
}
pub(super) fn sizes(r: &mut Reader<'_, '_>, stsz: &BoxRef) -> Result<Vec<u32>, DemuxError> {
    let b = r.body(stsz);
    full(b, 0, 0)?;
    let fixed = be32(b, 4)?;
    let count = be32(b, 8)? as usize;
    if count > r.limits.maximum_samples {
        return Err(DemuxError::Limit);
    }
    exact_table(b, 12, if fixed == 0 { count } else { 0 }, 4)?;
    r.entries(count)?;
    if fixed != 0 {
        return Ok(vec![fixed; count]);
    }
    let mut sizes = Vec::with_capacity(count);
    for row in b[12..].as_chunks::<4>().0 {
        let n = be32(row, 0)?;
        if n == 0 {
            return Err(DemuxError::Layout);
        }
        sizes.push(n);
    }
    Ok(sizes)
}
pub(super) fn offsets(r: &mut Reader<'_, '_>, tables: &[BoxRef]) -> Result<Vec<u64>, DemuxError> {
    let low = optional(tables, b"stco")?;
    let high = optional(tables, b"co64")?;
    let (b, width) = match (low, high) {
        (Some(b), None) => (b, 4),
        (None, Some(b)) => (b, 8),
        _ => return Err(DemuxError::Layout),
    };
    let (data, _) = r.table(&b, width, r.limits.maximum_samples)?;
    data.chunks_exact(width)
        .map(|row| {
            if width == 4 {
                be32(row, 0).map(u64::from)
            } else {
                be64(row, 0)
            }
        })
        .collect()
}
pub(super) fn locations(
    r: &mut Reader<'_, '_>,
    stsc: &BoxRef,
    sizes: &[u32],
    offsets: &[u64],
    media: &[Range<usize>],
) -> Result<Vec<Range<usize>>, DemuxError> {
    let (data, count) = r.table(stsc, 12, r.limits.maximum_samples)?;
    if count == 0 || offsets.is_empty() {
        return Err(DemuxError::Layout);
    }
    let mut runs = Vec::with_capacity(count);
    for row in data.as_chunks::<12>().0 {
        let first = be32(row, 0)? as usize;
        let per_chunk = be32(row, 4)? as usize;
        if first == 0
            || first > offsets.len()
            || per_chunk == 0
            || per_chunk > sizes.len()
            || be32(row, 8)? != 1
            || runs.last().is_some_and(|(p, _)| *p >= first)
        {
            return Err(DemuxError::Layout);
        }
        runs.push((first, per_chunk));
    }
    if runs[0].0 != 1 {
        return Err(DemuxError::Layout);
    }
    let mut result = Vec::with_capacity(sizes.len());
    let mut run = 0;
    for (chunk, offset) in offsets.iter().enumerate() {
        r.checkpoint()?;
        if run + 1 < runs.len() && runs[run + 1].0 == chunk + 1 {
            run += 1;
        }
        let mut at = usize::try_from(*offset).map_err(|_| DemuxError::Layout)?;
        for _ in 0..runs[run].1 {
            let size = *sizes.get(result.len()).ok_or(DemuxError::Layout)? as usize;
            let end = at.checked_add(size).ok_or(DemuxError::Layout)?;
            let containing = media
                .partition_point(|m| m.start <= at)
                .checked_sub(1)
                .and_then(|i| media.get(i));
            if containing.is_none_or(|m| end > m.end) {
                return Err(DemuxError::Layout);
            }
            result.push(at..end);
            at = end;
        }
    }
    if result.len() != sizes.len() {
        return Err(DemuxError::Layout);
    }
    let mut order = result.clone();
    order.sort_by_key(|r| r.start);
    if order.windows(2).any(|p| p[0].end > p[1].start) {
        return Err(DemuxError::Layout);
    }
    Ok(result)
}
pub(super) fn timing(
    r: &mut Reader<'_, '_>,
    stts: &BoxRef,
    samples: usize,
) -> Result<Vec<(u64, u32)>, DemuxError> {
    let (data, _) = r.table(stts, 8, samples)?;
    let mut result = Vec::with_capacity(samples);
    let mut time = 0_u64;
    for row in data.as_chunks::<8>().0 {
        let count = be32(row, 0)? as usize;
        let duration = be32(row, 4)?;
        if count == 0 || duration == 0 || count > samples - result.len() {
            return Err(DemuxError::Timeline);
        }
        for _ in 0..count {
            result.push((time, duration));
            time = time
                .checked_add(u64::from(duration))
                .ok_or(DemuxError::Timeline)?;
        }
    }
    if result.len() != samples {
        return Err(DemuxError::Timeline);
    }
    Ok(result)
}
pub(super) fn composition(
    r: &mut Reader<'_, '_>,
    ctts: Option<BoxRef>,
    samples: usize,
) -> Result<Vec<i64>, DemuxError> {
    let Some(ctts) = ctts else {
        return Ok(vec![0; samples]);
    };
    let b = r.body(&ctts);
    let version = *b.first().ok_or(DemuxError::Truncated)?;
    if version > 1 {
        return Err(DemuxError::Unsupported);
    }
    full(b, version, 0)?;
    let count = be32(b, 4)? as usize;
    if count > samples {
        return Err(DemuxError::Limit);
    }
    exact_table(b, 8, count, 8)?;
    r.entries(count)?;
    let mut result = Vec::with_capacity(samples);
    for row in b[8..].as_chunks::<8>().0 {
        let count = be32(row, 0)? as usize;
        if count == 0 || count > samples - result.len() {
            return Err(DemuxError::Timeline);
        }
        let value = be32(row, 4)?;
        let offset = if version == 1 {
            i64::from(value as i32)
        } else {
            i64::from(value)
        };
        result.resize(result.len() + count, offset);
    }
    if result.len() != samples {
        return Err(DemuxError::Timeline);
    }
    Ok(result)
}
pub(super) fn sync_samples(
    r: &mut Reader<'_, '_>,
    stss: Option<BoxRef>,
    samples: usize,
) -> Result<Vec<bool>, DemuxError> {
    let Some(stss) = stss else {
        return Ok(vec![true; samples]);
    };
    let (data, _) = r.table(&stss, 4, samples)?;
    let mut result = vec![false; samples];
    let mut previous = 0;
    for row in data.as_chunks::<4>().0 {
        let index = be32(row, 0)? as usize;
        if index <= previous || index > samples {
            return Err(DemuxError::Layout);
        }
        result[index - 1] = true;
        previous = index;
    }
    Ok(result)
}
pub(super) fn nal_kind(b: &[u8]) -> Result<u8, DemuxError> {
    let header = *b.first().ok_or(DemuxError::Nal)?;
    let kind = header & 31;
    if header & 0x80 != 0 || !matches!(kind, 1 | 5..=13) {
        return Err(DemuxError::Nal);
    }
    Ok(kind)
}
pub(super) fn nals(
    bytes: &[u8],
    range: Range<usize>,
    length: usize,
    visit: &mut impl FnMut(Range<usize>) -> Result<(), DemuxError>,
) -> Result<(), DemuxError> {
    let mut at = range.start;
    if range.is_empty() {
        return Err(DemuxError::Nal);
    }
    while at < range.end {
        let header_end = at
            .checked_add(length)
            .filter(|end| *end <= range.end)
            .ok_or(DemuxError::Nal)?;
        let size = bytes
            .get(at..header_end)
            .ok_or(DemuxError::Nal)?
            .iter()
            .fold(0_usize, |n, b| (n << 8) | usize::from(*b));
        let end = header_end
            .checked_add(size)
            .filter(|end| *end <= range.end)
            .ok_or(DemuxError::Nal)?;
        if size == 0 {
            return Err(DemuxError::Nal);
        }
        visit(header_end..end)?;
        at = end;
    }
    Ok(())
}

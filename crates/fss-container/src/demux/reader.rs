#![forbid(unsafe_code)]
//! Bounds-checked ISO BMFF box traversal. No allocation depends on an unchecked count.
use super::{DemuxError, DemuxLimits};
use std::ops::Range;

#[derive(Clone, Debug)]
pub(super) struct BoxRef {
    pub kind: [u8; 4],
    /// First byte of the box header.
    pub start: usize,
    pub body: Range<usize>,
}

pub(super) struct Reader<'a, 'c> {
    pub bytes: &'a [u8],
    pub limits: DemuxLimits,
    pub boxes: usize,
    pub entries: usize,
    pub nals: usize,
    check: &'c mut dyn FnMut() -> Result<(), DemuxError>,
}
impl<'a, 'c> Reader<'a, 'c> {
    pub fn new(
        bytes: &'a [u8],
        limits: DemuxLimits,
        check: &'c mut dyn FnMut() -> Result<(), DemuxError>,
    ) -> Self {
        Self {
            bytes,
            limits,
            boxes: 0,
            entries: 0,
            nals: 0,
            check,
        }
    }
    pub fn checkpoint(&mut self) -> Result<(), DemuxError> {
        (self.check)()
    }
    pub fn entries(&mut self, n: usize) -> Result<(), DemuxError> {
        self.entries = self
            .entries
            .checked_add(n)
            .filter(|n| *n <= self.limits.maximum_table_entries)
            .ok_or(DemuxError::Limit)?;
        self.checkpoint()
    }
    pub fn children(&mut self, range: Range<usize>, top: bool) -> Result<Vec<BoxRef>, DemuxError> {
        if range.start > range.end || range.end > self.bytes.len() {
            return Err(DemuxError::Layout);
        }
        let mut result = Vec::new();
        let mut start = range.start;
        while start < range.end {
            self.checkpoint()?;
            self.boxes = self
                .boxes
                .checked_add(1)
                .filter(|n| *n <= self.limits.maximum_boxes)
                .ok_or(DemuxError::Limit)?;
            let header = self.bytes.get(start..range.end).ok_or(DemuxError::Layout)?;
            let size = be32(header, 0)?;
            let kind: [u8; 4] = header
                .get(4..8)
                .ok_or(DemuxError::Truncated)?
                .try_into()
                .map_err(|_| DemuxError::Truncated)?;
            let (length, header_len) = match size {
                0 if top => (range.end - start, 8),
                0 => return Err(DemuxError::Layout),
                1 => (
                    usize::try_from(be64(header, 8)?).map_err(|_| DemuxError::Limit)?,
                    16,
                ),
                n => (n as usize, 8),
            };
            if length < header_len {
                return Err(DemuxError::Layout);
            }
            let end = start
                .checked_add(length)
                .filter(|end| *end <= range.end)
                .ok_or(DemuxError::Truncated)?;
            result.push(BoxRef {
                kind,
                start,
                body: start + header_len..end,
            });
            start = end;
        }
        Ok(result)
    }
    pub fn body(&self, b: &BoxRef) -> &'a [u8] {
        &self.bytes[b.body.clone()]
    }
    pub fn table<'b>(
        &mut self,
        b: &'b BoxRef,
        width: usize,
        max: usize,
    ) -> Result<(&'a [u8], usize), DemuxError> {
        let data = self.body(b);
        full(data, 0, 0)?;
        let count = be32(data, 4)? as usize;
        if count > max {
            return Err(DemuxError::Limit);
        }
        exact_table(data, 8, count, width)?;
        self.entries(count)?;
        Ok((&data[8..], count))
    }
}
pub(super) fn one(boxes: &[BoxRef], kind: &[u8; 4]) -> Result<BoxRef, DemuxError> {
    optional(boxes, kind)?.ok_or(DemuxError::MissingBox(*kind))
}
pub(super) fn optional(boxes: &[BoxRef], kind: &[u8; 4]) -> Result<Option<BoxRef>, DemuxError> {
    let mut found = boxes.iter().filter(|b| &b.kind == kind);
    let value = found.next().cloned();
    if found.next().is_some() {
        return Err(DemuxError::DuplicateBox(*kind));
    }
    Ok(value)
}
pub(super) fn be16(b: &[u8], at: usize) -> Result<u16, DemuxError> {
    let end = at.checked_add(2).ok_or(DemuxError::Limit)?;
    Ok(u16::from_be_bytes(
        b.get(at..end)
            .ok_or(DemuxError::Truncated)?
            .try_into()
            .map_err(|_| DemuxError::Truncated)?,
    ))
}
pub(super) fn be32(b: &[u8], at: usize) -> Result<u32, DemuxError> {
    let end = at.checked_add(4).ok_or(DemuxError::Limit)?;
    Ok(u32::from_be_bytes(
        b.get(at..end)
            .ok_or(DemuxError::Truncated)?
            .try_into()
            .map_err(|_| DemuxError::Truncated)?,
    ))
}
pub(super) fn be64(b: &[u8], at: usize) -> Result<u64, DemuxError> {
    let end = at.checked_add(8).ok_or(DemuxError::Limit)?;
    Ok(u64::from_be_bytes(
        b.get(at..end)
            .ok_or(DemuxError::Truncated)?
            .try_into()
            .map_err(|_| DemuxError::Truncated)?,
    ))
}
pub(super) fn full(b: &[u8], version: u8, flags: u32) -> Result<(), DemuxError> {
    if be32(b, 0)? != ((u32::from(version) << 24) | flags) {
        return Err(DemuxError::Unsupported);
    }
    Ok(())
}
pub(super) fn exact_table(
    b: &[u8],
    header: usize,
    count: usize,
    width: usize,
) -> Result<(), DemuxError> {
    let size = count
        .checked_mul(width)
        .and_then(|n| n.checked_add(header))
        .ok_or(DemuxError::Limit)?;
    if b.len() != size {
        return Err(DemuxError::Layout);
    }
    Ok(())
}

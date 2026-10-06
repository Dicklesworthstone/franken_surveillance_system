#![forbid(unsafe_code)]
//! Forward-only source assembly within the immutably borrowed deployment's snapshot.
//! Cache one verified chunk, not one copy per frame. Final event publication re-proves closure.

use super::*;

pub(super) struct ChunkCursor {
    chunk: Option<(usize, Vec<u8>)>,
    bytes_read: u64,
    maximum: u64,
    last_segment: Option<usize>,
}
impl ChunkCursor {
    pub(super) fn new(maximum: u64) -> Self {
        Self {
            chunk: None,
            bytes_read: 0,
            maximum,
            last_segment: None,
        }
    }
    pub(super) const fn bytes_read(&self) -> u64 {
        self.bytes_read
    }
    pub(super) fn segment(
        &mut self,
        deployment: &ReferenceDeployment,
        retained: &RetainedFileImport,
        index: usize,
        limits: RetainedReadLimits,
        cx: &ReplayCx,
    ) -> Result<Vec<u8>> {
        if self.last_segment.is_some_and(|previous| index <= previous) {
            return Err(WatchError::Conflict);
        }
        checkpoint(cx, "long_dwell:source")?;
        let manifest = retained.manifest();
        let span = manifest
            .segment_spans
            .get(index)
            .ok_or(RecordedDecodeError::Unavailable)?;
        if span.len > limits.max_segment_bytes || span.len > limits.max_source_bytes {
            return Err(WatchError::Limit);
        }
        let end = span.offset.checked_add(span.len).ok_or(WatchError::Limit)?;
        let first = span.offset / manifest.chunk_bytes;
        let last = (end - 1) / manifest.chunk_bytes;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(usize::try_from(span.len).map_err(|_| WatchError::Limit)?)
            .map_err(|_| WatchError::Limit)?;
        for position in first..=last {
            let chunk_index = usize::try_from(position).map_err(|_| WatchError::Limit)?;
            let chunk_start = position
                .checked_mul(manifest.chunk_bytes)
                .ok_or(WatchError::Limit)?;
            if self
                .chunk
                .as_ref()
                .is_none_or(|(cached, _)| *cached != chunk_index)
            {
                let digest = *manifest
                    .ordered_chunks
                    .get(chunk_index)
                    .ok_or(WatchError::Conflict)?;
                let expected_len = manifest
                    .input_bytes
                    .checked_sub(chunk_start)
                    .ok_or(WatchError::Conflict)?
                    .min(manifest.chunk_bytes);
                charge(&mut self.bytes_read, expected_len, self.maximum)?;
                checkpoint(cx, "long_dwell:chunk")?;
                let chunk = deployment.publisher().spool().read(digest)?;
                if chunk.len() as u64 != expected_len || ContentDigest::sha256(&chunk) != digest {
                    return Err(RecordedDecodeError::InvalidReceipt.into());
                }
                self.chunk = Some((chunk_index, chunk));
            }
            let (_, chunk) = self.chunk.as_ref().ok_or(WatchError::Conflict)?;
            let start = usize::try_from(span.offset.saturating_sub(chunk_start))
                .map_err(|_| WatchError::Limit)?;
            let stop = usize::try_from((end - chunk_start).min(chunk.len() as u64))
                .map_err(|_| WatchError::Limit)?;
            bytes.extend_from_slice(chunk.get(start..stop).ok_or(WatchError::Conflict)?);
        }
        if bytes.len() as u64 != span.len || ContentDigest::sha256(&bytes) != span.segment_sha256 {
            return Err(RecordedDecodeError::InvalidReceipt.into());
        }
        self.last_segment = Some(index);
        Ok(bytes)
    }
}

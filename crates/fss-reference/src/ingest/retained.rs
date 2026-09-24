#![forbid(unsafe_code)]
//! Restart-safe reads of ledgered file imports, independent of the original input path.
//!
//! Callers must authorize access to the deployment before entering this reference boundary.
//! A published root without final import authority is not a completed import. Custody of a
//! recorded file never certifies live coverage, capture-time precision, or absence.

use super::{
    ADP_FILE_GENERATION, ADP_FILE_ROW_ID, FILE_IMPORT_MANIFEST_SCHEMA, FileImportManifest,
    FileIngestError, FileOmissionSpan, SegmentSpan,
};
use crate::{ReferenceDeployment, ReplayCx};
use fss_core::{
    BatchId, CanonicalDecoder, CapsuleId, ContentDigest, ContractError, DigestAlgorithm,
    LedgerAnchor, Plane, Sha256Hasher,
};
use fss_publication::SlotName;
use std::collections::BTreeSet;

/// Hard v1 metadata size ceiling.
pub const MAX_RETAINED_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
/// Maximum entries in each retained manifest collection.
pub const MAX_RETAINED_ENTRIES: usize = 131_072;
/// Hard ceiling for a single chunk or returned segment allocation.
pub const MAX_RETAINED_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;
/// Checkpoint before reading authority or metadata.
pub const STAGE_RETAINED_OPEN: &str = "file_retained:open";
/// Checkpoint before each source chunk read.
pub const STAGE_RETAINED_CHUNK: &str = "file_retained:chunk";
/// Checkpoint before returning verified material.
pub const STAGE_RETAINED_COMPLETE: &str = "file_retained:complete";

/// Explicit ceilings for retained source reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedReadLimits {
    /// Maximum admitted source-file length.
    pub max_source_bytes: u64,
    /// Maximum size of one chunk, independent of the source length.
    pub max_chunk_bytes: u64,
    /// Maximum returned segment allocation.
    pub max_segment_bytes: u64,
}

impl Default for RetainedReadLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: 512 * 1024 * 1024,
            max_chunk_bytes: 16 * 1024 * 1024,
            max_segment_bytes: 16 * 1024 * 1024,
        }
    }
}

fn invalid(detail: &str) -> FileIngestError {
    FileIngestError::CorruptSegment {
        detail: format!("retained import: {detail}"),
    }
}

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<(), FileIngestError> {
    cx.checkpoint(stage)
        .map_err(|_| FileIngestError::CancellationRequested { stage })
}

fn count(d: &mut CanonicalDecoder<'_>, minimum_bytes: usize) -> Result<usize, FileIngestError> {
    let n = usize::try_from(d.u64()?).map_err(|_| invalid("count overflow"))?;
    if n > MAX_RETAINED_ENTRIES || n > d.remaining() / minimum_bytes {
        return Err(invalid("collection exceeds input or allocation bound"));
    }
    Ok(n)
}

fn digest(d: &mut CanonicalDecoder<'_>) -> Result<ContentDigest, FileIngestError> {
    let value = d.digest()?;
    if value.algorithm() != DigestAlgorithm::Sha256 {
        return Err(ContractError::UnsupportedDigestAlgorithm.into());
    }
    Ok(value)
}

impl FileImportManifest {
    /// Decodes exact v1 bytes after checking their authority-supplied digest.
    ///
    /// Counts are bounded before allocation. Unknown domains, trailing bytes, invalid ranges,
    /// and unresolved partitioned manifests fail closed. This is the inverse of the existing
    /// canonical writer, not a new serialization dialect.
    pub fn from_retained_bytes(
        bytes: &[u8],
        expected: ContentDigest,
        limits: RetainedReadLimits,
    ) -> Result<Self, FileIngestError> {
        if bytes.len() > MAX_RETAINED_MANIFEST_BYTES {
            return Err(invalid("manifest exceeds metadata ceiling"));
        }
        if ContentDigest::sha256(bytes) != expected {
            return Err(ContractError::DigestMismatch.into());
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != "fss.canonical.v1" || d.text()? != FILE_IMPORT_MANIFEST_SCHEMA {
            return Err(invalid("unsupported manifest domain"));
        }
        let input_sha256 = digest(&mut d)?;
        let input_bytes = d.u64()?;
        let format = d.text()?.to_owned();
        let detector_evidence = d.text()?.to_owned();
        let chunk_bytes = d.u64()?;
        let n = count(&mut d, 33)?;
        let mut ordered_chunks = Vec::with_capacity(n);
        for _ in 0..n {
            ordered_chunks.push(digest(&mut d)?);
        }
        let n = count(&mut d, 66)?;
        let mut segment_spans = Vec::with_capacity(n);
        for _ in 0..n {
            segment_spans.push(SegmentSpan {
                segment_index: usize::try_from(d.u64()?).map_err(|_| invalid("index overflow"))?,
                offset: d.u64()?,
                len: d.u64()?,
                segment_sha256: digest(&mut d)?,
                capsule_id: CapsuleId::parse(d.text()?)?,
                gap_before: d.bool()?,
            });
        }
        let n = count(&mut d, 24)?;
        let mut omission_spans = Vec::with_capacity(n);
        for _ in 0..n {
            omission_spans.push(FileOmissionSpan {
                offset: d.u64()?,
                len: d.u64()?,
                reason: d.text()?.to_owned(),
            });
        }
        let n = count(&mut d, 8)?;
        let mut capsule_ids = Vec::with_capacity(n);
        for _ in 0..n {
            capsule_ids.push(CapsuleId::parse(d.text()?)?);
        }
        let limits_digest = digest(&mut d)?;
        let adapter_id = d.text()?.to_owned();
        let adapter_generation = d.text()?.to_owned();
        let n = count(&mut d, 33)?;
        let mut part_roots = Vec::with_capacity(n);
        for _ in 0..n {
            part_roots.push(digest(&mut d)?);
        }
        let capture_time_label = d.text()?.to_owned();
        d.ensure_finished()?;
        let manifest = Self {
            input_sha256,
            input_bytes,
            format,
            detector_evidence,
            chunk_bytes,
            ordered_chunks,
            segment_spans,
            omission_spans,
            capsule_ids,
            limits_digest,
            adapter_id,
            adapter_generation,
            part_roots,
            capture_time_label,
        };
        manifest.validate_retained(limits)?;
        if manifest.canonical_bytes() != bytes || manifest.canonical_digest() != expected {
            return Err(ContractError::DigestMismatch.into());
        }
        Ok(manifest)
    }

    /// Checks structural invariants required for safe source assembly and range arithmetic.
    pub fn validate_retained(&self, limits: RetainedReadLimits) -> Result<(), FileIngestError> {
        if limits.max_source_bytes == 0
            || limits.max_chunk_bytes == 0
            || limits.max_segment_bytes == 0
            || limits.max_chunk_bytes > MAX_RETAINED_PAYLOAD_BYTES
            || limits.max_segment_bytes > MAX_RETAINED_PAYLOAD_BYTES
        {
            return Err(FileIngestError::InvalidLimits {
                detail: "retained read ceilings must be positive; chunk/segment ceiling is 64 MiB"
                    .to_owned(),
            });
        }
        if self.input_bytes == 0
            || self.input_bytes > limits.max_source_bytes
            || self.chunk_bytes == 0
            || self.chunk_bytes > limits.max_chunk_bytes
        {
            return Err(invalid("source or chunk length outside admitted bounds"));
        }
        if self.adapter_id != ADP_FILE_ROW_ID
            || self.adapter_generation != ADP_FILE_GENERATION
            || !matches!(self.format.as_str(), "annexb" | "hevc" | "mjpeg")
            || !matches!(
                self.capture_time_label.as_str(),
                "unknown" | "operator_assumption"
            )
            || self.detector_evidence.is_empty()
        {
            return Err(invalid(
                "unsupported adapter, format or time classification",
            ));
        }
        if !self.part_roots.is_empty() {
            return Err(invalid(
                "partitioned manifest needs explicit part resolution",
            ));
        }
        let expected_chunks = 1 + (self.input_bytes - 1) / self.chunk_bytes;
        if self.ordered_chunks.len() as u64 != expected_chunks
            || self.ordered_chunks.len() > MAX_RETAINED_ENTRIES
            || self.segment_spans.len() > MAX_RETAINED_ENTRIES
            || self.omission_spans.len() > MAX_RETAINED_ENTRIES
            || self.segment_spans.len() != self.capsule_ids.len()
        {
            return Err(invalid("inconsistent or excessive collections"));
        }
        if self.input_sha256.algorithm() != DigestAlgorithm::Sha256
            || self.limits_digest.algorithm() != DigestAlgorithm::Sha256
            || self
                .ordered_chunks
                .iter()
                .any(|d| d.algorithm() != DigestAlgorithm::Sha256)
        {
            return Err(ContractError::UnsupportedDigestAlgorithm.into());
        }
        let mut previous_end = 0;
        let mut ids = BTreeSet::new();
        for (index, segment) in self.segment_spans.iter().enumerate() {
            let end = segment
                .offset
                .checked_add(segment.len)
                .ok_or_else(|| invalid("segment range overflow"))?;
            if segment.segment_index != index
                || segment.len == 0
                || end > self.input_bytes
                || segment.offset < previous_end
                || (segment.offset > previous_end && !segment.gap_before)
                || segment.capsule_id != self.capsule_ids[index]
                || !ids.insert(segment.capsule_id.clone())
                || segment.segment_sha256.algorithm() != DigestAlgorithm::Sha256
            {
                return Err(invalid(
                    "inconsistent segment order, range, gap or capsule binding",
                ));
            }
            previous_end = end;
        }
        for omission in &self.omission_spans {
            if omission.len == 0
                || omission.reason.is_empty()
                || omission
                    .offset
                    .checked_add(omission.len)
                    .is_none_or(|end| end > self.input_bytes)
            {
                return Err(invalid("invalid omission span"));
            }
        }
        Ok(())
    }
}

/// Recovered metadata tied to a completed authority batch and current published root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedFileImport {
    import_identity: ContentDigest,
    import_root: ContentDigest,
    manifest_digest: ContentDigest,
    authority_anchor: LedgerAnchor,
    manifest: FileImportManifest,
}

impl RetainedFileImport {
    /// Recovers a completed import without reading or requiring the original source file.
    pub fn open(
        deployment: &ReferenceDeployment,
        import_identity: ContentDigest,
        limits: RetainedReadLimits,
        cx: &ReplayCx,
    ) -> Result<Self, FileIngestError> {
        checkpoint(cx, STAGE_RETAINED_OPEN)?;
        if import_identity.algorithm() != DigestAlgorithm::Sha256 {
            return Err(ContractError::UnsupportedDigestAlgorithm.into());
        }
        let hex: String = import_identity
            .bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let batch_id = BatchId::parse(format!("batch:file-import:{hex}:manifest"))?;
        let slot =
            SlotName::parse(&format!("fi-{hex}")).map_err(|_| ContractError::InvalidIdentifier)?;
        let batch = deployment
            .ledger()
            .batches()
            .iter()
            .find(|b| b.batch_id == batch_id)
            .ok_or_else(|| invalid("completed import authority is absent"))?;
        let object_id = format!("object:file-import-manifest:{hex}");
        let delta = batch
            .deltas
            .iter()
            .find(|d| {
                d.family == "file_import_manifest"
                    && d.object_id.as_str() == object_id
                    && d.plane == Plane::Authority
                    && d.prior_generation.is_none()
                    && d.new_generation == 1
            })
            .ok_or_else(|| invalid("manifest authority binding is absent"))?;
        let import_root = delta
            .witness_digest
            .ok_or_else(|| invalid("root witness is absent"))?;
        let manifest_digest = delta.payload_digest;
        let import_object = format!("object:file-import:{hex}");
        if !batch.children.contains(&manifest_digest)
            || !batch.children.contains(&import_root)
            || !batch.deltas.iter().any(|d| {
                d.family == "file_import"
                    && d.object_id.as_str() == import_object
                    && d.plane == Plane::Authority
                    && d.prior_generation == Some(1)
                    && d.new_generation == 2
                    && d.payload_digest == manifest_digest
                    && d.witness_digest == Some(import_root)
            })
        {
            return Err(invalid("completion and manifest authority disagree"));
        }
        let visible = deployment
            .publisher()
            .root(&slot)
            .ok_or_else(|| invalid("import root is unavailable"))?;
        if visible.root != import_root {
            return Err(ContractError::DigestMismatch.into());
        }
        let bytes = deployment.publisher().spool().read(manifest_digest)?;
        let manifest = FileImportManifest::from_retained_bytes(&bytes, manifest_digest, limits)?;
        checkpoint(cx, STAGE_RETAINED_COMPLETE)?;
        Ok(Self {
            import_identity,
            import_root,
            manifest_digest,
            authority_anchor: batch.new_anchor.clone(),
            manifest,
        })
    }

    /// Exact import identity.
    #[must_use]
    pub fn import_identity(&self) -> ContentDigest {
        self.import_identity
    }
    /// Published root witnessed by completion authority.
    #[must_use]
    pub fn import_root(&self) -> ContentDigest {
        self.import_root
    }
    /// Retained canonical manifest digest.
    #[must_use]
    pub fn manifest_digest(&self) -> ContentDigest {
        self.manifest_digest
    }
    /// Import completion anchor, rather than an unrelated later commit.
    #[must_use]
    pub fn authority_anchor(&self) -> &LedgerAnchor {
        &self.authority_anchor
    }
    /// Retained metadata, including omissions and capture-time uncertainty.
    #[must_use]
    pub fn manifest(&self) -> &FileImportManifest {
        &self.manifest
    }

    fn revalidate(
        &self,
        deployment: &ReferenceDeployment,
        limits: RetainedReadLimits,
        cx: &ReplayCx,
    ) -> Result<(), FileIngestError> {
        let current = Self::open(deployment, self.import_identity, limits, cx)?;
        if current != *self {
            return Err(ContractError::DigestMismatch.into());
        }
        Ok(())
    }

    /// Returns an exact bounded segment, verifying every touched chunk and the assembled bytes.
    /// Root availability and authority are rechecked on every call. No media decoding is implied.
    pub fn read_segment(
        &self,
        deployment: &ReferenceDeployment,
        index: usize,
        limits: RetainedReadLimits,
        cx: &ReplayCx,
    ) -> Result<Vec<u8>, FileIngestError> {
        self.revalidate(deployment, limits, cx)?;
        let bytes = assemble_segment(&self.manifest, index, limits, |d| {
            checkpoint(cx, STAGE_RETAINED_CHUNK)?;
            Ok(deployment.publisher().spool().read(d)?)
        })?;
        checkpoint(cx, STAGE_RETAINED_COMPLETE)?;
        Ok(bytes)
    }

    /// Verifies the entire source in recorded order with at most one chunk in memory.
    /// Repeated chunks are retained in the stream. Success proves byte custody, not coverage.
    pub fn verify_source(
        &self,
        deployment: &ReferenceDeployment,
        limits: RetainedReadLimits,
        cx: &ReplayCx,
    ) -> Result<ContentDigest, FileIngestError> {
        self.revalidate(deployment, limits, cx)?;
        let result = verify_source_chunks(&self.manifest, |d| {
            checkpoint(cx, STAGE_RETAINED_CHUNK)?;
            Ok(deployment.publisher().spool().read(d)?)
        })?;
        checkpoint(cx, STAGE_RETAINED_COMPLETE)?;
        Ok(result)
    }
}

fn verified_chunk(
    manifest: &FileImportManifest,
    index: usize,
    read: &mut impl FnMut(ContentDigest) -> Result<Vec<u8>, FileIngestError>,
) -> Result<Vec<u8>, FileIngestError> {
    let expected = *manifest
        .ordered_chunks
        .get(index)
        .ok_or_else(|| invalid("chunk index"))?;
    let offset = (index as u64)
        .checked_mul(manifest.chunk_bytes)
        .ok_or_else(|| invalid("chunk offset overflow"))?;
    let remaining = manifest
        .input_bytes
        .checked_sub(offset)
        .ok_or_else(|| invalid("chunk range"))?;
    let bytes = read(expected)?;
    if bytes.len() as u64 != remaining.min(manifest.chunk_bytes)
        || ContentDigest::sha256(&bytes) != expected
    {
        return Err(invalid("chunk length or checksum mismatch"));
    }
    Ok(bytes)
}

fn assemble_segment(
    manifest: &FileImportManifest,
    index: usize,
    limits: RetainedReadLimits,
    mut read: impl FnMut(ContentDigest) -> Result<Vec<u8>, FileIngestError>,
) -> Result<Vec<u8>, FileIngestError> {
    manifest.validate_retained(limits)?;
    let span =
        manifest
            .segment_spans
            .get(index)
            .ok_or(FileIngestError::SegmentIndexOutOfBounds {
                index,
                count: manifest.segment_spans.len(),
            })?;
    if span.len > limits.max_segment_bytes {
        return Err(FileIngestError::SpoolCapacityExceeded {
            limit: "retained_segment_bytes",
            required: span.len,
            available: limits.max_segment_bytes,
        });
    }
    let size = usize::try_from(span.len).map_err(|_| invalid("segment allocation overflow"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| invalid("segment allocation refused"))?;
    let end = span
        .offset
        .checked_add(span.len)
        .ok_or_else(|| invalid("range overflow"))?;
    let first = span.offset / manifest.chunk_bytes;
    let last = (end - 1) / manifest.chunk_bytes;
    for position in first..=last {
        let chunk_index = usize::try_from(position).map_err(|_| invalid("chunk index overflow"))?;
        let chunk = verified_chunk(manifest, chunk_index, &mut read)?;
        let chunk_start = position
            .checked_mul(manifest.chunk_bytes)
            .ok_or_else(|| invalid("offset overflow"))?;
        let start = usize::try_from(span.offset.saturating_sub(chunk_start))
            .map_err(|_| invalid("slice offset"))?;
        let stop = usize::try_from((end - chunk_start).min(chunk.len() as u64))
            .map_err(|_| invalid("slice end"))?;
        let slice = chunk
            .get(start..stop)
            .ok_or_else(|| invalid("source slice"))?;
        bytes.extend_from_slice(slice);
    }
    if bytes.len() != size || ContentDigest::sha256(&bytes) != span.segment_sha256 {
        return Err(invalid("assembled segment checksum or length mismatch"));
    }
    Ok(bytes)
}

fn verify_source_chunks(
    manifest: &FileImportManifest,
    mut read: impl FnMut(ContentDigest) -> Result<Vec<u8>, FileIngestError>,
) -> Result<ContentDigest, FileIngestError> {
    let mut hasher = Sha256Hasher::new();
    for index in 0..manifest.ordered_chunks.len() {
        hasher.update(&verified_chunk(manifest, index, &mut read)?);
    }
    let actual = ContentDigest::new(DigestAlgorithm::Sha256, hasher.finalize()?);
    if actual != manifest.input_sha256 {
        return Err(ContractError::DigestMismatch.into());
    }
    Ok(actual)
}

#[cfg(test)]
mod tests;

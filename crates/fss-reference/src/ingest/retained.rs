#![forbid(unsafe_code)]
//! Restart-safe reads of ledgered file imports, independent of the original input path.
//!
//! Callers must authorize access to the deployment before entering this reference boundary.
//! A published root without final import authority is not a completed import. Custody of a
//! recorded file never certifies live coverage, capture-time precision, or absence.

mod root_binding;

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
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

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
        let manifest = Self::decode_metadata(bytes, expected, limits)?;
        // Standalone metadata decoding has no publication resolver. Keep this API fail-closed
        // for typed parts; RetainedFileImport::open proves those roots before returning a handle.
        manifest.validate_retained(limits)?;
        Ok(manifest)
    }

    fn decode_metadata(
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
        if n > super::file_publication::MAX_FILE_PUBLICATION_PARTS {
            return Err(invalid("part count exceeds the reconstruction bound"));
        }
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
        manifest.validate_structure(limits)?;
        if manifest.canonical_bytes() != bytes || manifest.canonical_digest() != expected {
            return Err(ContractError::DigestMismatch.into());
        }
        Ok(manifest)
    }

    /// Checks a standalone flat manifest; typed parts require RetainedFileImport::open.
    pub fn validate_retained(&self, limits: RetainedReadLimits) -> Result<(), FileIngestError> {
        self.validate_structure(limits)?;
        if !self.part_roots.is_empty() {
            return Err(invalid(
                "partitioned manifest needs explicit part resolution",
            ));
        }
        Ok(())
    }

    /// Structural checks only. Never substitutes for root, part and completion authority.
    fn validate_structure(&self, limits: RetainedReadLimits) -> Result<(), FileIngestError> {
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
        // Per-adapter admission: the file row accepts every registered file
        // format; the Wyze live-lab row accepts the live annexb bitstreams
        // its tuple was qualified against. Unknown tuples fail closed.
        let admitted = if self.adapter_id == ADP_FILE_ROW_ID {
            self.adapter_generation == ADP_FILE_GENERATION
                && matches!(
                    self.format.as_str(),
                    "annexb" | "hevc" | "mjpeg" | "mp4avc" | "mp4hevc" | "mkvavc" | "mkvhevc"
                )
        } else if self.adapter_id == "ADP-WYZE-V4-LAB-001" {
            matches!(self.format.as_str(), "annexb" | "hevc")
        } else {
            false
        };
        if !admitted
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
        if self.part_roots.len() > super::file_publication::MAX_FILE_PUBLICATION_PARTS {
            return Err(invalid("part count exceeds the reconstruction bound"));
        }
        let mut parts = BTreeSet::new();
        for part in &self.part_roots {
            if part.algorithm() != DigestAlgorithm::Sha256 || !parts.insert(*part) {
                return Err(invalid(
                    "part roots are duplicated or use an unsupported digest",
                ));
            }
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
        // MP4 and Matroska samples are separated by container structure, never by lost media;
        // each family's structure carries its own reason prefix.
        let structure_prefix = match self.format.as_str() {
            "mp4avc" | "mp4hevc" => Some(super::MP4_STRUCTURE_REASON_PREFIX),
            "mkvavc" | "mkvhevc" => Some(super::MKV_STRUCTURE_REASON_PREFIX),
            _ => None,
        };
        let container = structure_prefix.is_some();
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
                || (segment.offset > previous_end && !segment.gap_before && !container)
                || (container && segment.gap_before)
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
            // A container import's only lost bytes are one unread tail ending the file.
            let truncated_tail = container
                && omission.reason == super::CONTAINER_TRUNCATED_TAIL_REASON
                && omission.offset + omission.len == self.input_bytes;
            if (omission.is_container_structure() != container && !truncated_tail)
                || structure_prefix
                    .is_some_and(|prefix| !truncated_tail && !omission.reason.starts_with(prefix))
            {
                return Err(invalid(
                    "container structure span outside its MP4 or Matroska import",
                ));
            }
        }
        if container {
            self.validate_container_tiling()?;
        }
        Ok(())
    }

    /// An MP4 or Matroska import accounts for every source byte exactly once: samples plus typed
    /// structure.
    fn validate_container_tiling(&self) -> Result<(), FileIngestError> {
        let mut ranges: Vec<(u64, u64)> = self
            .segment_spans
            .iter()
            .map(|span| (span.offset, span.len))
            .chain(
                self.omission_spans
                    .iter()
                    .map(|span| (span.offset, span.len)),
            )
            .collect();
        ranges.sort_unstable();
        let mut cursor = 0_u64;
        for (offset, len) in ranges {
            if offset != cursor {
                return Err(invalid("MP4 import does not account for every source byte"));
            }
            cursor = offset
                .checked_add(len)
                .ok_or_else(|| invalid("span range overflow"))?;
        }
        if cursor != self.input_bytes {
            return Err(invalid("MP4 import does not account for every source byte"));
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
        refuse_deleted(deployment, import_identity)?;
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
        let manifest = FileImportManifest::decode_metadata(&bytes, manifest_digest, limits)?;
        root_binding::verify(
            deployment,
            &slot,
            import_root,
            manifest_digest,
            batch,
            &manifest,
            cx,
        )?;
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
        self.read_segment_cached(
            deployment,
            index,
            limits,
            cx,
            &mut VerifiedChunkCache::default(),
        )
    }

    /// [`Self::read_segment`] for sequential readers: a chunk already digest-verified into
    /// `chunks` is reused instead of being read and hashed again for every segment it holds.
    /// The assembled segment is still checked against its own digest, and root availability and
    /// authority are still rechecked on every call.
    pub fn read_segment_cached(
        &self,
        deployment: &ReferenceDeployment,
        index: usize,
        limits: RetainedReadLimits,
        cx: &ReplayCx,
        chunks: &mut VerifiedChunkCache,
    ) -> Result<Vec<u8>, FileIngestError> {
        self.revalidate(deployment, limits, cx)?;
        let bytes = assemble_segment(&self.manifest, index, limits, chunks, |d| {
            checkpoint(cx, STAGE_RETAINED_CHUNK)?;
            Ok(deployment.publisher().spool().read(d)?)
        })?;
        checkpoint(cx, STAGE_RETAINED_COMPLETE)?;
        Ok(bytes)
    }

    /// Returns the exact bytes of one declared omission or structure span (for an MP4 import,
    /// an `avcC` parameter set), verifying every touched chunk. Root availability and authority
    /// are rechecked on every call.
    pub fn read_omission_span(
        &self,
        deployment: &ReferenceDeployment,
        index: usize,
        limits: RetainedReadLimits,
        cx: &ReplayCx,
    ) -> Result<Vec<u8>, FileIngestError> {
        self.read_omission_span_budgeted(deployment, index, limits, cx, None)
    }

    /// Internal source-read admission shared with a streaming decoder's recovery attempts.
    pub(crate) fn read_omission_span_budgeted(
        &self,
        deployment: &ReferenceDeployment,
        index: usize,
        limits: RetainedReadLimits,
        cx: &ReplayCx,
        budget: Option<&SourceReadBudget>,
    ) -> Result<Vec<u8>, FileIngestError> {
        self.revalidate(deployment, limits, cx)?;
        self.manifest.validate_structure(limits)?;
        let span = self
            .manifest
            .omission_spans
            .get(index)
            .ok_or_else(|| invalid("omission span index"))?;
        let mut chunks = VerifiedChunkCache::with_source_budget(budget);
        let bytes = assemble_range(
            &self.manifest,
            span.offset,
            span.len,
            limits,
            &mut chunks,
            |d| {
                checkpoint(cx, STAGE_RETAINED_CHUNK)?;
                Ok(deployment.publisher().spool().read(d)?)
            },
        )?;
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

/// Refuses an import a committed deletion record names, with the typed `deleted` state
/// ([`FileIngestError::EvidenceDeleted`]) rather than an ambiguous missing-authority error.
///
/// The record is authoritative from the moment it is durable, even while an interrupted deletion
/// has not unlinked every byte yet: deleted content is never served.
pub(crate) fn refuse_deleted(
    deployment: &ReferenceDeployment,
    import_identity: ContentDigest,
) -> Result<(), FileIngestError> {
    if !crate::deletion::has_records(deployment.ledger().batches()) {
        return Ok(());
    }
    let index = crate::deletion::DeletionIndex::read(deployment)
        .map_err(|error| invalid(&format!("deletion record unreadable: {error}")))?;
    match index.import(import_identity) {
        Some(entry) => Err(FileIngestError::EvidenceDeleted {
            import_identity,
            plan_digest: entry.plan_digest,
        }),
        None => Ok(()),
    }
}

/// Expected digest and exact length of custody chunk `index`.
fn chunk_identity(
    manifest: &FileImportManifest,
    index: usize,
) -> Result<(ContentDigest, u64), FileIngestError> {
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
    Ok((expected, remaining.min(manifest.chunk_bytes)))
}

fn verified_chunk(
    manifest: &FileImportManifest,
    index: usize,
    read: &mut impl FnMut(ContentDigest) -> Result<Vec<u8>, FileIngestError>,
) -> Result<Vec<u8>, FileIngestError> {
    let (expected, len) = chunk_identity(manifest, index)?;
    let bytes = read(expected)?;
    if bytes.len() as u64 != len || ContentDigest::sha256(&bytes) != expected {
        return Err(invalid("chunk length or checksum mismatch"));
    }
    Ok(bytes)
}

/// One source-read allowance shared by all decoder ranges and random-access recovery probes.
/// Reservations happen before reads and are never refunded, including for invalid codec input.
/// Cloning preserves the same allowance; it cannot reset accounting on a decoder restart.
#[derive(Clone, Debug)]
pub(crate) struct SourceReadBudget {
    maximum: u64,
    used: Arc<AtomicU64>,
}

impl SourceReadBudget {
    pub(crate) fn new(maximum: u64) -> Self {
        Self {
            maximum,
            used: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(crate) fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    fn reserve(&self, bytes: u64) -> Result<(), FileIngestError> {
        self.used
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.maximum)
            })
            .map(|_| ())
            .map_err(|used| FileIngestError::SpoolCapacityExceeded {
                limit: "stream_source_chunk_bytes",
                required: used.saturating_add(bytes),
                available: self.maximum,
            })
    }
}

/// Custody chunks already read and digest-verified, kept across sequential reads.
///
/// Holds at most two chunks (a segment may straddle one boundary), each keyed by its verified
/// SHA-256 digest and exact length: a chunk is served again only to a manifest naming that same
/// digest and length at the requested position, so a cache can never substitute other bytes.
/// Memory is bounded by twice the import's chunk size.
#[derive(Debug, Default)]
pub struct VerifiedChunkCache {
    slots: [Option<(ContentDigest, Vec<u8>)>; 2],
    loaded: u64,
    source_budget: Option<SourceReadBudget>,
}

impl VerifiedChunkCache {
    pub(crate) fn with_source_budget(source_budget: Option<&SourceReadBudget>) -> Self {
        Self {
            source_budget: source_budget.cloned(),
            ..Self::default()
        }
    }

    /// Charge additional origin-proof reads to the same optional whole-scan allowance.
    pub(crate) fn reserve_source_bytes(&self, bytes: u64) -> Result<(), FileIngestError> {
        match &self.source_budget {
            Some(budget) => budget.reserve(bytes),
            None => Ok(()),
        }
    }

    /// Bytes of every chunk this cache has read and verified (each load counted).
    #[must_use]
    pub const fn chunk_bytes_read(&self) -> u64 {
        self.loaded
    }

    fn chunk(
        &mut self,
        manifest: &FileImportManifest,
        index: usize,
        read: &mut impl FnMut(ContentDigest) -> Result<Vec<u8>, FileIngestError>,
    ) -> Result<&[u8], FileIngestError> {
        let (expected, len) = chunk_identity(manifest, index)?;
        let hit = |slot: &Option<(ContentDigest, Vec<u8>)>| {
            slot.as_ref()
                .is_some_and(|(digest, bytes)| *digest == expected && bytes.len() as u64 == len)
        };
        if hit(&self.slots[1]) {
            self.slots.swap(0, 1);
        } else if !hit(&self.slots[0]) {
            self.reserve_source_bytes(len)?;
            let bytes = verified_chunk(manifest, index, read)?;
            self.loaded = self.loaded.saturating_add(bytes.len() as u64);
            self.slots[1] = self.slots[0].take();
            self.slots[0] = Some((expected, bytes));
        }
        match &self.slots[0] {
            Some((_, bytes)) => Ok(bytes),
            None => Err(invalid("chunk cache")),
        }
    }
}

fn assemble_segment(
    manifest: &FileImportManifest,
    index: usize,
    limits: RetainedReadLimits,
    chunks: &mut VerifiedChunkCache,
    read: impl FnMut(ContentDigest) -> Result<Vec<u8>, FileIngestError>,
) -> Result<Vec<u8>, FileIngestError> {
    manifest.validate_structure(limits)?;
    let span =
        manifest
            .segment_spans
            .get(index)
            .ok_or(FileIngestError::SegmentIndexOutOfBounds {
                index,
                count: manifest.segment_spans.len(),
            })?;
    let bytes = assemble_range(manifest, span.offset, span.len, limits, chunks, read)?;
    if ContentDigest::sha256(&bytes) != span.segment_sha256 {
        return Err(invalid("assembled segment checksum or length mismatch"));
    }
    Ok(bytes)
}

/// Exact bytes `offset..offset + len` of the source, from digest-verified chunks.
fn assemble_range(
    manifest: &FileImportManifest,
    offset: u64,
    len: u64,
    limits: RetainedReadLimits,
    chunks: &mut VerifiedChunkCache,
    mut read: impl FnMut(ContentDigest) -> Result<Vec<u8>, FileIngestError>,
) -> Result<Vec<u8>, FileIngestError> {
    if len > limits.max_segment_bytes {
        return Err(FileIngestError::SpoolCapacityExceeded {
            limit: "retained_segment_bytes",
            required: len,
            available: limits.max_segment_bytes,
        });
    }
    let size = usize::try_from(len).map_err(|_| invalid("segment allocation overflow"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| invalid("segment allocation refused"))?;
    let end = offset
        .checked_add(len)
        .filter(|end| len > 0 && *end <= manifest.input_bytes)
        .ok_or_else(|| invalid("range overflow"))?;
    let first = offset / manifest.chunk_bytes;
    let last = (end - 1) / manifest.chunk_bytes;
    for position in first..=last {
        let chunk_index = usize::try_from(position).map_err(|_| invalid("chunk index overflow"))?;
        let chunk = chunks.chunk(manifest, chunk_index, &mut read)?;
        let chunk_start = position
            .checked_mul(manifest.chunk_bytes)
            .ok_or_else(|| invalid("offset overflow"))?;
        let start = usize::try_from(offset.saturating_sub(chunk_start))
            .map_err(|_| invalid("slice offset"))?;
        let stop = usize::try_from((end - chunk_start).min(chunk.len() as u64))
            .map_err(|_| invalid("slice end"))?;
        let slice = chunk
            .get(start..stop)
            .ok_or_else(|| invalid("source slice"))?;
        bytes.extend_from_slice(slice);
    }
    if bytes.len() != size {
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

#![forbid(unsafe_code)]
//! Matroska presentation queries over authenticated retained originals, independent of paths.

use super::{
    ADP_FILE_GENERATION, ADP_FILE_ROW_ID, FileImportManifest, FileIngestError, RetainedFileImport,
    RetainedReadLimits, checkpoint, invalid, verified_chunk,
};
use crate::{ReplayCx, RetainedSource};
use fss_container::demux::{
    DemuxError, MAX_MP4_INPUT_BYTES, MatroskaSelection, MatroskaSelectionLimits, MatroskaVideo,
    VideoCodec,
};
use fss_core::{ContentDigest, ContractError, DigestAlgorithm, LedgerAnchor, Sha256Hasher};
use std::ops::Range;

const STAGE_SOURCE: &str = "file_retained:matroska_source";
const STAGE_PARSE: &str = "file_retained:matroska_parse";
const STAGE_INDEX: &str = "file_retained:matroska_index";
const STAGE_SELECT: &str = "file_retained:matroska_select";
const STAGE_COMPLETE: &str = "file_retained:matroska_complete";
const HASH_CHECKPOINT_BYTES: usize = 64 * 1024;

/// Metadata-only Matroska selection tied to an exact completed file import.
///
/// Segment numbers are checked against the reparsed original's coding-order frame index.
/// The result contains no media bytes, creates no durable record and makes no capture-time,
/// live-coverage or physical-absence claim. Unknown presentation ends stay unknown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedMatroskaSelection {
    /// Exact completed import identity.
    pub import_identity: ContentDigest,
    /// Root revalidated before reading and before returning.
    pub import_root: ContentDigest,
    /// Canonical manifest authenticated by completion and root.
    pub manifest_digest: ContentDigest,
    /// Import completion anchor.
    pub authority_anchor: LedgerAnchor,
    /// Original source adapter identity.
    pub source_adapter_id: String,
    /// Original source adapter generation.
    pub source_adapter_generation: String,
    /// SHA-256 recomputed over the complete original.
    pub input_sha256: ContentDigest,
    /// Complete original length, including all unselected tracks and structure.
    pub input_bytes: u64,
    /// Original payload bytes read, exactly input_bytes; authority reads are additional.
    pub source_bytes_read: u64,
    /// Selected Matroska track number.
    pub track_number: u64,
    /// Codec reparsed and matched to the retained format.
    pub codec: VideoCodec,
    /// Unchanged import classification, unknown or operator_assumption.
    pub capture_time_label: String,
    /// Source-linked presentation intervals, uncertainty and coding prerequisites.
    pub selection: MatroskaSelection,
}

fn demux_refusal(refusal: DemuxError, stage: &'static str) -> FileIngestError {
    match refusal {
        DemuxError::Cancelled => FileIngestError::CancellationRequested { stage },
        refusal => FileIngestError::MatroskaRefused { refusal },
    }
}

impl RetainedFileImport {
    /// Select half-open Matroska Segment presentation nanoseconds from original ADP-FILE-001
    /// imports. The complete retained file is bounded before allocation, reconstructed from
    /// authenticated chunks, hashed, reparsed, and matched to every retained frame index/range/
    /// digest. Root/completion custody is revalidated before release.
    ///
    /// read_limits bounds the whole original; selection_limits independently bounds the
    /// requested coding spans including all preroll. A short interval never authorizes an
    /// unlimited full-file read. Immutable owners share the caller's cumulative read allowance.
    /// Recovered sources with an unread tail refuse temporal selection. No UTC origin or
    /// duration is invented, and an unclosed final presentation is explicitly unresolved.
    pub fn select_matroska_interval(
        &self,
        deployment: &dyn RetainedSource,
        query_ns: Range<u64>,
        read_limits: RetainedReadLimits,
        selection_limits: MatroskaSelectionLimits,
        cx: &ReplayCx,
    ) -> Result<RetainedMatroskaSelection, FileIngestError> {
        selection_limits
            .validate()
            .map_err(|error| demux_refusal(error, STAGE_SELECT))?;
        if query_ns.start >= query_ns.end {
            return Err(demux_refusal(DemuxError::Timeline, STAGE_SELECT));
        }
        let maximum = source_admission(&self.manifest, read_limits)?;
        checkpoint(cx, STAGE_SOURCE)?;
        self.revalidate(deployment, read_limits, cx)?;
        let mut source = Vec::new();
        source
            .try_reserve_exact(maximum)
            .map_err(|_| demux_refusal(DemuxError::Limit, STAGE_SOURCE))?;
        let mut source_hash = Sha256Hasher::new();
        for index in 0..self.manifest.ordered_chunks.len() {
            let bytes = verified_chunk(&self.manifest, index, &mut |digest, length| {
                checkpoint(cx, STAGE_SOURCE)?;
                let length = usize::try_from(length)
                    .map_err(|_| invalid("Matroska source chunk length overflow"))?;
                deployment.read_object_bounded(digest, length)
            })?;
            if source
                .len()
                .checked_add(bytes.len())
                .is_none_or(|length| length > maximum)
            {
                return Err(invalid("Matroska source exceeds retained length"));
            }
            for part in bytes.chunks(HASH_CHECKPOINT_BYTES) {
                checkpoint(cx, STAGE_SOURCE)?;
                source_hash.update(part);
                source.extend_from_slice(part);
            }
        }
        let input_sha256 = ContentDigest::new(DigestAlgorithm::Sha256, source_hash.finalize()?);
        if source.len() != maximum || input_sha256 != self.manifest.input_sha256 {
            return Err(ContractError::DigestMismatch.into());
        }
        let mut check = || {
            cx.checkpoint(STAGE_PARSE)
                .map_err(|_| DemuxError::Cancelled)
        };
        let video = MatroskaVideo::parse_with_checkpoint(
            &source,
            None,
            super::super::file_adapter::mp4_demux_limits(self.manifest.segment_spans.len()),
            &mut check,
        )
        .map_err(|error| demux_refusal(error, STAGE_PARSE))?;
        verify_sample_index(&self.manifest, &source, &video, || {
            checkpoint(cx, STAGE_INDEX)
        })?;
        let mut check = || {
            cx.checkpoint(STAGE_SELECT)
                .map_err(|_| DemuxError::Cancelled)
        };
        let selection = video
            .select_presentation_interval_with_checkpoint(query_ns, selection_limits, &mut check)
            .map_err(|error| demux_refusal(error, STAGE_SELECT))?;
        self.revalidate(deployment, read_limits, cx)?;
        checkpoint(cx, STAGE_COMPLETE)?;
        Ok(RetainedMatroskaSelection {
            import_identity: self.import_identity,
            import_root: self.import_root,
            manifest_digest: self.manifest_digest,
            authority_anchor: self.authority_anchor.clone(),
            source_adapter_id: self.manifest.adapter_id.clone(),
            source_adapter_generation: self.manifest.adapter_generation.clone(),
            input_sha256,
            input_bytes: self.manifest.input_bytes,
            source_bytes_read: source.len() as u64,
            track_number: video.track_number(),
            codec: video.codec(),
            capture_time_label: self.manifest.capture_time_label.clone(),
            selection,
        })
    }
}

fn source_admission(
    manifest: &FileImportManifest,
    limits: RetainedReadLimits,
) -> Result<usize, FileIngestError> {
    if manifest.adapter_id != ADP_FILE_ROW_ID
        || manifest.adapter_generation != ADP_FILE_GENERATION
        || !matches!(manifest.format.as_str(), "mkvavc" | "mkvhevc")
    {
        return Err(demux_refusal(DemuxError::Unsupported, STAGE_SOURCE));
    }
    if manifest.input_bytes > MAX_MP4_INPUT_BYTES as u64 {
        return Err(demux_refusal(DemuxError::Limit, STAGE_SOURCE));
    }
    manifest.validate_structure(limits)?;
    usize::try_from(manifest.input_bytes)
        .map_err(|_| demux_refusal(DemuxError::Limit, STAGE_SOURCE))
}

fn verify_sample_index(
    manifest: &FileImportManifest,
    source: &[u8],
    video: &MatroskaVideo<'_>,
    mut check: impl FnMut() -> Result<(), FileIngestError>,
) -> Result<(), FileIngestError> {
    let format = match video.codec() {
        VideoCodec::Avc => "mkvavc",
        VideoCodec::Hevc => "mkvhevc",
    };
    if manifest.format != format || manifest.segment_spans.len() != video.samples().len() {
        return Err(invalid(
            "Matroska track or count differs from retained segments",
        ));
    }
    for (index, (sample, segment)) in video
        .samples()
        .iter()
        .zip(&manifest.segment_spans)
        .enumerate()
    {
        check()?;
        if sample.index != index
            || segment.segment_index != index
            || sample.source.start as u64 != segment.offset
            || sample.source.len() as u64 != segment.len
            || segment.gap_before
        {
            return Err(invalid(
                "Matroska sample index or range differs from retained segment",
            ));
        }
        let bytes = source
            .get(sample.source.clone())
            .ok_or_else(|| invalid("Matroska frame outside retained original"))?;
        let mut hasher = Sha256Hasher::new();
        for part in bytes.chunks(HASH_CHECKPOINT_BYTES) {
            check()?;
            hasher.update(part);
        }
        let actual = ContentDigest::new(DigestAlgorithm::Sha256, hasher.finalize()?);
        if actual != segment.segment_sha256 {
            return Err(FileIngestError::SegmentDigestMismatch {
                segment_index: index,
                expected: segment.segment_sha256,
                actual,
            });
        }
    }
    if video.truncated_tail().is_some()
        || manifest
            .omission_spans
            .iter()
            .any(|span| span.reason == super::super::CONTAINER_TRUNCATED_TAIL_REASON)
    {
        return Err(invalid(
            "Matroska temporal selection requires a complete original",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;

#![forbid(unsafe_code)]
//! Movie-time queries over authenticated retained originals, independent of their former path.

use super::{
    ADP_FILE_GENERATION, ADP_FILE_ROW_ID, FileImportManifest, FileIngestError, RetainedFileImport,
    RetainedReadLimits, checkpoint, invalid, verified_chunk,
};
use crate::{ReferenceDeployment, ReplayCx};
use fss_container::demux::{
    AvcMp4, DemuxError, MAX_MP4_INPUT_BYTES, MovieSelection, MovieSelectionLimits, VideoCodec,
};
use fss_core::{ContentDigest, ContractError, DigestAlgorithm, LedgerAnchor, Sha256Hasher};
use std::ops::Range;

const STAGE_SOURCE: &str = "file_retained:movie_source";
const STAGE_PARSE: &str = "file_retained:movie_parse";
const STAGE_INDEX: &str = "file_retained:movie_index";
const STAGE_SELECT: &str = "file_retained:movie_select";
const STAGE_COMPLETE: &str = "file_retained:movie_complete";
const HASH_CHECKPOINT_BYTES: usize = 64 * 1024;

/// A movie-time selection tied to exact completed import custody.
///
/// Sample indices are original retained segment indices, checked against the reparsed source.
/// This is a read-only metadata result: it contains no source bytes or decoded pixels, creates
/// no durable record, and makes no capture-time, live-coverage, or scene-absence claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedMovieSelection {
    /// Exact completed import identity.
    pub import_identity: ContentDigest,
    /// Root revalidated before reading and before releasing this result.
    pub import_root: ContentDigest,
    /// Canonical manifest authenticated by the import completion and published root.
    pub manifest_digest: ContentDigest,
    /// Import completion anchor, not an unrelated later ledger anchor.
    pub authority_anchor: LedgerAnchor,
    /// SHA-256 of the complete original, recomputed from ordered verified custody chunks.
    pub input_sha256: ContentDigest,
    /// Complete original byte length, including unselected tracks, structure and unread tail.
    pub input_bytes: u64,
    /// Original source payload bytes read, including unselected media; exactly `input_bytes`.
    /// Metadata reads additionally consume any installed cumulative spool read allowance.
    pub source_bytes_read: u64,
    /// The unique selected video track of the authenticated original.
    pub track_id: u32,
    /// Codec reparsed from that track and checked against the retained format.
    pub codec: VideoCodec,
    /// Unchanged import classification (`unknown` or `operator_assumption`).
    pub capture_time_label: String,
    /// Exact half-open movie-tick mapping, source sample indices, gaps and decode prerequisites.
    pub selection: MovieSelection,
}

fn demux_refusal(refusal: DemuxError, stage: &'static str) -> FileIngestError {
    match refusal {
        DemuxError::Cancelled => FileIngestError::CancellationRequested { stage },
        refusal => FileIngestError::Mp4Refused { refusal },
    }
}

impl RetainedFileImport {
    /// Select a half-open interval in the original MP4/MOV movie timescale after custody checks.
    ///
    /// The complete original is read once, bounded by `read_limits.max_source_bytes` and the
    /// demuxer's absolute input ceiling **before** source allocation. The independent
    /// `selection_limits.max_source_bytes` bounds the quoted decode samples and their preroll;
    /// a small selection does not authorize an unbounded full-file read. Each chunk, the full
    /// original, every retained sample index/range/digest, and final root/completion authority
    /// are checked before any result is released. Cancellation or any refusal is atomic.
    ///
    /// Only original `ADP-FILE-001` MP4/MOV imports are supported. Reconstructed native RTSP
    /// origins and other formats return `Mp4Refused(Unsupported)`: an MP4 wrapper alone cannot
    /// establish their original-packet provenance. Indexed, fragmented, in-band-configuration,
    /// and recoverable-tail originals use the same parser admission as file ingestion.
    pub fn select_movie_interval(
        &self,
        deployment: &ReferenceDeployment,
        query: Range<u64>,
        read_limits: RetainedReadLimits,
        selection_limits: MovieSelectionLimits,
        cx: &ReplayCx,
    ) -> Result<RetainedMovieSelection, FileIngestError> {
        selection_limits
            .validate()
            .map_err(|error| demux_refusal(error, STAGE_SELECT))?;
        if query.start >= query.end {
            return Err(demux_refusal(DemuxError::Timeline, STAGE_SELECT));
        }
        let maximum = source_admission(&self.manifest, read_limits)?;
        checkpoint(cx, STAGE_SOURCE)?;
        self.revalidate(deployment, read_limits, cx)?;

        // A checked absolute ceiling applies even if the caller supplied an enormous retained
        // source limit. There is one full-source allocation, plus at most one bounded chunk.
        let mut source = Vec::new();
        source
            .try_reserve_exact(maximum)
            .map_err(|_| demux_refusal(DemuxError::Limit, STAGE_SOURCE))?;
        let mut source_hash = Sha256Hasher::new();
        for index in 0..self.manifest.ordered_chunks.len() {
            let bytes = verified_chunk(&self.manifest, index, &mut |digest, length| {
                checkpoint(cx, STAGE_SOURCE)?;
                let length = usize::try_from(length)
                    .map_err(|_| invalid("movie source chunk length overflow"))?;
                Ok(deployment
                    .publisher()
                    .spool()
                    .read_bounded(digest, length)?)
            })?;
            if source
                .len()
                .checked_add(bytes.len())
                .is_none_or(|n| n > maximum)
            {
                return Err(invalid("movie source exceeds its retained length"));
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
        let movie = AvcMp4::parse_inband_recovering_tail(
            &source,
            None,
            super::super::file_adapter::mp4_demux_limits(self.manifest.segment_spans.len()),
            &mut check,
        )
        .map_err(|error| demux_refusal(error, STAGE_PARSE))?;
        verify_sample_index(&self.manifest, &source, &movie, || {
            checkpoint(cx, STAGE_INDEX)
        })?;
        let mut check = || {
            cx.checkpoint(STAGE_SELECT)
                .map_err(|_| DemuxError::Cancelled)
        };
        let selection = movie
            .select_movie_interval_with_checkpoint(query, selection_limits, &mut check)
            .map_err(|error| demux_refusal(error, STAGE_SELECT))?;

        // Never release cached metadata after its witnessed custody becomes unavailable.
        // Reopening checks deletion, root/part closure and the exact completion binding again.
        self.revalidate(deployment, read_limits, cx)?;
        checkpoint(cx, STAGE_COMPLETE)?;
        Ok(RetainedMovieSelection {
            import_identity: self.import_identity,
            import_root: self.import_root,
            manifest_digest: self.manifest_digest,
            authority_anchor: self.authority_anchor.clone(),
            input_sha256,
            input_bytes: self.manifest.input_bytes,
            source_bytes_read: source.len() as u64,
            track_id: movie.track_id(),
            codec: movie.codec(),
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
        || !matches!(manifest.format.as_str(), "mp4avc" | "mp4hevc")
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

/// The import metadata is authenticated, but it is not a substitute for the sample tables.
/// Verify every coding index against the original before exposing any selected segment index.
fn verify_sample_index(
    manifest: &FileImportManifest,
    source: &[u8],
    movie: &AvcMp4<'_>,
    mut check: impl FnMut() -> Result<(), FileIngestError>,
) -> Result<(), FileIngestError> {
    let format = match movie.codec() {
        VideoCodec::Avc => "mp4avc",
        VideoCodec::Hevc => "mp4hevc",
    };
    if manifest.format != format || manifest.segment_spans.len() != movie.samples().len() {
        return Err(invalid(
            "movie track or sample count differs from retained segments",
        ));
    }
    for (index, (sample, segment)) in movie
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
                "movie sample index or range differs from retained segment",
            ));
        }
        let bytes = source
            .get(sample.source.clone())
            .ok_or_else(|| invalid("movie sample outside retained source"))?;
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
    let mut tails = manifest
        .omission_spans
        .iter()
        .filter(|span| span.reason == super::super::CONTAINER_TRUNCATED_TAIL_REASON);
    match (movie.truncated_tail(), tails.next(), tails.next()) {
        (None, None, None) => Ok(()),
        (Some(offset), Some(span), None)
            if span.offset == offset as u64
                && span.offset.checked_add(span.len) == Some(source.len() as u64) =>
        {
            Ok(())
        }
        _ => Err(invalid(
            "movie truncated tail differs from retained omission",
        )),
    }
}

#[cfg(test)]
mod tests;

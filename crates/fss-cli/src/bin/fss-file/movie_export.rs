#![forbid(unsafe_code)]
//! Authenticated movie selection -> complete native decode -> bounded private review output.

use super::super::{movie, value};
use super::movie_output::{
    DEFAULT_LUMA_BYTES, FrameInput, LINEAGE_DOMAIN, MAX_LUMA_BYTES, MAX_MOVIE_FRAMES, MovieOutput,
    MovieOutputError, SourceBinding,
};
use super::{
    ComponentInterpretation, DecodeLimits, DecoderLimits, EncodeBudget, ExportOptions,
    H265DecoderLimits, ParseResult, RecordedH264Range, RecordedH264Request, RecordedH265Range,
    RecordedH265Request, RecordedVideoDecodeBudget, RunResult, VIDEO_DECODE_WORK_MODEL, Values,
    encode_usage_lines, finish_video_export, jpeg_stream, malformed, number, parse_decode_limits,
    prepare_output_export, privacy_lines, source_selection_lines, text,
};
use fss_container::demux::{MovieDecodeSpan, VideoCodec};
use fss_core::{ContentDigest, SensorCapsule};
use fss_reference::ingest::retained::{RetainedMovieSelection, SourceReadBudget};
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use fss_reference::{ReferenceDeployment, ReplayCx};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;

const DEFAULT_DECODE_READ_BYTES: u64 = 512 * 1024 * 1024;
const MAX_DECODE_READ_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct Action {
    selection: movie::Action,
    read_limits: RetainedReadLimits,
    decode_limits: DecodeLimits,
    work_units: u64,
    maximum_decode_read_bytes: u64,
    maximum_luma_bytes: u64,
    export: ExportOptions,
}

impl Action {
    pub(super) fn identity(&self) -> ContentDigest {
        self.selection.identity()
    }
}

pub(super) fn accepts_option(option: &str) -> bool {
    movie::accepts_option("select-movie", option)
        || matches!(
            option,
            "--interpretation"
                | "--max-pixels"
                | "--max-dimension"
                | "--max-markers"
                | "--work-units"
                | "--output"
                | "--output-format"
                | "--output-rate"
                | "--max-output-bytes"
                | "--jpeg-quality"
                | "--encode-work-units"
                | "--max-cached-luma-bytes"
                | "--max-decode-read-bytes"
        )
}

pub(super) fn parse(
    identity: ContentDigest,
    read_limits: RetainedReadLimits,
    values: &Values,
) -> ParseResult<Action> {
    if text(values, "--interpretation")? != "ycbcr" {
        return Err(malformed("movie export requires --interpretation ycbcr"));
    }
    value(values, "--output")?;
    let maximum_luma_bytes = number(values, "--max-cached-luma-bytes", Some(DEFAULT_LUMA_BYTES))?;
    if maximum_luma_bytes == 0 || maximum_luma_bytes > MAX_LUMA_BYTES {
        return Err(malformed(
            "cached movie luma allowance must be 1..268435456 bytes",
        ));
    }
    let maximum_decode_read_bytes = number(
        values,
        "--max-decode-read-bytes",
        Some(DEFAULT_DECODE_READ_BYTES),
    )?;
    if maximum_decode_read_bytes == 0 || maximum_decode_read_bytes > MAX_DECODE_READ_BYTES {
        return Err(malformed(
            "movie decode read allowance must be 1..4294967296 bytes",
        ));
    }
    Ok(Action {
        selection: movie::parse_with_decode_limit(identity, values, MAX_MOVIE_FRAMES)?,
        read_limits,
        decode_limits: parse_decode_limits(read_limits, values)?,
        work_units: number(values, "--work-units", Some(100_000_000_u64))?,
        maximum_decode_read_bytes,
        maximum_luma_bytes,
        export: ExportOptions::parse(values)?,
    })
}

pub(super) fn run(
    action: &Action,
    retained: &RetainedFileImport,
    deployment: &ReferenceDeployment,
    root: &Path,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    let mut decode_budget = RecordedVideoDecodeBudget::new(action.work_units);
    let source_budget = SourceReadBudget::new(action.maximum_decode_read_bytes);
    let cancelled = || cx.is_cancelled();
    let mut encode_budget =
        EncodeBudget::with_cancellation_probe(action.export.encode_work_units, &cancelled);
    let result = export(
        action,
        retained,
        deployment,
        root,
        cx,
        out,
        (&mut decode_budget, &source_budget, &mut encode_budget),
    );
    encode_usage_lines(&action.export, &encode_budget, result.is_ok(), out)?;
    writeln!(out, "decode_work_units={}", decode_budget.used())?;
    writeln!(out, "decode_work_unit_model={VIDEO_DECODE_WORK_MODEL}")?;
    writeln!(out, "maximum_decode_work_units={}", action.work_units)?;
    writeln!(
        out,
        "remaining_decode_work_units={}",
        decode_budget.remaining()
    )?;
    writeln!(
        out,
        "movie_decode_source_bytes_read={}",
        source_budget.used()
    )?;
    writeln!(
        out,
        "maximum_movie_decode_source_bytes={}",
        action.maximum_decode_read_bytes
    )?;
    if result.is_ok() {
        cx.checkpoint("file_cli:movie_export_complete")?;
    }
    writeln!(out, "decode_complete={}", result.is_ok())?;
    writeln!(out, "movie_export_complete={}", result.is_ok())?;
    result
}

struct FrameProvenance {
    capsule: SensorCapsule,
    decoder: ContentDigest,
}

fn cache_checkpoint(cx: &ReplayCx) -> Result<(), MovieOutputError> {
    cx.checkpoint("file_cli:movie_cache")
        .map_err(|_| MovieOutputError::Cancelled)
}

fn export(
    action: &Action,
    retained: &RetainedFileImport,
    deployment: &ReferenceDeployment,
    root: &Path,
    cx: &ReplayCx,
    out: &mut impl Write,
    budgets: (
        &mut RecordedVideoDecodeBudget,
        &SourceReadBudget,
        &mut EncodeBudget<'_>,
    ),
) -> RunResult<()> {
    let (decode_budget, source_budget, encode_budget) = budgets;
    let selected = action
        .selection
        .select(retained, deployment, action.read_limits, cx)?;
    let mut output = MovieOutput::new(
        &selected.selection,
        SourceBinding {
            import_identity: selected.import_identity,
            import_root: selected.import_root,
            manifest_digest: selected.manifest_digest,
            input_sha256: selected.input_sha256,
            track_id: selected.track_id,
            codec: selected.codec,
        },
        action.maximum_luma_bytes,
    )?;
    movie::report(&selected, cx, out)?;
    let mut provenance = BTreeMap::new();
    let mut decoded_frames = 0_u64;
    for (ordinal, span) in selected.selection.decode_spans.iter().enumerate() {
        cx.checkpoint("file_cli:movie_decode_span")?;
        writeln!(out, "movie_decoding_span={ordinal}")?;
        let decoded = match selected.codec {
            VideoCodec::Avc => decode_avc(
                action,
                &selected,
                span,
                deployment,
                &mut output,
                &mut provenance,
                decode_budget,
                source_budget,
                cx,
                out,
            )?,
            VideoCodec::Hevc => decode_hevc(
                action,
                &selected,
                span,
                deployment,
                &mut output,
                &mut provenance,
                decode_budget,
                source_budget,
                cx,
                out,
            )?,
        };
        decoded_frames = decoded_frames
            .checked_add(decoded)
            .ok_or_else(|| io::Error::other("movie decode count overflow"))?;
    }
    // Completion is deliberately after every range's Ok(None), not after the last wanted
    // picture. A late source/codec refusal, or a selected RASL with no output, creates no file.
    let complete = output.finish(&mut || cache_checkpoint(cx))?;
    let mut export = prepare_output_export(&action.export, complete.frames(), root, cx)?
        .ok_or_else(|| io::Error::other("movie export requires an output destination"))?;
    for ordinal in 0..complete.frames() {
        cx.checkpoint("file_cli:movie_output_frame")?;
        let frame = complete
            .frame(ordinal)
            .ok_or_else(|| io::Error::other("movie occurrence has no decoded frame"))?;
        let source = provenance
            .get(&frame.segment)
            .ok_or_else(|| io::Error::other("movie occurrence has no source capsule"))?;
        export.frame(
            jpeg_stream::FrameInput {
                dimensions: frame.dimensions,
                pixels: frame.pixels(),
                luma_sha256: frame.luma_sha256,
                decode_receipt: frame.decode_receipt,
            },
            encode_budget,
            cx,
        )?;
        source_selection_lines(
            out,
            selected.import_identity,
            frame.segment as u64,
            &source.capsule,
        )?;
        writeln!(out, "movie_output_index={ordinal}")?;
        writeln!(out, "frame_segment={}", frame.segment)?;
        writeln!(
            out,
            "frame_width={}\nframe_height={}",
            frame.dimensions[0], frame.dimensions[1]
        )?;
        writeln!(
            out,
            "frame_luma_sha256={}",
            ContentDigest::new(fss_core::DigestAlgorithm::Sha256, frame.luma_sha256)
        )?;
        writeln!(out, "frame_receipt_digest={}", frame.decode_receipt)?;
        writeln!(out, "frame_decoder_identity={}", source.decoder)?;
        writeln!(
            out,
            "frame_capture_earliest_ns={}",
            source.capsule.capture.earliest.0
        )?;
        writeln!(
            out,
            "frame_capture_latest_ns={}",
            source.capsule.capture.latest.0
        )?;
    }
    finish_video_export(Some(export), cx, out)?;
    cx.checkpoint("file_cli:movie_export_report")?;
    writeln!(
        out,
        "movie_output_lineage_sha256={}",
        complete.lineage_digest()
    )?;
    writeln!(out, "movie_output_lineage_domain={LINEAGE_DOMAIN}")?;
    writeln!(out, "movie_output_frames={}", complete.frames())?;
    writeln!(out, "movie_cached_frames={}", complete.unique_frames())?;
    writeln!(out, "movie_cached_luma_bytes={}", complete.luma_bytes())?;
    writeln!(
        out,
        "maximum_movie_cached_luma_bytes={}",
        action.maximum_luma_bytes
    )?;
    writeln!(out, "movie_decoded_frames={decoded_frames}")?;
    writeln!(out, "selection_decoded_frames={decoded_frames}")?;
    writeln!(
        out,
        "selection_media_exported=true\nselection_complete=true"
    )?;
    writeln!(out, "movie_output_order=selected_presentation_occurrences")?;
    writeln!(
        out,
        "movie_output_source_timing_preserved=false\nmovie_output_gaps_filled=false"
    )?;
    writeln!(
        out,
        "decode_published=false\nselection_absence_certifiable=false"
    )?;
    Ok(())
}

fn check_source(retained: &RetainedFileImport, selected: &RetainedMovieSelection) -> RunResult<()> {
    if retained.import_identity() != selected.import_identity
        || retained.import_root() != selected.import_root
        || retained.manifest_digest() != selected.manifest_digest
        || retained.manifest().input_sha256 != selected.input_sha256
    {
        return Err(
            io::Error::other("movie decoder source differs from authenticated selection").into(),
        );
    }
    Ok(())
}

fn segment_in_span(segment: u64, span: &MovieDecodeSpan) -> RunResult<usize> {
    let segment =
        usize::try_from(segment).map_err(|_| io::Error::other("movie source index overflow"))?;
    let end = span
        .first_sample
        .checked_add(span.sample_count)
        .ok_or_else(|| io::Error::other("movie source span overflow"))?;
    if !(span.first_sample..end).contains(&segment) {
        return Err(io::Error::other("native movie frame is outside its prerequisite span").into());
    }
    Ok(segment)
}

fn decode_avc(
    action: &Action,
    selected: &RetainedMovieSelection,
    span: &MovieDecodeSpan,
    deployment: &ReferenceDeployment,
    output: &mut MovieOutput,
    provenance: &mut BTreeMap<usize, FrameProvenance>,
    budget: &mut RecordedVideoDecodeBudget,
    source_budget: &SourceReadBudget,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<u64> {
    let limits = action.decode_limits;
    let request = RecordedH264Request {
        import_identity: action.identity(),
        first_segment: span.first_sample,
        segment_count: span.sample_count,
        interpretation: ComponentInterpretation::YCbCr,
        read_limits: action.read_limits,
        decoder_limits: DecoderLimits {
            max_width: limits.maximum_dimension,
            max_height: limits.maximum_dimension,
            max_macroblocks: u32::try_from(limits.maximum_pixels / 256)?,
            max_pictures: span.sample_count as u64,
            max_nal_bytes: limits.maximum_bytes.min(16 * 1024 * 1024),
            max_slices_per_picture: u32::try_from(limits.maximum_markers)?
                .min(DecoderLimits::default().max_slices_per_picture),
            ..DecoderLimits::default()
        },
    };
    let mut range =
        RecordedH264Range::open_with_budgets(deployment, request, source_budget, budget, cx)?;
    check_source(range.retained(), selected)?;
    privacy_lines(out, range.mask().policy_digest(), range.mask().digest())?;
    while let Some(frame) = range.next_frame_with_budget(deployment, budget, cx)? {
        let segment = segment_in_span(frame.segment_index(), span)?;
        if output.wants(segment) {
            let receipt = frame.receipt();
            output.insert(
                FrameInput {
                    segment,
                    dimensions: frame.dimensions(),
                    pixels: frame.pixels(),
                    luma_sha256: receipt.luma_sha256().bytes(),
                    decode_receipt: receipt.digest(),
                },
                &mut || cache_checkpoint(cx),
            )?;
            provenance.insert(
                segment,
                FrameProvenance {
                    capsule: receipt.capsule().clone(),
                    decoder: receipt.decoder_identity(),
                },
            );
        }
    }
    Ok(range.decoded())
}

fn decode_hevc(
    action: &Action,
    selected: &RetainedMovieSelection,
    span: &MovieDecodeSpan,
    deployment: &ReferenceDeployment,
    output: &mut MovieOutput,
    provenance: &mut BTreeMap<usize, FrameProvenance>,
    budget: &mut RecordedVideoDecodeBudget,
    source_budget: &SourceReadBudget,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<u64> {
    let limits = action.decode_limits;
    let request = RecordedH265Request {
        import_identity: action.identity(),
        first_segment: span.first_sample,
        segment_count: span.sample_count,
        interpretation: ComponentInterpretation::YCbCr,
        read_limits: action.read_limits,
        decoder_limits: H265DecoderLimits {
            max_width: limits.maximum_dimension,
            max_height: limits.maximum_dimension,
            max_luma_samples: limits.maximum_pixels as u64,
            max_pictures: span.sample_count as u64,
            max_nal_bytes: limits.maximum_bytes.min(16 * 1024 * 1024),
            max_slices_per_picture: u32::try_from(limits.maximum_markers)?
                .min(H265DecoderLimits::default().max_slices_per_picture),
            ..H265DecoderLimits::default()
        },
    };
    let mut range =
        RecordedH265Range::open_with_budgets(deployment, request, source_budget, budget, cx)?;
    check_source(range.retained(), selected)?;
    privacy_lines(out, range.mask().policy_digest(), range.mask().digest())?;
    while let Some(frame) = range.next_frame_with_budget(deployment, budget, cx)? {
        let segment = segment_in_span(frame.segment_index(), span)?;
        if output.wants(segment) {
            let receipt = frame.receipt();
            output.insert(
                FrameInput {
                    segment,
                    dimensions: frame.dimensions(),
                    pixels: frame.pixels(),
                    luma_sha256: receipt.luma_sha256().bytes(),
                    decode_receipt: receipt.digest(),
                },
                &mut || cache_checkpoint(cx),
            )?;
            provenance.insert(
                segment,
                FrameProvenance {
                    capsule: receipt.capsule().clone(),
                    decoder: receipt.decoder_identity(),
                },
            );
        }
    }
    for segment in range.skipped_rasl_segments() {
        cx.checkpoint("file_cli:movie_skipped_rasl")?;
        writeln!(out, "movie_skipped_rasl_segment={segment}")?;
    }
    Ok(range.decoded())
}

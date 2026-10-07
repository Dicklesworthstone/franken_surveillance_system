#![forbid(unsafe_code)]
//! Operator commands using the same retained-source and canonical codec path as the library.

use super::{ParseResult, RunResult, Values, malformed, number, text, value, write_new};
use fss_core::ContentDigest;
use fss_reference::ingest::pixel_change::{
    PixelChangeConfig, PixelChangeDetector, PixelChangeError, PixelChangeObservation,
    PixelChangeStatistics, VideoPixelChangeObservation,
};
use fss_reference::ingest::recorded_decode::h264::{
    DecoderLimits, MAX_H264_RANGE_SEGMENTS, RecordedH264Frame, RecordedH264Range,
    RecordedH264Request,
};
use fss_reference::ingest::recorded_decode::h265::{
    DecoderLimits as H265DecoderLimits, RecordedH265Frame, RecordedH265Range, RecordedH265Request,
};
use fss_reference::ingest::recorded_decode::video_budget::{
    RecordedVideoDecodeBudget, VIDEO_DECODE_WORK_MODEL,
};
use fss_reference::ingest::recorded_decode::{
    ComponentInterpretation, DecodeBudget, DecodeLimits, RecordedDecodeError,
    RecordedDecodeRequest, RecordedFrame,
};
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use fss_reference::{ReferenceDeployment, ReplayCx};
use std::io::Write;
use std::path::{Path, PathBuf};

const MAX_SCAN_FRAMES: usize = 128;

#[derive(Clone, Copy, Debug)]
enum FrameMode {
    Decode,
    Read,
    Verify,
}

#[derive(Debug)]
pub(super) struct FrameAction {
    mode: FrameMode,
    request: RecordedDecodeRequest,
    /// Annex-B only: contiguous access units decoded from the IDR at `request.segment_index`.
    segment_count: usize,
    work_units: u64,
    output: Option<PathBuf>,
    receipt_output: Option<PathBuf>,
}

#[derive(Debug)]
pub(super) struct MotionAction {
    request: RecordedDecodeRequest,
    frame_count: usize,
    work_units: u64,
    maximum_comparisons: u64,
    thresholds: PixelChangeConfig,
    report_output: PathBuf,
}

#[derive(Debug)]
pub(super) enum Action {
    Frame(FrameAction),
    Motion(MotionAction),
}
impl Action {
    pub(super) fn identity(&self) -> ContentDigest {
        match self {
            Self::Frame(a) => a.request.import_identity,
            Self::Motion(a) => a.request.import_identity,
        }
    }
    pub(super) fn name(&self) -> &'static str {
        match self {
            Self::Frame(a) => match a.mode {
                FrameMode::Decode => "decode",
                FrameMode::Read => "read-decoded",
                FrameMode::Verify => "verify-decoded",
            },
            Self::Motion(_) => "motion",
        }
    }
}

pub(super) fn is_command(command: &str) -> bool {
    matches!(
        command,
        "decode" | "read-decoded" | "verify-decoded" | "motion"
    )
}

pub(super) fn accepts_option(command: &str, option: &str) -> bool {
    if !is_command(command) {
        return false;
    }
    matches!(
        option,
        "--interpretation" | "--max-pixels" | "--max-dimension" | "--max-markers"
    ) || (command != "read-decoded" && option == "--work-units")
        || (command != "motion" && matches!(option, "--segment" | "--output" | "--receipt-out"))
        || (command == "decode" && option == "--segment-count")
        || (command == "motion"
            && matches!(
                option,
                "--start-segment"
                    | "--frame-count"
                    | "--pixel-delta"
                    | "--minimum-changed-pixels"
                    | "--minimum-changed-ppm"
                    | "--max-comparisons"
                    | "--report-out"
            ))
}

pub(super) fn parse(
    command: &str,
    identity: ContentDigest,
    read_limits: RetainedReadLimits,
    values: &Values,
) -> ParseResult<Action> {
    let interpretation = match text(values, "--interpretation")? {
        "gray" => ComponentInterpretation::Grayscale,
        "ycbcr" => ComponentInterpretation::YCbCr,
        _ => return Err(malformed("interpretation must be explicitly gray or ycbcr")),
    };
    let defaults = DecodeLimits::default();
    let decode_limits = DecodeLimits {
        maximum_bytes: usize::try_from(
            read_limits
                .max_segment_bytes
                .min(defaults.maximum_bytes as u64),
        )
        .map_err(|_| malformed("compressed segment limit cannot be represented"))?,
        maximum_dimension: number(values, "--max-dimension", Some(defaults.maximum_dimension))?,
        maximum_pixels: number(values, "--max-pixels", Some(defaults.maximum_pixels))?,
        maximum_markers: number(values, "--max-markers", Some(defaults.maximum_markers))?,
    };
    if decode_limits.maximum_dimension == 0
        || decode_limits.maximum_dimension > 4096
        || decode_limits.maximum_pixels == 0
        || decode_limits.maximum_pixels > 4_194_304
        || decode_limits.maximum_markers == 0
        || decode_limits.maximum_markers > 4096
    {
        return Err(malformed(
            "positive codec limits required: dimension <=4096, pixels <=4194304, markers <=4096",
        ));
    }
    let request = RecordedDecodeRequest {
        import_identity: identity,
        segment_index: number(
            values,
            if command == "motion" {
                "--start-segment"
            } else {
                "--segment"
            },
            None,
        )?,
        interpretation,
        read_limits,
        decode_limits,
    };
    let work_units = number(values, "--work-units", Some(100_000_000_u64))?;
    if command == "motion" {
        let frame_count: usize = number(values, "--frame-count", None)?;
        if frame_count == 0
            || frame_count > MAX_SCAN_FRAMES
            || request.segment_index.checked_add(frame_count).is_none()
        {
            return Err(malformed(
                "frame count must be 1..128 and its source range must not overflow",
            ));
        }
        let thresholds = PixelChangeConfig {
            minimum_delta: number(values, "--pixel-delta", None)?,
            minimum_changed_pixels: number(values, "--minimum-changed-pixels", None)?,
            minimum_changed_fraction_ppm: number(values, "--minimum-changed-ppm", Some(0))?,
        };
        thresholds.validate().map_err(|_| {
            malformed("pixel-change thresholds must be positive and fraction <=1000000 ppm")
        })?;
        Ok(Action::Motion(MotionAction {
            request,
            frame_count,
            work_units,
            thresholds,
            maximum_comparisons: number(values, "--max-comparisons", Some(64_000_000_u64))?,
            report_output: PathBuf::from(value(values, "--report-out")?),
        }))
    } else {
        let mode = match command {
            "decode" => FrameMode::Decode,
            "read-decoded" => FrameMode::Read,
            "verify-decoded" => FrameMode::Verify,
            _ => return Err(malformed("unsupported decoded-frame operation")),
        };
        let segment_count: usize = number(values, "--segment-count", Some(1))?;
        if segment_count == 0
            || segment_count > MAX_H264_RANGE_SEGMENTS
            || request.segment_index.checked_add(segment_count).is_none()
        {
            return Err(malformed(
                "segment count must be 1..1024 and its source range must not overflow",
            ));
        }
        Ok(Action::Frame(FrameAction {
            mode,
            request,
            segment_count,
            work_units,
            output: values.get("--output").map(PathBuf::from),
            receipt_output: values.get("--receipt-out").map(PathBuf::from),
        }))
    }
}

pub(super) fn run(
    action: &Action,
    retained: &RetainedFileImport,
    deployment: &mut ReferenceDeployment,
    root: &Path,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    match action {
        Action::Frame(action)
            if matches!(
                retained.manifest().format.as_str(),
                "annexb" | "mp4avc" | "mkvavc"
            ) =>
        {
            run_h264(action, deployment, root, cx, out)
        }
        Action::Frame(action)
            if matches!(
                retained.manifest().format.as_str(),
                "hevc" | "mp4hevc" | "mkvhevc"
            ) =>
        {
            run_h265(action, deployment, root, cx, out)
        }
        Action::Frame(action) => run_frame(action, deployment, root, cx, out),
        Action::Motion(action) => run_motion(action, retained, deployment, root, cx, out),
    }
}

fn run_frame(
    action: &FrameAction,
    deployment: &mut ReferenceDeployment,
    root: &Path,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    if action.segment_count != 1 {
        return Err(std::io::Error::other("--segment-count applies only to H.264 and H.265 imports; JPEG frames decode one segment").into());
    }
    let mut budget = DecodeBudget::new(action.work_units);
    let frame = match action.mode {
        FrameMode::Decode => {
            RecordedFrame::decode_and_publish(deployment, &action.request, &mut budget, cx)?
        }
        FrameMode::Read | FrameMode::Verify => {
            RecordedFrame::open(deployment, &action.request, cx)?
        }
    };
    if matches!(action.mode, FrameMode::Verify) {
        frame.verify_by_replay(deployment, &action.request, &mut budget, cx)?;
    }
    if let Some(path) = &action.output {
        let bytes = frame.pgm_bytes();
        write_new(path, &bytes, root, cx)?;
        writeln!(out, "pgm_sha256={}", ContentDigest::sha256(&bytes))?;
    }
    if let Some(path) = &action.receipt_output {
        write_new(path, &frame.receipt().encoded()?, root, cx)?;
    }
    let receipt = frame.receipt();
    let [width, height] = receipt.dimensions();
    writeln!(out, "decode_identity={}", receipt.identity())?;
    writeln!(out, "decode_root={}", frame.publication_root())?;
    writeln!(out, "decode_receipt_digest={}", receipt.digest()?)?;
    writeln!(
        out,
        "decode_authority_sequence={}",
        frame.authority_anchor().commit_sequence
    )?;
    writeln!(out, "source_capsule={}", receipt.capsule().capsule_id)?;
    writeln!(
        out,
        "capture_earliest_ns={}",
        receipt.capsule().capture.earliest.0
    )?;
    writeln!(
        out,
        "capture_latest_ns={}",
        receipt.capsule().capture.latest.0
    )?;
    writeln!(out, "clock_basis={}", receipt.capsule().clock_basis)?;
    writeln!(
        out,
        "width={width}\nheight={height}\npixel_format=jpeg_full_range_y"
    )?;
    writeln!(
        out,
        "luma_sha256={}",
        fss_core::ContentDigest::new(
            fss_core::DigestAlgorithm::Sha256,
            receipt.codec().luma_sha256
        )
    )?;
    writeln!(
        out,
        "decoder_identity={}",
        fss_core::ContentDigest::new(fss_core::DigestAlgorithm::Sha256, receipt.codec().decoder)
    )?;
    writeln!(out, "recorded_decode_work_units={}", receipt.work_units())?;
    privacy_lines(out, receipt.mask_policy(), receipt.mask_binding())?;
    writeln!(out, "this_request_decode_work_units={}", budget.used())?;
    writeln!(
        out,
        "replay_verified={}",
        matches!(action.mode, FrameMode::Verify)
    )?;
    writeln!(out, "decode_complete=true")?;
    Ok(())
}

/// H.264 pictures predict from earlier pictures: decode the IDR-led range and export every
/// requested frame. The result is a deterministic derivation of retained custody; unlike JPEG
/// decode it is not published, so read-decoded/verify-decoded refuse Annex-B imports.
fn run_h264(
    action: &FrameAction,
    deployment: &mut ReferenceDeployment,
    root: &Path,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    if !matches!(action.mode, FrameMode::Decode) {
        return Err(
            fss_reference::ingest::recorded_decode::RecordedDecodeError::UnsupportedMedia.into(),
        );
    }
    if action.receipt_output.is_some() {
        return Err(std::io::Error::other(
            "--receipt-out applies to published JPEG decode receipts only",
        )
        .into());
    }
    let limits = action.request.decode_limits;
    let dimension = limits.maximum_dimension.max(16);
    let decoder_limits = DecoderLimits {
        max_width: dimension,
        max_height: dimension,
        max_macroblocks: u32::try_from(limits.maximum_pixels.div_ceil(256))
            .map_err(|_| std::io::Error::other("pixel ceiling"))?,
        max_pictures: action.segment_count as u64,
        max_nal_bytes: limits.maximum_bytes.clamp(2, 16 * 1024 * 1024),
        ..DecoderLimits::default()
    };
    let request = RecordedH264Request {
        import_identity: action.request.import_identity,
        first_segment: action.request.segment_index,
        segment_count: action.segment_count,
        interpretation: action.request.interpretation,
        read_limits: action.request.read_limits,
        decoder_limits,
    };
    let mut range = RecordedH264Range::open(deployment, request, cx)?;
    privacy_lines(out, range.mask().policy_digest(), range.mask().digest())?;
    let mut pgm = Vec::new();
    writeln!(
        out,
        "h264_range_first_segment={}\nh264_range_segment_count={}",
        action.request.segment_index, action.segment_count
    )?;
    while let Some(frame) = range.next_frame(deployment, cx)? {
        let receipt = frame.receipt();
        let [width, height] = receipt.dimensions();
        writeln!(
            out,
            "frame_segment={}\nframe_idr={}\nframe_width={width}\nframe_height={height}",
            receipt.segment_index(),
            receipt.is_idr()
        )?;
        writeln!(
            out,
            "frame_luma_sha256={}\nframe_i420_sha256={}\nframe_receipt_digest={}",
            receipt.luma_sha256(),
            receipt.i420_sha256(),
            receipt.digest()
        )?;
        writeln!(
            out,
            "frame_capture_earliest_ns={}\nframe_capture_latest_ns={}",
            receipt.capsule().capture.earliest.0,
            receipt.capsule().capture.latest.0
        )?;
        pgm.extend_from_slice(&frame.pgm_bytes());
    }
    if let Some(path) = &action.output {
        // Multi-image binary PGM: one complete P5 image per decoded frame, in decode order.
        write_new(path, &pgm, root, cx)?;
        writeln!(out, "pgm_sha256={}", ContentDigest::sha256(&pgm))?;
    }
    writeln!(
        out,
        "pixel_format=h264_yuv420p_luma\ndecoder_identity={}",
        fss_reference::ingest::recorded_decode::h264::h264_decoder_identity()
    )?;
    writeln!(
        out,
        "h264_frames_decoded={}\ndecode_published=false\ndecode_complete=true",
        range.decoded()
    )?;
    Ok(())
}

/// H.265 ranges start at an IRAP picture. When that is a CRA/BLA, its RASL pictures predict from
/// pictures before the range: the codec skips them, and each skipped segment is listed instead of
/// a frame. Like H.264, the frames are a deterministic, unpublished derivation of custody.
fn run_h265(
    action: &FrameAction,
    deployment: &mut ReferenceDeployment,
    root: &Path,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    if !matches!(action.mode, FrameMode::Decode) {
        return Err(
            fss_reference::ingest::recorded_decode::RecordedDecodeError::UnsupportedMedia.into(),
        );
    }
    if action.receipt_output.is_some() {
        return Err(std::io::Error::other(
            "--receipt-out applies to published JPEG decode receipts only",
        )
        .into());
    }
    let limits = action.request.decode_limits;
    let dimension = limits.maximum_dimension.max(16);
    let decoder_limits = H265DecoderLimits {
        max_width: dimension,
        max_height: dimension,
        max_luma_samples: (limits.maximum_pixels as u64).max(64),
        max_pictures: action.segment_count as u64,
        max_nal_bytes: limits.maximum_bytes.clamp(3, 16 * 1024 * 1024),
        ..H265DecoderLimits::default()
    };
    let request = RecordedH265Request {
        import_identity: action.request.import_identity,
        first_segment: action.request.segment_index,
        segment_count: action.segment_count,
        interpretation: action.request.interpretation,
        read_limits: action.request.read_limits,
        decoder_limits,
    };
    let mut range = RecordedH265Range::open(deployment, request, cx)?;
    privacy_lines(out, range.mask().policy_digest(), range.mask().digest())?;
    let mut pgm = Vec::new();
    writeln!(
        out,
        "h265_range_first_segment={}\nh265_range_segment_count={}",
        action.request.segment_index, action.segment_count
    )?;
    while let Some(frame) = range.next_frame(deployment, cx)? {
        let receipt = frame.receipt();
        let [width, height] = receipt.dimensions();
        writeln!(
            out,
            "frame_segment={}\nframe_nal_unit_type={}\nframe_irap={}\nframe_idr={}\nframe_width={width}\nframe_height={height}",
            receipt.segment_index(),
            receipt.nal_unit_type(),
            receipt.is_irap(),
            receipt.is_idr()
        )?;
        writeln!(
            out,
            "frame_luma_sha256={}\nframe_i420_sha256={}\nframe_receipt_digest={}",
            receipt.luma_sha256(),
            receipt.i420_sha256(),
            receipt.digest()
        )?;
        writeln!(
            out,
            "frame_capture_earliest_ns={}\nframe_capture_latest_ns={}",
            receipt.capsule().capture.earliest.0,
            receipt.capsule().capture.latest.0
        )?;
        pgm.extend_from_slice(&frame.pgm_bytes());
    }
    for segment in range.skipped_rasl_segments() {
        writeln!(out, "skipped_rasl_segment={segment}")?;
    }
    if let Some(path) = &action.output {
        // Multi-image binary PGM: one complete P5 image per decoded frame, in display order.
        write_new(path, &pgm, root, cx)?;
        writeln!(out, "pgm_sha256={}", ContentDigest::sha256(&pgm))?;
    }
    writeln!(
        out,
        "pixel_format=h265_yuv420p_luma\ndecoder_identity={}",
        fss_reference::ingest::recorded_decode::h265::h265_decoder_identity()
    )?;
    writeln!(
        out,
        "h265_frames_decoded={}\nh265_rasl_skipped={}\ndecode_published=false\ndecode_complete=true",
        range.decoded(),
        range.skipped_rasl_segments().len()
    )?;
    Ok(())
}

/// The privacy transform applied to the served pixels, as typed `key=value` lines.
fn privacy_lines(
    out: &mut impl Write,
    policy: Option<ContentDigest>,
    binding: ContentDigest,
) -> RunResult<()> {
    match policy {
        Some(policy) => writeln!(
            out,
            "privacy_mask_binding=sensor_policy\nprivacy_mask_policy={policy}\napplied_redaction_transform={}",
            fss_reference::ingest::privacy_mask::mask_transform().as_str()
        )?,
        None => writeln!(
            out,
            "privacy_mask_binding=no_policy_declared\nprivacy_mask_policy=none\napplied_redaction_transform=none"
        )?,
    }
    writeln!(out, "privacy_mask_binding_digest={binding}")?;
    Ok(())
}

fn observation_json(segment: usize, observation: &PixelChangeObservation) -> String {
    let predecessor = observation
        .predecessor_root
        .map(|root| format!("\"{root}\""))
        .unwrap_or_else(|| "null".to_owned());
    let resets = observation
        .reset_reasons
        .iter()
        .map(|reason| format!("\"{}\"", reason.as_str()))
        .collect::<Vec<_>>()
        .join(",");
    let comparison = comparison_json(&observation.statistics);
    // Digests, stable IDs, and enum spellings are validated portable strings, not arbitrary text.
    format!(
        "{{\"segment\":{segment},\"frame_root\":\"{}\",\"predecessor_root\":{predecessor},\"capsule_id\":\"{}\",\"capture_earliest_ns\":\"{}\",\"capture_latest_ns\":\"{}\",\"reset_reasons\":[{resets}],\"comparison\":{comparison}}}",
        observation.frame_root,
        observation.capsule_id,
        observation.capture.earliest.0,
        observation.capture.latest.0
    )
}

fn comparison_json(statistics: &Option<PixelChangeStatistics>) -> String {
    match statistics {
        None => "null".to_owned(),
        Some(statistics) => {
            let bounds = statistics
                .changed_bounds
                .map(|b| format!("[{}, {}, {}, {}]", b.left, b.top, b.right, b.bottom))
                .unwrap_or_else(|| "null".to_owned());
            format!(
                "{{\"compared_pixels\":{},\"changed_pixels\":{},\"absolute_difference_sum\":{},\"maximum_difference\":{},\"changed_bounds_half_open\":{},\"candidate\":{}}}",
                statistics.compared_pixels,
                statistics.changed_pixels,
                statistics.absolute_difference_sum,
                statistics.maximum_difference,
                bounds,
                statistics.candidate
            )
        }
    }
}

fn run_motion(
    action: &MotionAction,
    retained: &RetainedFileImport,
    deployment: &mut ReferenceDeployment,
    root: &Path,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    let start = action.request.segment_index;
    let end = start
        .checked_add(action.frame_count)
        .ok_or_else(|| std::io::Error::other("scan range overflow"))?;
    if end > retained.manifest().segment_spans.len() {
        return Err(std::io::Error::other(
            "scan range exceeds retained recording; nothing decoded",
        )
        .into());
    }
    if matches!(
        retained.manifest().format.as_str(),
        "annexb" | "mp4avc" | "mkvavc" | "hevc" | "mp4hevc" | "mkvhevc"
    ) {
        return run_video_motion(action, retained, deployment, root, cx, out);
    }
    let mut budget = DecodeBudget::new(action.work_units);
    let mut detector = PixelChangeDetector::new(action.thresholds, action.maximum_comparisons)?;
    let mut observations = Vec::with_capacity(action.frame_count);
    let mut next = start;
    let result = (|| -> RunResult<()> {
        for segment in start..end {
            next = segment;
            let mut request = action.request.clone();
            request.segment_index = segment;
            let frame = RecordedFrame::decode_and_publish(deployment, &request, &mut budget, cx)?;
            let observation = detector.push(&frame, cx)?;
            observations.push(observation_json(segment, &observation));
            next = segment + 1;
        }
        Ok(())
    })();
    let complete = result.is_ok();
    let error = if complete {
        "null"
    } else {
        "\"analysis_incomplete\""
    };
    let report = format!(
        concat!(
            "{{\"format\":\"fss.recorded_pixel_change_report.v1\",\"import_identity\":\"{}\",",
            "\"source_manifest_digest\":\"{}\",\"configuration_digest\":\"{}\",",
            "\"minimum_delta\":{},\"minimum_changed_pixels\":{},\"minimum_changed_fraction_ppm\":{},",
            "\"start_segment\":{},\"requested_frames\":{},\"observations\":[{}],",
            "\"complete\":{},\"next_segment\":{},\"resume_start_segment\":{},\"error\":{},",
            "\"decode_work_units\":{},\"pixel_comparisons\":{},\"absence_certifiable\":false}}\n"
        ),
        retained.import_identity(),
        retained.manifest_digest(),
        action.thresholds.digest(),
        action.thresholds.minimum_delta,
        action.thresholds.minimum_changed_pixels,
        action.thresholds.minimum_changed_fraction_ppm,
        start,
        action.frame_count,
        observations.join(",\n"),
        complete,
        next,
        next.saturating_sub(1).max(start),
        error,
        budget.used(),
        detector.comparisons_used()
    );
    // On ordinary failures a complete JSON document retains progress and an explicit next frame.
    // Cancelled/revoked authority cannot export: already committed frame roots remain recoverable.
    let export = write_new(&action.report_output, report.as_bytes(), root, cx);
    writeln!(out, "motion_complete={complete}")?;
    writeln!(out, "motion_observations={}", observations.len())?;
    writeln!(out, "motion_next_segment={next}")?;
    writeln!(out, "motion_decode_work_units={}", budget.used())?;
    writeln!(
        out,
        "motion_pixel_comparisons={}",
        detector.comparisons_used()
    )?;
    if export.is_ok() {
        writeln!(
            out,
            "motion_report_sha256={}",
            ContentDigest::sha256(report.as_bytes())
        )?;
    }
    result?;
    export?;
    Ok(())
}

/// The canonical video range owns prediction, display order, custody checks and privacy.
/// This adapter never constructs a JPEG frame or claims an unpublished receipt is a root.
enum MotionVideoRange {
    H264(Box<RecordedH264Range>),
    H265(Box<RecordedH265Range>),
}

enum MotionVideoFrame {
    H264(RecordedH264Frame),
    H265(RecordedH265Frame),
}

impl MotionVideoRange {
    fn open(
        action: &MotionAction,
        retained: &RetainedFileImport,
        deployment: &ReferenceDeployment,
        budget: &mut RecordedVideoDecodeBudget,
        cx: &ReplayCx,
    ) -> Result<Self, RecordedDecodeError> {
        let limits = action.request.decode_limits;
        match retained.manifest().format.as_str() {
            "annexb" | "mp4avc" | "mkvavc" => {
                // Round down: a caller's pixel or dimension ceiling must never be widened to
                // the next macroblock. The codec checks coded dimensions before allocation.
                let decoder_limits = DecoderLimits {
                    max_width: limits.maximum_dimension,
                    max_height: limits.maximum_dimension,
                    max_macroblocks: u32::try_from(limits.maximum_pixels / 256)
                        .map_err(|_| RecordedDecodeError::Limit)?,
                    max_pictures: action.frame_count as u64,
                    max_nal_bytes: limits.maximum_bytes.min(16 * 1024 * 1024),
                    max_slices_per_picture: u32::try_from(limits.maximum_markers)
                        .map_err(|_| RecordedDecodeError::Limit)?,
                    ..DecoderLimits::default()
                };
                let request = RecordedH264Request {
                    import_identity: action.request.import_identity,
                    first_segment: action.request.segment_index,
                    segment_count: action.frame_count,
                    interpretation: action.request.interpretation,
                    read_limits: action.request.read_limits,
                    decoder_limits,
                };
                Ok(Self::H264(Box::new(RecordedH264Range::open_with_budget(
                    deployment, request, budget, cx,
                )?)))
            }
            "hevc" | "mp4hevc" | "mkvhevc" => {
                let decoder_limits = H265DecoderLimits {
                    max_width: limits.maximum_dimension,
                    max_height: limits.maximum_dimension,
                    max_luma_samples: limits.maximum_pixels as u64,
                    max_pictures: action.frame_count as u64,
                    max_nal_bytes: limits.maximum_bytes.min(16 * 1024 * 1024),
                    max_slices_per_picture: u32::try_from(limits.maximum_markers)
                        .map_err(|_| RecordedDecodeError::Limit)?,
                    ..H265DecoderLimits::default()
                };
                let request = RecordedH265Request {
                    import_identity: action.request.import_identity,
                    first_segment: action.request.segment_index,
                    segment_count: action.frame_count,
                    interpretation: action.request.interpretation,
                    read_limits: action.request.read_limits,
                    decoder_limits,
                };
                Ok(Self::H265(Box::new(RecordedH265Range::open_with_budget(
                    deployment, request, budget, cx,
                )?)))
            }
            _ => Err(RecordedDecodeError::UnsupportedMedia),
        }
    }

    fn next(
        &mut self,
        deployment: &ReferenceDeployment,
        budget: &mut RecordedVideoDecodeBudget,
        cx: &ReplayCx,
    ) -> Result<Option<MotionVideoFrame>, RecordedDecodeError> {
        match self {
            Self::H264(range) => range
                .next_frame_with_budget(deployment, budget, cx)
                .map(|frame| frame.map(MotionVideoFrame::H264)),
            Self::H265(range) => range
                .next_frame_with_budget(deployment, budget, cx)
                .map(|frame| frame.map(MotionVideoFrame::H265)),
        }
    }

    fn next_source_segment(&self) -> usize {
        match self {
            Self::H264(range) => range.next_source_segment(),
            Self::H265(range) => range.next_source_segment(),
        }
    }

    fn decoded(&self) -> u64 {
        match self {
            Self::H264(range) => range.decoded(),
            Self::H265(range) => range.decoded(),
        }
    }

    fn skipped_rasl_segments(&self) -> &[usize] {
        match self {
            Self::H264(_) => &[],
            Self::H265(range) => range.skipped_rasl_segments(),
        }
    }
}

impl MotionVideoFrame {
    fn segment(&self) -> u64 {
        match self {
            Self::H264(frame) => frame.segment_index(),
            Self::H265(frame) => frame.segment_index(),
        }
    }

    fn observe(
        &self,
        detector: &mut PixelChangeDetector,
        cx: &ReplayCx,
    ) -> Result<VideoPixelChangeObservation, PixelChangeError> {
        match self {
            Self::H264(frame) => detector.push_h264(frame, cx),
            Self::H265(frame) => detector.push_h265(frame, cx),
        }
    }

    fn observation_json(&self, observation: &VideoPixelChangeObservation) -> String {
        let (receipt, luma, source_root, source_capsule_digest, decoder, mask, policy, dimensions) =
            match self {
                Self::H264(frame) => {
                    let receipt = frame.receipt();
                    (
                        receipt.encoded(),
                        receipt.luma_sha256(),
                        receipt.import_root(),
                        receipt.capsule_digest(),
                        fss_reference::ingest::recorded_decode::h264::h264_decoder_identity(),
                        receipt.mask_binding(),
                        receipt.mask_policy(),
                        receipt.dimensions(),
                    )
                }
                Self::H265(frame) => {
                    let receipt = frame.receipt();
                    (
                        receipt.encoded(),
                        receipt.luma_sha256(),
                        receipt.import_root(),
                        receipt.capsule_digest(),
                        fss_reference::ingest::recorded_decode::h265::h265_decoder_identity(),
                        receipt.mask_binding(),
                        receipt.mask_policy(),
                        receipt.dimensions(),
                    )
                }
            };
        let predecessor = observation
            .predecessor_receipt_digest
            .map(|digest| format!("\"{digest}\""))
            .unwrap_or_else(|| "null".to_owned());
        let policy = policy
            .map(|digest| format!("\"{digest}\""))
            .unwrap_or_else(|| "null".to_owned());
        let resets = observation
            .reset_reasons
            .iter()
            .map(|reason| format!("\"{}\"", reason.as_str()))
            .collect::<Vec<_>>()
            .join(",");
        let encoded = receipt
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let comparison = comparison_json(&observation.statistics);
        format!(
            concat!(
                "{{\"segment\":{},\"display_index\":{},\"frame_receipt_digest\":\"{}\",",
                "\"predecessor_receipt_digest\":{predecessor},\"decode_published\":false,",
                "\"receipt_encoding\":\"hex\",\"frame_receipt\":\"{encoded}\",",
                "\"source_import_root\":\"{source_root}\",\"source_capsule_digest\":\"{source_capsule_digest}\",",
                "\"capsule_id\":\"{}\",\"capture_earliest_ns\":\"{}\",\"capture_latest_ns\":\"{}\",",
                "\"width\":{},\"height\":{},\"luma_sha256\":\"{luma}\",\"decoder_identity\":\"{decoder}\",",
                "\"privacy_mask_policy\":{policy},\"privacy_mask_binding_digest\":\"{mask}\",",
                "\"reset_reasons\":[{resets}],\"comparison\":{comparison}}}"
            ),
            observation.segment_index,
            observation.output_index,
            observation.frame_receipt_digest,
            observation.capsule_id,
            observation.capture.earliest.0,
            observation.capture.latest.0,
            dimensions[0],
            dimensions[1],
            predecessor = predecessor,
            encoded = encoded,
            source_root = source_root,
            source_capsule_digest = source_capsule_digest,
            luma = luma,
            decoder = decoder,
            policy = policy,
            mask = mask,
            resets = resets,
            comparison = comparison
        )
    }
}

fn motion_error_json(error: &(dyn std::error::Error + 'static)) -> String {
    if let Some(error) = error.downcast_ref::<RecordedDecodeError>() {
        return format!(
            "{{\"kind\":\"decode_refusal\",\"refusal_id\":\"{}\"}}",
            error.stable_id()
        );
    }
    let kind = match error.downcast_ref::<PixelChangeError>() {
        Some(PixelChangeError::BudgetExceeded) => "comparison_budget_exceeded",
        Some(PixelChangeError::Cancelled) => "cancelled",
        Some(PixelChangeError::OutOfOrder) => "out_of_order",
        Some(PixelChangeError::InvalidConfig) => "invalid_configuration",
        Some(PixelChangeError::InvalidImage) => "invalid_image",
        None => "analysis_incomplete",
    };
    format!("{{\"kind\":\"{kind}\"}}")
}

fn run_video_motion(
    action: &MotionAction,
    retained: &RetainedFileImport,
    deployment: &ReferenceDeployment,
    root: &Path,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    let start = action.request.segment_index;
    let end = start
        .checked_add(action.frame_count)
        .ok_or(RecordedDecodeError::Limit)?;
    let mut budget = RecordedVideoDecodeBudget::new(action.work_units);
    let mut detector = PixelChangeDetector::new(action.thresholds, action.maximum_comparisons)?;
    let mut observations = Vec::with_capacity(action.frame_count);
    let mut observed = vec![false; action.frame_count];
    let mut range = None;
    let mut failure_segment = None;
    let result = (|| -> RunResult<()> {
        range = Some(MotionVideoRange::open(
            action,
            retained,
            deployment,
            &mut budget,
            cx,
        )?);
        let source = range.as_mut().ok_or(RecordedDecodeError::Unavailable)?;
        loop {
            let next_frame = source.next(deployment, &mut budget, cx);
            let next_frame = match next_frame {
                Ok(frame) => frame,
                Err(error) => {
                    // A single call may feed several access units before it can return a B
                    // picture. Locate input refusals after that work, never at the old cursor.
                    // Custody/receipt/output failures without a bound source position stay
                    // unattributed; explicit segment-bearing errors are selected below.
                    if matches!(
                        error,
                        RecordedDecodeError::H264(_)
                            | RecordedDecodeError::H265(_)
                            | RecordedDecodeError::Limit
                            | RecordedDecodeError::Source(_)
                    ) {
                        failure_segment = (source.next_source_segment() < end)
                            .then_some(source.next_source_segment());
                    }
                    return Err(error.into());
                }
            };
            let Some(frame) = next_frame else {
                break;
            };
            let segment = usize::try_from(frame.segment())
                .map_err(|_| RecordedDecodeError::InvalidReceipt)?;
            failure_segment = Some(segment);
            let offset = segment
                .checked_sub(start)
                .filter(|offset| *offset < observed.len())
                .ok_or(RecordedDecodeError::InvalidReceipt)?;
            if observed[offset] {
                return Err(RecordedDecodeError::InvalidReceipt.into());
            }
            let observation = frame.observe(&mut detector, cx)?;
            observations.push(frame.observation_json(&observation));
            observed[offset] = true;
            failure_segment = None;
        }
        Ok(())
    })();
    let skipped = range
        .as_ref()
        .map(MotionVideoRange::skipped_rasl_segments)
        .unwrap_or(&[]);
    let unobserved = (start..end)
        .filter(|segment| !observed[*segment - start])
        .collect::<Vec<_>>();
    // A decode cursor can pass B pictures that have not been compared yet. Account by original
    // source segment instead; a skipped RASL is classified but remains explicitly unobserved.
    let next = unobserved
        .iter()
        .copied()
        .find(|segment| !skipped.contains(segment))
        .unwrap_or(end);
    let complete = result.is_ok();
    let error = result
        .as_ref()
        .err()
        .map(|error| motion_error_json(error.as_ref()))
        .unwrap_or_else(|| "null".to_owned());
    let failure_segment = result
        .as_ref()
        .err()
        .and_then(|error| match error.downcast_ref::<RecordedDecodeError>() {
            Some(
                RecordedDecodeError::H264RangeNotIdr { segment }
                | RecordedDecodeError::H264SourceGap { segment }
                | RecordedDecodeError::H264AccessUnit { segment }
                | RecordedDecodeError::H265RangeNotIrap { segment }
                | RecordedDecodeError::H265SourceGap { segment }
                | RecordedDecodeError::H265AccessUnit { segment },
            ) => Some(*segment),
            _ => failure_segment,
        })
        .map(|segment| segment.to_string())
        .unwrap_or_else(|| "null".to_owned());
    let segments_json = |segments: &[usize]| {
        segments
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    let frames_decoded = range.as_ref().map(MotionVideoRange::decoded).unwrap_or(0);
    let report = format!(
        concat!(
            "{{\"format\":\"fss.recorded_pixel_change_report.v2\",\"import_identity\":\"{}\",",
            "\"source_import_root\":\"{}\",\"source_manifest_digest\":\"{}\",\"media_format\":\"{}\",",
            "\"configuration_digest\":\"{}\",\"minimum_delta\":{},\"minimum_changed_pixels\":{},\"minimum_changed_fraction_ppm\":{},",
            "\"start_segment\":{start},\"requested_segments\":{},\"frame_order\":\"decoder_display_order\",",
            "\"observations\":[{}],\"complete\":{complete},\"next_segment\":{next},\"failure_segment\":{failure_segment},",
            "\"resume_strategy\":\"replay_original_random_access_range\",\"resume_start_segment\":{start},\"resume_segment_count\":{},",
            "\"unobserved_segments\":[{}],\"skipped_rasl_segments\":[{}],\"all_requested_segments_observed\":{},",
            "\"error\":{error},\"decode_work_units\":{},\"decode_work_unit_model\":\"{VIDEO_DECODE_WORK_MODEL}\",",
            "\"maximum_decode_work_units\":{},\"frames_decoded\":{frames_decoded},\"pixel_comparisons\":{},",
            "\"decode_published\":false,\"absence_certifiable\":false}}\n"
        ),
        retained.import_identity(),
        retained.import_root(),
        retained.manifest_digest(),
        retained.manifest().format,
        action.thresholds.digest(),
        action.thresholds.minimum_delta,
        action.thresholds.minimum_changed_pixels,
        action.thresholds.minimum_changed_fraction_ppm,
        action.frame_count,
        observations.join(",\n"),
        action.frame_count,
        segments_json(&unobserved),
        segments_json(skipped),
        unobserved.is_empty(),
        budget.used(),
        action.work_units,
        detector.comparisons_used(),
        start = start,
        complete = complete,
        next = next,
        failure_segment = failure_segment,
        error = error,
        VIDEO_DECODE_WORK_MODEL = VIDEO_DECODE_WORK_MODEL,
        frames_decoded = frames_decoded
    );
    // Cancellation/revocation must still pass the common export boundary. Successful earlier
    // observations remain receipt-backed by custody even if the next decode/comparison refuses.
    let export = write_new(&action.report_output, report.as_bytes(), root, cx);
    writeln!(
        out,
        "motion_complete={complete}\nmotion_observations={}\nmotion_next_segment={next}",
        observations.len()
    )?;
    writeln!(
        out,
        "motion_resume_start_segment={start}\nmotion_resume_segment_count={}",
        action.frame_count
    )?;
    writeln!(
        out,
        "motion_decode_work_units={}\nmotion_decode_work_unit_model={VIDEO_DECODE_WORK_MODEL}",
        budget.used()
    )?;
    writeln!(
        out,
        "motion_pixel_comparisons={}\ndecode_published=false",
        detector.comparisons_used()
    )?;
    if export.is_ok() {
        writeln!(
            out,
            "motion_report_sha256={}",
            ContentDigest::sha256(report.as_bytes())
        )?;
    }
    result?;
    export?;
    Ok(())
}

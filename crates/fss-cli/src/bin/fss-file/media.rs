#![forbid(unsafe_code)]
//! Operator commands using the same retained-source and canonical codec path as the library.

use super::{ParseResult, RunResult, Values, malformed, number, text, value, write_new};
use fss_core::ContentDigest;
use fss_reference::ingest::pixel_change::{
    PixelChangeConfig, PixelChangeDetector, PixelChangeObservation,
};
use fss_reference::ingest::recorded_decode::h264::{
    DecoderLimits, MAX_H264_RANGE_SEGMENTS, RecordedH264Range, RecordedH264Request,
};
use fss_reference::ingest::recorded_decode::h265::{
    DecoderLimits as H265DecoderLimits, RecordedH265Range, RecordedH265Request,
};
use fss_reference::ingest::recorded_decode::{
    ComponentInterpretation, DecodeBudget, DecodeLimits, RecordedDecodeRequest, RecordedFrame,
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
        Action::Frame(action) if retained.manifest().format == "annexb" => {
            run_h264(action, deployment, root, cx, out)
        }
        Action::Frame(action) if retained.manifest().format == "hevc" => {
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
        return Err(std::io::Error::other("--segment-count applies only to annexb and hevc imports; JPEG frames decode one segment").into());
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
    let comparison = match &observation.statistics {
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
    };
    // Digests, stable IDs, and enum spellings are validated portable strings, not arbitrary text.
    format!(
        "{{\"segment\":{segment},\"frame_root\":\"{}\",\"predecessor_root\":{predecessor},\"capsule_id\":\"{}\",\"capture_earliest_ns\":\"{}\",\"capture_latest_ns\":\"{}\",\"reset_reasons\":[{resets}],\"comparison\":{comparison}}}",
        observation.frame_root,
        observation.capsule_id,
        observation.capture.earliest.0,
        observation.capture.latest.0
    )
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

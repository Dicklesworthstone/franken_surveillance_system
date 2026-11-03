#![forbid(unsafe_code)]
//! One native source walk and one set of inference/head owners for every admitted burst.

use std::collections::BTreeSet;
use std::error::Error;

use fss_codec_mjpeg::DecodeBudget;
use fss_codec_mjpeg::color::decode_rgb;

use super::{
    LongSentinelConfig, LongSentinelLimits, LongSentinelPlan, LongSentinelReport,
    LongSentinelRequest, LongSentinelUsage,
};
use crate::ingest::RetainedFileImport;
use crate::ingest::long_dwell::reader::ChunkCursor;
use crate::ingest::package_detect::{DecodedFrame, FrameRun, PackageDetectError};
use crate::ingest::privacy_mask::current_mask;
use crate::ingest::recorded_decode::source_capsule;
use crate::ingest::recorded_decode::video_budget::RecordedVideoDecodeBudget;
use crate::ingest::retained::SourceReadBudget;
use crate::ingest::rgb_detections::RgbDetectionBudget;
use crate::ingest::rgb_package::RgbDetectorPackage;
use crate::ingest::tolerant_decode::{TolerantItem, TolerantRequest, TolerantSource};
use crate::{ReferenceDeployment, ReplayCx, ScalarExecCx};

fn frame_error<E: Error + 'static>(segment: usize) -> impl FnOnce(E) -> PackageDetectError {
    move |error| PackageDetectError::Frame {
        segment,
        source: Box::new(error),
    }
}

fn refused(segment: usize, detail: &'static str) -> PackageDetectError {
    PackageDetectError::Frame {
        segment,
        source: detail.into(),
    }
}

fn checkpoint(
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
    stage: &'static str,
) -> Result<(), PackageDetectError> {
    cx.checkpoint(stage)
        .map_err(|_| PackageDetectError::Cancelled)?;
    scalar
        .checkpoint(stage)
        .map_err(|_| PackageDetectError::Cancelled)
}

fn source_owner(
    deployment: &ReferenceDeployment,
    cx: &ReplayCx,
    segment: usize,
) -> Result<(), PackageDetectError> {
    if cx.root_dir() != deployment.root() || !cx.io_authority().is_valid() {
        return Err(refused(
            segment,
            "source context does not own this deployment",
        ));
    }
    deployment
        .ledger()
        .verify_durable_head()
        .map_err(frame_error(segment))
}

fn charge_pixels(
    usage: &mut LongSentinelUsage,
    dimensions: [u32; 2],
    limits: &LongSentinelLimits,
    segment: usize,
) -> Result<(), PackageDetectError> {
    let pixels = u64::from(dimensions[0])
        .checked_mul(u64::from(dimensions[1]))
        .filter(|pixels| *pixels != 0)
        .ok_or_else(|| refused(segment, "invalid decoded raster dimensions"))?;
    let total = usage
        .pixel_samples
        .checked_add(pixels)
        .filter(|total| *total <= limits.maximum_pixel_samples)
        .ok_or_else(|| refused(segment, "whole-recording decoded pixel allowance exhausted"))?;
    usage.pixel_samples = total;
    usage.decoded_frames = usage
        .decoded_frames
        .checked_add(1)
        .ok_or(PackageDetectError::InvalidRequest)?;
    Ok(())
}

/// Run one strict native detector computation over an explicit whole-recording source range.
///
/// Scheduling uses neither foreground tracks nor detector results. The inference allowance is
/// consumed by whole contiguous bursts, and RGB is materialized only for their selected frames.
/// AVC/HEVC drain the entire requested IDR/IRAP-led range before any report is released; no
/// successful early burst can hide a later corrupt or missing source picture. MJPEG instead
/// reads and decodes only selected independent frames through one forward-only chunk cursor.
/// All completed bursts use the unchanged package-report writer and remain independently
/// retainable/trackable. This function performs no writes and authorizes no effects.
#[allow(clippy::too_many_arguments)]
pub fn run_long_sentinel_detection(
    deployment: &ReferenceDeployment,
    package: &RgbDetectorPackage,
    request: &LongSentinelRequest,
    config: LongSentinelConfig,
    limits: &LongSentinelLimits,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
) -> Result<LongSentinelReport, PackageDetectError> {
    checkpoint(cx, scalar, "long_sentinel:begin")?;
    let plan = LongSentinelPlan::new(request.first_segment, request.segment_count, config)?;
    let reservation = plan.reservation(limits)?;
    let selected = plan.selected_segments();
    let first = request.first_segment;
    let end = first + request.segment_count;
    source_owner(deployment, cx, first)?;
    let owned_contract;
    let contract = match request.minimum_score_ppm {
        None => package.contract(),
        Some(ppm) => {
            owned_contract = package
                .contract_with_threshold(ppm)
                .map_err(frame_error(first))?;
            &owned_contract
        }
    };
    let retained =
        RetainedFileImport::open(deployment, request.import_identity, limits.package.read, cx)
            .map_err(frame_error(first))?;
    if end > retained.manifest().segment_spans.len() {
        return Err(PackageDetectError::InvalidRequest);
    }
    let media_format = retained.manifest().format.clone();
    let import_root = retained.import_root();
    let (first_capsule, _) =
        source_capsule(deployment, &retained, first).map_err(frame_error(first))?;
    let privacy = current_mask(deployment, &first_capsule.sensor_id).map_err(frame_error(first))?;
    let mut run = FrameRun {
        package,
        contract,
        run: limits.package.run,
        import_root,
        budget: RgbDetectionBudget::new(
            limits.package.detection_work_units,
            limits.package.detection_scratch_bytes,
        ),
        scalar,
        cx,
    };
    let mut frames = Vec::with_capacity(selected.len());
    let mut seen_selected = BTreeSet::new();
    let mut usage = LongSentinelUsage::default();
    let mut jpeg = DecodeBudget::new(limits.package.jpeg_work_units);
    match media_format.as_str() {
        "mjpeg" => {
            let mut cursor = ChunkCursor::new(limits.maximum_source_chunk_bytes);
            for &segment in &selected {
                checkpoint(cx, scalar, "long_sentinel:jpeg")?;
                let (capsule, capsule_digest) =
                    source_capsule(deployment, &retained, segment).map_err(frame_error(segment))?;
                if capsule.sensor_id != first_capsule.sensor_id {
                    return Err(refused(segment, "selected source sensor changed"));
                }
                let bytes = cursor
                    .segment(deployment, &retained, segment, limits.package.read, cx)
                    .map_err(frame_error(segment))?;
                // The existing native SOF parser checks this remaining allowance before scan
                // reconstruction/entropy work or pixel allocation. No second JPEG parser or
                // optimistic post-work admission is introduced.
                let remaining_pixels = limits
                    .maximum_pixel_samples
                    .checked_sub(usage.pixel_samples)
                    .ok_or(PackageDetectError::InvalidRequest)?;
                let mut jpeg_limits = limits.package.jpeg;
                jpeg_limits.frame.maximum_pixels = jpeg_limits
                    .frame
                    .maximum_pixels
                    .min(usize::try_from(remaining_pixels).unwrap_or(usize::MAX));
                if jpeg_limits.frame.maximum_pixels == 0 {
                    return Err(refused(
                        segment,
                        "whole-recording JPEG pixel allowance exhausted",
                    ));
                }
                let image = decode_rgb(
                    &bytes,
                    capsule.source_digest.bytes(),
                    request.interpretation,
                    jpeg_limits,
                    &mut jpeg,
                )
                .map_err(frame_error(segment))?;
                charge_pixels(&mut usage, image.dimensions(), limits, segment)?;
                let frame =
                    DecodedFrame::jpeg(segment, capsule, capsule_digest, image, privacy.clone())?;
                frames.push(run.infer(frame)?);
                seen_selected.insert(segment);
            }
            usage.source_chunk_bytes = cursor.bytes_read();
        }
        "annexb" | "mp4avc" | "mkvavc" | "hevc" | "mp4hevc" | "mkvhevc" => {
            // The tolerant source is an existing streaming primitive, but this operation admits
            // no recovery. Refuse known gaps before decoding and every runtime Break below.
            if let Some(segment) = (first + 1..end)
                .find(|segment| retained.manifest().segment_spans[*segment].gap_before)
            {
                return Err(refused(
                    segment,
                    "source gap inside strict sentinel video range",
                ));
            }
            let source_budget = SourceReadBudget::new(limits.maximum_source_chunk_bytes);
            let video_budget = RecordedVideoDecodeBudget::with_separate_limits(
                limits.maximum_source_chunk_bytes,
                limits.maximum_pixel_samples,
            )
            .map_err(frame_error(first))?;
            let source_request = TolerantRequest {
                import_identity: request.import_identity,
                interpretation: request.interpretation,
                first_segment: first,
                end,
                read_limits: limits.package.read,
                jpeg_limits: limits.package.jpeg.frame,
                h264_limits: limits.package.h264,
                h265_limits: limits.package.h265,
                stream: true,
            };
            let mut source = TolerantSource::open_with_budgets(
                deployment,
                source_request,
                &source_budget,
                video_budget,
                cx,
            )
            .map_err(frame_error(first))?;
            source.select_rgb(&selected).map_err(frame_error(first))?;
            let mut seen_video = BTreeSet::new();
            loop {
                checkpoint(cx, scalar, "long_sentinel:video")?;
                let Some(item) = source
                    .next(deployment, &mut jpeg, cx)
                    .map_err(frame_error(first))?
                else {
                    break;
                };
                match item {
                    TolerantItem::Break(refusal) => {
                        let segment = refusal.as_ref().map_or(first, |value| value.first_segment);
                        return Err(refused(
                            segment,
                            "native video decode refused part of the sentinel range",
                        ));
                    }
                    TolerantItem::Frame(frame) => {
                        let segment = frame.segment;
                        if segment < first
                            || segment >= end
                            || !seen_video.insert(segment)
                            || frame.capsule.sensor_id != first_capsule.sensor_id
                        {
                            return Err(refused(
                                segment,
                                "native video source identity was repeated or changed",
                            ));
                        }
                        charge_pixels(&mut usage, frame.dimensions, limits, segment)?;
                        let color = source.take_rgb();
                        if selected.contains(&segment) {
                            let color = color.ok_or_else(|| {
                                refused(segment, "selected native RGB picture is missing")
                            })?;
                            if color.segment != segment || !seen_selected.insert(segment) {
                                return Err(refused(
                                    segment,
                                    "selected native RGB picture identity disagrees",
                                ));
                            }
                            let decoded = color.frame?;
                            if decoded.segment != segment
                                || decoded.capsule_digest != frame.capsule_digest
                                || decoded.dimensions != frame.dimensions
                                || decoded.mask != privacy
                            {
                                return Err(refused(
                                    segment,
                                    "selected RGB source or privacy binding disagrees",
                                ));
                            }
                            frames.push(run.infer(decoded)?);
                        } else if color.is_some() {
                            return Err(refused(segment, "unscheduled RGB picture was returned"));
                        }
                    }
                }
            }
            usage.source_chunk_bytes = source_budget.used();
            let budget = source
                .video_budget()
                .ok_or(PackageDetectError::InvalidRequest)?;
            usage.video_encoded_bytes = budget.encoded_bytes();
            usage.video_coded_luma_capacity = budget.coded_luma_capacity();
            usage.video_decode_work_units = budget.used();
        }
        _ => return Err(PackageDetectError::InvalidRequest),
    }
    if seen_selected != selected || frames.len() != reservation.inferences {
        return Err(refused(
            first,
            "one or more scheduled native pictures are missing",
        ));
    }
    usage.jpeg_work_units = jpeg.used();
    usage.detection_work_units = run.budget.used();
    usage.inferences = frames.len();
    for frame in &frames {
        usage.preprocess_work = usage
            .preprocess_work
            .checked_add(frame.inference.preprocess_work())
            .ok_or(PackageDetectError::InvalidRequest)?;
        usage.execution_macs = usage
            .execution_macs
            .checked_add(frame.inference.executed_macs())
            .ok_or(PackageDetectError::InvalidRequest)?;
    }
    if usage.source_chunk_bytes > reservation.source_chunk_bytes
        || usage.pixel_samples > reservation.pixel_samples
        || usage.video_encoded_bytes > reservation.video_encoded_bytes
        || usage.video_coded_luma_capacity > reservation.video_coded_luma_capacity
        || usage.video_decode_work_units > reservation.video_decode_work_units
        || usage.jpeg_work_units > reservation.jpeg_work_units
        || usage.detection_work_units > reservation.detection_work_units
        || usage.preprocess_work > reservation.preprocess_macs
        || usage.execution_macs > reservation.execution_macs
    {
        return Err(PackageDetectError::InvalidRequest);
    }
    checkpoint(cx, scalar, "long_sentinel:drained")?;
    let report = super::report::build_report(
        package,
        request,
        limits,
        contract,
        import_root,
        media_format,
        privacy,
        frames,
        plan,
        reservation,
        usage,
    )?;
    source_owner(deployment, cx, first)?;
    checkpoint(cx, scalar, "long_sentinel:complete")?;
    Ok(report)
}

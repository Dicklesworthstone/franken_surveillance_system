#![forbid(unsafe_code)]
//! Explicit native whole-recording watch configuration; no detector or tracker substitute.

use std::collections::BTreeMap;

use fss_cli::agent_json::{array, object, string};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchOptions, WatchTrackerConfig, WatchZone,
};
use fss_reference::ingest::rtsp_selected_watch::{
    RtspSelectedWatchLimits, RtspSelectedWatchPlan, RtspWatchSelection,
};

pub(super) const ALLOWED: &[&str] = &[
    "--interpretation",
    "--work-units",
    "--stream-read-bytes",
    "--stream-pixel-budget",
    "--stream-assignment-work",
    "--stream-trace-bytes",
    "--max-dimension",
    "--max-pixels",
    "--max-segment-bytes",
    "--pixel-threshold",
    "--threshold-sigma",
    "--learning-rate-num",
    "--learning-rate-den",
    "--min-region-pixels",
    "--confirmation-hits",
    "--maximum-missed-frames",
    "--minimum-iou-ppm",
    "--screened",
    "--tolerate-decode-refusals",
];

pub(super) fn number(
    values: &BTreeMap<&str, &str>,
    key: &str,
    default: u64,
    low: u64,
    high: u64,
) -> Result<u64, &'static str> {
    let n = match values.get(key).copied() {
        None => default,
        Some(text) if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => {
            text.parse().map_err(|_| "integer overflow")?
        }
        Some(_) => return Err("unsigned decimal integer required"),
    };
    if !(low..=high).contains(&n) {
        return Err("numeric bound exceeded");
    }
    Ok(n)
}

pub(super) fn zone(text: &str) -> Result<WatchZone, &'static str> {
    let (id, geometry) = text.split_once(':').ok_or("zone must be ID:X,Y,W,H")?;
    let parts = geometry
        .split(',')
        .map(|part| {
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err("unsigned zone coordinate required");
            }
            part.parse::<u32>().map_err(|_| "zone coordinate overflow")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let [x, y, width, height] = parts.as_slice() else {
        return Err("zone needs four coordinates");
    };
    Ok(WatchZone {
        zone_id: id.into(),
        x: *x,
        y: *y,
        width: *width,
        height: *height,
    })
}

pub(super) fn configure(
    values: &BTreeMap<&str, &str>,
    zones: Vec<WatchZone>,
    selections: Vec<RtspWatchSelection>,
) -> Result<(RtspSelectedWatchPlan, RtspSelectedWatchLimits), &'static str> {
    let (mut plan, limits) = configure_unselected(values, zones)?;
    plan.selections = selections;
    plan.digest(&limits).map_err(
        |_| "invalid native selection, timing, watch configuration or aggregate reservation",
    )?;
    Ok((plan, limits))
}

/// Pure shared native watch settings. The caller must bind and validate its own complete
/// selection before execution; an empty template is not an executable selected-watch plan.
pub(super) fn configure_unselected(
    values: &BTreeMap<&str, &str>,
    zones: Vec<WatchZone>,
) -> Result<(RtspSelectedWatchPlan, RtspSelectedWatchLimits), &'static str> {
    if values.get("--interpretation").copied() != Some("ycbcr") {
        return Err("explicit --interpretation ycbcr required for native AVC/HEVC watch");
    }
    let n = |key, default, low, high| number(values, key, default, low, high);
    let flag = |key| match values.get(key).copied().unwrap_or("no") {
        "yes" => Ok(true),
        "no" => Ok(false),
        _ => Err("boolean option requires yes or no"),
    };
    let mut limits = RtspSelectedWatchLimits::default();
    limits.maximum_report_bytes = n(
        "--max-report-bytes",
        limits.maximum_report_bytes as u64,
        1,
        16 * 1024 * 1024 + 65536,
    )? as usize;
    let watch = &mut limits.watch;
    watch.decode.jpeg_work_units = n(
        "--work-units",
        watch.decode.jpeg_work_units,
        1,
        1_000_000_000_000_000,
    )?;
    watch.decode.read_limits.max_segment_bytes = n(
        "--max-segment-bytes",
        watch.decode.read_limits.max_segment_bytes,
        1,
        16 * 1024 * 1024,
    )?;
    let dimension = n("--max-dimension", 4096, 16, 4096)? as u32;
    let pixels = n("--max-pixels", 4_194_304, 256, 4_194_304)? as usize;
    watch.decode.jpeg_limits.maximum_dimension = dimension;
    watch.decode.jpeg_limits.maximum_pixels = pixels;
    watch.decode.h264_limits.max_width = dimension;
    watch.decode.h264_limits.max_height = dimension;
    // AVC admits complete coded macroblocks. Round down so even a non-multiple input
    // cannot allocate or decode more coded luma pixels than the owner's exact ceiling.
    watch.decode.h264_limits.max_macroblocks = (pixels / 256) as u32;
    watch.decode.h265_limits.max_width = dimension;
    watch.decode.h265_limits.max_height = dimension;
    watch.decode.h265_limits.max_luma_samples = pixels as u64;
    watch.maximum_source_chunk_bytes = n(
        "--stream-read-bytes",
        watch.maximum_source_chunk_bytes,
        1,
        512 * 1024 * 1024,
    )?;
    watch.maximum_pixel_samples = n(
        "--stream-pixel-budget",
        watch.maximum_pixel_samples,
        1,
        u64::MAX,
    )?;
    watch.maximum_assignment_work = n(
        "--stream-assignment-work",
        watch.maximum_assignment_work,
        1,
        u64::MAX,
    )?;
    watch.maximum_trace_bytes = n(
        "--stream-trace-bytes",
        watch.maximum_trace_bytes as u64,
        1,
        8 * 1024 * 1024,
    )? as usize;
    let d = WatchDetectorConfig::default();
    let detector = WatchDetectorConfig {
        base_threshold: n(
            "--pixel-threshold",
            u64::from(d.base_threshold),
            0,
            u16::MAX as u64,
        )? as u16,
        threshold_sigma: n(
            "--threshold-sigma",
            u64::from(d.threshold_sigma),
            0,
            u16::MAX as u64,
        )? as u16,
        learning_rate_num: n(
            "--learning-rate-num",
            u64::from(d.learning_rate_num),
            0,
            u16::MAX as u64,
        )? as u16,
        learning_rate_den: n(
            "--learning-rate-den",
            u64::from(d.learning_rate_den),
            1,
            u16::MAX as u64,
        )? as u16,
        minimum_region_pixels: n(
            "--min-region-pixels",
            d.minimum_region_pixels as u64,
            1,
            4_194_304,
        )? as usize,
    };
    let t = WatchTrackerConfig::default();
    let tracker = WatchTrackerConfig {
        confirmation_hits: n(
            "--confirmation-hits",
            u64::from(t.confirmation_hits),
            1,
            u32::MAX as u64,
        )? as u32,
        maximum_missed_frames: n(
            "--maximum-missed-frames",
            u64::from(t.maximum_missed_frames),
            0,
            u32::MAX as u64,
        )? as u32,
        minimum_iou_ppm: n(
            "--minimum-iou-ppm",
            u64::from(t.minimum_iou_ppm),
            0,
            1_000_000,
        )? as u32,
    };
    let plan = RtspSelectedWatchPlan {
        selections: Vec::new(),
        interpretation: ComponentInterpretation::YCbCr,
        zones,
        detector,
        tracker,
        options: WatchOptions {
            tolerate_decode_refusals: flag("--tolerate-decode-refusals")?,
        },
        screened: flag("--screened")?,
    };
    Ok((plan, limits))
}

pub(super) fn configuration_json(
    plan: &RtspSelectedWatchPlan,
    limits: &RtspSelectedWatchLimits,
) -> String {
    let d = plan.detector;
    let t = plan.tracker;
    let w = limits.watch;
    object(&[
        ("interpretation", string("ycbcr")),
        (
            "zones",
            array(
                &plan
                    .zones
                    .iter()
                    .map(|zone| {
                        object(&[
                            ("id", string(&zone.zone_id)),
                            ("x", zone.x.to_string()),
                            ("y", zone.y.to_string()),
                            ("width", zone.width.to_string()),
                            ("height", zone.height.to_string()),
                        ])
                    })
                    .collect::<Vec<_>>(),
            ),
        ),
        (
            "detector",
            object(&[
                ("base_threshold", d.base_threshold.to_string()),
                ("threshold_sigma", d.threshold_sigma.to_string()),
                ("learning_rate_num", d.learning_rate_num.to_string()),
                ("learning_rate_den", d.learning_rate_den.to_string()),
                ("minimum_region_pixels", d.minimum_region_pixels.to_string()),
            ]),
        ),
        (
            "tracker",
            object(&[
                ("confirmation_hits", t.confirmation_hits.to_string()),
                ("maximum_missed_frames", t.maximum_missed_frames.to_string()),
                ("minimum_iou_ppm", t.minimum_iou_ppm.to_string()),
            ]),
        ),
        (
            "tolerate_decode_refusals",
            plan.options.tolerate_decode_refusals.to_string(),
        ),
        ("screened", plan.screened.to_string()),
        (
            "budgets_apply",
            string("per_selection_reserved_before_source_io"),
        ),
        ("work_units", w.decode.jpeg_work_units.to_string()),
        (
            "source_chunk_bytes",
            w.maximum_source_chunk_bytes.to_string(),
        ),
        ("pixel_samples", w.maximum_pixel_samples.to_string()),
        ("assignment_work", w.maximum_assignment_work.to_string()),
        ("trace_bytes", w.maximum_trace_bytes.to_string()),
        (
            "maximum_dimension",
            w.decode.jpeg_limits.maximum_dimension.to_string(),
        ),
        (
            "maximum_pixels",
            w.decode.jpeg_limits.maximum_pixels.to_string(),
        ),
        (
            "avc_coded_pixel_ceiling",
            (u64::from(w.decode.h264_limits.max_macroblocks) * 256).to_string(),
        ),
        (
            "hevc_coded_pixel_ceiling",
            w.decode.h265_limits.max_luma_samples.to_string(),
        ),
        (
            "maximum_segment_bytes",
            w.decode.read_limits.max_segment_bytes.to_string(),
        ),
    ])
}

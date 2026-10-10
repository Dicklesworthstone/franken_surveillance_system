#![forbid(unsafe_code)]
//! Exact native watch reruns: the import authority never becomes event authority.

use fss_cli::agent_json::{object, string};
use fss_core::ContentDigest;
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::WatchPlan;

use super::plan::Options;

fn quote(argument: &str) -> String {
    if !argument.is_empty()
        && argument
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:,./=@+".contains(&b))
    {
        argument.to_owned()
    } else {
        format!("'{}'", argument.replace('\'', "'\\''"))
    }
}

fn interpretation(options: &Options) -> &'static str {
    match options.plan.interpretation {
        ComponentInterpretation::Grayscale => "gray",
        ComponentInterpretation::YCbCr => "ycbcr",
    }
}

/// The exact shared watch configuration, expressed in existing fss-event watch options.
fn configuration(options: &Options) -> Vec<(&'static str, String)> {
    let p = &options.plan;
    let l = &options.limits.watch;
    let mut args = vec![
        ("--interpretation", interpretation(options).into()),
        ("--pixel-threshold", p.detector.base_threshold.to_string()),
        ("--threshold-sigma", p.detector.threshold_sigma.to_string()),
        (
            "--learning-rate-num",
            p.detector.learning_rate_num.to_string(),
        ),
        (
            "--learning-rate-den",
            p.detector.learning_rate_den.to_string(),
        ),
        (
            "--min-region-pixels",
            p.detector.minimum_region_pixels.to_string(),
        ),
        (
            "--confirmation-hits",
            p.tracker.confirmation_hits.to_string(),
        ),
        (
            "--maximum-missed-frames",
            p.tracker.maximum_missed_frames.to_string(),
        ),
        ("--minimum-iou-ppm", p.tracker.minimum_iou_ppm.to_string()),
        ("--work-units", l.decode.jpeg_work_units.to_string()),
        (
            "--max-dimension",
            l.decode.jpeg_limits.maximum_dimension.to_string(),
        ),
        (
            "--max-pixels",
            l.decode.jpeg_limits.maximum_pixels.to_string(),
        ),
        (
            "--max-segment-bytes",
            l.decode.read_limits.max_segment_bytes.to_string(),
        ),
        (
            "--stream-read-bytes",
            l.maximum_source_chunk_bytes.to_string(),
        ),
        ("--stream-pixel-budget", l.maximum_pixel_samples.to_string()),
        (
            "--stream-assignment-work",
            l.maximum_assignment_work.to_string(),
        ),
        ("--stream-trace-bytes", l.maximum_trace_bytes.to_string()),
    ];
    for zone in &p.zones {
        args.push((
            "--zone",
            format!(
                "{}:{},{},{},{}",
                zone.zone_id, zone.x, zone.y, zone.width, zone.height
            ),
        ));
    }
    if p.screened {
        args.push(("--sensor-health", "conservative-v1".into()));
    }
    args
}

pub(super) fn configuration_json(options: &Options) -> String {
    let values = configuration(options)
        .iter()
        .map(|(key, value)| object(&[("option", string(key)), ("value", string(value))]))
        .collect::<Vec<_>>()
        .join(",");
    object(&[
        ("mode", string("stream-watch")),
        ("options", format!("[{values}]")),
        (
            "tolerate_decode_refusals",
            options.plan.options.tolerate_decode_refusals.to_string(),
        ),
        (
            "budgets_apply",
            string("per_generation_reserved_before_history_io"),
        ),
    ])
}

fn command(
    options: &Options,
    import: ContentDigest,
    first: usize,
    count: usize,
) -> Result<String, &'static str> {
    let mut args = vec!["fss-event".into(), "watch".into(), "--stream-watch".into()];
    for (key, value) in [
        (
            "--root",
            options
                .root
                .to_str()
                .ok_or("UTF-8 path required")?
                .to_owned(),
        ),
        ("--site", options.site.clone()),
        ("--principal", options.principal.clone()),
        ("--import-id", import.to_text()),
        ("--first-segment", first.to_string()),
        ("--segment-count", count.to_string()),
    ]
    .into_iter()
    .chain(configuration(options))
    {
        args.push(quote(key));
        args.push(quote(&value));
    }
    if options.plan.options.tolerate_decode_refusals {
        args.push("--tolerate-decode-refusals".into());
    }
    let text = args.join(" ");
    if text.len() > 8192 {
        return Err("ERR-HTTP-HISTORY-WATCH-LIMIT-001");
    }
    Ok(text)
}

pub(super) fn preview_bound(options: &Options) -> Result<(), &'static str> {
    command(
        options,
        ContentDigest::sha256(b"history-watch-command-capacity"),
        0,
        options.limits.maximum_frames_per_generation,
    )
    .map(|_| ())
}

pub(super) fn watch_command(options: &Options, plan: &WatchPlan) -> Result<String, &'static str> {
    if plan.interpretation != options.plan.interpretation
        || plan.zones != options.plan.zones
        || plan.detector != options.plan.detector
        || plan.tracker != options.plan.tracker
        || plan.first_segment != 0
        || plan.segment_count == 0
        || plan.segment_count > options.limits.maximum_frames_per_generation
    {
        return Err("ERR-HTTP-HISTORY-WATCH-REQUEST-001");
    }
    command(
        options,
        plan.import_identity,
        plan.first_segment,
        plan.segment_count,
    )
}

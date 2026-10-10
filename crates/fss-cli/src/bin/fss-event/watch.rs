#![forbid(unsafe_code)]
//! `fss-event watch`: model-free single-camera candidates from a retained recording.
//!
//! Runs retained decode → foreground → Kalman tracker → zone gate through
//! `fss_reference::ingest::recorded_watch`. Without `--approve` it writes nothing to the
//! deployment and prints the JSON report with each candidate's exact proposal digest and the
//! rerun command that would publish it. With `--approve DIGEST[,DIGEST...]` it publishes only
//! those exact proposals as unclassified, indeterminate, single-sensor candidates through the
//! deployment's guarded event publisher; already-published candidates are never republished.
//! Every entry-mode report also proposes the run's coverage record; only `--retain-coverage`
//! with its exact approval digest retains it as authority.
//! `--detector-package PATH --detector-digest sha256:HEX --detector-max-inferences N` adds the
//! detection cascade: the verified package runs only on frames the cheap stage selected, and its
//! uncalibrated class evidence is attached to each candidate without changing its kind or state.
//! `--tolerate-decode-refusals` (a bare flag, echoed in every rerun command) turns a typed decode
//! refusal or source gap inside the range into a `decode_refused` coverage interval with its
//! error id instead of refusing the run: H.264/H.265 resume at the next IDR/IRAP and tracking
//! restarts after the gap. Without the flag the refusal is exactly today's.
//! `--dwell-for-ns N --dwell-max-gap-ns N [--dwell-min-observations N]` instead evaluates
//! sustained actual zone observations. It uses the same pipeline once, emits separately approved
//! dwell hypotheses, and refuses coverage retention: entry coverage is not dwell-absence proof.
//! Add `--stream-dwell` for one whole MJPEG, H.264 or H.265 (Annex-B or MP4) range (up to 65536
//! segments; inter-coded frames in display order), with persistent
//! foreground/tracker state and aggregate source-byte, pixel, assignment and trace ceilings.
//! This mode refuses detector-package flags rather than silently dropping a requested model.
//! `--sensor-health conservative-v1` additionally screens the same masked pixels in entry
//! mode. Suspect runs cannot contribute candidates or coverage witnesses. Whole-recording
//! `--stream-dwell` uses its existing whole-scan publication gate instead; short dwell is refused.
//! `--stream-watch` instead scans one whole bounded recording for actual confirmed zone entries,
//! preserving tracker state across the old 128-frame boundary. It uses its own approval identity,
//! aggregate `--stream-*` budgets, and the same optional whole-scan health gate. It has no dwell
//! rule, coverage-retention or alert authority. The same explicit detector-package options
//! select native RGB inference at entries and following actual track matches; the complete
//! recording shares one inference allowance and retains the verified package for cold replay.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

use fss_core::{ContentDigest, DigestAlgorithm, PrincipalId};
use fss_reference::ingest::RetainedFileImport;
use fss_reference::ingest::detector_cascade::DetectorCascade;
use fss_reference::ingest::long_dwell::{LongDwellLimits, LongDwellReport, MAX_LONG_DWELL_FRAMES};
use fss_reference::ingest::long_watch::{
    LongWatchDetector, LongWatchLimits, LongWatchReport, MAX_LONG_WATCH_FRAMES,
};
use fss_reference::ingest::package_detect::PackageDetectLimits;
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_dwell::DwellReport;
use fss_reference::ingest::recorded_health::RecordedHealthPolicy;
use fss_reference::ingest::recorded_watch::{
    MAX_WATCH_FRAMES, MAX_WATCH_ZONES, WatchDetectorConfig, WatchError, WatchLimits, WatchOptions,
    WatchPlan, WatchReport, WatchTrackerConfig, WatchZone,
};
use fss_reference::ingest::sensor_health::POLICY_NAME as HEALTH_POLICY_NAME;
use fss_reference::ingest::zone_dwell::DwellPolicy;
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};

use super::{RunResult, export};

const OPTIONS: &[&str] = &[
    "--root",
    "--site",
    "--principal",
    "--import-id",
    "--interpretation",
    "--first-segment",
    "--segment-count",
    "--pixel-threshold",
    "--threshold-sigma",
    "--learning-rate-num",
    "--learning-rate-den",
    "--min-region-pixels",
    "--confirmation-hits",
    "--maximum-missed-frames",
    "--minimum-iou-ppm",
    "--work-units",
    "--max-dimension",
    "--max-pixels",
    "--max-segment-bytes",
    "--approve",
    "--retain-coverage",
    "--report-out",
    "--dwell-for-ns",
    "--dwell-max-gap-ns",
    "--dwell-min-observations",
    "--dwell-read-bytes",
    "--dwell-pixel-budget",
    "--dwell-assignment-work",
    "--dwell-trace-bytes",
    "--stream-read-bytes",
    "--stream-pixel-budget",
    "--stream-assignment-work",
    "--stream-trace-bytes",
    "--sensor-health",
];

const STREAM_BUDGET_OPTIONS: &[&str] = &[
    "--dwell-read-bytes",
    "--dwell-pixel-budget",
    "--dwell-assignment-work",
    "--dwell-trace-bytes",
];

const STREAM_WATCH_BUDGET_OPTIONS: &[&str] = &[
    "--stream-read-bytes",
    "--stream-pixel-budget",
    "--stream-assignment-work",
    "--stream-trace-bytes",
];

/// Fully parsed watch request; nothing here is authority until `run` validates it.
#[derive(Debug)]
pub(super) struct WatchAction {
    pub(super) root: PathBuf,
    pub(super) site: String,
    pub(super) principal: String,
    import: ContentDigest,
    interpretation: ComponentInterpretation,
    zones: Vec<WatchZone>,
    first_segment: usize,
    segment_count: Option<usize>,
    detector: WatchDetectorConfig,
    tracker: WatchTrackerConfig,
    limits: WatchLimits,
    approvals: BTreeSet<ContentDigest>,
    retain_coverage: Option<ContentDigest>,
    report_out: Option<PathBuf>,
    cascade: Option<super::detector::DetectorOptions>,
    options: WatchOptions,
    dwell: Option<DwellPolicy>,
    stream_dwell: Option<LongDwellLimits>,
    stream_watch: Option<LongWatchLimits>,
    health_screen: bool,
    rerun: String,
}

fn number<T: std::str::FromStr>(
    values: &[(String, String)],
    key: &str,
    default: T,
) -> Result<T, String> {
    match values.iter().find(|(k, _)| k == key) {
        None => Ok(default),
        Some((_, value)) => value
            .parse()
            .map_err(|_| format!("invalid numeric value for {key}")),
    }
}

fn text<'a>(values: &'a [(String, String)], key: &str) -> Result<&'a str, String> {
    values
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
        .ok_or_else(|| format!("required option {key}"))
}

fn digest(value: &str, key: &str) -> Result<ContentDigest, String> {
    let parsed = ContentDigest::parse(value).map_err(|_| format!("invalid digest for {key}"))?;
    if parsed.algorithm() != DigestAlgorithm::Sha256 {
        return Err(format!("{key} requires SHA-256"));
    }
    Ok(parsed)
}

fn zone(value: &str) -> Result<WatchZone, String> {
    let (id, geometry) = value
        .split_once(':')
        .ok_or("zone must be ID:X,Y,W,H in decoded pixels")?;
    if geometry.contains(':') {
        return Err("zone kinds are not accepted: every candidate is unclassified".to_owned());
    }
    let parts: Vec<u32> = geometry
        .split(',')
        .map(str::parse)
        .collect::<Result<_, _>>()
        .map_err(|_| "zone geometry must be four unsigned integers X,Y,W,H")?;
    let [x, y, width, height] = parts[..] else {
        return Err("zone geometry must be four unsigned integers X,Y,W,H".to_owned());
    };
    Ok(WatchZone {
        zone_id: id.to_owned(),
        x,
        y,
        width,
        height,
    })
}

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

fn dwell_policy(values: &[(String, String)]) -> Result<Option<DwellPolicy>, String> {
    let has = |key| values.iter().any(|(name, _)| name == key);
    if !has("--dwell-for-ns") && !has("--dwell-max-gap-ns") && !has("--dwell-min-observations") {
        return Ok(None);
    }
    if !has("--dwell-for-ns") || !has("--dwell-max-gap-ns") {
        return Err("dwell requires both --dwell-for-ns and --dwell-max-gap-ns".to_owned());
    }
    if has("--retain-coverage") {
        return Err(
            "dwell refuses --retain-coverage: entry coverage does not certify dwell absence"
                .to_owned(),
        );
    }
    let rule = DwellPolicy {
        minimum_duration_ns: number(values, "--dwell-for-ns", 0_u64)?,
        maximum_sample_gap_ns: number(values, "--dwell-max-gap-ns", 0_u64)?,
        minimum_observations: number(values, "--dwell-min-observations", 2_usize)?,
    };
    rule.validate().map_err(|e| e.to_string())?;
    Ok(Some(rule))
}

/// Parses the arguments after `watch`. Every option takes one separate value; only `--zone`
/// repeats. Paths must be UTF-8 here because the report echoes an exact rerun command.
pub(super) fn parse(args: &[OsString]) -> Result<WatchAction, String> {
    let mut values: Vec<(String, String)> = Vec::new();
    let mut zones = Vec::new();
    let mut rerun = vec!["fss-event".to_owned(), "watch".to_owned()];
    let mut options = WatchOptions::default();
    let mut stream_dwell = false;
    let mut stream_watch = false;
    let mut index = 0;
    while index < args.len() {
        let key = args[index].to_str().ok_or("option names require UTF-8")?;
        if key == "--stream-watch" {
            if stream_watch {
                return Err("duplicate --stream-watch".to_owned());
            }
            stream_watch = true;
            rerun.push(key.to_owned());
            index += 1;
            continue;
        }
        if key == "--stream-dwell" {
            if stream_dwell {
                return Err("duplicate --stream-dwell".to_owned());
            }
            stream_dwell = true;
            rerun.push(key.to_owned());
            index += 1;
            continue;
        }
        if key == "--tolerate-decode-refusals" {
            if options.tolerate_decode_refusals {
                return Err("duplicate --tolerate-decode-refusals".to_owned());
            }
            options.tolerate_decode_refusals = true;
            rerun.push(key.to_owned());
            index += 1;
            continue;
        }
        let argument = args
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {key}"))?
            .to_str()
            .ok_or_else(|| format!("{key} requires a UTF-8 value"))?;
        if argument.is_empty() || argument.starts_with("--") {
            return Err(format!("missing value for {key}"));
        }
        if key == "--zone" {
            if zones.len() == MAX_WATCH_ZONES {
                return Err("at most sixteen zones".to_owned());
            }
            zones.push(zone(argument)?);
        } else if !OPTIONS.contains(&key) && !super::detector::OPTIONS.contains(&key) {
            return Err("unknown or inapplicable option".to_owned());
        } else if values.iter().any(|(k, _)| k == key) {
            return Err(format!("duplicate {key}"));
        } else {
            values.push((key.to_owned(), argument.to_owned()));
        }
        if key != "--approve" && key != "--retain-coverage" && key != "--report-out" {
            rerun.push(quote(key));
            rerun.push(quote(argument));
        }
        index += 2;
    }
    let health_screen = match text(&values, "--sensor-health") {
        Ok(value) if value != HEALTH_POLICY_NAME => {
            return Err(format!(
                "--sensor-health requires policy {HEALTH_POLICY_NAME}"
            ));
        }
        Ok(_) => true,
        Err(_) => false,
    };
    if zones.is_empty() {
        return Err("at least one --zone ID:X,Y,W,H is required".to_owned());
    }
    let site = text(&values, "--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| "invalid site lineage")?;
    let principal = match text(&values, "--principal") {
        Ok(value) => value.to_owned(),
        Err(_) => "principal:local-operator".to_owned(),
    };
    PrincipalId::parse(&principal).map_err(|_| "invalid principal ID")?;
    let interpretation = match text(&values, "--interpretation")? {
        "gray" => ComponentInterpretation::Grayscale,
        "ycbcr" => ComponentInterpretation::YCbCr,
        _ => return Err("interpretation must be explicitly gray or ycbcr".to_owned()),
    };
    let segment_count = match text(&values, "--segment-count") {
        Ok(_) => Some(number(&values, "--segment-count", 0_usize)?),
        Err(_) => None,
    };
    if stream_watch && (stream_dwell || values.iter().any(|(key, _)| key.starts_with("--dwell-"))) {
        return Err(
            "--stream-watch cannot be combined with --stream-dwell or dwell options".to_owned(),
        );
    }
    let maximum_frames = if stream_watch {
        MAX_LONG_WATCH_FRAMES
    } else if stream_dwell {
        MAX_LONG_DWELL_FRAMES
    } else {
        MAX_WATCH_FRAMES
    };
    if segment_count.is_some_and(|count| count == 0 || count > maximum_frames) {
        return Err(format!("segment count must be 1..{maximum_frames}"));
    }
    let defaults = WatchDetectorConfig::default();
    let detector = WatchDetectorConfig {
        base_threshold: number(&values, "--pixel-threshold", defaults.base_threshold)?,
        threshold_sigma: number(&values, "--threshold-sigma", defaults.threshold_sigma)?,
        learning_rate_num: number(&values, "--learning-rate-num", defaults.learning_rate_num)?,
        learning_rate_den: number(&values, "--learning-rate-den", defaults.learning_rate_den)?,
        minimum_region_pixels: number(
            &values,
            "--min-region-pixels",
            defaults.minimum_region_pixels,
        )?,
    };
    let defaults = WatchTrackerConfig::default();
    let tracker = WatchTrackerConfig {
        confirmation_hits: number(&values, "--confirmation-hits", defaults.confirmation_hits)?,
        maximum_missed_frames: number(
            &values,
            "--maximum-missed-frames",
            defaults.maximum_missed_frames,
        )?,
        minimum_iou_ppm: number(&values, "--minimum-iou-ppm", defaults.minimum_iou_ppm)?,
    };
    let mut limits = WatchLimits::default();
    limits.jpeg_work_units = number(&values, "--work-units", limits.jpeg_work_units)?;
    limits.read_limits.max_segment_bytes = number(
        &values,
        "--max-segment-bytes",
        limits.read_limits.max_segment_bytes,
    )?;
    let dimension: u32 = number(&values, "--max-dimension", 4096)?;
    let pixels: usize = number(&values, "--max-pixels", 4_194_304)?;
    if !(16..=4096).contains(&dimension) || pixels == 0 || pixels > 4_194_304 {
        return Err("codec limits: dimension 16..4096, pixels 1..4194304".to_owned());
    }
    limits.jpeg_limits.maximum_dimension = dimension;
    limits.jpeg_limits.maximum_pixels = pixels;
    limits.h264_limits.max_width = dimension;
    limits.h264_limits.max_height = dimension;
    limits.h264_limits.max_macroblocks =
        u32::try_from(pixels.div_ceil(256)).map_err(|_| "pixel ceiling")?;
    limits.h265_limits.max_width = dimension;
    limits.h265_limits.max_height = dimension;
    limits.h265_limits.max_luma_samples = pixels as u64;
    let mut approvals = BTreeSet::new();
    if let Ok(list) = text(&values, "--approve") {
        for item in list.split(',') {
            if !approvals.insert(digest(item, "--approve")?) {
                return Err("duplicate approval digest".to_owned());
            }
        }
    }
    let dwell = dwell_policy(&values)?;
    if health_screen && dwell.is_some() && !stream_dwell {
        return Err(
            "--sensor-health with dwell requires --stream-dwell; short dwell screening is unsupported"
                .to_owned(),
        );
    }
    if stream_dwell && dwell.is_none() {
        return Err("--stream-dwell requires the explicit dwell duration and gap rule".to_owned());
    }
    let stream_dwell = streaming_limits(&values, stream_dwell, limits)?;
    let stream_watch = streaming_watch_limits(&values, stream_watch, limits)?;
    if stream_dwell.is_some() && (site.len() > 256 || principal.len() > 128) {
        return Err("long-dwell site or principal exceeds byte bound".to_owned());
    }
    if stream_watch.is_some() && (site.len() > 256 || principal.len() > 128) {
        return Err("streaming watch site or principal exceeds byte bound".to_owned());
    }
    let rerun = rerun.join(" ");
    if stream_dwell.is_some() && rerun.len() > 8192 {
        return Err("long-dwell rerun command exceeds byte bound".to_owned());
    }
    if stream_watch.is_some() && rerun.len() > 8192 {
        return Err("streaming watch rerun command exceeds byte bound".to_owned());
    }
    Ok(WatchAction {
        root: PathBuf::from(text(&values, "--root")?),
        site,
        principal,
        import: digest(text(&values, "--import-id")?, "--import-id")?,
        interpretation,
        zones,
        first_segment: number(&values, "--first-segment", 0)?,
        segment_count,
        detector,
        tracker,
        limits,
        approvals,
        retain_coverage: match text(&values, "--retain-coverage") {
            Ok(value) => Some(digest(value, "--retain-coverage")?),
            Err(_) => None,
        },
        report_out: values
            .iter()
            .find(|(k, _)| k == "--report-out")
            .map(|(_, v)| PathBuf::from(v)),
        cascade: super::detector::parse(&values)?,
        options,
        dwell,
        stream_dwell,
        stream_watch,
        health_screen,
        rerun,
    })
}

/// Analyze, optionally publish exactly the approved proposals, and print the JSON report.
pub(super) fn run(
    action: &WatchAction,
    deployment: &mut ReferenceDeployment,
    root: &Path,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    if let Some(limits) = &action.stream_watch {
        let scalar = ScalarExecCx::new();
        let result = run_streaming_watch(action, deployment, root, limits, cx, &scalar, out);
        scalar.drain_and_finalize();
        return result;
    }
    if let Some(limits) = &action.stream_dwell {
        return run_streaming(action, deployment, root, limits, cx, out);
    }
    if action.health_screen && action.dwell.is_some() {
        return Err(
            WatchError::InvalidPlan("short dwell sensor-health screening is unsupported").into(),
        );
    }
    let scalar = ScalarExecCx::new();
    let result = run_with(action, deployment, root, cx, &scalar, out);
    scalar.drain_and_finalize();
    result
}

fn streaming_watch_limits(
    values: &[(String, String)],
    enabled: bool,
    decode: WatchLimits,
) -> Result<Option<LongWatchLimits>, String> {
    if !enabled {
        if values
            .iter()
            .any(|(key, _)| STREAM_WATCH_BUDGET_OPTIONS.contains(&key.as_str()))
        {
            return Err("aggregate streaming watch budgets require --stream-watch".to_owned());
        }
        return Ok(None);
    }
    if values.iter().any(|(key, _)| key == "--retain-coverage") {
        return Err("--stream-watch refuses --retain-coverage: no whole-recording absence certificate exists".to_owned());
    }
    let defaults = LongWatchLimits::default();
    let limits = LongWatchLimits {
        decode,
        maximum_source_chunk_bytes: number(
            values,
            "--stream-read-bytes",
            defaults.maximum_source_chunk_bytes,
        )?,
        maximum_pixel_samples: number(
            values,
            "--stream-pixel-budget",
            defaults.maximum_pixel_samples,
        )?,
        maximum_assignment_work: number(
            values,
            "--stream-assignment-work",
            defaults.maximum_assignment_work,
        )?,
        maximum_trace_bytes: number(values, "--stream-trace-bytes", defaults.maximum_trace_bytes)?,
    };
    limits.validate().map_err(|error| error.to_string())?;
    Ok(Some(limits))
}

fn run_streaming_watch(
    action: &WatchAction,
    deployment: &mut ReferenceDeployment,
    root: &Path,
    limits: &LongWatchLimits,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
    out: &mut impl Write,
) -> RunResult<()> {
    if action.retain_coverage.is_some() || action.dwell.is_some() || action.stream_dwell.is_some() {
        return Err(
            WatchError::InvalidPlan("streaming watch has no dwell or coverage owner").into(),
        );
    }
    // Verify the requested package before reading any source. The same archive is retained
    // with an approved event so a cold replay needs neither this path nor a model download.
    let package = action
        .cascade
        .as_ref()
        .map(|options| super::detector::load_with_archive(options, cx, scalar))
        .transpose()?;
    let detector = match (&action.cascade, &package) {
        (Some(options), Some((package, archive))) => Some(LongWatchDetector::new(
            package,
            archive,
            options.config,
            PackageDetectLimits::default(),
            scalar,
        )?),
        _ => None,
    };
    let segment_count = match action.segment_count {
        Some(count) => count,
        None => {
            let retained =
                RetainedFileImport::open(deployment, action.import, limits.decode.read_limits, cx)
                    .map_err(WatchError::from)?;
            retained
                .manifest()
                .segment_spans
                .len()
                .checked_sub(action.first_segment)
                .filter(|count| (1..=MAX_LONG_WATCH_FRAMES).contains(count))
                .ok_or(WatchError::InvalidPlan(
                    "select a nonempty streaming watch range of at most 65536 segments",
                ))?
        }
    };
    let plan = WatchPlan {
        import_identity: action.import,
        interpretation: action.interpretation,
        first_segment: action.first_segment,
        segment_count,
        zones: action.zones.clone(),
        detector: action.detector,
        tracker: action.tracker,
    };
    let mut report = match &detector {
        Some(detector) => LongWatchReport::analyze_with_detector(
            deployment,
            &plan,
            action.options,
            limits,
            detector,
            action.health_screen,
            cx,
        )?,
        None if action.health_screen => {
            LongWatchReport::analyze_screened(deployment, &plan, action.options, limits, cx)?
        }
        None => LongWatchReport::analyze(deployment, &plan, action.options, limits, cx)?,
    };
    // Complete report and exact approval hints must fit before any event commitment.
    report.to_json(
        deployment.current_anchor().commit_sequence,
        Some(&action.rerun),
    )?;
    if !action.approvals.is_empty() {
        report.publish(deployment, &action.approvals, cx)?;
    }
    let json = format!(
        "{}\n",
        report.to_json(
            deployment.current_anchor().commit_sequence,
            Some(&action.rerun),
        )?
    );
    if let Some(path) = &action.report_out {
        export(path, json.as_bytes(), root, cx)?;
    }
    out.write_all(json.as_bytes())?;
    Ok(())
}

fn run_with(
    action: &WatchAction,
    deployment: &mut ReferenceDeployment,
    root: &Path,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
    out: &mut impl Write,
) -> RunResult<()> {
    // The package is verified (digest before parsing) before any source is read.
    let package = match &action.cascade {
        Some(options) => Some(super::detector::load(options, cx, scalar)?),
        None => None,
    };
    let mut cascade = match (&action.cascade, &package) {
        (Some(options), Some(package)) => Some(DetectorCascade::new(
            package,
            options.config,
            PackageDetectLimits::default(),
            scalar,
        )?),
        _ => None,
    };
    let segment_count = match action.segment_count {
        Some(count) => count,
        None => {
            let retained =
                RetainedFileImport::open(deployment, action.import, action.limits.read_limits, cx)
                    .map_err(WatchError::from)?;
            let available = retained
                .manifest()
                .segment_spans
                .len()
                .checked_sub(action.first_segment)
                .filter(|count| *count > 0)
                .ok_or(WatchError::InvalidPlan(
                    "first segment is beyond the recording",
                ))?;
            if available > MAX_WATCH_FRAMES {
                return Err(WatchError::InvalidPlan(
                    "recording has more than 128 frames after --first-segment; pass --segment-count",
                )
                .into());
            }
            available
        }
    };
    let plan = WatchPlan {
        import_identity: action.import,
        interpretation: action.interpretation,
        first_segment: action.first_segment,
        segment_count,
        zones: action.zones.clone(),
        detector: action.detector,
        tracker: action.tracker,
    };
    if let Some(rule) = action.dwell {
        let mut report = DwellReport::analyze(
            deployment,
            &plan,
            rule,
            &action.limits,
            cascade.as_mut(),
            action.options,
            cx,
        )?;
        // Bound the actual rerun hint and complete report before any event publication.
        report.to_json(
            deployment.current_anchor().commit_sequence,
            Some(&action.rerun),
        )?;
        if !action.approvals.is_empty() {
            report.publish(deployment, &action.approvals, cx)?;
        }
        let json = format!(
            "{}\n",
            report.to_json(
                deployment.current_anchor().commit_sequence,
                Some(&action.rerun),
            )?
        );
        if let Some(path) = &action.report_out {
            export(path, json.as_bytes(), root, cx)?;
        }
        out.write_all(json.as_bytes())?;
        return Ok(());
    }
    let mut report = WatchReport::analyze_with_health(
        deployment,
        &plan,
        &action.limits,
        cascade.as_mut(),
        action.options,
        action
            .health_screen
            .then_some(RecordedHealthPolicy::ConservativeV1),
        cx,
    )?;
    // Both approvals are checked against the fresh analysis before anything is written.
    if let Some(approval) = action.retain_coverage {
        report.check_coverage_approval(deployment, approval)?;
    }
    let published = if action.approvals.is_empty() {
        0
    } else {
        report.publish(deployment, &action.approvals, cx)?
    };
    if let Some(approval) = action.retain_coverage {
        report.retain_coverage(deployment, approval, cx)?;
    }
    // A coverage proposal binds the authority anchor its analysis read; after this run published
    // candidates, the proposal is recomputed against the new anchor so its approval is current.
    let reproposed = if published > 0 && action.retain_coverage.is_none() {
        // Same cascade instance: completed inferences are reused, never re-run.
        Some(WatchReport::analyze_with_health(
            deployment,
            &plan,
            &action.limits,
            cascade.as_mut(),
            action.options,
            action
                .health_screen
                .then_some(RecordedHealthPolicy::ConservativeV1),
            cx,
        )?)
    } else {
        None
    };
    let proposal = reproposed.as_ref().unwrap_or(&report);
    let coverage = super::coverage::render(
        &[proposal.coverage()],
        proposal.coverage_status(),
        proposal.coverage_approval(),
        &action.rerun,
    );
    let json = report.to_json_with_coverage(
        deployment.current_anchor().commit_sequence,
        Some(&action.rerun),
        Some(&coverage),
    );
    let json = format!("{json}\n");
    if let Some(path) = &action.report_out {
        export(path, json.as_bytes(), root, cx)?;
    }
    out.write_all(json.as_bytes())?;
    Ok(())
}

fn streaming_limits(
    values: &[(String, String)],
    enabled: bool,
    decode: WatchLimits,
) -> Result<Option<LongDwellLimits>, String> {
    if !enabled {
        if values
            .iter()
            .any(|(key, _)| STREAM_BUDGET_OPTIONS.contains(&key.as_str()))
        {
            return Err("aggregate dwell budgets require --stream-dwell".to_owned());
        }
        return Ok(None);
    }
    if values
        .iter()
        .any(|(key, _)| super::detector::OPTIONS.contains(&key.as_str()))
    {
        return Err("--stream-dwell does not admit detector-package options".to_owned());
    }
    let defaults = LongDwellLimits::default();
    let limits = LongDwellLimits {
        decode,
        maximum_source_chunk_bytes: number(
            values,
            "--dwell-read-bytes",
            defaults.maximum_source_chunk_bytes,
        )?,
        maximum_pixel_samples: number(
            values,
            "--dwell-pixel-budget",
            defaults.maximum_pixel_samples,
        )?,
        maximum_assignment_work: number(
            values,
            "--dwell-assignment-work",
            defaults.maximum_assignment_work,
        )?,
        maximum_trace_bytes: number(values, "--dwell-trace-bytes", defaults.maximum_trace_bytes)?,
    };
    limits.validate().map_err(|error| error.to_string())?;
    Ok(Some(limits))
}

fn run_streaming(
    action: &WatchAction,
    deployment: &mut ReferenceDeployment,
    root: &Path,
    limits: &LongDwellLimits,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    // Refuse inapplicable modes even when a future internal caller bypasses parse.
    if action.cascade.is_some() || action.retain_coverage.is_some() {
        return Err(
            WatchError::InvalidPlan("streaming dwell has no model or coverage owner").into(),
        );
    }
    let rule = action
        .dwell
        .ok_or(WatchError::InvalidPlan("streaming dwell requires a rule"))?;
    let segment_count = match action.segment_count {
        Some(count) => count,
        None => {
            let retained =
                RetainedFileImport::open(deployment, action.import, limits.decode.read_limits, cx)
                    .map_err(WatchError::from)?;
            retained
                .manifest()
                .segment_spans
                .len()
                .checked_sub(action.first_segment)
                .filter(|count| (1..=MAX_LONG_DWELL_FRAMES).contains(count))
                .ok_or(WatchError::InvalidPlan(
                    "select a nonempty long-dwell range of at most 65536 segments",
                ))?
        }
    };
    let plan = WatchPlan {
        import_identity: action.import,
        interpretation: action.interpretation,
        first_segment: action.first_segment,
        segment_count,
        zones: action.zones.clone(),
        detector: action.detector,
        tracker: action.tracker,
    };
    let analyze = if action.health_screen {
        LongDwellReport::analyze_screened
    } else {
        LongDwellReport::analyze
    };
    let mut report = analyze(deployment, &plan, rule, action.options, limits, cx)?;
    // No partial JSON or oversized approval hints can be discovered only after an event commit.
    report.to_json(
        deployment.current_anchor().commit_sequence,
        Some(&action.rerun),
    )?;
    if !action.approvals.is_empty() {
        report.publish(deployment, &action.approvals, cx)?;
    }
    let json = format!(
        "{}\n",
        report.to_json(
            deployment.current_anchor().commit_sequence,
            Some(&action.rerun),
        )?
    );
    if let Some(path) = &action.report_out {
        export(path, json.as_bytes(), root, cx)?;
    }
    out.write_all(json.as_bytes())?;
    Ok(())
}

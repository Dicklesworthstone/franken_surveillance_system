#![forbid(unsafe_code)]
//! `fss-event watch`: model-free single-camera candidates from a retained recording.
//!
//! Runs retained decode → foreground → Kalman tracker → zone gate through
//! `fss_reference::ingest::recorded_watch`. Ordinary previews write nothing to the deployment
//! without an event or retention approval. Explicit incremental steps retain a work checkpoint.
//! Unapproved entry and dwell previews use an immutable retained owner during active ingest and
//! share one aggregate read allowance through final source, privacy and authority validation.
//! The complete JSON report contains each candidate's exact proposal digest and the
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
//! Optional `--fusion-profile PATH --fusion-digest sha256:HEX` adds read-only calibrated
//! class advice to sampled-dwell episodes. Short and whole-recording dwell use distinct profiles,
//! each pinning the complete dwell analysis; only scores observed in that episode may contribute.
//! Neither an entry coverage record nor class advice certifies continuous occupancy or dwell absence.
//! Add `--stream-dwell` for one whole MJPEG, H.264 or H.265 (Annex-B or MP4) range (up to 65536
//! segments; inter-coded frames in display order), with persistent
//! foreground/tracker state and aggregate source-byte, pixel, assignment and trace ceilings.
//! Explicit detector-package flags classify bounded actual samples from qualifying dwell
//! episodes, sharing the whole-recording source/pixel/JPEG and model-work allowances.
//! `--sensor-health conservative-v1` additionally screens the same masked pixels in entry or
//! short sampled-dwell mode. Suspect observations interrupt dwell spans and cannot contribute
//! candidates or coverage witnesses. Whole-recording `--stream-dwell` uses its existing
//! whole-scan publication gate instead. `--sensor-health conservative-optical-v1` also gates
//! short entry and dwell on blur and glare. Exact optional optical thresholds are part of
//! policy custody and approval reruns. Stream modes refuse this policy until they can preserve
//! its full semantics.
//! `--stream-watch` instead scans one whole bounded recording for actual confirmed zone entries,
//! preserving tracker state across the old 128-frame boundary. It uses its own approval identity,
//! aggregate `--stream-*` budgets, and the same optional whole-scan health gate. It has no dwell
//! rule, coverage-retention or alert authority. The same explicit detector-package options
//! select native RGB inference at entries and following actual track matches; the complete
//! recording shares one inference allowance and retains the verified package for cold replay.
//! `--dwell-step-frames N` advances a bounded native recording prefix and retains a source-bound
//! checkpoint. Its emitted continuation names both exact checkpoint pins and explicitly admits
//! the cold prefix reconstruction with `--dwell-restore-max-frames`. A partial prefix emits no
//! completed dwell event. Optional conservative health screening preserves its findings and
//! sample allowance across steps using an explicitly versioned checkpoint. Exact completed
//! unscreened checkpoints can instead supply read-only calibrated
//! advice without another checkpoint append. Existing final proposal approvals remain required.
//! With `--tolerate-decode-refusals`, native video steps count decoded pictures or explicit
//! discontinuities. Recovery resumes only at IDR/IRAP inputs and never bridges a dwell episode
//! across lost footage. Version-five checkpoints preserve the complete refusal and decode-work
//! history; version-three progress separates those gaps from actual display observations.
//! Screened whole-recording reports separately offer `--retain-health` for source-bound
//! historical diagnostics, including runs with no candidate or a blocking health finding.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use fss_cli::event_fusion::{EventFusionError, EventFusionProfile, EventFusionReport};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, DigestAlgorithm, OperationId, PrincipalId};
use fss_reference::ingest::RetainedFileImport;
use fss_reference::ingest::detector_cascade::DetectorCascade;
use fss_reference::ingest::long_dwell::{LongDwellLimits, LongDwellReport, MAX_LONG_DWELL_FRAMES};
use fss_reference::ingest::long_watch::{
    LongWatchDetector, LongWatchLimits, LongWatchReport, MAX_LONG_WATCH_FRAMES,
};
use fss_reference::ingest::osd_mask::validate_ignore_regions;
use fss_reference::ingest::package_detect::PackageDetectLimits;
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_dwell::DwellReport;
use fss_reference::ingest::recorded_health::RecordedHealthPolicy;
use fss_reference::ingest::recorded_watch::{
    ImageRect, MAX_IGNORE_REGIONS, MAX_WATCH_FRAMES, MAX_WATCH_ZONES, WatchDetectorConfig,
    WatchError, WatchLimits, WatchOptions, WatchPlan, WatchReport, WatchTrackerConfig, WatchZone,
};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::ingest::zone_dwell::DwellPolicy;
use fss_reference::retained_source::{ImmutableRetainedReadLimits, ImmutableRetainedSource};
use fss_reference::{ReferenceDeployment, ReplayCx, RetainedSource, ScalarExecCx};

use super::{RunResult, export};

#[path = "watch/immutable.rs"]
mod immutable;
#[path = "watch/incremental.rs"]
mod incremental;
#[path = "watch/whole.rs"]
mod whole;

pub(super) fn run_immutable_preview(action: &WatchAction, out: &mut impl Write) -> RunResult<()> {
    if action.ignore_regions.is_empty() {
        return immutable::run(action, out);
    }
    run_immutable_ignore_preview(action, out)
}

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
    "--max-read-bytes",
    "--max-read-objects",
    "--approve",
    "--retain-coverage",
    "--retain-health",
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
    "--dwell-step-frames",
    "--dwell-checkpoint",
    "--dwell-checkpoint-root",
    "--dwell-restore-max-frames",
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
    ignore_regions: Vec<ImageRect>,
    first_segment: usize,
    segment_count: Option<usize>,
    detector: WatchDetectorConfig,
    tracker: WatchTrackerConfig,
    limits: WatchLimits,
    read_limits: ImmutableRetainedReadLimits,
    approvals: BTreeSet<ContentDigest>,
    retain_coverage: Option<ContentDigest>,
    retain_health: Option<ContentDigest>,
    report_out: Option<PathBuf>,
    cascade: Option<super::detector::DetectorOptions>,
    options: WatchOptions,
    dwell: Option<DwellPolicy>,
    stream_dwell: Option<LongDwellLimits>,
    stream_watch: Option<LongWatchLimits>,
    health_screen: bool,
    health_policy: RecordedHealthPolicy,
    incremental: Option<incremental::StepOptions>,
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
/// and `--ignore-rect` repeat. Paths must be UTF-8 here because the report echoes an exact rerun command.
pub(super) fn parse(args: &[OsString]) -> Result<WatchAction, String> {
    let mut values: Vec<(String, String)> = Vec::new();
    let mut zones = Vec::new();
    let mut ignore_regions = Vec::new();
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
        } else if key == "--ignore-rect" {
            if ignore_regions.len() == MAX_IGNORE_REGIONS {
                return Err("at most sixteen ignore rects".to_owned());
            }
            ignore_regions
                .push(ImageRect::parse_xywh(argument).map_err(|error| error.to_string())?);
        } else if !OPTIONS.contains(&key)
            && !super::detector::OPTIONS.contains(&key)
            && !super::detector::FUSION_OPTIONS.contains(&key)
            && !super::optical_health::OPTIONS.contains(&key)
        {
            return Err("unknown or inapplicable option".to_owned());
        } else if values.iter().any(|(k, _)| k == key) {
            return Err(format!("duplicate {key}"));
        } else {
            values.push((key.to_owned(), argument.to_owned()));
        }
        if ![
            "--approve",
            "--retain-coverage",
            "--retain-health",
            "--report-out",
            "--max-read-bytes",
            "--max-read-objects",
            "--fusion-profile",
            "--fusion-digest",
            "--dwell-checkpoint",
            "--dwell-checkpoint-root",
            "--dwell-restore-max-frames",
        ]
        .contains(&key)
        {
            rerun.push(quote(key));
            rerun.push(quote(argument));
        }
        index += 2;
    }
    let cascade = super::detector::parse(&values)?;
    super::detector::check_watch_fusion_mode(
        cascade.as_ref(),
        !values.iter().any(|(key, _)| key == "--dwell-step-frames")
            || [
                "--dwell-checkpoint",
                "--dwell-checkpoint-root",
                "--dwell-restore-max-frames",
            ]
            .iter()
            .all(|required| values.iter().any(|(key, _)| key == required)),
        values.iter().any(|(key, _)| {
            ["--approve", "--retain-coverage", "--retain-health"].contains(&key.as_str())
        }),
    )?;
    let selected_health = super::optical_health::parse(&values)?;
    super::optical_health::short_only(
        selected_health,
        stream_watch || stream_dwell || values.iter().any(|(key, _)| key == "--dwell-step-frames"),
    )?;
    let health_screen = selected_health.is_some();
    let health_policy = selected_health.unwrap_or(RecordedHealthPolicy::ConservativeV1);
    let retain_health = match text(&values, "--retain-health") {
        Ok(value) => Some(digest(value, "--retain-health")?),
        Err(_) => None,
    };
    if retain_health.is_some() {
        if !health_screen || !(stream_watch || stream_dwell) {
            return Err(
                "--retain-health requires --sensor-health conservative-v1 and --stream-watch or --stream-dwell"
                    .to_owned(),
            );
        }
        if values.iter().any(|(key, _)| key == "--approve") {
            return Err(
                "retain health and publish event approvals in separate invocations".to_owned(),
            );
        }
    }
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
    limits.jpeg_work_units = number(
        &values,
        "--work-units",
        limits.jpeg_limits.luma_work_bound(),
    )?;
    limits.h264_limits.max_width = dimension;
    limits.h264_limits.max_height = dimension;
    // Complete coded AVC macroblocks must fit the requested ceiling. Keep the existing
    // one-macroblock placeholder for tiny JPEG-only requests, which never decode AVC.
    limits.h264_limits.max_macroblocks =
        u32::try_from((pixels / 256).max(1)).map_err(|_| "pixel ceiling")?;
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
    let ignore_regions =
        validate_ignore_regions(&ignore_regions).map_err(|error| error.to_string())?;
    if !ignore_regions.is_empty() && (stream_watch || stream_dwell || dwell.is_some()) {
        return Err(
            "--ignore-rect is supported only in short entry watch mode (not --stream-watch, --stream-dwell, or dwell)"
                .to_owned(),
        );
    }
    if stream_dwell && dwell.is_none() {
        return Err("--stream-dwell requires the explicit dwell duration and gap rule".to_owned());
    }
    let incremental = incremental::parse(&values, stream_dwell, health_screen)?;
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
    let read_values = values
        .iter()
        .map(|(key, value)| (key.clone(), OsString::from(value)))
        .collect();
    let read_limits = super::retained_read::parse_limits(&read_values)?;
    let action = WatchAction {
        root: PathBuf::from(text(&values, "--root")?),
        site,
        principal,
        import: digest(text(&values, "--import-id")?, "--import-id")?,
        interpretation,
        zones,
        ignore_regions,
        first_segment: number(&values, "--first-segment", 0)?,
        segment_count,
        detector,
        tracker,
        limits,
        read_limits,
        approvals,
        retain_coverage: match text(&values, "--retain-coverage") {
            Ok(value) => Some(digest(value, "--retain-coverage")?),
            Err(_) => None,
        },
        retain_health,
        report_out: values
            .iter()
            .find(|(k, _)| k == "--report-out")
            .map(|(_, v)| PathBuf::from(v)),
        cascade,
        options,
        dwell,
        stream_dwell,
        stream_watch,
        health_screen,
        health_policy,
        incremental,
        rerun,
    };
    if values
        .iter()
        .any(|(key, _)| matches!(key.as_str(), "--max-read-bytes" | "--max-read-objects"))
        && !action.is_immutable_preview()
    {
        return Err(
            "aggregate read allowances require an unapproved, nonincremental watch or dwell preview".to_owned(),
        );
    }
    Ok(action)
}

impl WatchAction {
    /// Unapproved entry and dwell analyses share an immutable owner. Incremental steps retain
    /// checkpoints and therefore keep their publisher. Saving an external report grants no authority.
    pub(super) fn is_immutable_preview(&self) -> bool {
        self.approvals.is_empty()
            && self.retain_coverage.is_none()
            && self.retain_health.is_none()
            && self.incremental.is_none()
    }
}

/// Analyze, optionally publish exactly the approved proposals, and print the JSON report.
pub(super) fn run(
    action: &WatchAction,
    deployment: &mut ReferenceDeployment,
    root: &Path,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    super::optical_health::short_only(
        action.health_screen.then_some(action.health_policy),
        action.stream_watch.is_some()
            || action.stream_dwell.is_some()
            || action.incremental.is_some(),
    )?;
    super::detector::check_watch_fusion_mode(
        action.cascade.as_ref(),
        action
            .incremental
            .is_none_or(|options| action.stream_dwell.is_some() && options.has_checkpoint()),
        !action.approvals.is_empty()
            || action.retain_coverage.is_some()
            || action.retain_health.is_some(),
    )?;
    if action.retain_health.is_some()
        && (!action.health_screen
            || (action.stream_watch.is_none() && action.stream_dwell.is_none())
            || !action.approvals.is_empty())
    {
        return Err(WatchError::InvalidPlan(
            "health retention requires screened whole-recording analysis and a separate event-approval invocation",
        )
        .into());
    }
    if !action.ignore_regions.is_empty()
        && (action.stream_watch.is_some()
            || action.stream_dwell.is_some()
            || action.dwell.is_some())
    {
        return Err(WatchError::InvalidPlan(
            "OSD ignore regions are supported only in short entry watch mode",
        )
        .into());
    }
    if let Some(limits) = &action.stream_watch {
        let scalar = ScalarExecCx::new();
        let result = run_streaming_watch(action, deployment, root, limits, cx, &scalar, out);
        scalar.drain_and_finalize();
        return result;
    }
    if let Some(limits) = &action.stream_dwell {
        let scalar = ScalarExecCx::new();
        let result = run_streaming(action, deployment, root, limits, cx, &scalar, out);
        scalar.drain_and_finalize();
        return result;
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
    // The parser is not an authority boundary: repeat read-only admission before profile,
    // package or source I/O, including for internal callers of this adapter.
    super::detector::check_watch_fusion_mode(
        action.cascade.as_ref(),
        true,
        !action.approvals.is_empty() || action.retain_health.is_some(),
    )?;
    let inputs = whole::Inputs::load(action, whole::Scope::Watch, cx, scalar)?;
    let (mut report, fusion) = inputs.watch(action, deployment, limits, cx, scalar)?;
    if !action.approvals.is_empty() {
        report.publish(deployment, &action.approvals, cx)?;
    }
    let retention = action
        .retain_health
        .map(|approval| -> RunResult<_> {
            report
                .health_diagnostic()
                .ok_or_else(|| -> Box<dyn std::error::Error> {
                    WatchError::InvalidPlan("no historical health diagnostic was produced").into()
                })?
                .retain(deployment, approval, cx)
                .map_err(Into::into)
        })
        .transpose()?;
    let json = format!(
        "{}\n",
        whole::render_watch(
            action,
            &report,
            deployment.current_anchor().commit_sequence,
            retention.as_ref(),
            fusion.as_ref(),
        )?
    );
    if fusion.is_some() {
        report.revalidate_derived_source(deployment, cx)?;
        cx.checkpoint("long_watch_fusion:output")?;
    }
    if let Some(path) = &action.report_out {
        export(path, json.as_bytes(), root, cx)?;
    }
    if fusion.is_some() {
        report.revalidate_derived_source(deployment, cx)?;
        cx.checkpoint("long_watch_fusion:stdout")?;
    }
    out.write_all(json.as_bytes())?;
    Ok(())
}

fn load_short_inputs(
    action: &WatchAction,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
) -> RunResult<(Option<EventFusionProfile>, Option<RgbDetectorPackage>)> {
    // Calibration bytes and package bytes are pinned before any retained source is read.
    let fusion_profile = super::detector::load_fusion(action.cascade.as_ref(), cx)?;
    if fusion_profile.as_ref().is_some_and(|p| {
        p.long_watch_analysis_root().is_some()
            || p.long_dwell_analysis_root().is_some()
            || p.long_corroboration_analysis_roots().is_some()
    }) {
        return Err(EventFusionError::Scope.into());
    }
    // The package is verified (digest before parsing) before any source is read.
    let package = match &action.cascade {
        Some(options) => Some(super::detector::load(options, cx, scalar)?),
        None => None,
    };
    Ok((fusion_profile, package))
}

fn short_cascade<'a>(
    action: &WatchAction,
    package: Option<&'a RgbDetectorPackage>,
    scalar: &'a ScalarExecCx,
) -> RunResult<Option<DetectorCascade<'a>>> {
    match (&action.cascade, package) {
        (Some(options), Some(package)) => Ok(Some(DetectorCascade::new(
            package,
            options.config,
            PackageDetectLimits::default(),
            scalar,
        )?)),
        (None, None) => Ok(None),
        _ => Err(EventFusionError::Scope.into()),
    }
}

fn short_plan(
    action: &WatchAction,
    deployment: &dyn RetainedSource,
    cx: &ReplayCx,
) -> RunResult<WatchPlan> {
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
    Ok(WatchPlan {
        import_identity: action.import,
        interpretation: action.interpretation,
        first_segment: action.first_segment,
        segment_count,
        zones: action.zones.clone(),
        detector: action.detector,
        tracker: action.tracker,
    })
}

fn run_with(
    action: &WatchAction,
    deployment: &mut ReferenceDeployment,
    root: &Path,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
    out: &mut impl Write,
) -> RunResult<()> {
    let (fusion_profile, package) = load_short_inputs(action, cx, scalar)?;
    let mut cascade = short_cascade(action, package.as_ref(), scalar)?;
    let plan = short_plan(action, deployment, cx)?;
    if let Some(rule) = action.dwell {
        let mut report = DwellReport::analyze_with_health(
            deployment,
            &plan,
            rule,
            &action.limits,
            cascade.as_mut(),
            action.options,
            action.health_screen.then_some(action.health_policy),
            cx,
        )?;
        let fusion = match (&fusion_profile, cascade.as_ref()) {
            (Some(profile), Some(cascade)) => Some(EventFusionReport::dwell(
                &report, cascade, profile, deployment, cx,
            )?),
            (None, _) => None,
            _ => return Err(EventFusionError::Scope.into()),
        };
        // Admit the entire native report plus advice before any publication or export.
        // Fusion admission forbids authority writes; ordinary dwell publication is unchanged.
        render_short_dwell(
            action,
            &report,
            deployment.current_anchor().commit_sequence,
            fusion.as_ref(),
        )?;
        if !action.approvals.is_empty() {
            report.publish(deployment, &action.approvals, cx)?;
        }
        let json = render_short_dwell(
            action,
            &report,
            deployment.current_anchor().commit_sequence,
            fusion.as_ref(),
        )?;
        if fusion.is_some() {
            report.revalidate_derived_source(deployment, cx)?;
            cx.checkpoint("event_fusion:dwell_delivery")?;
        }
        let json = format!("{json}\n");
        if let Some(path) = &action.report_out {
            export(path, json.as_bytes(), root, cx)?;
        }
        out.write_all(json.as_bytes())?;
        return Ok(());
    }
    let mut report = WatchReport::analyze_with_ignore_regions(
        deployment,
        &plan,
        &action.limits,
        cascade.as_mut(),
        action.options,
        action.health_screen.then_some(action.health_policy),
        &action.ignore_regions,
        cx,
    )?;
    let fusion = match (&fusion_profile, cascade.as_ref()) {
        (Some(profile), Some(cascade)) => Some(EventFusionReport::watch(
            &report, cascade, profile, deployment, cx,
        )?),
        (None, _) => None,
        _ => return Err(EventFusionError::Scope.into()),
    };
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
        Some(WatchReport::analyze_with_ignore_regions(
            deployment,
            &plan,
            &action.limits,
            cascade.as_mut(),
            action.options,
            action.health_screen.then_some(action.health_policy),
            &action.ignore_regions,
            cx,
        )?)
    } else {
        None
    };
    let proposal = reproposed.as_ref().unwrap_or(&report);
    let json = render_short_watch(
        action,
        &report,
        proposal,
        deployment.current_anchor().commit_sequence,
        fusion.as_ref(),
    )?;
    if fusion.is_some() {
        report.revalidate_derived_source(deployment, cx)?;
        cx.checkpoint("event_fusion:watch_delivery")?;
    }
    let json = format!("{json}\n");
    if let Some(path) = &action.report_out {
        export(path, json.as_bytes(), root, cx)?;
    }
    out.write_all(json.as_bytes())?;
    Ok(())
}

fn render_short_watch(
    action: &WatchAction,
    report: &WatchReport,
    proposal: &WatchReport,
    sequence: u64,
    fusion: Option<&EventFusionReport>,
) -> RunResult<String> {
    let coverage = super::coverage::render(
        &[proposal.coverage()],
        proposal.coverage_status(),
        proposal.coverage_approval(),
        &action.rerun,
    );
    let native = report.to_json_with_coverage(sequence, Some(&action.rerun), Some(&coverage));
    Ok(super::detector::with_fusion(native, fusion)?)
}

fn render_short_dwell(
    action: &WatchAction,
    report: &DwellReport,
    sequence: u64,
    fusion: Option<&EventFusionReport>,
) -> RunResult<String> {
    Ok(super::detector::with_fusion(
        report.to_json(sequence, Some(&action.rerun))?,
        fusion,
    )?)
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

#[allow(clippy::too_many_arguments)]
fn run_streaming(
    action: &WatchAction,
    deployment: &mut ReferenceDeployment,
    root: &Path,
    limits: &LongDwellLimits,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
    out: &mut impl Write,
) -> RunResult<()> {
    // Refuse inapplicable modes even when a future internal caller bypasses parse.
    if action.retain_coverage.is_some() {
        return Err(WatchError::InvalidPlan("streaming dwell has no coverage owner").into());
    }
    super::detector::check_watch_fusion_mode(
        action.cascade.as_ref(),
        action
            .incremental
            .is_none_or(|options| options.has_checkpoint()),
        !action.approvals.is_empty() || action.retain_health.is_some(),
    )?;
    if action.incremental.is_some() {
        return incremental::run(action, deployment, root, limits, cx, scalar, out);
    }
    let inputs = whole::Inputs::load(action, whole::Scope::Dwell, cx, scalar)?;
    let (mut report, fusion) = inputs.dwell(action, deployment, limits, cx, scalar)?;
    if !action.approvals.is_empty() {
        report.publish(deployment, &action.approvals, cx)?;
    }
    let retention = action
        .retain_health
        .map(|approval| -> RunResult<_> {
            report
                .health_diagnostic()
                .ok_or_else(|| -> Box<dyn std::error::Error> {
                    WatchError::InvalidPlan("no historical health diagnostic was produced").into()
                })?
                .retain(deployment, approval, cx)
                .map_err(Into::into)
        })
        .transpose()?;
    let json = format!(
        "{}\n",
        whole::render_dwell(
            action,
            &report,
            deployment.current_anchor().commit_sequence,
            retention.as_ref(),
            fusion.as_ref(),
        )?
    );
    if fusion.is_some() {
        report.revalidate_derived_source(deployment, cx)?;
        cx.checkpoint("long_dwell_fusion:output")?;
    }
    if let Some(path) = &action.report_out {
        export(path, json.as_bytes(), root, cx)?;
    }
    if fusion.is_some() {
        report.revalidate_derived_source(deployment, cx)?;
        cx.checkpoint("long_dwell_fusion:stdout")?;
    }
    out.write_all(json.as_bytes())?;
    Ok(())
}

fn run_immutable_ignore_preview(action: &WatchAction, out: &mut impl Write) -> RunResult<()> {
    if !action.is_immutable_preview() {
        return Err(WatchError::InvalidPlan(
            "immutable watch requires an unapproved, nonincremental preview",
        )
        .into());
    }
    if action.stream_watch.is_some() || action.stream_dwell.is_some() || action.dwell.is_some() {
        return Err(WatchError::InvalidPlan(
            "OSD ignore regions are supported only in short entry watch mode",
        )
        .into());
    }
    let root = std::fs::canonicalize(&action.root)?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:event-cli".into(),
        operation_id: OperationId::parse("operation:event-cli")?,
        principal: action.principal.clone(),
        capabilities: vec!["ADP-REPLAY-001".into(), "CAP-READ-MEDIA-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(action.read_limits.max_read_bytes as u64)
            .storage_operations(action.read_limits.max_read_objects as u64)
            .build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(action.site.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    let cx = ReplayCx::from_context_authority_read_only(&authority, root.clone())?;
    let scalar = ScalarExecCx::new();
    let started = Instant::now();
    let cancelled = || started.elapsed() >= super::retained_read::DEADLINE;
    let result = (|| -> RunResult<()> {
        super::optical_health::short_only(
            action.health_screen.then_some(action.health_policy),
            false,
        )?;
        super::detector::check_watch_fusion_mode(action.cascade.as_ref(), true, false)?;
        let (profile, package) = load_short_inputs(action, &cx, &scalar)?;
        let source =
            ImmutableRetainedSource::open_cancellable(&root, action.read_limits, &cx, &cancelled)?;
        if source.site_lineage() != action.site {
            return Err(
                WatchError::InvalidPlan("retained deployment site lineage mismatch").into(),
            );
        }
        let mut cascade = short_cascade(action, package.as_ref(), &scalar)?;
        let plan = short_plan(action, &source, &cx)?;
        let report = WatchReport::analyze_with_ignore_regions(
            &source,
            &plan,
            &action.limits,
            cascade.as_mut(),
            action.options,
            action.health_screen.then_some(action.health_policy),
            &action.ignore_regions,
            &cx,
        )?;
        let fusion = match (&profile, cascade.as_ref()) {
            (Some(profile), Some(cascade)) => Some(EventFusionReport::watch(
                &report, cascade, profile, &source, &cx,
            )?),
            (None, _) => None,
            _ => return Err(EventFusionError::Scope.into()),
        };
        let json = render_short_watch(
            action,
            &report,
            &report,
            source.current_anchor().commit_sequence,
            fusion.as_ref(),
        )?;
        report.revalidate_derived_source(&source, &cx)?;
        let json = format!("{json}\n");
        if json.len() > super::MAX_ANALYSIS_REPORT_BYTES {
            return Err(WatchError::Limit.into());
        }
        cx.checkpoint("watch_preview:delivery")?;
        source.revalidate_snapshot_metadata()?;
        source.revalidate()?;
        if let Some(path) = &action.report_out {
            export(path, json.as_bytes(), &root, &cx)?;
        }
        out.write_all(json.as_bytes())?;
        Ok(())
    })();
    scalar.drain_and_finalize();
    cx.drain_and_finalize();
    result
}

#[cfg(test)]
#[path = "watch_fusion_tests.rs"]
mod fusion_tests;

#[cfg(test)]
mod osd_and_budget_tests {
    use super::*;

    fn base_args() -> Vec<OsString> {
        [
            "--root",
            "unused",
            "--site",
            "site:watch-test",
            "--import-id",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "--interpretation",
            "ycbcr",
            "--zone",
            "door:0,0,64,64",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    #[test]
    fn default_work_units_derives_from_decode_limits_and_allows_override() -> Result<(), String> {
        let default_action = parse(&base_args())?;
        let default_bound = default_action.limits.jpeg_limits.luma_work_bound();
        assert_eq!(default_action.limits.jpeg_work_units, default_bound);
        assert!(default_action.limits.jpeg_work_units > 800_000_000);

        // Narrowed --max-pixels / --max-dimension shrinks the default dynamically.
        let mut narrow = base_args();
        narrow.extend(["--max-dimension", "640", "--max-pixels", "230400"].map(OsString::from));
        let narrow_action = parse(&narrow)?;
        assert_eq!(
            narrow_action.limits.jpeg_work_units,
            narrow_action.limits.jpeg_limits.luma_work_bound()
        );
        assert!(narrow_action.limits.jpeg_work_units < default_bound);

        // Explicit tiny --work-units is preserved verbatim.
        let mut tiny = base_args();
        tiny.extend(["--work-units", "1024"].map(OsString::from));
        let tiny_action = parse(&tiny)?;
        assert_eq!(tiny_action.limits.jpeg_work_units, 1024);
        Ok(())
    }

    #[test]
    fn ignore_rect_parses_canonically_echoes_in_rerun_and_refuses_invalid() -> Result<(), String> {
        let mut args = base_args();
        args.extend(
            ["--ignore-rect", "72,2,20,12", "--ignore-rect", "0,0,16,8"].map(OsString::from),
        );
        let action = parse(&args)?;
        assert_eq!(
            action.ignore_regions,
            vec![
                ImageRect {
                    x: 0,
                    y: 0,
                    width: 16,
                    height: 8
                },
                ImageRect {
                    x: 72,
                    y: 2,
                    width: 20,
                    height: 12
                },
            ]
        );
        assert!(action.rerun.contains("--ignore-rect 72,2,20,12"));
        assert!(action.rerun.contains("--ignore-rect 0,0,16,8"));

        // Duplicate, malformed, zero-sized, >16, and stream/dwell combinations are refused.
        for bad in [
            vec!["--ignore-rect", "0,0,10,10", "--ignore-rect", "0,0,10,10"],
            vec!["--ignore-rect", "0,0,0,10"],
            vec!["--ignore-rect", "0,0,10"],
            vec!["--ignore-rect", "bad"],
            vec!["--ignore-rect", "0,0,10,10", "--stream-watch"],
            vec![
                "--ignore-rect",
                "0,0,10,10",
                "--dwell-for-ns",
                "1000",
                "--dwell-max-gap-ns",
                "500",
            ],
        ] {
            let mut input = base_args();
            input.extend(bad.into_iter().map(OsString::from));
            assert!(parse(&input).is_err());
        }

        // More than 16 --ignore-rect flags are refused.
        let mut too_many = base_args();
        for i in 0..=MAX_IGNORE_REGIONS {
            too_many.push(OsString::from("--ignore-rect"));
            too_many.push(OsString::from(format!("{i},0,1,1")));
        }
        assert!(parse(&too_many).is_err());
        Ok(())
    }
}

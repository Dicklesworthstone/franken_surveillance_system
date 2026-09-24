#![forbid(unsafe_code)]
//! `fss-event watch`: model-free single-camera candidates from a retained recording.
//!
//! Runs retained decode → foreground → Kalman tracker → zone gate through
//! `fss_reference::ingest::recorded_watch`. Without `--approve` it writes nothing to the
//! deployment and prints the JSON report with each candidate's exact proposal digest and the
//! rerun command that would publish it. With `--approve DIGEST[,DIGEST...]` it publishes only
//! those exact proposals as unclassified, indeterminate, single-sensor candidates through the
//! deployment's guarded event publisher; already-published candidates are never republished.
//! Every report also proposes the run's coverage record (one `CoverageWitness` per sensor, zone
//! and contiguous observable interval, every other frame an explicit uncovered interval); only
//! `--retain-coverage DIGEST` with its exact approval digest retains it as authority.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

use fss_core::{ContentDigest, DigestAlgorithm, PrincipalId};
use fss_reference::ingest::RetainedFileImport;
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{
    MAX_WATCH_FRAMES, MAX_WATCH_ZONES, WatchDetectorConfig, WatchError, WatchLimits, WatchPlan,
    WatchReport, WatchTrackerConfig, WatchZone,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

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

/// Parses the arguments after `watch`. Every option takes one separate value; only `--zone`
/// repeats. Paths must be UTF-8 here because the report echoes an exact rerun command.
pub(super) fn parse(args: &[OsString]) -> Result<WatchAction, String> {
    let mut values: Vec<(String, String)> = Vec::new();
    let mut zones = Vec::new();
    let mut rerun = vec!["fss-event".to_owned(), "watch".to_owned()];
    let mut index = 0;
    while index < args.len() {
        let key = args[index].to_str().ok_or("option names require UTF-8")?;
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
        } else if !OPTIONS.contains(&key) {
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
    if segment_count.is_some_and(|count| count == 0 || count > MAX_WATCH_FRAMES) {
        return Err("segment count must be 1..128".to_owned());
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
        rerun: rerun.join(" "),
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
    let mut report = WatchReport::analyze(deployment, &plan, &action.limits, cx)?;
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
        Some(WatchReport::analyze(deployment, &plan, &action.limits, cx)?)
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

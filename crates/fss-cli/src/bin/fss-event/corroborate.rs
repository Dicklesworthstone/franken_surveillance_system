#![forbid(unsafe_code)]
//! `fss-event corroborate`: two recordings, two sensors, one corroborated ground-zone entry.
//!
//! Runs `fss_reference::ingest::recorded_corroboration`: per-recording model-free tracking, foot
//! points projected through owner-supplied image→ground homographies (not calibration
//! certificates), global cross-camera association under explicit time and distance gates, and the
//! zone-entry policy. Without `--approve` nothing is written and each prepared candidate lists the
//! exact rerun command that publishes it. With exact proposal digests it publishes those events;
//! policy may report the `prepare_alert` affordance, but no alert is prepared here. Each report
//! also proposes one coverage record per camera; `--retain-coverage DIGEST` retains both exactly.
//! The detector-cascade options of `watch` add uncalibrated class evidence to each ground entry
//! (one inference budget for both recordings); it never changes the policy's event or alert.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

use fss_core::{ContentDigest, DigestAlgorithm, PrincipalId};
use fss_reference::ingest::detector_cascade::DetectorCascade;
use fss_reference::ingest::package_detect::PackageDetectLimits;
use fss_reference::ingest::recorded_corroboration::{
    CorroborationCamera, CorroborationGates, CorroborationPlan, CorroborationReport,
    GroundHomography, GroundZone, MAX_CORROBORATION_ZONES,
};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{WatchDetectorConfig, WatchLimits, WatchTrackerConfig};
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};

use super::{RunResult, export};

const OPTIONS: &[&str] = &[
    "--root",
    "--site",
    "--principal",
    "--interpretation",
    "--time-gate-ns",
    "--distance-gate",
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

/// Fully parsed corroboration request; nothing here is authority until `run` validates it.
#[derive(Debug)]
pub(super) struct CorroborateAction {
    pub(super) root: PathBuf,
    pub(super) site: String,
    pub(super) principal: String,
    plan: CorroborationPlan,
    limits: WatchLimits,
    approvals: BTreeSet<ContentDigest>,
    retain_coverage: Option<ContentDigest>,
    report_out: Option<PathBuf>,
    cascade: Option<super::detector::DetectorOptions>,
    rerun: String,
}

fn find<'a>(values: &'a [(String, String)], key: &str) -> Option<&'a str> {
    values
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn required<'a>(values: &'a [(String, String)], key: &str) -> Result<&'a str, String> {
    find(values, key).ok_or_else(|| format!("required option {key}"))
}

fn number<T: std::str::FromStr>(
    values: &[(String, String)],
    key: &str,
    default: T,
) -> Result<T, String> {
    match find(values, key) {
        None => Ok(default),
        Some(value) => value
            .parse()
            .map_err(|_| format!("invalid numeric value for {key}")),
    }
}

fn digest(value: &str, key: &str) -> Result<ContentDigest, String> {
    let parsed = ContentDigest::parse(value).map_err(|_| format!("invalid digest for {key}"))?;
    if parsed.algorithm() != DigestAlgorithm::Sha256 {
        return Err(format!("{key} requires SHA-256"));
    }
    Ok(parsed)
}

fn finite(text: &str, what: &str) -> Result<f64, String> {
    let value: f64 = text
        .parse()
        .map_err(|_| format!("{what} must be a finite decimal number"))?;
    if value.is_finite() {
        Ok(value)
    } else {
        Err(format!("{what} must be a finite decimal number"))
    }
}

fn zone(value: &str) -> Result<GroundZone, String> {
    let (id, geometry) = value
        .split_once(':')
        .ok_or("zone must be ID:X,Y,W,H in ground units")?;
    let parts: Vec<f64> = geometry
        .split(',')
        .map(|part| finite(part, "zone geometry"))
        .collect::<Result<_, _>>()?;
    let [x, y, width, height] = parts[..] else {
        return Err("zone geometry must be four numbers X,Y,W,H".to_owned());
    };
    Ok(GroundZone {
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

/// Parses the arguments after `corroborate`. Every option takes one separate value; `--camera`,
/// `--ground` and `--zone` repeat. Paths must be UTF-8 because the report echoes rerun commands.
pub(super) fn parse(args: &[OsString]) -> Result<CorroborateAction, String> {
    let mut values: Vec<(String, String)> = Vec::new();
    let mut cameras: Vec<(String, ContentDigest)> = Vec::new();
    let mut grounds: Vec<(String, GroundHomography)> = Vec::new();
    let mut zones = Vec::new();
    let mut rerun = vec!["fss-event".to_owned(), "corroborate".to_owned()];
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
        match key {
            "--camera" => {
                let (name, import) = argument
                    .split_once(':')
                    .ok_or("camera must be NAME:sha256:IMPORT")?;
                if cameras.len() == 2 {
                    return Err("exactly two --camera recordings are required".to_owned());
                }
                cameras.push((name.to_owned(), digest(import, "--camera")?));
            }
            "--ground" => {
                let (name, matrix) = argument
                    .split_once(':')
                    .ok_or("ground homography must be NAME:h11,h12,h13,h21,h22,h23,h31,h32,h33")?;
                let entries: Vec<f64> = matrix
                    .split(',')
                    .map(|part| finite(part, "homography entry"))
                    .collect::<Result<_, _>>()?;
                let matrix: [f64; 9] = entries
                    .try_into()
                    .map_err(|_| "ground homography needs exactly nine row-major entries")?;
                if grounds.iter().any(|(n, _)| n == name) {
                    return Err(format!("duplicate --ground for camera {name}"));
                }
                grounds.push((name.to_owned(), GroundHomography { matrix }));
            }
            "--zone" => {
                if zones.len() == MAX_CORROBORATION_ZONES {
                    return Err("at most sixteen zones".to_owned());
                }
                zones.push(zone(argument)?);
            }
            _ if !OPTIONS.contains(&key) && !super::detector::OPTIONS.contains(&key) => {
                return Err("unknown or inapplicable option".to_owned());
            }
            _ if values.iter().any(|(k, _)| k == key) => return Err(format!("duplicate {key}")),
            _ => values.push((key.to_owned(), argument.to_owned())),
        }
        if key != "--approve" && key != "--retain-coverage" && key != "--report-out" {
            rerun.push(quote(key));
            rerun.push(quote(argument));
        }
        index += 2;
    }
    let [first, second]: [(String, ContentDigest); 2] = cameras
        .try_into()
        .map_err(|_| "exactly two --camera NAME:sha256:IMPORT recordings are required")?;
    if grounds.len() != 2 {
        return Err(
            "each camera needs exactly one --ground NAME:h11,...,h33 homography".to_owned(),
        );
    }
    let homography = |name: &str| {
        grounds
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, h)| *h)
            .ok_or_else(|| format!("missing --ground homography for camera {name}"))
    };
    let cameras = [
        CorroborationCamera {
            homography: homography(&first.0)?,
            name: first.0,
            import_identity: first.1,
        },
        CorroborationCamera {
            homography: homography(&second.0)?,
            name: second.0,
            import_identity: second.1,
        },
    ];
    if zones.is_empty() {
        return Err("at least one --zone ID:X,Y,W,H (ground units) is required".to_owned());
    }
    let site = required(&values, "--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| "invalid site lineage")?;
    let principal = find(&values, "--principal")
        .unwrap_or("principal:local-operator")
        .to_owned();
    PrincipalId::parse(&principal).map_err(|_| "invalid principal ID")?;
    let interpretation = match required(&values, "--interpretation")? {
        "gray" => ComponentInterpretation::Grayscale,
        "ycbcr" => ComponentInterpretation::YCbCr,
        _ => return Err("interpretation must be explicitly gray or ycbcr".to_owned()),
    };
    let time_gate_ns: u64 = required(&values, "--time-gate-ns")?
        .parse()
        .map_err(|_| "invalid numeric value for --time-gate-ns")?;
    let distance_gate = finite(required(&values, "--distance-gate")?, "--distance-gate")?;
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
    if let Some(list) = find(&values, "--approve") {
        for item in list.split(',') {
            if !approvals.insert(digest(item, "--approve")?) {
                return Err("duplicate approval digest".to_owned());
            }
        }
    }
    Ok(CorroborateAction {
        root: PathBuf::from(required(&values, "--root")?),
        site,
        principal,
        plan: CorroborationPlan {
            cameras,
            interpretation,
            zones,
            gates: CorroborationGates {
                time_gate_ns,
                distance_gate,
            },
            detector,
            tracker,
        },
        limits,
        approvals,
        retain_coverage: match find(&values, "--retain-coverage") {
            Some(value) => Some(digest(value, "--retain-coverage")?),
            None => None,
        },
        report_out: find(&values, "--report-out").map(PathBuf::from),
        cascade: super::detector::parse(&values)?,
        rerun: rerun.join(" "),
    })
}

/// Analyze, optionally publish exactly the approved proposals, and print the JSON report.
pub(super) fn run(
    action: &CorroborateAction,
    deployment: &mut ReferenceDeployment,
    root: &Path,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    let scalar = ScalarExecCx::new();
    let result = run_with(action, deployment, root, cx, &scalar, out);
    scalar.drain_and_finalize();
    result
}

fn run_with(
    action: &CorroborateAction,
    deployment: &mut ReferenceDeployment,
    root: &Path,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
    out: &mut impl Write,
) -> RunResult<()> {
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
    let mut report = CorroborationReport::analyze_with_detector(
        deployment,
        &action.plan,
        &action.limits,
        cascade.as_mut(),
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
        Some(CorroborationReport::analyze_with_detector(
            deployment,
            &action.plan,
            &action.limits,
            cascade.as_mut(),
            cx,
        )?)
    } else {
        None
    };
    let proposal = reproposed.as_ref().unwrap_or(&report);
    let records: Vec<_> = proposal.coverage().iter().collect();
    let coverage = super::coverage::render(
        &records,
        proposal.coverage_status(),
        proposal.coverage_approval(),
        &action.rerun,
    );
    let alert_hint = format!(
        "fss-event alert --root {} --site {}",
        quote(&action.root.to_string_lossy()),
        quote(&action.site)
    );
    let json = report.to_json_with_coverage(
        deployment.current_anchor().commit_sequence,
        Some(&action.rerun),
        Some(&alert_hint),
        Some(&coverage),
    );
    let json = format!("{json}\n");
    if let Some(path) = &action.report_out {
        export(path, json.as_bytes(), root, cx)?;
    }
    out.write_all(json.as_bytes())?;
    Ok(())
}

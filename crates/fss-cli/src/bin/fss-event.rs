#![forbid(unsafe_code)]
//! Local operator preparation, exact publication, and recovery of unresolved recorded events.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;

use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::{BudgetVector, ContentDigest, DigestAlgorithm, EventId, OperationId, PrincipalId};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_reference::{ReferenceDeployment, ReplayCx};
use fss_reference::ingest::analysis::{AnalysisBudget, AnalysisFrame, AnalysisLimits, AnalysisPlan, AnalysisReport, MAX_ANALYSIS_REPORT_BYTES};
use fss_reference::ingest::detections::{BoxEncoding, CoordinateSpace, DetectionSpec};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::tracking::TrackingConfig;
use fss_reference::ingest::recorded_event::{RecordedEvent, RecordedEventProposal};

#[path = "fss-event/watch.rs"]
mod watch;

const HELP: &str = "fss-event <report|prepare|publish|read|watch> [options]\n\
  All: --root DIR --site SITE [--principal ID]\n\
  report: --import-id sha256:HEX --runs FILE --interpretation gray|ycbcr\n\
          --model-digest sha256:HEX --output-port NAME --labels ORDERED,CLASS,NAMES\n\
          --box-format xyxy|cxcywh --coordinates pixels|normalized --report-out FILE\n\
  Report policies: --minimum-score-ppm N --nms-iou-ppm N --minimum-iou-ppm N\n\
                   --confirmation-hits N --maximum-missed-frames N --maximum-tracks N\n\
  prepare/publish: --report FILE --report-digest sha256:HEX --track sha256:HEX\n\
  publish additionally requires: --proposal-digest sha256:HEX\n\
  read: --event-id ID (report and original source/model files are not required)\n\
  Budgets: --detection-work-units N --association-work-units N --max-report-bytes N\n\
  Exports: --event-out FILE (canonical event JSON); read also accepts --report-out FILE\n\
  An existing operator-authorized deployment is required. Report inputs are complete\n\
  canonical AnalysisReport bytes, not detector CLI JSON or a tracker checkpoint.\n\
  Preparation writes no event authority. Publication records only an unclassified,\n\
  indeterminate candidate after exact approval and source revalidation. No alert,\n\
  calibrated presence, identity, arrival, departure, or absence claim is authorized.\n\
  Limits: at most 64 report frames and 16 MiB of report bytes. Exports must be new\n\
  files outside the deployment; options take separate values and paths preserve OS bytes.\n\
  watch (model-free, no trained model): --import-id sha256:HEX --interpretation gray|ycbcr\n\
          --zone ID:X,Y,W,H [--zone ...] (1..16, decoded pixels, UTF-8 arguments)\n\
          [--first-segment N] [--segment-count M (1..128; H.264 must start at an IDR)]\n\
          [--pixel-threshold N --threshold-sigma N --learning-rate-num N\n\
           --learning-rate-den N --min-region-pixels N] [--confirmation-hits N\n\
           --maximum-missed-frames N --minimum-iou-ppm N] [--work-units N\n\
           --max-dimension N --max-pixels N --max-segment-bytes N]\n\
          [--approve sha256:PROPOSAL[,sha256:PROPOSAL...]] [--report-out FILE]\n\
    Retained decode -> running-variance foreground -> Kalman tracker -> zone gate. Prints a\n\
    JSON report of candidates (zone, track, frame range, evidence digests, proposal digest).\n\
    Without --approve nothing is written; each prepared candidate lists the exact rerun\n\
    command that publishes it. --approve publishes only those exact proposals as\n\
    unclassified, indeterminate, single-sensor candidates (never corroborated, no alert);\n\
    reruns never republish. Thresholds are uncalibrated; synthetic scenes prove wiring,\n\
    not detection quality, and no candidate never means absence.\n";
type RunResult<T> = Result<T, Box<dyn Error>>;
type Values = BTreeMap<String, OsString>;
#[derive(Debug)]
enum Action {
    Report { import: ContentDigest, interpretation: ComponentInterpretation, detector: DetectionSpec,
        tracking: TrackingConfig, runs: PathBuf, output: PathBuf },
    Prepare { report: PathBuf, digest: ContentDigest, track: ContentDigest },
    Publish { report: PathBuf, digest: ContentDigest, track: ContentDigest, approved: ContentDigest },
    Read(EventId),
    Watch(Box<watch::WatchAction>),
}
#[derive(Debug)]
struct Options {
    root: PathBuf,
    site: String,
    principal: String,
    limits: AnalysisLimits,
    detection_units: u64,
    association_units: u64,
    event_out: Option<PathBuf>,
    report_out: Option<PathBuf>,
    action: Action,
}
fn value<'a>(v: &'a Values, key: &str) -> Result<&'a OsStr, String> {
    v.get(key).map(OsString::as_os_str).ok_or_else(|| format!("required option {key}"))
}
fn text<'a>(v: &'a Values, key: &str) -> Result<&'a str, String> {
    value(v, key)?.to_str().ok_or_else(|| format!("{key} requires UTF-8"))
}
fn number<T: FromStr>(v: &Values, key: &str, default: T) -> Result<T, String> {
    if !v.contains_key(key) { return Ok(default); }
    text(v, key)?.parse().map_err(|_| format!("invalid numeric value for {key}"))
}
fn digest(v: &Values, key: &str) -> Result<ContentDigest, String> {
    let d = ContentDigest::parse(text(v, key)?).map_err(|_| format!("invalid digest for {key}"))?;
    if d.algorithm() != DigestAlgorithm::Sha256 { return Err(format!("{key} requires SHA-256")); }
    Ok(d)
}
fn parse(args: &[OsString]) -> Result<Option<Options>, String> {
    if args.is_empty() { return Ok(None); }
    let action = args[0].to_str().ok_or("command requires UTF-8")?;
    if matches!(action, "help" | "--help" | "-h") {
        return if args.len() == 1 { Ok(None) } else { Err("help takes no additional arguments".into()) };
    }
    if action == "watch" {
        let watch = watch::parse(&args[1..])?;
        return Ok(Some(Options { root: watch.root.clone(), site: watch.site.clone(),
            principal: watch.principal.clone(), limits: AnalysisLimits::default(),
            detection_units: 0, association_units: 0, event_out: None, report_out: None,
            action: Action::Watch(Box::new(watch)) }));
    }
    if !matches!(action, "report" | "prepare" | "publish" | "read") { return Err("expected report, prepare, publish, read or watch".into()); }
    let common = ["--root", "--site", "--principal", "--detection-work-units", "--association-work-units", "--max-report-bytes", "--event-out"];
    let report_options = ["--import-id", "--runs", "--interpretation", "--model-digest", "--output-port", "--labels",
        "--box-format", "--coordinates", "--minimum-score-ppm", "--nms-iou-ppm", "--minimum-iou-ppm",
        "--confirmation-hits", "--maximum-missed-frames", "--maximum-tracks"];
    let mut v = Values::new();
    let mut index = 1;
    while index < args.len() {
        let key = args[index].to_str().ok_or("option names require UTF-8")?;
        let allowed = common.contains(&key)
            || (matches!(action, "prepare" | "publish") && matches!(key, "--report" | "--report-digest" | "--track"))
            || (action == "publish" && key == "--proposal-digest")
            || (action == "read" && key == "--event-id")
            || (matches!(action, "read" | "report") && key == "--report-out")
            || (action == "report" && report_options.contains(&key));
        if !allowed { return Err("unknown or inapplicable option".into()); }
        if v.contains_key(key) { return Err(format!("duplicate {key}")); }
        let argument = args.get(index + 1).ok_or_else(|| format!("missing value for {key}"))?;
        if argument.is_empty() || argument.to_str().is_some_and(|s| s.starts_with("--")) {
            return Err(format!("missing value for {key}"));
        }
        v.insert(key.to_owned(), argument.clone()); index += 2;
    }
    let site = text(&v, "--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site).map_err(|_| "invalid site lineage")?;
    let principal = if v.contains_key("--principal") { text(&v, "--principal")?.to_owned() }
        else { "principal:local-operator".to_owned() };
    PrincipalId::parse(&principal).map_err(|_| "invalid principal ID")?;
    let limits = AnalysisLimits { maximum_frames: 64,
        maximum_report_bytes: number(&v, "--max-report-bytes", MAX_ANALYSIS_REPORT_BYTES)?,
        ..AnalysisLimits::default() };
    if limits.maximum_report_bytes == 0 || limits.maximum_report_bytes > MAX_ANALYSIS_REPORT_BYTES {
        return Err("report ceiling must be 1..16777216 bytes".into());
    }
    if action == "report" && v.contains_key("--event-out") { return Err("report has no canonical event to export".into()); }
    let action = match action {
        "report" => {
            let interpretation = match text(&v, "--interpretation")? {
                "gray" => ComponentInterpretation::Grayscale, "ycbcr" => ComponentInterpretation::YCbCr,
                _ => return Err("interpretation must be gray or ycbcr".into()),
            };
            let encoding = match text(&v, "--box-format")? {
                "xyxy" => BoxEncoding::Xyxy, "cxcywh" => BoxEncoding::CenterSize,
                _ => return Err("box format must be xyxy or cxcywh".into()),
            };
            let coordinates = match text(&v, "--coordinates")? {
                "pixels" => CoordinateSpace::Pixels, "normalized" => CoordinateSpace::Normalized,
                _ => return Err("coordinates must be pixels or normalized".into()),
            };
            let detector = DetectionSpec { model_digest: digest(&v, "--model-digest")?, output_port: text(&v, "--output-port")?.to_owned(),
                labels: text(&v, "--labels")?.split(',').map(str::to_owned).collect(), encoding, coordinates,
                minimum_score_ppm: number(&v, "--minimum-score-ppm", 500_000)?, nms_iou_ppm: number(&v, "--nms-iou-ppm", 500_000)?,
                maximum_rows: 4096, maximum_detections: 128 };
            fss_reference::ingest::detections::DetectionContract::new(detector.clone()).map_err(|_| "invalid detector contract")?;
            let tracking = TrackingConfig { minimum_iou_ppm: number(&v, "--minimum-iou-ppm", 100_000)?,
                confirmation_hits: number(&v, "--confirmation-hits", 2)?, maximum_missed_frames: number(&v, "--maximum-missed-frames", 1)?,
                maximum_tracks: number(&v, "--maximum-tracks", 128)? };
            tracking.digest().map_err(|_| "invalid tracking contract")?;
            Action::Report { import: digest(&v, "--import-id")?, interpretation, detector, tracking,
                runs: PathBuf::from(value(&v, "--runs")?), output: PathBuf::from(value(&v, "--report-out")?) }
        }
        "read" => Action::Read(EventId::parse(text(&v, "--event-id")?).map_err(|_| "invalid event ID")?),
        "prepare" => Action::Prepare { report: PathBuf::from(value(&v, "--report")?),
            digest: digest(&v, "--report-digest")?, track: digest(&v, "--track")? },
        _ => Action::Publish { report: PathBuf::from(value(&v, "--report")?),
            digest: digest(&v, "--report-digest")?, track: digest(&v, "--track")?,
            approved: digest(&v, "--proposal-digest")? },
    };
    Ok(Some(Options { root: PathBuf::from(value(&v, "--root")?), site, principal, limits,
        detection_units: number(&v, "--detection-work-units", 100_000_000)?,
        association_units: number(&v, "--association-work-units", 100_000_000)?,
        event_out: v.get("--event-out").map(PathBuf::from), report_out: v.get("--report-out").map(PathBuf::from), action }))
}
fn load(path: &Path, maximum: usize, expected: ContentDigest, cx: &ReplayCx) -> RunResult<Vec<u8>> {
    cx.checkpoint("event_cli:load")?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > maximum as u64 {
        return Err(io::Error::other("report must be a bounded regular file, not a symlink").into());
    }
    let file = fs::File::open(path)?;
    if !file.metadata()?.file_type().is_file() { return Err(io::Error::other("report is not regular").into()); }
    let mut bytes = Vec::new(); file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum || ContentDigest::sha256(&bytes) != expected {
        return Err(io::Error::other("report bound or expected checksum mismatch").into());
    }
    cx.checkpoint("event_cli:loaded")?;
    Ok(bytes)
}
fn read_runs(path: &Path, cx: &ReplayCx) -> RunResult<Vec<AnalysisFrame>> {
    cx.checkpoint("event_cli:runs")?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > 65_536 {
        return Err(io::Error::other("run list must be a regular file of at most 64 KiB").into());
    }
    let file = fs::File::open(path)?;
    if !file.metadata()?.file_type().is_file() { return Err(io::Error::other("run list is not regular").into()); }
    let mut bytes = Vec::new(); file.take(65_537).read_to_end(&mut bytes)?;
    if bytes.len() > 65_536 { return Err(io::Error::other("run list exceeds 64 KiB").into()); }
    let mut frames: Vec<AnalysisFrame> = Vec::new();
    for line in std::str::from_utf8(&bytes)?.lines() {
        cx.checkpoint("event_cli:runs")?;
        let mut fields = line.split_ascii_whitespace();
        let segment_index: usize = fields.next().ok_or("empty run-list row")?.parse()?;
        let run_identity = ContentDigest::parse(fields.next().ok_or("missing run identity")?)?;
        if fields.next().is_some() || frames.len() >= 64 || run_identity.algorithm() != DigestAlgorithm::Sha256
            || frames.last().is_some_and(|old| old.segment_index >= segment_index)
        { return Err(io::Error::other("run list must contain 1..64 strictly increasing SEGMENT SHA256 pairs").into()); }
        frames.push(AnalysisFrame { segment_index, run_identity });
    }
    if frames.is_empty() { return Err(io::Error::other("empty run list").into()); }
    Ok(frames)
}
fn export(path: &Path, bytes: &[u8], root: &Path, cx: &ReplayCx) -> RunResult<()> {
    cx.checkpoint("event_cli:export")?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    if fs::canonicalize(parent)?.starts_with(fs::canonicalize(root)?) {
        return Err(io::Error::other("exports must be outside the deployment").into());
    }
    let mut options = OpenOptions::new(); options.write(true).create_new(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    let mut file = options.open(path)?; file.write_all(bytes)?; file.sync_all()?;
    cx.checkpoint_post_commit("event_cli:exported");
    Ok(())
}
fn run(options: Options, out: &mut impl Write) -> RunResult<()> {
    if !fs::symlink_metadata(&options.root)?.file_type().is_dir()
        || !fs::symlink_metadata(options.root.join("LAYOUT"))?.file_type().is_file()
    { return Err(io::Error::other("existing non-symlink deployment required").into()); }
    // The authenticated local process and filesystem are the boundary. The principal is an
    // audit label, not remote authentication; no model, device-control or notification grant.
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:event-cli".into(), operation_id: OperationId::parse("operation:event-cli")?,
        principal: options.principal, capabilities: vec!["ADP-REPLAY-001".into()], deadline: None, priority: 10,
        budgets: BudgetVector::builder().bytes(options.limits.maximum_report_bytes as u64).build()?,
        privacy_scope: "privacy:local-authorized-files".into(), retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()), generation: 1,
    })?;
    authority.validate()?;
    let cx = ReplayCx::from_context_authority(&authority, options.root.clone())?;
    let result = (|| -> RunResult<()> {
        let mut deployment = ReferenceDeployment::open(&options.root, &options.site, &cx)?;
        let mut budget = AnalysisBudget::new(options.detection_units, options.association_units);
        let (event, receipt, operation) = match &options.action {
            Action::Watch(action) => {
                watch::run(action, &mut deployment, &options.root, &cx, out)?;
                return Ok(());
            }
            Action::Report { import, interpretation, detector, tracking, runs, output } => {
                let plan = AnalysisPlan::new(*import, *interpretation, detector.clone(), *tracking, read_runs(runs, &cx)?)?;
                let report = AnalysisReport::read(&deployment, &plan, &options.limits, &mut budget, &cx)?;
                export(output, report.encoded(), &options.root, &cx)?;
                let tracks: BTreeSet<_> = report.observations().iter().flat_map(|o| &o.tracking().tracks)
                    .filter(|t| t.observed_row.is_some()).map(|t| t.id).collect();
                writeln!(out, "operation=report_verified\nreport_digest={}\nplan_digest={}\nframes={}\ntrack_count={}",
                    report.digest(), plan.digest(), report.observations().len(), tracks.len())?;
                for track in tracks { writeln!(out, "track={track}")?; }
                writeln!(out, "detection_work_units={}\nassociation_work_units={}\nabsence_certifiable=false\neffects_authorized=false",
                    budget.detection.used(), budget.association.used())?;
                return Ok(());
            }
            Action::Read(id) => {
                let record = RecordedEvent::open(&deployment, id, &options.limits, &mut budget, &cx)?;
                (record.event().clone(), Some(record), "read_verified")
            }
            Action::Prepare { report, digest, track } | Action::Publish { report, digest, track, .. } => {
                let bytes = load(report, options.limits.maximum_report_bytes, *digest, &cx)?;
                let proposal = RecordedEventProposal::prepare(&deployment, &bytes, *digest, *track,
                    &options.limits, &mut budget, &cx)?;
                match &options.action {
                    Action::Publish { approved, .. } => {
                        let record = proposal.publish(&mut deployment, *approved, &options.limits, &mut budget, &cx)?;
                        (record.event().clone(), Some(record), "published")
                    }
                    _ => {
                        writeln!(out, "proposal_digest={}", proposal.digest())?;
                        (proposal.event().clone(), None, "prepared")
                    }
                }
            }
        };
        if let Some(path) = &options.event_out {
            export(path, event.to_canonical_json().as_bytes(), &options.root, &cx)?;
        }
        if let Some(record) = &receipt {
            if let Some(path) = &options.report_out { export(path, record.report().encoded(), &options.root, &cx)?; }
            writeln!(out, "event_root={}\nauthority_sequence={}\nreport_digest={}\ntrack={}",
                record.root(), record.authority_anchor().commit_sequence, record.report().digest(), record.track())?;
        }
        writeln!(out, "operation={operation}\nevent_id={}\nrevision={}\nevent_revision_digest={}\nprovenance_root={}",
            event.event_id, event.revision, event.revision_digest(), event.decision_path.fingerprint)?;
        writeln!(out, "event_state={}\nevent_kind={}\nmodel_receipts={}\nevidence_items={}\ndetection_work_units={}\nassociation_work_units={}",
            event.state.as_str(), event.kind.as_str(), event.model_receipts.len(), event.evidence.len(),
            budget.detection.used(), budget.association.used())?;
        writeln!(out, "absence_certifiable=false\neffects_authorized=false")?;
        Ok(())
    })();
    cx.drain_and_finalize(); result
}
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match parse(&args) {
        Ok(None) => match io::stdout().lock().write_all(HELP.as_bytes()) {
            Ok(()) => ExitCode::from(0), Err(_) => ExitCode::from(1),
        },
        Ok(Some(options)) => match run(options, &mut io::stdout().lock()) {
            Ok(()) => ExitCode::from(0),
            Err(e) => {
                eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {e}");
                if let Some(refusal) = e.downcast_ref::<fss_reference::ingest::recorded_watch::WatchError>() {
                    eprintln!("refusal_id={}", refusal.stable_id());
                }
                eprintln!("Durable provenance/events are not rolled back by later failures; incomplete exports may remain.");
                ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
            }
        },
        Err(reason) => {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: {reason}; use fss-event help");
            ExitCode::from(ExitIdentity::MALFORMED_VALUE.code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(action: &str) -> Vec<OsString> {
        [action, "--root", "unused", "--site", "site:test", "--report", "report.bin", "--report-digest",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111", "--track",
            "sha256:2222222222222222222222222222222222222222222222222222222222222222"]
            .into_iter().map(OsString::from).collect()
    }
    #[test]
    fn publishing_requires_exact_approval() {
        assert!(parse(&args("prepare")).is_ok());
        assert!(parse(&args("publish")).is_err());
        let mut approved = args("publish"); approved.extend(["--proposal-digest", "sha256:3333333333333333333333333333333333333333333333333333333333333333"].into_iter().map(OsString::from));
        assert!(parse(&approved).is_ok());
    }
    #[test]
    fn duplicate_unknown_inapplicable_and_unbounded_options_are_refused() {
        for extra in [["--site", "other"], ["--approve-latest", "yes"], ["--proposal-digest", "bad"],
            ["--max-report-bytes", "0"], ["--max-report-bytes", "16777217"]] {
            let mut argv = args("prepare"); argv.extend(extra.into_iter().map(OsString::from));
            assert!(parse(&argv).is_err());
        }
    }
    #[cfg(unix)]
    #[test]
    fn report_paths_preserve_native_os_bytes() {
        use std::os::unix::ffi::OsStringExt;
        let mut argv = args("prepare"); argv[6] = OsString::from_vec(b"report-\xff.bin".to_vec());
        assert!(parse(&argv).is_ok());
    }
}

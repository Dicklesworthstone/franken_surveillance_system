#![forbid(unsafe_code)]
//! Explicit local-owner inspection and source-backed replay of committed long-dwell events.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use fss_cli::agent_json::{array, evidence_anchor, object, string};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, DigestAlgorithm, EventId, OperationId, PrincipalId};
use fss_reference::ingest::long_dwell_replay::{DwellReplayInspection, DwellReplayLimits, DwellReplayPins, inspect_dwell, replay_dwell};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::{DeploymentLayout, ReferenceDeployment, ReplayCx};

type Run<T> = Result<T, Box<dyn Error>>;
const HELP: &str = "fss-replay-dwell inspect --root EXISTING_DIR --site SITE --event-id EVENT\n\
fss-replay-dwell verify --root EXISTING_DIR --site SITE --event-id EVENT\n\
  --expected-event-revision sha256:HEX --expected-analysis-root sha256:HEX\n\
  --execute-perception yes [bounds]\n\
Inspect reconstructs the original retained recipe; it does NOT execute or verify perception.\n\
Verify natively decodes retained MJPEG, applies current privacy, and reruns foreground, tracking,\n\
dwell and the original optional health screen. The entire trace and committed event must match.\n\
No original input path, saved CLI command, external model, network or pixel export is needed.\n\
Changed privacy, missing custody, stale pins, unsupported profiles and divergence fail closed.\n\
Common bounds: --max-metadata-bytes N --max-report-bytes N [--principal ID]\n\
Execution bounds: --source-read-bytes N --pixel-budget N --assignment-work N --trace-bytes N\n\
  --decode-work N --max-dimension N --max-pixels N --max-segment-bytes N\n\
Only a current v1 whole-recording dwell event is admitted, not a preview or short-watch event.\n\
No threshold, zone, source, range, screening, approval or event-state override is accepted.\n\
Opening uses existing exclusive locks and restart recovery; it is not universally mutation-free.\n\
Inspection/replay themselves do not append authority or effects. Matching means reproducibility,\n\
not physical truth, detection quality, health, absence, alert delivery or release qualification.\n";
const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const COMMON: &[&str] = &["--root", "--site", "--event-id", "--principal", "--max-metadata-bytes", "--max-report-bytes"];
const EXECUTION: &[&str] = &["--expected-event-revision", "--expected-analysis-root", "--execute-perception",
    "--source-read-bytes", "--pixel-budget", "--assignment-work", "--trace-bytes", "--decode-work",
    "--max-dimension", "--max-pixels", "--max-segment-bytes"];

#[derive(Debug)]
struct Options {
    root: PathBuf,
    site: String,
    principal: String,
    event: EventId,
    pins: Option<DwellReplayPins>,
    limits: DwellReplayLimits,
    maximum_report_bytes: usize,
}
fn text<'a>(values: &'a BTreeMap<String, OsString>, key: &str) -> Result<&'a str, String> {
    values.get(key).ok_or_else(|| format!("required option {key}"))?.to_str().ok_or_else(|| format!("{key} requires UTF-8"))
}
fn number(values: &BTreeMap<String, OsString>, key: &str, default: u64, maximum: u64) -> Result<u64, String> {
    let n = if values.contains_key(key) {
        let value = text(values, key)?;
        if !value.bytes().all(|b| b.is_ascii_digit()) { return Err(format!("{key} requires unsigned decimal")); }
        value.parse().map_err(|_| format!("{key} integer overflow"))?
    } else { default };
    if n == 0 || n > maximum { return Err(format!("{key} outside bounds")); }
    Ok(n)
}
fn digest(value: &str) -> Result<ContentDigest, String> {
    let value = ContentDigest::parse(value).map_err(|_| "invalid content digest")?;
    if value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32] { return Err("nonzero SHA-256 required".into()); }
    Ok(value)
}
fn parse(args: &[OsString]) -> Result<Options, String> {
    if args.len() > 37 || args.iter().any(|v| v.as_encoded_bytes().len() > 4096) { return Err("argument bounds exceeded".into()); }
    let verify = match args.first().and_then(|s| s.to_str()) {
        Some("inspect") => false, Some("verify") => true, _ => return Err("expected inspect or verify".into()),
    };
    let mut values = BTreeMap::new();
    for pair in args[1..].chunks(2) {
        let key = pair[0].to_str().ok_or("option names require UTF-8")?;
        if !COMMON.contains(&key) && !(verify && EXECUTION.contains(&key)) { return Err(format!("unknown or inapplicable option {key}")); }
        let value = pair.get(1).filter(|v| !v.is_empty() && !v.to_str().is_some_and(|v| v.starts_with("--"))).ok_or("missing option value")?;
        if values.insert(key.to_owned(), value.clone()).is_some() { return Err(format!("duplicate {key}")); }
    }
    let root = PathBuf::from(values.get("--root").ok_or("required option --root")?);
    if !root.is_absolute() { return Err("--root must be absolute".into()); }
    let site = text(&values, "--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site).map_err(|_| "invalid site")?;
    let principal = if values.contains_key("--principal") { text(&values, "--principal")? } else { "principal:local-operator" }.to_owned();
    if site.len() > 256 || principal.len() > 128 { return Err("site or principal exceeds bound".into()); }
    PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
    let event = EventId::parse(text(&values, "--event-id")?).map_err(|_| "invalid event identity")?;
    let pins = if verify {
        if text(&values, "--execute-perception")? != "yes" { return Err("explicit --execute-perception yes is required".into()); }
        Some(DwellReplayPins {
            event_revision: digest(text(&values, "--expected-event-revision")?)?,
            analysis_root: digest(text(&values, "--expected-analysis-root")?)?,
        })
    } else { None };
    let mut limits = DwellReplayLimits::default();
    limits.maximum_metadata_bytes = number(&values, "--max-metadata-bytes", limits.maximum_metadata_bytes as u64, 32 * 1024 * 1024)? as usize;
    let maximum_report_bytes = number(&values, "--max-report-bytes", 65_536, 1024 * 1024)? as usize;
    let execution = &mut limits.execution;
    execution.maximum_source_chunk_bytes = number(&values, "--source-read-bytes", execution.maximum_source_chunk_bytes, 512 * 1024 * 1024)?;
    execution.maximum_pixel_samples = number(&values, "--pixel-budget", execution.maximum_pixel_samples, 64 * 1024 * 1024 * 1024)?;
    execution.maximum_assignment_work = number(&values, "--assignment-work", execution.maximum_assignment_work, 64 * 1024 * 1024 * 1024)?;
    execution.maximum_trace_bytes = number(&values, "--trace-bytes", execution.maximum_trace_bytes as u64, 8 * 1024 * 1024)? as usize;
    execution.decode.jpeg_work_units = number(&values, "--decode-work", execution.decode.jpeg_work_units, 1_000_000_000_000)?;
    execution.decode.jpeg_limits.maximum_dimension = number(&values, "--max-dimension", 4096, 4096)? as u32;
    execution.decode.jpeg_limits.maximum_pixels = number(&values, "--max-pixels", 4_194_304, 4_194_304)? as usize;
    execution.decode.read_limits.max_segment_bytes = number(&values, "--max-segment-bytes", execution.decode.read_limits.max_segment_bytes, 64 * 1024 * 1024)?;
    limits.validate().map_err(|e| e.to_string())?;
    Ok(Options { root, site, principal, event, pins, limits, maximum_report_bytes })
}

// Existing local-owner boundary: refuse absent deployments before ReplayCx can create a root.
// No arbitrary destination, report-file write, command execution, or recursive path walk exists.
fn preflight(root: &Path, site: &str, authority: &ContextAuthority) -> Run<PathBuf> {
    authority.validate()?;
    if !authority.has_capability("ADP-REPLAY-001") || authority.anchor_universe != ContentDigest::sha256(site.as_bytes()) {
        return Err("deployment-read authority does not match the requested site".into());
    }
    if !fs::symlink_metadata(root)?.file_type().is_dir() { return Err("existing non-symlink deployment directory required".into()); }
    let root = fs::canonicalize(root)?;
    let path = root.join("LAYOUT");
    let meta = fs::symlink_metadata(&path)?;
    if !meta.file_type().is_file() || meta.len() > 4096 { return Err("regular bounded deployment layout required".into()); }
    let mut bytes = Vec::new();
    File::open(&path)?.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 { return Err("deployment layout exceeds bound".into()); }
    let layout = DeploymentLayout::parse_canonical_text(std::str::from_utf8(&bytes)?)?;
    if layout.site_lineage != site { return Err("deployment site does not match".into()); }
    for relative in [layout.ledger_relpath, layout.effects_relpath] {
        let meta = fs::symlink_metadata(root.join(relative))?;
        if !meta.file_type().is_file() || meta.len() > MAX_JOURNAL_BYTES { return Err("regular existing journals at most 64 MiB required".into()); }
    }
    Ok(root)
}
fn quote(value: &str) -> String { format!("'{}'", value.replace('\'', "'\\''")) }
fn command(options: &Options, root: &Path, inspected: &DwellReplayInspection) -> Option<String> {
    let limits = options.limits;
    Some(format!(concat!(
        "fss-replay-dwell verify --root {} --site {} --principal {} --event-id {} ",
        "--expected-event-revision {} --expected-analysis-root {} --execute-perception yes ",
        "--max-metadata-bytes {} --max-report-bytes {} --source-read-bytes {} --pixel-budget {} ",
        "--assignment-work {} --trace-bytes {} --decode-work {} --max-dimension {} --max-pixels {} --max-segment-bytes {}"),
        quote(root.to_str()?), quote(&options.site), quote(&options.principal), quote(options.event.as_str()),
        inspected.pins().event_revision, inspected.pins().analysis_root,
        limits.maximum_metadata_bytes, options.maximum_report_bytes, limits.execution.maximum_source_chunk_bytes,
        limits.execution.maximum_pixel_samples, limits.execution.maximum_assignment_work,
        limits.execution.maximum_trace_bytes, limits.execution.decode.jpeg_work_units,
        limits.execution.decode.jpeg_limits.maximum_dimension, limits.execution.decode.jpeg_limits.maximum_pixels,
        limits.execution.decode.read_limits.max_segment_bytes))
}
fn report(options: &Options, root: &Path, inspected: &DwellReplayInspection, execution: Option<(usize, u64)>) -> Run<String> {
    let recipe = inspected.recipe();
    let plan = recipe.plan();
    let zones: Vec<_> = plan.zones.iter().map(|z| object(&[
        ("zone_id", string(&z.zone_id)), ("x", z.x.to_string()), ("y", z.y.to_string()),
        ("width", z.width.to_string()), ("height", z.height.to_string()),
    ])).collect();
    let verified = execution.is_some();
    let body = object(&[
        ("operation", string(if verified { "replay_dwell" } else { "inspect_dwell" })),
        ("status", string(if verified { "native_replay_matched" } else { "inspected_not_replayed" })),
        ("event_id", string(inspected.event().event_id.as_str())),
        ("event_revision_digest", string(&inspected.pins().event_revision.to_text())),
        ("event_root", string(&inspected.event_root().to_text())),
        ("analysis_root", string(&inspected.pins().analysis_root.to_text())),
        ("analysis_digest", string(&inspected.analysis_digest().to_text())),
        ("anchor", evidence_anchor(inspected.basis())),
        ("native_replayed", verified.to_string()),
        ("frames_replayed", execution.map_or_else(|| "null".into(), |(frames, _)| frames.to_string())),
        ("source_chunk_bytes_read", execution.map_or_else(|| "null".into(), |(_, bytes)| bytes.to_string())),
        ("metadata_payload_bytes_read", inspected.metadata_bytes_read().to_string()),
        ("bounds", object(&[
            ("metadata_bytes", options.limits.maximum_metadata_bytes.to_string()),
            ("source_chunk_bytes", options.limits.execution.maximum_source_chunk_bytes.to_string()),
            ("pixel_samples", options.limits.execution.maximum_pixel_samples.to_string()),
            ("assignment_work", options.limits.execution.maximum_assignment_work.to_string()),
            ("trace_bytes", options.limits.execution.maximum_trace_bytes.to_string()),
            ("jpeg_work", options.limits.execution.decode.jpeg_work_units.to_string()),
            ("report_bytes", options.maximum_report_bytes.to_string()),
        ])),
        ("import_identity", string(&plan.import_identity.to_text())),
        ("sensor", string(recipe.sensor().as_str())),
        ("first_segment", plan.first_segment.to_string()),
        ("segment_count", plan.segment_count.to_string()),
        ("interpretation", string(match plan.interpretation { ComponentInterpretation::Grayscale => "gray", ComponentInterpretation::YCbCr => "ycbcr" })),
        ("zones", array(&zones)),
        ("minimum_duration_ns", string(&recipe.rule().minimum_duration_ns.to_string())),
        ("maximum_sample_gap_ns", string(&recipe.rule().maximum_sample_gap_ns.to_string())),
        ("minimum_observations", recipe.rule().minimum_observations.to_string()),
        ("tolerate_decode_refusals", recipe.options().tolerate_decode_refusals.to_string()),
        ("screening_policy", if recipe.screened() { string("conservative-v1") } else { "null".into() }),
        ("perception", object(&[
            ("base_threshold", plan.detector.base_threshold.to_string()), ("threshold_sigma", plan.detector.threshold_sigma.to_string()),
            ("learning_rate_num", plan.detector.learning_rate_num.to_string()), ("learning_rate_den", plan.detector.learning_rate_den.to_string()),
            ("minimum_region_pixels", plan.detector.minimum_region_pixels.to_string()),
            ("confirmation_hits", plan.tracker.confirmation_hits.to_string()),
            ("maximum_missed_frames", plan.tracker.maximum_missed_frames.to_string()),
            ("minimum_iou_ppm", plan.tracker.minimum_iou_ppm.to_string()),
        ])),
        ("verification_command", if verified { "null".into() } else { command(options, root, inspected).map_or_else(|| "null".into(), |s| string(&s)) }),
        ("event_state", string(inspected.event().state.as_str())),
        ("capture_time_label", string("operator_assumption")),
        ("persistent_verification_record_written", "false".into()),
        ("physical_truth_verified", "false".into()), ("health_certified", "false".into()),
        ("absence_certifiable", "false".into()), ("alert_authorized", "false".into()),
        ("qualification", string("implemented_not_qualified")),
    ]);
    if body.len().checked_add(1).is_none_or(|n| n > options.maximum_report_bytes) { return Err("complete replay report exceeds byte bound".into()); }
    Ok(format!("{body}\n"))
}
fn run(options: Options) -> Run<String> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:dwell-replay-cli".into(), operation_id: OperationId::parse("operation:dwell-replay-cli")?,
        principal: options.principal.clone(), capabilities: vec!["ADP-REPLAY-001".into()], deadline: None,
        priority: 10, budgets: BudgetVector::builder().bytes(128 * 1024 * 1024).storage_operations(65_536).build()?,
        privacy_scope: "privacy:current-deployment-policy".into(), retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()), generation: 1,
    })?;
    authority.validate()?;
    let root = preflight(&options.root, &options.site, &authority)?;
    let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
    let result = (|| -> Run<String> {
        let deployment = ReferenceDeployment::open(&root, &options.site, &cx)?;
        match options.pins {
            None => report(&options, &root, &inspect_dwell(&deployment, &options.event, &options.limits, &cx)?, None),
            Some(pins) => {
                let verified = replay_dwell(&deployment, &options.event, pins, &options.limits, &cx)?;
                report(&options, &root, verified.inspection(), Some((verified.frames_replayed(), verified.source_chunk_bytes_read())))
            }
        }
    })();
    cx.drain_and_finalize();
    result
}
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && ["help", "--help", "-h"].iter().any(|s| args[0] == *s) {
        return match io::stdout().lock().write_all(HELP.as_bytes()) { Ok(()) => ExitCode::SUCCESS, Err(_) => ExitCode::from(1) };
    }
    let options = match parse(&args) {
        Ok(options) => options,
        Err(error) => { eprintln!("{ERR_CLI_MALFORMED_VALUE}: {error}"); return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code); }
    };
    match run(options).and_then(|json| { io::stdout().lock().write_all(json.as_bytes())?; Ok(()) }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => { eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}"); ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code) }
    }
}

#![forbid(unsafe_code)]
//! Cold inspection and explicit native replay of retained whole-recording events.
//!
//! Read inspects metadata. Verify separately admits native computation against exact selection
//! pins. Neither operation accepts an unanchored analysis file or an interpretation override.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fss_cli::agent_json::{digests, evidence_anchor, object, string};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, DigestAlgorithm, EventId, OperationId, PrincipalId};
use fss_reference::ingest::long_event_replay::{
    LongEventReplayInspection, LongEventReplayLimits, LongEventReplayPins, LongEventReplayRecipe,
    inspect_long_event, replay_long_event,
};
use fss_reference::{DeploymentLayout, ReferenceDeployment, ReplayCx};

type Run<T> = Result<T, Box<dyn Error>>;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;
const HELP: &str = "fss-event read --root EXISTING_DIR --site SITE --event-id EVENT\n\
fss-event verify --root EXISTING_DIR --site SITE --event-id EVENT\n\
  --expected-event-revision sha256:HEX --expected-provenance-root sha256:HEX\n\
  --execute-perception yes\n\
Supports committed event:long-watch: and event:long-corroborated: candidates.\n\
Read inspects retained event/analysis custody without decoding media. Its JSON contains exact\n\
verification pins and a verification command. Model-free watch retains its semantic recipe\n\
and five aggregate budgets; historical codec/read ceilings use current caller bounds.\n\
Detector-backed watch and corroboration retain complete canonical execution recipes.\n\
Verify natively decodes retained MJPEG/H.264/H.265, applies current privacy and reruns the\n\
original foreground/tracker, zone or ground gates, dependencies and optional health screen.\n\
Detector-backed watch also reloads its retained model archive and reruns the exact bounded\n\
RGB inference, threshold and association policy with the original kernel generation.\n\
Every complete analysis and the committed event must match. No source file, saved report,\n\
threshold, zone, model, screening override, publication approval or network is accepted.\n\
Common bounds: --max-metadata-bytes N (default 64 MiB, maximum 256 MiB)\n\
  --max-report-bytes N (default 1 MiB, maximum 16 MiB) [--principal ID]\n\
Per-camera execution ceilings (also accepted by read to bind its verification command):\n\
  --source-read-bytes N --pixel-budget N --assignment-work N --trace-bytes N\n\
  --decode-work N --max-dimension N --max-pixels N --max-segment-bytes N\n\
Ceilings may refuse replay; they cannot change the retained computation recipe.\n\
Optional create-only exports: --event-out FILE (event JSON), --report-out FILE (this JSON);\n\
both must be outside the deployment. Missing custody, stale pins, changed privacy, reviewed\n\
revisions, exhausted bounds and divergence fail closed with no success output.\n\
Existing deployment open takes exclusive locks and may perform restart recovery. Inspection\n\
and replay append no authority or effects. A match proves reproducibility, not physical\n\
truth, detector accuracy, independent sensors, health, absence or alert delivery.\n";

const COMMON: &[&str] = &[
    "--root",
    "--site",
    "--event-id",
    "--principal",
    "--max-metadata-bytes",
    "--max-report-bytes",
    "--source-read-bytes",
    "--pixel-budget",
    "--assignment-work",
    "--trace-bytes",
    "--decode-work",
    "--max-dimension",
    "--max-pixels",
    "--max-segment-bytes",
    "--event-out",
    "--report-out",
];
const VERIFY: &[&str] = &[
    "--expected-event-revision",
    "--expected-provenance-root",
    "--execute-perception",
];

#[derive(Debug)]
struct Options {
    root: PathBuf,
    site: String,
    principal: String,
    event: EventId,
    pins: Option<LongEventReplayPins>,
    limits: LongEventReplayLimits,
    maximum_report_bytes: usize,
    event_out: Option<PathBuf>,
    report_out: Option<PathBuf>,
}

fn supported(value: &str) -> bool {
    value.starts_with("event:long-watch:") || value.starts_with("event:long-corroborated:")
}

/// Keep every existing non-stream event read on its original parser and output contract.
pub(super) fn handles(args: &[OsString]) -> bool {
    args.first().is_some_and(|value| value == "verify")
        || (args.first().is_some_and(|value| value == "read")
            && args
                .windows(2)
                .any(|pair| pair[0] == "--event-id" && pair[1].to_str().is_some_and(supported)))
}

fn text<'a>(values: &'a BTreeMap<String, OsString>, key: &str) -> Result<&'a str, String> {
    values
        .get(key)
        .ok_or_else(|| format!("required option {key}"))?
        .to_str()
        .ok_or_else(|| format!("{key} requires UTF-8"))
}
fn number(
    values: &BTreeMap<String, OsString>,
    key: &str,
    default: u64,
    maximum: u64,
) -> Result<u64, String> {
    let n = if values.contains_key(key) {
        let value = text(values, key)?;
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("{key} requires unsigned decimal"));
        }
        value
            .parse()
            .map_err(|_| format!("{key} integer overflow"))?
    } else {
        default
    };
    if n == 0 || n > maximum {
        return Err(format!("{key} outside bounds"));
    }
    Ok(n)
}
fn digest(value: &str) -> Result<ContentDigest, String> {
    let value = ContentDigest::parse(value).map_err(|_| "invalid content digest")?;
    if value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32] {
        return Err("nonzero SHA-256 required".into());
    }
    Ok(value)
}
fn parse(args: &[OsString]) -> Result<Options, String> {
    if args.len() > 39 || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096) {
        return Err("argument bounds exceeded".into());
    }
    let verify = match args.first().and_then(|value| value.to_str()) {
        Some("read") => false,
        Some("verify") => true,
        _ => return Err("expected read or verify".into()),
    };
    let mut values = BTreeMap::new();
    for pair in args[1..].chunks(2) {
        let key = pair[0].to_str().ok_or("option names require UTF-8")?;
        if !COMMON.contains(&key) && !(verify && VERIFY.contains(&key)) {
            return Err(format!("unknown or inapplicable option {key}"));
        }
        let value = pair
            .get(1)
            .filter(|value| {
                !value.is_empty() && !value.to_str().is_some_and(|s| s.starts_with("--"))
            })
            .ok_or_else(|| format!("missing value for {key}"))?;
        if values.insert(key.to_owned(), value.clone()).is_some() {
            return Err(format!("duplicate {key}"));
        }
    }
    let root = PathBuf::from(values.get("--root").ok_or("required option --root")?);
    if !root.is_absolute() {
        return Err("--root must be absolute".into());
    }
    let site = text(&values, "--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| "invalid site lineage")?;
    let principal = values
        .get("--principal")
        .map_or(Ok("principal:local-operator"), |value| {
            value.to_str().ok_or("--principal requires UTF-8")
        })?
        .to_owned();
    if site.len() > 256 || principal.len() > 128 {
        return Err("site or principal exceeds bound".into());
    }
    PrincipalId::parse(&principal).map_err(|_| "invalid principal ID")?;
    let event = EventId::parse(text(&values, "--event-id")?).map_err(|_| "invalid event ID")?;
    let suffix = event
        .as_str()
        .strip_prefix("event:long-watch:")
        .or_else(|| event.as_str().strip_prefix("event:long-corroborated:"))
        .ok_or("cold read/verify requires a long-watch or long-corroborated event")?;
    if suffix.len() != 64
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("long-event ID requires exactly 64 lowercase hexadecimal digits".into());
    }
    let pins = if verify {
        if text(&values, "--execute-perception")? != "yes" {
            return Err("--execute-perception must be yes".into());
        }
        Some(LongEventReplayPins {
            event_revision: digest(text(&values, "--expected-event-revision")?)?,
            provenance_root: digest(text(&values, "--expected-provenance-root")?)?,
        })
    } else {
        None
    };
    let mut limits = LongEventReplayLimits::default();
    limits.maximum_metadata_bytes = number(
        &values,
        "--max-metadata-bytes",
        limits.maximum_metadata_bytes as u64,
        256 * 1024 * 1024,
    )? as usize;
    let execution = &mut limits.execution;
    execution.maximum_source_chunk_bytes = number(
        &values,
        "--source-read-bytes",
        execution.maximum_source_chunk_bytes,
        512 * 1024 * 1024,
    )?;
    execution.maximum_pixel_samples = number(
        &values,
        "--pixel-budget",
        execution.maximum_pixel_samples,
        64 * 1024 * 1024 * 1024,
    )?;
    execution.maximum_assignment_work = number(
        &values,
        "--assignment-work",
        execution.maximum_assignment_work,
        64 * 1024 * 1024 * 1024,
    )?;
    execution.maximum_trace_bytes = number(
        &values,
        "--trace-bytes",
        execution.maximum_trace_bytes as u64,
        8 * 1024 * 1024,
    )? as usize;
    execution.decode.jpeg_work_units = number(
        &values,
        "--decode-work",
        execution.decode.jpeg_work_units,
        1_000_000_000_000,
    )?;
    execution.decode.read_limits.max_segment_bytes = number(
        &values,
        "--max-segment-bytes",
        execution.decode.read_limits.max_segment_bytes,
        64 * 1024 * 1024,
    )?;
    let dimension = number(&values, "--max-dimension", 4096, 4096)? as u32;
    if dimension < 16 {
        return Err("--max-dimension must be 16..4096".into());
    }
    let pixels = number(&values, "--max-pixels", 4_194_304, 4_194_304)? as usize;
    execution.decode.jpeg_limits.maximum_dimension = dimension;
    execution.decode.jpeg_limits.maximum_pixels = pixels;
    execution.decode.h264_limits.max_width = dimension;
    execution.decode.h264_limits.max_height = dimension;
    execution.decode.h264_limits.max_macroblocks =
        u32::try_from(pixels.div_ceil(256)).map_err(|_| "pixel bound")?;
    execution.decode.h265_limits.max_width = dimension;
    execution.decode.h265_limits.max_height = dimension;
    execution.decode.h265_limits.max_luma_samples = pixels as u64;
    limits.validate().map_err(|error| error.to_string())?;
    Ok(Options {
        root,
        site,
        principal,
        event,
        pins,
        limits,
        maximum_report_bytes: number(
            &values,
            "--max-report-bytes",
            1024 * 1024,
            MAX_REPORT_BYTES as u64,
        )? as usize,
        event_out: values.get("--event-out").map(PathBuf::from),
        report_out: values.get("--report-out").map(PathBuf::from),
    })
}

// Refuse absent/wrong-site deployments before ReplayCx can create anything. Existing restart
// recovery retains its owning semantics; replay never calls a publication method.
fn preflight(root: &Path, site: &str, authority: &ContextAuthority) -> Run<PathBuf> {
    authority.validate()?;
    if !authority.has_capability("ADP-REPLAY-001")
        || authority.anchor_universe != ContentDigest::sha256(site.as_bytes())
    {
        return Err("deployment-read authority does not match the requested site".into());
    }
    if !fs::symlink_metadata(root)?.file_type().is_dir() {
        return Err("existing non-symlink deployment directory required".into());
    }
    let root = fs::canonicalize(root)?;
    let path = root.join("LAYOUT");
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_file() || metadata.len() > 4096 {
        return Err("regular bounded deployment layout required".into());
    }
    let mut bytes = Vec::new();
    File::open(path)?.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err("deployment layout exceeds bound".into());
    }
    let layout = DeploymentLayout::parse_canonical_text(std::str::from_utf8(&bytes)?)?;
    if layout.site_lineage != site {
        return Err("deployment site does not match".into());
    }
    for relative in [layout.ledger_relpath, layout.effects_relpath] {
        let metadata = fs::symlink_metadata(root.join(relative))?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_JOURNAL_BYTES {
            return Err("regular existing journals at most 64 MiB required".into());
        }
    }
    Ok(root)
}
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
fn command(
    options: &Options,
    root: &Path,
    inspection: &LongEventReplayInspection,
) -> Option<String> {
    let limits = &options.limits;
    Some(format!(
        concat!(
            "fss-event verify --root {} --site {} --principal {} --event-id {} ",
            "--expected-event-revision {} --expected-provenance-root {} --execute-perception yes ",
            "--max-metadata-bytes {} --max-report-bytes {} --source-read-bytes {} --pixel-budget {} ",
            "--assignment-work {} --trace-bytes {} --decode-work {} --max-dimension {} --max-pixels {} --max-segment-bytes {}"
        ),
        quote(root.to_str()?),
        quote(&options.site),
        quote(&options.principal),
        quote(options.event.as_str()),
        inspection.pins().event_revision,
        inspection.pins().provenance_root,
        limits.maximum_metadata_bytes,
        options.maximum_report_bytes,
        limits.execution.maximum_source_chunk_bytes,
        limits.execution.maximum_pixel_samples,
        limits.execution.maximum_assignment_work,
        limits.execution.maximum_trace_bytes,
        limits.execution.decode.jpeg_work_units,
        limits.execution.decode.jpeg_limits.maximum_dimension,
        limits.execution.decode.jpeg_limits.maximum_pixels,
        limits.execution.decode.read_limits.max_segment_bytes
    ))
}
fn report(
    options: &Options,
    root: &Path,
    inspection: &LongEventReplayInspection,
    execution: Option<(usize, u64)>,
) -> Run<String> {
    let verified = execution.is_some();
    let limits = &options.limits.execution;
    let (detector, complete_codec_limits) = match inspection.recipe() {
        LongEventReplayRecipe::Watch(recipe) => (
            recipe.detector_recipe(),
            recipe.complete_codec_limits_retained(),
        ),
        LongEventReplayRecipe::Corroboration(_) => (None, true),
    };
    let mut fields = vec![
        (
            "operation",
            string(if verified {
                "verify_long_event"
            } else {
                "read_long_event"
            }),
        ),
        (
            "status",
            string(if verified {
                "native_replay_matched"
            } else {
                "inspected_not_replayed"
            }),
        ),
        ("profile", string(inspection.profile())),
        ("event_id", string(inspection.event().event_id.as_str())),
        (
            "event_revision_digest",
            string(&inspection.pins().event_revision.to_text()),
        ),
        ("event_root", string(&inspection.event_root().to_text())),
        (
            "provenance_root",
            string(&inspection.pins().provenance_root.to_text()),
        ),
        (
            "decision_fingerprint",
            string(&inspection.event().decision_path.fingerprint.to_text()),
        ),
        ("analysis_roots", digests(inspection.analysis_roots())),
        ("analysis_digests", digests(inspection.analysis_digests())),
        ("anchor", evidence_anchor(inspection.basis())),
        ("native_replayed", verified.to_string()),
        (
            "frames_replayed",
            execution.map_or_else(|| "null".into(), |value| value.0.to_string()),
        ),
        (
            "source_chunk_bytes_read",
            execution.map_or_else(|| "null".into(), |value| value.1.to_string()),
        ),
        (
            "metadata_payload_bytes_read",
            inspection.metadata_bytes_read().to_string(),
        ),
        (
            "execution_budget_scope",
            string("per_camera_complete_recording"),
        ),
        (
            "bounds",
            object(&[
                (
                    "metadata_bytes",
                    options.limits.maximum_metadata_bytes.to_string(),
                ),
                (
                    "source_chunk_bytes",
                    limits.maximum_source_chunk_bytes.to_string(),
                ),
                ("pixel_samples", limits.maximum_pixel_samples.to_string()),
                (
                    "assignment_work",
                    limits.maximum_assignment_work.to_string(),
                ),
                ("trace_bytes", limits.maximum_trace_bytes.to_string()),
                ("jpeg_work", limits.decode.jpeg_work_units.to_string()),
                (
                    "max_dimension",
                    limits.decode.jpeg_limits.maximum_dimension.to_string(),
                ),
                (
                    "max_pixels",
                    limits.decode.jpeg_limits.maximum_pixels.to_string(),
                ),
                (
                    "max_segment_bytes",
                    limits.decode.read_limits.max_segment_bytes.to_string(),
                ),
                ("report_bytes", options.maximum_report_bytes.to_string()),
            ]),
        ),
        (
            "configuration_source",
            string(if detector.is_some() {
                "retained_canonical_watch_and_detector_recipe"
            } else if inspection.profile() == "long_watch" {
                "retained_semantic_recipe_and_five_aggregate_budgets"
            } else {
                "retained_canonical_recipe"
            }),
        ),
        (
            "decoder_and_read_ceiling_source",
            string(if complete_codec_limits {
                "retained_recipe_subject_to_caller_safety_ceilings"
            } else {
                "current_caller_bounded_ceilings_historical_ceilings_not_retained"
            }),
        ),
        (
            "verification_command",
            if verified {
                "null".into()
            } else {
                command(options, root, inspection)
                    .map_or_else(|| "null".into(), |value| string(&value))
            },
        ),
        ("event", inspection.event().to_canonical_json()),
        ("persistent_verification_record_written", "false".into()),
        ("physical_truth_verified", "false".into()),
        ("health_certified", "false".into()),
        ("absence_certifiable", "false".into()),
        ("alert_authorized", "false".into()),
        ("qualification", string("implemented_not_qualified")),
    ];
    if let Some(recipe) = detector {
        let config = recipe.config();
        fields.push((
            "retained_detector",
            object(&[
                ("recipe_digest", string(&recipe.digest().to_text())),
                ("package_digest", string(&recipe.package_digest().to_text())),
                (
                    "manifest_digest",
                    string(&recipe.manifest_digest().to_text()),
                ),
                ("model_digest", string(&recipe.model_digest().to_text())),
                (
                    "contract_digest",
                    string(&recipe.contract_digest().to_text()),
                ),
                ("kernel_backend", string(recipe.backend().stable_id())),
                (
                    "kernel_generation",
                    string(&recipe.backend().generation().to_text()),
                ),
                ("maximum_inferences", config.max_inferences.to_string()),
                ("frames_per_entry", config.frames_per_track.to_string()),
                (
                    "minimum_association_iou_ppm",
                    config.minimum_association_iou_ppm.to_string(),
                ),
                (
                    "minimum_score_ppm_override",
                    config
                        .minimum_score_ppm
                        .map_or_else(|| "null".into(), |value| value.to_string()),
                ),
                (
                    "package_custody",
                    string("complete_archive_retained_in_analysis_closure"),
                ),
                (
                    "evidence_scope",
                    string("uncalibrated_same_sensor_class_evidence"),
                ),
                ("loose_model_file_required", "false".into()),
            ]),
        ));
    }
    let body = object(&fields);
    if body
        .len()
        .checked_add(1)
        .is_none_or(|n| n > options.maximum_report_bytes)
    {
        return Err("complete replay report exceeds byte bound".into());
    }
    Ok(format!("{body}\n"))
}
fn run(options: Options) -> Run<String> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:long-event-replay-cli".into(),
        operation_id: OperationId::parse("operation:long-event-replay-cli")?,
        principal: options.principal.clone(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(128 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:current-deployment-policy".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })?;
    let root = preflight(&options.root, &options.site, &authority)?;
    let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
    let result = (|| -> Run<String> {
        let deployment = ReferenceDeployment::open(&root, &options.site, &cx)?;
        match options.pins {
            None => {
                let inspection =
                    inspect_long_event(&deployment, &options.event, &options.limits, &cx)?;
                let output = report(&options, &root, &inspection, None)?;
                finish(&options, &root, &inspection, output, &cx)
            }
            Some(pins) => {
                let verified =
                    replay_long_event(&deployment, &options.event, pins, &options.limits, &cx)?;
                let output = report(
                    &options,
                    &root,
                    verified.inspection(),
                    Some((
                        verified.frames_replayed(),
                        verified.source_chunk_bytes_read(),
                    )),
                )?;
                finish(&options, &root, verified.inspection(), output, &cx)
            }
        }
    })();
    cx.drain_and_finalize();
    result
}
fn finish(
    options: &Options,
    root: &Path,
    inspection: &LongEventReplayInspection,
    output: String,
    cx: &ReplayCx,
) -> Run<String> {
    // Construct and bound all response bytes before a create-only optional export.
    if let Some(path) = &options.event_out {
        super::export(
            path,
            inspection.event().to_canonical_json().as_bytes(),
            root,
            cx,
        )?;
    }
    if let Some(path) = &options.report_out {
        super::export(path, output.as_bytes(), root, cx)?;
    }
    Ok(output)
}

// A bounded response must also have bounded interruption handling at its output boundary.
fn emit(out: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    for chunk in bytes.chunks(64 * 1024) {
        let mut written = 0;
        let mut interruptions = 0;
        while written < chunk.len() {
            match out.write(&chunk[written..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) => written += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted && interruptions < 8 => {
                    interruptions += 1;
                }
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

pub(super) fn main(args: &[OsString]) -> ExitCode {
    if args.len() == 2
        && ["help", "--help", "-h"]
            .iter()
            .any(|value| args[1] == *value)
    {
        return match emit(&mut io::stdout().lock(), HELP.as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(1),
        };
    }
    let options = match parse(args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: {error}; use fss-event verify --help");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    match run(options).and_then(|output| {
        emit(&mut io::stdout().lock(), output.as_bytes())?;
        Ok(())
    }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}");
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

#[cfg(test)]
#[path = "replay/tests.rs"]
mod tests;

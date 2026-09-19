#![forbid(unsafe_code)]
//! Local operator bridge from retained recordings to exact model execution and replay.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use fss_cli::{ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::{BudgetVector, ContentDigest, OperationId, PrincipalId};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_reference::{ExecBudget, ReferenceDeployment, ReplayCx, ScalarExecCx};
use fss_reference::ingest::RetainedReadLimits;
use fss_reference::ingest::recorded_decode::{
    ComponentInterpretation, DecodeBudget, DecodeLimits, RecordedDecodeRequest, RecordedFrame,
};
use fss_reference::ingest::inference::{
    MAX_RECORDED_MODEL_BYTES, MAX_RUN_TENSOR_BYTES, RecordedInference, RecordedModel,
};

#[path = "fss-infer/detection_cli.rs"]
mod detection_cli;
#[path = "fss-infer/recording_cli.rs"]
mod recording_cli;

const HELP: &str = "fss-infer <run|read|replay|detect|track|analyze> [options]\n\
  run/read/replay: --root DIR --site SITE --import-id sha256:HEX --segment N\n\
       --interpretation gray|ycbcr [--principal ID]\n\
  run: --model FILE --model-digest sha256:HEX [--decode-work-units N]\n\
  read/replay: --run-id sha256:HEX (the model is recovered from storage)\n\
  run/replay budgets: --max-macs N --max-tensor-bytes N\n\
  Exports: --output FILE --receipt-out FILE --model-out FILE\n\
  detect/track: use fss-infer detect --help for explicit output contracts and run lists.\n\
  analyze: use fss-infer analyze --help for bounded recording-to-report execution.\n\
  A run decodes the exact retained source and executes its frozen model. No models are\n\
  downloaded or activated. Outputs are uncalibrated tensors, not alerts or certified\n\
  absence. Exports must be new files outside the deployment. All paths accept native\n\
  OS strings; options take separate values. Existing deployment and exact IDs required.\n";

type RunResult<T> = Result<T, Box<dyn Error>>;
type Values = BTreeMap<String, OsString>;
#[derive(Debug)]
enum Action { Run { path: PathBuf, digest: ContentDigest, decode_work: u64 }, Read(ContentDigest), Replay(ContentDigest) }
#[derive(Debug)]
struct Options {
    root: PathBuf, site: String, principal: String, source: RecordedDecodeRequest,
    budget: ExecBudget, action: Action, output: Option<PathBuf>, receipt: Option<PathBuf>, model_out: Option<PathBuf>,
}
fn value<'a>(values: &'a Values, key: &str) -> Result<&'a OsStr, String> {
    values.get(key).map(OsString::as_os_str).ok_or_else(|| format!("required option {key}"))
}
fn text<'a>(values: &'a Values, key: &str) -> Result<&'a str, String> {
    value(values, key)?.to_str().ok_or_else(|| format!("{key} must be UTF-8"))
}
fn number<T: FromStr>(values: &Values, key: &str, default: Option<T>) -> Result<T, String> {
    if !values.contains_key(key) { return default.ok_or_else(|| format!("required option {key}")); }
    text(values, key)?.parse().map_err(|_| format!("invalid numeric value for {key}"))
}
fn digest(values: &Values, key: &str) -> Result<ContentDigest, String> {
    let d = ContentDigest::parse(text(values, key)?).map_err(|_| format!("invalid digest for {key}"))?;
    if d.algorithm() != fss_core::DigestAlgorithm::Sha256 { return Err(format!("{key} requires SHA-256")); }
    Ok(d)
}
fn parse(args: &[OsString]) -> Result<Option<Options>, String> {
    if args.is_empty() { return Ok(None); }
    let action = args[0].to_str().ok_or("command must be UTF-8")?;
    if matches!(action, "help" | "--help" | "-h") {
        return if args.len() == 1 { Ok(None) } else { Err("help takes no other arguments".to_owned()) };
    }
    if !matches!(action, "run" | "read" | "replay") { return Err("expected run, read or replay".to_owned()); }
    let common = ["--root", "--site", "--import-id", "--segment", "--interpretation", "--principal", "--output", "--receipt-out", "--model-out"];
    let mut values = Values::new(); let mut i = 1;
    while i < args.len() {
        let key = args[i].to_str().ok_or("option names must be UTF-8")?;
        let allowed = common.contains(&key)
            || (action == "run" && matches!(key, "--model" | "--model-digest" | "--decode-work-units"))
            || (action != "run" && key == "--run-id")
            || (action != "read" && matches!(key, "--max-macs" | "--max-tensor-bytes"));
        if !allowed { return Err("unknown or inapplicable option".to_owned()); }
        if values.contains_key(key) { return Err(format!("duplicate {key}")); }
        let v = args.get(i + 1).ok_or_else(|| format!("missing value for {key}"))?;
        if v.is_empty() || v.to_str().is_some_and(|s| s.starts_with("--")) { return Err(format!("missing value for {key}")); }
        values.insert(key.to_owned(), v.clone()); i += 2;
    }
    let root = PathBuf::from(value(&values, "--root")?);
    let site = text(&values, "--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site).map_err(|_| "invalid site lineage")?;
    let principal = if values.contains_key("--principal") { text(&values, "--principal")?.to_owned() }
        else { "principal:local-operator".to_owned() };
    PrincipalId::parse(&principal).map_err(|_| "invalid principal ID")?;
    let interpretation = match text(&values, "--interpretation")? {
        "gray" => ComponentInterpretation::Grayscale, "ycbcr" => ComponentInterpretation::YCbCr,
        _ => return Err("interpretation must be explicit gray or ycbcr".to_owned()),
    };
    let source = RecordedDecodeRequest {
        import_identity: digest(&values, "--import-id")?, segment_index: number(&values, "--segment", None)?,
        interpretation, read_limits: RetainedReadLimits::default(), decode_limits: DecodeLimits::default(),
    };
    let budget = ExecBudget::new(number(&values, "--max-macs", Some(100_000_000))?,
        number(&values, "--max-tensor-bytes", Some(64 * 1024 * 1024))?);
    if budget.max_bytes == 0 || budget.max_bytes > MAX_RUN_TENSOR_BYTES { return Err("tensor ceiling must be 1..268435456 bytes".to_owned()); }
    let action = match action {
        "run" => Action::Run {
            path: PathBuf::from(value(&values, "--model")?), digest: digest(&values, "--model-digest")?,
            decode_work: number(&values, "--decode-work-units", Some(100_000_000))?,
        },
        "read" => Action::Read(digest(&values, "--run-id")?),
        _ => Action::Replay(digest(&values, "--run-id")?),
    };
    Ok(Some(Options { root, site, principal, source, budget, action,
        output: values.get("--output").map(PathBuf::from), receipt: values.get("--receipt-out").map(PathBuf::from),
        model_out: values.get("--model-out").map(PathBuf::from) }))
}
fn load_model(path: &Path, expected: ContentDigest) -> RunResult<RecordedModel> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_RECORDED_MODEL_BYTES as u64 {
        return Err(io::Error::other("model must be a bounded regular file, not a symlink").into());
    }
    let file = fs::File::open(path)?;
    if !file.metadata()?.file_type().is_file() { return Err(io::Error::other("model is not regular").into()); }
    let mut bytes = Vec::new(); file.take(MAX_RECORDED_MODEL_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    Ok(RecordedModel::decode(&bytes, expected)?)
}
fn export(path: &Path, bytes: &[u8], root: &Path, cx: &ReplayCx) -> RunResult<()> {
    cx.checkpoint("inference_cli:export")?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    if fs::canonicalize(parent)?.starts_with(fs::canonicalize(root)?) {
        return Err(io::Error::other("exports must be outside the deployment").into());
    }
    let mut options = OpenOptions::new(); options.write(true).create_new(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    let mut file = options.open(path)?; file.write_all(bytes)?; file.sync_all()?;
    cx.checkpoint_post_commit("inference_cli:export_complete");
    Ok(())
}
fn run(options: Options, out: &mut impl Write) -> RunResult<()> {
    // Read commands must never initialize an absent deployment. The authenticated local process
    // and filesystem permissions are the boundary; a principal label is not remote authentication.
    if !fs::symlink_metadata(&options.root)?.file_type().is_dir()
        || !fs::symlink_metadata(options.root.join("LAYOUT"))?.file_type().is_file()
    { return Err(io::Error::other("existing non-symlink deployment required").into()); }
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:inference-cli".to_owned(), operation_id: OperationId::parse("operation:inference-cli")?,
        principal: options.principal, capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None, priority: 10, budgets: BudgetVector::builder().bytes(options.budget.max_bytes as u64).build()?,
        privacy_scope: "privacy:local-authorized-files".to_owned(), retention_scope: "retention:existing-deployment-policy".to_owned(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()), generation: 1,
    })?;
    authority.validate()?;
    let cx = ReplayCx::from_context_authority(&authority, options.root.clone())?;
    let exec_cx = ScalarExecCx::new();
    let result = (|| -> RunResult<()> {
        cx.checkpoint("inference_cli:load")?;
        let model = match &options.action { Action::Run { path, digest, .. } => Some(load_model(path, *digest)?), _ => None };
        let mut deployment = ReferenceDeployment::open(&options.root, &options.site, &cx)?;
        let (result, operation) = match &options.action {
            Action::Run { decode_work, .. } => {
                let model = model.as_ref().ok_or_else(|| io::Error::other("model not loaded"))?;
                RecordedFrame::decode_and_publish(&mut deployment, &options.source, &mut DecodeBudget::new(*decode_work), &cx)?;
                (RecordedInference::run_and_publish(&mut deployment, &options.source, model, options.budget, &exec_cx, &cx)?, "run")
            }
            Action::Read(id) => (RecordedInference::open(&deployment, *id, &options.source, &cx)?, "read"),
            Action::Replay(id) => {
                let result = RecordedInference::open(&deployment, *id, &options.source, &cx)?;
                result.verify_by_replay(&deployment, &options.source, options.budget, &exec_cx, &cx)?;
                (result, "replay_verified")
            }
        };
        if let Some(path) = &options.output { export(path, result.output_bytes(), &options.root, &cx)?; }
        if let Some(path) = &options.receipt { export(path, &result.receipt_bytes()?, &options.root, &cx)?; }
        if let Some(path) = &options.model_out { export(path, result.model().encoded(), &options.root, &cx)?; }
        writeln!(out, "operation={operation}\nrun_identity={}\nmodel_digest={}\nframe_root={}",
            result.identity(), result.model().digest(), result.frame_root())?;
        writeln!(out, "authority_sequence={}\nexecuted_macs={}\nallocated_tensor_bytes={}",
            result.authority_anchor().commit_sequence, result.executed_macs(), result.allocated_tensor_bytes())?;
        writeln!(out, "output_digest={}\noutput_ports={}\nmodel_outputs=uncalibrated\nabsence_certifiable=false\neffects_authorized=false",
            ContentDigest::sha256(result.output_bytes()), result.outputs().len())?;
        Ok(())
    })();
    exec_cx.drain_and_finalize(); cx.drain_and_finalize(); result
}
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if let Some(exit) = recording_cli::dispatch(&args, &mut io::stdout().lock()) { return exit; }
    if let Some(exit) = detection_cli::dispatch(&args, &mut io::stdout().lock()) { return exit; }
    match parse(&args) {
        Ok(None) => match io::stdout().lock().write_all(HELP.as_bytes()) {
            Ok(()) => ExitCode::from(0), Err(_) => ExitCode::from(1),
        },
        Ok(Some(options)) => match run(options, &mut io::stdout().lock()) {
            Ok(()) => ExitCode::from(0),
            Err(e) => {
                eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {e}");
                eprintln!("Completed frame/model publications remain retained after a later failure. Partial exports may remain.");
                ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
            }
        },
        Err(reason) => {
            eprintln!("{}: {reason}; use fss-infer help", fss_cli::ERR_CLI_MALFORMED_VALUE);
            ExitCode::from(ExitIdentity::MALFORMED_VALUE.code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<OsString> {
        ["run", "--root", "unused", "--site", "site:test", "--import-id",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "--segment", "0", "--interpretation", "gray", "--model", "model.bin", "--model-digest",
            "sha256:2222222222222222222222222222222222222222222222222222222222222222"]
            .into_iter().map(OsString::from).collect()
    }
    #[test]
    fn exact_model_and_interpretation_are_required() {
        assert!(parse(&args()).is_ok());
        let mut missing = args(); missing.truncate(missing.len() - 2); assert!(parse(&missing).is_err());
        let mut wrong = args(); wrong[10] = "auto".into(); assert!(parse(&wrong).is_err());
    }
    #[test]
    fn duplicate_unknown_inapplicable_and_excessive_bounds_are_refused() {
        for extra in [["--site", "other"], ["--latest", "true"], ["--run-id", "x"],
            ["--max-tensor-bytes", "0"], ["--max-tensor-bytes", "268435457"]] {
            let mut a = args(); a.extend(extra.into_iter().map(OsString::from)); assert!(parse(&a).is_err());
        }
    }
    #[cfg(unix)]
    #[test]
    fn model_paths_preserve_native_os_bytes() {
        use std::os::unix::ffi::OsStringExt;
        let mut a = args(); a[12] = OsString::from_vec(b"model-\xff.bin".to_vec());
        assert!(parse(&a).is_ok());
    }
}

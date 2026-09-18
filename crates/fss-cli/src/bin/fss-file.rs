#![forbid(unsafe_code)]
//! Operator utility for importing, reopening, verifying and extracting retained camera files.
//! Uses existing canonical file-import manifests for machine interchange; it is not an
//! alternate agent protocol or a production camera/model service.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;

use fss_cli::{
    ERR_CLI_DUPLICATE_OPTION, ERR_CLI_INVALID_UNICODE, ERR_CLI_MALFORMED_VALUE,
    ERR_CLI_MISSING_VALUE, ERR_CLI_RUNTIME_FAILURE, ERR_CLI_UNKNOWN_COMMAND,
    ERR_CLI_UNKNOWN_OPTION, ExitIdentity,
};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::retained::{MAX_RETAINED_ENTRIES, MAX_RETAINED_PAYLOAD_BYTES};
use fss_reference::ingest::{
    CaptureHint, FileFormatHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest,
    RetainedFileImport, RetainedReadLimits,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

const HELP: &str = "fss-file <import|inspect|verify|extract> [options]\n\
  All commands: --root DIR --site SITE [--principal ID] [--manifest-out FILE]\n\
  import: --input FILE --sensor ID --stream ID --receive-time-ns N\n\
          [--media-format auto|mjpeg|annexb]\n\
          [--capture-start-ns N --capture-uncertainty-ns N --assumed-fps F]\n\
  inspect/verify: --import-id sha256:HEX\n\
  extract: --import-id sha256:HEX --segment N --output FILE\n\
  Bounds: --max-source-bytes N --chunk-bytes N --max-segment-bytes N\n\
  Options use separate values. Paths accept native OS strings. Outputs must be new files\n\
  outside the deployment. Import requires explicit receive time; no host clock is inferred.\n\
  inspect verifies metadata/authority; verify checks every source byte; extract checks the\n\
  selected segment. None certifies coverage, absence, capture precision or model quality.\n";

type Values = BTreeMap<String, OsString>;
type ParseResult<T> = Result<T, (&'static str, String)>;
type RunResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug)]
enum Action {
    Import(FileIngestRequest),
    Inspect(ContentDigest),
    Verify(ContentDigest),
    Extract { identity: ContentDigest, segment: usize, output: PathBuf },
}

#[derive(Debug)]
struct Options {
    root: PathBuf,
    site: String,
    principal: String,
    manifest_output: Option<PathBuf>,
    limits: RetainedReadLimits,
    action: Action,
}

fn value<'a>(values: &'a Values, key: &str) -> ParseResult<&'a OsStr> {
    values.get(key).map(OsString::as_os_str)
        .ok_or_else(|| (ERR_CLI_MISSING_VALUE, format!("required option {key}")))
}

fn text<'a>(values: &'a Values, key: &str) -> ParseResult<&'a str> {
    value(values, key)?.to_str()
        .ok_or_else(|| (ERR_CLI_INVALID_UNICODE, format!("{key} must be UTF-8")))
}

fn number<T: FromStr>(values: &Values, key: &str, default: Option<T>) -> ParseResult<T> {
    if !values.contains_key(key) {
        return default.ok_or_else(|| (ERR_CLI_MISSING_VALUE, format!("required option {key}")));
    }
    text(values, key)?.parse()
        .map_err(|_| (ERR_CLI_MALFORMED_VALUE, format!("invalid numeric value for {key}")))
}

fn malformed(reason: &str) -> (&'static str, String) {
    (ERR_CLI_MALFORMED_VALUE, reason.to_owned())
}

fn parse(args: &[OsString]) -> ParseResult<Option<Options>> {
    if args.is_empty() { return Ok(None); }
    let command = args[0].to_str().ok_or_else(|| (ERR_CLI_INVALID_UNICODE, "command must be UTF-8".to_owned()))?;
    if matches!(command, "help" | "--help" | "-h") {
        if args.len() != 1 { return Err(malformed("help accepts no additional arguments")); }
        return Ok(None);
    }
    if !matches!(command, "import" | "inspect" | "verify" | "extract") {
        return Err((ERR_CLI_UNKNOWN_COMMAND, "expected import, inspect, verify or extract".to_owned()));
    }
    let common = ["--root", "--site", "--principal", "--manifest-out", "--max-source-bytes", "--chunk-bytes", "--max-segment-bytes"];
    let import = ["--input", "--sensor", "--stream", "--receive-time-ns", "--media-format", "--capture-start-ns", "--capture-uncertainty-ns", "--assumed-fps"];
    let mut values = Values::new();
    let mut index = 1;
    while index < args.len() {
        let key = args[index].to_str().ok_or_else(|| (ERR_CLI_INVALID_UNICODE, "option names must be UTF-8".to_owned()))?;
        let allowed = common.contains(&key)
            || (command == "import" && import.contains(&key))
            || (command != "import" && key == "--import-id")
            || (command == "extract" && matches!(key, "--segment" | "--output"));
        if !allowed { return Err((ERR_CLI_UNKNOWN_OPTION, "unknown or inapplicable option".to_owned())); }
        if values.contains_key(key) { return Err((ERR_CLI_DUPLICATE_OPTION, format!("duplicate {key}"))); }
        let argument = args.get(index + 1).ok_or_else(|| (ERR_CLI_MISSING_VALUE, format!("missing value for {key}")))?;
        if argument.is_empty() || argument.to_str().is_some_and(|s| s.starts_with("--")) {
            return Err((ERR_CLI_MISSING_VALUE, format!("missing value for {key}")));
        }
        values.insert(key.to_owned(), argument.clone());
        index += 2;
    }
    let root = PathBuf::from(value(&values, "--root")?);
    let site = text(&values, "--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| malformed("invalid site lineage"))?;
    let principal = if values.contains_key("--principal") {
        text(&values, "--principal")?.to_owned()
    } else { "principal:local-operator".to_owned() };
    fss_core::PrincipalId::parse(&principal).map_err(|_| malformed("invalid principal ID"))?;
    let defaults = RetainedReadLimits::default();
    let limits = RetainedReadLimits {
        max_source_bytes: number(&values, "--max-source-bytes", Some(defaults.max_source_bytes))?,
        max_chunk_bytes: number(&values, "--chunk-bytes", Some(defaults.max_chunk_bytes))?,
        max_segment_bytes: number(&values, "--max-segment-bytes", Some(defaults.max_segment_bytes))?,
    };
    if limits.max_source_bytes == 0 || limits.max_chunk_bytes == 0 || limits.max_segment_bytes == 0
        || limits.max_chunk_bytes > MAX_RETAINED_PAYLOAD_BYTES
        || limits.max_segment_bytes > MAX_RETAINED_PAYLOAD_BYTES
    { return Err(malformed("positive limits required; chunks and returned segments are capped at 64 MiB")); }
    let action = if command == "import" {
        let sensor = SensorId::parse(text(&values, "--sensor")?).map_err(|_| malformed("invalid sensor ID"))?;
        let stream = StreamId::parse(text(&values, "--stream")?).map_err(|_| malformed("invalid stream ID"))?;
        let receive: i128 = number(&values, "--receive-time-ns", None)?;
        if receive < 0 { return Err(malformed("receive time must be nonnegative")); }
        let mut request = FileIngestRequest::new(PathBuf::from(value(&values, "--input")?), sensor, stream)
            .with_receive_time(TimestampNs(receive));
        request.limits = FileIngestLimits { max_file_bytes: limits.max_source_bytes, chunk_bytes: limits.max_chunk_bytes, ..FileIngestLimits::standard() };
        if values.contains_key("--media-format") {
            request.format_hint = match text(&values, "--media-format")? {
                "auto" => None,
                "mjpeg" => Some(FileFormatHint::JpegStream),
                "annexb" => Some(FileFormatHint::AnnexB),
                _ => return Err(malformed("media format must be auto, mjpeg or annexb")),
            };
        }
        let hint_keys = ["--capture-start-ns", "--capture-uncertainty-ns", "--assumed-fps"];
        let supplied = hint_keys.iter().filter(|k| values.contains_key(**k)).count();
        if supplied != 0 && supplied != hint_keys.len() {
            return Err(malformed("capture start, uncertainty and assumed fps must be supplied together"));
        }
        if supplied != 0 {
            let start: i128 = number(&values, "--capture-start-ns", None)?;
            if start < 0 || start > receive { return Err(malformed("capture start must lie between zero and receive time")); }
            request.capture_hint = Some(CaptureHint::new(
                TimestampNs(start), number(&values, "--capture-uncertainty-ns", None)?,
                number(&values, "--assumed-fps", None)?,
            ).map_err(|_| malformed("assumed fps must be finite and positive"))?);
        }
        Action::Import(request)
    } else {
        let identity = ContentDigest::parse(text(&values, "--import-id")?).map_err(|_| malformed("invalid import digest"))?;
        if identity.algorithm() != fss_core::DigestAlgorithm::Sha256 { return Err(malformed("import ID must use SHA-256")); }
        match command {
            "inspect" => Action::Inspect(identity),
            "verify" => Action::Verify(identity),
            _ => Action::Extract {
                identity, segment: number(&values, "--segment", None)?,
                output: PathBuf::from(value(&values, "--output")?),
            },
        }
    };
    Ok(Some(Options {
        root, site, principal,
        manifest_output: values.get("--manifest-out").map(PathBuf::from), limits, action,
    }))
}

fn write_new(path: &Path, bytes: &[u8], deployment_root: &Path, cx: &ReplayCx) -> RunResult<()> {
    cx.checkpoint("file_cli:export")?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    if fs::canonicalize(parent)?.starts_with(fs::canonicalize(deployment_root)?) {
        return Err(io::Error::other("exports must be outside the deployment").into());
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    // Existing destinations are never overwritten. On I/O failure, an incomplete destination
    // may remain for inspection; it is not imported into the evidence graph or reported complete.
    cx.checkpoint_post_commit("file_cli:export_complete");
    Ok(())
}

fn run(options: Options, out: &mut impl Write) -> RunResult<()> {
    let importing = matches!(&options.action, Action::Import(_));
    if !importing {
        let layout = fs::symlink_metadata(options.root.join("LAYOUT"))?;
        if !layout.file_type().is_file() { return Err(io::Error::other("not an existing deployment layout").into()); }
    }
    if let Ok(metadata) = fs::symlink_metadata(&options.root) {
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(io::Error::other("deployment root must be a directory, not a symlink").into());
        }
    }
    // This operator process is the local trust boundary. The principal string is an audit
    // label, not remote authentication; no network, model or external-effect grants are issued.
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:file-cli".to_owned(), operation_id: OperationId::parse("operation:file-cli")?,
        principal: options.principal, capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None, priority: 10,
        budgets: BudgetVector::builder().bytes(options.limits.max_source_bytes)
            .storage_operations(MAX_RETAINED_ENTRIES as u64).build()?,
        privacy_scope: "privacy:local-authorized-files".to_owned(),
        retention_scope: "retention:existing-deployment-policy".to_owned(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()), generation: 1,
    })?;
    authority.validate()?;
    let cx = ReplayCx::from_context_authority(&authority, options.root.clone())?;
    let result = (|| -> RunResult<()> {
        let mut deployment = ReferenceDeployment::open(&options.root, &options.site, &cx)?;
        let (identity, operation) = match &options.action {
            Action::Import(request) => {
                let receipt = FileIngestAdapter::ingest(request.clone(), &cx, &mut deployment)?;
                (receipt.import_identity, receipt.outcome.as_str())
            }
            Action::Inspect(id) => (*id, "inspect"),
            Action::Verify(id) => (*id, "verify"),
            Action::Extract { identity, .. } => (*identity, "extract"),
        };
        let retained = RetainedFileImport::open(&deployment, identity, options.limits, &cx)?;
        let manifest = retained.manifest();
        writeln!(out, "operation={operation}")?;
        writeln!(out, "import_identity={}", retained.import_identity())?;
        writeln!(out, "import_root={}", retained.import_root())?;
        writeln!(out, "manifest_digest={}", retained.manifest_digest())?;
        writeln!(out, "authority_sequence={}", retained.authority_anchor().commit_sequence)?;
        writeln!(out, "input_sha256={}", manifest.input_sha256)?;
        writeln!(out, "input_bytes={}", manifest.input_bytes)?;
        writeln!(out, "media_format={}", manifest.format)?;
        writeln!(out, "segment_count={}", manifest.segment_spans.len())?;
        writeln!(out, "omission_count={}", manifest.omission_spans.len())?;
        writeln!(out, "capture_time_class={}", manifest.capture_time_label)?;
        writeln!(out, "absence_certifiable=false")?;
        match &options.action {
            Action::Import(_) | Action::Verify(_) => {
                let verified = retained.verify_source(&deployment, options.limits, &cx)?;
                writeln!(out, "verified_source_sha256={verified}")?;
            }
            Action::Extract { segment, output, .. } => {
                let bytes = retained.read_segment(&deployment, *segment, options.limits, &cx)?;
                write_new(output, &bytes, &options.root, &cx)?;
                writeln!(out, "extracted_segment={segment}")?;
                writeln!(out, "extracted_bytes={}", bytes.len())?;
                writeln!(out, "extracted_sha256={}", ContentDigest::sha256(&bytes))?;
            }
            Action::Inspect(_) => {}
        }
        if let Some(path) = &options.manifest_output {
            write_new(path, &manifest.canonical_bytes(), &options.root, &cx)?;
            writeln!(out, "canonical_manifest_written=true")?;
        }
        Ok(())
    })();
    cx.drain_and_finalize();
    result
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match parse(&args) {
        Ok(None) => {
            match io::stdout().lock().write_all(HELP.as_bytes()) {
                Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
                Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
            }
        }
        Ok(Some(options)) => match run(options, &mut io::stdout().lock()) {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(error) => {
                eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}");
                eprintln!("A completed import is not rolled back by a later verify/export failure. An incomplete export may remain.");
                ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
            }
        },
        Err((code, reason)) => {
            eprintln!("{code}: {reason}; use fss-file help");
            ExitCode::from(ExitIdentity::MALFORMED_VALUE.code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(extra: &[&str]) -> Vec<OsString> {
        ["import", "--root", "/unused", "--site", "site:test", "--input", "camera.h264", "--sensor", "sensor:test", "--stream", "stream:test", "--receive-time-ns", "1000000000"]
            .into_iter().chain(extra.iter().copied()).map(OsString::from).collect()
    }

    #[test]
    fn strict_arguments_require_explicit_time_and_reject_silent_options() {
        assert!(parse(&args(&[])).is_ok());
        for extra in [vec!["--unknown", "x"], vec!["--site", "site:other"], vec!["--chunk-bytes", "0"], vec!["--max-segment-bytes", "67108865"], vec!["--capture-start-ns", "0"], vec!["--media-format", "rtpplay"]] {
            assert!(parse(&args(&extra)).is_err());
        }
        let mut missing_time = args(&[]);
        missing_time.truncate(missing_time.len() - 2);
        assert!(parse(&missing_time).is_err());
    }

    #[test]
    fn explicit_capture_assumptions_require_all_parameters() {
        assert!(parse(&args(&["--capture-start-ns", "0", "--capture-uncertainty-ns", "1000", "--assumed-fps", "30"])).is_ok());
        assert!(parse(&args(&["--capture-start-ns", "0", "--capture-uncertainty-ns", "1000", "--assumed-fps", "NaN"])).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn native_source_paths_are_not_forced_through_utf8() {
        use std::os::unix::ffi::OsStringExt;
        let mut argv = args(&[]);
        argv[6] = OsString::from_vec(b"camera-\xff.h264".to_vec());
        assert!(parse(&argv).is_ok());
    }
}

#![forbid(unsafe_code)]
//! Cold replay-receipt inspection through the existing native custody verifier.
//! This local operator report carries metadata, never original packet payloads.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use fss_cli::{
    ERR_CLI_DUPLICATE_OPTION, ERR_CLI_INVALID_UNICODE, ERR_CLI_MALFORMED_VALUE,
    ERR_CLI_MISSING_VALUE, ERR_CLI_RUNTIME_FAILURE, ERR_CLI_UNKNOWN_OPTION, ExitIdentity,
    escape_json_str,
};
use fss_core::{ContentDigest, DigestAlgorithm, SensorId, StreamId};
use fss_object::SpoolLimits;
use fss_publication::{
    LocalPublicationLimits, LocalRootPublisher, PublishCancellation, PublishCutPoint,
};
use fss_reference::rtsp::recording::{MAX_RECORDING_BYTES, RecordingScope};
use fss_reference::rtsp::recording_archive::ArchiveNamespace;
use fss_reference::rtsp::recording_archive::hevc::HevcArchiveNamespace;
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_replay::{
    ReplayCodec, hevc_replay_slot, load_hevc_replay_receipt, load_replay_receipt, replay_slot,
};

const MAX_REPORT_BYTES: usize = 64 * 1024;
pub(super) const HELP: &str = "fss-archive inspect-replay [options]\n\
  Required: --root EXISTING_DIR --codec avc|hevc --sensor ID --stream ID --generation N\n\
            --anchor sha256:HEX --receive-clock sha256:HEX\n\
            --decode-clock sha256:HEX --time-scale N\n\
            --expected-replay-root sha256:HEX --expected-replay-request sha256:HEX\n\
  Bounds: [--timeout-ms N] [--max-scan-roots N] [--max-objects N]\n\
          [--max-object-bytes N] [--max-total-bytes N]\n\
  Requires the exact replay-bound decode clock and independently pinned receipt/request.\n\
  Revalidates every original window with the explicitly selected native codec verifier.\n\
  At most 64 original windows; output is at most 64 KiB and contains no source bytes.\n\
  Requested and acknowledged UTC ranges are protocol assertions, not calibrated frame\n\
  capture times. Publication completeness never proves complete requested UTC coverage.\n\
  Open takes existing exclusive locks and performs normal recovery and verification I/O;\n\
  it is not a forensic read-only open. No network, guessed pins, publication or deletion.\n";

pub(super) fn handles(args: &[OsString]) -> bool {
    args.first().is_some_and(|arg| arg == "inspect-replay")
}

struct Error {
    code: &'static str,
    message: &'static str,
    usage: bool,
}
type Result<T> = std::result::Result<T, Error>;

fn argument(code: &'static str, message: &'static str) -> Error {
    Error {
        code,
        message,
        usage: true,
    }
}
fn malformed(message: &'static str) -> Error {
    argument(ERR_CLI_MALFORMED_VALUE, message)
}
fn runtime(message: &'static str) -> Error {
    Error {
        code: ERR_CLI_RUNTIME_FAILURE,
        message,
        usage: false,
    }
}

struct Options {
    root: PathBuf,
    codec: ReplayCodec,
    scope: CatalogScope,
    receipt: ContentDigest,
    request: ContentDigest,
    storage: LocalPublicationLimits,
    timeout: Duration,
}

fn parse(args: &[OsString]) -> Result<Options> {
    if !handles(args)
        || args.len() > 65
        || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
    {
        return Err(malformed("command or argument count/length bound exceeded"));
    }
    let allowed = [
        "--root",
        "--codec",
        "--sensor",
        "--stream",
        "--generation",
        "--anchor",
        "--receive-clock",
        "--decode-clock",
        "--time-scale",
        "--expected-replay-root",
        "--expected-replay-request",
        "--timeout-ms",
        "--max-scan-roots",
        "--max-objects",
        "--max-object-bytes",
        "--max-total-bytes",
    ];
    let mut values: BTreeMap<&str, &OsStr> = BTreeMap::new();
    for pair in args[1..].chunks(2) {
        let key = pair[0]
            .to_str()
            .ok_or_else(|| argument(ERR_CLI_INVALID_UNICODE, "option name must be UTF-8"))?;
        if !allowed.contains(&key) {
            return Err(argument(
                ERR_CLI_UNKNOWN_OPTION,
                "unknown or inapplicable option",
            ));
        }
        if values.contains_key(key) {
            return Err(argument(ERR_CLI_DUPLICATE_OPTION, "duplicate option"));
        }
        let value = pair
            .get(1)
            .filter(|value| {
                !value.is_empty() && !value.to_str().is_some_and(|text| text.starts_with("--"))
            })
            .ok_or_else(|| argument(ERR_CLI_MISSING_VALUE, "missing option value"))?;
        values.insert(key, value.as_os_str());
    }
    let required = |key: &str| {
        values
            .get(key)
            .copied()
            .ok_or_else(|| argument(ERR_CLI_MISSING_VALUE, "required option missing"))
    };
    let text = |key: &str| {
        required(key)?
            .to_str()
            .ok_or_else(|| argument(ERR_CLI_INVALID_UNICODE, "identity/value must be UTF-8"))
    };
    let number = |key: &str, default: Option<u64>, minimum: u64, maximum: u64| -> Result<u64> {
        let value = if values.contains_key(key) {
            let raw = text(key)?;
            if !raw.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(malformed("expected unsigned decimal integer"));
            }
            raw.parse::<u64>()
                .map_err(|_| malformed("integer overflow"))?
        } else {
            default
                .ok_or_else(|| argument(ERR_CLI_MISSING_VALUE, "required numeric option missing"))?
        };
        if !(minimum..=maximum).contains(&value) {
            return Err(malformed("numeric value outside supported bounds"));
        }
        Ok(value)
    };
    let digest = |key: &str| -> Result<ContentDigest> {
        let value = ContentDigest::parse(text(key)?).map_err(|_| malformed("invalid digest"))?;
        if value.algorithm() != DigestAlgorithm::Sha256
            || value.is_laboratory()
            || value.bytes() == [0; 32]
        {
            return Err(malformed("nonzero production SHA-256 required"));
        }
        Ok(value)
    };
    let codec = match text("--codec")? {
        "avc" => ReplayCodec::Avc,
        "hevc" => ReplayCodec::Hevc,
        _ => {
            return Err(malformed(
                "replay receipts require explicit avc or hevc codec",
            ));
        }
    };
    let scope = CatalogScope {
        recording: RecordingScope {
            sensor: SensorId::parse(text("--sensor")?)
                .map_err(|_| malformed("invalid sensor ID"))?,
            stream: StreamId::parse(text("--stream")?)
                .map_err(|_| malformed("invalid stream ID"))?,
            generation: number("--generation", None, 1, u64::MAX)?,
            anchor: digest("--anchor")?,
            receive_clock: digest("--receive-clock")?,
        },
        decode_clock: digest("--decode-clock")?,
        time_scale: number("--time-scale", None, 1, u64::from(u32::MAX))? as u32,
    };
    let receipt = digest("--expected-replay-root")?;
    let request = digest("--expected-replay-request")?;
    match codec {
        ReplayCodec::Avc => replay_slot(&scope, request),
        ReplayCodec::Hevc => hevc_replay_slot(&scope, request),
    }
    .map_err(|_| malformed("invalid pinned replay scope"))?;
    let scan = number("--max-scan-roots", Some(16_384), 1, 65_536)? as usize;
    let objects = number("--max-objects", Some(65_536), 1, 131_072)? as usize;
    let storage = LocalPublicationLimits::new(
        scan,
        512,
        scan,
        scan,
        SpoolLimits::new(
            objects,
            number(
                "--max-total-bytes",
                Some(1024 * 1024 * 1024),
                1,
                1024 * 1024 * 1024 * 1024,
            )?,
            number(
                "--max-object-bytes",
                Some(MAX_RECORDING_BYTES as u64),
                1,
                MAX_RECORDING_BYTES as u64,
            )? as usize,
            objects,
        ),
    );
    storage
        .validate()
        .map_err(|_| malformed("inconsistent storage ceilings"))?;
    Ok(Options {
        root: PathBuf::from(required("--root")?),
        codec,
        scope,
        receipt,
        request,
        storage,
        timeout: Duration::from_millis(number("--timeout-ms", Some(30_000), 1, 3_600_000)?),
    })
}

struct Clock {
    start: Instant,
    timeout: Duration,
}
impl Clock {
    fn check(&self) -> Result<()> {
        if self.start.elapsed() >= self.timeout {
            return Err(runtime("operation deadline expired"));
        }
        Ok(())
    }
}
impl PublishCancellation for Clock {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        self.start.elapsed() >= self.timeout
    }
}

fn existing(path: &Path) -> Result<PathBuf> {
    let directory = |path: &Path| std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir());
    let file = |path: &Path| std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file());
    if !directory(path) {
        return Err(runtime("expected an existing non-symlink archive"));
    }
    let root =
        std::fs::canonicalize(path).map_err(|_| runtime("archive path resolution failed"))?;
    for name in [
        "roots",
        "tombstones",
        "spool",
        "spool/objects",
        "spool/staging",
        "spool/verified",
    ] {
        if !directory(&root.join(name)) {
            return Err(runtime("existing archive layout is required"));
        }
    }
    for name in ["LOCK", "spool/LOCK"] {
        if !file(&root.join(name)) {
            return Err(runtime("existing archive lock layout is required"));
        }
    }
    Ok(root)
}

fn append(report: &mut String, part: &str) -> Result<()> {
    if part.len() > MAX_REPORT_BYTES.saturating_sub(report.len()) {
        return Err(runtime("report byte bound exceeded"));
    }
    report
        .try_reserve(part.len())
        .map_err(|_| runtime("report allocation refused"))?;
    report.push_str(part);
    Ok(())
}
fn quoted(value: &str) -> String {
    format!("\"{}\"", escape_json_str(value))
}

fn run(options: Options) -> Result<String> {
    let clock = Clock {
        start: Instant::now(),
        timeout: options.timeout,
    };
    let root = existing(&options.root)?;
    clock.check()?;
    let publisher = LocalRootPublisher::open(root, options.storage)
        .map_err(|_| runtime("archive open or exclusive ownership refused"))?;
    // Existing owner open is count/byte bounded but has no cancellation argument.
    clock.check()?;
    let load = match options.codec {
        ReplayCodec::Avc => load_replay_receipt,
        ReplayCodec::Hevc => load_hevc_replay_receipt,
    };
    let receipt = load(
        &publisher,
        options.receipt,
        &options.scope,
        options.request,
        &clock,
    )
    .map_err(|_| runtime("pinned replay receipt or original source verification failed"))?;
    clock.check()?;
    let request = receipt.request();
    let scope = receipt.scope();
    let namespace = match options.codec {
        ReplayCodec::Avc => {
            ArchiveNamespace::new(scope.clone()).map(|namespace| namespace.digest())
        }
        ReplayCodec::Hevc => {
            HevcArchiveNamespace::new(scope.clone()).map(|namespace| namespace.digest())
        }
    }
    .map_err(|_| runtime("verified replay namespace could not be reconstructed"))?;
    let slot = receipt
        .slot()
        .map_err(|_| runtime("verified replay slot could not be reconstructed"))?;
    let mut report = String::new();
    append(
        &mut report,
        &format!(
            "{{\"schema\":\"fss.local_replay_operator_report.v1\",\"command\":\"inspect-replay\",\"codec\":{},\"replay_receipt_root\":{},\"replay_receipt_slot\":{},\"replay_request\":{},\"route\":{},\"approval\":{},\"namespace\":{},\"sensor\":{},\"stream\":{},\"generation\":{},\"anchor\":{},\"receive_clock\":{},\"base_decode_clock\":{},\"decode_clock\":{},\"time_scale\":{},",
            quoted(options.codec.as_str()),
            quoted(&receipt.root().to_text()),
            quoted(slot.as_str()),
            quoted(&request.digest().to_text()),
            quoted(&request.route().to_text()),
            quoted(&receipt.approval().to_text()),
            quoted(&namespace.to_text()),
            quoted(scope.recording.sensor.as_str()),
            quoted(scope.recording.stream.as_str()),
            scope.recording.generation,
            quoted(&scope.recording.anchor.to_text()),
            quoted(&scope.recording.receive_clock.to_text()),
            quoted(&request.base_decode_clock().to_text()),
            quoted(&scope.decode_clock.to_text()),
            scope.time_scale,
        ),
    )?;
    if let Some(source) = request.onvif_source() {
        append(&mut report, &format!("\"onvif_source\":{},", fss_cli::onvif_replay_plan::source_json(source)))?;
    }
    append(
        &mut report,
        &format!(
            "\"requested_range\":{},\"acknowledged_range\":{},\"play_cseq\":{},\"rate_control\":\"no\",\"termination\":{},\"publication_complete\":{},\"durable_windows\":{},\"windows\":[",
            quoted(&request.window().to_string()),
            quoted(&receipt.acceptance().acknowledged().to_string()),
            receipt.acceptance().cseq(),
            quoted(receipt.termination().as_str()),
            receipt.publication_complete(),
            receipt.windows().len(),
        ),
    )?;
    for (ordinal, window) in receipt.windows().iter().enumerate() {
        clock.check()?;
        if ordinal != 0 {
            append(&mut report, ",")?;
        }
        let interval = window.decode_interval();
        append(
            &mut report,
            &format!(
                "{{\"ordinal\":{ordinal},\"root\":{},\"slot\":{},\"decode_interval\":[{},{}],\"packets\":{},\"samples\":{},\"nals\":{},\"whole_window_bytes\":{}}}",
                quoted(&window.root().to_text()),
                quoted(window.slot().as_str()),
                interval.start,
                interval.end,
                window.packets(),
                window.samples(),
                window.nals(),
                window.byte_len(),
            ),
        )?;
    }
    append(
        &mut report,
        "],\"original_source_verified\":true,\"time_basis\":\"original_decode_ticks\",\"coverage_claim\":\"not_claimed\",\"frame_capture_time\":\"unknown\",\"source_bytes_emitted\":false,\"operation_complete\":true}\n",
    )?;
    clock.check()?;
    Ok(report)
}

pub(super) fn dispatch(args: &[OsString]) -> ExitCode {
    let result = if args.len() == 2 && args[1] == "--help" {
        Ok(HELP.to_owned())
    } else {
        parse(args).and_then(run)
    };
    match result {
        Ok(report) => match super::emit(&mut std::io::stdout().lock(), report.as_bytes()) {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        },
        Err(error) => {
            eprintln!("{}: {}", error.code, error.message);
            eprintln!(
                "No complete report was emitted. Retain the exact replay pins and existing archive. Use fss-archive inspect-replay --help."
            );
            ExitCode::from(if error.usage {
                ExitIdentity::MALFORMED_VALUE.code
            } else {
                ExitIdentity::RUNTIME_FAILURE.code
            })
        }
    }
}

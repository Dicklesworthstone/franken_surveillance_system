#![forbid(unsafe_code)]
//! Cold retained-RTP inspection and privacy-projected native pixel export.
//! This utility uses the existing recovery, decoder, privacy and PGM export owners.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

use fss_cli::{
    ERR_CLI_DUPLICATE_OPTION, ERR_CLI_INVALID_UNICODE, ERR_CLI_MALFORMED_VALUE,
    ERR_CLI_MISSING_VALUE, ERR_CLI_RUNTIME_FAILURE, ERR_CLI_UNKNOWN_COMMAND,
    ERR_CLI_UNKNOWN_OPTION, ExitIdentity,
};
use fss_core::{BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_reference::ingest::ADP_FILE_ROW_ID;
use fss_reference::ingest::rtpdump::decode::{RtpDecodeEffect, RtpDecodeRecovery};
use fss_reference::ingest::rtpdump::import::ImportEnd;
use fss_reference::ingest::rtpdump::recovery::checked_decode::{
    CheckedRetainedRtpH264Decoder, RtpCustodyDecodeLimits,
};
use fss_reference::ingest::rtpdump::recovery::decode::{
    RetainedRtpDecodeRequest, RetainedRtpDecodeStats, RetainedRtpDecodeStep, RetainedRtpH264Decoder,
};
use fss_reference::ingest::rtpdump::recovery::{
    RtpRecoveryPolicy, RtpRecoveryState, inspect_rtp_import,
};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx};

#[path = "fss-file/pgm_stream.rs"]
mod pgm_stream;

#[path = "fss-decode-rtp/detect_cmd.rs"]
mod detect_cmd;
#[path = "fss-decode-rtp/motion_cmd.rs"]
mod motion_cmd;
#[path = "fss-decode-rtp/receipt_cmd.rs"]
mod receipt_cmd;
#[path = "fss-decode-rtp/track_cmd.rs"]
mod track_cmd;

const HELP: &str = "fss-decode-rtp <inspect|decode|receipts|verify-receipts|motion|detect|cascade|track> --root DIR --site SITE --source-root sha256:HEX\n\
  inspect: verifies one retained original RTP graph and lists in-source SPS/PPS candidates.\n\
  decode: native ordered AVC decoding from completed retained custody, with current privacy.\n\
    [--sps sha256:HEX --pps sha256:HEX] (omit only for one unambiguous pair)\n\
    [--output FRAMES.pgm] [--recovery stop|next-idr] [--max-frames N]\n\
    [--max-output-bytes N] [--max-decode-bytes N] [--max-decode-calls N]\n\
    [--max-dimension N] [--max-pixels N] [--max-spans N] [--max-steps N]\n\
    [--custody snapshot|current] [--max-custody-read-bytes N]\n\
    Current mode rechecks the complete graph before each frame; its read budget is separate\n\
    from the initial recovery budget. Default snapshot behavior remains unchanged.\n\
  receipts: native current-custody decode with --receipts-out FILE [--output FRAMES.pgm]\n\
  verify-receipts: --receipts-in FILE --receipts-sha256 sha256:HEX (no outputs)\n\
    Both require --custody current and the same decode options for reproduction.\n\
    [--max-receipt-bytes N] [--max-receipts-bytes N] bound the portable receipt stream.\n\
  motion: --custody current --pixel-delta N --minimum-changed-pixels N --report-out FILE\n\
    [--minimum-changed-ppm N] [--max-comparisons N] [--max-report-bytes N]\n\
    Measures masked frame changes, not people or physical absence; accepts no --output.\n\
  detect: --custody current --package FILE --package-sha256 sha256:HEX --report-out FILE\n\
    [--minimum-score-ppm N] [--max-report-bytes N]\n\
    Runs the verified neural package over every custody-checked native frame; no pixel output.\n\
  cascade: same required package/custody/report options as detect, plus\n\
    --pixel-delta N --minimum-changed-pixels N --sentinel-stride 1..256\n\
    [--minimum-changed-ppm N] [--post-activity-frames 0..256]\n\
    [--max-comparisons N] [--max-baseline-bytes N] [--max-sampling-bytes N]\n\
    [--max-inference-frames N] [--required-frames INDEX=sha256:HEX,...]\n\
    Explicitly skips neural work, never source checks. Every skip has a native receipt.\n\
    Unmeasured comparisons require inference; sampling completion is not exhaustive detection.\n\
  track: --custody current --package FILE --package-sha256 sha256:HEX --class-index N\n\
    --report-out FILE [--minimum-score-ppm N] [--track-min-hits N] [--track-max-misses N]\n\
    [--track-iou-ppm N] [--max-track-frames N] [--max-report-bytes N]\n\
    Runs verified neural detection plus anonymous source-witnessed tracking; no pixel output.\n\
  Common bounds: [--max-source-bytes N] [--max-read-bytes N] [--max-records N]\n\
  Outputs are new private files outside the deployment, one binary PGM per served frame.\n\
  Decode/refusal progress is bounded key=value output; partial output is never marked complete.\n\
  No input path, loose codec configuration, implicit recovery write, network or live coverage.\n\
  Capture time stays unknown. Native recovery does not erase gaps or certify absence.\n";

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;
type ParseResult<T> = std::result::Result<T, (&'static str, &'static str)>;
type Values = BTreeMap<String, OsString>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Inspect,
    Decode,
}

#[derive(Debug)]
struct Options {
    mode: Mode,
    root: PathBuf,
    site: String,
    source_root: ContentDigest,
    parameters: Option<[ContentDigest; 2]>,
    policy: RtpRecoveryPolicy,
    decode: RetainedRtpDecodeRequest,
    output: Option<PathBuf>,
    output_bytes: u64,
    steps: usize,
    custody_read_bytes: Option<u64>,
}
fn required<'a>(values: &'a Values, key: &str) -> ParseResult<&'a OsString> {
    values
        .get(key)
        .ok_or((ERR_CLI_MISSING_VALUE, "required option absent"))
}
fn text<'a>(values: &'a Values, key: &str) -> ParseResult<&'a str> {
    required(values, key)?
        .to_str()
        .ok_or((ERR_CLI_INVALID_UNICODE, "option must be UTF-8"))
}
fn number<T: FromStr>(values: &Values, key: &str, default: T) -> ParseResult<T> {
    if !values.contains_key(key) {
        return Ok(default);
    }
    text(values, key)?
        .parse()
        .map_err(|_| (ERR_CLI_MALFORMED_VALUE, "invalid numeric option"))
}
fn digest(values: &Values, key: &str) -> ParseResult<ContentDigest> {
    text(values, key)?
        .parse()
        .map_err(|_| (ERR_CLI_MALFORMED_VALUE, "invalid content digest"))
}
fn parse(args: &[OsString]) -> ParseResult<Option<Options>> {
    if args.is_empty() || (args.len() == 1 && matches!(args[0].to_str(), Some("--help" | "-h"))) {
        return Ok(None);
    }
    let mode = match args[0].to_str() {
        Some("inspect") => Mode::Inspect,
        Some("decode") => Mode::Decode,
        _ => return Err((ERR_CLI_UNKNOWN_COMMAND, "expected inspect or decode")),
    };
    let common = [
        "--root",
        "--site",
        "--source-root",
        "--max-source-bytes",
        "--max-read-bytes",
        "--max-records",
    ];
    let decoding = [
        "--sps",
        "--pps",
        "--output",
        "--recovery",
        "--max-frames",
        "--max-output-bytes",
        "--max-decode-bytes",
        "--max-decode-calls",
        "--max-dimension",
        "--max-pixels",
        "--max-spans",
        "--max-steps",
        "--custody",
        "--max-custody-read-bytes",
    ];
    let mut values = Values::new();
    let mut at = 1;
    while at < args.len() {
        let key = args[at]
            .to_str()
            .ok_or((ERR_CLI_INVALID_UNICODE, "option name must be UTF-8"))?;
        if !common.contains(&key) && !(mode == Mode::Decode && decoding.contains(&key)) {
            return Err((
                ERR_CLI_UNKNOWN_OPTION,
                "option not supported by this command",
            ));
        }
        let value = args
            .get(at + 1)
            .ok_or((ERR_CLI_MISSING_VALUE, "option needs a value"))?;
        if values.insert(key.to_owned(), value.clone()).is_some() {
            return Err((ERR_CLI_DUPLICATE_OPTION, "duplicate option"));
        }
        at += 2;
    }
    let root = PathBuf::from(required(&values, "--root")?);
    let site = text(&values, "--site")?.to_owned();
    if site.is_empty() || site.len() > 256 || site.chars().any(char::is_control) {
        return Err((ERR_CLI_MALFORMED_VALUE, "invalid site identity"));
    }
    let source_root = digest(&values, "--source-root")?;
    let parameters = match (values.contains_key("--sps"), values.contains_key("--pps")) {
        (false, false) => None,
        (true, true) => Some([digest(&values, "--sps")?, digest(&values, "--pps")?]),
        _ => {
            return Err((
                ERR_CLI_MISSING_VALUE,
                "SPS and PPS must be supplied together",
            ));
        }
    };
    let mut policy = RtpRecoveryPolicy::default();
    policy.max_source_bytes = number(&values, "--max-source-bytes", policy.max_source_bytes)?;
    policy.max_read_bytes = number(&values, "--max-read-bytes", policy.max_read_bytes)?;
    policy.max_records = number(&values, "--max-records", policy.max_records)?;
    let mut decode = RetainedRtpDecodeRequest::new([source_root; 2]);
    decode.decode.max_groups = number(&values, "--max-frames", 1024)?;
    decode.decode.max_decode_bytes = number(
        &values,
        "--max-decode-bytes",
        decode.decode.max_decode_bytes,
    )?;
    decode.decode.max_decode_calls = number(
        &values,
        "--max-decode-calls",
        decode.decode.max_decode_calls,
    )?;
    decode.decode.max_source_spans =
        number(&values, "--max-spans", decode.decode.max_source_spans)?;
    let dimension = number(&values, "--max-dimension", 2048_u32)?;
    let pixels = number(&values, "--max-pixels", 4_194_304_u32)?;
    let output_bytes = number(
        &values,
        "--max-output-bytes",
        pgm_stream::DEFAULT_OUTPUT_BYTES,
    )?;
    let steps = number(&values, "--max-steps", 1_000_000_usize)?;
    if !(1..=1024).contains(&decode.decode.max_groups)
        || !(16..=4096).contains(&dimension)
        || !(256..=4_194_304).contains(&pixels)
        || output_bytes == 0
        || output_bytes > pgm_stream::MAX_OUTPUT_BYTES
        || !(1..=5_000_000).contains(&steps)
        || !(1..=256 * 1024 * 1024).contains(&policy.max_source_bytes)
        || !(1..=65_536).contains(&policy.max_records)
        || policy.max_read_bytes < policy.max_object_bytes as u64
        || policy.max_read_bytes > 2 * 1024 * 1024 * 1024
        || !(2..=65_536).contains(&decode.decode.max_decode_calls)
        || !(1..=65_536).contains(&decode.decode.max_source_spans)
        || !(1..=256 * 1024 * 1024).contains(&decode.decode.max_decode_bytes)
    {
        return Err((
            ERR_CLI_MALFORMED_VALUE,
            "requested bounds exceed the native command profile",
        ));
    }
    decode.decode.codec.max_width = dimension;
    decode.decode.codec.max_height = dimension;
    decode.decode.codec.max_macroblocks = pixels / 256;
    decode.decode.codec.max_pictures = decode.decode.max_groups as u64;
    decode.decode.max_output_bytes = output_bytes as usize;
    if values.contains_key("--recovery") {
        decode.decode.recovery = match text(&values, "--recovery")? {
            "stop" => RtpDecodeRecovery::Stop,
            "next-idr" => RtpDecodeRecovery::NextIdr,
            _ => return Err((ERR_CLI_MALFORMED_VALUE, "recovery must be stop or next-idr")),
        };
    }
    let custody_read_bytes = match values.get("--custody") {
        None => None,
        Some(_) => match text(&values, "--custody")? {
            "snapshot" => None,
            "current" => Some(number(
                &values,
                "--max-custody-read-bytes",
                RtpCustodyDecodeLimits::default().max_read_bytes,
            )?),
            _ => {
                return Err((
                    ERR_CLI_MALFORMED_VALUE,
                    "custody must be snapshot or current",
                ));
            }
        },
    };
    if (values.contains_key("--max-custody-read-bytes") && custody_read_bytes.is_none())
        || custody_read_bytes.is_some_and(|bytes| {
            bytes < policy.max_object_bytes as u64 || bytes > 2 * 1024 * 1024 * 1024
        })
    {
        return Err((
            ERR_CLI_MALFORMED_VALUE,
            "a bounded custody read allowance requires --custody current",
        ));
    }
    Ok(Some(Options {
        mode,
        root,
        site,
        source_root,
        parameters,
        policy,
        decode,
        output: values.get("--output").map(PathBuf::from),
        output_bytes,
        steps,
        custody_read_bytes,
    }))
}
fn failure(reason: &'static str) -> Error {
    io::Error::other(reason).into()
}
fn run(options: Options, out: &mut impl Write) -> Result<()> {
    run_with(options, out, execute)
}
fn run_with<W: Write>(
    options: Options,
    out: &mut W,
    execute: impl FnOnce(&Options, &std::path::Path, &ReplayCx, &mut W) -> Result<()>,
) -> Result<()> {
    // ReplayCx can create its root: never let a read-only command create a missing deployment.
    let metadata = std::fs::symlink_metadata(&options.root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(failure("an existing real deployment directory is required"));
    }
    let root = std::fs::canonicalize(&options.root)?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:retained-rtp-decode".into(),
        operation_id: OperationId::parse("operation:retained-rtp-decode")?,
        principal: "operator:retained-rtp-decode".into(),
        capabilities: vec![ADP_REPLAY_ROW_ID.into(), ADP_FILE_ROW_ID.into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".into(),
        retention_scope: "retention:ephemeral".into(),
        anchor_universe: options.source_root,
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, &root)?;
    let result = execute(&options, &root, &cx, out);
    cx.drain_and_finalize();
    result
}
fn statistics(stats: RetainedRtpDecodeStats, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "records_visited={}\nframes_decoded={}\nrefused_steps={}\nskipped_groups={}",
        stats.records, stats.frames, stats.refusals, stats.skipped_groups
    )?;
    writeln!(
        out,
        "input_ended={}\nnative_flushed={}\ndecode_ended={}\ndecode_complete={}",
        stats.input_ended,
        stats.native_finished,
        stats.ended,
        stats.complete()
    )
}
enum DecodeOwner<'a> {
    Snapshot(RetainedRtpH264Decoder<'a>),
    Current(CheckedRetainedRtpH264Decoder<'a>),
}
impl DecodeOwner<'_> {
    fn step(
        &mut self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<RetainedRtpDecodeStep> {
        match self {
            Self::Snapshot(decoder) => Ok(decoder.step(deployment, cx)?),
            Self::Current(decoder) => Ok(decoder.step(deployment, cx)?),
        }
    }
    fn stats(&self) -> RetainedRtpDecodeStats {
        match self {
            Self::Snapshot(decoder) => decoder.stats(),
            Self::Current(decoder) => decoder.stats(),
        }
    }
}
fn execute(
    options: &Options,
    root: &std::path::Path,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> Result<()> {
    let deployment = ReferenceDeployment::reopen(root, &options.site, cx)?;
    let retained = inspect_rtp_import(options.source_root, 1, options.policy, cx, &deployment)?;
    let candidates = retained.h264_parameters(cx)?;
    writeln!(
        out,
        "operation=retained_rtp_{:?}\nsource_root={}\nsource_sha256={}\nsource_bytes={}",
        options.mode,
        retained.root(),
        retained.report().input_digest(),
        retained.report().input_bytes()
    )?;
    let complete = matches!(retained.state(), RtpRecoveryState::Complete { .. });
    writeln!(
        out,
        "import_complete={complete}\nsource_records={}\nsource_nals={}",
        retained.report().records().len(),
        retained.report().nals().len()
    )?;
    writeln!(
        out,
        "container_end={}\ncapture_time_class=unknown\nabsence_certifiable=false\ndecode_published=false",
        if matches!(retained.report().end(), ImportEnd::Ended) {
            "ended"
        } else {
            "framing_refused"
        }
    )?;
    for digest in &candidates.sequence {
        writeln!(out, "sps_candidate={digest}")?;
    }
    for digest in &candidates.picture {
        writeln!(out, "pps_candidate={digest}")?;
    }
    if options.mode == Mode::Inspect {
        return Ok(());
    }
    let parameters = options
        .parameters
        .or_else(|| candidates.unique_pair())
        .ok_or_else(|| {
            failure("select an exact in-source SPS/PPS pair; no unambiguous pair exists")
        })?;
    let request = RetainedRtpDecodeRequest {
        parameters,
        ..options.decode
    };
    let mut decoder = match options.custody_read_bytes {
        Some(max_read_bytes) => {
            let decoder = retained.decode_h264_checked(
                request,
                RtpCustodyDecodeLimits {
                    max_source_bytes: options.policy.max_source_bytes,
                    max_records: options.policy.max_records,
                    max_object_bytes: options.policy.max_object_bytes,
                    max_read_bytes,
                    max_steps: options.steps,
                    ..RtpCustodyDecodeLimits::default()
                },
                &deployment,
                cx,
            )?;
            writeln!(
                out,
                "custody_mode=current\ncustody_read_limit_bytes={max_read_bytes}"
            )?;
            DecodeOwner::Current(decoder)
        }
        None => DecodeOwner::Snapshot(retained.decode_h264(request, &deployment, cx)?),
    };
    let mut export = options
        .output
        .as_ref()
        .map(|path| {
            pgm_stream::PgmExport::prepare(
                path,
                root,
                options.output_bytes,
                request.decode.max_groups,
                cx,
            )
        })
        .transpose()?;
    let mut ended = false;
    let decode_result = (|| -> Result<()> {
        for _ in 0..options.steps {
            match decoder.step(&deployment, cx)? {
                RetainedRtpDecodeStep::Frame(frame) => {
                    let [width, height] = frame.dimensions();
                    writeln!(
                        out,
                        "frame_group={}\nframe_decoder_epoch={}\nframe_rtp_timestamp={}\nframe_width={width}\nframe_height={height}",
                        frame.source().group,
                        frame.source().decoder_epoch,
                        frame.source().timestamp
                    )?;
                    writeln!(
                        out,
                        "frame_luma_sha256={}\nframe_cb_sha256={}\nframe_cr_sha256={}",
                        ContentDigest::sha256(frame.pixels()),
                        ContentDigest::sha256(frame.cb()),
                        ContentDigest::sha256(frame.cr())
                    )?;
                    writeln!(
                        out,
                        "privacy_mask_policy={}\nprivacy_mask_binding={}",
                        frame
                            .mask()
                            .policy_digest()
                            .map_or_else(|| "none".to_owned(), |d| d.to_string()),
                        frame.mask().digest()
                    )?;
                    writeln!(
                        out,
                        "frame_capture_earliest_ns={}\nframe_capture_latest_ns={}",
                        frame.capture().earliest.0,
                        frame.capture().latest.0
                    )?;
                    if let Some(writer) = &mut export {
                        writer.frame(frame.dimensions(), frame.pixels(), cx)?;
                    }
                }
                RetainedRtpDecodeStep::Progress { effect, .. } => {
                    if let RtpDecodeEffect::Refused {
                        error,
                        retired_groups,
                        awaiting_idr,
                        resumed_group,
                    } = effect
                    {
                        writeln!(
                            out,
                            "decode_refusal={error:?}\nretired_groups={retired_groups}\nawaiting_idr={awaiting_idr}\nresumed_group={resumed_group:?}"
                        )?;
                    }
                }
                RetainedRtpDecodeStep::Ended(_) => {
                    ended = true;
                    break;
                }
            }
        }
        if !ended {
            return Err(failure("bounded decode step allowance exhausted"));
        }
        if !decoder.stats().complete() {
            return Err(failure(
                "retained RTP decode is incomplete; inspect refusal and skipped-group counts",
            ));
        }
        Ok(())
    })();
    statistics(decoder.stats(), out)?;
    if let DecodeOwner::Current(decoder) = &decoder {
        writeln!(
            out,
            "custody_read_bytes={}\ncustody_steps={}",
            decoder.read_bytes(),
            decoder.steps()
        )?;
    }
    if let Err(error) = decode_result {
        writeln!(out, "export_complete=false")?;
        return Err(error);
    }
    if let Some(export) = export {
        match export.finish(cx) {
            Ok(receipt) => writeln!(
                out,
                "export_complete=true\nexport_bytes={}\nexport_frames={}\nexport_sha256={}",
                receipt.bytes, receipt.frames, receipt.digest
            )?,
            Err(error) => {
                writeln!(out, "export_complete=false")?;
                return Err(error.into());
            }
        }
    }
    Ok(())
}
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if let Some(exit) = detect_cmd::dispatch(&args) {
        return exit;
    }
    if let Some(exit) = track_cmd::dispatch(&args) {
        return exit;
    }
    if let Some(exit) = motion_cmd::dispatch(&args) {
        return exit;
    }
    if let Some(exit) = receipt_cmd::dispatch(&args) {
        return exit;
    }
    match parse(&args) {
        Ok(None) => match io::stdout().lock().write_all(HELP.as_bytes()) {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        },
        Ok(Some(options)) => match run(options, &mut io::stdout().lock()) {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(error) => {
                eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}");
                ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
            }
        },
        Err((id, message)) => {
            eprintln!("{id}: {message}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod custody_tests {
    use super::*;

    fn args(extra: &[&str]) -> Vec<OsString> {
        let mut args: Vec<OsString> = [
            "decode",
            "--root",
            "unused-root",
            "--site",
            "site:test",
            "--source-root",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        args.push(ContentDigest::sha256(b"root").to_string().into());
        args.extend(extra.iter().map(|value| OsString::from(*value)));
        args
    }

    #[test]
    fn default_and_explicit_snapshot_keep_existing_admission() -> Result<()> {
        for extra in [&[][..], &["--custody", "snapshot"][..]] {
            let Ok(Some(options)) = parse(&args(extra)) else {
                return Err(failure("snapshot parsing failed"));
            };
            assert_eq!(options.custody_read_bytes, None);
        }
        Ok(())
    }

    #[test]
    fn current_mode_has_a_separate_explicit_read_allowance() -> Result<()> {
        let Ok(Some(default)) = parse(&args(&["--custody", "current"])) else {
            return Err(failure("current mode parsing failed"));
        };
        assert_eq!(default.custody_read_bytes, Some(512 * 1024 * 1024));
        let Ok(Some(explicit)) = parse(&args(&[
            "--custody",
            "current",
            "--max-custody-read-bytes",
            "134217728",
            "--max-read-bytes",
            "268435456",
        ])) else {
            return Err(failure("explicit current mode parsing failed"));
        };
        assert_eq!(explicit.custody_read_bytes, Some(128 * 1024 * 1024));
        assert_eq!(explicit.policy.max_read_bytes, 256 * 1024 * 1024);
        Ok(())
    }

    #[test]
    fn invalid_or_unselected_custody_allowances_refuse() {
        for extra in [
            vec!["--max-custody-read-bytes", "134217728"],
            vec![
                "--custody",
                "snapshot",
                "--max-custody-read-bytes",
                "134217728",
            ],
            vec!["--custody", "latest"],
            vec!["--custody", "current", "--max-custody-read-bytes", "1"],
            vec![
                "--custody",
                "current",
                "--max-custody-read-bytes",
                "2147483649",
            ],
        ] {
            assert!(matches!(
                parse(&args(&extra)),
                Err((ERR_CLI_MALFORMED_VALUE, _))
            ));
        }
    }

    #[test]
    fn custody_is_not_silently_accepted_by_inspection() {
        let mut args = args(&["--custody", "current"]);
        args[0] = "inspect".into();
        assert!(matches!(parse(&args), Err((ERR_CLI_UNKNOWN_OPTION, _))));
    }
}

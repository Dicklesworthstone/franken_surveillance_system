#![forbid(unsafe_code)]
//! Operator access to the existing canonical trajectory exporter and native verifier.
//! Saved transcripts supply no source, model, tracking policy, or allocation authority.

use super::*;
use super::super::receipt_cmd::{ReceiptWriter, open_saved};
use fss_reference::ingest::rtpdump::track_stream::{
    RtpTrackStreamCompletion, RtpTrackStreamError, RtpTrackStreamRequest,
    RtpTrackStreamSummary, verify_tracking_stream, write_tracking_stream,
};

const HELP: &str = "fss-decode-rtp <track-stream|verify-tracks> [ordinary track source/model options]\n\
  Require --root DIR --site SITE --source-root sha256:HEX --custody current\n\
  and --package FILE --package-sha256 sha256:HEX --class-index N.\n\
  track-stream: --tracks-out NEW_FILE\n\
  verify-tracks: --tracks-in FILE --tracks-sha256 sha256:HEX; no output files.\n\
  [--completion complete|diagnostic] (default complete)\n\
  [--max-tracks-bytes N] [--max-track-record-bytes N] [--max-track-records N]\n\
  All ordinary track numerical/source limits apply; repeat them exactly to verify.\n\
  Verification replays original custody, native decode, verified inference and tracking.\n\
  Saved bytes never configure the replay. A checksum alone does not verify a trajectory.\n\
  Diagnostic transcripts preserve source gaps: tracking_complete remains false.\n\
  Export is private, new-file-only and outside the deployment. Keep partial files on failure;\n\
  retry at a new destination. No camera, source write, physical identity or absence claim.\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Export,
    Verify,
}
impl Mode {
    fn marker(self) -> &'static str {
        match self {
            Self::Export => "tracks_export_complete",
            Self::Verify => "tracks_verified",
        }
    }
}

#[derive(Debug)]
struct StreamOptions {
    track: TrackOptions,
    stream: StreamSettings,
}
#[derive(Debug)]
struct StreamSettings {
    mode: Mode,
    path: PathBuf,
    expected: Option<ContentDigest>,
    completion: RtpTrackStreamCompletion,
    maximum_bytes: u64,
    maximum_frame: usize,
    maximum_records: u64,
}

pub(super) fn dispatch(args: &[OsString]) -> Option<ExitCode> {
    let mode = match args.first().and_then(|arg| arg.to_str()) {
        Some("track-stream") => Mode::Export,
        Some("verify-tracks") => Mode::Verify,
        _ => return None,
    };
    if args.len() == 2 && matches!(args[1].to_str(), Some("--help" | "-h")) {
        let result = io::stdout().lock().write_all(HELP.as_bytes());
        return Some(ExitCode::from(if result.is_ok() {
            ExitIdentity::SUCCESS.code
        } else {
            ExitIdentity::RUNTIME_FAILURE.code
        }));
    }
    Some(match parse(args, mode) {
        Err((identity, reason)) => {
            eprintln!("{identity}: {reason}");
            ExitCode::from(ExitIdentity::MALFORMED_VALUE.code)
        }
        Ok(options) => {
            let StreamOptions {
                track: TrackOptions { base, settings },
                stream,
            } = options;
            let mut out = io::stdout().lock();
            let result = super::super::run_with(base, &mut out, |base, root, cx, out| {
                execute(base, &settings, &stream, root, cx, out)
            });
            match result {
                Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
                Err(error) => {
                    let _ = writeln!(out, "{}=false\ntracking_complete=false", mode.marker());
                    eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}");
                    ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
                }
            }
        }
    })
}

fn parse(args: &[OsString], mode: Mode) -> ParseResult<StreamOptions> {
    // Bound argument copies before invoking the unchanged source/numerical parser.
    if args.is_empty() || args.len() > 257 || !(args.len() - 1).is_multiple_of(2)
        || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
    {
        return Err((ERR_CLI_MALFORMED_VALUE, "bounded option/value pairs required"));
    }
    let mut native = vec![OsString::from("track")];
    let mut values = BTreeMap::new();
    for pair in args[1..].chunks_exact(2) {
        let key = pair[0].to_str().ok_or((ERR_CLI_INVALID_UNICODE, "UTF-8 option required"))?;
        if matches!(key, "--output" | "--report-out" | "--max-report-bytes") {
            return Err((ERR_CLI_UNKNOWN_OPTION, "trajectory commands do not emit pixels or JSON reports"));
        }
        if matches!(key, "--tracks-out" | "--tracks-in" | "--tracks-sha256"
            | "--completion" | "--max-tracks-bytes" | "--max-track-record-bytes"
            | "--max-track-records")
        {
            if (mode == Mode::Export && matches!(key, "--tracks-in" | "--tracks-sha256"))
                || (mode == Mode::Verify && key == "--tracks-out")
            {
                return Err((ERR_CLI_UNKNOWN_OPTION, "trajectory option belongs to the other mode"));
            }
            if values.insert(key.to_owned(), pair[1].clone()).is_some() {
                return Err((ERR_CLI_DUPLICATE_OPTION, "duplicate trajectory option"));
            }
        } else {
            native.extend_from_slice(pair);
        }
    }
    // This is the ordinary track parser without its presentation-only report requirement.
    // It still rejects missing model/class/current-custody and every invalid numerical policy.
    let track = super::parse_native(&native)?;
    let path_key = if mode == Mode::Export { "--tracks-out" } else { "--tracks-in" };
    let path = PathBuf::from(super::super::required(&values, path_key)?);
    if path.as_os_str().is_empty() {
        return Err((ERR_CLI_MALFORMED_VALUE, "nonempty trajectory path required"));
    }
    let expected = if mode == Mode::Verify {
        let expected = super::super::digest(&values, "--tracks-sha256")?;
        if expected.algorithm() != DigestAlgorithm::Sha256 {
            return Err((ERR_CLI_MALFORMED_VALUE, "independent SHA-256 required"));
        }
        Some(expected)
    } else {
        None
    };
    let completion = match values.get("--completion") {
        None => RtpTrackStreamCompletion::CompleteSource,
        Some(value) => match value.to_str() {
            Some("complete") => RtpTrackStreamCompletion::CompleteSource,
            Some("diagnostic") => RtpTrackStreamCompletion::SourceDiagnostics,
            _ => return Err((ERR_CLI_MALFORMED_VALUE, "completion must be complete or diagnostic")),
        },
    };
    let maximum_bytes = super::super::number(&values, "--max-tracks-bytes", 64 * 1024 * 1024_u64)?;
    let maximum_frame = super::super::number(&values, "--max-track-record-bytes", 16 * 1024 * 1024_usize)?;
    let maximum_records = super::super::number(&values, "--max-track-records", 1_000_002_u64)?;
    if !(1..=256 * 1024 * 1024).contains(&maximum_bytes)
        || !(1..=16 * 1024 * 1024).contains(&maximum_frame)
        || !(3..=5_000_002).contains(&maximum_records)
    {
        return Err((ERR_CLI_MALFORMED_VALUE, "trajectory bounds exceed native profile"));
    }
    Ok(StreamOptions {
        track,
        stream: StreamSettings {
            mode, path, expected, completion, maximum_bytes, maximum_frame, maximum_records,
        },
    })
}

fn execute(
    base: &Options,
    settings: &TrackSettings,
    stream: &StreamSettings,
    root: &Path,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> Result<()> {
    // Reject unsafe/missing destinations before model or source readback. Export creation stays
    // lazy until the native owner admits its header; verification never constructs a writer.
    let destination = if stream.mode == Mode::Export {
        Some(PrivateOutputPath::prepare(&stream.path, root, cx)?)
    } else {
        None
    };
    let mut saved = if stream.mode == Mode::Verify {
        Some(open_saved(&stream.path, stream.maximum_bytes, cx)?)
    } else {
        None
    };
    let scalar = ScalarExecCx::new();
    let result = (|| -> Result<()> {
        cx.checkpoint("rtpdump:trajectory:package")
            .map_err(|_| failure("trajectory operation cancelled"))?;
        let bytes = super::read_package(&settings.package)?;
        cx.checkpoint("rtpdump:trajectory:package_loaded")
            .map_err(|_| failure("trajectory operation cancelled"))?;
        let package = RgbDetectorPackage::load(&bytes, settings.package_digest, 1 << 36, cx, &scalar)?;
        if settings.class_index >= package.spec().labels.len() {
            return Err(failure("selected class is outside the verified package vocabulary"));
        }
        let deployment = ReferenceDeployment::reopen(root, &base.site, cx)?;
        let retained = inspect_rtp_import(base.source_root, 1, base.policy, cx, &deployment)?;
        let parameters = base.parameters.or(retained.h264_parameters(cx)?.unique_pair())
            .ok_or_else(|| failure("select an exact in-source SPS/PPS pair"))?;
        let mut request = RtpTrackStreamRequest::new(super::tracking_request(base, settings, parameters)?);
        request.completion = stream.completion;
        request.max_stream_bytes = stream.maximum_bytes;
        request.max_frame_bytes = stream.maximum_frame;
        request.max_records = stream.maximum_records;
        let result = match stream.mode {
            Mode::Export => {
                let destination = destination.ok_or_else(|| failure("export destination absent"))?;
                let mut writer = ReceiptWriter::new(destination, cx);
                let result = write_tracking_stream(
                    &retained, &package, request, &mut writer, &deployment, cx, &scalar,
                );
                match result {
                    Ok(summary) => {
                        // No success digest or completion marker precedes durable file+directory sync.
                        writer.finish()?;
                        Ok(summary)
                    }
                    Err(error) => Err(error),
                }
            }
            Mode::Verify => verify_tracking_stream(
                &retained,
                &package,
                request,
                saved.as_mut().ok_or_else(|| failure("verification input absent"))?,
                stream.expected.ok_or_else(|| failure("independent digest absent"))?,
                &deployment,
                cx,
                &scalar,
            ),
        };
        let summary = match result {
            Ok(summary) => summary,
            Err(RtpTrackStreamError::Incomplete(stats)) => {
                super::write_stats(stats, out)?;
                return Err(RtpTrackStreamError::Incomplete(stats).into());
            }
            Err(error) => return Err(error.into()),
        };
        cx.checkpoint("rtpdump:trajectory:report")
            .map_err(|_| failure("trajectory operation cancelled"))?;
        let mut status = Vec::new();
        report(&summary, stream.mode, &mut status)?;
        let mut check = || -> io::Result<()> {
            cx.checkpoint("rtpdump:trajectory:status")
                .map_err(|_| io::Error::other("trajectory status cancelled"))?;
            scalar.checkpoint("rtpdump:trajectory:status")
                .map_err(|_| io::Error::other("trajectory status cancelled"))?;
            Ok(())
        };
        // Same bounded/interruptible writer as ordinary tracking reports. All status fields
        // are fixed enum spellings, checked counters or canonical digests, never source text.
        let mut output = ReportWriter::new(out, 4096);
        output.record(&status, &mut check)?;
        check()?;
        output.writer.flush()?;
        check()?;
        Ok(())
    })();
    scalar.drain_and_finalize();
    result
}

fn report(summary: &RtpTrackStreamSummary, mode: Mode, out: &mut impl Write) -> io::Result<()> {
    super::write_stats(summary.stats, out)?;
    // Transcript completion and source completeness deliberately remain separate. A diagnostic
    // transcript can be verified while tracking_complete is false; no source facts are upgraded.
    writeln!(out, "operation={}\ntracking_complete={}\ntracks_bytes={}\ntracks_records={}\ntracks_observations={}\ntracking_recipe={}\nnative_recipe={}\nlast_track_frame={}\ntracks_sha256={}\n{}=true",
        if mode == Mode::Export { "rtp_trajectory_export" } else { "rtp_trajectory_verification" },
        summary.stats.complete(), summary.bytes, summary.records, summary.observations,
        summary.recipe, summary.native_recipe, summary.last_frame, summary.digest, mode.marker())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(mode: Mode) -> Vec<OsString> {
        let source = ContentDigest::sha256(b"source").to_string();
        let package = ContentDigest::sha256(b"package").to_string();
        let saved = ContentDigest::sha256(b"saved").to_string();
        let mut args: Vec<OsString> = [
            if mode == Mode::Export { "track-stream" } else { "verify-tracks" },
            "--root", "unopened", "--site", "site:trajectory", "--source-root", &source,
            "--custody", "current", "--package", "unopened.fmpk", "--package-sha256", &package,
            "--class-index", "0",
        ].into_iter().map(OsString::from).collect();
        if mode == Mode::Export {
            args.extend(["--tracks-out".into(), "new.tracks".into()]);
        } else {
            args.extend(["--tracks-in".into(), "saved.tracks".into(), "--tracks-sha256".into(), saved.into()]);
        }
        args
    }
    fn extra(args: &mut Vec<OsString>, key: &str, value: &str) {
        args.extend([key.into(), value.into()]);
    }

    #[test]
    fn both_modes_reuse_track_admission_without_a_fake_report_destination() -> Result<()> {
        for mode in [Mode::Export, Mode::Verify] {
            let parsed = parse(&args(mode), mode).map_err(|(_, reason)| failure(reason))?;
            assert!(parsed.track.settings.report.is_none());
            assert_eq!(parsed.track.settings.class_index, 0);
            assert_eq!(parsed.stream.completion, RtpTrackStreamCompletion::CompleteSource);
            assert_eq!(parsed.stream.maximum_bytes, 64 * 1024 * 1024);
            assert_eq!(parsed.stream.expected.is_some(), mode == Mode::Verify);
        }
        Ok(())
    }
    #[test]
    fn mandatory_source_model_class_and_digest_are_not_derived_from_saved_bytes() {
        for mode in [Mode::Export, Mode::Verify] {
            let original = args(mode);
            let mut required = vec!["--source-root", "--custody", "--package", "--package-sha256", "--class-index"];
            required.push(if mode == Mode::Export { "--tracks-out" } else { "--tracks-in" });
            if mode == Mode::Verify { required.push("--tracks-sha256"); }
            for key in required {
                let mut input = vec![original[0].clone()];
                for pair in original[1..].chunks_exact(2).filter(|pair| pair[0] != key) {
                    input.extend_from_slice(pair);
                }
                assert!(parse(&input, mode).is_err(), "missing {key}");
            }
        }
    }
    #[test]
    fn verification_cannot_become_export_or_pixel_output() {
        for (key, value) in [
            ("--tracks-out", "other"), ("--report-out", "other"), ("--output", "other"),
            ("--max-report-bytes", "4096"),
        ] {
            let mut input = args(Mode::Verify);
            extra(&mut input, key, value);
            assert!(matches!(parse(&input, Mode::Verify), Err((ERR_CLI_UNKNOWN_OPTION, _))));
        }
        let mut input = args(Mode::Export);
        extra(&mut input, "--tracks-in", "other");
        assert!(parse(&input, Mode::Export).is_err());
    }
    #[test]
    fn independent_bounds_and_duplicate_options_refuse_in_pure_parsing() {
        for (key, value) in [
            ("--max-tracks-bytes", "0"), ("--max-tracks-bytes", "268435457"),
            ("--max-track-record-bytes", "0"), ("--max-track-record-bytes", "16777217"),
            ("--max-track-records", "2"), ("--max-track-records", "5000003"),
            ("--completion", "automatic"), ("--track-min-hits", "0"),
        ] {
            let mut input = args(Mode::Export);
            extra(&mut input, key, value);
            assert!(parse(&input, Mode::Export).is_err(), "{key}={value}");
        }
        let mut duplicate = args(Mode::Verify);
        extra(&mut duplicate, "--tracks-in", "second");
        assert!(matches!(parse(&duplicate, Mode::Verify), Err((ERR_CLI_DUPLICATE_OPTION, _))));
        let mut missing_value = args(Mode::Export);
        missing_value.push("--max-track-records".into());
        assert!(parse(&missing_value, Mode::Export).is_err());
    }
    #[test]
    fn diagnostics_require_an_explicit_choice_without_weakening_native_limits() -> Result<()> {
        let mut input = args(Mode::Verify);
        extra(&mut input, "--completion", "diagnostic");
        extra(&mut input, "--max-track-frames", "1");
        let parsed = parse(&input, Mode::Verify).map_err(|(_, reason)| failure(reason))?;
        assert_eq!(parsed.stream.completion, RtpTrackStreamCompletion::SourceDiagnostics);
        assert_eq!(parsed.track.settings.max_track_frames, 1);
        Ok(())
    }
}

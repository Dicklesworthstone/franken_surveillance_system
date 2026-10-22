#![forbid(unsafe_code)]
//! `fss-infer package-detect`: retained recording -> verified RGB detector package -> report.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, PrincipalId};
use fss_reference::ingest::package_detect::sentinel::{
    SentinelConfig, SentinelPlan, run_sentinel_detection,
};
use fss_reference::ingest::package_detect::{
    MAX_PACKAGE_DETECT_FRAMES, PackageDetectLimits, PackageDetectRequest, run_package_detection,
};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::rgb_package::{MAX_RGB_PACKAGE_BYTES, RgbDetectorPackage};
use fss_reference::{
    ExecBudget, ExecThreads, KernelBackend, MAX_EXEC_THREADS, ReferenceDeployment, ReplayCx,
    ScalarExecCx,
};

use super::long_sentinel_cli;
use super::{RunResult, Values, digest, export, number, text, value};

const HELP: &str = "fss-infer package-detect [options]\n\
  --root DIR --site SITE --import-id sha256:HEX --first-segment N --frames N (1..64)\n\
  --package FILE --package-digest sha256:HEX --interpretation gray|ycbcr\n\
  [--minimum-score-ppm N] [--max-macs N] [--max-tensor-bytes N] [--report-out FILE] [--principal ID]\n\
  [--retain yes]\n\
  [--sentinel-every-frames N --sentinel-max-inferences M [--sentinel-burst-frames K]]\n\
  [--stream-sentinel yes --stream-read-bytes N --stream-pixel-budget N --max-report-bytes N]\n\
  [--max-frame-pixels N (stream-sentinel only)]\n\
  [--kernels optimized-cpu|scalar-reference] [--threads N|auto]\n\
  Runs a digest-pinned, verified RGB detector package (for example models/yolox-nano/\n\
  yolox_nano.fmpk) over a retained MJPEG, H.264 or H.265 import. JPEG frames are decoded to\n\
  RGB; H.264/H.265 frames are converted from decoded luma and chroma with the declared BT.601\n\
  limited-range transform (color ycbcr420_bt601_limited_rgb). H.264 ranges must start at an IDR\n\
  and H.265 at an IRAP; interpretation must be ycbcr for both. Prints a\n\
  fss.package_detection_report.v1 JSON document: uncalibrated proposals with source, inference,\n\
  contract and package identities. Nothing is downloaded, activated or alerted; a frame without\n\
  detections is not evidence of absence. --retain yes additionally retains this exact report as\n\
  cognition-plane evidence (root-last plus one package_detection_record delta) so `fss-event\n\
  report --package-report sha256:REPORT` can consume it; stdout stays the exact report bytes and\n\
  the retention receipt goes to stderr (package_detection_retained=, status=, root=).\n\
  Sentinel mode samples short contiguous bursts independently of foreground or motion.\n\
  --frames is the whole source/decode range (1..64); the first burst starts at --first-segment.\n\
  Period N is 1..64; burst K is 1..8 (default 3, no larger than N); allowance M is explicit,\n\
  at least K and at most 64 for the whole invocation. Only complete bursts are admitted.\n\
  Later budget-skipped bursts and every unsampled segment remain explicit. AVC/HEVC decode\n\
  the whole IDR/IRAP-led range once, but only admitted frames run RGB conversion and inference.\n\
  Prints fss.sentinel_detection_report.v1 with separate ordinary reports for completed bursts.\n\
  --retain yes retains each child report independently for the existing event workflow;\n\
  a later failure does not undo earlier children. Retry exact inputs to resume idempotently.\n\
  No tracking bridges the gaps. No continuous coverage, absence, recall or alert claim is made.\n\
  --stream-sentinel yes permits a complete source range and period up to 65536 frames,\n\
  keeping burst length at most 8 and one shared inference allowance at most 64. It requires\n\
  the explicit sentinel period and inference allowance. Source-read/pixel/report ceilings\n\
  default to 536870912 bytes, 1073741824 luma samples and 16777216 report bytes.\n\
  --max-frame-pixels accepts 256..9437184 and only narrows native JPEG/AVC/HEVC ceilings.\n\
  AVC rounds down to whole 256-pixel macroblocks; omitted values preserve native defaults.\n\
  Video admission charges configured coded-luma capacity before every access unit, including\n\
  decode-ahead and skipped CRA leading pictures. This differs from actual returned raster\n\
  usage. The default video capacity is 9437184 samples per access unit; a tighter known\n\
  camera ceiling permits longer footage within the same whole-operation allowance.\n\
  AVC/HEVC decode the full strict range once, including the suffix after the last sample;\n\
  a source gap or decode refusal fails the computation. MJPEG decodes selected frames only.\n\
  All source, JPEG and detection-head allowances are shared across bursts. Model MACs and\n\
  tensor scratch remain per inference; the full inference/output reservation is admitted\n\
  before source reads. Whole-recording retention also saves the exact package and recipe\n\
  for fss-infer sentinel-replay without loose model or source files.\n\
  Without sentinel options the existing output and retention behavior are unchanged.\n\
  The default threshold is the package's own; --minimum-score-ppm is an explicit override.\n\
  --kernels selects the executor: optimized-cpu (default; certified bit-identical to the\n\
  scalar reference) or scalar-reference (the slow oracle, seconds per 416x416 frame). The\n\
  choice is bound into the model digest recorded in the report.\n\
  --threads N (1..64) sets the optimized executor's scoped worker threads (default 1: the\n\
  calling thread only); auto uses the host's available parallelism capped at 64. Outputs are\n\
  bit-identical for every N, so the report bytes do not depend on it.\n";

#[derive(Debug)]
struct Options {
    root: PathBuf,
    site: String,
    principal: String,
    package: PathBuf,
    package_digest: ContentDigest,
    kernels: KernelBackend,
    threads: ExecThreads,
    request: PackageDetectRequest,
    limits: PackageDetectLimits,
    report: Option<PathBuf>,
    retain: bool,
    sentinel: Option<SentinelConfig>,
    stream_sentinel: Option<long_sentinel_cli::StreamOptions>,
}

fn parse(args: &[OsString]) -> Result<Option<Options>, String> {
    if args.is_empty() {
        return Ok(None);
    }
    if matches!(args[0].to_str(), Some("help" | "--help" | "-h")) {
        return if args.len() == 1 {
            Ok(None)
        } else {
            Err("help takes no other arguments".into())
        };
    }
    let allowed = [
        "--root",
        "--site",
        "--principal",
        "--import-id",
        "--first-segment",
        "--frames",
        "--package",
        "--package-digest",
        "--interpretation",
        "--minimum-score-ppm",
        "--max-macs",
        "--max-tensor-bytes",
        "--report-out",
        "--retain",
        "--kernels",
        "--threads",
        "--sentinel-every-frames",
        "--sentinel-burst-frames",
        "--sentinel-max-inferences",
    ];
    let mut values = Values::new();
    for pair in args.chunks(2) {
        let key = pair[0].to_str().ok_or("option names require UTF-8")?;
        if !allowed.contains(&key) && !long_sentinel_cli::RUN_OPTIONS.contains(&key) {
            return Err("unknown or inapplicable package-detect option".into());
        }
        if values.contains_key(key) {
            return Err(format!("duplicate {key}"));
        }
        let v = pair
            .get(1)
            .ok_or_else(|| format!("missing value for {key}"))?;
        if v.is_empty() || v.to_str().is_some_and(|s| s.starts_with("--")) {
            return Err(format!("missing value for {key}"));
        }
        values.insert(key.to_owned(), v.clone());
    }
    let site = text(&values, "--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| "invalid site lineage")?;
    let principal = if values.contains_key("--principal") {
        text(&values, "--principal")?.to_owned()
    } else {
        "principal:local-operator".to_owned()
    };
    PrincipalId::parse(&principal).map_err(|_| "invalid principal ID")?;
    let interpretation = match text(&values, "--interpretation")? {
        "gray" => ComponentInterpretation::Grayscale,
        "ycbcr" => ComponentInterpretation::YCbCr,
        _ => return Err("interpretation requires explicit gray or ycbcr".into()),
    };
    let frames: usize = number(&values, "--frames", None)?;
    let first_segment: usize = number(&values, "--first-segment", None)?;
    let minimum_score_ppm = if values.contains_key("--minimum-score-ppm") {
        let ppm: u32 = number(&values, "--minimum-score-ppm", None)?;
        if ppm > 1_000_000 {
            return Err("minimum score must be 0..1000000 ppm".into());
        }
        Some(ppm)
    } else {
        None
    };
    let stream_sentinel = long_sentinel_cli::enabled(&values)?;
    let maximum_frames = if stream_sentinel {
        fss_reference::ingest::long_watch::MAX_LONG_WATCH_FRAMES
    } else {
        MAX_PACKAGE_DETECT_FRAMES
    };
    if frames == 0 || frames > maximum_frames || first_segment.checked_add(frames).is_none() {
        return Err(format!(
            "frames must be 1..{maximum_frames} within the addressable range"
        ));
    }
    let sentinel = if stream_sentinel {
        None
    } else {
        parse_sentinel(&values, first_segment, frames)?
    };
    let kernels = if values.contains_key("--kernels") {
        match text(&values, "--kernels")? {
            "optimized-cpu" => KernelBackend::OptimizedCpuV1,
            "scalar-reference" => KernelBackend::ScalarReference,
            _ => return Err("kernels must be optimized-cpu or scalar-reference".into()),
        }
    } else {
        KernelBackend::OptimizedCpuV1
    };
    let threads = match values.get("--threads").map(|v| v.to_str()) {
        None => ExecThreads::SINGLE,
        Some(Some("auto")) => {
            // The CLI (not the library) may consult the host; the count never affects outputs.
            let host = std::thread::available_parallelism().map_or(1, |n| n.get());
            ExecThreads::new(host.min(MAX_EXEC_THREADS)).unwrap_or(ExecThreads::SINGLE)
        }
        Some(_) => {
            let n: usize = number(&values, "--threads", None)?;
            ExecThreads::new(n).map_err(|e| format!("--threads: {e}"))?
        }
    };
    let mut limits = PackageDetectLimits::default();
    let max_bytes: usize = number(
        &values,
        "--max-tensor-bytes",
        Some(limits.run.execution.max_bytes),
    )?;
    if max_bytes == 0 || max_bytes > 256 * 1024 * 1024 {
        return Err("tensor ceiling must be 1..268435456 bytes".into());
    }
    limits.run.execution = ExecBudget::new(
        number(&values, "--max-macs", Some(limits.run.execution.max_macs))?,
        max_bytes,
    );
    let stream_sentinel = long_sentinel_cli::parse_run(&values, first_segment, frames, limits)?;
    Ok(Some(Options {
        root: PathBuf::from(value(&values, "--root")?),
        site,
        principal,
        package: PathBuf::from(value(&values, "--package")?),
        package_digest: digest(&values, "--package-digest")?,
        kernels,
        threads,
        sentinel,
        stream_sentinel,
        request: PackageDetectRequest {
            import_identity: digest(&values, "--import-id")?,
            first_segment,
            segment_count: frames,
            interpretation,
            minimum_score_ppm,
        },
        limits,
        report: values.get("--report-out").map(PathBuf::from),
        retain: match values.get("--retain").map(|v| v.to_str()) {
            None => false,
            Some(Some("yes")) => true,
            Some(_) => return Err("--retain accepts only yes".into()),
        },
    }))
}

fn parse_sentinel(
    values: &Values,
    first_segment: usize,
    frames: usize,
) -> Result<Option<SentinelConfig>, String> {
    if !values.contains_key("--sentinel-every-frames") {
        if values.contains_key("--sentinel-burst-frames")
            || values.contains_key("--sentinel-max-inferences")
        {
            return Err("sentinel burst/allowance requires --sentinel-every-frames".into());
        }
        return Ok(None);
    }
    let config = SentinelConfig {
        every_frames: number(values, "--sentinel-every-frames", None)?,
        burst_frames: number(values, "--sentinel-burst-frames", Some(3))?,
        max_inferences: number(values, "--sentinel-max-inferences", None)?,
    };
    SentinelPlan::new(first_segment, frames, config).map_err(|_| {
        "sentinel requires period 1..64, burst 1..8 no larger than period/range, and explicit allowance burst..64"
            .to_owned()
    })?;
    Ok(Some(config))
}

fn read_package(path: &Path) -> RunResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_RGB_PACKAGE_BYTES as u64 {
        return Err(
            io::Error::other("package must be a bounded regular file, not a symlink").into(),
        );
    }
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_RGB_PACKAGE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn run(options: Options, out: &mut impl Write) -> RunResult<()> {
    let authority_bytes = match &options.stream_sentinel {
        Some(stream) => stream.authority_bytes()?,
        None => 64 * 1024 * 1024,
    };
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:package-detect-cli".into(),
        operation_id: OperationId::parse("operation:package-detect-cli")?,
        principal: options.principal,
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(authority_bytes).build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    if !fs::symlink_metadata(&options.root)?.file_type().is_dir()
        || !fs::symlink_metadata(options.root.join("LAYOUT"))?
            .file_type()
            .is_file()
    {
        return Err(io::Error::other("existing non-symlink deployment required").into());
    }
    let cx = ReplayCx::from_context_authority(&authority, options.root.clone())?;
    let scalar = ScalarExecCx::new();
    let result = (|| -> RunResult<()> {
        let bytes = read_package(&options.package)?;
        let package = RgbDetectorPackage::load_with_backend(
            &bytes,
            options.package_digest,
            1 << 36,
            options.kernels,
            &cx,
            &scalar,
        )?
        .with_execution_threads(options.threads);
        let mut deployment = ReferenceDeployment::open(&options.root, &options.site, &cx)?;
        if let Some(stream) = &options.stream_sentinel {
            let request = stream.request(&options.request);
            let report = fss_reference::ingest::long_sentinel::run_long_sentinel_detection(
                &deployment,
                &package,
                &request,
                stream.config,
                &stream.limits,
                &cx,
                &scalar,
            )?;
            if options.retain {
                let retained = fss_reference::ingest::long_sentinel::retained::retain_long_sentinel_detection(
                    &mut deployment, &package, &bytes, &report, &cx,
                ).inspect_err(|_| {
                    eprintln!("Earlier retained sentinel children may be durable; retry the exact source, package, schedule and ceilings to reconcile.");
                })?;
                eprintln!(
                    "long_sentinel_retained={}\nstatus={}\nroot={}\nrecipe={}\npackage={}\nchildren={}\nauthority_sequence={}",
                    retained.report_digest(),
                    retained.status().as_str(),
                    retained.root(),
                    retained.recipe_digest(),
                    retained.package_digest(),
                    retained.child_reports().len(),
                    retained.authority_anchor().commit_sequence,
                );
            }
            if let Some(path) = &options.report {
                export(path, report.json().as_bytes(), &options.root, &cx)?;
            }
            cx.checkpoint("long_sentinel:cli_release")?;
            out.write_all(report.json().as_bytes())?;
            return Ok(());
        }
        if let Some(config) = options.sentinel {
            let report = run_sentinel_detection(
                &deployment,
                &package,
                &options.request,
                config,
                &options.limits,
                &cx,
                &scalar,
            )?;
            if let Some(path) = &options.report {
                export(path, report.json().as_bytes(), &options.root, &cx)?;
            }
            if options.retain {
                // The child reports use the existing root-last publication and deletion closure.
                // This is intentionally not an atomic multi-burst transaction. Each completed
                // receipt remains truthful if a later child fails; exact reruns are idempotent.
                for child in report.reports() {
                    let retained = fss_reference::ingest::package_event::retain_package_detection(
                        &mut deployment, &package, child, &cx,
                    ).inspect_err(|_| {
                        eprintln!("Earlier completed sentinel burst roots remain retained; retry exact inputs to reconcile remaining children.");
                    })?;
                    eprintln!(
                        "package_detection_retained={}\nstatus={}\nroot={}\nrecord={}\nauthority_sequence={}",
                        child.digest,
                        retained.status().as_str(),
                        retained.root(),
                        retained.record_digest(),
                        retained.authority_anchor().commit_sequence
                    );
                }
            }
            // Never print a completed invocation after a requested child retention failed.
            out.write_all(report.json().as_bytes())?;
            return Ok(());
        }
        let report = run_package_detection(
            &deployment,
            &package,
            &options.request,
            &options.limits,
            &cx,
            &scalar,
        )?;
        if let Some(path) = &options.report {
            export(path, report.json.as_bytes(), &options.root, &cx)?;
        }
        out.write_all(report.json.as_bytes())?;
        if options.retain {
            let retained = fss_reference::ingest::package_event::retain_package_detection(
                &mut deployment,
                &package,
                &report,
                &cx,
            )?;
            eprintln!(
                "package_detection_retained={}\nstatus={}\nroot={}\nrecord={}\nauthority_sequence={}",
                report.digest,
                retained.status().as_str(),
                retained.root(),
                retained.record_digest(),
                retained.authority_anchor().commit_sequence
            );
        }
        Ok(())
    })();
    scalar.drain_and_finalize();
    cx.drain_and_finalize();
    result
}

/// Handles only `package-detect`, preserving every existing subcommand.
pub(super) fn dispatch(args: &[OsString], out: &mut impl Write) -> Option<ExitCode> {
    if args.first().and_then(|a| a.to_str()) != Some("package-detect") {
        return None;
    }
    Some(match parse(&args[1..]) {
        Ok(None) => ExitCode::from(if out.write_all(HELP.as_bytes()).is_ok() {
            0
        } else {
            1
        }),
        Ok(Some(options)) => match run(options, out) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                let id = error.downcast_ref::<fss_reference::ingest::rgb_package::RgbPackageError>().map(|e| e.stable_id())
                    .or_else(|| error.downcast_ref::<fss_reference::ingest::package_detect::PackageDetectError>().map(|e| e.stable_id()))
                    .or_else(|| error.downcast_ref::<fss_reference::ingest::package_event::PackageEventError>().map(|e| e.stable_id()))
                    .or_else(|| error.downcast_ref::<fss_reference::ingest::long_sentinel::retained::LongSentinelRetentionError>().map(|e| e.stable_id()))
                    .unwrap_or(fss_cli::ERR_CLI_RUNTIME_FAILURE);
                eprintln!("{id}: {error}");
                ExitCode::from(fss_cli::ExitIdentity::RUNTIME_FAILURE.code)
            }
        },
        Err(reason) => {
            eprintln!(
                "{}: {reason}; use fss-infer package-detect --help",
                fss_cli::ERR_CLI_MALFORMED_VALUE
            );
            ExitCode::from(fss_cli::ExitIdentity::MALFORMED_VALUE.code)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<OsString> {
        [
            "--root",
            "unused",
            "--site",
            "site:package",
            "--import-id",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "--first-segment",
            "0",
            "--frames",
            "2",
            "--interpretation",
            "ycbcr",
            "--package",
            "yolox_nano.fmpk",
            "--package-digest",
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }
    #[test]
    fn exact_package_digest_range_and_interpretation_are_required() {
        assert!(matches!(parse(&args()), Ok(Some(_))));
        for key in [
            "--package-digest",
            "--package",
            "--frames",
            "--interpretation",
            "--import-id",
        ] {
            let mut a = args();
            if let Some(i) = a.iter().position(|v| v == key) {
                a.drain(i..i + 2);
            }
            assert!(parse(&a).is_err(), "{key}");
        }
    }
    #[test]
    fn unknown_duplicate_and_out_of_bound_options_are_refused() {
        for extra in [
            ["--latest", "true"],
            ["--site", "site:other"],
            ["--minimum-score-ppm", "1000001"],
            ["--max-tensor-bytes", "0"],
            ["--max-tensor-bytes", "268435457"],
            ["--model", "x"],
            ["--retain", "true"],
        ] {
            let mut a = args();
            a.extend(extra.map(OsString::from));
            assert!(parse(&a).is_err(), "{extra:?}");
        }
        let mut a = args();
        if let Some(i) = a.iter().position(|v| v == "--frames") {
            a[i + 1] = "65".into();
        }
        assert!(parse(&a).is_err());
        assert!(matches!(parse(&["--help".into()]), Ok(None)));
    }

    #[test]
    fn sentinel_is_opt_in_and_requires_its_own_explicit_allowance() -> Result<(), String> {
        let ordinary = parse(&args())?.ok_or("missing ordinary request")?;
        assert!(ordinary.sentinel.is_none());
        for flags in [
            vec!["--sentinel-every-frames", "8"],
            vec!["--sentinel-burst-frames", "1"],
            vec!["--sentinel-max-inferences", "1"],
        ] {
            let mut a = args();
            a.extend(flags.into_iter().map(OsString::from));
            assert!(parse(&a).is_err());
        }
        let mut a = args();
        a.extend(
            [
                "--sentinel-every-frames",
                "8",
                "--sentinel-burst-frames",
                "1",
                "--sentinel-max-inferences",
                "1",
            ]
            .map(OsString::from),
        );
        let parsed = parse(&a)?.ok_or("missing sentinel request")?;
        assert_eq!(
            parsed.sentinel,
            Some(SentinelConfig {
                every_frames: 8,
                burst_frames: 1,
                max_inferences: 1,
            })
        );
        Ok(())
    }

    #[test]
    fn sentinel_rejects_partial_burst_budget_and_duplicate_sampling_options() {
        for flags in [
            vec![
                "--sentinel-every-frames",
                "0",
                "--sentinel-max-inferences",
                "3",
            ],
            vec![
                "--sentinel-every-frames",
                "8",
                "--sentinel-max-inferences",
                "65",
            ],
            vec![
                "--sentinel-every-frames",
                "8",
                "--sentinel-max-inferences",
                "1",
            ],
            vec![
                "--sentinel-every-frames",
                "8",
                "--sentinel-max-inferences",
                "3",
            ],
            vec![
                "--sentinel-every-frames",
                "2",
                "--sentinel-max-inferences",
                "4",
                "--sentinel-burst-frames",
                "3",
            ],
            vec![
                "--sentinel-every-frames",
                "8",
                "--sentinel-max-inferences",
                "1",
                "--sentinel-burst-frames",
                "1",
                "--sentinel-every-frames",
                "16",
            ],
        ] {
            let mut a = args(); // A two-frame source cannot contain the default three-frame burst.
            a.extend(flags.into_iter().map(OsString::from));
            assert!(parse(&a).is_err());
        }
    }

    #[test]
    fn sentinel_default_burst_and_retention_are_explicit() -> Result<(), String> {
        let mut a = args();
        let frames = a
            .iter()
            .position(|v| v == "--frames")
            .ok_or("no frame count")?;
        a[frames + 1] = "20".into();
        a.extend(
            [
                "--sentinel-every-frames",
                "8",
                "--sentinel-max-inferences",
                "6",
                "--retain",
                "yes",
            ]
            .map(OsString::from),
        );
        let parsed = parse(&a)?.ok_or("missing sentinel request")?;
        assert_eq!(
            parsed.sentinel,
            Some(SentinelConfig {
                every_frames: 8,
                burst_frames: 3,
                max_inferences: 6,
            })
        );
        assert!(parsed.retain);
        Ok(())
    }

    fn stream_args() -> Vec<OsString> {
        let mut input = args();
        let frames = input
            .iter()
            .position(|value| value == "--frames")
            .expect("fixture frames");
        input[frames + 1] = "170".into();
        input.extend(
            [
                "--stream-sentinel",
                "yes",
                "--sentinel-every-frames",
                "130",
                "--sentinel-burst-frames",
                "3",
                "--sentinel-max-inferences",
                "6",
            ]
            .map(OsString::from),
        );
        input
    }

    fn replace(input: &mut [OsString], key: &str, value: &str) {
        let at = input
            .iter()
            .position(|argument| argument == key)
            .expect("fixture option");
        input[at + 1] = value.into();
    }

    #[test]
    fn whole_recording_sentinel_admits_late_bursts_without_widening_short_paths()
    -> Result<(), String> {
        let mut input = stream_args();
        let parsed = parse(&input)?.ok_or("missing stream request")?;
        assert!(parsed.sentinel.is_none());
        let stream = parsed
            .stream_sentinel
            .ok_or("missing whole-recording mode")?;
        let plan = fss_reference::ingest::long_sentinel::LongSentinelPlan::new(
            parsed.request.first_segment,
            parsed.request.segment_count,
            stream.config,
        )
        .map_err(|error| error.to_string())?;
        assert_eq!(
            plan.selected_segments(),
            std::collections::BTreeSet::from([0, 1, 2, 130, 131, 132])
        );
        let reservation = plan
            .reservation(&stream.limits)
            .map_err(|error| error.to_string())?;
        assert_eq!(reservation.inferences, 6);
        assert_eq!(
            reservation.execution_macs,
            6 * stream.limits.package.run.execution.max_macs
        );
        assert_eq!(
            reservation.output_bytes,
            6 * stream.limits.package.run.maximum_output_bytes as u64
        );
        let mode = input
            .iter()
            .position(|value| value == "--stream-sentinel")
            .ok_or("mode")?;
        input.drain(mode..mode + 2);
        assert!(parse(&input).is_err());
        assert!(parse(&args())?.ok_or("ordinary")?.stream_sentinel.is_none());
        Ok(())
    }

    #[test]
    fn whole_recording_ceiling_options_require_explicit_stream_mode() {
        for flags in [
            ["--stream-read-bytes", "1024"],
            ["--stream-pixel-budget", "1024"],
            ["--max-report-bytes", "1024"],
            ["--max-frame-pixels", "1024"],
            ["--stream-sentinel", "yes"],
            ["--stream-sentinel", "no"],
        ] {
            let mut input = args();
            input.extend(flags.map(OsString::from));
            assert!(parse(&input).is_err(), "{flags:?}");
        }
        for (key, value) in [
            ("--frames", "65537"),
            ("--sentinel-every-frames", "65537"),
            ("--sentinel-burst-frames", "9"),
            ("--sentinel-max-inferences", "65"),
            ("--sentinel-max-inferences", "2"),
        ] {
            let mut input = stream_args();
            replace(&mut input, key, value);
            assert!(parse(&input).is_err(), "{key}={value}");
        }
        for flags in [
            ["--stream-read-bytes", "536870913"],
            ["--stream-pixel-budget", "68719476737"],
            ["--max-report-bytes", "16777217"],
            ["--max-frame-pixels", "255"],
            ["--max-frame-pixels", "9437185"],
            ["--max-macs", "18446744073709551615"],
            ["--stream-sentinel", "yes"],
        ] {
            let mut input = stream_args();
            input.extend(flags.map(OsString::from));
            assert!(parse(&input).is_err(), "{flags:?}");
        }
    }

    #[test]
    fn explicit_stream_allowances_are_admitted_together_before_source_reads() -> Result<(), String>
    {
        let mut input = stream_args();
        input.extend(
            [
                "--stream-read-bytes",
                "1048576",
                "--stream-pixel-budget",
                "262144",
                "--max-report-bytes",
                "524288",
                "--max-frame-pixels",
                "512",
                "--max-macs",
                "2000",
                "--max-tensor-bytes",
                "1048576",
                "--retain",
                "yes",
            ]
            .map(OsString::from),
        );
        let parsed = parse(&input)?.ok_or("request")?;
        assert!(parsed.retain);
        let stream = parsed.stream_sentinel.ok_or("stream")?;
        let plan = fss_reference::ingest::long_sentinel::LongSentinelPlan::new(
            parsed.request.first_segment,
            parsed.request.segment_count,
            stream.config,
        )
        .map_err(|error| error.to_string())?;
        let reservation = plan
            .reservation(&stream.limits)
            .map_err(|error| error.to_string())?;
        assert_eq!(reservation.source_chunk_bytes, 1048576);
        assert_eq!(reservation.pixel_samples, 262144);
        assert_eq!(reservation.report_bytes, 524288);
        assert_eq!(reservation.execution_macs, 12000);
        assert_eq!(stream.limits.package.run.execution.max_bytes, 1048576);
        assert_eq!(stream.limits.package.jpeg.frame.maximum_pixels, 512);
        assert_eq!(stream.limits.package.h264.max_macroblocks, 2);
        assert_eq!(stream.limits.package.h265.max_luma_samples, 512);
        assert_eq!(stream.request(&parsed.request).segment_count, 170);
        Ok(())
    }

    #[test]
    fn stream_frame_ceiling_never_rounds_up_or_raises_native_defaults() -> Result<(), String> {
        let defaults = PackageDetectLimits::default();
        let original = parse(&stream_args())?
            .ok_or("stream request")?
            .stream_sentinel
            .ok_or("stream mode")?
            .limits;
        for (pixels, macroblocks) in [
            (256_u64, 1_u32),
            (257, 1),
            (511, 1),
            (512, 2),
            (9437184, 36864),
        ] {
            let mut input = stream_args();
            input.extend([
                OsString::from("--max-frame-pixels"),
                pixels.to_string().into(),
            ]);
            let limits = parse(&input)?
                .ok_or("stream request")?
                .stream_sentinel
                .ok_or("stream mode")?
                .limits;
            assert_eq!(
                limits.package.jpeg.frame.maximum_pixels,
                defaults.jpeg.frame.maximum_pixels.min(pixels as usize)
            );
            assert_eq!(limits.package.h264.max_macroblocks, macroblocks);
            assert_eq!(
                limits.package.h265.max_luma_samples,
                defaults.h265.max_luma_samples.min(pixels)
            );
            if pixels < 9437184 {
                assert_ne!(
                    limits.digest(),
                    original.digest(),
                    "retained recipe must bind codec ceilings"
                );
            } else {
                assert_eq!(limits.digest(), original.digest());
            }
        }
        Ok(())
    }
}

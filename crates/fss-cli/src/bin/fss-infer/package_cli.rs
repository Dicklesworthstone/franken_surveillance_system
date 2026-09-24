#![forbid(unsafe_code)]
//! `fss-infer package-detect`: retained recording -> verified RGB detector package -> report.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, PrincipalId};
use fss_reference::ingest::package_detect::{
    MAX_PACKAGE_DETECT_FRAMES, PackageDetectLimits, PackageDetectRequest, run_package_detection,
};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::rgb_package::{MAX_RGB_PACKAGE_BYTES, RgbDetectorPackage};
use fss_reference::{ExecBudget, KernelBackend, ReferenceDeployment, ReplayCx, ScalarExecCx};

use super::{RunResult, Values, digest, export, number, text, value};

const HELP: &str = "fss-infer package-detect [options]\n\
  --root DIR --site SITE --import-id sha256:HEX --first-segment N --frames N (1..64)\n\
  --package FILE --package-digest sha256:HEX --interpretation gray|ycbcr\n\
  [--minimum-score-ppm N] [--max-macs N] [--max-tensor-bytes N] [--report-out FILE] [--principal ID]\n\
  [--retain yes]\n\
  [--kernels optimized-cpu|scalar-reference]\n\
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
  The default threshold is the package's own; --minimum-score-ppm is an explicit override.\n\
  --kernels selects the executor: optimized-cpu (default; certified bit-identical to the\n\
  scalar reference) or scalar-reference (the slow oracle, seconds per 416x416 frame). The\n\
  choice is bound into the model digest recorded in the report.\n";

#[derive(Debug)]
struct Options {
    root: PathBuf,
    site: String,
    principal: String,
    package: PathBuf,
    package_digest: ContentDigest,
    kernels: KernelBackend,
    request: PackageDetectRequest,
    limits: PackageDetectLimits,
    report: Option<PathBuf>,
    retain: bool,
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
    ];
    let mut values = Values::new();
    for pair in args.chunks(2) {
        let key = pair[0].to_str().ok_or("option names require UTF-8")?;
        if !allowed.contains(&key) {
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
    if frames == 0
        || frames > MAX_PACKAGE_DETECT_FRAMES
        || first_segment.checked_add(frames).is_none()
    {
        return Err("frames must be 1..64 within the addressable range".into());
    }
    let kernels = if values.contains_key("--kernels") {
        match text(&values, "--kernels")? {
            "optimized-cpu" => KernelBackend::OptimizedCpuV1,
            "scalar-reference" => KernelBackend::ScalarReference,
            _ => return Err("kernels must be optimized-cpu or scalar-reference".into()),
        }
    } else {
        KernelBackend::OptimizedCpuV1
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
    Ok(Some(Options {
        root: PathBuf::from(value(&values, "--root")?),
        site,
        principal,
        package: PathBuf::from(value(&values, "--package")?),
        package_digest: digest(&values, "--package-digest")?,
        kernels,
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
    if !fs::symlink_metadata(&options.root)?.file_type().is_dir()
        || !fs::symlink_metadata(options.root.join("LAYOUT"))?
            .file_type()
            .is_file()
    {
        return Err(io::Error::other("existing non-symlink deployment required").into());
    }
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:package-detect-cli".into(),
        operation_id: OperationId::parse("operation:package-detect-cli")?,
        principal: options.principal,
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
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
        )?;
        let mut deployment = ReferenceDeployment::open(&options.root, &options.site, &cx)?;
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
}

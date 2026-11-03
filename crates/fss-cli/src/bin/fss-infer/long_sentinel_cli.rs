#![forbid(unsafe_code)]
//! Whole-recording motion-independent sampling and retained numerical replay.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, PrincipalId};
use fss_reference::ingest::long_sentinel::retained::{
    LongSentinelReplayLimits, LongSentinelRetentionError, rerun_long_sentinel_detection,
};
use fss_reference::ingest::long_sentinel::{
    LongSentinelConfig, LongSentinelLimits, LongSentinelPlan, LongSentinelRequest,
};
use fss_reference::ingest::package_detect::{PackageDetectLimits, PackageDetectRequest};
use fss_reference::ingest::rgb_package::MAX_RGB_PACKAGE_BYTES;
use fss_reference::{ExecBudget, ReferenceDeployment, ReplayCx, ScalarExecCx};

use super::{RunResult, Values, digest, export, number, text, value};

pub(super) const RUN_OPTIONS: &[&str] = &[
    "--stream-sentinel",
    "--stream-read-bytes",
    "--stream-pixel-budget",
    "--max-report-bytes",
    "--max-frame-pixels",
];

// The largest current native default is 4096*2304 coded luma samples. This operator
// option only narrows native capacities; it never raises an existing codec ceiling.
const MAX_FRAME_PIXELS: u64 = 4096 * 2304;

#[derive(Debug)]
pub(super) struct StreamOptions {
    pub config: LongSentinelConfig,
    pub limits: LongSentinelLimits,
}

impl StreamOptions {
    pub fn request(&self, source: &PackageDetectRequest) -> LongSentinelRequest {
        LongSentinelRequest {
            import_identity: source.import_identity,
            first_segment: source.first_segment,
            segment_count: source.segment_count,
            interpretation: source.interpretation,
            minimum_score_ppm: source.minimum_score_ppm,
        }
    }

    /// The analysis ceiling and separate bounded native child-custody checks share one owner.
    pub fn authority_bytes(&self) -> Result<u64, String> {
        authority_bytes(&self.limits, 64 * 1024 * 1024)
    }
}

fn authority_bytes(limits: &LongSentinelLimits, metadata: usize) -> Result<u64, String> {
    // Package retention independently revalidates at most 64 bounded children. Aggregate
    // retention/replay additionally verifies the complete retained import. These readers
    // keep their existing per-import contract; custody reads do not renew analysis,
    // inference, JPEG, or head allowances.
    let custody = limits
        .package
        .read
        .max_source_bytes
        .checked_add(limits.maximum_report_bytes as u64)
        .and_then(|bytes| bytes.checked_mul(64))
        .ok_or("sentinel custody reservation overflow")?;
    [
        limits.package.read.max_source_bytes,
        limits.maximum_source_chunk_bytes,
        limits.maximum_report_bytes as u64,
        MAX_RGB_PACKAGE_BYTES as u64,
        metadata as u64,
    ]
    .into_iter()
    .try_fold(custody, |sum, bytes| {
        sum.checked_add(bytes)
            .ok_or_else(|| "sentinel authority byte reservation overflow".to_owned())
    })
}

/// No new limit is silently applied to the original short-range commands.
pub(super) fn enabled(values: &Values) -> Result<bool, String> {
    match values.get("--stream-sentinel").map(|value| value.to_str()) {
        Some(Some("yes")) => Ok(true),
        Some(_) => Err("--stream-sentinel accepts only yes".into()),
        None if RUN_OPTIONS[1..].iter().any(|key| values.contains_key(*key)) => {
            Err("whole-recording limits require --stream-sentinel yes".into())
        }
        None => Ok(false),
    }
}

fn limits(values: &Values, mut package: PackageDetectLimits) -> Result<LongSentinelLimits, String> {
    if values.contains_key("--max-frame-pixels") {
        let pixels: u64 = number(values, "--max-frame-pixels", None)?;
        if !(256..=MAX_FRAME_PIXELS).contains(&pixels) {
            return Err(format!(
                "frame pixel ceiling must be 256..{MAX_FRAME_PIXELS}"
            ));
        }
        package.jpeg.frame.maximum_pixels = package.jpeg.frame.maximum_pixels.min(pixels as usize);
        // AVC reconstructs whole 16x16 macroblocks. Rounding upward would exceed the
        // explicit pixel ceiling, e.g. 257 pixels must still admit only one macroblock.
        package.h264.max_macroblocks = package.h264.max_macroblocks.min((pixels / 256) as u32);
        package.h265.max_luma_samples = package.h265.max_luma_samples.min(pixels);
    }
    let defaults = LongSentinelLimits::default();
    let limits = LongSentinelLimits {
        package,
        maximum_source_chunk_bytes: number(
            values,
            "--stream-read-bytes",
            Some(defaults.maximum_source_chunk_bytes),
        )?,
        maximum_pixel_samples: number(
            values,
            "--stream-pixel-budget",
            Some(defaults.maximum_pixel_samples),
        )?,
        maximum_report_bytes: number(
            values,
            "--max-report-bytes",
            Some(defaults.maximum_report_bytes),
        )?,
    };
    limits.validate().map_err(|error| error.to_string())?;
    Ok(limits)
}

pub(super) fn parse_run(
    values: &Values,
    first: usize,
    count: usize,
    package: PackageDetectLimits,
) -> Result<Option<StreamOptions>, String> {
    if !enabled(values)? {
        return Ok(None);
    }
    // Read required values explicitly, so a bare mode flag cannot silently choose a cadence.
    let _ = text(values, "--sentinel-every-frames")?;
    let _ = text(values, "--sentinel-max-inferences")?;
    let config = LongSentinelConfig {
        every_frames: number(values, "--sentinel-every-frames", None)?,
        burst_frames: number(values, "--sentinel-burst-frames", Some(3))?,
        max_inferences: number(values, "--sentinel-max-inferences", None)?,
    };
    let plan = LongSentinelPlan::new(first, count, config).map_err(|error| error.to_string())?;
    let limits = limits(values, package)?;
    // Checked aggregate preprocess/model/output reservation precedes any I/O or model load.
    plan.reservation(&limits)
        .map_err(|error| error.to_string())?;
    Ok(Some(StreamOptions { config, limits }))
}

const REPLAY_HELP: &str = "fss-infer sentinel-replay [options]\n\
  --root DIR --site SITE --report-digest sha256:HEX [--principal ID] [--report-out FILE]\n\
  Independent current ceilings: --stream-read-bytes N --stream-pixel-budget N\n\
    --max-report-bytes N --max-frame-pixels N --max-macs N --max-tensor-bytes N\n\
    --max-metadata-bytes N\n\
  Reopens one retained whole-recording sentinel aggregate and reruns its exact native\n\
  source range, sample schedule, package, threshold and saved execution backend. No loose\n\
  model or source file is accepted; there are no downloads or implicit replacement models.\n\
  Stored reservations must fit every current ceiling; a smaller allowance refuses instead\n\
  of changing the saved computation. Source/pixel/report defaults are 536870912 bytes,\n\
  1073741824 luma samples and 16777216 bytes. Metadata defaults to 67108864 bytes (maximum\n\
  134217728). Per-inference model MAC/tensor defaults are 8000000000 and 268435456 bytes.\n\
  --max-frame-pixels accepts 256..9437184 and only narrows native JPEG/AVC/HEVC ceilings.\n\
  AVC rounds down to whole 256-pixel macroblocks; omitted values preserve native defaults.\n\
  Video admission charges configured coded-luma capacity before each access unit, including\n\
  decode-ahead and skipped CRA leading pictures. This differs from actual returned raster\n\
  usage; the default video capacity is 9437184 samples per access unit. A current frame\n\
  ceiling must admit the saved recipe, and never changes its original execution settings.\n\
  Source-read limits govern analysis. Native retained-child custody verification keeps its\n\
  separate bounded source-read contract. The owner reserves both before opening stores.\n\
  On success stdout is the exact reproduced computation JSON, after digest comparison.\n\
  An optional report export must be a new file outside the existing deployment.\n\
  This opens the native deployment owner, which may finish existing restart recovery. It\n\
  creates no new detection/event publication, calibration, coverage, absence or alert authority.\n";

#[derive(Debug)]
struct ReplayOptions {
    root: PathBuf,
    site: String,
    principal: String,
    report_digest: ContentDigest,
    report: Option<PathBuf>,
    limits: LongSentinelReplayLimits,
}

fn parse_replay(args: &[OsString]) -> Result<Option<ReplayOptions>, String> {
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
    if args.len() > 24 || !args.len().is_multiple_of(2) {
        return Err("bounded option/value pairs required".into());
    }
    let mut values = Values::new();
    for pair in args.as_chunks::<2>().0 {
        let key = pair[0].to_str().ok_or("option names require UTF-8")?;
        if ![
            "--root",
            "--site",
            "--principal",
            "--report-digest",
            "--report-out",
            "--stream-read-bytes",
            "--stream-pixel-budget",
            "--max-report-bytes",
            "--max-frame-pixels",
            "--max-macs",
            "--max-tensor-bytes",
            "--max-metadata-bytes",
        ]
        .contains(&key)
        {
            return Err("unknown or inapplicable sentinel-replay option".into());
        }
        if pair[1].is_empty()
            || pair[1]
                .to_str()
                .is_some_and(|value| value.starts_with("--"))
        {
            return Err(format!("missing value for {key}"));
        }
        if values.insert(key.to_owned(), pair[1].clone()).is_some() {
            return Err(format!("duplicate {key}"));
        }
    }
    let site = text(&values, "--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| "invalid site lineage")?;
    let principal = if values.contains_key("--principal") {
        text(&values, "--principal")?
    } else {
        "principal:local-operator"
    }
    .to_owned();
    PrincipalId::parse(&principal).map_err(|_| "invalid principal ID")?;
    let mut package = PackageDetectLimits::default();
    let maximum_tensor_bytes = number(
        &values,
        "--max-tensor-bytes",
        Some(package.run.execution.max_bytes),
    )?;
    if !(1..=256 * 1024 * 1024).contains(&maximum_tensor_bytes) {
        return Err("tensor ceiling must be 1..268435456 bytes".into());
    }
    package.run.execution = ExecBudget::new(
        number(&values, "--max-macs", Some(package.run.execution.max_macs))?,
        maximum_tensor_bytes,
    );
    let maximum_metadata_bytes = number(&values, "--max-metadata-bytes", Some(64 * 1024 * 1024))?;
    if !(1..=128 * 1024 * 1024).contains(&maximum_metadata_bytes) {
        return Err("metadata ceiling must be 1..134217728 bytes".into());
    }
    let execution = limits(&values, package)?;
    let limits = LongSentinelReplayLimits {
        execution,
        maximum_metadata_bytes,
    };
    limits.validate().map_err(|error| error.to_string())?;
    authority_bytes(&limits.execution, maximum_metadata_bytes)?;
    Ok(Some(ReplayOptions {
        root: PathBuf::from(value(&values, "--root")?),
        site,
        principal,
        report_digest: digest(&values, "--report-digest")?,
        report: values.get("--report-out").map(PathBuf::from),
        limits,
    }))
}

fn replay(options: ReplayOptions, out: &mut impl Write) -> RunResult<()> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:long-sentinel-replay".into(),
        operation_id: OperationId::parse("operation:long-sentinel-replay")?,
        principal: options.principal,
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(authority_bytes(
                &options.limits.execution,
                options.limits.maximum_metadata_bytes,
            )?)
            .build()?,
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
        let deployment = ReferenceDeployment::open(&options.root, &options.site, &cx)?;
        let report = rerun_long_sentinel_detection(
            &deployment,
            options.report_digest,
            &options.limits,
            &cx,
            &scalar,
        )?;
        if report.digest() != options.report_digest {
            return Err(io::Error::other("retained sentinel replay identity mismatch").into());
        }
        if let Some(path) = &options.report {
            export(path, report.json().as_bytes(), &options.root, &cx)?;
        }
        cx.checkpoint("long_sentinel:cli_replay_release")?;
        out.write_all(report.json().as_bytes())?;
        Ok(())
    })();
    scalar.drain_and_finalize();
    cx.drain_and_finalize();
    result
}

pub(super) fn dispatch(args: &[OsString], out: &mut impl Write) -> Option<ExitCode> {
    if args.first().and_then(|value| value.to_str()) != Some("sentinel-replay") {
        return None;
    }
    Some(match parse_replay(&args[1..]) {
        Ok(None) => {
            if out.write_all(REPLAY_HELP.as_bytes()).is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(fss_cli::ExitIdentity::RUNTIME_FAILURE.code)
            }
        }
        Ok(Some(options)) => match replay(options, out) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                let id = error
                    .downcast_ref::<LongSentinelRetentionError>()
                    .map_or(fss_cli::ERR_CLI_RUNTIME_FAILURE, |error| error.stable_id());
                eprintln!("{id}: {error}");
                ExitCode::from(fss_cli::ExitIdentity::RUNTIME_FAILURE.code)
            }
        },
        Err(reason) => {
            eprintln!(
                "{}: {reason}; use fss-infer sentinel-replay --help",
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
            "/missing/retained-sentinel",
            "--site",
            "site:sentinel-replay",
            "--report-digest",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        ]
        .map(OsString::from)
        .to_vec()
    }

    #[test]
    fn replay_requires_exact_retained_identity_and_refuses_computation_overrides() {
        assert!(matches!(parse_replay(&args()), Ok(Some(_))));
        for key in ["--root", "--site", "--report-digest"] {
            let mut input = args();
            let index = input
                .iter()
                .position(|value| value == key)
                .expect("fixture option");
            input.drain(index..index + 2);
            assert!(parse_replay(&input).is_err(), "{key}");
        }
        for flags in [
            ["--site", "site:other"],
            ["--package", "replacement.fmpk"],
            ["--import-id", "sha256:replacement"],
            ["--first-segment", "0"],
            ["--frames", "3"],
            ["--kernels", "scalar-reference"],
            ["--sentinel-every-frames", "8"],
            ["--minimum-score-ppm", "0"],
            ["--stream-read-bytes", "536870913"],
            ["--stream-pixel-budget", "68719476737"],
            ["--max-report-bytes", "16777217"],
            ["--max-tensor-bytes", "0"],
            ["--max-tensor-bytes", "268435457"],
            ["--max-metadata-bytes", "0"],
            ["--max-metadata-bytes", "134217729"],
            ["--max-frame-pixels", "255"],
            ["--max-frame-pixels", "9437185"],
        ] {
            let mut input = args();
            input.extend(flags.map(OsString::from));
            assert!(parse_replay(&input).is_err(), "{flags:?}");
        }
        let mut missing = args();
        missing.push("--max-macs".into());
        assert!(parse_replay(&missing).is_err());
        assert!(matches!(parse_replay(&["--help".into()]), Ok(None)));
        assert!(parse_replay(&["--help".into(), "x".into()]).is_err());
    }

    #[test]
    fn replay_accepts_independent_current_limits_before_any_store_access() -> Result<(), String> {
        let defaults = parse_replay(&args())?.ok_or("replay request")?;
        assert_eq!(
            defaults.limits.execution.digest(),
            LongSentinelLimits::default().digest()
        );
        assert_eq!(defaults.limits.maximum_metadata_bytes, 64 * 1024 * 1024);
        let mut input = args();
        input.extend(
            [
                "--stream-read-bytes",
                "1048576",
                "--stream-pixel-budget",
                "262144",
                "--max-report-bytes",
                "524288",
                "--max-macs",
                "2000",
                "--max-tensor-bytes",
                "1048576",
                "--max-metadata-bytes",
                "2097152",
                "--max-frame-pixels",
                "511",
            ]
            .map(OsString::from),
        );
        let limits = parse_replay(&input)?.ok_or("replay request")?.limits;
        assert_eq!(limits.execution.maximum_source_chunk_bytes, 1048576);
        assert_eq!(limits.execution.maximum_pixel_samples, 262144);
        assert_eq!(limits.execution.maximum_report_bytes, 524288);
        assert_eq!(limits.execution.package.run.execution.max_macs, 2000);
        assert_eq!(limits.execution.package.run.execution.max_bytes, 1048576);
        assert_eq!(limits.execution.package.jpeg.frame.maximum_pixels, 511);
        assert_eq!(limits.execution.package.h264.max_macroblocks, 1);
        assert_eq!(limits.execution.package.h265.max_luma_samples, 511);
        assert_eq!(limits.maximum_metadata_bytes, 2097152);
        assert!(
            authority_bytes(&limits.execution, limits.maximum_metadata_bytes)?
                > limits.execution.maximum_source_chunk_bytes
        );
        Ok(())
    }
}

#![forbid(unsafe_code)]
//! `fss-event health optical`: read-only Stage-1 optical quality screening (Laplacian blur
//! variance and localized highlight glare) over a retained MJPEG, H.264, or H.265 recording.
//!
//! Applies the sensor's current retained privacy mask before screening, writes nothing to the
//! deployment, and never certifies camera health, tamper, physical absence, or effect authority.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, DigestAlgorithm, OperationId, PrincipalId};
use fss_reference::ingest::RetainedFileImport;
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{
    MAX_WATCH_FRAMES, WatchDetectorConfig, WatchLimits, WatchPlan, WatchTrackerConfig, WatchZone,
};
use fss_reference::ingest::sensor_health::OpticalThresholds;
use fss_reference::ingest::sensor_health::retained::ScreeningReport;
use fss_reference::{ReferenceDeployment, ReplayCx};

type Run<T> = Result<T, Box<dyn Error>>;

const MAX_SAMPLES_DEFAULT: u64 = 64 * 1024 * 1024;
const MAX_SAMPLES_CEILING: u64 = 1_073_741_824;

const HELP: &str = "fss-event health optical --root EXISTING_DIR --site SITE\n\
  --import-id sha256:IMPORT --interpretation gray|ycbcr\n\
  [--first-segment N] [--segment-count M (1..128)] [--principal ID]\n\
  [--min-laplacian-variance-x1000 N] [--glare-luma-min N (0..255)]\n\
  [--max-glare-ppm N (0..1000000)] [--max-samples N] [--report-out FILE]\n\
Screens privacy-masked retained luma frames for severe defocus blur (exact integer 4-neighbor\n\
Laplacian variance) and localized highlight glare saturation. Emits bounded diagnostic JSON\n\
with zero raw pixels; never certifies health, tamper, absence, or effect authority.\n";

const OPTIONS: &[&str] = &[
    "--root",
    "--site",
    "--principal",
    "--import-id",
    "--interpretation",
    "--first-segment",
    "--segment-count",
    "--min-laplacian-variance-x1000",
    "--glare-luma-min",
    "--max-glare-ppm",
    "--max-samples",
    "--report-out",
];

#[derive(Debug, Eq, PartialEq)]
struct OpticalOptions {
    root: PathBuf,
    site: String,
    principal: String,
    import_id: ContentDigest,
    interpretation: ComponentInterpretation,
    first_segment: usize,
    segment_count: Option<usize>,
    thresholds: OpticalThresholds,
    max_samples: u64,
    report_out: Option<PathBuf>,
}

fn req_text<'a>(values: &'a BTreeMap<String, OsString>, key: &str) -> Result<&'a str, String> {
    values
        .get(key)
        .ok_or_else(|| format!("required option {key}"))?
        .to_str()
        .ok_or_else(|| format!("{key} requires UTF-8"))
}

fn opt_u64(
    values: &BTreeMap<String, OsString>,
    key: &str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, String> {
    let val = if values.contains_key(key) {
        let raw = req_text(values, key)?;
        if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("{key} requires unsigned decimal"));
        }
        raw.parse::<u64>()
            .map_err(|_| format!("{key} integer overflow"))?
    } else {
        default
    };
    if val < min || val > max {
        return Err(format!("{key} outside bounds {min}..={max}"));
    }
    Ok(val)
}

fn parse(args: &[OsString]) -> Result<OpticalOptions, String> {
    if args.len() > 25 || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096) {
        return Err("argument bounds exceeded".into());
    }
    if args.first().and_then(|arg| arg.to_str()) != Some("optical") {
        return Err("expected health optical".into());
    }
    let mut values = BTreeMap::new();
    for pair in args[1..].chunks(2) {
        let key = pair[0].to_str().ok_or("option names require UTF-8")?;
        if !OPTIONS.contains(&key) {
            return Err(format!("unknown option {key}"));
        }
        let value = pair
            .get(1)
            .filter(|v| !v.is_empty() && !v.to_str().is_some_and(|s| s.starts_with("--")))
            .ok_or_else(|| format!("missing value for {key}"))?;
        if values.insert(key.to_owned(), value.clone()).is_some() {
            return Err(format!("duplicate {key}"));
        }
    }
    let root = PathBuf::from(values.get("--root").ok_or("required option --root")?);
    if !root.is_absolute() {
        return Err("--root must be absolute".into());
    }
    let site = req_text(&values, "--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| "invalid site lineage")?;
    let principal = values
        .get("--principal")
        .map_or(Ok("principal:local-operator"), |v| {
            v.to_str().ok_or("--principal requires UTF-8")
        })?
        .to_owned();
    if site.len() > 256 || principal.len() > 128 {
        return Err("site or principal exceeds bound".into());
    }
    PrincipalId::parse(&principal).map_err(|_| "invalid principal ID")?;

    let import_id =
        ContentDigest::parse(req_text(&values, "--import-id")?).map_err(|_| "invalid import ID")?;
    if import_id.algorithm() != DigestAlgorithm::Sha256 || import_id.bytes() == [0; 32] {
        return Err("--import-id requires nonzero SHA-256".into());
    }
    let interpretation = match req_text(&values, "--interpretation")? {
        "gray" => ComponentInterpretation::Grayscale,
        "ycbcr" => ComponentInterpretation::YCbCr,
        _ => return Err("--interpretation must be gray or ycbcr".into()),
    };
    let first_segment = opt_u64(&values, "--first-segment", 0, 0, u64::MAX)? as usize;
    let segment_count = if values.contains_key("--segment-count") {
        Some(opt_u64(&values, "--segment-count", 1, 1, MAX_WATCH_FRAMES as u64)? as usize)
    } else {
        None
    };

    let defaults = OpticalThresholds::default();
    let thresholds = OpticalThresholds {
        min_laplacian_variance_x1000: opt_u64(
            &values,
            "--min-laplacian-variance-x1000",
            defaults.min_laplacian_variance_x1000,
            0,
            u64::MAX,
        )?,
        glare_luma_min: opt_u64(
            &values,
            "--glare-luma-min",
            u64::from(defaults.glare_luma_min),
            0,
            255,
        )? as u8,
        max_glare_ppm: opt_u64(
            &values,
            "--max-glare-ppm",
            u64::from(defaults.max_glare_ppm),
            0,
            1_000_000,
        )? as u32,
    };
    let max_samples = opt_u64(
        &values,
        "--max-samples",
        MAX_SAMPLES_DEFAULT,
        1,
        MAX_SAMPLES_CEILING,
    )?;

    Ok(OpticalOptions {
        root,
        site,
        principal,
        import_id,
        interpretation,
        first_segment,
        segment_count,
        thresholds,
        max_samples,
        report_out: values.get("--report-out").map(PathBuf::from),
    })
}

fn run(options: OpticalOptions) -> Run<String> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:optical-health-cli".into(),
        operation_id: OperationId::parse("operation:optical-health-cli")?,
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
    let root = super::super::replay::preflight(&options.root, &options.site, &authority)?;
    let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
    let result = (|| -> Run<String> {
        let deployment = ReferenceDeployment::open(&root, &options.site, &cx)?;
        let limits = WatchLimits::default();
        let retained =
            RetainedFileImport::open(&deployment, options.import_id, limits.read_limits, &cx)?;
        let available = retained
            .manifest()
            .segment_spans
            .len()
            .saturating_sub(options.first_segment);
        let segment_count = options
            .segment_count
            .unwrap_or_else(|| available.min(MAX_WATCH_FRAMES));
        if segment_count == 0 {
            return Err("no segments available in requested range".into());
        }
        let plan = WatchPlan {
            import_identity: options.import_id,
            interpretation: options.interpretation,
            first_segment: options.first_segment,
            segment_count,
            zones: vec![WatchZone {
                zone_id: "optical_screen".to_owned(),
                x: 0,
                y: 0,
                width: 1,
                height: 1,
            }],
            detector: WatchDetectorConfig::default(),
            tracker: WatchTrackerConfig::default(),
        };
        let report = ScreeningReport::analyze_with_optical(
            &deployment,
            &plan,
            &limits,
            options.max_samples,
            Some(options.thresholds),
            &cx,
        )?;
        let output = format!("{}\n", report.to_optical_json());
        if let Some(path) = &options.report_out {
            super::super::export(path, output.as_bytes(), &root, &cx)?;
        }
        Ok(output)
    })();
    cx.drain_and_finalize();
    result
}

pub(super) fn main(args: &[OsString]) -> ExitCode {
    if args.len() == 2 && ["help", "--help", "-h"].iter().any(|arg| args[1] == *arg) {
        return match super::super::replay::emit(&mut io::stdout().lock(), HELP.as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(1),
        };
    }
    let options = match parse(args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: {error}; use fss-event health optical --help");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    match run(options).and_then(|output| {
        super::super::replay::emit(&mut io::stdout().lock(), output.as_bytes())?;
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
mod tests {
    use super::*;
    use fss_core::{SensorId, StreamId, TimestampNs};
    use fss_reference::ingest::{FileIngestAdapter, FileIngestRequest};
    use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
    use std::fs;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Run<Self> {
            for attempt in 0..100_u32 {
                let path = std::env::temp_dir().join(format!(
                    "fss-health-optical-cli-{tag}-{}-{attempt}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Ok(Self(path)),
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Err(io::Error::other("temp dir capacity").into())
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn optical_cli_screens_retained_mjpeg_and_reports_blur_and_glare() -> Run<()> {
        let dir = TempDir::new("e2e")?;
        let root = dir.0.join("deployment");
        let w = 64_u32;
        let h = 48_u32;
        let cfg = JpegConfig {
            quality: 95,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        };
        let mut sharp = vec![0_u8; (w * h) as usize];
        for y in 0..h {
            for x in 0..w {
                sharp[(y * w + x) as usize] = if ((x / 4) + (y / 4)) % 2 == 0 {
                    200
                } else {
                    40
                };
            }
        }
        let blurred = vec![120_u8; (w * h) as usize];
        let mut glared = sharp.clone();
        for y in 0..(h / 4) {
            for x in 0..w {
                glared[(y * w + x) as usize] = 255;
            }
        }
        let mut bytes = Vec::new();
        for frame in [&sharp, &blurred, &glared] {
            bytes.extend(encode_jpeg(w, h, frame, &cfg)?);
        }
        let path = dir.0.join("sample.mjpeg");
        fs::write(&path, &bytes)?;

        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:optical-cli-test".into(),
            operation_id: OperationId::parse("operation:optical-cli-test")?,
            principal: "principal:test".into(),
            capabilities: vec!["ADP-REPLAY-001".into()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(64 * 1024 * 1024)
                .storage_operations(4096)
                .build()?,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"site:optical-cli"),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        let mut deployment = ReferenceDeployment::open(&root, "site:optical-cli", &cx)?;
        let import_id = FileIngestAdapter::ingest(
            FileIngestRequest::new(
                path,
                SensorId::parse("sensor:optical-cli")?,
                StreamId::parse("stream:main")?,
            )
            .with_receive_time(TimestampNs(1_000_000_000)),
            &cx,
            &mut deployment,
        )?
        .import_identity;
        drop(deployment);
        cx.drain_and_finalize();

        let argv: Vec<OsString> = vec![
            "optical".into(),
            "--root".into(),
            root.as_os_str().to_owned(),
            "--site".into(),
            "site:optical-cli".into(),
            "--import-id".into(),
            import_id.to_text().into(),
            "--interpretation".into(),
            "gray".into(),
        ];
        let options = parse(&argv).map_err(|e| format!("parse failed: {e}"))?;
        let json = run(options)?;
        assert!(json.contains("\"severe_blur\""), "{json}");
        assert!(json.contains("\"localized_highlight_glare\""), "{json}");
        assert!(json.contains("\"optical_admitted\":false"), "{json}");
        assert!(json.contains("\"health_certified\":false"), "{json}");
        assert!(json.contains("\"effect_authority\":false"), "{json}");
        Ok(())
    }

    #[test]
    fn optical_cli_rejects_out_of_range_thresholds_and_relative_root() {
        let valid_digest = ContentDigest::sha256(b"import").to_text();
        let bad_ppm: Vec<OsString> = vec![
            "optical".into(),
            "--root".into(),
            "/tmp/fake-deployment".into(),
            "--site".into(),
            "site:test".into(),
            "--import-id".into(),
            valid_digest.clone().into(),
            "--interpretation".into(),
            "gray".into(),
            "--max-glare-ppm".into(),
            "1000001".into(),
        ];
        assert!(parse(&bad_ppm).is_err());

        let relative_root: Vec<OsString> = vec![
            "optical".into(),
            "--root".into(),
            "relative/path".into(),
            "--site".into(),
            "site:test".into(),
            "--import-id".into(),
            valid_digest.into(),
            "--interpretation".into(),
            "gray".into(),
        ];
        assert!(parse(&relative_root).is_err());
    }
}

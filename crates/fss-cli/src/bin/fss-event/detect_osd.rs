#![forbid(unsafe_code)]
//! `fss-event detect-osd`: read-only corner/edge OSD timestamp candidate proposals.
//!
//! Inspects a retained MJPEG, H.264, or H.265 clip through [`ImmutableRetainedSource`] (never
//! acquiring a writer lock or modifying custody) and prints a deterministic
//! `fss.osd_candidate_report.v1` JSON document containing candidate `--ignore-rect X,Y,W,H`
//! proposals and their canonical provenance digest. Proposed rectangles are NEVER activated
//! automatically; an operator must review and pass them explicitly to `fss-event watch`.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, DigestAlgorithm, OperationId, PrincipalId};
use fss_reference::ReplayCx;
use fss_reference::ingest::RetainedFileImport;
use fss_reference::ingest::osd_mask::{
    MAX_OSD_DETECT_FRAMES, MIN_OSD_DETECT_FRAMES, OsdDetectConfig, OsdDetectLimits,
    OsdDetectRequest, OsdMaskError, detect_osd_candidates,
};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::retained_source::{
    ImmutableRetainedReadLimits, ImmutableRetainedSource, RetainedSource,
};

type Run<T> = Result<T, Box<dyn Error>>;

const MAX_REPORT_BYTES: usize = 1024 * 1024;
const HELP: &str = "fss-event detect-osd --root EXISTING_DIR --site SITE --import-id sha256:HEX\n\
  --interpretation gray|ycbcr [--principal ID] [--first-segment N] [--segment-count M (4..128)]\n\
  [--pixel-delta N] [--min-transitions N] [--min-active-pixels N]\n\
  [--max-candidate-area-ppm N] [--edge-margin-ppm N] [--min-border-quiet-ppm N]\n\
  [--merge-gap-x N] [--merge-gap-y N] [--padding N]\n\
  [--work-units N] [--max-dimension N] [--max-pixels N] [--max-segment-bytes N]\n\
  [--max-read-bytes N] [--max-read-objects N] [--report-out FILE]\n\
\n\
  Read-only detector for small corner/edge OSD overlays (such as ticking HH:MM:SS camera\n\
  timestamps) over a retained MJPEG, H.264, or H.265 import. Opens immutable custody without\n\
  acquiring a writer lock or modifying deployment state, applies any current privacy mask\n\
  before pixel inspection, and prints a deterministic fss.osd_candidate_report.v1 JSON proposal\n\
  containing candidate --ignore-rect X,Y,W,H arguments and provenance digests.\n\
\n\
  Proposals are NEVER activated automatically. Review the suggested rectangles and pass them\n\
  explicitly as --ignore-rect X,Y,W,H to `fss-event watch`. OSD ignore regions exclude only\n\
  foreground motion triggers while keeping original pixels untouched in custody; they are\n\
  strictly distinct from privacy masks.\n";

const OPTIONS: &[&str] = &[
    "--root",
    "--site",
    "--principal",
    "--import-id",
    "--interpretation",
    "--first-segment",
    "--segment-count",
    "--pixel-delta",
    "--min-transitions",
    "--min-active-pixels",
    "--max-candidate-area-ppm",
    "--edge-margin-ppm",
    "--min-border-quiet-ppm",
    "--merge-gap-x",
    "--merge-gap-y",
    "--padding",
    "--work-units",
    "--max-dimension",
    "--max-pixels",
    "--max-segment-bytes",
    "--max-read-bytes",
    "--max-read-objects",
    "--report-out",
];

#[derive(Debug)]
struct Options {
    root: PathBuf,
    site: String,
    principal: String,
    import_identity: ContentDigest,
    interpretation: ComponentInterpretation,
    first_segment: usize,
    segment_count: Option<usize>,
    config: OsdDetectConfig,
    limits: OsdDetectLimits,
    read_limits: ImmutableRetainedReadLimits,
    report_out: Option<PathBuf>,
}

fn text<'a>(values: &'a BTreeMap<String, OsString>, key: &str) -> Result<&'a str, String> {
    values
        .get(key)
        .ok_or_else(|| format!("required option {key}"))?
        .to_str()
        .ok_or_else(|| format!("{key} requires UTF-8"))
}

fn optional_number<T: std::str::FromStr>(
    values: &BTreeMap<String, OsString>,
    key: &str,
    default: T,
) -> Result<T, String> {
    if !values.contains_key(key) {
        return Ok(default);
    }
    text(values, key)?
        .parse()
        .map_err(|_| format!("invalid numeric value for {key}"))
}

fn digest(values: &BTreeMap<String, OsString>, key: &str) -> Result<ContentDigest, String> {
    let parsed = ContentDigest::parse(text(values, key)?)
        .map_err(|_| format!("invalid digest for {key}"))?;
    if parsed.algorithm() != DigestAlgorithm::Sha256 {
        return Err(format!("{key} requires SHA-256"));
    }
    Ok(parsed)
}

fn parse(args: &[OsString]) -> Result<Option<Options>, String> {
    if args.is_empty() {
        return Ok(None);
    }
    if matches!(args[0].to_str(), Some("help" | "--help" | "-h")) {
        return if args.len() == 1 {
            Ok(None)
        } else {
            Err("help takes no other arguments".to_owned())
        };
    }
    let mut values: BTreeMap<String, OsString> = BTreeMap::new();
    for pair in args.chunks(2) {
        let key = pair[0].to_str().ok_or("option names require UTF-8")?;
        if !OPTIONS.contains(&key) {
            return Err(format!("unknown or inapplicable detect-osd option {key}"));
        }
        if values.contains_key(key) {
            return Err(format!("duplicate {key}"));
        }
        let argument = pair
            .get(1)
            .ok_or_else(|| format!("missing value for {key}"))?;
        if argument.is_empty() || argument.to_str().is_some_and(|s| s.starts_with("--")) {
            return Err(format!("missing value for {key}"));
        }
        values.insert(key.to_owned(), argument.clone());
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
        _ => return Err("interpretation must be explicitly gray or ycbcr".to_owned()),
    };
    let first_segment: usize = optional_number(&values, "--first-segment", 0)?;
    let segment_count = if values.contains_key("--segment-count") {
        let count: usize = optional_number(&values, "--segment-count", 0)?;
        if !(MIN_OSD_DETECT_FRAMES..=MAX_OSD_DETECT_FRAMES).contains(&count) {
            return Err(format!(
                "segment count must be {MIN_OSD_DETECT_FRAMES}..{MAX_OSD_DETECT_FRAMES}"
            ));
        }
        if first_segment.checked_add(count).is_none() {
            return Err("segment range overflows".to_owned());
        }
        Some(count)
    } else {
        None
    };
    let defaults = OsdDetectConfig::default();
    let config = OsdDetectConfig {
        pixel_delta_threshold: optional_number(
            &values,
            "--pixel-delta",
            defaults.pixel_delta_threshold,
        )?,
        min_transitions: optional_number(&values, "--min-transitions", defaults.min_transitions)?,
        min_active_pixels: optional_number(
            &values,
            "--min-active-pixels",
            defaults.min_active_pixels,
        )?,
        max_candidate_area_ppm: optional_number(
            &values,
            "--max-candidate-area-ppm",
            defaults.max_candidate_area_ppm,
        )?,
        edge_margin_ppm: optional_number(&values, "--edge-margin-ppm", defaults.edge_margin_ppm)?,
        min_border_quiet_ppm: optional_number(
            &values,
            "--min-border-quiet-ppm",
            defaults.min_border_quiet_ppm,
        )?,
        merge_gap_x: optional_number(&values, "--merge-gap-x", defaults.merge_gap_x)?,
        merge_gap_y: optional_number(&values, "--merge-gap-y", defaults.merge_gap_y)?,
        padding_px: optional_number(&values, "--padding", defaults.padding_px)?,
    };
    config.validate().map_err(|error| error.to_string())?;

    let mut limits = OsdDetectLimits::default();
    limits.read_limits.max_segment_bytes = optional_number(
        &values,
        "--max-segment-bytes",
        limits.read_limits.max_segment_bytes,
    )?;
    let dimension: u32 = optional_number(&values, "--max-dimension", 4096)?;
    let pixels: usize = optional_number(&values, "--max-pixels", 4_194_304)?;
    if !(16..=4096).contains(&dimension) || pixels == 0 || pixels > 4_194_304 {
        return Err("codec limits: dimension 16..4096, pixels 1..4194304".to_owned());
    }
    limits.jpeg_limits.maximum_dimension = dimension;
    limits.jpeg_limits.maximum_pixels = pixels;
    limits.jpeg_work_units = optional_number(
        &values,
        "--work-units",
        limits.jpeg_limits.luma_work_bound(),
    )?;
    limits.h264_limits.max_width = dimension;
    limits.h264_limits.max_height = dimension;
    limits.h264_limits.max_macroblocks =
        u32::try_from((pixels / 256).max(1)).map_err(|_| "pixel ceiling")?;
    limits.h265_limits.max_width = dimension;
    limits.h265_limits.max_height = dimension;
    limits.h265_limits.max_luma_samples = pixels as u64;
    let read_limits = super::retained_read::parse_limits(&values)?;
    let root = values
        .get("--root")
        .ok_or("required option --root")?
        .clone();
    Ok(Some(Options {
        root: PathBuf::from(root),
        site,
        principal,
        import_identity: digest(&values, "--import-id")?,
        interpretation,
        first_segment,
        segment_count,
        config,
        limits,
        read_limits,
        report_out: values.get("--report-out").map(PathBuf::from),
    }))
}

fn resolve_segment_count(
    options: &Options,
    source: &dyn RetainedSource,
    cx: &ReplayCx,
) -> Run<usize> {
    if let Some(count) = options.segment_count {
        return Ok(count);
    }
    let retained = RetainedFileImport::open(
        source,
        options.import_identity,
        options.limits.read_limits,
        cx,
    )
    .map_err(OsdMaskError::from)?;
    let available = retained
        .manifest()
        .segment_spans
        .len()
        .checked_sub(options.first_segment)
        .filter(|count| *count >= MIN_OSD_DETECT_FRAMES)
        .ok_or(OsdMaskError::InvalidRequest(
            "at least four segments are required after --first-segment",
        ))?;
    if available > MAX_OSD_DETECT_FRAMES {
        return Err(OsdMaskError::InvalidRequest(
            "recording has more than 128 segments after --first-segment; pass --segment-count",
        )
        .into());
    }
    Ok(available)
}

fn run(options: &Options, out: &mut impl Write) -> Run<()> {
    if !fs::symlink_metadata(&options.root)?.file_type().is_dir()
        || !fs::symlink_metadata(options.root.join("LAYOUT"))?
            .file_type()
            .is_file()
    {
        return Err(io::Error::other("existing non-symlink deployment required").into());
    }
    let root = fs::canonicalize(&options.root)?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:detect-osd-cli".into(),
        operation_id: OperationId::parse("operation:detect-osd-cli")?,
        principal: options.principal.clone(),
        capabilities: vec!["ADP-REPLAY-001".into(), "CAP-READ-MEDIA-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(options.read_limits.max_read_bytes as u64)
            .storage_operations(options.read_limits.max_read_objects as u64)
            .build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    let cx = ReplayCx::from_context_authority_read_only(&authority, root.clone())?;
    let started = Instant::now();
    let cancelled = || started.elapsed() >= super::retained_read::DEADLINE;
    let result = run_with(options, &root, &cx, &cancelled, out);
    cx.drain_and_finalize();
    result
}

fn run_with(
    options: &Options,
    root: &Path,
    cx: &ReplayCx,
    cancelled: &(dyn Fn() -> bool + Sync),
    out: &mut impl Write,
) -> Run<()> {
    let source =
        ImmutableRetainedSource::open_cancellable(root, options.read_limits, cx, cancelled)?;
    if source.site_lineage() != options.site {
        return Err(
            OsdMaskError::InvalidRequest("retained deployment site lineage mismatch").into(),
        );
    }
    let segment_count = resolve_segment_count(options, &source, cx)?;
    let request = OsdDetectRequest {
        import_identity: options.import_identity,
        interpretation: options.interpretation,
        first_segment: options.first_segment,
        segment_count,
        config: options.config,
    };
    let report = detect_osd_candidates(&source, &request, &options.limits, cx)?;
    let json = format!("{}\n", report.to_json());
    if json.len() > MAX_REPORT_BYTES {
        return Err(OsdMaskError::Limit.into());
    }
    cx.checkpoint("detect_osd:delivery")?;
    source.revalidate_snapshot_metadata()?;
    source.revalidate()?;
    if let Some(path) = &options.report_out {
        super::export(path, json.as_bytes(), root, cx)?;
    }
    out.write_all(json.as_bytes())?;
    Ok(())
}

pub(super) fn main(args: &[OsString]) -> ExitCode {
    match parse(args) {
        Ok(None) => ExitCode::from(if io::stdout().lock().write_all(HELP.as_bytes()).is_ok() {
            ExitIdentity::SUCCESS.code
        } else {
            ExitIdentity::RUNTIME_FAILURE.code
        }),
        Ok(Some(options)) => match run(&options, &mut io::stdout().lock()) {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(error) => {
                eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}");
                if let Some(refusal) = error.downcast_ref::<OsdMaskError>() {
                    eprintln!("refusal_id={}", refusal.stable_id());
                }
                ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
            }
        },
        Err(reason) => {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: {reason}; use fss-event detect-osd --help");
            ExitCode::from(ExitIdentity::MALFORMED_VALUE.code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> Vec<OsString> {
        [
            "--root",
            "unused",
            "--site",
            "site:detect-osd",
            "--import-id",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "--interpretation",
            "ycbcr",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    #[test]
    fn parses_defaults_dynamic_work_bound_and_explicit_overrides() -> Result<(), String> {
        assert!(parse(&[])?.is_none());
        assert!(parse(&[OsString::from("--help")])?.is_none());
        assert!(parse(&[OsString::from("--help"), OsString::from("extra")]).is_err());

        let parsed = parse(&base_args())?.ok_or("options")?;
        assert_eq!(parsed.first_segment, 0);
        assert_eq!(parsed.segment_count, None);
        assert_eq!(
            parsed.limits.jpeg_work_units,
            parsed.limits.jpeg_limits.luma_work_bound()
        );
        assert!(parsed.limits.jpeg_work_units > 800_000_000);

        let mut custom = base_args();
        custom.extend(
            [
                "--first-segment",
                "2",
                "--segment-count",
                "12",
                "--pixel-delta",
                "30",
                "--min-transitions",
                "4",
                "--padding",
                "4",
                "--max-dimension",
                "640",
                "--max-pixels",
                "230400",
            ]
            .map(OsString::from),
        );
        let custom_parsed = parse(&custom)?.ok_or("custom options")?;
        assert_eq!(custom_parsed.first_segment, 2);
        assert_eq!(custom_parsed.segment_count, Some(12));
        assert_eq!(custom_parsed.config.pixel_delta_threshold, 30);
        assert_eq!(custom_parsed.config.min_transitions, 4);
        assert_eq!(custom_parsed.config.padding_px, 4);
        assert_eq!(
            custom_parsed.limits.jpeg_work_units,
            custom_parsed.limits.jpeg_limits.luma_work_bound()
        );
        assert!(custom_parsed.limits.jpeg_work_units < parsed.limits.jpeg_work_units);

        // Explicit tiny --work-units is respected verbatim.
        let mut tiny = base_args();
        tiny.extend(["--work-units", "512"].map(OsString::from));
        let tiny_parsed = parse(&tiny)?.ok_or("tiny options")?;
        assert_eq!(tiny_parsed.limits.jpeg_work_units, 512);
        Ok(())
    }

    #[test]
    fn refuses_out_of_bound_and_unknown_options() {
        for bad in [
            vec!["--segment-count", "3"],
            vec!["--segment-count", "129"],
            vec!["--pixel-delta", "0"],
            vec!["--min-transitions", "1"],
            vec!["--padding", "65"],
            vec!["--max-dimension", "8"],
            vec!["--max-pixels", "0"],
            vec!["--approve", "yes"],
            vec!["--site", "site:dup"],
        ] {
            let mut input = base_args();
            input.extend(bad.into_iter().map(OsString::from));
            assert!(parse(&input).is_err());
        }
    }
}

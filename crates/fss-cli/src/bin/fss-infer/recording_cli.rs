#![forbid(unsafe_code)]
//! One local operator command for bounded recording inference and complete analysis.

use std::collections::BTreeSet;

use super::*;
use fss_reference::ingest::analysis::{
    AnalysisBudget, AnalysisLimits, MAX_ANALYSIS_FRAMES, MAX_ANALYSIS_REPORT_BYTES,
};
use fss_reference::ingest::detections::{
    BoxEncoding, CoordinateSpace, DetectionContract, DetectionSpec,
};
use fss_reference::ingest::recording_pipeline::{
    RecordingBudget, RecordingProgress, RecordingRequest, run_recording,
};
use fss_reference::ingest::tracking::TrackingConfig;

const HELP: &str = "fss-infer analyze [options]\n\
  --root DIR --site SITE --import-id sha256:HEX --first-segment N --frames N\n\
  --interpretation gray|ycbcr --model-digest sha256:HEX [--model FILE]\n\
  --output-port NAME --labels ORDERED,CLASS,NAMES\n\
  --box-format xyxy|cxcywh --coordinates pixels|normalized --report-out FILE\n\
  Optional policy: --minimum-score-ppm N --nms-iou-ppm N --minimum-iou-ppm N\n\
    --confirmation-hits N --maximum-missed-frames N --maximum-tracks N\n\
    --maximum-rows N --maximum-detections N\n\
  Whole-command work: --decode-work-units N --max-macs N\n\
    --detection-work-units N --association-work-units N\n\
  Bounds: --max-tensor-bytes N (per model invocation), --max-report-bytes N\n\
  Optional: --runs-out FILE --principal ID\n\
  Processes 1..256 retained JPEG/MJPEG segments and writes a complete canonical\n\
  AnalysisReport, not detection CLI JSON. With no --model, recover the exact model\n\
  object already retained at --model-digest; no download or model activation occurs.\n\
  Retry the SAME original range to reuse completed numeric work and reconstruct\n\
  the same tracking history. Failed inference conservatively charges its reserved\n\
  remaining model-work allowance. No partial report is exported on analysis failure.\n\
  Exports must be new files outside the existing deployment. No alert, calibrated\n\
  presence, physical identity, or absence is authorized by this command.\n";

#[derive(Debug)]
struct Options {
    root: PathBuf,
    site: String,
    principal: String,
    model: Option<PathBuf>,
    report: PathBuf,
    runs: Option<PathBuf>,
    request: RecordingRequest,
    budget: RecordingBudget<'static>,
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
        "--interpretation",
        "--model",
        "--model-digest",
        "--output-port",
        "--labels",
        "--box-format",
        "--coordinates",
        "--report-out",
        "--runs-out",
        "--minimum-score-ppm",
        "--nms-iou-ppm",
        "--minimum-iou-ppm",
        "--confirmation-hits",
        "--maximum-missed-frames",
        "--maximum-tracks",
        "--maximum-rows",
        "--maximum-detections",
        "--decode-work-units",
        "--max-macs",
        "--detection-work-units",
        "--association-work-units",
        "--max-tensor-bytes",
        "--max-report-bytes",
    ];
    let mut values = Values::new();
    for pair in args.chunks(2) {
        let key = pair[0].to_str().ok_or("option names require UTF-8")?;
        if !allowed.contains(&key) {
            return Err("unknown or inapplicable analyze option".into());
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
    let detector = DetectionSpec {
        model_digest: digest(&values, "--model-digest")?,
        output_port: text(&values, "--output-port")?.to_owned(),
        labels: text(&values, "--labels")?
            .split(',')
            .map(str::to_owned)
            .collect(),
        encoding: match text(&values, "--box-format")? {
            "xyxy" => BoxEncoding::Xyxy,
            "cxcywh" => BoxEncoding::CenterSize,
            _ => return Err("box-format requires xyxy or cxcywh".into()),
        },
        coordinates: match text(&values, "--coordinates")? {
            "pixels" => CoordinateSpace::Pixels,
            "normalized" => CoordinateSpace::Normalized,
            _ => return Err("coordinates require pixels or normalized".into()),
        },
        minimum_score_ppm: number(&values, "--minimum-score-ppm", Some(500_000))?,
        nms_iou_ppm: number(&values, "--nms-iou-ppm", Some(500_000))?,
        maximum_rows: number(&values, "--maximum-rows", Some(4096))?,
        maximum_detections: number(&values, "--maximum-detections", Some(256))?,
    };
    DetectionContract::new(detector.clone()).map_err(|e| e.to_string())?;
    let tracking = TrackingConfig {
        minimum_iou_ppm: number(&values, "--minimum-iou-ppm", Some(300_000))?,
        confirmation_hits: number(&values, "--confirmation-hits", Some(2))?,
        maximum_missed_frames: number(&values, "--maximum-missed-frames", Some(2))?,
        maximum_tracks: number(&values, "--maximum-tracks", Some(128))?,
    };
    tracking.digest().map_err(|e| e.to_string())?;
    let first_segment: usize = number(&values, "--first-segment", None)?;
    let segment_count: usize = number(&values, "--frames", None)?;
    let maximum_tensor_bytes: usize =
        number(&values, "--max-tensor-bytes", Some(64 * 1024 * 1024))?;
    let maximum_report_bytes: usize = number(
        &values,
        "--max-report-bytes",
        Some(MAX_ANALYSIS_REPORT_BYTES),
    )?;
    if segment_count == 0
        || segment_count > MAX_ANALYSIS_FRAMES
        || first_segment.checked_add(segment_count).is_none()
        || maximum_tensor_bytes == 0
        || maximum_tensor_bytes > MAX_RUN_TENSOR_BYTES
        || maximum_report_bytes == 0
        || maximum_report_bytes > MAX_ANALYSIS_REPORT_BYTES
    {
        return Err("invalid range or tensor/report bound".into());
    }
    let request = RecordingRequest {
        import_identity: digest(&values, "--import-id")?,
        interpretation,
        first_segment,
        segment_count,
        detector,
        tracking,
        maximum_tensor_bytes,
        limits: AnalysisLimits {
            maximum_report_bytes,
            ..AnalysisLimits::default()
        },
    };
    Ok(Some(Options {
        root: PathBuf::from(value(&values, "--root")?),
        site,
        principal,
        model: values.get("--model").map(PathBuf::from),
        report: PathBuf::from(value(&values, "--report-out")?),
        runs: values.get("--runs-out").map(PathBuf::from),
        request,
        budget: RecordingBudget::new(
            DecodeBudget::new(number(&values, "--decode-work-units", Some(1_000_000_000))?),
            number(&values, "--max-macs", Some(1_000_000_000))?,
            AnalysisBudget::new(
                number(&values, "--detection-work-units", Some(10_000_000))?,
                number(&values, "--association-work-units", Some(10_000_000))?,
            ),
        ),
    }))
}

// Check obvious export refusals before expensive work. The existing export owner repeats the
// containment test and opens with create_new; this is not a hostile-filesystem race-proof API.
fn destination(path: &Path, root: &Path) -> RunResult<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(_) => return Err(io::Error::other("export destination already exists").into()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent)?;
    if parent.starts_with(fs::canonicalize(root)?) {
        return Err(io::Error::other("exports must be outside the deployment").into());
    }
    Ok(parent.join(
        path.file_name()
            .ok_or_else(|| io::Error::other("export file name required"))?,
    ))
}

fn progress(
    out: &mut impl Write,
    state: &RecordingProgress,
    work: &RecordingBudget<'_>,
    complete: bool,
) -> io::Result<()> {
    writeln!(
        out,
        "operation=analyze\ncomplete={complete}\nstage={}\ncompleted_inferences={}",
        state.stage.as_str(),
        state.completed.len()
    )?;
    match state.next_segment {
        Some(segment) => writeln!(out, "next_segment={segment}")?,
        None => writeln!(out, "next_segment=none")?,
    }
    writeln!(
        out,
        "new_decodes={}\nreused_decodes={}\nnew_inferences={}\nreused_inferences={}",
        state.new_decodes, state.reused_decodes, state.new_inferences, state.reused_inferences
    )?;
    writeln!(
        out,
        "decode_work_units={}\nmodel_work_charged={}\nmodel_work_remaining={}",
        work.decode.used(),
        work.model_charged(),
        work.model_remaining()
    )?;
    writeln!(
        out,
        "detection_work_units={}\nassociation_work_units={}\nauthority_sequence={}",
        work.analysis.detection.used(),
        work.analysis.association.used(),
        state.anchor.commit_sequence
    )?;
    for frame in &state.completed {
        writeln!(out, "run.{}={}", frame.segment_index, frame.run_identity)?;
    }
    writeln!(
        out,
        "model_outputs=uncalibrated\nassociation_is_hypothesis=true\nabsence_certifiable=false\neffects_authorized=false"
    )
}

fn run(mut options: Options, out: &mut impl Write) -> RunResult<()> {
    if !fs::symlink_metadata(&options.root)?.file_type().is_dir()
        || !fs::symlink_metadata(options.root.join("LAYOUT"))?
            .file_type()
            .is_file()
    {
        return Err(io::Error::other("existing non-symlink deployment required").into());
    }
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:recording-cli".into(),
        operation_id: OperationId::parse("operation:recording-cli")?,
        principal: options.principal.clone(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(options.request.maximum_tensor_bytes as u64)
            .build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    let cx = ReplayCx::from_context_authority(&authority, options.root.clone())?;
    let exec = ScalarExecCx::new();
    let result = (|| -> RunResult<()> {
        cx.checkpoint("recording_cli:preflight")?;
        let report_destination = destination(&options.report, &options.root)?;
        if let Some(path) = &options.runs
            && destination(path, &options.root)? == report_destination
        {
            return Err(io::Error::other("report and run-list exports must differ").into());
        }
        let mut deployment = ReferenceDeployment::open(&options.root, &options.site, &cx)?;
        let expected = options.request.detector.model_digest;
        cx.checkpoint("recording_cli:model")?;
        let model = match &options.model {
            Some(path) => load_model(path, expected)?,
            None => {
                RecordedModel::decode(&deployment.publisher().spool().read(expected)?, expected)?
            }
        };
        let outcome = match run_recording(
            &mut deployment,
            &options.request,
            &model,
            &mut options.budget,
            &exec,
            &cx,
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                progress(out, &error.progress, &options.budget, false)?;
                return Err(error);
            }
        };
        export(
            &options.report,
            outcome.report.encoded(),
            &options.root,
            &cx,
        )?;
        if let Some(path) = &options.runs {
            let mut bytes = Vec::new();
            for frame in &outcome.progress.completed {
                writeln!(&mut bytes, "{} {}", frame.segment_index, frame.run_identity)?;
            }
            export(path, &bytes, &options.root, &cx)?;
        }
        progress(out, &outcome.progress, &options.budget, true)?;
        writeln!(
            out,
            "report_digest={}\nanalysis_plan_digest={}\nmodel_digest={}",
            outcome.report.digest(),
            outcome.report.plan().digest(),
            model.digest()
        )?;
        let tracks: BTreeSet<_> = outcome
            .report
            .observations()
            .iter()
            .flat_map(|observation| &observation.tracking().tracks)
            .filter(|track| track.observed_row.is_some())
            .map(|track| track.id)
            .collect();
        writeln!(out, "candidate_tracks={}", tracks.len())?;
        for track in tracks {
            writeln!(out, "track={track}")?;
        }
        Ok(())
    })();
    exec.drain_and_finalize();
    cx.drain_and_finalize();
    result
}

pub(super) fn dispatch(args: &[OsString], out: &mut impl Write) -> Option<ExitCode> {
    if args.first().and_then(|arg| arg.to_str()) != Some("analyze") {
        return None;
    }
    Some(match parse(&args[1..]) {
        Ok(None) => match out.write_all(HELP.as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        },
        Ok(Some(options)) => match run(options, out) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}");
                eprintln!(
                    "Retained frame/model results survive failure. Retry the original range; partial exports may remain."
                );
                ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
            }
        },
        Err(error) => {
            eprintln!(
                "{}: {error}; use fss-infer analyze --help",
                fss_cli::ERR_CLI_MALFORMED_VALUE
            );
            ExitCode::from(ExitIdentity::MALFORMED_VALUE.code)
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
            "site:analyze",
            "--import-id",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "--first-segment",
            "0",
            "--frames",
            "3",
            "--interpretation",
            "gray",
            "--model-digest",
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "--output-port",
            "detections",
            "--labels",
            "vehicle,animal",
            "--box-format",
            "xyxy",
            "--coordinates",
            "normalized",
            "--report-out",
            "report.bin",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn replace(args: &mut [OsString], key: &str, replacement: OsString) -> TestResult {
        let index = args
            .iter()
            .position(|arg| arg == key)
            .ok_or("test option present")?;
        args[index + 1] = replacement;
        Ok(())
    }
    #[test]
    fn exact_selection_contract_and_report_are_required() -> TestResult {
        assert!(parse(&args()).is_ok());
        for key in [
            "--frames",
            "--first-segment",
            "--model-digest",
            "--report-out",
            "--labels",
        ] {
            let mut a = args();
            let index = a
                .iter()
                .position(|arg| arg == key)
                .ok_or("test option present")?;
            a.drain(index..index + 2);
            assert!(parse(&a).is_err());
        }
        Ok(())
    }
    #[test]
    fn duplicates_unknown_options_and_invalid_bounds_fail_before_io() -> TestResult {
        for extra in [
            ["--site", "site:other"],
            ["--latest", "yes"],
            ["--run-id", "x"],
            ["--max-macs", "-1"],
            ["--max-tensor-bytes", "0"],
            ["--max-report-bytes", "16777217"],
        ] {
            let mut a = args();
            a.extend(extra.map(OsString::from));
            assert!(parse(&a).is_err());
        }
        for (key, bad) in [
            ("--frames", "0"),
            ("--frames", "257"),
            ("--interpretation", "auto"),
            ("--box-format", "guess"),
            ("--coordinates", "auto"),
            ("--labels", "vehicle,vehicle"),
        ] {
            let mut a = args();
            replace(&mut a, key, bad.into())?;
            assert!(parse(&a).is_err());
        }
        Ok(())
    }
    #[test]
    fn cached_numeric_zero_budgets_are_admitted_and_help_is_storage_free() {
        let mut a = args();
        a.extend(["--max-macs", "0", "--decode-work-units", "0"].map(OsString::from));
        assert!(parse(&a).is_ok());
        assert!(matches!(parse(&["--help".into()]), Ok(None)));
        assert!(parse(&["--help".into(), "extra".into()]).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn export_and_model_paths_preserve_native_bytes() -> TestResult {
        use std::os::unix::ffi::OsStringExt;
        let mut a = args();
        replace(
            &mut a,
            "--report-out",
            OsString::from_vec(b"report-\xff.bin".to_vec()),
        )?;
        a.extend([
            OsString::from("--model"),
            OsString::from_vec(b"model-\xff.bin".to_vec()),
        ]);
        assert!(parse(&a).is_ok());
        Ok(())
    }
}

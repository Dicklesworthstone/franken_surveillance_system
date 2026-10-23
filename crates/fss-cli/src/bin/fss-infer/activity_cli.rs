#![forbid(unsafe_code)]
//! Explicit retained JPEG import -> native scalar activity -> cold verification recipe.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use fss_cli::agent_json::{array, evidence_anchor, object, string, strings};
use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, OperationId, PrincipalId, RootAuthoritySpec,
    SensorId, StreamId,
};
use fss_reference::activity_replay::ActivityReplayPlan;
use fss_reference::executor_activity::{ActivityThresholdPolicy, ExecutorModelOutcome};
use fss_reference::executor_activity_package::ACTIVITY_PACKAGE_V1_SHA256;
use fss_reference::ingest::recorded_activity::{
    RecordedActivityError, RecordedActivityLimits, RecordedActivityReceipt,
    RecordedActivityRequest, produce_recorded_activity,
};
use fss_reference::{ExecBudget, ReferenceDeployment, ReplayCx, ScalarExecCx};

use super::{RunResult, Values, digest, number, text, value};

const MAX_ARGUMENTS: usize = 65;
const MAX_ARGUMENT_BYTES: usize = 4096;
const MAX_REPORT_BYTES: usize = 64 * 1024;
const HELP: &str = "fss-infer activity --root DIR --site SITE --import-id sha256:HEX\n\
  --reference-segment N --segment N --sensor ID --stream ID --job ID\n\
  --interpretation gray|ycbcr --package-digest sha256:HEX\n\
  --policy-generation N --threshold-bits HEX8\n\
  --execution-macs N --execution-bytes N [--principal ID]\n\
  [--max-source-bytes N] [--max-segment-bytes N] [--max-source-read-bytes N]\n\
  [--max-frame-pixels N] [--max-dimension N] [--max-decode-work N]\n\
  [--max-staged-bytes N] [--max-history-entries N]\n\
\n\
  Runs the committed first-party model:fss-activity:v1 scalar graph over two exact\n\
  retained JPEG frames from one real MJPEG import. The reference segment must precede\n\
  the evaluated segment; sensor and stream must match both retained source capsules.\n\
  The package pin is the whole-archive SHA-256 printed below, not a model root. No\n\
  model is downloaded or activated, and no import/watch/capture command enables this\n\
  computation implicitly. AVC and HEVC sources are not supported by this command.\n\
\n\
  The threshold policy is mandatory. HEX8 is eight lowercase hexadecimal digits for\n\
  an exact finite nonnegative f32; 3c23d70a encodes 0.01f32. A finite score strictly\n\
  above the threshold is activity; a score at or below it is no_activity, never\n\
  absence. Executor exhaustion is retained as abstained, never no_activity.\n\
\n\
  Current privacy and deletion restrictions apply before original-pixel computation.\n\
  A privacy-masked sensor is refused: this model's retained RGB receipt cannot bind\n\
  masked inputs. No override or unmasked export is provided. The command retains\n\
  exact source/decode bindings plus the result and complete invocation receipt.\n\
  Equal-payload source roles share content-addressed objects. Exact retries reopen\n\
  the same publications; a refusal never repairs or replaces damaged evidence.\n\
\n\
  Prints one fss.recorded_activity_report.v1 JSON document with source/result roots,\n\
  exact policy and execution settings, charged work, and a verification_arguments\n\
  array for fss-evidence. Execute that array as arguments, not as shell text. For\n\
  non-UTF-8 root paths, supply --root with the original native path separately.\n\
  An abstention has no successful-score verification recipe. A later output failure\n\
  can leave valid publications retained; repeat the exact request to reconcile.\n\
\n\
  The score is uncalibrated pixel change, reference-only. It is not an object class,\n\
  probability, identity, coverage certificate, corroboration, event or alert.\n\
  No effect is authorized. Native filesystem and decode calls are bounded but not\n\
  preempted; source reads, JPEG work and executor allowances are separate ceilings.\n";

#[derive(Debug)]
struct Options {
    root: PathBuf,
    site: String,
    principal: String,
    request: RecordedActivityRequest,
    limits: RecordedActivityLimits,
}

fn bounded_number(
    values: &Values,
    key: &str,
    default: Option<u64>,
    low: u64,
    high: u64,
) -> Result<u64, String> {
    let n = number(values, key, default)?;
    if !(low..=high).contains(&n) {
        return Err(format!("{key} is outside its admitted bounds"));
    }
    Ok(n)
}

fn parse(args: &[OsString]) -> Result<Option<Options>, String> {
    if args.len() > MAX_ARGUMENTS
        || args
            .iter()
            .any(|a| a.as_encoded_bytes().len() > MAX_ARGUMENT_BYTES)
    {
        return Err("activity argument count or byte bound exceeded".to_owned());
    }
    if args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help" | "-h")) {
        return Ok(None);
    }
    let allowed = [
        "--root",
        "--site",
        "--principal",
        "--import-id",
        "--reference-segment",
        "--segment",
        "--sensor",
        "--stream",
        "--job",
        "--interpretation",
        "--package-digest",
        "--policy-generation",
        "--threshold-bits",
        "--execution-macs",
        "--execution-bytes",
        "--max-source-bytes",
        "--max-segment-bytes",
        "--max-source-read-bytes",
        "--max-frame-pixels",
        "--max-dimension",
        "--max-decode-work",
        "--max-staged-bytes",
        "--max-history-entries",
    ];
    let mut values = Values::new();
    for pair in args.chunks(2) {
        let key = pair[0].to_str().ok_or("option names require UTF-8")?;
        if !allowed.contains(&key) {
            return Err("unknown or inapplicable activity option".to_owned());
        }
        if values.contains_key(key) {
            return Err(format!("duplicate {key}"));
        }
        let argument = pair
            .get(1)
            .ok_or_else(|| format!("missing value for {key}"))?;
        if argument.is_empty() || argument.to_str().is_some_and(|v| v.starts_with("--")) {
            return Err(format!("missing value for {key}"));
        }
        values.insert(key.to_owned(), argument.clone());
    }
    let site = text(&values, "--site")?.to_owned();
    if site.len() > 256
        || fss_reference::reference_deployment::validate_site_lineage(&site).is_err()
    {
        return Err("invalid bounded site lineage".to_owned());
    }
    let principal = values.get("--principal").map_or_else(
        || Ok("principal:local-operator".to_owned()),
        |_| text(&values, "--principal").map(str::to_owned),
    )?;
    PrincipalId::parse(&principal).map_err(|_| "invalid principal ID")?;
    let job = text(&values, "--job")?;
    if job.is_empty() || job.len() > 128 || !job.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("job requires 1..128 ASCII graphic bytes".to_owned());
    }
    let reference_segment: usize = number(&values, "--reference-segment", None)?;
    let segment: usize = number(&values, "--segment", None)?;
    if reference_segment >= segment {
        return Err("reference segment must precede evaluated segment".to_owned());
    }
    let interpretation = match text(&values, "--interpretation")? {
        "gray" => ComponentInterpretation::Grayscale,
        "ycbcr" => ComponentInterpretation::YCbCr,
        _ => return Err("interpretation requires explicit gray or ycbcr".to_owned()),
    };
    let bits = text(&values, "--threshold-bits")?;
    if bits.len() != 8
        || !bits
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("threshold bits require eight lowercase hex digits".to_owned());
    }
    let threshold =
        f32::from_bits(u32::from_str_radix(bits, 16).map_err(|_| "invalid threshold bits")?);
    let policy = ActivityThresholdPolicy::new(
        bounded_number(&values, "--policy-generation", None, 1, u64::MAX)?,
        threshold,
    )
    .map_err(|_| "threshold must be finite and nonnegative")?;
    let package = digest(&values, "--package-digest")?;
    if package.to_text() != ACTIVITY_PACKAGE_V1_SHA256 {
        return Err("activity requires the exact committed first-party package pin".to_owned());
    }
    let mut limits = RecordedActivityLimits::default();
    limits.read.max_source_bytes = bounded_number(
        &values,
        "--max-source-bytes",
        Some(limits.read.max_source_bytes),
        1,
        4 * 1024 * 1024 * 1024,
    )?;
    limits.read.max_segment_bytes = bounded_number(
        &values,
        "--max-segment-bytes",
        Some(limits.read.max_segment_bytes),
        1,
        16 * 1024 * 1024,
    )?;
    limits.max_source_read_bytes = bounded_number(
        &values,
        "--max-source-read-bytes",
        Some(limits.max_source_read_bytes),
        1,
        4 * 1024 * 1024 * 1024,
    )?;
    limits.decode.frame.maximum_pixels = bounded_number(
        &values,
        "--max-frame-pixels",
        Some(limits.decode.frame.maximum_pixels as u64),
        1,
        fss_reference::executor_activity::MAX_ACTIVITY_MODEL_PIXELS as u64,
    )? as usize;
    limits.decode.frame.maximum_dimension = bounded_number(
        &values,
        "--max-dimension",
        Some(u64::from(limits.decode.frame.maximum_dimension)),
        1,
        4096,
    )? as u32;
    limits.max_decode_work = bounded_number(
        &values,
        "--max-decode-work",
        Some(limits.max_decode_work),
        0,
        1_000_000_000,
    )?;
    limits.max_staged_bytes = bounded_number(
        &values,
        "--max-staged-bytes",
        Some(limits.max_staged_bytes),
        1,
        64 * 1024 * 1024,
    )?;
    limits.max_history_entries = bounded_number(
        &values,
        "--max-history-entries",
        Some(limits.max_history_entries as u64),
        1,
        1_000_000,
    )? as usize;
    Ok(Some(Options {
        root: PathBuf::from(value(&values, "--root")?),
        site,
        principal,
        request: RecordedActivityRequest {
            import_identity: digest(&values, "--import-id")?,
            reference_segment,
            segment,
            expected_package_sha256: package,
            plan: ActivityReplayPlan {
                sensor_id: SensorId::parse(text(&values, "--sensor")?)
                    .map_err(|_| "invalid sensor ID")?,
                stream_id: StreamId::parse(text(&values, "--stream")?)
                    .map_err(|_| "invalid stream ID")?,
                job_id: job.to_owned(),
                policy,
                interpretation,
                execution: ExecBudget::new(
                    bounded_number(&values, "--execution-macs", None, 1, 1_000_000_000_000)?,
                    bounded_number(&values, "--execution-bytes", None, 1, 512 * 1024 * 1024)?
                        as usize,
                ),
            },
        },
        limits,
    }))
}

fn interpretation(value: ComponentInterpretation) -> &'static str {
    match value {
        ComponentInterpretation::Grayscale => "grayscale",
        ComponentInterpretation::YCbCr => "ycbcr",
    }
}

fn verification_arguments(options: &Options, receipt: &RecordedActivityReceipt) -> Vec<String> {
    let plan = &receipt.plan;
    let mut arguments = vec!["verify-activity".to_owned()];
    if let Some(root) = options.root.to_str() {
        arguments.extend(["--root".to_owned(), root.to_owned()]);
    }
    for (key, value) in [
        ("--site", options.site.clone()),
        ("--result", receipt.retained.result_digest.to_text()),
        ("--reference-capsule", receipt.reference_capsule.to_text()),
        ("--source-slot", receipt.source_slot.as_str().to_owned()),
        ("--sensor", plan.sensor_id.as_str().to_owned()),
        ("--stream", plan.stream_id.as_str().to_owned()),
        ("--job", plan.job_id.clone()),
        (
            "--interpretation",
            interpretation(plan.interpretation).to_owned(),
        ),
        ("--policy-generation", plan.policy.generation().to_string()),
        (
            "--threshold-bits",
            format!("{:08x}", plan.policy.threshold().to_bits()),
        ),
        ("--execution-macs", plan.execution.max_macs.to_string()),
        ("--execution-bytes", plan.execution.max_bytes.to_string()),
        (
            "--max-decode-work",
            options.limits.max_decode_work.to_string(),
        ),
    ] {
        arguments.extend([key.to_owned(), value]);
    }
    arguments
}

fn report(options: &Options, receipt: &RecordedActivityReceipt) -> String {
    let result = &receipt.retained.result;
    let plan = &receipt.plan;
    let verification = match result.outcome {
        ExecutorModelOutcome::Abstained { .. } => "null".to_owned(),
        _ => strings(&verification_arguments(options, receipt)),
    };
    let score = result.outcome.score().map_or_else(
        || "null".to_owned(),
        |value| string(&format!("{:08x}", value.to_bits())),
    );
    let abstention = match result.outcome {
        ExecutorModelOutcome::Abstained {
            reason,
            receipt_outcome,
        } => object(&[
            ("reason", string(reason.as_str())),
            ("receipt_outcome", string(receipt_outcome.as_str())),
        ]),
        _ => "null".to_owned(),
    };
    object(&[
        ("format", string("fss.recorded_activity_report.v1")),
        ("operation", string("activity_retained")),
        ("site", string(&options.site)),
        ("anchor", evidence_anchor(&receipt.final_anchor)),
        (
            "import_identity",
            string(&receipt.import_identity.to_text()),
        ),
        ("import_root", string(&receipt.import_root.to_text())),
        ("reference_segment", receipt.reference_segment.to_string()),
        ("segment", receipt.segment.to_string()),
        (
            "reference_capsule",
            string(&receipt.reference_capsule.to_text()),
        ),
        ("frame_capsule", string(&receipt.frame_capsule.to_text())),
        ("source_slot", string(receipt.source_slot.as_str())),
        ("source_root", string(&receipt.source_root.to_text())),
        (
            "result_digest",
            string(&receipt.retained.result_digest.to_text()),
        ),
        ("result_root", string(&receipt.retained.root.to_text())),
        (
            "invocation_receipt_digest",
            string(&result.invocation_receipt_digest.to_text()),
        ),
        (
            "invocation_receipt_object",
            string(&result.invocation_receipt_object.to_text()),
        ),
        ("sensor", string(plan.sensor_id.as_str())),
        ("stream", string(plan.stream_id.as_str())),
        ("job", string(&plan.job_id)),
        (
            "interpretation",
            string(interpretation(plan.interpretation)),
        ),
        ("model_generation", string(&result.model_generation)),
        ("model_digest", string(&result.model_digest.to_text())),
        ("package_sha256", string(&receipt.package_sha256.to_text())),
        ("package_root", string(&receipt.package_root.to_text())),
        ("policy_generation", plan.policy.generation().to_string()),
        (
            "threshold_bits",
            string(&format!("{:08x}", plan.policy.threshold().to_bits())),
        ),
        ("policy_digest", string(&plan.policy.digest().to_text())),
        ("execution_macs", plan.execution.max_macs.to_string()),
        ("execution_bytes", plan.execution.max_bytes.to_string()),
        ("outcome", string(result.outcome.as_str())),
        ("score_bits", score),
        ("abstention", abstention),
        ("reference_only", result.reference_only.to_string()),
        ("score_calibrated", "false".to_owned()),
        (
            "supports_absence_claim",
            result.supports_absence_claim().to_string(),
        ),
        ("effects_authorized", "false".to_owned()),
        ("source_read_bytes", receipt.source_read_bytes.to_string()),
        ("decode_work", receipt.decode_work.to_string()),
        ("staged_input_bytes", receipt.staged_input_bytes.to_string()),
        (
            "limits",
            object(&[
                (
                    "source_bytes",
                    options.limits.read.max_source_bytes.to_string(),
                ),
                (
                    "source_chunk_bytes",
                    options.limits.read.max_chunk_bytes.to_string(),
                ),
                (
                    "segment_bytes",
                    options.limits.read.max_segment_bytes.to_string(),
                ),
                (
                    "source_read_bytes",
                    options.limits.max_source_read_bytes.to_string(),
                ),
                (
                    "frame_pixels",
                    options.limits.decode.frame.maximum_pixels.to_string(),
                ),
                (
                    "frame_dimension",
                    options.limits.decode.frame.maximum_dimension.to_string(),
                ),
                ("decode_work", options.limits.max_decode_work.to_string()),
                (
                    "staged_input_bytes",
                    options.limits.max_staged_bytes.to_string(),
                ),
                (
                    "history_batches",
                    options.limits.max_history_batches.to_string(),
                ),
                (
                    "history_entries",
                    options.limits.max_history_entries.to_string(),
                ),
            ]),
        ),
        ("verification_program", string("fss-evidence")),
        ("verification_arguments", verification),
        (
            "verification_root_argument_required",
            options.root.to_str().is_none().to_string(),
        ),
        (
            "limitations",
            array(&[
                string("Uncalibrated reference-only pixel change; no event or alert is published."),
                string("NoActivity is not absence, coverage, person detection or corroboration."),
                string(
                    "Cold verification independently rechecks current custody and deletion authority.",
                ),
            ]),
        ),
    ])
}

fn run(options: &Options, out: &mut impl Write) -> RunResult<()> {
    if !fs::symlink_metadata(&options.root)?.file_type().is_dir()
        || !fs::symlink_metadata(options.root.join("LAYOUT"))?
            .file_type()
            .is_file()
    {
        return Err(io::Error::other("existing non-symlink deployment required").into());
    }
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:recorded-activity-cli".to_owned(),
        operation_id: OperationId::parse("operation:recorded-activity-cli")?,
        principal: options.principal.clone(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(options.limits.max_source_read_bytes)
            .build()?,
        privacy_scope: "privacy:local-authorized-files".to_owned(),
        retention_scope: "retention:existing-deployment-policy".to_owned(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, options.root.clone())?;
    let scalar = ScalarExecCx::new();
    let result = (|| -> RunResult<()> {
        let mut deployment = ReferenceDeployment::open(&options.root, &options.site, &cx)?;
        let receipt = produce_recorded_activity(
            &mut deployment,
            options.request.clone(),
            options.limits,
            &cx,
            &scalar,
        )?;
        let document = report(options, &receipt);
        if document.len() > MAX_REPORT_BYTES {
            return Err(io::Error::other("activity metadata report exceeds its bound").into());
        }
        writeln!(out, "{document}")?;
        Ok(())
    })();
    scalar.drain_and_finalize();
    cx.drain_and_finalize();
    result
}

pub(super) fn dispatch(args: &[OsString], out: &mut impl Write) -> Option<ExitCode> {
    if args.first().and_then(|v| v.to_str()) != Some("activity") {
        return None;
    }
    Some(match parse(&args[1..]) {
        Ok(None) => {
            let help = format!("{HELP}\nCommitted package SHA-256: {ACTIVITY_PACKAGE_V1_SHA256}\n");
            ExitCode::from(if out.write_all(help.as_bytes()).is_ok() {
                fss_cli::ExitIdentity::SUCCESS.code
            } else {
                fss_cli::ExitIdentity::RUNTIME_FAILURE.code
            })
        }
        Ok(Some(options)) => match run(&options, out) {
            Ok(()) => ExitCode::from(fss_cli::ExitIdentity::SUCCESS.code),
            Err(error) => {
                let code = error.downcast_ref::<RecordedActivityError>().map_or(
                    fss_cli::ERR_CLI_RUNTIME_FAILURE,
                    RecordedActivityError::stable_id,
                );
                eprintln!("{code}: {error}");
                eprintln!(
                    "Completed activity publications may remain retained. Repeat the exact request to reconcile; no damaged evidence is replaced."
                );
                ExitCode::from(fss_cli::ExitIdentity::RUNTIME_FAILURE.code)
            }
        },
        Err(reason) => {
            eprintln!(
                "{}: {reason}; use fss-infer activity --help",
                fss_cli::ERR_CLI_MALFORMED_VALUE
            );
            ExitCode::from(fss_cli::ExitIdentity::MALFORMED_VALUE.code)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Vec<OsString> {
        [
            "--root",
            "unused",
            "--site",
            "site:activity-cli",
            "--import-id",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "--reference-segment",
            "0",
            "--segment",
            "1",
            "--sensor",
            "sensor:activity-cli",
            "--stream",
            "stream:activity-cli",
            "--job",
            "job:activity-cli",
            "--interpretation",
            "gray",
            "--package-digest",
            ACTIVITY_PACKAGE_V1_SHA256,
            "--policy-generation",
            "1",
            "--threshold-bits",
            "3c23d70a",
            "--execution-macs",
            "10000000",
            "--execution-bytes",
            "16777216",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    #[test]
    fn policy_package_and_execution_are_explicit_before_any_io() {
        let parsed = parse(&request())
            .expect("valid explicit request")
            .expect("request");
        assert_eq!(parsed.request.plan.policy.threshold().to_bits(), 0x3c23d70a);
        assert_eq!(parsed.request.plan.policy.generation(), 1);
        for required in [
            "--sensor",
            "--stream",
            "--job",
            "--package-digest",
            "--policy-generation",
            "--threshold-bits",
            "--execution-macs",
            "--execution-bytes",
            "--reference-segment",
            "--segment",
            "--interpretation",
        ] {
            let mut args = request();
            let index = args
                .iter()
                .position(|v| v == required)
                .expect("required flag");
            args.drain(index..index + 2);
            assert!(parse(&args).is_err(), "missing {required} accepted");
        }
    }

    #[test]
    fn malformed_or_ambiguous_activity_configuration_is_refused() {
        for (key, bad) in [
            ("--policy-generation", "0"),
            ("--threshold-bits", "0.01"),
            ("--threshold-bits", "7fc00000"),
            ("--threshold-bits", "7f800000"),
            ("--threshold-bits", "bf800000"),
            ("--threshold-bits", "3C23D70A"),
            ("--reference-segment", "1"),
            ("--execution-bytes", "0"),
            (
                "--package-digest",
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            ),
            ("--job", "job:\ninvalid"),
        ] {
            let mut args = request();
            let index = args.iter().position(|v| v == key).expect("flag");
            args[index + 1] = bad.into();
            assert!(parse(&args).is_err(), "{key}={bad} accepted");
        }
        for extra in [
            ["--threshold-bits", "3c23d70a"],
            ["--approve", "yes"],
            ["--execute-perception", "yes"],
            ["--package", "unverified.fmpk"],
        ] {
            let mut args = request();
            args.extend(extra.map(OsString::from));
            assert!(parse(&args).is_err());
        }
        assert!(parse(&["--help".into(), "extra".into()]).is_err());
    }
}

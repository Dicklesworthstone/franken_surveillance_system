#![forbid(unsafe_code)]
//! Bounded local operator entry point for independently verified retained native activity.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use fss_cli::agent_json::{array, evidence_anchor, object, string, strings};
use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::{ContentDigest, DigestAlgorithm, SensorId, StreamId};
use fss_object::HostSpoolIo;
use fss_publication::SlotName;
use fss_reference::activity_replay::ActivityReplayPlan;
use fss_reference::activity_replay::belief::ActivityEvidenceBinding;
use fss_reference::activity_replay::operator::{
    ActivityVerificationLimits, ActivityVerificationRequest, MAX_ACTIVITY_SOURCE_SLOTS,
    VerifiedActivityObservation, verify_retained_activity,
};
use fss_reference::executor_activity::{ActivityThresholdPolicy, ExecutorModelOutcome};
use fss_reference::{ExecBudget, ScalarExecCx};

use super::{CommandError, MAX_ARG_BYTES, MAX_REPORT_BYTES, number, text};

pub(super) const MAX_ARGS: usize = 81;
const HELP: &str = "fss-evidence verify-activity --root DIR --site SITE\n\
  --result sha256:HEX --reference-capsule sha256:HEX\n\
  --source-slot SLOT [--source-slot SLOT ...] --sensor ID --stream ID --job ID\n\
  --interpretation grayscale|ycbcr --execution-macs N --execution-bytes N\n\
  [--expected-ledger-root sha256:HEX] [--policy-generation N] [--threshold-bits HEX8]\n\
  [--max-journal-bytes N] [--max-custody-read-bytes N] [--max-object-bytes N]\n\
  [--max-objects N] [--max-retained-bytes N] [--max-deletion-bytes N]\n\
  [--max-decode-work N] [--max-report-bytes N] [--timeout-ms N]\n\
\n\
  Cold, read-only verification of a result retained by retain_executor_result. Reads\n\
  only the explicit source-slot closures and deterministic result/receipt slot.\n\
  Replays complete committed deletion authority, verifies native custody and exact\n\
  anchor membership, then decodes both original JPEGs and reruns the pinned native\n\
  scalar activity model. Complete invocation receipt AND result bytes must match.\n\
  No missing role, source slot, codec, model, policy or execution budget is inferred.\n\
\n\
  The reference threshold policy defaults to generation 1 and threshold 0.01f32.\n\
  --threshold-bits selects an exact nonnegative finite f32 using eight lowercase hex\n\
  digits. --execution-* must match the ORIGINAL invocation receipt's allowances.\n\
  --reference-capsule selects the earlier capsule; identical frame bytes are valid.\n\
  Up to eight explicit source slots are allowed. Nested published manifests work;\n\
  every object in each selected closure must verify, including unused siblings.\n\
\n\
  The optional --expected-ledger-root pins the complete authority history and anchor.\n\
  The report always returns this pin; a second read must observe the same head.\n\
  Defaults: 1 MiB per journal read, 512 MiB charged custody reads, 16 MiB per object,\n\
  16384 custody objects, 64 MiB captured bytes, 64 MiB deletion metadata, 20000000\n\
  JPEG work units, 2 MiB report, 30000 ms. History replay additionally admits at most\n\
  256 batches, 16384 delta/child entries, 65536 snapshot entries and 4 MiB copied text.\n\
  Custody, deletion, graph copies and native work have separate nonrefillable budgets.\n\
  Journal reads are bounded separately and are not included in custody byte counters.\n\
  Timeout is cooperative: bounded filesystem calls/native replay are not preempted.\n\
\n\
  Exit 0 verifies the computation at an observed anchor. The belief stays Estimated,\n\
  Derived, uncalibrated and reference-only, with uncertainty [0,1]. NoActivity is NOT\n\
  absence, coverage, person detection or corroboration. No effect is authorized.\n\
  This operator-local metadata report is not a privacy-transformed evidence export\n\
  or agent-session response. No files, locks, repair, write or source bytes are emitted.\n\
  Missing/corrupt/deleted sources, drift and exhausted budgets refuse before stdout.\n";

struct Request {
    root: PathBuf,
    site: String,
    result: ContentDigest,
    reference_capsule: ContentDigest,
    source_slots: Vec<SlotName>,
    expected: Option<ContentDigest>,
    plan: ActivityReplayPlan,
    limits: ActivityVerificationLimits,
    report_limit: usize,
    timeout: Duration,
}

fn digest(value: &std::ffi::OsStr) -> Result<ContentDigest, CommandError> {
    let value =
        ContentDigest::parse(text(value)?).map_err(|_| CommandError::Usage("invalid digest"))?;
    if value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32] {
        return Err(CommandError::Usage("nonzero SHA-256 digest is required"));
    }
    Ok(value)
}

fn parse(args: &[OsString]) -> Result<Option<Request>, CommandError> {
    if args.len() > MAX_ARGS
        || args
            .iter()
            .any(|v| v.as_encoded_bytes().len() > MAX_ARG_BYTES)
    {
        return Err(CommandError::Usage(
            "argument count or length exceeds its bound",
        ));
    }
    if args.len() == 2
        && args[0] == "verify-activity"
        && matches!(args[1].to_str(), Some("--help" | "-h"))
    {
        return Ok(None);
    }
    if args.first().and_then(|v| v.to_str()) != Some("verify-activity") || args.len() % 2 != 1 {
        return Err(CommandError::Usage(
            "expected verify-activity and separate option/value pairs",
        ));
    }
    let (mut root, mut site, mut result, mut reference_capsule) = (None, None, None, None);
    let (mut sensor, mut stream, mut job, mut interpretation) = (None, None, None, None);
    let (mut macs, mut bytes, mut expected) = (None, None, None);
    let mut source_slots = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut limits = ActivityVerificationLimits::default();
    let mut policy_generation = 1;
    let mut threshold = 0.01_f32;
    let mut report_limit = MAX_REPORT_BYTES;
    let mut timeout = Duration::from_millis(30_000);
    for pair in args[1..].as_chunks::<2>().0 {
        let key = text(&pair[0])?;
        let value = &pair[1];
        if value.is_empty() || value.to_str().is_some_and(|v| v.starts_with("--")) {
            return Err(CommandError::Usage("missing option value"));
        }
        if key != "--source-slot" && !seen.insert(key) {
            return Err(CommandError::Usage("duplicate singleton option"));
        }
        match key {
            "--root" => root = Some(PathBuf::from(value)),
            "--site" => {
                let raw = text(value)?;
                if raw.len() > 256
                    || fss_reference::reference_deployment::validate_site_lineage(raw).is_err()
                {
                    return Err(CommandError::Usage("invalid bounded site lineage"));
                }
                site = Some(raw.to_owned());
            }
            "--result" => result = Some(digest(value)?),
            "--reference-capsule" => reference_capsule = Some(digest(value)?),
            "--expected-ledger-root" => expected = Some(digest(value)?),
            "--source-slot" => {
                let slot = SlotName::parse(text(value)?)
                    .map_err(|_| CommandError::Usage("invalid source slot"))?;
                if !source_slots.insert(slot) || source_slots.len() > MAX_ACTIVITY_SOURCE_SLOTS {
                    return Err(CommandError::Usage(
                        "source slots must be distinct and at most eight",
                    ));
                }
            }
            "--sensor" => {
                sensor = Some(
                    SensorId::parse(text(value)?)
                        .map_err(|_| CommandError::Usage("invalid sensor ID"))?,
                )
            }
            "--stream" => {
                stream = Some(
                    StreamId::parse(text(value)?)
                        .map_err(|_| CommandError::Usage("invalid stream ID"))?,
                )
            }
            "--job" => {
                let raw = text(value)?;
                if raw.len() > 256 || raw.chars().any(char::is_control) {
                    return Err(CommandError::Usage(
                        "job requires bounded non-control UTF-8",
                    ));
                }
                job = Some(raw.to_owned());
            }
            "--interpretation" => {
                interpretation = Some(match text(value)? {
                    "grayscale" => ComponentInterpretation::Grayscale,
                    "ycbcr" => ComponentInterpretation::YCbCr,
                    _ => {
                        return Err(CommandError::Usage(
                            "interpretation must be grayscale or ycbcr",
                        ));
                    }
                })
            }
            "--execution-macs" => macs = Some(number(value, 1, 1_000_000_000_000)?),
            "--execution-bytes" => bytes = Some(number(value, 1, 512 * 1024 * 1024)? as usize),
            "--policy-generation" => policy_generation = number(value, 1, u64::MAX)?,
            "--threshold-bits" => {
                let raw = text(value)?;
                if raw.len() != 8
                    || !raw
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                {
                    return Err(CommandError::Usage(
                        "threshold bits require eight lowercase hex digits",
                    ));
                }
                threshold = f32::from_bits(
                    u32::from_str_radix(raw, 16)
                        .map_err(|_| CommandError::Usage("invalid threshold bits"))?,
                );
            }
            "--max-journal-bytes" => {
                limits.history.max_journal_bytes = number(value, 1, 16 * 1024 * 1024)? as usize
            }
            "--max-custody-read-bytes" => {
                limits.verification.custody.max_read_bytes =
                    number(value, 1, 4 * 1024 * 1024 * 1024)?
            }
            "--max-object-bytes" => {
                let n = number(value, 1, 16 * 1024 * 1024)? as usize;
                limits.history.max_object_bytes = n;
                limits.verification.custody.max_object_bytes = n;
                limits.verification.graph.verification.max_root_bytes = n;
            }
            "--max-objects" => {
                let n = number(value, 1, 65_536)? as usize;
                limits.verification.custody.max_objects = n;
                limits.verification.graph.max_graph_objects = n;
            }
            "--max-retained-bytes" => {
                limits.verification.max_retained_bytes = number(value, 1, 64 * 1024 * 1024)?
            }
            "--max-deletion-bytes" => {
                limits.deletion.max_total_record_bytes =
                    number(value, 1, 64 * 1024 * 1024)? as usize
            }
            "--max-decode-work" => limits.max_decode_work = number(value, 0, 1_000_000_000)?,
            "--max-report-bytes" => {
                report_limit = number(value, 1024, MAX_REPORT_BYTES as u64)? as usize
            }
            "--timeout-ms" => timeout = Duration::from_millis(number(value, 1, 3_600_000)?),
            _ => return Err(CommandError::Usage("unknown or inapplicable option")),
        }
    }
    if source_slots.is_empty() {
        return Err(CommandError::Usage("--source-slot is required"));
    }
    let policy = ActivityThresholdPolicy::new(policy_generation, threshold)
        .map_err(|_| CommandError::Usage("threshold must be finite and nonnegative"))?;
    Ok(Some(Request {
        root: root.ok_or(CommandError::Usage("--root is required"))?,
        site: site.ok_or(CommandError::Usage("--site is required"))?,
        result: result.ok_or(CommandError::Usage("--result is required"))?,
        reference_capsule: reference_capsule
            .ok_or(CommandError::Usage("--reference-capsule is required"))?,
        source_slots: source_slots.into_iter().collect(),
        expected,
        plan: ActivityReplayPlan {
            sensor_id: sensor.ok_or(CommandError::Usage("--sensor is required"))?,
            stream_id: stream.ok_or(CommandError::Usage("--stream is required"))?,
            job_id: job.ok_or(CommandError::Usage("--job is required"))?,
            interpretation: interpretation
                .ok_or(CommandError::Usage("--interpretation is required"))?,
            execution: ExecBudget::new(
                macs.ok_or(CommandError::Usage("--execution-macs is required"))?,
                bytes.ok_or(CommandError::Usage("--execution-bytes is required"))?,
            ),
            policy,
        },
        limits,
        report_limit,
        timeout,
    }))
}

fn binding(role: &str, value: &ActivityEvidenceBinding) -> String {
    object(&[
        ("role", string(role)),
        ("digest", string(&value.digest.to_text())),
        ("authorityObject", string(value.authority.as_str())),
        (
            "authorityRoot",
            string(&value.revision.payload_digest.to_text()),
        ),
        ("authorityGeneration", value.revision.generation.to_string()),
    ])
}

fn render(request: &Request, value: &VerifiedActivityObservation) -> Result<String, CommandError> {
    let belief = value.belief();
    let result = value.result();
    let (outcome, score_bits) = match result.outcome {
        ExecutorModelOutcome::Activity { score_bits } => ("activity", score_bits),
        ExecutorModelOutcome::NoActivity { score_bits } => ("no_activity", score_bits),
        ExecutorModelOutcome::Abstained { .. } => {
            return Err(CommandError::Activity(
                "unscored activity cannot become verified cognition".to_owned(),
            ));
        }
    };
    let evidence = value.evidence();
    let roles = [
        ("result", &evidence.result),
        ("invocation", &evidence.invocation),
        ("frame_source", &evidence.frame_source),
        ("reference_source", &evidence.reference_source),
        ("frame_capsule", &evidence.frame_capsule),
        ("reference_capsule", &evidence.reference_capsule),
        ("frame_decode", &evidence.frame_decode),
        ("reference_decode", &evidence.reference_decode),
    ];
    let graph = value.graph_usage();
    let deletion = value.deletion_usage();
    let audit = value.custody();
    let limits = request.limits;
    let report = object(&[
        ("format", string("fss.activity_verification.v1")),
        ("verified", "true".to_owned()), ("site", string(&request.site)),
        ("anchor", evidence_anchor(belief.anchor())),
        ("ledger_root", string(&value.ledger_root().to_text())),
        ("sourceSlots", array(&request.source_slots.iter().map(|s| string(s.as_str())).collect::<Vec<_>>())),
        ("beliefId", string(belief.belief_id())), ("statement", string(belief.statement())),
        ("knowledgeState", string(belief.knowledge_state().as_str())), ("provenance", string(belief.provenance().as_str())),
        ("uncertainty", object(&[("lowerPpm", belief.uncertainty().lower_micro().to_string()), ("upperPpm", belief.uncertainty().upper_micro().to_string())])),
        ("referenceOnly", result.reference_only.to_string()),
        ("supportsAbsenceClaim", result.supports_absence_claim().to_string()),
        ("effectsAuthorized", "false".to_owned()),
        ("outcome", string(outcome)), ("scoreBits", string(&format!("{score_bits:08x}"))),
        ("modelGeneration", string(&result.model_generation)), ("modelDigest", string(&result.model_digest.to_text())),
        ("policyGeneration", result.threshold_policy_generation.to_string()),
        ("policyDigest", string(&result.threshold_policy_digest.to_text())),
        ("derivationReceipt", string(&belief.derivation_receipt().to_text())),
        ("roles", array(&roles.iter().map(|(name, role)| binding(name, role)).collect::<Vec<_>>())),
        ("usage", object(&[
            ("historyObservations", "2".to_owned()), ("historyBatches", deletion.history_batches.to_string()),
            ("deletionRecordReads", deletion.record_reads.to_string()), ("deletionRecordBytes", deletion.record_bytes.to_string()),
            ("custodyReadBytes", audit.charged_read_bytes().to_string()),
            ("custodyPeakReservedReadBytes", audit.peak_reserved_read_bytes().to_string()),
            ("custodyIoCalls", audit.io_calls().to_string()), ("custodyObjects", audit.objects().len().to_string()),
            ("graphReadAttempts", graph.read_attempts.to_string()), ("graphInputBytes", graph.admitted_bytes.to_string()),
            ("graphVisits", graph.visits.to_string()), ("derivations", graph.derivations.to_string()),
            ("decodeWork", value.decode_work().to_string()),
        ])),
        ("limits", object(&[
            ("journalBytesPerRead", limits.history.max_journal_bytes.to_string()),
            ("deletionRecordBytes", limits.deletion.max_total_record_bytes.to_string()),
            ("custodyReadBytes", limits.verification.custody.max_read_bytes.to_string()),
            ("objectBytes", limits.verification.custody.max_object_bytes.to_string()),
            ("custodyObjects", limits.verification.custody.max_objects.to_string()),
            ("capturedBytes", limits.verification.max_retained_bytes.to_string()),
            ("graphInputBytes", limits.verification.graph.verification.max_total_bytes.to_string()),
            ("decodeWork", limits.max_decode_work.to_string()),
            ("reportBytes", request.report_limit.to_string()),
        ])),
        ("limitations", strings(&[
            "computation verification is not physical truth, calibration, coverage, independence or absence".to_owned(),
            "custody and unchanged authority are sequential observations, not a future availability lease".to_owned(),
            "operator-local metadata; no export privacy transform or agent-session authority".to_owned(),
        ])),
    ]) + "\n";
    if report.len() > request.report_limit {
        return Err(CommandError::OutputBound);
    }
    Ok(report)
}

pub(super) fn run(args: &[OsString]) -> Result<String, CommandError> {
    let Some(request) = parse(args)? else {
        return Ok(HELP.to_owned());
    };
    let started = Instant::now();
    let cancelled = || started.elapsed() >= request.timeout;
    let verified = verify_retained_activity(
        ActivityVerificationRequest {
            root: &request.root,
            site: &request.site,
            expected_ledger_root: request.expected,
            result: request.result,
            reference_capsule: request.reference_capsule,
            source_slots: &request.source_slots,
            plan: request.plan.clone(),
        },
        &HostSpoolIo,
        request.limits,
        &ScalarExecCx::new(),
        &cancelled,
    )
    .map_err(|error| CommandError::Activity(error.to_string()))?;
    let report = render(&request, &verified)?;
    if cancelled() {
        return Err(CommandError::Stopped);
    }
    Ok(report)
}

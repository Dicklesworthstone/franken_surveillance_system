#![forbid(unsafe_code)]
//! Existing retained package output to the event evaluator, with complete native provenance.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Component, PathBuf};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, ClockBasis, ContentDigest, DigestAlgorithm, LedgerAnchor, OperationId,
    PrincipalId,
};
use fss_reference::ReplayCx;
use fss_reference::evaluation::{EvaluationPolicy, EventCandidate, FalseAlertBudget};
use fss_reference::ingest::package_evaluation::contract::{
    MAX_PACKAGE_EVALUATION_OUTPUT_BYTES, MAX_PACKAGE_EVALUATION_SOURCE_BYTES,
    PACKAGE_EVALUATION_LIMITATIONS, PackageEvaluationConfirmation, PackageEvaluationFrameBinding,
    PackageEvaluationProvenance, PackageEvaluationTrackProvenance,
};
use fss_reference::ingest::package_evaluation::{
    PackageEvaluationRequest, RETAINED_PACKAGE_EVALUATION_SCHEMA, RetainedPackageEvaluation,
};
use fss_reference::ingest::package_event::PackageTrackingConfig;

use super::{Failure, Result, array, integer, object, parse_labels, read_input, report_json, text};

const HELP: &str = "fss-evaluate retained-package --root ABSOLUTE_EXISTING_DIR --site SITE \
--labels LABELS.tsv --package-report SHA256 --label NATIVE_LABEL \
--clip-id CLIP --clip-origin-ns SIGNED_NS --stream-id STREAM --clock-basis BASIS \
--max-false-alerts N --per-observed-ns N \
[--confirmation-hits N] [--maximum-missed-frames N] [--minimum-iou-ppm N] \
[--early-tolerance-ns N] [--late-tolerance-ns N] \
[--maximum-source-bytes N] [--principal ID]\n\n\
Evaluates all tracks of one retained native label against one declared clip.\n\
Requires a complete report retained by fss-infer package-detect --retain yes.\n\
First confirmation uses its actual assigned F32 score; later samples never replace it.\n\
Labels must contain one matching clip and only unzoned truths of the selected native class.\n\
At least two analysed frames must have known singleton, increasing capture times.\n\
The declared [origin,origin+duration) window must fit within [first_sample,last_sample+1).\n\
Clock basis: utc_disciplined, device_monotonic, host_monotonic, or estimated.\n\
Tracker defaults: confirmation hits 2, maximum missed frames 1, minimum IoU 100000 ppm.\n\
Limits: 64 frames; 128 tracks, truths, and gaps; 16384 matching cells; 1 MiB JSON.\n\
Source reads share a nonrenewing maximum of 4 GiB across construction and revalidation.\n\
The local principal is an audit label, not remote authentication. Local store-opening\n\
housekeeping may recover publisher state. No evaluation, event, calibration, threshold,\n\
or external effect is published, activated, sent, or reconciled.\n\
Coverage remains caller-declared; scores remain uncalibrated. No model inference runs.\n";

struct Options {
    root: PathBuf,
    site: String,
    principal: String,
    labels: PathBuf,
    request: PackageEvaluationRequest,
    policy: EvaluationPolicy,
    maximum_source_bytes: u64,
}

fn value<'a>(values: &'a BTreeMap<String, OsString>, key: &str) -> Result<&'a str> {
    super::unicode(super::required(values, key)?)
}

fn signed(value: &str) -> Result<i128> {
    let digits = value.strip_prefix('-').unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Failure::new("evaluation.cli.invalid_integer"));
    }
    value
        .parse()
        .map_err(|_| Failure::new("evaluation.cli.invalid_integer"))
}

fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Option<Options>> {
    let mut bounded = Vec::new();
    for arg in args {
        if bounded.len() == 36 || arg.len() > 4096 {
            return Err(Failure::new("evaluation.cli.arguments_limit"));
        }
        bounded.push(arg);
    }
    if bounded.len() == 1 && bounded[0] == OsStr::new("--help") {
        return Ok(None);
    }
    let mut args = bounded.into_iter();
    let mut values = BTreeMap::new();
    while let Some(flag) = args.next() {
        let flag = super::unicode(&flag)?;
        if !matches!(
            flag,
            "--root"
                | "--site"
                | "--principal"
                | "--labels"
                | "--package-report"
                | "--label"
                | "--clip-id"
                | "--clip-origin-ns"
                | "--stream-id"
                | "--clock-basis"
                | "--confirmation-hits"
                | "--maximum-missed-frames"
                | "--minimum-iou-ppm"
                | "--max-false-alerts"
                | "--per-observed-ns"
                | "--early-tolerance-ns"
                | "--late-tolerance-ns"
                | "--maximum-source-bytes"
        ) {
            return Err(Failure::new("evaluation.cli.unknown_option"));
        }
        let next = args
            .next()
            .ok_or_else(|| Failure::new("evaluation.cli.missing_value"))?;
        if next.to_str().is_some_and(|next| next.starts_with("--")) {
            return Err(Failure::new("evaluation.cli.missing_value"));
        }
        if values.insert(flag.to_owned(), next).is_some() {
            return Err(Failure::new("evaluation.cli.duplicate_option"));
        }
    }
    let optional = |key: &str, default: u64| -> Result<u64> {
        values
            .get(key)
            .map_or(Ok(default), |input| integer(super::unicode(input)?))
    };
    let narrow = |key: &str, default: u64| -> Result<u32> {
        u32::try_from(optional(key, default)?)
            .map_err(|_| Failure::new("evaluation.cli.invalid_integer"))
    };
    let root = PathBuf::from(super::required(&values, "--root")?);
    if !root.is_absolute()
        || root
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(Failure::new("evaluation.retained.root"));
    }
    let site = value(&values, "--site")?.to_owned();
    if site.len() > 512
        || fss_reference::reference_deployment::validate_site_lineage(&site).is_err()
    {
        return Err(Failure::new("evaluation.retained.site"));
    }
    let principal = values
        .get("--principal")
        .map_or(Ok("principal:local-operator"), |principal| {
            super::unicode(principal)
        })?;
    if principal.len() > 512 || PrincipalId::parse(principal).is_err() {
        return Err(Failure::new("evaluation.retained.principal"));
    }
    let report_digest = ContentDigest::parse(value(&values, "--package-report")?)
        .map_err(|_| Failure::new("evaluation.retained.report_digest"))?;
    if report_digest.algorithm() != DigestAlgorithm::Sha256 {
        return Err(Failure::new("evaluation.retained.report_digest"));
    }
    let request = PackageEvaluationRequest {
        report_digest,
        label: value(&values, "--label")?.to_owned(),
        tracking: PackageTrackingConfig {
            confirmation_hits: narrow("--confirmation-hits", 2)?,
            maximum_missed_frames: narrow("--maximum-missed-frames", 1)?,
            minimum_iou_ppm: narrow("--minimum-iou-ppm", 100_000)?,
        },
        clip_id: value(&values, "--clip-id")?.to_owned(),
        clip_origin_ns: signed(value(&values, "--clip-origin-ns")?)?,
        stream_id: value(&values, "--stream-id")?.to_owned(),
        clock_basis: ClockBasis::parse(value(&values, "--clock-basis")?)
            .map_err(|_| Failure::new("evaluation.retained.clock_basis"))?,
    };
    request
        .validate()
        .map_err(|error| Failure::new(error.code()))?;
    let policy = EvaluationPolicy {
        early_tolerance_ns: optional("--early-tolerance-ns", 0)?,
        late_tolerance_ns: optional("--late-tolerance-ns", 0)?,
        false_alert_budget: FalseAlertBudget {
            max_false_alerts: integer(value(&values, "--max-false-alerts")?)?,
            per_observed_ns: integer(value(&values, "--per-observed-ns")?)?,
        },
    };
    if policy.false_alert_budget.per_observed_ns == 0 {
        return Err(Failure::new("evaluation.invalid_budget"));
    }
    let maximum_source_bytes = optional(
        "--maximum-source-bytes",
        MAX_PACKAGE_EVALUATION_SOURCE_BYTES,
    )?;
    if maximum_source_bytes == 0 || maximum_source_bytes > MAX_PACKAGE_EVALUATION_SOURCE_BYTES {
        return Err(Failure::new("evaluation.retained.source_limit"));
    }
    Ok(Some(Options {
        root,
        site,
        principal: principal.to_owned(),
        labels: PathBuf::from(super::required(&values, "--labels")?),
        request,
        policy,
        maximum_source_bytes,
    }))
}

fn digest(value: ContentDigest) -> String {
    text(&value.to_string())
}

fn decimal(value: impl ToString) -> String {
    text(&value.to_string())
}

fn anchor(value: &LedgerAnchor) -> String {
    object(&[
        ("site_lineage", text(&value.site_lineage)),
        ("ledger_epoch", decimal(value.ledger_epoch)),
        ("commit_sequence", decimal(value.commit_sequence)),
        (
            "adapter_registry_epoch",
            decimal(value.adapter_registry_epoch),
        ),
        ("schema_epoch", decimal(value.schema_epoch)),
        ("policy_epoch", decimal(value.policy_epoch)),
        ("privacy_epoch", decimal(value.privacy_epoch)),
        ("state_root", digest(value.state_root)),
    ])
}

fn frame(value: &PackageEvaluationFrameBinding) -> String {
    object(&[
        ("segment", decimal(value.segment)),
        ("capsule_digest", digest(value.capsule_digest)),
        ("source_digest", digest(value.source_digest)),
        ("sensor_id", text(&value.sensor_id)),
        ("stream_id", text(&value.stream_id)),
        ("sequence", decimal(value.sequence)),
        ("clock_basis", text(value.clock_basis.as_str())),
        (
            "capture_ns",
            array([
                decimal(value.capture.earliest.0),
                decimal(value.capture.latest.0),
            ]),
        ),
        ("gap_before", value.gap_before.to_string()),
    ])
}

fn confirmation(value: &PackageEvaluationConfirmation) -> String {
    object(&[
        ("observation_index", value.observation_index.to_string()),
        ("segment", decimal(value.segment)),
        ("capsule_digest", digest(value.capsule_digest)),
        ("source_digest", digest(value.source_digest)),
        ("inference_identity", digest(value.inference_identity)),
        ("output_digest", digest(value.output_digest)),
        (
            "detection_report_digest",
            digest(value.detection_report_digest),
        ),
        ("detection_row", decimal(value.detection_row)),
        ("class_index", decimal(value.class_index)),
        ("score_bits", value.score_bits.to_string()),
        ("score_ppm", value.score_ppm.to_string()),
        ("capture_ns", decimal(value.capture_ns)),
    ])
}

fn candidate(value: &EventCandidate) -> String {
    object(&[
        ("candidate_id", text(&value.candidate_id)),
        ("clip_id", text(&value.clip_id)),
        ("class", text(&value.class)),
        ("zone", "null".to_owned()),
        ("detect_ns", decimal(value.detect_ns)),
        ("score_ppm", value.score_ppm.to_string()),
    ])
}

fn track(value: &PackageEvaluationTrackProvenance) -> String {
    object(&[
        ("track", digest(value.track)),
        ("track_id", decimal(value.track_id)),
        ("observations", value.observations.to_string()),
        ("disposition", text(value.disposition.as_str())),
        (
            "first_confirmation",
            value
                .first_confirmation
                .as_ref()
                .map_or_else(|| "null".to_owned(), confirmation),
        ),
        (
            "candidate",
            value
                .candidate
                .as_ref()
                .map_or_else(|| "null".to_owned(), candidate),
        ),
    ])
}

fn provenance(value: &PackageEvaluationProvenance) -> String {
    let source = &value.source;
    let request = &value.request;
    object(&[
        ("site_lineage", text(&source.site_lineage)),
        ("principal", text(&source.principal)),
        ("authority_anchor", anchor(&source.authority_anchor)),
        ("retained_anchor", anchor(&source.retained_anchor)),
        ("package_report_digest", digest(request.report_digest)),
        ("analysis_digest", digest(source.analysis_digest)),
        ("record_digest", digest(source.record_digest)),
        ("retained_root", digest(source.retained_root)),
        ("package_digest", digest(value.package_digest)),
        ("manifest_digest", digest(value.manifest_digest)),
        ("model_id", text(&value.model_id)),
        ("model_generation", text(&value.model_generation)),
        ("model_digest", digest(value.model_digest)),
        ("graph_digest", digest(value.graph_digest)),
        ("contract_digest", digest(value.contract_digest)),
        ("label", text(&request.label)),
        ("class_index", decimal(value.class_index)),
        ("minimum_score_ppm", value.minimum_score_ppm.to_string()),
        ("import_identity", digest(value.import_identity)),
        ("import_root", digest(value.import_root)),
        (
            "import_manifest_digest",
            digest(source.import_manifest_digest),
        ),
        ("media_format", text(&value.media_format)),
        ("first_segment", decimal(value.first_segment)),
        ("segment_count", decimal(value.segment_count)),
        ("privacy_binding", digest(source.privacy_binding)),
        (
            "privacy_policy",
            source
                .privacy_policy
                .map_or_else(|| "null".to_owned(), digest),
        ),
        (
            "tracking",
            object(&[
                (
                    "confirmation_hits",
                    request.tracking.confirmation_hits.to_string(),
                ),
                (
                    "maximum_missed_frames",
                    request.tracking.maximum_missed_frames.to_string(),
                ),
                (
                    "minimum_iou_ppm",
                    request.tracking.minimum_iou_ppm.to_string(),
                ),
            ]),
        ),
        (
            "clip_mapping",
            object(&[
                ("clip_id", text(&request.clip_id)),
                ("clip_origin_ns", decimal(request.clip_origin_ns)),
                ("duration_ns", decimal(value.clip_duration_ns)),
                ("stream_id", text(&request.stream_id)),
                ("clock_basis", text(request.clock_basis.as_str())),
                ("capture_time_label", text(&source.capture_time_label)),
                (
                    "analysed_sample_hull_inclusive_ns",
                    array(value.analysed_sample_hull.map(decimal)),
                ),
                ("trailing_duration_inferred", "false".to_owned()),
            ]),
        ),
        (
            "non_container_omissions",
            source.non_container_omissions.to_string(),
        ),
        (
            "first_source_gap",
            source
                .first_source_gap
                .map_or_else(|| "null".to_owned(), decimal),
        ),
        (
            "tracking_boundaries",
            array(source.boundaries.iter().map(|boundary| {
                object(&[
                    ("before_segment", decimal(boundary.before_segment)),
                    ("source_gap", boundary.source_gap.to_string()),
                    ("sequence_gap", boundary.sequence_gap.to_string()),
                    (
                        "dimensions_changed",
                        boundary.dimensions_changed.to_string(),
                    ),
                ])
            })),
        ),
        ("frames", array(source.frames.iter().map(frame))),
        ("tracks", array(value.tracks.iter().map(track))),
    ])
}

fn output(value: &RetainedPackageEvaluation) -> Result<String> {
    let result = object(&[
        ("schema", text(RETAINED_PACKAGE_EVALUATION_SCHEMA)),
        ("derived_only", "true".to_owned()),
        ("coverage_basis", text("caller_declared")),
        ("threshold_activated", "false".to_owned()),
        ("model_inference_executed", "false".to_owned()),
        ("external_effects_reconciled", "false".to_owned()),
        ("evaluation_published", "false".to_owned()),
        ("opening_housekeeping", text("existing_publisher_recovery")),
        ("result_digest", digest(value.digest())),
        ("projection_digest", digest(value.projection().digest)),
        ("source_bytes_read", decimal(value.source_bytes_read())),
        (
            "maximum_source_bytes",
            decimal(value.maximum_source_bytes()),
        ),
        ("source_verification_passes", "2".to_owned()),
        ("provenance", provenance(&value.projection().provenance)),
        ("evaluation", report_json(value.report())),
        (
            "limitations",
            array(
                PACKAGE_EVALUATION_LIMITATIONS
                    .iter()
                    .map(|value| text(value)),
            ),
        ),
    ]);
    if result.len() > MAX_PACKAGE_EVALUATION_OUTPUT_BYTES {
        return Err(Failure::new("evaluation.retained.output_limit"));
    }
    Ok(result)
}

pub(super) fn run(args: impl IntoIterator<Item = OsString>) -> Result<String> {
    let Some(options) = parse(args)? else {
        return Ok(HELP.to_owned());
    };
    // The local process and filesystem authorize the read. The principal is only its audit
    // label; no supplied ID authenticates a remote party, and no effect capability is granted.
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:retained-package-evaluation".into(),
        operation_id: OperationId::parse("operation:retained-package-evaluation")
            .map_err(|_| Failure::new("evaluation.retained.authority"))?,
        principal: options.principal,
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(options.maximum_source_bytes + 8 * 1024 * 1024)
            .storage_operations(65_536)
            .build()
            .map_err(|_| Failure::new("evaluation.retained.authority"))?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })
    .map_err(|_| Failure::new("evaluation.retained.authority"))?;
    let cx = ReplayCx::from_context_authority_read_only(&authority, options.root.clone())
        .map_err(|_| Failure::new("evaluation.retained.authority"))?;
    let result = (|| {
        cx.checkpoint("evaluation_cli:labels")
            .map_err(|_| Failure::new("evaluation.cancelled"))?;
        let labels = parse_labels(&read_input(&options.labels)?)?;
        let evaluated = RetainedPackageEvaluation::open(
            &options.root,
            &options.site,
            &options.request,
            &labels,
            &options.policy,
            options.maximum_source_bytes,
            &cx,
        )
        .map_err(|error| Failure::new(error.code()))?;
        let result = output(&evaluated)?;
        cx.checkpoint("evaluation_cli:complete")
            .map_err(|_| Failure::new("evaluation.cancelled"))?;
        Ok(result)
    })();
    cx.drain_and_finalize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments() -> Vec<OsString> {
        let digest = ContentDigest::sha256(b"retained report").to_string();
        [
            "--root",
            "/existing",
            "--site",
            "site:evaluation",
            "--labels",
            "labels.tsv",
            "--package-report",
            &digest,
            "--label",
            "person",
            "--clip-id",
            "clip",
            "--clip-origin-ns",
            "-100",
            "--stream-id",
            "stream:evaluation",
            "--clock-basis",
            "estimated",
            "--max-false-alerts",
            "0",
            "--per-observed-ns",
            "1000000000",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    #[test]
    fn explicit_source_clock_and_signed_origin_are_preserved() -> Result<()> {
        let options = parse(arguments())?.ok_or_else(|| Failure::new("test.missing_options"))?;
        assert_eq!(options.request.clip_origin_ns, -100);
        assert_eq!(options.request.stream_id, "stream:evaluation");
        assert_eq!(options.request.clock_basis, ClockBasis::Estimated);
        assert_eq!(options.request.tracking.confirmation_hits, 2);
        assert_eq!(
            options.maximum_source_bytes,
            MAX_PACKAGE_EVALUATION_SOURCE_BYTES
        );
        Ok(())
    }

    #[test]
    fn fabricated_generations_calibration_and_manual_candidates_are_refused() {
        for flag in [
            "--pipeline-generation",
            "--model-generation",
            "--policy-generation",
            "--calibration-generation",
            "--candidates",
            "--track",
        ] {
            let mut args = arguments();
            args.extend([OsString::from(flag), OsString::from("caller-supplied")]);
            assert!(matches!(
                parse(args),
                Err(Failure {
                    code: "evaluation.cli.unknown_option",
                    ..
                })
            ));
        }
    }

    #[test]
    fn relative_roots_unknown_clocks_and_source_limit_escalation_are_refused() {
        for (flag, replacement, code) in [
            ("--root", "relative", "evaluation.retained.root"),
            (
                "--clock-basis",
                "synchronized",
                "evaluation.retained.clock_basis",
            ),
            ("--clip-origin-ns", "+100", "evaluation.cli.invalid_integer"),
        ] {
            let mut args = arguments();
            if let Some(index) = args.iter().position(|arg| arg == flag) {
                args[index + 1] = replacement.into();
            }
            assert!(matches!(parse(args), Err(error) if error.code == code));
        }
        let mut args = arguments();
        args.extend([
            OsString::from("--maximum-source-bytes"),
            OsString::from((MAX_PACKAGE_EVALUATION_SOURCE_BYTES + 1).to_string()),
        ]);
        assert!(matches!(
            parse(args),
            Err(Failure {
                code: "evaluation.retained.source_limit",
                ..
            })
        ));
    }
}

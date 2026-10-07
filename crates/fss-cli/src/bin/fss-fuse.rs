#![forbid(unsafe_code)]
//! Offline, read-only adapter for the reference evidence fusion rule (`fss-fusion`).
//!
//! Reads one fusion query (JSON) and optionally a score calibration (the `fss-evaluate
//! --calibration-bins` report, rebuilt from its per-bin counts and refused unless its digest
//! matches), and prints the digest-bound decision as JSON. It decides nothing durable: no
//! event is published, no threshold is activated, no alert is prepared or sent.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

use fss_cli::escape_json_str;
use fss_cli::json_input::{Value, read_document};
use fss_fusion::{
    Calibration, Coverage, Decision, EvidenceItem, FusionOutcome, FusionPolicy, FusionQuery,
    LlrInterval, Observability, Opportunity, Probe, ScoreCalibration, Severity, fuse,
};

const HELP: &str = "fss-fuse --query QUERY.json|- [--calibration EVALUATION.json]\n\n\
Read-only evidence fusion; prints a fss.fusion_outcome.v1 JSON decision to stdout. Nothing is\n\
published, activated or sent; a decision grants no effect authority.\n\n\
Query (schema fss.fusion_query.v1): hypothesis, kind, prior ([lo, hi] millibans or\n\
\"calibration\"), coverage ({state: complete|degraded|gap, reason}), looks, now_ns,\n\
severity {expected_harm, false_alert_cost, delay_cost_per_second, reversible}, policy\n\
{generation, alert_threshold, retain_threshold, reject_threshold, min_independent_support,\n\
urgent_single_domain_threshold|null, max_wait_ns, look_penalty_per_doubling,\n\
operator_confirmation_available}, evidence [{id, sensor, failure_domains[], observability:\n\
observed|redacted|stale|{not_observable: reason}, calibration: {generation, llr: [lo, hi]} |\n\
{uncalibrated: reason} | {score_ppm: N}}], opportunities [{id, sensor, failure_domains[],\n\
window_start_ns, window_end_ns, positive: [lo, hi], negative: [lo, hi]}], probes [{id, kind,\n\
failure_domains[], cost, latency_ns, positive, negative}]. Log-likelihood ratios are integer\n\
millibans (thousandths of log10 odds). A score_ppm needs --calibration.\n";

/// A typed refusal: a stable code and a short detail (never document bytes).
struct Failure {
    code: String,
    detail: String,
}

fn fail(code: &str, detail: impl Into<String>) -> Failure {
    Failure {
        code: code.to_owned(),
        detail: detail.into(),
    }
}

type Result<T> = std::result::Result<T, Failure>;

fn field<'a>(object: &'a BTreeMap<String, Value>, key: &str) -> Result<&'a Value> {
    object
        .get(key)
        .ok_or_else(|| fail("fusion.cli.missing_field", key))
}

fn as_object<'a>(value: &'a Value, what: &str) -> Result<&'a BTreeMap<String, Value>> {
    value
        .object()
        .ok_or_else(|| fail("fusion.cli.expected_object", what))
}

fn as_text(value: &Value, what: &str) -> Result<String> {
    value
        .text()
        .map(str::to_owned)
        .ok_or_else(|| fail("fusion.cli.expected_string", what))
}

fn as_integer<T: TryFrom<i128>>(value: &Value, what: &str) -> Result<T> {
    value
        .integer()
        .and_then(|number| T::try_from(number).ok())
        .ok_or_else(|| fail("fusion.cli.expected_integer", what))
}

fn as_bool(value: &Value, what: &str) -> Result<bool> {
    value
        .boolean()
        .ok_or_else(|| fail("fusion.cli.expected_boolean", what))
}

fn interval(value: &Value, what: &str) -> Result<LlrInterval> {
    let items = value
        .array()
        .filter(|items| items.len() == 2)
        .ok_or_else(|| fail("fusion.cli.expected_interval", what))?;
    LlrInterval::new(as_integer(&items[0], what)?, as_integer(&items[1], what)?)
        .map_err(|error| fail(error.stable_id(), what))
}

fn domains(value: &Value, what: &str) -> Result<BTreeSet<String>> {
    let items = value
        .array()
        .ok_or_else(|| fail("fusion.cli.expected_array", what))?;
    items.iter().map(|item| as_text(item, what)).collect()
}

fn items<'a>(object: &'a BTreeMap<String, Value>, key: &str) -> Result<&'a [Value]> {
    match object.get(key) {
        None => Ok(&[]),
        Some(value) => value
            .array()
            .ok_or_else(|| fail("fusion.cli.expected_array", key)),
    }
}

fn load_calibration(path: &str) -> Result<ScoreCalibration> {
    let document =
        read_document(path).map_err(|detail| fail("fusion.cli.calibration_unreadable", detail))?;
    let top = as_object(&document, "calibration")?;
    let object = match top.get("score_calibration") {
        Some(inner) => as_object(inner, "score_calibration")?,
        None => top,
    };
    if object.get("schema").and_then(Value::text) != Some("fss.score_calibration.v1") {
        return Err(fail(
            "fusion.cli.calibration_schema",
            "expected fss.score_calibration.v1",
        ));
    }
    let generation = as_text(field(object, "generation")?, "generation")?;
    let mut edges = Vec::new();
    let mut counts = Vec::new();
    for bin in items(object, "bins")? {
        let bin = as_object(bin, "bin")?;
        edges.push(as_integer(field(bin, "lo_ppm")?, "lo_ppm")?);
        counts.push((
            as_integer(field(bin, "true_positives")?, "true_positives")?,
            as_integer(field(bin, "false_positives")?, "false_positives")?,
        ));
    }
    let calibration = ScoreCalibration::from_counts(&generation, &edges, &counts)
        .map_err(|error| fail(error.stable_id(), "score calibration"))?;
    let declared = as_text(field(object, "digest")?, "digest")?;
    if declared != calibration.digest.to_text() {
        return Err(fail(
            "fusion.cli.calibration_digest_mismatch",
            "the calibration does not reproduce its declared digest",
        ));
    }
    Ok(calibration)
}

fn parse_query(document: &Value, calibration: Option<&ScoreCalibration>) -> Result<FusionQuery> {
    let query = as_object(document, "query")?;
    if query.get("schema").and_then(Value::text) != Some("fss.fusion_query.v1") {
        return Err(fail(
            "fusion.cli.query_schema",
            "expected fss.fusion_query.v1",
        ));
    }
    let need_calibration = || {
        calibration.ok_or_else(|| {
            fail(
                "fusion.cli.calibration_required",
                "score_ppm or a calibration prior needs --calibration",
            )
        })
    };
    let prior = match field(query, "prior")? {
        Value::Text(text) if text == "calibration" => need_calibration()?.prior,
        value => interval(value, "prior")?,
    };
    let coverage = {
        let coverage = as_object(field(query, "coverage")?, "coverage")?;
        let reason =
            || -> Result<String> { as_text(field(coverage, "reason")?, "coverage reason") };
        match as_text(field(coverage, "state")?, "coverage state")?.as_str() {
            "complete" => Coverage::Complete,
            "degraded" => Coverage::Degraded { reason: reason()? },
            "gap" => Coverage::Gap { reason: reason()? },
            other => return Err(fail("fusion.cli.coverage_state", other)),
        }
    };
    let severity = {
        let s = as_object(field(query, "severity")?, "severity")?;
        Severity {
            expected_harm: as_integer(field(s, "expected_harm")?, "expected_harm")?,
            false_alert_cost: as_integer(field(s, "false_alert_cost")?, "false_alert_cost")?,
            delay_cost_per_second: as_integer(
                field(s, "delay_cost_per_second")?,
                "delay_cost_per_second",
            )?,
            reversible: as_bool(field(s, "reversible")?, "reversible")?,
        }
    };
    let policy = {
        let p = as_object(field(query, "policy")?, "policy")?;
        FusionPolicy {
            generation: as_text(field(p, "generation")?, "policy generation")?,
            alert_threshold: as_integer(field(p, "alert_threshold")?, "alert_threshold")?,
            retain_threshold: as_integer(field(p, "retain_threshold")?, "retain_threshold")?,
            reject_threshold: as_integer(field(p, "reject_threshold")?, "reject_threshold")?,
            min_independent_support: as_integer(
                field(p, "min_independent_support")?,
                "min_independent_support",
            )?,
            urgent_single_domain_threshold: match p.get("urgent_single_domain_threshold") {
                None | Some(Value::Null) => None,
                Some(value) => Some(as_integer(value, "urgent_single_domain_threshold")?),
            },
            max_wait_ns: as_integer(field(p, "max_wait_ns")?, "max_wait_ns")?,
            look_penalty_per_doubling: as_integer(
                field(p, "look_penalty_per_doubling")?,
                "look_penalty_per_doubling",
            )?,
            operator_confirmation_available: as_bool(
                field(p, "operator_confirmation_available")?,
                "operator_confirmation_available",
            )?,
        }
    };
    let mut evidence = Vec::new();
    for item in items(query, "evidence")? {
        let item = as_object(item, "evidence")?;
        let observability = match field(item, "observability")? {
            Value::Text(state) => match state.as_str() {
                "observed" => Observability::Observed,
                "redacted" => Observability::Redacted,
                "stale" => Observability::Stale,
                other => return Err(fail("fusion.cli.observability", other)),
            },
            value => {
                let object = as_object(value, "observability")?;
                Observability::NotObservable {
                    reason: as_text(field(object, "not_observable")?, "not_observable")?,
                }
            }
        };
        let calibration_value = as_object(field(item, "calibration")?, "calibration")?;
        let item_calibration = if let Some(score) = calibration_value.get("score_ppm") {
            need_calibration()?.calibrate(as_integer(score, "score_ppm")?)
        } else if let Some(reason) = calibration_value.get("uncalibrated") {
            Calibration::Uncalibrated {
                reason: as_text(reason, "uncalibrated")?,
            }
        } else {
            Calibration::Calibrated {
                generation: as_text(
                    field(calibration_value, "generation")?,
                    "calibration generation",
                )?,
                llr: interval(field(calibration_value, "llr")?, "llr")?,
            }
        };
        evidence.push(EvidenceItem {
            id: as_text(field(item, "id")?, "evidence id")?,
            sensor: as_text(field(item, "sensor")?, "sensor")?,
            failure_domains: domains(field(item, "failure_domains")?, "failure_domains")?,
            calibration: item_calibration,
            observability,
        });
    }
    let mut opportunities = Vec::new();
    for item in items(query, "opportunities")? {
        let item = as_object(item, "opportunity")?;
        opportunities.push(Opportunity {
            id: as_text(field(item, "id")?, "opportunity id")?,
            sensor: as_text(field(item, "sensor")?, "sensor")?,
            failure_domains: domains(field(item, "failure_domains")?, "failure_domains")?,
            window_start: as_integer(field(item, "window_start_ns")?, "window_start_ns")?,
            window_end: as_integer(field(item, "window_end_ns")?, "window_end_ns")?,
            positive: interval(field(item, "positive")?, "positive")?,
            negative: interval(field(item, "negative")?, "negative")?,
        });
    }
    let mut probes = Vec::new();
    for item in items(query, "probes")? {
        let item = as_object(item, "probe")?;
        probes.push(Probe {
            id: as_text(field(item, "id")?, "probe id")?,
            kind: as_text(field(item, "kind")?, "probe kind")?,
            failure_domains: domains(field(item, "failure_domains")?, "failure_domains")?,
            cost: as_integer(field(item, "cost")?, "cost")?,
            latency_ns: as_integer(field(item, "latency_ns")?, "latency_ns")?,
            positive: interval(field(item, "positive")?, "positive")?,
            negative: interval(field(item, "negative")?, "negative")?,
        });
    }
    Ok(FusionQuery {
        hypothesis: as_text(field(query, "hypothesis")?, "hypothesis")?,
        kind: as_text(field(query, "kind")?, "kind")?,
        prior,
        evidence,
        coverage,
        opportunities,
        probes,
        severity,
        policy,
        looks: as_integer(field(query, "looks")?, "looks")?,
        now_ns: as_integer(field(query, "now_ns")?, "now_ns")?,
    })
}

fn text(value: &str) -> String {
    format!("\"{}\"", escape_json_str(value))
}

fn object(fields: &[(&str, String)]) -> String {
    format!(
        "{{{}}}",
        fields
            .iter()
            .map(|(key, value)| format!("{}:{value}", text(key)))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn array(values: impl IntoIterator<Item = String>) -> String {
    format!("[{}]", values.into_iter().collect::<Vec<_>>().join(","))
}

fn pair(interval: LlrInterval) -> String {
    format!("[{},{}]", interval.lo(), interval.hi())
}

fn decision_json(decision: &Decision) -> String {
    let mut fields = vec![("kind", text(decision.as_str()))];
    match decision {
        Decision::WaitForCorroboration {
            opportunity,
            deadline_ns,
            value_bound,
        } => {
            fields.push(("opportunity", text(opportunity)));
            fields.push(("deadline_ns", text(&deadline_ns.to_string())));
            fields.push(("value_bound", value_bound.to_string()));
        }
        Decision::RequestObservation { probe, value_bound } => {
            fields.push(("probe", text(probe)));
            fields.push(("value_bound", value_bound.to_string()));
        }
        _ => {}
    }
    object(&fields)
}

fn outcome_json(outcome: &FusionOutcome, calibration: Option<&ScoreCalibration>) -> String {
    let optional = |value: Option<i64>| value.map_or_else(|| "null".to_owned(), |v| v.to_string());
    object(&[
        ("schema", text("fss.fusion_outcome.v1")),
        ("implementation", text(fss_fusion::IMPLEMENTATION_ID)),
        ("query_digest", text(&outcome.query_digest.to_text())),
        ("decision_digest", text(&outcome.decision_digest.to_text())),
        ("policy_generation", text(&outcome.policy_generation)),
        (
            "score_calibration_digest",
            calibration.map_or_else(|| "null".to_owned(), |c| text(&c.digest.to_text())),
        ),
        ("decision", decision_json(&outcome.decision)),
        (
            "reasons",
            array(outcome.reasons.iter().map(|reason| text(reason.as_str()))),
        ),
        ("knowledge_state", text(outcome.knowledge_state)),
        ("provenance_class", text("derived")),
        ("posterior_log_odds_millibans", pair(outcome.posterior)),
        (
            "probability_ppm",
            format!(
                "[{},{}]",
                outcome.probability_ppm.0, outcome.probability_ppm.1
            ),
        ),
        (
            "sequential_alert_threshold",
            outcome.sequential_alert_threshold.to_string(),
        ),
        (
            "supporting_clusters",
            outcome.supporting_clusters.to_string(),
        ),
        (
            "contradicting_clusters",
            outcome.contradicting_clusters.to_string(),
        ),
        ("support_to_alert", optional(outcome.support_to_alert)),
        ("reduction_to_retain", optional(outcome.reduction_to_retain)),
        (
            "clusters",
            array(outcome.clusters.iter().map(|cluster| {
                object(&[
                    ("label", cluster.label.to_string()),
                    ("members", array(cluster.members.iter().map(|m| text(m)))),
                    (
                        "failure_domains",
                        array(cluster.failure_domains.iter().map(|d| text(d))),
                    ),
                    ("llr_millibans", pair(cluster.llr)),
                    ("direction", text(cluster.direction.as_str())),
                ])
            })),
        ),
        (
            "excluded",
            array(
                outcome
                    .excluded
                    .iter()
                    .map(|(id, reason)| object(&[("id", text(id)), ("reason", text(reason))])),
            ),
        ),
        (
            "uncalibrated",
            array(outcome.uncalibrated.iter().map(|id| text(id))),
        ),
        (
            "counterfactuals",
            array(outcome.counterfactuals.iter().map(|counterfactual| {
                object(&[
                    (
                        "removed_cluster",
                        counterfactual.removed_cluster.to_string(),
                    ),
                    (
                        "posterior_log_odds_millibans",
                        pair(counterfactual.posterior),
                    ),
                    ("decision", decision_json(&counterfactual.decision)),
                ])
            })),
        ),
        ("effect_authority", "false".to_owned()),
    ])
}

fn run(args: Vec<OsString>) -> Result<String> {
    if args.len() > 4 {
        return Err(fail("fusion.cli.arguments_limit", "too many arguments"));
    }
    if args.len() == 1 && args[0] == "--help" {
        return Ok(HELP.to_owned());
    }
    let mut values: BTreeMap<String, String> = BTreeMap::new();
    let mut iter = args.into_iter();
    while let Some(flag) = iter.next() {
        let flag = flag
            .into_string()
            .map_err(|_| fail("fusion.cli.invalid_unicode", "argument"))?;
        if !matches!(flag.as_str(), "--query" | "--calibration") {
            return Err(fail("fusion.cli.unknown_option", flag));
        }
        let value = iter
            .next()
            .and_then(|value| value.into_string().ok())
            .filter(|value| !value.starts_with("--"))
            .ok_or_else(|| fail("fusion.cli.missing_value", flag.clone()))?;
        if values.insert(flag.clone(), value).is_some() {
            return Err(fail("fusion.cli.duplicate_option", flag));
        }
    }
    let query_path = values
        .get("--query")
        .ok_or_else(|| fail("fusion.cli.missing_option", "--query"))?;
    let calibration = values
        .get("--calibration")
        .map(|path| load_calibration(path))
        .transpose()?;
    let document =
        read_document(query_path).map_err(|detail| fail("fusion.cli.query_unreadable", detail))?;
    let query = parse_query(&document, calibration.as_ref())?;
    let outcome = fuse(&query).map_err(|error| fail(error.stable_id(), error.to_string()))?;
    Ok(outcome_json(&outcome, calibration.as_ref()))
}

fn main() -> ExitCode {
    match run(std::env::args_os().skip(1).collect()) {
        Ok(output) => {
            if writeln!(io::stdout().lock(), "{output}").is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(failure) => {
            let diagnostic = object(&[
                ("schema", text("fss.fusion.cli_error.v1")),
                ("code", text(&failure.code)),
                ("detail", text(&failure.detail)),
                ("effect_started", "false".to_owned()),
            ]);
            let _ = writeln!(io::stderr().lock(), "{diagnostic}");
            ExitCode::from(2)
        }
    }
}

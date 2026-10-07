#![forbid(unsafe_code)]
//! Offline, read-only adapter for the reference evidence fusion rule (`fss-fusion`).
//!
//! Reads one fusion query (JSON) and up to sixteen score calibrations (the `fss-evaluate
//! --calibration-bins` reports, rebuilt from their per-bin counts and refused unless their
//! digests match). Every raw score names its exact calibration generation and digest. It
//! prints a decision and the selected calibration provenance as JSON, with no durable effect:
//! no event is published, no threshold is activated, no alert is prepared or sent.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

use fss_cli::escape_json_str;
use fss_cli::json_input::{Value, read_document};
use fss_core::{CanonicalEncoder, ContentDigest};
use fss_fusion::{
    Calibration, Coverage, Decision, EvidenceItem, FusionOutcome, FusionPolicy, FusionQuery,
    LlrInterval, Observability, Opportunity, Probe, ScoreCalibration, Severity, fuse,
};
use fss_graph_algorithms::certified::Budget;
use fss_graph_algorithms::temporal::{
    self, Reachability, TemporalNetworkBuilder, TemporalOutput, Transit,
};

/// Operation budget of one transit reachability run (fails closed beyond it).
const TRANSIT_OPERATIONS: u64 = 20_000_000;
/// Interval cap of one transit presence set.
const TRANSIT_INTERVALS: u32 = 4_096;
/// Maximum independently named calibration artifacts accepted by one invocation.
const MAX_CALIBRATIONS: usize = 16;

const HELP: &str = "fss-fuse --query QUERY.json|- [--calibration EVALUATION.json]...\n\n\
Read-only evidence fusion; prints a fss.fusion_outcome.v1 JSON decision to stdout. Nothing is\n\
published, activated or sent; a decision grants no effect authority.\n\n\
Query (schema fss.fusion_query.v2; v1 remains readable): hypothesis, kind, prior ([lo, hi]\n\
millibans, {generation, digest}, or\n\
\"calibration\" with exactly one loaded artifact), coverage ({state: complete|degraded|gap, reason}), looks, now_ns,\n\
severity {expected_harm, false_alert_cost, delay_cost_per_second, reversible}, policy\n\
{generation, alert_threshold, retain_threshold, reject_threshold, min_independent_support,\n\
urgent_single_domain_threshold|null, max_wait_ns, look_penalty_per_doubling,\n\
operator_confirmation_available}, evidence [{id, sensor, failure_domains[], observability:\n\
observed|redacted|stale|{not_observable: reason}, calibration: {generation, llr: [lo, hi]} |\n\
{uncalibrated: reason} | {score_ppm: N, generation, digest}}], opportunities [{id, sensor, failure_domains[],\n\
window_start_ns, window_end_ns, positive: [lo, hi], negative: [lo, hi]}], probes [{id, kind,\n\
failure_domains[], cost, latency_ns, positive, negative}]. Log-likelihood ratios are integer\n\
millibans (thousandths of log10 odds). A score_ppm needs its exact --calibration artifact.\n\
Repeat --calibration up to 16 times for distinct producers; raw scores without an explicit\n\
generation and digest are refused, including legacy v1 scores. Reusing one artifact shares a\n\
common-cause domain. Caller-declared score spaces do not establish deployment qualification.\n\n\
Optional transit {origin: {zone, earliest_ns, latest_ns}, zones: [{id, max_wait_ns}],\n\
transits: [{from, to, open_ns, close_ns, min_travel_ns, max_travel_ns}], observers: [{zone,\n\
sensor, failure_domains[], positive, negative}]}: exact temporal reachability (ALG-TREACH-001)\n\
from the origin's capture interval turns each observer whose zone the entity can reach within\n\
policy.max_wait_ns into a corroboration opportunity over the reachable window; observers it\n\
cannot reach in time are reported as temporally_infeasible or no_path, never waited for.\n";

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

/// Calibrations are selected by content identity, never by argument order.
type Calibrations = BTreeMap<String, ScoreCalibration>;

#[derive(Clone)]
struct CalibrationIdentity {
    generation: String,
    digest: ContentDigest,
}

impl CalibrationIdentity {
    fn of(calibration: &ScoreCalibration) -> Self {
        Self {
            generation: calibration.generation.clone(),
            digest: calibration.digest,
        }
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.generation);
        encoder.digest(self.digest);
    }

    fn to_json(&self) -> String {
        object(&[
            ("generation", text(&self.generation)),
            ("digest", text(&self.digest.to_text())),
        ])
    }
}

struct ScoreBinding {
    evidence_id: String,
    score_ppm: u32,
    calibration: CalibrationIdentity,
}

/// Adapter provenance retains inputs lost when scores and priors become LLR intervals.
#[derive(Default)]
struct CalibrationBindings {
    prior: Option<CalibrationIdentity>,
    scores: Vec<ScoreBinding>,
}

impl CalibrationBindings {
    fn digest(&self, query_digest: ContentDigest) -> Result<ContentDigest> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.fusion.calibrated_input.v1");
        encoder.digest(query_digest);
        encoder.bool(self.prior.is_some());
        if let Some(prior) = &self.prior {
            prior.encode(&mut encoder);
        }
        encoder.u64(self.scores.len() as u64);
        for score in &self.scores {
            encoder.text(&score.evidence_id);
            encoder.u32(score.score_ppm);
            score.calibration.encode(&mut encoder);
        }
        let bytes = encoder.finish_checked().map_err(|_| {
            fail(
                "fusion.cli.binding_encoding",
                "calibration provenance exceeds canonical encoding bounds",
            )
        })?;
        Ok(ContentDigest::sha256(&bytes))
    }

    fn scores_json(&self) -> String {
        array(self.scores.iter().map(|score| {
            object(&[
                ("evidence_id", text(&score.evidence_id)),
                ("score_ppm", score.score_ppm.to_string()),
                ("calibration", score.calibration.to_json()),
            ])
        }))
    }
}

fn select_calibration<'a>(
    binding: &BTreeMap<String, Value>,
    calibrations: &'a Calibrations,
) -> Result<&'a ScoreCalibration> {
    if calibrations.is_empty() {
        return Err(fail(
            "fusion.cli.calibration_required",
            "score_ppm or a calibration prior needs --calibration",
        ));
    }
    let generation = binding.get("generation").and_then(Value::text);
    let digest = binding.get("digest").and_then(Value::text);
    let (Some(generation), Some(digest)) = (generation, digest) else {
        return Err(fail(
            "fusion.cli.calibration_binding_required",
            "a raw score or calibration prior must name its generation and digest",
        ));
    };
    let selected = calibrations.get(digest).ok_or_else(|| {
        fail(
            "fusion.cli.calibration_unknown",
            "the named calibration digest was not loaded",
        )
    })?;
    if generation != selected.generation {
        return Err(fail(
            "fusion.cli.calibration_generation_mismatch",
            "the named generation does not match the selected calibration artifact",
        ));
    }
    Ok(selected)
}

fn implicit_prior(calibrations: &Calibrations) -> Result<&ScoreCalibration> {
    if calibrations.is_empty() {
        return Err(fail(
            "fusion.cli.calibration_required",
            "a calibration prior needs --calibration",
        ));
    }
    if calibrations.len() != 1 {
        return Err(fail(
            "fusion.cli.prior_ambiguous",
            "with multiple artifacts the prior must name its generation and digest",
        ));
    }
    calibrations.values().next().ok_or_else(|| {
        fail(
            "fusion.cli.calibration_required",
            "a calibration prior needs --calibration",
        )
    })
}

/// One observer of the transit plan and what reachability says about it.
struct TransitObserver {
    zone: String,
    sensor: String,
    reachability: Reachability,
    presence: Vec<(u64, u64)>,
    window: Option<(u64, u64)>,
}

/// The transit-derived corroboration plan of one query.
struct TransitPlan {
    origin: String,
    start: (u64, u64),
    horizon: u64,
    observers: Vec<TransitObserver>,
    output_digest: String,
    decision_path_digest: String,
}

fn parse_transit(
    transit: &BTreeMap<String, Value>,
    now: u64,
    max_wait: u64,
    opportunities: &mut Vec<Opportunity>,
) -> Result<TransitPlan> {
    let horizon = now.checked_add(max_wait).ok_or_else(|| {
        fail(
            "fusion.cli.transit_horizon",
            "now_ns + max_wait_ns overflows",
        )
    })?;
    let mut builder = TemporalNetworkBuilder::new("ns", horizon);
    for zone in items(transit, "zones")? {
        let zone = as_object(zone, "zone")?;
        builder.add_node(
            as_text(field(zone, "id")?, "zone id")?,
            as_integer(field(zone, "max_wait_ns")?, "max_wait_ns")?,
        );
    }
    for edge in items(transit, "transits")? {
        let edge = as_object(edge, "transit")?;
        builder.add_transit(
            as_text(field(edge, "from")?, "from")?,
            as_text(field(edge, "to")?, "to")?,
            Transit {
                open: as_integer(field(edge, "open_ns")?, "open_ns")?,
                close: as_integer(field(edge, "close_ns")?, "close_ns")?,
                min_travel: as_integer(field(edge, "min_travel_ns")?, "min_travel_ns")?,
                max_travel: as_integer(field(edge, "max_travel_ns")?, "max_travel_ns")?,
            },
        );
    }
    let network = builder
        .build()
        .map_err(|error| fail(error.stable_id(), error.to_string()))?;
    let origin = as_object(field(transit, "origin")?, "origin")?;
    let origin_zone = as_text(field(origin, "zone")?, "origin zone")?;
    let start = (
        as_integer(field(origin, "earliest_ns")?, "earliest_ns")?,
        as_integer(field(origin, "latest_ns")?, "latest_ns")?,
    );
    let run = temporal::temporal_reachability(
        &network,
        &origin_zone,
        start,
        TRANSIT_INTERVALS,
        Budget::new(TRANSIT_OPERATIONS, u64::from(TRANSIT_INTERVALS) * 1024),
    )
    .map_err(|error| fail(error.stable_id(), error.to_string()))?;
    let reached: &TemporalOutput = &run.output;
    let mut observers = Vec::new();
    for observer in items(transit, "observers")? {
        let observer = as_object(observer, "observer")?;
        let zone = as_text(field(observer, "zone")?, "observer zone")?;
        let sensor = as_text(field(observer, "sensor")?, "observer sensor")?;
        let row = reached.row(&zone).ok_or_else(|| {
            fail(
                "ERR-GRAPH-INPUT-INVALID-001",
                format!("unknown observer zone {zone}"),
            )
        })?;
        // The first reachable presence interval that is still open now.
        let window = row
            .presence
            .iter()
            .find(|&&(_, hi)| hi >= now)
            .map(|&(lo, hi)| (lo.max(now), hi));
        if let Some((window_start, window_end)) = window {
            opportunities.push(Opportunity {
                id: format!("transit:{sensor}:{zone}"),
                sensor: sensor.clone(),
                failure_domains: domains(field(observer, "failure_domains")?, "failure_domains")?,
                window_start,
                window_end,
                positive: interval(field(observer, "positive")?, "positive")?,
                negative: interval(field(observer, "negative")?, "negative")?,
            });
        }
        observers.push(TransitObserver {
            zone,
            sensor,
            reachability: row.reachability,
            presence: row.presence.clone(),
            window,
        });
    }
    Ok(TransitPlan {
        origin: origin_zone,
        start,
        horizon,
        observers,
        output_digest: run.output_digest.to_text(),
        decision_path_digest: run.decision_path_digest.to_text(),
    })
}

fn parse_query(
    document: &Value,
    calibrations: &Calibrations,
) -> Result<(FusionQuery, Option<TransitPlan>, CalibrationBindings)> {
    let query = as_object(document, "query")?;
    if !matches!(
        query.get("schema").and_then(Value::text),
        Some("fss.fusion_query.v1" | "fss.fusion_query.v2")
    ) {
        return Err(fail(
            "fusion.cli.query_schema",
            "expected fss.fusion_query.v1 or fss.fusion_query.v2",
        ));
    }
    let mut bindings = CalibrationBindings::default();
    let prior = match field(query, "prior")? {
        Value::Text(text) if text == "calibration" => {
            let selected = implicit_prior(calibrations)?;
            bindings.prior = Some(CalibrationIdentity::of(selected));
            selected.prior
        }
        Value::Object(binding) => {
            let selected = select_calibration(binding, calibrations)?;
            bindings.prior = Some(CalibrationIdentity::of(selected));
            selected.prior
        }
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
        let modes = ["score_ppm", "uncalibrated", "llr"]
            .iter()
            .filter(|key| calibration_value.contains_key(**key))
            .count();
        if modes != 1 {
            return Err(fail(
                "fusion.cli.calibration_mode",
                "calibration must contain exactly one of score_ppm, uncalibrated, or llr",
            ));
        }
        let evidence_id = as_text(field(item, "id")?, "evidence id")?;
        let mut failure_domains = domains(field(item, "failure_domains")?, "failure_domains")?;
        let item_calibration = if let Some(score) = calibration_value.get("score_ppm") {
            let selected = select_calibration(calibration_value, calibrations)?;
            let score_ppm: u32 = as_integer(score, "score_ppm")?;
            if score_ppm > fss_fusion::calibration::MAX_SCORE_PPM {
                return Err(fail(
                    "fusion.cli.score_out_of_range",
                    "score_ppm must be in 0..=1000000",
                ));
            }
            failure_domains.insert(format!("calibration:{}", selected.digest.to_text()));
            bindings.scores.push(ScoreBinding {
                evidence_id: evidence_id.clone(),
                score_ppm,
                calibration: CalibrationIdentity::of(selected),
            });
            selected.calibrate(score_ppm)
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
            id: evidence_id,
            sensor: as_text(field(item, "sensor")?, "sensor")?,
            failure_domains,
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
    let now_ns: u64 = as_integer(field(query, "now_ns")?, "now_ns")?;
    let transit = match query.get("transit") {
        None => None,
        Some(value) => Some(parse_transit(
            as_object(value, "transit")?,
            now_ns,
            policy.max_wait_ns,
            &mut opportunities,
        )?),
    };
    let fusion = FusionQuery {
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
        now_ns,
    };
    bindings
        .scores
        .sort_by(|a, b| a.evidence_id.cmp(&b.evidence_id));
    Ok((fusion, transit, bindings))
}

fn transit_json(plan: &TransitPlan) -> String {
    object(&[
        ("algorithm", text(temporal::IDENTITY.algorithm_id)),
        ("implementation", text(temporal::IDENTITY.implementation_id)),
        ("origin", text(&plan.origin)),
        (
            "origin_interval_ns",
            format!("[\"{}\",\"{}\"]", plan.start.0, plan.start.1),
        ),
        ("horizon_ns", text(&plan.horizon.to_string())),
        ("output_digest", text(&plan.output_digest)),
        ("decision_path_digest", text(&plan.decision_path_digest)),
        (
            "observers",
            array(plan.observers.iter().map(|observer| {
                object(&[
                    ("zone", text(&observer.zone)),
                    ("sensor", text(&observer.sensor)),
                    ("reachability", text(observer.reachability.as_str())),
                    (
                        "presence_ns",
                        array(
                            observer
                                .presence
                                .iter()
                                .map(|(lo, hi)| format!("[\"{lo}\",\"{hi}\"]")),
                        ),
                    ),
                    (
                        "opportunity_window_ns",
                        observer.window.map_or_else(
                            || "null".to_owned(),
                            |(lo, hi)| format!("[\"{lo}\",\"{hi}\"]"),
                        ),
                    ),
                ])
            })),
        ),
    ])
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

fn outcome_json(
    outcome: &FusionOutcome,
    calibrations: &Calibrations,
    bindings: &CalibrationBindings,
    input_binding_digest: ContentDigest,
    transit: Option<&TransitPlan>,
) -> String {
    let optional = |value: Option<i64>| value.map_or_else(|| "null".to_owned(), |v| v.to_string());
    object(&[
        ("schema", text("fss.fusion_outcome.v1")),
        ("implementation", text(fss_fusion::IMPLEMENTATION_ID)),
        ("query_digest", text(&outcome.query_digest.to_text())),
        ("decision_digest", text(&outcome.decision_digest.to_text())),
        ("policy_generation", text(&outcome.policy_generation)),
        (
            "score_calibration_digest",
            if calibrations.len() == 1 {
                calibrations
                    .values()
                    .next()
                    .map_or_else(|| "null".to_owned(), |c| text(&c.digest.to_text()))
            } else {
                "null".to_owned()
            },
        ),
        (
            "score_calibrations",
            array(
                calibrations
                    .values()
                    .map(|calibration| CalibrationIdentity::of(calibration).to_json()),
            ),
        ),
        (
            "prior_calibration",
            bindings
                .prior
                .as_ref()
                .map_or_else(|| "null".to_owned(), CalibrationIdentity::to_json),
        ),
        ("score_calibration_bindings", bindings.scores_json()),
        (
            "input_binding_digest",
            text(&input_binding_digest.to_text()),
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
        (
            "transit",
            transit.map_or_else(|| "null".to_owned(), transit_json),
        ),
        ("effect_authority", "false".to_owned()),
    ])
}

fn run(args: Vec<OsString>) -> Result<String> {
    if args.len() > 2 * (MAX_CALIBRATIONS + 1) {
        return Err(fail("fusion.cli.arguments_limit", "too many arguments"));
    }
    if args.len() == 1 && args[0] == "--help" {
        return Ok(HELP.to_owned());
    }
    let mut query_path = None;
    let mut calibration_paths = Vec::new();
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
        if flag == "--query" {
            if query_path.replace(value).is_some() {
                return Err(fail("fusion.cli.duplicate_option", flag));
            }
        } else {
            calibration_paths.push(value);
            if calibration_paths.len() > MAX_CALIBRATIONS {
                return Err(fail(
                    "fusion.cli.arguments_limit",
                    "at most sixteen calibration artifacts are accepted",
                ));
            }
        }
    }
    let query_path = query_path.ok_or_else(|| fail("fusion.cli.missing_option", "--query"))?;
    let stdin_uses = usize::from(query_path == "-")
        + calibration_paths
            .iter()
            .filter(|path| path.as_str() == "-")
            .count();
    if stdin_uses > 1 {
        return Err(fail(
            "fusion.cli.stdin_conflict",
            "only one query or calibration artifact can be read from stdin",
        ));
    }
    let mut calibrations = Calibrations::new();
    let mut generations = BTreeSet::new();
    for path in calibration_paths {
        let calibration = load_calibration(&path)?;
        let digest = calibration.digest.to_text();
        if calibrations.contains_key(&digest) {
            return Err(fail(
                "fusion.cli.calibration_duplicate",
                "the same calibration artifact was supplied more than once",
            ));
        }
        if !generations.insert(calibration.generation.clone()) {
            return Err(fail(
                "fusion.cli.calibration_generation_conflict",
                "one calibration generation cannot name different contents",
            ));
        }
        calibrations.insert(digest, calibration);
    }
    let document =
        read_document(&query_path).map_err(|detail| fail("fusion.cli.query_unreadable", detail))?;
    let (query, transit, bindings) = parse_query(&document, &calibrations)?;
    let outcome = fuse(&query).map_err(|error| fail(error.stable_id(), error.to_string()))?;
    let input_binding_digest = bindings.digest(outcome.query_digest)?;
    Ok(outcome_json(
        &outcome,
        &calibrations,
        &bindings,
        input_binding_digest,
        transit.as_ref(),
    ))
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

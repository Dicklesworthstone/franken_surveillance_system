#![forbid(unsafe_code)]
//! Pure, bounded sensitivity to losing declared event failure domains.
//!
//! The retained event is the source of declaration identities, not numeric measurements.
//! Scores, calibration applicability and the consequence profile are explicit hypothetical
//! assumptions. The native fusion owner recomputes both complete queries; this adapter never
//! infers physical sensor independence, current coverage, historical policy or effect authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::{
    CanonicalEncoder, ContentDigest, DigestAlgorithm, EventHypothesis, EvidenceEdgeRelation,
    ExplainQuestion, ExplainReceipt,
};
use fss_fusion::{
    AblationTarget, Coverage, EvidenceItem, FusionAblation, FusionPolicy, FusionQuery,
    Observability, ScoreCalibration, Severity, ablate,
};
use fss_reference::agent_orient::EventExplanation;

use crate::fusion_json::fusion_ablation_json;
use crate::json_input::{Value, parse};
use crate::json_output::{array, object, string, strings};

/// The only admitted inline scenario schema.
pub const EVENT_COUNTERFACTUAL_REQUEST_SCHEMA: &str = "fss.event_counterfactual_request.v1";
/// Complete hypothetical source-loss projection, not a persisted event revision.
pub const EVENT_COUNTERFACTUAL_SCHEMA: &str = "fss.event_counterfactual.v1";
/// Canonical normalized request identity, including the exact raw ppm assumptions.
pub const EVENT_COUNTERFACTUAL_REQUEST_DOMAIN: &str = "fss.event_counterfactual.request.v1";
/// Source revision, publication, assumptions and both numerical executions.
pub const EVENT_COUNTERFACTUAL_DOMAIN: &str = "fss.event_counterfactual.explanation.v1";
/// Request bound below the MCP input frame ceiling; it grants no path or I/O authority.
pub const MAX_COUNTERFACTUAL_REQUEST_BYTES: usize = 32 * 1024;
/// Whole-result ceiling before the protected agent response is constructed.
pub const MAX_COUNTERFACTUAL_BYTES: usize = 256 * 1024;
/// A declared failure-domain label also has to fit the native fusion text contract.
pub const MAX_COUNTERFACTUAL_DOMAIN_BYTES: usize = 256;

const POLICY_GENERATION: &str = "fss.explain.fusion_policy.v1";
const DEFAULT_POLICY: &str = "1000,0,-1000";
const NO_COVERAGE: &str = "event metadata supplies no current physical coverage witness";
const SYNTHETIC_GROUP: &str = "event-evidence-projection";
const INTERVAL: &str = "wilson_z2_per_bin_not_simultaneous";

/// Typed refusal with no input payload, private path or untrusted domain in its message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventCounterfactualError {
    /// Malformed, incomplete, ambiguous or out-of-scope input.
    InvalidRequest(&'static str),
    /// The selected event no longer has exactly the requested immutable revision.
    StaleRevision,
    /// The supplied retained record fails its own canonical contract.
    InvalidEvent,
    /// The complete output or encoding cannot fit its declared finite bounds.
    Limit,
    /// The unchanged native fusion rule refused the constructed numerical scenario.
    Fusion,
}

impl EventCounterfactualError {
    /// Existing registered error identity; this operation creates no new retry vocabulary.
    #[must_use]
    pub const fn stable_id(&self) -> &'static str {
        match self {
            Self::StaleRevision => "ERR-PRECONDITION-STALE-001",
            Self::Limit => "ERR-AGENT-CONTEXT-INCOMPLETE-001",
            Self::InvalidRequest(_) | Self::InvalidEvent | Self::Fusion => {
                "ERR-FUSION-INPUT-INVALID-001"
            }
        }
    }
}

impl fmt::Display for EventCounterfactualError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidRequest(reason) => reason,
            Self::StaleRevision => "event counterfactual revision precondition is stale",
            Self::InvalidEvent => "event counterfactual source record is invalid",
            Self::Limit => "complete event counterfactual exceeds its bounds",
            Self::Fusion => "native fusion refused the hypothetical event query",
        })
    }
}

impl std::error::Error for EventCounterfactualError {}

type Result<T> = std::result::Result<T, EventCounterfactualError>;

fn invalid(reason: &'static str) -> EventCounterfactualError {
    EventCounterfactualError::InvalidRequest(reason)
}

fn field<'a>(fields: &'a BTreeMap<String, Value>, key: &str) -> Result<&'a Value> {
    fields.get(key).ok_or_else(|| invalid("counterfactual field is missing"))
}

fn only(fields: &BTreeMap<String, Value>, names: &[&str]) -> Result<()> {
    if fields.keys().any(|key| !names.contains(&key.as_str())) {
        return Err(invalid("unknown counterfactual or calibration field"));
    }
    Ok(())
}

fn text(value: &Value) -> Result<&str> {
    value.text().ok_or_else(|| invalid("counterfactual field must be a string"))
}

fn unsigned(value: &Value) -> Result<u64> {
    if !matches!(value, Value::Number(_)) {
        return Err(invalid("counterfactual count or score must be a JSON integer"));
    }
    value.integer().and_then(|n| u64::try_from(n).ok())
        .ok_or_else(|| invalid("counterfactual count or score is outside its integer bounds"))
}

fn exact_digest(value: &Value) -> Result<ContentDigest> {
    let raw = text(value)?;
    ContentDigest::parse(raw).ok().filter(|digest| {
        digest.algorithm() == DigestAlgorithm::Sha256
            && digest.to_text() == raw
            && digest.bytes().iter().any(|byte| *byte != 0)
    }).ok_or_else(|| invalid("expected an exact nonzero canonical SHA-256 digest"))
}

fn valid_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_COUNTERFACTUAL_DOMAIN_BYTES
        && !value.chars().any(char::is_control)
}

fn same_count(fields: &BTreeMap<String, Value>, key: &str, expected: u64) -> Result<()> {
    if let Some(value) = fields.get(key)
        && unsigned(value)? != expected
    {
        return Err(invalid("calibration summary does not reproduce from its counts"));
    }
    Ok(())
}

fn same_interval(
    fields: &BTreeMap<String, Value>,
    key: &str,
    lo: i64,
    hi: i64,
) -> Result<()> {
    let Some(value) = fields.get(key) else {
        return Ok(());
    };
    let pair = value.array().filter(|pair| pair.len() == 2)
        .ok_or_else(|| invalid("calibration interval must be a two-integer array"))?;
    for (value, expected) in pair.iter().zip([lo, hi]) {
        if !matches!(value, Value::Number(_)) || value.integer() != Some(i128::from(expected)) {
            return Err(invalid("calibration interval does not reproduce from its counts"));
        }
    }
    Ok(())
}

fn calibration(value: &Value) -> Result<ScoreCalibration> {
    let fields = value.object().ok_or_else(|| invalid("score_calibration must be an object"))?;
    only(fields, &[
        "schema", "generation", "digest", "bins", "true_positives", "false_positives",
        "prior_log_odds_millibans", "interval",
    ])?;
    if text(field(fields, "schema")?)? != "fss.score_calibration.v1" {
        return Err(invalid("unsupported score calibration schema"));
    }
    let generation = text(field(fields, "generation")?)?;
    // Native per-row generations append '@' and the 71-byte canonical SHA-256 identity.
    if generation.len() > 184 {
        return Err(invalid("score calibration generation exceeds native projection bounds"));
    }
    let bins = field(fields, "bins")?.array()
        .filter(|bins| !bins.is_empty() && bins.len() <= fss_fusion::calibration::MAX_BINS)
        .ok_or_else(|| invalid("score calibration bin count is outside its bounds"))?;
    let mut edges = Vec::with_capacity(bins.len());
    let mut counts = Vec::with_capacity(bins.len());
    for value in bins {
        let bin = value.object().ok_or_else(|| invalid("score calibration bin must be an object"))?;
        only(bin, &["lo_ppm", "hi_ppm", "true_positives", "false_positives", "llr_millibans"])?;
        edges.push(u32::try_from(unsigned(field(bin, "lo_ppm")?)?)
            .map_err(|_| invalid("score bin edge is outside ppm bounds"))?);
        counts.push((
            unsigned(field(bin, "true_positives")?)?,
            unsigned(field(bin, "false_positives")?)?,
        ));
    }
    let rebuilt = ScoreCalibration::from_counts(generation, &edges, &counts)
        .map_err(|_| invalid("score calibration counts or edges are invalid"))?;
    if exact_digest(field(fields, "digest")?)? != rebuilt.digest {
        return Err(invalid("score calibration digest does not reproduce from its counts"));
    }
    same_count(fields, "true_positives", rebuilt.positives)?;
    same_count(fields, "false_positives", rebuilt.negatives)?;
    same_interval(fields, "prior_log_odds_millibans", rebuilt.prior.lo(), rebuilt.prior.hi())?;
    if let Some(value) = fields.get("interval")
        && text(value)? != INTERVAL
    {
        return Err(invalid("unsupported score calibration interval method"));
    }
    for (value, expected) in bins.iter().zip(&rebuilt.bins) {
        let bin = value.object().ok_or_else(|| invalid("score calibration bin must be an object"))?;
        same_count(bin, "hi_ppm", u64::from(expected.hi_ppm))?;
        same_interval(bin, "llr_millibans", expected.llr.lo(), expected.llr.hi())?;
    }
    Ok(rebuilt)
}

fn calibration_json(calibration: &ScoreCalibration) -> String {
    let bins: Vec<_> = calibration.bins.iter().map(|bin| object(&[
        ("lo_ppm", bin.lo_ppm.to_string()),
        ("hi_ppm", bin.hi_ppm.to_string()),
        ("true_positives", bin.positives.to_string()),
        ("false_positives", bin.negatives.to_string()),
        ("llr_millibans", format!("[{},{}]", bin.llr.lo(), bin.llr.hi())),
    ])).collect();
    object(&[
        ("schema", string("fss.score_calibration.v1")),
        ("generation", string(&calibration.generation)),
        ("digest", string(&calibration.digest.to_text())),
        ("true_positives", calibration.positives.to_string()),
        ("false_positives", calibration.negatives.to_string()),
        ("prior_log_odds_millibans", format!("[{},{}]", calibration.prior.lo(), calibration.prior.hi())),
        ("interval", string(INTERVAL)),
        ("bins", array(&bins)),
    ])
}

fn policy(raw: &str) -> Result<FusionPolicy> {
    let parts: Vec<_> = raw.split(',').collect();
    if parts.len() != 3 {
        return Err(invalid("fusion_policy must be three canonical signed integers"));
    }
    let mut thresholds = [0_i64; 3];
    for (destination, part) in thresholds.iter_mut().zip(parts) {
        let value = part.parse::<i64>()
            .map_err(|_| invalid("fusion_policy threshold is invalid"))?;
        if value.to_string() != part || !(-fss_fusion::MAX_ABS_LLR..=fss_fusion::MAX_ABS_LLR).contains(&value) {
            return Err(invalid("fusion_policy threshold is outside canonical native bounds"));
        }
        *destination = value;
    }
    let [alert_threshold, retain_threshold, reject_threshold] = thresholds;
    if !(reject_threshold < retain_threshold && retain_threshold <= alert_threshold) {
        return Err(invalid("fusion_policy thresholds are not strictly ordered"));
    }
    Ok(FusionPolicy {
        generation: POLICY_GENERATION.to_owned(),
        alert_threshold,
        retain_threshold,
        reject_threshold,
        min_independent_support: 2,
        urgent_single_domain_threshold: None,
        max_wait_ns: 0,
        look_penalty_per_doubling: 0,
        operator_confirmation_available: false,
    })
}

fn policy_text(policy: &FusionPolicy) -> String {
    format!("{},{},{}", policy.alert_threshold, policy.retain_threshold, policy.reject_threshold)
}

fn scores_json(scores: &BTreeMap<String, u32>) -> String {
    let rows: Vec<_> = scores.iter()
        .map(|(domain, score)| format!("{}:{score}", string(domain)))
        .collect();
    format!("{{{}}}", rows.join(","))
}

/// Immutable inline assumptions. Construction performs no I/O or authority discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventCounterfactualRequest {
    expected_revision: ContentDigest,
    without_domains: Vec<String>,
    calibration: ScoreCalibration,
    scores: BTreeMap<String, u32>,
    policy: FusionPolicy,
    digest: ContentDigest,
}

impl EventCounterfactualRequest {
    /// Decode one whole closed scenario, verifying calibration counts and all supplied summaries.
    /// Duplicate JSON keys, unknown fields, score aliases, paths and implicit scores are refused.
    pub fn parse(input: &str) -> Result<Self> {
        if input.len() > MAX_COUNTERFACTUAL_REQUEST_BYTES {
            return Err(EventCounterfactualError::Limit);
        }
        let value = parse(input).map_err(|_| invalid("counterfactual is not strict bounded JSON"))?;
        let fields = value.object().ok_or_else(|| invalid("counterfactual must be an object"))?;
        only(fields, &[
            "schema", "event_revision_digest", "without_domains", "score_calibration",
            "domain_scores_ppm", "fusion_policy",
        ])?;
        if text(field(fields, "schema")?)? != EVENT_COUNTERFACTUAL_REQUEST_SCHEMA {
            return Err(invalid("unsupported event counterfactual request schema"));
        }
        let expected_revision = exact_digest(field(fields, "event_revision_digest")?)?;
        let calibration = calibration(field(fields, "score_calibration")?)?;
        let policy = match fields.get("fusion_policy") {
            Some(value) => policy(text(value)?)?,
            None => policy(DEFAULT_POLICY)?,
        };
        let mapping = field(fields, "domain_scores_ppm")?.object()
            .filter(|mapping| !mapping.is_empty() && mapping.len() <= fss_fusion::MAX_EVIDENCE)
            .ok_or_else(|| invalid("explicit score map is outside its bounds"))?;
        let mut scores = BTreeMap::new();
        for (domain, value) in mapping {
            if !valid_domain(domain) {
                return Err(invalid("score mapping has an invalid failure-domain identity"));
            }
            let score = u32::try_from(unsigned(value)?)
                .ok().filter(|score| *score <= fss_fusion::calibration::MAX_SCORE_PPM)
                .ok_or_else(|| invalid("score mapping is outside ppm bounds"))?;
            scores.insert(domain.clone(), score);
        }
        let selectors = field(fields, "without_domains")?.array()
            .filter(|selectors| !selectors.is_empty() && selectors.len() <= fss_fusion::MAX_ABLATION_TARGETS)
            .ok_or_else(|| invalid("failure-domain loss selector count is outside its bounds"))?;
        let mut unique = BTreeSet::new();
        for selector in selectors {
            let domain = text(selector)?;
            if !valid_domain(domain) || !scores.contains_key(domain) || !unique.insert(domain.to_owned()) {
                return Err(invalid("failure-domain loss selector is invalid, duplicated or unmapped"));
            }
        }
        let without_domains: Vec<_> = unique.into_iter().collect();
        let mut encoder = CanonicalEncoder::new();
        encoder.text(EVENT_COUNTERFACTUAL_REQUEST_DOMAIN);
        encoder.digest(expected_revision);
        encoder.digest(calibration.digest);
        encoder.text(&policy_text(&policy));
        encoder.u32(without_domains.len() as u32);
        for domain in &without_domains {
            encoder.text(domain);
        }
        encoder.u32(scores.len() as u32);
        for (domain, score) in &scores {
            encoder.text(domain);
            encoder.u32(*score);
        }
        let digest = ContentDigest::sha256(
            &encoder.finish_checked().map_err(|_| EventCounterfactualError::Limit)?,
        );
        let request = Self { expected_revision, without_domains, calibration, scores, policy, digest };
        // Transport adapters retain this spelling. Canonical expansion must obey the same cap.
        if request.canonical_request_json().len() > MAX_COUNTERFACTUAL_REQUEST_BYTES {
            return Err(EventCounterfactualError::Limit);
        }
        Ok(request)
    }

    /// Exact immutable source precondition, independent of the mutable event ID.
    #[must_use]
    pub const fn expected_revision(&self) -> ContentDigest {
        self.expected_revision
    }

    /// Normalized request identity; raw scores remain bound even within the same calibration bin.
    #[must_use]
    pub const fn request_digest(&self) -> ContentDigest {
        self.digest
    }

    /// Complete canonical control JSON, with sorted maps/selectors and verified calibration.
    /// This is an input projection, not a canonical durable format.
    #[must_use]
    pub fn canonical_request_json(&self) -> String {
        object(&[
            ("schema", string(EVENT_COUNTERFACTUAL_REQUEST_SCHEMA)),
            ("event_revision_digest", string(&self.expected_revision.to_text())),
            ("without_domains", strings(&self.without_domains)),
            ("score_calibration", calibration_json(&self.calibration)),
            ("domain_scores_ppm", scores_json(&self.scores)),
            ("fusion_policy", string(&policy_text(&self.policy))),
        ])
    }

    /// Recompute against the exact source revision supplied by the verified explanation owner.
    /// The caller retains responsibility for current metadata custody and final revalidation.
    pub fn compute(&self, explanation: &EventExplanation) -> Result<EventCounterfactual> {
        let retained = &explanation.event;
        if retained.revision_digest != retained.event.revision_digest()
            || retained.revisions.last() != Some(&retained.event)
        {
            return Err(EventCounterfactualError::InvalidEvent);
        }
        self.compute_event(&retained.event, retained.event_root)
    }

    fn compute_event(&self, event: &EventHypothesis, source_root: ContentDigest) -> Result<EventCounterfactual> {
        event.verify().map_err(|_| EventCounterfactualError::InvalidEvent)?;
        if event.revision_digest() != self.expected_revision {
            return Err(EventCounterfactualError::StaleRevision);
        }
        if source_root.algorithm() != DigestAlgorithm::Sha256
            || source_root.bytes().iter().all(|byte| *byte == 0)
        {
            return Err(EventCounterfactualError::InvalidEvent);
        }
        let domains: BTreeSet<_> = event.evidence.iter().filter(|edge| {
            matches!(edge.relation, EvidenceEdgeRelation::Supports | EvidenceEdgeRelation::Contradicts)
        }).map(|edge| edge.failure_domain.as_str()).collect();
        if domains.is_empty()
            || domains.len() != self.scores.len()
            || domains.iter().any(|domain| !self.scores.contains_key(*domain))
        {
            return Err(invalid("score map must exactly cover the contributing declared event domains"));
        }
        let shared_calibration = format!("calibration:{}", self.calibration.digest);
        let shared_sensor = format!("sensor:{SYNTHETIC_GROUP}");
        if domains.contains(shared_calibration.as_str()) || domains.contains(shared_sensor.as_str()) {
            return Err(invalid("declared event domain collides with a synthetic common-cause grouping"));
        }
        let mut evidence = Vec::new();
        for (ordinal, edge) in event.evidence.iter().enumerate() {
            if !matches!(edge.relation, EvidenceEdgeRelation::Supports | EvidenceEdgeRelation::Contradicts) {
                continue;
            }
            let score = self.scores.get(&edge.failure_domain).copied()
                .ok_or_else(|| invalid("contributing event domain has no explicit score"))?;
            evidence.push(EvidenceItem {
                id: format!("edge:{ordinal}:{}", edge.digest),
                sensor: SYNTHETIC_GROUP.to_owned(),
                failure_domains: BTreeSet::from([edge.failure_domain.clone(), shared_calibration.clone()]),
                calibration: self.calibration.calibrate(score),
                observability: Observability::Observed,
            });
        }
        if evidence.len() > fss_fusion::MAX_EVIDENCE {
            return Err(EventCounterfactualError::Limit);
        }
        let query = FusionQuery {
            hypothesis: event.event_id.as_str().to_owned(),
            kind: event.kind.as_str().to_owned(),
            prior: self.calibration.prior,
            evidence,
            coverage: Coverage::Gap { reason: NO_COVERAGE.to_owned() },
            opportunities: Vec::new(),
            probes: Vec::new(),
            severity: Severity {
                expected_harm: 1_000,
                false_alert_cost: 100,
                delay_cost_per_second: 10,
                reversible: false,
            },
            policy: self.policy.clone(),
            looks: 1,
            now_ns: 0,
        };
        let targets: Vec<_> = self.without_domains.iter().cloned()
            .map(AblationTarget::FailureDomain).collect();
        let ablation = ablate(&query, &targets).map_err(|_| EventCounterfactualError::Fusion)?;
        let receipt = ExplainReceipt::compile(
            ExplainQuestion::WhatIf,
            self.expected_revision,
            vec![source_root, self.digest, ablation.digest()],
            Vec::new(),
            0,
        ).map_err(|_| EventCounterfactualError::Limit)?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text(EVENT_COUNTERFACTUAL_DOMAIN);
        encoder.digest(self.expected_revision);
        encoder.digest(source_root);
        encoder.digest(self.digest);
        encoder.digest(ablation.digest());
        encoder.digest(receipt.receipt_digest());
        let digest = ContentDigest::sha256(
            &encoder.finish_checked().map_err(|_| EventCounterfactualError::Limit)?,
        );
        let result = EventCounterfactual {
            request: self.clone(),
            source: event.clone(),
            source_root,
            ablation,
            receipt,
            digest,
        };
        result.to_json()?;
        Ok(result)
    }
}

/// Complete immutable hypothetical computation, with its original event declaration attached.
#[derive(Clone, Debug)]
pub struct EventCounterfactual {
    request: EventCounterfactualRequest,
    source: EventHypothesis,
    source_root: ContentDigest,
    ablation: FusionAblation,
    receipt: ExplainReceipt,
    digest: ContentDigest,
}

impl EventCounterfactual {
    /// Exact normalized assumptions, including raw scores and the caller's event pin.
    #[must_use]
    pub const fn request_digest(&self) -> ContentDigest {
        self.request.digest
    }

    /// Both complete queries and both recomputed numerical results.
    #[must_use]
    pub const fn ablation(&self) -> &FusionAblation {
        &self.ablation
    }

    /// Existing typed WhatIf receipt; it authorizes no effect or publication.
    #[must_use]
    pub const fn receipt(&self) -> &ExplainReceipt {
        &self.receipt
    }

    /// Binds the exact event, publication, complete assumptions and numerical derivation.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    /// Whole deterministic projection. Failure never returns a truncated baseline or alternative.
    pub fn to_json(&self) -> Result<String> {
        let ablation = fusion_ablation_json(&self.ablation).ok_or(EventCounterfactualError::Limit)?;
        let result = object(&[
            ("schema", string(EVENT_COUNTERFACTUAL_SCHEMA)),
            ("question", string("what_if")),
            ("scope", string("hypothetical_declared_failure_domain_loss")),
            ("source_event", self.source.to_canonical_json()),
            ("source_event_revision_digest", string(&self.source.revision_digest().to_text())),
            ("source_publication_root", string(&self.source_root.to_text())),
            ("request", self.request.canonical_request_json()),
            ("request_digest", string(&self.request.digest.to_text())),
            ("ablation", ablation),
            ("explain_receipt_digest", string(&self.receipt.receipt_digest().to_text())),
            ("counterfactual_digest", string(&self.digest.to_text())),
            ("assumptions", strings([
                "Raw ppm scores and calibration applicability are caller-declared hypothetical inputs, not measured scores recovered from support/contradiction labels.",
                "All projected evidence shares one synthetic sensor grouping and the supplied calibration failure domain. Distinct event domain labels do not prove physical sensor independence.",
                "Baseline rows are assumed available only for this numerical experiment; original media, models and current source custody were not verified by this pure computation.",
                "Coverage remains a gap in both queries. No physical absence, restored coverage or permission is inferred.",
                "The prior comes from the caller calibration; policy thresholds come from this request. Severity is the fixed 1000/100/10 irreversible consequence profile, one look and virtual time zero, with no future observations or probes.",
                "This is hypothetical calibrated sensitivity, not replay of the event's original decision. The original event, uncertainty, noncontributing edges and recorded policy path are preserved unchanged in source_event.",
                "Derived receipts are recomputable read products, not newly retained objects or hydration authority.",
            ])),
            ("source_custody_verified", "false".to_owned()),
            ("historical_decision_replayed", "false".to_owned()),
            ("physical_coverage_certified", "false".to_owned()),
            ("event_policy_changed", "false".to_owned()),
            ("published", "false".to_owned()),
            ("effect_authority", "false".to_owned()),
        ]);
        if result.len().saturating_add(1) > MAX_COUNTERFACTUAL_BYTES {
            return Err(EventCounterfactualError::Limit);
        }
        Ok(result)
    }
}

#[cfg(test)]
#[path = "event_counterfactual/tests.rs"]
mod tests;

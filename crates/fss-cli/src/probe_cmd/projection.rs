#![forbid(unsafe_code)]
//! Complete decision projection of a native, already source-validated historical report.
//!
//! Neither native numbers nor knowledge states are recomputed here. Every window, common-cause
//! cluster, counterfactual, exclusion and source-health warning is preserved. Spatial rows and
//! numeric model internals remain behind the exact native payload identity, with omission stated.

use fss_core::{ContentDigest, EnvelopeProposition, KnowledgeState};
use std::collections::BTreeSet;

use crate::json_input::Value;
use crate::orient_cmd::RenderError;

type Result<T> = std::result::Result<T, RenderError>;

pub(super) struct Projection {
    pub propositions: Vec<EnvelopeProposition>,
    pub not_observable: Vec<String>,
    pub observation_count: usize,
    pub window_count: usize,
    bytes: usize,
}

pub(super) fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value
        .object()
        .and_then(|fields| fields.get(name))
        .ok_or(RenderError("native probe field missing"))
}

fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    field(value, name)?
        .text()
        .ok_or(RenderError("native probe text differs"))
}

fn rows<'a>(value: &'a Value, name: &str) -> Result<&'a [Value]> {
    field(value, name)?
        .array()
        .ok_or(RenderError("native probe list differs"))
}

fn scalar(value: &Value) -> Result<String> {
    match value {
        Value::Text(value) | Value::Number(value) => Ok(value.clone()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Null => Ok("none".to_owned()),
        _ => Err(RenderError("native probe scalar differs")),
    }
}

fn exclusion_value(value: &Value) -> Result<String> {
    if let Value::Object(fields) = value {
        let fields: Vec<_> = fields
            .iter()
            .map(|(key, value)| scalar(value).map(|value| format!("{key}={value}")))
            .collect::<Result<_>>()?;
        return Ok(fields.join(", "));
    }
    scalar(value)
}

fn at(value: &Value, name: &str) -> Result<String> {
    scalar(field(value, name)?)
}

fn list(value: &Value) -> Result<String> {
    let rows = value
        .array()
        .ok_or(RenderError("native probe scalar list differs"))?;
    let values: Vec<_> = rows.iter().map(scalar).collect::<Result<_>>()?;
    Ok(if values.is_empty() {
        "none".to_owned()
    } else {
        values.join(", ")
    })
}

fn names(value: &Value, name: &str) -> Result<String> {
    list(field(value, name)?)
}

fn pair(value: &Value, name: &str) -> Result<String> {
    let values = rows(value, name)?;
    if values.len() != 2 {
        return Err(RenderError("native probe interval differs"));
    }
    Ok(format!(
        "[{}, {}]",
        scalar(&values[0])?,
        scalar(&values[1])?
    ))
}

fn digest(value: &Value, name: &str) -> Result<ContentDigest> {
    ContentDigest::parse(text(value, name)?).map_err(|_| RenderError("native probe digest differs"))
}

fn state(value: &str) -> Result<KnowledgeState> {
    Ok(match value {
        "known" => KnowledgeState::Known,
        "estimated" => KnowledgeState::Estimated,
        "unknown" => KnowledgeState::Unknown,
        "conflicted" => KnowledgeState::Conflicted,
        "stale" => KnowledgeState::Stale,
        "not_observable" => KnowledgeState::NotObservable,
        "redacted" => KnowledgeState::Redacted,
        "indeterminate" => KnowledgeState::Indeterminate,
        "not_applicable" => KnowledgeState::NotApplicable,
        _ => return Err(RenderError("native probe knowledge state differs")),
    })
}

fn decision(value: &Value) -> Result<String> {
    let kind = text(value, "kind")?;
    let mut fields = vec![kind.to_owned()];
    let object = value
        .object()
        .ok_or(RenderError("native probe decision differs"))?;
    for (key, value) in object {
        if key != "kind" {
            fields.push(format!("{key}={}", scalar(value)?));
        }
    }
    Ok(fields.join("; "))
}

impl Projection {
    fn push(
        &mut self,
        label: &str,
        statement: String,
        state: KnowledgeState,
        evidence: &[ContentDigest],
    ) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(statement.len())
            .ok_or(RenderError("probe projection size overflows"))?;
        if statement.len() > 16_384 || self.bytes > 128 * 1024 || self.propositions.len() >= 4096 {
            return Err(RenderError(
                "complete probe projection exceeds bounded context",
            ));
        }
        self.propositions.push(EnvelopeProposition {
            id: format!("probe:{label}:{}", self.propositions.len()),
            statement,
            state,
            provenance: "derived".to_owned(),
            evidence: evidence.iter().map(|d| d.to_text()).collect(),
        });
        Ok(())
    }

    fn health(&mut self, observation: &Value, source: ContentDigest) -> Result<()> {
        let Some(health) = observation
            .object()
            .and_then(|fields| fields.get("historical_health"))
        else {
            return Ok(());
        };
        self.push("health", format!(
            "Historical health: sensor {}; segment {}; state {}; support withheld={}; screening incomplete={}; reasons [{}]. No current-health or physical-cause claim.",
            text(health, "sensor_id")?, at(health, "segment")?, text(health, "state")?,
            at(health, "support_withheld")?, at(health, "screening_incomplete")?, names(health, "reasons")?,
        ), KnowledgeState::Known, &[source])?;
        for finding in rows(health, "findings")? {
            self.push(
                "health-finding",
                format!(
                    "Diagnostic {}: {}; finding segments {}..{}; support withheld segments {}..{}.",
                    text(finding, "diagnostic")?,
                    text(finding, "finding")?,
                    at(finding, "finding_first_segment")?,
                    at(finding, "finding_last_segment")?,
                    at(finding, "withheld_first_segment")?,
                    at(finding, "withheld_last_segment")?,
                ),
                KnowledgeState::Known,
                &[
                    source,
                    digest(finding, "diagnostic")?,
                    digest(finding, "provenance_root")?,
                ],
            )?;
        }
        for pin in rows(health, "diagnostics")? {
            self.push(
                "health-pin",
                format!(
                    "Historical diagnostic {}; provenance root {}; trace {}.",
                    text(pin, "record_digest")?,
                    text(pin, "provenance_root")?,
                    text(pin, "trace_digest")?
                ),
                KnowledgeState::Known,
                &[
                    digest(pin, "record_digest")?,
                    digest(pin, "provenance_root")?,
                    digest(pin, "trace_digest")?,
                ],
            )?;
        }
        Ok(())
    }

    fn window(&mut self, window: &Value, report: ContentDigest) -> Result<()> {
        let index = at(window, "window_index")?;
        let outcome = field(window, "outcome")?;
        let query = field(window, "query")?;
        let receipt = digest(outcome, "decision_digest")?;
        let knowledge = state(text(outcome, "knowledge_state")?)?;
        let coverage = field(query, "coverage")?;
        let reason = coverage
            .object()
            .and_then(|fields| fields.get("reason"))
            .map(scalar)
            .transpose()?
            .unwrap_or_else(|| "none".to_owned());
        let missing = names(window, "cameras_without_new_observations")?;
        self.push("window", format!(
            "Window {index}; end {} ns; advice {}; reasons [{}]; knowledge {}; new/unique observations {}/{}; cameras without new observations [{missing}]; posterior log odds {} millibans; probability {} ppm; support/contradiction clusters {}/{}; sequential alert threshold {}; support to alert {}; reduction to retain {}; coverage {}: {reason}.",
            at(window, "end_ns")?, decision(field(outcome, "decision")?)?, names(outcome, "reasons")?,
            text(outcome, "knowledge_state")?, at(window, "new_observations")?, at(window, "unique_observations")?,
            pair(outcome, "posterior_log_odds_millibans")?, pair(outcome, "probability_ppm")?,
            at(outcome, "supporting_clusters")?, at(outcome, "contradicting_clusters")?,
            at(outcome, "sequential_alert_threshold")?, at(outcome, "support_to_alert")?, at(outcome, "reduction_to_retain")?, text(coverage, "state")?,
        ), knowledge, &[report, receipt, digest(outcome, "query_digest")?])?;
        if text(coverage, "state")? != "complete" || missing != "none" {
            self.not_observable.push(format!(
                "window:{index}: coverage {}; no new observations from {missing}; {reason}",
                text(coverage, "state")?
            ));
        }
        let policy = field(query, "policy")?;
        let severity = field(query, "severity")?;
        self.push("policy", format!(
            "Window {index} policy {}; prior {}; declared looks {}; expected harm {}; false-alert cost {}; delay cost/second {}; reversible={}; alert/retain/reject thresholds {}/{}/{}; minimum independent support {}; urgent single-domain threshold {}; maximum wait {} ns; look penalty/doubling {}; operator confirmation available={}.",
            text(policy, "generation")?, pair(query, "prior")?, at(query, "looks")?, at(severity, "expected_harm")?,
            at(severity, "false_alert_cost")?, at(severity, "delay_cost_per_second")?, at(severity, "reversible")?,
            at(policy, "alert_threshold")?, at(policy, "retain_threshold")?, at(policy, "reject_threshold")?,
            at(policy, "min_independent_support")?, at(policy, "urgent_single_domain_threshold")?, at(policy, "max_wait_ns")?,
            at(policy, "look_penalty_per_doubling")?, at(policy, "operator_confirmation_available")?,
        ), KnowledgeState::Known, &[receipt])?;
        for evidence in rows(query, "evidence")? {
            let observability = field(evidence, "observability")?;
            let observation = match observability {
                Value::Text(value) => value.clone(),
                Value::Object(_) => {
                    format!("not observable: {}", text(observability, "not_observable")?)
                }
                _ => return Err(RenderError("native probe observability differs")),
            };
            let calibration = field(evidence, "calibration")?;
            let calibration = if let Some(reason) = calibration
                .object()
                .and_then(|fields| fields.get("uncalibrated"))
            {
                format!("uncalibrated: {}", scalar(reason)?)
            } else {
                format!(
                    "calibration {}; log-likelihood interval {}",
                    text(calibration, "generation")?,
                    pair(calibration, "llr")?
                )
            };
            self.push("evidence", format!("Window {index} evidence {}; sensor {}; observability {observation}; {calibration}; failure domains [{}].",
                text(evidence, "id")?, text(evidence, "sensor")?, names(evidence, "failure_domains")?),
                KnowledgeState::Known, &[receipt])?;
        }
        for cluster in rows(outcome, "clusters")? {
            self.push("cluster", format!("Window {index} common-cause cluster {}; direction {}; members [{}]; failure domains [{}]; log-likelihood {} millibans. Members are not independent corroboration.",
                at(cluster, "label")?, text(cluster, "direction")?, names(cluster, "members")?, names(cluster, "failure_domains")?, pair(cluster, "llr_millibans")?), KnowledgeState::Known, &[receipt])?;
        }
        for exclusion in rows(outcome, "excluded")? {
            self.push(
                "exclusion",
                format!(
                    "Window {index} excludes evidence {}: {}.",
                    text(exclusion, "id")?,
                    text(exclusion, "reason")?
                ),
                KnowledgeState::NotObservable,
                &[receipt],
            )?;
        }
        self.push(
            "uncalibrated",
            format!(
                "Window {index} uncalibrated evidence: {}.",
                names(outcome, "uncalibrated")?
            ),
            KnowledgeState::Known,
            &[receipt],
        )?;
        for counterfactual in rows(outcome, "counterfactuals")? {
            self.push("counterfactual", format!("Window {index} removing cluster {}: posterior log odds {} millibans; advice {}.",
                at(counterfactual, "removed_cluster")?, pair(counterfactual, "posterior_log_odds_millibans")?, decision(field(counterfactual, "decision")?)?), KnowledgeState::Known, &[receipt])?;
        }
        Ok(())
    }
}

pub(super) fn project(report: &Value, native_receipt: ContentDigest) -> Result<Projection> {
    let event = text(report, "schema")? == "fss.retained_supervisor_discovery_report.v1";
    let body = if event {
        field(report, "supervision")?
    } else {
        report
    };
    let mut result = Projection {
        propositions: Vec::new(),
        not_observable: Vec::new(),
        observation_count: rows(body, "observations")?.len(),
        window_count: rows(body, "windows")?.len(),
        bytes: 0,
    };
    result.push("scope", format!(
        "Historical probe {}; class {}; start {} ns; selected-source custody verified; calibration applicability {}; looks {} (not lifetime exposure). No cross-camera identity, synchronized clocks, current health, physical cause, class absence, anytime-valid bound or effect authority. {}",
        text(body, "hypothesis_id")?, text(body, "label")?, at(body, "start_ns")?,
        text(body, "calibration_applicability")?, text(body, "look_count_provenance")?,
        if event { "Package tracks do not establish actor identity." } else { "Within-camera tracking association is not established." },
    ), KnowledgeState::Known, &[native_receipt])?;
    let health = field(body, "health_catalog")?;
    result.push("health-catalog", format!(
        "Historical health catalog: seen {}; loaded {}; deleted {}; metadata bytes {}; reads {}; admitted history work {}; assessment work {}; findings {}; native trace replayed={}; current camera health established={}; physical cause established={}; absence certified={}. Metadata inspection is not native trace replay.",
        at(health, "records_seen")?, at(health, "records_loaded")?, at(health, "deleted_records")?,
        at(health, "metadata_bytes_read")?, at(health, "metadata_reads")?, at(health, "history_work_admitted")?,
        at(health, "assessment_work")?, at(health, "findings_returned")?, at(health, "native_trace_replayed")?,
        at(health, "current_camera_health_established")?, at(health, "physical_cause_established")?, at(health, "absence_certified")?,
    ), KnowledgeState::Known, &[native_receipt])?;
    let mut calibrations = BTreeSet::new();
    for camera in rows(body, "cameras")? {
        let calibration = field(camera, "calibration")?;
        let calibration_id = match calibration {
            Value::Null => None,
            _ => Some(digest(calibration, "digest")?),
        };
        result.push("camera", format!(
            "Camera {}; sensor {}; package {}; model {}; contract {}; class {}; declared failure domains [{}]; calibration {}. Declarations do not establish independence or calibration qualification.",
            text(camera, "camera_id")?, text(camera, "sensor_id")?, text(camera, "package_digest")?,
            text(camera, "model_digest")?, text(camera, "contract_digest")?, at(camera, "class_index")?,
            names(camera, "failure_domains")?, calibration_id.map_or_else(|| "uncalibrated".to_owned(), |id| id.to_text()),
        ), KnowledgeState::Known, &[native_receipt])?;
        if let Some(id) = calibration_id
            && calibrations.insert(id)
        {
            result.push("calibration", format!(
                "Calibration {id}; generation {}; prior log odds {} millibans; true/false-positive samples {}/{}; interval {}. Per-bin Wilson intervals are not simultaneous or anytime-valid. All bins follow; shared tables appear once.",
                text(calibration, "generation")?, pair(calibration, "prior_log_odds_millibans")?,
                at(calibration, "true_positives")?, at(calibration, "false_positives")?, text(calibration, "interval")?,
            ), KnowledgeState::Known, &[native_receipt, id])?;
            for bin in rows(calibration, "bins")? {
                result.push("calibration-bin", format!(
                    "Calibration {id}; bin {}..{} ppm; true/false-positive samples {}/{}; log-likelihood {} millibans.",
                    at(bin, "lo_ppm")?, at(bin, "hi_ppm")?, at(bin, "true_positives")?,
                    at(bin, "false_positives")?, pair(bin, "llr_millibans")?,
                ), KnowledgeState::Known, &[id])?;
            }
        }
    }
    for observation in rows(body, "observations")? {
        let source = digest(observation, "identity")?;
        result.push("observation", format!(
            "Observation {source}; sensor {}; segment {}; capture {} ns; clock {} ({}); model {}; generation {}; class {}; original score {} ppm; applied calibration {}. Detector observation, not qualified presence or actor identity.",
            text(observation, "sensor_id")?, at(observation, "segment")?, pair(observation, "capture_ns")?,
            text(observation, "clock_basis")?, text(observation, "capture_time_label")?, text(observation, "model_id")?,
            text(observation, "generation")?, at(observation, "class_index")?, pair(observation, "score_ppm_outward")?, at(observation, "calibration_digest")?,
        ), KnowledgeState::Estimated, &[source, digest(observation, "capsule_digest")?, digest(observation, "package_digest")?,
            digest(observation, "model_digest")?, digest(observation, "contract_digest")?, digest(observation, "detection_report_digest")?])?;
        result.health(observation, source)?;
    }
    for window in rows(body, "windows")? {
        result.window(window, native_receipt)?;
    }
    for source in rows(report, "source_inventory")? {
        let (identity, root) = if event {
            (
                text(source, "event_id")?.to_owned(),
                digest(source, "event_root")?,
            )
        } else {
            (
                text(source, "report_digest")?.to_owned(),
                digest(source, "detection_root")?,
            )
        };
        result.push("source", format!("Historical source {identity}; root {root}; source verified={}; health binding {}. Metadata exclusions do not prove availability.",
            at(source, "source_verified")?, at(source, "health_digest")?), KnowledgeState::Known, &[native_receipt, root])?;
    }
    for exclusion in rows(field(report, "discovery")?, "exclusions")? {
        let fields = exclusion
            .object()
            .ok_or(RenderError("native discovery exclusion differs"))?;
        let identities: Vec<String> = fields
            .iter()
            .filter(|(key, _)| key.as_str() != "reason")
            .map(|(key, value)| exclusion_value(value).map(|value| format!("{key}={value}")))
            .collect::<Result<_>>()?;
        result.push(
            "discovery-exclusion",
            format!(
                "Native discovery exclusion: {}; {}.",
                text(exclusion, "reason")?,
                identities.join("; ")
            ),
            KnowledgeState::NotObservable,
            &[native_receipt],
        )?;
    }
    result.not_observable.push("Physical class absence, continuous occupancy, present camera health and independent cross-camera actor identity are not certified by retained supervision.".to_owned());
    Ok(result)
}

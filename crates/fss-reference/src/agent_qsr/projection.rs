#![forbid(unsafe_code)]
//! Complete native QSR rows inside the existing cognitive envelope.
//!
//! Each named row carries lossless JSON from the verified native report. This keeps
//! exact integer/time spellings, unknown samples, health barriers and lane breaks;
//! no favorable subset or alternate interpretation is invented by the bridge.

use fss_core::json_input::{self, Value};
use fss_core::{EnvelopeCoverage, EnvelopeEpistemic, EnvelopeProposition, KnowledgeState};

use super::{DeploymentQsrQuery, QsrQueryError};
use crate::ingest::qsr_observations::QsrObservationReport;

const MAX_NATIVE_BYTES: usize = 256 * 1024;
const MAX_PROJECTION_ROWS: usize = 3_500;
const MAX_STATEMENT_BYTES: usize = 16_384;

fn quote(value: &str, out: &mut String) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn json(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => out.push_str(value),
        Value::Text(value) => quote(value, out),
        Value::Array(values) => {
            out.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    out.push(',');
                }
                json(value, out);
            }
            out.push(']');
        }
        Value::Object(values) => {
            out.push('{');
            for (index, (key, value)) in values.iter().enumerate() {
                if index != 0 {
                    out.push(',');
                }
                quote(key, out);
                out.push(':');
                json(value, out);
            }
            out.push('}');
        }
    }
}

fn state(section: &str, value: &Value) -> KnowledgeState {
    let field = |key| value.object().and_then(|object| object.get(key));
    match section {
        "samples" if field("presence").and_then(Value::text) == Some("unknown") => {
            KnowledgeState::Unknown
        }
        "zones" if matches!(field("maximum_observed_count"), Some(Value::Null)) => {
            KnowledgeState::Unknown
        }
        "frames" if field("support_allowed").and_then(Value::boolean) != Some(true) => {
            KnowledgeState::Unknown
        }
        "lane_interruptions" => KnowledgeState::Unknown,
        "traversals" if field("status").and_then(Value::text) != Some("completed") => {
            KnowledgeState::Unknown
        }
        "traversals" | "summary" => KnowledgeState::Estimated,
        "samples" | "zones" | "sampled_dwell" | "lane_transitions" => KnowledgeState::Estimated,
        _ => KnowledgeState::Known,
    }
}

pub(super) fn epistemic(report: &QsrObservationReport) -> Result<EnvelopeEpistemic, QsrQueryError> {
    let native = report.to_json().map_err(QsrQueryError::Observation)?;
    let companion = report.lane_traversals().to_json();
    if native
        .len()
        .checked_add(companion.len())
        .is_none_or(|n| n > MAX_NATIVE_BYTES)
    {
        return Err(QsrQueryError::ResultLimit);
    }
    let value = json_input::parse(&native).map_err(|_| QsrQueryError::ResultLimit)?;
    let object = value.object().ok_or(QsrQueryError::Contract)?;
    let header = [
        "schema",
        "operation",
        "report_digest",
        "policy_digest",
        "configuration_digest",
        "source",
        "coverage",
        "interpretation",
        "configuration",
    ];
    let arrays = [
        "frames",
        "zones",
        "samples",
        "sampled_dwell",
        "lane_transitions",
        "lane_interruptions",
    ];
    if object.len() != header.len() + arrays.len()
        || header
            .iter()
            .chain(arrays.iter())
            .any(|key| !object.contains_key(*key))
    {
        return Err(QsrQueryError::Contract);
    }
    let evidence = vec![
        report.digest().to_text(),
        report.source().digest().to_text(),
        report.source().provenance_root().to_text(),
    ];
    let mut propositions = Vec::new();
    let mut push = |namespace: &str,
                    section: &str,
                    ordinal: Option<usize>,
                    row: &Value,
                    evidence: &[String]|
     -> Result<(), QsrQueryError> {
        if propositions.len() >= MAX_PROJECTION_ROWS {
            return Err(QsrQueryError::ResultLimit);
        }
        let id = ordinal.map_or_else(|| section.to_owned(), |n| format!("{section}:{n}"));
        let label = if namespace == "qsr" {
            "QSR"
        } else {
            "QSR lane"
        };
        let mut statement = format!("Verified native {label} {id}: ");
        json(row, &mut statement);
        if statement.len() > MAX_STATEMENT_BYTES {
            return Err(QsrQueryError::ResultLimit);
        }
        propositions.push(EnvelopeProposition {
            id: format!("claim:{namespace}:{id}"),
            statement,
            state: state(section, row),
            provenance: "derived".to_owned(),
            evidence: evidence.to_vec(),
        });
        Ok(())
    };
    for section in header {
        push(
            "qsr",
            section,
            None,
            object.get(section).ok_or(QsrQueryError::Contract)?,
            &evidence,
        )?;
    }
    for section in arrays {
        let rows = object
            .get(section)
            .and_then(Value::array)
            .ok_or(QsrQueryError::Contract)?;
        for (ordinal, row) in rows.iter().enumerate() {
            push("qsr", section, Some(ordinal), row, &evidence)?;
        }
        // An empty result is explicitly represented, without claiming physical absence.
        if rows.is_empty() {
            push("qsr", section, None, &Value::Array(Vec::new()), &evidence)?;
        }
    }
    let companion = json_input::parse(companion).map_err(|_| QsrQueryError::ResultLimit)?;
    let companion = companion.object().ok_or(QsrQueryError::Contract)?;
    let header = [
        "schema",
        "operation",
        "report_digest",
        "policy_digest",
        "source_qsr_report",
        "source_zone_report",
        "provenance_root",
        "sampled_frames",
        "maximum_sample_gap_ns",
        "lane_stages",
        "interpretation",
        "summary",
    ];
    if companion.len() != header.len() + 1 || header.iter().any(|key| !companion.contains_key(*key))
    {
        return Err(QsrQueryError::Contract);
    }
    let companion_evidence = vec![
        report.lane_traversals().digest().to_text(),
        report.digest().to_text(),
        report.source().digest().to_text(),
        report.source().provenance_root().to_text(),
    ];
    for section in header {
        push(
            "qsr-lane",
            section,
            None,
            companion.get(section).ok_or(QsrQueryError::Contract)?,
            &companion_evidence,
        )?;
    }
    let rows = companion
        .get("traversals")
        .and_then(Value::array)
        .ok_or(QsrQueryError::Contract)?;
    for (ordinal, row) in rows.iter().enumerate() {
        push(
            "qsr-lane",
            "traversals",
            Some(ordinal),
            row,
            &companion_evidence,
        )?;
    }
    if rows.is_empty() {
        push(
            "qsr-lane",
            "traversals",
            None,
            &Value::Array(Vec::new()),
            &companion_evidence,
        )?;
    }
    Ok(EnvelopeEpistemic {
        propositions,
        assumptions: vec![
            "Each named QSR row contains the complete native JSON value; array ordinals preserve native ordering. No selected row was truncated.".to_owned(),
            "Counts concern confirmed model tracks at sampled frames. Detection accuracy, physical identity, continuous coverage, physical absence and service/wait duration remain unestablished.".to_owned(),
            "Whole-lane completion means every declared stage was observed in adjacent order within one admitted finite sequence. Partial suffixes, report-end censoring and interruptions are explicit; elapsed intervals use original capture endpoints, never summed stage uncertainty or a physical wait-time estimate.".to_owned(),
            "The principal is an operator audit label. Source verification grants no media disclosure, new inference, persistence or effects; evidence handles allow H0 metadata only.".to_owned(),
        ],
        invalidators: vec!["Any current authority/effect history, deletion restriction, source custody, screening, mask, report, configuration or allowance change requires a fresh complete query.".to_owned()],
    })
}

impl DeploymentQsrQuery {
    /// All selected native rows, with source-world observability limits kept separate.
    #[must_use]
    pub fn coverage(&self) -> EnvelopeCoverage {
        EnvelopeCoverage {
            authorized_domain: vec!["one exact retained, historically screened package-zone report under current source custody and deletion restrictions".to_owned()],
            observed_domain: vec!["complete native source/configuration pins, sampled frame screening, zone summaries, per-frame counts/presence, sampled dwell, lane transitions/interruptions and independently identified complete/incomplete/interrupted observed lane sequences".to_owned()],
            not_observable_domain: vec!["physical identity, true occupancy, service or wait duration, continuous coverage, physical absence, model accuracy, current camera health, unsampled intervals and other sources".to_owned()],
            omitted_count: 0,
            omission_reasons: vec!["Original media and model bytes are outside this metadata projection. Masked and unsupported samples remain explicit; no selected semantic row is omitted.".to_owned()],
            stop_reason: "exact_retained_qsr_report_exhausted".to_owned(),
        }
    }
}

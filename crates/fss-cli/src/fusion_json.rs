#![forbid(unsafe_code)]
//! Pure deterministic JSON projection of sequential fusion receipts.
//!
//! Shared by supervisor reports and offline checkpoint continuation so both adapters expose
//! the same complete source admission and numerical transcript without loading runtime owners.

use fss_fusion::{
    EPROCESS_TRANSCRIPT_SCHEMA, EProcessStepInput, EProcessTranscript, SourceDisposition,
    UNIQUE_SOURCE_STEP_SCHEMA, UniqueSourceStepOutcome,
};

use crate::json_output::{array, object, string};

fn unsigned(value: u64) -> String {
    value.to_string()
}

fn nullable(value: Option<String>) -> String {
    value.unwrap_or_else(|| "null".to_owned())
}

/// Render the complete registered numerical evidence transcript.
#[must_use]
pub fn fusion_transcript_json(transcript: &EProcessTranscript) -> String {
    let input = match transcript.input() {
        EProcessStepInput::Observation {
            query_digest,
            decision_digest,
        } => object(&[
            ("kind", string("observation")),
            ("query_digest", string(&query_digest.to_text())),
            ("decision_digest", string(&decision_digest.to_text())),
        ]),
        EProcessStepInput::RegimeReset { reason_digest } => object(&[
            ("kind", string("regime_reset")),
            ("reason_digest", string(&reason_digest.to_text())),
        ]),
    };
    object(&[
        ("schema", string(EPROCESS_TRANSCRIPT_SCHEMA)),
        (
            "previous_transcript_digest",
            nullable(transcript.previous().map(|d| string(&d.to_text()))),
        ),
        ("input", input),
        (
            "numerical_step_digest",
            string(&transcript.numerical_step_digest().to_text()),
        ),
        ("state_digest", string(&transcript.state_digest().to_text())),
        (
            "supporting_domains_digest",
            string(&transcript.supporting_domains_digest().to_text()),
        ),
        ("transcript_digest", string(&transcript.digest().to_text())),
    ])
}

/// Render one canonical source-once receipt shared by supervisor and continuation commands.
#[must_use]
pub fn unique_source_step_json(step: &UniqueSourceStepOutcome) -> String {
    let rows: Vec<_> = step
        .admissions()
        .iter()
        .map(|row| {
            object(&[
                ("evidence_id", string(row.evidence_id())),
                (
                    "source_digest",
                    nullable(row.source_digest().map(|digest| string(&digest.to_text()))),
                ),
                ("item_digest", string(&row.item_digest().to_text())),
                (
                    "disposition",
                    string(match row.disposition() {
                        SourceDisposition::Admitted => "admitted",
                        SourceDisposition::AlreadyAdmitted => "already_admitted",
                        SourceDisposition::NonNumeric => "non_numeric",
                    }),
                ),
                (
                    "first_admitted_step",
                    nullable(row.first_admitted_step().map(unsigned)),
                ),
            ])
        })
        .collect();
    object(&[
        ("schema", string(UNIQUE_SOURCE_STEP_SCHEMA)),
        (
            "previous_receipt_digest",
            nullable(step.previous().map(|digest| string(&digest.to_text()))),
        ),
        (
            "submitted_query_digest",
            nullable(
                step.submitted_query_digest()
                    .map(|digest| string(&digest.to_text())),
            ),
        ),
        (
            "effective_query_digest",
            nullable(
                step.effective_query_digest()
                    .map(|digest| string(&digest.to_text())),
            ),
        ),
        ("source_limit", unsigned(step.source_limit() as u64)),
        ("sources_seen", unsigned(step.sources_seen() as u64)),
        (
            "inventory_digest",
            string(&step.inventory_digest().to_text()),
        ),
        ("admissions", array(&rows)),
        (
            "fusion_transcript",
            fusion_transcript_json(&step.step().transcript),
        ),
        ("receipt_digest", string(&step.digest().to_text())),
    ])
}

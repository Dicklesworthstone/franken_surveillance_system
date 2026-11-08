#![forbid(unsafe_code)]
//! Metadata-only presentation of the runtime that owns a single alert attempt.

use fss_core::ContentDigest;
use fss_core::region::TaskOutcome;
use fss_reference::webhook::retained::RetainedWebhookEvidence;

use super::{AlertRuntimeSummary, WIRE_RETENTION_POLICY, outcome_text};
use crate::agent_json;
use crate::agent_json::{object, string};

fn outcome(value: &TaskOutcome) -> (&'static str, Option<&str>) {
    match value {
        TaskOutcome::Success => ("success", None),
        TaskOutcome::Failed(reason) => ("failed", Some(reason)),
        TaskOutcome::Cancelled => ("cancelled", None),
        TaskOutcome::Indeterminate(reason) => ("indeterminate", Some(reason)),
    }
}

/// Runtime metadata for the native alert report. Request and response bytes are excluded.
#[must_use]
pub fn json(summary: &AlertRuntimeSummary) -> String {
    let task = summary.task_receipt.as_ref().map_or_else(
        || "null".to_owned(),
        |receipt| {
            let (state, reason) = outcome(&receipt.outcome);
            agent_json::object(&[
                ("task_id", agent_json::string(receipt.task_id.as_str())),
                ("region_id", agent_json::string(receipt.region_id.as_str())),
                (
                    "registered_at_ns",
                    agent_json::string(&receipt.registered_at.0.to_string()),
                ),
                (
                    "completed_at_ns",
                    agent_json::string(&receipt.completed_at.0.to_string()),
                ),
                ("outcome", agent_json::string(state)),
                ("reason", agent_json::optional_string(reason)),
            ])
        },
    );
    let quiescence = summary.quiescence.as_ref().map_or_else(
        || "null".to_owned(),
        |proof| {
            agent_json::object(&[
                ("region_id", agent_json::string(proof.region_id.as_str())),
                (
                    "parent_id",
                    agent_json::optional_string(proof.parent_id.as_ref().map(|id| id.as_str())),
                ),
                (
                    "closed_at_ns",
                    agent_json::string(&proof.closed_at.0.to_string()),
                ),
                ("total_tasks", proof.total_tasks.to_string()),
                ("total_obligations", proof.total_obligations.to_string()),
                (
                    "indeterminate_obligations",
                    proof.indeterminate_obligations.to_string(),
                ),
                (
                    "proof_digest",
                    agent_json::string(&proof.proof_digest.to_text()),
                ),
            ])
        },
    );
    agent_json::object(&[
        ("task_receipt", task),
        ("quiescence", quiescence),
        ("consumed", agent_json::budget(&summary.consumed)),
        ("remaining", agent_json::budget(&summary.remaining)),
        ("network_admissions", summary.network_admissions.to_string()),
        (
            "source_read_reserved_bytes",
            summary.source_read_reserved_bytes.to_string(),
        ),
        (
            "source_read_attempts",
            summary.source_read_attempts.to_string(),
        ),
        ("recovery_required", summary.recovery_required.to_string()),
        (
            "recording_error",
            agent_json::optional_string(summary.recording_error.as_deref()),
        ),
        (
            "runtime_error",
            agent_json::optional_string(summary.runtime_error.as_deref()),
        ),
    ])
}

/// Compact runtime accounting for the existing agent execution-boundary schema.
#[must_use]
pub fn audit_statement(summary: &AlertRuntimeSummary) -> String {
    let task = summary.task_receipt.as_ref().map_or_else(
        || "no completed task receipt".to_owned(),
        |receipt| format!("task {} ({})", receipt.task_id, outcome(&receipt.outcome).0),
    );
    let quiescence = summary.quiescence.as_ref().map_or_else(
        || "quiescence not proven".to_owned(),
        |proof| format!("quiescence {}", proof.proof_digest),
    );
    format!(
        "Owned alert runtime: {task}; {quiescence}; {} network admissions charged {} network \
         bytes, {} source bytes reserved across {} reads, {} storage operations charged; \
         recovery_required={}.",
        summary.network_admissions,
        summary.consumed.network_bytes,
        summary.source_read_reserved_bytes,
        summary.source_read_attempts,
        summary.consumed.storage_operations,
        summary.recovery_required,
    )
}

/// Verified local custody metadata; arbitrary request and response bytes are never formatted.
/// The journal flag is supplied by the caller's later receipt or its cold verified snapshot.
#[must_use]
pub fn wire_json(evidence: &RetainedWebhookEvidence, journal_observation_recorded: bool) -> String {
    object(&[
        ("observation_digest", string(&evidence.digest().to_text())),
        ("manifest_root", string(&evidence.manifest_root().to_text())),
        ("publication_slot", string(evidence.slot().as_str())),
        (
            "prepared_record_digest",
            string(&evidence.prepared_record_digest().to_text()),
        ),
        (
            "commitment_root",
            string(&evidence.commitment_root().to_text()),
        ),
        ("route_digest", string(&evidence.route_digest().to_text())),
        ("outcome", string(&outcome_text(evidence.outcome()))),
        (
            "request_sha256",
            string(&ContentDigest::sha256(evidence.request()).to_text()),
        ),
        ("request_bytes", evidence.request().len().to_string()),
        ("sent_bytes", evidence.sent_bytes().to_string()),
        (
            "response_prefix_bytes",
            evidence.response_prefix().len().to_string(),
        ),
        ("io_calls", evidence.io_calls().to_string()),
        (
            "committed_at_ns",
            string(&evidence.committed_ns().to_string()),
        ),
        (
            "network_deadline_ns",
            string(&evidence.deadline_ns().to_string()),
        ),
        (
            "last_admission_ns",
            string(&evidence.last_admission_ns().to_string()),
        ),
        (
            "journal_observation_recorded",
            journal_observation_recorded.to_string(),
        ),
        ("custody", string("locally_verified_root_last")),
        (
            "human_delivery",
            string("not_inferred_from_wire_observation"),
        ),
    ])
}

/// Compact local custody evidence for the canonical agent response boundary.
#[must_use]
pub fn wire_custody_statement(
    retained: Option<&RetainedWebhookEvidence>,
    journal_observation_recorded: bool,
) -> String {
    match retained {
        Some(wire) => format!(
            "Local wire custody: root {}, observation {}, slot {}; journal observation recorded={}. Retention policy {}. This is local transport evidence, not human delivery proof.",
            wire.root(),
            wire.digest(),
            wire.slot(),
            journal_observation_recorded,
            WIRE_RETENTION_POLICY,
        ),
        None => format!(
            "Local wire custody was not verified; recovery is required before reconciliation, never resend. Retention policy {}.",
            WIRE_RETENTION_POLICY,
        ),
    }
}

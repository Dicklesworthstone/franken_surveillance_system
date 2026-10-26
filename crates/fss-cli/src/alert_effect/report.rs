#![forbid(unsafe_code)]
//! Metadata-only presentation of the runtime that owns a single alert attempt.

use fss_core::region::TaskOutcome;

use super::AlertRuntimeSummary;
use crate::agent_json;

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

#![forbid(unsafe_code)]
//! Metadata-only rendering shared by native supervision listing and agent session views.

use fss_core::ContentDigest;
use fss_reference::agent_session::checkpoint::journal::supervision::SupervisionInventoryEntry;

use super::{evidence_anchor, object, string};

fn digest(value: Option<ContentDigest>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| string(&value.to_text()))
}

/// Render every recovery descriptor without configuration bytes, report bytes or source pins.
#[must_use]
pub fn supervision_inventory_entry(entry: &SupervisionInventoryEntry) -> String {
    let reservation = entry.reservation.as_ref().map_or_else(
        || "null".to_owned(),
        |value| {
            object(&[
                ("ordinal", value.ordinal().to_string()),
                ("receipt", string(&value.receipt().to_text())),
                ("anchor", evidence_anchor(value.anchor())),
                (
                    "generations_current",
                    entry
                        .reservation_generations_current
                        .map_or_else(|| "null".to_owned(), |value| value.to_string()),
                ),
            ])
        },
    );
    let pending = entry.pending.as_ref().map_or_else(
        || "null".to_owned(),
        |value| {
            object(&[
                ("receipt", string(&value.receipt.to_text())),
                ("report_receipt", string(&value.report_receipt.to_text())),
                ("anchor", evidence_anchor(&value.anchor)),
                ("payload_digest", string(&value.payload_digest.to_text())),
                ("payload_len", value.payload_len.to_string()),
                (
                    "active_window_count",
                    value
                        .active_window_count
                        .map_or_else(|| "null".to_owned(), |value| value.to_string()),
                ),
                ("generations_current", value.generations_current.to_string()),
                ("report_is_historical", "true".to_owned()),
                ("sources_revalidated", "false".to_owned()),
            ])
        },
    );
    let schedule = entry.schedule.as_ref().map_or_else(
        || "null".to_owned(),
        |value| {
            let advance = value.last_advance().map_or_else(
                || "null".to_owned(),
                |advance| {
                    object(&[
                        ("target_window_count", advance.target_count().to_string()),
                        ("after_receipt", string(&advance.after_receipt().to_text())),
                        ("receipt", string(&advance.receipt().to_text())),
                    ])
                },
            );
            object(&[
                ("total_windows", value.total_windows().to_string()),
                (
                    "active_window_count",
                    value.active_window_count().to_string(),
                ),
                (
                    "active_window_index",
                    (value.active_window_count() - 1).to_string(),
                ),
                ("last_terminal_receipt", digest(value.resolved_receipt())),
                (
                    "last_terminal_acknowledged",
                    value
                        .resolved_acknowledged()
                        .map_or_else(|| "null".to_owned(), |value| value.to_string()),
                ),
                ("last_advance", advance),
            ])
        },
    );
    object(&[
        ("subscription_id", string(&entry.subscription_id)),
        ("subscription_digest", string(&entry.state_digest.to_text())),
        (
            "authority_digest",
            string(&entry.authority_digest.to_text()),
        ),
        ("authority_current", entry.authority_current.to_string()),
        (
            "configuration_digest",
            string(&entry.configuration_digest.to_text()),
        ),
        ("maximum_attempts", entry.maximum_attempts.to_string()),
        ("attempts_reserved", entry.attempts_reserved.to_string()),
        (
            "attempts_remaining",
            entry
                .maximum_attempts
                .saturating_sub(entry.attempts_reserved)
                .to_string(),
        ),
        (
            "max_read_bytes_per_attempt",
            entry.max_read_bytes.to_string(),
        ),
        (
            "max_read_attempts_per_attempt",
            entry.max_read_attempts.to_string(),
        ),
        ("max_report_bytes", entry.max_report_bytes.to_string()),
        ("reserved_bytes", entry.reserved_bytes.to_string()),
        (
            "reserved_read_attempts",
            entry.reserved_read_attempts.to_string(),
        ),
        ("reservation", reservation),
        ("pending", pending),
        ("schedule", schedule),
        ("last_acknowledged", digest(entry.last_acknowledged)),
        ("last_discarded", digest(entry.last_discarded)),
    ])
}

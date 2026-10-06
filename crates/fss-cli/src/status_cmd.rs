#![forbid(unsafe_code)]
//! `fss status --json [--root <dir>]` (SCHEMA-STATUS-001, `fss.status.v1`).
//!
//! Without `--root` the legacy design-phase document is printed unchanged. With `--root` the
//! deployment is read through [`fss_reference::deployment_status`]: read-only over verified
//! committed authority, never locking, creating, writing, or repairing anything. The rule of the
//! schema is that no status field may imply unsupported readiness, so this projection:
//!
//! - reports sensors and streams as an inventory of retained capsule metadata, never as devices
//!   that are connected, online, or acquiring;
//! - reports per-stream continuity as knowledge about committed history only, and a recorded-file
//!   source as `not_observable_file_source` with a `no_live_continuity` degradation;
//! - names `capabilities_exercised` only from evidence families this root actually committed;
//! - states `not_claimed` for device acquisition, live streaming, and real-provider alerts;
//! - reports situation and handoff digests as `not_observable`, because the reader does not read
//!   them, rather than inventing or omitting them;
//! - refuses (never truncates) when a read or output bound is exceeded, so no count is ever a
//!   total from a partial replay.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fss_core::{EffectState, ObligationState};
use fss_reference::agent_orient::{OrientLimits, obligation_state_str};
use fss_reference::deployment_status::{
    DeploymentStatus, StatusError, StatusLimits, StreamContinuity, StreamInventory,
    inspect_deployment_status,
};
use fss_reference::doctor::writer_state_name;

use crate::agent_json::{array, object, optional_string, string, strings};
use crate::error::{CliError, ERR_DOCTOR_NOT_A_DEPLOYMENT, ExitIdentity};
use crate::orient_cmd::{collect_options, take};
use crate::redact::redact_value_or_digest;
use crate::token::ArgToken;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Schema identity of status output (SCHEMA-STATUS-001).
pub const STATUS_SCHEMA: &str = "fss.status.v1";
/// Maximum complete status document size. An oversized document is refused, never truncated.
pub const MAX_STATUS_OUTPUT_BYTES: usize = 1024 * 1024;
/// Largest admitted `--max-journal-bytes` (the reader's own ceiling).
pub const MAX_STATUS_JOURNAL_BYTES: usize = 64 * 1024 * 1024;

/// `fss status`: a status read refused because a required input cannot be read.
pub const ERR_STATUS_UNREADABLE: &str = "ERR-STATUS-UNREADABLE-001";
/// `fss status`: committed history, an object, or an identity failed verification.
pub const ERR_STATUS_CORRUPT: &str = "ERR-STATUS-CORRUPT-001";
/// `fss status`: a read, aggregate, or output bound was exceeded; no partial totals are printed.
pub const ERR_STATUS_OVER_BUDGET: &str = "ERR-STATUS-OVER-BUDGET-001";
/// `fss status`: committed authority changed during the read; the read may be retried.
pub const ERR_STATUS_CHANGED: &str = "ERR-STATUS-CHANGED-001";
/// `fss status`: the read was cancelled at a checkpoint.
pub const ERR_STATUS_CANCELLED: &str = "ERR-STATUS-CANCELLED-001";

/// Readiness the status document never claims, whatever the root contains.
pub const NOT_CLAIMED_READINESS: [&str; 3] = [
    "device_acquisition",
    "live_streaming",
    "real_provider_alerts",
];

/// Options for `fss status`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StatusArgs {
    /// Deployment root to inspect read-only; `None` prints the legacy document.
    pub root: Option<PathBuf>,
    /// Ledger and effect-journal byte bound (`--max-journal-bytes`); `None` is the reader default.
    pub max_journal_bytes: Option<usize>,
}

/// Parses `status --json [--root <dir>] [--max-journal-bytes <n>]`, each at most once.
pub fn parse_status_args(tokens: &[ArgToken]) -> Result<StatusArgs, CliError> {
    let values = collect_options("status", tokens, &["--root", "--max-journal-bytes"])?;
    let root = take(&values, "--root").map(|(_, value, _)| PathBuf::from(value));
    let max_journal_bytes = match take(&values, "--max-journal-bytes") {
        None => None,
        Some((_, value, index)) => {
            let malformed = || CliError::MalformedValue {
                option: "--max-journal-bytes".to_owned(),
                value: value.clone(),
                reason: format!(
                    "expected a canonical decimal integer in 1..={MAX_STATUS_JOURNAL_BYTES}"
                ),
                command: Some("status".to_owned()),
                index: *index,
            };
            let parsed: usize = value.parse().map_err(|_| malformed())?;
            if parsed == 0 || parsed > MAX_STATUS_JOURNAL_BYTES || parsed.to_string() != *value {
                return Err(malformed());
            }
            Some(parsed)
        }
    };
    if max_journal_bytes.is_some() && root.is_none() {
        return Err(CliError::MissingValue {
            option: "--root".to_owned(),
            command: Some("status".to_owned()),
            expected: "`--max-journal-bytes` bounds a deployment read and needs `--root <dir>`"
                .to_owned(),
        });
    }
    Ok(StatusArgs {
        root,
        max_journal_bytes,
    })
}

/// The legacy document printed without `--root` (unchanged since the design phase).
#[must_use]
pub fn legacy_status() -> String {
    format!(
        "{{\"schema\":\"fss.status.v1\",\"version\":\"{VERSION}\",\"phase\":\"reference_implementation_unqualified\",\"deployment\":\"not_specified\",\"sensors\":[],\"events\":[],\"degraded\":[\"no_deployment_root_inspected\",\"not_release_qualified\"]}}"
    )
}

/// Executes `fss status`.
#[must_use]
pub fn execute_status(args: &StatusArgs) -> (String, ExitIdentity) {
    let Some(root) = &args.root else {
        return (legacy_status(), ExitIdentity::SUCCESS);
    };
    let mut limits = StatusLimits::default();
    if let Some(bytes) = args.max_journal_bytes {
        limits.snapshot = OrientLimits {
            max_journal_bytes: bytes,
            ..limits.snapshot
        };
    }
    match inspect_deployment_status(root, &limits) {
        Ok(status) => {
            let rendered = render_status(&status, &limits);
            if rendered.len() > MAX_STATUS_OUTPUT_BYTES {
                return refusal(root, StatusError::OverBudget);
            }
            (rendered, ExitIdentity::SUCCESS)
        }
        Err(error) => refusal(root, error),
    }
}

/// Error and exit identities of one refusal; not-a-deployment shares the doctor's identities.
#[must_use]
pub const fn refusal_identity(error: StatusError) -> (&'static str, ExitIdentity) {
    match error {
        StatusError::NotADeployment => (
            ERR_DOCTOR_NOT_A_DEPLOYMENT,
            ExitIdentity::DOCTOR_NOT_A_DEPLOYMENT,
        ),
        StatusError::Unreadable => (ERR_STATUS_UNREADABLE, ExitIdentity::STATUS_REFUSED),
        StatusError::Corrupt => (ERR_STATUS_CORRUPT, ExitIdentity::STATUS_REFUSED),
        StatusError::OverBudget => (ERR_STATUS_OVER_BUDGET, ExitIdentity::STATUS_REFUSED),
        StatusError::Changed => (ERR_STATUS_CHANGED, ExitIdentity::STATUS_REFUSED),
        StatusError::Cancelled => (ERR_STATUS_CANCELLED, ExitIdentity::STATUS_REFUSED),
    }
}

fn refusal(root: &Path, error: StatusError) -> (String, ExitIdentity) {
    let (error_id, exit) = refusal_identity(error);
    let (retryable, recovery) = match error {
        StatusError::Changed => (true, "safe_read_retry"),
        StatusError::OverBudget => (false, "never_unchanged"),
        _ => (false, "operator_action_required"),
    };
    let input = redact_value_or_digest(&root.to_string_lossy());
    let rendered = object(&[
        ("schema", string("fss.cli_diagnostic.v1")),
        ("phase", string("execution")),
        ("binary", string("fss")),
        ("command", string("status")),
        ("argument_index", "null".to_owned()),
        ("redacted_input", string(&input)),
        ("error_id", string(error_id)),
        ("exit_id", string(exit.identifier)),
        ("exit_code", exit.code.to_string()),
        ("reason", string(&error.to_string())),
        ("contract_basis", string("fss/1")),
        ("effect_started", "false".to_owned()),
        ("partial_totals", "false".to_owned()),
        ("retryable", retryable.to_string()),
        ("recovery_class", string(recovery)),
        ("correlation_id", string(&format!("corr-fss-{error_id}"))),
        ("proof_handle", string("fss://proof/cli/status-refusal")),
    ]);
    (rendered, exit)
}

/// Capability label exercised by one committed evidence family; `None` for families not named.
fn family_capability(family: &str) -> Option<&'static str> {
    Some(match family {
        "sensor_capsule" => "source_custody_capsules",
        "file_import_manifest" => "reference_file_import",
        "rtpdump_import" => "recorded_rtp_session_import",
        "acquisition_transition" => "recorded_file_acquisition_history",
        "decode_receipt" => "reference_decode_receipts",
        "model_invocation_receipt" => "reference_model_invocation",
        "executor_model_result" => "scalar_executor_results",
        "event_revision" => "reference_event_publication",
        "sensor_tamper_status" => "sensor_tamper_status",
        "alert_effect_outcome" => "alert_effect_outcome_records",
        "coverage_witness" => "retained_coverage_witnesses",
        "virtual_capture" => "virtual_camera_capture",
        "twin_localization_receipt" => "twin_localization_receipts",
        "privacy_mask_policy" => "owner_privacy_mask_policy",
        "evidence_hold" => "evidence_holds",
        "deletion_record" | "deletion_tombstone" | "deletion_completion" => "committed_deletion",
        _ => return None,
    })
}

fn degraded(kind: &str, subject: Option<&str>, count: Option<usize>) -> String {
    let mut fields = vec![("kind", string(kind))];
    if let Some(subject) = subject {
        fields.push(("subject", string(subject)));
    }
    if let Some(count) = count {
        fields.push(("count", count.to_string()));
    }
    object(&fields)
}

fn capture_time_class(row: &StreamInventory) -> &'static str {
    if row.clock_bases.contains("estimated") {
        "estimated_not_capture_truth"
    } else {
        "declared_by_source_clock"
    }
}

fn stream_json(row: &StreamInventory) -> String {
    object(&[
        ("stream_id", string(&row.stream_id)),
        ("capsules", row.capsules.to_string()),
        ("recorded_gaps", row.recorded_gaps.to_string()),
        (
            "declared_source_bytes",
            row.declared_source_bytes.to_string(),
        ),
        (
            "capture_interval",
            object(&[
                ("earliest_ns", row.capture_earliest.0.to_string()),
                ("latest_ns", row.capture_latest.0.to_string()),
                ("clock_bases", strings(&row.clock_bases)),
                ("capture_time_class", string(capture_time_class(row))),
            ]),
        ),
        (
            "continuity",
            object(&[
                ("knowledge", string(row.continuity.as_str())),
                ("witnessed_continuous", row.witnessed_continuous.to_string()),
                ("witnessed_degraded", row.witnessed_degraded.to_string()),
                ("scope", string("committed_history_only")),
                ("live", string("not_claimed")),
            ]),
        ),
    ])
}

fn counts_json(counts: &BTreeMap<&str, usize>) -> String {
    object(
        &counts
            .iter()
            .map(|(key, value)| (*key, value.to_string()))
            .collect::<Vec<_>>(),
    )
}

/// Renders one successful read as `fss.status.v1`.
#[must_use]
pub fn render_status(status: &DeploymentStatus, limits: &StatusLimits) -> String {
    let snapshot = &status.snapshot;
    let sources = &status.sources;

    let mut sensors: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for row in &sources.streams {
        sensors
            .entry(row.sensor_id.as_str())
            .or_default()
            .push(stream_json(row));
    }
    let sensor_rows: Vec<String> = sensors
        .iter()
        .map(|(sensor, streams)| {
            object(&[
                ("sensor_id", string(sensor)),
                ("inventory_basis", string("retained_capsule_metadata")),
                ("streams", array(streams)),
            ])
        })
        .collect();

    let mut events_by_state: BTreeMap<&str, usize> = BTreeMap::new();
    for retained in &snapshot.events {
        *events_by_state
            .entry(retained.event.state.as_str())
            .or_default() += 1;
    }
    let mut obligations_by_state: BTreeMap<&str, usize> = BTreeMap::new();
    let (mut terminal, mut pending, mut indeterminate) = (0_usize, 0_usize, 0_usize);
    for obligation in &snapshot.obligations {
        *obligations_by_state
            .entry(obligation_state_str(obligation.state))
            .or_default() += 1;
        match obligation.state {
            ObligationState::Pending => pending += 1,
            ObligationState::Indeterminate => indeterminate += 1,
            ObligationState::Verified | ObligationState::Failed | ObligationState::Cancelled => {
                terminal += 1;
            }
        }
    }
    let mut operations_by_state: BTreeMap<&str, usize> = BTreeMap::new();
    for operation in &snapshot.operations {
        *operations_by_state
            .entry(operation.state.as_str())
            .or_default() += 1;
    }
    let indeterminate_effects = snapshot
        .operations
        .iter()
        .filter(|operation| operation.state == EffectState::Indeterminate)
        .count();

    let mut exercised = Vec::new();
    let mut other_families = Vec::new();
    for (family, count) in &snapshot.family_counts {
        match family_capability(family) {
            Some(capability) => exercised.push(object(&[
                ("capability", string(capability)),
                ("evidence_family", string(family)),
                ("committed_deltas", count.to_string()),
            ])),
            None => other_families.push(object(&[
                ("evidence_family", string(family)),
                ("committed_deltas", count.to_string()),
            ])),
        }
    }
    if !snapshot.operations.is_empty() {
        exercised.push(object(&[
            ("capability", string("durable_effect_journal")),
            ("evidence_family", string("effect_journal")),
            ("committed_deltas", snapshot.operations.len().to_string()),
        ]));
    }

    let possibly_stale = status.possibly_stale();
    let mut degradations = vec![degraded("not_release_qualified", None, None)];
    let file_streams = sources
        .streams
        .iter()
        .filter(|row| row.continuity == StreamContinuity::NotObservableFileSource)
        .count();
    if file_streams > 0 {
        degradations.push(degraded("no_live_continuity", None, Some(file_streams)));
    }
    let unwitnessed = sources
        .streams
        .iter()
        .filter(|row| row.continuity == StreamContinuity::NotObservable)
        .count();
    if unwitnessed > 0 {
        degradations.push(degraded(
            "continuity_not_witnessed",
            None,
            Some(unwitnessed),
        ));
    }
    let degraded_streams = sources
        .streams
        .iter()
        .filter(|row| row.continuity == StreamContinuity::Degraded)
        .count();
    if degraded_streams > 0 {
        degradations.push(degraded(
            "continuity_degraded",
            None,
            Some(degraded_streams),
        ));
    }
    let gaps: usize = sources.streams.iter().map(|row| row.recorded_gaps).sum();
    if gaps > 0 {
        degradations.push(degraded("recorded_gaps", None, Some(gaps)));
    }
    for import in &sources.incomplete_imports {
        degradations.push(degraded("incomplete_import", Some(import), None));
    }
    if sources.incomplete_import_capsules > 0 {
        degradations.push(degraded(
            "incomplete_import_capsules_excluded",
            None,
            Some(sources.incomplete_import_capsules),
        ));
    }
    let gapped_coverage = snapshot
        .source_coverage
        .iter()
        .filter(|retained| {
            retained.record.witness.continuity != fss_core::CoverageContinuity::Continuous
        })
        .count();
    if gapped_coverage > 0 {
        degradations.push(degraded("coverage_gap", None, Some(gapped_coverage)));
    }
    if indeterminate_effects > 0 {
        degradations.push(degraded(
            "indeterminate_effects",
            None,
            Some(indeterminate_effects),
        ));
    }
    if pending + indeterminate > 0 {
        degradations.push(degraded(
            "open_obligations",
            None,
            Some(pending + indeterminate),
        ));
    }
    if snapshot.ledger_tail_uncommitted {
        degradations.push(degraded("ledger_tail_uncommitted", None, None));
    }
    if snapshot.effect_tail_uncommitted {
        degradations.push(degraded("effect_tail_uncommitted", None, None));
    }
    if !status.ledger_present {
        degradations.push(degraded("no_committed_ledger", None, None));
    }
    if snapshot.doctor_verdict.as_str() != "healthy" {
        degradations.push(degraded(
            "doctor_attention",
            Some(snapshot.doctor_verdict.as_str()),
            None,
        ));
    }
    if snapshot.coverage_evidence_unattributed {
        degradations.push(degraded("coverage_evidence_unattributed", None, None));
    }
    if possibly_stale {
        degradations.push(degraded("possibly_stale", None, None));
    }

    let last_manifest_root = snapshot.completed_imports.last().map(|d| d.to_text());
    let rtpdump_records = snapshot
        .family_counts
        .get("rtpdump_import")
        .copied()
        .unwrap_or(0);

    object(&[
        ("schema", string(STATUS_SCHEMA)),
        ("version", string(VERSION)),
        ("phase", string("reference_implementation_unqualified")),
        ("deployment", string("inspected_read_only")),
        ("read_only", "true".to_owned()),
        (
            "anchor",
            object(&[
                ("site_lineage", string(&snapshot.site_lineage)),
                ("ledger_epoch", snapshot.anchor.ledger_epoch.to_string()),
                (
                    "commit_sequence",
                    snapshot.anchor.commit_sequence.to_string(),
                ),
                ("state_root", string(&snapshot.anchor.state_root.to_text())),
                ("ledger_root", string(&snapshot.ledger_root.to_text())),
                ("batch_count", snapshot.batch_count.to_string()),
                (
                    "effect_records",
                    snapshot
                        .position
                        .effect_records
                        .map_or_else(|| "null".to_owned(), |n| n.to_string()),
                ),
                ("ledger_present", status.ledger_present.to_string()),
                (
                    "ledger_tail_uncommitted",
                    snapshot.ledger_tail_uncommitted.to_string(),
                ),
                (
                    "effect_tail_uncommitted",
                    snapshot.effect_tail_uncommitted.to_string(),
                ),
            ]),
        ),
        (
            "writer",
            object(&[
                (
                    "state_before",
                    string(writer_state_name(&status.writer_before)),
                ),
                (
                    "state_after",
                    string(writer_state_name(&status.writer_after)),
                ),
                ("possibly_stale", possibly_stale.to_string()),
                ("basis", string("lock_table_observation_no_lock_taken")),
            ]),
        ),
        ("doctor_verdict", string(snapshot.doctor_verdict.as_str())),
        ("sensors", array(&sensor_rows)),
        (
            "capsules",
            object(&[
                ("retained", sources.retained_capsules.to_string()),
                ("historical_objects", sources.capsule_objects.to_string()),
                ("deleted", sources.deleted_capsules.to_string()),
                (
                    "excluded_incomplete_import",
                    sources.incomplete_import_capsules.to_string(),
                ),
                (
                    "metadata_bytes_read",
                    sources.metadata_bytes_read.to_string(),
                ),
                ("source_payloads_read", "false".to_owned()),
            ]),
        ),
        (
            "imports",
            object(&[
                (
                    "file_imports_completed",
                    sources.completed_imports.to_string(),
                ),
                (
                    "file_imports_incomplete",
                    sources.incomplete_imports.len().to_string(),
                ),
                ("file_imports_deleted", sources.deleted_imports.to_string()),
                (
                    "last_import_manifest_root",
                    optional_string(last_manifest_root.as_deref()),
                ),
                (
                    "last_import_ledger_root",
                    optional_string(snapshot.import_ledger_root.map(|d| d.to_text()).as_deref()),
                ),
                ("rtpdump_import_records", rtpdump_records.to_string()),
            ]),
        ),
        (
            "events",
            object(&[
                ("count", snapshot.events.len().to_string()),
                ("by_state", counts_json(&events_by_state)),
                (
                    "deletions_committed",
                    snapshot.deletions_committed.to_string(),
                ),
                ("hydrate", string("fss query --json --root <dir>")),
            ]),
        ),
        (
            "obligations",
            object(&[
                ("count", snapshot.obligations.len().to_string()),
                ("terminal", terminal.to_string()),
                ("pending", pending.to_string()),
                ("indeterminate", indeterminate.to_string()),
                ("by_state", counts_json(&obligations_by_state)),
            ]),
        ),
        (
            "effects",
            object(&[
                (
                    "journal_present",
                    snapshot.effect_journal_present.to_string(),
                ),
                ("operations", snapshot.operations.len().to_string()),
                ("by_state", counts_json(&operations_by_state)),
                ("provider_identity", string("not_read_by_status")),
            ]),
        ),
        (
            "situation",
            object(&[
                ("last_situation_digest", "null".to_owned()),
                ("last_handoff_digest", "null".to_owned()),
                ("knowledge", string("not_observable")),
                (
                    "reason",
                    string("situation and handoff digests are not read by status"),
                ),
                (
                    "affordance",
                    string("fss session orient --json --root <dir>"),
                ),
            ]),
        ),
        ("capabilities_exercised", array(&exercised)),
        ("other_committed_families", array(&other_families)),
        (
            "readiness",
            object(&[
                ("device_acquisition", string("not_claimed")),
                ("live_streaming", string("not_claimed")),
                ("real_provider_alerts", string("not_claimed")),
                ("release_qualification", string("not_qualified")),
            ]),
        ),
        ("degraded", array(&degradations)),
        (
            "bounds",
            object(&[
                (
                    "max_journal_bytes",
                    limits.snapshot.max_journal_bytes.to_string(),
                ),
                ("max_streams", limits.max_streams.to_string()),
                ("max_capsules", limits.max_capsules.to_string()),
                ("max_output_bytes", MAX_STATUS_OUTPUT_BYTES.to_string()),
                ("complete", "true".to_owned()),
                ("on_exceed", string("refuse_never_truncate")),
            ]),
        ),
        (
            "next",
            strings([
                "fss doctor --json --root <dir>",
                "fss query --json --root <dir>",
                "fss session orient --json --root <dir>",
            ]),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::tokenize_os_args;
    use std::ffi::OsString;

    fn parse(args: &[&str]) -> Result<StatusArgs, CliError> {
        let tokens = tokenize_os_args(args.iter().map(OsString::from))?;
        parse_status_args(&tokens)
    }

    #[test]
    fn grammar_is_exact() -> Result<(), CliError> {
        assert_eq!(parse(&["status", "--json"])?, StatusArgs::default());
        assert_eq!(
            parse(&[
                "status",
                "--json",
                "--root",
                "/d",
                "--max-journal-bytes",
                "4096"
            ])?,
            StatusArgs {
                root: Some(PathBuf::from("/d")),
                max_journal_bytes: Some(4096),
            }
        );
        assert_eq!(
            parse(&["status", "--root=/d", "--json"])?.root,
            Some(PathBuf::from("/d"))
        );
        for bad in [
            &["status"][..],
            &["status", "--root", "/d"],
            &["status", "--json", "extra"],
            &["status", "--json", "--root", "/a", "--root", "/b"],
            &[
                "status",
                "--json",
                "--root",
                "/d",
                "--max-journal-bytes",
                "0",
            ],
            &[
                "status",
                "--json",
                "--root",
                "/d",
                "--max-journal-bytes",
                "007",
            ],
            &[
                "status",
                "--json",
                "--root",
                "/d",
                "--max-journal-bytes",
                "67108865",
            ],
            &["status", "--json", "--max-journal-bytes", "4096"],
            &["status", "--json", "--verbose"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?} must be refused");
        }
        Ok(())
    }

    #[test]
    fn legacy_document_is_unchanged() {
        assert_eq!(
            legacy_status(),
            format!(
                "{{\"schema\":\"fss.status.v1\",\"version\":\"{VERSION}\",\"phase\":\"reference_implementation_unqualified\",\"deployment\":\"not_specified\",\"sensors\":[],\"events\":[],\"degraded\":[\"no_deployment_root_inspected\",\"not_release_qualified\"]}}"
            )
        );
    }

    #[test]
    fn every_refusal_has_a_registered_identity() {
        for (error, id) in [
            (StatusError::NotADeployment, ERR_DOCTOR_NOT_A_DEPLOYMENT),
            (StatusError::Unreadable, ERR_STATUS_UNREADABLE),
            (StatusError::Corrupt, ERR_STATUS_CORRUPT),
            (StatusError::OverBudget, ERR_STATUS_OVER_BUDGET),
            (StatusError::Changed, ERR_STATUS_CHANGED),
            (StatusError::Cancelled, ERR_STATUS_CANCELLED),
        ] {
            let (error_id, exit) = refusal_identity(error);
            assert_eq!(error_id, id);
            assert_ne!(exit.code, 0);
            assert!(crate::crosswalk::REGISTERED_EXIT_IDENTITIES.contains(&exit.identifier));
        }
    }

    #[test]
    fn family_capabilities_never_name_unsupported_readiness() {
        for family in [
            "sensor_capsule",
            "file_import_manifest",
            "rtpdump_import",
            "acquisition_transition",
            "decode_receipt",
            "model_invocation_receipt",
            "executor_model_result",
            "event_revision",
            "sensor_tamper_status",
            "alert_effect_outcome",
            "coverage_witness",
            "virtual_capture",
            "twin_localization_receipt",
            "privacy_mask_policy",
            "evidence_hold",
            "deletion_record",
        ] {
            let capability = family_capability(family).unwrap_or("unnamed");
            for forbidden in NOT_CLAIMED_READINESS {
                assert!(!capability.contains(forbidden), "{family} -> {capability}");
            }
            assert!(!capability.contains("live"), "{family} -> {capability}");
        }
        assert_eq!(family_capability("unknown_family"), None);
    }
}

#![forbid(unsafe_code)]
//! Bounded cold custody inspection; no deployment mutation owner is opened.

use super::{
    BudgetVector, CAP_ALERT_STATUS, ContentDigest, ContextAuthority, MAX_CONTROL_JOURNAL_BYTES,
    OperationId, Options, ReplayCx, RootAuthoritySpec, RunResult, object, string,
};
use fss_cli::alert_effect::report::wire_json;
use fss_reference::webhook::retained::{
    WebhookRetentionError, read_retained_webhook_evidence_from_root,
};

pub(super) fn run(options: &Options) -> RunResult<String> {
    let operation = options
        .operation
        .as_ref()
        .ok_or(WebhookRetentionError::NotAlert)?;
    let root = if options.root.is_absolute() {
        options.root.clone()
    } else {
        std::env::current_dir()?.join(&options.root)
    };
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:alert-wire-inspection-cli".into(),
        operation_id: OperationId::parse("operation:alert-wire-inspection-cli")?,
        principal: options.principal.clone(),
        capabilities: vec!["ADP-REPLAY-001".into(), CAP_ALERT_STATUS.into()],
        deadline: None,
        priority: 10,
        // Both journals are bounded and reread to detect mixed snapshots. Metadata and each
        // actual file read are charged by the strict inspector before invoking read-only I/O.
        budgets: BudgetVector::builder()
            .bytes(4 * MAX_CONTROL_JOURNAL_BYTES + 1024 * 1024)
            .storage_operations(512)
            .build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:read-existing-only".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority_read_only(&authority, root.clone())?;
    let result = read_retained_webhook_evidence_from_root(&root, operation, &authority, &cx);
    cx.drain_and_finalize();
    let retained = result?;
    Ok(object(&[
        ("format", string("fss.alert_lifecycle_cli.v1")),
        ("action", string("evidence")),
        ("site", string(&options.site)),
        ("operation_id", string(operation.as_str())),
        (
            "wire_evidence",
            retained.as_ref().map_or_else(
                || "null".into(),
                |wire| wire_json(wire, wire.journal_observation_recorded()),
            ),
        ),
        (
            "next_step",
            string(
                if retained
                    .as_ref()
                    .is_some_and(|wire| !wire.journal_observation_recorded())
                {
                    "inspect_unrecorded_observation_and_reconcile_do_not_resend"
                } else if retained.is_some() {
                    "inspect_delivery_obligation_and_independent_evidence_do_not_resend"
                } else {
                    "no_published_wire_observation_inspect_operation_before_any_action"
                },
            ),
        ),
        ("network_access", "false".into()),
        ("writes", string("none")),
        ("dispatch_authorized", "false".into()),
        ("qualification", string("implemented_not_qualified")),
    ]))
}

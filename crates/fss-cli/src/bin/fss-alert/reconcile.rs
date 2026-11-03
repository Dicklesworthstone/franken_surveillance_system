#![forbid(unsafe_code)]
//! Source-independent access to the canonical owner-attestation reconciliation contract.

use super::{
    AlertAttestation, AlertControlError, BudgetVector, ContentDigest, ContextAuthority, Options,
    ReferenceDeployment, ReplayCx, RootAuthoritySpec, RunResult, TimestampNs, evidence_anchor,
    object, operation_json, preflight, shell_arg, string,
};
use fss_core::OperationId;
use fss_reference::alert_reconcile::{
    AlertReconciliationPlan, CAP_ALERT_RECONCILE, preview_alert_reconciliation,
    reconcile_alert_operation,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn approval_command(options: &Options, plan: &AlertReconciliationPlan) -> Option<String> {
    let attestation = plan.attestation();
    Some(format!(
        "fss-alert reconcile --root {} --site {} --operation-id {} --principal {} \
         --outcome {} --evidence {} --statement {} --approve {}",
        shell_arg(options.root.to_str()?),
        shell_arg(&options.site),
        shell_arg(plan.prepared().intent.operation_id.as_str()),
        shell_arg(plan.principal()),
        attestation.outcome.as_str(),
        attestation.evidence.to_text(),
        shell_arg(&attestation.statement),
        plan.approval_digest().to_text(),
    ))
}

fn plan_json(options: &Options, plan: &AlertReconciliationPlan) -> String {
    let attestation = plan.attestation();
    object(&[
        (
            "operation_id",
            string(plan.prepared().intent.operation_id.as_str()),
        ),
        (
            "obligation_id",
            string(plan.prepared().obligation_id.as_str()),
        ),
        (
            "prepared_record_digest",
            string(&plan.prepared().prepared_record_digest().to_text()),
        ),
        ("principal", string(plan.principal())),
        ("attested_outcome", string(attestation.outcome.as_str())),
        ("evidence_digest", string(&attestation.evidence.to_text())),
        ("statement", string(&attestation.statement)),
        (
            "observed_receipt_digest",
            string(&plan.observed_receipt().to_text()),
        ),
        (
            "attestation_record_digest",
            string(&plan.record_digest().to_text()),
        ),
        ("approval_digest", string(&plan.approval_digest().to_text())),
        (
            "approve_command",
            approval_command(options, plan).map_or_else(|| "null".into(), |s| string(&s)),
        ),
        (
            "command_encoding",
            string(if options.root.to_str().is_some() {
                "posix_shell_quoted"
            } else {
                "non_utf8_root_reuse_original_command_and_append_approval"
            }),
        ),
        ("approval_is_authority", "false".into()),
    ])
}

pub(super) fn run(options: &Options, attestation: &AlertAttestation) -> RunResult<String> {
    let operation = options
        .operation
        .as_ref()
        .ok_or(AlertControlError::NotAlert)?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:alert-reconcile-cli".into(),
        operation_id: OperationId::parse("operation:alert-reconcile-cli")?,
        principal: options.principal.clone(),
        capabilities: vec!["ADP-REPLAY-001".into(), CAP_ALERT_RECONCILE.into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(super::MAX_REPORT_BYTES as u64)
            .storage_operations(8192)
            .build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })?;
    // Refuse a missing/foreign deployment before ReplayCx can create its root. No
    // orientation snapshot is needed: the canonical owner verifies both physical
    // journals and the exact preparation, then retains its own attestation proof.
    preflight(options)?;
    let cx = ReplayCx::from_context_authority(&authority, options.root.clone())?;
    let result = (|| -> RunResult<String> {
        let mut deployment = ReferenceDeployment::open(&options.root, &options.site, &cx)?;
        let (plan, outcome, state) = match options.approval {
            None => {
                let plan = preview_alert_reconciliation(
                    &deployment,
                    operation,
                    attestation,
                    &authority,
                    &cx,
                )?;
                let receipt = deployment
                    .effects()
                    .operation(operation)
                    .ok_or(AlertControlError::NotAlert)?;
                let obligation = deployment
                    .effects()
                    .obligation(&plan.prepared().obligation_id)
                    .ok_or(AlertControlError::Inconsistent)?;
                let state = operation_json(receipt, obligation, true);
                (plan, "proposed", state)
            }
            Some(approval) => {
                cx.checkpoint("alert_reconcile:journal_time")?;
                let now = TimestampNs(i128::try_from(
                    SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
                )?);
                let receipt = reconcile_alert_operation(
                    &mut deployment,
                    operation,
                    attestation,
                    approval,
                    now,
                    &authority,
                    &cx,
                )?;
                let state = operation_json(&receipt.operation, &receipt.obligation, true);
                (receipt.plan, receipt.outcome.as_str(), state)
            }
        };
        Ok(object(&[
            ("format", string("fss.alert_lifecycle_cli.v1")),
            ("action", string("reconcile")),
            ("site", string(&options.site)),
            ("anchor", evidence_anchor(deployment.current_anchor())),
            (
                "effect_journal_root",
                string(&deployment.effects().last_root().to_text()),
            ),
            ("outcome", string(outcome)),
            ("plan", plan_json(options, &plan)),
            ("operation", state),
            (
                "new_reconciliation_committed",
                (outcome == "reconciled").to_string(),
            ),
            ("provenance", string("operator_asserted")),
            ("provider_receipt_verified", "false".into()),
            ("cited_evidence_custody", string("not_inspected")),
            ("source_custody", string("not_inspected")),
            (
                "attestation_record_custody",
                string(if outcome == "proposed" {
                    "not_inspected"
                } else {
                    "verified"
                }),
            ),
            ("required_capability", string(CAP_ALERT_RECONCILE)),
            (
                "deployment_open_may_perform_restart_recovery",
                "true".into(),
            ),
            ("network_access", "false".into()),
            ("dispatch_authorized", "false".into()),
            ("qualification", string("implemented_not_qualified")),
        ]))
    })();
    cx.drain_and_finalize();
    result
}

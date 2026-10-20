#![forbid(unsafe_code)]
//! Operator reconciliation must retain its exact proof on new, interrupted, and cold retries.
//! These fixtures use local durable journals only; no alert provider is contacted.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, EffectIntent, EffectState, IdempotencyKey,
    ObligationId, ObligationState, OperationId, RootAuthoritySpec, TimestampNs,
};
use fss_object::ObjectManifest;
use fss_reference::alert_reconcile::{
    AlertAttestation, AlertReconcileError, AlertReconcileOutcome, AlertReconciliationOutcome,
    AlertReconciliationPlan, CAP_ALERT_RECONCILE, preview_alert_reconciliation,
    reconcile_alert_operation,
};
use fss_reference::{REFERENCE_ALERT_TERMINAL_PREDICATE, ReferenceDeployment, ReplayCx};

type TestResult = Result<(), Box<dyn Error>>;
const SITE: &str = "site:alert-reconciliation-contract";

struct Directory(PathBuf);

impl Directory {
    fn new(label: &str) -> Result<Self, Box<dyn Error>> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-alert-reconcile-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("test directory capacity".into())
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn context(root: &Path) -> Result<(ContextAuthority, ReplayCx), Box<dyn Error>> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:reconciliation-contract".into(),
        operation_id: OperationId::parse("operation:reconciliation-contract")?,
        principal: "principal:local-owner".into(),
        capabilities: vec!["ADP-REPLAY-001".into(), CAP_ALERT_RECONCILE.into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(8 * 1024 * 1024)
            .storage_operations(8192)
            .build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, root.to_path_buf())?;
    Ok((authority, cx))
}

fn dispatched(dep: &mut ReferenceDeployment) -> Result<OperationId, Box<dyn Error>> {
    let id = OperationId::parse("operation:alert:lost-ack")?;
    let journal = dep.effects_and_ledger().0;
    journal.prepare(
        EffectIntent::new(
            id.clone(),
            IdempotencyKey::parse("idempotency:alert:lost-ack")?,
            "alert.dispatch",
            ContentDigest::sha256(b"request"),
            ContentDigest::sha256(b"preconditions"),
        )?,
        ObligationId::parse("obligation:alert:lost-ack")?,
        REFERENCE_ALERT_TERMINAL_PREDICATE,
        TimestampNs(100),
    )?;
    journal.transition(&id, EffectState::Committed, TimestampNs(101), None, None)?;
    journal.transition(
        &id,
        EffectState::AdapterAccepted,
        TimestampNs(102),
        None,
        None,
    )?;
    journal.mark_indeterminate(&id, TimestampNs(103), "delivery_unknown")?;
    Ok(id)
}

fn attestation(outcome: AlertReconciliationOutcome) -> AlertAttestation {
    AlertAttestation {
        outcome,
        evidence: ContentDigest::sha256(b"independent owner observation"),
        statement: "Owner checked the recipient's notification history".into(),
    }
}

fn manifest(plan: &AlertReconciliationPlan) -> Result<ObjectManifest, Box<dyn Error>> {
    let hex: String = plan
        .record_digest()
        .bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(ObjectManifest::new(
        format!("alert-reconcile-{hex}"),
        vec![plan.record_digest()],
        None,
    )?)
}

fn journal(dep: &ReferenceDeployment) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(fs::read(dep.effects().path())?)
}

#[test]
fn exact_reconciliation_survives_cold_retry_without_duplicate_transitions() -> TestResult {
    for outcome in [
        AlertReconciliationOutcome::Delivered,
        AlertReconciliationOutcome::NotDelivered,
    ] {
        let dir = Directory::new("cold")?;
        let (auth, cx) = context(&dir.0)?;
        let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let id = dispatched(&mut dep)?;
        let attestation = attestation(outcome);
        let plan = preview_alert_reconciliation(&dep, &id, &attestation, &auth, &cx)?;
        let before = journal(&dep)?;
        assert!(matches!(
            reconcile_alert_operation(
                &mut dep,
                &id,
                &attestation,
                ContentDigest::sha256(b"wrong approval"),
                TimestampNs(104),
                &auth,
                &cx,
            ),
            Err(AlertReconcileError::ApprovalMismatch)
        ));
        assert_eq!(before, journal(&dep)?);
        let result = reconcile_alert_operation(
            &mut dep,
            &id,
            &attestation,
            plan.approval_digest(),
            TimestampNs(104),
            &auth,
            &cx,
        )?;
        let expected = match outcome {
            AlertReconciliationOutcome::Delivered => EffectState::Verified,
            AlertReconciliationOutcome::NotDelivered => EffectState::Failed,
        };
        assert_eq!(result.outcome, AlertReconcileOutcome::Reconciled);
        assert_eq!(result.operation.state, expected);
        assert_eq!(result.operation.result_digest, Some(plan.record_digest()));
        assert_ne!(result.obligation.state, ObligationState::Pending);
        assert_eq!(result.obligation.proof_digest, Some(plan.record_digest()));
        let after = journal(&dep)?;
        let anchor = dep.current_anchor().clone();
        drop(dep);
        cx.drain_and_finalize();
        let (auth, cx) = context(&dir.0)?;
        let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let retry = reconcile_alert_operation(
            &mut dep,
            &id,
            &attestation,
            plan.approval_digest(),
            TimestampNs(0),
            &auth,
            &cx,
        )?;
        assert_eq!(retry.outcome, AlertReconcileOutcome::AlreadyReconciled);
        assert_eq!(retry.operation, result.operation);
        assert_eq!(retry.obligation, result.obligation);
        assert_eq!(journal(&dep)?, after);
        assert_eq!(dep.current_anchor(), &anchor);
    }
    Ok(())
}

#[test]
fn interrupted_publication_cannot_finish_with_lost_or_corrupt_attestation_custody() -> TestResult {
    for damage_manifest in [false, true] {
        for missing in [false, true] {
            let dir = Directory::new("published")?;
            let (auth, cx) = context(&dir.0)?;
            let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
            let id = dispatched(&mut dep)?;
            let attestation = attestation(AlertReconciliationOutcome::Delivered);
            let plan = preview_alert_reconciliation(&dep, &id, &attestation, &auth, &cx)?;
            cx.set_cancel_at_checkpoint("alert_reconcile:request_published");
            assert!(matches!(
                reconcile_alert_operation(
                    &mut dep,
                    &id,
                    &attestation,
                    plan.approval_digest(),
                    TimestampNs(104),
                    &auth,
                    &cx,
                ),
                Err(AlertReconcileError::Cancelled)
            ));
            let (auth, cx) = context(&dir.0)?;
            let anchor = dep.current_anchor().clone();
            let before = journal(&dep)?;
            let digest = if damage_manifest {
                manifest(&plan)?.root()
            } else {
                plan.record_digest()
            };
            let path = dep.publisher().spool().object_path(digest);
            let retained = fs::read(&path)?;
            if missing {
                fs::remove_file(&path)?;
            } else {
                fs::write(&path, vec![0; 8192])?;
            }
            assert!(matches!(
                reconcile_alert_operation(
                    &mut dep,
                    &id,
                    &attestation,
                    plan.approval_digest(),
                    TimestampNs(105),
                    &auth,
                    &cx,
                ),
                Err(AlertReconcileError::Inconsistent)
            ));
            assert_eq!(
                dep.effects().operation(&id).map(|op| op.state),
                Some(EffectState::Indeterminate)
            );
            assert_eq!(journal(&dep)?, before);
            assert_eq!(dep.current_anchor(), &anchor);
            fs::write(&path, retained)?;
            let result = reconcile_alert_operation(
                &mut dep,
                &id,
                &attestation,
                plan.approval_digest(),
                TimestampNs(105),
                &auth,
                &cx,
            )?;
            assert_eq!(result.operation.state, EffectState::Verified);
            assert_eq!(
                dep.current_anchor(),
                &anchor,
                "retry reused the published request"
            );
        }
    }
    Ok(())
}

#[test]
fn observed_and_terminal_retries_revalidate_the_record_and_manifest() -> TestResult {
    for state in [
        EffectState::Observed,
        EffectState::Verified,
        EffectState::Failed,
    ] {
        for damage_manifest in [false, true] {
            let dir = Directory::new("resume")?;
            let (auth, cx) = context(&dir.0)?;
            let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
            let id = dispatched(&mut dep)?;
            let attestation = attestation(if state == EffectState::Failed {
                AlertReconciliationOutcome::NotDelivered
            } else {
                AlertReconciliationOutcome::Delivered
            });
            let plan = preview_alert_reconciliation(&dep, &id, &attestation, &auth, &cx)?;
            if state == EffectState::Observed {
                cx.set_cancel_at_checkpoint("alert_reconcile:request_published");
                assert!(matches!(
                    reconcile_alert_operation(
                        &mut dep,
                        &id,
                        &attestation,
                        plan.approval_digest(),
                        TimestampNs(104),
                        &auth,
                        &cx,
                    ),
                    Err(AlertReconcileError::Cancelled)
                ));
                dep.effects_and_ledger().0.transition(
                    &id,
                    EffectState::Observed,
                    TimestampNs(104),
                    Some(plan.record_digest()),
                    None,
                )?;
            } else {
                reconcile_alert_operation(
                    &mut dep,
                    &id,
                    &attestation,
                    plan.approval_digest(),
                    TimestampNs(104),
                    &auth,
                    &cx,
                )?;
            }
            let (auth, cx) = context(&dir.0)?;
            let before = journal(&dep)?;
            let anchor = dep.current_anchor().clone();
            let digest = if damage_manifest {
                manifest(&plan)?.root()
            } else {
                plan.record_digest()
            };
            let path = dep.publisher().spool().object_path(digest);
            let retained = fs::read(&path)?;
            fs::remove_file(&path)?;
            assert!(matches!(
                reconcile_alert_operation(
                    &mut dep,
                    &id,
                    &attestation,
                    plan.approval_digest(),
                    TimestampNs(106),
                    &auth,
                    &cx,
                ),
                Err(AlertReconcileError::Inconsistent)
            ));
            assert_eq!(journal(&dep)?, before);
            assert_eq!(dep.current_anchor(), &anchor);
            assert_eq!(dep.effects().operation(&id).map(|op| op.state), Some(state));
            fs::write(&path, retained)?;
            let retry = reconcile_alert_operation(
                &mut dep,
                &id,
                &attestation,
                plan.approval_digest(),
                TimestampNs(106),
                &auth,
                &cx,
            )?;
            assert_eq!(
                retry.outcome,
                if state == EffectState::Observed {
                    AlertReconcileOutcome::Reconciled
                } else {
                    AlertReconcileOutcome::AlreadyReconciled
                }
            );
        }
    }
    Ok(())
}

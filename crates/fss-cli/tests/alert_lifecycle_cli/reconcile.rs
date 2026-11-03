#![forbid(unsafe_code)]
//! Recovery through the actual CLI after the old event custody has been lost.

use super::{
    ContentDigest, Directory, OPERATION, OrientLimits, TestResult, context, digest_field, files,
    fixture, fs, invoke, open, publish_hypothesis, read_deployment, success,
};
use fss_core::{BudgetVector, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_reference::ReplayCx;
use fss_reference::alert_reconcile::{
    AlertAttestation, AlertReconcileError, AlertReconciliationOutcome, CAP_ALERT_RECONCILE,
    preview_alert_reconciliation,
};

fn args<'a>(outcome: &'a str, evidence: &'a str, statement: &'a str) -> Vec<&'a str> {
    vec![
        "--operation-id",
        OPERATION,
        "--outcome",
        outcome,
        "--evidence",
        evidence,
        "--statement",
        statement,
    ]
}

#[test]
fn delivery_and_non_delivery_reconcile_without_old_event_custody() -> TestResult {
    for (outcome, terminal) in [("delivered", "verified"), ("not_delivered", "failed")] {
        for missing in [true, false] {
            let dir = Directory::new("reconcile-source-loss")?;
            fixture(&dir.0, true)?;
            let manifest = publish_hypothesis(&dir.0)?;
            read_deployment(&dir.0, &OrientLimits::default())?;
            if missing {
                fs::remove_file(&manifest)?;
            } else {
                fs::write(&manifest, b"corrupt old event manifest")?;
            }
            assert!(read_deployment(&dir.0, &OrientLimits::default()).is_err());
            let evidence = ContentDigest::sha256(outcome.as_bytes()).to_text();
            let statement = "Recipient's independently observed outcome; no relay ACK inference";
            let mut request = args(outcome, &evidence, statement);
            let before = files(&dir.0)?;
            let preview = success(invoke(&dir.0, "reconcile", &request)?)?;
            assert!(preview.contains("\"outcome\":\"proposed\""));
            assert!(preview.contains("\"new_reconciliation_committed\":false"));
            assert!(preview.contains("\"reconciliation_candidate\":true"));
            assert!(preview.contains("fss-alert reconcile"));
            assert!(preview.contains("posix_shell_quoted"));
            assert_eq!(
                before,
                files(&dir.0)?,
                "preview cannot change the attestation"
            );

            let approval = digest_field(&preview, "approval_digest")?;
            request.extend(["--approve", approval.as_str()]);
            let reconciled = success(invoke(&dir.0, "reconcile", &request)?)?;
            assert!(reconciled.contains("\"outcome\":\"reconciled\""));
            assert!(reconciled.contains("\"new_reconciliation_committed\":true"));
            assert!(reconciled.contains("\"reconciliation_candidate\":false"));
            assert!(reconciled.contains(&format!("\"state\":\"{terminal}\"")));
            assert!(reconciled.contains("\"provenance\":\"operator_asserted\""));
            assert!(reconciled.contains("\"provider_receipt_verified\":false"));
            assert!(reconciled.contains("\"cited_evidence_custody\":\"not_inspected\""));
            assert!(reconciled.contains("\"source_custody\":\"not_inspected\""));
            assert!(reconciled.contains("\"attestation_record_custody\":\"verified\""));
            assert!(reconciled.contains("\"network_access\":false"));
            assert!(reconciled.contains("\"dispatch_authorized\":false"));
            assert_eq!(
                digest_field(&preview, "attestation_record_digest")?,
                digest_field(&reconciled, "attestation_record_digest")?
            );
            assert_eq!(
                digest_field(&preview, "prepared_record_digest")?,
                digest_field(&reconciled, "prepared_record_digest")?
            );
            assert!(read_deployment(&dir.0, &OrientLimits::default()).is_err());
            assert_eq!(
                manifest.exists(),
                !missing,
                "reconciliation cannot repair old custody"
            );

            let after = files(&dir.0)?;
            let retry = success(invoke(&dir.0, "reconcile", &request)?)?;
            assert!(retry.contains("\"outcome\":\"already_reconciled\""));
            assert!(retry.contains("\"new_reconciliation_committed\":false"));
            assert_eq!(
                digest_field(&reconciled, "receipt_digest")?,
                digest_field(&retry, "receipt_digest")?
            );
            assert_eq!(after, files(&dir.0)?, "cold retry must append nothing");
        }
    }
    Ok(())
}

#[test]
fn old_approval_cannot_reconcile_a_different_attestation_or_principal() -> TestResult {
    let dir = Directory::new("reconcile-approval")?;
    fixture(&dir.0, true)?;
    let evidence = ContentDigest::sha256(b"recipient confirmation").to_text();
    let other_evidence = ContentDigest::sha256(b"another observation").to_text();
    let request = args("delivered", &evidence, "The recipient confirmed receipt");
    let preview = success(invoke(&dir.0, "reconcile", &request)?)?;
    let approval = digest_field(&preview, "approval_digest")?;
    let before = files(&dir.0)?;
    for mut changed in [
        args(
            "not_delivered",
            &evidence,
            "The recipient confirmed receipt",
        ),
        args(
            "delivered",
            &other_evidence,
            "The recipient confirmed receipt",
        ),
        args("delivered", &evidence, "A different statement"),
        {
            let mut changed = request.clone();
            changed.extend(["--principal", "principal:another-owner"]);
            changed
        },
    ] {
        changed.extend(["--approve", approval.as_str()]);
        let refused = invoke(&dir.0, "reconcile", &changed)?;
        assert!(!refused.status.success());
        assert!(refused.stdout.is_empty());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("ERR-ALERT-APPROVAL-STALE-001"));
        assert_eq!(before, files(&dir.0)?);
    }
    let mut approved = request;
    approved.extend(["--approve", approval.as_str()]);
    success(invoke(&dir.0, "reconcile", &approved)?)?;
    let after = files(&dir.0)?;
    let mut changed = args(
        "delivered",
        &evidence,
        "A new statement after reconciliation",
    );
    changed.extend(["--approve", approval.as_str()]);
    let refused = invoke(&dir.0, "reconcile", &changed)?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert_eq!(
        after,
        files(&dir.0)?,
        "a different retry cannot inherit terminal proof"
    );
    Ok(())
}

#[test]
fn retained_attestation_custody_is_still_required_on_an_exact_retry() -> TestResult {
    let dir = Directory::new("reconcile-proof-loss")?;
    fixture(&dir.0, true)?;
    let evidence = ContentDigest::sha256(b"confirmed delivery").to_text();
    let mut request = args("delivered", &evidence, "Confirmed by the recipient");
    let preview = success(invoke(&dir.0, "reconcile", &request)?)?;
    let approval = digest_field(&preview, "approval_digest")?;
    request.extend(["--approve", approval.as_str()]);
    let reconciled = success(invoke(&dir.0, "reconcile", &request)?)?;
    let record = digest_field(&reconciled, "attestation_record_digest")?;
    fs::remove_file(
        dir.0
            .join("objects/spool/objects")
            .join(record.trim_start_matches("sha256:")),
    )?;
    let after_loss = files(&dir.0)?;
    let refused = invoke(&dir.0, "reconcile", &request)?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("ERR-ALERT-AUTHORITY-001"));
    assert_eq!(
        after_loss,
        files(&dir.0)?,
        "a terminal proof cannot be recreated silently"
    );
    Ok(())
}

#[test]
fn undispatched_and_unknown_operations_cannot_be_reconciled() -> TestResult {
    let dir = Directory::new("reconcile-prepared")?;
    fixture(&dir.0, false)?;
    let evidence = ContentDigest::sha256(b"operator statement").to_text();
    let before = files(&dir.0)?;
    for outcome in ["delivered", "not_delivered"] {
        let request = args(
            outcome,
            &evidence,
            "Prepared intent is not dispatch evidence",
        );
        let refused = invoke(&dir.0, "reconcile", &request)?;
        assert!(!refused.status.success());
        assert!(refused.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&refused.stderr).contains("ERR-OP-PRECONDITION-FAILED-001")
        );
        assert_eq!(before, files(&dir.0)?);
    }
    let mut request = args("delivered", &evidence, "Unknown operation");
    request[1] = "operation:unknown-alert";
    let refused = invoke(&dir.0, "reconcile", &request)?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("ERR-ALERT-AUTHORITY-001"));
    assert_eq!(before, files(&dir.0)?);
    Ok(())
}

#[test]
fn corrupt_or_missing_journals_cannot_be_recreated_by_reconciliation() -> TestResult {
    let evidence = ContentDigest::sha256(b"recipient confirmation").to_text();
    for relative in ["ledger/journal.fssj", "effects/journal.fssj"] {
        for missing in [true, false] {
            let dir = Directory::new("reconcile-journal")?;
            fixture(&dir.0, true)?;
            fs::remove_file(publish_hypothesis(&dir.0)?)?;
            let path = dir.0.join(relative);
            if missing {
                fs::remove_file(&path)?;
            } else {
                let mut bytes = fs::read(&path)?;
                *bytes
                    .get_mut(88)
                    .ok_or("fixture has no committed payload")? ^= 1;
                fs::write(&path, bytes)?;
            }
            let before = files(&dir.0)?;
            let refused = invoke(
                &dir.0,
                "reconcile",
                &args("delivered", &evidence, "Recipient confirmation"),
            )?;
            assert!(!refused.status.success());
            assert!(refused.stdout.is_empty());
            assert_eq!(before, files(&dir.0)?);
        }
    }
    Ok(())
}

#[test]
fn reconciliation_requires_its_specific_live_owner_grant() -> TestResult {
    let dir = Directory::new("reconcile-grant")?;
    fixture(&dir.0, true)?;
    let cx = context(&dir.0)?;
    let deployment = open(&dir.0, &cx)?;
    let before = files(&dir.0)?;
    let attestation = AlertAttestation {
        outcome: AlertReconciliationOutcome::Delivered,
        evidence: ContentDigest::sha256(b"recipient confirmation"),
        statement: "Recipient confirmed receipt".into(),
    };
    let make_authority = |capabilities| -> TestResult<ContextAuthority> {
        Ok(ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:reconcile-grant-test".into(),
            operation_id: OperationId::parse("operation:reconcile-grant-test")?,
            principal: "principal:local-operator".into(),
            capabilities,
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(8 * 1024 * 1024)
                .storage_operations(8192)
                .build()?,
            privacy_scope: "privacy:local-authorized-files".into(),
            retention_scope: "retention:existing-deployment-policy".into(),
            anchor_universe: ContentDigest::sha256(super::SITE.as_bytes()),
            generation: 1,
        })?)
    };
    let denied_authority = make_authority(vec!["ADP-REPLAY-001".into()])?;
    assert!(matches!(
        preview_alert_reconciliation(
            &deployment,
            &OperationId::parse(OPERATION)?,
            &attestation,
            &denied_authority,
            &cx,
        ),
        Err(AlertReconcileError::Unauthorized)
    ));
    let authority = make_authority(vec!["ADP-REPLAY-001".into(), CAP_ALERT_RECONCILE.into()])?;
    let approved_cx = ReplayCx::from_context_authority(&authority, dir.0.clone())?;
    let owner_plan = preview_alert_reconciliation(
        &deployment,
        &OperationId::parse(OPERATION)?,
        &attestation,
        &authority,
        &approved_cx,
    )?;
    drop(deployment);
    cx.drain_and_finalize();
    approved_cx.drain_and_finalize();
    let evidence = attestation.evidence.to_text();
    let preview = success(invoke(
        &dir.0,
        "reconcile",
        &args("delivered", &evidence, &attestation.statement),
    )?)?;
    assert_eq!(
        digest_field(&preview, "approval_digest")?,
        owner_plan.approval_digest().to_text(),
        "CLI must not define a second reconciliation approval contract"
    );
    assert_eq!(before, files(&dir.0)?);
    Ok(())
}

#[test]
fn malformed_attestations_fail_before_creating_a_deployment() -> TestResult {
    let dir = Directory::new("reconcile-parse")?;
    let missing = dir.0.join("absent");
    let evidence = ContentDigest::sha256(b"attestation").to_text();
    let too_long = "s".repeat(1025);
    let valid = args("delivered", &evidence, "Confirmed by the recipient");
    for request in [
        vec!["--operation-id", OPERATION],
        args("accepted", &evidence, "Relay acceptance is not delivery"),
        args("delivered", "sha256:bad", "Invalid evidence handle"),
        args("delivered", &evidence, ""),
        args("delivered", &evidence, "   "),
        args("delivered", &evidence, "two\nlines"),
        args("delivered", &evidence, &too_long),
        {
            let mut duplicate = valid.clone();
            duplicate.extend(["--outcome", "not_delivered"]);
            duplicate
        },
    ] {
        let refused = invoke(&missing, "reconcile", &request)?;
        assert!(!refused.status.success());
        assert!(refused.stdout.is_empty());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("ERR-CLI-MALFORMED-VALUE-001"));
        assert!(!missing.exists());
    }
    let refused = invoke(&missing, "reconcile", &valid)?;
    assert!(!refused.status.success());
    assert!(!missing.exists());
    Ok(())
}

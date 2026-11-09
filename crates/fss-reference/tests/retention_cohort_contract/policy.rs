#![forbid(unsafe_code)]
//! Policy adoption, exact generation-bound cleanup and durable interruption recovery.

use super::*;
use fss_core::{BatchId, EvidenceDelta, ObjectId, Plane};
use fss_reference::ReferenceError;
use fss_reference::deletion::retention::RETENTION_POLICY_SELECTION_DOMAIN;
use fss_reference::deletion::retention::policy::{
    POLICY_OBJECT_PREFIX, PolicyChangeRequest, PolicyError, PolicyOutcome, RetentionPolicyRecord,
    STAGE_POLICY_COMMITTED, STAGE_POLICY_IMPACT_STAGED, STAGE_POLICY_READ,
    STAGE_POLICY_REVALIDATED, STAGE_POLICY_STAGED, commit_policy_change, list_policies,
    preview_policy_change, request_from_policy,
};
use fss_reference::reference_deployment::FAMILY_RETENTION_POLICY;

fn change(
    expected_policy: Option<ContentDigest>,
    enabled: bool,
) -> TestResult<PolicyChangeRequest> {
    Ok(PolicyChangeRequest {
        sensor: SensorId::parse(SENSOR)?,
        enabled,
        retain_for_ns: 100,
        max_retained_source_bytes: Some(0),
        expected_policy,
        attested_now: interval(1000, 1010)?,
        reason: "Owner-reviewed file-import cleanup settings".to_owned(),
    })
}

fn adopt(f: &mut Fixture, request: &PolicyChangeRequest) -> TestResult<RetentionPolicyRecord> {
    let preview = preview_policy_change(&f.deployment, request, &f.authority, &f.cx)?;
    let receipt = commit_policy_change(
        &mut f.deployment,
        request,
        preview.record.approval(),
        &f.authority,
        &f.cx,
    )?;
    assert_eq!(receipt.outcome, PolicyOutcome::Committed);
    Ok(receipt.record)
}

#[test]
fn adoption_is_read_only_until_exact_approval_and_never_deletes_media() -> TestResult {
    let mut f = Fixture::new("policy-adoption")?;
    let held = f.ingest("held", 40)?;
    let free = f.ingest("free", 80)?;
    f.hold("incident", held, HoldState::Held)?;
    let request = change(None, true)?;
    let before = snapshot(f.deployment.root())?;
    let preview = preview_policy_change(&f.deployment, &request, &f.authority, &f.cx)?;
    assert_eq!(preview.outcome, PolicyOutcome::Proposed);
    assert_eq!(preview.record.generation(), 1);
    let impact = preview.affected.as_ref().ok_or("impact")?;
    let impact_plan = impact.deletion.as_ref().ok_or("impact plan")?;
    assert_eq!(impact_plan.imports, vec![free.identity]);
    assert_eq!(preview.record.affected_plan(), Some(impact_plan.digest()?));
    assert_eq!(snapshot(f.deployment.root())?, before);
    assert!(matches!(
        commit_policy_change(
            &mut f.deployment,
            &request,
            ContentDigest::sha256(b"wrong"),
            &f.authority,
            &f.cx
        ),
        Err(PolicyError::StaleApproval)
    ));
    assert_eq!(snapshot(f.deployment.root())?, before);
    let receipt = commit_policy_change(
        &mut f.deployment,
        &request,
        preview.record.approval(),
        &f.authority,
        &f.cx,
    )?;
    assert_eq!(receipt.record, preview.record);
    assert_eq!(receipt.outcome, PolicyOutcome::Committed);
    f.readable(held)?;
    f.readable(free)?;
    assert!(DeletionIndex::read(&f.deployment)?.entries().is_empty());
    let impact_bytes = f
        .deployment
        .publisher()
        .spool()
        .read(impact_plan.digest()?)?;
    assert_eq!(
        DeletionPlan::decode(&impact_bytes, impact_plan.digest()?)?,
        *impact_plan
    );
    let mut f = f.reopen()?;
    assert_eq!(
        list_policies(&f.deployment, &f.authority, &f.cx)?,
        vec![preview.record.clone()]
    );
    let before = snapshot(f.deployment.root())?;
    let retry = commit_policy_change(
        &mut f.deployment,
        &request,
        preview.record.approval(),
        &f.authority,
        &f.cx,
    )?;
    assert_eq!(retry.outcome, PolicyOutcome::AlreadyCurrent);
    assert_eq!(retry.record, preview.record);
    assert_eq!(snapshot(f.deployment.root())?, before);
    Ok(())
}

#[test]
fn policy_cleanup_inherits_zero_budget_binds_revision_and_keeps_holds_unknown_and_young()
-> TestResult {
    let mut f = Fixture::new("policy-cleanup")?;
    let held = f.ingest("held", 40)?;
    let free = f.ingest("free", 80)?;
    let young = f.ingest_at("young", 120, SENSOR, Some(990))?;
    let unknown = f.ingest_at("unknown", 160, SENSOR, None)?;
    f.hold("incident", held, HoldState::Held)?;
    let policy = adopt(&mut f, &change(None, true)?)?;
    let request =
        request_from_policy(&f.deployment, policy.digest(), interval(1000, 1010)?, &f.cx)?;
    assert_eq!(request.policy_digest(), Some(policy.digest()));
    assert_eq!(request.source_byte_budget(), Some(0));
    let preview = plan_retention(&f.deployment, &request, &f.cx)?;
    assert_eq!(
        preview.assessment.selection.domain(),
        RETENTION_POLICY_SELECTION_DOMAIN
    );
    let accounting = preview
        .assessment
        .selection
        .byte_accounting()
        .ok_or("accounting")?;
    assert_eq!(accounting.max_retained_source_bytes, 0);
    assert!(accounting.unmet_source_bytes > 0);
    let plan = preview.deletion.ok_or("deletion plan")?;
    assert_eq!(plan.imports, vec![free.identity]);
    let digest = plan.digest()?;
    assert_eq!(
        DeletionPlan::decode(&plan.canonical_bytes()?, digest)?,
        plan
    );
    assert_eq!(
        plan_scope_deletion(&f.deployment, &plan.scope, &f.cx)?,
        plan
    );
    let approval = plan.approval_digest(PRINCIPAL)?;
    let overridden = request.clone().with_source_byte_budget(1);
    assert!(matches!(plan_retention(&f.deployment, &overridden, &f.cx),
        Err(DeletionError::RetentionPolicy(error)) if matches!(*error, PolicyError::InvalidRecord)));
    let wrong_time =
        request_from_policy(&f.deployment, policy.digest(), interval(1001, 1010)?, &f.cx)?;
    assert!(matches!(
        commit_retention(
            &mut f.deployment,
            &wrong_time,
            digest,
            approval,
            PRINCIPAL,
            &f.cx
        ),
        Err(DeletionError::StalePlan(_))
    ));
    let receipt = commit_retention(
        &mut f.deployment,
        &request,
        digest,
        approval,
        PRINCIPAL,
        &f.cx,
    )?;
    assert_eq!(receipt.outcome, CommitOutcome::Completed);
    for import in [held, young, unknown] {
        f.readable(import)?;
    }
    assert!(f.deployment.publisher().spool().read(free.source).is_err());
    assert_eq!(
        list_policies(&f.deployment, &f.authority, &f.cx)?,
        vec![policy]
    );
    Ok(())
}

#[test]
fn adoption_approval_is_stale_after_inventory_hold_or_authority_head_changes() -> TestResult {
    for mutation in 0..3 {
        let mut f = Fixture::new("policy-stale-impact")?;
        let import = f.ingest("old", 40)?;
        let request = change(None, true)?;
        let preview = preview_policy_change(&f.deployment, &request, &f.authority, &f.cx)?;
        match mutation {
            0 => {
                f.ingest("new", 80)?;
            }
            1 => f.hold("incident", import, HoldState::Held)?,
            _ => {
                let mut other = change(None, true)?;
                other.sensor = SensorId::parse("sensor:other")?;
                adopt(&mut f, &other)?;
            }
        }
        let before = snapshot(f.deployment.root())?;
        assert!(matches!(
            commit_policy_change(
                &mut f.deployment,
                &request,
                preview.record.approval(),
                &f.authority,
                &f.cx
            ),
            Err(PolicyError::StaleApproval)
        ));
        assert_eq!(snapshot(f.deployment.root())?, before);
        f.readable(import)?;
    }
    Ok(())
}

#[test]
fn superseded_and_disabled_policies_refuse_fresh_cleanup_and_stale_predecessors() -> TestResult {
    let mut f = Fixture::new("policy-generations")?;
    let import = f.ingest("old", 40)?;
    let first = adopt(&mut f, &change(None, true)?)?;
    let first_request =
        request_from_policy(&f.deployment, first.digest(), interval(1000, 1010)?, &f.cx)?;
    let first_plan = plan_retention(&f.deployment, &first_request, &f.cx)?
        .deletion
        .ok_or("plan")?;
    let mut update = change(Some(first.digest()), true)?;
    update.retain_for_ns = 200;
    let second = adopt(&mut f, &update)?;
    assert_eq!(second.generation(), 2);
    assert!(
        matches!(plan_retention(&f.deployment, &first_request, &f.cx),
        Err(DeletionError::RetentionPolicy(error)) if matches!(*error, PolicyError::StalePolicy))
    );
    assert!(
        commit_retention(
            &mut f.deployment,
            &first_request,
            first_plan.digest()?,
            first_plan.approval_digest(PRINCIPAL)?,
            PRINCIPAL,
            &f.cx
        )
        .is_err()
    );
    assert!(matches!(
        preview_policy_change(
            &f.deployment,
            &change(Some(first.digest()), false)?,
            &f.authority,
            &f.cx
        ),
        Err(PolicyError::StalePolicy)
    ));
    let disabled = adopt(&mut f, &change(Some(second.digest()), false)?)?;
    assert_eq!(disabled.generation(), 3);
    let disabled_request = request_from_policy(
        &f.deployment,
        disabled.digest(),
        interval(1000, 1010)?,
        &f.cx,
    )?;
    assert!(
        matches!(plan_retention(&f.deployment, &disabled_request, &f.cx),
        Err(DeletionError::RetentionPolicy(error)) if matches!(*error, PolicyError::Disabled))
    );
    let current = list_policies(&f.deployment, &f.authority, &f.cx)?;
    assert_eq!(current, vec![disabled]);
    f.readable(import)?;
    Ok(())
}

#[test]
fn policy_staging_interruptions_reopen_and_retry_the_original_approval() -> TestResult {
    for stage in [
        STAGE_POLICY_READ,
        STAGE_POLICY_REVALIDATED,
        STAGE_POLICY_IMPACT_STAGED,
        STAGE_POLICY_STAGED,
    ] {
        let mut f = Fixture::new("policy-cut")?;
        let import = f.ingest("old", 40)?;
        let request = change(None, true)?;
        let preview = preview_policy_change(&f.deployment, &request, &f.authority, &f.cx)?;
        let head = f.deployment.current_anchor().clone();
        f.cx.set_cancel_at_checkpoint(stage);
        assert!(matches!(
            commit_policy_change(
                &mut f.deployment,
                &request,
                preview.record.approval(),
                &f.authority,
                &f.cx
            ),
            Err(PolicyError::Cancelled)
        ));
        assert_eq!(*f.deployment.current_anchor(), head);
        let mut f = f.reopen()?;
        assert!(list_policies(&f.deployment, &f.authority, &f.cx)?.is_empty());
        let retry_preview = preview_policy_change(&f.deployment, &request, &f.authority, &f.cx)?;
        assert_eq!(retry_preview, preview, "stage {stage}");
        f.cx.set_cancel_at_checkpoint(STAGE_POLICY_COMMITTED);
        let receipt = commit_policy_change(
            &mut f.deployment,
            &request,
            preview.record.approval(),
            &f.authority,
            &f.cx,
        )?;
        assert_eq!(receipt.outcome, PolicyOutcome::Committed);
        let f = f.reopen()?;
        assert_eq!(
            list_policies(&f.deployment, &f.authority, &f.cx)?,
            vec![preview.record]
        );
        f.readable(import)?;
    }
    Ok(())
}

#[test]
fn every_policy_cleanup_cut_reopens_exactly_and_pending_deletion_blocks_policy_changes()
-> TestResult {
    for stage in DELETION_CUT_POINTS {
        let mut f = Fixture::new("policy-cleanup-cut")?;
        let held = f.ingest("held", 40)?;
        let free = f.ingest("free", 80)?;
        f.hold("incident", held, HoldState::Held)?;
        let policy = adopt(&mut f, &change(None, true)?)?;
        let request =
            request_from_policy(&f.deployment, policy.digest(), interval(1000, 1010)?, &f.cx)?;
        let plan = plan_retention(&f.deployment, &request, &f.cx)?
            .deletion
            .ok_or("plan")?;
        let digest = plan.digest()?;
        let approval = plan.approval_digest(PRINCIPAL)?;
        f.cx.set_cancel_at_checkpoint(stage);
        assert!(
            matches!(commit_retention(&mut f.deployment, &request, digest, approval, PRINCIPAL, &f.cx),
            Err(DeletionError::Cancelled { stage: hit }) if hit == *stage)
        );
        let durable = DeletionIndex::read(&f.deployment)?.plan(digest).is_some();
        let mut f = f.reopen()?;
        if durable {
            assert!(matches!(
                preview_policy_change(
                    &f.deployment,
                    &change(Some(policy.digest()), false)?,
                    &f.authority,
                    &f.cx
                ),
                Err(PolicyError::DeletionInProgress)
            ));
        }
        let request =
            request_from_policy(&f.deployment, policy.digest(), interval(1000, 1010)?, &f.cx)?;
        let receipt = commit_retention(
            &mut f.deployment,
            &request,
            digest,
            approval,
            PRINCIPAL,
            &f.cx,
        )?;
        assert_eq!(
            receipt.outcome,
            if durable {
                CommitOutcome::Resumed
            } else {
                CommitOutcome::Completed
            }
        );
        f.readable(held)?;
        assert!(f.deployment.publisher().spool().read(free.source).is_err());
        adopt(&mut f, &change(Some(policy.digest()), false)?)?;
        let mut f = f.reopen()?;
        let old_request =
            request_from_policy(&f.deployment, policy.digest(), interval(1000, 1010)?, &f.cx)?;
        assert!(plan_retention(&f.deployment, &old_request, &f.cx).is_err());
        let retry = commit_retention(
            &mut f.deployment,
            &old_request,
            digest,
            approval,
            PRINCIPAL,
            &f.cx,
        )?;
        assert_eq!(retry.outcome, CommitOutcome::AlreadyComplete);
        assert_eq!(retry.completion_digest, receipt.completion_digest);
    }
    Ok(())
}

#[test]
fn policy_authority_is_guarded_and_damaged_custody_never_becomes_no_policy() -> TestResult {
    let mut f = Fixture::new("policy-guard")?;
    f.ingest("old", 40)?;
    let request = change(None, true)?;
    let preview_only = f.authority.narrow(fss_core::region::ContextNarrowingSpec {
        operation_id: f.authority.operation_id.clone(),
        capabilities: f
            .authority
            .capabilities()
            .iter()
            .filter(|capability| capability.as_str() != CAP_HOLD_COMMIT)
            .cloned()
            .collect(),
        deadline: f.authority.deadline,
        priority: f.authority.priority,
        budgets: f.authority.budgets,
        privacy_scope: f.authority.privacy_scope.clone(),
        retention_scope: f.authority.retention_scope.clone(),
        lease_fence: f.authority.lease_fence,
        idempotency_key: f.authority.idempotency_key.clone(),
        lab_controls: f.authority.lab_controls.clone(),
    })?;
    let preview = preview_policy_change(&f.deployment, &request, &preview_only, &f.cx)?;
    assert!(matches!(
        commit_policy_change(
            &mut f.deployment,
            &request,
            preview.record.approval(),
            &preview_only,
            &f.cx
        ),
        Err(PolicyError::Unauthorized)
    ));
    let head = f.deployment.current_anchor().clone();
    for (family, object) in [
        (FAMILY_RETENTION_POLICY, "object:any".to_owned()),
        ("other_family", format!("{POLICY_OBJECT_PREFIX}shadow")),
    ] {
        let digest = ContentDigest::sha256(b"not staged");
        assert!(matches!(
            f.deployment.append_batch(
                BatchId::parse("batch:forged-policy")?,
                vec![EvidenceDelta {
                    delta_id: "delta:forged-policy".to_owned(),
                    family: family.to_owned(),
                    object_id: ObjectId::parse(object)?,
                    prior_generation: None,
                    new_generation: 1,
                    validity: interval(0, 0)?,
                    plane: Plane::Authority,
                    payload_digest: digest,
                    witness_digest: None,
                    operation_id: None,
                }],
                vec![digest],
                &f.cx
            ),
            Err(ReferenceError::ReservedDeltaFamily { .. })
        ));
    }
    assert_eq!(*f.deployment.current_anchor(), head);
    let policy = adopt(&mut f, &request)?;
    let path = f
        .deployment
        .publisher()
        .spool()
        .object_path(policy.digest());
    let mut bytes = fs::read(&path)?;
    let last = bytes.last_mut().ok_or("record")?;
    *last ^= 1;
    fs::write(path, bytes)?;
    assert!(list_policies(&f.deployment, &f.authority, &f.cx).is_err());
    assert!(
        request_from_policy(&f.deployment, policy.digest(), interval(1000, 1010)?, &f.cx).is_err()
    );
    Ok(())
}

#[test]
fn retained_policy_impact_plan_corruption_is_fail_closed() -> TestResult {
    let mut f = Fixture::new("policy-impact-custody")?;
    let import = f.ingest("old", 40)?;
    let policy = adopt(&mut f, &change(None, true)?)?;
    let digest = policy.affected_plan().ok_or("impact plan")?;
    let path = f.deployment.publisher().spool().object_path(digest);
    fs::write(path, b"damaged policy impact")?;
    assert!(list_policies(&f.deployment, &f.authority, &f.cx).is_err());
    f.readable(import)?;
    Ok(())
}

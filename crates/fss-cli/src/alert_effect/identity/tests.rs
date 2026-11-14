#![forbid(unsafe_code)]
use super::*;
use fss_core::{EffectJournal, EffectState, TimestampNs};
use std::collections::BTreeSet;
use webhook_profile::{WebhookDisclosureProfile, route_digest};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn digest(value: &str) -> ContentDigest {
    ContentDigest::sha256(value.as_bytes())
}
fn route(profile: WebhookDisclosureProfile, metadata: Option<&str>) -> Test<ContentDigest> {
    Ok(route_digest(
        "127.0.0.1:8080".parse()?,
        "/alerts",
        digest("plain"),
        profile,
        metadata.map(digest),
    )?)
}
fn intent(identities: &AlertIdentities) -> Test<EffectIntent> {
    Ok(EffectIntent::new(
        identities.operation.clone(),
        identities.idempotency.clone(),
        "alert.dispatch",
        digest("request"),
        digest("precondition"),
    )?)
}
fn approval(intent: &EffectIntent, ids: &AlertIdentities, route: ContentDigest) -> ContentDigest {
    plan_approval_parts(
        intent,
        &ids.obligation,
        &format!("http-webhook:{}", hex(route)),
        digest("root"),
        digest("revision"),
        route,
        "principal:owner",
    )
}

#[test]
fn legacy_operation_plan_and_dispatch_approval_remain_byte_identical() -> Test {
    let route = route(WebhookDisclosureProfile::ReferencesV1, None)?;
    let ids = alert_identities(digest("revision"), route)?;
    let suffix = "71f5d1d9d30ec57b0aca45c089ae94f8f063a739cba260caa712c32c0ad31665";
    assert_eq!(ids.operation.as_str(), format!("operation:alert:{suffix}"));
    assert_eq!(
        ids.idempotency.as_str(),
        format!("idempotency:alert:{suffix}")
    );
    assert_eq!(
        ids.obligation.as_str(),
        format!("obligation:alert:{suffix}")
    );
    let intent = intent(&ids)?;
    let plan = approval(&intent, &ids, route);
    assert_eq!(
        plan.to_text(),
        "sha256:e5fc930c54166ff7f0ebfa10c6278f773ae25f1311ceb93aff2311e03fe19eb2"
    );
    let mut journal = EffectJournal::new();
    let receipt = journal.prepare(
        intent,
        ids.obligation,
        "delivery independently observed",
        TimestampNs(100),
    )?;
    assert_eq!(
        dispatch_approval_digest(plan, receipt, 5000, "principal:owner").to_text(),
        "sha256:cb425e19a16fa1b9eb14c21c496767e6237dec840be0592ef562b2381c154265"
    );
    Ok(())
}

#[test]
fn richer_profile_and_each_metadata_approval_need_disjoint_operations_and_approvals() -> Test {
    let mut operations = BTreeSet::new();
    let mut idempotencies = BTreeSet::new();
    let mut obligations = BTreeSet::new();
    let mut plans = BTreeSet::new();
    let mut dispatches = BTreeSet::new();
    for route in [
        route(WebhookDisclosureProfile::ReferencesV1, None)?,
        route(
            WebhookDisclosureProfile::EventMetadataV1,
            Some("metadata:a"),
        )?,
        route(
            WebhookDisclosureProfile::EventMetadataV1,
            Some("metadata:b"),
        )?,
    ] {
        let ids = alert_identities(digest("revision"), route)?;
        assert_eq!(ids, alert_identities(digest("revision"), route)?);
        let intent = intent(&ids)?;
        let plan = approval(&intent, &ids, route);
        let mut journal = EffectJournal::new();
        let receipt = journal.prepare(
            intent,
            ids.obligation.clone(),
            "delivery independently observed",
            TimestampNs(100),
        )?;
        operations.insert(ids.operation);
        idempotencies.insert(ids.idempotency);
        obligations.insert(ids.obligation);
        plans.insert(plan);
        dispatches.insert(dispatch_approval_digest(
            plan,
            receipt,
            5000,
            "principal:owner",
        ));
    }
    assert_eq!(
        (
            operations.len(),
            idempotencies.len(),
            obligations.len(),
            plans.len(),
            dispatches.len()
        ),
        (3, 3, 3, 3, 3)
    );
    Ok(())
}

#[test]
fn neither_route_relabeling_nor_prepared_state_changes_reuse_an_old_dispatch_approval() -> Test {
    let old = route(WebhookDisclosureProfile::ReferencesV1, None)?;
    let rich = route(WebhookDisclosureProfile::EventMetadataV1, Some("metadata"))?;
    let ids = alert_identities(digest("revision"), old)?;
    let intent = intent(&ids)?;
    let old_plan = approval(&intent, &ids, old);
    // Even a caller holding the old intent cannot preserve its approval while swapping routes.
    let relabeled = approval(&intent, &ids, rich);
    assert_ne!(old_plan, relabeled);
    let mut journal = EffectJournal::new();
    let prepared = journal
        .prepare(
            intent,
            ids.obligation,
            "delivery independently observed",
            TimestampNs(100),
        )?
        .clone();
    let old_dispatch = dispatch_approval_digest(old_plan, &prepared, 5000, "principal:owner");
    assert_ne!(
        old_dispatch,
        dispatch_approval_digest(relabeled, &prepared, 5000, "principal:owner")
    );
    assert_ne!(
        old_dispatch,
        dispatch_approval_digest(old_plan, &prepared, 5001, "principal:owner")
    );
    assert_ne!(
        old_dispatch,
        dispatch_approval_digest(old_plan, &prepared, 5000, "principal:other")
    );
    let mut changed = prepared.clone();
    changed.prepared_at = TimestampNs(101);
    assert_ne!(
        old_dispatch,
        dispatch_approval_digest(old_plan, &changed, 5000, "principal:owner")
    );
    let committed = journal.transition(
        &ids.operation,
        EffectState::Committed,
        TimestampNs(102),
        None,
        None,
    )?;
    assert_ne!(
        old_dispatch,
        dispatch_approval_digest(old_plan, committed, 5000, "principal:owner")
    );
    Ok(())
}

#[test]
fn exact_rich_retry_preserves_one_operation_and_cannot_restore_prepared_state() -> Test {
    let route = route(WebhookDisclosureProfile::EventMetadataV1, Some("metadata"))?;
    let ids = alert_identities(digest("revision"), route)?;
    let intent = intent(&ids)?;
    let mut journal = EffectJournal::new();
    let first = journal
        .prepare(
            intent.clone(),
            ids.obligation.clone(),
            "delivery independently observed",
            TimestampNs(100),
        )?
        .clone();
    let retry = journal.prepare(
        intent.clone(),
        ids.obligation.clone(),
        "delivery independently observed",
        TimestampNs(101),
    )?;
    assert_eq!(*retry, first);
    assert_eq!(journal.operations().count(), 1);
    journal.transition(
        &ids.operation,
        EffectState::Committed,
        TimestampNs(102),
        None,
        None,
    )?;
    journal.transition(
        &ids.operation,
        EffectState::Indeterminate,
        TimestampNs(103),
        Some(digest("lost acknowledgement")),
        Some("acknowledgement_lost".into()),
    )?;
    let retry = journal.prepare(
        intent,
        ids.obligation,
        "delivery independently observed",
        TimestampNs(104),
    )?;
    assert_eq!(retry.state, EffectState::Indeterminate);
    assert_eq!(retry.prepared_at, TimestampNs(100));
    assert_eq!(journal.operations().count(), 1);
    assert!(
        journal
            .transition(
                &ids.operation,
                EffectState::Committed,
                TimestampNs(105),
                None,
                None
            )
            .is_err()
    );
    Ok(())
}

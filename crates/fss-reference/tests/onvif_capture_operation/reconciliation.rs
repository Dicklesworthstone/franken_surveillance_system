#![forbid(unsafe_code)]
//! End-to-end retained control custody discharges only its originally bound operation.

use std::cell::Cell;

use fss_core::ObligationState;
use fss_reference::onvif::capture_operation::{
    CaptureCleanupEvidence, STAGE_CLEANUP_ACCEPTED, STAGE_CLEANUP_OBSERVED,
    STAGE_CLEANUP_RECONCILED, STAGE_CLEANUP_REVALIDATED, reconcile_cleanup, reserve_for_create,
};
use fss_reference::onvif::control::{
    RetainedCreateIntent, RetainedUnsubscribe, UnsubscribeBinding, UnsubscribeIntentBinding,
    UnsubscribeOutcomeBinding, inspect_cleanup, prepare_unsubscribe, retain_unsubscribe_outcome,
    retain_unsubscribed,
};
use fss_reference::onvif::wire::unsubscribe_pull_point_request;

use super::*;

fn create_binding(message: &str) -> Test<CreateIntentBinding> {
    Ok(CreateIntentBinding {
        source: SourceBinding {
            sensor_id: SensorId::parse("sensor:capture-fence")?,
            device_generation: ContentDigest::sha256(b"device-generation"),
            profile_generation: ContentDigest::sha256(b"profile-generation"),
            profile_token: "private-profile-canary".into(),
            receive_interval: CaptureInterval::new(TimestampNs(10_000), TimestampNs(10_000))?,
        },
        events: HttpRoute::event_service(
            "192.0.2.4:80".parse()?,
            "192.0.2.4",
            "/onvif/events",
            1,
            ContentDigest::sha256(b"owner-approved-request"),
        )?,
        service_root: "/onvif".into(),
        message_id: message.into(),
        started_ns: 1_000,
        lifetime_seconds: 120,
    })
}

fn opened_capture(
    dep: &mut ReferenceDeployment,
    base: &CaptureOperationBinding,
    message: &str,
    cx: &ReplayCx,
) -> Test<RetainedSubscription> {
    let create = create_binding(message)?;
    let expected = create.identity(SITE)?;
    let guard = reserve_for_create(dep, base, &create, TimestampNs(10_000), cx)?;
    assert_eq!(guard.prepared().create_intent, Some(expected));
    let intent = prepare_create(dep, create, cx)?;
    assert_eq!(intent.identity(), expected);
    guard.commit_with_intent(dep, &intent, TimestampNs(10_005), cx)?;
    let source =
        std::str::from_utf8(SOURCE)?.replace("urn:fss:onvif:create-operation-test", message);
    Ok(retain_created(
        dep,
        &intent,
        1_010,
        false,
        source.as_bytes(),
        cx,
    )?)
}

fn cleanup_binding() -> Test<UnsubscribeBinding> {
    Ok(UnsubscribeBinding {
        route: HttpRoute::event_service(
            "192.0.2.4:80".parse()?,
            "192.0.2.4",
            "/onvif/private-subscription-canary?Idx=7",
            1,
            ContentDigest::sha256(b"fresh-cleanup-approval"),
        )?,
        message_id: "urn:fss:onvif:capture-cleanup".into(),
        started_ns: 50,
        completed_ns: 60,
        receive_interval: CaptureInterval::new(TimestampNs(20_000), TimestampNs(20_010))?,
        client_authenticated: false,
    })
}

fn cleanup_source() -> Vec<u8> {
    br#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://www.w3.org/2005/08/addressing" xmlns:n="http://docs.oasis-open.org/wsn/b-2"><s:Header><w:Action s:mustUnderstand="1">http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/UnsubscribeResponse</w:Action><w:RelatesTo>urn:fss:onvif:capture-cleanup</w:RelatesTo></s:Header><s:Body><n:UnsubscribeResponse/></s:Body></s:Envelope>"#.to_vec()
}

fn terminal(
    dep: &mut ReferenceDeployment,
    created: &RetainedSubscription,
    cx: &ReplayCx,
) -> Test<RetainedUnsubscribe> {
    Ok(retain_unsubscribed(
        dep,
        created,
        cleanup_binding()?,
        &cleanup_source(),
        cx,
    )?)
}

fn selector(terminal: &RetainedUnsubscribe) -> CaptureCleanupEvidence {
    CaptureCleanupEvidence::Unsubscribed {
        identity: terminal.identity(),
        root: terminal.publication_root(),
    }
}

fn clock() -> impl FnMut() -> Result<TimestampNs, CaptureOperationError> {
    let mut now = 30_000;
    move || {
        now += 1;
        Ok(TimestampNs(now))
    }
}

#[test]
fn bound_dispatch_requires_the_exact_fresh_retained_intent() -> Test {
    for mismatch in [
        "unbound-commit",
        "other-intent",
        "cold-handle",
        "missing-source",
    ] {
        let dir = Directory::new(mismatch)?;
        let cx = dir.cx()?;
        let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let base = binding()?;
        let create = create_binding("urn:fss:onvif:bound-create")?;
        let guard = reserve_for_create(&mut dep, &base, &create, TimestampNs(10_000), &cx)?;
        let intent = prepare_create(&mut dep, create, &cx)?;
        let before = dep.effects().last_root();
        let result = match mismatch {
            "unbound-commit" => guard.commit(&mut dep, TimestampNs(10_005), &cx),
            "other-intent" => {
                let other = prepare_create(&mut dep, create_binding("urn:fss:onvif:other")?, &cx)?;
                guard.commit_with_intent(&mut dep, &other, TimestampNs(10_005), &cx)
            }
            "cold-handle" => {
                let cold = RetainedCreateIntent::open(
                    &dep,
                    intent.identity(),
                    Some(intent.publication_root()),
                    &cx,
                )?;
                guard.commit_with_intent(&mut dep, &cold, TimestampNs(10_005), &cx)
            }
            _ => {
                let plan = plan_deletion(&dep, intent.identity(), &cx)?;
                commit_deletion(
                    &mut dep,
                    plan.digest()?,
                    plan.approval_digest(PRINCIPAL)?,
                    PRINCIPAL,
                    &cx,
                )?;
                guard.commit_with_intent(&mut dep, &intent, TimestampNs(10_005), &cx)
            }
        };
        assert!(
            matches!(result, Err(CaptureOperationError::Custody)),
            "{mismatch}: {result:?}"
        );
        assert_eq!(dep.effects().last_root(), before);
        existing(
            reserve(&mut dep, &base, TimestampNs(40_000), &cx),
            EffectState::Prepared,
        )?;
    }
    Ok(())
}

#[test]
fn prior_or_cloned_intent_handles_cannot_authorize_a_second_dispatch() -> Test {
    for prior_intent in [false, true] {
        let dir = Directory::new("reconcile-unique-create")?;
        let cx = dir.cx()?;
        let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let base = binding()?;
        let create = create_binding("urn:fss:onvif:unique-create")?;
        if prior_intent {
            let intent = prepare_create(&mut dep, create.clone(), &cx)?;
            let guard = reserve_for_create(&mut dep, &base, &create, TimestampNs(10_000), &cx)?;
            let before = dep.effects().last_root();
            assert!(matches!(
                guard.commit_with_intent(&mut dep, &intent, TimestampNs(10_005), &cx),
                Err(CaptureOperationError::Custody)
            ));
            assert_eq!(dep.effects().last_root(), before);
        } else {
            let guard = reserve_for_create(&mut dep, &base, &create, TimestampNs(10_000), &cx)?;
            let mut other = base.clone();
            other.operation_id = OperationId::parse("operation:second-id-same-create")?;
            let before = dep.effects().last_root();
            assert!(matches!(
                reserve_for_create(&mut dep, &other, &create, TimestampNs(10_000), &cx),
                Err(CaptureOperationError::Custody)
            ));
            assert_eq!(dep.effects().last_root(), before);
            assert_eq!(dep.effects().operations().count(), 1);
            let intent = prepare_create(&mut dep, create.clone(), &cx)?;
            guard.commit_with_intent(&mut dep, &intent, TimestampNs(10_005), &cx)?;
            let committed = dep.effects().last_root();
            assert!(matches!(
                reserve_for_create(&mut dep, &other, &create, TimestampNs(10_000), &cx),
                Err(CaptureOperationError::Custody)
            ));
            assert_eq!(dep.effects().last_root(), committed);
        }
    }
    Ok(())
}

#[test]
fn another_stores_newer_intent_handle_cannot_relabel_old_local_custody_as_fresh() -> Test {
    let first = Directory::new("reconcile-intent-local")?;
    let second = Directory::new("reconcile-intent-other")?;
    let first_cx = first.cx()?;
    let second_cx = second.cx()?;
    let mut local = ReferenceDeployment::open(&first.0, SITE, &first_cx)?;
    let mut other = ReferenceDeployment::open(&second.0, SITE, &second_cx)?;
    let base = binding()?;
    let create = create_binding("urn:fss:onvif:shared-intent-bytes")?;
    let old_local = prepare_create(&mut local, create.clone(), &first_cx)?;
    let guard = reserve_for_create(&mut local, &base, &create, TimestampNs(10_000), &first_cx)?;
    prepare_create(
        &mut other,
        create_binding("urn:fss:onvif:unrelated-first")?,
        &second_cx,
    )?;
    let newer_handle = prepare_create(&mut other, create, &second_cx)?;
    assert_eq!(old_local.identity(), newer_handle.identity());
    assert_eq!(
        old_local.publication_root(),
        newer_handle.publication_root()
    );
    assert!(
        newer_handle.authority_anchor().commit_sequence
            > old_local.authority_anchor().commit_sequence
    );
    let before = fs::read(local.effects().path())?;
    assert!(matches!(
        guard.commit_with_intent(&mut local, &newer_handle, TimestampNs(10_005), &first_cx),
        Err(CaptureOperationError::Custody)
    ));
    assert_eq!(fs::read(local.effects().path())?, before);
    assert_eq!(
        inspect(&local, &base.operation_id, None, None, &first_cx)?
            .receipt
            .state,
        EffectState::Prepared
    );
    Ok(())
}

#[test]
fn cold_success_closes_the_obligation_and_exact_retry_never_writes_or_reads_clock() -> Test {
    let dir = Directory::new("reconcile-cold")?;
    let cx = dir.cx()?;
    let base = binding()?;
    let (evidence, committed_root) = {
        let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let created = opened_capture(&mut dep, &base, "urn:fss:onvif:first", &cx)?;
        let terminal = terminal(&mut dep, &created, &cx)?;
        (selector(&terminal), dep.effects().last_root())
    };
    let mut dep = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
    assert_eq!(
        inspect(&dep, &base.operation_id, None, None, &cx)?
            .receipt
            .state,
        EffectState::Indeterminate
    );
    let ledger = fs::read(dep.ledger().path())?;
    let reconciled = reconcile_cleanup(
        &mut dep,
        &base.operation_id,
        evidence,
        Some(committed_root),
        clock(),
        &cx,
    )?;
    assert_eq!(reconciled.receipt.state, EffectState::Verified);
    assert_eq!(reconciled.obligation_state, ObligationState::Verified);
    assert_eq!(reconciled.proof_digest, reconciled.receipt.result_digest);
    assert!(reconciled.proof_digest.is_some());
    assert!(reconciled.receipt.indeterminate_reason.is_some());
    assert_eq!(fs::read(dep.ledger().path())?, ledger);
    let bytes = fs::read(dep.effects().path())?;
    let retry = reconcile_cleanup(
        &mut dep,
        &base.operation_id,
        evidence,
        Some(reconciled.journal_root),
        || Err(CaptureOperationError::Authority),
        &cx,
    )?;
    assert_eq!(retry, reconciled);
    assert_eq!(fs::read(dep.effects().path())?, bytes);
    drop(dep);
    let mut cold = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
    assert_eq!(
        inspect(
            &cold,
            &base.operation_id,
            None,
            Some(reconciled.journal_root),
            &cx
        )?
        .receipt,
        reconciled.receipt
    );
    existing(
        reserve(&mut cold, &base, TimestampNs(40_000), &cx),
        EffectState::Verified,
    )?;
    Ok(())
}

#[test]
fn each_reconciliation_crash_cut_resumes_without_repeating_any_effect() -> Test {
    for (stage, expected) in [
        (STAGE_CLEANUP_REVALIDATED, EffectState::Committed),
        (STAGE_CLEANUP_ACCEPTED, EffectState::AdapterAccepted),
        (STAGE_CLEANUP_OBSERVED, EffectState::Observed),
        (STAGE_CLEANUP_RECONCILED, EffectState::Verified),
    ] {
        let dir = Directory::new("reconcile-cut")?;
        let cx = dir.cx()?;
        let base = binding()?;
        let evidence = {
            let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
            let created = opened_capture(&mut dep, &base, "urn:fss:onvif:cut", &cx)?;
            let ended = terminal(&mut dep, &created, &cx)?;
            let evidence = selector(&ended);
            cx.set_cancel_at_checkpoint(stage);
            let result =
                reconcile_cleanup(&mut dep, &base.operation_id, evidence, None, clock(), &cx);
            assert_eq!(result.is_ok(), stage == STAGE_CLEANUP_RECONCILED);
            assert_eq!(
                dep.effects()
                    .operation(&operation_key(SITE, &base.operation_id)?)
                    .ok_or("missing operation")?
                    .state,
                expected
            );
            evidence
        };
        let fresh = dir.cx()?;
        let mut dep = ReferenceDeployment::reopen(&dir.0, SITE, &fresh)?;
        let mut time = 40_000;
        let result = reconcile_cleanup(
            &mut dep,
            &base.operation_id,
            evidence,
            None,
            || {
                time += 1;
                Ok(TimestampNs(time))
            },
            &fresh,
        )?;
        assert_eq!(result.receipt.state, EffectState::Verified);
        assert_eq!(result.obligation_state, ObligationState::Verified);
        existing(
            reserve(&mut dep, &base, TimestampNs(50_000), &fresh),
            EffectState::Verified,
        )?;
    }
    Ok(())
}

#[test]
fn unrelated_cleanup_cannot_discharge_another_capture_even_on_the_same_endpoint() -> Test {
    let dir = Directory::new("reconcile-other")?;
    let cx = dir.cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let base = binding()?;
    opened_capture(&mut dep, &base, "urn:fss:onvif:original", &cx)?;
    let mut other = binding()?;
    other.operation_id = OperationId::parse("operation:other-capture")?;
    let created = opened_capture(&mut dep, &other, "urn:fss:onvif:another", &cx)?;
    let ended = terminal(&mut dep, &created, &cx)?;
    let before = fs::read(dep.effects().path())?;
    assert!(matches!(
        reconcile_cleanup(
            &mut dep,
            &base.operation_id,
            selector(&ended),
            None,
            clock(),
            &cx
        ),
        Err(CaptureOperationError::Custody)
    ));
    assert_eq!(fs::read(dep.effects().path())?, before);
    let result = reconcile_cleanup(
        &mut dep,
        &other.operation_id,
        selector(&ended),
        None,
        clock(),
        &cx,
    )?;
    assert_eq!(result.receipt.state, EffectState::Verified);
    assert_eq!(
        inspect(&dep, &base.operation_id, None, None, &cx)?
            .receipt
            .state,
        EffectState::Committed
    );
    Ok(())
}

#[test]
fn raw_success_is_sufficient_without_marker_but_rejected_outcomes_never_complete() -> Test {
    for (status, completed) in [(200, Some(60)), (200, None), (500, Some(60))] {
        let dir = Directory::new("reconcile-raw")?;
        let cx = dir.cx()?;
        let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let base = binding()?;
        let created = opened_capture(&mut dep, &base, "urn:fss:onvif:raw", &cx)?;
        let cleanup = cleanup_binding()?;
        let request = unsubscribe_pull_point_request(created.subscription())?
            .with_message_id(&cleanup.message_id)?;
        let expected_control = inspect_cleanup(&dep, &created, &cx)?.witness;
        let intent = prepare_unsubscribe(
            &mut dep,
            &created,
            UnsubscribeIntentBinding {
                route: cleanup.route,
                create_message_id: created.binding().message_id.clone(),
                message_id: cleanup.message_id,
                request_digest: ContentDigest::sha256(request.body()),
                started_ns: cleanup.started_ns,
                receive_time: cleanup.receive_interval.earliest,
                expected_control,
            },
            &cx,
        )?;
        let raw = retain_unsubscribe_outcome(
            &mut dep,
            &intent,
            UnsubscribeOutcomeBinding {
                completed_ns: completed,
                client_authenticated: false,
                http_status: status,
                soap_content_type: true,
            },
            &cleanup_source(),
            &cx,
        )?;
        let evidence = CaptureCleanupEvidence::Outcome {
            identity: raw.identity(),
            root: raw.publication_root(),
        };
        let before = dep.effects().last_root();
        let result = reconcile_cleanup(&mut dep, &base.operation_id, evidence, None, clock(), &cx);
        if status == 200 {
            assert_eq!(result?.receipt.state, EffectState::Verified);
        } else {
            assert!(matches!(result, Err(CaptureOperationError::Custody)));
            assert_eq!(dep.effects().last_root(), before);
        }
    }
    Ok(())
}

#[test]
fn legacy_or_never_committed_operations_cannot_borrow_a_terminal_receipt() -> Test {
    for legacy in [false, true] {
        let dir = Directory::new("reconcile-legacy")?;
        let cx = dir.cx()?;
        let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let base = binding()?;
        let create = create_binding("urn:fss:onvif:create-operation-test")?;
        let guard = if legacy {
            reserve(&mut dep, &base, TimestampNs(10_000), &cx)?
        } else {
            reserve_for_create(&mut dep, &base, &create, TimestampNs(10_000), &cx)?
        };
        let intent = prepare_create(&mut dep, create, &cx)?;
        if legacy {
            guard.commit(&mut dep, TimestampNs(10_005), &cx)?;
        } else {
            drop(guard);
        }
        let created = retain_created(&mut dep, &intent, 1_010, false, SOURCE, &cx)?;
        let ended = terminal(&mut dep, &created, &cx)?;
        let before = dep.effects().last_root();
        assert!(matches!(
            reconcile_cleanup(
                &mut dep,
                &base.operation_id,
                selector(&ended),
                None,
                clock(),
                &cx
            ),
            Err(CaptureOperationError::Custody)
        ));
        assert_eq!(dep.effects().last_root(), before);
    }
    Ok(())
}

#[test]
fn wrong_owner_root_minimum_or_deleted_custody_cannot_close_an_obligation() -> Test {
    for case in ["owner", "root", "minimum", "deleted", "clock"] {
        let dir = Directory::new("reconcile-refuse")?;
        let cx = dir.cx()?;
        let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let base = binding()?;
        let created = opened_capture(&mut dep, &base, "urn:fss:onvif:refuse", &cx)?;
        let ended = terminal(&mut dep, &created, &cx)?;
        let mut evidence = selector(&ended);
        let mut minimum = None;
        let wrong_owner = dir.cx_for("operator:other")?;
        if case == "root" {
            evidence = CaptureCleanupEvidence::Unsubscribed {
                identity: ended.identity(),
                root: ContentDigest::sha256(b"wrong-root"),
            };
        } else if case == "minimum" {
            minimum = Some(ContentDigest::sha256(b"missing-history"));
        } else if case == "deleted" {
            let deletion = plan_deletion(&dep, created.intent_identity(), &cx)?;
            commit_deletion(
                &mut dep,
                deletion.digest()?,
                deletion.approval_digest(PRINCIPAL)?,
                PRINCIPAL,
                &cx,
            )?;
        }
        let before = fs::read(dep.effects().path())?;
        let calls = Cell::new(0);
        let result = reconcile_cleanup(
            &mut dep,
            &base.operation_id,
            evidence,
            minimum,
            || {
                calls.set(calls.get() + 1);
                Ok(TimestampNs(1))
            },
            if case == "owner" { &wrong_owner } else { &cx },
        );
        assert!(result.is_err(), "{case}");
        assert_eq!(fs::read(dep.effects().path())?, before, "{case}");
        assert_eq!(calls.get(), usize::from(case == "clock"), "{case}");
    }
    Ok(())
}

#[test]
fn deleting_private_sources_preserves_verified_history_and_the_consumed_owner_id() -> Test {
    let dir = Directory::new("reconcile-deleted-terminal")?;
    let cx = dir.cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let base = binding()?;
    let created = opened_capture(&mut dep, &base, "urn:fss:onvif:delete-terminal", &cx)?;
    let ended = terminal(&mut dep, &created, &cx)?;
    let verified = reconcile_cleanup(
        &mut dep,
        &base.operation_id,
        selector(&ended),
        None,
        clock(),
        &cx,
    )?;
    let deletion = plan_deletion(&dep, created.intent_identity(), &cx)?;
    assert!(deletion.blockers.is_empty(), "{:?}", deletion.blockers);
    commit_deletion(
        &mut dep,
        deletion.digest()?,
        deletion.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &cx,
    )?;
    assert!(RetainedUnsubscribe::open(&dep, ended.identity(), None, &cx).is_err());
    let after = inspect(
        &dep,
        &base.operation_id,
        None,
        Some(verified.journal_root),
        &cx,
    )?;
    assert_eq!(after.receipt, verified.receipt);
    assert_eq!(after.proof_digest, verified.proof_digest);
    existing(
        reserve(&mut dep, &base, TimestampNs(40_000), &cx),
        EffectState::Verified,
    )?;
    drop(dep);
    let mut cold = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
    assert_eq!(
        inspect(&cold, &base.operation_id, None, None, &cx)?.receipt,
        verified.receipt
    );
    existing(
        reserve(&mut cold, &base, TimestampNs(50_000), &cx),
        EffectState::Verified,
    )?;
    let bytes = fs::read(cold.effects().path())?;
    for private in [
        OWNER_ID,
        PRINCIPAL,
        "private-subscription-canary",
        "private-profile-canary",
    ] {
        assert!(
            !bytes
                .windows(private.len())
                .any(|part| part == private.as_bytes())
        );
    }
    Ok(())
}

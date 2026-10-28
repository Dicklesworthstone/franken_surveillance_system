#![forbid(unsafe_code)]
//! Durable cleanup attempts, raw outcomes and cold reconciliation without repeating effects.

use std::fs;
use std::path::PathBuf;

use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
    SensorId, TimestampNs,
};
use fss_reference::deletion::{commit_deletion, plan_deletion};
use fss_reference::onvif::control::{
    ControlKind, CreateIntentBinding, RetainedSubscription, RetainedUnsubscribe,
    RetainedUnsubscribeIntent, RetainedUnsubscribeOutcome, STAGE_UNSUBSCRIBE_INTENT_PUBLISH,
    UnsubscribeBinding, UnsubscribeIntentBinding, UnsubscribeOutcomeBinding, inspect_cleanup,
    list_control, prepare_create, prepare_unsubscribe, retain_created, retain_unsubscribe_outcome,
    retain_unsubscribed,
};
use fss_reference::onvif::http::HttpRoute;
use fss_reference::onvif::metadata::{MetadataError, SourceBinding};
use fss_reference::onvif::wire::unsubscribe_pull_point_request;
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:onvif-cleanup-attempt-test";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..64 {
            let path = std::env::temp_dir().join(format!(
                "fss-onvif-cleanup-attempt-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("fixture directories exhausted".into())
    }

    fn cx(&self) -> Test<ReplayCx> {
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:onvif-cleanup-test".into(),
            operation_id: OperationId::parse("operation:onvif-cleanup-test")?,
            principal: "operator:onvif-cleanup-test".into(),
            capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.into()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(16 * 1024 * 1024)
                .storage_operations(2048)
                .build()?,
            privacy_scope: "privacy:fixture".into(),
            retention_scope: "retention:fixture".into(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        Ok(ReplayCx::from_context_authority_read_only(
            &authority,
            self.0.clone(),
        )?)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn created(deployment: &mut ReferenceDeployment, cx: &ReplayCx) -> Test<RetainedSubscription> {
    let intent = prepare_create(
        deployment,
        CreateIntentBinding {
            source: SourceBinding {
                sensor_id: SensorId::parse("sensor:front")?,
                device_generation: ContentDigest::sha256(b"device-generation-1"),
                profile_generation: ContentDigest::sha256(b"profile-generation-1"),
                profile_token: "private-profile-canary".into(),
                receive_interval: CaptureInterval::new(TimestampNs(10_000), TimestampNs(10_000))?,
            },
            events: HttpRoute::event_service(
                "192.0.2.4:80".parse()?,
                "192.0.2.4",
                "/onvif/events",
                1,
                ContentDigest::sha256(b"original-capture-approval"),
            )?,
            service_root: "/onvif".into(),
            message_id: "urn:fss:onvif:create-1".into(),
            started_ns: 1_000,
            lifetime_seconds: 120,
        },
        cx,
    )?;
    let xml = br#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:e="http://www.onvif.org/ver10/events/wsdl" xmlns:w="http://www.w3.org/2005/08/addressing" xmlns:n="http://docs.oasis-open.org/wsn/b-2" xmlns:v="urn:private-vendor"><s:Header><w:RelatesTo>urn:fss:onvif:create-1</w:RelatesTo></s:Header><s:Body><e:CreatePullPointSubscriptionResponse><e:SubscriptionReference><w:Address>http://192.0.2.4/onvif/subscription?Idx=7</w:Address><w:ReferenceParameters><v:Token>private-reference-canary</v:Token></w:ReferenceParameters></e:SubscriptionReference><n:CurrentTime>2026-10-27T00:00:00Z</n:CurrentTime><n:TerminationTime>2026-10-27T00:02:00Z</n:TerminationTime></e:CreatePullPointSubscriptionResponse></s:Body></s:Envelope>"#;
    Ok(retain_created(deployment, &intent, 1_010, true, xml, cx)?)
}

fn binding() -> Test<UnsubscribeBinding> {
    Ok(UnsubscribeBinding {
        route: HttpRoute::event_service(
            "192.0.2.4:80".parse()?,
            "192.0.2.4",
            "/onvif/subscription?Idx=7",
            1,
            ContentDigest::sha256(b"current-cleanup-approval"),
        )?,
        message_id: "urn:fss:onvif:cleanup-1".into(),
        // A cold owner has an independent monotonic origin.
        started_ns: 50,
        completed_ns: 60,
        receive_interval: CaptureInterval::new(TimestampNs(20_000), TimestampNs(20_010))?,
        client_authenticated: true,
    })
}

fn response(relates_to: &str) -> Vec<u8> {
    format!(
        r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://www.w3.org/2005/08/addressing" xmlns:n="http://docs.oasis-open.org/wsn/b-2"><s:Header><w:Action s:mustUnderstand="1">http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/UnsubscribeResponse</w:Action><w:RelatesTo>{relates_to}</w:RelatesTo></s:Header><s:Body><n:UnsubscribeResponse/></s:Body></s:Envelope>"#
    )
    .into_bytes()
}

fn source() -> Vec<u8> {
    response("urn:fss:onvif:cleanup-1")
}

fn intent_binding(
    deployment: &ReferenceDeployment,
    created: &RetainedSubscription,
    approval: &str,
    message_id: &str,
    cx: &ReplayCx,
) -> Test<UnsubscribeIntentBinding> {
    let prior = binding()?;
    let route = HttpRoute::event_service(
        prior.route.peer(),
        prior.route.authority(),
        prior.route.target(),
        prior.route.generation(),
        ContentDigest::sha256(approval.as_bytes()),
    )?;
    let request =
        unsubscribe_pull_point_request(created.subscription())?.with_message_id(message_id)?;
    Ok(UnsubscribeIntentBinding {
        route,
        create_message_id: created.binding().message_id.clone(),
        message_id: message_id.into(),
        request_digest: ContentDigest::sha256(request.body()),
        started_ns: 50,
        receive_time: TimestampNs(20_000),
        expected_control: inspect_cleanup(deployment, created, cx)?.witness,
    })
}

fn outcome_binding() -> UnsubscribeOutcomeBinding {
    UnsubscribeOutcomeBinding {
        completed_ns: Some(60),
        client_authenticated: true,
        http_status: 200,
        soap_content_type: true,
    }
}

#[test]
fn durable_intent_survives_lost_response_and_exact_retry_never_restores_dispatch() -> Test {
    let dir = Directory::new("intent-cold")?;
    let cx = dir.cx()?;
    let (created_id, intent_id, root, frozen) = {
        let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let created = created(&mut deployment, &cx)?;
        let binding = intent_binding(
            &deployment,
            &created,
            "cleanup-approval-one",
            "urn:fss:onvif:cleanup-1",
            &cx,
        )?;
        let intent = prepare_unsubscribe(&mut deployment, &created, binding.clone(), &cx)?;
        assert!(intent.newly_prepared());
        let status = inspect_cleanup(&deployment, &created, &cx)?;
        assert_eq!(status.attempts, 1);
        assert!(status.terminal.is_none());
        assert_eq!(
            status.latest_intent.map(|entry| entry.identity),
            Some(intent.identity())
        );
        assert_ne!(status.witness, binding.expected_control);
        (
            created.identity(),
            intent.identity(),
            intent.publication_root(),
            binding,
        )
    };
    let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let created = RetainedSubscription::open(&deployment, created_id, None, &cx)?;
    let cold = RetainedUnsubscribeIntent::open(&deployment, intent_id, Some(root), &cx)?;
    assert!(!cold.newly_prepared());
    let head = deployment.current_anchor().clone();
    let retry = prepare_unsubscribe(&mut deployment, &created, frozen, &cx)?;
    assert!(!retry.newly_prepared());
    assert_eq!(retry.identity(), intent_id);
    assert_eq!(deployment.current_anchor(), &head);
    assert!(!format!("{cold:?}").contains("private-reference-canary"));
    Ok(())
}

#[test]
fn complete_failed_empty_and_clock_uncertain_outcomes_remain_cold_verifiable() -> Test {
    let cases = [
        (source(), outcome_binding(), true),
        (
            source(),
            UnsubscribeOutcomeBinding {
                completed_ns: None,
                ..outcome_binding()
            },
            true,
        ),
        (
            Vec::new(),
            UnsubscribeOutcomeBinding {
                http_status: 401,
                soap_content_type: false,
                ..outcome_binding()
            },
            false,
        ),
        (
            b"private-malformed-cleanup".to_vec(),
            outcome_binding(),
            false,
        ),
        (
            source(),
            UnsubscribeOutcomeBinding {
                http_status: 500,
                ..outcome_binding()
            },
            false,
        ),
        (
            source(),
            UnsubscribeOutcomeBinding {
                soap_content_type: false,
                ..outcome_binding()
            },
            false,
        ),
        (
            response("urn:fss:onvif:wrong-operation"),
            outcome_binding(),
            false,
        ),
    ];
    for (index, (raw, observation, success)) in cases.into_iter().enumerate() {
        let dir = Directory::new(&format!("raw-{index}"))?;
        let cx = dir.cx()?;
        let (created_id, outcome_id, root) = {
            let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
            let created = created(&mut deployment, &cx)?;
            let binding = intent_binding(
                &deployment,
                &created,
                "cleanup-approval-one",
                "urn:fss:onvif:cleanup-1",
                &cx,
            )?;
            let intent = prepare_unsubscribe(&mut deployment, &created, binding, &cx)?;
            let retained = retain_unsubscribe_outcome(
                &mut deployment,
                &intent,
                observation.clone(),
                &raw,
                &cx,
            )?;
            assert_eq!(retained.success_observed(), success);
            if observation.completed_ns.is_none() {
                assert_eq!(
                    retained.receive_interval().earliest,
                    retained.receive_interval().latest
                );
            }
            (
                created.identity(),
                retained.identity(),
                retained.publication_root(),
            )
        };
        let deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let cold = RetainedUnsubscribeOutcome::open(&deployment, outcome_id, Some(root), &cx)?;
        assert_eq!(cold.source(), raw);
        assert_eq!(cold.binding(), &observation);
        assert_eq!(cold.success_observed(), success);
        let created = RetainedSubscription::open(&deployment, created_id, None, &cx)?;
        let status = inspect_cleanup(&deployment, &created, &cx)?;
        assert_eq!(status.terminal.is_some(), success);
        if success {
            assert_eq!(
                status.terminal.map(|entry| entry.kind),
                Some(ControlKind::UnsubscribeOutcome)
            );
        }
        let catalog = list_control(&deployment, 4, &cx)?;
        assert_eq!(catalog.len(), 4);
        assert_eq!(
            catalog
                .last()
                .map(|entry| entry.unsubscribe_intent_identity),
            Some(Some(cold.intent().identity()))
        );
    }
    Ok(())
}

#[test]
fn new_attempt_requires_current_fence_fresh_approval_unique_id_and_exact_epr_body() -> Test {
    let dir = Directory::new("attempt-fences")?;
    let cx = dir.cx()?;
    let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let created = created(&mut deployment, &cx)?;
    let first = intent_binding(
        &deployment,
        &created,
        "cleanup-one",
        "urn:fss:onvif:cleanup-1",
        &cx,
    )?;
    let original_witness = first.expected_control;
    prepare_unsubscribe(&mut deployment, &created, first, &cx)?;
    let good = intent_binding(
        &deployment,
        &created,
        "cleanup-two",
        "urn:fss:onvif:cleanup-2",
        &cx,
    )?;
    let mut stale = good.clone();
    stale.expected_control = original_witness;
    let reused_approval = intent_binding(
        &deployment,
        &created,
        "cleanup-one",
        "urn:fss:onvif:cleanup-2",
        &cx,
    )?;
    let reused_id = intent_binding(
        &deployment,
        &created,
        "cleanup-two",
        "urn:fss:onvif:cleanup-1",
        &cx,
    )?;
    let mut other_epr = good.clone();
    other_epr.request_digest =
        ContentDigest::sha256(b"same origin, different opaque subscription token");
    let mut wrong_create = good.clone();
    wrong_create.create_message_id = "urn:fss:onvif:other-create".into();
    let head = deployment.current_anchor().clone();
    let objects = deployment.publisher().spool().object_count();
    for invalid in [stale, reused_approval, reused_id, other_epr, wrong_create] {
        assert!(prepare_unsubscribe(&mut deployment, &created, invalid, &cx).is_err());
        assert_eq!(deployment.current_anchor(), &head);
        assert_eq!(deployment.publisher().spool().object_count(), objects);
    }
    let second = prepare_unsubscribe(&mut deployment, &created, good, &cx)?;
    assert!(second.newly_prepared());
    assert_eq!(inspect_cleanup(&deployment, &created, &cx)?.attempts, 2);
    Ok(())
}

#[test]
fn successful_raw_outcome_or_legacy_terminal_blocks_another_effect_before_staging() -> Test {
    for legacy in [false, true] {
        let dir = Directory::new(if legacy {
            "legacy-terminal"
        } else {
            "raw-terminal"
        })?;
        let cx = dir.cx()?;
        let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let created = created(&mut deployment, &cx)?;
        let terminal = if legacy {
            let terminal =
                retain_unsubscribed(&mut deployment, &created, binding()?, &source(), &cx)?;
            RetainedUnsubscribe::open(
                &deployment,
                terminal.identity(),
                Some(terminal.publication_root()),
                &cx,
            )?;
            terminal.identity()
        } else {
            let binding = intent_binding(
                &deployment,
                &created,
                "cleanup-one",
                "urn:fss:onvif:cleanup-1",
                &cx,
            )?;
            let intent = prepare_unsubscribe(&mut deployment, &created, binding, &cx)?;
            // Missing completion time and no separate v1 marker still preserve a valid ACK.
            retain_unsubscribe_outcome(
                &mut deployment,
                &intent,
                UnsubscribeOutcomeBinding {
                    completed_ns: None,
                    ..outcome_binding()
                },
                &source(),
                &cx,
            )?
            .identity()
        };
        let status = inspect_cleanup(&deployment, &created, &cx)?;
        assert_eq!(status.terminal.map(|entry| entry.identity), Some(terminal));
        let binding = intent_binding(
            &deployment,
            &created,
            "fresh-but-unnecessary",
            "urn:fss:onvif:cleanup-2",
            &cx,
        )?;
        let head = deployment.current_anchor().clone();
        let objects = deployment.publisher().spool().object_count();
        assert!(prepare_unsubscribe(&mut deployment, &created, binding, &cx).is_err());
        assert_eq!(deployment.current_anchor(), &head);
        assert_eq!(deployment.publisher().spool().object_count(), objects);
    }
    Ok(())
}

#[test]
fn damaged_required_outcome_refuses_reopen_reconciliation_and_exact_retry_without_repair() -> Test {
    let dir = Directory::new("damage")?;
    let cx = dir.cx()?;
    let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let created = created(&mut deployment, &cx)?;
    let binding = intent_binding(
        &deployment,
        &created,
        "cleanup-one",
        "urn:fss:onvif:cleanup-1",
        &cx,
    )?;
    let intent = prepare_unsubscribe(&mut deployment, &created, binding, &cx)?;
    let outcome =
        retain_unsubscribe_outcome(&mut deployment, &intent, outcome_binding(), &source(), &cx)?;
    let path = deployment
        .publisher()
        .spool()
        .object_path(outcome.source_digest());
    fs::write(&path, b"damaged-cleanup-source")?;
    assert!(RetainedUnsubscribeOutcome::open(&deployment, outcome.identity(), None, &cx).is_err());
    assert!(inspect_cleanup(&deployment, &created, &cx).is_err());
    assert!(
        retain_unsubscribe_outcome(&mut deployment, &intent, outcome_binding(), &source(), &cx)
            .is_err()
    );
    assert_eq!(fs::read(path)?, b"damaged-cleanup-source");
    Ok(())
}

#[test]
fn selected_cleanup_query_does_not_load_unrelated_create_source() -> Test {
    let dir = Directory::new("targeted-query")?;
    let cx = dir.cx()?;
    let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let selected = created(&mut deployment, &cx)?;
    let mut other_binding = selected.binding().clone();
    other_binding.message_id = "urn:fss:onvif:create-other".into();
    other_binding.source.sensor_id = SensorId::parse("sensor:other")?;
    let other_source = std::str::from_utf8(selected.source())?
        .replace(&selected.binding().message_id, &other_binding.message_id);
    let other_intent = prepare_create(&mut deployment, other_binding, &cx)?;
    let other = retain_created(
        &mut deployment,
        &other_intent,
        1_010,
        true,
        other_source.as_bytes(),
        &cx,
    )?;
    fs::remove_file(
        deployment
            .publisher()
            .spool()
            .object_path(other.source_digest()),
    )?;
    let status = inspect_cleanup(&deployment, &selected, &cx)?;
    assert_eq!(status.attempts, 0);
    assert!(status.terminal.is_none());
    // The complete catalog still refuses damaged custody; the target query makes no claim
    // about the unrelated subscription's validity or complete global inventory.
    assert!(list_control(&deployment, 128, &cx).is_err());
    Ok(())
}

#[test]
fn cancellation_and_deletion_never_restore_a_dispatchable_intent_or_deleted_outcome() -> Test {
    let dir = Directory::new("cancel-delete")?;
    let cx = dir.cx()?;
    let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let created = created(&mut deployment, &cx)?;
    let binding = intent_binding(
        &deployment,
        &created,
        "cleanup-one",
        "urn:fss:onvif:cleanup-1",
        &cx,
    )?;
    cx.set_cancel_at_checkpoint(STAGE_UNSUBSCRIBE_INTENT_PUBLISH);
    assert!(prepare_unsubscribe(&mut deployment, &created, binding.clone(), &cx).is_err());
    let cx = dir.cx()?;
    let intent = prepare_unsubscribe(&mut deployment, &created, binding, &cx)?;
    assert!(
        !intent.newly_prepared(),
        "a visible prior intent never regains dispatch permission"
    );
    let outcome =
        retain_unsubscribe_outcome(&mut deployment, &intent, outcome_binding(), &source(), &cx)?;
    let plan = plan_deletion(&deployment, outcome.identity(), &cx)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    let plan_digest = plan.digest()?;
    let approval = plan.approval_digest("operator:onvif-cleanup-test")?;
    commit_deletion(
        &mut deployment,
        plan_digest,
        approval,
        "operator:onvif-cleanup-test",
        &cx,
    )?;
    assert!(matches!(
        RetainedUnsubscribeOutcome::open(&deployment, outcome.identity(), None, &cx),
        Err(MetadataError::EvidenceDeleted { .. })
    ));
    assert!(matches!(
        retain_unsubscribe_outcome(&mut deployment, &intent, outcome_binding(), &source(), &cx),
        Err(MetadataError::EvidenceDeleted { .. })
    ));
    Ok(())
}

#![forbid(unsafe_code)]
//! Native root/ledger custody for pre-dispatch intents and zero-poll Create receipts.
//! Synthetic SOAP and local deployments do not establish camera interoperability.

use std::fs;
use std::path::PathBuf;

use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
    SensorId, TimestampNs,
};
use fss_publication::{LedgerCutPoint, SlotName};
use fss_reference::onvif::control::{
    CreateIntentBinding, MAX_CONTROL_RECORD_BYTES, RetainedCreateIntent, RetainedSubscription,
    STAGE_CREATE_INTENT_PUBLISH, STAGE_CREATED_PUBLISH, prepare_create, retain_created,
};
use fss_reference::onvif::http::HttpRoute;
use fss_reference::onvif::metadata::{MetadataError, SourceBinding};
use fss_reference::onvif::wire::unsubscribe_pull_point_request;
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:onvif-control-test";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..64 {
            let path = std::env::temp_dir().join(format!(
                "fss-onvif-control-{label}-{}-{attempt}",
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
            trace_id: "trace:onvif-control-test".into(),
            operation_id: OperationId::parse("operation:onvif-control-test")?,
            principal: "operator:onvif-control-test".into(),
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

fn binding() -> Test<CreateIntentBinding> {
    Ok(CreateIntentBinding {
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
            ContentDigest::sha256(b"explicit-capture-approval"),
        )?,
        service_root: "/onvif".into(),
        message_id: "urn:fss:onvif:create-1".into(),
        started_ns: 1_000,
        lifetime_seconds: 120,
    })
}

fn created_source(endpoint: &str, relates_to: &str) -> Vec<u8> {
    format!(
        r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:e="http://www.onvif.org/ver10/events/wsdl" xmlns:w="http://www.w3.org/2005/08/addressing" xmlns:n="http://docs.oasis-open.org/wsn/b-2" xmlns:v="urn:private-vendor"><s:Header><w:Action s:mustUnderstand="1">http://www.onvif.org/ver10/events/wsdl/EventPortType/CreatePullPointSubscriptionResponse</w:Action><w:RelatesTo>{relates_to}</w:RelatesTo></s:Header><s:Body><e:CreatePullPointSubscriptionResponse><e:SubscriptionReference><w:Address>{endpoint}</w:Address><w:ReferenceParameters><v:Token>private-reference-canary</v:Token></w:ReferenceParameters></e:SubscriptionReference><n:CurrentTime>2026-10-27T00:00:00Z</n:CurrentTime><n:TerminationTime>2026-10-27T00:02:00Z</n:TerminationTime></e:CreatePullPointSubscriptionResponse></s:Body></s:Envelope>"#
    )
    .into_bytes()
}

fn source() -> Vec<u8> {
    created_source(
        "http://192.0.2.4/onvif/subscription?Idx=7",
        "urn:fss:onvif:create-1",
    )
}

fn intent_slot(identity: ContentDigest) -> Test<SlotName> {
    Ok(SlotName::parse(&format!(
        "onvif-create-intent-{}",
        &identity.to_text()[7..]
    ))?)
}

#[test]
fn intent_survives_restart_before_any_dispatch_or_response() -> Test {
    let dir = Directory::new("intent-cold")?;
    let cx = dir.cx()?;
    let (identity, root, anchor) = {
        let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let intent = prepare_create(&mut deployment, binding()?, &cx)?;
        assert!(intent.newly_prepared());
        assert_eq!(deployment.ledger().batches().len(), 1);
        assert_eq!(intent.binding(), &binding()?);
        let retry = prepare_create(&mut deployment, binding()?, &cx)?;
        assert!(!retry.newly_prepared());
        assert_eq!(retry.identity(), intent.identity());
        assert_eq!(retry.authority_anchor(), intent.authority_anchor());
        assert_eq!(deployment.ledger().batches().len(), 1);
        (
            intent.identity(),
            intent.publication_root(),
            intent.authority_anchor().clone(),
        )
    };
    let deployment = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
    let intent = RetainedCreateIntent::open(&deployment, identity, Some(root), &cx)?;
    assert!(!intent.newly_prepared());
    assert_eq!(intent.binding(), &binding()?);
    assert_eq!(intent.authority_anchor(), &anchor);
    assert!(RetainedSubscription::open(&deployment, identity, None, &cx).is_err());
    Ok(())
}

#[test]
fn create_response_and_reference_parameters_survive_zero_polls_and_restart() -> Test {
    let dir = Directory::new("created-cold")?;
    let cx = dir.cx()?;
    let xml = source();
    let (identity, root, parent, anchor) = {
        let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let intent = prepare_create(&mut deployment, binding()?, &cx)?;
        let created = retain_created(&mut deployment, &intent, 1_010, true, &xml, &cx)?;
        assert_eq!(created.source(), xml);
        assert_eq!(
            created.receive_interval(),
            CaptureInterval::new(TimestampNs(10_000), TimestampNs(10_010))?
        );
        assert_eq!(created.subscription().reference_parameter_count(), 1);
        let retry = retain_created(&mut deployment, &intent, 1_010, true, &xml, &cx)?;
        assert_eq!(retry.identity(), created.identity());
        assert_eq!(retry.authority_anchor(), created.authority_anchor());
        assert_eq!(deployment.ledger().batches().len(), 2);
        (
            created.identity(),
            created.publication_root(),
            intent.identity(),
            created.authority_anchor().clone(),
        )
    };
    let deployment = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
    let created = RetainedSubscription::open(&deployment, identity, Some(root), &cx)?;
    assert_eq!(created.intent_identity(), parent);
    assert_eq!(created.authority_anchor(), &anchor);
    assert_eq!(created.source(), xml);
    assert!(created.client_authenticated());
    assert_eq!(created.completed_ns(), 1_010);
    assert_eq!(
        created.subscription().endpoint(),
        "http://192.0.2.4/onvif/subscription?Idx=7"
    );
    let cleanup = unsubscribe_pull_point_request(created.subscription())?
        .with_message_id("urn:fss:onvif:cleanup-1")?;
    assert!(std::str::from_utf8(cleanup.body())?.contains("private-reference-canary"));
    let debug = format!("{created:?} {:?} {:?}", created.intent(), created.binding());
    assert!(!debug.contains("private-reference-canary"));
    assert!(!debug.contains("private-profile-canary"));
    assert!(!debug.contains("Idx=7"));
    Ok(())
}

#[test]
fn changed_owner_request_fields_produce_distinct_intents() -> Test {
    let dir = Directory::new("request-binding")?;
    let cx = dir.cx()?;
    let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let original = binding()?;
    let first = prepare_create(&mut deployment, original.clone(), &cx)?;
    let mut different_id = original.clone();
    different_id.message_id = "urn:fss:onvif:create-2".into();
    let mut different_generation = original.clone();
    different_generation.events = HttpRoute::event_service(
        original.events.peer(),
        original.events.authority(),
        original.events.target(),
        2,
        original.events.plaintext_approval(),
    )?;
    let mut different_lifetime = original;
    different_lifetime.lifetime_seconds = 60;
    for changed in [different_id, different_generation, different_lifetime] {
        let intent = prepare_create(&mut deployment, changed, &cx)?;
        assert_ne!(intent.identity(), first.identity());
    }
    assert_eq!(deployment.ledger().batches().len(), 4);
    Ok(())
}

#[test]
fn invalid_intent_never_publishes_or_grants_dispatch() -> Test {
    let dir = Directory::new("intent-refusals")?;
    let cx = dir.cx()?;
    let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let mut interval = binding()?;
    interval.source.receive_interval = CaptureInterval::new(TimestampNs(1), TimestampNs(2))?;
    let mut message = binding()?;
    message.message_id.clear();
    let mut subtree = binding()?;
    subtree.service_root = "/other".into();
    let mut lifetime = binding()?;
    lifetime.lifetime_seconds = 0;
    let mut media_route = binding()?;
    media_route.events = HttpRoute::new(
        media_route.events.peer(),
        media_route.events.authority(),
        media_route.events.target(),
        1,
        media_route.events.plaintext_approval(),
    )?;
    for bad in [interval, message, subtree, lifetime, media_route] {
        assert!(prepare_create(&mut deployment, bad, &cx).is_err());
    }
    assert!(deployment.ledger().batches().is_empty());
    assert_eq!(deployment.publisher().visible_roots().count(), 0);
    Ok(())
}

#[test]
fn malformed_hostile_or_mismatched_create_leaves_only_durable_intent() -> Test {
    let dir = Directory::new("created-refusals")?;
    let cx = dir.cx()?;
    let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let intent = prepare_create(&mut deployment, binding()?, &cx)?;
    for xml in [
        b"malformed SOAP".to_vec(),
        created_source(
            "http://192.0.2.99/onvif/subscription",
            "urn:fss:onvif:create-1",
        ),
        created_source(
            "http://192.0.2.4/outside/subscription",
            "urn:fss:onvif:create-1",
        ),
        created_source("http://192.0.2.4/onvif/subscription", "urn:fss:onvif:wrong"),
    ] {
        assert!(retain_created(&mut deployment, &intent, 1_010, false, &xml, &cx).is_err());
    }
    assert!(retain_created(&mut deployment, &intent, 999, false, &source(), &cx).is_err());
    assert!(
        retain_created(
            &mut deployment,
            &intent,
            60_000_001_001,
            false,
            &source(),
            &cx
        )
        .is_err()
    );
    assert_eq!(deployment.ledger().batches().len(), 1);
    assert_eq!(deployment.publisher().visible_roots().count(), 1);
    assert_eq!(
        RetainedCreateIntent::open(&deployment, intent.identity(), None, &cx)?.identity(),
        intent.identity()
    );
    Ok(())
}

#[test]
fn durable_create_requires_explicit_namespace_correct_reply_correlation() -> Test {
    use fss_reference::onvif::wire::{require_relates_to, validate_relates_to};
    let dir = Directory::new("explicit-correlation")?;
    let cx = dir.cx()?;
    let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let intent = prepare_create(&mut deployment, binding()?, &cx)?;
    let xml = String::from_utf8(source())?;
    let field = "<w:RelatesTo>urn:fss:onvif:create-1</w:RelatesTo>";
    let absent = xml.replace(field, "");
    // Preserve the established live-device compatibility contract.
    assert!(validate_relates_to(absent.as_bytes(), &intent.binding().message_id).is_ok());
    for bad in [
        absent,
        xml.replace("w:RelatesTo", "v:RelatesTo"),
        xml.replace(field, &format!("{field}{field}")),
        xml.replace(
            "<w:RelatesTo>",
            "<w:RelatesTo RelationshipType=\"urn:not-a-reply\">",
        ),
    ] {
        assert!(
            retain_created(&mut deployment, &intent, 1_010, false, bad.as_bytes(), &cx).is_err()
        );
    }
    let renamed = xml
        .replace(
            "<w:RelatesTo>",
            "<reply:RelatesTo xmlns:reply=\"http://www.w3.org/2005/08/addressing\">",
        )
        .replace("</w:RelatesTo>", "</reply:RelatesTo>");
    assert!(require_relates_to(renamed.as_bytes(), &intent.binding().message_id).is_ok());
    assert_eq!(deployment.ledger().batches().len(), 1);
    Ok(())
}

#[test]
fn missing_or_corrupt_intent_and_source_are_not_repaired_by_retry() -> Test {
    for damage_intent in [false, true] {
        for remove in [false, true] {
            let dir = Directory::new("damage")?;
            let cx = dir.cx()?;
            let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
            let intent = prepare_create(&mut deployment, binding()?, &cx)?;
            let created = retain_created(&mut deployment, &intent, 1_010, false, &source(), &cx)?;
            let digest = if damage_intent {
                intent.identity()
            } else {
                created.source_digest()
            };
            let path = deployment.publisher().spool().object_path(digest);
            if remove {
                fs::remove_file(&path)?;
            } else {
                fs::write(&path, b"corrupted control custody")?;
            }
            assert!(
                RetainedSubscription::open(&deployment, created.identity(), None, &cx).is_err()
            );
            assert!(
                retain_created(&mut deployment, &intent, 1_010, false, &source(), &cx).is_err()
            );
            if damage_intent {
                assert!(prepare_create(&mut deployment, binding()?, &cx).is_err());
            }
            if remove {
                assert!(!path.exists());
            } else {
                assert_eq!(fs::read(&path)?, b"corrupted control custody");
            }
            assert_eq!(deployment.ledger().batches().len(), 2);
        }
    }
    Ok(())
}

#[test]
fn cancellation_before_intent_publication_preserves_no_success_receipt() -> Test {
    let dir = Directory::new("cancel-intent")?;
    let cx = dir.cx()?;
    let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    cx.set_cancel_at_checkpoint(STAGE_CREATE_INTENT_PUBLISH);
    assert!(matches!(
        prepare_create(&mut deployment, binding()?, &cx),
        Err(MetadataError::Cancelled)
    ));
    assert!(deployment.ledger().batches().is_empty());
    assert_eq!(deployment.publisher().visible_roots().count(), 0);
    Ok(())
}

#[test]
fn cancellation_before_response_publication_keeps_original_intent() -> Test {
    let dir = Directory::new("cancel-created")?;
    let cx = dir.cx()?;
    let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let intent = prepare_create(&mut deployment, binding()?, &cx)?;
    cx.set_cancel_at_checkpoint(STAGE_CREATED_PUBLISH);
    assert!(retain_created(&mut deployment, &intent, 1_010, false, &source(), &cx).is_err());
    assert_eq!(deployment.ledger().batches().len(), 1);
    assert_eq!(deployment.publisher().visible_roots().count(), 1);
    let fresh = dir.cx()?;
    let retained = RetainedCreateIntent::open(
        &deployment,
        intent.identity(),
        Some(intent.publication_root()),
        &fresh,
    )?;
    assert_eq!(retained.authority_anchor(), intent.authority_anchor());
    Ok(())
}

#[test]
fn cancellation_after_each_commit_preserves_known_durable_handles() -> Test {
    for stage in [
        "onvif_control:intent_committed",
        "onvif_control:created_committed",
    ] {
        let dir = Directory::new("post-commit")?;
        let cx = dir.cx()?;
        let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        if stage.contains("intent_") {
            cx.set_cancel_at_checkpoint(stage);
        }
        let intent = prepare_create(&mut deployment, binding()?, &cx)?;
        let created = if stage.contains("created_") {
            cx.set_cancel_at_checkpoint(stage);
            Some(retain_created(
                &mut deployment,
                &intent,
                1_010,
                false,
                &source(),
                &cx,
            )?)
        } else {
            None
        };
        assert!(!cx.io_authority().is_valid());
        drop(deployment);
        let fresh = dir.cx()?;
        let deployment = ReferenceDeployment::reopen(&dir.0, SITE, &fresh)?;
        assert_eq!(
            RetainedCreateIntent::open(
                &deployment,
                intent.identity(),
                Some(intent.publication_root()),
                &fresh
            )?
            .authority_anchor(),
            intent.authority_anchor()
        );
        if let Some(created) = created {
            assert_eq!(
                RetainedSubscription::open(
                    &deployment,
                    created.identity(),
                    Some(created.publication_root()),
                    &fresh
                )?
                .authority_anchor(),
                created.authority_anchor()
            );
        }
    }
    Ok(())
}

#[test]
fn root_durable_intent_interruption_requires_exact_storage_retry() -> Test {
    let dir = Directory::new("intent-linkage")?;
    let cx = dir.cx()?;
    let (identity, root) = {
        let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        deployment.inject_ledger_crash_at(LedgerCutPoint::AfterRootDurable);
        assert!(prepare_create(&mut deployment, binding()?, &cx).is_err());
        assert!(deployment.ledger().batches().is_empty());
        let visible = deployment
            .publisher()
            .visible_roots()
            .next()
            .ok_or("durable root")?;
        let hex = visible
            .slot
            .as_str()
            .strip_prefix("onvif-create-intent-")
            .ok_or("slot")?;
        (
            ContentDigest::parse(&format!("sha256:{hex}"))?,
            visible.root,
        )
    };
    let mut deployment = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
    assert!(RetainedCreateIntent::open(&deployment, identity, Some(root), &cx).is_err());
    let intent = prepare_create(&mut deployment, binding()?, &cx)?;
    assert_eq!(intent.identity(), identity);
    assert_eq!(intent.publication_root(), root);
    assert_eq!(deployment.ledger().batches().len(), 1);
    Ok(())
}

#[test]
fn exact_retry_refuses_an_intent_ledgered_with_wrong_validity() -> Test {
    let template = Directory::new("validity-template")?;
    let template_cx = template.cx()?;
    let mut original = ReferenceDeployment::open(&template.0, SITE, &template_cx)?;
    let intent = prepare_create(&mut original, binding()?, &template_cx)?;
    let recipe = original
        .publisher()
        .spool()
        .read_bounded(intent.identity(), MAX_CONTROL_RECORD_BYTES)?;
    let dir = Directory::new("validity")?;
    let cx = dir.cx()?;
    let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let slot = intent_slot(intent.identity())?;
    let staged = deployment.stage_and_publish(&slot, &[recipe.as_slice()], &cx)?;
    assert_eq!(staged.manifest.root(), intent.publication_root());
    deployment.publish_and_commit(
        &slot,
        &staged.manifest,
        CaptureInterval::new(TimestampNs(999), TimestampNs(999))?,
        &cx,
    )?;
    assert!(matches!(
        RetainedCreateIntent::open(&deployment, intent.identity(), None, &cx),
        Err(MetadataError::Custody)
    ));
    assert!(matches!(
        prepare_create(&mut deployment, binding()?, &cx),
        Err(MetadataError::Custody)
    ));
    assert_eq!(deployment.ledger().batches().len(), 1);
    Ok(())
}

#[test]
fn wrong_deployment_authority_and_expected_root_are_refused() -> Test {
    let dir = Directory::new("authority")?;
    let other = Directory::new("other-authority")?;
    let cx = dir.cx()?;
    let wrong = other.cx()?;
    let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    assert!(matches!(
        prepare_create(&mut deployment, binding()?, &wrong),
        Err(MetadataError::Authority)
    ));
    let intent = prepare_create(&mut deployment, binding()?, &cx)?;
    assert!(
        RetainedCreateIntent::open(
            &deployment,
            intent.identity(),
            Some(ContentDigest::sha256(b"wrong")),
            &cx
        )
        .is_err()
    );
    assert!(matches!(
        RetainedCreateIntent::open(&deployment, intent.identity(), None, &wrong),
        Err(MetadataError::Authority)
    ));
    assert!(matches!(
        retain_created(&mut deployment, &intent, 1_010, false, &source(), &wrong),
        Err(MetadataError::Authority)
    ));
    Ok(())
}

#[cfg(test)]
mod catalog {
    use super::*;
    use fss_reference::onvif::control::{
        ControlKind, MAX_CATALOG_RECORDS, UnsubscribeBinding, list_control, retain_unsubscribed,
    };

    #[test]
    fn discovers_intent_after_restart_without_an_output_receipt() -> Test {
        let dir = Directory::new("catalog-intent")?;
        let cx = dir.cx()?;
        {
            let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
            prepare_create(&mut deployment, binding()?, &cx)?;
            // Simulate process/output loss: no identity is carried across this boundary.
        }
        let deployment = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
        let records = list_control(&deployment, 128, &cx)?;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, ControlKind::CreateIntent);
        assert_eq!(records[0].intent_identity, records[0].identity);
        assert!(records[0].subscription_identity.is_none());
        let intent = RetainedCreateIntent::open(
            &deployment,
            records[0].identity,
            Some(records[0].root),
            &cx,
        )?;
        assert_eq!(intent.binding(), &binding()?);
        assert!(!intent.newly_prepared());
        Ok(())
    }

    #[test]
    fn preserves_multiple_create_observations_and_terminal_links() -> Test {
        let dir = Directory::new("catalog-lifecycle")?;
        let cx = dir.cx()?;
        let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let intent = prepare_create(&mut deployment, binding()?, &cx)?;
        let first = retain_created(&mut deployment, &intent, 1_010, false, &source(), &cx)?;
        let alternate = created_source(
            "http://192.0.2.4/onvif/subscription?Idx=8",
            "urn:fss:onvif:create-1",
        );
        let second = retain_created(&mut deployment, &intent, 1_020, false, &alternate, &cx)?;
        let route = first
            .binding()
            .events
            .event_subscription(first.subscription().endpoint(), "/onvif")?;
        let cleanup = br#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://www.w3.org/2005/08/addressing" xmlns:n="http://docs.oasis-open.org/wsn/b-2"><s:Header><w:RelatesTo>urn:fss:onvif:cleanup-1</w:RelatesTo></s:Header><s:Body><n:UnsubscribeResponse/></s:Body></s:Envelope>"#;
        let ended = retain_unsubscribed(
            &mut deployment,
            &first,
            UnsubscribeBinding {
                route,
                message_id: "urn:fss:onvif:cleanup-1".into(),
                started_ns: 2_000,
                completed_ns: 2_010,
                receive_interval: CaptureInterval::new(TimestampNs(20_000), TimestampNs(20_010))?,
                client_authenticated: false,
            },
            cleanup,
            &cx,
        )?;
        let records = list_control(&deployment, 4, &cx)?;
        assert_eq!(records.len(), 4);
        assert_eq!(
            records
                .iter()
                .map(|r| r.authority_sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        assert_eq!(
            records.iter().map(|r| r.identity).collect::<Vec<_>>(),
            vec![
                intent.identity(),
                first.identity(),
                second.identity(),
                ended.identity()
            ]
        );
        assert!(
            records
                .iter()
                .all(|r| r.intent_identity == intent.identity())
        );
        assert_eq!(records[1].kind, ControlKind::Created);
        assert_eq!(records[2].kind, ControlKind::Created);
        assert_eq!(records[3].kind, ControlKind::Unsubscribed);
        assert_eq!(records[3].subscription_identity, Some(first.identity()));
        Ok(())
    }

    #[test]
    fn a_small_catalog_limit_refuses_the_whole_result() -> Test {
        let dir = Directory::new("catalog-limit")?;
        let cx = dir.cx()?;
        let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let intent = prepare_create(&mut deployment, binding()?, &cx)?;
        retain_created(&mut deployment, &intent, 1_010, false, &source(), &cx)?;
        assert!(list_control(&deployment, 0, &cx).is_err());
        assert!(list_control(&deployment, MAX_CATALOG_RECORDS + 1, &cx).is_err());
        assert!(matches!(
            list_control(&deployment, 1, &cx),
            Err(MetadataError::Limit)
        ));
        assert_eq!(list_control(&deployment, 2, &cx)?.len(), 2);
        Ok(())
    }

    #[test]
    fn damaged_source_or_missing_published_root_is_never_omitted() -> Test {
        for remove_root in [false, true] {
            let dir = Directory::new("catalog-damage")?;
            let cx = dir.cx()?;
            let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
            let intent = prepare_create(&mut deployment, binding()?, &cx)?;
            let created = retain_created(&mut deployment, &intent, 1_010, false, &source(), &cx)?;
            if remove_root {
                let path = deployment
                    .publisher()
                    .root_dir()
                    .join("roots")
                    .join(format!(
                        "onvif-subscription-{}.root",
                        &created.identity().to_text()[7..]
                    ));
                fs::remove_file(path)?;
            } else {
                let path = deployment
                    .publisher()
                    .spool()
                    .object_path(created.source_digest());
                fs::write(path, b"corrupted control source")?;
            }
            assert!(list_control(&deployment, 128, &cx).is_err());
        }
        Ok(())
    }

    #[test]
    fn unledgered_control_root_and_wrong_authority_refuse_a_successful_catalog() -> Test {
        let dir = Directory::new("catalog-unledgered")?;
        let other = Directory::new("catalog-other")?;
        let cx = dir.cx()?;
        let wrong = other.cx()?;
        {
            let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
            assert!(list_control(&deployment, 128, &wrong).is_err());
            deployment.inject_ledger_crash_at(LedgerCutPoint::AfterRootDurable);
            assert!(prepare_create(&mut deployment, binding()?, &cx).is_err());
        }
        let deployment = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
        assert!(list_control(&deployment, 128, &cx).is_err());
        Ok(())
    }
}

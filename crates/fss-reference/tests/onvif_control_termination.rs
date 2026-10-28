#![forbid(unsafe_code)]
//! Durable terminal cleanup observations remain separate from current network authority.

use std::fs;
use std::path::PathBuf;

use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
    SensorId, TimestampNs,
};
use fss_reference::onvif::control::{
    CreateIntentBinding, RetainedSubscription, RetainedUnsubscribe, STAGE_UNSUBSCRIBED_PUBLISH,
    UnsubscribeBinding, prepare_create, retain_created, retain_unsubscribed,
};
use fss_reference::onvif::http::HttpRoute;
use fss_reference::onvif::metadata::SourceBinding;
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:onvif-cleanup-test";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..64 {
            let path = std::env::temp_dir().join(format!(
                "fss-onvif-cleanup-{label}-{}-{attempt}",
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

#[test]
fn terminal_receipt_survives_restart_with_independently_current_approval() -> Test {
    let dir = Directory::new("cold")?;
    let cx = dir.cx()?;
    let xml = source();
    let (identity, root, parent, anchor) = {
        let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let created = created(&mut deployment, &cx)?;
        let current = binding()?;
        assert_ne!(
            current.route.plaintext_approval(),
            created.binding().events.plaintext_approval()
        );
        let ended = retain_unsubscribed(&mut deployment, &created, current.clone(), &xml, &cx)?;
        assert_eq!(ended.subscription_identity(), created.identity());
        assert_eq!(ended.binding(), &current);
        assert_eq!(ended.source(), xml);
        assert_eq!(deployment.ledger().batches().len(), 3);
        let retry = retain_unsubscribed(&mut deployment, &created, current, &xml, &cx)?;
        assert_eq!(retry.identity(), ended.identity());
        assert_eq!(retry.authority_anchor(), ended.authority_anchor());
        assert_eq!(deployment.ledger().batches().len(), 3);
        (
            ended.identity(),
            ended.publication_root(),
            created.identity(),
            ended.authority_anchor().clone(),
        )
    };
    let deployment = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
    let ended = RetainedUnsubscribe::open(&deployment, identity, Some(root), &cx)?;
    assert_eq!(ended.subscription_identity(), parent);
    assert_eq!(ended.authority_anchor(), &anchor);
    assert_eq!(ended.source(), xml);
    assert_eq!(ended.binding(), &binding()?);
    assert_eq!(
        ended
            .subscription()
            .subscription()
            .reference_parameter_count(),
        1
    );
    let debug = format!("{ended:?} {:?}", ended.binding());
    assert!(!debug.contains("Idx=7"));
    assert!(!debug.contains("cleanup-1"));
    assert!(!debug.contains("private-reference-canary"));
    Ok(())
}

#[test]
fn cleanup_refuses_peer_query_generation_and_time_rebinding() -> Test {
    let dir = Directory::new("binding")?;
    let cx = dir.cx()?;
    let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let created = created(&mut deployment, &cx)?;
    let mut query = binding()?;
    query.route = query.route.with_target("/onvif/subscription?Idx=8")?;
    let mut peer = binding()?;
    peer.route = HttpRoute::event_service(
        "192.0.2.99:80".parse()?,
        "192.0.2.99",
        "/onvif/subscription?Idx=7",
        1,
        peer.route.plaintext_approval(),
    )?;
    let mut generation = binding()?;
    generation.route = HttpRoute::event_service(
        generation.route.peer(),
        generation.route.authority(),
        generation.route.target(),
        2,
        generation.route.plaintext_approval(),
    )?;
    let mut backwards = binding()?;
    backwards.completed_ns = 49;
    let mut span = binding()?;
    span.completed_ns = 61;
    let mut earlier = binding()?;
    earlier.receive_interval = CaptureInterval::new(TimestampNs(9_000), TimestampNs(9_010))?;
    let mut reused_create = binding()?;
    reused_create.message_id = created.binding().message_id.clone();
    let mut malformed_id = binding()?;
    malformed_id.message_id = "urn:bad identity".into();
    for bad in [
        query,
        peer,
        generation,
        backwards,
        span,
        earlier,
        reused_create,
        malformed_id,
    ] {
        assert!(retain_unsubscribed(&mut deployment, &created, bad, &source(), &cx).is_err());
    }
    assert_eq!(deployment.ledger().batches().len(), 2);
    assert_eq!(deployment.publisher().visible_roots().count(), 2);
    Ok(())
}

#[test]
fn cleanup_requires_a_successful_exactly_correlated_response() -> Test {
    let dir = Directory::new("response")?;
    let cx = dir.cx()?;
    let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let created = created(&mut deployment, &cx)?;
    let exact = String::from_utf8(source())?;
    let field = "<w:RelatesTo>urn:fss:onvif:cleanup-1</w:RelatesTo>";
    for xml in [
        exact.replace(field, "").into_bytes(),
        exact.replace("w:RelatesTo", "n:RelatesTo").into_bytes(),
        exact
            .replace(field, &format!("{field}{field}"))
            .into_bytes(),
        exact
            .replace(
                "<w:RelatesTo>",
                "<w:RelatesTo RelationshipType=\"urn:not-a-reply\">",
            )
            .into_bytes(),
        response("urn:fss:onvif:wrong"),
        created.source().to_vec(),
        b"not SOAP".to_vec(),
        Vec::new(),
    ] {
        assert!(retain_unsubscribed(&mut deployment, &created, binding()?, &xml, &cx).is_err());
    }
    assert_eq!(deployment.ledger().batches().len(), 2);
    Ok(())
}

#[test]
fn missing_cleanup_or_parent_source_refuses_reopen_and_retry_without_repair() -> Test {
    for damage_parent in [false, true] {
        for remove in [false, true] {
            let dir = Directory::new("damage")?;
            let cx = dir.cx()?;
            let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
            let created = created(&mut deployment, &cx)?;
            let ended = retain_unsubscribed(&mut deployment, &created, binding()?, &source(), &cx)?;
            let digest = if damage_parent {
                created.source_digest()
            } else {
                ended.source_digest()
            };
            let path = deployment.publisher().spool().object_path(digest);
            if remove {
                fs::remove_file(&path)?;
            } else {
                fs::write(&path, b"corrupted control source")?;
            }
            assert!(RetainedUnsubscribe::open(&deployment, ended.identity(), None, &cx).is_err());
            assert!(
                retain_unsubscribed(&mut deployment, &created, binding()?, &source(), &cx).is_err()
            );
            if remove {
                assert!(!path.exists());
            } else {
                assert_eq!(fs::read(&path)?, b"corrupted control source");
            }
            assert_eq!(deployment.ledger().batches().len(), 3);
        }
    }
    Ok(())
}

#[test]
fn cancellation_before_terminal_publication_leaves_only_prior_receipts() -> Test {
    let dir = Directory::new("cancel")?;
    let cx = dir.cx()?;
    let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let created = created(&mut deployment, &cx)?;
    cx.set_cancel_at_checkpoint(STAGE_UNSUBSCRIBED_PUBLISH);
    assert!(retain_unsubscribed(&mut deployment, &created, binding()?, &source(), &cx).is_err());
    assert_eq!(deployment.ledger().batches().len(), 2);
    assert_eq!(deployment.publisher().visible_roots().count(), 2);
    let fresh = dir.cx()?;
    let reopened = RetainedSubscription::open(
        &deployment,
        created.identity(),
        Some(created.publication_root()),
        &fresh,
    )?;
    assert_eq!(reopened.authority_anchor(), created.authority_anchor());
    Ok(())
}

#[test]
fn cancellation_after_terminal_commit_preserves_cold_verifiable_success() -> Test {
    let dir = Directory::new("post-commit")?;
    let cx = dir.cx()?;
    let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let created = created(&mut deployment, &cx)?;
    cx.set_cancel_at_checkpoint("onvif_control:unsubscribed_committed");
    let ended = retain_unsubscribed(&mut deployment, &created, binding()?, &source(), &cx)?;
    assert!(!cx.io_authority().is_valid());
    assert_eq!(deployment.ledger().batches().len(), 3);
    drop(deployment);
    let fresh = dir.cx()?;
    let deployment = ReferenceDeployment::reopen(&dir.0, SITE, &fresh)?;
    let reopened = RetainedUnsubscribe::open(
        &deployment,
        ended.identity(),
        Some(ended.publication_root()),
        &fresh,
    )?;
    assert_eq!(reopened.authority_anchor(), ended.authority_anchor());
    Ok(())
}

#[test]
fn terminal_reads_require_exact_root_and_current_deployment_authority() -> Test {
    let dir = Directory::new("authority")?;
    let other = Directory::new("other-authority")?;
    let cx = dir.cx()?;
    let wrong = other.cx()?;
    let mut deployment = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let created = created(&mut deployment, &cx)?;
    assert!(retain_unsubscribed(&mut deployment, &created, binding()?, &source(), &wrong).is_err());
    let ended = retain_unsubscribed(&mut deployment, &created, binding()?, &source(), &cx)?;
    assert!(
        RetainedUnsubscribe::open(
            &deployment,
            ended.identity(),
            Some(ContentDigest::sha256(b"wrong")),
            &cx
        )
        .is_err()
    );
    assert!(RetainedUnsubscribe::open(&deployment, ended.identity(), None, &wrong).is_err());
    assert!(RetainedSubscription::open(&deployment, ended.identity(), None, &cx).is_err());
    Ok(())
}

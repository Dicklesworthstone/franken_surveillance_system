#![forbid(unsafe_code)]
//! Cold process recovery uses retained local cleanup, with no camera or credentials.

use fss_core::{
    BudgetVector, CaptureInterval, ContextAuthority, OperationId, RootAuthoritySpec, SensorId,
    TimestampNs,
};
use fss_reference::onvif::capture_operation::{CaptureOperationBinding, reserve_for_create};
use fss_reference::onvif::control::{
    CreateIntentBinding, UnsubscribeBinding, prepare_create, retain_created, retain_unsubscribed,
};
use fss_reference::onvif::http::HttpRoute;
use fss_reference::onvif::metadata::SourceBinding;
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::*;

const OWNER: &str = "operator:cold-capture-reconciliation";
const OPERATION: &str = "operation:cold-capture-reconciliation";

fn prepared_fixture(root: &Path) -> Test<(ContentDigest, ContentDigest)> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:cold-capture-reconciliation".into(),
        operation_id: OperationId::parse("operation:fixture-construction")?,
        principal: OWNER.into(),
        capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(4096)
            .build()?,
        privacy_scope: "privacy:fixture".into(),
        retention_scope: "retention:fixture".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority_read_only(&authority, root.to_path_buf())?;
    let mut dep = ReferenceDeployment::open(root, SITE, &cx)?;
    let operation = CaptureOperationBinding {
        operation_id: OperationId::parse(OPERATION)?,
        principal: OWNER.into(),
        request_digest: ContentDigest::sha256(b"native-approved-request"),
        precondition_digest: ContentDigest::sha256(b"native-approved-pins"),
    };
    let create = CreateIntentBinding {
        source: SourceBinding {
            sensor_id: SensorId::parse(SENSOR)?,
            device_generation: ContentDigest::sha256(b"fixture-camera"),
            profile_generation: ContentDigest::sha256(b"fixture-profile"),
            profile_token: PROFILE.into(),
            receive_interval: CaptureInterval::new(TimestampNs(10_000), TimestampNs(10_000))?,
        },
        events: HttpRoute::event_service(
            "192.0.2.4:80".parse()?,
            "192.0.2.4",
            "/onvif/events",
            1,
            ContentDigest::sha256(b"fixture-explicit-owner-approval"),
        )?,
        service_root: "/onvif".into(),
        message_id: "urn:fss:onvif:cli-reconcile-create".into(),
        started_ns: 1000,
        lifetime_seconds: 120,
    };
    let guard = reserve_for_create(&mut dep, &operation, &create, TimestampNs(10_000), &cx)?;
    let intent = prepare_create(&mut dep, create, &cx)?;
    guard.commit_with_intent(&mut dep, &intent, TimestampNs(10_005), &cx)?;
    let source = br#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:e="http://www.onvif.org/ver10/events/wsdl" xmlns:w="http://www.w3.org/2005/08/addressing" xmlns:n="http://docs.oasis-open.org/wsn/b-2"><s:Header><w:RelatesTo>urn:fss:onvif:cli-reconcile-create</w:RelatesTo></s:Header><s:Body><e:CreatePullPointSubscriptionResponse><e:SubscriptionReference><w:Address>http://192.0.2.4/onvif/private-cli-subscription?Idx=7</w:Address></e:SubscriptionReference><n:CurrentTime>2026-10-27T00:00:00Z</n:CurrentTime><n:TerminationTime>2026-10-27T00:02:00Z</n:TerminationTime></e:CreatePullPointSubscriptionResponse></s:Body></s:Envelope>"#;
    let created = retain_created(&mut dep, &intent, 1010, false, source, &cx)?;
    let cleanup = UnsubscribeBinding {
        route: created
            .binding()
            .events
            .event_subscription(created.subscription().endpoint(), "/onvif")?,
        message_id: "urn:fss:onvif:cli-reconcile-cleanup".into(),
        started_ns: 50,
        completed_ns: 60,
        receive_interval: CaptureInterval::new(TimestampNs(20_000), TimestampNs(20_010))?,
        client_authenticated: false,
    };
    let terminal = br#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://www.w3.org/2005/08/addressing" xmlns:n="http://docs.oasis-open.org/wsn/b-2"><s:Header><w:Action s:mustUnderstand="1">http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/UnsubscribeResponse</w:Action><w:RelatesTo>urn:fss:onvif:cli-reconcile-cleanup</w:RelatesTo></s:Header><s:Body><n:UnsubscribeResponse/></s:Body></s:Envelope>"#;
    let ended = retain_unsubscribed(&mut dep, &created, cleanup, terminal, &cx)?;
    Ok((ended.identity(), ended.publication_root()))
}

fn reconcile_args(
    root: &Path,
    identity: ContentDigest,
    publication: ContentDigest,
) -> Vec<OsString> {
    let mut args = vec![
        "control".into(),
        "reconcile-operation".into(),
        "--root".into(),
        root.into(),
    ];
    for (key, value) in [
        ("--site", SITE),
        ("--principal", OWNER),
        ("--operation-id", OPERATION),
        ("--kind", "unsubscribed"),
        ("--receive-origin-ns", "50000"),
        ("--owner-authorized", "yes"),
        ("--reconcile", "yes"),
    ] {
        args.extend([key.into(), value.into()]);
    }
    args.extend([
        "--control-id".into(),
        identity.to_text().into(),
        "--expected-root".into(),
        publication.to_text().into(),
    ]);
    args
}

#[test]
fn cold_process_reconciles_exact_cleanup_and_retries_without_any_camera_request() -> Test {
    let dir = Directory::new("cold-operation-reconciliation")?;
    let root = dir.root();
    let (identity, publication) = prepared_fixture(&root)?;
    let args = reconcile_args(&root, identity, publication);
    let output = run(&args)?;
    let first = report(&output, true)?;
    private_report(&output);
    for (key, expected) in [
        ("operation", "control_operation_reconcile"),
        ("phase", "verified"),
        ("capture_operation.snapshot_state", "Verified"),
        ("capture_operation.obligation_state", "Verified"),
        ("capture_operation.create_retry_allowed", "false"),
        ("cleanup_custody_verified", "true"),
        ("current_remote_state", "unknown"),
        ("http_exchanges", "0"),
        ("create_dispatched", "false"),
        ("polls_dispatched", "0"),
        ("unsubscribe_dispatched", "false"),
    ] {
        assert_eq!(field(&first, key)?, expected, "{key}");
    }
    let journal = fs::read(root.join("effects/journal.fssj"))?;
    let retry = report(&run(&args)?, true)?;
    assert_eq!(
        field(&retry, "capture_operation.terminal_proof")?,
        field(&first, "capture_operation.terminal_proof")?
    );
    assert_eq!(
        field(&retry, "capture_operation.journal_root")?,
        field(&first, "capture_operation.journal_root")?
    );
    assert_eq!(fs::read(root.join("effects/journal.fssj"))?, journal);
    let mut wrong_owner = args;
    set(&mut wrong_owner, "--principal", "operator:another-owner")?;
    let refused = run(&wrong_owner)?;
    assert!(!refused.status.success());
    assert!(
        String::from_utf8(refused.stderr)?.contains("ERR-ONVIF-CAPTURE-OPERATION-AUTHORITY-001")
    );
    assert_eq!(fs::read(root.join("effects/journal.fssj"))?, journal);
    Ok(())
}

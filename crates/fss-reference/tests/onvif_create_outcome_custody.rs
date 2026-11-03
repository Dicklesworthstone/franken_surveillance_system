#![forbid(unsafe_code)]
//! Complete Create response custody, cold reconciliation and native privacy lifecycle.
//! Synthetic SOAP and local files prove no camera support or current remote subscription state.

use std::fs;
use std::path::PathBuf;

use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
    SensorId, TimestampNs,
};
use fss_publication::LedgerCutPoint;
use fss_reference::deletion::holds::{
    CAP_HOLD_COMMIT, CAP_HOLD_PREPARE, HoldRequest, HoldState, commit_hold, preview_hold,
};
use fss_reference::deletion::{
    DeletionError, DeletionScope, commit_deletion, plan_deletion, plan_scope_deletion,
};
use fss_reference::onvif::control::{
    ControlKind, CreateIntentBinding, CreateOutcomeBinding, RetainedCreateIntent,
    RetainedCreateOutcome, RetainedSubscription, STAGE_CREATE_OUTCOME_PUBLISH,
    STAGE_CREATED_PUBLISH, list_control, prepare_create, recover_created, retain_create_outcome,
    retain_created,
};
use fss_reference::onvif::http::HttpRoute;
use fss_reference::onvif::metadata::{MAX_SOURCE_BYTES, MetadataError, SourceBinding};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:onvif-create-outcome-test";
const PRINCIPAL: &str = "operator:onvif-create-outcome-test";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..64 {
            let path = std::env::temp_dir().join(format!(
                "fss-onvif-create-outcome-{label}-{}-{attempt}",
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

    fn authority(&self) -> Test<ContextAuthority> {
        Ok(ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:onvif-create-outcome-test".into(),
            operation_id: OperationId::parse("operation:onvif-create-outcome-test")?,
            principal: PRINCIPAL.into(),
            // These are local custody/hold capabilities, not network or camera capabilities.
            capabilities: vec![
                fss_reference::ADP_REPLAY_ROW_ID.into(),
                CAP_HOLD_PREPARE.into(),
                CAP_HOLD_COMMIT.into(),
            ],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(64 * 1024 * 1024)
                .storage_operations(8192)
                .build()?,
            privacy_scope: "privacy:fixture".into(),
            retention_scope: "retention:fixture".into(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?)
    }

    fn cx(&self) -> Test<ReplayCx> {
        Ok(ReplayCx::from_context_authority(
            &self.authority()?,
            &self.0,
        )?)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binding(sensor: &str) -> Test<CreateIntentBinding> {
    Ok(CreateIntentBinding {
        source: SourceBinding {
            sensor_id: SensorId::parse(format!("sensor:{sensor}"))?,
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
            ContentDigest::sha256(b"historical-capture-approval"),
        )?,
        service_root: "/onvif".into(),
        message_id: "urn:fss:onvif:create-1".into(),
        started_ns: 1_000,
        lifetime_seconds: 120,
    })
}

fn response(endpoint: &str, relates_to: &str) -> Vec<u8> {
    format!(
        r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:e="http://www.onvif.org/ver10/events/wsdl" xmlns:w="http://www.w3.org/2005/08/addressing" xmlns:n="http://docs.oasis-open.org/wsn/b-2" xmlns:v="urn:private-vendor"><s:Header><w:Action s:mustUnderstand="1">http://www.onvif.org/ver10/events/wsdl/EventPortType/CreatePullPointSubscriptionResponse</w:Action><w:RelatesTo>{relates_to}</w:RelatesTo></s:Header><s:Body><e:CreatePullPointSubscriptionResponse><e:SubscriptionReference><w:Address>{endpoint}</w:Address><w:ReferenceParameters><v:Token>private-reference-canary</v:Token></w:ReferenceParameters></e:SubscriptionReference><n:CurrentTime>2026-10-27T00:00:00Z</n:CurrentTime><n:TerminationTime>2026-10-27T00:02:00Z</n:TerminationTime></e:CreatePullPointSubscriptionResponse></s:Body></s:Envelope>"#
    )
    .into_bytes()
}

fn source() -> Vec<u8> {
    response(
        "http://192.0.2.4/onvif/subscription?Idx=7",
        "urn:fss:onvif:create-1",
    )
}

fn outcome_binding() -> CreateOutcomeBinding {
    CreateOutcomeBinding {
        completed_ns: Some(1_010),
        client_authenticated: true,
        http_status: 200,
        soap_content_type: true,
    }
}

fn deleted<T>(result: Result<T, MetadataError>, plan: ContentDigest) -> Test {
    match result {
        Err(MetadataError::EvidenceDeleted { plan: actual, .. }) => {
            assert_eq!(actual, plan);
            Ok(())
        }
        Err(error) => Err(format!("expected native deletion refusal, got {error}").into()),
        Ok(_) => Err("deleted Create evidence was served or recreated".into()),
    }
}

#[test]
fn complete_rejected_bodies_survive_restart_without_becoming_subscriptions() -> Test {
    let dir = Directory::new("rejected")?;
    let cx = dir.cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let intent = prepare_create(&mut dep, binding("north")?, &cx)?;
    let missing_correlation = String::from_utf8(source())?
        .replace("<w:RelatesTo>urn:fss:onvif:create-1</w:RelatesTo>", "")
        .into_bytes();
    let wrong_namespace = String::from_utf8(source())?
        .replace("w:RelatesTo", "v:RelatesTo")
        .into_bytes();
    let cases = [
        (b"private-malformed-create-body".to_vec(), outcome_binding()),
        (Vec::new(), outcome_binding()),
        (vec![0xff, 0x00, 0x80], outcome_binding()),
        (missing_correlation, outcome_binding()),
        (wrong_namespace, outcome_binding()),
        (
            response("http://192.0.2.4/onvif/subscription", "urn:wrong:request"),
            outcome_binding(),
        ),
        (
            response(
                "http://192.0.2.99/onvif/subscription",
                "urn:fss:onvif:create-1",
            ),
            outcome_binding(),
        ),
        (
            response(
                "http://192.0.2.4/outside/subscription",
                "urn:fss:onvif:create-1",
            ),
            outcome_binding(),
        ),
        (
            source(),
            CreateOutcomeBinding {
                http_status: 401,
                ..outcome_binding()
            },
        ),
        (
            source(),
            CreateOutcomeBinding {
                http_status: 500,
                ..outcome_binding()
            },
        ),
        (
            source(),
            CreateOutcomeBinding {
                soap_content_type: false,
                ..outcome_binding()
            },
        ),
        (
            source(),
            CreateOutcomeBinding {
                completed_ns: None,
                ..outcome_binding()
            },
        ),
    ];
    let mut retained = Vec::new();
    for (bytes, binding) in cases {
        let raw = retain_create_outcome(&mut dep, &intent, binding.clone(), &bytes, &cx)?;
        assert_eq!(raw.source(), bytes);
        assert_eq!(raw.source_bytes(), bytes.len());
        assert_eq!(raw.source_digest(), ContentDigest::sha256(&bytes));
        assert_eq!(raw.binding(), &binding);
        assert!(raw.scoped_subscription().is_none());
        assert!(!raw.intent().newly_prepared());
        let head = dep.current_anchor().clone();
        assert!(recover_created(&mut dep, &raw, &cx).is_err());
        assert_eq!(dep.current_anchor(), &head);
        let expected_latest = if binding.completed_ns.is_some() {
            10_010
        } else {
            10_000
        };
        assert_eq!(
            raw.receive_interval(),
            CaptureInterval::new(TimestampNs(10_000), TimestampNs(expected_latest))?
        );
        retained.push((raw.identity(), raw.publication_root(), bytes, binding));
    }
    assert_eq!(dep.ledger().batches().len(), 1 + retained.len());
    drop(dep);
    let mut dep = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
    for (identity, root, bytes, binding) in &retained {
        let raw = RetainedCreateOutcome::open(&dep, *identity, Some(*root), &cx)?;
        assert_eq!(raw.source(), bytes);
        assert_eq!(raw.binding(), binding);
        assert!(raw.scoped_subscription().is_none());
        assert!(recover_created(&mut dep, &raw, &cx).is_err());
    }
    let catalog = list_control(&dep, 64, &cx)?;
    assert_eq!(catalog.len(), 1 + retained.len());
    assert_eq!(catalog[0].kind, ControlKind::CreateIntent);
    for entry in &catalog[1..] {
        assert_eq!(entry.kind, ControlKind::CreateOutcome);
        assert_eq!(entry.intent_identity, intent.identity());
        assert!(entry.subscription_identity.is_none());
    }
    Ok(())
}

#[test]
fn cold_explicit_recovery_reproduces_existing_created_bytes_and_never_rearms_create() -> Test {
    let legacy_dir = Directory::new("legacy")?;
    let legacy_cx = legacy_dir.cx()?;
    let mut legacy = ReferenceDeployment::open(&legacy_dir.0, SITE, &legacy_cx)?;
    let legacy_intent = prepare_create(&mut legacy, binding("north")?, &legacy_cx)?;
    let frozen = retain_created(
        &mut legacy,
        &legacy_intent,
        1_010,
        true,
        &source(),
        &legacy_cx,
    )?;
    let frozen_bytes = fs::read(legacy.publisher().spool().object_path(frozen.identity()))?;

    let dir = Directory::new("recovery")?;
    let cx = dir.cx()?;
    let (identity, root, original_anchor) = {
        let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let intent = prepare_create(&mut dep, binding("north")?, &cx)?;
        let raw = retain_create_outcome(&mut dep, &intent, outcome_binding(), &source(), &cx)?;
        let retry = retain_create_outcome(&mut dep, &intent, outcome_binding(), &source(), &cx)?;
        assert_eq!(retry.identity(), raw.identity());
        assert_eq!(retry.publication_root(), raw.publication_root());
        assert_eq!(retry.authority_anchor(), raw.authority_anchor());
        assert_eq!(dep.ledger().batches().len(), 2);
        assert_eq!(
            list_control(&dep, 2, &cx)?[1].kind,
            ControlKind::CreateOutcome
        );
        assert!(RetainedSubscription::open(&dep, raw.identity(), None, &cx).is_err());
        (
            raw.identity(),
            raw.publication_root(),
            raw.authority_anchor().clone(),
        )
    };
    let mut dep = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
    let raw = RetainedCreateOutcome::open(&dep, identity, Some(root), &cx)?;
    assert_eq!(raw.authority_anchor(), &original_anchor);
    assert_eq!(raw.source(), source());
    assert!(!raw.intent().newly_prepared());
    assert_eq!(
        raw.scoped_subscription()
            .ok_or("scoped response")?
            .reference_parameter_count(),
        1
    );
    assert!(
        RetainedCreateOutcome::open(&dep, identity, Some(frozen.publication_root()), &cx).is_err()
    );
    let debug = format!(
        "{raw:?} {:?} {:?}",
        raw.intent(),
        list_control(&dep, 2, &cx)?
    );
    for private in [
        "private-reference-canary",
        "private-profile-canary",
        "Idx=7",
    ] {
        assert!(!debug.contains(private));
    }
    let created = recover_created(&mut dep, &raw, &cx)?;
    assert_eq!(created.identity(), frozen.identity());
    assert_eq!(created.publication_root(), frozen.publication_root());
    assert_eq!(
        fs::read(dep.publisher().spool().object_path(created.identity()))?,
        frozen_bytes
    );
    assert!(!created.intent().newly_prepared());
    let before = dep.current_anchor().clone();
    let again = recover_created(&mut dep, &raw, &cx)?;
    assert_eq!(again.authority_anchor(), created.authority_anchor());
    assert_eq!(dep.current_anchor(), &before);
    assert!(!prepare_create(&mut dep, binding("north")?, &cx)?.newly_prepared());
    assert_eq!(list_control(&dep, 3, &cx)?[2].kind, ControlKind::Created);
    Ok(())
}

#[test]
fn changed_source_or_http_observation_is_a_distinct_immutable_outcome() -> Test {
    let dir = Directory::new("different-observation")?;
    let cx = dir.cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let intent = prepare_create(&mut dep, binding("north")?, &cx)?;
    let raw = retain_create_outcome(&mut dep, &intent, outcome_binding(), &source(), &cx)?;
    for changed in [
        CreateOutcomeBinding {
            completed_ns: Some(1_011),
            ..outcome_binding()
        },
        CreateOutcomeBinding {
            client_authenticated: false,
            ..outcome_binding()
        },
        CreateOutcomeBinding {
            http_status: 500,
            ..outcome_binding()
        },
        CreateOutcomeBinding {
            soap_content_type: false,
            ..outcome_binding()
        },
    ] {
        let other = retain_create_outcome(&mut dep, &intent, changed, &source(), &cx)?;
        assert_ne!(other.identity(), raw.identity());
        assert_eq!(other.source_digest(), raw.source_digest());
    }
    let changed =
        String::from_utf8(source())?.replace("private-reference-canary", "new-private-token");
    let other = retain_create_outcome(
        &mut dep,
        &intent,
        outcome_binding(),
        changed.as_bytes(),
        &cx,
    )?;
    assert_ne!(other.identity(), raw.identity());
    assert_ne!(other.source_digest(), raw.source_digest());
    assert_eq!(
        RetainedCreateOutcome::open(&dep, raw.identity(), None, &cx)?.source(),
        source()
    );
    Ok(())
}

#[test]
fn historical_receipt_cannot_bypass_current_deployment_authority() -> Test {
    let dir = Directory::new("authority")?;
    let other = Directory::new("different-authority")?;
    let cx = dir.cx()?;
    let denied = other.cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let intent = prepare_create(&mut dep, binding("north")?, &cx)?;
    let raw = retain_create_outcome(&mut dep, &intent, outcome_binding(), &source(), &cx)?;
    let before = dep.current_anchor().clone();
    assert!(matches!(
        RetainedCreateOutcome::open(&dep, raw.identity(), None, &denied),
        Err(MetadataError::Authority)
    ));
    assert!(matches!(
        recover_created(&mut dep, &raw, &denied),
        Err(MetadataError::Authority)
    ));
    assert!(matches!(
        retain_create_outcome(&mut dep, &intent, outcome_binding(), &source(), &denied),
        Err(MetadataError::Authority)
    ));
    assert_eq!(dep.current_anchor(), &before);
    assert_eq!(dep.publisher().visible_roots().count(), 2);
    Ok(())
}

#[test]
fn corrupt_or_missing_source_parent_record_and_roots_refuse_without_implicit_repair() -> Test {
    for member in 0..5 {
        for remove in [false, true] {
            let dir = Directory::new("corrupt")?;
            let cx = dir.cx()?;
            let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
            let intent = prepare_create(&mut dep, binding("north")?, &cx)?;
            let raw = retain_create_outcome(&mut dep, &intent, outcome_binding(), &source(), &cx)?;
            let digest = [
                raw.identity(),
                raw.source_digest(),
                raw.publication_root(),
                intent.identity(),
                intent.publication_root(),
            ][member];
            let path = dep.publisher().spool().object_path(digest);
            if remove {
                fs::remove_file(&path)?;
            } else {
                fs::write(&path, b"corrupt Create custody")?;
            }
            let head = dep.current_anchor().clone();
            assert!(RetainedCreateOutcome::open(&dep, raw.identity(), None, &cx).is_err());
            assert!(recover_created(&mut dep, &raw, &cx).is_err());
            assert!(
                retain_create_outcome(&mut dep, &intent, outcome_binding(), &source(), &cx)
                    .is_err()
            );
            assert!(list_control(&dep, 8, &cx).is_err());
            assert_eq!(dep.current_anchor(), &head);
            if remove {
                assert!(!path.exists());
            } else {
                assert_eq!(fs::read(&path)?, b"corrupt Create custody");
            }
            drop(dep);
            let dep = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
            assert!(RetainedCreateOutcome::open(&dep, raw.identity(), None, &cx).is_err());
        }
    }
    Ok(())
}

#[test]
fn malformed_binding_and_oversize_body_refuse_before_any_new_publication() -> Test {
    let dir = Directory::new("limits")?;
    let cx = dir.cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let intent = prepare_create(&mut dep, binding("north")?, &cx)?;
    for observation in [
        CreateOutcomeBinding {
            http_status: 0,
            ..outcome_binding()
        },
        CreateOutcomeBinding {
            http_status: 600,
            ..outcome_binding()
        },
        CreateOutcomeBinding {
            completed_ns: Some(999),
            ..outcome_binding()
        },
        CreateOutcomeBinding {
            completed_ns: Some(60_000_001_001),
            ..outcome_binding()
        },
    ] {
        assert!(retain_create_outcome(&mut dep, &intent, observation, &source(), &cx).is_err());
    }
    assert!(matches!(
        retain_create_outcome(
            &mut dep,
            &intent,
            outcome_binding(),
            &vec![b'x'; MAX_SOURCE_BYTES + 1],
            &cx
        ),
        Err(MetadataError::Limit)
    ));
    assert_eq!(dep.ledger().batches().len(), 1);
    assert_eq!(dep.publisher().visible_roots().count(), 1);
    Ok(())
}

#[test]
fn interrupted_raw_publication_reconciles_storage_without_rearming_dispatch() -> Test {
    for ledger_cut in [false, true] {
        let dir = Directory::new("cut")?;
        let cx = dir.cx()?;
        let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let intent = prepare_create(&mut dep, binding("north")?, &cx)?;
        if ledger_cut {
            dep.inject_ledger_crash_at(LedgerCutPoint::AfterRootDurable);
        } else {
            cx.set_cancel_at_checkpoint(STAGE_CREATE_OUTCOME_PUBLISH);
        }
        assert!(
            retain_create_outcome(&mut dep, &intent, outcome_binding(), &source(), &cx).is_err()
        );
        assert_eq!(dep.ledger().batches().len(), 1);
        drop(dep);
        let fresh = dir.cx()?;
        let mut dep = ReferenceDeployment::reopen(&dir.0, SITE, &fresh)?;
        let intent = RetainedCreateIntent::open(&dep, intent.identity(), None, &fresh)?;
        assert!(!intent.newly_prepared());
        let raw = retain_create_outcome(&mut dep, &intent, outcome_binding(), &source(), &fresh)?;
        assert_eq!(raw.source(), source());
        assert!(!raw.intent().newly_prepared());
        assert_eq!(dep.ledger().batches().len(), 2);
        assert_eq!(
            list_control(&dep, 2, &fresh)?[1].kind,
            ControlKind::CreateOutcome
        );
    }
    Ok(())
}

#[test]
fn cancelled_success_marker_preserves_raw_response_for_explicit_cold_recovery() -> Test {
    let dir = Directory::new("marker-cancel")?;
    let cx = dir.cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let intent = prepare_create(&mut dep, binding("north")?, &cx)?;
    let raw = retain_create_outcome(&mut dep, &intent, outcome_binding(), &source(), &cx)?;
    cx.set_cancel_at_checkpoint(STAGE_CREATED_PUBLISH);
    assert!(recover_created(&mut dep, &raw, &cx).is_err());
    assert_eq!(dep.ledger().batches().len(), 2);
    drop(dep);
    let fresh = dir.cx()?;
    let mut dep = ReferenceDeployment::reopen(&dir.0, SITE, &fresh)?;
    let raw =
        RetainedCreateOutcome::open(&dep, raw.identity(), Some(raw.publication_root()), &fresh)?;
    assert_eq!(raw.source(), source());
    let created = recover_created(&mut dep, &raw, &fresh)?;
    assert_eq!(created.source(), source());
    assert!(!created.intent().newly_prepared());
    assert_eq!(dep.ledger().batches().len(), 3);
    Ok(())
}

#[test]
fn post_commit_cancellation_keeps_the_raw_handle_durable() -> Test {
    let dir = Directory::new("post-commit")?;
    let cx = dir.cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let intent = prepare_create(&mut dep, binding("north")?, &cx)?;
    cx.set_cancel_at_checkpoint("onvif_control:create_outcome_committed");
    let raw = retain_create_outcome(&mut dep, &intent, outcome_binding(), &source(), &cx)?;
    assert!(!cx.io_authority().is_valid());
    drop(dep);
    let fresh = dir.cx()?;
    let dep = ReferenceDeployment::reopen(&dir.0, SITE, &fresh)?;
    let reopened =
        RetainedCreateOutcome::open(&dep, raw.identity(), Some(raw.publication_root()), &fresh)?;
    assert_eq!(reopened.source(), source());
    assert_eq!(reopened.authority_anchor(), raw.authority_anchor());
    assert_eq!(dep.ledger().batches().len(), 2);
    Ok(())
}

#[test]
fn raw_outcome_hold_blocks_sensor_deletion_and_release_enables_complete_closure() -> Test {
    let dir = Directory::new("hold")?;
    let authority = dir.authority()?;
    let cx = dir.cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let intent = prepare_create(&mut dep, binding("north")?, &cx)?;
    let raw = retain_create_outcome(&mut dep, &intent, outcome_binding(), &source(), &cx)?;
    let created = recover_created(&mut dep, &raw, &cx)?;
    let other = prepare_create(&mut dep, binding("south")?, &cx)?;
    let held = HoldRequest {
        hold_id: "create-response-evidence".into(),
        import_identity: raw.identity(),
        state: HoldState::Held,
        reason: "Review of an interrupted subscription creation".into(),
    };
    let preview = preview_hold(&dep, &held, &authority, &cx)?;
    commit_hold(&mut dep, &held, preview.record.approval(), &authority, &cx)?;
    drop(dep);
    let mut dep = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
    let scope = DeletionScope::Sensor(SensorId::parse("sensor:north")?);
    let blocked = plan_scope_deletion(&dep, &scope, &cx)?;
    assert!(
        blocked
            .blockers
            .iter()
            .any(|finding| finding.kind == "evidence_hold")
    );
    assert!(matches!(
        commit_deletion(
            &mut dep,
            blocked.digest()?,
            blocked.approval_digest(PRINCIPAL)?,
            PRINCIPAL,
            &cx
        ),
        Err(DeletionError::Blocked(_))
    ));
    let released = HoldRequest {
        state: HoldState::Released,
        ..held
    };
    let preview = preview_hold(&dep, &released, &authority, &cx)?;
    commit_hold(
        &mut dep,
        &released,
        preview.record.approval(),
        &authority,
        &cx,
    )?;
    let plan = plan_scope_deletion(&dep, &scope, &cx)?;
    let mut expected = vec![intent.identity(), raw.identity(), created.identity()];
    expected.sort_unstable();
    assert_eq!(plan.imports, expected);
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    for digest in [raw.identity(), raw.publication_root(), raw.source_digest()] {
        assert!(plan.deleted_set().contains(&digest));
    }
    let digest = plan.digest()?;
    commit_deletion(
        &mut dep,
        digest,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &cx,
    )?;
    deleted(
        RetainedCreateOutcome::open(&dep, raw.identity(), None, &cx),
        digest,
    )?;
    deleted(recover_created(&mut dep, &raw, &cx), digest)?;
    deleted(
        retain_create_outcome(&mut dep, &intent, outcome_binding(), &source(), &cx),
        digest,
    )?;
    deleted(
        retain_create_outcome(&mut dep, &other, outcome_binding(), &source(), &cx),
        digest,
    )?;
    let catalog = list_control(&dep, 1, &cx)?;
    assert_eq!(catalog.len(), 1);
    assert_eq!(catalog[0].identity, other.identity());
    drop(dep);
    let mut dep = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
    deleted(recover_created(&mut dep, &raw, &cx), digest)?;
    assert_eq!(list_control(&dep, 1, &cx)?[0].identity, other.identity());
    Ok(())
}

#[test]
fn deleting_only_raw_outcome_preserves_shared_success_source_and_parent_intent() -> Test {
    let dir = Directory::new("shared-source")?;
    let cx = dir.cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let intent = prepare_create(&mut dep, binding("north")?, &cx)?;
    let raw = retain_create_outcome(&mut dep, &intent, outcome_binding(), &source(), &cx)?;
    let created = recover_created(&mut dep, &raw, &cx)?;
    let plan = plan_deletion(&dep, raw.identity(), &cx)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    assert!(!plan.deleted_set().contains(&intent.identity()));
    assert!(!plan.deleted_set().contains(&created.identity()));
    assert!(!plan.deleted_set().contains(&raw.source_digest()));
    let digest = plan.digest()?;
    commit_deletion(
        &mut dep,
        digest,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &cx,
    )?;
    deleted(
        RetainedCreateOutcome::open(&dep, raw.identity(), None, &cx),
        digest,
    )?;
    deleted(recover_created(&mut dep, &raw, &cx), digest)?;
    assert_eq!(
        RetainedSubscription::open(&dep, created.identity(), None, &cx)?.source(),
        source()
    );
    assert!(!RetainedCreateIntent::open(&dep, intent.identity(), None, &cx)?.newly_prepared());
    assert_eq!(list_control(&dep, 2, &cx)?.len(), 2);
    Ok(())
}

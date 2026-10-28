#![forbid(unsafe_code)]
//! Native hold/deletion ownership for durable ONVIF subscription-control evidence.
//! Synthetic sources prove local custody and recovery, never live-device behavior.

use std::fs;
use std::path::PathBuf;

use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
    SensorId, TimestampNs,
};
use fss_publication::SlotName;
use fss_reference::deletion::holds::{
    CAP_HOLD_COMMIT, CAP_HOLD_PREPARE, HoldRequest, HoldState, commit_hold, list_holds,
    preview_hold,
};
use fss_reference::deletion::{
    CommitOutcome, DeletionError, DeletionIndex, DeletionScope, STAGE_DELETION_RECORD_APPENDED,
    commit_deletion, plan_deletion, plan_scope_deletion,
};
use fss_reference::onvif::control::{
    CreateIntentBinding, RetainedCreateIntent, RetainedSubscription, RetainedUnsubscribe,
    UnsubscribeBinding, list_control, prepare_create, retain_created, retain_unsubscribed,
};
use fss_reference::onvif::http::HttpRoute;
use fss_reference::onvif::metadata::{MetadataError, SourceBinding};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:onvif-control-lifecycle";
const PRINCIPAL: &str = "principal:onvif-control-lifecycle";
const CREATE: &[u8] = br#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:e="http://www.onvif.org/ver10/events/wsdl" xmlns:w="http://www.w3.org/2005/08/addressing" xmlns:n="http://docs.oasis-open.org/wsn/b-2"><s:Header><w:RelatesTo>urn:fss:onvif:create-1</w:RelatesTo></s:Header><s:Body><e:CreatePullPointSubscriptionResponse><e:SubscriptionReference><w:Address>http://192.0.2.4/onvif/subscription?Idx=7</w:Address></e:SubscriptionReference><n:CurrentTime>2026-10-27T00:00:00Z</n:CurrentTime><n:TerminationTime>2026-10-27T00:02:00Z</n:TerminationTime></e:CreatePullPointSubscriptionResponse></s:Body></s:Envelope>"#;
const CLEANUP: &[u8] = br#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://www.w3.org/2005/08/addressing" xmlns:n="http://docs.oasis-open.org/wsn/b-2"><s:Header><w:RelatesTo>urn:fss:onvif:cleanup-1</w:RelatesTo></s:Header><s:Body><n:UnsubscribeResponse/></s:Body></s:Envelope>"#;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..64 {
            let path = std::env::temp_dir().join(format!(
                "fss-onvif-control-lifecycle-{label}-{}-{attempt}",
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
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    dep: ReferenceDeployment,
    cx: ReplayCx,
    authority: ContextAuthority,
    _dir: Directory,
}
impl Fixture {
    fn new(label: &str) -> Test<Self> {
        let dir = Directory::new(label)?;
        let root = dir.0.join("deployment");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:onvif-control-lifecycle".into(),
            operation_id: OperationId::parse("operation:onvif-control-lifecycle")?,
            principal: PRINCIPAL.into(),
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
        })?;
        let cx = ReplayCx::from_context_authority(&authority, &root)?;
        let dep = ReferenceDeployment::open(&root, SITE, &cx)?;
        Ok(Self {
            dep,
            cx,
            authority,
            _dir: dir,
        })
    }

    fn chain(
        &mut self,
    ) -> Test<(
        RetainedCreateIntent,
        RetainedSubscription,
        RetainedUnsubscribe,
    )> {
        let intent = prepare_create(&mut self.dep, binding("north")?, &self.cx)?;
        let created = retain_created(&mut self.dep, &intent, 1_010, false, CREATE, &self.cx)?;
        let cleanup = cleanup_binding()?;
        let ended = retain_unsubscribed(&mut self.dep, &created, cleanup, CLEANUP, &self.cx)?;
        Ok((intent, created, ended))
    }
}

fn binding(sensor: &str) -> Test<CreateIntentBinding> {
    Ok(CreateIntentBinding {
        source: SourceBinding {
            sensor_id: SensorId::parse(format!("sensor:{sensor}"))?,
            device_generation: ContentDigest::sha256(b"device-generation-1"),
            profile_generation: ContentDigest::sha256(b"profile-generation-1"),
            profile_token: "main".into(),
            receive_interval: CaptureInterval::new(TimestampNs(10_000), TimestampNs(10_000))?,
        },
        events: HttpRoute::event_service(
            "192.0.2.4:80".parse()?,
            "192.0.2.4",
            "/onvif/events",
            1,
            ContentDigest::sha256(b"current-capture-approval"),
        )?,
        service_root: "/onvif".into(),
        message_id: "urn:fss:onvif:create-1".into(),
        started_ns: 1_000,
        lifetime_seconds: 120,
    })
}
fn cleanup_binding() -> Test<UnsubscribeBinding> {
    Ok(UnsubscribeBinding {
        route: HttpRoute::event_service(
            "192.0.2.4:80".parse()?,
            "192.0.2.4",
            "/onvif/subscription?Idx=7",
            1,
            ContentDigest::sha256(b"independently-current-cleanup-approval"),
        )?,
        message_id: "urn:fss:onvif:cleanup-1".into(),
        started_ns: 50,
        completed_ns: 60,
        receive_interval: CaptureInterval::new(TimestampNs(20_000), TimestampNs(20_010))?,
        client_authenticated: false,
    })
}
fn hold(identity: ContentDigest, state: HoldState) -> HoldRequest {
    HoldRequest {
        hold_id: "control-evidence".into(),
        import_identity: identity,
        state,
        reason: "Owner review of incomplete remote subscription lifecycle".into(),
    }
}
fn deleted<T>(result: Result<T, MetadataError>, plan: ContentDigest) -> Test {
    match result {
        Err(MetadataError::EvidenceDeleted { plan: actual, .. }) => {
            assert_eq!(actual, plan);
            Ok(())
        }
        Err(error) => Err(format!("expected native deleted evidence refusal, got {error}").into()),
        Ok(_) => Err("deleted control evidence was served or recreated".into()),
    }
}
fn control_unit(identity: ContentDigest, intent: bool) -> String {
    format!(
        "slot:{}-{}",
        if intent {
            "onvif-create-intent"
        } else {
            "onvif-subscription"
        },
        &identity.to_text()[7..]
    )
}

#[test]
fn control_parent_deletion_reaches_observations_without_absorbing_ancestors() -> Test {
    for selected in 0..3 {
        let mut f = Fixture::new("closure")?;
        let (intent, created, ended) = f.chain()?;
        let identities = [intent.identity(), created.identity(), ended.identity()];
        let roots = [
            intent.publication_root(),
            created.publication_root(),
            ended.publication_root(),
        ];
        let plan = plan_deletion(&f.dep, identities[selected], &f.cx)?;
        assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
        assert_eq!(plan.imports, vec![identities[selected]]);
        for index in 0..3 {
            let unit = control_unit(identities[index], index == 0);
            assert_eq!(
                plan.units.iter().any(|member| member.id == unit),
                index >= selected
            );
            if index >= selected {
                assert!(plan.deleted_set().contains(&identities[index]));
                assert!(plan.deleted_set().contains(&roots[index]));
            }
        }
        // The Create SOAP remains when only its terminal observation is deleted.
        assert_eq!(
            plan.deleted_set().contains(&created.source_digest()),
            selected <= 1
        );
        assert!(plan.deleted_set().contains(&ended.source_digest()));
        let digest = plan.digest()?;
        let approval = plan.approval_digest(PRINCIPAL)?;
        commit_deletion(&mut f.dep, digest, approval, PRINCIPAL, &f.cx)?;
        deleted(
            RetainedUnsubscribe::open(&f.dep, ended.identity(), None, &f.cx),
            digest,
        )?;
        if selected <= 1 {
            deleted(
                RetainedSubscription::open(&f.dep, created.identity(), None, &f.cx),
                digest,
            )?;
        } else {
            RetainedSubscription::open(&f.dep, created.identity(), None, &f.cx)?;
        }
        if selected == 0 {
            deleted(
                RetainedCreateIntent::open(&f.dep, intent.identity(), None, &f.cx),
                digest,
            )?;
        } else {
            RetainedCreateIntent::open(&f.dep, intent.identity(), None, &f.cx)?;
        }
        assert_eq!(list_control(&f.dep, 128, &f.cx)?.len(), selected);
        let Fixture {
            dep,
            cx,
            authority: _,
            _dir: dir,
        } = f;
        let root = dep.root().to_path_buf();
        drop(dep);
        let mut dep = ReferenceDeployment::reopen(&root, SITE, &cx)?;
        assert_eq!(list_control(&dep, 128, &cx)?.len(), selected);
        // Old deleted publication batches do not poison later lifecycle scans.
        let mut fresh = binding("south")?;
        fresh.message_id = "urn:fss:onvif:create-2".into();
        let other = prepare_create(&mut dep, fresh, &cx)?;
        assert!(
            plan_deletion(&dep, other.identity(), &cx)?
                .blockers
                .is_empty()
        );
        drop(dep);
        drop(dir);
    }
    Ok(())
}

#[test]
fn every_control_kind_uses_existing_holds_and_cold_deletion_approval() -> Test {
    for held_kind in 0..3 {
        let mut f = Fixture::new("hold")?;
        let (intent, created, ended) = f.chain()?;
        let held = [intent.identity(), created.identity(), ended.identity()][held_kind];
        let request = hold(held, HoldState::Held);
        let preview = preview_hold(&f.dep, &request, &f.authority, &f.cx)?;
        let placed = commit_hold(
            &mut f.dep,
            &request,
            preview.record.approval(),
            &f.authority,
            &f.cx,
        )?
        .record
        .digest();
        let Fixture {
            dep,
            cx,
            authority,
            _dir: dir,
        } = f;
        let root = dep.root().to_path_buf();
        drop(dep);
        let mut dep = ReferenceDeployment::reopen(&root, SITE, &cx)?;
        assert_eq!(list_holds(&dep, &authority, &cx)?.len(), 1);
        let blocked = plan_deletion(&dep, intent.identity(), &cx)?;
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
        RetainedUnsubscribe::open(&dep, ended.identity(), None, &cx)?;
        let release = hold(held, HoldState::Released);
        let preview = preview_hold(&dep, &release, &authority, &cx)?;
        let released = commit_hold(
            &mut dep,
            &release,
            preview.record.approval(),
            &authority,
            &cx,
        )?
        .record
        .digest();
        let plan = plan_deletion(&dep, intent.identity(), &cx)?;
        assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
        for record in [placed, released] {
            assert!(
                plan.retained
                    .iter()
                    .any(|object| object.digest == record && object.reason == "authority_history")
            );
        }
        commit_deletion(
            &mut dep,
            plan.digest()?,
            plan.approval_digest(PRINCIPAL)?,
            PRINCIPAL,
            &cx,
        )?;
        assert!(list_control(&dep, 128, &cx)?.is_empty());
        drop(dep);
        drop(dir);
    }
    Ok(())
}

#[test]
fn durable_tombstone_fences_control_reads_and_new_owner_source_reuse_before_unlink() -> Test {
    let mut f = Fixture::new("interrupted")?;
    let (intent, created, ended) = f.chain()?;
    // A separate intent exists before deletion, but never acquired this raw Create response.
    let other = prepare_create(&mut f.dep, binding("south")?, &f.cx)?;
    let scope = DeletionScope::Sensor(SensorId::parse("sensor:north")?);
    let plan = plan_scope_deletion(&f.dep, &scope, &f.cx)?;
    let mut expected = vec![intent.identity(), created.identity(), ended.identity()];
    expected.sort_unstable();
    assert_eq!(plan.imports, expected);
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    assert!(plan.deleted_set().contains(&created.source_digest()));
    let digest = plan.digest()?;
    let approval = plan.approval_digest(PRINCIPAL)?;
    let stop = ReplayCx::from_context_authority(&f.authority, f.dep.root())?;
    stop.set_cancel_at_checkpoint(STAGE_DELETION_RECORD_APPENDED);
    assert!(matches!(
        commit_deletion(&mut f.dep, digest, approval, PRINCIPAL, &stop),
        Err(DeletionError::Cancelled {
            stage: STAGE_DELETION_RECORD_APPENDED
        })
    ));
    assert!(plan.deletable.iter().all(|object| {
        f.dep
            .publisher()
            .spool()
            .object_path(object.digest)
            .exists()
    }));
    let head = f.dep.current_anchor().clone();
    let objects = f.dep.publisher().spool().object_count();
    deleted(
        RetainedCreateIntent::open(&f.dep, intent.identity(), None, &f.cx),
        digest,
    )?;
    deleted(
        RetainedSubscription::open(&f.dep, created.identity(), None, &f.cx),
        digest,
    )?;
    deleted(
        RetainedUnsubscribe::open(&f.dep, ended.identity(), None, &f.cx),
        digest,
    )?;
    deleted(prepare_create(&mut f.dep, binding("north")?, &f.cx), digest)?;
    deleted(
        retain_created(&mut f.dep, &intent, 1_010, false, CREATE, &f.cx),
        digest,
    )?;
    deleted(
        retain_created(&mut f.dep, &other, 1_010, false, CREATE, &f.cx),
        digest,
    )?;
    deleted(
        retain_unsubscribed(&mut f.dep, &created, cleanup_binding()?, CLEANUP, &f.cx),
        digest,
    )?;
    assert_eq!(f.dep.current_anchor(), &head);
    assert_eq!(f.dep.publisher().spool().object_count(), objects);
    let catalog = list_control(&f.dep, 1, &f.cx)?;
    assert_eq!(catalog.len(), 1);
    assert_eq!(catalog[0].identity, other.identity());
    let Fixture {
        dep,
        cx,
        authority: _,
        _dir: dir,
    } = f;
    let root = dep.root().to_path_buf();
    drop(dep);
    let mut dep = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    assert_eq!(
        commit_deletion(&mut dep, digest, approval, PRINCIPAL, &cx)?.outcome,
        CommitOutcome::Resumed
    );
    assert!(
        DeletionIndex::read(&dep)?
            .import(intent.identity())
            .is_some_and(|entry| entry.is_complete())
    );
    deleted(
        retain_created(&mut dep, &other, 1_010, false, CREATE, &cx),
        digest,
    )?;
    assert_eq!(list_control(&dep, 1, &cx)?[0].identity, other.identity());
    drop(dep);
    drop(dir);
    Ok(())
}

#[test]
fn a_named_control_root_cannot_invent_verified_lifecycle_membership() -> Test {
    let mut f = Fixture::new("unverified")?;
    let junk = b"not a canonical control intent";
    let identity = ContentDigest::sha256(junk);
    let slot = SlotName::parse(&format!("onvif-create-intent-{}", &identity.to_text()[7..]))?;
    let staged = f.dep.stage_and_publish(&slot, &[junk.as_slice()], &f.cx)?;
    assert!(matches!(
        plan_deletion(&f.dep, identity, &f.cx),
        Err(DeletionError::UnknownImport(_))
    ));
    f.dep.publish_and_commit(
        &slot,
        &staged.manifest,
        binding("north")?.source.receive_interval,
        &f.cx,
    )?;
    let before = f.dep.current_anchor().clone();
    assert!(matches!(
        plan_deletion(&f.dep, identity, &f.cx),
        Err(DeletionError::RecordMismatch)
    ));
    assert!(
        preview_hold(
            &f.dep,
            &hold(identity, HoldState::Held),
            &f.authority,
            &f.cx
        )
        .is_err()
    );
    assert!(list_control(&f.dep, 128, &f.cx).is_err());
    assert_eq!(f.dep.current_anchor(), &before);
    Ok(())
}

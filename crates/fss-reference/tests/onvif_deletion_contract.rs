#![forbid(unsafe_code)]
//! Verified ONVIF metadata uses the existing hold, deletion and crash-recovery lifecycle.
//! Local fixtures prove custody behavior only, never live-device or physical-truth qualification.

#[path = "cascade_support/mod.rs"]
mod support;

use std::fs;

use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
    SensorId, StreamId, TimestampNs,
};
use fss_publication::SlotName;
use fss_reference::deletion::holds::{
    CAP_HOLD_COMMIT, CAP_HOLD_PREPARE, HoldOutcome, HoldRequest, HoldState, commit_hold,
    list_holds, preview_hold,
};
use fss_reference::deletion::{
    CommitOutcome, DeletionError, DeletionIndex, DeletionScope, STAGE_DELETION_RECORD_APPENDED,
    commit_deletion, plan_deletion, plan_scope_deletion,
};
use fss_reference::onvif::metadata::{
    Interpretation, MetadataError, PullPointAcquisition, RetainedMetadata, SourceBinding, retain,
    retain_pullpoint, retain_with_interpretation,
};
use fss_reference::{FileIngestAdapter, FileIngestRequest, ReferenceDeployment, ReplayCx};
use support::{OwnedDirectory, TestResult};

const SITE: &str = "site:onvif-lifecycle";
const PRINCIPAL: &str = "principal:onvif-lifecycle";
const SOURCE: &[u8] =
    include_bytes!("../../../fixtures/onvif-metadata-v1/legacy_supported_analytics.xml");
const JPEG: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg");

struct Fixture {
    dep: ReferenceDeployment,
    cx: ReplayCx,
    authority: ContextAuthority,
    dir: OwnedDirectory,
}

impl Fixture {
    fn new(label: &str) -> TestResult<Self> {
        let dir = OwnedDirectory::new(label)?;
        let root = dir.0.join("deployment");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:onvif-lifecycle".into(),
            operation_id: OperationId::parse("operation:onvif-lifecycle")?,
            principal: PRINCIPAL.into(),
            capabilities: vec![
                "ADP-REPLAY-001".into(),
                CAP_HOLD_PREPARE.into(),
                CAP_HOLD_COMMIT.into(),
            ],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(64 * 1024 * 1024)
                .storage_operations(8192)
                .build()?,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority(&authority, &root)?;
        let dep = ReferenceDeployment::open(&root, SITE, &cx)?;
        Ok(Self {
            dep,
            cx,
            authority,
            dir,
        })
    }

    fn publish(
        &mut self,
        sensor: &str,
        interpretation: Interpretation,
    ) -> TestResult<RetainedMetadata> {
        Ok(retain_with_interpretation(
            &mut self.dep,
            binding(sensor)?,
            SOURCE,
            interpretation,
            &self.cx,
        )?)
    }

    fn apply_hold(&mut self, request: &HoldRequest) -> TestResult<ContentDigest> {
        let preview = preview_hold(&self.dep, request, &self.authority, &self.cx)?;
        Ok(commit_hold(
            &mut self.dep,
            request,
            preview.record.approval(),
            &self.authority,
            &self.cx,
        )?
        .record
        .digest())
    }
}

fn binding(sensor: &str) -> TestResult<SourceBinding> {
    Ok(SourceBinding {
        sensor_id: SensorId::parse(format!("sensor:{sensor}"))?,
        device_generation: ContentDigest::sha256(b"device-generation-1"),
        profile_generation: ContentDigest::sha256(b"profile-generation-1"),
        profile_token: "main".into(),
        receive_interval: CaptureInterval::new(TimestampNs(100), TimestampNs(110))?,
    })
}

fn hold(identity: ContentDigest, state: HoldState) -> HoldRequest {
    HoldRequest {
        hold_id: "incident".into(),
        import_identity: identity,
        state,
        reason: "Owner incident evidence review".into(),
    }
}

fn assert_deleted<T>(
    result: Result<T, MetadataError>,
    identity: Option<ContentDigest>,
    plan: ContentDigest,
) -> TestResult {
    match result {
        Err(MetadataError::EvidenceDeleted {
            identity: actual,
            plan: actual_plan,
        }) => {
            assert_eq!(actual_plan, plan);
            if let Some(identity) = identity {
                assert_eq!(actual, identity);
            }
            Ok(())
        }
        Err(error) => Err(format!("wrong refusal: {error}").into()),
        Ok(_) => Err("deleted metadata was read or republished".into()),
    }
}

#[test]
fn metadata_holds_survive_restart_and_gate_existing_deletion_approval() -> TestResult {
    let mut f = Fixture::new("onvif-hold-delete")?;
    let retained = f.publish("north", Interpretation::AnalyticsV2)?;
    let identity = retained.identity();
    let before = f.dep.current_anchor().clone();
    let objects = f.dep.publisher().spool().object_count();
    let initial = plan_deletion(&f.dep, identity, &f.cx)?;
    assert!(initial.blockers.is_empty(), "{:?}", initial.blockers);
    assert_eq!(initial.imports, vec![identity]);
    assert_eq!(initial.validity, retained.binding().receive_interval);
    assert!(
        initial.units.iter().any(
            |unit| unit.kind == "import_custody" && unit.id.starts_with("slot:onvif-metadata-")
        )
    );
    for digest in [
        identity,
        retained.publication_root(),
        retained.source_digest(),
        retained.projection_digest(),
    ] {
        assert!(initial.deleted_set().contains(&digest));
    }
    assert_eq!(f.dep.current_anchor(), &before);
    assert_eq!(f.dep.publisher().spool().object_count(), objects);
    let req = hold(identity, HoldState::Held);
    let placed = f.apply_hold(&req)?;
    let again = preview_hold(&f.dep, &req, &f.authority, &f.cx)?;
    assert_eq!(again.outcome, HoldOutcome::AlreadyCurrent);
    let Fixture {
        dep,
        cx,
        authority,
        dir,
    } = f;
    let root = dep.root().to_path_buf();
    drop(dep);
    let mut dep = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    assert_eq!(list_holds(&dep, &authority, &cx)?.len(), 1);
    let blocked = plan_deletion(&dep, identity, &cx)?;
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
    RetainedMetadata::open(&dep, identity, Some(retained.publication_root()), &cx)?;
    let release = hold(identity, HoldState::Released);
    let preview = preview_hold(&dep, &release, &authority, &cx)?;
    let released = commit_hold(
        &mut dep,
        &release,
        preview.record.approval(),
        &authority,
        &cx,
    )?;
    let plan = plan_deletion(&dep, identity, &cx)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    for receipt in [placed, released.record.digest()] {
        assert!(
            plan.retained
                .iter()
                .any(|object| object.digest == receipt && object.reason == "authority_history")
        );
    }
    let head = dep.current_anchor().clone();
    assert!(matches!(
        commit_deletion(
            &mut dep,
            plan.digest()?,
            ContentDigest::sha256(b"wrong approval"),
            PRINCIPAL,
            &cx
        ),
        Err(DeletionError::ApprovalMismatch(_))
    ));
    assert_eq!(dep.current_anchor(), &head);
    let digest = plan.digest()?;
    let approval = plan.approval_digest(PRINCIPAL)?;
    commit_deletion(&mut dep, digest, approval, PRINCIPAL, &cx)?;
    assert_deleted(
        RetainedMetadata::open(&dep, identity, None, &cx),
        Some(identity),
        digest,
    )?;
    assert!(
        plan.deletable.iter().all(|object| !dep
            .publisher()
            .spool()
            .object_path(object.digest)
            .exists())
    );
    let head = dep.current_anchor().clone();
    assert_eq!(
        commit_deletion(&mut dep, digest, approval, PRINCIPAL, &cx)?.outcome,
        CommitOutcome::AlreadyComplete
    );
    assert_eq!(dep.current_anchor(), &head);
    drop(dep);
    drop(dir);
    Ok(())
}

#[test]
fn durable_deletion_denies_open_exact_retry_and_new_binding_before_unlink() -> TestResult {
    for interpretation in [Interpretation::EventsV1, Interpretation::AnalyticsV2] {
        let mut f = Fixture::new(if interpretation == Interpretation::EventsV1 {
            "onvif-v1-cut"
        } else {
            "onvif-v2-cut"
        })?;
        let retained = f.publish("north", interpretation)?;
        let identity = retained.identity();
        let plan = plan_deletion(&f.dep, identity, &f.cx)?;
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
        assert_deleted(
            RetainedMetadata::open(&f.dep, identity, None, &f.cx),
            Some(identity),
            digest,
        )?;
        assert_deleted(
            retain_with_interpretation(
                &mut f.dep,
                binding("north")?,
                SOURCE,
                interpretation,
                &f.cx,
            ),
            Some(identity),
            digest,
        )?;
        assert_deleted(
            retain(&mut f.dep, binding("new-owner")?, SOURCE, &f.cx),
            None,
            digest,
        )?;
        assert_eq!(f.dep.current_anchor(), &head);
        assert_eq!(f.dep.publisher().spool().object_count(), objects);
        let Fixture {
            dep,
            cx,
            authority: _,
            dir,
        } = f;
        let root = dep.root().to_path_buf();
        drop(dep);
        let mut dep = ReferenceDeployment::reopen(&root, SITE, &cx)?;
        assert_deleted(
            RetainedMetadata::open(&dep, identity, None, &cx),
            Some(identity),
            digest,
        )?;
        assert_eq!(
            commit_deletion(&mut dep, digest, approval, PRINCIPAL, &cx)?.outcome,
            CommitOutcome::Resumed
        );
        assert!(
            DeletionIndex::read(&dep)?
                .import(identity)
                .is_some_and(|entry| entry.is_complete())
        );
        assert_deleted(
            retain_with_interpretation(&mut dep, binding("north")?, SOURCE, interpretation, &cx),
            Some(identity),
            digest,
        )?;
        drop(dep);
        drop(dir);
    }
    Ok(())
}

#[test]
fn sensor_scope_includes_metadata_and_file_imports_without_deleting_shared_other_sensor()
-> TestResult {
    let mut f = Fixture::new("onvif-sensor-shared")?;
    let first = f.publish("north", Interpretation::EventsV1)?;
    let second = f.publish("north", Interpretation::AnalyticsV2)?;
    let other = f.publish("south", Interpretation::AnalyticsV2)?;
    let path = f.dir.0.join("north.mjpeg");
    fs::write(&path, JPEG)?;
    let file = FileIngestAdapter::ingest(
        FileIngestRequest::new(
            path,
            SensorId::parse("sensor:north")?,
            StreamId::parse("stream:north")?,
        )
        .with_receive_time(TimestampNs(1_000_000_000)),
        &f.cx,
        &mut f.dep,
    )?;
    let scope = DeletionScope::Sensor(SensorId::parse("sensor:north")?);
    let plan = plan_scope_deletion(&f.dep, &scope, &f.cx)?;
    let mut expected = vec![first.identity(), second.identity(), file.import_identity];
    expected.sort();
    assert_eq!(plan.imports, expected);
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    assert!(!plan.deleted_set().contains(&other.source_digest()));
    assert!(!plan.deleted_set().contains(&other.projection_digest()));
    assert!(!plan.deleted_set().contains(&other.publication_root()));
    let digest = plan.digest()?;
    commit_deletion(
        &mut f.dep,
        digest,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &f.cx,
    )?;
    assert_deleted(
        RetainedMetadata::open(&f.dep, first.identity(), None, &f.cx),
        Some(first.identity()),
        digest,
    )?;
    assert_deleted(
        RetainedMetadata::open(&f.dep, second.identity(), None, &f.cx),
        Some(second.identity()),
        digest,
    )?;
    let surviving = RetainedMetadata::open(
        &f.dep,
        other.identity(),
        Some(other.publication_root()),
        &f.cx,
    )?;
    assert_eq!(surviving.source_digest(), first.source_digest());
    let last = plan_deletion(&f.dep, other.identity(), &f.cx)?;
    assert!(last.deleted_set().contains(&other.source_digest()));
    commit_deletion(
        &mut f.dep,
        last.digest()?,
        last.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &f.cx,
    )?;
    assert!(
        !f.dep
            .publisher()
            .spool()
            .object_path(other.source_digest())
            .exists()
    );
    Ok(())
}

#[test]
fn names_and_corrupt_metadata_never_supply_lifecycle_membership() -> TestResult {
    let mut f = Fixture::new("onvif-unverified-lifecycle")?;
    let junk = b"not an ONVIF custody recipe";
    let identity = ContentDigest::sha256(junk);
    let slot = SlotName::parse(&format!("onvif-metadata-{}", &identity.to_text()[7..]))?;
    let published = f.dep.stage_and_publish(&slot, &[junk.as_slice()], &f.cx)?;
    assert!(matches!(
        plan_deletion(&f.dep, identity, &f.cx),
        Err(DeletionError::UnknownImport(_))
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
    f.dep.publish_and_commit(
        &slot,
        &published.manifest,
        binding("north")?.receive_interval,
        &f.cx,
    )?;
    let head = f.dep.current_anchor().clone();
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
    assert_eq!(f.dep.current_anchor(), &head);

    let mut valid = Fixture::new("onvif-corrupt-lifecycle")?;
    let retained = valid.publish("north", Interpretation::AnalyticsV2)?;
    let path = valid
        .dep
        .publisher()
        .spool()
        .object_path(retained.projection_digest());
    let mut bytes = fs::read(&path)?;
    *bytes.last_mut().ok_or("empty projection")? ^= 1;
    fs::write(path, bytes)?;
    let head = valid.dep.current_anchor().clone();
    assert!(
        plan_scope_deletion(
            &valid.dep,
            &DeletionScope::Sensor(SensorId::parse("sensor:north")?),
            &valid.cx
        )
        .is_err()
    );
    assert!(
        preview_hold(
            &valid.dep,
            &hold(retained.identity(), HoldState::Held),
            &valid.authority,
            &valid.cx
        )
        .is_err()
    );
    assert_eq!(valid.dep.current_anchor(), &head);
    Ok(())
}

#[test]
fn metadata_removed_as_a_derivative_is_not_readmitted_by_its_old_publication_batch() -> TestResult {
    let mut f = Fixture::new("onvif-derivative-deletion")?;
    let path = f.dir.0.join("parent.mjpeg");
    fs::write(&path, JPEG)?;
    let parent = FileIngestAdapter::ingest(
        FileIngestRequest::new(
            path,
            SensorId::parse("sensor:parent")?,
            StreamId::parse("stream:parent")?,
        )
        .with_receive_time(TimestampNs(1_000_000_000)),
        &f.cx,
        &mut f.dep,
    )?;
    // A retained owner pin names the parent identity, so the ordinary graph walk reaches this
    // root as a derivative. No special ONVIF dependency or extra scope member is invented.
    let mut pinned = binding("derivative")?;
    pinned.device_generation = parent.import_identity;
    let derivative = retain(&mut f.dep, pinned, SOURCE, &f.cx)?;
    let other = f.publish("independent", Interpretation::AnalyticsV2)?;
    let plan = plan_deletion(&f.dep, parent.import_identity, &f.cx)?;
    assert_eq!(plan.imports, vec![parent.import_identity]);
    assert!(plan.units.iter().any(|unit| unit.id
        == format!(
            "slot:onvif-metadata-{}",
            &derivative.identity().to_text()[7..]
        )));
    let digest = plan.digest()?;
    commit_deletion(
        &mut f.dep,
        digest,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &f.cx,
    )?;
    assert_deleted(
        RetainedMetadata::open(&f.dep, derivative.identity(), None, &f.cx),
        Some(derivative.identity()),
        digest,
    )?;
    RetainedMetadata::open(&f.dep, other.identity(), None, &f.cx)?;
    let next = plan_deletion(&f.dep, other.identity(), &f.cx)?;
    assert!(next.blockers.is_empty(), "{:?}", next.blockers);
    Ok(())
}

#[test]
fn native_pullpoint_deletion_fences_subscription_custody_for_a_different_future_poll() -> TestResult
{
    let mut f = Fixture::new("onvif-native-subscription-deletion")?;
    let subscription = br#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:e="http://www.onvif.org/ver10/events/wsdl" xmlns:w="http://www.w3.org/2005/08/addressing" xmlns:n="http://docs.oasis-open.org/wsn/b-2"><s:Header><w:Action s:mustUnderstand="1">http://www.onvif.org/ver10/events/wsdl/EventPortType/CreatePullPointSubscriptionResponse</w:Action></s:Header><s:Body><e:CreatePullPointSubscriptionResponse><e:SubscriptionReference><w:Address>http://192.0.2.4/onvif/subscription?Idx=7</w:Address></e:SubscriptionReference><n:CurrentTime>2026-10-27T00:00:00Z</n:CurrentTime><n:TerminationTime>2026-10-27T00:02:00Z</n:TerminationTime></e:CreatePullPointSubscriptionResponse></s:Body></s:Envelope>"#;
    let poll = |second| {
        format!(r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:e="http://www.onvif.org/ver10/events/wsdl"><s:Body><e:PullMessagesResponse><e:CurrentTime>2026-10-27T00:00:0{second}Z</e:CurrentTime><e:TerminationTime>2026-10-27T00:01:01Z</e:TerminationTime></e:PullMessagesResponse></s:Body></s:Envelope>"#).into_bytes()
    };
    let acquisition = PullPointAcquisition {
        approval: ContentDigest::sha256(b"native-owner-approval"),
        event_route: ContentDigest::sha256(b"native-event-route"),
        subscription_route: ContentDigest::sha256(b"native-subscription-route"),
        subscription_source: ContentDigest::sha256(subscription),
        subscription_source_bytes: subscription.len(),
        pull_index: 0,
        started_ns: 1000,
        completed_ns: 1010,
        client_authenticated: true,
        message_id: "urn:fss:onvif:pull-0".into(),
        subscription_message_id: "urn:fss:onvif:create-0".into(),
        subscription_started_ns: 900,
        subscription_completed_ns: 990,
    };
    let first = retain_pullpoint(
        &mut f.dep,
        binding("north")?,
        &poll(1),
        acquisition.clone(),
        subscription,
        &f.cx,
    )?;
    let future_source = poll(2);
    // Keep this distinct future response and its projection in ordinary file custody, so the
    // next refusal can only come from the deleted native subscription response.
    let future_file = retain_with_interpretation(
        &mut f.dep,
        binding("north")?,
        &future_source,
        Interpretation::EventsV1,
        &f.cx,
    )?;
    let plan = plan_deletion(&f.dep, first.identity(), &f.cx)?;
    assert_eq!(plan.imports, vec![first.identity()]);
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    assert!(
        plan.deleted_set()
            .contains(&acquisition.subscription_source)
    );
    assert!(!plan.deleted_set().contains(&future_file.source_digest()));
    assert!(
        !plan
            .deleted_set()
            .contains(&future_file.projection_digest())
    );
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
    let mut next = acquisition;
    next.pull_index = 1;
    next.message_id = "urn:fss:onvif:pull-1".into();
    next.started_ns = 1020;
    next.completed_ns = 1030;
    let head = f.dep.current_anchor().clone();
    let objects = f.dep.publisher().spool().object_count();
    assert_deleted(
        retain_pullpoint(
            &mut f.dep,
            binding("north")?,
            &future_source,
            next.clone(),
            subscription,
            &f.cx,
        ),
        None,
        digest,
    )?;
    assert_eq!(f.dep.current_anchor(), &head);
    assert_eq!(f.dep.publisher().spool().object_count(), objects);
    RetainedMetadata::open(&f.dep, future_file.identity(), None, &f.cx)?;
    commit_deletion(&mut f.dep, digest, approval, PRINCIPAL, &f.cx)?;
    assert_deleted(
        retain_pullpoint(
            &mut f.dep,
            binding("north")?,
            &future_source,
            next,
            subscription,
            &f.cx,
        ),
        None,
        digest,
    )?;
    Ok(())
}

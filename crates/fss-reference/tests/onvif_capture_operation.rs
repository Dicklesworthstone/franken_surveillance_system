#![forbid(unsafe_code)]
//! Stable owner capture identity, crash cuts and private-source deletion independence.
//! These local journal tests do not claim a sent request or live camera behavior.

use std::fs;
use std::path::PathBuf;

use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, EffectState, OperationId,
    RootAuthoritySpec, SensorId, TimestampNs,
};
use fss_reference::deletion::{commit_deletion, plan_deletion};
use fss_reference::onvif::capture_operation::{
    CaptureOperationBinding, CaptureOperationError, CaptureOperationGuard, EFFECT_CLASS,
    STAGE_COMMIT, STAGE_COMMITTED, STAGE_PREPARE, STAGE_PREPARED, inspect, operation_key, reserve,
};
use fss_reference::onvif::control::{
    CreateIntentBinding, RetainedSubscription, prepare_create, retain_created,
};
use fss_reference::onvif::http::HttpRoute;
use fss_reference::onvif::metadata::{MetadataError, SourceBinding};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:capture-operation-fixture";
const PRINCIPAL: &str = "operator:private-owner-operation-canary";
const OWNER_ID: &str = "operation:private-capture-id-canary";
const SOURCE: &[u8] = br#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:e="http://www.onvif.org/ver10/events/wsdl" xmlns:w="http://www.w3.org/2005/08/addressing" xmlns:n="http://docs.oasis-open.org/wsn/b-2"><s:Header><w:RelatesTo>urn:fss:onvif:create-operation-test</w:RelatesTo></s:Header><s:Body><e:CreatePullPointSubscriptionResponse><e:SubscriptionReference><w:Address>http://192.0.2.4/onvif/private-subscription-canary?Idx=7</w:Address></e:SubscriptionReference><n:CurrentTime>2026-10-27T00:00:00Z</n:CurrentTime><n:TerminationTime>2026-10-27T00:02:00Z</n:TerminationTime></e:CreatePullPointSubscriptionResponse></s:Body></s:Envelope>"#;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..64 {
            let path = std::env::temp_dir().join(format!(
                "fss-onvif-operation-{label}-{}-{attempt}",
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
    fn cx_for(&self, principal: &str) -> Test<ReplayCx> {
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:capture-operation-fixture".into(),
            operation_id: OperationId::parse("operation:fixture-context")?,
            principal: principal.into(),
            capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.into()],
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
        Ok(ReplayCx::from_context_authority(&authority, &self.0)?)
    }
    fn cx(&self) -> Test<ReplayCx> {
        self.cx_for(PRINCIPAL)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binding() -> Test<CaptureOperationBinding> {
    Ok(CaptureOperationBinding {
        operation_id: OperationId::parse(OWNER_ID)?,
        principal: PRINCIPAL.into(),
        request_digest: ContentDigest::sha256(b"canonical-effective-capture-request"),
        precondition_digest: ContentDigest::sha256(b"canonical-owner-sensor-device-profile-pins"),
    })
}
fn existing(
    result: Result<CaptureOperationGuard, CaptureOperationError>,
    state: EffectState,
) -> Test {
    match result {
        Err(CaptureOperationError::Existing(receipt)) => {
            assert_eq!(receipt.receipt.state, state);
            Ok(())
        }
        other => Err(format!("expected consumed operation, received {other:?}").into()),
    }
}

#[test]
fn same_owner_id_binds_one_key_and_conflicts_without_appending() -> Test {
    let dir = Directory::new("conflicts")?;
    let cx = dir.cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let base = binding()?;
    let guard = reserve(&mut dep, &base, TimestampNs(10), &cx)?;
    let original_root = dep.effects().last_root();
    assert_eq!(
        guard.prepared().internal_operation_id,
        operation_key(SITE, &base.operation_id)?
    );
    assert_ne!(
        operation_key(SITE, &base.operation_id)?,
        operation_key("site:other", &base.operation_id)?
    );
    existing(
        reserve(&mut dep, &base, TimestampNs(999), &cx),
        EffectState::Prepared,
    )?;
    for field in 0..3 {
        let mut changed = base.clone();
        match field {
            0 => {
                changed.request_digest = ContentDigest::sha256(b"changed-lifetime-or-auth-locator")
            }
            1 => changed.precondition_digest = ContentDigest::sha256(b"changed-owner-pins"),
            _ => changed.principal = "operator:another-admitted-owner".into(),
        }
        let current_cx = dir.cx_for(&changed.principal)?;
        assert!(matches!(
            reserve(&mut dep, &changed, TimestampNs(20), &current_cx),
            Err(CaptureOperationError::Conflict(_))
        ));
        assert_eq!(dep.effects().last_root(), original_root);
    }
    drop(guard);
    drop(dep);
    let cx = dir.cx()?;
    let mut cold = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
    existing(
        reserve(&mut cold, &base, TimestampNs(30), &cx),
        EffectState::Prepared,
    )?;
    assert_eq!(cold.effects().last_root(), original_root);
    Ok(())
}

#[test]
fn committed_and_restart_indeterminate_history_never_recreate_and_remain_source_free() -> Test {
    let dir = Directory::new("commit-cold")?;
    let cx = dir.cx()?;
    let base = binding()?;
    let committed_root = {
        let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let guard = reserve(&mut dep, &base, TimestampNs(10), &cx)?;
        let prepared_root = guard.prepared().journal_root;
        let committed = guard.commit(&mut dep, TimestampNs(20), &cx)?;
        assert_eq!(committed.receipt.state, EffectState::Committed);
        assert_eq!(committed.receipt.intent.effect_class, EFFECT_CLASS);
        assert_ne!(committed.receipt.authority.principal, PRINCIPAL);
        assert_ne!(committed.receipt.authority.principal, "system:operator");
        assert!(
            committed
                .receipt
                .authority
                .principal
                .starts_with("principal:onvif-capture:sha256:")
        );
        assert!(
            committed
                .receipt
                .authority
                .capability
                .starts_with("onvif:capture:")
        );
        assert_eq!(
            inspect(
                &dep,
                &base.operation_id,
                Some(&base),
                Some(prepared_root),
                &cx
            )?
            .receipt,
            committed.receipt
        );
        existing(
            reserve(&mut dep, &base, TimestampNs(30), &cx),
            EffectState::Committed,
        )?;
        let raw = fs::read(dep.effects().path())?;
        for private in [OWNER_ID, PRINCIPAL, SITE, "private-subscription-canary"] {
            assert!(
                !raw.windows(private.len())
                    .any(|bytes| bytes == private.as_bytes())
            );
        }
        committed.journal_root
    };
    let cx = dir.cx()?;
    let mut cold = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
    let observed = inspect(
        &cold,
        &base.operation_id,
        Some(&base),
        Some(committed_root),
        &cx,
    )?;
    assert_eq!(observed.receipt.state, EffectState::Indeterminate);
    existing(
        reserve(&mut cold, &base, TimestampNs(40), &cx),
        EffectState::Indeterminate,
    )?;
    Ok(())
}

#[test]
fn forged_owner_and_changed_commit_owner_refuse_before_mutation() -> Test {
    let dir = Directory::new("owner")?;
    let cx = dir.cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let mut forged = binding()?;
    forged.principal = "operator:forged-owner".into();
    let root = dep.effects().last_root();
    assert!(matches!(
        reserve(&mut dep, &forged, TimestampNs(10), &cx),
        Err(CaptureOperationError::Authority)
    ));
    assert_eq!(dep.effects().last_root(), root);
    assert_eq!(dep.effects().operations().count(), 0);
    let base = binding()?;
    let guard = reserve(&mut dep, &base, TimestampNs(10), &cx)?;
    let prepared_root = dep.effects().last_root();
    let wrong_owner = dir.cx_for("operator:other")?;
    assert!(matches!(
        guard.commit(&mut dep, TimestampNs(20), &wrong_owner),
        Err(CaptureOperationError::Authority)
    ));
    assert_eq!(dep.effects().last_root(), prepared_root);
    existing(
        reserve(&mut dep, &base, TimestampNs(30), &cx),
        EffectState::Prepared,
    )?;
    // Read authority is distinct from permission to label or dispatch another owner's effect.
    inspect(
        &dep,
        &base.operation_id,
        None,
        Some(prepared_root),
        &wrong_owner,
    )?;
    Ok(())
}

#[test]
fn cancellation_cuts_never_leak_a_guard_or_reopen_a_consumed_operation() -> Test {
    for stage in [STAGE_PREPARE, STAGE_PREPARED, STAGE_COMMIT, STAGE_COMMITTED] {
        let dir = Directory::new("cancel")?;
        let cx = dir.cx()?;
        let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let base = binding()?;
        if matches!(stage, STAGE_PREPARE | STAGE_PREPARED) {
            cx.set_cancel_at_checkpoint(stage);
            assert!(matches!(
                reserve(&mut dep, &base, TimestampNs(10), &cx),
                Err(CaptureOperationError::Authority)
            ));
        } else {
            let guard = reserve(&mut dep, &base, TimestampNs(10), &cx)?;
            cx.set_cancel_at_checkpoint(stage);
            assert!(matches!(
                guard.commit(&mut dep, TimestampNs(20), &cx),
                Err(CaptureOperationError::Authority)
            ));
        }
        let fresh = dir.cx()?;
        if stage == STAGE_PREPARE {
            assert_eq!(dep.effects().operations().count(), 0);
            let guard = reserve(&mut dep, &base, TimestampNs(30), &fresh)?;
            drop(guard);
        } else {
            let expected = if stage == STAGE_COMMITTED {
                EffectState::Committed
            } else {
                EffectState::Prepared
            };
            existing(reserve(&mut dep, &base, TimestampNs(30), &fresh), expected)?;
            assert_eq!(
                inspect(&dep, &base.operation_id, Some(&base), None, &fresh)?
                    .receipt
                    .state,
                expected
            );
        }
    }
    Ok(())
}

#[test]
fn a_live_guard_cannot_commit_a_copied_store_or_changed_prepared_receipt() -> Test {
    let first = Directory::new("pin-a")?;
    let second = Directory::new("pin-b")?;
    let first_cx = first.cx()?;
    let second_cx = second.cx()?;
    let mut a = ReferenceDeployment::open(&first.0, SITE, &first_cx)?;
    let mut b = ReferenceDeployment::open(&second.0, SITE, &second_cx)?;
    let base = binding()?;
    let first_guard = reserve(&mut a, &base, TimestampNs(10), &first_cx)?;
    let second_guard = reserve(&mut b, &base, TimestampNs(10), &second_cx)?;
    let before = b.effects().last_root();
    assert!(matches!(
        first_guard.commit(&mut b, TimestampNs(20), &second_cx),
        Err(CaptureOperationError::Authority)
    ));
    assert_eq!(b.effects().last_root(), before);
    let key = operation_key(SITE, &base.operation_id)?;
    b.effects_mut()
        .transition(&key, EffectState::Committed, TimestampNs(20), None, None)?;
    let changed = b.effects().last_root();
    assert!(matches!(
        second_guard.commit(&mut b, TimestampNs(30), &second_cx),
        Err(CaptureOperationError::Custody)
    ));
    assert_eq!(b.effects().last_root(), changed);
    existing(
        reserve(&mut a, &base, TimestampNs(30), &first_cx),
        EffectState::Prepared,
    )?;
    Ok(())
}

#[test]
fn independent_minimum_detects_a_valid_older_prefix_and_still_refuses_prepared_retry() -> Test {
    let dir = Directory::new("minimum")?;
    let base = binding()?;
    let (older, committed_root) = {
        let cx = dir.cx()?;
        let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let guard = reserve(&mut dep, &base, TimestampNs(10), &cx)?;
        let older = fs::read(dep.effects().path())?;
        let committed = guard.commit(&mut dep, TimestampNs(20), &cx)?;
        assert!(matches!(
            inspect(
                &dep,
                &base.operation_id,
                None,
                Some(ContentDigest::sha256(b"not-in-history")),
                &cx
            ),
            Err(CaptureOperationError::Minimum)
        ));
        (older, committed.journal_root)
    };
    // Fixture-owned valid rollback: an independent later pin is needed to expose it.
    fs::write(dir.0.join("effects/journal.fssj"), older)?;
    let cx = dir.cx()?;
    let mut cold = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
    assert!(matches!(
        inspect(
            &cold,
            &base.operation_id,
            Some(&base),
            Some(committed_root),
            &cx
        ),
        Err(CaptureOperationError::Minimum)
    ));
    existing(
        reserve(&mut cold, &base, TimestampNs(30), &cx),
        EffectState::Prepared,
    )?;
    Ok(())
}

#[test]
fn onvif_source_deletion_cannot_erase_the_stable_capture_fence() -> Test {
    let dir = Directory::new("source-deletion")?;
    let cx = dir.cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let base = binding()?;
    let guard = reserve(&mut dep, &base, TimestampNs(10), &cx)?;
    let create = prepare_create(
        &mut dep,
        CreateIntentBinding {
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
            message_id: "urn:fss:onvif:create-operation-test".into(),
            started_ns: 1_000,
            lifetime_seconds: 120,
        },
        &cx,
    )?;
    let committed = guard.commit(&mut dep, TimestampNs(20), &cx)?;
    let created = retain_created(&mut dep, &create, 1_010, false, SOURCE, &cx)?;
    let plan = plan_deletion(&dep, create.identity(), &cx)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    assert!(plan.deleted_set().contains(&created.source_digest()));
    let digest = plan.digest()?;
    let approval = plan.approval_digest(PRINCIPAL)?;
    commit_deletion(&mut dep, digest, approval, PRINCIPAL, &cx)?;
    assert!(matches!(
        RetainedSubscription::open(&dep, created.identity(), None, &cx),
        Err(MetadataError::EvidenceDeleted { .. })
    ));
    let after = inspect(
        &dep,
        &base.operation_id,
        Some(&base),
        Some(committed.journal_root),
        &cx,
    )?;
    assert_eq!(after.receipt, committed.receipt);
    existing(
        reserve(&mut dep, &base, TimestampNs(30), &cx),
        EffectState::Committed,
    )?;
    drop(dep);
    let cx = dir.cx()?;
    let mut cold = ReferenceDeployment::reopen(&dir.0, SITE, &cx)?;
    inspect(
        &cold,
        &base.operation_id,
        Some(&base),
        Some(committed.journal_root),
        &cx,
    )?;
    existing(
        reserve(&mut cold, &base, TimestampNs(40), &cx),
        EffectState::Indeterminate,
    )?;
    Ok(())
}

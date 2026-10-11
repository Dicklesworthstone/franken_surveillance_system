#![forbid(unsafe_code)]
//! Actual prepared-alert snapshots remain historical evidence, never a new dispatch lease.

use super::*;
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::alert_control::{
    AlertControlError, CAP_ALERT_CANCEL, cancel_prepared_alert, preview_alert_cancellation,
};
use crate::deployment_backup::{
    BACKUP_PAYLOAD_DIRECTORY, BackupAccess, BackupAuthority, BackupLimits, FAMILY_RESTORE_FENCE,
    RESTORE_FENCE_OBJECT_ID, RESTORE_INCOMPLETE_FILENAME, RestoreFence, create_backup,
    prepare_backup, restore_backup,
};
use crate::webhook::{
    WebhookAttempt, WebhookAuthority, WebhookBoundary, WebhookDenial, WebhookEndpoint,
    WebhookError, WebhookLimits, WebhookScope,
};
use crate::{
    AlertDispatchTimes, ReferenceAlertProvider, dispatch_reference_alert,
    rehydrate_reference_alert_plan,
};
use fss_core::{BatchId, EvidenceDelta, ObjectId, Plane};

struct Grant<'a> {
    source: &'a Path,
    bundle: &'a Path,
    destination: &'a Path,
}
impl BackupAuthority for Grant<'_> {
    fn permit(&self, access: BackupAccess<'_>) -> bool {
        match access {
            BackupAccess::ReadDeployment { source } => source == self.source,
            BackupAccess::WriteBundle { source, bundle, .. } => {
                source == self.source && bundle == self.bundle
            }
            BackupAccess::ReadBundle { bundle, .. } => bundle == self.bundle,
            BackupAccess::RestoreDeployment {
                bundle,
                destination,
                ..
            } => bundle == self.bundle && destination == self.destination,
        }
    }
}
struct Trees {
    source: PathBuf,
    bundle: PathBuf,
    destination: PathBuf,
}
impl Drop for Trees {
    fn drop(&mut self) {
        for path in [&self.source, &self.bundle, &self.destination] {
            let _ = fs::remove_dir_all(path);
        }
    }
}
struct Restored {
    // Drop all held deployment locks before cleaning the trees.
    fixture: Prepared,
    trees: Trees,
    fence: ContentDigest,
}
fn restored(tag: &str, channel: &str) -> Result<Restored, Box<dyn Error>> {
    let Prepared {
        root,
        dep,
        decision,
        event_receipt,
        plan,
    } = prepared_for_channel(tag, channel)?;
    let limits = *dep.limits();
    let anchor = dep.current_anchor().clone();
    let effect_bytes = fs::read(root.join("effects/journal.fssj"))?;
    drop(dep);
    let trees = Trees {
        source: root,
        bundle: fresh_root(&format!("{tag}-bundle"))?,
        destination: fresh_root(&format!("{tag}-restored"))?,
    };
    let grant = Grant {
        source: &trees.source,
        bundle: &trees.bundle,
        destination: &trees.destination,
    };
    let cx = test_cx(&format!("{tag}-backup"))?;
    let manifest = prepare_backup(&trees.source, limits, BackupLimits::default(), &grant, &cx)?;
    create_backup(
        &trees.source,
        &trees.bundle,
        manifest.digest(),
        limits,
        BackupLimits::default(),
        &grant,
        &cx,
    )?;
    // The captured Prepared operation genuinely becomes dispatched on the ORIGINAL afterward.
    // Therefore cancelling/replaying the copied Prepared state would assert something false.
    let mut original = ReferenceDeployment::open(&trees.source, SITE, &cx)?;
    let sent = original.dispatch_alert(
        &plan,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(T_COMMIT),
        TimestampNs(T_OUTCOME),
        &cx,
    )?;
    assert_eq!(sent.state, EffectState::AdapterAccepted);
    assert_eq!(provider_effects(&original), 1);
    drop(original);
    let receipt = restore_backup(
        &trees.bundle,
        &trees.destination,
        manifest.digest(),
        BackupLimits::default(),
        &grant,
        &cx,
    )?;
    assert_eq!(receipt.manifest().source_anchor(), &anchor);
    assert_eq!(
        receipt.destination_anchor().commit_sequence,
        anchor.commit_sequence + 1
    );
    assert_eq!(
        fs::read(trees.destination.join("effects/journal.fssj"))?,
        effect_bytes
    );
    let dep = ReferenceDeployment::open(&trees.destination, SITE, &cx)?;
    let fence = receipt.fence_digest();
    let retained = dep.publisher().spool().read(fence)?;
    let retained = RestoreFence::from_bytes(&retained, fence)?;
    assert_eq!(retained.source_manifest(), manifest.digest());
    assert_eq!(retained.source_anchor(), &anchor);
    assert_eq!(state_of(&dep, &plan), Some(EffectState::Prepared));
    assert_eq!(obligation_of(&dep, &plan), Some(ObligationState::Pending));
    cx.drain_and_finalize();
    Ok(Restored {
        fixture: Prepared {
            root: trees.destination.clone(),
            dep,
            decision,
            event_receipt,
            plan,
        },
        trees,
        fence,
    })
}
fn assert_fenced<T: std::fmt::Debug>(result: Result<T, ReferenceError>, fence: ContentDigest) {
    assert!(
        matches!(result, Err(ReferenceError::RestoredDeploymentEffectsFenced { restore_record }) if restore_record == fence),
        "{result:?}"
    );
}
fn journal_bytes(f: &Prepared) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    Ok((
        fs::read(f.root.join("ledger/journal.fssj"))?,
        fs::read(f.root.join("effects/journal.fssj"))?,
    ))
}
fn assert_pending(f: &Prepared) {
    assert_eq!(state_of(&f.dep, &f.plan), Some(EffectState::Prepared));
    assert_eq!(
        obligation_of(&f.dep, &f.plan),
        Some(ObligationState::Pending)
    );
    assert_eq!(provider_effects(&f.dep), 0);
}

#[test]
fn restored_prepared_alert_and_rehydrated_plan_refuse_all_dispatch_owners() -> TestResult {
    let mut r = restored("backup-dispatch", "simulated-channel")?;
    let f = &mut r.fixture;
    let before = journal_bytes(f)?;
    let operation = f
        .dep
        .effects()
        .operation(&f.plan.intent.operation_id)
        .ok_or("missing operation")?;
    let plan = rehydrate_reference_alert_plan(
        operation,
        f.plan.obligation_id.clone(),
        &f.decision.event,
        &f.event_receipt,
        f.dep.ledger(),
        &f.plan.channel,
    )?;
    assert_eq!(plan.intent, f.plan.intent);
    let cx = test_cx("backup-dispatch-refuse")?;
    assert_fenced(
        f.dep.dispatch_alert(
            &plan,
            ReferenceProviderBehavior::Deliver,
            TimestampNs(T_COMMIT),
            TimestampNs(T_OUTCOME),
            &cx,
        ),
        r.fence,
    );
    let objects = InMemoryObjectStore::new(ObjectLimits::new(1, 1));
    let mut provider = ReferenceAlertProvider::new("provider:backup-memory");
    let mut memory = f.dep.effects().effect_journal().clone();
    let memory_before = memory.clone();
    assert_fenced(
        dispatch_reference_alert(
            &plan,
            f.dep.ledger(),
            &objects,
            ReferenceProviderBehavior::Deliver,
            AlertDispatchTimes::new(TimestampNs(T_COMMIT), TimestampNs(T_OUTCOME)),
            &mut memory,
            &mut provider,
        ),
        r.fence,
    );
    assert_eq!(memory, memory_before);
    let (effects, ledger) = f.dep.effects_and_ledger();
    let result = effects.dispatch_alert(
        &plan,
        ledger,
        &objects,
        ReferenceProviderBehavior::Deliver,
        AlertDispatchTimes::new(TimestampNs(T_COMMIT), TimestampNs(T_OUTCOME)),
        &mut provider,
    );
    assert!(
        matches!(result, Err(DurableEffectError::Reference(ReferenceError::RestoredDeploymentEffectsFenced { restore_record })) if restore_record == r.fence),
        "{result:?}"
    );
    assert_eq!(provider.message_count() + provider.failure_count(), 0);
    assert_eq!(journal_bytes(f)?, before);
    assert_pending(f);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn restored_deployment_refuses_new_preparation_without_changing_pending_work() -> TestResult {
    let mut r = restored("backup-prepare", "simulated-channel")?;
    let f = &mut r.fixture;
    let before = journal_bytes(f)?;
    let (effects, ledger) = f.dep.effects_and_ledger();
    let result = effects.prepare_alert(PrepareAlertParams {
        decision: &f.decision,
        event_receipt: &f.event_receipt,
        authority: ledger,
        operation_id: OperationId::parse("operation:backup:new-alert")?,
        idempotency_key: IdempotencyKey::parse("idempotency:backup:new-alert")?,
        obligation_id: ObligationId::parse("obligation:backup:new-alert")?,
        channel: f.plan.channel.clone(),
        now: TimestampNs(T_OUTCOME + 1),
    });
    assert!(
        matches!(result, Err(DurableEffectError::Reference(ReferenceError::RestoredDeploymentEffectsFenced { restore_record })) if restore_record == r.fence),
        "{result:?}"
    );
    assert_eq!(journal_bytes(f)?, before);
    assert_pending(f);
    Ok(())
}

#[test]
fn cancellation_cannot_claim_that_a_restored_preparation_was_never_sent() -> TestResult {
    let mut r = restored("backup-cancel", "simulated-channel")?;
    let f = &mut r.fixture;
    let before = journal_bytes(f)?;
    let cancelled = test_cx("backup-cancel-stop")?;
    cancelled.request_cancellation();
    assert_fenced(
        f.dep.dispatch_alert(
            &f.plan,
            ReferenceProviderBehavior::Deliver,
            TimestampNs(T_COMMIT),
            TimestampNs(T_OUTCOME),
            &cancelled,
        ),
        r.fence,
    );
    assert!(cancelled.is_drain_completed());
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:backup-cancel".into(),
        operation_id: OperationId::parse("operation:backup-cancel")?,
        principal: "operator:backup-cancel".into(),
        capabilities: vec![ADP_REPLAY_ROW_ID.into(), CAP_ALERT_CANCEL.into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".into(),
        retention_scope: "retention:ephemeral".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, &f.root)?;
    let preview = preview_alert_cancellation(&f.dep, &f.plan.intent.operation_id, &authority, &cx);
    assert!(
        matches!(preview, Err(AlertControlError::Deployment(ReferenceError::RestoredDeploymentEffectsFenced { restore_record })) if restore_record == r.fence),
        "{preview:?}"
    );
    let cancelled = cancel_prepared_alert(
        &mut f.dep,
        &f.plan.intent.operation_id,
        ContentDigest::sha256(b"not-a-new-grant"),
        TimestampNs(T_OUTCOME + 1),
        &authority,
        &cx,
    );
    assert!(
        matches!(cancelled, Err(AlertControlError::Deployment(ReferenceError::RestoredDeploymentEffectsFenced { restore_record })) if restore_record == r.fence),
        "{cancelled:?}"
    );
    assert_eq!(journal_bytes(f)?, before);
    assert_pending(f);
    cx.drain_and_finalize();
    Ok(())
}

struct WebhookOwner {
    operation: OperationId,
    path: PathBuf,
    route: ContentDigest,
    calls: AtomicUsize,
}
impl WebhookAuthority for WebhookOwner {
    fn checkpoint(
        &self,
        scope: WebhookScope<'_>,
        boundary: WebhookBoundary,
        now: u64,
        deadline: u64,
    ) -> Result<(), WebhookDenial> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if scope.operation.intent.operation_id != self.operation
            || scope.effect_journal != self.path
            || scope.endpoint.digest() != self.route
            || now >= deadline
            || boundary != WebhookBoundary::Commit
        {
            return Err(WebhookDenial::Unauthorized);
        }
        Ok(())
    }
}
#[test]
fn restored_webhook_refuses_before_commit_connection_or_false_cancellation() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let endpoint = WebhookEndpoint::new(
        listener.local_addr()?,
        "/notify",
        ContentDigest::sha256(b"explicit-loopback-test-only-plaintext"),
    )?;
    let mut r = restored("backup-webhook", endpoint.channel())?;
    let f = &mut r.fixture;
    let before = journal_bytes(f)?;
    let owner = WebhookOwner {
        operation: f.plan.intent.operation_id.clone(),
        path: f.dep.effects().path().to_path_buf(),
        route: endpoint.digest(),
        calls: AtomicUsize::new(0),
    };
    {
        let (effects, ledger, publisher) = f.dep.effect_dispatch_parts();
        let result = WebhookAttempt::begin(
            &f.plan,
            &endpoint,
            ledger,
            effects,
            WebhookLimits {
                io_calls: 8,
                io_bytes: 4096,
                response_bytes: 1024,
                connect_timeout_ns: 1_000_000,
            },
            T_COMMIT as u64,
            T_COMMIT as u64 + 1_000_000_000,
            &owner,
            |digest| {
                publisher
                    .spool()
                    .read(digest)
                    .map_err(fss_publication::LocalPublicationError::Spool)
            },
        );
        assert!(
            matches!(result, Err(WebhookError::Authority(ReferenceError::RestoredDeploymentEffectsFenced { restore_record })) if restore_record == r.fence)
        );
    }
    assert_eq!(owner.calls.load(Ordering::SeqCst), 1);
    assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    assert_eq!(journal_bytes(f)?, before);
    assert_pending(f);
    Ok(())
}

#[test]
fn generic_authority_append_cannot_shadow_or_remove_the_restore_fence() -> TestResult {
    let mut r = restored("backup-shadow", "simulated-channel")?;
    let f = &mut r.fixture;
    let cx = test_cx("backup-shadow-append")?;
    let payload = f.dep.stage_payload(b"unrelated valid payload")?;
    let fence_id = ObjectId::parse(RESTORE_FENCE_OBJECT_ID)?;
    let prior = f
        .dep
        .ledger()
        .current()
        .objects
        .get(&fence_id)
        .ok_or("missing fence")?
        .generation;
    let before = journal_bytes(f)?;
    for (id, family, prior_generation) in [
        (fence_id, "sensor_capsule", Some(prior)),
        (
            ObjectId::parse("object:backup:forged-fence")?,
            FAMILY_RESTORE_FENCE,
            None,
        ),
    ] {
        let delta = EvidenceDelta {
            delta_id: format!("delta:backup-shadow:{family}"),
            family: family.into(),
            object_id: id,
            prior_generation,
            new_generation: prior_generation.unwrap_or(0) + 1,
            validity: CaptureInterval::new(TimestampNs(0), TimestampNs(0))?,
            plane: Plane::Authority,
            payload_digest: payload,
            witness_digest: None,
            operation_id: None,
        };
        let result = f.dep.append_batch(
            BatchId::parse(format!("batch:backup-shadow:{family}"))?,
            vec![delta],
            vec![payload],
            &cx,
        );
        assert!(
            matches!(result, Err(ReferenceError::ReservedDeltaFamily { .. })),
            "{result:?}"
        );
    }
    assert_eq!(journal_bytes(f)?, before);
    let delta = EvidenceDelta {
        delta_id: "delta:backup:unrelated".into(),
        family: "sensor_capsule".into(),
        object_id: ObjectId::parse("object:backup:unrelated")?,
        prior_generation: None,
        new_generation: 1,
        validity: CaptureInterval::new(TimestampNs(0), TimestampNs(0))?,
        plane: Plane::Authority,
        payload_digest: payload,
        witness_digest: None,
        operation_id: None,
    };
    f.dep.append_batch(
        BatchId::parse("batch:backup:unrelated")?,
        vec![delta],
        vec![payload],
        &cx,
    )?;
    assert_fenced(
        f.dep.dispatch_alert(
            &f.plan,
            ReferenceProviderBehavior::Deliver,
            TimestampNs(T_COMMIT),
            TimestampNs(T_OUTCOME),
            &cx,
        ),
        r.fence,
    );
    assert_pending(f);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn inert_bundle_refuses_open_and_repair_without_journal_changes() -> TestResult {
    let r = restored("backup-inert", "simulated-channel")?;
    let payload = r.trees.bundle.join(BACKUP_PAYLOAD_DIRECTORY);
    let before = fs::read(payload.join("effects/journal.fssj"))?;
    let cx = test_cx("backup-inert-open")?;
    assert!(payload.join(RESTORE_INCOMPLETE_FILENAME).is_file());
    assert!(matches!(
        ReferenceDeployment::open(&payload, SITE, &cx),
        Err(ReferenceError::NotADeployment { .. })
    ));
    let result = ReferenceDeployment::open_for_recovery(
        &payload,
        crate::reference_deployment::RecoveryAction::TruncateIncompleteEffectTail,
        &cx,
    );
    assert!(
        matches!(result, Err(ReferenceError::NotADeployment { .. })),
        "{result:?}"
    );
    assert_eq!(fs::read(payload.join("effects/journal.fssj"))?, before);
    assert!(!payload.join("objects/LOCK").exists());
    cx.drain_and_finalize();
    Ok(())
}

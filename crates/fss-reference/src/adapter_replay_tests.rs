#![forbid(unsafe_code)]
//! Crate-internal unit tests for ReplayAdapter checkpoint cancellation.
//!
//! Validates:
//! - Pre-commit cancellation via `run_replay` checkpoint leaves target stores untouched
//! - Post-commit cancellation via `compute_audit` checkpoint returns CancelledAfterCommit
//! - All execution checkpoints (`preflight`, `run_replay`, `compute_audit`) are honoured (R6b)
//! - All verification checkpoints (`staging_execute`, `publish_on_match`, `post_publish`) are honoured

use std::error::Error;
use std::path::PathBuf;

use fss_core::{
    BudgetVector, CapsuleId, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
    SensorId,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};

use crate::{
    ADP_REPLAY_GOLDEN_AUDIT_HASH, ADP_REPLAY_GOLDEN_STATE_ROOT, ADP_REPLAY_ROW_ID,
    DeliveryDirective, DeliveryPlan, ReplayAdapter, ReplayAdapterError, ReplayBundle, ReplayCx,
    ReplayExecutionRequest, ReplayIoAuthority, ReplayTerminalStatus, ScopedLedgerDir,
    VirtualCameraSpec,
};

fn test_context_authority(label: &str) -> Result<ContextAuthority, Box<dyn Error>> {
    let spec = RootAuthoritySpec {
        trace_id: format!("trace:unit-test-{label}"),
        operation_id: OperationId::parse(format!("operation:unit-test-{label}"))?,
        principal: format!("operator:unit-test-{label}"),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"test-anchor-universe"),
        generation: 1,
    };
    Ok(ContextAuthority::new_root(spec)?)
}

fn test_cx(label: &str) -> Result<ReplayCx, Box<dyn Error>> {
    let root_auth = test_context_authority(label)?;
    let scratch_root = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(format!("test-replay-cx-unit-{label}"));
    let io = ReplayIoAuthority::from_context_authority(&root_auth, scratch_root)?;
    Ok(ReplayCx::new(io))
}

fn sample_bundle() -> Result<ReplayBundle, Box<dyn Error>> {
    let spec = VirtualCameraSpec {
        capture_id: CapsuleId::parse("capture:replay:contract:1")?,
        sensor_id: SensorId::parse("sensor:replay-lane")?,
        seed: 0xfeed_face_cafe_beef,
        packet_count: 6,
        packet_bytes: 64,
        start_ns: 10_000,
        period_ns: 1_000_000,
        uncertainty_ns: 5_000,
    };
    let plan = DeliveryPlan::new(vec![
        DeliveryDirective::exact(1),
        DeliveryDirective::exact(2),
        DeliveryDirective::corrupt(3),
        DeliveryDirective::exact(4),
        DeliveryDirective::exact(5),
        DeliveryDirective::exact(6),
    ])?;
    Ok(ReplayBundle::new("site:replay-contract", spec, plan)?)
}

#[test]
fn test_checkpoint_cancellation_pre_and_post_commit() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;
    let bundle = sample_bundle()?;

    // 1. Cancel injected BEFORE commit (at run_replay checkpoint):
    // returns Err(CancellationRequested) and leaves target stores untouched (0 objects, unchanged ledger).
    let cx_pre = test_cx("cancel_pre")?;
    cx_pre.set_cancel_at_checkpoint("run_replay");
    let dir_pre = ScopedLedgerDir::new("cancel_pre_commit", &cx_pre)?;
    let mut obj_pre = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led_pre = DurableReferenceLedger::open(
        dir_pre.journal_path("cancel_pre_commit"),
        bundle.site_lineage(),
        IncompleteTailPolicy::Reject,
    )?;
    let initial_anchor_pre = led_pre.current().anchor.clone();
    let req_pre = ReplayExecutionRequest::new(bundle.clone());

    match adapter.execute(&cx_pre, &req_pre, &mut obj_pre, &mut led_pre) {
        Err(ReplayAdapterError::CancellationRequested) => {}
        other => return Err(format!("expected CancellationRequested, got {other:?}").into()),
    }
    assert_eq!(
        obj_pre.object_count(),
        0,
        "No objects committed on pre-commit cancellation"
    );
    assert_eq!(
        led_pre.current().anchor,
        initial_anchor_pre,
        "Ledger unchanged on pre-commit cancellation"
    );

    // 2. Cancel injected AFTER commit (at compute_audit checkpoint):
    // returns Ok(...) with status CancelledAfterCommit.
    // Never report cancelled while the effect stands.
    let cx_post_cancel = test_cx("cancel_post_cancel")?;
    cx_post_cancel.set_cancel_at_checkpoint("compute_audit");
    let dir_post_cancel = ScopedLedgerDir::new("cancel_post_audit", &cx_post_cancel)?;
    let mut obj_post_cancel = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led_post_cancel = DurableReferenceLedger::open(
        dir_post_cancel.journal_path("cancel_post_audit"),
        bundle.site_lineage(),
        IncompleteTailPolicy::Reject,
    )?;
    let req_post_cancel = ReplayExecutionRequest::new(bundle);

    let out_post = adapter.execute(
        &cx_post_cancel,
        &req_post_cancel,
        &mut obj_post_cancel,
        &mut led_post_cancel,
    )?;
    assert_eq!(out_post.status, ReplayTerminalStatus::CancelledAfterCommit);
    assert!(obj_post_cancel.object_count() > 0);
    assert!(cx_post_cancel.is_cancelled());

    Ok(())
}

#[test]
fn test_all_execute_checkpoints_honoured_r6b() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;
    let bundle = sample_bundle()?;

    // Test checkpoint 1: "preflight"
    let cx1 = test_cx("ckpt1")?;
    cx1.set_cancel_at_checkpoint("preflight");
    let dir1 = ScopedLedgerDir::new("ckpt1", &cx1)?;
    let mut obj1 = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led1 = DurableReferenceLedger::open(
        dir1.journal_path("ckpt1"),
        bundle.site_lineage(),
        IncompleteTailPolicy::Reject,
    )?;
    let req1 = ReplayExecutionRequest::new(bundle.clone());
    match adapter.execute(&cx1, &req1, &mut obj1, &mut led1) {
        Err(ReplayAdapterError::CancellationRequested) => {
            assert_eq!(cx1.checkpoints_reached(), 1);
            assert_eq!(obj1.object_count(), 0);
        }
        other => {
            return Err(
                format!("expected CancellationRequested at preflight, got {other:?}").into(),
            );
        }
    }

    // Test checkpoint 2: "run_replay" (pre-commit)
    let cx2 = test_cx("ckpt2")?;
    cx2.set_cancel_at_checkpoint("run_replay");
    let dir2 = ScopedLedgerDir::new("ckpt2", &cx2)?;
    let mut obj2 = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led2 = DurableReferenceLedger::open(
        dir2.journal_path("ckpt2"),
        bundle.site_lineage(),
        IncompleteTailPolicy::Reject,
    )?;
    let req2 = ReplayExecutionRequest::new(bundle.clone());
    match adapter.execute(&cx2, &req2, &mut obj2, &mut led2) {
        Err(ReplayAdapterError::CancellationRequested) => {
            assert_eq!(cx2.checkpoints_reached(), 2);
            assert_eq!(obj2.object_count(), 0);
        }
        other => {
            return Err(
                format!("expected CancellationRequested at run_replay, got {other:?}").into(),
            );
        }
    }

    // Test checkpoint 3: "compute_audit" (post-commit)
    let cx3 = test_cx("ckpt3")?;
    cx3.set_cancel_at_checkpoint("compute_audit");
    let dir3 = ScopedLedgerDir::new("ckpt3", &cx3)?;
    let mut obj3 = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led3 = DurableReferenceLedger::open(
        dir3.journal_path("ckpt3"),
        bundle.site_lineage(),
        IncompleteTailPolicy::Reject,
    )?;
    let req3 = ReplayExecutionRequest::new(bundle);
    let out3 = adapter.execute(&cx3, &req3, &mut obj3, &mut led3)?;
    assert_eq!(cx3.checkpoints_reached(), 3);
    assert_eq!(out3.status, ReplayTerminalStatus::CancelledAfterCommit);
    assert!(obj3.object_count() > 0);
    assert!(cx3.is_cancelled());

    Ok(())
}

#[test]
fn test_verify_cancel_injection_checkpoints() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;
    let bundle = sample_bundle()?;
    let golden_root = ContentDigest::parse(ADP_REPLAY_GOLDEN_STATE_ROOT)?;
    let golden_audit = ContentDigest::parse(ADP_REPLAY_GOLDEN_AUDIT_HASH)?;

    // 1. Checkpoint "staging_execute": cancel injected during isolated staging
    let cx1 = test_cx("verify_ckpt1")?;
    cx1.set_cancel_at_checkpoint("staging_execute");
    let dir1 = ScopedLedgerDir::new("verify_ckpt1", &cx1)?;
    let mut obj1 = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led1 = DurableReferenceLedger::open(
        dir1.journal_path("verify_ckpt1"),
        bundle.site_lineage(),
        IncompleteTailPolicy::Reject,
    )?;
    let req1 = ReplayExecutionRequest::new(bundle.clone());
    match adapter.verify_against_expected(
        &cx1,
        &req1,
        &mut obj1,
        &mut led1,
        &golden_root,
        &golden_audit,
    ) {
        Err(ReplayAdapterError::CancellationRequested) => {
            assert_eq!(obj1.object_count(), 0);
            assert!(cx1.is_cancelled());
        }
        other => {
            return Err(format!(
                "expected CancellationRequested at staging_execute, got {other:?}"
            )
            .into());
        }
    }

    // 2. Checkpoint "publish_on_match": cancel injected after match verified, before target commit
    let cx2 = test_cx("verify_ckpt2")?;
    cx2.set_cancel_at_checkpoint("publish_on_match");
    let dir2 = ScopedLedgerDir::new("verify_ckpt2", &cx2)?;
    let mut obj2 = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led2 = DurableReferenceLedger::open(
        dir2.journal_path("verify_ckpt2"),
        bundle.site_lineage(),
        IncompleteTailPolicy::Reject,
    )?;
    let req2 = ReplayExecutionRequest::new(bundle.clone());
    match adapter.verify_against_expected(
        &cx2,
        &req2,
        &mut obj2,
        &mut led2,
        &golden_root,
        &golden_audit,
    ) {
        Err(ReplayAdapterError::CancellationRequested) => {
            assert_eq!(obj2.object_count(), 0);
            assert!(cx2.is_cancelled());
        }
        other => {
            return Err(format!(
                "expected CancellationRequested at publish_on_match, got {other:?}"
            )
            .into());
        }
    }

    // 3. Checkpoint "post_publish": cancel injected after target commit
    let cx3 = test_cx("verify_ckpt3")?;
    cx3.set_cancel_at_checkpoint("post_publish");
    let dir3 = ScopedLedgerDir::new("verify_ckpt3", &cx3)?;
    let mut obj3 = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led3 = DurableReferenceLedger::open(
        dir3.journal_path("verify_ckpt3"),
        bundle.site_lineage(),
        IncompleteTailPolicy::Reject,
    )?;
    let req3 = ReplayExecutionRequest::new(bundle);
    let out3 = adapter.verify_against_expected(
        &cx3,
        &req3,
        &mut obj3,
        &mut led3,
        &golden_root,
        &golden_audit,
    )?;
    assert_eq!(out3.status, ReplayTerminalStatus::CancelledAfterCommit);
    assert!(obj3.object_count() > 0);
    assert!(cx3.is_cancelled());

    Ok(())
}

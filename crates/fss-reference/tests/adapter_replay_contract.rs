#![forbid(unsafe_code)]
//! Contract tests for ADP-REPLAY-001 deterministic replay adapter.
//!
//! Enforces:
//! 1. Row identity and typed protocol contract (ADP-REPLAY-001, T0, GATE-010, pure Rust)
//! 2. Consistency between code constants and `architecture/device_adapters.json`
//! 3. Deterministic replay produces identical state roots and audit hashes matching golden constants
//! 4. Fail-closed divergence detection leaves target object store and ledger pristine
//! 5. Audit hash covers bundle digest, generation, and row ID
//! 6. Incompatible generation rejection in both execute and verify_against_expected (N1)
//! 7. Cooperative cancellation handling via ReplayCx with request->drain->finalize in both execute and verify (N1, N3)
//! 8. Packet budget enforcement (including exact budget == count) in both execute and verify (N1)
//! 9. Hard bounds enforcement (packet count, packet bytes, aggregate bytes, zero-bound rejection) (N1, mutants R2, R3, R6b, R6f, R7c)
//! 10. Fail-closed target publish rollback on partial failure preventing orphan staged objects (N2)
//! 11. Unforgeable ReplayIoAuthority and ReplayCx lifecycle state transitions (N3)
//! 12. Independent state root and audit hash divergence detection (mutants R8a, R10)
//! 13. Zero unwrap, expect, or panic anywhere in test suite

use std::error::Error;

use fss_core::{
    AdapterCapabilities, AdapterKind, BudgetVector, CapsuleId, ContentDigest, ContextAuthority,
    CredentialMethod, IsolationMode, OperationId, RootAuthoritySpec, SensorId,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};
use fss_reference::{
    ADP_REPLAY_CURRENT_STATE, ADP_REPLAY_GENERATION, ADP_REPLAY_GOLDEN_AUDIT_HASH,
    ADP_REPLAY_GOLDEN_STATE_ROOT, ADP_REPLAY_MAX_PACKET_BYTES, ADP_REPLAY_MAX_PACKETS,
    ADP_REPLAY_MAX_TOTAL_BYTES, ADP_REPLAY_PROMOTION_GATE, ADP_REPLAY_PROTOCOL_PROFILE,
    ADP_REPLAY_ROW_ID, ADP_REPLAY_SURFACE, ADP_REPLAY_TIER, DeliveryDirective, DeliveryPlan,
    ERR_ADAPTER_REPLAY_DIVERGED, ReplayAdapter, ReplayAdapterConfig, ReplayAdapterError,
    ReplayBundle, ReplayCx, ReplayExecutionRequest, ReplayIoAuthority, ReplayLifecycleState,
    ScopedLedgerDir, VirtualCameraSpec,
};

fn test_cx() -> Result<ReplayCx, Box<dyn Error>> {
    let auth = ReplayIoAuthority::authorize("operator:contract-test", ADP_REPLAY_ROW_ID)?;
    Ok(ReplayCx::new(auth))
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
fn test_01_row_metadata_and_identity() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;

    assert_eq!(adapter.row_id(), "ADP-REPLAY-001");
    assert_eq!(adapter.row_id(), ADP_REPLAY_ROW_ID);
    assert_eq!(adapter.surface(), "deterministic replay");
    assert_eq!(adapter.surface(), ADP_REPLAY_SURFACE);
    assert_eq!(adapter.tier(), "T0");
    assert_eq!(adapter.tier(), ADP_REPLAY_TIER);
    assert_eq!(adapter.current_state(), "specified");
    assert_eq!(adapter.current_state(), ADP_REPLAY_CURRENT_STATE);
    assert_eq!(adapter.promotion_gate(), "GATE-010");
    assert_eq!(adapter.promotion_gate(), ADP_REPLAY_PROMOTION_GATE);
    assert_eq!(adapter.generation(), "gen:fss1:adapters-v1");
    assert_eq!(adapter.generation(), ADP_REPLAY_GENERATION);
    assert_eq!(adapter.config().max_packets, ADP_REPLAY_MAX_PACKETS);
    assert_eq!(adapter.config().max_total_bytes, ADP_REPLAY_MAX_TOTAL_BYTES);

    let id = adapter.identity();
    assert_eq!(id.adapter_id.as_str(), "adapter:adp-replay-001");
    assert_eq!(id.adapter_kind, AdapterKind::VirtualSimulated);
    assert_eq!(id.protocol_profile, ADP_REPLAY_PROTOCOL_PROFILE);
    assert_eq!(id.isolation_mode, IsolationMode::NativePureRust);
    assert_eq!(id.credential_method, CredentialMethod::None);
    assert_eq!(id.capabilities, AdapterCapabilities::NONE);
    assert!(id.verify().is_ok());

    // Verify consistency with architecture/device_adapters.json
    ReplayAdapter::verify_registry_row_constants()?;

    Ok(())
}

#[test]
fn test_02_deterministic_replay_and_golden_pinning() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;
    let bundle = sample_bundle()?;
    let cx1 = test_cx()?;
    let cx2 = test_cx()?;

    let dir1 = ScopedLedgerDir::new("det1", cx1.io_authority().clone())?;
    let dir2 = ScopedLedgerDir::new("det2", cx2.io_authority().clone())?;

    let p1 = dir1.journal_path("det1");
    let p2 = dir2.journal_path("det2");

    let mut obj1 = InMemoryObjectStore::new(ObjectLimits::new(128, 2 * 1024 * 1024));
    let mut led1 =
        DurableReferenceLedger::open(&p1, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;
    let req1 = ReplayExecutionRequest::new(bundle.clone());
    let out1 = adapter.execute(&cx1, &req1, &mut obj1, &mut led1)?;

    let mut obj2 = InMemoryObjectStore::new(ObjectLimits::new(128, 2 * 1024 * 1024));
    let mut led2 =
        DurableReferenceLedger::open(&p2, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;
    let req2 = ReplayExecutionRequest::new(bundle);
    let out2 = adapter.execute(&cx2, &req2, &mut obj2, &mut led2)?;

    assert_eq!(out1.audit_record.state_root, out2.audit_record.state_root);
    assert_eq!(out1.audit_record.audit_hash, out2.audit_record.audit_hash);
    assert_eq!(out1.audit_record.packets_delivered, 6);
    assert_eq!(out1.audit_record.packets_mutated, 1);
    assert_eq!(out1.capture.receipt, out2.capture.receipt);

    // Verify pinned golden constants
    assert_eq!(
        out1.audit_record.state_root.to_string(),
        ADP_REPLAY_GOLDEN_STATE_ROOT
    );
    assert_eq!(
        out1.audit_record.audit_hash.to_string(),
        ADP_REPLAY_GOLDEN_AUDIT_HASH
    );

    Ok(())
}

#[test]
fn test_03_incompatible_generation_rejected() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;
    let bundle = sample_bundle()?;
    let cx = test_cx()?;
    let dir = ScopedLedgerDir::new("incompat_gen", cx.io_authority().clone())?;
    let p = dir.journal_path("incompat_gen");

    let mut obj = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led =
        DurableReferenceLedger::open(&p, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;

    // 1. Caller controls request.generation with wrong generation in execute
    let mut req = ReplayExecutionRequest::new(bundle.clone());
    req.generation = "gen:fss1:adapters-v2-future".to_string();

    match adapter.execute(&cx, &req, &mut obj, &mut led) {
        Err(ReplayAdapterError::IncompatibleGeneration { expected, actual }) => {
            assert_eq!(expected, "gen:fss1:adapters-v1");
            assert_eq!(actual, "gen:fss1:adapters-v2-future");
        }
        other => {
            return Err(format!("expected IncompatibleGeneration, got {other:?}").into());
        }
    }

    // 2. Caller controls request.generation with wrong generation in verify_against_expected (N1)
    let golden_root = ContentDigest::sha256(ADP_REPLAY_GOLDEN_STATE_ROOT.as_bytes());
    let golden_audit = ContentDigest::sha256(ADP_REPLAY_GOLDEN_AUDIT_HASH.as_bytes());
    match adapter.verify_against_expected(
        &cx,
        &req,
        &mut obj,
        &mut led,
        &golden_root,
        &golden_audit,
    ) {
        Err(ReplayAdapterError::IncompatibleGeneration { expected, actual }) => {
            assert_eq!(expected, "gen:fss1:adapters-v1");
            assert_eq!(actual, "gen:fss1:adapters-v2-future");
        }
        other => {
            return Err(format!(
                "expected IncompatibleGeneration in verify_against_expected, got {other:?}"
            )
            .into());
        }
    }

    // 3. Caller tries to construct adapter with wrong generation in config
    let bad_config = ReplayAdapterConfig {
        generation: "gen:fss1:adapters-v2-custom".to_string(),
        ..ReplayAdapterConfig::default()
    };
    match ReplayAdapter::with_config(bad_config) {
        Err(ReplayAdapterError::IncompatibleGeneration { expected, actual }) => {
            assert_eq!(expected, "gen:fss1:adapters-v1");
            assert_eq!(actual, "gen:fss1:adapters-v2-custom");
        }
        other => {
            return Err(format!("expected IncompatibleGeneration on config, got {other:?}").into());
        }
    }

    Ok(())
}

#[test]
fn test_04_cooperative_cancellation_and_drain() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;
    let bundle = sample_bundle()?;
    let cx = test_cx()?;
    let dir = ScopedLedgerDir::new("cancel", cx.io_authority().clone())?;
    let p = dir.journal_path("cancel");

    let mut obj = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led =
        DurableReferenceLedger::open(&p, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;

    // Case 1: cancel via request flag in execute
    let mut req = ReplayExecutionRequest::new(bundle.clone());
    req.cancel_requested = true;

    match adapter.execute(&cx, &req, &mut obj, &mut led) {
        Err(ReplayAdapterError::CancellationRequested) => {
            assert!(cx.is_cancelled());
            assert!(cx.is_drain_completed());
            assert_eq!(cx.lifecycle_state(), ReplayLifecycleState::Finalized);
        }
        other => {
            return Err(format!("expected CancellationRequested, got {other:?}").into());
        }
    }

    // Case 2: cancel via request flag in verify_against_expected (N1)
    let cx_verify = test_cx()?;
    let golden_root = ContentDigest::sha256(ADP_REPLAY_GOLDEN_STATE_ROOT.as_bytes());
    let golden_audit = ContentDigest::sha256(ADP_REPLAY_GOLDEN_AUDIT_HASH.as_bytes());
    match adapter.verify_against_expected(
        &cx_verify,
        &req,
        &mut obj,
        &mut led,
        &golden_root,
        &golden_audit,
    ) {
        Err(ReplayAdapterError::CancellationRequested) => {
            assert!(cx_verify.is_cancelled());
            assert!(cx_verify.is_drain_completed());
            assert_eq!(cx_verify.lifecycle_state(), ReplayLifecycleState::Finalized);
        }
        other => {
            return Err(format!(
                "expected CancellationRequested in verify_against_expected, got {other:?}"
            )
            .into());
        }
    }

    // Case 3: cancel via ReplayCx directly in execute
    let cx2 = test_cx()?;
    cx2.request_cancellation();
    assert_eq!(
        cx2.lifecycle_state(),
        ReplayLifecycleState::CancellationRequested
    );
    let req2 = ReplayExecutionRequest::new(bundle.clone());
    match adapter.execute(&cx2, &req2, &mut obj, &mut led) {
        Err(ReplayAdapterError::CancellationRequested) => {
            assert!(cx2.is_cancelled());
            assert!(cx2.is_drain_completed());
            assert_eq!(cx2.lifecycle_state(), ReplayLifecycleState::Finalized);
        }
        other => {
            return Err(format!("expected CancellationRequested on cx2, got {other:?}").into());
        }
    }

    // Case 4: cancel via ReplayCx directly in verify_against_expected (N1)
    let cx3 = test_cx()?;
    cx3.request_cancellation();
    match adapter.verify_against_expected(
        &cx3,
        &req2,
        &mut obj,
        &mut led,
        &golden_root,
        &golden_audit,
    ) {
        Err(ReplayAdapterError::CancellationRequested) => {
            assert!(cx3.is_cancelled());
            assert!(cx3.is_drain_completed());
            assert_eq!(cx3.lifecycle_state(), ReplayLifecycleState::Finalized);
        }
        other => {
            return Err(
                format!("expected CancellationRequested on cx3 in verify, got {other:?}").into(),
            );
        }
    }

    Ok(())
}

#[test]
fn test_05_budget_exhaustion_and_exact_budget() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;
    let bundle = sample_bundle()?;
    let cx = test_cx()?;
    let dir = ScopedLedgerDir::new("budget", cx.io_authority().clone())?;
    let p = dir.journal_path("budget");

    let mut obj = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led =
        DurableReferenceLedger::open(&p, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;

    // 1. Budget exhausted in execute (limit 3 < requested 6)
    let mut req = ReplayExecutionRequest::new(bundle.clone());
    req.max_packet_budget = Some(3);

    match adapter.execute(&cx, &req, &mut obj, &mut led) {
        Err(ReplayAdapterError::BudgetExhausted { requested, limit }) => {
            assert_eq!(requested, 6);
            assert_eq!(limit, 3);
        }
        other => {
            return Err(format!("expected BudgetExhausted, got {other:?}").into());
        }
    }

    // 2. Budget exhausted in verify_against_expected (N1)
    let golden_root = ContentDigest::sha256(ADP_REPLAY_GOLDEN_STATE_ROOT.as_bytes());
    let golden_audit = ContentDigest::sha256(ADP_REPLAY_GOLDEN_AUDIT_HASH.as_bytes());
    match adapter.verify_against_expected(
        &cx,
        &req,
        &mut obj,
        &mut led,
        &golden_root,
        &golden_audit,
    ) {
        Err(ReplayAdapterError::BudgetExhausted { requested, limit }) => {
            assert_eq!(requested, 6);
            assert_eq!(limit, 3);
        }
        other => {
            return Err(format!("expected BudgetExhausted in verify, got {other:?}").into());
        }
    }

    // 3. Exact budget match (limit 6 == requested 6) succeeds in execute
    let mut req_exact = ReplayExecutionRequest::new(bundle);
    req_exact.max_packet_budget = Some(6);
    let out = adapter.execute(&cx, &req_exact, &mut obj, &mut led)?;
    assert_eq!(out.audit_record.packets_delivered, 6);

    Ok(())
}

#[test]
fn test_06_bounds_enforcement_and_zero_bounds() -> Result<(), Box<dyn Error>> {
    let bundle = sample_bundle()?;
    let cx = test_cx()?;
    let dir = ScopedLedgerDir::new("bounds", cx.io_authority().clone())?;
    let p = dir.journal_path("bounds");

    // 1. Zero bound rejected at config construction (mutants R2, R3)
    let zero_packets_cfg = ReplayAdapterConfig {
        max_packets: 0,
        ..ReplayAdapterConfig::default()
    };
    match ReplayAdapter::with_config(zero_packets_cfg) {
        Err(ReplayAdapterError::BoundExceeded(b)) => {
            assert_eq!(b, "max_packets cannot be zero");
        }
        other => {
            return Err(
                format!("expected BoundExceeded for zero max_packets, got {other:?}").into(),
            );
        }
    }

    let zero_bytes_cfg = ReplayAdapterConfig {
        max_bytes: 0,
        ..ReplayAdapterConfig::default()
    };
    match ReplayAdapter::with_config(zero_bytes_cfg) {
        Err(ReplayAdapterError::BoundExceeded(b)) => {
            assert_eq!(b, "packet_bytes");
        }
        other => {
            return Err(format!("expected BoundExceeded for zero max_bytes, got {other:?}").into());
        }
    }

    let excessive_bytes_cfg = ReplayAdapterConfig {
        max_bytes: ADP_REPLAY_MAX_PACKET_BYTES + 1,
        ..ReplayAdapterConfig::default()
    };
    match ReplayAdapter::with_config(excessive_bytes_cfg) {
        Err(ReplayAdapterError::BoundExceeded(b)) => {
            assert_eq!(b, "packet_bytes");
        }
        other => {
            return Err(
                format!("expected BoundExceeded for excessive max_bytes, got {other:?}").into(),
            );
        }
    }

    // Exact upper bound succeeds
    let max_allowed_bytes_cfg = ReplayAdapterConfig {
        max_bytes: ADP_REPLAY_MAX_PACKET_BYTES,
        ..ReplayAdapterConfig::default()
    };
    assert!(ReplayAdapter::with_config(max_allowed_bytes_cfg).is_ok());

    // Zero max_total_bytes rejected (mutant R2)
    let zero_total_cfg = ReplayAdapterConfig {
        max_total_bytes: 0,
        ..ReplayAdapterConfig::default()
    };
    match ReplayAdapter::with_config(zero_total_cfg) {
        Err(ReplayAdapterError::BoundExceeded(b)) => {
            assert_eq!(b, "max_total_bytes cannot be zero");
        }
        other => {
            return Err(
                format!("expected BoundExceeded for zero max_total_bytes, got {other:?}").into(),
            );
        }
    }

    // Positive max_total_bytes succeeds
    let pos_total_cfg = ReplayAdapterConfig {
        max_total_bytes: 1,
        ..ReplayAdapterConfig::default()
    };
    assert!(ReplayAdapter::with_config(pos_total_cfg).is_ok());

    // 2. Packet count bound exceeded during execute and verify (mutant R6b, N1)
    let config_packets = ReplayAdapterConfig {
        max_packets: 4, // bundle has 6
        ..ReplayAdapterConfig::default()
    };
    let adapter_packets = ReplayAdapter::with_config(config_packets)?;

    let mut obj = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led =
        DurableReferenceLedger::open(&p, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;

    let req = ReplayExecutionRequest::new(bundle.clone());
    match adapter_packets.execute(&cx, &req, &mut obj, &mut led) {
        Err(ReplayAdapterError::BoundExceeded(bound)) => {
            assert_eq!(bound, "packet_count");
        }
        other => {
            return Err(format!("expected BoundExceeded packet_count, got {other:?}").into());
        }
    }

    let golden_root = ContentDigest::sha256(ADP_REPLAY_GOLDEN_STATE_ROOT.as_bytes());
    let golden_audit = ContentDigest::sha256(ADP_REPLAY_GOLDEN_AUDIT_HASH.as_bytes());
    match adapter_packets.verify_against_expected(
        &cx,
        &req,
        &mut obj,
        &mut led,
        &golden_root,
        &golden_audit,
    ) {
        Err(ReplayAdapterError::BoundExceeded(bound)) => {
            assert_eq!(bound, "packet_count");
        }
        other => {
            return Err(
                format!("expected BoundExceeded packet_count in verify, got {other:?}").into(),
            );
        }
    }

    // 3. Packet payload bytes bound exceeded during execute and verify (mutant R6f, N1)
    let config_bytes = ReplayAdapterConfig {
        max_bytes: 32, // bundle has 64
        ..ReplayAdapterConfig::default()
    };
    let adapter_bytes = ReplayAdapter::with_config(config_bytes)?;
    match adapter_bytes.execute(&cx, &req, &mut obj, &mut led) {
        Err(ReplayAdapterError::BoundExceeded(bound)) => {
            assert_eq!(bound, "packet_bytes");
        }
        other => {
            return Err(format!("expected BoundExceeded packet_bytes, got {other:?}").into());
        }
    }
    match adapter_bytes.verify_against_expected(
        &cx,
        &req,
        &mut obj,
        &mut led,
        &golden_root,
        &golden_audit,
    ) {
        Err(ReplayAdapterError::BoundExceeded(bound)) => {
            assert_eq!(bound, "packet_bytes");
        }
        other => {
            return Err(
                format!("expected BoundExceeded packet_bytes in verify, got {other:?}").into(),
            );
        }
    }

    // 4. Aggregate total bytes bound exceeded during execute and verify (mutant R7c, N1)
    let config_total = ReplayAdapterConfig {
        max_total_bytes: 100, // bundle has 6 * 64 = 384 bytes
        ..ReplayAdapterConfig::default()
    };
    let adapter_total = ReplayAdapter::with_config(config_total)?;
    match adapter_total.execute(&cx, &req, &mut obj, &mut led) {
        Err(ReplayAdapterError::BoundExceeded(bound)) => {
            assert_eq!(bound, "max_total_bytes");
        }
        other => {
            return Err(format!("expected BoundExceeded max_total_bytes, got {other:?}").into());
        }
    }
    match adapter_total.verify_against_expected(
        &cx,
        &req,
        &mut obj,
        &mut led,
        &golden_root,
        &golden_audit,
    ) {
        Err(ReplayAdapterError::BoundExceeded(bound)) => {
            assert_eq!(bound, "max_total_bytes");
        }
        other => {
            return Err(
                format!("expected BoundExceeded max_total_bytes in verify, got {other:?}").into(),
            );
        }
    }

    Ok(())
}

#[test]
fn test_07_fail_closed_divergence_leaves_target_unmutated() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;
    let bundle = sample_bundle()?;
    let cx = test_cx()?;
    let dir = ScopedLedgerDir::new("diverge", cx.io_authority().clone())?;
    let p = dir.journal_path("diverge");

    let mut obj = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led =
        DurableReferenceLedger::open(&p, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;

    let initial_anchor = led.current().anchor.clone();
    let req = ReplayExecutionRequest::new(bundle);

    // Compute actual roots to test independent state_root vs audit_hash divergence
    let (actual_root, actual_audit) = {
        let dir_tmp = ScopedLedgerDir::new("tmp_golden", cx.io_authority().clone())?;
        let mut obj_tmp = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
        let mut led_tmp = DurableReferenceLedger::open(
            dir_tmp.journal_path("tmp"),
            "site:replay-contract",
            IncompleteTailPolicy::Reject,
        )?;
        let out = adapter.execute(&cx, &req, &mut obj_tmp, &mut led_tmp)?;
        (out.audit_record.state_root, out.audit_record.audit_hash)
    };

    let wrong_digest = ContentDigest::sha256(b"intentionally wrong reference digest");
    let wrong_audit = ContentDigest::sha256(b"intentionally wrong audit hash");

    // Case 1: Both roots wrong
    match adapter.verify_against_expected(
        &cx,
        &req,
        &mut obj,
        &mut led,
        &wrong_digest,
        &wrong_audit,
    ) {
        Err(ReplayAdapterError::ReplayDiverged(divergence)) => {
            assert_eq!(divergence.expected_root, wrong_digest);
            assert_eq!(divergence.actual_root, actual_root);
            assert_eq!(divergence.expected_audit_hash, wrong_audit);
            assert_eq!(divergence.actual_audit_hash, actual_audit);

            let display = format!("{}", ReplayAdapterError::ReplayDiverged(divergence));
            assert!(display.contains(ERR_ADAPTER_REPLAY_DIVERGED));
        }
        other => {
            return Err(format!("expected ReplayDiverged, got {other:?}").into());
        }
    }
    assert_eq!(led.current().anchor, initial_anchor);
    assert_eq!(obj.object_count(), 0);

    // Case 2: Matching state_root, but diverged audit_hash (kills mutant R10!)
    match adapter.verify_against_expected(&cx, &req, &mut obj, &mut led, &actual_root, &wrong_audit)
    {
        Err(ReplayAdapterError::ReplayDiverged(divergence)) => {
            assert_eq!(divergence.expected_root, actual_root);
            assert_eq!(divergence.actual_root, actual_root);
            assert_eq!(divergence.expected_audit_hash, wrong_audit);
            assert_ne!(divergence.actual_audit_hash, wrong_audit);
        }
        other => {
            return Err(format!("expected ReplayDiverged on audit hash, got {other:?}").into());
        }
    }
    assert_eq!(led.current().anchor, initial_anchor);
    assert_eq!(obj.object_count(), 0);

    // Case 3: Matching audit_hash, but diverged state_root (kills mutant R8a!)
    match adapter.verify_against_expected(
        &cx,
        &req,
        &mut obj,
        &mut led,
        &wrong_digest,
        &actual_audit,
    ) {
        Err(ReplayAdapterError::ReplayDiverged(divergence)) => {
            assert_eq!(divergence.expected_root, wrong_digest);
            assert_ne!(divergence.actual_root, wrong_digest);
            assert_eq!(divergence.expected_audit_hash, actual_audit);
            assert_eq!(divergence.actual_audit_hash, actual_audit);
        }
        other => {
            return Err(format!("expected ReplayDiverged on state root, got {other:?}").into());
        }
    }
    assert_eq!(led.current().anchor, initial_anchor);
    assert_eq!(obj.object_count(), 0);

    Ok(())
}

#[test]
fn test_08_target_publish_rollback_on_partial_failure() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;
    let bundle = sample_bundle()?;
    let cx = test_cx()?;
    let dir = ScopedLedgerDir::new("rollback", cx.io_authority().clone())?;
    let p = dir.journal_path("rollback");

    // 1. Rollback on empty target store: capacity 3 causes failure during replay after 3 objects
    let mut obj_empty = InMemoryObjectStore::new(ObjectLimits::new(3, 1024 * 1024));
    let mut led =
        DurableReferenceLedger::open(&p, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;

    let req = ReplayExecutionRequest::new(bundle.clone());
    let res = adapter.execute(&cx, &req, &mut obj_empty, &mut led);
    assert!(res.is_err(), "Must fail when capacity exceeded");
    // INVARIANT (N2): Failed publish MUST NOT leave orphan staged objects!
    assert_eq!(
        obj_empty.object_count(),
        0,
        "Target object store must be rolled back to 0 objects on failure (no orphan objects)"
    );

    // 2. Rollback preserves pre-existing objects without orphan additions
    let dir2 = ScopedLedgerDir::new("rollback2", cx.io_authority().clone())?;
    let p2 = dir2.journal_path("rollback2");
    let mut led2 =
        DurableReferenceLedger::open(&p2, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;

    let mut obj_existing = InMemoryObjectStore::new(ObjectLimits::new(3, 1024 * 1024));
    let pre_existing_digest = obj_existing.put_verified(b"pre_existing_data_packet")?;
    assert_eq!(obj_existing.object_count(), 1);

    let res2 = adapter.execute(&cx, &req, &mut obj_existing, &mut led2);
    assert!(res2.is_err(), "Must fail when capacity exceeded");
    assert_eq!(
        obj_existing.object_count(),
        1,
        "Target object store must restore exact pre-existing object state (1 object)"
    );
    assert!(obj_existing.read_verified(pre_existing_digest).is_ok());

    Ok(())
}

#[test]
fn test_09_unforgeable_authority_and_cx_lifecycle() -> Result<(), Box<dyn Error>> {
    // 1. Unforgeable ReplayIoAuthority constructor validation (N3)
    // Empty principal rejected
    match ReplayIoAuthority::authorize("", ADP_REPLAY_ROW_ID) {
        Err(ReplayAdapterError::Unauthorized { reason }) => {
            assert_eq!(reason, "principal cannot be empty");
        }
        other => {
            return Err(format!("expected Unauthorized empty principal, got {other:?}").into());
        }
    }

    // Empty capability rejected
    match ReplayIoAuthority::authorize("test-principal", "") {
        Err(ReplayAdapterError::Unauthorized { reason }) => {
            assert_eq!(reason, "capability cannot be empty");
        }
        other => {
            return Err(format!("expected Unauthorized empty capability, got {other:?}").into());
        }
    }

    // Unauthorized capability scope rejected
    match ReplayIoAuthority::authorize("test-principal", "wrong:capability") {
        Err(ReplayAdapterError::Unauthorized { reason }) => {
            assert_eq!(
                reason,
                "capability does not grant ADP-REPLAY-001 I/O authority"
            );
        }
        other => {
            return Err(format!("expected Unauthorized wrong capability, got {other:?}").into());
        }
    }

    // Valid authorizations succeed
    let auth1 = ReplayIoAuthority::authorize("test-principal", ADP_REPLAY_ROW_ID)?;
    assert_eq!(auth1.principal(), "test-principal");
    assert_eq!(auth1.capability(), ADP_REPLAY_ROW_ID);

    let auth2 = ReplayIoAuthority::authorize("test-principal", "io:adapter:adp-replay-001")?;
    assert_eq!(auth2.capability(), "io:adapter:adp-replay-001");

    // 2. ContextAuthority bridge validation (N3)
    let valid_root_spec = RootAuthoritySpec {
        trace_id: "trace:root-001".to_string(),
        operation_id: OperationId::parse("operation:root-001")?,
        principal: "principal:system-root".to_string(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"test-anchor-universe"),
        generation: 1,
    };
    let valid_context = ContextAuthority::new_root(valid_root_spec)?;
    let auth_from_cx = ReplayIoAuthority::from_context_authority(&valid_context)?;
    assert_eq!(auth_from_cx.principal(), "principal:system-root");

    let invalid_root_spec = RootAuthoritySpec {
        trace_id: "trace:root-002".to_string(),
        operation_id: OperationId::parse("operation:root-002")?,
        principal: "principal:unauthorized-root".to_string(),
        capabilities: vec!["unrelated:capability".to_string()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"test-anchor-universe"),
        generation: 1,
    };
    let invalid_context = ContextAuthority::new_root(invalid_root_spec)?;
    match ReplayIoAuthority::from_context_authority(&invalid_context) {
        Err(ReplayAdapterError::Unauthorized { reason }) => {
            assert_eq!(
                reason,
                "ContextAuthority does not grant ADP-REPLAY-001 capability"
            );
        }
        other => {
            return Err(
                format!("expected Unauthorized on missing capability, got {other:?}").into(),
            );
        }
    }

    // 3. Real ReplayCx lifecycle state machine (N3)
    let cx = ReplayCx::new(auth1);
    assert_eq!(cx.lifecycle_state(), ReplayLifecycleState::Active);
    assert_eq!(cx.lifecycle_state().as_str(), "active");
    assert!(!cx.is_cancelled());
    assert!(!cx.is_drain_completed());
    assert_eq!(cx.checkpoints_reached(), 0);

    // Checkpoint while active succeeds and increments counter
    assert!(cx.checkpoint("stage_1").is_ok());
    assert_eq!(cx.checkpoints_reached(), 1);

    // Transition: Active -> CancellationRequested
    cx.request_cancellation();
    assert_eq!(
        cx.lifecycle_state(),
        ReplayLifecycleState::CancellationRequested
    );
    assert_eq!(cx.lifecycle_state().as_str(), "cancellation_requested");
    assert!(cx.is_cancelled());

    // Transition: CancellationRequested -> Draining
    cx.drain();
    assert_eq!(cx.lifecycle_state(), ReplayLifecycleState::Draining);
    assert_eq!(cx.lifecycle_state().as_str(), "draining");

    // Transition: Draining -> Finalized
    cx.finalize();
    assert_eq!(cx.lifecycle_state(), ReplayLifecycleState::Finalized);
    assert_eq!(cx.lifecycle_state().as_str(), "finalized");
    assert!(cx.is_drain_completed());

    // Checkpoint while finalized returns CancellationRequested
    match cx.checkpoint("stage_terminal") {
        Err(ReplayAdapterError::CancellationRequested) => {}
        other => return Err(format!("expected CancellationRequested, got {other:?}").into()),
    }
    assert_eq!(cx.checkpoints_reached(), 2);

    Ok(())
}

#[test]
fn test_10_verify_against_expected_success() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;
    let bundle = sample_bundle()?;
    let cx1 = test_cx()?;
    let cx2 = test_cx()?;

    let dir1 = ScopedLedgerDir::new("exp_succ1", cx1.io_authority().clone())?;
    let dir2 = ScopedLedgerDir::new("exp_succ2", cx2.io_authority().clone())?;

    let p1 = dir1.journal_path("exp_succ1");
    let p2 = dir2.journal_path("exp_succ2");

    // Compute ground truth root and audit hash
    let mut obj1 = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led1 =
        DurableReferenceLedger::open(&p1, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;
    let req1 = ReplayExecutionRequest::new(bundle.clone());
    let out1 = adapter.execute(&cx1, &req1, &mut obj1, &mut led1)?;
    let known_root = out1.audit_record.state_root;
    let known_audit = out1.audit_record.audit_hash;

    // Verify against known root and audit hash on second fresh ledger
    let mut obj2 = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led2 =
        DurableReferenceLedger::open(&p2, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;
    let req2 = ReplayExecutionRequest::new(bundle);
    let out2 = adapter.verify_against_expected(
        &cx2,
        &req2,
        &mut obj2,
        &mut led2,
        &known_root,
        &known_audit,
    )?;

    assert_eq!(out2.audit_record.state_root, known_root);
    assert_eq!(out2.audit_record.audit_hash, known_audit);
    assert_eq!(
        out2.audit_record.state_root.to_string(),
        ADP_REPLAY_GOLDEN_STATE_ROOT
    );
    assert_eq!(
        out2.audit_record.audit_hash.to_string(),
        ADP_REPLAY_GOLDEN_AUDIT_HASH
    );

    // On match, publication succeeds into target object store and ledger
    assert!(obj2.object_count() > 0);
    assert_ne!(
        led2.current().anchor,
        DurableReferenceLedger::open(
            dir2.journal_path("genesis_check"),
            "site:replay-contract",
            IncompleteTailPolicy::Reject,
        )?
        .current()
        .anchor
    );

    Ok(())
}

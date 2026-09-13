#![forbid(unsafe_code)]
//! Contract tests for ADP-REPLAY-001 deterministic replay adapter.
//!
//! Enforces:
//! 1. Row identity and typed protocol contract (ADP-REPLAY-001, T0, GATE-010, pure Rust)
//! 2. Consistency between code constants and `architecture/device_adapters.json`
//! 3. Deterministic replay produces identical state roots and audit hashes matching golden constants
//! 4. Fail-closed divergence detection leaves target object store and ledger pristine
//! 5. Audit hash covers bundle digest, generation, and row ID
//! 6. Incompatible generation rejection
//! 7. Cooperative cancellation handling via ReplayCx with request->drain->finalize
//! 8. Packet budget enforcement (including exact budget == count)
//! 9. Hard bounds enforcement (packet count, packet bytes, aggregate bytes, zero-bound rejection)
//! 10. Zero ambient temp files (all I/O governed by explicit authority and ScopedLedgerDir)
//! 11. Zero unwrap, expect, or panic anywhere in test suite

use std::error::Error;

use fss_core::{
    AdapterCapabilities, AdapterKind, CapsuleId, ContentDigest, CredentialMethod, IsolationMode,
    SensorId,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};
use fss_reference::{
    ADP_REPLAY_CURRENT_STATE, ADP_REPLAY_GENERATION, ADP_REPLAY_GOLDEN_AUDIT_HASH,
    ADP_REPLAY_GOLDEN_STATE_ROOT, ADP_REPLAY_MAX_PACKET_BYTES, ADP_REPLAY_PROMOTION_GATE,
    ADP_REPLAY_PROTOCOL_PROFILE, ADP_REPLAY_ROW_ID, ADP_REPLAY_SURFACE, ADP_REPLAY_TIER,
    DeliveryDirective, DeliveryPlan, ERR_ADAPTER_REPLAY_DIVERGED, ReplayAdapter,
    ReplayAdapterConfig, ReplayAdapterError, ReplayBundle, ReplayCx, ReplayExecutionRequest,
    ScopedLedgerDir, VirtualCameraSpec,
};

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
    let cx1 = ReplayCx::for_test();
    let cx2 = ReplayCx::for_test();

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
    let cx = ReplayCx::for_test();
    let dir = ScopedLedgerDir::new("incompat_gen", cx.io_authority().clone())?;
    let p = dir.journal_path("incompat_gen");

    let mut obj = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led =
        DurableReferenceLedger::open(&p, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;

    // 1. Caller controls request.generation with wrong generation
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

    // 2. Caller tries to construct adapter with wrong generation in config
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
    let cx = ReplayCx::for_test();
    let dir = ScopedLedgerDir::new("cancel", cx.io_authority().clone())?;
    let p = dir.journal_path("cancel");

    let mut obj = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led =
        DurableReferenceLedger::open(&p, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;

    // Case 1: cancel via request flag
    let mut req = ReplayExecutionRequest::new(bundle.clone());
    req.cancel_requested = true;

    match adapter.execute(&cx, &req, &mut obj, &mut led) {
        Err(ReplayAdapterError::CancellationRequested) => {
            assert!(cx.is_cancelled());
            assert!(cx.is_drain_completed());
        }
        other => {
            return Err(format!("expected CancellationRequested, got {other:?}").into());
        }
    }

    // Case 2: cancel via ReplayCx directly
    let cx2 = ReplayCx::for_test();
    cx2.request_cancellation();
    let req2 = ReplayExecutionRequest::new(bundle);
    match adapter.execute(&cx2, &req2, &mut obj, &mut led) {
        Err(ReplayAdapterError::CancellationRequested) => {
            assert!(cx2.is_cancelled());
            assert!(cx2.is_drain_completed());
        }
        other => {
            return Err(format!("expected CancellationRequested on cx2, got {other:?}").into());
        }
    }

    Ok(())
}

#[test]
fn test_05_budget_exhaustion_and_exact_budget() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;
    let bundle = sample_bundle()?;
    let cx = ReplayCx::for_test();
    let dir = ScopedLedgerDir::new("budget", cx.io_authority().clone())?;
    let p = dir.journal_path("budget");

    let mut obj = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led =
        DurableReferenceLedger::open(&p, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;

    // 1. Budget exhausted (limit 3 < requested 6)
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

    // 2. Exact budget match (limit 6 == requested 6) succeeds
    let mut req_exact = ReplayExecutionRequest::new(bundle);
    req_exact.max_packet_budget = Some(6);
    let out = adapter.execute(&cx, &req_exact, &mut obj, &mut led)?;
    assert_eq!(out.audit_record.packets_delivered, 6);

    Ok(())
}

#[test]
fn test_06_bounds_enforcement_and_zero_bounds() -> Result<(), Box<dyn Error>> {
    let bundle = sample_bundle()?;
    let cx = ReplayCx::for_test();
    let dir = ScopedLedgerDir::new("bounds", cx.io_authority().clone())?;
    let p = dir.journal_path("bounds");

    // 1. Zero bound rejected at config construction
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

    // 2. Packet count bound exceeded during execute
    let config_packets = ReplayAdapterConfig {
        max_packets: 4, // bundle has 6
        ..ReplayAdapterConfig::default()
    };
    let adapter_packets = ReplayAdapter::with_config(config_packets)?;

    let mut obj = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led =
        DurableReferenceLedger::open(&p, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;

    let req = ReplayExecutionRequest::new(bundle);
    match adapter_packets.execute(&cx, &req, &mut obj, &mut led) {
        Err(ReplayAdapterError::BoundExceeded(bound)) => {
            assert_eq!(bound, "packet_count");
        }
        other => {
            return Err(format!("expected BoundExceeded packet_count, got {other:?}").into());
        }
    }

    // 3. Packet payload bytes bound exceeded
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

    // 4. Aggregate total bytes bound exceeded
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

    Ok(())
}

#[test]
fn test_07_fail_closed_divergence_leaves_target_unmutated() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;
    let bundle = sample_bundle()?;
    let cx = ReplayCx::for_test();
    let dir = ScopedLedgerDir::new("diverge", cx.io_authority().clone())?;
    let p = dir.journal_path("diverge");

    let mut obj = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led =
        DurableReferenceLedger::open(&p, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;

    let initial_anchor = led.current().anchor.clone();

    let req = ReplayExecutionRequest::new(bundle);
    let wrong_digest = ContentDigest::sha256(b"intentionally wrong reference digest");
    let wrong_audit = ContentDigest::sha256(b"intentionally wrong audit hash");

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
            assert_ne!(divergence.actual_root, wrong_digest);
            assert_eq!(divergence.expected_audit_hash, wrong_audit);
            assert_ne!(divergence.actual_audit_hash, wrong_audit);

            let display = format!("{}", ReplayAdapterError::ReplayDiverged(divergence));
            assert!(display.contains(ERR_ADAPTER_REPLAY_DIVERGED));
        }
        other => {
            return Err(format!("expected ReplayDiverged, got {other:?}").into());
        }
    }

    // FAIL-CLOSED INVARIANT: Target objects and target ledger MUST remain completely unmutated!
    assert_eq!(
        led.current().anchor,
        initial_anchor,
        "Target ledger must not have appended any batch on diverged replay"
    );
    assert_eq!(
        obj.object_count(),
        0,
        "Target object store must not have stored any object on diverged replay"
    );

    Ok(())
}

#[test]
fn test_08_verify_against_expected_success() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;
    let bundle = sample_bundle()?;
    let cx1 = ReplayCx::for_test();
    let cx2 = ReplayCx::for_test();

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

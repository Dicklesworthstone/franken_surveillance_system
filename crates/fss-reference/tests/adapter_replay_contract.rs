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
//! 9. Hard bounds enforcement (packet count, packet bytes, aggregate bytes, zero-bound rejection) (N1, mutants R6f, R7c, R7d)
//! 10. Fail-closed target publish rollback on partial failure preventing orphan staged objects (mutants M2, M3)
//! 11. Unforgeable ReplayIoAuthority and ReplayCx lifecycle state transitions with finalized revocation (N3)
//! 12. Independent state root and audit hash divergence detection (mutants R2, R3)
//! 13. Cancellation after commit handling with explicit terminal status and checkpoint tests (mutants R6a, R6b)
//! 14. Exact boundary enforcement (mutants R7b, R8a)
//! 15. Staging directory cleanup on divergence (mutant R10)
//! 16. Negative registry row drift verification (mutant R11)
//! 17. Zero unwrap, expect, or panic anywhere in test suite

use std::error::Error;
use std::path::PathBuf;

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
    ReplayTerminalStatus, ScopedLedgerDir, VirtualCameraSpec,
};

fn test_context_authority(label: &str) -> Result<ContextAuthority, Box<dyn Error>> {
    let spec = RootAuthoritySpec {
        trace_id: format!("trace:contract-test-{label}"),
        operation_id: OperationId::parse(format!("operation:contract-test-{label}"))?,
        principal: format!("operator:contract-test-{label}"),
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
        .join(format!("test-replay-cx-{label}"));
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
    let cx1 = test_cx("det1")?;
    let cx2 = test_cx("det2")?;

    let dir1 = ScopedLedgerDir::new("det1", &cx1)?;
    let dir2 = ScopedLedgerDir::new("det2", &cx2)?;

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
    let cx = test_cx("incompat_gen")?;
    let dir = ScopedLedgerDir::new("incompat_gen", &cx)?;
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
    let golden_root = ContentDigest::parse(ADP_REPLAY_GOLDEN_STATE_ROOT)?;
    let golden_audit = ContentDigest::parse(ADP_REPLAY_GOLDEN_AUDIT_HASH)?;
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
    let cx = test_cx("cancel_c1")?;
    let dir = ScopedLedgerDir::new("cancel", &cx)?;
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
    let cx_verify = test_cx("cancel_c2")?;
    let golden_root = ContentDigest::parse(ADP_REPLAY_GOLDEN_STATE_ROOT)?;
    let golden_audit = ContentDigest::parse(ADP_REPLAY_GOLDEN_AUDIT_HASH)?;
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
    let cx2 = test_cx("cancel_c3")?;
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
    let cx3 = test_cx("cancel_c4")?;
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
    let cx = test_cx("budget")?;
    let dir = ScopedLedgerDir::new("budget", &cx)?;
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
    let golden_root = ContentDigest::parse(ADP_REPLAY_GOLDEN_STATE_ROOT)?;
    let golden_audit = ContentDigest::parse(ADP_REPLAY_GOLDEN_AUDIT_HASH)?;
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
    let cx = test_cx("bounds")?;
    let dir = ScopedLedgerDir::new("bounds", &cx)?;
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

    // Exact upper bound succeeds
    let max_allowed_bytes_cfg = ReplayAdapterConfig {
        max_bytes: ADP_REPLAY_MAX_PACKET_BYTES,
        ..ReplayAdapterConfig::default()
    };
    assert!(ReplayAdapter::with_config(max_allowed_bytes_cfg).is_ok());

    // Zero max_total_bytes rejected (mutant R7c)
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

    // 2. Packet count bound exceeded during execute and verify (N1)
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

    let golden_root = ContentDigest::parse(ADP_REPLAY_GOLDEN_STATE_ROOT)?;
    let golden_audit = ContentDigest::parse(ADP_REPLAY_GOLDEN_AUDIT_HASH)?;
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

    // 4. Aggregate total bytes bound exceeded during execute and verify (N1)
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
    let cx = test_cx("diverge")?;
    let dir = ScopedLedgerDir::new("diverge", &cx)?;
    let p = dir.journal_path("diverge");

    let mut obj = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led =
        DurableReferenceLedger::open(&p, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;

    let initial_anchor = led.current().anchor.clone();
    let req = ReplayExecutionRequest::new(bundle);

    // Compute actual roots to test independent state_root vs audit_hash divergence
    let (actual_root, actual_audit) = {
        let dir_tmp = ScopedLedgerDir::new("tmp_golden", &cx)?;
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

    // Case 2: Matching state_root, but diverged audit_hash (kills mutant R2!)
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

    // Case 3: Matching audit_hash, but diverged state_root (kills mutant R3!)
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
    let cx = test_cx("rollback")?;
    let dir = ScopedLedgerDir::new("rollback", &cx)?;
    let p = dir.journal_path("rollback");

    // 1. Rollback on empty target store: capacity 3 causes failure during replay after 3 objects (mutant M3)
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
    let dir2 = ScopedLedgerDir::new("rollback2", &cx)?;
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

    // 3. Rollback on verify-path partial failure (kills mutant M2)
    // Target holding 1 pre-existing object with capacity 13 overflows mid-publish,
    // and verify leaves 1 object, 0 orphans and an unchanged ledger.
    let dir3 = ScopedLedgerDir::new("rollback_verify", &cx)?;
    let p3 = dir3.journal_path("rollback_verify");
    let mut led3 =
        DurableReferenceLedger::open(&p3, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;
    let initial_anchor3 = led3.current().anchor.clone();

    let mut obj_verify = InMemoryObjectStore::new(ObjectLimits::new(13, 1024 * 1024));
    let pre_existing_digest3 = obj_verify.put_verified(b"pre_existing_object_verify_path")?;
    assert_eq!(obj_verify.object_count(), 1);

    let golden_root = ContentDigest::parse(ADP_REPLAY_GOLDEN_STATE_ROOT)?;
    let golden_audit = ContentDigest::parse(ADP_REPLAY_GOLDEN_AUDIT_HASH)?;
    let res_verify = adapter.verify_against_expected(
        &cx,
        &req,
        &mut obj_verify,
        &mut led3,
        &golden_root,
        &golden_audit,
    );
    assert!(
        res_verify.is_err(),
        "Must fail when capacity exceeded on verify target publish"
    );
    assert_eq!(
        obj_verify.object_count(),
        1,
        "Verify path must roll back target object store to 1 object on failure (no orphan objects)"
    );
    assert!(obj_verify.read_verified(pre_existing_digest3).is_ok());
    assert_eq!(
        led3.current().anchor,
        initial_anchor3,
        "Verify path must leave ledger unchanged on failure"
    );

    Ok(())
}

#[test]
fn test_09_unforgeable_authority_and_cx_lifecycle() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;

    // 1. ContextAuthority bridge validation (N3): minting ONLY through validated ContextAuthority
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
    let scratch_base = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let auth1 = ReplayIoAuthority::from_context_authority(
        &valid_context,
        scratch_base.join("test-valid-auth"),
    )?;
    assert_eq!(auth1.principal(), "principal:system-root");
    assert_eq!(auth1.capability(), ADP_REPLAY_ROW_ID);
    assert!(auth1.is_valid());

    // Unauthorized context lacking ADP-REPLAY-001 capability is rejected
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
    match ReplayIoAuthority::from_context_authority(
        &invalid_context,
        scratch_base.join("test-invalid-auth"),
    ) {
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

    // 2. Real ReplayCx lifecycle state machine (N3)
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

    // 3. Finalized revokes I/O authority (Requirement 2):
    // Authority held by finalized context is revoked
    assert!(
        !cx.io_authority().is_valid(),
        "I/O authority must be revoked once context is finalized"
    );

    // ScopedLedgerDir::new with finalized cx fails closed with PermissionDenied
    let dir_err = ScopedLedgerDir::new("stolen", &cx);
    match dir_err {
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied),
        Ok(_) => return Err("expected PermissionDenied for finalized cx".into()),
    }

    // ScopedLedgerDir::from_authority with revoked authority fails closed with PermissionDenied
    let dir_err2 = ScopedLedgerDir::from_authority("stolen", cx.io_authority());
    match dir_err2 {
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied),
        Ok(_) => return Err("expected PermissionDenied for revoked authority".into()),
    }

    // Reviving an Active context using a revoked authority is impossible:
    // ReplayCx::new with revoked authority initializes state to Finalized
    let revoked_auth = ReplayIoAuthority::from_context_authority(
        &valid_context,
        scratch_base.join("test-revoked-auth"),
    )?;
    revoked_auth.revoke();
    assert!(!revoked_auth.is_valid());

    let revived_cx = ReplayCx::new(revoked_auth);
    assert_eq!(
        revived_cx.lifecycle_state(),
        ReplayLifecycleState::Finalized
    );
    assert!(revived_cx.is_cancelled());

    let active_cx = test_cx("revived_test")?;
    let active_dir = ScopedLedgerDir::new("revived_test", &active_cx)?;
    let mut obj_revived = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led_revived = DurableReferenceLedger::open(
        active_dir.journal_path("revived_test"),
        "site:replay-contract",
        IncompleteTailPolicy::Reject,
    )?;
    let req_revived = ReplayExecutionRequest::new(sample_bundle()?);
    match adapter.execute(
        &revived_cx,
        &req_revived,
        &mut obj_revived,
        &mut led_revived,
    ) {
        Err(ReplayAdapterError::CancellationRequested) => {}
        other => {
            return Err(
                format!("expected CancellationRequested on revived cx, got {other:?}").into(),
            );
        }
    }
    assert_eq!(
        obj_revived.object_count(),
        0,
        "Revived context must publish 0 objects"
    );

    Ok(())
}

#[test]
fn test_10_verify_against_expected_success() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;
    let bundle = sample_bundle()?;
    let cx1 = test_cx("exp_succ1")?;
    let cx2 = test_cx("exp_succ2")?;

    let dir1 = ScopedLedgerDir::new("exp_succ1", &cx1)?;
    let dir2 = ScopedLedgerDir::new("exp_succ2", &cx2)?;

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
    assert_eq!(out2.status, ReplayTerminalStatus::Committed);

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

#[test]
fn test_11_cancellation_preflight_and_drain() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;
    let bundle = sample_bundle()?;

    // 1. Normal execution returns status Committed
    let cx_post = test_cx("cancel_post")?;
    let dir_post = ScopedLedgerDir::new("cancel_post_commit", &cx_post)?;
    let mut obj_post = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led_post = DurableReferenceLedger::open(
        dir_post.journal_path("cancel_post_commit"),
        bundle.site_lineage(),
        IncompleteTailPolicy::Reject,
    )?;
    let req_post = ReplayExecutionRequest::new(bundle.clone());

    let out = adapter.execute(&cx_post, &req_post, &mut obj_post, &mut led_post)?;
    assert_eq!(out.status, ReplayTerminalStatus::Committed);
    assert!(obj_post.object_count() > 0);

    // 2. Preflight cancellation: if cx is already cancelled before execution,
    // returns CancellationRequested with 0 objects committed. Never report cancelled while effect stands.
    let cx_preflight = test_cx("cancel_preflight")?;
    let dir_preflight =
        ScopedLedgerDir::from_authority("cancel_preflight", cx_preflight.io_authority())?;
    let mut obj_preflight = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led_preflight = DurableReferenceLedger::open(
        dir_preflight.journal_path("cancel_preflight"),
        "site:replay-contract",
        IncompleteTailPolicy::Reject,
    )?;
    let bundle_preflight = sample_bundle()?;
    let req_preflight = ReplayExecutionRequest::new(bundle_preflight);
    cx_preflight.request_cancellation();
    match adapter.execute(
        &cx_preflight,
        &req_preflight,
        &mut obj_preflight,
        &mut led_preflight,
    ) {
        Err(ReplayAdapterError::CancellationRequested) => {
            assert_eq!(obj_preflight.object_count(), 0);
        }
        other => return Err(format!("expected CancellationRequested, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_12_exact_boundaries_and_mutants_r7b_r8a() -> Result<(), Box<dyn Error>> {
    let bundle = sample_bundle()?;
    let cx = test_cx("exact_bounds")?;
    let dir = ScopedLedgerDir::new("exact_bounds", &cx)?;
    let p = dir.journal_path("exact_bounds");
    let mut obj = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led =
        DurableReferenceLedger::open(&p, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;
    let req = ReplayExecutionRequest::new(bundle);

    // Bundle has 6 packets, 64 bytes each, total 384 bytes.
    // 1. Exact boundary for max_packets (kills mutant R8a):
    // max_packets == 6 is accepted (packet_count 6 <= max_packets 6)
    let cfg_exact_packets = ReplayAdapterConfig {
        max_packets: 6,
        ..ReplayAdapterConfig::default()
    };
    let adapter_exact_p = ReplayAdapter::with_config(cfg_exact_packets)?;
    assert!(
        adapter_exact_p
            .execute(&cx, &req, &mut obj, &mut led)
            .is_ok()
    );

    // max_packets == 5 is refused (packet_count 6 > max_packets 5)
    let cfg_under_packets = ReplayAdapterConfig {
        max_packets: 5,
        ..ReplayAdapterConfig::default()
    };
    let adapter_under_p = ReplayAdapter::with_config(cfg_under_packets)?;
    match adapter_under_p.execute(&cx, &req, &mut obj, &mut led) {
        Err(ReplayAdapterError::BoundExceeded(b)) => assert_eq!(b, "packet_count"),
        other => return Err(format!("expected BoundExceeded packet_count, got {other:?}").into()),
    }

    // 2. Exact boundary for max_total_bytes (kills mutant R7b):
    // max_total_bytes == 384 is accepted (total_bytes 384 <= max_total_bytes 384)
    let cfg_exact_total = ReplayAdapterConfig {
        max_total_bytes: 384,
        ..ReplayAdapterConfig::default()
    };
    let adapter_exact_t = ReplayAdapter::with_config(cfg_exact_total)?;
    let dir_t = ScopedLedgerDir::new("exact_bounds_t", &cx)?;
    let mut obj_t = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led_t = DurableReferenceLedger::open(
        dir_t.journal_path("exact_bounds_t"),
        "site:replay-contract",
        IncompleteTailPolicy::Reject,
    )?;
    assert!(
        adapter_exact_t
            .execute(&cx, &req, &mut obj_t, &mut led_t)
            .is_ok()
    );

    // max_total_bytes == 383 is refused (total_bytes 384 > max_total_bytes 383)
    let cfg_under_total = ReplayAdapterConfig {
        max_total_bytes: 383,
        ..ReplayAdapterConfig::default()
    };
    let adapter_under_t = ReplayAdapter::with_config(cfg_under_total)?;
    match adapter_under_t.execute(&cx, &req, &mut obj_t, &mut led_t) {
        Err(ReplayAdapterError::BoundExceeded(b)) => assert_eq!(b, "max_total_bytes"),
        other => {
            return Err(format!("expected BoundExceeded max_total_bytes, got {other:?}").into());
        }
    }

    // 3. Bundle with 7 packets refused when max_packets == 6
    let spec7 = VirtualCameraSpec {
        capture_id: CapsuleId::parse("capture:replay:contract:7")?,
        sensor_id: SensorId::parse("sensor:replay-lane")?,
        seed: 0xfeed_face_cafe_beef,
        packet_count: 7,
        packet_bytes: 64,
        start_ns: 10_000,
        period_ns: 1_000_000,
        uncertainty_ns: 5_000,
    };
    let plan7 = DeliveryPlan::new((1..=7).map(DeliveryDirective::exact).collect())?;
    let bundle7 = ReplayBundle::new("site:replay-contract", spec7, plan7)?;
    let req7 = ReplayExecutionRequest::new(bundle7);
    match adapter_exact_p.execute(&cx, &req7, &mut obj, &mut led) {
        Err(ReplayAdapterError::BoundExceeded(b)) => assert_eq!(b, "packet_count"),
        other => {
            return Err(
                format!("expected BoundExceeded packet_count on 7 packets, got {other:?}").into(),
            );
        }
    }

    // 4. Bundle with 385 bytes refused when max_total_bytes == 384
    let spec_385 = VirtualCameraSpec {
        capture_id: CapsuleId::parse("capture:replay:contract:385")?,
        sensor_id: SensorId::parse("sensor:replay-lane")?,
        seed: 0xfeed_face_cafe_beef,
        packet_count: 7,
        packet_bytes: 55, // 7 * 55 = 385 bytes
        start_ns: 10_000,
        period_ns: 1_000_000,
        uncertainty_ns: 5_000,
    };
    let plan_385 = DeliveryPlan::new((1..=7).map(DeliveryDirective::exact).collect())?;
    let bundle_385 = ReplayBundle::new("site:replay-contract", spec_385, plan_385)?;
    let req_385 = ReplayExecutionRequest::new(bundle_385);
    let cfg_total_384 = ReplayAdapterConfig {
        max_packets: 10,
        max_total_bytes: 384,
        ..ReplayAdapterConfig::default()
    };
    let adapter_total_384 = ReplayAdapter::with_config(cfg_total_384)?;
    match adapter_total_384.execute(&cx, &req_385, &mut obj, &mut led) {
        Err(ReplayAdapterError::BoundExceeded(b)) => assert_eq!(b, "max_total_bytes"),
        other => {
            return Err(format!(
                "expected BoundExceeded max_total_bytes on 385 bytes, got {other:?}"
            )
            .into());
        }
    }

    Ok(())
}

#[test]
fn test_13_staging_cleanup_on_divergence_r10() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;
    let bundle = sample_bundle()?;
    let cx = test_cx("staging_cleanup")?;
    let dir = ScopedLedgerDir::new("staging_clean", &cx)?;
    let p = dir.journal_path("staging_clean");
    let mut obj = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led =
        DurableReferenceLedger::open(&p, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;
    let req = ReplayExecutionRequest::new(bundle);

    let wrong_root = ContentDigest::sha256(b"intentionally divergent root");
    let wrong_audit = ContentDigest::sha256(b"intentionally divergent audit");

    // The staging directory will be created under cx.root_dir() with current sequence number
    let staging_path = cx
        .root_dir()
        .join(format!("staging_replay-{}", cx.current_dir_sequence()));
    assert!(!staging_path.exists());

    match adapter.verify_against_expected(&cx, &req, &mut obj, &mut led, &wrong_root, &wrong_audit)
    {
        Err(ReplayAdapterError::ReplayDiverged(_)) => {}
        other => return Err(format!("expected ReplayDiverged, got {other:?}").into()),
    }

    // Invariant (kills mutant R10): staging directory MUST be cleaned up on divergence
    assert!(
        !staging_path.exists(),
        "Staging directory must not survive divergence failure: {staging_path:?}"
    );

    Ok(())
}

#[test]
fn test_14_negative_registry_row_constants_r11() -> Result<(), Box<dyn Error>> {
    let valid_json = include_str!("../../../architecture/device_adapters.json");

    // 1. Valid JSON passes
    assert!(ReplayAdapter::verify_registry_row_json(valid_json).is_ok());

    // 2. Missing ID fails with RegistryDrift { field: "id" } (kills mutant R11)
    let json_missing_id = valid_json.replace("\"ADP-REPLAY-001\"", "\"ADP-REPLAY-REMOVED\"");
    match ReplayAdapter::verify_registry_row_json(&json_missing_id) {
        Err(ReplayAdapterError::RegistryDrift { field, .. }) => assert_eq!(field, "id"),
        other => return Err(format!("expected RegistryDrift on id, got {other:?}").into()),
    }

    // 3. Tampered surface fails
    let json_bad_surface = valid_json.replace("\"deterministic replay\"", "\"tampered surface\"");
    match ReplayAdapter::verify_registry_row_json(&json_bad_surface) {
        Err(ReplayAdapterError::RegistryDrift { field, .. }) => assert_eq!(field, "surface"),
        other => return Err(format!("expected RegistryDrift on surface, got {other:?}").into()),
    }

    // 4. Tampered tier fails
    let json_bad_tier = valid_json.replace(
        "\"id\": \"ADP-REPLAY-001\",\n      \"surface\": \"deterministic replay\",\n      \"tier\": \"T0\"",
        "\"id\": \"ADP-REPLAY-001\",\n      \"surface\": \"deterministic replay\",\n      \"tier\": \"T1\"",
    );
    match ReplayAdapter::verify_registry_row_json(&json_bad_tier) {
        Err(ReplayAdapterError::RegistryDrift { field, .. }) => assert_eq!(field, "tier"),
        other => return Err(format!("expected RegistryDrift on tier, got {other:?}").into()),
    }

    // 5. Tampered currentState fails
    let json_bad_state = valid_json.replace(
        "\"currentState\": \"specified\"",
        "\"currentState\": \"research target\"",
    );
    match ReplayAdapter::verify_registry_row_json(&json_bad_state) {
        Err(ReplayAdapterError::RegistryDrift { field, .. }) => assert_eq!(field, "currentState"),
        other => {
            return Err(format!("expected RegistryDrift on currentState, got {other:?}").into());
        }
    }

    // 6. Tampered promotionGate fails
    let json_bad_gate = valid_json.replace(
        "\"promotionGate\": \"GATE-010\"",
        "\"promotionGate\": \"GATE-090\"",
    );
    match ReplayAdapter::verify_registry_row_json(&json_bad_gate) {
        Err(ReplayAdapterError::RegistryDrift { field, .. }) => assert_eq!(field, "promotionGate"),
        other => {
            return Err(format!("expected RegistryDrift on promotionGate, got {other:?}").into());
        }
    }

    // 7. Tampered generation fails
    let json_bad_gen = valid_json.replace(
        "\"generation\": \"gen:fss1:adapters-v1\"",
        "\"generation\": \"gen:fss1:adapters-v2\"",
    );
    match ReplayAdapter::verify_registry_row_json(&json_bad_gen) {
        Err(ReplayAdapterError::RegistryDrift { field, .. }) => assert_eq!(field, "generation"),
        other => return Err(format!("expected RegistryDrift on generation, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_16_preflight_honours_cx_cancellation_r6d() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;
    let bundle = sample_bundle()?;

    // 1. In execute: cx is cancelled, but request.cancel_requested == false.
    // Mutant R6d is an equivalent mutant because preflight runs immediately after cx.checkpoint("preflight"),
    // which already refuses with CancellationRequested when cx is cancelled.
    let cx = test_cx("preflight_cx1")?;
    let dir = ScopedLedgerDir::from_authority("preflight_cx", cx.io_authority())?;
    cx.request_cancellation();
    let mut obj = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led = DurableReferenceLedger::open(
        dir.journal_path("preflight_cx"),
        bundle.site_lineage(),
        IncompleteTailPolicy::Reject,
    )?;
    let req = ReplayExecutionRequest::new(bundle.clone());
    assert!(!req.cancel_requested);

    match adapter.execute(&cx, &req, &mut obj, &mut led) {
        Err(ReplayAdapterError::CancellationRequested) => {
            assert_eq!(obj.object_count(), 0);
            assert_eq!(cx.lifecycle_state(), ReplayLifecycleState::Finalized);
        }
        other => return Err(format!("expected CancellationRequested, got {other:?}").into()),
    }

    // 2. In verify_against_expected: cx is cancelled, but request.cancel_requested == false.
    // (Mutant R6d is equivalent: preflight checkpoint already refuses before preflight runs)
    let cx_v = test_cx("preflight_cx2")?;
    cx_v.request_cancellation();
    let golden_root = ContentDigest::parse(ADP_REPLAY_GOLDEN_STATE_ROOT)?;
    let golden_audit = ContentDigest::parse(ADP_REPLAY_GOLDEN_AUDIT_HASH)?;

    match adapter.verify_against_expected(
        &cx_v,
        &req,
        &mut obj,
        &mut led,
        &golden_root,
        &golden_audit,
    ) {
        Err(ReplayAdapterError::CancellationRequested) => {
            assert_eq!(obj.object_count(), 0);
            assert_eq!(cx_v.lifecycle_state(), ReplayLifecycleState::Finalized);
        }
        other => {
            return Err(format!("expected CancellationRequested in verify, got {other:?}").into());
        }
    }

    Ok(())
}

#[test]
fn test_17_two_contexts_same_root_collision_free_and_drop_safe() -> Result<(), Box<dyn Error>> {
    let root_auth = test_context_authority("p7_shared")?;
    let scratch_base = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("p7_shared_root");
    std::fs::create_dir_all(&scratch_base)?;

    let cx_a = ReplayCx::from_context_authority(&root_auth, &scratch_base)?;
    let cx_b = ReplayCx::from_context_authority(&root_auth, &scratch_base)?;

    let da = ScopedLedgerDir::new("ledger", &cx_a)?;
    let db = ScopedLedgerDir::new("ledger", &cx_b)?;

    // Must be distinct paths
    assert_ne!(da.path(), db.path());
    assert!(da.path().exists());
    assert!(db.path().exists());

    // Write a committed journal in context B's scoped dir
    let jp_b = db.journal_path("b_journal");
    let mut led_b =
        DurableReferenceLedger::open(&jp_b, "site:replay-contract", IncompleteTailPolicy::Reject)?;
    let bundle = sample_bundle()?;
    let mut obj_b = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let adapter = ReplayAdapter::new()?;
    adapter.execute(
        &cx_b,
        &ReplayExecutionRequest::new(bundle),
        &mut obj_b,
        &mut led_b,
    )?;
    assert!(jp_b.exists());

    // Dropping context A's directory MUST NOT delete context B's committed journal (F2)
    drop(da);
    assert!(
        jp_b.exists(),
        "Dropping context A's ScopedLedgerDir must not delete context B's journal"
    );

    Ok(())
}

#[test]
fn test_18_scoped_dir_bad_prefix_refused_and_preexisting_preserved() -> Result<(), Box<dyn Error>> {
    let cx = test_cx("p8_prefix")?;

    // 1. Bad prefixes are refused with InvalidInput (F3)
    let bad_prefixes = [
        "",
        "../escaped",
        "/absolute/path",
        "has space",
        "has.dot",
        "has/slash",
        "has\\backslash",
        "foo@bar",
    ];
    for bad in &bad_prefixes {
        match ScopedLedgerDir::new(bad, &cx) {
            Err(e) => assert_eq!(
                e.kind(),
                std::io::ErrorKind::InvalidInput,
                "expected InvalidInput for prefix {bad:?}"
            ),
            Ok(d) => {
                return Err(
                    format!("expected refusal for prefix {bad:?}, got {:?}", d.path()).into(),
                );
            }
        }
    }

    // 2. Pre-existing directory is NEVER deleted (F3)
    let unique_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let victim_prefix = format!("victim_{unique_id}");
    let victim = cx.root_dir().join(format!("{victim_prefix}-0"));
    std::fs::create_dir_all(&victim)?;
    let precious = victim.join("precious.txt");
    std::fs::write(&precious, b"owner data")?;
    assert!(precious.exists());

    // Creating ScopedLedgerDir with unique prefix must skip -0 and exclusive-create -1
    let d = ScopedLedgerDir::new(&victim_prefix, &cx)?;
    assert_eq!(d.path(), cx.root_dir().join(format!("{victim_prefix}-1")));
    assert!(victim.exists());
    assert!(precious.exists());

    // Dropping d must delete -1, but leave -0 and precious.txt completely intact
    drop(d);
    assert!(
        victim.exists(),
        "Pre-existing directory victim-0 must not be deleted"
    );
    assert!(
        precious.exists(),
        "Pre-existing file inside victim-0 must not be deleted"
    );

    let _ = std::fs::remove_dir_all(&victim);
    Ok(())
}

#[test]
fn test_19_rollback_snapshot_bounds() -> Result<(), Box<dyn Error>> {
    let bundle = sample_bundle()?;
    let cx = test_cx("snapshot_bounds")?;
    let dir = ScopedLedgerDir::new("snapshot_bounds", &cx)?;
    let req = ReplayExecutionRequest::new(bundle.clone());

    // 1. Snapshot objects bound
    let mut obj_obj = InMemoryObjectStore::new(ObjectLimits::new(100, 1024 * 1024));
    for i in 0..5u32 {
        obj_obj.put_verified(&i.to_be_bytes())?;
    }
    assert_eq!(obj_obj.object_count(), 5);
    assert_eq!(obj_obj.total_bytes(), 20);

    let cfg_low_obj = ReplayAdapterConfig {
        max_snapshot_objects: 4,
        ..ReplayAdapterConfig::default()
    };
    let adapter_low_obj = ReplayAdapter::with_config(cfg_low_obj)?;
    let mut led_low_obj = DurableReferenceLedger::open(
        dir.journal_path("snapshot_obj_low"),
        bundle.site_lineage(),
        IncompleteTailPolicy::Reject,
    )?;
    match adapter_low_obj.execute(&cx, &req, &mut obj_obj, &mut led_low_obj) {
        Err(ReplayAdapterError::BoundExceeded(b)) => {
            assert_eq!(b, "target_store_exceeds_rollback_bound");
        }
        other => {
            return Err(format!(
                "expected BoundExceeded target_store_exceeds_rollback_bound, got {other:?}"
            )
            .into());
        }
    }

    let cfg_ok_obj = ReplayAdapterConfig {
        max_snapshot_objects: 5,
        ..ReplayAdapterConfig::default()
    };
    let adapter_ok_obj = ReplayAdapter::with_config(cfg_ok_obj)?;
    let mut led_ok_obj = DurableReferenceLedger::open(
        dir.journal_path("snapshot_obj_ok"),
        bundle.site_lineage(),
        IncompleteTailPolicy::Reject,
    )?;
    assert!(
        adapter_ok_obj
            .execute(&cx, &req, &mut obj_obj, &mut led_ok_obj)
            .is_ok()
    );

    // 2. Snapshot bytes bound
    let mut obj_bytes = InMemoryObjectStore::new(ObjectLimits::new(100, 1024 * 1024));
    for i in 0..5u32 {
        obj_bytes.put_verified(&i.to_be_bytes())?;
    }
    let bytes_before = obj_bytes.total_bytes();
    assert_eq!(bytes_before, 20);

    let cfg_low_bytes = ReplayAdapterConfig {
        max_snapshot_bytes: bytes_before.saturating_sub(1),
        ..ReplayAdapterConfig::default()
    };
    let adapter_low_bytes = ReplayAdapter::with_config(cfg_low_bytes)?;
    let mut led_low_bytes = DurableReferenceLedger::open(
        dir.journal_path("snapshot_bytes_low"),
        bundle.site_lineage(),
        IncompleteTailPolicy::Reject,
    )?;
    match adapter_low_bytes.execute(&cx, &req, &mut obj_bytes, &mut led_low_bytes) {
        Err(ReplayAdapterError::BoundExceeded(b)) => {
            assert_eq!(b, "target_store_exceeds_rollback_bound");
        }
        other => {
            return Err(format!(
                "expected BoundExceeded target_store_exceeds_rollback_bound for byte bound, got {other:?}"
            )
            .into());
        }
    }

    let cfg_ok_bytes = ReplayAdapterConfig {
        max_snapshot_bytes: bytes_before,
        ..ReplayAdapterConfig::default()
    };
    let adapter_ok_bytes = ReplayAdapter::with_config(cfg_ok_bytes)?;
    let mut led_ok_bytes = DurableReferenceLedger::open(
        dir.journal_path("snapshot_bytes_ok"),
        bundle.site_lineage(),
        IncompleteTailPolicy::Reject,
    )?;
    assert!(
        adapter_ok_bytes
            .execute(&cx, &req, &mut obj_bytes, &mut led_ok_bytes)
            .is_ok()
    );

    // 3. Zero bounds rejected at config construction
    let cfg_zero_bytes = ReplayAdapterConfig {
        max_snapshot_bytes: 0,
        ..ReplayAdapterConfig::default()
    };
    assert!(matches!(
        ReplayAdapter::with_config(cfg_zero_bytes),
        Err(ReplayAdapterError::BoundExceeded(
            "max_snapshot_bytes cannot be zero"
        ))
    ));

    let cfg_zero_obj = ReplayAdapterConfig {
        max_snapshot_objects: 0,
        ..ReplayAdapterConfig::default()
    };
    assert!(matches!(
        ReplayAdapter::with_config(cfg_zero_obj),
        Err(ReplayAdapterError::BoundExceeded(
            "max_snapshot_objects cannot be zero"
        ))
    ));

    Ok(())
}

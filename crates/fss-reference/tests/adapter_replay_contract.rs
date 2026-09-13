#![forbid(unsafe_code)]
//! Contract tests for ADP-REPLAY-001 deterministic replay adapter.
//!
//! Enforces:
//! 1. Row identity and typed protocol contract (ADP-REPLAY-001, T0, GATE-010, pure Rust)
//! 2. Deterministic replay produces identical state roots and audit hashes across runs
//! 3. Replay divergence detection fails closed with ERR-REPLAY-DIVERGED-001
//! 4. Incompatible generation rejection
//! 5. Cooperative cancellation handling
//! 6. Packet budget and hard bounds enforcement
//! 7. Zero unwrap, expect, or panic anywhere in test suite

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_core::{
    AdapterCapabilities, AdapterKind, CapsuleId, ContentDigest, CredentialMethod, IsolationMode,
    SensorId,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};
use fss_reference::{
    ADP_REPLAY_CURRENT_STATE, ADP_REPLAY_GENERATION, ADP_REPLAY_PROMOTION_GATE,
    ADP_REPLAY_PROTOCOL_PROFILE, ADP_REPLAY_ROW_ID, ADP_REPLAY_SURFACE, ADP_REPLAY_TIER,
    DeliveryDirective, DeliveryPlan, ERR_REPLAY_DIVERGED, ReplayAdapter, ReplayAdapterConfig,
    ReplayAdapterError, ReplayBundle, ReplayExecutionRequest, VirtualCameraSpec,
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

fn temp_ledger_path(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "fss-adp-replay-contract-{}-{suffix}.journal",
        std::process::id()
    ))
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

    Ok(())
}

#[test]
fn test_02_deterministic_replay_produces_identical_state_root() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;
    let bundle = sample_bundle()?;

    let p1 = temp_ledger_path("det1");
    let p2 = temp_ledger_path("det2");
    let _ = fs::remove_file(&p1);
    let _ = fs::remove_file(&p2);

    let mut obj1 = InMemoryObjectStore::new(ObjectLimits::new(128, 2 * 1024 * 1024));
    let mut led1 =
        DurableReferenceLedger::open(&p1, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;
    let req1 = ReplayExecutionRequest::new(bundle.clone());
    let out1 = adapter.execute(&req1, &mut obj1, &mut led1)?;

    let mut obj2 = InMemoryObjectStore::new(ObjectLimits::new(128, 2 * 1024 * 1024));
    let mut led2 =
        DurableReferenceLedger::open(&p2, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;
    let req2 = ReplayExecutionRequest::new(bundle);
    let out2 = adapter.execute(&req2, &mut obj2, &mut led2)?;

    assert_eq!(out1.audit_record.state_root, out2.audit_record.state_root);
    assert_eq!(out1.audit_record.audit_hash, out2.audit_record.audit_hash);
    assert_eq!(out1.audit_record.packets_delivered, 6);
    assert_eq!(out1.audit_record.packets_mutated, 1);
    assert_eq!(out1.capture.receipt, out2.capture.receipt);

    let _ = fs::remove_file(&p1);
    let _ = fs::remove_file(&p2);
    Ok(())
}

#[test]
fn test_03_incompatible_generation_rejected() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;
    let bundle = sample_bundle()?;
    let p = temp_ledger_path("incompat_gen");
    let _ = fs::remove_file(&p);

    let mut obj = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led =
        DurableReferenceLedger::open(&p, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;

    let mut req = ReplayExecutionRequest::new(bundle);
    req.generation = "gen:fss1:adapters-v2-future".to_string();

    match adapter.execute(&req, &mut obj, &mut led) {
        Err(ReplayAdapterError::IncompatibleGeneration { expected, actual }) => {
            assert_eq!(expected, "gen:fss1:adapters-v1");
            assert_eq!(actual, "gen:fss1:adapters-v2-future");
        }
        other => {
            return Err(format!("expected IncompatibleGeneration, got {other:?}").into());
        }
    }

    let _ = fs::remove_file(&p);
    Ok(())
}

#[test]
fn test_04_cooperative_cancellation() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;
    let bundle = sample_bundle()?;
    let p = temp_ledger_path("cancel");
    let _ = fs::remove_file(&p);

    let mut obj = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led =
        DurableReferenceLedger::open(&p, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;

    let mut req = ReplayExecutionRequest::new(bundle);
    req.cancel_requested = true;

    match adapter.execute(&req, &mut obj, &mut led) {
        Err(ReplayAdapterError::CancellationRequested) => {}
        other => {
            return Err(format!("expected CancellationRequested, got {other:?}").into());
        }
    }

    let _ = fs::remove_file(&p);
    Ok(())
}

#[test]
fn test_05_budget_exhaustion() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;
    let bundle = sample_bundle()?;
    let p = temp_ledger_path("budget");
    let _ = fs::remove_file(&p);

    let mut obj = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led =
        DurableReferenceLedger::open(&p, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;

    let mut req = ReplayExecutionRequest::new(bundle);
    req.max_packet_budget = Some(3); // bundle has 6 packets, so 3 is exhausted

    match adapter.execute(&req, &mut obj, &mut led) {
        Err(ReplayAdapterError::BudgetExhausted { requested, limit }) => {
            assert_eq!(requested, 6);
            assert_eq!(limit, 3);
        }
        other => {
            return Err(format!("expected BudgetExhausted, got {other:?}").into());
        }
    }

    let _ = fs::remove_file(&p);
    Ok(())
}

#[test]
fn test_06_bound_exceeded_config() -> Result<(), Box<dyn Error>> {
    let mut config = ReplayAdapterConfig::default();
    config.max_packets = 4; // bundle has 6
    let adapter = ReplayAdapter::with_config(config)?;

    let bundle = sample_bundle()?;
    let p = temp_ledger_path("bound_exceeded");
    let _ = fs::remove_file(&p);

    let mut obj = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led =
        DurableReferenceLedger::open(&p, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;

    let req = ReplayExecutionRequest::new(bundle);
    match adapter.execute(&req, &mut obj, &mut led) {
        Err(ReplayAdapterError::BoundExceeded(bound)) => {
            assert_eq!(bound, "packet_count");
        }
        other => {
            return Err(format!("expected BoundExceeded, got {other:?}").into());
        }
    }

    let _ = fs::remove_file(&p);
    Ok(())
}

#[test]
fn test_07_divergence_detection_and_reporting() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;
    let bundle = sample_bundle()?;
    let p = temp_ledger_path("diverge");
    let _ = fs::remove_file(&p);

    let mut obj = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led =
        DurableReferenceLedger::open(&p, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;

    let req = ReplayExecutionRequest::new(bundle);
    let wrong_digest = ContentDigest::sha256(b"intentionally wrong reference digest");

    match adapter.verify_against_expected(&req, &mut obj, &mut led, &wrong_digest) {
        Err(ReplayAdapterError::ReplayDiverged {
            expected_root,
            actual_root,
        }) => {
            assert_eq!(expected_root, wrong_digest);
            assert_ne!(actual_root, wrong_digest);
            let display = format!(
                "{}",
                ReplayAdapterError::ReplayDiverged {
                    expected_root,
                    actual_root
                }
            );
            assert!(display.contains(ERR_REPLAY_DIVERGED));
        }
        other => {
            return Err(format!("expected ReplayDiverged, got {other:?}").into());
        }
    }

    let _ = fs::remove_file(&p);
    Ok(())
}

#[test]
fn test_08_verify_against_expected_success() -> Result<(), Box<dyn Error>> {
    let adapter = ReplayAdapter::new()?;
    let bundle = sample_bundle()?;
    let p1 = temp_ledger_path("exp_succ1");
    let p2 = temp_ledger_path("exp_succ2");
    let _ = fs::remove_file(&p1);
    let _ = fs::remove_file(&p2);

    // Compute ground truth root
    let mut obj1 = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led1 =
        DurableReferenceLedger::open(&p1, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;
    let req1 = ReplayExecutionRequest::new(bundle.clone());
    let out1 = adapter.execute(&req1, &mut obj1, &mut led1)?;
    let known_root = out1.audit_record.state_root;

    // Verify against known root on second fresh ledger
    let mut obj2 = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));
    let mut led2 =
        DurableReferenceLedger::open(&p2, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;
    let req2 = ReplayExecutionRequest::new(bundle);
    let out2 = adapter.verify_against_expected(&req2, &mut obj2, &mut led2, &known_root)?;
    assert_eq!(out2.audit_record.state_root, known_root);

    let _ = fs::remove_file(&p1);
    let _ = fs::remove_file(&p2);
    Ok(())
}

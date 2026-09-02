use std::error::Error;
use std::fs;

use fss_core::{CapsuleId, ProbabilityInterval, SensorId};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits, VerifiedObjectCatalog};

use crate::{
    DeliveryDirective, DeliveryPlan, MockAbstentionReason, MockModelOutcome, MockModelScript,
    MockModelSpec, MockSemanticLabel, VirtualCameraSpec, execute_mock_model, run_reference_capture,
};

fn spec() -> Result<VirtualCameraSpec, Box<dyn Error>> {
    Ok(VirtualCameraSpec {
        capture_id: CapsuleId::parse("capture:model:1")?,
        sensor_id: SensorId::parse("sensor:model-camera")?,
        seed: 42,
        packet_count: 3,
        packet_bytes: 24,
        start_ns: 1_000,
        period_ns: 1_000_000,
        uncertainty_ns: 100,
    })
}

fn temp_journal(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "fss-mock-model-{}-{name}.journal",
        std::process::id()
    ))
}

#[test]
fn exact_delivery_produces_retained_derived_finding() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("exact");
    let _ = fs::remove_file(&path);
    let spec = spec()?;
    let plan = DeliveryPlan::identity(spec.packet_count)?;
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(128, 1024 * 1024));
    let mut ledger =
        DurableReferenceLedger::open(&path, "site:model", IncompleteTailPolicy::Reject)?;
    let capture = run_reference_capture(&spec, &plan, &mut objects, &mut ledger)?;
    let model = MockModelSpec::new(
        "mock:model:person:v1",
        MockModelScript::RequireExactDelivery {
            label: MockSemanticLabel::PersonLike,
            probability: ProbabilityInterval::new(0.8, 0.9)?,
        },
    )?;

    let result = execute_mock_model(&model, &capture, &mut objects)?;
    assert!(matches!(
        result.outcome,
        MockModelOutcome::Finding {
            label: MockSemanticLabel::PersonLike,
            ..
        }
    ));
    assert_eq!(result.input_capture_root, capture.receipt.capture_root);
    assert_eq!(result.continuity_digest, capture.receipt.continuity_digest);
    objects.require_verified(result.object_digest())?;

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn degraded_delivery_causes_explicit_abstention_when_required() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("abstain");
    let _ = fs::remove_file(&path);
    let spec = spec()?;
    let plan = DeliveryPlan::new(vec![
        DeliveryDirective::exact(1),
        DeliveryDirective::exact(3),
    ])?;
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(128, 1024 * 1024));
    let mut ledger =
        DurableReferenceLedger::open(&path, "site:model", IncompleteTailPolicy::Reject)?;
    let capture = run_reference_capture(&spec, &plan, &mut objects, &mut ledger)?;
    let model = MockModelSpec::new(
        "mock:model:person:v1",
        MockModelScript::RequireExactDelivery {
            label: MockSemanticLabel::PersonLike,
            probability: ProbabilityInterval::new(0.8, 0.9)?,
        },
    )?;

    let result = execute_mock_model(&model, &capture, &mut objects)?;
    assert_eq!(
        result.outcome,
        MockModelOutcome::Abstained {
            reason: MockAbstentionReason::DeliveryDegraded,
        }
    );
    assert_eq!(result.input_capture_root, capture.receipt.capture_root);
    objects.require_verified(result.object_digest())?;

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn model_generation_identity_changes_result_identity() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("generation");
    let _ = fs::remove_file(&path);
    let spec = spec()?;
    let plan = DeliveryPlan::identity(spec.packet_count)?;
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(128, 1024 * 1024));
    let mut ledger =
        DurableReferenceLedger::open(&path, "site:model", IncompleteTailPolicy::Reject)?;
    let capture = run_reference_capture(&spec, &plan, &mut objects, &mut ledger)?;
    let script = MockModelScript::Fixed {
        label: MockSemanticLabel::AnimalLike,
        probability: ProbabilityInterval::new(0.6, 0.75)?,
    };
    let first = MockModelSpec::new("mock:model:animal:v1", script.clone())?;
    let second = MockModelSpec::new("mock:model:animal:v2", script)?;

    let first_result = execute_mock_model(&first, &capture, &mut objects)?;
    let second_result = execute_mock_model(&second, &capture, &mut objects)?;
    assert_ne!(first.spec_digest(), second.spec_digest());
    assert_ne!(first_result.object_digest(), second_result.object_digest());

    let _ = fs::remove_file(path);
    Ok(())
}

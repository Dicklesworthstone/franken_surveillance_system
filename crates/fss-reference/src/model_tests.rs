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

fn delivered_capsule(gap_before: bool) -> Result<fss_core::SensorCapsule, Box<dyn Error>> {
    use fss_core::{
        CaptureInterval, ClockBasis, SensorCapsule, SensorSourceBytesSpec, StreamId, TimestampNs,
    };
    Ok(SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
        capsule_id: CapsuleId::parse("capsule:model-camera:7")?,
        sensor_id: SensorId::parse("sensor:model-camera")?,
        stream_id: StreamId::parse("stream:model-camera")?,
        sequence: 7,
        capture: CaptureInterval::new(TimestampNs(7_000), TimestampNs(8_000))?,
        receive_time: TimestampNs(8_000),
        clock_basis: ClockBasis::DeviceMonotonic,
        source: b"packet:model-camera:7",
        frame_count: 1,
        gap_before,
    })?)
}

/// fss-f8jls: the analysed-nothing outcome names the exact capsule the generation analysed, is
/// retained as bytes that decode back exactly, and is never negative evidence on its own.
#[test]
fn analysed_nothing_binds_the_exact_capsule_and_round_trips() -> Result<(), Box<dyn Error>> {
    use fss_core::{CanonicalEncode as _, ContentDigest, ContractError};

    use crate::{MockModelError, MockModelResult, analyse_mock_capsule};

    let capsule = delivered_capsule(false)?;
    let capsule_digest = ContentDigest::sha256(&capsule.canonical_bytes());
    let spec = MockModelSpec::new("mock:model:presence:v1", MockModelScript::NothingFound)?;
    let result = analyse_mock_capsule(&spec, &capsule);
    assert_eq!(
        result.outcome,
        MockModelOutcome::NothingFound {
            analysed_capsule: capsule_digest
        }
    );
    assert_eq!(result.continuity_digest, capsule_digest);
    assert_eq!(result.input_capture_root, capsule.source_digest);
    assert_eq!(result.sensor_id, capsule.sensor_id);
    assert_eq!(result.generation_id, "mock:model:presence:v1");
    assert_eq!(result.model_spec_digest, spec.spec_digest());
    assert!(matches!(
        result.outcome.assert_not_negative_evidence(),
        Err(MockModelError::AnalysedNothingRequiresCoverageWitness { analysed_capsule })
            if analysed_capsule == capsule_digest
    ));

    // Retained bytes decode to exactly the result, and only against their own digest.
    let bytes = result.canonical_bytes();
    assert_eq!(
        MockModelResult::from_retained_bytes(&bytes, result.object_digest())?,
        result
    );
    assert_eq!(
        MockModelResult::from_retained_bytes(&bytes, ContentDigest::sha256(b"other")),
        Err(ContractError::DigestMismatch)
    );
    // Another capsule or another generation is another result.
    let other = analyse_mock_capsule(&spec, &delivered_capsule(true)?);
    assert_ne!(other.object_digest(), result.object_digest());
    let other_generation =
        MockModelSpec::new("mock:model:presence:v2", MockModelScript::NothingFound)?;
    let regenerated = analyse_mock_capsule(&other_generation, &capsule);
    assert_ne!(regenerated.model_spec_digest, result.model_spec_digest);
    assert_ne!(regenerated.object_digest(), result.object_digest());

    // Findings and abstentions round-trip too.
    let finding_spec = MockModelSpec::new(
        "mock:model:person:v1",
        MockModelScript::RequireExactDelivery {
            label: MockSemanticLabel::PersonLike,
            probability: ProbabilityInterval::new(0.8, 0.9)?,
        },
    )?;
    for result in [
        analyse_mock_capsule(&finding_spec, &capsule),
        analyse_mock_capsule(&finding_spec, &delivered_capsule(true)?),
    ] {
        let bytes = result.canonical_bytes();
        assert_eq!(
            MockModelResult::from_retained_bytes(&bytes, result.object_digest())?,
            result
        );
    }
    assert_eq!(
        analyse_mock_capsule(&finding_spec, &delivered_capsule(true)?).outcome,
        MockModelOutcome::Abstained {
            reason: MockAbstentionReason::DeliveryDegraded
        }
    );
    Ok(())
}

/// A capture is not one capsule: the capture seam refuses a nothing-found generation rather than
/// invent which capsule it analysed.
#[test]
fn the_capture_seam_refuses_an_analysed_nothing_generation() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("nothing-found");
    let _ = fs::remove_file(&path);
    let spec = spec()?;
    let plan = DeliveryPlan::identity(spec.packet_count)?;
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(128, 1024 * 1024));
    let mut ledger =
        DurableReferenceLedger::open(&path, "site:model", IncompleteTailPolicy::Reject)?;
    let capture = run_reference_capture(&spec, &plan, &mut objects, &mut ledger)?;
    let model = MockModelSpec::new("mock:model:presence:v1", MockModelScript::NothingFound)?;
    assert!(matches!(
        execute_mock_model(&model, &capture, &mut objects),
        Err(crate::ReferenceError::InvalidSpec(
            "nothing_found_requires_capsule_analysis"
        ))
    ));
    let _ = fs::remove_file(path);
    Ok(())
}

use std::error::Error;
use std::fs;

use fss_core::{CaptureInterval, CapsuleId, EventId, EventState, ProbabilityInterval, SensorId};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectError, ObjectLimits};

use crate::{
    DeliveryPlan, MockModelScript, MockModelSpec, MockSemanticLabel, ReferenceError,
    ReferenceModelObservation, ReferencePolicyAction, VirtualCameraSpec, evaluate_unknown_presence,
    execute_mock_model, publish_reference_event, run_reference_capture,
};

fn temp_journal(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "fss-reference-policy-{}-{name}.journal",
        std::process::id()
    ))
}

fn capture_and_model(
    capture_name: &str,
    sensor_name: &str,
    seed: u64,
    label: MockSemanticLabel,
    failure_domain: &str,
    objects: &mut InMemoryObjectStore,
    ledger: &mut DurableReferenceLedger,
) -> Result<ReferenceModelObservation, Box<dyn Error>> {
    let spec = VirtualCameraSpec {
        capture_id: CapsuleId::parse(capture_name)?,
        sensor_id: SensorId::parse(sensor_name)?,
        seed,
        packet_count: 3,
        packet_bytes: 32,
        start_ns: i128::from(seed) * 1_000,
        period_ns: 1_000_000,
        uncertainty_ns: 1_000,
    };
    let capture = run_reference_capture(
        &spec,
        &DeliveryPlan::identity(spec.packet_count)?,
        objects,
        ledger,
    )?;
    let model = MockModelSpec::new(
        format!("mock:{sensor_name}:v1"),
        MockModelScript::Fixed {
            label,
            probability: ProbabilityInterval::new(0.99, 1.0)?,
        },
    )?;
    let result = execute_mock_model(&model, &capture, objects)?;
    let first = capture.source_packets.first().ok_or(ReferenceError::InvalidSpec(
        "source_packet_count",
    ))?;
    let last = capture.source_packets.last().ok_or(ReferenceError::InvalidSpec(
        "source_packet_count",
    ))?;
    let interval = CaptureInterval::new(first.capture.earliest, last.capture.latest)?;
    Ok(ReferenceModelObservation::new(
        result,
        failure_domain,
        interval,
    )?)
}

#[test]
fn independent_person_findings_enable_alert_preparation_only() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("independent");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(256, 4 * 1024 * 1024));
    let mut ledger =
        DurableReferenceLedger::open(&path, "site:policy", IncompleteTailPolicy::Reject)?;
    let first = capture_and_model(
        "capture:policy:a",
        "sensor:policy:a",
        10,
        MockSemanticLabel::PersonLike,
        "power:a",
        &mut objects,
        &mut ledger,
    )?;
    let second = capture_and_model(
        "capture:policy:b",
        "sensor:policy:b",
        20,
        MockSemanticLabel::PersonLike,
        "power:b",
        &mut objects,
        &mut ledger,
    )?;

    let decision = evaluate_unknown_presence(
        EventId::parse("event:unknown-person:1")?,
        vec![second, first],
    )?;
    assert_eq!(decision.event.state, EventState::Corroborated);
    assert_eq!(decision.action, ReferencePolicyAction::PrepareAlert);
    assert_eq!(decision.event.probability.lower, 0.0);
    assert_eq!(decision.event.probability.upper, 1.0);
    assert_eq!(ledger.current().anchor.commit_sequence, 2);

    let receipt = publish_reference_event(&decision, &mut objects, &mut ledger)?;
    assert_eq!(receipt.authority_anchor.commit_sequence, 3);
    assert_eq!(ledger.batches().len(), 3);
    assert_eq!(ledger.batches()[2].deltas[0].payload_digest, receipt.event_root);
    assert_eq!(
        ledger.batches()[2].deltas[0].witness_digest,
        Some(receipt.event_revision_digest)
    );

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn shared_failure_domain_cannot_self_corroborate() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("shared-domain");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(256, 4 * 1024 * 1024));
    let mut ledger =
        DurableReferenceLedger::open(&path, "site:policy", IncompleteTailPolicy::Reject)?;
    let first = capture_and_model(
        "capture:policy:c",
        "sensor:policy:c",
        30,
        MockSemanticLabel::PersonLike,
        "switch:one",
        &mut objects,
        &mut ledger,
    )?;
    let second = capture_and_model(
        "capture:policy:d",
        "sensor:policy:d",
        40,
        MockSemanticLabel::PersonLike,
        "switch:one",
        &mut objects,
        &mut ledger,
    )?;

    let decision = evaluate_unknown_presence(
        EventId::parse("event:unknown-person:2")?,
        vec![first, second],
    )?;
    assert_eq!(decision.event.state, EventState::Witnessed);
    assert_eq!(decision.action, ReferencePolicyAction::Hold);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn contradictory_animal_finding_forces_indeterminate_hold() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("conflict");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(256, 4 * 1024 * 1024));
    let mut ledger =
        DurableReferenceLedger::open(&path, "site:policy", IncompleteTailPolicy::Reject)?;
    let person = capture_and_model(
        "capture:policy:e",
        "sensor:policy:e",
        50,
        MockSemanticLabel::PersonLike,
        "power:e",
        &mut objects,
        &mut ledger,
    )?;
    let animal = capture_and_model(
        "capture:policy:f",
        "sensor:policy:f",
        60,
        MockSemanticLabel::AnimalLike,
        "power:f",
        &mut objects,
        &mut ledger,
    )?;

    let decision = evaluate_unknown_presence(
        EventId::parse("event:unknown-person:3")?,
        vec![person, animal],
    )?;
    assert_eq!(decision.event.state, EventState::Indeterminate);
    assert_eq!(decision.action, ReferencePolicyAction::Hold);
    assert!(decision.event.evidence.iter().any(|edge| !edge.supports));

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn same_model_receipt_cannot_be_laundered_into_two_domains() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("duplicate-receipt");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(128, 2 * 1024 * 1024));
    let mut ledger =
        DurableReferenceLedger::open(&path, "site:policy", IncompleteTailPolicy::Reject)?;
    let first = capture_and_model(
        "capture:policy:g",
        "sensor:policy:g",
        70,
        MockSemanticLabel::PersonLike,
        "domain:one",
        &mut objects,
        &mut ledger,
    )?;
    let second = ReferenceModelObservation::new(
        first.result.clone(),
        "domain:two",
        first.interval,
    )?;

    assert!(matches!(
        evaluate_unknown_presence(
            EventId::parse("event:unknown-person:4")?,
            vec![first, second],
        ),
        Err(ReferenceError::InvalidSpec("duplicate_model_result"))
    ));

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn event_publication_requires_retained_model_objects() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("missing-model-object");
    let _ = fs::remove_file(&path);
    let mut source_objects = InMemoryObjectStore::new(ObjectLimits::new(256, 4 * 1024 * 1024));
    let mut ledger =
        DurableReferenceLedger::open(&path, "site:policy", IncompleteTailPolicy::Reject)?;
    let first = capture_and_model(
        "capture:policy:h",
        "sensor:policy:h",
        80,
        MockSemanticLabel::PersonLike,
        "domain:h",
        &mut source_objects,
        &mut ledger,
    )?;
    let decision = evaluate_unknown_presence(
        EventId::parse("event:unknown-person:5")?,
        vec![first],
    )?;
    let mut empty_objects = InMemoryObjectStore::new(ObjectLimits::new(64, 1024 * 1024));

    assert!(matches!(
        publish_reference_event(&decision, &mut empty_objects, &mut ledger),
        Err(ReferenceError::Object(ObjectError::Missing(_)))
    ));
    assert_eq!(ledger.current().anchor.commit_sequence, 1);

    let _ = fs::remove_file(path);
    Ok(())
}

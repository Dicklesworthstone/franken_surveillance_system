use std::error::Error;
use std::fs;

use fss_core::{
    CapsuleId, CaptureInterval, EffectJournal, EffectState, EventId, IdempotencyKey, ObjectId,
    ObligationId, OperationId, Plane, ProbabilityInterval, SensorId, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};

use crate::{
    DeliveryPlan, MockModelScript, MockModelSpec, MockSemanticLabel, ReferenceAlertPlan,
    ReferenceAlertProvider, ReferenceError, ReferenceModelObservation, ReferenceProviderBehavior,
    VirtualCameraSpec, dispatch_reference_alert, evaluate_unknown_presence, execute_mock_model,
    prepare_reference_alert, publish_reference_alert_outcome, publish_reference_event,
    run_reference_capture,
};

struct OutcomeHarness {
    path: std::path::PathBuf,
    objects: InMemoryObjectStore,
    authority: DurableReferenceLedger,
    journal: EffectJournal,
    plan: ReferenceAlertPlan,
    event_object_id: ObjectId,
}

impl OutcomeHarness {
    fn new(name: &str, behavior: ReferenceProviderBehavior) -> Result<Self, Box<dyn Error>> {
        let path = std::env::temp_dir().join(format!(
            "fss-reference-outcome-{}-{name}.journal",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let mut objects = InMemoryObjectStore::new(ObjectLimits::new(1024, 16 * 1024 * 1024));
        let mut authority =
            DurableReferenceLedger::open(&path, "site:outcome", IncompleteTailPolicy::Reject)?;

        let first = observation(
            name,
            "a",
            41,
            "power:outcome:a",
            &mut objects,
            &mut authority,
        )?;
        let second = observation(
            name,
            "b",
            82,
            "power:outcome:b",
            &mut objects,
            &mut authority,
        )?;
        let event_id = EventId::parse(format!("event:outcome:{name}"))?;
        let decision = evaluate_unknown_presence(event_id.clone(), vec![first, second])?;
        let event_receipt = publish_reference_event(&decision, &mut objects, &mut authority)?;

        let mut journal = EffectJournal::new();
        let plan = prepare_reference_alert(
            &decision,
            &event_receipt,
            &authority,
            OperationId::parse(format!("operation:outcome:{name}"))?,
            IdempotencyKey::parse(format!("idempotency:outcome:{name}"))?,
            ObligationId::parse(format!("obligation:outcome:{name}"))?,
            "operator:oncall",
            TimestampNs(100),
            &mut journal,
        )?;
        let mut provider = ReferenceAlertProvider::new();
        let _ = dispatch_reference_alert(
            &plan,
            behavior,
            TimestampNs(101),
            TimestampNs(102),
            &mut journal,
            &mut provider,
        )?;

        Ok(Self {
            path,
            objects,
            authority,
            journal,
            plan,
            event_object_id: ObjectId::parse(format!("object:event:{}", event_id.as_str()))?,
        })
    }

    fn cleanup(self) {
        let path = self.path.clone();
        drop(self);
        let _ = fs::remove_file(path);
    }
}

fn observation(
    test_name: &str,
    lane: &str,
    seed: u64,
    failure_domain: &str,
    objects: &mut InMemoryObjectStore,
    ledger: &mut DurableReferenceLedger,
) -> Result<ReferenceModelObservation, Box<dyn Error>> {
    let spec = VirtualCameraSpec {
        capture_id: CapsuleId::parse(format!("capture:outcome:{test_name}:{lane}"))?,
        sensor_id: SensorId::parse(format!("sensor:outcome:{test_name}:{lane}"))?,
        seed,
        packet_count: 3,
        packet_bytes: 32,
        start_ns: i128::from(seed) * 10_000,
        period_ns: 1_000_000,
        uncertainty_ns: 100,
    };
    let capture = run_reference_capture(
        &spec,
        &DeliveryPlan::identity(spec.packet_count)?,
        objects,
        ledger,
    )?;
    let model = MockModelSpec::new(
        format!("mock:outcome:{test_name}:{lane}:v1"),
        MockModelScript::Fixed {
            label: MockSemanticLabel::PersonLike,
            probability: ProbabilityInterval::new(0.95, 1.0)?,
        },
    )?;
    let result = execute_mock_model(&model, &capture, objects)?;
    let first = capture
        .source_packets
        .first()
        .ok_or(ReferenceError::InvalidSpec("source_packet_count"))?;
    let last = capture
        .source_packets
        .last()
        .ok_or(ReferenceError::InvalidSpec("source_packet_count"))?;
    Ok(ReferenceModelObservation::new(
        result,
        failure_domain,
        CaptureInterval::new(first.capture.earliest, last.capture.latest)?,
    )?)
}

#[test]
fn verified_outcome_is_authoritative_and_exact_retry_is_read_like() -> Result<(), Box<dyn Error>> {
    let mut harness = OutcomeHarness::new("verified", ReferenceProviderBehavior::Deliver)?;
    let before_batches = harness.authority.batches().len();

    let first = publish_reference_alert_outcome(
        &harness.plan,
        &harness.journal,
        &mut harness.objects,
        &mut harness.authority,
    )?;
    assert_eq!(first.outcome.operation_receipt.state, EffectState::Verified);
    let proof = first
        .outcome
        .proof_object_digest
        .ok_or(ReferenceError::InvalidSpec("missing_provider_proof"))?;
    assert_eq!(first.outcome.operation_receipt.result_digest, Some(proof));
    assert!(!harness.objects.read_verified(proof)?.is_empty());
    assert!(harness.objects.verify_closure(first.outcome_root)? >= 5);

    let current = harness
        .authority
        .current()
        .objects
        .get(&first.effect_object_id)
        .ok_or(ReferenceError::InvalidSpec("missing_effect_object"))?;
    assert_eq!(current.generation, 1);
    assert_eq!(current.family, "alert_effect_outcome");
    assert_eq!(current.plane, Plane::Effect);
    assert_eq!(current.payload_digest, first.outcome_root);
    let published_delta = harness
        .authority
        .batches()
        .last()
        .and_then(|batch| batch.deltas.first())
        .ok_or(ReferenceError::InvalidSpec("missing_effect_delta"))?;
    assert_eq!(
        published_delta.witness_digest,
        Some(first.outcome.operation_receipt.receipt_digest())
    );

    let second = publish_reference_alert_outcome(
        &harness.plan,
        &harness.journal,
        &mut harness.objects,
        &mut harness.authority,
    )?;
    assert_eq!(second.outcome_root, first.outcome_root);
    assert_eq!(second.authority_anchor, first.authority_anchor);
    assert_eq!(harness.authority.batches().len(), before_batches + 1);

    harness.cleanup();
    Ok(())
}

#[test]
fn indeterminate_outcome_preserves_event_and_does_not_invent_proof() -> Result<(), Box<dyn Error>> {
    let mut harness = OutcomeHarness::new(
        "indeterminate",
        ReferenceProviderBehavior::LoseAckAfterDelivery,
    )?;
    let event_before = harness
        .authority
        .current()
        .objects
        .get(&harness.event_object_id)
        .ok_or(ReferenceError::InvalidSpec("missing_event_object"))?
        .clone();

    let receipt = publish_reference_alert_outcome(
        &harness.plan,
        &harness.journal,
        &mut harness.objects,
        &mut harness.authority,
    )?;
    assert_eq!(
        receipt.outcome.operation_receipt.state,
        EffectState::Indeterminate
    );
    assert_eq!(receipt.outcome.operation_receipt.result_digest, None);
    assert_eq!(receipt.outcome.proof_object_digest, None);
    assert_eq!(
        harness
            .authority
            .current()
            .objects
            .get(&harness.event_object_id),
        Some(&event_before)
    );

    harness.cleanup();
    Ok(())
}

#[test]
fn known_failure_retains_non_delivery_proof() -> Result<(), Box<dyn Error>> {
    let mut harness = OutcomeHarness::new("failed", ReferenceProviderBehavior::FailBeforeDelivery)?;

    let receipt = publish_reference_alert_outcome(
        &harness.plan,
        &harness.journal,
        &mut harness.objects,
        &mut harness.authority,
    )?;
    assert_eq!(receipt.outcome.operation_receipt.state, EffectState::Failed);
    let proof = receipt
        .outcome
        .proof_object_digest
        .ok_or(ReferenceError::InvalidSpec("missing_failure_proof"))?;
    assert_eq!(receipt.outcome.operation_receipt.result_digest, Some(proof));
    assert!(!harness.objects.read_verified(proof)?.is_empty());

    harness.cleanup();
    Ok(())
}

#[test]
fn mutated_plan_is_rejected_before_object_or_authority_mutation() -> Result<(), Box<dyn Error>> {
    let mut harness = OutcomeHarness::new("tampered", ReferenceProviderBehavior::Deliver)?;
    let object_count = harness.objects.object_count();
    let batch_count = harness.authority.batches().len();
    let mut tampered = harness.plan.clone();
    tampered.channel = "operator:other".to_owned();

    assert!(matches!(
        publish_reference_alert_outcome(
            &tampered,
            &harness.journal,
            &mut harness.objects,
            &mut harness.authority,
        ),
        Err(ReferenceError::InvalidSpec("alert_plan_integrity"))
    ));
    assert_eq!(harness.objects.object_count(), object_count);
    assert_eq!(harness.authority.batches().len(), batch_count);

    harness.cleanup();
    Ok(())
}

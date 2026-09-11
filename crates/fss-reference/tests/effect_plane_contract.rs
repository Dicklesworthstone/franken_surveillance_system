#![forbid(unsafe_code)]
//! Integration contract tests for effect plane invariants and defect hunt fixes F2-F6.

use std::error::Error;
use std::fs;

use fss_core::{
    CapsuleId, CaptureInterval, ContentDigest, ContractError, EffectIntent, EffectJournal,
    EffectState, EventId, EventState, IdempotencyKey, ObligationId, ObligationState, OperationId,
    ProbabilityInterval, SensorId, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};
use fss_reference::{
    DeliveryPlan, MockModelScript, MockModelSpec, MockSemanticLabel, PrepareAlertParams,
    ProviderDispatch, REFERENCE_ALERT_TERMINAL_PREDICATE, ReferenceAlertPlan,
    ReferenceAlertProvider, ReferenceError, ReferenceEventReceipt, ReferenceModelObservation,
    ReferencePolicyAction, ReferencePolicyDecision, ReferenceProviderBehavior, VirtualCameraSpec,
    dispatch_reference_alert, evaluate_unknown_presence, execute_mock_model,
    observe_reference_alert, prepare_reference_alert, publish_reference_alert_outcome,
    publish_reference_event, reconcile_reference_alert, run_reference_capture,
    verify_reference_alert,
};

fn temp_journal(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "fss-effect-plane-contract-{}-{name}.journal",
        std::process::id()
    ))
}

fn observation(
    capture_name: &str,
    sensor_name: &str,
    seed: u64,
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
            label: MockSemanticLabel::PersonLike,
            probability: ProbabilityInterval::new(0.99, 1.0)?,
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
    let interval = CaptureInterval::new(first.capture.earliest, last.capture.latest)?;
    Ok(ReferenceModelObservation::new(
        result,
        failure_domain,
        interval,
    )?)
}

fn eligible_event(
    objects: &mut InMemoryObjectStore,
    ledger: &mut DurableReferenceLedger,
) -> Result<(ReferencePolicyDecision, ReferenceEventReceipt), Box<dyn Error>> {
    let first = observation(
        "capture:effect:a",
        "sensor:effect:a",
        11,
        "power:effect:a",
        objects,
        ledger,
    )?;
    let second = observation(
        "capture:effect:b",
        "sensor:effect:b",
        22,
        "power:effect:b",
        objects,
        ledger,
    )?;
    let decision = evaluate_unknown_presence(
        EventId::parse("event:effect:unknown-person")?,
        vec![first, second],
    )?;
    let receipt = publish_reference_event(&decision, objects, ledger)?;
    Ok((decision, receipt))
}

fn prepare_alert(
    decision: &ReferencePolicyDecision,
    event_receipt: &ReferenceEventReceipt,
    authority: &DurableReferenceLedger,
    journal: &mut EffectJournal,
) -> Result<ReferenceAlertPlan, ReferenceError> {
    prepare_reference_alert(
        PrepareAlertParams {
            decision,
            event_receipt,
            authority,
            operation_id: OperationId::parse("operation:effect:alert:1")?,
            idempotency_key: IdempotencyKey::parse("idempotency:effect:alert:1")?,
            obligation_id: ObligationId::parse("obligation:effect:alert:1")?,
            channel: "operator:oncall".to_owned(),
            now: TimestampNs(100),
        },
        journal,
    )
}

/// F2: ReferenceAlertProvider binds full intent (idempotency key, operation_id, request_digest,
/// precondition_digest, effect_class). Conflicting intents sharing the same idempotency key are
/// rejected with typed conflict errors.
#[test]
fn test_f2_idempotency_key_shared_by_different_intents_is_typed_conflict()
-> Result<(), Box<dyn Error>> {
    let mut provider = ReferenceAlertProvider::new();
    let shared_idempotency_key = IdempotencyKey::parse("idempotency:alert:shared")?;
    let request_digest = ContentDigest::sha256(b"alert-request-body");

    let intent_a = EffectIntent {
        operation_id: OperationId::parse("operation:alert:a")?,
        idempotency_key: shared_idempotency_key.clone(),
        effect_class: "alert.dispatch".to_owned(),
        request_digest,
        precondition_digest: ContentDigest::sha256(b"precondition-at-anchor-1"),
    };

    let intent_b = EffectIntent {
        operation_id: OperationId::parse("operation:alert:b")?,
        idempotency_key: shared_idempotency_key,
        effect_class: "alert.dispatch".to_owned(),
        request_digest,
        precondition_digest: ContentDigest::sha256(b"precondition-at-anchor-2"),
    };

    if intent_a == intent_b {
        return Err("intents must differ for this test".into());
    }

    // First dispatch succeeds
    let dispatch_a = provider.dispatch(&intent_a, ReferenceProviderBehavior::Deliver);
    match dispatch_a {
        ProviderDispatch::Delivered(proof) => {
            let expected_proof = intent_a.terminal_proof(REFERENCE_ALERT_TERMINAL_PREDICATE);
            if proof != expected_proof {
                return Err("proof digest mismatch on delivered intent a".into());
            }
        }
        _ => return Err("expected Delivered for intent_a".into()),
    }

    // Exact retry with intent_a succeeds idempotently
    let dispatch_a_retry = provider.dispatch(&intent_a, ReferenceProviderBehavior::Deliver);
    if dispatch_a_retry != dispatch_a {
        return Err("exact retry must return identical delivery proof".into());
    }

    let lookup_a = provider.lookup(&intent_a)?;
    if lookup_a.is_none() {
        return Err("lookup for intent_a should return Some(proof)".into());
    }

    // Conflicting dispatch with intent_b under same idempotency key is rejected
    let dispatch_b = provider.dispatch(&intent_b, ReferenceProviderBehavior::Deliver);
    if dispatch_b != ProviderDispatch::ConflictingIdempotency {
        return Err(
            "differing intent under shared idempotency key must return ConflictingIdempotency"
                .into(),
        );
    }

    // Lookup with intent_b under same idempotency key returns typed IdempotencyConflict
    match provider.lookup(&intent_b) {
        Err(ReferenceError::Contract(ContractError::IdempotencyConflict)) => {}
        other => {
            return Err(format!(
                "expected IdempotencyConflict on lookup of conflicting intent, got: {other:?}"
            )
            .into());
        }
    }

    Ok(())
}

/// F3: reconcile_verified and transition reject forged or replayed terminal proofs.
#[test]
fn test_f3_receipt_forgery_and_replay_rejected() -> Result<(), Box<dyn Error>> {
    let mut journal = EffectJournal::new();
    let op_id = OperationId::parse("operation:alert:target")?;
    let intent_a = EffectIntent {
        operation_id: op_id.clone(),
        idempotency_key: IdempotencyKey::parse("idempotency:alert:target")?,
        effect_class: "alert.dispatch".to_owned(),
        request_digest: ContentDigest::sha256(b"target-request"),
        precondition_digest: ContentDigest::sha256(b"target-precondition"),
    };
    let obligation_id = ObligationId::parse("obligation:alert:target")?;
    journal.prepare(
        intent_a.clone(),
        obligation_id.clone(),
        REFERENCE_ALERT_TERMINAL_PREDICATE,
        TimestampNs(100),
    )?;
    journal.transition(&op_id, EffectState::Committed, TimestampNs(101), None, None)?;
    journal.mark_indeterminate(&op_id, TimestampNs(102), "lost_ack")?;

    // Forged proof is rejected
    let forged_proof = ContentDigest::sha256(b"completely_unrelated_forged_proof_bytes");
    let forge_result = journal.reconcile_verified(&op_id, forged_proof, TimestampNs(103));
    match forge_result {
        Err(ContractError::InvalidDigest) => {}
        other => {
            return Err(format!("expected InvalidDigest on forged proof, got: {other:?}").into());
        }
    }

    let obligation = journal
        .obligations()
        .find(|o| o.obligation_id == obligation_id)
        .ok_or("obligation missing")?;
    if obligation.state != ObligationState::Indeterminate {
        return Err("obligation state must not mutate on failed forged reconciliation".into());
    }

    // Replay proof from a different intent is rejected
    let intent_b = EffectIntent {
        operation_id: OperationId::parse("operation:alert:other")?,
        idempotency_key: IdempotencyKey::parse("idempotency:alert:other")?,
        effect_class: "alert.dispatch".to_owned(),
        request_digest: ContentDigest::sha256(b"other-request"),
        precondition_digest: ContentDigest::sha256(b"other-precondition"),
    };
    let replay_proof = intent_b.terminal_proof(REFERENCE_ALERT_TERMINAL_PREDICATE);
    let replay_result = journal.reconcile_verified(&op_id, replay_proof, TimestampNs(104));
    match replay_result {
        Err(ContractError::InvalidDigest) => {}
        other => {
            return Err(format!("expected InvalidDigest on replayed proof, got: {other:?}").into());
        }
    }

    // Authoritative proof closes obligation cleanly
    let valid_proof = intent_a.terminal_proof(REFERENCE_ALERT_TERMINAL_PREDICATE);
    let verified = journal.reconcile_verified(&op_id, valid_proof, TimestampNs(105))?;
    if verified.state != EffectState::Verified {
        return Err("expected Verified state on authoritative proof".into());
    }
    let obligation = journal
        .obligations()
        .find(|o| o.obligation_id == obligation_id)
        .ok_or("obligation missing")?;
    if obligation.state != ObligationState::Verified || obligation.proof_digest != Some(valid_proof)
    {
        return Err("obligation must be Verified with matching proof digest".into());
    }

    Ok(())
}

/// F4: Transport acceptance (Delivered) moves to AdapterAccepted only.
/// Observed requires independent observation input, Verified requires verified observation,
/// and Cancelled requires proof evidence.
#[test]
fn test_f4_adapter_acceptance_does_not_promote_to_verified_without_observation()
-> Result<(), Box<dyn Error>> {
    let path = temp_journal("f4-adapter-accepted");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare_alert(&decision, &event_receipt, &authority, &mut journal)?;
    let mut provider = ReferenceAlertProvider::new();

    // 1. Adapter delivery transitions to AdapterAccepted only, not Observed or Verified
    let receipt = dispatch_reference_alert(
        &plan,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    )?;
    if receipt.state != EffectState::AdapterAccepted {
        return Err("dispatch_reference_alert must move to AdapterAccepted only".into());
    }
    let obligation = journal
        .obligations()
        .find(|o| o.obligation_id == plan.obligation_id)
        .ok_or("obligation missing")?;
    if obligation.state != ObligationState::Pending {
        return Err("obligation must remain Pending upon AdapterAccepted".into());
    }

    // 2. Observe transitions to Observed
    let obs_proof = ContentDigest::sha256(b"telemetry-observation-proof");
    let observed = observe_reference_alert(&plan, obs_proof, TimestampNs(103), &mut journal)?;
    if observed.state != EffectState::Observed {
        return Err("observe_reference_alert must advance to Observed".into());
    }

    // 3. Verify transitions to Verified
    let verified = verify_reference_alert(&plan, TimestampNs(104), &mut journal, &provider)?;
    if verified.state != EffectState::Verified {
        return Err("verify_reference_alert must advance to Verified".into());
    }
    let obligation = journal
        .obligations()
        .find(|o| o.obligation_id == plan.obligation_id)
        .ok_or("obligation missing")?;
    if obligation.state != ObligationState::Verified {
        return Err("obligation must be Verified after verify_reference_alert".into());
    }

    // 4. Cancelled transition requires proof evidence
    let cancel_op_id = OperationId::parse("operation:alert:cancel")?;
    let cancel_intent = EffectIntent {
        operation_id: cancel_op_id.clone(),
        idempotency_key: IdempotencyKey::parse("idempotency:alert:cancel")?,
        effect_class: "alert.dispatch".to_owned(),
        request_digest: ContentDigest::sha256(b"cancel-req"),
        precondition_digest: ContentDigest::sha256(b"cancel-pre"),
    };
    let cancel_ob_id = ObligationId::parse("obligation:alert:cancel")?;
    journal.prepare(
        cancel_intent,
        cancel_ob_id.clone(),
        "cancelled with proof",
        TimestampNs(200),
    )?;

    // Transition to Cancelled with proof None fails with EvidenceRequired
    let cancel_no_proof = journal.transition(
        &cancel_op_id,
        EffectState::Cancelled,
        TimestampNs(201),
        None,
        None,
    );
    match cancel_no_proof {
        Err(ContractError::EvidenceRequired) => {}
        other => {
            return Err(format!(
                "expected EvidenceRequired on cancel without proof, got: {other:?}"
            )
            .into());
        }
    }

    // Transition to Cancelled with proof succeeds
    let cancel_proof = ContentDigest::sha256(b"cancel-reason-proof");
    let cancelled = journal.transition(
        &cancel_op_id,
        EffectState::Cancelled,
        TimestampNs(202),
        Some(cancel_proof),
        Some("operator_revoked".to_owned()),
    )?;
    if cancelled.state != EffectState::Cancelled {
        return Err("expected Cancelled state".into());
    }
    let cancel_ob = journal
        .obligations()
        .find(|o| o.obligation_id == cancel_ob_id)
        .ok_or("cancel obligation missing")?;
    if cancel_ob.state != ObligationState::Cancelled || cancel_ob.proof_digest != Some(cancel_proof)
    {
        return Err("cancel obligation must be Cancelled with proof digest".into());
    }

    let _ = fs::remove_file(path);
    Ok(())
}

/// F5: Two models run over the same camera capture (same input_capture_root) must NOT be
/// classified as Corroborated or trigger PrepareAlert, even if given distinct caller labels.
#[test]
fn test_f5_single_camera_capture_two_models_rejected_as_corroborated() -> Result<(), Box<dyn Error>>
{
    let path = temp_journal("f5-single-camera");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(256, 4 * 1024 * 1024));
    let mut ledger =
        DurableReferenceLedger::open(&path, "site:policy", IncompleteTailPolicy::Reject)?;

    // Single physical capture from camera 1
    let spec = VirtualCameraSpec {
        capture_id: CapsuleId::parse("capture:camera:1")?,
        sensor_id: SensorId::parse("sensor:camera:1")?,
        seed: 10,
        packet_count: 3,
        packet_bytes: 32,
        start_ns: 10_000,
        period_ns: 1_000_000,
        uncertainty_ns: 100,
    };
    let capture = run_reference_capture(
        &spec,
        &DeliveryPlan::identity(spec.packet_count)?,
        &mut objects,
        &mut ledger,
    )?;

    // Two distinct models run on the SAME capture
    let model_1 = MockModelSpec::new(
        "mock:camera1:m1:v1",
        MockModelScript::Fixed {
            label: MockSemanticLabel::PersonLike,
            probability: ProbabilityInterval::new(0.95, 1.0)?,
        },
    )?;
    let result_1 = execute_mock_model(&model_1, &capture, &mut objects)?;

    let model_2 = MockModelSpec::new(
        "mock:camera1:m2:v1",
        MockModelScript::Fixed {
            label: MockSemanticLabel::PersonLike,
            probability: ProbabilityInterval::new(0.90, 1.0)?,
        },
    )?;
    let result_2 = execute_mock_model(&model_2, &capture, &mut objects)?;

    if result_1.input_capture_root != result_2.input_capture_root {
        return Err("both results must share the same input_capture_root for this test".into());
    }

    let first = capture
        .source_packets
        .first()
        .ok_or(ReferenceError::InvalidSpec("source_packet_count"))?;
    let last = capture
        .source_packets
        .last()
        .ok_or(ReferenceError::InvalidSpec("source_packet_count"))?;
    let interval = CaptureInterval::new(first.capture.earliest, last.capture.latest)?;

    // Caller gives them distinct failure domain labels ("power:a" vs "power:b")
    let obs_1 = ReferenceModelObservation::new(result_1, "power:sensor1:a", interval)?;
    let obs_2 = ReferenceModelObservation::new(result_2, "power:sensor1:b", interval)?;

    // evaluate_unknown_presence must classify as Witnessed with Hold, NOT Corroborated with PrepareAlert
    let decision = evaluate_unknown_presence(
        EventId::parse("event:unknown-person:single-sensor")?,
        vec![obs_1, obs_2],
    )?;

    if decision.event.state == EventState::Corroborated {
        return Err("single camera capture must never produce EventState::Corroborated".into());
    }
    if decision.event.state != EventState::Witnessed {
        return Err(
            "single camera capture with two supporting models should be EventState::Witnessed"
                .into(),
        );
    }
    if decision.action != ReferencePolicyAction::Hold {
        return Err(
            "single camera capture must not trigger PrepareAlert; action must be Hold".into(),
        );
    }

    // Attempting to prepare an alert with this decision must fail
    let event_receipt = publish_reference_event(&decision, &mut objects, &mut ledger)?;
    let mut journal = EffectJournal::new();
    let prepare_attempt = prepare_reference_alert(
        PrepareAlertParams {
            decision: &decision,
            event_receipt: &event_receipt,
            authority: &ledger,
            operation_id: OperationId::parse("operation:illegal:single:sensor")?,
            idempotency_key: IdempotencyKey::parse("idempotency:illegal:single:sensor")?,
            obligation_id: ObligationId::parse("obligation:illegal:single:sensor")?,
            channel: "operator:oncall".to_owned(),
            now: TimestampNs(100),
        },
        &mut journal,
    );
    match prepare_attempt {
        Err(ReferenceError::InvalidSpec("alert_not_eligible")) => {}
        other => {
            return Err(format!(
                "expected alert_not_eligible when preparing alert on single-sensor event, got: {other:?}"
            )
            .into());
        }
    }

    let _ = fs::remove_file(path);
    Ok(())
}

/// F6: Reconciliation preserves indeterminate error_code provenance, allows terminal
/// outcome publication as generation 2 with prior_generation = Some(1), and supports reconcile_failed.
#[test]
fn test_f6_reconciliation_preserves_indeterminate_provenance_and_publishes_successive_generation()
-> Result<(), Box<dyn Error>> {
    // 1. Provenance preservation in EffectJournal
    let mut journal = EffectJournal::new();
    let op_id = OperationId::parse("operation:alert:drop")?;
    let intent = EffectIntent {
        operation_id: op_id.clone(),
        idempotency_key: IdempotencyKey::parse("idempotency:alert:drop")?,
        effect_class: "alert.dispatch".to_owned(),
        request_digest: ContentDigest::sha256(b"request"),
        precondition_digest: ContentDigest::sha256(b"precondition"),
    };
    journal.prepare(
        intent.clone(),
        ObligationId::parse("obligation:alert:drop")?,
        REFERENCE_ALERT_TERMINAL_PREDICATE,
        TimestampNs(100),
    )?;
    journal.transition(&op_id, EffectState::Committed, TimestampNs(101), None, None)?;
    journal.mark_indeterminate(&op_id, TimestampNs(102), "provider_ack_lost")?;

    let op_receipt = journal.operation(&op_id).ok_or("operation missing")?;
    if op_receipt.error_code.as_deref() != Some("provider_ack_lost") {
        return Err("error_code must be provider_ack_lost before reconciliation".into());
    }

    // Reconcile with valid proof
    let proof = intent.terminal_proof(REFERENCE_ALERT_TERMINAL_PREDICATE);
    journal.reconcile_verified(&op_id, proof, TimestampNs(103))?;

    // Provenance must NOT be wiped
    let reconciled_receipt = journal.operation(&op_id).ok_or("operation missing")?;
    if reconciled_receipt.error_code.as_deref() != Some("provider_ack_lost") {
        return Err("reconcile_verified must preserve indeterminate error_code provenance".into());
    }

    // 2. Publication generation succession (Gen 1 Indeterminate -> Gen 2 Verified)
    let path = temp_journal("f6-generation-succession");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(1024, 16 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:outcome", IncompleteTailPolicy::Reject)?;

    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut alert_journal = EffectJournal::new();
    let plan = prepare_alert(&decision, &event_receipt, &authority, &mut alert_journal)?;
    let mut provider = ReferenceAlertProvider::new();

    // Dispatch with LoseAckAfterDelivery
    let dispatched = dispatch_reference_alert(
        &plan,
        ReferenceProviderBehavior::LoseAckAfterDelivery,
        TimestampNs(101),
        TimestampNs(102),
        &mut alert_journal,
        &mut provider,
    )?;
    if dispatched.state != EffectState::Indeterminate {
        return Err("expected Indeterminate state from LoseAckAfterDelivery".into());
    }

    // Publish Indeterminate outcome at Generation 1
    let gen1_receipt =
        publish_reference_alert_outcome(&plan, &alert_journal, &mut objects, &mut authority)?;
    if gen1_receipt.effect_generation != 1 {
        return Err("initial outcome must be Generation 1".into());
    }
    if gen1_receipt.outcome.operation_receipt.state != EffectState::Indeterminate {
        return Err("generation 1 outcome must be Indeterminate".into());
    }

    // Reconcile alert via provider
    let reconciled_op =
        reconcile_reference_alert(&plan, TimestampNs(105), &mut alert_journal, &provider)?
            .ok_or("expected successful reconciliation from provider")?;
    if reconciled_op.state != EffectState::Verified {
        return Err("reconciled operation must be Verified".into());
    }

    // Publish reconciled outcome: must succeed as Generation 2
    let gen2_receipt =
        publish_reference_alert_outcome(&plan, &alert_journal, &mut objects, &mut authority)?;
    if gen2_receipt.effect_generation != 2 {
        return Err("reconciled terminal outcome must publish as Generation 2".into());
    }
    if gen2_receipt.outcome.operation_receipt.state != EffectState::Verified {
        return Err("generation 2 outcome must be Verified".into());
    }

    // Verify authority delta has prior_generation = Some(1) and new_generation = 2
    let last_delta = authority
        .batches()
        .last()
        .and_then(|b| b.deltas.first())
        .ok_or("missing latest delta in authority")?;
    if last_delta.prior_generation != Some(1) {
        return Err("terminal outcome delta must set prior_generation = Some(1)".into());
    }
    if last_delta.new_generation != 2 {
        return Err("terminal outcome delta must set new_generation = 2".into());
    }

    // Exact retry of Generation 2 is read-like
    let gen2_retry =
        publish_reference_alert_outcome(&plan, &alert_journal, &mut objects, &mut authority)?;
    if gen2_retry.effect_generation != 2 || gen2_retry.outcome_root != gen2_receipt.outcome_root {
        return Err("exact retry of Generation 2 outcome must match".into());
    }

    // 3. reconcile_failed path
    let fail_op_id = OperationId::parse("operation:alert:failed:drop")?;
    let fail_intent = EffectIntent {
        operation_id: fail_op_id.clone(),
        idempotency_key: IdempotencyKey::parse("idempotency:alert:failed:drop")?,
        effect_class: "alert.dispatch".to_owned(),
        request_digest: ContentDigest::sha256(b"request-fail"),
        precondition_digest: ContentDigest::sha256(b"precondition-fail"),
    };
    let fail_ob_id = ObligationId::parse("obligation:alert:failed:drop")?;
    alert_journal.prepare(
        fail_intent,
        fail_ob_id.clone(),
        "failed terminal predicate",
        TimestampNs(200),
    )?;
    alert_journal.transition(
        &fail_op_id,
        EffectState::Committed,
        TimestampNs(201),
        None,
        None,
    )?;
    alert_journal.mark_indeterminate(&fail_op_id, TimestampNs(202), "lost_ack")?;

    let fail_proof = ContentDigest::sha256(b"provider-refusal-proof");
    let failed_receipt = alert_journal.reconcile_failed(
        &fail_op_id,
        fail_proof,
        TimestampNs(203),
        "provider_refused_delivery",
    )?;
    if failed_receipt.state != EffectState::Failed {
        return Err("expected Failed state from reconcile_failed".into());
    }
    if failed_receipt.error_code.as_deref() != Some("provider_refused_delivery") {
        return Err("reconcile_failed must record failure reason in error_code".into());
    }
    let fail_ob = alert_journal
        .obligations()
        .find(|o| o.obligation_id == fail_ob_id)
        .ok_or("failed obligation missing")?;
    if fail_ob.state != ObligationState::Failed || fail_ob.proof_digest != Some(fail_proof) {
        return Err("obligation must be Failed with matching failure proof".into());
    }

    let _ = fs::remove_file(path);
    Ok(())
}

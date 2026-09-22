#![forbid(unsafe_code)]
//! Integration contract tests for effect plane invariants and defect hunt fixes F2-F6.

use std::error::Error;
use std::fs;

use fss_core::{
    CanonicalEncode, CapsuleId, CaptureInterval, ContentDigest, ContractError, EffectIntent,
    EffectJournal, EffectState, EventId, EventState, IdempotencyKey, ObligationId, ObligationState,
    OperationId, ProbabilityInterval, SensorId, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};
use fss_reference::{
    DeliveryPlan, MockModelScript, MockModelSpec, MockSemanticLabel, PrepareAlertParams,
    ProviderObservationReceipt, REFERENCE_ALERT_TERMINAL_PREDICATE, ReferenceAlertPlan,
    ReferenceAlertProvider, ReferenceError, ReferenceEventReceipt, ReferenceModelObservation,
    ReferencePolicyAction, ReferencePolicyDecision, ReferenceProviderBehavior, VirtualCameraSpec,
    dispatch_reference_alert, evaluate_unknown_presence, execute_mock_model,
    observe_reference_alert, prepare_reference_alert, publish_reference_alert_outcome,
    publish_reference_event, reconcile_failed_reference_alert, reconcile_reference_alert,
    run_reference_capture, verify_reference_alert,
};

fn temp_journal(name: &str) -> std::path::PathBuf {
    let base = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(std::path::PathBuf::from)
        .or_else(|| std::option_env!("CARGO_TARGET_TMPDIR").map(std::path::PathBuf::from))
        .unwrap_or_else(std::env::temp_dir);
    let pid = std::process::id();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    for attempt in 0..64 {
        let dir_name = format!("fss-effect-plane-{pid}-{now}-{attempt}-{name}");
        let dir = base.join(dir_name);
        if fs::create_dir(&dir).is_ok() {
            return dir.join(format!("{name}.journal"));
        }
    }
    base.join(format!(
        "fss-effect-plane-{pid}-{now}-fallback-{name}.journal"
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
    let path = temp_journal("f2-lifecycle");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let shared_idempotency_key = IdempotencyKey::parse("idempotency:alert:shared")?;

    // Plan A
    let plan_a = prepare_reference_alert(
        PrepareAlertParams {
            decision: &decision,
            event_receipt: &event_receipt,
            authority: &authority,
            operation_id: OperationId::parse("operation:alert:a")?,
            idempotency_key: shared_idempotency_key.clone(),
            obligation_id: ObligationId::parse("obligation:alert:a")?,
            channel: "operator:channel_a".to_owned(),
            now: TimestampNs(100),
        },
        &mut journal,
    )?;

    // 1. In the same journal, preparing conflicting plan_b is rejected with IdempotencyConflict:
    let err_prepare = prepare_reference_alert(
        PrepareAlertParams {
            decision: &decision,
            event_receipt: &event_receipt,
            authority: &authority,
            operation_id: OperationId::parse("operation:alert:b")?,
            idempotency_key: shared_idempotency_key.clone(),
            obligation_id: ObligationId::parse("obligation:alert:b")?,
            channel: "operator:channel_b".to_owned(),
            now: TimestampNs(100),
        },
        &mut journal,
    );
    assert!(matches!(
        err_prepare,
        Err(ReferenceError::Contract(ContractError::IdempotencyConflict))
    ));

    // 2. In a separate journal (e.g. concurrent node/process), plan_b is prepared:
    let mut journal_b = EffectJournal::new();
    let plan_b = prepare_reference_alert(
        PrepareAlertParams {
            decision: &decision,
            event_receipt: &event_receipt,
            authority: &authority,
            operation_id: OperationId::parse("operation:alert:b")?,
            idempotency_key: shared_idempotency_key,
            obligation_id: ObligationId::parse("obligation:alert:b")?,
            channel: "operator:channel_b".to_owned(),
            now: TimestampNs(100),
        },
        &mut journal_b,
    )?;

    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:idempotency");

    // 3. First dispatch of plan_a through dispatch_reference_alert succeeds:
    let dispatch_a = dispatch_reference_alert(
        &plan_a,
        &authority,
        &objects,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    )?;
    assert_eq!(dispatch_a.state, EffectState::AdapterAccepted);

    // 4. Conflicting dispatch of plan_b with different intent under same idempotency key fails:
    let err_b = dispatch_reference_alert(
        &plan_b,
        &authority,
        &objects,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(103),
        TimestampNs(104),
        &mut journal_b,
        &mut provider,
    );
    assert!(matches!(
        err_b,
        Err(ReferenceError::Contract(ContractError::IdempotencyConflict))
    ));

    // 3. Provider lookup for conflicting intent returns IdempotencyConflict:
    match provider.lookup(&plan_b.intent) {
        Err(ReferenceError::Contract(ContractError::IdempotencyConflict)) => {}
        other => {
            return Err(
                format!("expected IdempotencyConflict on plan_b lookup, got {other:?}").into(),
            );
        }
    }

    // 4. Progress plan_a through observation, verification, and outcome publication:
    let provider_receipt_a = provider
        .lookup(&plan_a.intent)?
        .ok_or("missing receipt a")?;
    let _ = observe_reference_alert(
        &plan_a,
        provider_receipt_a.receipt_digest(),
        TimestampNs(105),
        &mut journal,
        &provider,
    )?;
    let _ = verify_reference_alert(&plan_a, TimestampNs(106), &mut journal, &provider)?;

    let outcome_receipt = publish_reference_alert_outcome(
        &plan_a,
        &journal,
        &mut objects,
        &mut authority,
        &provider,
    )?;
    assert_eq!(
        outcome_receipt.outcome.operation_receipt.state,
        EffectState::Verified
    );

    // 5. Exact retry of publication on plan_a is idempotent:
    let outcome_retry = publish_reference_alert_outcome(
        &plan_a,
        &journal,
        &mut objects,
        &mut authority,
        &provider,
    )?;
    assert_eq!(outcome_retry, outcome_receipt);

    let _ = fs::remove_file(path);
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

    // Direct reconcile_verified while Indeterminate without observation is rejected
    let forged_proof = ContentDigest::sha256(b"completely_unrelated_forged_proof_bytes");
    let res = journal.reconcile_verified(&op_id, forged_proof, TimestampNs(103));
    assert_eq!(res, Err(ContractError::InvalidEffectTransition));

    // Transition to Observed with an observation witness
    let obs_witness = ContentDigest::sha256(b"observation_witness_a");
    journal.transition(
        &op_id,
        EffectState::Observed,
        TimestampNs(103),
        Some(obs_witness),
        None,
    )?;

    // In Observed state, forged proof (mismatched with observation witness) is rejected
    let forge_result = journal.reconcile_verified(&op_id, forged_proof, TimestampNs(104));
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

    // Replay proof from a different witness is rejected
    let replay_proof = ContentDigest::sha256(b"observation_witness_b");
    let replay_result = journal.reconcile_verified(&op_id, replay_proof, TimestampNs(105));
    match replay_result {
        Err(ContractError::InvalidDigest) => {}
        other => {
            return Err(format!("expected InvalidDigest on replayed proof, got: {other:?}").into());
        }
    }

    // Authoritative proof matching observation witness closes obligation cleanly
    let verified = journal.reconcile_verified(&op_id, obs_witness, TimestampNs(106))?;
    if verified.state != EffectState::Verified {
        return Err("expected Verified state on authoritative proof".into());
    }
    let obligation = journal
        .obligations()
        .find(|o| o.obligation_id == obligation_id)
        .ok_or("obligation missing")?;
    if obligation.state != ObligationState::Verified || obligation.proof_digest != Some(obs_witness)
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
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:adapter_accepted");

    // 1. Adapter delivery transitions to AdapterAccepted only, not Observed or Verified
    let receipt = dispatch_reference_alert(
        &plan,
        &authority,
        &objects,
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
    let provider_receipt = provider
        .lookup(&plan.intent)?
        .ok_or("provider receipt missing")?;
    let observed = observe_reference_alert(
        &plan,
        provider_receipt.receipt_digest(),
        TimestampNs(103),
        &mut journal,
        &provider,
    )?;
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
        cancel_intent.clone(),
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
    let cancel_proof = cancel_intent.cancellation_proof(TimestampNs(200), TimestampNs(202))?;
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

    // Transition to Observed with observation witness
    let obs_proof = ContentDigest::sha256(b"provider_observation_witness");
    journal.transition(
        &op_id,
        EffectState::Observed,
        TimestampNs(103),
        Some(obs_proof),
        None,
    )?;

    // Reconcile with valid proof matching observation witness
    journal.reconcile_verified(&op_id, obs_proof, TimestampNs(104))?;

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
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:outcome_preserves");

    // Dispatch with LoseAckAfterDelivery
    let dispatched = dispatch_reference_alert(
        &plan,
        &authority,
        &objects,
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
    let gen1_receipt = publish_reference_alert_outcome(
        &plan,
        &alert_journal,
        &mut objects,
        &mut authority,
        &provider,
    )?;
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
    let gen2_receipt = publish_reference_alert_outcome(
        &plan,
        &alert_journal,
        &mut objects,
        &mut authority,
        &provider,
    )?;
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
    let gen2_retry = publish_reference_alert_outcome(
        &plan,
        &alert_journal,
        &mut objects,
        &mut authority,
        &provider,
    )?;
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
        fail_intent.clone(),
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

    let fail_proof = fail_intent.failure_proof("provider_refused_delivery");
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

#[test]
fn test_finding_1_failure_proof_cross_operation_replay() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("finding-1-replay");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();

    let plan1 = prepare_reference_alert(
        PrepareAlertParams {
            decision: &decision,
            event_receipt: &event_receipt,
            authority: &authority,
            operation_id: OperationId::parse("op:alert:review:001")?,
            idempotency_key: IdempotencyKey::parse("idempotency:alert:review:001")?,
            obligation_id: ObligationId::parse("obligation:alert:001")?,
            channel: "operator:oncall".to_owned(),
            now: TimestampNs(100),
        },
        &mut journal,
    )?;

    let plan2 = prepare_reference_alert(
        PrepareAlertParams {
            decision: &decision,
            event_receipt: &event_receipt,
            authority: &authority,
            operation_id: OperationId::parse("op:alert:review:002")?,
            idempotency_key: IdempotencyKey::parse("idempotency:alert:review:002")?,
            obligation_id: ObligationId::parse("obligation:alert:002")?,
            channel: "operator:oncall".to_owned(),
            now: TimestampNs(100),
        },
        &mut journal,
    )?;

    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:finding1");

    // Dispatch plan1 and plan2 which both lose ACK and become Indeterminate:
    let _ = dispatch_reference_alert(
        &plan1,
        &authority,
        &objects,
        ReferenceProviderBehavior::LoseAckAfterDelivery,
        TimestampNs(150),
        TimestampNs(200),
        &mut journal,
        &mut provider,
    )?;
    let _ = dispatch_reference_alert(
        &plan2,
        &authority,
        &objects,
        ReferenceProviderBehavior::LoseAckAfterDelivery,
        TimestampNs(150),
        TimestampNs(200),
        &mut journal,
        &mut provider,
    )?;

    // External provider records failures for op1 and op2:
    // But op1 failure receipt cannot be replayed for op2!
    let mut failure_provider =
        ReferenceAlertProvider::with_provider_id("provider:test:finding1_fail");
    let op1_receipt = failure_provider.record_failure(&plan1.intent, "timeout")?;
    let op2_receipt = failure_provider.record_failure(&plan2.intent, "timeout")?;

    // Attempting to reconcile plan2 using op1's failure proof MUST BE REJECTED
    let err = reconcile_failed_reference_alert(
        &plan2,
        op1_receipt.receipt_digest(),
        "timeout",
        TimestampNs(300),
        &mut journal,
        &failure_provider,
    );
    assert!(matches!(
        err,
        Err(ReferenceError::Contract(ContractError::InvalidDigest))
    ));

    // Valid failure proof for plan2 succeeds
    let receipt2 = reconcile_failed_reference_alert(
        &plan2,
        op2_receipt.receipt_digest(),
        "timeout",
        TimestampNs(300),
        &mut journal,
        &failure_provider,
    )?;
    assert_eq!(receipt2.state, EffectState::Failed);
    assert_eq!(receipt2.result_digest, Some(op2_receipt.receipt_digest()));

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn test_finding_2_trivial_receipt_forgery_without_provider() -> Result<(), Box<dyn Error>> {
    let mut journal = EffectJournal::new();
    let now = TimestampNs(1_000);
    let op = OperationId::parse("op:alert:review:forge")?;
    let key = IdempotencyKey::parse("idempotency:alert:review:forge")?;
    let intent = EffectIntent {
        operation_id: op.clone(),
        idempotency_key: key,
        effect_class: "alert.dispatch".to_string(),
        request_digest: ContentDigest::sha256(b"req"),
        precondition_digest: ContentDigest::sha256(b"pre"),
    };

    journal.prepare(
        intent.clone(),
        ObligationId::parse("obligation:alert:review:forge")?,
        "delivery_acknowledged_by_provider",
        now,
    )?;
    journal.transition(&op, EffectState::Committed, TimestampNs(1_500), None, None)?;
    journal.mark_indeterminate(&op, TimestampNs(2_000), "simulated timeout")?;

    // Caller synthesizes the terminal proof offline without provider interaction:
    let forged_proof = intent.terminal_proof("delivery_acknowledged_by_provider");
    // Attempting to reconcile directly from Indeterminate must be rejected:
    let res = journal.reconcile_verified(&op, forged_proof, TimestampNs(3_000));
    assert_eq!(res, Err(ContractError::InvalidEffectTransition));

    // Even if caller transitions to Observed using forged_proof, journal reconciliation checks against observation witness:
    journal.transition(
        &op,
        EffectState::Observed,
        TimestampNs(2_500),
        Some(forged_proof),
        None,
    )?;
    // An offline synthesized proof cannot be verified with a provider that never saw it:
    let provider = ReferenceAlertProvider::with_provider_id("provider:test:finding2");
    assert!(provider.lookup(&intent)?.is_none());
    Ok(())
}

#[test]
fn test_finding_3_zero_input_observation_and_same_timestamp() -> Result<(), Box<dyn Error>> {
    let mut journal = EffectJournal::new();
    let t0 = TimestampNs(5_000);
    let op = OperationId::parse("op:alert:review:instant")?;
    let key = IdempotencyKey::parse("idempotency:alert:review:instant")?;
    let intent = EffectIntent {
        operation_id: op.clone(),
        idempotency_key: key,
        effect_class: "alert.dispatch".to_string(),
        request_digest: ContentDigest::sha256(b"r"),
        precondition_digest: ContentDigest::sha256(b"p"),
    };

    journal.prepare(
        intent.clone(),
        ObligationId::parse("obligation:alert:review:instant")?,
        "delivery_acknowledged_by_provider",
        t0,
    )?;

    // 1. Same timestamp transition must be rejected:
    let same_time_res = journal.transition(&op, EffectState::Committed, t0, None, None);
    assert_eq!(same_time_res, Err(ContractError::InvertedTimeInterval));

    // 2. Advancing timestamp succeeds:
    let t1 = TimestampNs(5_001);
    journal.transition(&op, EffectState::Committed, t1, None, None)?;
    let t2 = TimestampNs(5_002);
    journal.transition(&op, EffectState::AdapterAccepted, t2, None, None)?;

    // 3. Transition to Observed with NO result_digest must fail with EvidenceRequired:
    let t3 = TimestampNs(5_003);
    let empty_obs_res = journal.transition(&op, EffectState::Observed, t3, None, None);
    assert_eq!(empty_obs_res, Err(ContractError::EvidenceRequired));

    // 4. Transition to Observed with non-empty observation witness succeeds:
    let obs_digest = ContentDigest::sha256(b"valid_obs_digest");
    journal.transition(&op, EffectState::Observed, t3, Some(obs_digest), None)?;

    // 5. Reconcile verified at same timestamp t3 must fail:
    let same_ts_verify = journal.reconcile_verified(&op, obs_digest, t3);
    assert_eq!(same_ts_verify, Err(ContractError::InvertedTimeInterval));

    // 6. Reconcile verified at strictly advancing timestamp succeeds:
    let t4 = TimestampNs(5_004);
    let ver = journal.reconcile_verified(&op, obs_digest, t4)?;
    assert_eq!(ver.state, EffectState::Verified);
    Ok(())
}

#[test]
fn test_finding_4_corroboration_faked_single_camera() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("f4-corroboration");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut ledger =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;

    let obs1 = observation(
        "capture:camera:cam1_frame1",
        "sensor:camera:fixed_001",
        10,
        "failure-domain-alpha",
        &mut objects,
        &mut ledger,
    )?;
    let obs2 = observation(
        "capture:camera:cam1_frame2",
        "sensor:camera:fixed_001",
        20,
        "failure-domain-beta",
        &mut objects,
        &mut ledger,
    )?;

    let decision = evaluate_unknown_presence(
        EventId::parse("event:unknown-presence:fake")?,
        vec![obs1, obs2],
    )?;
    // With only one physical camera, state must NOT be Corroborated; it must remain Witnessed and Hold!
    assert_eq!(decision.event.state, EventState::Witnessed);
    assert_eq!(decision.action, ReferencePolicyAction::Hold);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn test_finding_5_delivered_effect_marked_failed() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("finding-5");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare_alert(&decision, &event_receipt, &authority, &mut journal)?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:finding5");

    let t1 = TimestampNs(101);
    let t2 = TimestampNs(102);
    let dispatch_res = dispatch_reference_alert(
        &plan,
        &authority,
        &objects,
        ReferenceProviderBehavior::LoseAckAfterDelivery,
        t1,
        t2,
        &mut journal,
        &mut provider,
    )?;
    assert_eq!(dispatch_res.state, EffectState::Indeterminate);

    // Provider confirms it was actually delivered:
    assert!(provider.lookup(&plan.intent)?.is_some());

    // Attempting to mark it failed via reconcile_failed_reference_alert must be refused:
    let fail_proof = plan.intent.failure_proof("declared_failed");
    let res = reconcile_failed_reference_alert(
        &plan,
        fail_proof,
        "declared_failed",
        TimestampNs(103),
        &mut journal,
        &provider,
    );
    assert!(matches!(
        res,
        Err(ReferenceError::Contract(
            ContractError::InvalidEffectTransition
        ))
    ));

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn test_finding_6_reconciliation_not_idempotent() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("finding-6");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare_alert(&decision, &event_receipt, &authority, &mut journal)?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:finding6");

    let t1 = TimestampNs(101);
    let t2 = TimestampNs(102);
    let dispatch_res = dispatch_reference_alert(
        &plan,
        &authority,
        &objects,
        ReferenceProviderBehavior::LoseAckAfterDelivery,
        t1,
        t2,
        &mut journal,
        &mut provider,
    )?;
    assert_eq!(dispatch_res.state, EffectState::Indeterminate);

    // First reconciliation succeeds:
    let res1 = reconcile_reference_alert(&plan, TimestampNs(103), &mut journal, &provider)?;
    assert!(res1.is_some());
    assert_eq!(res1.as_ref().map(|r| r.state), Some(EffectState::Verified));

    // Second identical reconciliation attempt must succeed idempotently:
    let res2 = reconcile_reference_alert(&plan, TimestampNs(105), &mut journal, &provider)?;
    assert!(res2.is_some());
    assert_eq!(res2.as_ref().map(|r| r.state), Some(EffectState::Verified));

    // Calling with a conflicting proof returns IdempotencyConflict:
    let bogus_proof = ContentDigest::sha256(b"conflicting_proof");
    let conflict_res =
        journal.reconcile_verified(&plan.intent.operation_id, bogus_proof, TimestampNs(106));
    assert_eq!(conflict_res, Err(ContractError::IdempotencyConflict));

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn test_f1_uncalled_provider_refuses_failure_reconciliation() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("f1-uncalled");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare_alert(&decision, &event_receipt, &authority, &mut journal)?;
    let provider = ReferenceAlertProvider::with_provider_id("provider:test:f1");

    journal.transition(
        &plan.intent.operation_id,
        EffectState::Committed,
        TimestampNs(101),
        None,
        None,
    )?;
    journal.mark_indeterminate(&plan.intent.operation_id, TimestampNs(102), "drop")?;

    // Anyone can synthesize a failure proof with an arbitrary reason:
    let fake_reason = "fabricated_carrier_outage";
    let forged_failure_proof = plan.intent.failure_proof(fake_reason);

    // The provider was NEVER called and issued no failure receipt:
    assert!(provider.lookup(&plan.intent)?.is_none());

    // DEFECT: reconcile_failed_reference_alert succeeds without any provider-issued failure receipt!
    let res = reconcile_failed_reference_alert(
        &plan,
        forged_failure_proof,
        fake_reason,
        TimestampNs(103),
        &mut journal,
        &provider,
    );
    assert!(
        res.is_err(),
        "Reconciling failure must require a provider-issued failure receipt, not a public hash of intent!"
    );
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn test_f2_independent_providers_mint_distinct_nonces() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("f2-nonces");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal_a = EffectJournal::new();
    let mut journal_b = EffectJournal::new();
    let plan_a = prepare_reference_alert(
        PrepareAlertParams {
            decision: &decision,
            event_receipt: &event_receipt,
            authority: &authority,
            operation_id: OperationId::parse("op:alert:nonce:a")?,
            idempotency_key: IdempotencyKey::parse("idempotency:alert:nonce:a")?,
            obligation_id: ObligationId::parse("obligation:alert:nonce:a")?,
            channel: "operator:oncall".to_owned(),
            now: TimestampNs(100),
        },
        &mut journal_a,
    )?;
    let plan_b = prepare_reference_alert(
        PrepareAlertParams {
            decision: &decision,
            event_receipt: &event_receipt,
            authority: &authority,
            operation_id: OperationId::parse("op:alert:nonce:b")?,
            idempotency_key: IdempotencyKey::parse("idempotency:alert:nonce:b")?,
            obligation_id: ObligationId::parse("obligation:alert:nonce:b")?,
            channel: "operator:oncall".to_owned(),
            now: TimestampNs(100),
        },
        &mut journal_b,
    )?;

    let mut provider_a = ReferenceAlertProvider::with_provider_id("provider:test:f2:alpha");
    let mut provider_b = ReferenceAlertProvider::with_provider_id("provider:test:f2:beta");

    let _ = dispatch_reference_alert(
        &plan_a,
        &authority,
        &objects,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal_a,
        &mut provider_a,
    )?;
    let _ = dispatch_reference_alert(
        &plan_b,
        &authority,
        &objects,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal_b,
        &mut provider_b,
    )?;

    let receipt_a = provider_a
        .lookup(&plan_a.intent)?
        .ok_or("missing receipt a")?;
    let receipt_b = provider_b
        .lookup(&plan_b.intent)?
        .ok_or("missing receipt b")?;

    assert_ne!(
        receipt_a.provider_nonce, receipt_b.provider_nonce,
        "Distinct provider instances must never issue identical provider nonces!"
    );
    Ok(())
}

#[test]
fn test_deterministic_provider_mints_bit_identical_receipts_for_same_id()
-> Result<(), Box<dyn Error>> {
    let path = temp_journal("f2-deterministic");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare_alert(&decision, &event_receipt, &authority, &mut journal)?;

    let mut journal_2 = EffectJournal::new();
    let plan_2 = prepare_alert(&decision, &event_receipt, &authority, &mut journal_2)?;

    let mut provider_1 = ReferenceAlertProvider::with_provider_id("provider:test:deterministic");
    let mut provider_2 = ReferenceAlertProvider::with_provider_id("provider:test:deterministic");

    let _ = dispatch_reference_alert(
        &plan,
        &authority,
        &objects,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider_1,
    )?;
    let _ = dispatch_reference_alert(
        &plan_2,
        &authority,
        &objects,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal_2,
        &mut provider_2,
    )?;

    let receipt_1 = provider_1
        .lookup(&plan.intent)?
        .ok_or("missing receipt 1")?;
    let receipt_2 = provider_2
        .lookup(&plan.intent)?
        .ok_or("missing receipt 2")?;

    assert_eq!(receipt_1.provider_nonce, receipt_2.provider_nonce);
    assert_eq!(receipt_1.canonical_bytes(), receipt_2.canonical_bytes());
    assert_eq!(receipt_1.receipt_digest(), receipt_2.receipt_digest());
    Ok(())
}

#[test]
fn test_f3_unissued_observation_receipt_rejected() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("f3-unissued");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare_alert(&decision, &event_receipt, &authority, &mut journal)?;
    let provider = ReferenceAlertProvider::with_provider_id("provider:test:f3");

    journal.transition(
        &plan.intent.operation_id,
        EffectState::Committed,
        TimestampNs(101),
        None,
        None,
    )?;
    journal.transition(
        &plan.intent.operation_id,
        EffectState::AdapterAccepted,
        TimestampNs(102),
        None,
        None,
    )?;

    // Caller fabricates an observation receipt offline:
    let fake_receipt = ProviderObservationReceipt {
        provider_nonce: ContentDigest::sha256(b"fabricated_nonce"),
        message_digest: plan.intent.canonical_digest("fss.effect_proof.v1"),
    };
    let forged_proof = fake_receipt.receipt_digest();

    let res = observe_reference_alert(
        &plan,
        forged_proof,
        TimestampNs(103),
        &mut journal,
        &provider,
    );
    assert!(
        res.is_err(),
        "observe_reference_alert must reject caller-built receipts never issued by provider"
    );
    let _ = fs::remove_file(path);
    Ok(())
}

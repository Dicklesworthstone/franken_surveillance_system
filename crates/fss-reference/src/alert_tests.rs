use std::error::Error;
use std::fs;

use fss_core::{
    CaptureInterval, CapsuleId, EffectJournal, EffectState, EventId, IdempotencyKey, ObligationId,
    ObligationState, OperationId, ProbabilityInterval, SensorId, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};

use crate::{
    DeliveryPlan, MockModelScript, MockModelSpec, MockSemanticLabel, ReferenceAlertProvider,
    ReferenceError, ReferenceModelObservation, ReferencePolicyDecision, ReferenceProviderBehavior,
    VirtualCameraSpec, dispatch_reference_alert, evaluate_unknown_presence, execute_mock_model,
    prepare_reference_alert, publish_reference_event, reconcile_reference_alert,
    run_reference_capture,
};

fn temp_journal(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "fss-reference-alert-{}-{name}.journal",
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
        format!("mock:alert:{sensor_name}:v1"),
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

fn eligible_event(
    objects: &mut InMemoryObjectStore,
    ledger: &mut DurableReferenceLedger,
) -> Result<(ReferencePolicyDecision, crate::ReferenceEventReceipt), Box<dyn Error>> {
    let first = observation(
        "capture:alert:a",
        "sensor:alert:a",
        11,
        "power:alert:a",
        objects,
        ledger,
    )?;
    let second = observation(
        "capture:alert:b",
        "sensor:alert:b",
        22,
        "power:alert:b",
        objects,
        ledger,
    )?;
    let decision = evaluate_unknown_presence(
        EventId::parse("event:alert:unknown-person")?,
        vec![first, second],
    )?;
    let receipt = publish_reference_event(&decision, objects, ledger)?;
    Ok((decision, receipt))
}

fn prepare(
    decision: &ReferencePolicyDecision,
    event_receipt: &crate::ReferenceEventReceipt,
    authority: &DurableReferenceLedger,
    journal: &mut EffectJournal,
) -> Result<crate::ReferenceAlertPlan, ReferenceError> {
    prepare_reference_alert(
        decision,
        event_receipt,
        authority,
        OperationId::parse("operation:alert:1")?,
        IdempotencyKey::parse("idempotency:alert:1")?,
        ObligationId::parse("obligation:alert:1")?,
        "operator:oncall",
        TimestampNs(100),
        journal,
    )
}

#[test]
fn delivered_alert_closes_verified_obligation() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("delivered");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &event_receipt, &authority, &mut journal)?;
    assert_eq!(
        journal.operation(&plan.intent.operation_id)?.state,
        EffectState::Prepared
    );

    let mut provider = ReferenceAlertProvider::new();
    let receipt = dispatch_reference_alert(
        &plan,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    )?;
    assert_eq!(receipt.state, EffectState::Verified);
    assert_eq!(provider.message_count(), 1);
    let obligation = journal
        .obligations()
        .find(|item| item.obligation_id == plan.obligation_id)
        .ok_or(ReferenceError::InvalidSpec("missing_obligation"))?;
    assert_eq!(obligation.state, ObligationState::Verified);
    assert!(obligation.proof_digest.is_some());

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn lost_ack_blocks_resend_until_provider_reconciliation() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("lost-ack");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &event_receipt, &authority, &mut journal)?;
    let mut provider = ReferenceAlertProvider::new();

    let first = dispatch_reference_alert(
        &plan,
        ReferenceProviderBehavior::LoseAckAfterDelivery,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    )?;
    assert_eq!(first.state, EffectState::Indeterminate);
    assert_eq!(provider.message_count(), 1);

    assert!(matches!(
        dispatch_reference_alert(
            &plan,
            ReferenceProviderBehavior::Deliver,
            TimestampNs(103),
            TimestampNs(104),
            &mut journal,
            &mut provider,
        ),
        Err(ReferenceError::Contract(
            fss_core::ContractError::ReconciliationRequired
        ))
    ));
    assert_eq!(provider.message_count(), 1);

    let reconciled = reconcile_reference_alert(
        &plan,
        TimestampNs(105),
        &mut journal,
        &provider,
    )?
    .ok_or(ReferenceError::InvalidSpec("missing_provider_proof"))?;
    assert_eq!(reconciled.state, EffectState::Verified);
    assert_eq!(provider.message_count(), 1);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn known_pre_delivery_failure_never_creates_provider_message() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("known-failure");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &event_receipt, &authority, &mut journal)?;
    let mut provider = ReferenceAlertProvider::new();

    let receipt = dispatch_reference_alert(
        &plan,
        ReferenceProviderBehavior::FailBeforeDelivery,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    )?;
    assert_eq!(receipt.state, EffectState::Failed);
    assert_eq!(provider.message_count(), 0);
    let obligation = journal
        .obligations()
        .find(|item| item.obligation_id == plan.obligation_id)
        .ok_or(ReferenceError::InvalidSpec("missing_obligation"))?;
    assert_eq!(obligation.state, ObligationState::Failed);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn stale_event_authority_cannot_prepare_alert() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("stale-event");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let _ = observation(
        "capture:alert:later",
        "sensor:alert:later",
        33,
        "power:alert:later",
        &mut objects,
        &mut authority,
    )?;
    let mut journal = EffectJournal::new();

    assert!(matches!(
        prepare(&decision, &event_receipt, &authority, &mut journal),
        Err(ReferenceError::InvalidSpec("event_authority_stale"))
    ));
    assert_eq!(journal.obligations().count(), 0);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn exact_prepare_retry_does_not_duplicate_obligation() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("prepare-retry");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let first = prepare(&decision, &event_receipt, &authority, &mut journal)?;
    let second = prepare(&decision, &event_receipt, &authority, &mut journal)?;
    assert_eq!(first, second);
    assert_eq!(journal.obligations().count(), 1);

    let _ = fs::remove_file(path);
    Ok(())
}

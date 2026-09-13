use std::error::Error;
use std::fs;

use fss_core::{
    CapsuleId, CaptureInterval, EffectJournal, EffectState, EventId, IdempotencyKey, ObligationId,
    ObligationState, OperationId, ProbabilityInterval, SensorId, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};

use crate::{
    DeliveryPlan, MockModelScript, MockModelSpec, MockSemanticLabel, PrepareAlertParams,
    ReferenceAlertProvider, ReferenceError, ReferenceModelObservation, ReferencePolicyDecision,
    ReferenceProviderBehavior, VirtualCameraSpec, dispatch_reference_alert,
    evaluate_unknown_presence, execute_mock_model, observe_reference_alert,
    prepare_reference_alert, publish_reference_event, reconcile_reference_alert,
    run_reference_capture, verify_reference_alert,
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
        PrepareAlertParams {
            decision,
            event_receipt,
            authority,
            operation_id: OperationId::parse("operation:alert:1")?,
            idempotency_key: IdempotencyKey::parse("idempotency:alert:1")?,
            obligation_id: ObligationId::parse("obligation:alert:1")?,
            channel: "operator:oncall".to_owned(),
            now: TimestampNs(100),
        },
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
        journal
            .operation(&plan.intent.operation_id)
            .ok_or("prepared operation receipt missing")?
            .state,
        EffectState::Prepared
    );

    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:alert");
    let receipt = dispatch_reference_alert(
        &plan,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    )?;
    assert_eq!(receipt.state, EffectState::AdapterAccepted);
    assert_eq!(provider.message_count(), 1);
    let obligation = journal
        .obligations()
        .find(|item| item.obligation_id == plan.obligation_id)
        .ok_or(ReferenceError::InvalidSpec("missing_obligation"))?;
    assert_eq!(obligation.state, ObligationState::Pending);

    let provider_receipt = provider
        .lookup(&plan.intent)?
        .ok_or(ReferenceError::InvalidSpec("missing_provider_receipt"))?;
    let observed = observe_reference_alert(
        &plan,
        provider_receipt.receipt_digest(),
        TimestampNs(103),
        &mut journal,
        &provider,
    )?;
    assert_eq!(observed.state, EffectState::Observed);

    let verified = verify_reference_alert(&plan, TimestampNs(104), &mut journal, &provider)?;
    assert_eq!(verified.state, EffectState::Verified);
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
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:lost_ack");

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

    let reconciled = reconcile_reference_alert(&plan, TimestampNs(105), &mut journal, &provider)?
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
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:known_failure");

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

#[test]
fn tamper_report_vetoes_alert_preparation() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("tamper-veto");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let mut observations = Vec::new();
    for (lane, seed, domain) in [
        ("a", 31, "power:alert:alpha"),
        ("b", 32, "power:alert:beta"),
        ("c", 33, "power:alert:gamma"),
    ] {
        observations.push(observation(
            &format!("capture:alert:tamper-{lane}"),
            &format!("sensor:alert:tamper-{lane}"),
            seed,
            domain,
            &mut objects,
            &mut authority,
        )?);
    }
    let mut decision =
        evaluate_unknown_presence(EventId::parse("event:alert:tamper-bypass")?, observations)?;
    let receipt = publish_reference_event(&decision, &mut objects, &mut authority)?;
    // The reviewer's planted bypass: the third finding is re-typed as a tamper report after
    // policy, so the revision stays corroborated by two supports.
    let tamper = decision
        .event
        .evidence
        .iter_mut()
        .find(|edge| edge.failure_domain == "power:alert:gamma")
        .ok_or(ReferenceError::InvalidSpec("missing_gamma_edge"))?;
    tamper.supports = false;
    tamper.relation = fss_core::EvidenceEdgeRelation::SensorTamper;
    assert_eq!(decision.event.state, fss_core::EventState::Corroborated);

    // Publication verifies, so the tampered revision never becomes authority.
    let published = publish_reference_event(&decision, &mut objects, &mut authority);
    assert!(
        matches!(
            published,
            Err(ReferenceError::Contract(
                fss_core::ContractError::SensorIntegrityRisk
            ))
        ),
        "{published:?}"
    );
    // The alert veto is probed directly, against the authority receipt of the untampered
    // revision: it refuses before any receipt check.
    let mut journal = EffectJournal::new();
    let refused = prepare(&decision, &receipt, &authority, &mut journal);
    assert!(
        matches!(
            refused,
            Err(ReferenceError::Contract(
                fss_core::ContractError::SensorIntegrityRisk
            ))
        ),
        "a tamper report must veto alert preparation"
    );
    assert_eq!(journal.obligations().count(), 0);
    let _ = fs::remove_file(path);
    Ok(())
}

/// Builds the revision of `prior` that carries `next`'s policy outcome.
fn successor(
    prior: &fss_core::EventHypothesis,
    next: &ReferencePolicyDecision,
) -> Result<ReferencePolicyDecision, Box<dyn Error>> {
    let event = next.event.clone();
    Ok(ReferencePolicyDecision {
        event: prior.supersede(fss_core::event::EventSupersedeParams {
            state: event.state,
            kind: event.kind,
            interval: event.interval,
            uncertainty_reason: event.uncertainty_reason,
            zone_ids: event.zone_ids,
            track_ids: event.track_ids,
            probability: event.probability,
            evidence: event.evidence,
            model_receipts: event.model_receipts,
            decision_path: event.decision_path,
        })?,
        action: next.action,
    })
}

#[test]
fn forked_revision_is_refused_at_publish_and_never_prepared() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("fork");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let event_id = EventId::parse("event:alert:fork")?;
    // Revision 1 (A) is published from one support.
    let a = observation(
        "capture:alert:fork-a",
        "sensor:alert:fork-a",
        41,
        "power:alert:alpha",
        &mut objects,
        &mut authority,
    )?;
    let published = evaluate_unknown_presence(event_id.clone(), vec![a])?;
    let published_receipt = publish_reference_event(&published, &mut objects, &mut authority)?;
    // Revision 1 (B) of the same event is built from other evidence but never published.
    let b = observation(
        "capture:alert:fork-b",
        "sensor:alert:fork-b",
        42,
        "power:alert:beta",
        &mut objects,
        &mut authority,
    )?;
    let unpublished = evaluate_unknown_presence(event_id.clone(), vec![b])?;
    // A corroborated policy outcome from two further independent supports.
    let c = observation(
        "capture:alert:fork-c",
        "sensor:alert:fork-c",
        43,
        "power:alert:gamma",
        &mut objects,
        &mut authority,
    )?;
    let d = observation(
        "capture:alert:fork-d",
        "sensor:alert:fork-d",
        44,
        "power:alert:delta",
        &mut objects,
        &mut authority,
    )?;
    let corroborated = evaluate_unknown_presence(event_id, vec![c, d])?;
    assert_eq!(corroborated.event.state, fss_core::EventState::Corroborated);

    // Probe P6: B superseded to a corroborated revision 2 whose supersedes names B, not A.
    let fork = successor(&unpublished.event, &corroborated)?;
    assert_ne!(
        fork.event.supersedes,
        Some(published.event.revision_digest())
    );
    let anchor = authority.current().anchor.clone();
    let refused = publish_reference_event(&fork, &mut objects, &mut authority);
    assert!(
        matches!(
            refused,
            Err(ReferenceError::Contract(
                fss_core::ContractError::SupersessionMismatch
            ))
        ),
        "{refused:?}"
    );
    // A second genesis of an already published event is a fork too.
    let regenesis = publish_reference_event(&unpublished, &mut objects, &mut authority);
    assert!(
        matches!(
            regenesis,
            Err(ReferenceError::Contract(
                fss_core::ContractError::SupersessionMismatch
            ))
        ),
        "{regenesis:?}"
    );
    assert_eq!(authority.current().anchor, anchor);
    // The fork never reaches effect authority: no authority receipt witnesses it.
    let mut journal = EffectJournal::new();
    let prepared = prepare(&fork, &published_receipt, &authority, &mut journal);
    assert!(
        matches!(
            prepared,
            Err(ReferenceError::InvalidSpec("event_receipt_mismatch"))
        ),
        "a forked revision must never be prepared"
    );
    assert_eq!(journal.obligations().count(), 0);

    // Control: the legitimate successor of A is published and prepared.
    let succession = successor(&published.event, &corroborated)?;
    let receipt = publish_reference_event(&succession, &mut objects, &mut authority)?;
    let plan = prepare(&succession, &receipt, &authority, &mut journal)?;
    assert_eq!(
        journal
            .operation(&plan.intent.operation_id)
            .ok_or("prepared operation receipt missing")?
            .state,
        EffectState::Prepared
    );
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn retry_of_already_current_revision_is_idempotent_and_exact_equal() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("retry-idempotent");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let event_id = EventId::parse("event:alert:retry")?;

    // Observation 1 for Genesis (Revision 1)
    let a = observation(
        "capture:alert:retry-a",
        "sensor:alert:retry-a",
        51,
        "power:alert:alpha",
        &mut objects,
        &mut authority,
    )?;
    let published_1 = evaluate_unknown_presence(event_id.clone(), vec![a])?;
    let published_receipt_1 = publish_reference_event(&published_1, &mut objects, &mut authority)?;
    let anchor_after_first = authority.current().anchor.clone();
    let batch_count_after_first = authority.batches().len();

    // Re-publishing the exact identical revision 1 that is already current is idempotent.
    let retry_receipt_1 = publish_reference_event(&published_1, &mut objects, &mut authority)?;
    // Exact equality check between original receipt and retry receipt:
    assert_eq!(retry_receipt_1, published_receipt_1);
    // Authority ledger is completely unchanged:
    assert_eq!(authority.current().anchor, anchor_after_first);
    assert_eq!(authority.batches().len(), batch_count_after_first);

    // Fork attempt: another revision 1 (B) with different evidence is refused with SupersessionMismatch.
    let b = observation(
        "capture:alert:retry-b",
        "sensor:alert:retry-b",
        52,
        "power:alert:beta",
        &mut objects,
        &mut authority,
    )?;
    let unpublished = evaluate_unknown_presence(event_id.clone(), vec![b])?;
    let anchor_before_fork = authority.current().anchor.clone();
    let batch_count_before_fork = authority.batches().len();
    let fork_regenesis = publish_reference_event(&unpublished, &mut objects, &mut authority);
    assert!(
        matches!(
            fork_regenesis,
            Err(ReferenceError::Contract(
                fss_core::ContractError::SupersessionMismatch
            ))
        ),
        "{fork_regenesis:?}"
    );
    assert_eq!(authority.current().anchor, anchor_before_fork);
    assert_eq!(authority.batches().len(), batch_count_before_fork);

    // Publish legitimate successor (Revision 2)
    let c = observation(
        "capture:alert:retry-c",
        "sensor:alert:retry-c",
        53,
        "power:alert:gamma",
        &mut objects,
        &mut authority,
    )?;
    let d = observation(
        "capture:alert:retry-d",
        "sensor:alert:retry-d",
        54,
        "power:alert:delta",
        &mut objects,
        &mut authority,
    )?;
    let corroborated = evaluate_unknown_presence(event_id.clone(), vec![c, d])?;
    let legitimate_2 = successor(&published_1.event, &corroborated)?;
    let published_receipt_2 = publish_reference_event(&legitimate_2, &mut objects, &mut authority)?;
    let anchor_after_second = authority.current().anchor.clone();
    let batch_count_after_second = authority.batches().len();
    assert_ne!(anchor_after_first, anchor_after_second);

    // Re-publishing the exact identical revision 2 that is already current is idempotent.
    let retry_receipt_2 = publish_reference_event(&legitimate_2, &mut objects, &mut authority)?;
    // Exact equality check between original receipt and retry receipt:
    assert_eq!(retry_receipt_2, published_receipt_2);
    // Authority ledger is completely unchanged:
    assert_eq!(authority.current().anchor, anchor_after_second);
    assert_eq!(authority.batches().len(), batch_count_after_second);

    // Fork attempt: revision 2 superseding B (the unpublished revision) rather than A.
    let fork_rev_2 = successor(&unpublished.event, &corroborated)?;
    let fork_rev_2_result = publish_reference_event(&fork_rev_2, &mut objects, &mut authority);
    assert!(
        matches!(
            fork_rev_2_result,
            Err(ReferenceError::Contract(
                fss_core::ContractError::SupersessionMismatch
            ))
        ),
        "{fork_rev_2_result:?}"
    );
    assert_eq!(authority.current().anchor, anchor_after_second);

    // Fork attempt: re-publishing stale revision 1 now that revision 2 is current
    // must be refused with SupersessionMismatch (since revision 1 is no longer current witness).
    let stale_retry = publish_reference_event(&published_1, &mut objects, &mut authority);
    assert!(
        matches!(
            stale_retry,
            Err(ReferenceError::Contract(
                fss_core::ContractError::SupersessionMismatch
            ))
        ),
        "{stale_retry:?}"
    );
    assert_eq!(authority.current().anchor, anchor_after_second);

    let _ = fs::remove_file(path);
    Ok(())
}

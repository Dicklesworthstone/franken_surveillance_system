use std::error::Error;
use std::fs;

use fss_core::{
    CapsuleId, CaptureInterval, ContractError, EffectJournal, EffectState, EventId, IdempotencyKey,
    ObligationId, ObligationState, OperationId, ProbabilityInterval, SensorId, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};

use crate::{
    DeliveryPlan, DurableEffectError, DurableEffectJournal, MockModelScript, MockModelSpec,
    MockSemanticLabel, ObligationLedgerState, PrepareAlertParams, ReferenceAlertProvider,
    ReferenceError, ReferenceModelObservation, ReferencePolicyDecision, ReferenceProviderBehavior,
    VirtualCameraSpec, dispatch_reference_alert, evaluate_unknown_presence, execute_mock_model,
    observe_reference_alert, prepare_reference_alert, publish_reference_event,
    reconcile_reference_alert, run_reference_capture, verify_reference_alert,
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
    observation_with_label(
        capture_name,
        sensor_name,
        seed,
        failure_domain,
        MockSemanticLabel::PersonLike,
        objects,
        ledger,
    )
}

fn observation_with_label(
    capture_name: &str,
    sensor_name: &str,
    seed: u64,
    failure_domain: &str,
    label: MockSemanticLabel,
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
            label,
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
        &authority,
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
        &authority,
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
            &authority,
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
        &authority,
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

#[test]
fn retry_after_unrelated_batch_returns_original_receipt_and_anchor() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("retry-unrelated-batch");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let event_id = EventId::parse("event:alert:retry-unrelated")?;
    let a = observation(
        "capture:alert:retry-unrelated-a",
        "sensor:alert:retry-unrelated-a",
        61,
        "power:alert:alpha",
        &mut objects,
        &mut authority,
    )?;
    let decision = evaluate_unknown_presence(event_id, vec![a])?;
    let receipt = publish_reference_event(&decision, &mut objects, &mut authority)?;

    // An unrelated authority batch lands after the event publication, advancing the ledger anchor.
    let _e = observation(
        "capture:alert:retry-unrelated-e",
        "sensor:alert:retry-unrelated-e",
        62,
        "power:alert:epsilon",
        &mut objects,
        &mut authority,
    )?;
    let anchor_before = authority.current().anchor.clone();
    let batches_before = authority.batches().len();

    // The current ledger anchor is now strictly different from the event's commit anchor.
    assert_ne!(anchor_before, receipt.authority_anchor);

    // Retrying the exact event revision returns the original receipt and committed anchor (kills mutant M2).
    let retry = publish_reference_event(&decision, &mut objects, &mut authority)?;
    assert_eq!(retry, receipt);
    assert_eq!(retry.authority_anchor, receipt.authority_anchor);
    assert_ne!(retry.authority_anchor, anchor_before);

    // Ledger is completely unchanged by the idempotent retry:
    assert_eq!(authority.current().anchor, anchor_before);
    assert_eq!(authority.batches().len(), batches_before);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn retry_after_crash_reopen_recovers_original_receipt_and_anchor() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("retry-crash-reopen");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let event_id = EventId::parse("event:alert:retry-reopen")?;
    let a = observation(
        "capture:alert:retry-reopen-a",
        "sensor:alert:retry-reopen-a",
        71,
        "power:alert:alpha",
        &mut objects,
        &mut authority,
    )?;
    let decision = evaluate_unknown_presence(event_id, vec![a])?;
    let receipt = publish_reference_event(&decision, &mut objects, &mut authority)?;
    let batches = authority.batches().len();

    // Drop the authority ledger and reopen from disk (simulating crash recovery).
    drop(authority);
    let mut reopened =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    assert_eq!(reopened.batches().len(), batches);

    // Retry against the reopened ledger returns the exact original receipt and anchor.
    let retry = publish_reference_event(&decision, &mut objects, &mut reopened)?;
    assert_eq!(retry, receipt);
    assert_eq!(retry.authority_anchor, receipt.authority_anchor);
    assert_eq!(reopened.batches().len(), batches);

    // With a fresh object store (in-memory store lost in the crash), the retry must not
    // silently succeed with unverified model receipts, and must not touch authority.
    let mut fresh = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let lost = publish_reference_event(&decision, &mut fresh, &mut reopened);
    assert!(lost.is_err(), "{lost:?}");
    assert_eq!(reopened.batches().len(), batches);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn retry_same_revision2_different_content_refused_exact_retried() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("retry-rev2-diff");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let event_id = EventId::parse("event:alert:retry-rev2")?;
    let a = observation(
        "capture:alert:retry-rev2-a",
        "sensor:alert:retry-rev2-a",
        81,
        "power:alert:alpha",
        &mut objects,
        &mut authority,
    )?;
    let first = evaluate_unknown_presence(event_id.clone(), vec![a])?;
    let _r1 = publish_reference_event(&first, &mut objects, &mut authority)?;

    let c = observation(
        "capture:alert:retry-rev2-c",
        "sensor:alert:retry-rev2-c",
        82,
        "power:alert:gamma",
        &mut objects,
        &mut authority,
    )?;
    let d = observation(
        "capture:alert:retry-rev2-d",
        "sensor:alert:retry-rev2-d",
        83,
        "power:alert:delta",
        &mut objects,
        &mut authority,
    )?;
    let f = observation(
        "capture:alert:retry-rev2-f",
        "sensor:alert:retry-rev2-f",
        84,
        "power:alert:phi",
        &mut objects,
        &mut authority,
    )?;

    let rev2 = successor(
        &first.event,
        &evaluate_unknown_presence(event_id.clone(), vec![c.clone(), d])?,
    )?;
    let r2 = publish_reference_event(&rev2, &mut objects, &mut authority)?;

    // Same revision number 2, correct supersedes (rev1), but different evidence.
    let rev2_alt = successor(
        &first.event,
        &evaluate_unknown_presence(event_id, vec![c, f])?,
    )?;
    assert_eq!(rev2_alt.event.revision, rev2.event.revision);
    assert_eq!(rev2_alt.event.supersedes, rev2.event.supersedes);
    assert_ne!(
        rev2_alt.event.revision_digest(),
        rev2.event.revision_digest()
    );

    let batches = authority.batches().len();
    let anchor = authority.current().anchor.clone();
    let res = publish_reference_event(&rev2_alt, &mut objects, &mut authority);
    assert!(
        matches!(
            res,
            Err(ReferenceError::Contract(
                fss_core::ContractError::SupersessionMismatch
            ))
        ),
        "{res:?}"
    );
    assert_eq!(authority.batches().len(), batches);
    assert_eq!(authority.current().anchor, anchor);

    // Original revision 2 still retries idempotently.
    assert_eq!(
        publish_reference_event(&rev2, &mut objects, &mut authority)?,
        r2
    );

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn stale_event_authority_cannot_dispatch_alert() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("stale-dispatch");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &event_receipt, &authority, &mut journal)?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:stale_dispatch");

    // Later observation creates a newer indeterminate revision without tamper.
    let later_obs = observation_with_label(
        "capture:alert:later-unknown",
        "sensor:alert:later-unknown",
        51,
        "power:alert:later-unknown",
        MockSemanticLabel::Unknown,
        &mut objects,
        &mut authority,
    )?;
    let evaluation_2 = evaluate_unknown_presence(decision.event.event_id.clone(), vec![later_obs])?;
    assert_eq!(
        evaluation_2.event.state,
        fss_core::EventState::Indeterminate
    );
    let decision_2 = successor(&decision.event, &evaluation_2)?;
    let _receipt_2 = publish_reference_event(&decision_2, &mut objects, &mut authority)?;

    // Dispatching against authority (which now has revision 2) fails with StaleEventAuthority.
    let res = dispatch_reference_alert(
        &plan,
        &authority,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    );
    assert!(
        matches!(res, Err(ReferenceError::StaleEventAuthority)),
        "expected StaleEventAuthority, got: {res:?}"
    );
    assert_eq!(provider.message_count(), 0);
    assert_eq!(
        journal
            .operation(&plan.intent.operation_id)
            .ok_or(ReferenceError::InvalidSpec("missing_operation"))?
            .state,
        EffectState::Cancelled
    );
    assert_eq!(
        journal
            .obligations()
            .find(|item| item.obligation_id == plan.obligation_id)
            .ok_or(ReferenceError::InvalidSpec("missing_obligation"))?
            .state,
        ObligationState::Cancelled
    );

    // A second dispatch call on the same plan must also fail (operation not in Prepared state).
    let second_res = dispatch_reference_alert(
        &plan,
        &authority,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(103),
        TimestampNs(104),
        &mut journal,
        &mut provider,
    );
    assert!(
        matches!(
            second_res,
            Err(ReferenceError::Contract(
                fss_core::ContractError::InvalidEffectTransition
            ))
        ),
        "expected InvalidEffectTransition, got: {second_res:?}"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn later_tamper_revision_vetoes_in_flight_alert_dispatch_p5b() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("p5b-tamper-veto");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision_1, event_receipt_1) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision_1, &event_receipt_1, &authority, &mut journal)?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:p5b");

    assert_eq!(
        journal
            .operation(&plan.intent.operation_id)
            .ok_or(ReferenceError::InvalidSpec("missing_operation"))?
            .state,
        EffectState::Prepared
    );
    assert_eq!(
        journal
            .obligations()
            .find(|item| item.obligation_id == plan.obligation_id)
            .ok_or(ReferenceError::InvalidSpec("missing_obligation"))?
            .state,
        ObligationState::Pending
    );

    // Later tamper report arrives.
    let tamper_obs = observation_with_label(
        "capture:alert:p5b-tamper",
        "sensor:alert:p5b-tamper",
        99,
        "power:alert:p5b-tamper",
        MockSemanticLabel::TamperLike,
        &mut objects,
        &mut authority,
    )?;
    let evaluation_2 = evaluate_unknown_presence(
        decision_1.event.event_id.clone(),
        vec![
            observation(
                "capture:alert:p5b-a",
                "sensor:alert:p5b-a",
                111,
                "power:alert:p5b-a",
                &mut objects,
                &mut authority,
            )?,
            observation(
                "capture:alert:p5b-b",
                "sensor:alert:p5b-b",
                222,
                "power:alert:p5b-b",
                &mut objects,
                &mut authority,
            )?,
            tamper_obs,
        ],
    )?;
    assert_eq!(
        evaluation_2.event.state,
        fss_core::EventState::Indeterminate
    );
    let decision_2 = successor(&decision_1.event, &evaluation_2)?;
    let _receipt_2 = publish_reference_event(&decision_2, &mut objects, &mut authority)?;

    assert_eq!(decision_2.event.revision, 2);
    assert_eq!(
        decision_2.event.supersedes,
        Some(decision_1.event.revision_digest())
    );

    // Dispatching against authority after tamper revision published must refuse with StaleEventAuthority.
    let dispatch_result = dispatch_reference_alert(
        &plan,
        &authority,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    );
    assert!(
        matches!(dispatch_result, Err(ReferenceError::StaleEventAuthority)),
        "expected StaleEventAuthority, got: {dispatch_result:?}"
    );

    assert_eq!(provider.message_count(), 0);
    assert_eq!(
        journal
            .operation(&plan.intent.operation_id)
            .ok_or(ReferenceError::InvalidSpec("missing_operation"))?
            .state,
        EffectState::Cancelled
    );
    assert_eq!(
        journal
            .obligations()
            .find(|item| item.obligation_id == plan.obligation_id)
            .ok_or(ReferenceError::InvalidSpec("missing_obligation"))?
            .state,
        ObligationState::Cancelled
    );

    // A second dispatch call on the same plan must also fail (operation not in Prepared state).
    let second_dispatch = dispatch_reference_alert(
        &plan,
        &authority,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(103),
        TimestampNs(104),
        &mut journal,
        &mut provider,
    );
    assert!(
        matches!(
            second_dispatch,
            Err(ReferenceError::Contract(
                fss_core::ContractError::InvalidEffectTransition
            ))
        ),
        "expected InvalidEffectTransition, got: {second_dispatch:?}"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn unrelated_observation_batch_still_delivers_alert_p6() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("unrelated-batch-p6");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &event_receipt, &authority, &mut journal)?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:p6:unrelated");

    // An unrelated observation arrives for a different sensor and is committed to authority.
    let _unrelated_obs = observation_with_label(
        "capture:alert:unrelated-sensor",
        "sensor:alert:unrelated-sensor",
        501,
        "power:alert:unrelated",
        MockSemanticLabel::PersonLike,
        &mut objects,
        &mut authority,
    )?;

    // Dispatching against authority must SUCCEED because this event's revision was not modified.
    let receipt = dispatch_reference_alert(
        &plan,
        &authority,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    )?;

    assert_eq!(receipt.state, EffectState::AdapterAccepted);
    assert_eq!(provider.message_count(), 1);
    assert_eq!(
        journal
            .operation(&plan.intent.operation_id)
            .ok_or(ReferenceError::InvalidSpec("missing_operation"))?
            .state,
        EffectState::AdapterAccepted
    );

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn refusal_at_or_before_prepare_time_cancels_op_and_obligation_p7() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("p7-time-monotonic");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    // Prepare time is 100ns.
    let plan = prepare_reference_alert(
        PrepareAlertParams {
            decision: &decision,
            event_receipt: &event_receipt,
            authority: &authority,
            operation_id: OperationId::parse("op:alert:p7")?,
            idempotency_key: IdempotencyKey::parse("idempotency:alert:p7")?,
            obligation_id: ObligationId::parse("obligation:alert:p7")?,
            channel: "security-sms".to_string(),
            now: TimestampNs(100),
        },
        &mut journal,
    )?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:p7");

    // Later tamper report arrives, making event authority stale.
    let tamper_obs = observation_with_label(
        "capture:alert:p7-tamper",
        "sensor:alert:p7-tamper",
        99,
        "power:alert:p7-tamper",
        MockSemanticLabel::TamperLike,
        &mut objects,
        &mut authority,
    )?;
    let evaluation_2 =
        evaluate_unknown_presence(decision.event.event_id.clone(), vec![tamper_obs])?;
    let decision_2 = successor(&decision.event, &evaluation_2)?;
    let _receipt_2 = publish_reference_event(&decision_2, &mut objects, &mut authority)?;

    // Dispatch requested at commit_at = 50ns (STRICTLY BEFORE prepare time 100ns).
    let res = dispatch_reference_alert(
        &plan,
        &authority,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(50),
        TimestampNs(60),
        &mut journal,
        &mut provider,
    );
    assert!(
        matches!(res, Err(ReferenceError::StaleEventAuthority)),
        "expected StaleEventAuthority, got: {res:?}"
    );

    // The operation and obligation MUST NOT remain Prepared/Pending!
    let op = journal
        .operation(&plan.intent.operation_id)
        .ok_or(ReferenceError::InvalidSpec("missing_operation"))?;
    assert_eq!(
        op.state,
        EffectState::Cancelled,
        "operation must be Cancelled, not left Prepared"
    );
    assert!(
        op.updated_at > TimestampNs(100),
        "cancellation time must be strictly after prepare time"
    );

    let obl = journal
        .obligations()
        .find(|item| item.obligation_id == plan.obligation_id)
        .ok_or(ReferenceError::InvalidSpec("missing_obligation"))?;
    assert_eq!(
        obl.state,
        ObligationState::Cancelled,
        "obligation must be Cancelled, not left Pending"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn durable_dispatch_refuses_on_tamper_and_persists_cancelled_record_p8()
-> Result<(), Box<dyn Error>> {
    let ledger_path = temp_journal("p8-tamper-ledger");
    let journal_path = temp_journal("p8-tamper-journal");
    let _ = fs::remove_file(&ledger_path);
    let _ = fs::remove_file(&journal_path);

    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&ledger_path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision_1, event_receipt_1) = eligible_event(&mut objects, &mut authority)?;

    let mut durable_journal =
        crate::DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
    let plan = durable_journal.prepare_alert(PrepareAlertParams {
        decision: &decision_1,
        event_receipt: &event_receipt_1,
        authority: &authority,
        operation_id: OperationId::parse("op:alert:p8")?,
        idempotency_key: IdempotencyKey::parse("idempotency:alert:p8")?,
        obligation_id: ObligationId::parse("obligation:alert:p8")?,
        channel: "security-sms".to_string(),
        now: TimestampNs(100),
    })?;

    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:p8");

    // Later tamper report arrives in authority ledger.
    let tamper_obs = observation_with_label(
        "capture:alert:p8-tamper",
        "sensor:alert:p8-tamper",
        99,
        "power:alert:p8-tamper",
        MockSemanticLabel::TamperLike,
        &mut objects,
        &mut authority,
    )?;
    let evaluation_2 =
        evaluate_unknown_presence(decision_1.event.event_id.clone(), vec![tamper_obs])?;
    let decision_2 = successor(&decision_1.event, &evaluation_2)?;
    let _receipt_2 = publish_reference_event(&decision_2, &mut objects, &mut authority)?;

    // Durable dispatch must be refused with StaleEventAuthority.
    let dispatch_res = durable_journal.dispatch_alert(
        &plan,
        &authority,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(110),
        TimestampNs(120),
        &mut provider,
    );
    assert!(
        matches!(
            dispatch_res,
            Err(crate::DurableEffectError::Reference(
                ReferenceError::StaleEventAuthority
            ))
        ),
        "expected StaleEventAuthority, got: {dispatch_res:?}"
    );

    // 0 messages delivered.
    assert_eq!(provider.message_count(), 0);

    // In-memory state is Cancelled.
    let op = durable_journal
        .operation(&plan.intent.operation_id)
        .ok_or(ReferenceError::InvalidSpec("missing_operation"))?;
    assert_eq!(op.state, EffectState::Cancelled);

    let obl = durable_journal
        .obligations()
        .find(|item| item.obligation_id == plan.obligation_id)
        .ok_or(ReferenceError::InvalidSpec("missing_obligation"))?;
    assert_eq!(obl.state, ObligationState::Cancelled);

    // Drop and reopen from disk (replaying journal): Cancelled state must persist!
    drop(durable_journal);
    let mut reopened =
        crate::DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
    let reopened_op = reopened
        .operation(&plan.intent.operation_id)
        .ok_or(ReferenceError::InvalidSpec("missing_operation"))?;
    assert_eq!(
        reopened_op.state,
        EffectState::Cancelled,
        "Cancelled state must persist across journal reopen"
    );
    let reopened_obl = reopened
        .obligations()
        .find(|item| item.obligation_id == plan.obligation_id)
        .ok_or(ReferenceError::InvalidSpec("missing_obligation"))?;
    assert_eq!(
        reopened_obl.state,
        ObligationState::Cancelled,
        "Cancelled obligation must persist across journal reopen"
    );

    // A second dispatch attempt on the reopened journal must fail with InvalidEffectTransition.
    let second_res = reopened.dispatch_alert(
        &plan,
        &authority,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(200),
        TimestampNs(210),
        &mut provider,
    );
    assert!(
        matches!(
            second_res,
            Err(crate::DurableEffectError::Contract(
                fss_core::ContractError::InvalidEffectTransition
            ))
        ),
        "expected InvalidEffectTransition on second dispatch, got: {second_res:?}"
    );

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(journal_path);
    Ok(())
}

#[test]
fn cancel_proof_binds_operation_id_and_both_anchors_p10() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("p10-cancel-proof");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &event_receipt, &authority, &mut journal)?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:p10");

    let tamper_obs = observation_with_label(
        "capture:alert:p10-tamper",
        "sensor:alert:p10-tamper",
        99,
        "power:alert:p10-tamper",
        MockSemanticLabel::TamperLike,
        &mut objects,
        &mut authority,
    )?;
    let evaluation_2 =
        evaluate_unknown_presence(decision.event.event_id.clone(), vec![tamper_obs])?;
    let decision_2 = successor(&decision.event, &evaluation_2)?;
    let _receipt_2 = publish_reference_event(&decision_2, &mut objects, &mut authority)?;

    let displacing_anchor = authority.current().anchor.clone();
    assert_ne!(plan.authority_anchor, displacing_anchor);

    let res = dispatch_reference_alert(
        &plan,
        &authority,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    );
    assert!(matches!(res, Err(ReferenceError::StaleEventAuthority)));

    let expected_proof = crate::alert_cancel_proof(
        &plan.intent.operation_id,
        &plan.authority_anchor,
        &displacing_anchor,
    );

    let op = journal
        .operation(&plan.intent.operation_id)
        .ok_or(ReferenceError::InvalidSpec("missing_operation"))?;
    assert_eq!(op.result_digest, Some(expected_proof));

    // Ensure cancel proof is distinct when operation_id or displacing anchor changes.
    let diff_op = OperationId::parse("operation:alert:different")?;
    let diff_proof =
        crate::alert_cancel_proof(&diff_op, &plan.authority_anchor, &displacing_anchor);
    assert_ne!(expected_proof, diff_proof);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn test_rewritten_plan_refused_on_in_memory_dispatch_x6() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("x6-in-memory");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let mut plan = prepare(&decision, &event_receipt, &authority, &mut journal)?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:x6_mem");

    // Publish a tampered revision
    let tamper_obs = observation_with_label(
        "capture:alert:x6-tamper",
        "sensor:alert:x6-tamper",
        99,
        "power:alert:x6-tamper",
        MockSemanticLabel::TamperLike,
        &mut objects,
        &mut authority,
    )?;
    let evaluation_2 =
        evaluate_unknown_presence(decision.event.event_id.clone(), vec![tamper_obs])?;
    let decision_2 = successor(&decision.event, &evaluation_2)?;
    let receipt_2 = publish_reference_event(&decision_2, &mut objects, &mut authority)?;

    // Probe X6: Rewriting the plan's fields to point at the tampered revision
    plan.event_root = receipt_2.event_root;
    plan.event_revision_digest = receipt_2.event_revision_digest;
    plan.authority_anchor = receipt_2.authority_anchor.clone();
    plan.intent.request_digest = crate::alert::alert_request_digest(&receipt_2, &plan.channel);

    let res = dispatch_reference_alert(
        &plan,
        &authority,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    );

    assert!(matches!(res, Err(ReferenceError::StaleEventAuthority)));
    assert_eq!(provider.message_count(), 0);

    let op = journal
        .operation(&plan.intent.operation_id)
        .ok_or(ReferenceError::InvalidSpec("missing_operation"))?;
    assert_eq!(op.state, EffectState::Cancelled);

    let ob = journal
        .obligations()
        .find(|o| o.operation_id == plan.intent.operation_id)
        .ok_or(ReferenceError::InvalidSpec("missing_obligation"))?;
    assert_eq!(ob.state, ObligationState::Cancelled);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn test_rewritten_plan_refused_on_durable_dispatch_x6() -> Result<(), Box<dyn Error>> {
    let ledger_path = temp_journal("x6-durable-ledger");
    let journal_path = temp_journal("x6-durable-journal");
    let _ = fs::remove_file(&ledger_path);
    let _ = fs::remove_file(&journal_path);

    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&ledger_path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;

    let mut durable_journal =
        DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
    let mut plan = durable_journal.prepare_alert(PrepareAlertParams {
        decision: &decision,
        event_receipt: &event_receipt,
        authority: &authority,
        operation_id: OperationId::parse("operation:alert:x6-durable")?,
        idempotency_key: IdempotencyKey::parse("idempotency:alert:x6-durable")?,
        obligation_id: ObligationId::parse("obligation:alert:x6-durable")?,
        channel: "operator:oncall".to_owned(),
        now: TimestampNs(100),
    })?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:x6_durable");

    // Publish a tampered revision
    let tamper_obs = observation_with_label(
        "capture:alert:x6-durable-tamper",
        "sensor:alert:x6-durable-tamper",
        99,
        "power:alert:x6-durable-tamper",
        MockSemanticLabel::TamperLike,
        &mut objects,
        &mut authority,
    )?;
    let evaluation_2 =
        evaluate_unknown_presence(decision.event.event_id.clone(), vec![tamper_obs])?;
    let decision_2 = successor(&decision.event, &evaluation_2)?;
    let receipt_2 = publish_reference_event(&decision_2, &mut objects, &mut authority)?;

    // Probe X6: Rewriting the plan's fields to point at the tampered revision
    plan.event_root = receipt_2.event_root;
    plan.event_revision_digest = receipt_2.event_revision_digest;
    plan.authority_anchor = receipt_2.authority_anchor.clone();
    plan.intent.request_digest = crate::alert::alert_request_digest(&receipt_2, &plan.channel);

    let res = durable_journal.dispatch_alert(
        &plan,
        &authority,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut provider,
    );

    assert!(matches!(
        res,
        Err(DurableEffectError::Reference(
            ReferenceError::StaleEventAuthority
        ))
    ));
    assert_eq!(provider.message_count(), 0);

    let op = durable_journal
        .operation(&plan.intent.operation_id)
        .ok_or(ReferenceError::InvalidSpec("missing_operation"))?;
    assert_eq!(op.state, EffectState::Cancelled);

    let ob = durable_journal
        .obligation(&plan.obligation_id)
        .ok_or(ReferenceError::InvalidSpec("missing_obligation"))?;
    assert_eq!(ob.state, ObligationState::Cancelled);

    // Verify persistence across reopen
    let reopened = DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
    let reopened_op = reopened
        .operation(&plan.intent.operation_id)
        .ok_or(ReferenceError::InvalidSpec("missing_operation_reopened"))?;
    assert_eq!(reopened_op.state, EffectState::Cancelled);

    let reopened_ob = reopened
        .obligation(&plan.obligation_id)
        .ok_or(ReferenceError::InvalidSpec("missing_obligation_reopened"))?;
    assert_eq!(reopened_ob.state, ObligationState::Cancelled);

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(journal_path);
    Ok(())
}

#[test]
fn test_tamper_before_dispatch_refused_and_cancels_x1() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("x1-public-tamper");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &event_receipt, &authority, &mut journal)?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:x1");

    // Publish tamper before dispatch
    let tamper_obs = observation_with_label(
        "capture:alert:x1-tamper",
        "sensor:alert:x1-tamper",
        99,
        "power:alert:x1-tamper",
        MockSemanticLabel::TamperLike,
        &mut objects,
        &mut authority,
    )?;
    let evaluation_2 =
        evaluate_unknown_presence(decision.event.event_id.clone(), vec![tamper_obs])?;
    let decision_2 = successor(&decision.event, &evaluation_2)?;
    let _receipt_2 = publish_reference_event(&decision_2, &mut objects, &mut authority)?;

    // Public dispatch call must refuse
    let res = dispatch_reference_alert(
        &plan,
        &authority,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    );
    assert!(matches!(res, Err(ReferenceError::StaleEventAuthority)));
    assert_eq!(provider.message_count(), 0);

    let op = journal
        .operation(&plan.intent.operation_id)
        .ok_or(ReferenceError::InvalidSpec("missing_operation"))?;
    assert_eq!(op.state, EffectState::Cancelled);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn test_cross_ledger_authority_refused_and_cancels_x2() -> Result<(), Box<dyn Error>> {
    let path_a = temp_journal("x2-ledger-a");
    let path_b = temp_journal("x2-ledger-b");
    let _ = fs::remove_file(&path_a);
    let _ = fs::remove_file(&path_b);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority_a =
        DurableReferenceLedger::open(&path_a, "site:alert:a", IncompleteTailPolicy::Reject)?;
    let mut authority_b =
        DurableReferenceLedger::open(&path_b, "site:alert:b", IncompleteTailPolicy::Reject)?;

    let (decision_a, event_receipt_a) = eligible_event(&mut objects, &mut authority_a)?;
    let (decision_b, event_receipt_b) = eligible_event(&mut objects, &mut authority_b)?;

    let mut journal_a = EffectJournal::new();
    let _plan_a = prepare(&decision_a, &event_receipt_a, &authority_a, &mut journal_a)?;

    let mut journal_b = EffectJournal::new();
    let plan_b = prepare(&decision_b, &event_receipt_b, &authority_b, &mut journal_b)?;

    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:x2");

    // Attempting to dispatch plan B using authority ledger A must be refused
    let res = dispatch_reference_alert(
        &plan_b,
        &authority_a,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal_b,
        &mut provider,
    );
    assert!(matches!(res, Err(ReferenceError::StaleEventAuthority)));
    assert_eq!(provider.message_count(), 0);

    let op = journal_b
        .operation(&plan_b.intent.operation_id)
        .ok_or(ReferenceError::InvalidSpec("missing_operation"))?;
    assert_eq!(op.state, EffectState::Cancelled);

    let _ = fs::remove_file(path_a);
    let _ = fs::remove_file(path_b);
    Ok(())
}

#[test]
fn test_crash_after_commit_recovery_requires_reconcile() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("crash-commit-requires-reconcile");
    let ledger_path = temp_journal("crash-commit-requires-reconcile-ledger");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&ledger_path);

    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&ledger_path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;

    let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
    let plan = journal.prepare_alert(PrepareAlertParams {
        decision: &decision,
        event_receipt: &event_receipt,
        authority: &authority,
        operation_id: OperationId::parse("operation:alert:crash1")?,
        idempotency_key: IdempotencyKey::parse("idempotency:alert:crash1")?,
        obligation_id: ObligationId::parse("obligation:alert:crash1")?,
        channel: "operator:oncall".to_owned(),
        now: TimestampNs(100),
    })?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:crash1");

    // Session 1: Commit durably on disk, then direct provider dispatch simulates crash before AdapterAccepted
    journal.transition(
        &plan.intent.operation_id,
        EffectState::Committed,
        TimestampNs(110),
        None,
        None,
    )?;
    provider.dispatch(&plan.intent, ReferenceProviderBehavior::Deliver);

    // Session 2: System reboots; journal is replayed from disk in Committed state
    let mut rebooted = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
    let redispatch_res = rebooted.dispatch_alert(
        &plan,
        &authority,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(200),
        TimestampNs(210),
        &mut provider,
    );
    assert!(matches!(
        redispatch_res,
        Err(DurableEffectError::Contract(
            ContractError::ReconciliationRequired
        ))
    ));

    // Reconcile alert with provider evidence
    let provider_proof = provider
        .lookup(&plan.intent)?
        .ok_or(ContractError::NotFound)?
        .receipt_digest();
    let reconciled = rebooted.reconcile_alert(&plan, TimestampNs(215), &provider)?;
    let receipt = reconciled.ok_or(ContractError::NotFound)?;
    assert_eq!(receipt.state, EffectState::Verified);
    assert_eq!(receipt.result_digest, Some(provider_proof));

    let obligation = rebooted
        .obligations()
        .find(|o| o.obligation_id == plan.obligation_id)
        .ok_or(ContractError::NotFound)?;
    assert_eq!(obligation.state, ObligationState::Verified);

    match rebooted.classify_obligation(&plan.obligation_id, &authority)? {
        ObligationLedgerState::PendingLedger(pending) => {
            assert_eq!(pending.obligation.obligation_id, plan.obligation_id);
            assert_eq!(pending.obligation.state, ObligationState::Verified);
        }
        other => return Err(format!("expected PendingLedger, got {other:?}").into()),
    }

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(ledger_path);
    Ok(())
}

#[test]
fn test_crash_after_commit_recovery_via_reconcile() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("crash-commit-via-reconcile");
    let ledger_path = temp_journal("crash-commit-via-reconcile-ledger");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&ledger_path);

    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&ledger_path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;

    let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
    let plan = journal.prepare_alert(PrepareAlertParams {
        decision: &decision,
        event_receipt: &event_receipt,
        authority: &authority,
        operation_id: OperationId::parse("operation:alert:crash2")?,
        idempotency_key: IdempotencyKey::parse("idempotency:alert:crash2")?,
        obligation_id: ObligationId::parse("obligation:alert:crash2")?,
        channel: "operator:oncall".to_owned(),
        now: TimestampNs(100),
    })?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:crash2");

    journal.transition(
        &plan.intent.operation_id,
        EffectState::Committed,
        TimestampNs(110),
        None,
        None,
    )?;
    provider.dispatch(&plan.intent, ReferenceProviderBehavior::Deliver);
    let provider_proof = provider
        .lookup(&plan.intent)?
        .ok_or(ContractError::NotFound)?
        .receipt_digest();

    // Session 2: System reboots; operator runs reconciliation on open obligations
    let mut rebooted = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
    let reconciled = rebooted.reconcile_alert(&plan, TimestampNs(200), &provider)?;
    let receipt = reconciled.ok_or(ContractError::NotFound)?;
    assert_eq!(receipt.state, EffectState::Verified);
    assert_eq!(receipt.result_digest, Some(provider_proof));

    let obligation = rebooted
        .obligations()
        .find(|o| o.obligation_id == plan.obligation_id)
        .ok_or(ContractError::NotFound)?;
    assert_eq!(obligation.state, ObligationState::Verified);

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(ledger_path);
    Ok(())
}

#[test]
fn test_crash_after_commit_blind_redispatch_refused_on_reboot() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("crash-commit-redispatch-refused");
    let ledger_path = temp_journal("crash-commit-redispatch-refused-ledger");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&ledger_path);

    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&ledger_path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;

    let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
    let plan = journal.prepare_alert(PrepareAlertParams {
        decision: &decision,
        event_receipt: &event_receipt,
        authority: &authority,
        operation_id: OperationId::parse("operation:alert:crash3")?,
        idempotency_key: IdempotencyKey::parse("idempotency:alert:crash3")?,
        obligation_id: ObligationId::parse("obligation:alert:crash3")?,
        channel: "operator:oncall".to_owned(),
        now: TimestampNs(100),
    })?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:crash3");

    journal.transition(
        &plan.intent.operation_id,
        EffectState::Committed,
        TimestampNs(110),
        None,
        None,
    )?;
    provider.dispatch(&plan.intent, ReferenceProviderBehavior::Deliver);

    // Session 2: Reopen; calling dispatch_alert MUST NOT blindly redispatch
    let mut rebooted = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
    let redispatch_res = rebooted.dispatch_alert(
        &plan,
        &authority,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(200),
        TimestampNs(210),
        &mut provider,
    );

    assert!(matches!(
        redispatch_res,
        Err(DurableEffectError::Contract(
            ContractError::ReconciliationRequired
        ))
    ));

    // Reconcile alert instead of re-dispatching
    let reconciled = rebooted.reconcile_alert(&plan, TimestampNs(220), &provider)?;
    let receipt = reconciled.ok_or(ContractError::NotFound)?;
    assert_eq!(receipt.state, EffectState::Verified);

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(ledger_path);
    Ok(())
}

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
    MockSemanticLabel, ObligationLedgerState, PrepareAlertParams,
    REFERENCE_ALERT_TERMINAL_PREDICATE, ReferenceAlertProvider, ReferenceError,
    ReferenceModelObservation, ReferencePolicyDecision, ReferenceProviderBehavior,
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
        &objects,
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
        &objects,
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
            &objects,
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
        &objects,
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

/// Builds the revision of the genesis `prior` that carries `next`'s policy outcome.
fn successor(
    prior: &fss_core::EventHypothesis,
    next: &ReferencePolicyDecision,
) -> Result<ReferencePolicyDecision, Box<dyn Error>> {
    successor_in(std::slice::from_ref(prior), next)
}

/// Builds the successor of the last revision of `chain` (that revision's complete lineage, genesis
/// first) carrying `next`'s policy outcome.
fn successor_in(
    chain: &[fss_core::EventHypothesis],
    next: &ReferencePolicyDecision,
) -> Result<ReferencePolicyDecision, Box<dyn Error>> {
    let prior = chain.last().ok_or("empty lineage")?;
    let event = next.event.clone();
    Ok(ReferencePolicyDecision {
        event: prior.supersede(
            fss_core::event::EventSupersedeParams {
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
            },
            chain,
        )?,
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
        &objects,
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
        &objects,
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
        &objects,
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
        &objects,
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
        &objects,
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
        &objects,
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
    // The tamper successor published a newer revision of the event after the prepared anchor, so
    // the refusal's recorded evidence names that displacing anchor and verifies (fss-thzlz). The
    // same cancellation claimed at the prepared anchor itself, where nothing was displaced, is
    // refused (rthz2 H2).
    let prepared = journal.prepared_record(&plan.intent.operation_id)?;
    let displacing_anchor = authority.current().anchor.clone();
    assert_ne!(displacing_anchor, plan.authority_anchor);
    let recorded = journal
        .operation(&plan.intent.operation_id)
        .and_then(|operation| operation.result_digest)
        .ok_or(ReferenceError::InvalidSpec("missing_cancellation_proof"))?;
    assert_eq!(
        recorded,
        crate::alert::alert_cancellation_proof(
            &prepared,
            &plan.authority_anchor,
            &displacing_anchor
        )
    );
    assert!(crate::alert::alert_cancellation_is_bound(
        recorded, &prepared, &plan, &authority
    ));
    let undisplaced = crate::alert::alert_cancellation_proof(
        &prepared,
        &plan.authority_anchor,
        &plan.authority_anchor,
    );
    assert_ne!(undisplaced, recorded);
    assert!(!crate::alert::alert_cancellation_is_bound(
        undisplaced,
        &prepared,
        &plan,
        &authority
    ));

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
        &objects,
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
        &objects,
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
        &objects,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    );
    assert!(matches!(res, Err(ReferenceError::StaleEventAuthority)));

    // The cancel-request evidence binds the operation id and both anchors; the journal binds it
    // with its whole prepared record (obligation id and terminal predicate included) into the
    // cancellation proof that becomes the result digest (fss-thzlz).
    let expected_evidence = crate::alert_cancel_proof(
        &plan.intent.operation_id,
        &plan.authority_anchor,
        &displacing_anchor,
    );
    let prepared = journal.prepared_record(&plan.intent.operation_id)?;
    assert_eq!(prepared.intent, plan.intent);
    assert_eq!(prepared.obligation_id, plan.obligation_id);
    assert_eq!(
        prepared.terminal_predicate,
        REFERENCE_ALERT_TERMINAL_PREDICATE
    );
    let expected_proof =
        fss_core::EffectCancellationRecord::for_prepared(&prepared, expected_evidence)
            .proof_digest();
    assert_eq!(
        expected_proof,
        crate::alert::alert_cancellation_proof(
            &prepared,
            &plan.authority_anchor,
            &displacing_anchor
        )
    );

    let op = journal
        .operation(&plan.intent.operation_id)
        .ok_or(ReferenceError::InvalidSpec("missing_operation"))?;
    assert_eq!(op.result_digest, Some(expected_proof));
    let obligation = journal
        .obligations()
        .find(|item| item.obligation_id == plan.obligation_id)
        .ok_or(ReferenceError::InvalidSpec("missing_obligation"))?;
    assert_eq!(obligation.proof_digest, Some(expected_proof));

    // Ensure cancel proof is distinct when operation_id or displacing anchor changes.
    let diff_op = OperationId::parse("operation:alert:different")?;
    let diff_evidence =
        crate::alert_cancel_proof(&diff_op, &plan.authority_anchor, &displacing_anchor);
    assert_ne!(expected_evidence, diff_evidence);
    let diff_proof =
        fss_core::EffectCancellationRecord::for_prepared(&prepared, diff_evidence).proof_digest();
    assert_ne!(expected_proof, diff_proof);
    // A different displacing anchor: here the prepared anchor itself, as if nothing displaced it.
    let undisplaced_evidence = crate::alert_cancel_proof(
        &plan.intent.operation_id,
        &plan.authority_anchor,
        &plan.authority_anchor,
    );
    assert_ne!(expected_evidence, undisplaced_evidence);
    assert_ne!(
        expected_proof,
        crate::alert::alert_cancellation_proof(
            &prepared,
            &plan.authority_anchor,
            &plan.authority_anchor
        )
    );
    // A different prepared anchor gives different evidence too.
    assert_ne!(
        expected_evidence,
        crate::alert_cancel_proof(
            &plan.intent.operation_id,
            &displacing_anchor,
            &displacing_anchor
        )
    );
    // The proof binds the whole prepared record: another obligation gives another proof.
    let other_obligation = fss_core::PreparedEffect {
        obligation_id: ObligationId::parse("obligation:alert:different")?,
        ..prepared.clone()
    };
    assert_ne!(
        expected_proof,
        fss_core::EffectCancellationRecord::for_prepared(&other_obligation, expected_evidence)
            .proof_digest()
    );

    // The guard's check (rthz2 H2): a proof verifies only at an anchor the ledger published at or
    // after the batch that displaced the plan's event revision; never at the prepared anchor, never
    // before it, and never at a later anchor that changed no revision of the event (the tamper
    // capture published between them).
    let batches = authority.batches();
    let prepared_index = batches
        .iter()
        .position(|batch| batch.new_anchor == plan.authority_anchor)
        .ok_or(ReferenceError::InvalidSpec("missing_prepared_batch"))?;
    let successor_revision = decision_2.event.revision_digest();
    let displacing_index = batches
        .iter()
        .position(|batch| {
            batch.deltas.iter().any(|delta| {
                delta.family == "event_revision" && delta.witness_digest == Some(successor_revision)
            })
        })
        .ok_or(ReferenceError::InvalidSpec("missing_successor_batch"))?;
    assert!(
        displacing_index > prepared_index + 1,
        "a later, non-displacing anchor lies between the prepared and the displacing batch"
    );
    for (index, batch) in batches.iter().enumerate() {
        let proof = crate::alert::alert_cancellation_proof(
            &prepared,
            &plan.authority_anchor,
            &batch.new_anchor,
        );
        assert_eq!(
            crate::alert::alert_cancellation_is_bound(proof, &prepared, &plan, &authority),
            index >= displacing_index,
            "anchor of batch {index} (prepared {prepared_index}, displacing {displacing_index})"
        );
    }
    assert!(crate::alert::alert_cancellation_is_bound(
        expected_proof,
        &prepared,
        &plan,
        &authority
    ));

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
        &objects,
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
        &objects,
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
        &objects,
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
        &objects,
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
    let prep_receipt = journal
        .operation(&plan.intent.operation_id)
        .ok_or("missing prep operation")?;
    assert_eq!(prep_receipt.state, EffectState::Prepared);

    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:crash1");

    // Session 1: Commit durably on disk, then direct provider dispatch simulates crash before AdapterAccepted
    let commit_receipt = journal.transition(
        &plan.intent.operation_id,
        EffectState::Committed,
        TimestampNs(110),
        None,
        None,
    )?;
    assert_eq!(commit_receipt.state, EffectState::Committed);
    provider.dispatch(&plan.intent, ReferenceProviderBehavior::Deliver);

    // Session 2: System reboots; journal is replayed from disk in Committed state
    let mut reopened = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
    let receipt = reopened
        .operation(&plan.intent.operation_id)
        .ok_or(ContractError::NotFound)?;
    assert_eq!(receipt.state, EffectState::Committed);
    let redispatch_res = reopened.dispatch_alert(
        &plan,
        &authority,
        &objects,
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
    let reconciled = reopened.reconcile_alert(&plan, TimestampNs(215), &provider)?;
    let reconciled_receipt = reconciled.ok_or(ContractError::NotFound)?;
    assert_eq!(reconciled_receipt.state, EffectState::Verified);
    assert_eq!(reconciled_receipt.result_digest, Some(provider_proof));

    let obligation = reopened
        .obligations()
        .find(|o| o.obligation_id == plan.obligation_id)
        .ok_or(ContractError::NotFound)?;
    assert_eq!(obligation.state, ObligationState::Verified);

    match reopened.classify_obligation(&plan.obligation_id, &authority)? {
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
        &objects,
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

#[test]
fn test_x7_mem_self_prepared_intent_on_tamper_revision() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("x7m-tamper");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &event_receipt, &authority, &mut journal)?;

    // Publish tamper revision
    let tamper_obs = observation_with_label(
        "capture:alert:x7m-tamper",
        "sensor:alert:x7m-tamper",
        199,
        "power:alert:x7m-tamper",
        MockSemanticLabel::TamperLike,
        &mut objects,
        &mut authority,
    )?;
    let eval_2 = evaluate_unknown_presence(decision.event.event_id.clone(), vec![tamper_obs])?;
    let dec_2 = successor(&decision.event, &eval_2)?;
    let rc_2 = publish_reference_event(&dec_2, &mut objects, &mut authority)?;

    // Attacker crafts forged plan pointing to tampered revision and prepares own intent
    let mut forged = plan.clone();
    forged.event_root = rc_2.event_root;
    forged.event_revision_digest = rc_2.event_revision_digest;
    forged.authority_anchor = rc_2.authority_anchor.clone();
    forged.intent.operation_id = OperationId::parse("operation:alert:x7m-self")?;
    forged.intent.idempotency_key = IdempotencyKey::parse("idempotency:alert:x7m-self")?;
    forged.obligation_id = ObligationId::parse("obligation:alert:x7m-self")?;
    forged.intent.request_digest = crate::alert::alert_request_digest(&rc_2, &forged.channel);

    let _ = journal.prepare(
        forged.intent.clone(),
        forged.obligation_id.clone(),
        REFERENCE_ALERT_TERMINAL_PREDICATE,
        TimestampNs(100),
    )?;

    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:x7m");
    let res = dispatch_reference_alert(
        &forged,
        &authority,
        &objects,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    );

    assert!(matches!(res, Err(ReferenceError::StaleEventAuthority)));
    assert_eq!(provider.message_count(), 0);
    let op = journal
        .operation(&forged.intent.operation_id)
        .ok_or("missing op")?;
    assert_eq!(op.state, EffectState::Cancelled);
    let ob = journal
        .obligations()
        .find(|o| o.obligation_id == forged.obligation_id)
        .ok_or("missing ob")?;
    assert_eq!(ob.state, ObligationState::Cancelled);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn test_x7_dur_self_prepared_intent_on_tamper_revision() -> Result<(), Box<dyn Error>> {
    let ledger_path = temp_journal("x7d-tamper-ledger");
    let journal_path = temp_journal("x7d-tamper-journal");
    let _ = fs::remove_file(&ledger_path);
    let _ = fs::remove_file(&journal_path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&ledger_path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut durable_journal =
        DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
    let plan = durable_journal.prepare_alert(PrepareAlertParams {
        decision: &decision,
        event_receipt: &event_receipt,
        authority: &authority,
        operation_id: OperationId::parse("operation:alert:x7d")?,
        idempotency_key: IdempotencyKey::parse("idempotency:alert:x7d")?,
        obligation_id: ObligationId::parse("obligation:alert:x7d")?,
        channel: "operator:oncall".to_owned(),
        now: TimestampNs(100),
    })?;

    // Publish tamper revision
    let tamper_obs = observation_with_label(
        "capture:alert:x7d-tamper",
        "sensor:alert:x7d-tamper",
        299,
        "power:alert:x7d-tamper",
        MockSemanticLabel::TamperLike,
        &mut objects,
        &mut authority,
    )?;
    let eval_2 = evaluate_unknown_presence(decision.event.event_id.clone(), vec![tamper_obs])?;
    let dec_2 = successor(&decision.event, &eval_2)?;
    let rc_2 = publish_reference_event(&dec_2, &mut objects, &mut authority)?;

    let mut forged = plan.clone();
    forged.event_root = rc_2.event_root;
    forged.event_revision_digest = rc_2.event_revision_digest;
    forged.authority_anchor = rc_2.authority_anchor.clone();
    forged.intent.operation_id = OperationId::parse("operation:alert:x7d-self")?;
    forged.intent.idempotency_key = IdempotencyKey::parse("idempotency:alert:x7d-self")?;
    forged.obligation_id = ObligationId::parse("obligation:alert:x7d-self")?;
    forged.intent.request_digest = crate::alert::alert_request_digest(&rc_2, &forged.channel);

    let _ = durable_journal.prepare(
        forged.intent.clone(),
        forged.obligation_id.clone(),
        REFERENCE_ALERT_TERMINAL_PREDICATE,
        TimestampNs(100),
    )?;

    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:x7d");
    let res = durable_journal.dispatch_alert(
        &forged,
        &authority,
        &objects,
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
        .operation(&forged.intent.operation_id)
        .ok_or("missing op")?;
    assert_eq!(op.state, EffectState::Cancelled);
    let ob = durable_journal
        .obligation(&forged.obligation_id)
        .ok_or("missing ob")?;
    assert_eq!(ob.state, ObligationState::Cancelled);

    let reopened = DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
    assert_eq!(
        reopened
            .operation(&forged.intent.operation_id)
            .ok_or("missing reopened op")?
            .state,
        EffectState::Cancelled
    );

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(journal_path);
    Ok(())
}

#[test]
fn test_x7b_mem_self_prepared_on_uncorroborated_revision() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("x7bm-uncorroborated");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &event_receipt, &authority, &mut journal)?;

    // Publish uncorroborated revision
    let unknown_obs = observation_with_label(
        "capture:alert:x7bm-unknown",
        "sensor:alert:x7bm-unknown",
        399,
        "power:alert:x7bm-unknown",
        MockSemanticLabel::Unknown,
        &mut objects,
        &mut authority,
    )?;
    let eval_2 = evaluate_unknown_presence(decision.event.event_id.clone(), vec![unknown_obs])?;
    let dec_2 = successor(&decision.event, &eval_2)?;
    let rc_2 = publish_reference_event(&dec_2, &mut objects, &mut authority)?;

    let mut forged = plan.clone();
    forged.event_root = rc_2.event_root;
    forged.event_revision_digest = rc_2.event_revision_digest;
    forged.authority_anchor = rc_2.authority_anchor.clone();
    forged.intent.operation_id = OperationId::parse("operation:alert:x7bm-self")?;
    forged.intent.idempotency_key = IdempotencyKey::parse("idempotency:alert:x7bm-self")?;
    forged.obligation_id = ObligationId::parse("obligation:alert:x7bm-self")?;
    forged.intent.request_digest = crate::alert::alert_request_digest(&rc_2, &forged.channel);

    let _ = journal.prepare(
        forged.intent.clone(),
        forged.obligation_id.clone(),
        REFERENCE_ALERT_TERMINAL_PREDICATE,
        TimestampNs(100),
    )?;

    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:x7bm");
    let res = dispatch_reference_alert(
        &forged,
        &authority,
        &objects,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    );

    assert!(matches!(res, Err(ReferenceError::StaleEventAuthority)));
    assert_eq!(provider.message_count(), 0);
    let op = journal
        .operation(&forged.intent.operation_id)
        .ok_or("missing op")?;
    assert_eq!(op.state, EffectState::Cancelled);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn test_x7b_dur_self_prepared_on_uncorroborated_revision() -> Result<(), Box<dyn Error>> {
    let ledger_path = temp_journal("x7bd-uncorroborated-ledger");
    let journal_path = temp_journal("x7bd-uncorroborated-journal");
    let _ = fs::remove_file(&ledger_path);
    let _ = fs::remove_file(&journal_path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&ledger_path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut durable_journal =
        DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
    let plan = durable_journal.prepare_alert(PrepareAlertParams {
        decision: &decision,
        event_receipt: &event_receipt,
        authority: &authority,
        operation_id: OperationId::parse("operation:alert:x7bd")?,
        idempotency_key: IdempotencyKey::parse("idempotency:alert:x7bd")?,
        obligation_id: ObligationId::parse("obligation:alert:x7bd")?,
        channel: "operator:oncall".to_owned(),
        now: TimestampNs(100),
    })?;

    // Publish uncorroborated revision
    let unknown_obs = observation_with_label(
        "capture:alert:x7bd-unknown",
        "sensor:alert:x7bd-unknown",
        499,
        "power:alert:x7bd-unknown",
        MockSemanticLabel::Unknown,
        &mut objects,
        &mut authority,
    )?;
    let eval_2 = evaluate_unknown_presence(decision.event.event_id.clone(), vec![unknown_obs])?;
    let dec_2 = successor(&decision.event, &eval_2)?;
    let rc_2 = publish_reference_event(&dec_2, &mut objects, &mut authority)?;

    let mut forged = plan.clone();
    forged.event_root = rc_2.event_root;
    forged.event_revision_digest = rc_2.event_revision_digest;
    forged.authority_anchor = rc_2.authority_anchor.clone();
    forged.intent.operation_id = OperationId::parse("operation:alert:x7bd-self")?;
    forged.intent.idempotency_key = IdempotencyKey::parse("idempotency:alert:x7bd-self")?;
    forged.obligation_id = ObligationId::parse("obligation:alert:x7bd-self")?;
    forged.intent.request_digest = crate::alert::alert_request_digest(&rc_2, &forged.channel);

    let _ = durable_journal.prepare(
        forged.intent.clone(),
        forged.obligation_id.clone(),
        REFERENCE_ALERT_TERMINAL_PREDICATE,
        TimestampNs(100),
    )?;

    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:x7bd");
    let res = durable_journal.dispatch_alert(
        &forged,
        &authority,
        &objects,
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
        .operation(&forged.intent.operation_id)
        .ok_or("missing op")?;
    assert_eq!(op.state, EffectState::Cancelled);

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(journal_path);
    Ok(())
}

#[test]
fn test_x2_stale_ledger_handle_after_tamper() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("x2s-stale");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &event_receipt, &authority, &mut journal)?;

    // Open second handle on the same journal path and commit tamper
    let mut h2 = DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let tamper_obs = observation_with_label(
        "capture:alert:x2s-tamper",
        "sensor:alert:x2s-tamper",
        599,
        "power:alert:x2s-tamper",
        MockSemanticLabel::TamperLike,
        &mut objects,
        &mut h2,
    )?;
    let eval_2 = evaluate_unknown_presence(decision.event.event_id.clone(), vec![tamper_obs])?;
    let dec_2 = successor(&decision.event, &eval_2)?;
    let _rc_2 = publish_reference_event(&dec_2, &mut objects, &mut h2)?;

    // Now dispatch using original authority handle (which has not observed h2 commits)
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:x2s");
    let res = dispatch_reference_alert(
        &plan,
        &authority,
        &objects,
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
        .ok_or("missing op")?;
    assert_eq!(op.state, EffectState::Cancelled);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn test_x6b_mem_root_rewrite_without_request_digest_cancels_prepared_op()
-> Result<(), Box<dyn Error>> {
    let path = temp_journal("x6bm-rewrite-noreq");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &event_receipt, &authority, &mut journal)?;

    // Tamper published
    let tamper_obs = observation_with_label(
        "capture:alert:x6bm-tamper",
        "sensor:alert:x6bm-tamper",
        699,
        "power:alert:x6bm-tamper",
        MockSemanticLabel::TamperLike,
        &mut objects,
        &mut authority,
    )?;
    let eval_2 = evaluate_unknown_presence(decision.event.event_id.clone(), vec![tamper_obs])?;
    let dec_2 = successor(&decision.event, &eval_2)?;
    let rc_2 = publish_reference_event(&dec_2, &mut objects, &mut authority)?;

    // Forge root/revision WITHOUT updating request digest
    let mut forged = plan.clone();
    forged.event_root = rc_2.event_root;
    forged.event_revision_digest = rc_2.event_revision_digest;
    forged.authority_anchor = rc_2.authority_anchor.clone();

    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:x6bm");
    let r1 = dispatch_reference_alert(
        &forged,
        &authority,
        &objects,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    );
    assert!(r1.is_err());
    assert_eq!(provider.message_count(), 0);

    // Operation must be Cancelled, NOT left Prepared
    let op = journal
        .operation(&plan.intent.operation_id)
        .ok_or("missing op")?;
    assert_eq!(op.state, EffectState::Cancelled);

    // Second dispatch attempt with original plan must also fail because op is Cancelled
    let r2 = dispatch_reference_alert(
        &plan,
        &authority,
        &objects,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(103),
        TimestampNs(104),
        &mut journal,
        &mut provider,
    );
    assert!(r2.is_err());
    assert_eq!(provider.message_count(), 0);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn test_m8_mismatched_obligation_id_refused_and_cancels() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("m8-obligation-mismatch");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();

    // Prepare operation 1
    let plan1 = prepare(&decision, &event_receipt, &authority, &mut journal)?;

    // Prepare operation 2 on the same event
    let plan2 = prepare_reference_alert(
        PrepareAlertParams {
            decision: &decision,
            event_receipt: &event_receipt,
            authority: &authority,
            operation_id: OperationId::parse("operation:alert:m8-op2")?,
            idempotency_key: IdempotencyKey::parse("idempotency:alert:m8-op2")?,
            obligation_id: ObligationId::parse("obligation:alert:m8-obl2")?,
            channel: "operator:oncall".to_owned(),
            now: TimestampNs(100),
        },
        &mut journal,
    )?;

    // Mismatched plan: op1's intent but pointing to plan2's obligation_id
    let mut mismatched = plan1.clone();
    mismatched.obligation_id = plan2.obligation_id.clone();

    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:m8");
    let res = dispatch_reference_alert(
        &mismatched,
        &authority,
        &objects,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    );

    assert!(matches!(res, Err(ReferenceError::StaleEventAuthority)));
    assert_eq!(provider.message_count(), 0);

    // Operation 1 must be Cancelled
    let op1 = journal
        .operation(&plan1.intent.operation_id)
        .ok_or("missing op1")?;
    assert_eq!(op1.state, EffectState::Cancelled);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn test_divergent_ledger_head_refused_and_cancels() -> Result<(), Box<dyn Error>> {
    let path_a = temp_journal("div-ledger-a");
    let path_b = temp_journal("div-ledger-b");
    let _ = fs::remove_file(&path_a);
    let _ = fs::remove_file(&path_b);
    let mut objects_a = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut ledger_a =
        DurableReferenceLedger::open(&path_a, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects_a, &mut ledger_a)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &event_receipt, &ledger_a, &mut journal)?;

    // Ledger B records a different history before the same event is published, so A's history
    // is not a prefix of B's: B is genuinely divergent, not an extension of A. It then also takes a
    // divergent subsequent batch / head.
    let mut objects_b = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut ledger_b =
        DurableReferenceLedger::open(&path_b, "site:alert", IncompleteTailPolicy::Reject)?;
    let _pre_event_divergence = observation_with_label(
        "capture:alert:div-pre",
        "sensor:alert:div-pre",
        797,
        "power:alert:div-pre",
        MockSemanticLabel::PersonLike,
        &mut objects_b,
        &mut ledger_b,
    )?;
    let (_dec_b, _rc_b) = eligible_event(&mut objects_b, &mut ledger_b)?;
    assert_ne!(
        ledger_a.batches().first().map(|batch| batch.batch_digest),
        ledger_b.batches().first().map(|batch| batch.batch_digest),
        "ledger B must not share ledger A's history"
    );
    let divergent_obs = observation_with_label(
        "capture:alert:div-other",
        "sensor:alert:div-other",
        799,
        "power:alert:div-other",
        MockSemanticLabel::PersonLike,
        &mut objects_b,
        &mut ledger_b,
    )?;
    let _ = divergent_obs;

    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:divergent");
    let res = dispatch_reference_alert(
        &plan,
        &ledger_b,
        &objects_b,
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
        .ok_or("missing op")?;
    assert_eq!(op.state, EffectState::Cancelled);
    assert_cancelled_mem(&journal, &plan)?;

    let _ = fs::remove_file(path_a);
    let _ = fs::remove_file(path_b);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// fss-wjisz round 6: dispatch re-derives eligibility from the authority ledger and fails closed.

fn assert_cancelled_mem(
    journal: &EffectJournal,
    plan: &crate::ReferenceAlertPlan,
) -> Result<(), Box<dyn Error>> {
    let op = journal
        .operation(&plan.intent.operation_id)
        .ok_or("missing operation")?;
    assert_eq!(op.state, EffectState::Cancelled);
    let obligation = journal
        .obligations()
        .find(|item| item.obligation_id == plan.obligation_id)
        .ok_or("missing obligation")?;
    assert_eq!(obligation.state, ObligationState::Cancelled);
    Ok(())
}

fn assert_cancelled_durable(
    journal: &DurableEffectJournal,
    plan: &crate::ReferenceAlertPlan,
) -> Result<(), Box<dyn Error>> {
    let op = journal
        .operation(&plan.intent.operation_id)
        .ok_or("missing operation")?;
    assert_eq!(op.state, EffectState::Cancelled);
    let obligation = journal
        .obligation(&plan.obligation_id)
        .ok_or("missing obligation")?;
    assert_eq!(obligation.state, ObligationState::Cancelled);
    Ok(())
}

fn durable_params<'a>(
    decision: &'a ReferencePolicyDecision,
    event_receipt: &'a crate::ReferenceEventReceipt,
    authority: &'a DurableReferenceLedger,
) -> Result<PrepareAlertParams<'a>, Box<dyn Error>> {
    Ok(PrepareAlertParams {
        decision,
        event_receipt,
        authority,
        operation_id: OperationId::parse("operation:alert:1")?,
        idempotency_key: IdempotencyKey::parse("idempotency:alert:1")?,
        obligation_id: ObligationId::parse("obligation:alert:1")?,
        channel: "operator:oncall".to_owned(),
        now: TimestampNs(100),
    })
}

/// Rewrites `plan` into a fully self-consistent plan for revision `decision`/`receipt`, exactly as
/// a caller holding the public journal prepare could: the request digest, revision encoding,
/// prepare-time head, and precondition digest all agree with that revision, so only the
/// dispatch-time eligibility re-derivation can refuse it.
fn self_consistent_forgery(
    plan: &crate::ReferenceAlertPlan,
    decision: &ReferencePolicyDecision,
    receipt: &crate::ReferenceEventReceipt,
    authority: &DurableReferenceLedger,
    tag: &str,
) -> Result<crate::ReferenceAlertPlan, Box<dyn Error>> {
    forgery_with_encoding(plan, receipt, &decision.event, authority, tag)
}

/// Rewrites `plan` to name `receipt`'s revision (root, revision digest, anchor) while carrying the
/// canonical encoding of `encode_from`, with the current ledger head and the request and
/// precondition digests recomputed over that content exactly as prepare would, under fresh
/// self-prepared identities. With `encode_from` the named revision itself this is a fully
/// self-consistent forgery; with another revision it is an encoding swap.
fn forgery_with_encoding(
    plan: &crate::ReferenceAlertPlan,
    receipt: &crate::ReferenceEventReceipt,
    encode_from: &fss_core::EventHypothesis,
    authority: &DurableReferenceLedger,
    tag: &str,
) -> Result<crate::ReferenceAlertPlan, Box<dyn Error>> {
    let head = authority.batches().last().ok_or("empty authority ledger")?;
    let mut forged = plan.clone();
    forged.event_root = receipt.event_root;
    forged.event_revision_digest = receipt.event_revision_digest;
    forged.authority_anchor = receipt.authority_anchor.clone();
    forged.event_revision_encoding = crate::alert::event_revision_encoding(encode_from);
    forged.prior_revision_encodings = receipt.prior_revision_encodings.clone();
    forged.prepared_head_sequence = u64::try_from(authority.batches().len())?;
    forged.prepared_head_digest = head.batch_digest;
    forged.intent.operation_id = OperationId::parse(format!("operation:alert:{tag}-self"))?;
    forged.intent.idempotency_key = IdempotencyKey::parse(format!("idempotency:alert:{tag}-self"))?;
    forged.obligation_id = ObligationId::parse(format!("obligation:alert:{tag}-self"))?;
    forged.intent.request_digest = crate::alert::alert_request_digest(receipt, &forged.channel);
    forged.intent.precondition_digest = crate::alert::alert_precondition_digest_parts(
        receipt.event_revision_digest,
        &receipt.authority_anchor,
        encode_from.state,
        encode_from.decision_path.fingerprint,
        forged.prepared_head_sequence,
        forged.prepared_head_digest,
    );
    Ok(forged)
}

/// The round-5 "eligible" terminal predicate a caller can write through the public prepare.
fn forged_eligible_predicate(
    receipt: &crate::ReferenceEventReceipt,
    authority: &DurableReferenceLedger,
) -> Result<String, Box<dyn Error>> {
    let head = authority.batches().last().ok_or("empty authority ledger")?;
    Ok(format!(
        "{REFERENCE_ALERT_TERMINAL_PREDICATE}:eligible:{}:head:{}:{}",
        receipt.event_revision_digest,
        authority.batches().len(),
        head.batch_digest
    ))
}

/// X7 / X7b: the event's current authority revision is ineligible; a caller self-prepares a
/// self-consistent plan for it through the public journal prepare with a forged "eligible"
/// terminal predicate. Dispatch must re-derive eligibility from the ledger and refuse.
fn forged_predicate_on_ineligible_revision(
    tag: &str,
    label: MockSemanticLabel,
    seed: u64,
    durable: bool,
) -> Result<(), Box<dyn Error>> {
    let ledger_path = temp_journal(&format!("{tag}-ledger"));
    let journal_path = temp_journal(&format!("{tag}-journal"));
    let _ = fs::remove_file(&ledger_path);
    let _ = fs::remove_file(&journal_path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&ledger_path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let mut durable_journal =
        DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
    let plan = if durable {
        durable_journal.prepare_alert(durable_params(&decision, &event_receipt, &authority)?)?
    } else {
        prepare(&decision, &event_receipt, &authority, &mut journal)?
    };

    let next_obs = observation_with_label(
        &format!("capture:alert:{tag}-rev2"),
        &format!("sensor:alert:{tag}-rev2"),
        seed,
        &format!("power:alert:{tag}-rev2"),
        label,
        &mut objects,
        &mut authority,
    )?;
    let eval_2 = evaluate_unknown_presence(decision.event.event_id.clone(), vec![next_obs])?;
    let dec_2 = successor(&decision.event, &eval_2)?;
    let rc_2 = publish_reference_event(&dec_2, &mut objects, &mut authority)?;
    assert!(
        crate::alert::verify_event_alert_eligibility(
            dec_2.event.state,
            dec_2.action,
            &dec_2.event.evidence
        )
        .is_err(),
        "{tag}: revision 2 must be ineligible"
    );

    let forged = self_consistent_forgery(&plan, &dec_2, &rc_2, &authority, tag)?;
    let predicate = forged_eligible_predicate(&rc_2, &authority)?;
    let mut provider = ReferenceAlertProvider::with_provider_id(format!("provider:test:{tag}"));
    if durable {
        let _ = durable_journal.prepare(
            forged.intent.clone(),
            forged.obligation_id.clone(),
            predicate,
            TimestampNs(100),
        )?;
        let res = durable_journal.dispatch_alert(
            &forged,
            &authority,
            &objects,
            ReferenceProviderBehavior::Deliver,
            TimestampNs(101),
            TimestampNs(102),
            &mut provider,
        );
        assert!(
            matches!(
                res,
                Err(DurableEffectError::Reference(ReferenceError::InvalidSpec(
                    "alert_not_eligible"
                )))
            ),
            "{tag}: {res:?}"
        );
        assert_eq!(provider.message_count(), 0, "{tag}: alert delivered");
        assert_cancelled_durable(&durable_journal, &forged)?;
        drop(durable_journal);
        let reopened = DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
        assert_cancelled_durable(&reopened, &forged)?;
    } else {
        let _ = journal.prepare(
            forged.intent.clone(),
            forged.obligation_id.clone(),
            predicate,
            TimestampNs(100),
        )?;
        let res = dispatch_reference_alert(
            &forged,
            &authority,
            &objects,
            ReferenceProviderBehavior::Deliver,
            TimestampNs(101),
            TimestampNs(102),
            &mut journal,
            &mut provider,
        );
        assert!(
            matches!(res, Err(ReferenceError::InvalidSpec("alert_not_eligible"))),
            "{tag}: {res:?}"
        );
        assert_eq!(provider.message_count(), 0, "{tag}: alert delivered");
        assert_cancelled_mem(&journal, &forged)?;
    }

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(journal_path);
    Ok(())
}

#[test]
fn test_x7_mem_forged_eligible_predicate_on_tamper_revision_refused() -> Result<(), Box<dyn Error>>
{
    forged_predicate_on_ineligible_revision(
        "x7m-forged",
        MockSemanticLabel::TamperLike,
        1_199,
        false,
    )
}

#[test]
fn test_x7_dur_forged_eligible_predicate_on_tamper_revision_refused() -> Result<(), Box<dyn Error>>
{
    forged_predicate_on_ineligible_revision(
        "x7d-forged",
        MockSemanticLabel::TamperLike,
        1_299,
        true,
    )
}

#[test]
fn test_x7b_mem_forged_eligible_predicate_on_uncorroborated_revision_refused()
-> Result<(), Box<dyn Error>> {
    forged_predicate_on_ineligible_revision("x7bm-forged", MockSemanticLabel::Unknown, 1_399, false)
}

#[test]
fn test_x7b_dur_forged_eligible_predicate_on_uncorroborated_revision_refused()
-> Result<(), Box<dyn Error>> {
    forged_predicate_on_ineligible_revision("x7bd-forged", MockSemanticLabel::Unknown, 1_499, true)
}

#[derive(Clone, Copy, Debug)]
enum AuthorityFault {
    CorruptTail,
    PathRemoved,
}

/// X2-stale fail-closed variants: the durable authority behind the dispatching handle gains a
/// corrupt tail or disappears (optionally after another handle committed a tamper revision the
/// dispatching handle never saw). Dispatch must refuse typed and cancel, never skip the check.
fn authority_fault_case(
    tag: &str,
    fault: AuthorityFault,
    newer_revision: bool,
    durable: bool,
) -> Result<(), Box<dyn Error>> {
    use std::io::Write as _;

    let ledger_path = temp_journal(&format!("{tag}-ledger"));
    let journal_path = temp_journal(&format!("{tag}-journal"));
    let moved_path = ledger_path.with_extension("moved");
    let _ = fs::remove_file(&ledger_path);
    let _ = fs::remove_file(&journal_path);
    let _ = fs::remove_file(&moved_path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&ledger_path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let mut durable_journal =
        DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
    let plan = if durable {
        durable_journal.prepare_alert(durable_params(&decision, &event_receipt, &authority)?)?
    } else {
        prepare(&decision, &event_receipt, &authority, &mut journal)?
    };

    if newer_revision {
        let mut h2 =
            DurableReferenceLedger::open(&ledger_path, "site:alert", IncompleteTailPolicy::Reject)?;
        let tamper_obs = observation_with_label(
            &format!("capture:alert:{tag}-tamper"),
            &format!("sensor:alert:{tag}-tamper"),
            1_599,
            &format!("power:alert:{tag}-tamper"),
            MockSemanticLabel::TamperLike,
            &mut objects,
            &mut h2,
        )?;
        let eval_2 = evaluate_unknown_presence(decision.event.event_id.clone(), vec![tamper_obs])?;
        let dec_2 = successor(&decision.event, &eval_2)?;
        let _rc_2 = publish_reference_event(&dec_2, &mut objects, &mut h2)?;
        assert!(h2.batches().len() > authority.batches().len());
    }
    match fault {
        AuthorityFault::CorruptTail => {
            let mut file = fs::OpenOptions::new().append(true).open(&ledger_path)?;
            file.write_all(b"NOTMAGIC")?;
            file.sync_all()?;
        }
        AuthorityFault::PathRemoved => fs::rename(&ledger_path, &moved_path)?,
    }

    let mut provider = ReferenceAlertProvider::with_provider_id(format!("provider:test:{tag}"));
    let refusal = if durable {
        match durable_journal.dispatch_alert(
            &plan,
            &authority,
            &objects,
            ReferenceProviderBehavior::Deliver,
            TimestampNs(101),
            TimestampNs(102),
            &mut provider,
        ) {
            Ok(receipt) => return Err(format!("{tag}: dispatch accepted: {receipt:?}").into()),
            Err(DurableEffectError::Reference(error)) => error,
            Err(other) => return Err(format!("{tag}: unexpected error shape: {other:?}").into()),
        }
    } else {
        match dispatch_reference_alert(
            &plan,
            &authority,
            &objects,
            ReferenceProviderBehavior::Deliver,
            TimestampNs(101),
            TimestampNs(102),
            &mut journal,
            &mut provider,
        ) {
            Ok(receipt) => return Err(format!("{tag}: dispatch accepted: {receipt:?}").into()),
            Err(error) => error,
        }
    };
    match fault {
        AuthorityFault::CorruptTail => assert!(
            matches!(refusal, ReferenceError::StaleEventAuthority),
            "{tag}: {refusal:?}"
        ),
        AuthorityFault::PathRemoved => assert!(
            matches!(
                &refusal,
                ReferenceError::AuthorityLedgerUnreadable(error)
                    if matches!(
                        error.as_ref(),
                        fss_ledger::DurableLedgerError::Journal(fss_ledger::JournalError::Io(io))
                            if io.kind() == std::io::ErrorKind::NotFound
                    )
            ),
            "{tag}: {refusal:?}"
        ),
    }
    assert_eq!(provider.message_count(), 0, "{tag}: alert delivered");
    if durable {
        assert_cancelled_durable(&durable_journal, &plan)?;
        drop(durable_journal);
        let reopened = DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
        assert_cancelled_durable(&reopened, &plan)?;
    } else {
        assert_cancelled_mem(&journal, &plan)?;
    }

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(moved_path);
    let _ = fs::remove_file(journal_path);
    Ok(())
}

#[test]
fn test_x2_stale_handle_corrupt_tail_mem_refused_and_cancels() -> Result<(), Box<dyn Error>> {
    authority_fault_case("x2sc-mem", AuthorityFault::CorruptTail, true, false)
}

#[test]
fn test_x2_stale_handle_corrupt_tail_dur_refused_and_cancels() -> Result<(), Box<dyn Error>> {
    authority_fault_case("x2sc-dur", AuthorityFault::CorruptTail, true, true)
}

#[test]
fn test_x2_stale_handle_path_removed_mem_refused_and_cancels() -> Result<(), Box<dyn Error>> {
    authority_fault_case("x2sr-mem", AuthorityFault::PathRemoved, true, false)
}

#[test]
fn test_x2_stale_handle_path_removed_dur_refused_and_cancels() -> Result<(), Box<dyn Error>> {
    authority_fault_case("x2sr-dur", AuthorityFault::PathRemoved, true, true)
}

#[test]
fn test_unreadable_authority_path_removed_mem_fails_closed() -> Result<(), Box<dyn Error>> {
    authority_fault_case("fc-removed-mem", AuthorityFault::PathRemoved, false, false)
}

#[test]
fn test_unreadable_authority_path_removed_dur_fails_closed() -> Result<(), Box<dyn Error>> {
    authority_fault_case("fc-removed-dur", AuthorityFault::PathRemoved, false, true)
}

#[test]
fn test_corrupt_authority_tail_mem_fails_closed() -> Result<(), Box<dyn Error>> {
    authority_fault_case("fc-corrupt-mem", AuthorityFault::CorruptTail, false, false)
}

#[test]
fn test_corrupt_authority_tail_dur_fails_closed() -> Result<(), Box<dyn Error>> {
    authority_fault_case("fc-corrupt-dur", AuthorityFault::CorruptTail, false, true)
}

/// Kills M1: a plan must be exactly the intent the journal recorded; the same operation under
/// another idempotency key is refused.
#[test]
fn test_m1_plan_intent_must_equal_prepared_intent() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("m1-intent-equality");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &event_receipt, &authority, &mut journal)?;

    let mut rekeyed = plan.clone();
    rekeyed.intent.idempotency_key = IdempotencyKey::parse("idempotency:alert:m1-rekeyed")?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:m1");
    let res = dispatch_reference_alert(
        &rekeyed,
        &authority,
        &objects,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    );
    assert!(
        matches!(res, Err(ReferenceError::StaleEventAuthority)),
        "{res:?}"
    );
    assert_eq!(provider.message_count(), 0);
    assert_cancelled_mem(&journal, &plan)?;

    let _ = fs::remove_file(path);
    Ok(())
}

/// Kills M1 (intent equality removed), and equally an intent comparison that skips the request
/// digest: a plan rerouted to another channel with a self-consistent request digest passes plan
/// integrity but is not the intent the journal recorded.
#[test]
fn test_m1_rerouted_channel_plan_is_not_the_prepared_intent() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("m1-rerouted-channel");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &event_receipt, &authority, &mut journal)?;

    let mut rerouted = plan.clone();
    rerouted.channel = "operator:elsewhere".to_owned();
    rerouted.intent.request_digest =
        crate::alert::alert_request_digest(&event_receipt, &rerouted.channel);
    assert!(crate::alert::validate_reference_alert_plan(&rerouted).is_ok());
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:m1-rerouted");
    let res = dispatch_reference_alert(
        &rerouted,
        &authority,
        &objects,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    );
    assert!(
        matches!(res, Err(ReferenceError::StaleEventAuthority)),
        "{res:?}"
    );
    assert_eq!(provider.message_count(), 0);
    assert_cancelled_mem(&journal, &plan)?;

    let _ = fs::remove_file(path);
    Ok(())
}

/// Kills M4: the batch that published the current revision must carry the plan's authority
/// anchor. A self-prepared plan naming another anchor, with a precondition digest made consistent
/// with that anchor, is refused.
#[test]
fn test_m4_foreign_authority_anchor_refused() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("m4-authority-anchor");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &event_receipt, &authority, &mut journal)?;
    let _unrelated = observation(
        "capture:alert:m4-unrelated",
        "sensor:alert:m4-unrelated",
        1_699,
        "power:alert:m4-unrelated",
        &mut objects,
        &mut authority,
    )?;

    let mut reanchored = plan.clone();
    reanchored.authority_anchor = authority.current().anchor.clone();
    assert_ne!(reanchored.authority_anchor, plan.authority_anchor);
    reanchored.intent.operation_id = OperationId::parse("operation:alert:m4-self")?;
    reanchored.intent.idempotency_key = IdempotencyKey::parse("idempotency:alert:m4-self")?;
    reanchored.obligation_id = ObligationId::parse("obligation:alert:m4-self")?;
    reanchored.intent.precondition_digest = crate::alert::alert_precondition_digest_parts(
        event_receipt.event_revision_digest,
        &reanchored.authority_anchor,
        decision.event.state,
        decision.event.decision_path.fingerprint,
        reanchored.prepared_head_sequence,
        reanchored.prepared_head_digest,
    );
    let _ = journal.prepare(
        reanchored.intent.clone(),
        reanchored.obligation_id.clone(),
        REFERENCE_ALERT_TERMINAL_PREDICATE,
        TimestampNs(100),
    )?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:m4");
    let res = dispatch_reference_alert(
        &reanchored,
        &authority,
        &objects,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    );
    assert!(
        matches!(res, Err(ReferenceError::StaleEventAuthority)),
        "{res:?}"
    );
    assert_eq!(provider.message_count(), 0);
    assert_cancelled_mem(&journal, &reanchored)?;

    let _ = fs::remove_file(path);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// fss-wjisz round 6 review: forgeries that isolate each remaining dispatch check (F1 encoding
// swap, F8 divergence after publication, F9 head rebinding, M2 unbound request digest), plus the
// C1 control proving the self-prepared forgery harness delivers when every check truly passes.

/// Prepares `plan` through the public raw journal prepare in a fresh journal on the chosen path
/// and dispatches it. Returns the refusal, if any. A refusal must leave zero provider messages and
/// the operation and obligation Cancelled (also after reopening a durable journal); an acceptance
/// must be exactly one `AdapterAccepted` delivery.
fn dispatch_self_prepared(
    tag: &str,
    plan: &crate::ReferenceAlertPlan,
    authority: &DurableReferenceLedger,
    objects: &InMemoryObjectStore,
    durable: bool,
) -> Result<Option<ReferenceError>, Box<dyn Error>> {
    let journal_path = temp_journal(&format!("{tag}-self-journal"));
    let _ = fs::remove_file(&journal_path);
    let mut provider = ReferenceAlertProvider::with_provider_id(format!("provider:test:{tag}"));
    let refusal = if durable {
        let mut journal = DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
        let _ = journal.prepare(
            plan.intent.clone(),
            plan.obligation_id.clone(),
            REFERENCE_ALERT_TERMINAL_PREDICATE,
            TimestampNs(100),
        )?;
        let refusal = match journal.dispatch_alert(
            plan,
            authority,
            &objects,
            ReferenceProviderBehavior::Deliver,
            TimestampNs(101),
            TimestampNs(102),
            &mut provider,
        ) {
            Ok(receipt) => {
                assert_eq!(receipt.state, EffectState::AdapterAccepted, "{tag}");
                None
            }
            Err(DurableEffectError::Reference(error)) => Some(error),
            // A contract refusal keeps its contract identity through the durable journal.
            Err(DurableEffectError::Contract(error)) => Some(ReferenceError::Contract(error)),
            Err(other) => return Err(format!("{tag}: unexpected error shape: {other:?}").into()),
        };
        if refusal.is_some() {
            assert_cancelled_durable(&journal, plan)?;
            drop(journal);
            let reopened = DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
            assert_cancelled_durable(&reopened, plan)?;
        }
        refusal
    } else {
        let mut journal = EffectJournal::new();
        let _ = journal.prepare(
            plan.intent.clone(),
            plan.obligation_id.clone(),
            REFERENCE_ALERT_TERMINAL_PREDICATE,
            TimestampNs(100),
        )?;
        match dispatch_reference_alert(
            plan,
            authority,
            &objects,
            ReferenceProviderBehavior::Deliver,
            TimestampNs(101),
            TimestampNs(102),
            &mut journal,
            &mut provider,
        ) {
            Ok(receipt) => {
                assert_eq!(receipt.state, EffectState::AdapterAccepted, "{tag}");
                None
            }
            Err(error) => {
                assert_cancelled_mem(&journal, plan)?;
                Some(error)
            }
        }
    };
    let expected_messages = usize::from(refusal.is_none());
    assert_eq!(
        provider.message_count(),
        expected_messages,
        "{tag}: provider messages"
    );
    let _ = fs::remove_file(journal_path);
    Ok(refusal)
}

/// Publishes the successor of the last decision of `lineage` (oldest first) carrying the policy
/// outcome of `observations`.
fn publish_successor(
    lineage: &[&ReferencePolicyDecision],
    observations: Vec<ReferenceModelObservation>,
    objects: &mut InMemoryObjectStore,
    authority: &mut DurableReferenceLedger,
) -> Result<(ReferencePolicyDecision, crate::ReferenceEventReceipt), Box<dyn Error>> {
    let prior = lineage.last().ok_or("empty lineage")?;
    let chain: Vec<fss_core::EventHypothesis> = lineage.iter().map(|d| d.event.clone()).collect();
    let evaluated = evaluate_unknown_presence(prior.event.event_id.clone(), observations)?;
    let next = successor_in(&chain, &evaluated)?;
    let receipt = publish_reference_event(&next, objects, authority)?;
    Ok((next, receipt))
}

fn tamper_observation(
    tag: &str,
    seed: u64,
    objects: &mut InMemoryObjectStore,
    authority: &mut DurableReferenceLedger,
) -> Result<ReferenceModelObservation, Box<dyn Error>> {
    observation_with_label(
        &format!("capture:alert:{tag}-tamper"),
        &format!("sensor:alert:{tag}-tamper"),
        seed,
        &format!("power:alert:{tag}-tamper"),
        MockSemanticLabel::TamperLike,
        objects,
        authority,
    )
}

fn unrelated_observation(
    tag: &str,
    seed: u64,
    objects: &mut InMemoryObjectStore,
    authority: &mut DurableReferenceLedger,
) -> Result<ReferenceModelObservation, Box<dyn Error>> {
    observation(
        &format!("capture:alert:{tag}"),
        &format!("sensor:alert:{tag}"),
        seed,
        &format!("power:alert:{tag}"),
        objects,
        authority,
    )
}

/// C1 control: eligible, then tamper, then eligible again (a corroborated revision cannot directly
/// supersede one). The self-consistent self-prepared forgery for the current eligible revision
/// DELIVERS, so every refusal of the same harness below comes from a dispatch check, not from the
/// harness itself.
///
/// A tamper is sticky (fss-2uftm): revision 3 is eligible only because it carries an evidenced
/// integrity restoration from the tampered sensor, and it and its corroborating observations are
/// all captured strictly after the tamper's capture ended (seed 1801 ends at 20.0101 ms).
fn self_prepared_control_case(tag: &str, durable: bool) -> Result<(), Box<dyn Error>> {
    let ledger_path = temp_journal(&format!("{tag}-ledger"));
    let _ = fs::remove_file(&ledger_path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&ledger_path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &event_receipt, &authority, &mut journal)?;

    let tamper = tamper_observation(tag, 1_801, &mut objects, &mut authority)?;
    let (dec_2, _rc_2) =
        publish_successor(&[&decision], vec![tamper], &mut objects, &mut authority)?;
    let restored = observation_with_label(
        &format!("capture:alert:{tag}-tamper-restored"),
        &format!("sensor:alert:{tag}-tamper"),
        2_002,
        &format!("power:alert:{tag}-tamper"),
        MockSemanticLabel::IntegrityRestored,
        &mut objects,
        &mut authority,
    )?;
    let first = unrelated_observation(&format!("{tag}-e1"), 2_011, &mut objects, &mut authority)?;
    let second = unrelated_observation(&format!("{tag}-e2"), 2_022, &mut objects, &mut authority)?;
    let (dec_3, rc_3) = publish_successor(
        &[&decision, &dec_2],
        vec![restored, first, second],
        &mut objects,
        &mut authority,
    )?;
    assert!(
        crate::alert::verify_event_alert_eligibility(
            dec_3.event.state,
            dec_3.action,
            &dec_3.event.evidence
        )
        .is_ok(),
        "{tag}: revision 3 must be eligible"
    );

    let forged = self_consistent_forgery(&plan, &dec_3, &rc_3, &authority, tag)?;
    let refusal = dispatch_self_prepared(tag, &forged, &authority, &objects, durable)?;
    assert!(refusal.is_none(), "{tag}: control refused: {refusal:?}");

    let _ = fs::remove_file(ledger_path);
    Ok(())
}

#[test]
fn test_c1_self_prepared_forgery_harness_delivers_for_eligible_current_mem()
-> Result<(), Box<dyn Error>> {
    self_prepared_control_case("c1-mem", false)
}

#[test]
fn test_c1_self_prepared_forgery_harness_delivers_for_eligible_current_dur()
-> Result<(), Box<dyn Error>> {
    self_prepared_control_case("c1-dur", true)
}

/// F1 encoding swap: the plan names the CURRENT tamper revision (so the ledger-current, anchor,
/// head, and request checks pass) but carries the older eligible revision's canonical encoding,
/// with the precondition computed over that older content. Only binding the carried encoding to
/// the named revision digest can refuse it (kills ME2).
fn encoding_swap_case(tag: &str, durable: bool) -> Result<(), Box<dyn Error>> {
    let ledger_path = temp_journal(&format!("{tag}-ledger"));
    let _ = fs::remove_file(&ledger_path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&ledger_path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &event_receipt, &authority, &mut journal)?;
    let tamper = tamper_observation(tag, 1_701, &mut objects, &mut authority)?;
    let (_dec_2, rc_2) =
        publish_successor(&[&decision], vec![tamper], &mut objects, &mut authority)?;

    let forged = forgery_with_encoding(&plan, &rc_2, &decision.event, &authority, tag)?;
    let refusal = dispatch_self_prepared(tag, &forged, &authority, &objects, durable)?;
    assert!(
        matches!(refusal, Some(ReferenceError::StaleEventAuthority)),
        "{tag}: {refusal:?}"
    );

    let _ = fs::remove_file(ledger_path);
    Ok(())
}

#[test]
fn test_f1_encoding_swap_to_older_eligible_revision_mem_refused() -> Result<(), Box<dyn Error>> {
    encoding_swap_case("f1-mem", false)
}

#[test]
fn test_f1_encoding_swap_to_older_eligible_revision_dur_refused() -> Result<(), Box<dyn Error>> {
    encoding_swap_case("f1-dur", true)
}

/// F8: ledgers A and B share history through the event's publishing batch (same anchor), then
/// diverge with different unrelated batches. The self-prepared plan names A's later head, while
/// the event stays current and eligible on B under the planned anchor. Only the prepare-time
/// head-in-history check can refuse dispatch against B (kills MH).
fn divergence_after_publication_case(tag: &str, durable: bool) -> Result<(), Box<dyn Error>> {
    let path_a = temp_journal(&format!("{tag}-a"));
    let path_b = temp_journal(&format!("{tag}-b"));
    let _ = fs::remove_file(&path_a);
    let _ = fs::remove_file(&path_b);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut ledger_a =
        DurableReferenceLedger::open(&path_a, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut ledger_a)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &event_receipt, &ledger_a, &mut journal)?;

    fs::copy(&path_a, &path_b)?;
    let _ua = unrelated_observation(&format!("{tag}-ua"), 1_901, &mut objects, &mut ledger_a)?;
    let mut ledger_b =
        DurableReferenceLedger::open(&path_b, "site:alert", IncompleteTailPolicy::Reject)?;
    let _ub = unrelated_observation(&format!("{tag}-ub"), 1_902, &mut objects, &mut ledger_b)?;
    assert_eq!(ledger_a.batches().len(), ledger_b.batches().len());
    assert_ne!(
        ledger_a.batches().last().map(|batch| batch.batch_digest),
        ledger_b.batches().last().map(|batch| batch.batch_digest),
        "{tag}: ledgers must diverge after the publishing batch"
    );

    let forged = self_consistent_forgery(&plan, &decision, &event_receipt, &ledger_a, tag)?;
    let refusal = dispatch_self_prepared(tag, &forged, &ledger_b, &objects, durable)?;
    assert!(
        matches!(refusal, Some(ReferenceError::StaleEventAuthority)),
        "{tag}: {refusal:?}"
    );

    let _ = fs::remove_file(path_a);
    let _ = fs::remove_file(path_b);
    Ok(())
}

#[test]
fn test_f8_divergence_after_publication_mem_refused() -> Result<(), Box<dyn Error>> {
    divergence_after_publication_case("f8-mem", false)
}

#[test]
fn test_f8_divergence_after_publication_dur_refused() -> Result<(), Box<dyn Error>> {
    divergence_after_publication_case("f8-dur", true)
}

/// F9 head rebinding: a legitimately prepared plan whose prepare-time head fields are moved to a
/// later head that is still in the ledger's history, leaving the recorded intent untouched. Only
/// recomputing the precondition against the journal-recorded intent can refuse it (kills MP).
fn head_rebinding_case(tag: &str, durable: bool) -> Result<(), Box<dyn Error>> {
    let ledger_path = temp_journal(&format!("{tag}-ledger"));
    let journal_path = temp_journal(&format!("{tag}-journal"));
    let _ = fs::remove_file(&ledger_path);
    let _ = fs::remove_file(&journal_path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&ledger_path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let mut durable_journal =
        DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
    let plan = if durable {
        durable_journal.prepare_alert(durable_params(&decision, &event_receipt, &authority)?)?
    } else {
        prepare(&decision, &event_receipt, &authority, &mut journal)?
    };
    let _unrelated =
        unrelated_observation(&format!("{tag}-later"), 1_903, &mut objects, &mut authority)?;

    let mut moved = plan.clone();
    moved.prepared_head_sequence = u64::try_from(authority.batches().len())?;
    moved.prepared_head_digest = authority
        .batches()
        .last()
        .ok_or("empty authority ledger")?
        .batch_digest;
    assert_ne!(moved.prepared_head_sequence, plan.prepared_head_sequence);

    let mut provider = ReferenceAlertProvider::with_provider_id(format!("provider:test:{tag}"));
    if durable {
        let res = durable_journal.dispatch_alert(
            &moved,
            &authority,
            &objects,
            ReferenceProviderBehavior::Deliver,
            TimestampNs(101),
            TimestampNs(102),
            &mut provider,
        );
        assert!(
            matches!(
                res,
                Err(DurableEffectError::Reference(
                    ReferenceError::StaleEventAuthority
                ))
            ),
            "{tag}: {res:?}"
        );
        assert_eq!(provider.message_count(), 0, "{tag}: alert delivered");
        assert_cancelled_durable(&durable_journal, &plan)?;
        drop(durable_journal);
        let reopened = DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
        assert_cancelled_durable(&reopened, &plan)?;
    } else {
        let res = dispatch_reference_alert(
            &moved,
            &authority,
            &objects,
            ReferenceProviderBehavior::Deliver,
            TimestampNs(101),
            TimestampNs(102),
            &mut journal,
            &mut provider,
        );
        assert!(
            matches!(res, Err(ReferenceError::StaleEventAuthority)),
            "{tag}: {res:?}"
        );
        assert_eq!(provider.message_count(), 0, "{tag}: alert delivered");
        assert_cancelled_mem(&journal, &plan)?;
    }

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(journal_path);
    Ok(())
}

#[test]
fn test_f9_head_rebinding_to_later_in_history_head_mem_refused() -> Result<(), Box<dyn Error>> {
    head_rebinding_case("f9-mem", false)
}

#[test]
fn test_f9_head_rebinding_to_later_in_history_head_dur_refused() -> Result<(), Box<dyn Error>> {
    head_rebinding_case("f9-dur", true)
}

/// M2: plan integrity binds the request digest to the event root, revision, and channel. A
/// self-prepared intent identical to the legitimate one except for an unbound request digest (so
/// intent equality, eligibility, head, and precondition all pass) is refused as plan-integrity.
fn unbound_request_digest_case(tag: &str, durable: bool) -> Result<(), Box<dyn Error>> {
    let ledger_path = temp_journal(&format!("{tag}-ledger"));
    let _ = fs::remove_file(&ledger_path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&ledger_path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &event_receipt, &authority, &mut journal)?;

    let mut unbound = plan.clone();
    unbound.intent.request_digest =
        fss_core::ContentDigest::sha256(b"request digest bound to no event and no channel");
    unbound.intent.operation_id = OperationId::parse(format!("operation:alert:{tag}-self"))?;
    unbound.intent.idempotency_key =
        IdempotencyKey::parse(format!("idempotency:alert:{tag}-self"))?;
    unbound.obligation_id = ObligationId::parse(format!("obligation:alert:{tag}-self"))?;
    assert!(crate::alert::validate_reference_alert_plan(&unbound).is_err());

    let refusal = dispatch_self_prepared(tag, &unbound, &authority, &objects, durable)?;
    assert!(
        matches!(
            refusal,
            Some(ReferenceError::InvalidSpec("alert_plan_integrity"))
        ),
        "{tag}: {refusal:?}"
    );

    let _ = fs::remove_file(ledger_path);
    Ok(())
}

#[test]
fn test_m2_unbound_request_digest_refused_mem() -> Result<(), Box<dyn Error>> {
    unbound_request_digest_case("m2-unbound-mem", false)
}

#[test]
fn test_m2_unbound_request_digest_refused_dur() -> Result<(), Box<dyn Error>> {
    unbound_request_digest_case("m2-unbound-dur", true)
}

// ============ Round 4b (fss-2uftm H1): prepare and dispatch recompute the event's lineage ============

/// Publishes `rev` straight through the authority publisher, bypassing every check
/// `publish_reference_event` runs, with either the honest lineage tamper witness or an all-clear
/// one. The receipt carries the true lineage.
fn plant_revision(
    rev: &fss_core::EventHypothesis,
    prior: &[fss_core::EventHypothesis],
    prior_generation: u64,
    all_clear_witness: bool,
    objects: &mut InMemoryObjectStore,
    authority: &mut DurableReferenceLedger,
) -> Result<crate::ReferenceEventReceipt, Box<dyn Error>> {
    use fss_core::CanonicalEncode as _;
    use fss_object::VerifiedObjectCatalog as _;
    for model_receipt in &rev.model_receipts {
        objects.require_verified(*model_receipt)?;
    }
    let event_object_digest = objects.put_verified(&rev.canonical_bytes())?;
    let mut encoder = fss_core::CanonicalEncoder::new();
    encoder.text("fss.canonical.v1");
    encoder.text("fss.event_hypothesis.v1");
    rev.encode_canonical(&mut encoder);
    let event_revision_digest = objects.put_verified(&encoder.finish())?;
    let manifest = fss_object::ObjectManifest::new(
        "event-revision",
        rev.model_receipts.iter().copied(),
        Some(event_object_digest),
    )?;
    let event_root = objects.publish_manifest(manifest)?.root;
    let name = rev.event_id.as_str();
    let status = if all_clear_witness {
        fss_core::SensorTamperStatus::default()
    } else {
        fss_core::event::compute_sensor_tamper_status_with_interval(
            prior.iter(),
            Some(&rev.evidence),
            Some(rev.interval),
        )
    };
    let mut status_encoder = fss_core::CanonicalEncoder::new();
    status.encode_canonical(&mut status_encoder);
    let _ = objects.put_verified(&status_encoder.finish())?;
    let delta = fss_core::EvidenceDelta {
        delta_id: format!("delta:event:{name}:{}", rev.revision),
        family: "event_revision".to_owned(),
        object_id: fss_core::ObjectId::parse(format!("object:event:{name}"))?,
        prior_generation: Some(prior_generation),
        new_generation: rev.revision,
        validity: rev.interval,
        plane: fss_core::Plane::Authority,
        payload_digest: event_root,
        witness_digest: Some(event_revision_digest),
        operation_id: None,
    };
    let tamper_delta = fss_core::EvidenceDelta {
        delta_id: format!("delta:event:{name}:tamper:{}", rev.revision),
        family: "sensor_tamper_status".to_owned(),
        object_id: fss_core::ObjectId::parse(format!("object:event:{name}:tamper"))?,
        prior_generation: Some(prior_generation),
        new_generation: rev.revision,
        validity: rev.interval,
        plane: fss_core::Plane::Authority,
        payload_digest: event_root,
        witness_digest: Some(status.canonical_digest()),
        operation_id: None,
    };
    let authority_anchor = {
        let mut publisher = fss_publication::AuthorityPublisher::new(objects, authority);
        let batch = publisher.prepare_batch(
            fss_core::BatchId::parse(format!("batch:event:{name}:{}", rev.revision))?,
            vec![delta, tamper_delta],
            [event_root],
        )?;
        publisher.append(batch)?
    };
    Ok(crate::ReferenceEventReceipt {
        event_root,
        event_object_digest,
        event_revision_digest,
        authority_anchor,
        lineage_tamper_status: status,
        prior_revision_encodings: prior
            .iter()
            .map(crate::alert::event_revision_encoding)
            .collect(),
    })
}

/// Outcome of preparing an alert for a planted revision, and the dispatch refusal of the
/// self-prepared forgery naming it (`None` when dispatch delivered).
type PlantedOutcome = (Result<(), ReferenceError>, Option<ReferenceError>);

/// Eligible genesis, a published tamper revision, then a Corroborated revision that drops the
/// unretired tamper, which honest publication refuses and which is planted with the given witness.
/// Returns the outcome of preparing an alert for it and the dispatch refusal of the fully
/// self-consistent self-prepared forgery naming it (the C1 harness, which delivers for an eligible
/// current revision).
fn planted_drop_case(
    tag: &str,
    durable: bool,
    all_clear_witness: bool,
) -> Result<PlantedOutcome, Box<dyn Error>> {
    let ledger_path = temp_journal(&format!("{tag}-ledger"));
    let _ = fs::remove_file(&ledger_path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&ledger_path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &event_receipt, &authority, &mut journal)?;
    let tamper = tamper_observation(tag, 1_801, &mut objects, &mut authority)?;
    let (dec_2, _rc_2) =
        publish_successor(&[&decision], vec![tamper], &mut objects, &mut authority)?;
    let first = unrelated_observation(&format!("{tag}-e1"), 2_011, &mut objects, &mut authority)?;
    let second = unrelated_observation(&format!("{tag}-e2"), 2_022, &mut objects, &mut authority)?;
    let candidate =
        evaluate_unknown_presence(decision.event.event_id.clone(), vec![first, second])?;
    let rev_3 = fss_core::EventHypothesis {
        revision: dec_2.event.revision + 1,
        supersedes: Some(dec_2.event.revision_digest()),
        ..candidate.event.clone()
    };
    rev_3.validate()?;
    let dec_3 = ReferencePolicyDecision {
        event: rev_3,
        action: candidate.action,
    };
    assert!(
        publish_reference_event(&dec_3, &mut objects, &mut authority).is_err(),
        "{tag}: honest publication accepted the tamper-dropping revision"
    );
    let rc_3 = plant_revision(
        &dec_3.event,
        &[decision.event.clone(), dec_2.event.clone()],
        2,
        all_clear_witness,
        &mut objects,
        &mut authority,
    )?;
    let mut prepare_journal = EffectJournal::new();
    let prepared = prepare_reference_alert(
        PrepareAlertParams {
            decision: &dec_3,
            event_receipt: &rc_3,
            authority: &authority,
            operation_id: OperationId::parse(format!("operation:alert:{tag}-prep").as_str())?,
            idempotency_key: IdempotencyKey::parse(
                format!("idempotency:alert:{tag}-prep").as_str(),
            )?,
            obligation_id: ObligationId::parse(format!("obligation:alert:{tag}-prep").as_str())?,
            channel: "security-ops".to_owned(),
            now: TimestampNs(3_000),
        },
        &mut prepare_journal,
    )
    .map(|_| ());
    let forged = self_consistent_forgery(&plan, &dec_3, &rc_3, &authority, tag)?;
    let refusal = dispatch_self_prepared(tag, &forged, &authority, &objects, durable)?;
    let _ = fs::remove_file(ledger_path);
    Ok((prepared, refusal))
}

fn is_integrity_risk(error: Option<&ReferenceError>) -> bool {
    matches!(
        error,
        Some(ReferenceError::Contract(
            fss_core::ContractError::SensorIntegrityRisk
        ))
    )
}

fn is_witness_mismatch(error: Option<&ReferenceError>) -> bool {
    matches!(
        error,
        Some(ReferenceError::InvalidSpec(
            "sensor_tamper_witness_mismatch"
        ))
    )
}

/// H1: with the honest witness (whose status names the open tamper), prepare and dispatch both
/// refuse; dispatch recomputes the lineage rather than trusting the revision's own edges.
#[test]
fn planted_tamper_drop_with_honest_witness_is_refused_mem() -> Result<(), Box<dyn Error>> {
    let (prepared, refusal) = planted_drop_case("h1-honest-mem", false, false)?;
    assert!(is_integrity_risk(prepared.as_ref().err()), "{prepared:?}");
    assert!(is_integrity_risk(refusal.as_ref()), "{refusal:?}");
    Ok(())
}

#[test]
fn planted_tamper_drop_with_honest_witness_is_refused_dur() -> Result<(), Box<dyn Error>> {
    let (prepared, refusal) = planted_drop_case("h1-honest-dur", true, false)?;
    assert!(is_integrity_risk(prepared.as_ref().err()), "{prepared:?}");
    assert!(is_integrity_risk(refusal.as_ref()), "{refusal:?}");
    Ok(())
}

/// H1 residual: a planted all-clear witness is refused by prepare and by dispatch, because the
/// status recomputed from the ledger's lineage disagrees with it.
#[test]
fn planted_tamper_drop_with_all_clear_witness_is_refused_mem() -> Result<(), Box<dyn Error>> {
    let (prepared, refusal) = planted_drop_case("h1-clear-mem", false, true)?;
    assert!(is_witness_mismatch(prepared.as_ref().err()), "{prepared:?}");
    assert!(is_witness_mismatch(refusal.as_ref()), "{refusal:?}");
    Ok(())
}

#[test]
fn planted_tamper_drop_with_all_clear_witness_is_refused_dur() -> Result<(), Box<dyn Error>> {
    let (prepared, refusal) = planted_drop_case("h1-clear-dur", true, true)?;
    assert!(is_witness_mismatch(prepared.as_ref().err()), "{prepared:?}");
    assert!(is_witness_mismatch(refusal.as_ref()), "{refusal:?}");
    Ok(())
}

/// A dispatch plan must carry the event's whole lineage: the same self-consistent forgery with the
/// earlier revisions omitted is refused (the ledger names more revisions than the plan carries).
#[test]
fn dispatch_refuses_a_plan_without_the_event_lineage() -> Result<(), Box<dyn Error>> {
    let tag = "h1-no-lineage";
    let ledger_path = temp_journal(&format!("{tag}-ledger"));
    let _ = fs::remove_file(&ledger_path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&ledger_path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &event_receipt, &authority, &mut journal)?;
    let tamper = tamper_observation(tag, 1_801, &mut objects, &mut authority)?;
    let (dec_2, _rc_2) =
        publish_successor(&[&decision], vec![tamper], &mut objects, &mut authority)?;
    let restored = observation_with_label(
        &format!("capture:alert:{tag}-tamper-restored"),
        &format!("sensor:alert:{tag}-tamper"),
        2_002,
        &format!("power:alert:{tag}-tamper"),
        MockSemanticLabel::IntegrityRestored,
        &mut objects,
        &mut authority,
    )?;
    let first = unrelated_observation(&format!("{tag}-e1"), 2_011, &mut objects, &mut authority)?;
    let second = unrelated_observation(&format!("{tag}-e2"), 2_022, &mut objects, &mut authority)?;
    let (dec_3, rc_3) = publish_successor(
        &[&decision, &dec_2],
        vec![restored, first, second],
        &mut objects,
        &mut authority,
    )?;
    let mut forged = self_consistent_forgery(&plan, &dec_3, &rc_3, &authority, tag)?;
    forged.prior_revision_encodings.clear();
    let refusal = dispatch_self_prepared(tag, &forged, &authority, &objects, false)?;
    let _ = fs::remove_file(ledger_path);
    assert!(
        matches!(refusal, Some(ReferenceError::StaleEventAuthority)),
        "{refusal:?}"
    );
    Ok(())
}

// ==== Round 4d (fss-2uftm): a lineage with the right count but a substituted earlier revision ====
//
// Each case plants, straight through the authority publisher, a current revision whose receipt
// carries a lineage of the right length that is not the ledger's own, and whose published
// sensor_tamper_status witness is honest to that supplied lineage. The witness cross-check
// therefore passes; the admission check named by the case is the only guard, and prepare and
// dispatch must both refuse with `StaleEventAuthority`.

/// Publishes `rev` under the event object `object_event` straight through the authority
/// publisher. `generations` is the delta's (prior, new) generation, the witness is the status of
/// `status_lineage` followed by `rev`, and the receipt carries `receipt_prior`. Nothing checks them.
fn plant_substituted(
    rev: &fss_core::EventHypothesis,
    object_event: &str,
    generations: (Option<u64>, u64),
    status_lineage: &[fss_core::EventHypothesis],
    receipt_prior: &[fss_core::EventHypothesis],
    objects: &mut InMemoryObjectStore,
    authority: &mut DurableReferenceLedger,
) -> Result<crate::ReferenceEventReceipt, Box<dyn Error>> {
    use fss_core::CanonicalEncode as _;
    use fss_object::VerifiedObjectCatalog as _;
    for model_receipt in &rev.model_receipts {
        objects.require_verified(*model_receipt)?;
    }
    let event_object_digest = objects.put_verified(&rev.canonical_bytes())?;
    let event_revision_digest =
        objects.put_verified(&crate::alert::event_revision_encoding(rev))?;
    let manifest = fss_object::ObjectManifest::new(
        "event-revision",
        rev.model_receipts.iter().copied(),
        Some(event_object_digest),
    )?;
    let event_root = objects.publish_manifest(manifest)?.root;
    let status = fss_core::event::compute_sensor_tamper_status_with_interval(
        status_lineage.iter(),
        Some(&rev.evidence),
        Some(rev.interval),
    );
    let mut status_encoder = fss_core::CanonicalEncoder::new();
    status.encode_canonical(&mut status_encoder);
    let _ = objects.put_verified(&status_encoder.finish())?;
    let (prior_generation, new_generation) = generations;
    let delta = fss_core::EvidenceDelta {
        delta_id: format!("delta:event:{object_event}:{new_generation}"),
        family: "event_revision".to_owned(),
        object_id: fss_core::ObjectId::parse(format!("object:event:{object_event}"))?,
        prior_generation,
        new_generation,
        validity: rev.interval,
        plane: fss_core::Plane::Authority,
        payload_digest: event_root,
        witness_digest: Some(event_revision_digest),
        operation_id: None,
    };
    let tamper_delta = fss_core::EvidenceDelta {
        delta_id: format!("delta:event:{object_event}:tamper:{new_generation}"),
        family: "sensor_tamper_status".to_owned(),
        object_id: fss_core::ObjectId::parse(format!("object:event:{object_event}:tamper"))?,
        prior_generation,
        new_generation,
        validity: rev.interval,
        plane: fss_core::Plane::Authority,
        payload_digest: event_root,
        witness_digest: Some(status.canonical_digest()),
        operation_id: None,
    };
    let authority_anchor = {
        let mut publisher = fss_publication::AuthorityPublisher::new(objects, authority);
        let batch = publisher.prepare_batch(
            fss_core::BatchId::parse(format!("batch:event:{object_event}:{new_generation}"))?,
            vec![delta, tamper_delta],
            [event_root],
        )?;
        publisher.append(batch)?
    };
    Ok(crate::ReferenceEventReceipt {
        event_root,
        event_object_digest,
        event_revision_digest,
        authority_anchor,
        lineage_tamper_status: status,
        prior_revision_encodings: receipt_prior
            .iter()
            .map(crate::alert::event_revision_encoding)
            .collect(),
    })
}

/// A Corroborated, alert-eligible revision of `event_id` from two fresh unrelated observations.
fn corroborated_candidate(
    tag: &str,
    event_id: &EventId,
    objects: &mut InMemoryObjectStore,
    authority: &mut DurableReferenceLedger,
) -> Result<ReferencePolicyDecision, Box<dyn Error>> {
    let first = unrelated_observation(&format!("{tag}-a"), 2_101, objects, authority)?;
    let second = unrelated_observation(&format!("{tag}-b"), 2_202, objects, authority)?;
    Ok(evaluate_unknown_presence(
        event_id.clone(),
        vec![first, second],
    )?)
}

/// `candidate` renumbered as `revision`, superseding `supersedes`.
fn renumbered(
    candidate: &fss_core::EventHypothesis,
    revision: u64,
    supersedes: fss_core::ContentDigest,
) -> Result<fss_core::EventHypothesis, Box<dyn Error>> {
    let rev = fss_core::EventHypothesis {
        revision,
        supersedes: Some(supersedes),
        ..candidate.clone()
    };
    rev.validate()?;
    Ok(rev)
}

#[derive(Clone, Copy, Debug)]
enum Substitution {
    /// A fabricated clean revision 2 in place of the published tamper revision 2 (MHD).
    Digest,
    /// The current revision numbered 3 where the ledger publishes it as generation 2 (MHG).
    Generation,
    /// A revision of another event planted as the genesis of the event object (MHE).
    EventId,
    /// The current revision supersedes a genesis the ledger never published (MHS).
    Supersedes,
    /// The ledger's two earlier revisions supplied in the wrong order.
    Reordered,
}

/// Plants the case's current revision and returns the prepare outcome and the dispatch refusal
/// of the fully self-consistent self-prepared forgery naming it (the C1 harness).
fn substituted_lineage_case(
    kind: Substitution,
    tag: &str,
) -> Result<PlantedOutcome, Box<dyn Error>> {
    let ledger_path = temp_journal(&format!("{tag}-ledger"));
    let _ = fs::remove_file(&ledger_path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&ledger_path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision, event_receipt) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &event_receipt, &authority, &mut journal)?;
    let genesis = decision.event.clone();
    let event_id = genesis.event_id.clone();
    let event_name = event_id.as_str().to_owned();
    let (current, receipt) = match kind {
        Substitution::Digest => {
            let tamper = tamper_observation(tag, 1_801, &mut objects, &mut authority)?;
            let (dec_2, _rc_2) =
                publish_successor(&[&decision], vec![tamper], &mut objects, &mut authority)?;
            let fake = corroborated_candidate(
                &format!("{tag}-fake"),
                &event_id,
                &mut objects,
                &mut authority,
            )?;
            let fake_2 = renumbered(&fake.event, 2, genesis.revision_digest())?;
            let cand = corroborated_candidate(tag, &event_id, &mut objects, &mut authority)?;
            let current = ReferencePolicyDecision {
                event: renumbered(&cand.event, 3, fake_2.revision_digest())?,
                action: cand.action,
            };
            let supplied = [genesis.clone(), fake_2];
            let receipt = plant_substituted(
                &current.event,
                &event_name,
                (Some(dec_2.event.revision), 3),
                &supplied,
                &supplied,
                &mut objects,
                &mut authority,
            )?;
            (current, receipt)
        }
        Substitution::Generation => {
            let cand = corroborated_candidate(tag, &event_id, &mut objects, &mut authority)?;
            let current = ReferencePolicyDecision {
                event: renumbered(&cand.event, 3, genesis.revision_digest())?,
                action: cand.action,
            };
            let supplied = [genesis.clone()];
            let receipt = plant_substituted(
                &current.event,
                &event_name,
                (Some(1), 2),
                &supplied,
                &supplied,
                &mut objects,
                &mut authority,
            )?;
            (current, receipt)
        }
        Substitution::EventId => {
            let spliced_name = "event:alert:spliced";
            let spliced = EventId::parse(spliced_name)?;
            let foreign = corroborated_candidate(
                &format!("{tag}-foreign"),
                &EventId::parse("event:alert:foreign")?,
                &mut objects,
                &mut authority,
            )?;
            let _ = plant_substituted(
                &foreign.event,
                spliced_name,
                (None, 1),
                &[],
                &[],
                &mut objects,
                &mut authority,
            )?;
            let cand = corroborated_candidate(tag, &spliced, &mut objects, &mut authority)?;
            let current = ReferencePolicyDecision {
                event: renumbered(&cand.event, 2, foreign.event.revision_digest())?,
                action: cand.action,
            };
            let supplied = [foreign.event.clone()];
            let receipt = plant_substituted(
                &current.event,
                spliced_name,
                (Some(1), 2),
                &supplied,
                &supplied,
                &mut objects,
                &mut authority,
            )?;
            (current, receipt)
        }
        Substitution::Supersedes => {
            let stray = corroborated_candidate(
                &format!("{tag}-stray"),
                &event_id,
                &mut objects,
                &mut authority,
            )?;
            let cand = corroborated_candidate(tag, &event_id, &mut objects, &mut authority)?;
            let current = ReferencePolicyDecision {
                event: renumbered(&cand.event, 2, stray.event.revision_digest())?,
                action: cand.action,
            };
            let supplied = [genesis.clone()];
            let receipt = plant_substituted(
                &current.event,
                &event_name,
                (Some(1), 2),
                &supplied,
                &supplied,
                &mut objects,
                &mut authority,
            )?;
            (current, receipt)
        }
        Substitution::Reordered => {
            let middle = corroborated_candidate(
                &format!("{tag}-middle"),
                &event_id,
                &mut objects,
                &mut authority,
            )?;
            let middle_2 = renumbered(&middle.event, 2, genesis.revision_digest())?;
            let _ = plant_substituted(
                &middle_2,
                &event_name,
                (Some(1), 2),
                std::slice::from_ref(&genesis),
                std::slice::from_ref(&genesis),
                &mut objects,
                &mut authority,
            )?;
            let cand = corroborated_candidate(tag, &event_id, &mut objects, &mut authority)?;
            let current = ReferencePolicyDecision {
                event: renumbered(&cand.event, 3, middle_2.revision_digest())?,
                action: cand.action,
            };
            let receipt = plant_substituted(
                &current.event,
                &event_name,
                (Some(2), 3),
                &[genesis.clone(), middle_2.clone()],
                &[middle_2, genesis.clone()],
                &mut objects,
                &mut authority,
            )?;
            (current, receipt)
        }
    };
    let mut prepare_journal = EffectJournal::new();
    let prepared = prepare_reference_alert(
        PrepareAlertParams {
            decision: &current,
            event_receipt: &receipt,
            authority: &authority,
            operation_id: OperationId::parse(format!("operation:alert:{tag}-prep").as_str())?,
            idempotency_key: IdempotencyKey::parse(
                format!("idempotency:alert:{tag}-prep").as_str(),
            )?,
            obligation_id: ObligationId::parse(format!("obligation:alert:{tag}-prep").as_str())?,
            channel: "security-ops".to_owned(),
            now: TimestampNs(3_000),
        },
        &mut prepare_journal,
    )
    .map(|_| ());
    let forged = self_consistent_forgery(&plan, &current, &receipt, &authority, tag)?;
    let refusal = dispatch_self_prepared(tag, &forged, &authority, &objects, false)?;
    let _ = fs::remove_file(ledger_path);
    Ok((prepared, refusal))
}

fn assert_stale_everywhere(outcome: &PlantedOutcome, case: &str) {
    let (prepared, refusal) = outcome;
    assert!(
        matches!(prepared, Err(ReferenceError::StaleEventAuthority)),
        "{case}: prepare {prepared:?}"
    );
    assert!(
        matches!(refusal, Some(ReferenceError::StaleEventAuthority)),
        "{case}: dispatch {refusal:?}"
    );
}

/// MHD: a fabricated clean revision 2 hides the published tamper revision 2. The witness is honest
/// to the fabricated lineage, so only the per-position digest check refuses it.
#[test]
fn substituted_earlier_revision_digest_is_refused() -> Result<(), Box<dyn Error>> {
    let outcome = substituted_lineage_case(Substitution::Digest, "r4d-digest")?;
    assert_stale_everywhere(&outcome, "digest");
    Ok(())
}

/// MHG: the revision number the lineage carries disagrees with the ledger generation.
#[test]
fn substituted_generation_is_refused() -> Result<(), Box<dyn Error>> {
    let outcome = substituted_lineage_case(Substitution::Generation, "r4d-generation")?;
    assert_stale_everywhere(&outcome, "generation");
    Ok(())
}

/// MHE: a revision of another event is planted as the event object's genesis.
#[test]
fn substituted_event_id_is_refused() -> Result<(), Box<dyn Error>> {
    let outcome = substituted_lineage_case(Substitution::EventId, "r4d-event")?;
    assert_stale_everywhere(&outcome, "event id");
    Ok(())
}

/// MHS: the ledger's revisions do not form one supersession chain.
#[test]
fn broken_supersession_chain_is_refused() -> Result<(), Box<dyn Error>> {
    let outcome = substituted_lineage_case(Substitution::Supersedes, "r4d-supersedes")?;
    assert_stale_everywhere(&outcome, "supersedes");
    Ok(())
}

/// The ledger's own earlier revisions supplied in the wrong order.
#[test]
fn reordered_lineage_is_refused() -> Result<(), Box<dyn Error>> {
    let outcome = substituted_lineage_case(Substitution::Reordered, "r4d-reordered")?;
    assert_stale_everywhere(&outcome, "reordered");
    Ok(())
}

/// fss-ct73p P6c: a sensor-tamper observation published under a DIFFERENT event of the same
/// failure domain refuses the in-flight alert even though the alerting event's own lineage never
/// changes (no new event revision). Refusal cancels the operation and obligation and delivers
/// zero provider messages.
#[test]
fn cross_event_domain_tamper_refuses_dispatch_p6c() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("p6c-domain-tamper");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision_1, event_receipt_1) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision_1, &event_receipt_1, &authority, &mut journal)?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:p6c");

    // The tamper rides a SECOND event of the alerting event's cited failure domain.
    let tamper_obs = observation_with_label(
        "capture:alert:p6c-tamper",
        "sensor:alert:p6c-tamper",
        99,
        "power:alert:a",
        MockSemanticLabel::TamperLike,
        &mut objects,
        &mut authority,
    )?;
    let health_eval =
        evaluate_unknown_presence(EventId::parse("event:alert:p6c-health")?, vec![tamper_obs])?;
    let _health_receipt = publish_reference_event(&health_eval, &mut objects, &mut authority)?;

    let dispatch_result = dispatch_reference_alert(
        &plan,
        &authority,
        &objects,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    );
    assert!(
        matches!(
            dispatch_result,
            Err(ReferenceError::Contract(
                fss_core::ContractError::SensorIntegrityRisk
            ))
        ),
        "expected SensorIntegrityRisk, got: {dispatch_result:?}"
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

    let _ = fs::remove_file(&path);
    Ok(())
}

/// fss-ct73p P6c acceptance: an evidenced sensor-integrity restoration on the other event retires
/// the domain tamper, so the unchanged in-flight alert delivers.
#[test]
fn evidenced_restoration_reenables_dispatch_p6c() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("p6c-restoration");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision_1, event_receipt_1) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision_1, &event_receipt_1, &authority, &mut journal)?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:p6c-restored");

    // Open tamper under the health event of the same domain.
    let tamper_obs = observation_with_label(
        "capture:alert:p6c-restored-tamper",
        "sensor:alert:p6c-restored",
        99,
        "power:alert:a",
        MockSemanticLabel::TamperLike,
        &mut objects,
        &mut authority,
    )?;
    let health_id = EventId::parse("event:alert:p6c-restored-health")?;
    let health_eval = evaluate_unknown_presence(health_id.clone(), vec![tamper_obs])?;
    let _health_receipt = publish_reference_event(&health_eval, &mut objects, &mut authority)?;
    let health_rev1 = health_eval.event.clone();

    // Evidenced restoration, captured strictly after the tamper, on the same sensor identity.
    let restored_obs = observation_with_label(
        "capture:alert:p6c-restored-back",
        "sensor:alert:p6c-restored",
        500,
        "power:alert:a",
        MockSemanticLabel::IntegrityRestored,
        &mut objects,
        &mut authority,
    )?;
    let candidate = evaluate_unknown_presence(health_id, vec![restored_obs])?;
    // The evidenced restoration retires the open tamper, so the successor may drop its edge.
    let decision_2 = successor(&health_rev1, &candidate)?;
    let _health_receipt_2 = publish_reference_event(&decision_2, &mut objects, &mut authority)?;

    // The tamper is retired, so the unchanged in-flight plan delivers.
    let receipt = dispatch_reference_alert(
        &plan,
        &authority,
        &objects,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(201),
        TimestampNs(202),
        &mut journal,
        &mut provider,
    )?;
    assert_eq!(receipt.state, EffectState::AdapterAccepted);
    assert_eq!(provider.message_count(), 1);

    let _ = fs::remove_file(&path);
    Ok(())
}

/// fss-ct73p P6c acceptance: a tamper in an unrelated failure domain never blocks the raw
/// dispatch path, and the durable dispatch path refuses exactly like the raw path.
#[test]
fn unrelated_domain_tamper_and_durable_path_p6c() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("p6c-unrelated");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(768, 12 * 1024 * 1024));
    let mut authority =
        DurableReferenceLedger::open(&path, "site:alert", IncompleteTailPolicy::Reject)?;
    let (decision_1, event_receipt_1) = eligible_event(&mut objects, &mut authority)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision_1, &event_receipt_1, &authority, &mut journal)?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:p6c-unrelated");

    // Prepare the durable-plan subject BEFORE any unrelated batch moves the latest authority
    // batch: a receipt is only preparable while its revision is the latest batch's event.
    let durable_path = temp_journal("p6c-durable");
    let _ = fs::remove_file(&durable_path);
    let mut durable_journal =
        crate::DurableEffectJournal::open(&durable_path, IncompleteTailPolicy::Reject)?;
    let durable_plan = durable_journal.prepare_alert(PrepareAlertParams {
        decision: &decision_1,
        event_receipt: &event_receipt_1,
        authority: &authority,
        operation_id: OperationId::parse("operation:alert:p6c-durable")?,
        idempotency_key: IdempotencyKey::parse("idempotency:alert:p6c-durable")?,
        obligation_id: ObligationId::parse("obligation:alert:p6c-durable")?,
        channel: "operator:oncall".to_owned(),
        now: TimestampNs(300),
    })?;

    // Tamper under an UNRELATED failure domain: the raw dispatch is not blocked.
    let tamper_obs = observation_with_label(
        "capture:alert:p6c-unrelated",
        "sensor:alert:p6c-unrelated",
        99,
        "power:alert:unrelated",
        MockSemanticLabel::TamperLike,
        &mut objects,
        &mut authority,
    )?;
    let health_eval = evaluate_unknown_presence(
        EventId::parse("event:alert:p6c-unrelated-health")?,
        vec![tamper_obs],
    )?;
    let _health_receipt = publish_reference_event(&health_eval, &mut objects, &mut authority)?;

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
    assert_eq!(receipt.state, EffectState::AdapterAccepted);
    assert_eq!(provider.message_count(), 1);

    // A tamper on the alerting event's OWN cited domain refuses the durable dispatch.
    let opened_tamper_obs = observation_with_label(
        "capture:alert:p6c-durable-tamper",
        "sensor:alert:p6c-durable",
        600,
        "power:alert:b",
        MockSemanticLabel::TamperLike,
        &mut objects,
        &mut authority,
    )?;
    let opened_eval = evaluate_unknown_presence(
        EventId::parse("event:alert:p6c-durable-health")?,
        vec![opened_tamper_obs],
    )?;
    let _opened_receipt = publish_reference_event(&opened_eval, &mut objects, &mut authority)?;

    let durable_result = durable_journal.dispatch_alert(
        &durable_plan,
        &authority,
        &objects,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(301),
        TimestampNs(302),
        &mut provider,
    );
    // The durable journal maps the revalidation refusal onto its contract error identity.
    assert!(
        matches!(
            durable_result,
            Err(DurableEffectError::Contract(
                fss_core::ContractError::SensorIntegrityRisk
            ))
        ),
        "expected SensorIntegrityRisk on the durable path, got: {durable_result:?}"
    );
    assert_eq!(
        durable_journal
            .operation(&durable_plan.intent.operation_id)
            .ok_or(ReferenceError::InvalidSpec("missing_operation"))?
            .state,
        EffectState::Cancelled
    );

    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&durable_path);
    Ok(())
}

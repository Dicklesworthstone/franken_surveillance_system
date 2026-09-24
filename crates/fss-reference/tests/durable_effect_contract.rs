#![forbid(unsafe_code)]
//! Integration contract tests for DurableEffectJournal restart durability and crash invariants (fss-x4a.16.13).

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

use fss_core::{
    AffordanceClass, BatchId, CapsuleId, CaptureInterval, Completeness, ContentDigest,
    ContractBasis, ContractBasisRegistryBytes, ContractError, EffectIntent, EffectJournal,
    EffectState, EventId, EvidenceDelta, HandoffId, IdempotencyKey, MissionId, ObjectId,
    ObligationId, ObligationState, OperationId, Plane, PrincipalId, ProbabilityInterval, SensorId,
    SessionId, TimestampNs,
};
use fss_ledger::{AppendPhase, DurableReferenceLedger, IncompleteTailPolicy, JournalError};
use fss_object::{InMemoryObjectStore, ObjectLimits};
use fss_reference::{
    AlertDispatchTimes, CAPABILITY_EFFECT_RECONCILE, DeliveryPlan, DurableEffectError,
    DurableEffectJournal, EFFECT_RECONCILE_AFFORDANCE, MockModelScript, MockModelSpec,
    MockSemanticLabel, ObligationLedgerState, PrepareAlertParams, ReferenceAlertPlan,
    ReferenceAlertProvider, ReferenceError, ReferenceEventReceipt, ReferenceModelObservation,
    ReferencePolicyAction, ReferencePolicyDecision, ReferenceProviderBehavior,
    ReferenceSituationRequest, VirtualCameraSpec, compile_reference_situation_with_durable_journal,
    dispatch_reference_alert, evaluate_unknown_presence, execute_mock_model,
    prepare_reference_alert, publish_reference_event, run_reference_capture,
    seal_reference_handoff,
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
        let dir_name = format!("fss-durable-effect-{pid}-{now}-{attempt}-{name}");
        let dir = base.join(dir_name);
        if std::fs::create_dir(&dir).is_ok() {
            return dir.join(format!("{name}.journal"));
        }
    }
    base.join(format!(
        "fss-durable-effect-{pid}-{now}-fallback-{name}.journal"
    ))
}

fn sample_intent(op_name: &str, key_name: &str) -> Result<EffectIntent, Box<dyn Error>> {
    Ok(EffectIntent {
        operation_id: OperationId::parse(op_name)?,
        idempotency_key: IdempotencyKey::parse(key_name)?,
        effect_class: "alert.dispatch".to_string(),
        request_digest: ContentDigest::sha256(b"sample_request"),
        precondition_digest: ContentDigest::sha256(b"sample_preconditions"),
    })
}

/// Builds the eligible reference alert plan and prepares it durably in `journal_path` through the
/// eligible path: `prepare_alert` verifies the published event's eligibility against the authority
/// ledger and records the prepare-time ledger head from the ledger itself (fss-wjisz). The same
/// plan is also prepared in a process-local in-memory journal, returned for crash modelling.
fn setup_alert_plan(
    journal_path: &std::path::Path,
    ledger_path: &std::path::Path,
) -> Result<
    (
        ReferenceAlertPlan,
        EffectJournal,
        DurableReferenceLedger,
        InMemoryObjectStore,
    ),
    Box<dyn Error>,
> {
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut authority = DurableReferenceLedger::open(
        ledger_path,
        "site:durable_alert",
        IncompleteTailPolicy::Reject,
    )?;

    let spec_a = VirtualCameraSpec {
        capture_id: CapsuleId::parse("capture:cam:alpha")?,
        sensor_id: SensorId::parse("sensor:cam:alpha")?,
        seed: 111,
        packet_count: 2,
        packet_bytes: 32,
        start_ns: 10_000,
        period_ns: 1_000_000,
        uncertainty_ns: 1_000,
    };
    let cap_a = run_reference_capture(
        &spec_a,
        &DeliveryPlan::identity(spec_a.packet_count)?,
        &mut objects,
        &mut authority,
    )?;
    let model_a = MockModelSpec::new(
        "mock:cam:alpha:v1".to_string(),
        MockModelScript::Fixed {
            label: MockSemanticLabel::PersonLike,
            probability: ProbabilityInterval::new(0.99, 1.0)?,
        },
    )?;
    let res_a = execute_mock_model(&model_a, &cap_a, &mut objects)?;
    let obs_a = ReferenceModelObservation::new(
        res_a,
        "power:cam:alpha",
        CaptureInterval::new(TimestampNs(10_000), TimestampNs(20_000))?,
    )?;

    let spec_b = VirtualCameraSpec {
        capture_id: CapsuleId::parse("capture:cam:beta")?,
        sensor_id: SensorId::parse("sensor:cam:beta")?,
        seed: 222,
        packet_count: 2,
        packet_bytes: 32,
        start_ns: 10_000,
        period_ns: 1_000_000,
        uncertainty_ns: 1_000,
    };
    let cap_b = run_reference_capture(
        &spec_b,
        &DeliveryPlan::identity(spec_b.packet_count)?,
        &mut objects,
        &mut authority,
    )?;
    let model_b = MockModelSpec::new(
        "mock:cam:beta:v1".to_string(),
        MockModelScript::Fixed {
            label: MockSemanticLabel::PersonLike,
            probability: ProbabilityInterval::new(0.99, 1.0)?,
        },
    )?;
    let res_b = execute_mock_model(&model_b, &cap_b, &mut objects)?;
    let obs_b = ReferenceModelObservation::new(
        res_b,
        "power:cam:beta",
        CaptureInterval::new(TimestampNs(10_000), TimestampNs(20_000))?,
    )?;

    let decision = evaluate_unknown_presence(
        EventId::parse("event:unknown-presence:durable")?,
        vec![obs_a, obs_b],
    )?;
    assert_eq!(decision.action, ReferencePolicyAction::PrepareAlert);

    let event_receipt = publish_reference_event(&decision, &mut objects, &mut authority)?;

    let mut journal = EffectJournal::new();
    let plan = prepare_reference_alert(
        PrepareAlertParams {
            decision: &decision,
            event_receipt: &event_receipt,
            authority: &authority,
            operation_id: OperationId::parse("op:alert:durable:test")?,
            idempotency_key: IdempotencyKey::parse("idempotency:alert:durable:test")?,
            obligation_id: ObligationId::parse("obligation:alert:durable:test")?,
            channel: "security-sms".to_string(),
            now: TimestampNs(30_000),
        },
        &mut journal,
    )?;

    let durable_plan = {
        let mut durable = DurableEffectJournal::open(journal_path, IncompleteTailPolicy::Reject)?;
        let durable_plan = durable.prepare_alert(PrepareAlertParams {
            decision: &decision,
            event_receipt: &event_receipt,
            authority: &authority,
            operation_id: OperationId::parse("op:alert:durable:test")?,
            idempotency_key: IdempotencyKey::parse("idempotency:alert:durable:test")?,
            obligation_id: ObligationId::parse("obligation:alert:durable:test")?,
            channel: "security-sms".to_string(),
            now: TimestampNs(100),
        })?;
        let prepared = durable
            .operation(&durable_plan.intent.operation_id)
            .ok_or(ContractError::NotFound)?;
        assert_eq!(prepared.state, EffectState::Prepared);
        durable_plan
    };
    assert_eq!(durable_plan, plan);

    Ok((plan, journal, authority, objects))
}

struct AlertTestContext {
    decision: ReferencePolicyDecision,
    event_receipt: ReferenceEventReceipt,
    objects: InMemoryObjectStore,
    authority: DurableReferenceLedger,
}

fn setup_alert_context(ledger_path: &std::path::Path) -> Result<AlertTestContext, Box<dyn Error>> {
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut authority = DurableReferenceLedger::open(
        ledger_path,
        "site:durable_alert",
        IncompleteTailPolicy::Reject,
    )?;

    let spec_a = VirtualCameraSpec {
        capture_id: CapsuleId::parse("capture:cam:alpha")?,
        sensor_id: SensorId::parse("sensor:cam:alpha")?,
        seed: 111,
        packet_count: 2,
        packet_bytes: 32,
        start_ns: 10_000,
        period_ns: 1_000_000,
        uncertainty_ns: 1_000,
    };
    let cap_a = run_reference_capture(
        &spec_a,
        &DeliveryPlan::identity(spec_a.packet_count)?,
        &mut objects,
        &mut authority,
    )?;
    let model_a = MockModelSpec::new(
        "mock:cam:alpha:v1".to_string(),
        MockModelScript::Fixed {
            label: MockSemanticLabel::PersonLike,
            probability: ProbabilityInterval::new(0.99, 1.0)?,
        },
    )?;
    let res_a = execute_mock_model(&model_a, &cap_a, &mut objects)?;
    let obs_a = ReferenceModelObservation::new(
        res_a,
        "power:cam:alpha",
        CaptureInterval::new(TimestampNs(10_000), TimestampNs(20_000))?,
    )?;

    let spec_b = VirtualCameraSpec {
        capture_id: CapsuleId::parse("capture:cam:beta")?,
        sensor_id: SensorId::parse("sensor:cam:beta")?,
        seed: 222,
        packet_count: 2,
        packet_bytes: 32,
        start_ns: 10_000,
        period_ns: 1_000_000,
        uncertainty_ns: 1_000,
    };
    let cap_b = run_reference_capture(
        &spec_b,
        &DeliveryPlan::identity(spec_b.packet_count)?,
        &mut objects,
        &mut authority,
    )?;
    let model_b = MockModelSpec::new(
        "mock:cam:beta:v1".to_string(),
        MockModelScript::Fixed {
            label: MockSemanticLabel::PersonLike,
            probability: ProbabilityInterval::new(0.99, 1.0)?,
        },
    )?;
    let res_b = execute_mock_model(&model_b, &cap_b, &mut objects)?;
    let obs_b = ReferenceModelObservation::new(
        res_b,
        "power:cam:beta",
        CaptureInterval::new(TimestampNs(10_000), TimestampNs(20_000))?,
    )?;

    let decision = evaluate_unknown_presence(
        EventId::parse("event:unknown-presence:durable")?,
        vec![obs_a, obs_b],
    )?;
    assert_eq!(decision.action, ReferencePolicyAction::PrepareAlert);

    let event_receipt = publish_reference_event(&decision, &mut objects, &mut authority)?;

    Ok(AlertTestContext {
        decision,
        event_receipt,
        objects,
        authority,
    })
}

fn situation_request<'a>(
    decision: &'a ReferencePolicyDecision,
    receipt: &'a ReferenceEventReceipt,
    plan: Option<&'a ReferenceAlertPlan>,
) -> Result<ReferenceSituationRequest<'a>, Box<dyn Error>> {
    Ok(ReferenceSituationRequest {
        mission_id: MissionId::parse("mission:situation:inv111")?,
        session_id: SessionId::parse("session:situation:inv111")?,
        principal_id: PrincipalId::parse("principal:situation:inv111")?,
        objective_id: "objective:protect-reference-boundary".to_owned(),
        revision: 1,
        contract_basis: ContractBasis::from_registry_bytes(
            ContractBasisRegistryBytes::new(
                b"schemas",
                b"operations",
                b"views",
                b"capabilities",
                b"errors",
                b"costs",
                "fss-reference:test",
            )
            .with_accepted_nightly("nightly-2026-08-31"),
        ),
        previous_anchor: None,
        predecessor_publication: None,
        decision,
        event_receipt: receipt,
        alert_plan: plan,
        alert_outcome: None,
        coverage_witness: None,
        available_capabilities: [
            "capability:alert.prepare",
            "capability:alert.commit",
            CAPABILITY_EFFECT_RECONCILE,
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect(),
        created_at: TimestampNs(1_000),
    })
}

#[test]
fn test_positive_prepare_transition_reconcile_durably_replayed_identically()
-> Result<(), Box<dyn Error>> {
    let path = temp_journal("positive-replay");
    let _ = fs::remove_file(&path);

    let op1 = OperationId::parse("op:durable:test:1")?;
    let obl1 = ObligationId::parse("obligation:durable:test:1")?;
    let intent1 = sample_intent("op:durable:test:1", "idempotency:durable:test:1")?;

    let op2 = OperationId::parse("op:durable:test:2")?;
    let obl2 = ObligationId::parse("obligation:durable:test:2")?;
    let intent2 = sample_intent("op:durable:test:2", "idempotency:durable:test:2")?;

    let obs_proof = ContentDigest::sha256(b"independent_obs_proof");
    let fail_proof = intent2.failure_proof("network_unreachable");

    // Phase 1: Mutate durable journal
    let memory_before = {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;

        // Prepare op1 and advance to Verified
        let _ = journal.prepare(intent1, obl1.clone(), "delivery_ack", TimestampNs(100))?;
        let _ = journal.transition(&op1, EffectState::Committed, TimestampNs(110), None, None)?;
        let _ = journal.transition(
            &op1,
            EffectState::AdapterAccepted,
            TimestampNs(120),
            None,
            None,
        )?;
        let _ = journal.transition(
            &op1,
            EffectState::Observed,
            TimestampNs(130),
            Some(obs_proof),
            None,
        )?;
        let _ = journal.reconcile_verified(&op1, obs_proof, TimestampNs(140))?;

        // Prepare op2 and fail it via reconcile_failed
        let _ = journal.prepare(intent2, obl2.clone(), "delivery_ack", TimestampNs(150))?;
        let _ = journal.transition(&op2, EffectState::Committed, TimestampNs(160), None, None)?;
        let _ = journal.mark_indeterminate(&op2, TimestampNs(170), "timeout_waiting_ack")?;
        let _ =
            journal.reconcile_failed(&op2, fail_proof, TimestampNs(180), "network_unreachable")?;

        journal.effect_journal().clone()
    };

    // Phase 2: Reopen from disk and verify exact identity of EffectJournal
    let reopened = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
    assert_eq!(reopened.effect_journal(), &memory_before);

    // Verify individual operation states and obligation states
    let r1 = reopened.operation(&op1).ok_or(ContractError::NotFound)?;
    assert_eq!(r1.state, EffectState::Verified);
    assert_eq!(r1.result_digest, Some(obs_proof));

    let r2 = reopened.operation(&op2).ok_or(ContractError::NotFound)?;
    assert_eq!(r2.state, EffectState::Failed);
    assert_eq!(r2.result_digest, Some(fail_proof));
    assert_eq!(r2.error_code.as_deref(), Some("network_unreachable"));

    let o1 = reopened
        .obligations()
        .find(|o| o.obligation_id == obl1)
        .ok_or(ContractError::NotFound)?;
    assert_eq!(o1.state, ObligationState::Verified);
    assert_eq!(o1.proof_digest, Some(obs_proof));

    let o2 = reopened
        .obligations()
        .find(|o| o.obligation_id == obl2)
        .ok_or(ContractError::NotFound)?;
    assert_eq!(o2.state, ObligationState::Failed);
    assert_eq!(o2.proof_digest, Some(fail_proof));

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn test_planted_negative_lose_ack_reopen_refuses_second_commit_before_provider_touched()
-> Result<(), Box<dyn Error>> {
    let path = temp_journal("planted-lose-ack");
    let ledger_path = temp_journal("planted-lose-ack-ledger");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&ledger_path);

    let (plan, _init_journal, authority, objects) = setup_alert_plan(&path, &ledger_path)?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:durable:lose_ack");

    // Session 1: Prepare and dispatch with LoseAckAfterDelivery
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;

        let outcome = journal.dispatch_alert(
            &plan,
            &authority,
            &objects,
            ReferenceProviderBehavior::LoseAckAfterDelivery,
            AlertDispatchTimes::new(TimestampNs(110), TimestampNs(120)),
            &mut provider,
        )?;
        assert_eq!(outcome.state, EffectState::Indeterminate);
    }

    // Provider (surviving external oracle) recorded delivery:
    assert!(provider.lookup(&plan.intent)?.is_some());

    // Session 2: Process restart — reopen journal
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let current = journal
            .operation(&plan.intent.operation_id)
            .ok_or(ContractError::NotFound)?;
        assert_eq!(current.state, EffectState::Indeterminate);

        // Attempt second blind commit of the same intent:
        // Must be REFUSED before provider is touched!
        let commit_res = journal.dispatch_alert(
            &plan,
            &authority,
            &objects,
            ReferenceProviderBehavior::Deliver,
            AlertDispatchTimes::new(TimestampNs(200), TimestampNs(210)),
            &mut provider,
        );

        match commit_res {
            Err(DurableEffectError::Contract(ContractError::ReconciliationRequired)) => (),
            other => {
                return Err(format!(
                    "expected ReconciliationRequired before touching provider, got {other:?}"
                )
                .into());
            }
        }
    }

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(ledger_path);
    Ok(())
}

#[test]
fn test_planted_negative_reconciliation_after_reopen_closes_obligation_with_provider_proof()
-> Result<(), Box<dyn Error>> {
    let path = temp_journal("planted-reopen-reconcile");
    let ledger_path = temp_journal("planted-reopen-reconcile-ledger");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&ledger_path);

    let (plan, _, authority, objects) = setup_alert_plan(&path, &ledger_path)?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:durable:reopen");

    // Session 1: Prepare and dispatch with LoseAckAfterDelivery
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let outcome = journal.dispatch_alert(
            &plan,
            &authority,
            &objects,
            ReferenceProviderBehavior::LoseAckAfterDelivery,
            AlertDispatchTimes::new(TimestampNs(110), TimestampNs(120)),
            &mut provider,
        )?;
        assert_eq!(outcome.state, EffectState::Indeterminate);
    }

    // Session 2: Reopen journal and reconcile with provider evidence
    let expected_proof = provider
        .lookup(&plan.intent)?
        .ok_or(ReferenceError::InvalidSpec("missing_provider_receipt"))?
        .receipt_digest();

    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let reconciled = journal.reconcile_alert(&plan, TimestampNs(300), &provider)?;
        let receipt = reconciled.ok_or(ContractError::NotFound)?;
        assert_eq!(receipt.state, EffectState::Verified);
        assert_eq!(receipt.result_digest, Some(expected_proof));

        let obligation = journal
            .obligations()
            .find(|o| o.obligation_id == plan.obligation_id)
            .ok_or(ContractError::NotFound)?;
        assert_eq!(obligation.state, ObligationState::Verified);
        assert_eq!(obligation.proof_digest, Some(expected_proof));
    }

    // Session 3: Another restart to verify reconciliation persisted durably
    {
        let journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let receipt = journal
            .operation(&plan.intent.operation_id)
            .ok_or(ContractError::NotFound)?;
        assert_eq!(receipt.state, EffectState::Verified);
        assert_eq!(receipt.result_digest, Some(expected_proof));

        let obligation = journal
            .obligations()
            .find(|o| o.obligation_id == plan.obligation_id)
            .ok_or(ContractError::NotFound)?;
        assert_eq!(obligation.state, ObligationState::Verified);
        assert_eq!(obligation.proof_digest, Some(expected_proof));
    }

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(ledger_path);
    Ok(())
}

#[test]
fn test_planted_negative_torn_final_effect_record_is_incomplete_tail_and_prior_state_replays()
-> Result<(), Box<dyn Error>> {
    let path = temp_journal("planted-torn-tail");
    let _ = fs::remove_file(&path);

    let intent1 = sample_intent("op:torn:1", "key:torn:1")?;
    let obl1 = ObligationId::parse("obligation:torn:1")?;
    let op1 = intent1.operation_id.clone();

    // Session 1: Write a valid committed record
    let valid_memory = {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let _ = journal.prepare(intent1, obl1, "predicate_1", TimestampNs(100))?;
        journal.effect_journal().clone()
    };

    // Simulate crash tearing: append incomplete record header bytes (partial write)
    {
        let mut file = OpenOptions::new().append(true).open(&path)?;
        // Write incomplete 12 bytes (record magic + part of header, but truncated before trailer)
        file.write_all(b"FSSJRN01\x00\x01\x00\x00")?;
        file.sync_all()?;
    }

    // Session 2: Opening with IncompleteTailPolicy::Reject must return IncompleteTail error
    let reject_res = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject);
    assert!(matches!(
        reject_res,
        Err(DurableEffectError::Journal(
            JournalError::IncompleteTail { .. }
        ))
    ));

    // Session 3: Opening with IncompleteTailPolicy::Truncate must truncate torn tail and replay valid prefix
    let truncated_journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Truncate)?;
    assert_eq!(truncated_journal.effect_journal(), &valid_memory);
    assert!(truncated_journal.operation(&op1).is_some());

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn test_planted_negative_edited_record_chain_is_corrupt() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("planted-corrupt-chain");
    let _ = fs::remove_file(&path);

    let intent = sample_intent("op:corrupt:1", "key:corrupt:1")?;
    let obl = ObligationId::parse("obligation:corrupt:1")?;

    // Session 1: Write valid committed records
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let _ = journal.prepare(intent, obl, "predicate", TimestampNs(100))?;
    }

    // Tamper with record body: modify a byte within the record payload
    {
        let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;
        // Flip a byte in the payload area
        if content.len() > 64 {
            content[60] ^= 0xFF;
            file.seek(SeekFrom::Start(0))?;
            file.write_all(&content)?;
            file.sync_all()?;
        }
    }

    // Session 2: Opening journal must detect corruption and refuse
    let corrupt_res = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject);
    assert!(matches!(
        corrupt_res,
        Err(DurableEffectError::Journal(JournalError::Corrupt { .. }))
    ));

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn test_crash_after_commit_recovery_via_reconcile_failed() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("planted-crash-commit-fail");
    let ledger_path = temp_journal("planted-crash-commit-fail-ledger");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&ledger_path);

    let (plan, _, _, objects) = setup_alert_plan(&path, &ledger_path)?;
    let mut provider =
        ReferenceAlertProvider::with_provider_id("provider:test:durable:crash_commit_fail");

    // Provider recorded external failure
    let fail_receipt = provider.record_failure(&plan.intent, "carrier_gateway_timeout")?;

    // Session 1: Committed on disk
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let _ = journal.transition(
            &plan.intent.operation_id,
            EffectState::Committed,
            TimestampNs(110),
            None,
            None,
        )?;
    }

    // Session 2: System reboots; operator reconciles terminal failure
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let failed_receipt = journal.reconcile_failed_alert(
            &plan,
            fail_receipt.receipt_digest(),
            "carrier_gateway_timeout",
            TimestampNs(200),
            &provider,
        )?;
        assert_eq!(failed_receipt.state, EffectState::Failed);
        assert_eq!(
            failed_receipt.result_digest,
            Some(fail_receipt.receipt_digest())
        );

        let obligation = journal
            .obligations()
            .find(|o| o.obligation_id == plan.obligation_id)
            .ok_or(ContractError::NotFound)?;
        assert_eq!(obligation.state, ObligationState::Failed);
    }

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(ledger_path);
    Ok(())
}

#[test]
fn test_reconcile_alert_accepts_adapter_accepted_after_restart() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("planted-reconcile-accepted");
    let ledger_path = temp_journal("planted-reconcile-accepted-ledger");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&ledger_path);

    let (plan, _, authority, objects) = setup_alert_plan(&path, &ledger_path)?;
    let mut provider =
        ReferenceAlertProvider::with_provider_id("provider:test:durable:reconcile_accepted");

    // Session 1: Prepare and dispatch alert; provider accepts delivery
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let outcome = journal.dispatch_alert(
            &plan,
            &authority,
            &objects,
            ReferenceProviderBehavior::Deliver,
            AlertDispatchTimes::new(TimestampNs(110), TimestampNs(120)),
            &mut provider,
        )?;
        assert_eq!(outcome.state, EffectState::AdapterAccepted);
        // Crash occurs before observe_alert / verify_alert
    }

    // Surviving external provider recorded delivery receipt
    assert!(provider.lookup(&plan.intent)?.is_some());

    // Session 2: System reboots; operator runs reconciliation on open obligations
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let receipt = journal
            .operation(&plan.intent.operation_id)
            .ok_or(ContractError::NotFound)?;
        assert_eq!(receipt.state, EffectState::AdapterAccepted);

        // Attempt reconciliation via reconcile_alert:
        // Must observe provider receipt and reconcile to Verified.
        let reconciled = journal.reconcile_alert(&plan, TimestampNs(200), &provider)?;
        let receipt = reconciled.ok_or(ContractError::NotFound)?;
        assert_eq!(receipt.state, EffectState::Verified);

        let obligation = journal
            .obligations()
            .find(|o| o.obligation_id == plan.obligation_id)
            .ok_or(ContractError::NotFound)?;
        assert_eq!(obligation.state, ObligationState::Verified);
    }

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(ledger_path);
    Ok(())
}

#[test]
fn test_inv_111_crash_with_open_indeterminate_obligation_reopens_with_reconcile_affordance()
-> Result<(), Box<dyn Error>> {
    let path = temp_journal("inv111-indeterminate-crash");
    let ledger_path = temp_journal("inv111-indeterminate-crash-ledger");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&ledger_path);

    let mut ctx = setup_alert_context(&ledger_path)?;
    let mut provider =
        ReferenceAlertProvider::with_provider_id("provider:test:inv111:indeterminate");

    let plan;
    // Session 1: Prepare alert durably and dispatch with LostAck; simulates crash with open obligation
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        plan = journal.prepare_alert(PrepareAlertParams {
            decision: &ctx.decision,
            event_receipt: &ctx.event_receipt,
            authority: &ctx.authority,
            operation_id: OperationId::parse("op:alert:inv111:lostack")?,
            idempotency_key: IdempotencyKey::parse("idempotency:alert:inv111:lostack")?,
            obligation_id: ObligationId::parse("obligation:alert:inv111:lostack")?,
            channel: "security-sms".to_string(),
            now: TimestampNs(30_000),
        })?;

        // Before dispatch, obligation is Pending
        let obl = journal.acknowledge_obligation(&plan.obligation_id)?;
        assert_eq!(obl.state, ObligationState::Pending);

        let outcome = journal.dispatch_alert(
            &plan,
            &ctx.authority,
            &ctx.objects,
            ReferenceProviderBehavior::LoseAckAfterDelivery,
            AlertDispatchTimes::new(TimestampNs(31_000), TimestampNs(32_000)),
            &mut provider,
        )?;
        assert_eq!(outcome.state, EffectState::Indeterminate);

        let obl = journal.acknowledge_obligation(&plan.obligation_id)?;
        assert_eq!(obl.state, ObligationState::Indeterminate);
        // Process crashes here before reconciliation or publication!
    }

    // Session 2: System reboots; verify INV-111 continuity from durable journal
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let mut authority = DurableReferenceLedger::open(
            &ledger_path,
            "site:durable_alert",
            IncompleteTailPolicy::Reject,
        )?;

        // 1. Classification against ledger must report PendingLedger (durable on disk, unledgered)
        let state = journal.classify_obligation(&plan.obligation_id, &authority)?;
        match state {
            ObligationLedgerState::PendingLedger(pending) => {
                assert_eq!(pending.obligation.obligation_id, plan.obligation_id);
                assert_eq!(pending.obligation.state, ObligationState::Indeterminate);
                assert_eq!(pending.receipt.state, EffectState::Indeterminate);
            }
            other => {
                return Err(format!("expected PendingLedger, got {other:?}").into());
            }
        }

        // 2. Compile situation using durable journal projection
        let req = situation_request(&ctx.decision, &ctx.event_receipt, Some(&plan))?;
        let situation =
            compile_reference_situation_with_durable_journal(req, &journal, &authority)?;

        // Obligation risk and reconciliation necessity are explicitly projected
        assert!(
            situation
                .capsule
                .frame
                .at_risk
                .iter()
                .any(|r| r.contains("reconciled"))
        );

        // Reconcile affordance is exposed; commit affordance is NEVER exposed
        assert!(
            situation
                .capsule
                .affordances
                .iter()
                .all(|a| a.operation != "commit")
        );
        let reconcile_aff = situation
            .capsule
            .affordances
            .iter()
            .find(|a| a.affordance_id == EFFECT_RECONCILE_AFFORDANCE)
            .ok_or(ContractError::NotFound)?;
        assert_eq!(reconcile_aff.class, AffordanceClass::Probe);
        assert_eq!(
            reconcile_aff.target,
            format!(
                "fss://operation/{}/reconcile",
                plan.intent.operation_id.as_str()
            )
        );
        assert_eq!(
            situation.capsule.frame.next,
            vec![EFFECT_RECONCILE_AFFORDANCE.to_owned()]
        );
        assert_eq!(situation.capsule.completeness, Completeness::Partial);

        // 3. Seal handoff preserves situation root and child proof roots
        let handoff = seal_reference_handoff(
            &situation,
            HandoffId::parse("handoff:inv111:reboot")?,
            TimestampNs(40_000),
            TimestampNs(50_000),
        )?;
        assert_eq!(handoff.situation_capsule_root, situation.verify()?);
        let receipt = journal
            .operation(&plan.intent.operation_id)
            .ok_or(ContractError::NotFound)?;
        assert!(handoff.child_roots.contains(&receipt.receipt_digest()));

        // 4. Operator reconciles indeterminate alert with provider
        let reconciled = journal.reconcile_alert(&plan, TimestampNs(41_000), &provider)?;
        let receipt = reconciled.ok_or(ContractError::NotFound)?;
        assert_eq!(receipt.state, EffectState::Verified);
        let obl = journal.acknowledge_obligation(&plan.obligation_id)?;
        assert_eq!(obl.state, ObligationState::Verified);

        // 5. Durably publish outcome to canonical ledger
        let outcome_receipt =
            journal.publish_alert_outcome(&plan, &mut ctx.objects, &mut authority, &provider)?;
        assert_eq!(
            outcome_receipt.outcome.operation_receipt.state,
            EffectState::Verified
        );

        // 6. Classification now reports Ledgered
        let state = journal.classify_obligation(&plan.obligation_id, &authority)?;
        match state {
            ObligationLedgerState::Ledgered(ledgered) => {
                assert_eq!(ledgered.obligation.obligation_id, plan.obligation_id);
                assert_eq!(ledgered.receipt.state, EffectState::Verified);
                assert_eq!(ledgered.outcome_root, outcome_receipt.outcome_root);
            }
            other => {
                return Err(format!("expected Ledgered, got {other:?}").into());
            }
        }
    }

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(ledger_path);
    Ok(())
}

#[test]
fn test_inv_111_planted_negative_transient_only_obligation_rejected() -> Result<(), Box<dyn Error>>
{
    let path = temp_journal("inv111-transient-rejected");
    let ledger_path = temp_journal("inv111-transient-rejected-ledger");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&ledger_path);

    let mut ctx = setup_alert_context(&ledger_path)?;
    let provider = ReferenceAlertProvider::with_provider_id("provider:test:inv111:transient");

    // Construct a transient-only plan (never persisted in DurableEffectJournal)
    let mut transient_journal = EffectJournal::new();
    let transient_plan = prepare_reference_alert(
        PrepareAlertParams {
            decision: &ctx.decision,
            event_receipt: &ctx.event_receipt,
            authority: &ctx.authority,
            operation_id: OperationId::parse("op:alert:inv111:transient")?,
            idempotency_key: IdempotencyKey::parse("idempotency:alert:inv111:transient")?,
            obligation_id: ObligationId::parse("obligation:alert:inv111:transient")?,
            channel: "security-sms".to_string(),
            now: TimestampNs(30_000),
        },
        &mut transient_journal,
    )?;

    // Open a fresh DurableEffectJournal that does not contain this transient obligation
    let journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;

    // 1. acknowledge_obligation must fail with TransientObligation
    let ack_err = journal.acknowledge_obligation(&transient_plan.obligation_id);
    match ack_err {
        Err(DurableEffectError::TransientObligation { obligation_id }) => {
            assert_eq!(obligation_id, transient_plan.obligation_id);
        }
        other => {
            return Err(format!("expected TransientObligation error, got {other:?}").into());
        }
    }

    // 2. compile_reference_situation_with_durable_journal must reject transient obligation
    let req = situation_request(&ctx.decision, &ctx.event_receipt, Some(&transient_plan))?;
    let compile_err =
        compile_reference_situation_with_durable_journal(req, &journal, &ctx.authority);
    match compile_err {
        Err(ReferenceError::InvalidSpec("transient_obligation_rejected")) => {}
        other => {
            return Err(format!("expected transient_obligation_rejected, got {other:?}").into());
        }
    }

    // 3. publish_alert_outcome must reject transient obligation
    let pub_err = journal.publish_alert_outcome(
        &transient_plan,
        &mut ctx.objects,
        &mut ctx.authority,
        &provider,
    );
    match pub_err {
        Err(DurableEffectError::TransientObligation { obligation_id }) => {
            assert_eq!(obligation_id, transient_plan.obligation_id);
        }
        other => {
            return Err(format!("expected TransientObligation error, got {other:?}").into());
        }
    }

    // 4. classify_obligation reports Absent
    let state = journal.classify_obligation(&transient_plan.obligation_id, &ctx.authority)?;
    assert_eq!(state, ObligationLedgerState::Absent);

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(ledger_path);
    Ok(())
}

#[test]
fn test_inv_111_obligation_classification_states() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("inv111-classification-states");
    let ledger_path = temp_journal("inv111-classification-states-ledger");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&ledger_path);

    let mut ctx = setup_alert_context(&ledger_path)?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:inv111:classify");
    let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;

    // 1. Absent: unknown obligation ID
    let absent_id = ObligationId::parse("obligation:unknown:none")?;
    let absent_op = OperationId::parse("op:unknown:none")?;
    assert_eq!(
        journal.classify_obligation(&absent_id, &ctx.authority)?,
        ObligationLedgerState::Absent
    );
    assert_eq!(
        journal.classify_operation(&absent_op, &ctx.authority)?,
        ObligationLedgerState::Absent
    );

    // 2. InFlight: prepared in journal, but unledgered and non-terminal
    let plan = journal.prepare_alert(PrepareAlertParams {
        decision: &ctx.decision,
        event_receipt: &ctx.event_receipt,
        authority: &ctx.authority,
        operation_id: OperationId::parse("op:alert:inv111:classify")?,
        idempotency_key: IdempotencyKey::parse("idempotency:alert:inv111:classify")?,
        obligation_id: ObligationId::parse("obligation:alert:inv111:classify")?,
        channel: "security-sms".to_string(),
        now: TimestampNs(30_000),
    })?;
    let state = journal.classify_obligation(&plan.obligation_id, &ctx.authority)?;
    match state {
        ObligationLedgerState::InFlight {
            obligation,
            receipt,
        } => {
            assert_eq!(obligation.obligation_id, plan.obligation_id);
            assert_eq!(obligation.state, ObligationState::Pending);
            assert_eq!(receipt.state, EffectState::Prepared);
        }
        other => {
            return Err(format!("expected InFlight, got {other:?}").into());
        }
    }

    // 3. Dispatch and reconcile to Verified
    let _ = journal.dispatch_alert(
        &plan,
        &ctx.authority,
        &ctx.objects,
        ReferenceProviderBehavior::Deliver,
        AlertDispatchTimes::new(TimestampNs(31_000), TimestampNs(32_000)),
        &mut provider,
    )?;
    let _ = journal.reconcile_alert(&plan, TimestampNs(33_000), &provider)?;

    // Still PendingLedger until published to canonical ledger
    match journal.classify_obligation(&plan.obligation_id, &ctx.authority)? {
        ObligationLedgerState::PendingLedger(pending) => {
            assert_eq!(pending.obligation.state, ObligationState::Verified);
        }
        other => {
            return Err(format!("expected PendingLedger, got {other:?}").into());
        }
    }

    // 4. Publish outcome to ledger -> Ledgered
    let outcome_receipt =
        journal.publish_alert_outcome(&plan, &mut ctx.objects, &mut ctx.authority, &provider)?;
    match journal.classify_obligation(&plan.obligation_id, &ctx.authority)? {
        ObligationLedgerState::Ledgered(ledgered) => {
            assert_eq!(ledgered.obligation.obligation_id, plan.obligation_id);
            assert_eq!(ledgered.outcome_root, outcome_receipt.outcome_root);
        }
        other => {
            return Err(format!("expected Ledgered, got {other:?}").into());
        }
    }
    match journal.classify_operation(&plan.intent.operation_id, &ctx.authority)? {
        ObligationLedgerState::Ledgered(ledgered) => {
            assert_eq!(ledgered.obligation.obligation_id, plan.obligation_id);
        }
        other => {
            return Err(format!("expected Ledgered, got {other:?}").into());
        }
    }

    // 5. UnbackedLedgerClaim: when an operation exists in the ledger but is not in the journal
    let unbacked_op = plan.intent.operation_id.clone();
    let empty_path = temp_journal("inv111-empty");
    let _ = fs::remove_file(&empty_path);
    let empty_journal = DurableEffectJournal::open(&empty_path, IncompleteTailPolicy::Reject)?;
    match empty_journal.classify_operation(&unbacked_op, &ctx.authority)? {
        ObligationLedgerState::UnbackedLedgerClaim {
            operation_id,
            ledgered_root,
        } => {
            assert_eq!(operation_id, unbacked_op);
            assert_eq!(ledgered_root, outcome_receipt.outcome_root);
        }
        other => {
            return Err(format!("expected UnbackedLedgerClaim, got {other:?}").into());
        }
    }

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(empty_path);
    Ok(())
}

#[test]
fn test_finding_f2_classify_obligation_fails_closed_on_unreconciled_ledger_append()
-> Result<(), Box<dyn Error>> {
    let path = temp_journal("finding-pending-ledger-append");
    let ledger_path = temp_journal("finding-pending-ledger-append-ledger");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&ledger_path);

    let mut ctx = setup_alert_context(&ledger_path)?;
    let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;

    let plan = journal.prepare_alert(PrepareAlertParams {
        decision: &ctx.decision,
        event_receipt: &ctx.event_receipt,
        authority: &ctx.authority,
        operation_id: OperationId::parse("op:alert:finding:pending_append")?,
        idempotency_key: IdempotencyKey::parse("idempotency:alert:finding:pending_append")?,
        obligation_id: ObligationId::parse("obligation:alert:finding:pending_append")?,
        channel: "security-sms".to_string(),
        now: TimestampNs(30_000),
    })?;

    // Simulate unreconciled pending append in ledger
    let delta = EvidenceDelta {
        delta_id: "delta:test:pending:classify".to_owned(),
        family: "sensor_capsule".to_owned(),
        object_id: ObjectId::parse("object:camera:pending_test")?,
        prior_generation: None,
        new_generation: 1,
        validity: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
        plane: Plane::Authority,
        payload_digest: ContentDigest::sha256(b"payload"),
        witness_digest: Some(ContentDigest::sha256(b"witness")),
        operation_id: None,
    };
    let batch = ctx.authority.prepare_batch(
        BatchId::parse("batch:pending:classify:test")?,
        vec![delta],
        [ContentDigest::sha256(b"child")],
    )?;
    ctx.authority
        .fail_journal_after_phase(AppendPhase::CommitSync);
    let _ = ctx.authority.append(batch);
    let expected_sequence = ctx
        .authority
        .pending_append_sequence()
        .ok_or("missing pending append sequence")?;

    let classify_res = journal.classify_obligation(&plan.obligation_id, &ctx.authority);
    match classify_res {
        Err(DurableEffectError::LedgerReconciliationRequired { sequence })
            if sequence == expected_sequence =>
        {
            // Correct behavior
        }
        Ok(state) => {
            return Err(format!(
                "CRITICAL: classify_obligation ignored pending append in ledger and returned {:?}",
                state
            )
            .into());
        }
        Err(other) => return Err(format!("unexpected error: {:?}", other).into()),
    }

    let classify_op_res = journal.classify_operation(&plan.intent.operation_id, &ctx.authority);
    match classify_op_res {
        Err(DurableEffectError::LedgerReconciliationRequired { sequence })
            if sequence == expected_sequence =>
        {
            // Correct behavior
        }
        Ok(state) => {
            return Err(format!(
                "CRITICAL: classify_operation ignored pending append in ledger and returned {:?}",
                state
            )
            .into());
        }
        Err(other) => return Err(format!("unexpected error: {:?}", other).into()),
    }

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(ledger_path);
    Ok(())
}

#[test]
fn test_finding_f3_classify_obligation_rejects_prepared_as_pending_ledger()
-> Result<(), Box<dyn Error>> {
    let path = temp_journal("finding-prepared-pending-ledger");
    let ledger_path = temp_journal("finding-prepared-pending-ledger-ledger");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&ledger_path);

    let ctx = setup_alert_context(&ledger_path)?;
    let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;

    let plan = journal.prepare_alert(PrepareAlertParams {
        decision: &ctx.decision,
        event_receipt: &ctx.event_receipt,
        authority: &ctx.authority,
        operation_id: OperationId::parse("op:alert:finding:in_flight")?,
        idempotency_key: IdempotencyKey::parse("idempotency:alert:finding:in_flight")?,
        obligation_id: ObligationId::parse("obligation:alert:finding:in_flight")?,
        channel: "security-sms".to_string(),
        now: TimestampNs(30_000),
    })?;

    // 1. Prepared must be classified as InFlight, NOT PendingLedger
    let state = journal.classify_obligation(&plan.obligation_id, &ctx.authority)?;
    match state {
        ObligationLedgerState::InFlight {
            obligation,
            receipt,
        } => {
            assert_eq!(obligation.obligation_id, plan.obligation_id);
            assert_eq!(obligation.state, ObligationState::Pending);
            assert_eq!(receipt.state, EffectState::Prepared);
        }
        ObligationLedgerState::PendingLedger(_) => {
            return Err("DEFECT: Prepared obligation was classified as PendingLedger even though publish_alert_outcome rejects it as alert_outcome_not_publishable!".into());
        }
        other => return Err(format!("unexpected state: {:?}", other).into()),
    }

    // 2. Committed must also be InFlight
    let _ = journal.transition(
        &plan.intent.operation_id,
        EffectState::Committed,
        TimestampNs(31_000),
        None,
        None,
    )?;
    let state_committed = journal.classify_obligation(&plan.obligation_id, &ctx.authority)?;
    match state_committed {
        ObligationLedgerState::InFlight { receipt, .. } => {
            assert_eq!(receipt.state, EffectState::Committed);
        }
        other => return Err(format!("expected InFlight for Committed, got {:?}", other).into()),
    }

    // 3. Indeterminate is terminal and publishable, so it CAN be PendingLedger
    let _ = journal.mark_indeterminate(
        &plan.intent.operation_id,
        TimestampNs(32_000),
        "test_timeout",
    )?;
    let state_indet = journal.classify_obligation(&plan.obligation_id, &ctx.authority)?;
    match state_indet {
        ObligationLedgerState::PendingLedger(pending) => {
            assert_eq!(pending.obligation.state, ObligationState::Indeterminate);
            assert_eq!(pending.receipt.state, EffectState::Indeterminate);
        }
        other => {
            return Err(
                format!("expected PendingLedger for Indeterminate, got {:?}", other).into(),
            );
        }
    }

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(ledger_path);
    Ok(())
}

#[test]
fn test_finding_f4_reconcile_alert_must_not_drop_provider_failure() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("finding-reconcile-drop-failure");
    let ledger_path = temp_journal("finding-reconcile-drop-failure-ledger");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&ledger_path);

    let (plan, _, _, objects) = setup_alert_plan(&path, &ledger_path)?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:finding:fail_drop");

    // Session 1: Indeterminate with terminal provider failure
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let _ = journal.transition(
            &plan.intent.operation_id,
            EffectState::Committed,
            TimestampNs(110),
            None,
            None,
        )?;
        let _ = journal.mark_indeterminate(
            &plan.intent.operation_id,
            TimestampNs(120),
            "provider_timeout",
        )?;
        let _ = provider.record_failure(&plan.intent, "carrier_rejected")?;
    }

    // Session 2: System reboots; operator reconciles indeterminate alert
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let reconciled = journal.reconcile_alert(&plan, TimestampNs(200), &provider)?;
        let receipt = reconciled.ok_or("DEFECT: reconcile_alert silently returned Ok(None) when provider had a recorded failure!")?;
        assert_eq!(receipt.state, EffectState::Failed);
        assert_eq!(receipt.error_code, Some("carrier_rejected".to_string()));

        let obl = journal
            .obligation(&plan.obligation_id)
            .ok_or(ContractError::NotFound)?;
        assert_eq!(obl.state, ObligationState::Failed);
    }

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(ledger_path);
    Ok(())
}

#[test]
fn test_finding_f5_reopen_from_disk_with_reopened_authority_ledger() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("finding-reopen-authority");
    let ledger_path = temp_journal("finding-reopen-authority-ledger");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&ledger_path);

    let plan;
    {
        let ctx = setup_alert_context(&ledger_path)?;
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        plan = journal.prepare_alert(PrepareAlertParams {
            decision: &ctx.decision,
            event_receipt: &ctx.event_receipt,
            authority: &ctx.authority,
            operation_id: OperationId::parse("op:alert:finding:reboot")?,
            idempotency_key: IdempotencyKey::parse("idempotency:alert:finding:reboot")?,
            obligation_id: ObligationId::parse("obligation:alert:finding:reboot")?,
            channel: "security-sms".to_string(),
            now: TimestampNs(30_000),
        })?;
    }

    // Session 2: Reopen both files from disk
    {
        let journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let authority = DurableReferenceLedger::open(
            &ledger_path,
            "site:durable_alert",
            IncompleteTailPolicy::Reject,
        )?;

        let state = journal.classify_obligation(&plan.obligation_id, &authority)?;
        match state {
            ObligationLedgerState::InFlight {
                obligation,
                receipt,
            } => {
                assert_eq!(obligation.obligation_id, plan.obligation_id);
                assert_eq!(obligation.state, ObligationState::Pending);
                assert_eq!(receipt.state, EffectState::Prepared);
            }
            other => {
                return Err(format!("expected InFlight on true reboot, got {:?}", other).into());
            }
        }
    }

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(ledger_path);
    Ok(())
}

#[test]
fn test_finding_f6_delta_payload_mismatch_fails_closed_to_ledger_conflict()
-> Result<(), Box<dyn Error>> {
    let path = temp_journal("finding-f6-conflict");
    let ledger_path = temp_journal("finding-f6-conflict-ledger");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&ledger_path);

    let mut ctx = setup_alert_context(&ledger_path)?;
    let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:finding:f6");

    let plan = journal.prepare_alert(PrepareAlertParams {
        decision: &ctx.decision,
        event_receipt: &ctx.event_receipt,
        authority: &ctx.authority,
        operation_id: OperationId::parse("op:alert:finding:f6")?,
        idempotency_key: IdempotencyKey::parse("idempotency:alert:finding:f6")?,
        obligation_id: ObligationId::parse("obligation:alert:finding:f6")?,
        channel: "security-sms".to_string(),
        now: TimestampNs(30_000),
    })?;
    let _ = journal.dispatch_alert(
        &plan,
        &ctx.authority,
        &ctx.objects,
        ReferenceProviderBehavior::Deliver,
        AlertDispatchTimes::new(TimestampNs(31_000), TimestampNs(32_000)),
        &mut provider,
    )?;
    let _ = journal.reconcile_alert(&plan, TimestampNs(33_000), &provider)?;
    let _outcome_receipt =
        journal.publish_alert_outcome(&plan, &mut ctx.objects, &mut ctx.authority, &provider)?;

    // Tamper with delta payload in ledger by creating a batch with mismatched payload digest
    let effect_object_id = ObjectId::parse(format!(
        "object:effect:{}",
        plan.intent.operation_id.as_str()
    ))?;
    let delta = EvidenceDelta {
        delta_id: "delta:test:tampered".to_owned(),
        family: "alert_effect_outcome".to_owned(),
        object_id: effect_object_id,
        prior_generation: Some(1),
        new_generation: 2,
        validity: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
        plane: Plane::Effect,
        payload_digest: ContentDigest::sha256(b"corrupted_payload_digest"),
        witness_digest: Some(ContentDigest::sha256(b"wrong_witness")),
        operation_id: Some(plan.intent.operation_id.clone()),
    };
    let batch = ctx.authority.prepare_batch(
        BatchId::parse("batch:tampered:f6")?,
        vec![delta],
        [ContentDigest::sha256(b"child")],
    )?;
    ctx.authority.append(batch)?;

    // Classify obligation must fail closed to LedgerConflict, NOT default to passing equality
    let state = journal.classify_obligation(&plan.obligation_id, &ctx.authority)?;
    match state {
        ObligationLedgerState::LedgerConflict { obligation_id, .. } => {
            assert_eq!(obligation_id, plan.obligation_id);
        }
        other => return Err(format!("expected LedgerConflict, got {:?}", other).into()),
    }

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(ledger_path);
    Ok(())
}

#[test]
fn test_finding_f7_situation_guard_rejects_transient_and_mismatched_obligation()
-> Result<(), Box<dyn Error>> {
    let path = temp_journal("finding-f7-guard");
    let ledger_path = temp_journal("finding-f7-guard-ledger");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&ledger_path);

    let mut ctx = setup_alert_context(&ledger_path)?;
    let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
    let provider = ReferenceAlertProvider::with_provider_id("provider:test:finding:f7");

    let valid_plan = journal.prepare_alert(PrepareAlertParams {
        decision: &ctx.decision,
        event_receipt: &ctx.event_receipt,
        authority: &ctx.authority,
        operation_id: OperationId::parse("op:alert:finding:f7:valid")?,
        idempotency_key: IdempotencyKey::parse("idempotency:alert:finding:f7:valid")?,
        obligation_id: ObligationId::parse("obligation:alert:finding:f7:valid")?,
        channel: "security-sms".to_string(),
        now: TimestampNs(30_000),
    })?;

    // 1. Mismatched obligation ID vs operation ID in alert_plan
    let mut mismatched_plan = valid_plan.clone();
    mismatched_plan.intent.operation_id = OperationId::parse("op:alert:finding:f7:other")?;
    let req1 = situation_request(&ctx.decision, &ctx.event_receipt, Some(&mismatched_plan))?;
    let err1 = compile_reference_situation_with_durable_journal(req1, &journal, &ctx.authority);
    assert!(matches!(
        err1,
        Err(ReferenceError::InvalidSpec("obligation_operation_mismatch"))
    ));

    // 2. Alert outcome provided with alert_plan = None, but outcome was NEVER in durable journal
    let mut transient_journal = EffectJournal::new();
    let transient_plan = prepare_reference_alert(
        PrepareAlertParams {
            decision: &ctx.decision,
            event_receipt: &ctx.event_receipt,
            authority: &ctx.authority,
            operation_id: OperationId::parse("op:alert:finding:f7:transient")?,
            idempotency_key: IdempotencyKey::parse("idempotency:alert:finding:f7:transient")?,
            obligation_id: ObligationId::parse("obligation:alert:finding:f7:transient")?,
            channel: "security-sms".to_string(),
            now: TimestampNs(30_000),
        },
        &mut transient_journal,
    )?;
    let _ = transient_journal.transition(
        &transient_plan.intent.operation_id,
        EffectState::Committed,
        TimestampNs(31_000),
        None,
        None,
    )?;
    let _ = transient_journal.mark_indeterminate(
        &transient_plan.intent.operation_id,
        TimestampNs(32_000),
        "transient_indeterminate",
    )?;
    let transient_outcome = fss_reference::publish_reference_alert_outcome(
        &transient_plan,
        &transient_journal,
        &mut ctx.objects,
        &mut ctx.authority,
        &provider,
    )?;

    // Passing transient outcome with alert_plan: None must be rejected by durable journal guard
    let mut req2 = situation_request(&ctx.decision, &ctx.event_receipt, None)?;
    req2.alert_outcome = Some(&transient_outcome);
    let err2 = compile_reference_situation_with_durable_journal(req2, &journal, &ctx.authority);
    assert!(matches!(
        err2,
        Err(ReferenceError::InvalidSpec("transient_obligation_rejected"))
    ));

    // 3. Mismatched obligation ID vs operation ID in alert_outcome
    let mut mismatched_outcome = transient_outcome.clone();
    mismatched_outcome.outcome.obligation_id =
        ObligationId::parse("obligation:alert:finding:f7:mismatch")?;
    let mut req3 = situation_request(&ctx.decision, &ctx.event_receipt, None)?;
    req3.alert_outcome = Some(&mismatched_outcome);
    let err3 = compile_reference_situation_with_durable_journal(req3, &journal, &ctx.authority);
    assert!(matches!(
        err3,
        Err(ReferenceError::InvalidSpec("transient_obligation_rejected"))
            | Err(ReferenceError::InvalidSpec("obligation_operation_mismatch"))
    ));

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(ledger_path);
    Ok(())
}

/// Delivers `plan` through the sealed public dispatch path using a throwaway in-memory journal.
///
/// This models a process that reached the provider and then crashed: the external provider keeps
/// its delivery message, while the in-memory journal holding `AdapterAccepted` is lost with the
/// process. The durable journal under test never observes that acceptance.
fn deliver_then_lose_process_journal(
    plan: &ReferenceAlertPlan,
    authority: &DurableReferenceLedger,
    objects: &InMemoryObjectStore,
    crashed_process_journal: &mut EffectJournal,
    provider: &mut ReferenceAlertProvider,
) -> Result<(), Box<dyn Error>> {
    let lost_outcome = dispatch_reference_alert(
        plan,
        authority,
        &objects,
        ReferenceProviderBehavior::Deliver,
        AlertDispatchTimes::new(TimestampNs(30_100), TimestampNs(30_200)),
        crashed_process_journal,
        provider,
    )?;
    assert_eq!(lost_outcome.state, EffectState::AdapterAccepted);
    assert_eq!(provider.message_count(), 1);
    Ok(())
}

#[test]
fn test_crash_after_commit_recovery_via_reconcile() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("planted-crash-commit-reconcile");
    let ledger_path = temp_journal("planted-crash-commit-reconcile-ledger");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&ledger_path);

    let (plan, mut crashed_process_journal, authority, objects) =
        setup_alert_plan(&path, &ledger_path)?;
    let mut provider =
        ReferenceAlertProvider::with_provider_id("provider:test:durable:crash_commit_reconcile");

    // Provider external dispatch succeeded, but crash occurred before journal recorded AdapterAccepted
    deliver_then_lose_process_journal(
        &plan,
        &authority,
        &objects,
        &mut crashed_process_journal,
        &mut provider,
    )?;
    let provider_proof = provider
        .lookup(&plan.intent)?
        .ok_or("missing provider receipt")?
        .receipt_digest();

    // Session 1: Committed on disk
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let _ = journal.transition(
            &plan.intent.operation_id,
            EffectState::Committed,
            TimestampNs(110),
            None,
            None,
        )?;
    }

    // Session 2: System reboots; operator runs reconciliation on open obligations
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let reconciled = journal.reconcile_alert(&plan, TimestampNs(200), &provider)?;
        let receipt = reconciled.ok_or(ContractError::NotFound)?;
        assert_eq!(receipt.state, EffectState::Verified);
        assert_eq!(receipt.result_digest, Some(provider_proof));

        let obligation = journal
            .obligations()
            .find(|o| o.obligation_id == plan.obligation_id)
            .ok_or(ContractError::NotFound)?;
        assert_eq!(obligation.state, ObligationState::Verified);
        // Reconciliation reads provider state; it never resends.
        assert_eq!(provider.message_count(), 1);
    }

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(ledger_path);
    Ok(())
}

#[test]
fn test_crash_after_commit_recovery_via_redispatch() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("planted-crash-commit-redispatch");
    let ledger_path = temp_journal("planted-crash-commit-redispatch-ledger");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&ledger_path);

    let (plan, mut crashed_process_journal, setup_authority, setup_objects) =
        setup_alert_plan(&path, &ledger_path)?;
    let mut provider =
        ReferenceAlertProvider::with_provider_id("provider:test:durable:crash_commit_redispatch");

    // Session 1: Prepare and commit effect to durable journal, then simulate crash
    // immediately between Step 1 (commit) and Step 2 (provider dispatch).
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let prep_receipt = journal
            .operation(&plan.intent.operation_id)
            .ok_or(ContractError::NotFound)?;
        assert_eq!(prep_receipt.state, EffectState::Prepared);

        let commit_receipt = journal.transition(
            &plan.intent.operation_id,
            EffectState::Committed,
            TimestampNs(110),
            None,
            None,
        )?;
        assert_eq!(commit_receipt.state, EffectState::Committed);
        // Process crash occurs here: external provider dispatch executed, but crash happened before
        // journal recorded adapter acceptance or completion. State remains Committed on disk.
        deliver_then_lose_process_journal(
            &plan,
            &setup_authority,
            &setup_objects,
            &mut crashed_process_journal,
            &mut provider,
        )?;
    }

    // Session 2: System reboots; journal is replayed from disk.
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let authority = DurableReferenceLedger::open(
            &ledger_path,
            "site:durable_alert",
            IncompleteTailPolicy::Reject,
        )?;
        let receipt = journal
            .operation(&plan.intent.operation_id)
            .ok_or(ContractError::NotFound)?;
        assert_eq!(receipt.state, EffectState::Committed);

        // Recovery: Re-dispatching MUST be refused with ReconciliationRequired to prevent duplicate external effect!
        let redispatch_res = journal.dispatch_alert(
            &plan,
            &authority,
            &setup_objects,
            ReferenceProviderBehavior::Deliver,
            AlertDispatchTimes::new(TimestampNs(200), TimestampNs(210)),
            &mut provider,
        );
        assert!(matches!(
            redispatch_res,
            Err(DurableEffectError::Contract(
                ContractError::ReconciliationRequired
            ))
        ));
        // The refused redispatch never reached the provider.
        assert_eq!(provider.message_count(), 1);

        // Reconcile alert with provider evidence instead of re-sending:
        let provider_proof = provider
            .lookup(&plan.intent)?
            .ok_or("missing provider receipt")?
            .receipt_digest();
        let reconciled_receipt = journal
            .reconcile_alert(&plan, TimestampNs(215), &provider)?
            .ok_or("reconciliation failed")?;
        assert_eq!(reconciled_receipt.state, EffectState::Verified);
        assert_eq!(reconciled_receipt.result_digest, Some(provider_proof));

        let obligation = journal
            .obligations()
            .find(|o| o.obligation_id == plan.obligation_id)
            .ok_or(ContractError::NotFound)?;
        assert_eq!(obligation.state, ObligationState::Verified);

        // Obligation is now verified and classified as PendingLedger
        match journal.classify_obligation(&plan.obligation_id, &authority)? {
            ObligationLedgerState::PendingLedger(pending) => {
                assert_eq!(pending.obligation.obligation_id, plan.obligation_id);
                assert_eq!(pending.obligation.state, ObligationState::Verified);
            }
            other => return Err(format!("expected PendingLedger, got {other:?}").into()),
        }
    }

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(ledger_path);
    Ok(())
}

#[test]
fn test_finding_f1_crash_after_commit_blind_duplicate_redispatch_fails()
-> Result<(), Box<dyn Error>> {
    let path = temp_journal("finding-crash-redispatch");
    let ledger_path = temp_journal("finding-crash-redispatch-ledger");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&ledger_path);

    let (plan, mut crashed_process_journal, authority, objects) =
        setup_alert_plan(&path, &ledger_path)?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:finding:redispatch");

    // Session 1: Committed on disk; external dispatch occurred before crash
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let _ = journal.transition(
            &plan.intent.operation_id,
            EffectState::Committed,
            TimestampNs(110),
            None,
            None,
        )?;
        deliver_then_lose_process_journal(
            &plan,
            &authority,
            &objects,
            &mut crashed_process_journal,
            &mut provider,
        )?;
    }

    // Session 2: System reboots; journal is in Committed state.
    // Calling dispatch_alert MUST NOT blindly redispatch to the provider!
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let redispatch_res = journal.dispatch_alert(
            &plan,
            &authority,
            &objects,
            ReferenceProviderBehavior::Deliver,
            AlertDispatchTimes::new(TimestampNs(200), TimestampNs(210)),
            &mut provider,
        );

        match redispatch_res {
            Err(DurableEffectError::Contract(ContractError::ReconciliationRequired)) => {
                // Correct behavior: fails closed to prevent duplicate physical/external effect
            }
            Ok(_) => {
                return Err("CRITICAL: dispatch_alert allowed blind duplicate provider dispatch on Committed state!".into());
            }
            Err(other) => return Err(format!("unexpected error: {:?}", other).into()),
        }
        // No duplicate provider message was created.
        assert_eq!(provider.message_count(), 1);

        // Reconcile alert instead of re-dispatching
        let reconciled = journal.reconcile_alert(&plan, TimestampNs(220), &provider)?;
        let receipt = reconciled.ok_or(ContractError::NotFound)?;
        assert_eq!(receipt.state, EffectState::Verified);
    }

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(ledger_path);
    Ok(())
}

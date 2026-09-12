#![forbid(unsafe_code)]
//! Integration contract tests for DurableEffectJournal restart durability and crash invariants (fss-x4a.16.13).

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

use fss_core::{
    CapsuleId, CaptureInterval, ContentDigest, ContractError, EffectIntent, EffectJournal,
    EffectState, EventId, IdempotencyKey, ObligationId, ObligationState, OperationId,
    ProbabilityInterval, SensorId, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy, JournalError};
use fss_object::{InMemoryObjectStore, ObjectLimits};
use fss_reference::{
    DeliveryPlan, DurableEffectError, DurableEffectJournal, MockModelScript, MockModelSpec,
    MockSemanticLabel, PrepareAlertParams, ReferenceAlertPlan, ReferenceAlertProvider,
    ReferenceError, ReferenceModelObservation, ReferencePolicyAction, ReferenceProviderBehavior,
    VirtualCameraSpec, evaluate_unknown_presence, execute_mock_model, prepare_reference_alert,
    publish_reference_event, run_reference_capture,
};

fn temp_journal(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "fss-durable-effect-contract-{}-{name}.journal",
        std::process::id()
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

fn setup_alert_plan(
    ledger_path: &std::path::Path,
) -> Result<(ReferenceAlertPlan, EffectJournal), Box<dyn Error>> {
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

    Ok((plan, journal))
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

    let (plan, _init_journal) = setup_alert_plan(&ledger_path)?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:durable:lose_ack");

    // Session 1: Prepare and dispatch with LoseAckAfterDelivery
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let _ = journal.prepare(
            plan.intent.clone(),
            plan.obligation_id.clone(),
            "delivery_acknowledged_by_provider",
            TimestampNs(100),
        )?;

        let outcome = journal.dispatch_alert(
            &plan,
            ReferenceProviderBehavior::LoseAckAfterDelivery,
            TimestampNs(110),
            TimestampNs(120),
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
            ReferenceProviderBehavior::Deliver,
            TimestampNs(200),
            TimestampNs(210),
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

    let (plan, _) = setup_alert_plan(&ledger_path)?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:durable:reopen");

    // Session 1: Prepare and dispatch with LoseAckAfterDelivery
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let _ = journal.prepare(
            plan.intent.clone(),
            plan.obligation_id.clone(),
            "delivery_acknowledged_by_provider",
            TimestampNs(100),
        )?;
        let outcome = journal.dispatch_alert(
            &plan,
            ReferenceProviderBehavior::LoseAckAfterDelivery,
            TimestampNs(110),
            TimestampNs(120),
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
fn test_crash_after_commit_recovery_via_redispatch() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("planted-crash-commit-redispatch");
    let ledger_path = temp_journal("planted-crash-commit-redispatch-ledger");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&ledger_path);

    let (plan, _) = setup_alert_plan(&ledger_path)?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:durable:crash_commit_redispatch");

    // Session 1: Prepare and commit effect to durable journal, then simulate crash
    // immediately between Step 1 (commit) and Step 2 (provider dispatch).
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let prep_receipt = journal.prepare(
            plan.intent.clone(),
            plan.obligation_id.clone(),
            "delivery_acknowledged_by_provider",
            TimestampNs(100),
        )?;
        assert_eq!(prep_receipt.state, EffectState::Prepared);

        let commit_receipt = journal.transition(
            &plan.intent.operation_id,
            EffectState::Committed,
            TimestampNs(110),
            None,
            None,
        )?;
        assert_eq!(commit_receipt.state, EffectState::Committed);
        // Process crash occurs here: state is Committed on disk, provider dispatch never ran.
    }

    // Session 2: System reboots; journal is replayed from disk.
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let receipt = journal
            .operation(&plan.intent.operation_id)
            .ok_or(ContractError::NotFound)?;
        assert_eq!(receipt.state, EffectState::Committed);

        // Recovery: Re-dispatching must succeed as idempotent continuation without failing Committed -> Committed
        let redispatch_receipt = journal.dispatch_alert(
            &plan,
            ReferenceProviderBehavior::Deliver,
            TimestampNs(200),
            TimestampNs(210),
            &mut provider,
        )?;
        assert_eq!(redispatch_receipt.state, EffectState::AdapterAccepted);

        let provider_proof = provider.lookup(&plan.intent)?.unwrap().receipt_digest();
        let _ = journal.observe_alert(&plan, provider_proof, TimestampNs(215), &provider)?;

        // Verification must be able to complete normally
        let verified_receipt = journal.verify_alert(&plan, TimestampNs(220), &provider)?;
        assert_eq!(verified_receipt.state, EffectState::Verified);

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
fn test_crash_after_commit_recovery_via_reconcile() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("planted-crash-commit-reconcile");
    let ledger_path = temp_journal("planted-crash-commit-reconcile-ledger");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&ledger_path);

    let (plan, _) = setup_alert_plan(&ledger_path)?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:durable:crash_commit_reconcile");

    // Provider external dispatch succeeded, but crash occurred before journal recorded AdapterAccepted
    let _ = provider.dispatch(&plan.intent, ReferenceProviderBehavior::Deliver);
    let provider_proof = provider.lookup(&plan.intent)?.unwrap().receipt_digest();

    // Session 1: Committed on disk
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let _ = journal.prepare(
            plan.intent.clone(),
            plan.obligation_id.clone(),
            "delivery_acknowledged_by_provider",
            TimestampNs(100),
        )?;
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
    }

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(ledger_path);
    Ok(())
}

#[test]
fn test_crash_after_commit_recovery_via_reconcile_failed() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("planted-crash-commit-fail");
    let ledger_path = temp_journal("planted-crash-commit-fail-ledger");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&ledger_path);

    let (plan, _) = setup_alert_plan(&ledger_path)?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:durable:crash_commit_fail");

    // Provider recorded external failure
    let fail_receipt = provider.record_failure(&plan.intent, "carrier_gateway_timeout")?;

    // Session 1: Committed on disk
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let _ = journal.prepare(
            plan.intent.clone(),
            plan.obligation_id.clone(),
            "delivery_acknowledged_by_provider",
            TimestampNs(100),
        )?;
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

    let (plan, _) = setup_alert_plan(&ledger_path)?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:durable:reconcile_accepted");

    // Session 1: Prepare and dispatch alert; provider accepts delivery
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let _ = journal.prepare(
            plan.intent.clone(),
            plan.obligation_id.clone(),
            "delivery_acknowledged_by_provider",
            TimestampNs(100),
        )?;
        let outcome = journal.dispatch_alert(
            &plan,
            ReferenceProviderBehavior::Deliver,
            TimestampNs(110),
            TimestampNs(120),
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

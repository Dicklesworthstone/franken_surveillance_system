#![forbid(unsafe_code)]
//! Real durable-journal lifecycle tests. No provider, camera, or network is contacted.

use super::*;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::{BudgetVector, EffectIntent, IdempotencyKey, ObligationId, RootAuthoritySpec};

type TestResult = Result<(), Box<dyn Error>>;
const SITE: &str = "site:alert-control-tests";
const OWNER: &str = "principal:local-owner";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Result<Self, Box<dyn Error>> {
        for n in 0..100 {
            let path = std::env::temp_dir().join(format!("fss-alert-control-{label}-{}-{n}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("test directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

fn context(root: &Path, principal: &str, cancel: bool) -> Result<(ContextAuthority, ReplayCx), Box<dyn Error>> {
    let mut capabilities = vec!["ADP-REPLAY-001".to_owned()];
    if cancel { capabilities.push(CAP_ALERT_CANCEL.to_owned()); }
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:alert-control-test".into(),
        operation_id: OperationId::parse("operation:alert-control-test")?,
        principal: principal.to_owned(), capabilities, deadline: None, priority: 10,
        budgets: BudgetVector::builder().bytes(8 * 1024 * 1024).storage_operations(8192).build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()), generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, root.to_path_buf())?;
    Ok((authority, cx))
}

fn prepare(dep: &mut ReferenceDeployment, name: &str, class: &str) -> Result<OperationId, Box<dyn Error>> {
    let id = OperationId::parse(format!("operation:alert:{name}"))?;
    dep.effects_and_ledger().0.prepare(
        EffectIntent::new(id.clone(), IdempotencyKey::parse(format!("idempotency:alert:{name}"))?,
            class, ContentDigest::sha256(name.as_bytes()), ContentDigest::sha256(b"preconditions"))?,
        ObligationId::parse(format!("obligation:alert:{name}"))?,
        crate::REFERENCE_ALERT_TERMINAL_PREDICATE, TimestampNs(100),
    )?;
    Ok(id)
}

fn journal(dep: &ReferenceDeployment) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(fs::read(dep.effects().path())?)
}

#[test]
fn preview_approval_and_cold_exact_retry_preserve_one_terminal_transition() -> TestResult {
    let dir = Directory::new("cold")?;
    let (auth, cx) = context(&dir.0, OWNER, true)?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let id = prepare(&mut dep, "one", "alert.dispatch")?;
    let before = journal(&dep)?;
    let anchor = dep.current_anchor().clone();
    let preview = preview_alert_cancellation(&dep, &id, &auth, &cx)?;
    assert_eq!(preview, preview_alert_cancellation(&dep, &id, &auth, &cx)?);
    assert_eq!(before, journal(&dep)?);
    assert!(matches!(cancel_prepared_alert(&mut dep, &id, ContentDigest::sha256(b"wrong"),
        TimestampNs(101), &auth, &cx), Err(AlertControlError::ApprovalMismatch)));
    assert_eq!(before, journal(&dep)?);
    let result = cancel_prepared_alert(&mut dep, &id, preview.approval_digest(), TimestampNs(101), &auth, &cx)?;
    assert_eq!(result.outcome, AlertCancellationOutcome::Cancelled);
    assert_eq!(result.operation.state, EffectState::Cancelled);
    assert_eq!(result.operation.committed_at, None);
    assert_eq!(result.operation.result_digest, Some(preview.proof_digest()));
    assert_eq!(result.operation.error_code.as_deref(), Some("operator_cancel:principal:local-owner"));
    assert_eq!(dep.effects().obligation(&result.obligation.obligation_id), Some(&result.obligation));
    assert_eq!(result.obligation.state, ObligationState::Cancelled);
    assert!(dep.current_anchor().commit_sequence > anchor.commit_sequence);
    assert!(request_is_ledgered(dep.ledger(), preview.evidence_digest()));
    let after = journal(&dep)?;
    assert!(after.len() > before.len());
    drop(dep);
    cx.drain_and_finalize();
    let (auth, cx) = context(&dir.0, OWNER, true)?;
    let mut reopened = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    // Retry is about the already-durable transition; it need not invent a new time.
    let retry = cancel_prepared_alert(&mut reopened, &id, preview.approval_digest(), TimestampNs(0), &auth, &cx)?;
    assert_eq!(retry.outcome, AlertCancellationOutcome::AlreadyCancelled);
    assert_eq!(retry.operation, result.operation);
    assert_eq!(retry.obligation, result.obligation);
    assert_eq!(journal(&reopened)?, after);
    Ok(())
}

#[test]
fn capability_actor_site_and_root_are_checked_before_writing() -> TestResult {
    let dir = Directory::new("authority")?;
    let (auth, cx) = context(&dir.0, OWNER, true)?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let id = prepare(&mut dep, "one", "alert.dispatch")?;
    let preview = preview_alert_cancellation(&dep, &id, &auth, &cx)?;
    let before = journal(&dep)?;
    let (denied, denied_cx) = context(&dir.0, OWNER, false)?;
    assert!(matches!(preview_alert_cancellation(&dep, &id, &denied, &denied_cx), Err(AlertControlError::Unauthorized)));
    let (other, other_cx) = context(&dir.0, "principal:another-owner", true)?;
    let other_plan = preview_alert_cancellation(&dep, &id, &other, &other_cx)?;
    assert_ne!(preview.approval_digest(), other_plan.approval_digest());
    assert_ne!(preview.proof_digest(), other_plan.proof_digest());
    assert!(matches!(cancel_prepared_alert(&mut dep, &id, preview.approval_digest(), TimestampNs(101),
        &other, &other_cx), Err(AlertControlError::ApprovalMismatch)));
    let mut wrong_site = auth.clone();
    wrong_site.anchor_universe = ContentDigest::sha256(b"another-site");
    assert!(preview_alert_cancellation(&dep, &id, &wrong_site, &cx).is_err());
    let other_dir = Directory::new("foreign-root")?;
    let (_, foreign_cx) = context(&other_dir.0, OWNER, true)?;
    assert!(preview_alert_cancellation(&dep, &id, &auth, &foreign_cx).is_err());
    assert_eq!(before, journal(&dep)?);
    Ok(())
}

#[test]
fn old_preparation_can_be_cancelled_after_unrelated_journal_progress() -> TestResult {
    let dir = Directory::new("unrelated")?;
    let (auth, cx) = context(&dir.0, OWNER, true)?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let id = prepare(&mut dep, "old", "alert.dispatch")?;
    let old = preview_alert_cancellation(&dep, &id, &auth, &cx)?;
    let newer = prepare(&mut dep, "new", "alert.dispatch")?;
    assert_eq!(old, preview_alert_cancellation(&dep, &id, &auth, &cx)?);
    let other = preview_alert_cancellation(&dep, &newer, &auth, &cx)?;
    assert_ne!(old.approval_digest(), other.approval_digest());
    cancel_prepared_alert(&mut dep, &id, old.approval_digest(), TimestampNs(102), &auth, &cx)?;
    assert_eq!(dep.effects().operation(&newer).map(|o| o.state), Some(EffectState::Prepared));
    // An old dispatch approval cannot resurrect the cancelled operation at the core boundary.
    assert!(dep.effects_and_ledger().0.transition(&id, EffectState::Committed, TimestampNs(103), None, None).is_err());
    Ok(())
}

#[test]
fn commitment_after_preview_invalidates_cancellation_without_an_append() -> TestResult {
    let dir = Directory::new("dispatch-race")?;
    let (auth, cx) = context(&dir.0, OWNER, true)?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let id = prepare(&mut dep, "one", "alert.dispatch")?;
    let preview = preview_alert_cancellation(&dep, &id, &auth, &cx)?;
    dep.effects_and_ledger().0.transition(&id, EffectState::Committed, TimestampNs(101), None, None)?;
    for state in [EffectState::Committed, EffectState::AdapterAccepted, EffectState::Indeterminate] {
        if state == EffectState::AdapterAccepted {
            dep.effects_and_ledger().0.transition(&id, state, TimestampNs(102), None, None)?;
        } else if state == EffectState::Indeterminate {
            dep.effects_and_ledger().0.mark_indeterminate(&id, TimestampNs(103), "lost_ack")?;
        }
        let before = journal(&dep)?;
        assert!(matches!(cancel_prepared_alert(&mut dep, &id, preview.approval_digest(), TimestampNs(104),
            &auth, &cx), Err(AlertControlError::NotPrepared(actual)) if actual == state));
        assert_eq!(before, journal(&dep)?);
    }
    Ok(())
}

#[test]
fn another_cancellation_or_actor_cannot_be_relabelled_as_an_exact_retry() -> TestResult {
    let dir = Directory::new("cancel-race")?;
    let (auth, cx) = context(&dir.0, OWNER, true)?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let id = prepare(&mut dep, "one", "alert.dispatch")?;
    let original = preview_alert_cancellation(&dep, &id, &auth, &cx)?;
    dep.effects_and_ledger().0.cancel(&id, TimestampNs(101), ContentDigest::sha256(b"different evidence"),
        Some("cooperative_cancellation_requested".to_owned()))?;
    let before = journal(&dep)?;
    assert!(matches!(cancel_prepared_alert(&mut dep, &id, original.approval_digest(), TimestampNs(102),
        &auth, &cx), Err(AlertControlError::CancellationMismatch)));
    assert_eq!(before, journal(&dep)?);
    let id = prepare(&mut dep, "two", "alert.dispatch")?;
    let original = preview_alert_cancellation(&dep, &id, &auth, &cx)?;
    cancel_prepared_alert(&mut dep, &id, original.approval_digest(), TimestampNs(101), &auth, &cx)?;
    let (other, other_cx) = context(&dir.0, "principal:other", true)?;
    assert!(matches!(preview_alert_cancellation(&dep, &id, &other, &other_cx), Err(AlertControlError::CancellationMismatch)));
    Ok(())
}

#[test]
fn cancellation_checkpoints_preserve_precommit_or_terminal_state() -> TestResult {
    for stage in [STAGE_CANCEL_READ, STAGE_CANCEL_REVALIDATED, STAGE_CANCEL_REQUEST_PUBLISHED, STAGE_CANCEL_COMMITTED] {
        let dir = Directory::new("cut")?;
        let (auth, cx) = context(&dir.0, OWNER, true)?;
        let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
        let id = prepare(&mut dep, "one", "alert.dispatch")?;
        let preview = preview_alert_cancellation(&dep, &id, &auth, &cx)?;
        let before = journal(&dep)?;
        cx.set_cancel_at_checkpoint(stage);
        let result = cancel_prepared_alert(&mut dep, &id, preview.approval_digest(), TimestampNs(101), &auth, &cx);
        if stage == STAGE_CANCEL_COMMITTED {
            assert_eq!(result?.outcome, AlertCancellationOutcome::Cancelled);
            assert_eq!(dep.effects().operation(&id).map(|o| o.state), Some(EffectState::Cancelled));
        } else {
            assert!(matches!(result, Err(AlertControlError::Cancelled)));
            assert_eq!(before, journal(&dep)?);
            assert_eq!(dep.effects().operation(&id).map(|o| o.state), Some(EffectState::Prepared));
            if stage == STAGE_CANCEL_REQUEST_PUBLISHED {
                assert!(request_is_ledgered(dep.ledger(), preview.evidence_digest()));
                let anchor = dep.current_anchor().clone();
                drop(dep);
                let (auth, cx) = context(&dir.0, OWNER, true)?;
                let mut reopened = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
                let resumed = cancel_prepared_alert(&mut reopened, &id, preview.approval_digest(), TimestampNs(102), &auth, &cx)?;
                assert_eq!(resumed.outcome, AlertCancellationOutcome::Cancelled);
                assert_eq!(reopened.current_anchor(), &anchor, "request is not republished");
            }
        }
    }
    Ok(())
}

#[test]
fn wrong_effect_and_nonmonotone_time_do_not_touch_history() -> TestResult {
    let dir = Directory::new("bounds")?;
    let (auth, cx) = context(&dir.0, OWNER, true)?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &cx)?;
    let not_alert = prepare(&mut dep, "not-alert", "camera.ptz")?;
    assert!(matches!(preview_alert_cancellation(&dep, &not_alert, &auth, &cx), Err(AlertControlError::NotAlert)));
    let id = prepare(&mut dep, "one", "alert.dispatch")?;
    let preview = preview_alert_cancellation(&dep, &id, &auth, &cx)?;
    let before = journal(&dep)?;
    for time in [i128::MIN, 99, 100] {
        assert!(cancel_prepared_alert(&mut dep, &id, preview.approval_digest(), TimestampNs(time), &auth, &cx).is_err());
        assert_eq!(before, journal(&dep)?);
    }
    assert!(!valid_principal(""));
    assert!(!valid_principal("principal:bad\nactor"));
    assert!(!valid_principal(&"a".repeat(MAX_CANCEL_PRINCIPAL_BYTES + 1)));
    assert!(valid_principal(&"a".repeat(MAX_CANCEL_PRINCIPAL_BYTES)));
    Ok(())
}

fn copy_directory(from: &Path, to: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let destination = to.join(entry.file_name());
        if entry.file_type()?.is_dir() { copy_directory(&entry.path(), &destination)?; }
        else { fs::copy(entry.path(), destination)?; }
    }
    Ok(())
}

#[test]
fn byte_copied_journals_do_not_inherit_the_original_approval() -> TestResult {
    let dir = Directory::new("pins")?;
    let root = dir.0.join("original");
    let (auth, cx) = context(&root, OWNER, true)?;
    let mut dep = ReferenceDeployment::open(&root, SITE, &cx)?;
    let id = prepare(&mut dep, "one", "alert.dispatch")?;
    let old = preview_alert_cancellation(&dep, &id, &auth, &cx)?;
    drop(dep);
    let copied = dir.0.join("copy");
    copy_directory(&root, &copied)?;
    let (auth, cx) = context(&copied, OWNER, true)?;
    let mut dep = ReferenceDeployment::open(&copied, SITE, &cx)?;
    let new = preview_alert_cancellation(&dep, &id, &auth, &cx)?;
    assert_eq!(old.prepared(), new.prepared());
    assert_ne!(old.approval_digest(), new.approval_digest());
    let before = journal(&dep)?;
    assert!(matches!(cancel_prepared_alert(&mut dep, &id, old.approval_digest(), TimestampNs(101), &auth, &cx),
        Err(AlertControlError::ApprovalMismatch)));
    assert_eq!(before, journal(&dep)?);
    Ok(())
}

#[test]
fn operator_request_is_required_and_real_alert_situation_accepts_only_its_bound_proof() -> TestResult {
    use fss_core::{
        CapsuleId, ContractBasis, ContractBasisRegistryBytes, EventId, MissionId,
        ProbabilityInterval, SensorId, SessionId,
    };
    use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
    use fss_object::{InMemoryObjectStore, ObjectLimits};
    use crate::{
        DeliveryPlan, MockModelScript, MockModelSpec, MockSemanticLabel, PrepareAlertParams,
        ReferenceModelObservation, ReferenceSituationRequest, VirtualCameraSpec,
        execute_mock_model, run_reference_capture,
    };
    let dir = Directory::new("guard")?;
    let root = dir.0.join("deployment");
    let (auth, cx) = context(&root, OWNER, true)?;
    let mut dep = ReferenceDeployment::open(&root, SITE, &cx)?;
    let mut captures = DurableReferenceLedger::open(dir.0.join("captures.fssj"), "site:captures", IncompleteTailPolicy::Reject)?;
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut observations = Vec::new();
    for (name, seed) in [("alpha", 111), ("beta", 222)] {
        let camera = VirtualCameraSpec {
            capture_id: CapsuleId::parse(format!("capture:{name}"))?,
            sensor_id: SensorId::parse(format!("sensor:{name}"))?, seed,
            packet_count: 2, packet_bytes: 32, start_ns: 10_000, period_ns: 1_000_000, uncertainty_ns: 1_000,
        };
        let capture = run_reference_capture(&camera, &DeliveryPlan::identity(2)?, &mut objects, &mut captures)?;
        let model = MockModelSpec::new(format!("mock:{name}"), MockModelScript::Fixed {
            label: MockSemanticLabel::PersonLike, probability: ProbabilityInterval::new(0.99, 1.0)?,
        })?;
        let result = execute_mock_model(&model, &capture, &mut objects)?;
        observations.push(ReferenceModelObservation::new(result, format!("power:{name}"),
            CaptureInterval::new(TimestampNs(10_000), TimestampNs(20_000))?)?);
    }
    let decision = dep.evaluate_policy(EventId::parse("event:alert-control")?, observations, &cx)?;
    for receipt in &decision.event.model_receipts {
        assert_eq!(dep.stage_payload(objects.read_verified(*receipt)?)?, *receipt);
    }
    let event_receipt = dep.publish_event(&decision, &cx)?;
    let alert = {
        let (effects, ledger) = dep.effects_and_ledger();
        effects.prepare_alert(PrepareAlertParams {
            decision: &decision, event_receipt: &event_receipt, authority: ledger,
            operation_id: OperationId::parse("operation:guard-alert")?,
            idempotency_key: IdempotencyKey::parse("idempotency:guard-alert")?,
            obligation_id: ObligationId::parse("obligation:guard-alert")?,
            channel: "owner-test-channel".into(), now: TimestampNs(1_700_000_000),
        })?
    };
    let preview = preview_alert_cancellation(&dep, &alert.intent.operation_id, &auth, &cx)?;
    let reason = format!("{REASON_PREFIX}{OWNER}");
    assert!(!operator_cancellation_is_bound(preview.proof_digest(), Some(&reason), preview.prepared(), &alert, dep.ledger()),
        "a preview digest is not ledger-published cancellation evidence");
    let receipt = cancel_prepared_alert(&mut dep, &alert.intent.operation_id, preview.approval_digest(),
        TimestampNs(1_700_000_001), &auth, &cx)?;
    assert!(operator_cancellation_is_bound(receipt.plan.proof_digest(), Some(&reason), preview.prepared(), &alert, dep.ledger()));
    for forged_reason in ["operator_cancel:principal:someone-else", "operator_cancel:", "arbitrary", "cooperative_cancellation_requested"] {
        assert!(!operator_cancellation_is_bound(receipt.plan.proof_digest(), Some(forged_reason), preview.prepared(), &alert, dep.ledger()));
    }
    let mut forged_preparation = preview.prepared().clone();
    forged_preparation.terminal_predicate.push('!');
    assert!(!operator_cancellation_is_bound(receipt.plan.proof_digest(), Some(&reason), &forged_preparation, &alert, dep.ledger()));
    let request = || -> Result<ReferenceSituationRequest<'_>, Box<dyn Error>> {
        Ok(ReferenceSituationRequest {
            mission_id: MissionId::parse("mission:alert-control")?,
            session_id: SessionId::parse("session:alert-control")?,
            principal_id: PrincipalId::parse(OWNER)?, objective_id: "objective:alert-control".into(), revision: 1,
            contract_basis: ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
                b"schemas", b"operations", b"views", b"capabilities", b"errors", b"costs", "fss-reference:test",
            ).with_accepted_nightly("nightly-2026-08-31")),
            previous_anchor: None, predecessor_publication: None,
            decision: &decision, event_receipt: &event_receipt, alert_plan: Some(&alert), alert_outcome: None,
            coverage_witness: None,
            available_capabilities: ["capability:alert.prepare".into(), "capability:alert.commit".into(),
                crate::CAPABILITY_EFFECT_RECONCILE.into()].into_iter().collect(),
            created_at: TimestampNs(1_800_000_000),
        })
    };
    let situation = crate::compile_reference_situation_with_durable_journal(request()?, dep.effects(), dep.ledger())?;
    assert!(situation.capsule.frame.now.iter().any(|line| line.contains(" is cancelled.")));
    assert!(!situation.capsule.affordances.iter().any(|a| a.operation == "commit"));
    assert_eq!(dep.alert_provider().message_count(), 0);
    assert_eq!(dep.alert_provider().failure_count(), 0);
    let mut forged = receipt.operation.clone();
    forged.error_code = Some("operator_cancel:principal:someone-else".into());
    assert!(crate::compile_reference_situation_with_operation_receipt(request()?, &forged, dep.ledger(),
        dep.effects().effect_journal()).is_err());
    Ok(())
}

#![forbid(unsafe_code)]
//! Evidence remains in custody until every bound alert reaches a terminal journal state.
//! Synthetic policy observations and explicit journal transitions, not real alert delivery.

mod file_import_fault_support;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use file_import_fault_support::{TestResult, cx, fixture, fresh_dir, open, request, standard};
use fss_core::{
    CapsuleId, CaptureInterval, ContentDigest, EffectState, EventEvidence, EventId,
    EvidenceClass, EvidenceEdgeRelation, IdempotencyKey, ObligationId, OperationId,
    ProbabilityInterval, SensorId, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};
use fss_reference::deletion::{
    CommitOutcome, DeletionError, DeletionScope, commit_deletion,
    plan_deletion, plan_scope_deletion,
};
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use fss_reference::{
    DeliveryPlan, FileIngestAdapter, MockModelScript, MockModelSpec, MockSemanticLabel,
    PrepareAlertParams, ReferenceAlertPlan, ReferenceDeployment, ReferenceEventReceipt,
    ReferenceModelObservation, ReferencePolicyAction, ReferencePolicyDecision, ReplayCx,
    VirtualCameraSpec, evaluate_unknown_presence, execute_mock_model, run_reference_capture,
};

type ResultOf<T> = Result<T, Box<dyn std::error::Error>>;
const PRINCIPAL: &str = "operator:deletion-effect-lifecycle";
const PREPARED_AT: i128 = 3_000_000_000;

struct Harness {
    root: PathBuf,
    deployment: ReferenceDeployment,
    context: ReplayCx,
    import: ContentDigest,
    source_digest: ContentDigest,
    input: fss_reference::FileIngestRequest,
    decision: ReferencePolicyDecision,
    event: ReferenceEventReceipt,
}

impl Harness {
    fn new(label: &str) -> ResultOf<Self> {
        let dir = fresh_dir(&format!("deletion-effects-{label}"))?;
        let source = dir.join("source.mjpeg");
        let frame = fs::read(fixture("jpeg/gray_16x16_flat.jpg")?)?;
        fs::write(&source, frame.repeat(2))?;
        let root = dir.join("deployment");
        let mut deployment = open(&root, standard())?;
        let context = cx("deletion-effects")?;
        let input = request(&source, frame.len() as u64, 8)?;
        let imported = FileIngestAdapter::ingest(input.clone(), &context, &mut deployment)?;
        let mut objects = InMemoryObjectStore::new(ObjectLimits::new(2048, 32 * 1024 * 1024));
        let mut captures = DurableReferenceLedger::open(
            dir.join("captures.journal"), "site:deletion-effect-captures",
            IncompleteTailPolicy::Reject,
        )?;
        let mut observations = Vec::new();
        for (lane, seed) in [("a", 111), ("b", 222)] {
            let spec = VirtualCameraSpec {
                capture_id: CapsuleId::parse(format!("capture:deletion-effects:{lane}"))?,
                sensor_id: SensorId::parse(format!("sensor:deletion-effects:{lane}"))?,
                seed,
                packet_count: 2,
                packet_bytes: 32,
                start_ns: 10_000,
                period_ns: 1_000_000,
                uncertainty_ns: 100,
            };
            let capture = run_reference_capture(
                &spec, &DeliveryPlan::identity(spec.packet_count)?, &mut objects, &mut captures,
            )?;
            let model = MockModelSpec::new(
                format!("mock:deletion-effects:{lane}:v1"),
                MockModelScript::Fixed {
                    label: MockSemanticLabel::PersonLike,
                    probability: ProbabilityInterval::new(0.99, 1.0)?,
                },
            )?;
            let result = execute_mock_model(&model, &capture, &mut objects)?;
            observations.push(ReferenceModelObservation::new(
                result, format!("power:deletion-effects:{lane}"),
                CaptureInterval::new(TimestampNs(10_000), TimestampNs(20_000))?,
            )?);
        }
        let mut decision = evaluate_unknown_presence(
            EventId::parse("event:deletion-effects")?, observations,
        )?;
        assert_eq!(decision.action, ReferencePolicyAction::PrepareAlert);
        // An explicit synthetic dependency, not extra corroboration or an inference on the file.
        decision.event.evidence.push(EventEvidence {
            digest: imported.import_identity,
            class: EvidenceClass::Assertion,
            failure_domain: "dependency:retained-recording".to_owned(),
            supports: false,
            relation: EvidenceEdgeRelation::RequiredBy,
            capsule_digest: None,
            identity_digest: None,
        });
        decision.event.validate()?;
        for digest in &decision.event.model_receipts {
            assert_eq!(deployment.stage_payload(objects.read_verified(*digest)?)?, *digest);
        }
        let event = deployment.publish_event(&decision, &context)?;
        let harness = Self {
            root, deployment, context, import: imported.import_identity,
            source_digest: imported.input_sha256, input, decision, event,
        };
        let plan = plan_deletion(&harness.deployment, harness.import, &harness.context)?;
        assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
        assert!(plan.events.iter().any(|event| event.object_id == "object:event:event:deletion-effects"));
        assert!(!plan.deletable.is_empty());
        Ok(harness)
    }

    fn prepare(&mut self, label: &str) -> ResultOf<ReferenceAlertPlan> {
        let (journal, authority) = self.deployment.effects_and_ledger();
        Ok(journal.prepare_alert(PrepareAlertParams {
            decision: &self.decision,
            event_receipt: &self.event,
            authority,
            operation_id: OperationId::parse(format!("op:deletion-effects:{label}"))?,
            idempotency_key: IdempotencyKey::parse(format!("idempotency:deletion-effects:{label}"))?,
            obligation_id: ObligationId::parse(format!("obligation:deletion-effects:{label}"))?,
            channel: "test-only-no-dispatch".to_owned(),
            now: TimestampNs(PREPARED_AT),
        })?)
    }

    fn advance(&mut self, plan: &ReferenceAlertPlan, state: EffectState) -> TestResult {
        let journal = self.deployment.effects_mut();
        let id = &plan.intent.operation_id;
        let proof = ContentDigest::sha256(b"synthetic journal-state proof, not delivery");
        match state {
            EffectState::Prepared => return Ok(()),
            EffectState::Cancelled => {
                journal.cancel(id, TimestampNs(PREPARED_AT + 1), proof, Some("test cancel".to_owned()))?;
                return Ok(());
            }
            _ => {}
        }
        journal.transition(id, EffectState::Committed, TimestampNs(PREPARED_AT + 1), None, None)?;
        if state == EffectState::Committed {
            return Ok(());
        }
        if matches!(state, EffectState::Indeterminate | EffectState::Failed) {
            journal.mark_indeterminate(id, TimestampNs(PREPARED_AT + 2), "test lost acknowledgement")?;
            if state == EffectState::Failed {
                journal.reconcile_failed(id, proof, TimestampNs(PREPARED_AT + 3), "test known failure")?;
            }
            return Ok(());
        }
        journal.transition(id, EffectState::AdapterAccepted, TimestampNs(PREPARED_AT + 2), None, None)?;
        if state == EffectState::AdapterAccepted {
            return Ok(());
        }
        journal.transition(id, EffectState::Observed, TimestampNs(PREPARED_AT + 3), Some(proof), None)?;
        if state == EffectState::Verified {
            journal.reconcile_verified(id, proof, TimestampNs(PREPARED_AT + 4))?;
        }
        assert_eq!(journal.operation(id).ok_or("missing operation")?.state, state);
        Ok(())
    }

    fn assert_readable(&self) -> TestResult {
        let retained = RetainedFileImport::open(
            &self.deployment, self.import, RetainedReadLimits::default(), &self.context,
        )?;
        assert_eq!(retained.verify_source(
            &self.deployment, RetainedReadLimits::default(), &self.context,
        )?, self.source_digest);
        Ok(())
    }

    fn assert_blocked(&mut self, alert: &ReferenceAlertPlan, state: EffectState) -> TestResult {
        let before = snapshot(&self.root)?;
        for scope in [
            DeletionScope::Import(self.import),
            DeletionScope::Sensor(self.input.sensor_id.clone()),
            DeletionScope::Event(self.decision.event.event_id.clone()),
        ] {
            let plan = plan_scope_deletion(&self.deployment, &scope, &self.context)?;
            let blockers: Vec<_> = plan.blockers.iter().filter(|finding| finding.kind == "open_effect").collect();
            assert_eq!(blockers.len(), 1, "{scope:?}: {:?}", plan.blockers);
            assert_eq!(blockers[0].subject, alert.intent.operation_id.as_str());
            assert!(blockers[0].detail.contains(state.as_str()));
            let result = commit_deletion(
                &mut self.deployment, plan.digest()?, plan.approval_digest(PRINCIPAL)?,
                PRINCIPAL, &self.context,
            );
            match result {
                Err(DeletionError::Blocked(findings)) => assert_eq!(findings, plan.blockers),
                other => return Err(format!("blocked cleanup returned {other:?}").into()),
            }
        }
        assert_eq!(snapshot(&self.root)?, before, "planning/refusal must not change any file");
        self.assert_readable()
    }
}

fn snapshot(root: &Path) -> ResultOf<BTreeMap<PathBuf, Vec<u8>>> {
    fn visit(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) -> TestResult {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                visit(root, &path, out)?;
            } else if kind.is_file() {
                out.insert(path.strip_prefix(root)?.to_owned(), fs::read(path)?);
            } else {
                return Err("unexpected non-regular test deployment entry".into());
            }
        }
        Ok(())
    }
    let mut files = BTreeMap::new();
    visit(root, root, &mut files)?;
    Ok(files)
}

#[test]
fn every_nonterminal_alert_protects_import_sensor_and_event_cleanup() -> TestResult {
    for state in [EffectState::Prepared, EffectState::Committed, EffectState::AdapterAccepted,
        EffectState::Observed, EffectState::Indeterminate] {
        let mut harness = Harness::new(state.as_str())?;
        let alert = harness.prepare("pending")?;
        harness.advance(&alert, state)?;
        harness.assert_blocked(&alert, state)?;
    }
    Ok(())
}

#[test]
fn accepted_and_observed_alerts_still_protect_evidence_after_reopen() -> TestResult {
    for state in [EffectState::AdapterAccepted, EffectState::Observed] {
        let mut harness = Harness::new(&format!("reopen-{}", state.as_str()))?;
        let alert = harness.prepare("restart")?;
        harness.advance(&alert, state)?;
        let before = snapshot(&harness.root)?;
        let Harness { root, deployment, context, import, source_digest, input, decision, event } = harness;
        drop(deployment);
        let deployment = open(&root, standard())?;
        assert_eq!(deployment.effects().operation(&alert.intent.operation_id).ok_or("missing operation")?.state, state);
        assert_eq!(snapshot(&root)?, before);
        let mut reopened = Harness { root, deployment, context, import, source_digest, input, decision, event };
        reopened.assert_blocked(&alert, state)?;
    }
    Ok(())
}

#[test]
fn only_terminal_states_release_the_guard_and_external_copy_disclosures_survive() -> TestResult {
    for state in [EffectState::Verified, EffectState::Cancelled, EffectState::Failed] {
        let mut harness = Harness::new(state.as_str())?;
        let alert = harness.prepare("terminal")?;
        harness.advance(&alert, state)?;
        let plan = plan_deletion(&harness.deployment, harness.import, &harness.context)?;
        assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
        let copies: Vec<_> = plan.unknown_copies.iter().filter(|finding| finding.kind == "alert_dispatch").collect();
        assert_eq!(copies.len(), usize::from(state != EffectState::Cancelled));
        if let Some(copy) = copies.first() {
            assert_eq!(copy.subject, alert.intent.operation_id.as_str());
        }
        let result = commit_deletion(
            &mut harness.deployment, plan.digest()?, plan.approval_digest(PRINCIPAL)?,
            PRINCIPAL, &harness.context,
        )?;
        assert_eq!(result.outcome, CommitOutcome::Completed);
        assert_eq!(result.completion.not_proven, plan.unknown_copies);
    }
    Ok(())
}

#[test]
fn a_terminal_sibling_never_releases_another_alerts_evidence() -> TestResult {
    let mut harness = Harness::new("siblings")?;
    let terminal = harness.prepare("terminal-sibling")?;
    let pending = harness.prepare("pending-sibling")?;
    harness.advance(&terminal, EffectState::Verified)?;
    harness.advance(&pending, EffectState::Observed)?;
    harness.assert_blocked(&pending, EffectState::Observed)?;
    Ok(())
}

#[test]
fn approval_from_before_alert_preparation_cannot_bypass_the_guard() -> TestResult {
    let mut harness = Harness::new("stale")?;
    let before = plan_deletion(&harness.deployment, harness.import, &harness.context)?;
    let digest = before.digest()?;
    let approval = before.approval_digest(PRINCIPAL)?;
    let alert = harness.prepare("after-approval")?;
    harness.advance(&alert, EffectState::AdapterAccepted)?;
    let files = snapshot(&harness.root)?;
    assert!(matches!(commit_deletion(
        &mut harness.deployment, digest, approval, PRINCIPAL, &harness.context,
    ), Err(DeletionError::StalePlan(stale)) if stale == digest));
    assert_eq!(snapshot(&harness.root)?, files);
    harness.assert_blocked(&alert, EffectState::AdapterAccepted)
}

#[test]
fn an_unrelated_import_can_be_deleted_while_the_bound_alert_remains_observed() -> TestResult {
    let mut harness = Harness::new("unrelated")?;
    let mut input = harness.input.clone();
    input.sensor_id = SensorId::parse("sensor:unrelated-cleanup")?;
    let outside = FileIngestAdapter::ingest(input, &harness.context, &mut harness.deployment)?;
    let alert = harness.prepare("bound-only")?;
    harness.advance(&alert, EffectState::Observed)?;
    let plan = plan_deletion(&harness.deployment, outside.import_identity, &harness.context)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    assert!(plan.events.is_empty());
    commit_deletion(
        &mut harness.deployment, plan.digest()?, plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL, &harness.context,
    )?;
    harness.assert_readable()?;
    harness.assert_blocked(&alert, EffectState::Observed)?;
    let protected: BTreeSet<_> = harness.deployment.effects().operations()
        .filter(|operation| !operation.state.is_terminal())
        .map(|operation| operation.intent.operation_id.clone()).collect();
    assert_eq!(protected, BTreeSet::from([alert.intent.operation_id]));
    Ok(())
}

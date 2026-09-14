#![forbid(unsafe_code)]
//! Integration contract tests verifying reference situation invariants:
//! - F1: `KnowledgeState::Unknown` claims are preserved in context pack as epistemic boundary critical items.
//! - F2: `required_context_item_ids` and `ReferenceSituationPublication::verify` propagate errors.
//! - F2b: Hard clamps to `Unavailable` preserve `unsafe_worlds` and `branch_predicate`.
//! - F3: Hard clamps (`Unavailable` / `Blocked` affordances) are included in the context pack as critical items.
//! - F6: Alert `prepare` and `commit` affordances are `Conditional`, not `Robust`, and name the presence world.
//! - F7: `Corroborated` state retains a protected adversarial residual world, and consequence severity >= 4 is critical.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;

use fss_core::event::EventSupersedeParams;
use fss_core::{
    ActionAffordance, AffordanceClass, BudgetVector, CapsuleId, CaptureInterval, Completeness,
    ContentDigest, ContractBasis, ContractBasisRegistryBytes, ContractError, EffectJournal,
    EventId, IdempotencyKey, KnowledgeCell, KnowledgeCellParams, KnowledgeState, LedgerAnchor,
    MissionId, ObligationId, OperationId, PossibleWorld, PrincipalId, ProbabilityInterval,
    ProvenanceClass, ResourcePressure, SensorId, SessionId, SituationCapsule, SituationFrame,
    TimestampNs, WorldEnvelope,
};
use fss_core::{DeltaPriority, MeaningfulDeltaClass};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};
use fss_reference::classify_reference_meaningful_delta;
use fss_reference::{
    DeliveryPlan, MockModelScript, MockModelSpec, MockSemanticLabel, PrepareAlertParams,
    ReferenceAlertPlan, ReferenceError, ReferenceEventReceipt, ReferenceModelObservation,
    ReferencePolicyDecision, ReferenceProjectionSpec, ReferenceSituation,
    ReferenceSituationPublication, ReferenceSituationRequest, VirtualCameraSpec,
    compile_reference_situation, compile_reference_situation_with_operation_receipt,
    evaluate_unknown_presence, execute_mock_model, prepare_reference_alert,
    project_reference_situation, publish_reference_event, run_reference_capture,
};

fn required_context_item_ids(
    situation: &ReferenceSituation,
) -> Result<BTreeSet<String>, ReferenceError> {
    ReferenceSituationPublication::required_context_item_ids(situation)
}

fn create_exclusive_run_dir(
    prefix: &str,
    name: &str,
) -> Result<std::path::PathBuf, Box<dyn Error>> {
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
        let dir_name = format!("{prefix}-{pid}-{now}-{attempt}-{name}");
        let dir = base.join(dir_name);
        match fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        }
    }
    Err(format!("exhausted 64 attempts creating exclusive run directory for {name}").into())
}

struct TestHarness {
    run_dir: std::path::PathBuf,
    path: std::path::PathBuf,
    objects: InMemoryObjectStore,
    authority: DurableReferenceLedger,
}

impl TestHarness {
    fn new(name: &str) -> Result<Self, Box<dyn Error>> {
        let run_dir = create_exclusive_run_dir("fss-ref-situation-inv", name)?;
        let path = run_dir.join(format!("{name}.journal"));
        if path.exists() {
            return Err(format!(
                "TestHarness refused to silently reuse or overwrite existing journal at {path:?}"
            )
            .into());
        }
        let authority = DurableReferenceLedger::open(
            &path,
            format!("site:situation-inv:{name}"),
            IncompleteTailPolicy::Reject,
        )?;
        if !authority.batches().is_empty() {
            return Err(format!(
                "TestHarness journal path {path:?} unexpectedly reused non-empty journal state"
            )
            .into());
        }
        Ok(Self {
            run_dir,
            authority,
            objects: InMemoryObjectStore::new(ObjectLimits::new(2048, 32 * 1024 * 1024)),
            path,
        })
    }

    fn observation(
        &mut self,
        test_name: &str,
        lane: &str,
        seed: u64,
        failure_domain: &str,
        label: MockSemanticLabel,
    ) -> Result<ReferenceModelObservation, Box<dyn Error>> {
        let spec = VirtualCameraSpec {
            capture_id: CapsuleId::parse(format!("capture:situation-inv:{test_name}:{lane}"))?,
            sensor_id: SensorId::parse(format!("sensor:situation-inv:{test_name}:{lane}"))?,
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
            &mut self.objects,
            &mut self.authority,
        )?;
        let model = MockModelSpec::new(
            format!("mock:situation-inv:{test_name}:{lane}:v1"),
            MockModelScript::Fixed {
                label,
                probability: ProbabilityInterval::new(0.9, 1.0)?,
            },
        )?;
        let result = execute_mock_model(&model, &capture, &mut self.objects)?;
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

    fn publish_corroborated_decision(
        &mut self,
        name: &str,
    ) -> Result<(ReferencePolicyDecision, ReferenceEventReceipt), Box<dyn Error>> {
        let obs_a = self.observation(
            name,
            "lane_alpha",
            50,
            "power:alpha",
            MockSemanticLabel::PersonLike,
        )?;
        let obs_b = self.observation(
            name,
            "lane_beta",
            51,
            "power:beta",
            MockSemanticLabel::PersonLike,
        )?;
        let decision = evaluate_unknown_presence(
            EventId::parse(format!("event:situation-inv:{name}"))?,
            vec![obs_a, obs_b],
        )?;
        let receipt = publish_reference_event(&decision, &mut self.objects, &mut self.authority)?;
        Ok((decision, receipt))
    }

    fn publish_witnessed_decision(
        &mut self,
        name: &str,
    ) -> Result<(ReferencePolicyDecision, ReferenceEventReceipt), Box<dyn Error>> {
        let obs = self.observation(
            name,
            "lane_alpha",
            60,
            "power:alpha",
            MockSemanticLabel::PersonLike,
        )?;
        let decision = evaluate_unknown_presence(
            EventId::parse(format!("event:situation-inv:{name}"))?,
            vec![obs],
        )?;
        let receipt = publish_reference_event(&decision, &mut self.objects, &mut self.authority)?;
        Ok((decision, receipt))
    }

    fn publish_rejected_decision(
        &mut self,
        name: &str,
    ) -> Result<(ReferencePolicyDecision, ReferenceEventReceipt), Box<dyn Error>> {
        let obs = self.observation(
            name,
            "lane_alpha",
            70,
            "power:alpha",
            MockSemanticLabel::AnimalLike,
        )?;
        let decision = evaluate_unknown_presence(
            EventId::parse(format!("event:situation-inv:{name}"))?,
            vec![obs],
        )?;
        let receipt = publish_reference_event(&decision, &mut self.objects, &mut self.authority)?;
        Ok((decision, receipt))
    }

    fn publish_indeterminate_decision(
        &mut self,
        name: &str,
    ) -> Result<(ReferencePolicyDecision, ReferenceEventReceipt), Box<dyn Error>> {
        let obs_a = self.observation(
            name,
            "lane_alpha",
            80,
            "power:alpha",
            MockSemanticLabel::PersonLike,
        )?;
        let obs_b = self.observation(
            name,
            "lane_beta",
            81,
            "power:beta",
            MockSemanticLabel::Unknown,
        )?;
        let decision = evaluate_unknown_presence(
            EventId::parse(format!("event:situation-inv:{name}"))?,
            vec![obs_a, obs_b],
        )?;
        let receipt = publish_reference_event(&decision, &mut self.objects, &mut self.authority)?;
        Ok((decision, receipt))
    }

    fn cleanup(self) {
        let path = self.path.clone();
        let run_dir = self.run_dir.clone();
        drop(self);
        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(run_dir);
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_dir_all(&self.run_dir);
    }
}

fn test_basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(
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
    )
}

fn test_spec(target_tokens: u64) -> ReferenceProjectionSpec {
    let available_tokens = target_tokens.saturating_add(10_000).max(20_000);
    ReferenceProjectionSpec {
        view_id: "AVIEW-001".to_owned(),
        available_resources: BudgetVector::builder()
            .latency_ms(10_000)
            .tokens(available_tokens)
            .bytes(1_000_000)
            .model_calls(10)
            .cpu_millis(10_000)
            .accelerator_millis(10_000)
            .energy_millijoules(1_000_000)
            .network_bytes(1_000_000)
            .storage_operations(10_000)
            .privacy_exposure(10.0)
            .operator_attention_seconds(1_000.0)
            .build()
            .unwrap_or(BudgetVector::ZERO),
        reserved_resources: BudgetVector::builder()
            .latency_ms(100)
            .tokens(100)
            .bytes(1_000)
            .storage_operations(1)
            .build()
            .unwrap_or(BudgetVector::ZERO),
        pressure: ResourcePressure::Nominal,
        degraded_dimensions: BTreeSet::new(),
        target_tokens,
    }
}

fn test_request<'a>(
    decision: &'a ReferencePolicyDecision,
    event_receipt: &'a ReferenceEventReceipt,
    alert_plan: Option<&'a ReferenceAlertPlan>,
    capabilities: BTreeSet<String>,
) -> Result<ReferenceSituationRequest<'a>, ContractError> {
    Ok(ReferenceSituationRequest {
        mission_id: MissionId::parse("mission:situation-inv:test")?,
        session_id: SessionId::parse("session:situation-inv:test")?,
        principal_id: PrincipalId::parse("principal:situation-inv:test")?,
        objective_id: "objective:situation-inv".to_owned(),
        revision: 1,
        contract_basis: test_basis(),
        previous_anchor: None,
        predecessor_publication: None,
        decision,
        event_receipt,
        alert_plan,
        alert_outcome: None,
        coverage_witness: None,
        available_capabilities: capabilities,
        created_at: TimestampNs(1_000),
    })
}

fn synthetic_situation(
    custom_worlds: Vec<PossibleWorld>,
    custom_affordances: Vec<ActionAffordance>,
    next: Vec<String>,
) -> Result<ReferenceSituation, Box<dyn Error>> {
    let anchor = LedgerAnchor::genesis("site:synthetic-test");
    let evidence = ContentDigest::sha256(b"synthetic-evidence");
    let envelope = WorldEnvelope {
        envelope_id: "world-envelope:synthetic".to_owned(),
        objective_id: "objective:synthetic".to_owned(),
        anchor: anchor.clone(),
        nominal_claim_ids: BTreeSet::from(["claim:presence".to_owned()]),
        certified_core_claim_ids: BTreeSet::new(),
        alternatives: custom_worlds,
        adversarial_residuals: Vec::new(),
        common_invariants: BTreeSet::from(["invariant:synthetic".to_owned()]),
        coverage_boundary_handles: BTreeSet::from(["fss://coverage/synthetic".to_owned()]),
    };
    let cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:presence".to_owned(),
        statement: "Synthetic presence claim.".to_owned(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![evidence],
        contradictions: Vec::new(),
        valid_until: None,
        state_basis: None,
    })?;
    let frame = SituationFrame {
        frame_id: "frame:synthetic".to_owned(),
        objective_id: "objective:synthetic".to_owned(),
        anchor: anchor.clone(),
        world_envelope: envelope,
        knowledge_cells: vec![cell],
        now: vec!["Synthetic observation.".to_owned()],
        changed: Vec::new(),
        why: vec!["Synthetic rationale.".to_owned()],
        unknown: Vec::new(),
        at_risk: Vec::new(),
        next,
        evidence_handles: BTreeSet::from([format!("fss://proof/{evidence}")]),
    };
    let capsule = SituationCapsule {
        capsule_id: "situation:synthetic".to_owned(),
        revision: 1,
        contract_basis: test_basis(),
        mission_id: MissionId::parse("mission:synthetic")?,
        session_id: SessionId::parse("session:synthetic")?,
        principal_id: PrincipalId::parse("principal:synthetic")?,
        anchor,
        previous_anchor: None,
        frame,
        obligations: Vec::new(),
        affordances: custom_affordances,
        completeness: Completeness::Complete,
        created_at: TimestampNs(1_000),
        mission_state: None,
    };
    capsule.validate()?;
    Ok(ReferenceSituation::new(capsule, BTreeSet::from([evidence])))
}

// ---------------------------------------------------------------------------
// Finding 2: required_context_item_ids propagates error; verify fails closed
// ---------------------------------------------------------------------------

#[test]
fn test_f2_required_context_item_ids_propagates_error() -> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("f2")?;
    let (decision, receipt) = harness.publish_corroborated_decision("f2")?;
    let req = test_request(
        &decision,
        &receipt,
        None,
        BTreeSet::from(["capability:alert.prepare".to_owned()]),
    )?;
    let mut situation = compile_reference_situation(req, &harness.authority)?;

    // Baseline: valid situation has a computable required context set and verifies
    let baseline_required = required_context_item_ids(&situation)?;
    assert!(!baseline_required.is_empty());
    let pub_res = project_reference_situation(situation.clone(), &test_spec(10_000))?;
    pub_res.verify()?;

    // Plant defect: frame.next references an affordance NOT present in capsule.affordances
    situation
        .capsule
        .frame
        .next
        .push("affordance:non_existent".to_owned());

    // Invariant F2-1: required_context_item_ids must return Err, NOT swallow with unwrap_or_default
    let err = required_context_item_ids(&situation);
    assert!(
        matches!(err, Err(ReferenceError::Contract(ContractError::NotFound))),
        "Expected ContractError::NotFound, got: {err:?}"
    );

    // Invariant F2-2: ReferenceSituationPublication::required_context_item_ids also returns Err
    let assoc_err = ReferenceSituationPublication::required_context_item_ids(&situation);
    assert!(
        matches!(
            assoc_err,
            Err(ReferenceError::Contract(ContractError::NotFound))
        ),
        "Expected ContractError::NotFound from associated method, got: {assoc_err:?}"
    );

    // Invariant F2-3: Publication verification must fail when required_context_item_ids errors
    let mut corrupted_pub = pub_res.clone();
    corrupted_pub.situation = situation;
    let verify_err = corrupted_pub.verify();
    assert!(
        matches!(
            verify_err,
            Err(ReferenceError::Contract(ContractError::NotFound))
        ),
        "Publication verification must fail closed when candidate extraction errors, got: {verify_err:?}"
    );

    harness.cleanup();
    Ok(())
}

// ---------------------------------------------------------------------------
// Finding 3: Hard clamps (Unavailable/Blocked) are included in context pack
// ---------------------------------------------------------------------------

#[test]
fn test_f3_hard_clamps_included_in_context_pack() -> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("f3")?;
    let (decision, receipt) = harness.publish_corroborated_decision("f3")?;

    // Request with EMPTY capabilities: capability:alert.prepare is missing, so the affordance
    // is classified as Unavailable (a hard clamp).
    let req = test_request(&decision, &receipt, None, BTreeSet::new())?;
    let situation = compile_reference_situation(req, &harness.authority)?;

    // Verify pre-condition: affordance is Unavailable and NOT in frame.next
    let prepare_affordance = situation
        .capsule
        .affordances
        .iter()
        .find(|a| a.affordance_id == "affordance:alert:prepare")
        .ok_or(ReferenceError::InvalidSpec("missing_prepare_affordance"))?;
    assert_eq!(prepare_affordance.class, AffordanceClass::Unavailable);
    assert!(
        !situation
            .capsule
            .frame
            .next
            .contains(&"affordance:alert:prepare".to_owned())
    );

    // Project situation to publication
    let pub_res = project_reference_situation(situation.clone(), &test_spec(10_000))?;

    // Invariant F3-1: Context pack must contain the hard clamp item
    let hard_clamp_item = pub_res
        .context_pack
        .items
        .iter()
        .find(|i| i.item_id == "context:hard_clamp:affordance:alert:prepare");
    assert!(
        hard_clamp_item.is_some(),
        "Context pack must contain context:hard_clamp:affordance:alert:prepare"
    );
    let item = hard_clamp_item.ok_or(ReferenceError::InvalidSpec("hard_clamp_missing"))?;
    assert_eq!(item.kind, "hard_clamp");
    assert_eq!(item.epistemic_state, KnowledgeState::Known);
    assert!(
        item.content.contains("capability:alert.prepare"),
        "Hard clamp item content must explain the missing capability: {}",
        item.content
    );
    assert!(
        item.basis.contains("capability:alert.prepare"),
        "Hard clamp item basis must include the missing capability"
    );

    // Invariant F3-2: Compression receipt must count the hard clamp as known critical item
    assert!(
        pub_res
            .compression_receipt
            .selected_classes
            .contains("hard_clamp"),
        "Receipt selected_classes must include 'hard_clamp'"
    );
    assert_eq!(
        pub_res.compression_receipt.stop_reason,
        fss_core::CompressionStopReason::Complete
    );
    assert_eq!(
        pub_res
            .compression_receipt
            .critical_preservation
            .omitted_critical_items,
        0
    );

    // Invariant F3-3: required_context_item_ids must include the hard clamp ID
    let required = required_context_item_ids(&situation)?;
    assert!(
        required.contains("context:hard_clamp:affordance:alert:prepare"),
        "required_context_item_ids must include hard clamp candidate"
    );

    // Invariant F3-4: Publication must pass verification
    pub_res.verify()?;

    // Real pipeline test for an explicitly Blocked affordance:
    // Under ReferencePolicyAction::Hold (e.g. from single-domain Witnessed state),
    // alert preparation is blocked by policy preconditions and classified as Blocked.
    let (w_decision, w_receipt) = harness.publish_witnessed_decision("f3-blocked")?;
    let w_req = test_request(
        &w_decision,
        &w_receipt,
        None,
        BTreeSet::from(["capability:alert.prepare".to_owned()]),
    )?;
    let w_situation = compile_reference_situation(w_req, &harness.authority)?;
    let blocked_prepare = w_situation
        .capsule
        .affordances
        .iter()
        .find(|a| a.affordance_id == "affordance:alert:prepare")
        .ok_or(ReferenceError::InvalidSpec("missing_blocked_prepare"))?;
    assert_eq!(blocked_prepare.class, AffordanceClass::Blocked);
    assert!(
        !w_situation
            .capsule
            .frame
            .next
            .contains(&"affordance:alert:prepare".to_owned())
    );

    let w_pub = project_reference_situation(w_situation.clone(), &test_spec(10_000))?;
    let blocked_clamp_item = w_pub
        .context_pack
        .items
        .iter()
        .find(|i| i.item_id == "context:hard_clamp:affordance:alert:prepare");
    assert!(
        blocked_clamp_item.is_some(),
        "Blocked affordance must appear as hard_clamp in context pack"
    );
    let blocked_item =
        blocked_clamp_item.ok_or(ReferenceError::InvalidSpec("missing_blocked_item"))?;
    assert_eq!(blocked_item.kind, "hard_clamp");
    assert!(
        blocked_item.content.contains("blocked"),
        "Hard clamp item content must explain the Blocked state: {}",
        blocked_item.content
    );

    let w_required = required_context_item_ids(&w_situation)?;
    assert!(
        w_required.contains("context:hard_clamp:affordance:alert:prepare"),
        "required_context_item_ids must include blocked hard clamp candidate"
    );
    w_pub.verify()?;

    harness.cleanup();
    Ok(())
}

// ---------------------------------------------------------------------------
// Finding 6: Alert prepare and commit are Conditional, not Robust
// ---------------------------------------------------------------------------

#[test]
fn test_f6_alert_prepare_and_commit_are_conditional_not_robust() -> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("f6")?;
    let (decision, receipt) = harness.publish_corroborated_decision("f6")?;
    let presence_world = format!("world:event:{}:present", decision.event.event_id.as_str());

    // Case A: Prepare Alert affordance
    let req_prepare = test_request(
        &decision,
        &receipt,
        None,
        BTreeSet::from(["capability:alert.prepare".to_owned()]),
    )?;
    let situation_prepare = compile_reference_situation(req_prepare, &harness.authority)?;
    let prepare = situation_prepare
        .capsule
        .affordances
        .iter()
        .find(|a| a.operation == "plan")
        .ok_or(ReferenceError::InvalidSpec("missing_prepare_affordance"))?;

    // Invariant F6-1: prepare must be Conditional, not Robust
    assert_ne!(
        prepare.class,
        AffordanceClass::Robust,
        "Alert prepare affordance must not be classified as Robust"
    );
    assert_eq!(
        prepare.class,
        AffordanceClass::Conditional,
        "Alert prepare affordance must be classified as Conditional"
    );

    // Invariant F6-2: prepare must name the presence world as branch predicate
    assert_eq!(
        prepare.branch_predicate,
        Some(presence_world.clone()),
        "Branch predicate must name the presence world"
    );
    assert!(
        prepare.supported_worlds.contains(&presence_world),
        "supported_worlds must contain the presence world"
    );
    assert!(
        !prepare.unsafe_worlds.is_empty(),
        "unsafe_worlds must not be empty; must contain non-presence worlds"
    );
    assert!(
        prepare.supported_worlds.is_disjoint(&prepare.unsafe_worlds),
        "supported_worlds and unsafe_worlds must be disjoint"
    );
    prepare.validate_against(&situation_prepare.capsule.frame.world_envelope)?;

    // Verify ControlEnvelope categorizes it as conditional
    let pub_prepare = project_reference_situation(situation_prepare, &test_spec(10_000))?;
    assert!(
        pub_prepare
            .control_envelope
            .conditional_affordance_ids
            .contains("affordance:alert:prepare")
    );
    assert!(
        !pub_prepare
            .control_envelope
            .robust_affordance_ids
            .contains("affordance:alert:prepare")
    );
    pub_prepare.verify()?;

    // Case B: Commit Alert affordance
    let mut journal = EffectJournal::new();
    let alert_plan = prepare_reference_alert(
        PrepareAlertParams {
            decision: &decision,
            event_receipt: &receipt,
            authority: &harness.authority,
            operation_id: OperationId::parse("op:situation-inv:f6:alert")?,
            idempotency_key: IdempotencyKey::parse("idemp:situation-inv:f6:alert")?,
            obligation_id: ObligationId::parse("obligation:situation-inv:f6:alert")?,
            channel: "security-ops".to_owned(),
            now: TimestampNs(1_000),
        },
        &mut journal,
    )?;

    let op_receipt = journal
        .operation(&alert_plan.intent.operation_id)
        .cloned()
        .ok_or(ReferenceError::InvalidSpec("missing_operation_receipt"))?;

    let req_commit = test_request(
        &decision,
        &receipt,
        Some(&alert_plan),
        BTreeSet::from(["capability:alert.commit".to_owned()]),
    )?;
    let situation_commit = compile_reference_situation_with_operation_receipt(
        req_commit,
        &op_receipt,
        &harness.authority,
    )?;
    let commit = situation_commit
        .capsule
        .affordances
        .iter()
        .find(|a| a.operation == "commit")
        .ok_or(ReferenceError::InvalidSpec("missing_commit_affordance"))?;

    // Invariant F6-3: commit must be Conditional, not Robust
    assert_ne!(
        commit.class,
        AffordanceClass::Robust,
        "Alert commit affordance must not be classified as Robust"
    );
    assert_eq!(
        commit.class,
        AffordanceClass::Conditional,
        "Alert commit affordance must be classified as Conditional"
    );

    // Invariant F6-4: commit must name the presence world as branch predicate
    assert_eq!(
        commit.branch_predicate,
        Some(presence_world.clone()),
        "Branch predicate must name the presence world"
    );
    assert!(
        commit.supported_worlds.contains(&presence_world),
        "supported_worlds must contain the presence world"
    );
    assert!(
        !commit.unsafe_worlds.is_empty(),
        "unsafe_worlds must not be empty; must contain non-presence worlds"
    );
    assert!(
        commit.supported_worlds.is_disjoint(&commit.unsafe_worlds),
        "supported_worlds and unsafe_worlds must be disjoint"
    );
    assert!(
        !commit.reversible,
        "Alert commit must be marked non-reversible"
    );
    commit.validate_against(&situation_commit.capsule.frame.world_envelope)?;

    // Verify ControlEnvelope categorizes it as conditional
    let pub_commit = project_reference_situation(situation_commit, &test_spec(10_000))?;
    assert!(
        pub_commit
            .control_envelope
            .conditional_affordance_ids
            .contains("affordance:alert:commit")
    );
    assert!(
        !pub_commit
            .control_envelope
            .robust_affordance_ids
            .contains("affordance:alert:commit")
    );
    pub_commit.verify()?;

    harness.cleanup();
    Ok(())
}

// ---------------------------------------------------------------------------
// Finding 7: Corroborated retains adversarial residual; severity >= 4 is critical
// ---------------------------------------------------------------------------

#[test]
fn test_f7_corroborated_envelope_retains_protected_adversarial_residual_and_high_severity_is_critical()
-> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("f7")?;
    let (decision, receipt) = harness.publish_corroborated_decision("f7")?;
    let req = test_request(
        &decision,
        &receipt,
        None,
        BTreeSet::from(["capability:alert.prepare".to_owned()]),
    )?;
    let situation = compile_reference_situation(req, &harness.authority)?;

    // Invariant F7-1: Corroborated world envelope must retain a protected adversarial residual world
    let envelope = &situation.capsule.frame.world_envelope;
    assert!(
        !envelope.adversarial_residuals.is_empty(),
        "Corroborated world envelope must not empty adversarial_residuals!"
    );
    let residual = envelope
        .adversarial_residuals
        .iter()
        .find(|w| w.protected)
        .ok_or(ReferenceError::InvalidSpec("missing_protected_residual"))?;
    assert!(
        residual.world_id.contains("spoofing-or-simultaneous-error"),
        "Residual world ID must indicate spoofing/simultaneous-error: {}",
        residual.world_id
    );
    assert!(
        residual.consequence_severity >= 4,
        "Residual world consequence severity must be >= 4: {}",
        residual.consequence_severity
    );
    assert!(
        residual.protected,
        "Residual world must be marked protected"
    );

    // Invariant F7-2: High-loss world with consequence_severity >= 4 is critical REGARDLESS of protected flag.
    // In an Indeterminate event, compile_reference_situation emits an unmitigated-exposure world
    // with consequence_severity = 4 and protected = false.
    let (indet_decision, indet_receipt) = harness.publish_indeterminate_decision("f7-indet")?;
    let indet_req = test_request(&indet_decision, &indet_receipt, None, BTreeSet::new())?;
    let indet_situation = compile_reference_situation(indet_req, &harness.authority)?;
    // PersonLike + Unknown: the unknown finding is an abstention, not a contradiction, so the
    // physical cell stays indeterminate and keeps its reconciliation basis.
    let indet_physical = indet_situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id().ends_with(":unknown-presence"))
        .ok_or(ReferenceError::InvalidSpec("missing_physical_cell"))?;
    assert_eq!(
        indet_physical.knowledge_state(),
        KnowledgeState::Indeterminate
    );
    assert!(indet_physical.state_basis().is_some());
    assert!(indet_physical.contradictions().is_empty());
    let indet_envelope = &indet_situation.capsule.frame.world_envelope;

    let unmitigated_world = indet_envelope
        .alternatives
        .iter()
        .find(|w| w.world_id.contains("unmitigated-exposure"))
        .ok_or(ReferenceError::InvalidSpec("missing_unmitigated_world"))?;
    assert_eq!(unmitigated_world.consequence_severity, 4);
    assert!(
        !unmitigated_world.protected,
        "unmitigated-exposure world must have protected = false"
    );

    // required_context_item_ids must include this world because consequence_severity >= 4 makes it critical
    let indet_required = required_context_item_ids(&indet_situation)?;
    let unmitigated_item_id = format!("context:world:{}", unmitigated_world.world_id);
    assert!(
        indet_required.contains(&unmitigated_item_id),
        "A world with consequence_severity >= 4 must be required (critical) regardless of protected flag"
    );

    let indet_pub = project_reference_situation(indet_situation, &test_spec(10_000))?;
    let unmitigated_item = indet_pub
        .context_pack
        .items
        .iter()
        .find(|i| i.item_id == unmitigated_item_id);
    assert!(
        unmitigated_item.is_some(),
        "High-severity unprotected world must be present in context pack"
    );
    let item = unmitigated_item.ok_or(ReferenceError::InvalidSpec("missing_unmitigated_item"))?;
    assert_eq!(item.kind, "protected_world");
    indet_pub.verify()?;

    // Contrast with a low-loss unprotected world (consequence_severity < 4 and protected = false):
    // In a Rejected event, compile_reference_situation emits candidate-rejected with severity 1, protected false.
    let (rej_decision, rej_receipt) = harness.publish_rejected_decision("f7-rej")?;
    let rej_req = test_request(&rej_decision, &rej_receipt, None, BTreeSet::new())?;
    let rej_situation = compile_reference_situation(rej_req, &harness.authority)?;
    let rej_envelope = &rej_situation.capsule.frame.world_envelope;

    let rejected_world = rej_envelope
        .alternatives
        .iter()
        .find(|w| w.world_id.contains("candidate-rejected"))
        .ok_or(ReferenceError::InvalidSpec("missing_rejected_world"))?;
    assert_eq!(rejected_world.consequence_severity, 1);
    assert!(!rejected_world.protected);

    let rej_required = required_context_item_ids(&rej_situation)?;
    let rejected_item_id = format!("context:world:{}", rejected_world.world_id);
    assert!(
        !rej_required.contains(&rejected_item_id),
        "A world with consequence_severity < 4 and protected = false must NOT be required"
    );

    let rej_pub = project_reference_situation(rej_situation, &test_spec(10_000))?;
    let rejected_item = rej_pub
        .context_pack
        .items
        .iter()
        .find(|i| i.item_id == rejected_item_id);
    assert!(
        rejected_item.is_some(),
        "Rejected event candidate world present in context pack under ample budget"
    );
    let r_item = rejected_item.ok_or(ReferenceError::InvalidSpec("missing_rejected_item"))?;
    assert_eq!(r_item.kind, "possible_world");
    rej_pub.verify()?;

    // Synthetic differential check: low-severity unprotected world presence under ample budget
    let high_severity_unprotected = PossibleWorld {
        world_id: "world:high-loss-unprotected".to_owned(),
        description: "High loss world with protected = false.".to_owned(),
        claim_ids: BTreeSet::from(["claim:presence".to_owned()]),
        evidence: vec![ContentDigest::sha256(b"ev1")],
        consequence_severity: 4,
        protected: false,
    };
    let low_severity_unprotected = PossibleWorld {
        world_id: "world:low-loss-unprotected".to_owned(),
        description: "Low loss world with protected = false.".to_owned(),
        claim_ids: BTreeSet::from(["claim:presence".to_owned()]),
        evidence: vec![ContentDigest::sha256(b"ev2")],
        consequence_severity: 3,
        protected: false,
    };

    let syn = synthetic_situation(
        vec![
            high_severity_unprotected.clone(),
            low_severity_unprotected.clone(),
        ],
        Vec::new(),
        Vec::new(),
    )?;

    let required = required_context_item_ids(&syn)?;
    assert!(
        required.contains("context:world:world:high-loss-unprotected"),
        "A world with consequence_severity >= 4 must be required (critical) regardless of protected flag"
    );
    assert!(
        !required.contains("context:world:world:low-loss-unprotected"),
        "A world with consequence_severity < 4 and protected = false must NOT be required"
    );

    let syn_pub = project_reference_situation(syn, &test_spec(10_000))?;
    let high_loss_item = syn_pub
        .context_pack
        .items
        .iter()
        .find(|i| i.item_id == "context:world:world:high-loss-unprotected");
    assert!(
        high_loss_item.is_some(),
        "High-severity world must be present in context pack"
    );
    let item = high_loss_item.ok_or(ReferenceError::InvalidSpec("missing_high_loss_item"))?;
    assert_eq!(item.kind, "protected_world");

    let low_loss_item = syn_pub
        .context_pack
        .items
        .iter()
        .find(|i| i.item_id == "context:world:world:low-loss-unprotected");
    assert!(
        low_loss_item.is_some(),
        "Low-severity world present under ample budget"
    );
    let low_item = low_loss_item.ok_or(ReferenceError::InvalidSpec("missing_low_loss_item"))?;
    assert_eq!(low_item.kind, "possible_world");
    syn_pub.verify()?;

    harness.cleanup();
    Ok(())
}

// ---------------------------------------------------------------------------
// Review-391 Finding 1: Unknown knowledge cells preserved in context pack
// ---------------------------------------------------------------------------

#[test]
fn test_f1_unknown_knowledge_cell_is_preserved_in_context_pack() -> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("f1-unknown")?;
    // A rejected policy decision produces an uncertified absence claim with KnowledgeState::Unknown
    let (decision, receipt) = harness.publish_rejected_decision("f1-unknown")?;
    let req = test_request(&decision, &receipt, None, BTreeSet::new())?;
    let situation = compile_reference_situation(req, &harness.authority)?;

    // Verify pre-condition: the situation contains the uncertified absence claim with KnowledgeState::Unknown
    let absence_cell = situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|c| c.claim_id().contains("absence"))
        .ok_or(ReferenceError::InvalidSpec("missing_absence_cell"))?;
    assert_eq!(
        absence_cell.knowledge_state(),
        KnowledgeState::Unknown,
        "Absence claim must have KnowledgeState::Unknown"
    );

    let absence_context_id = format!("context:epistemic:{}", absence_cell.claim_id());

    // Invariant: required_context_item_ids must include the Unknown cell as a critical epistemic boundary
    let required = required_context_item_ids(&situation)?;
    assert!(
        required.contains(&absence_context_id),
        "required_context_item_ids must include Unknown knowledge cell"
    );

    // Project situation to publication
    let pub_res = project_reference_situation(situation, &test_spec(10_000))?;

    // Invariant: context pack must contain the Unknown cell as epistemic_boundary
    let unknown_item = pub_res
        .context_pack
        .items
        .iter()
        .find(|i| i.item_id == absence_context_id);
    assert!(
        unknown_item.is_some(),
        "Unknown knowledge cell must be preserved in context pack as epistemic_boundary!"
    );
    let item = unknown_item.ok_or(ReferenceError::InvalidSpec("missing_unknown_item"))?;
    assert_eq!(item.kind, "epistemic_boundary");
    assert_eq!(item.epistemic_state, KnowledgeState::Unknown);

    // Invariant: zero critical items omitted
    assert_eq!(
        pub_res
            .compression_receipt
            .critical_preservation
            .omitted_critical_items,
        0
    );
    pub_res.verify()?;

    harness.cleanup();
    Ok(())
}

// ---------------------------------------------------------------------------
// Review-391 Finding 2: Unavailable hard clamp preserves unsafe_worlds & branch predicate
// ---------------------------------------------------------------------------

#[test]
fn test_f2_unavailable_hard_clamp_preserves_unsafe_worlds_and_branch_predicate()
-> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("f2-clamp")?;
    let (decision, receipt) = harness.publish_corroborated_decision("f2-clamp")?;

    // Missing capability:alert.prepare -> prepare affordance is clamped to Unavailable
    let req = test_request(&decision, &receipt, None, BTreeSet::new())?;
    let situation = compile_reference_situation(req, &harness.authority)?;

    let prepare = situation
        .capsule
        .affordances
        .iter()
        .find(|a| a.affordance_id == "affordance:alert:prepare")
        .ok_or(ReferenceError::InvalidSpec("missing_prepare"))?;

    assert_eq!(prepare.class, AffordanceClass::Unavailable);

    // Invariant: Clamping to Unavailable must NOT erase unsafe_worlds or branch_predicate
    assert!(
        !prepare.unsafe_worlds.is_empty(),
        "unsafe_worlds must NOT be erased by project_affordance when clamped to Unavailable!"
    );
    assert!(
        prepare.branch_predicate.is_some(),
        "branch_predicate must NOT be erased by project_affordance when clamped to Unavailable!"
    );

    let presence_world = format!("world:event:{}:present", decision.event.event_id.as_str());
    assert_eq!(
        prepare.branch_predicate,
        Some(presence_world),
        "branch_predicate must preserve the target presence world"
    );

    // supported_worlds must be empty since capability is missing
    assert!(
        prepare.supported_worlds.is_empty(),
        "supported_worlds must be empty when required capability is missing"
    );

    // Affordance must validate against the world envelope
    prepare.validate_against(&situation.capsule.frame.world_envelope)?;

    let pub_res = project_reference_situation(situation, &test_spec(10_000))?;
    pub_res.verify()?;

    harness.cleanup();
    Ok(())
}

/// Publishes one decision from `labels`, compiles its situation, and projects it.
fn labelled_publication(
    harness: &mut TestHarness,
    name: &str,
    labels: &[(MockSemanticLabel, &str)],
) -> Result<ReferenceSituationPublication, Box<dyn Error>> {
    let mut observations = Vec::new();
    for (index, (label, domain)) in labels.iter().enumerate() {
        observations.push(harness.observation(
            name,
            &format!("lane{index}"),
            90 + index as u64,
            domain,
            *label,
        )?);
    }
    let decision = evaluate_unknown_presence(
        EventId::parse(format!("event:situation-inv:{name}"))?,
        observations,
    )?;
    let receipt = publish_reference_event(&decision, &mut harness.objects, &mut harness.authority)?;
    let situation = compile_reference_situation(
        test_request(&decision, &receipt, None, BTreeSet::new())?,
        &harness.authority,
    )?;
    Ok(project_reference_situation(situation, &test_spec(10_000))?)
}

/// Publishes revision 1 of one event (PersonLike on `power:alpha`) and projects its situation,
/// then publishes revision 2 of the SAME event, adding `second` on `power:beta`, and projects that.
fn revised_publications(
    harness: &mut TestHarness,
    name: &str,
    second: MockSemanticLabel,
) -> Result<(ReferenceSituationPublication, ReferenceSituationPublication), Box<dyn Error>> {
    let event_id = EventId::parse(format!("event:situation-inv:{name}"))?;
    let person = harness.observation(
        name,
        "lane0",
        90,
        "power:alpha",
        MockSemanticLabel::PersonLike,
    )?;
    let first = evaluate_unknown_presence(event_id.clone(), vec![person])?;
    let first_receipt =
        publish_reference_event(&first, &mut harness.objects, &mut harness.authority)?;
    let basis = project_reference_situation(
        compile_reference_situation(
            test_request(&first, &first_receipt, None, BTreeSet::new())?,
            &harness.authority,
        )?,
        &test_spec(10_000),
    )?;

    let person = harness.observation(
        name,
        "lane1",
        91,
        "power:alpha",
        MockSemanticLabel::PersonLike,
    )?;
    let other = harness.observation(name, "lane2", 92, "power:beta", second)?;
    let ReferencePolicyDecision {
        event: candidate,
        action,
    } = evaluate_unknown_presence(event_id, vec![person, other])?;
    let revised = first.event.supersede(
        EventSupersedeParams {
            state: candidate.state,
            kind: candidate.kind,
            interval: candidate.interval,
            uncertainty_reason: candidate.uncertainty_reason,
            zone_ids: candidate.zone_ids,
            track_ids: candidate.track_ids,
            probability: candidate.probability,
            evidence: candidate.evidence,
            model_receipts: candidate.model_receipts,
            decision_path: candidate.decision_path,
        },
        std::slice::from_ref(&first.event),
    )?;
    let revision = ReferencePolicyDecision {
        event: revised,
        action,
    };
    let revision_receipt =
        publish_reference_event(&revision, &mut harness.objects, &mut harness.authority)?;
    let result = project_reference_situation(
        compile_reference_situation(
            test_request(&revision, &revision_receipt, None, BTreeSet::new())?,
            &harness.authority,
        )?,
        &test_spec(10_000),
    )?;
    Ok((basis, result))
}

fn physical_claim_ids(publication: &ReferenceSituationPublication) -> Vec<String> {
    publication
        .situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .filter(|cell| cell.claim_id().ends_with(":unknown-presence"))
        .map(|cell| cell.claim_id().to_owned())
        .collect()
}

#[test]
fn tamper_result_after_person_basis_is_a_critical_contradiction_delta() -> Result<(), Box<dyn Error>>
{
    let mut harness = TestHarness::new("tamper-delta")?;
    let (basis, tampered) =
        revised_publications(&mut harness, "tamper-rev", MockSemanticLabel::TamperLike)?;
    // One event: revision 2 supersedes revision 1 under the same physical claim identity.
    assert_eq!(physical_claim_ids(&basis).len(), 1);
    assert_eq!(physical_claim_ids(&basis), physical_claim_ids(&tampered));
    // The tamper risk is typed in the revised situation.
    let frame = &tampered.situation.capsule.frame;
    assert!(frame.knowledge_cells.iter().any(|cell| {
        cell.claim_id().ends_with(":sensor-integrity") && !cell.contradictions().is_empty()
    }));
    assert!(
        frame
            .world_envelope
            .adversarial_residuals
            .iter()
            .any(|world| world.protected && world.world_id.ends_with(":sensor-tamper"))
    );
    // A new tamper signal is a contradiction delta: never silence, never coalescible.
    let delta = classify_reference_meaningful_delta(&basis, &tampered)?;
    assert!(
        delta.classes.contains(&MeaningfulDeltaClass::Contradiction),
        "{:?}",
        delta.classes
    );
    assert!(delta.is_non_coalescible());
    assert_eq!(delta.priority, DeltaPriority::Critical);
    delta.validate()?;

    // Control: a revision adding an unknown finding instead is not a contradiction delta.
    let (control_basis, unknown) =
        revised_publications(&mut harness, "unknown-rev", MockSemanticLabel::Unknown)?;
    let control = classify_reference_meaningful_delta(&control_basis, &unknown)?;
    assert!(
        !control
            .classes
            .contains(&MeaningfulDeltaClass::Contradiction),
        "{:?}",
        control.classes
    );
    harness.cleanup();
    Ok(())
}

#[test]
fn cleared_tamper_is_reported_as_a_material_change_not_silence() -> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("tamper-cleared")?;
    let tampered = labelled_publication(
        &mut harness,
        "cleared-basis",
        &[
            (MockSemanticLabel::PersonLike, "power:alpha"),
            (MockSemanticLabel::TamperLike, "power:beta"),
        ],
    )?;
    let clean = labelled_publication(
        &mut harness,
        "cleared-result",
        &[(MockSemanticLabel::PersonLike, "power:alpha")],
    )?;
    // Retiring the tamper world is a material change, never silence. It is not a contradiction
    // delta: that class must be witnessed by a changed result cell, and a retired claim has none.
    let delta = classify_reference_meaningful_delta(&tampered, &clean)?;
    assert!(
        delta.classes.contains(&MeaningfulDeltaClass::MaterialState),
        "{:?}",
        delta.classes
    );
    assert!(
        !delta
            .classes
            .contains(&MeaningfulDeltaClass::NoMeaningfulChange),
        "{:?}",
        delta.classes
    );
    assert!(delta.silence_certificate.is_none());
    delta.validate()?;
    harness.cleanup();
    Ok(())
}

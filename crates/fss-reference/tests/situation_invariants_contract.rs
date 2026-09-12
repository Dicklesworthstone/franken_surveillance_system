#![forbid(unsafe_code)]
//! Integration contract tests verifying reference situation invariants:
//! - F2: `required_context_item_ids` and `ReferenceSituationPublication::verify` propagate errors.
//! - F3: Hard clamps (`Unavailable` / `Blocked` affordances) are included in the context pack as critical items.
//! - F6: Alert `prepare` and `commit` affordances are `Conditional`, not `Robust`, and name the presence world.
//! - F7: `Corroborated` state retains a protected adversarial residual world, and consequence severity >= 4 is critical.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;

use fss_core::{
    ActionAffordance, AffordanceClass, BudgetVector, CapsuleId, CaptureInterval, Completeness,
    ContentDigest, ContractBasis, ContractBasisRegistryBytes, ContractError, EffectJournal,
    EventId, IdempotencyKey, KnowledgeCell, KnowledgeState, LedgerAnchor, MissionId, ObligationId,
    OperationId, PossibleWorld, PrincipalId, ProbabilityInterval, ProvenanceClass,
    ResourcePressure, SensorId, SessionId, SituationCapsule, SituationFrame, TimestampNs,
    WorldEnvelope,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};
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

struct TestHarness {
    path: std::path::PathBuf,
    objects: InMemoryObjectStore,
    authority: DurableReferenceLedger,
}

impl TestHarness {
    fn new(name: &str) -> Result<Self, Box<dyn Error>> {
        let path = std::env::temp_dir().join(format!(
            "fss-ref-situation-inv-{}-{name}.journal",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        Ok(Self {
            authority: DurableReferenceLedger::open(
                &path,
                format!("site:situation-inv:{name}"),
                IncompleteTailPolicy::Reject,
            )?,
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

    fn cleanup(self) {
        let path = self.path.clone();
        drop(self);
        let _ = fs::remove_file(path);
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
    ReferenceProjectionSpec {
        view_id: "AVIEW-001".to_owned(),
        available_resources: BudgetVector::builder()
            .latency_ms(10_000)
            .tokens(20_000)
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
        decision,
        event_receipt,
        alert_plan,
        alert_outcome: None,
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
    let cell = KnowledgeCell {
        claim_id: "claim:presence".to_owned(),
        statement: "Synthetic presence claim.".to_owned(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![evidence],
        contradictions: Vec::new(),
        valid_until: None,
    };
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
    };
    capsule.validate()?;
    Ok(ReferenceSituation {
        capsule,
        proof_roots: BTreeSet::from([evidence]),
    })
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

    // Also test an explicitly Blocked affordance
    let blocked_affordance = ActionAffordance {
        affordance_id: "affordance:policy:restricted".to_owned(),
        operation: "dispatch".to_owned(),
        target: "fss://policy/restricted".to_owned(),
        rationale: "Action blocked by safety policy constraint.".to_owned(),
        class: AffordanceClass::Blocked,
        supported_worlds: BTreeSet::new(),
        unsafe_worlds: BTreeSet::new(),
        required_capabilities: BTreeSet::from(["capability:admin".to_owned()]),
        cost: BudgetVector::ZERO,
        reversible: false,
        branch_predicate: None,
    };
    let synthetic = synthetic_situation(
        vec![PossibleWorld {
            world_id: "world:base".to_owned(),
            description: "Base world.".to_owned(),
            claim_ids: BTreeSet::from(["claim:presence".to_owned()]),
            evidence: vec![ContentDigest::sha256(b"ev")],
            consequence_severity: 2,
            protected: false,
        }],
        vec![blocked_affordance],
        Vec::new(),
    )?;
    let synthetic_pub = project_reference_situation(synthetic, &test_spec(10_000))?;
    assert!(
        synthetic_pub
            .context_pack
            .items
            .iter()
            .any(|i| i.item_id == "context:hard_clamp:affordance:policy:restricted"),
        "Blocked affordance must also appear as hard_clamp in context pack"
    );
    synthetic_pub.verify()?;

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

    // Invariant F7-2: High-loss world with consequence_severity >= 4 is critical REGARDLESS of protected flag
    let high_severity_unprotected = PossibleWorld {
        world_id: "world:high-loss-unprotected".to_owned(),
        description: "High loss world with protected = false.".to_owned(),
        claim_ids: BTreeSet::from(["claim:presence".to_owned()]),
        evidence: vec![ContentDigest::sha256(b"ev1")],
        consequence_severity: 4,
        protected: false, // NOT PROTECTED, but severity >= 4!
    };
    let low_severity_unprotected = PossibleWorld {
        world_id: "world:low-loss-unprotected".to_owned(),
        description: "Low loss world with protected = false.".to_owned(),
        claim_ids: BTreeSet::from(["claim:presence".to_owned()]),
        evidence: vec![ContentDigest::sha256(b"ev2")],
        consequence_severity: 3,
        protected: false, // NOT PROTECTED, severity < 4
    };

    let syn = synthetic_situation(
        vec![
            high_severity_unprotected.clone(),
            low_severity_unprotected.clone(),
        ],
        Vec::new(),
        Vec::new(),
    )?;

    // required_context_item_ids must include the high-severity world because severity >= 4 makes it critical
    let required = required_context_item_ids(&syn)?;
    assert!(
        required.contains("context:world:world:high-loss-unprotected"),
        "A world with consequence_severity >= 4 must be required (critical) regardless of protected flag"
    );
    assert!(
        !required.contains("context:world:world:low-loss-unprotected"),
        "A world with consequence_severity < 4 and protected = false must NOT be required"
    );

    // Context pack from projection must contain high-severity world as protected_world kind
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

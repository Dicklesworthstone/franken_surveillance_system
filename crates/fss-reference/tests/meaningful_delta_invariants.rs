#![forbid(unsafe_code)]
//! Verification of meaningful delta invariants: silence certificates under degraded coverage,
//! terminal transition non-coalescing, and plan invalidation on Estimated and Known premises.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;

use fss_core::{
    ActionAffordance, AffordanceClass, BudgetVector, CapsuleId, CaptureInterval, Completeness,
    ContentDigest, ContractBasis, ContractBasisRegistryBytes, ContractError, CoverageContinuity,
    CoverageStopReason, CoverageWitness, DeltaPriority, EffectJournal, EventId,
    HypothesisDisposition, IdempotencyKey, KnowledgeCell, KnowledgeState, LedgerAnchor,
    MeaningfulDeltaClass, MissionId, MissionLifecycleState, ObligationId, OperationId, PrincipalId,
    ProbabilityInterval, ProvenanceClass, ResourcePressure, SensorId, SessionId,
    SilenceCertificate, SituationCapsule, SituationFrame, TimestampNs, WorldEnvelope,
};

use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};
use fss_reference::{
    DeliveryPlan, MockModelScript, MockModelSpec, MockSemanticLabel, PrepareAlertParams,
    ReferenceAlertPlan, ReferenceAlertProvider, ReferenceError, ReferenceEventReceipt,
    ReferenceModelObservation, ReferencePolicyDecision, ReferenceProjectionSpec,
    ReferenceProviderBehavior, ReferenceSituation, ReferenceSituationPublication,
    ReferenceSituationRequest, VirtualCameraSpec, classify_reference_meaningful_delta,
    compile_reference_situation, compile_reference_situation_with_operation_receipt,
    dispatch_reference_alert, evaluate_unknown_presence, execute_mock_model,
    observe_reference_alert, prepare_reference_alert, project_reference_situation,
    publish_reference_alert_outcome, publish_reference_event, run_reference_capture,
    verify_reference_alert,
};

#[derive(Clone, Debug)]
struct Variant {
    sequence: u64,
    completeness: Completeness,
    coverage: BTreeSet<String>,
    premise_state: KnowledgeState,
    premise_statement: String,
    premise_contradictions: Vec<ContentDigest>,
    premise_hypothesis: Option<HypothesisDisposition>,
    include_affordance: bool,
    obligations: Vec<ObligationId>,
    effect_state: Option<KnowledgeState>,
    effect_statement: Option<String>,
    pressure: ResourcePressure,
    degraded_dimensions: BTreeSet<String>,
    mission_statement: String,
    mission_state: Option<MissionLifecycleState>,
    custom_cells: Vec<KnowledgeCell>,
    custom_revision: Option<u64>,
    contract_basis: Option<ContractBasis>,
}

impl Variant {
    fn baseline() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            sequence: 1,
            completeness: Completeness::Complete,
            coverage: BTreeSet::from([
                "fss://coverage/alpha".to_owned(),
                "fss://coverage/beta".to_owned(),
            ]),
            premise_state: KnowledgeState::Known,
            premise_statement: "The reference premise has the current typed state.".to_owned(),
            premise_contradictions: Vec::new(),
            premise_hypothesis: None,
            include_affordance: true,
            obligations: Vec::new(),
            effect_state: None,
            effect_statement: None,
            pressure: ResourcePressure::Nominal,
            degraded_dimensions: BTreeSet::new(),
            mission_statement: "The reference mission remains active.".to_owned(),
            mission_state: Some(MissionLifecycleState::Active),
            custom_cells: Vec::new(),
            custom_revision: None,
            contract_basis: None,
        })
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
        let run_dir = create_exclusive_run_dir("fss-ref-meaningful-delta", name)?;
        let path = run_dir.join(format!("{name}.journal"));
        Self::open_at_path(run_dir, path, name)
    }

    fn open_at_path(
        run_dir: std::path::PathBuf,
        path: std::path::PathBuf,
        name: &str,
    ) -> Result<Self, Box<dyn Error>> {
        if path.exists() {
            return Err(format!(
                "TestHarness refused to silently reuse or overwrite existing journal at {path:?}"
            )
            .into());
        }
        let authority = DurableReferenceLedger::open(
            &path,
            format!("site:meaningful-delta-inv:{name}"),
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
            path,
            objects: InMemoryObjectStore::new(ObjectLimits::new(2048, 32 * 1024 * 1024)),
            authority,
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
            capture_id: CapsuleId::parse(format!(
                "capture:meaningful-delta-inv:{test_name}:{lane}"
            ))?,
            sensor_id: SensorId::parse(format!("sensor:meaningful-delta-inv:{test_name}:{lane}"))?,
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
            format!("mock:meaningful-delta-inv:{test_name}:{lane}:v1"),
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
            EventId::parse(format!("event:meaningful-delta-inv:{name}"))?,
            vec![obs_a, obs_b],
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
            50,
            "power:alpha",
            MockSemanticLabel::AnimalLike,
        )?;
        let decision = evaluate_unknown_presence(
            EventId::parse(format!("event:meaningful-delta-inv:{name}"))?,
            vec![obs],
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

fn test_spec(target_tokens: u64) -> Result<ReferenceProjectionSpec, Box<dyn Error>> {
    let available_tokens = target_tokens.saturating_add(10_000).max(20_000);
    Ok(ReferenceProjectionSpec {
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
            .build()?,
        reserved_resources: BudgetVector::builder()
            .latency_ms(100)
            .tokens(100)
            .bytes(1_000)
            .storage_operations(1)
            .build()?,
        pressure: ResourcePressure::Nominal,
        degraded_dimensions: BTreeSet::new(),
        target_tokens,
    })
}

fn test_request<'a>(
    decision: &'a ReferencePolicyDecision,
    event_receipt: &'a ReferenceEventReceipt,
    alert_plan: Option<&'a ReferenceAlertPlan>,
    capabilities: BTreeSet<String>,
) -> Result<ReferenceSituationRequest<'a>, ContractError> {
    Ok(ReferenceSituationRequest {
        mission_id: MissionId::parse("mission:meaningful-delta-inv:test")?,
        session_id: SessionId::parse("session:meaningful-delta-inv:test")?,
        principal_id: PrincipalId::parse("principal:meaningful-delta-inv:test")?,
        objective_id: "objective:meaningful-delta-inv".to_owned(),
        revision: 1,
        contract_basis: test_basis(),
        previous_anchor: None,
        created_at: TimestampNs(1_000),
        decision,
        event_receipt,
        alert_plan,
        alert_outcome: None,
        coverage_witness: None,
        available_capabilities: capabilities,
    })
}

fn publication(variant: &Variant) -> Result<ReferenceSituationPublication, Box<dyn Error>> {
    let mut anchor = LedgerAnchor::genesis("site:meaningful-delta");
    anchor.commit_sequence = variant.sequence;
    let evidence = ContentDigest::sha256(b"meaningful-delta-evidence");
    let world = fss_core::PossibleWorld {
        world_id: "world:meaningful-delta:protected".to_owned(),
        description: "A protected world remains decision-relevant.".to_owned(),
        claim_ids: BTreeSet::from(["claim:premise".to_owned()]),
        evidence: vec![evidence],
        consequence_severity: 5,
        protected: true,
    };
    let world_envelope = WorldEnvelope {
        envelope_id: format!("world-envelope:meaningful-delta:{}", variant.sequence),
        objective_id: "objective:meaningful-delta".to_owned(),
        anchor: anchor.clone(),
        nominal_claim_ids: BTreeSet::from(["claim:premise".to_owned()]),
        certified_core_claim_ids: BTreeSet::new(),
        alternatives: vec![world],
        adversarial_residuals: Vec::new(),
        common_invariants: BTreeSet::from(["invariant:no-blind-effect".to_owned()]),
        coverage_boundary_handles: variant.coverage.clone(),
    };
    let retained_worlds = world_envelope.world_ids();
    let affordances = if variant.include_affordance {
        vec![ActionAffordance {
            affordance_id: "affordance:meaningful-delta:investigate".to_owned(),
            operation: "investigate".to_owned(),
            target: "fss://event/meaningful-delta/evidence".to_owned(),
            rationale: "Acquire independent evidence.".to_owned(),
            class: AffordanceClass::Probe,
            supported_worlds: retained_worlds,
            unsafe_worlds: BTreeSet::new(),
            required_capabilities: BTreeSet::from(["capability:evidence.query".to_owned()]),
            cost: BudgetVector::builder()
                .latency_ms(100)
                .tokens(50)
                .bytes(1_024)
                .cpu_millis(10)
                .accelerator_millis(5)
                .energy_millijoules(20)
                .privacy_exposure(0.1)
                .build()?,
            reversible: true,
            branch_predicate: None,
        }]
    } else {
        Vec::new()
    };
    let mut knowledge_cells = vec![KnowledgeCell {
        claim_id: "claim:premise".to_owned(),
        statement: variant.premise_statement.clone(),
        knowledge_state: variant.premise_state,
        provenance: ProvenanceClass::Derived,
        hypothesis: variant.premise_hypothesis,
        evidence: vec![evidence],
        contradictions: variant.premise_contradictions.clone(),
        valid_until: None,
        state_basis: None,
    }];
    if let Some(effect_state) = variant.effect_state {
        let statement = match &variant.effect_statement {
            Some(custom) => custom.clone(),
            None => match effect_state {
                KnowledgeState::Indeterminate => {
                    "The external effect may have happened and requires reconciliation.".to_owned()
                }
                KnowledgeState::Known => {
                    "Alert delivery is terminally verified by retained provider proof.".to_owned()
                }
                _ => "The external effect has another explicit typed state.".to_owned(),
            },
        };
        knowledge_cells.push(KnowledgeCell {
            claim_id: "claim:effect:meaningful-delta:outcome".to_owned(),
            statement,
            knowledge_state: effect_state,
            provenance: ProvenanceClass::Observed,
            hypothesis: None,
            evidence: vec![ContentDigest::sha256(b"effect-outcome")],
            contradictions: Vec::new(),
            valid_until: None,
            state_basis: None,
        });
    }
    knowledge_cells.extend(variant.custom_cells.iter().cloned());
    knowledge_cells.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));

    let next = affordances
        .iter()
        .map(|affordance| affordance.affordance_id.clone())
        .collect();
    let frame = SituationFrame {
        frame_id: format!("frame:meaningful-delta:{}", variant.sequence),
        objective_id: "objective:meaningful-delta".to_owned(),
        anchor: anchor.clone(),
        world_envelope,
        knowledge_cells,
        now: vec![variant.mission_statement.clone()],
        changed: Vec::new(),
        why: vec!["The typed evidence frontier determines the available control.".to_owned()],
        unknown: Vec::new(),
        at_risk: Vec::new(),
        next,
        evidence_handles: BTreeSet::from([format!("fss://proof/{evidence}")]),
    };
    let revision = variant.custom_revision.unwrap_or(variant.sequence);
    let capsule = SituationCapsule {
        capsule_id: format!("situation:meaningful-delta:{}", variant.sequence),
        revision,
        contract_basis: variant.contract_basis.clone().unwrap_or_else(test_basis),
        mission_id: MissionId::parse("mission:meaningful-delta")?,
        session_id: SessionId::parse("session:meaningful-delta")?,
        principal_id: PrincipalId::parse("principal:meaningful-delta")?,
        anchor,
        previous_anchor: None,
        frame,
        obligations: variant.obligations.clone(),
        affordances,
        completeness: variant.completeness,
        created_at: TimestampNs(1_000 + i128::from(variant.sequence)),
        mission_state: variant.mission_state,
    };
    capsule.validate()?;
    let mut proof_roots = BTreeSet::from([evidence]);
    proof_roots.extend(variant.premise_contradictions.iter().cloned());
    if variant.effect_state.is_some() {
        proof_roots.insert(ContentDigest::sha256(b"effect-outcome"));
    }
    for cell in &variant.custom_cells {
        proof_roots.extend(cell.evidence.iter().cloned());
        proof_roots.extend(cell.contradictions.iter().cloned());
    }
    let situation = ReferenceSituation {
        capsule,
        proof_roots,
    };
    project_reference_situation(
        situation,
        &ReferenceProjectionSpec {
            view_id: "AVIEW-001".to_owned(),
            available_resources: BudgetVector::builder()
                .latency_ms(10_000)
                .tokens(50_000)
                .bytes(2_000_000)
                .model_calls(10)
                .cpu_millis(10_000)
                .accelerator_millis(10_000)
                .energy_millijoules(1_000_000)
                .network_bytes(1_000_000)
                .storage_operations(10_000)
                .privacy_exposure(10.0)
                .operator_attention_seconds(1_000.0)
                .build()?,
            reserved_resources: BudgetVector::builder()
                .latency_ms(100)
                .tokens(100)
                .bytes(1_000)
                .storage_operations(1)
                .build()?,
            pressure: variant.pressure,
            degraded_dimensions: variant.degraded_dimensions.clone(),
            target_tokens: 25_000,
        },
    )
    .map_err(|error| -> Box<dyn Error> { Box::new(error) })
}

/// F1: A silence certificate must never be issued under degraded coverage or coverage gaps.
#[test]
fn test_f1_silence_certificate_rejected_when_coverage_degraded() -> Result<(), Box<dyn Error>> {
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.completeness = Completeness::Partial;

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.completeness = Completeness::Partial;

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;

    assert!(
        delta.silence_certificate.is_none(),
        "Silence certificate must not be issued during degraded coverage!"
    );
    assert!(
        delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss),
        "Degraded-but-unchanged comparison must report CoverageLoss!"
    );
    assert_ne!(
        delta.classes,
        BTreeSet::from([MeaningfulDeltaClass::NoMeaningfulChange]),
        "NoMeaningfulChange must never certify silence during degraded coverage!"
    );
    assert!(
        delta.is_non_coalescible(),
        "CoverageLoss must be non-coalescible!"
    );
    delta.validate()?;
    Ok(())
}

/// F4: Terminal event transition (e.g. candidate rejection or resolution) emits TerminalTransition
/// and is non-coalescible, proven by a coalescing attempt that is rejected.
#[test]
fn test_f4_terminal_event_transition_is_non_coalescible() -> Result<(), Box<dyn Error>> {
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.premise_hypothesis = Some(HypothesisDisposition::Supported);

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.premise_hypothesis = Some(HypothesisDisposition::Refuted);

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    let delta1 = classify_reference_meaningful_delta(&pub1, &pub2)?;

    assert!(
        delta1
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "Terminal event rejection must emit TerminalTransition!"
    );
    assert!(
        delta1.is_non_coalescible(),
        "Terminal transition must be non-coalescible!"
    );
    assert_eq!(delta1.priority, DeltaPriority::Critical);

    let mut v3 = Variant::baseline()?;
    v3.sequence = 3;
    v3.pressure = ResourcePressure::Elevated;
    let pub3 = publication(&v3)?;
    let delta2 = classify_reference_meaningful_delta(&pub2, &pub3)?;

    let can_coalesce = delta1.can_coalesce_with(&delta2)?;
    assert!(
        !can_coalesce,
        "TerminalTransition must never coalesce with subsequent deltas!"
    );
    let coalesce_result = delta1.coalesce(
        &delta2,
        "delta:coalesced",
        "continuation:coalesced",
        ContentDigest::sha256(b"coalesced"),
    );
    assert!(
        coalesce_result.is_err(),
        "Coalescing a terminal transition delta must fail!"
    );

    delta1.validate()?;
    Ok(())
}

/// F4: Obligation terminalization (active obligation resolved/removed) emits TerminalTransition.
#[test]
fn test_f4_obligation_terminalization_emits_terminal_transition() -> Result<(), Box<dyn Error>> {
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.obligations = vec![ObligationId::parse("obligation:test:001")?];

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.obligations.clear();

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;

    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "Obligation terminalization must emit TerminalTransition!"
    );
    assert!(
        delta.classes.contains(&MeaningfulDeltaClass::Obligation),
        "Obligation transition must emit Obligation class!"
    );
    assert!(
        delta.is_non_coalescible(),
        "Terminal obligation delta must be non-coalescible!"
    );
    let mut v3 = Variant::baseline()?;
    v3.sequence = 3;
    v3.pressure = ResourcePressure::Elevated;
    let pub3 = publication(&v3)?;
    let delta2 = classify_reference_meaningful_delta(&pub2, &pub3)?;
    assert!(
        delta
            .coalesce(
                &delta2,
                "delta:coalesced",
                "continuation:coalesced",
                ContentDigest::sha256(b"coalesced"),
            )
            .is_err()
    );
    delta.validate()?;
    Ok(())
}

/// F4: Effect terminalization emits TerminalTransition and is non-coalescible.
#[test]
fn test_f4_effect_terminalization_emits_terminal_transition() -> Result<(), Box<dyn Error>> {
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.effect_state = Some(KnowledgeState::Indeterminate);

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.effect_state = Some(KnowledgeState::Known);

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;

    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "Effect terminalization must emit TerminalTransition!"
    );
    assert!(
        delta.is_non_coalescible(),
        "Effect terminal transition must be non-coalescible!"
    );
    let mut v3 = Variant::baseline()?;
    v3.sequence = 3;
    v3.pressure = ResourcePressure::Elevated;
    let pub3 = publication(&v3)?;
    let delta2 = classify_reference_meaningful_delta(&pub2, &pub3)?;
    assert!(
        delta
            .coalesce(
                &delta2,
                "delta:coalesced",
                "continuation:coalesced",
                ContentDigest::sha256(b"coalesced"),
            )
            .is_err()
    );
    delta.validate()?;
    Ok(())
}

/// F4: Mission terminalization (mission active -> concluded) emits TerminalTransition.
#[test]
fn test_f4_mission_terminalization_emits_terminal_transition() -> Result<(), Box<dyn Error>> {
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.mission_state = Some(MissionLifecycleState::Active);
    v1.mission_statement = "The reference mission remains active.".to_owned();

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.mission_state = Some(MissionLifecycleState::Closed);
    v2.mission_statement = "The reference mission has concluded.".to_owned();

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;

    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "Mission terminalization must emit TerminalTransition!"
    );
    assert!(
        delta.is_non_coalescible(),
        "Mission terminal transition must be non-coalescible!"
    );
    let mut v3 = Variant::baseline()?;
    v3.sequence = 3;
    v3.pressure = ResourcePressure::Elevated;
    let pub3 = publication(&v3)?;
    let delta2 = classify_reference_meaningful_delta(&pub2, &pub3)?;
    assert!(
        delta
            .coalesce(
                &delta2,
                "delta:coalesced",
                "continuation:coalesced",
                ContentDigest::sha256(b"coalesced"),
            )
            .is_err()
    );
    delta.validate()?;
    Ok(())
}

/// F5: Plan invalidation must be emitted when an Estimated premise degrades or disappears.
#[test]
fn test_f5_plan_invalidation_emitted_for_estimated_premise() -> Result<(), Box<dyn Error>> {
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.premise_state = KnowledgeState::Estimated;

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.premise_state = KnowledgeState::Unknown;

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;

    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::PlanInvalidation),
        "Invalidation of an Estimated premise must emit PlanInvalidation!"
    );
    assert!(
        !delta.invalidated_assumptions.is_empty(),
        "Invalidated assumptions must not be empty!"
    );
    assert!(
        delta
            .invalidated_assumptions
            .iter()
            .any(|a| a.contains("estimated premise claim:premise became unknown")),
        "Invalidated assumption must describe the estimated premise transition!"
    );
    assert!(
        delta.is_non_coalescible(),
        "PlanInvalidation must be non-coalescible!"
    );
    delta.validate()?;
    Ok(())
}

/// F5: Plan invalidation must be emitted when a Known premise degrades to Estimated.
#[test]
fn test_f5_plan_invalidation_emitted_when_known_degrades_to_estimated() -> Result<(), Box<dyn Error>>
{
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.premise_state = KnowledgeState::Known;

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.premise_state = KnowledgeState::Estimated;

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;

    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::PlanInvalidation),
        "Degradation from Known to Estimated must emit PlanInvalidation!"
    );
    assert!(
        !delta.invalidated_assumptions.is_empty(),
        "Invalidated assumptions must not be empty!"
    );
    assert!(
        delta.is_non_coalescible(),
        "PlanInvalidation must be non-coalescible!"
    );
    delta.validate()?;
    Ok(())
}

/// F5: Plan invalidation must be emitted when contradictory evidence attaches to an Estimated premise.
#[test]
fn test_f5_plan_invalidation_emitted_when_estimated_premise_gains_contradictions()
-> Result<(), Box<dyn Error>> {
    let contradiction = ContentDigest::sha256(b"contradictory-evidence");

    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.premise_state = KnowledgeState::Estimated;

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.premise_state = KnowledgeState::Estimated;
    v2.premise_contradictions = vec![contradiction];

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;

    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::PlanInvalidation),
        "Contradictions added to an Estimated premise must emit PlanInvalidation!"
    );
    assert!(
        !delta.invalidated_assumptions.is_empty(),
        "Invalidated assumptions must not be empty when contradictions arise!"
    );
    assert!(
        delta.is_non_coalescible(),
        "PlanInvalidation must be non-coalescible!"
    );
    delta.validate()?;
    Ok(())
}

/// Proven coalescing test: non-critical deltas coalesce, but any delta carrying
/// a terminal transition or plan invalidation is preserved and cannot be coalesced.
#[test]
fn test_coalescing_preserves_terminal_and_invalidation_deltas() -> Result<(), Box<dyn Error>> {
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.pressure = ResourcePressure::Nominal;

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.pressure = ResourcePressure::Elevated;
    v2.degraded_dimensions = BTreeSet::from(["model_calls".to_owned()]);

    let mut v3 = Variant::baseline()?;
    v3.sequence = 3;
    v3.premise_hypothesis = Some(HypothesisDisposition::Refuted);

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    let pub3 = publication(&v3)?;

    let delta_budget = classify_reference_meaningful_delta(&pub1, &pub2)?;
    let delta_terminal = classify_reference_meaningful_delta(&pub2, &pub3)?;

    assert!(!delta_budget.is_non_coalescible());
    assert!(delta_terminal.is_non_coalescible());

    assert!(!delta_budget.can_coalesce_with(&delta_terminal)?);
    assert!(!delta_terminal.can_coalesce_with(&delta_budget)?);

    let result = delta_budget.coalesce(
        &delta_terminal,
        "delta:coalesced",
        "continuation:coalesced",
        ContentDigest::sha256(b"coalesced"),
    );
    assert!(matches!(result, Err(ContractError::EvidenceRequired)));

    Ok(())
}

/// Planted negatives: 'unverified', 'not failed', and 'disclosed' free-text statements
/// must NEVER spoof or trigger a TerminalTransition when typed fields are non-terminal.
#[test]
fn test_planted_negatives_free_text_statements_do_not_spoof_terminal_transition()
-> Result<(), Box<dyn Error>> {
    // Negative 1: Effect cell statement says "unverified" and "not failed", but typed state is Indeterminate.
    let mut v1_base = Variant::baseline()?;
    v1_base.sequence = 1;
    v1_base.effect_state = Some(KnowledgeState::Indeterminate);
    v1_base.effect_statement = Some("Alert delivery is pending adapter response.".to_owned());

    let mut v1_spoof = Variant::baseline()?;
    v1_spoof.sequence = 2;
    v1_spoof.effect_state = Some(KnowledgeState::Indeterminate);
    v1_spoof.effect_statement =
        Some("Alert delivery is unverified and not failed, pending adapter response.".to_owned());

    let pub1_base = publication(&v1_base)?;
    let pub1_spoof = publication(&v1_spoof)?;
    let delta1 = classify_reference_meaningful_delta(&pub1_base, &pub1_spoof)?;

    assert!(
        !delta1
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "Planted negative: 'unverified' and 'not failed' statements must NOT produce TerminalTransition!"
    );

    // Negative 2: Mission statement in frame.now says "disclosed", but mission_state remains Active.
    let mut v2_base = Variant::baseline()?;
    v2_base.sequence = 3;
    v2_base.mission_state = Some(MissionLifecycleState::Active);
    v2_base.mission_statement = "Routine telemetry collection active.".to_owned();

    let mut v2_spoof = Variant::baseline()?;
    v2_spoof.sequence = 4;
    v2_spoof.mission_state = Some(MissionLifecycleState::Active);
    v2_spoof.mission_statement =
        "Preliminary telemetry was disclosed to the field unit.".to_owned();

    let pub2_base = publication(&v2_base)?;
    let pub2_spoof = publication(&v2_spoof)?;
    let delta2 = classify_reference_meaningful_delta(&pub2_base, &pub2_spoof)?;

    assert!(
        !delta2
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "Planted negative: 'disclosed' statement must NOT spoof mission TerminalTransition!"
    );

    // Negative 3: Event statement claims "rejected" or "resolved" in text, but hypothesis is Live/Supported.
    let mut v3_base = Variant::baseline()?;
    v3_base.sequence = 5;
    v3_base.premise_hypothesis = Some(HypothesisDisposition::Supported);
    v3_base.premise_statement = "Candidate anomaly detected.".to_owned();

    let mut v3_spoof = Variant::baseline()?;
    v3_spoof.sequence = 6;
    v3_spoof.premise_hypothesis = Some(HypothesisDisposition::Supported);
    v3_spoof.premise_statement =
        "Candidate anomaly was resolved in discussion but not rejected or closed.".to_owned();

    let pub3_base = publication(&v3_base)?;
    let pub3_spoof = publication(&v3_spoof)?;
    let delta3 = classify_reference_meaningful_delta(&pub3_base, &pub3_spoof)?;

    assert!(
        !delta3
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "Planted negative: 'resolved'/'rejected' in free-text with Supported hypothesis must NOT produce TerminalTransition!"
    );

    Ok(())
}

/// A typed terminal state paired with a completely neutral statement MUST produce TerminalTransition.
#[test]
fn test_neutral_statement_with_typed_terminal_state_emits_terminal_transition()
-> Result<(), Box<dyn Error>> {
    // 1. Event: neutral statement + HypothesisDisposition::Refuted -> MUST emit TerminalTransition
    let mut v1_base = Variant::baseline()?;
    v1_base.sequence = 1;
    v1_base.premise_hypothesis = Some(HypothesisDisposition::Supported);
    v1_base.premise_statement = "Neutral event entry #41 recorded.".to_owned();

    let mut v1_term = Variant::baseline()?;
    v1_term.sequence = 2;
    v1_term.premise_hypothesis = Some(HypothesisDisposition::Refuted);
    v1_term.premise_statement = "Neutral event entry #42 recorded.".to_owned();

    let pub1_base = publication(&v1_base)?;
    let pub1_term = publication(&v1_term)?;
    let delta_event = classify_reference_meaningful_delta(&pub1_base, &pub1_term)?;

    assert!(
        delta_event
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "Typed terminal event hypothesis with neutral statement MUST emit TerminalTransition!"
    );

    // 2. Effect: neutral statement + KnowledgeState::Known -> MUST emit TerminalTransition
    let mut v2_base = Variant::baseline()?;
    v2_base.sequence = 3;
    v2_base.effect_state = Some(KnowledgeState::Indeterminate);
    v2_base.effect_statement = Some("Operation in progress.".to_owned());

    let mut v2_term = Variant::baseline()?;
    v2_term.sequence = 4;
    v2_term.effect_state = Some(KnowledgeState::Known);
    v2_term.effect_statement = Some("Routine effect log entry posted.".to_owned());

    let pub2_base = publication(&v2_base)?;
    let pub2_term = publication(&v2_term)?;
    let delta_effect = classify_reference_meaningful_delta(&pub2_base, &pub2_term)?;

    assert!(
        delta_effect
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "Typed terminal effect claim with neutral statement MUST emit TerminalTransition!"
    );

    // 3. Mission: neutral statement + MissionLifecycleState::Closed -> MUST emit TerminalTransition
    let mut v3_base = Variant::baseline()?;
    v3_base.sequence = 5;
    v3_base.mission_state = Some(MissionLifecycleState::Active);
    v3_base.mission_statement = "Routine system heartbeat checkpoint.".to_owned();

    let mut v3_term = Variant::baseline()?;
    v3_term.sequence = 6;
    v3_term.mission_state = Some(MissionLifecycleState::Closed);
    v3_term.mission_statement = "Routine system heartbeat checkpoint.".to_owned();

    let pub3_base = publication(&v3_base)?;
    let pub3_term = publication(&v3_term)?;
    let delta_mission = classify_reference_meaningful_delta(&pub3_base, &pub3_term)?;

    assert!(
        delta_mission
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "Typed terminal mission state with neutral statement MUST emit TerminalTransition!"
    );

    Ok(())
}

/// F1: An unchanged degraded resource pressure or degraded dimensions must NOT yield NoMeaningfulChange or SilenceCertificate.
#[test]
fn test_f1_degraded_unchanged_budget_pressure_must_not_produce_silence_certificate()
-> Result<(), Box<dyn Error>> {
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.pressure = ResourcePressure::Constrained;
    v1.degraded_dimensions = BTreeSet::from(["model_calls".to_owned()]);

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.pressure = ResourcePressure::Constrained;
    v2.degraded_dimensions = BTreeSet::from(["model_calls".to_owned()]);

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    pub1.verify()?;
    pub2.verify()?;

    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;

    assert!(
        delta.silence_certificate.is_none(),
        "Silence certificate must NOT be issued when operating under degraded resource pressure!"
    );
    assert_ne!(
        delta.classes,
        BTreeSet::from([MeaningfulDeltaClass::NoMeaningfulChange]),
        "NoMeaningfulChange must never certify silence while resources are degraded!"
    );
    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::BudgetPressure)
            || delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss),
        "Degraded-but-unchanged comparison must emit BudgetPressure or CoverageLoss!"
    );
    delta.validate()?;
    Ok(())
}

/// F1: An unchanged degraded epistemic cell must NOT yield NoMeaningfulChange or SilenceCertificate.
#[test]
fn test_f1_unchanged_degraded_epistemic_cell_must_not_produce_silence_certificate()
-> Result<(), Box<dyn Error>> {
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.premise_state = KnowledgeState::NotObservable;

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.premise_state = KnowledgeState::NotObservable;

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    pub1.verify()?;
    pub2.verify()?;

    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;

    assert!(
        delta.silence_certificate.is_none(),
        "Silence certificate must NOT be issued with degraded epistemic cell!"
    );
    assert_ne!(
        delta.classes,
        BTreeSet::from([MeaningfulDeltaClass::NoMeaningfulChange]),
        "NoMeaningfulChange must never certify silence with degraded epistemic cell!"
    );
    assert!(
        delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss),
        "Degraded-but-unchanged epistemic cell comparison must emit CoverageLoss!"
    );
    delta.validate()?;
    Ok(())
}

/// F2: Terminal effect failure with non-standard phrasing must emit TerminalTransition and refuse coalesce().
#[test]
fn test_f2_terminal_effect_failure_without_magic_substring_must_not_coalesce()
-> Result<(), Box<dyn Error>> {
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.effect_state = None;

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.effect_state = Some(KnowledgeState::Known);
    v2.effect_statement =
        Some("The external dispatch was permanently refused due to expired lease.".to_owned());

    let mut v3 = Variant::baseline()?;
    v3.sequence = 3;
    v3.pressure = ResourcePressure::Elevated;

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    let pub3 = publication(&v3)?;
    pub1.verify()?;
    pub2.verify()?;
    pub3.verify()?;

    let delta1 = classify_reference_meaningful_delta(&pub1, &pub2)?;
    let delta2 = classify_reference_meaningful_delta(&pub2, &pub3)?;

    assert!(
        delta1
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "Terminal effect transition must emit TerminalTransition regardless of statement phrasing!"
    );
    assert!(
        delta1.is_non_coalescible(),
        "Terminal delta must be non-coalescible!"
    );
    let coalesce_result = delta1.coalesce(
        &delta2,
        "delta:coalesced",
        "continuation:coalesced",
        ContentDigest::sha256(b"coalesced"),
    );
    assert!(
        coalesce_result.is_err(),
        "Coalescing a terminal effect transition must be rejected!"
    );
    delta1.validate()?;
    Ok(())
}

/// F4: Real situation compilation and publication validation for F1 (degraded budget pressure).
#[test]
fn test_f4_real_situation_f1_unchanged_degraded_budget_pressure_no_silence()
-> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("f1-real")?;
    let (decision, receipt) = harness.publish_corroborated_decision("f1-real")?;
    let req1 = test_request(
        &decision,
        &receipt,
        None,
        BTreeSet::from(["capability:alert.prepare".to_owned()]),
    )?;
    let situation1 = compile_reference_situation(req1, &harness.authority)?;

    let mut spec = test_spec(10_000)?;
    spec.pressure = ResourcePressure::Constrained;
    spec.degraded_dimensions = BTreeSet::from(["model_calls".to_owned()]);

    let pub1 = project_reference_situation(situation1.clone(), &spec)?;
    let pub2 = project_reference_situation(situation1, &spec)?;
    pub1.verify()?;
    pub2.verify()?;

    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;
    assert!(
        delta.silence_certificate.is_none(),
        "Silence certificate must NOT be issued when operating under degraded resource pressure!"
    );
    assert_ne!(
        delta.classes,
        BTreeSet::from([MeaningfulDeltaClass::NoMeaningfulChange]),
        "NoMeaningfulChange must never certify silence while resources are degraded!"
    );
    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::BudgetPressure),
        "Degraded-but-unchanged comparison must emit BudgetPressure!"
    );
    delta.validate()?;
    harness.cleanup();
    Ok(())
}

/// F4: Real situation compilation and publication validation for F2 (terminal effect transition non-coalescing).
#[test]
fn test_f4_real_situation_f2_terminal_effect_transition_non_coalescible()
-> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("f2-real")?;
    let (decision, receipt) = harness.publish_corroborated_decision("f2-real")?;
    let mut journal = EffectJournal::new();
    let alert_plan = prepare_reference_alert(
        PrepareAlertParams {
            decision: &decision,
            event_receipt: &receipt,
            authority: &harness.authority,
            operation_id: OperationId::parse("op:meaningful-delta:f2:alert")?,
            idempotency_key: IdempotencyKey::parse("idemp:meaningful-delta:f2:alert")?,
            obligation_id: ObligationId::parse("obligation:meaningful-delta:f2:alert")?,
            channel: "security-ops".to_owned(),
            now: TimestampNs(1_000),
        },
        &mut journal,
    )?;

    // Situation 1: prepared alert (indeterminate effect)
    let req1 = test_request(
        &decision,
        &receipt,
        Some(&alert_plan),
        BTreeSet::from(["capability:alert.commit".to_owned()]),
    )?;
    let op_receipt = journal
        .operation(&alert_plan.intent.operation_id)
        .cloned()
        .ok_or(ReferenceError::InvalidSpec("missing_op_receipt"))?;
    let situation1 =
        compile_reference_situation_with_operation_receipt(req1, &op_receipt, &harness.authority)?;
    let pub1 = project_reference_situation(situation1, &test_spec(10_000)?)?;
    pub1.verify()?;

    // Dispatch and publish verified outcome
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:meaningful_delta");
    let _ = dispatch_reference_alert(
        &alert_plan,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(1_001),
        TimestampNs(1_002),
        &mut journal,
        &mut provider,
    )?;
    let provider_receipt = provider
        .lookup(&alert_plan.intent)?
        .ok_or(ReferenceError::InvalidSpec("missing_provider_receipt"))?;
    let _ = observe_reference_alert(
        &alert_plan,
        provider_receipt.receipt_digest(),
        TimestampNs(1_003),
        &mut journal,
        &provider,
    )?;
    let _ = verify_reference_alert(&alert_plan, TimestampNs(1_004), &mut journal, &provider)?;
    let outcome = publish_reference_alert_outcome(
        &alert_plan,
        &journal,
        &mut harness.objects,
        &mut harness.authority,
        &provider,
    )?;

    // Situation 2: verified terminal outcome
    let mut req2 = test_request(
        &decision,
        &receipt,
        Some(&alert_plan),
        BTreeSet::from(["capability:alert.commit".to_owned()]),
    )?;
    req2.alert_outcome = Some(&outcome);
    let situation2 = compile_reference_situation(req2, &harness.authority)?;
    let pub2 = project_reference_situation(situation2, &test_spec(10_000)?)?;
    pub2.verify()?;

    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;
    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "Terminal effect outcome transition must emit TerminalTransition!"
    );
    assert!(
        delta.is_non_coalescible(),
        "Terminal effect transition must be non-coalescible!"
    );

    // Situation 3 for subsequent delta to prove coalesce() is rejected
    let mut spec3 = test_spec(10_000)?;
    spec3.pressure = ResourcePressure::Elevated;
    let mut req3 = test_request(
        &decision,
        &receipt,
        Some(&alert_plan),
        BTreeSet::from(["capability:alert.commit".to_owned()]),
    )?;
    req3.alert_outcome = Some(&outcome);
    let situation3 = compile_reference_situation(req3, &harness.authority)?;
    let pub3 = project_reference_situation(situation3, &spec3)?;
    pub3.verify()?;
    let delta2 = classify_reference_meaningful_delta(&pub2, &pub3)?;

    let coalesce_result = delta.coalesce(
        &delta2,
        "delta:coalesced",
        "continuation:coalesced",
        ContentDigest::sha256(b"coalesced"),
    );
    assert!(
        coalesce_result.is_err(),
        "Coalescing terminal effect transition must return Err!"
    );
    delta.validate()?;
    harness.cleanup();
    Ok(())
}

/// F4: Real situation compilation and publication validation for F3 (contradictions on estimated premise).
#[test]
fn test_f4_real_situation_f3_contradictory_evidence_on_estimated_premise_invalidates_plan()
-> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("f3-real")?;
    let (decision, receipt) = harness.publish_corroborated_decision("f3-real")?;
    let req1 = test_request(
        &decision,
        &receipt,
        None,
        BTreeSet::from(["capability:alert.prepare".to_owned()]),
    )?;
    let situation1 = compile_reference_situation(req1, &harness.authority)?;
    let pub1 = project_reference_situation(situation1.clone(), &test_spec(10_000)?)?;
    pub1.verify()?;

    // Create situation2 where the premise gains contradictory evidence
    let mut situation2 = situation1;
    let contradiction = ContentDigest::sha256(b"real-contradiction-root");
    situation2.proof_roots.insert(contradiction);
    for cell in &mut situation2.capsule.frame.knowledge_cells {
        if cell.knowledge_state == KnowledgeState::Estimated
            || cell.knowledge_state == KnowledgeState::Known
        {
            cell.contradictions.push(contradiction);
        }
    }
    let pub2 = project_reference_situation(situation2, &test_spec(10_000)?)?;
    pub2.verify()?;

    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;
    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::PlanInvalidation),
        "Contradictions added to a premise must emit PlanInvalidation!"
    );
    assert!(
        !delta.invalidated_assumptions.is_empty(),
        "Invalidated assumptions must not be empty when contradictions arise!"
    );
    assert!(
        delta.is_non_coalescible(),
        "PlanInvalidation must be non-coalescible!"
    );
    delta.validate()?;
    harness.cleanup();
    Ok(())
}

/// INV-056: Silence certificate requires non-empty authorized domain and generation, and is issued
/// when two nominal publications have identical coverage and no decision-relevant changes.
#[test]
fn test_inv056_silence_certificate_issued_for_identical_nominal_publications()
-> Result<(), Box<dyn Error>> {
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.completeness = Completeness::Complete;

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.completeness = Completeness::Complete;

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    pub1.verify()?;
    pub2.verify()?;

    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;
    assert_eq!(
        delta.classes,
        BTreeSet::from([MeaningfulDeltaClass::NoMeaningfulChange]),
        "Identical nominal publications must emit NoMeaningfulChange!"
    );
    let cert = delta
        .silence_certificate
        .as_ref()
        .ok_or(ReferenceError::InvalidSpec("missing_silence_certificate"))?;
    assert!(
        !cert.authorized_domain.is_empty(),
        "Authorized domain must not be empty!"
    );
    assert_eq!(
        cert.authorized_generation, delta.contract_basis.ontology_generation_id,
        "Authorized generation must match contract basis ontology generation!"
    );
    cert.validate()?;
    delta.validate()?;
    Ok(())
}

/// INV-056: Coverage gap between publications (e.g. missing domain in result) refuses silence certificate
/// and emits CoverageLoss explicitly naming the missing domain identities.
#[test]
fn test_inv056_silence_certificate_rejected_on_coverage_gap_names_missing_identity()
-> Result<(), Box<dyn Error>> {
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.coverage = BTreeSet::from([
        "fss://coverage/alpha".to_owned(),
        "fss://coverage/beta".to_owned(),
        "fss://coverage/extra-zone".to_owned(),
    ]);

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.coverage = BTreeSet::from([
        "fss://coverage/alpha".to_owned(),
        "fss://coverage/beta".to_owned(),
    ]);

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    pub1.verify()?;
    pub2.verify()?;

    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;
    assert!(
        delta.silence_certificate.is_none(),
        "Silence certificate must NOT be issued when coverage domain has a gap!"
    );
    assert!(
        delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss),
        "Coverage gap must emit CoverageLoss!"
    );
    assert!(
        delta
            .coverage_changes
            .iter()
            .any(|change| change.contains("fss://coverage/extra-zone")),
        "CoverageLoss must explicitly name the missing domain identity! Changes: {:?}",
        delta.coverage_changes
    );
    delta.validate()?;
    Ok(())
}

/// INV-056: Stale capsule revision in result refuses silence certificate and emits CoverageLoss naming stale revision.
#[test]
fn test_inv056_silence_certificate_rejected_on_stale_capsule_revision() -> Result<(), Box<dyn Error>>
{
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.custom_revision = Some(5);

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.custom_revision = Some(2);

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    pub1.verify()?;
    pub2.verify()?;

    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;
    assert!(
        delta.silence_certificate.is_none(),
        "Silence certificate must NOT be issued when result capsule revision is stale!"
    );
    assert!(
        delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss),
        "Stale revision must emit CoverageLoss!"
    );
    assert!(
        delta
            .coverage_changes
            .iter()
            .any(|change| change.contains("stale capsule revision")),
        "CoverageLoss must explicitly name the stale revision! Changes: {:?}",
        delta.coverage_changes
    );
    delta.validate()?;
    Ok(())
}

/// INV-056: Silence certificate direct validation fails on empty domain or empty generation.
#[test]
fn test_inv056_silence_certificate_validation_fails_on_empty_domain_or_generation() {
    let cert_empty_domain = SilenceCertificate {
        basis_frame_digest: ContentDigest::sha256(b"basis"),
        result_frame_digest: ContentDigest::sha256(b"result"),
        selection_witness: ContentDigest::sha256(b"witness"),
        authorized_domain: BTreeSet::new(),
        authorized_generation: "ontology:reference:v1".to_owned(),
        reason: "no change".to_owned(),
    };
    assert_eq!(
        cert_empty_domain.validate(),
        Err(ContractError::EvidenceRequired)
    );

    let cert_empty_gen = SilenceCertificate {
        authorized_domain: BTreeSet::from(["claim:premise".to_owned()]),
        authorized_generation: String::new(),
        ..cert_empty_domain
    };
    assert_eq!(
        cert_empty_gen.validate(),
        Err(ContractError::EvidenceRequired)
    );
}

/// INV-056: Real situation compilation of a rejected event without a coverage witness
/// CANNOT claim absence: absence cell is Unknown and protected residual world is preserved.
#[test]
fn test_inv056_rejected_event_without_coverage_witness_cannot_claim_absence()
-> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("inv056-none")?;
    let (decision, receipt) = harness.publish_rejected_decision("inv056-none")?;
    let req = test_request(
        &decision,
        &receipt,
        None,
        BTreeSet::from(["capability:evidence.query".to_owned()]),
    )?;
    let situation = compile_reference_situation(req, &harness.authority)?;

    let absence = situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id.ends_with(":absence-certification"))
        .ok_or(ReferenceError::InvalidSpec("missing_absence_cell"))?;
    assert_eq!(
        absence.knowledge_state,
        KnowledgeState::Unknown,
        "Absence without CoverageWitness must remain Unknown!"
    );
    assert!(
        absence
            .statement
            .contains("Physical absence is not certified"),
        "Absence statement must indicate absence is uncertified!"
    );
    assert!(
        situation
            .capsule
            .frame
            .world_envelope
            .adversarial_residuals
            .iter()
            .any(|w| w.protected && w.world_id.ends_with(":absence-uncertified")),
        "Protected absence-uncertified residual world MUST be retained without coverage witness!"
    );
    assert!(
        situation
            .capsule
            .frame
            .unknown
            .iter()
            .any(|s| s.contains("physical absence remains unproved")),
        "Unknowns must state physical absence remains unproved!"
    );

    situation.verify()?;
    harness.cleanup();
    Ok(())
}

/// INV-056: Real situation compilation with a stale/mismatched generation coverage witness
/// fails certification: absence cell is Unknown, names the generation conflict, and retains protected residual.
#[test]
fn test_inv056_rejected_event_with_stale_generation_coverage_witness_fails_certification()
-> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("inv056-stale-gen")?;
    let (decision, receipt) = harness.publish_rejected_decision("inv056-stale-gen")?;
    let req = test_request(
        &decision,
        &receipt,
        None,
        BTreeSet::from(["capability:evidence.query".to_owned()]),
    )?;

    let anchor = harness.authority.current().anchor.clone();
    let witness = CoverageWitness {
        anchor,
        authorized_domain: BTreeSet::from(["power:alpha".to_owned()]),
        observed_domain: BTreeSet::from(["power:alpha".to_owned()]),
        excluded_domain: BTreeSet::new(),
        continuity: CoverageContinuity::Continuous,
        completeness: Completeness::Complete,
        negative_predicate: "no_unknown_person_present".to_owned(),
        stop_reason: CoverageStopReason::Complete,
        authorized_generation: 999,
        observed_generation: 1,
    };
    assert!(!witness.certifies_absence());

    let mut req = req;
    req.coverage_witness = Some(&witness);
    let situation = compile_reference_situation(req, &harness.authority)?;

    let absence = situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id.ends_with(":absence-certification"))
        .ok_or(ReferenceError::InvalidSpec("missing_absence_cell"))?;
    assert_eq!(
        absence.knowledge_state,
        KnowledgeState::Unknown,
        "Absence with mismatched generation CoverageWitness must remain Unknown!"
    );
    assert!(
        absence
            .statement
            .contains("conflicts with observed generation"),
        "Absence statement must name generation conflict! Statement: {}",
        absence.statement
    );
    assert!(
        situation
            .capsule
            .frame
            .world_envelope
            .adversarial_residuals
            .iter()
            .any(|w| w.protected && w.world_id.ends_with(":absence-uncertified")),
        "Protected absence-uncertified residual world MUST be retained on generation mismatch!"
    );

    situation.verify()?;
    harness.cleanup();
    Ok(())
}

/// INV-056: Real situation compilation with a gapped coverage witness fails certification:
/// absence cell is Unknown, names continuity gap, and retains protected residual.
#[test]
fn test_inv056_rejected_event_with_gapped_coverage_witness_fails_certification()
-> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("inv056-gapped")?;
    let (decision, receipt) = harness.publish_rejected_decision("inv056-gapped")?;
    let req = test_request(
        &decision,
        &receipt,
        None,
        BTreeSet::from(["capability:evidence.query".to_owned()]),
    )?;

    let anchor = harness.authority.current().anchor.clone();
    let current_epoch = anchor.policy_epoch;
    let witness = CoverageWitness {
        anchor,
        authorized_domain: BTreeSet::from(["power:alpha".to_owned()]),
        observed_domain: BTreeSet::from(["power:alpha".to_owned()]),
        excluded_domain: BTreeSet::new(),
        continuity: CoverageContinuity::Gapped,
        completeness: Completeness::Complete,
        negative_predicate: "no_unknown_person_present".to_owned(),
        stop_reason: CoverageStopReason::Complete,
        authorized_generation: current_epoch,
        observed_generation: current_epoch,
    };
    assert!(!witness.certifies_absence());

    let mut req = req;
    req.coverage_witness = Some(&witness);
    let situation = compile_reference_situation(req, &harness.authority)?;

    let absence = situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id.ends_with(":absence-certification"))
        .ok_or(ReferenceError::InvalidSpec("missing_absence_cell"))?;
    assert_eq!(
        absence.knowledge_state,
        KnowledgeState::Unknown,
        "Absence with gapped CoverageWitness must remain Unknown!"
    );
    assert!(
        absence.statement.contains("continuity is Gapped"),
        "Absence statement must name continuity gap! Statement: {}",
        absence.statement
    );
    assert!(
        situation
            .capsule
            .frame
            .world_envelope
            .adversarial_residuals
            .iter()
            .any(|w| w.protected && w.world_id.ends_with(":absence-uncertified")),
        "Protected absence-uncertified residual world MUST be retained on gapped coverage!"
    );

    situation.verify()?;
    harness.cleanup();
    Ok(())
}

/// INV-056: Real situation compilation with an out-of-domain coverage witness fails certification:
/// absence cell is Unknown, names domain mismatch, and retains protected residual.
#[test]
fn test_inv056_rejected_event_with_out_of_domain_coverage_witness_fails_certification()
-> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("inv056-domain-mismatch")?;
    let (decision, receipt) = harness.publish_rejected_decision("inv056-domain-mismatch")?;
    let req = test_request(
        &decision,
        &receipt,
        None,
        BTreeSet::from(["capability:evidence.query".to_owned()]),
    )?;

    let anchor = harness.authority.current().anchor.clone();
    let current_epoch = anchor.policy_epoch;
    let witness = CoverageWitness {
        anchor,
        authorized_domain: BTreeSet::from(["power:alpha".to_owned()]),
        observed_domain: BTreeSet::from(["power:other_zone".to_owned()]),
        excluded_domain: BTreeSet::new(),
        continuity: CoverageContinuity::Continuous,
        completeness: Completeness::Complete,
        negative_predicate: "no_unknown_person_present".to_owned(),
        stop_reason: CoverageStopReason::Complete,
        authorized_generation: current_epoch,
        observed_generation: current_epoch,
    };
    assert!(!witness.certifies_absence());

    let mut req = req;
    req.coverage_witness = Some(&witness);
    let situation = compile_reference_situation(req, &harness.authority)?;

    let absence = situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id.ends_with(":absence-certification"))
        .ok_or(ReferenceError::InvalidSpec("missing_absence_cell"))?;
    assert_eq!(
        absence.knowledge_state,
        KnowledgeState::Unknown,
        "Absence with out-of-domain CoverageWitness must remain Unknown!"
    );
    assert!(
        absence
            .statement
            .contains("does not match authorized domain"),
        "Absence statement must name domain mismatch! Statement: {}",
        absence.statement
    );
    assert!(
        situation
            .capsule
            .frame
            .world_envelope
            .adversarial_residuals
            .iter()
            .any(|w| w.protected && w.world_id.ends_with(":absence-uncertified")),
        "Protected absence-uncertified residual world MUST be retained on domain mismatch!"
    );

    situation.verify()?;
    harness.cleanup();
    Ok(())
}

/// INV-056: Real situation compilation with a fully valid CoverageWitness over the authorized
/// domain and generation successfully certifies absence: KnowledgeState is Known (Refuted),
/// witness digest is in proof roots, and uncertified-absence residual world is resolved.
#[test]
fn test_inv056_rejected_event_with_valid_coverage_witness_certifies_absence()
-> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("inv056-certified")?;
    let (decision, receipt) = harness.publish_rejected_decision("inv056-certified")?;
    let req = test_request(
        &decision,
        &receipt,
        None,
        BTreeSet::from(["capability:evidence.query".to_owned()]),
    )?;

    let anchor = harness.authority.current().anchor.clone();
    let current_epoch = anchor.policy_epoch;
    let witness = CoverageWitness {
        anchor,
        authorized_domain: BTreeSet::from(["power:alpha".to_owned()]),
        observed_domain: BTreeSet::from(["power:alpha".to_owned()]),
        excluded_domain: BTreeSet::new(),
        continuity: CoverageContinuity::Continuous,
        completeness: Completeness::Complete,
        negative_predicate: "no_unknown_person_present".to_owned(),
        stop_reason: CoverageStopReason::Complete,
        authorized_generation: current_epoch,
        observed_generation: current_epoch,
    };
    assert!(
        witness.certifies_absence(),
        "Valid witness must certify absence!"
    );
    assert_eq!(witness.require_certified_absence(), Ok(()));

    let mut req = req;
    req.coverage_witness = Some(&witness);
    let situation = compile_reference_situation(req, &harness.authority)?;

    let absence = situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id.ends_with(":absence-certification"))
        .ok_or(ReferenceError::InvalidSpec("missing_absence_cell"))?;
    assert_eq!(
        absence.knowledge_state,
        KnowledgeState::Known,
        "Absence with complete continuous CoverageWitness over authorized domain and generation must be Known!"
    );
    assert_eq!(
        absence.hypothesis,
        Some(HypothesisDisposition::Refuted),
        "Absence hypothesis disposition must be Refuted!"
    );
    assert!(
        absence
            .statement
            .contains("Physical absence is certified across authorized domain"),
        "Absence statement must indicate certified absence! Statement: {}",
        absence.statement
    );
    assert!(
        situation.proof_roots.contains(&witness.witness_digest()),
        "Situation proof roots must include the CoverageWitness digest!"
    );
    assert!(
        !situation
            .capsule
            .frame
            .world_envelope
            .adversarial_residuals
            .iter()
            .any(|w| w.world_id.ends_with(":absence-uncertified")),
        "Protected absence-uncertified residual world MUST NOT be present when absence is certified!"
    );

    situation.verify()?;
    harness.cleanup();
    Ok(())
}

/// DEFECT 1 & 4 TEST: A CoverageWitness for an unrelated domain must NOT certify absence
/// for an event in power:alpha, and must NOT drop the protected absence-uncertified world.
#[test]
fn test_inv056_failing_wrong_domain_witness_must_not_certify_absence() -> Result<(), Box<dyn Error>>
{
    let mut harness = TestHarness::new("inv056-wrong-domain")?;
    let (decision, receipt) = harness.publish_rejected_decision("inv056-wrong-domain")?;
    let req = test_request(
        &decision,
        &receipt,
        None,
        BTreeSet::from(["capability:evidence.query".to_owned()]),
    )?;

    let anchor = harness.authority.current().anchor.clone();
    let current_epoch = anchor.policy_epoch;
    // Witness is for "power:completely_unrelated_parking_lot", NOT "power:alpha"!
    let witness = CoverageWitness {
        anchor,
        authorized_domain: BTreeSet::from(["power:completely_unrelated_parking_lot".to_owned()]),
        observed_domain: BTreeSet::from(["power:completely_unrelated_parking_lot".to_owned()]),
        excluded_domain: BTreeSet::new(),
        continuity: CoverageContinuity::Continuous,
        completeness: Completeness::Complete,
        negative_predicate: "no_unknown_person_present".to_owned(),
        stop_reason: CoverageStopReason::Complete,
        authorized_generation: current_epoch,
        observed_generation: current_epoch,
    };

    let mut req = req;
    req.coverage_witness = Some(&witness);
    let situation = compile_reference_situation(req, &harness.authority)?;

    let absence = situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id.ends_with(":absence-certification"))
        .ok_or(ReferenceError::InvalidSpec("missing_absence_cell"))?;

    assert_eq!(
        absence.knowledge_state,
        KnowledgeState::Unknown,
        "A witness for an unrelated domain must NOT certify absence!"
    );
    assert!(
        situation
            .capsule
            .frame
            .world_envelope
            .adversarial_residuals
            .iter()
            .any(|w| w.protected && w.world_id.ends_with(":absence-uncertified")),
        "Protected absence-uncertified residual world MUST be retained when domain does not match event!"
    );

    harness.cleanup();
    Ok(())
}

/// DEFECT 2 TEST: Concurrent budget pressure must NOT swallow CoverageLoss or coverage_changes.
#[test]
fn test_inv056_failing_coverage_gap_with_concurrent_budget_pressure_must_emit_coverage_loss()
-> Result<(), Box<dyn Error>> {
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.coverage = BTreeSet::from([
        "fss://coverage/alpha".to_owned(),
        "fss://coverage/extra-zone".to_owned(),
    ]);

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.coverage = BTreeSet::from(["fss://coverage/alpha".to_owned()]); // Missing extra-zone!
    v2.pressure = ResourcePressure::Constrained; // Triggers BudgetPressure!

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    pub1.verify()?;
    pub2.verify()?;

    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;

    assert!(
        delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss),
        "CoverageLoss must be emitted even when BudgetPressure is also present! Classes: {:?}",
        delta.classes
    );
    assert!(
        delta
            .coverage_changes
            .iter()
            .any(|c| c.contains("missing coverage for authorized domain identities")),
        "coverage_changes must name missing domain identities even under budget pressure! Changes: {:?}",
        delta.coverage_changes
    );

    Ok(())
}

/// DEFECT 2 TEST: Degraded epistemic cell with concurrent budget pressure must emit CoverageLoss and coverage_changes.
#[test]
fn test_inv056_failing_degraded_epistemic_cell_with_concurrent_budget_pressure_must_emit_coverage_loss()
-> Result<(), Box<dyn Error>> {
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.premise_state = KnowledgeState::NotObservable; // Degraded epistemic cell!
    v2.pressure = ResourcePressure::Constrained; // Concurrent BudgetPressure!

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    pub1.verify()?;
    pub2.verify()?;

    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;

    assert!(
        delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss),
        "CoverageLoss must be emitted when epistemic cell is degraded even under budget pressure! Classes: {:?}",
        delta.classes
    );
    assert!(
        delta
            .coverage_changes
            .iter()
            .any(|c| c.contains("epistemic cell degraded")),
        "coverage_changes must record degraded epistemic cell even under budget pressure! Changes: {:?}",
        delta.coverage_changes
    );

    Ok(())
}

/// DEFECT 2 (DEAD CODE) TEST: Ontology generation mismatch must emit CoverageLoss and explain it in coverage_changes.
#[test]
fn test_inv056_failing_generation_mismatch_must_emit_coverage_loss_and_coverage_changes()
-> Result<(), Box<dyn Error>> {
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    // Different ontology generation:
    let mut basis2 = test_basis();
    basis2.ontology_generation_id = "ontology:reference:v2".to_owned();
    v2.contract_basis = Some(basis2);

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    pub1.verify()?;
    pub2.verify()?;

    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;

    assert!(
        delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss),
        "Generation mismatch must emit CoverageLoss! Classes: {:?}",
        delta.classes
    );
    assert!(
        delta
            .coverage_changes
            .iter()
            .any(|c| c.contains("generation mismatch")),
        "coverage_changes must record generation mismatch! Changes: {:?}",
        delta.coverage_changes
    );

    Ok(())
}

/// DEFECT 4 TEST: A witness certifying a different predicate (e.g. no_vehicle_present)
/// must NOT certify absence of unknown persons.
#[test]
fn test_inv056_failing_wrong_predicate_must_not_certify_person_absence()
-> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("inv056-wrong-predicate")?;
    let (decision, receipt) = harness.publish_rejected_decision("inv056-wrong-predicate")?;
    let req = test_request(
        &decision,
        &receipt,
        None,
        BTreeSet::from(["capability:evidence.query".to_owned()]),
    )?;

    let anchor = harness.authority.current().anchor.clone();
    let current_epoch = anchor.policy_epoch;
    let witness = CoverageWitness {
        anchor,
        authorized_domain: BTreeSet::from(["power:alpha".to_owned()]),
        observed_domain: BTreeSet::from(["power:alpha".to_owned()]),
        excluded_domain: BTreeSet::new(),
        continuity: CoverageContinuity::Continuous,
        completeness: Completeness::Complete,
        // Predicate is for vehicles, NOT unknown person!
        negative_predicate: "no_vehicle_present".to_owned(),
        stop_reason: CoverageStopReason::Complete,
        authorized_generation: current_epoch,
        observed_generation: current_epoch,
    };

    let mut req = req;
    req.coverage_witness = Some(&witness);
    let situation = compile_reference_situation(req, &harness.authority)?;

    let absence = situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id.ends_with(":absence-certification"))
        .ok_or(ReferenceError::InvalidSpec("missing_absence_cell"))?;

    assert_eq!(
        absence.knowledge_state,
        KnowledgeState::Unknown,
        "Witness with predicate 'no_vehicle_present' must not certify absence of unknown persons!"
    );

    harness.cleanup();
    Ok(())
}

/// DEFECT 3 TEST: A witness with a stale authority anchor commit sequence must NOT certify absence.
#[test]
fn test_inv056_failing_stale_anchor_commit_sequence_must_not_certify_absence()
-> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("inv056-stale-anchor")?;
    let (decision, receipt) = harness.publish_rejected_decision("inv056-stale-anchor")?;
    let req = test_request(
        &decision,
        &receipt,
        None,
        BTreeSet::from(["capability:evidence.query".to_owned()]),
    )?;

    // Anchor with stale commit_sequence (0 instead of live sequence >= 1)
    let mut stale_anchor = harness.authority.current().anchor.clone();
    stale_anchor.commit_sequence = 0;
    stale_anchor.state_root = ContentDigest::sha256(b"ancient-state-root");

    let current_epoch = stale_anchor.policy_epoch;
    let witness = CoverageWitness {
        anchor: stale_anchor,
        authorized_domain: BTreeSet::from(["power:alpha".to_owned()]),
        observed_domain: BTreeSet::from(["power:alpha".to_owned()]),
        excluded_domain: BTreeSet::new(),
        continuity: CoverageContinuity::Continuous,
        completeness: Completeness::Complete,
        negative_predicate: "no_unknown_person_present".to_owned(),
        stop_reason: CoverageStopReason::Complete,
        authorized_generation: current_epoch,
        observed_generation: current_epoch,
    };

    let mut req = req;
    req.coverage_witness = Some(&witness);
    let situation = compile_reference_situation(req, &harness.authority)?;

    let absence = situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id.ends_with(":absence-certification"))
        .ok_or(ReferenceError::InvalidSpec("missing_absence_cell"))?;

    assert_eq!(
        absence.knowledge_state,
        KnowledgeState::Unknown,
        "Witness with stale anchor commit sequence must not certify absence!"
    );

    harness.cleanup();
    Ok(())
}

/// DEFECT 6 TEST: Planted-negative test driven fully through real producers:
/// capture -> model -> policy -> ledger event -> compile situation -> project situation -> classify meaningful delta.
#[test]
fn test_inv056_failing_producer_driven_planted_negative_meaningful_delta()
-> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("inv056-producer-driven")?;
    let (decision, receipt) = harness.publish_rejected_decision("inv056-producer-driven")?;
    let req1 = test_request(
        &decision,
        &receipt,
        None,
        BTreeSet::from(["capability:evidence.query".to_owned()]),
    )?;

    // Situation 1: without coverage witness -> uncertified absence
    let sit1 = compile_reference_situation(req1, &harness.authority)?;
    let spec1 = test_spec(10_000)?;
    let unreserved1 = spec1
        .available_resources
        .tokens
        .saturating_sub(spec1.reserved_resources.tokens);
    let pub1 = project_reference_situation(sit1, &spec1).map_err(|err| {
        format!(
            "pub1 project failed with target_tokens={}, available_tokens={}, reserved_tokens={}, unreserved_tokens={}, available_bytes={}: {err:?}",
            spec1.target_tokens,
            spec1.available_resources.tokens,
            spec1.reserved_resources.tokens,
            unreserved1,
            spec1.available_resources.bytes,
        )
    })?;

    // Situation 2: with valid coverage witness -> certified absence
    let anchor = harness.authority.current().anchor.clone();
    let current_epoch = anchor.policy_epoch;
    let witness = CoverageWitness {
        anchor,
        authorized_domain: BTreeSet::from(["power:alpha".to_owned()]),
        observed_domain: BTreeSet::from(["power:alpha".to_owned()]),
        excluded_domain: BTreeSet::new(),
        continuity: CoverageContinuity::Continuous,
        completeness: Completeness::Complete,
        negative_predicate: "no_unknown_person_present".to_owned(),
        stop_reason: CoverageStopReason::Complete,
        authorized_generation: current_epoch,
        observed_generation: current_epoch,
    };
    let mut req2 = test_request(
        &decision,
        &receipt,
        None,
        BTreeSet::from(["capability:evidence.query".to_owned()]),
    )?;
    req2.revision = 2;
    req2.coverage_witness = Some(&witness);
    let sit2 = compile_reference_situation(req2, &harness.authority)?;
    let spec2 = test_spec(10_000)?;
    let unreserved2 = spec2
        .available_resources
        .tokens
        .saturating_sub(spec2.reserved_resources.tokens);
    let pub2 = project_reference_situation(sit2, &spec2).map_err(|err| {
        format!(
            "pub2 project failed with target_tokens={}, available_tokens={}, reserved_tokens={}, unreserved_tokens={}, available_bytes={}: {err:?}",
            spec2.target_tokens,
            spec2.available_resources.tokens,
            spec2.reserved_resources.tokens,
            unreserved2,
            spec2.available_resources.bytes,
        )
    })?;

    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;
    // Transition from uncertified to certified absence changes knowledge cell from Unknown to Known
    assert!(
        delta.classes.contains(&MeaningfulDeltaClass::MaterialState),
        "Transition to certified absence must emit MaterialState! Classes: {:?}",
        delta.classes
    );

    harness.cleanup();
    Ok(())
}

/// Proves that TestHarness refuses to silently reuse or overwrite a pre-existing journal:
/// when a path already exists, TestHarness fails loudly instead of silently appending or clobbering.
#[test]
fn test_harness_proves_no_silent_append_to_stale_journal() -> Result<(), Box<dyn Error>> {
    let test_name = "stale-isolation-proof";
    let run_dir = create_exclusive_run_dir("fss-ref-stale-isolation", test_name)?;
    let path = run_dir.join(format!("{test_name}.journal"));

    // 1. Pre-create a stale journal file at the target path.
    fs::write(&path, b"stale-journal-pre-existing-content")?;
    assert!(path.exists(), "Pre-created stale journal file must exist");
    assert!(
        fs::metadata(&path)?.len() > 0,
        "Stale journal must have non-zero length"
    );

    // 2. Prove that TestHarness refuses to silently overwrite or append to an existing journal:
    // It fails loudly with an error rather than silently reusing or deleting the file.
    let err = TestHarness::open_at_path(run_dir.clone(), path.clone(), test_name);
    assert!(
        err.is_err(),
        "TestHarness::open_at_path must fail loudly if journal path already exists!"
    );
    let err_msg = match err {
        Err(e) => e.to_string(),
        Ok(_) => String::new(),
    };
    assert!(
        err_msg.contains("refused to silently reuse or overwrite"),
        "Error message must clearly report refusal to reuse existing path: {err_msg}"
    );

    // Clean up the stale file and dir
    let _ = fs::remove_file(&path);
    let _ = fs::remove_dir_all(&run_dir);

    // 3. Normal TestHarness::new allocates an exclusive run directory and creates fresh journal cleanly:
    let mut harness = TestHarness::new(test_name)?;
    assert_eq!(
        harness.authority.batches().len(),
        0,
        "Fresh harness must have zero batches"
    );
    assert_eq!(
        harness.authority.current().anchor.commit_sequence,
        0,
        "Fresh harness must have commit sequence 0"
    );

    let (_decision, receipt) = harness.publish_rejected_decision(test_name)?;
    assert_eq!(
        harness.authority.batches().len(),
        2,
        "Harness must commit 2 batches"
    );
    assert_eq!(
        harness.authority.current().anchor.commit_sequence,
        2,
        "Commit sequence must be 2"
    );
    assert_eq!(
        receipt.authority_anchor.commit_sequence, 2,
        "Receipt anchor sequence must be 2"
    );

    let journal_path = harness.path.clone();
    let harness_dir = harness.run_dir.clone();
    harness.cleanup();
    assert!(
        !journal_path.exists(),
        "Harness cleanup must remove journal file"
    );
    assert!(
        !harness_dir.exists(),
        "Harness cleanup must remove run directory"
    );
    Ok(())
}

#![forbid(unsafe_code)]
//! Integration contract tests verifying sensor tamper stickiness across revisions (fss-2uftm).
//!
//! Verifies:
//! - A sensor tamper observation compiles the `claim:event:{name}:sensor-integrity` cell
//!   as `Unknown`, disfavored, with tamper roots as contradictions, and keeps the physical
//!   presence cell from reaching `Known`.
//! - Planted-bypass attempt: if a later evaluation omits the tamper observation (or reports
//!   `PersonLike`), the delta must NOT coalesce: `contradiction_changed` detects the missing
//!   prior contradiction, classifying the delta as `Contradiction` with `Critical` priority.
//! - Evidenced integrity restoration: an explicit `IntegrityRestored` observation retires
//!   the tamper risk, compiling `sensor-integrity` as `Known` with restoration evidence,
//!   retiring the protected tamper world, and allowing the physical cell to reach `Known`.
//! - Multi-domain tamper isolation: partial restoration leaves unretired domains active.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;

use fss_core::event::EventSupersedeParams;
use fss_core::{
    BudgetVector, CapsuleId, CaptureInterval, ContractBasis, ContractBasisRegistryBytes,
    DeltaPriority, EventEvidence, EventHypothesis, EventId, EventKind, EventState, EvidenceClass,
    EvidenceEdgeRelation, HypothesisDisposition, KnowledgeState, MeaningfulDeltaClass, MissionId,
    PrincipalId, ProbabilityInterval, ResourcePressure, SensorId, SessionId, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};
use fss_reference::{
    DeliveryPlan, MockModelScript, MockModelSpec, MockSemanticLabel, ReferenceError,
    ReferenceEventReceipt, ReferenceModelObservation, ReferencePolicyAction,
    ReferencePolicyDecision, ReferenceProjectionSpec, ReferenceSituationRequest,
    VirtualCameraSpec, classify_reference_meaningful_delta, compile_reference_situation,
    evaluate_unknown_presence, execute_mock_model, project_reference_situation,
    publish_reference_event, run_reference_capture,
};

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
            Err(err) => return Err(Box::new(err)),
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
        let run_dir = create_exclusive_run_dir("fss-ref-tamper-stickiness", name)?;
        let path = run_dir.join(format!("{name}.journal"));
        let authority = DurableReferenceLedger::open(
            &path,
            format!("site:tamper-stickiness:{name}"),
            IncompleteTailPolicy::Reject,
        )?;
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
            capture_id: CapsuleId::parse(format!("capture:tamper-stickiness:{test_name}:{lane}"))?,
            sensor_id: SensorId::parse(format!("sensor:tamper-stickiness:{test_name}:{lane}"))?,
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
            format!("mock:tamper-stickiness:{test_name}:{lane}:v1"),
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

    fn cleanup(self) {
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

fn test_request<'a>(
    decision: &'a ReferencePolicyDecision,
    receipt: &'a ReferenceEventReceipt,
) -> Result<ReferenceSituationRequest<'a>, Box<dyn Error>> {
    Ok(ReferenceSituationRequest {
        mission_id: MissionId::parse("mission:tamper-stickiness:test")?,
        session_id: SessionId::parse("session:tamper-stickiness:test")?,
        principal_id: PrincipalId::parse("principal:tamper-stickiness:test")?,
        objective_id: "objective:tamper-stickiness".to_owned(),
        revision: 1,
        contract_basis: test_basis(),
        previous_anchor: None,
        predecessor_publication: None,
        created_at: TimestampNs(1_000),
        decision,
        event_receipt: receipt,
        alert_plan: None,
        alert_outcome: None,
        coverage_witness: None,
        available_capabilities: BTreeSet::new(),
    })
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

#[test]
fn test_tamper_blocks_known_physical_cell_and_sets_contradiction_integrity_cell()
-> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("tamper-blocks-known")?;
    let obs_tamper = harness.observation(
        "tamper-blocks-known",
        "lane0",
        10,
        "power:alpha",
        MockSemanticLabel::TamperLike,
    )?;
    let obs_person = harness.observation(
        "tamper-blocks-known",
        "lane1",
        11,
        "power:beta",
        MockSemanticLabel::PersonLike,
    )?;

    let decision = evaluate_unknown_presence(
        EventId::parse("event:tamper:blocks-known")?,
        vec![obs_tamper, obs_person],
    )?;
    let receipt = publish_reference_event(&decision, &mut harness.objects, &mut harness.authority)?;
    let situation =
        compile_reference_situation(test_request(&decision, &receipt)?, &harness.authority)?;

    let frame = &situation.capsule.frame;

    // Sensor integrity cell is Unknown, disfavored, and carries the tamper roots as contradictions
    let integrity_cell = frame
        .knowledge_cells
        .iter()
        .find(|c| c.claim_id.ends_with(":sensor-integrity"))
        .ok_or("missing sensor-integrity cell")?;
    assert_eq!(integrity_cell.knowledge_state, KnowledgeState::Unknown);
    assert_eq!(
        integrity_cell.hypothesis,
        Some(HypothesisDisposition::Disfavored)
    );
    assert!(!integrity_cell.contradictions.is_empty());
    assert!(integrity_cell.evidence.is_empty());

    // Physical presence cell cannot reach Known while tamper is unretired
    let physical_cell = frame
        .knowledge_cells
        .iter()
        .find(|c| {
            c.claim_id.ends_with(":unknown-presence") && !c.claim_id.starts_with("claim:policy:")
        })
        .ok_or("missing physical presence cell")?;
    assert_ne!(physical_cell.knowledge_state, KnowledgeState::Known);

    // Protected tamper world is present in adversarial residuals
    assert!(
        frame
            .world_envelope
            .adversarial_residuals
            .iter()
            .any(|w| w.protected && w.world_id.ends_with(":sensor-tamper"))
    );

    harness.cleanup();
    Ok(())
}

#[test]
fn test_planted_bypass_omitting_tamper_is_critical_non_coalescible_delta()
-> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("bypass-non-coalescible")?;

    // Basis: observation with TamperLike on power:alpha
    let obs_tamper = harness.observation(
        "bypass-non-coalescible",
        "lane0",
        20,
        "power:alpha",
        MockSemanticLabel::TamperLike,
    )?;
    let basis_decision = evaluate_unknown_presence(
        EventId::parse("event:tamper:bypass-delta")?,
        vec![obs_tamper],
    )?;
    let basis_receipt = publish_reference_event(
        &basis_decision,
        &mut harness.objects,
        &mut harness.authority,
    )?;
    let basis = project_reference_situation(
        compile_reference_situation(
            test_request(&basis_decision, &basis_receipt)?,
            &harness.authority,
        )?,
        &test_spec(10_000),
    )?;

    // Basis has the sensor-integrity cell with contradictions
    assert!(
        basis
            .situation
            .capsule
            .frame
            .knowledge_cells
            .iter()
            .any(|c| c.claim_id.ends_with(":sensor-integrity") && !c.contradictions.is_empty())
    );

    // Planted bypass in result: a later evaluation omits the tamper observation,
    // reporting only PersonLike on power:alpha and power:beta.
    let obs_person_a = harness.observation(
        "bypass-non-coalescible",
        "lane1",
        21,
        "power:alpha",
        MockSemanticLabel::PersonLike,
    )?;
    let obs_person_b = harness.observation(
        "bypass-non-coalescible",
        "lane2",
        22,
        "power:beta",
        MockSemanticLabel::PersonLike,
    )?;
    // Craft a bypass hypothesis that supersedes basis_decision but drops the tamper edge
    let bypass_hypothesis = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_string(),
        event_id: basis_decision.event.event_id.clone(),
        revision: 2,
        supersedes: Some(basis_decision.event.revision_digest()),
        state: EventState::Corroborated,
        kind: EventKind::UnknownPresence,
        interval: basis_decision.event.interval,
        uncertainty_reason: None,
        zone_ids: vec!["zone-1".to_string()],
        track_ids: vec!["track-1".to_string()],
        probability: ProbabilityInterval::new(0.8, 0.95)?,
        evidence: vec![
            EventEvidence {
                digest: obs_person_a.result.object_digest(),
                class: EvidenceClass::Derived,
                failure_domain: "power:alpha".to_string(),
                supports: true,
                relation: EvidenceEdgeRelation::Supports,
                capsule_digest: None,
                identity_digest: None,
            },
            EventEvidence {
                digest: obs_person_b.result.object_digest(),
                class: EvidenceClass::Derived,
                failure_domain: "power:beta".to_string(),
                supports: true,
                relation: EvidenceEdgeRelation::Supports,
                capsule_digest: None,
                identity_digest: None,
            },
        ],
        model_receipts: vec![
            obs_person_a.result.object_digest(),
            obs_person_b.result.object_digest(),
        ],
        decision_path: basis_decision.event.decision_path.clone(),
    };
    bypass_hypothesis.validate()?;
    let bypass_decision = ReferencePolicyDecision {
        event: bypass_hypothesis,
        action: ReferencePolicyAction::PrepareAlert,
    };
    let bypass_receipt = publish_reference_event(
        &bypass_decision,
        &mut harness.objects,
        &mut harness.authority,
    )?;
    let mut request = test_request(&bypass_decision, &bypass_receipt)?;
    request.revision = 2;
    request.previous_anchor = Some(basis.situation.capsule.anchor.clone());
    request.created_at = TimestampNs(2_000);
    let result = project_reference_situation(
        compile_reference_situation(request, &harness.authority)?,
        &test_spec(10_000),
    )?;

    // In the bypass result, sensor-integrity cell was omitted
    assert!(
        !result
            .situation
            .capsule
            .frame
            .knowledge_cells
            .iter()
            .any(|c| c.claim_id.ends_with(":sensor-integrity"))
    );

    // Classifying the delta between basis and result:
    // The missing prior contradiction MUST NOT produce a coalescible High delta!
    // It MUST be classified as Contradiction and Critical priority.
    let delta = classify_reference_meaningful_delta(&basis, &result)?;
    assert!(
        delta.classes.contains(&MeaningfulDeltaClass::Contradiction),
        "expected Contradiction class in delta classes: {:?}",
        delta.classes
    );
    assert_eq!(
        delta.priority,
        DeltaPriority::Critical,
        "expected Critical priority, found {:?}",
        delta.priority
    );
    assert!(delta.is_non_coalescible(), "delta must be non-coalescible");
    assert!(
        delta.priority.is_urgent(),
        "delta priority must be urgent (non-coalescing)"
    );
    delta.validate()?;

    harness.cleanup();
    Ok(())
}

#[test]
fn test_evidenced_integrity_restoration_retires_tamper_and_enables_known()
-> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("restoration-enables-known")?;

    // Step 1: Tampered basis
    let obs_tamper = harness.observation(
        "restoration-enables-known",
        "lane0",
        30,
        "power:alpha",
        MockSemanticLabel::TamperLike,
    )?;
    let basis_decision = evaluate_unknown_presence(
        EventId::parse("event:tamper:restoration-known")?,
        vec![obs_tamper],
    )?;
    let basis_receipt = publish_reference_event(
        &basis_decision,
        &mut harness.objects,
        &mut harness.authority,
    )?;
    let basis = project_reference_situation(
        compile_reference_situation(
            test_request(&basis_decision, &basis_receipt)?,
            &harness.authority,
        )?,
        &test_spec(10_000),
    )?;

    // Step 2: Explicit evidenced restoration on power:alpha, plus corroborating person observations
    let obs_restoration = harness.observation(
        "restoration-enables-known",
        "lane1",
        31,
        "power:alpha",
        MockSemanticLabel::IntegrityRestored,
    )?;
    let obs_person_a = harness.observation(
        "restoration-enables-known",
        "lane2",
        32,
        "power:alpha",
        MockSemanticLabel::PersonLike,
    )?;
    let obs_person_b = harness.observation(
        "restoration-enables-known",
        "lane3",
        33,
        "power:beta",
        MockSemanticLabel::PersonLike,
    )?;

    let ReferencePolicyDecision {
        event: candidate,
        action,
    } = evaluate_unknown_presence(
        EventId::parse("event:tamper:restoration-known")?,
        vec![obs_restoration, obs_person_a, obs_person_b],
    )?;
    let revised = basis_decision.event.supersede(EventSupersedeParams {
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
    })?;
    let restored_decision = ReferencePolicyDecision {
        event: revised,
        action,
    };
    let restored_receipt = publish_reference_event(
        &restored_decision,
        &mut harness.objects,
        &mut harness.authority,
    )?;
    let mut request = test_request(&restored_decision, &restored_receipt)?;
    request.revision = 2;
    request.previous_anchor = Some(basis.situation.capsule.anchor.clone());
    request.created_at = TimestampNs(2_000);
    let result = project_reference_situation(
        compile_reference_situation(
            request,
            &harness.authority,
        )?,
        &test_spec(10_000),
    )?;

    let frame = &result.situation.capsule.frame;

    // Sensor integrity cell is now Known, favored, has restoration evidence, no contradictions
    let integrity_cell = frame
        .knowledge_cells
        .iter()
        .find(|c| c.claim_id.ends_with(":sensor-integrity"))
        .ok_or("missing sensor-integrity cell in restored situation")?;
    assert_eq!(integrity_cell.knowledge_state, KnowledgeState::Known);
    assert_eq!(
        integrity_cell.hypothesis,
        Some(HypothesisDisposition::Supported)
    );
    assert!(!integrity_cell.evidence.is_empty());
    assert!(integrity_cell.contradictions.is_empty());

    // Protected sensor-tamper world is retired
    assert!(
        !frame
            .world_envelope
            .adversarial_residuals
            .iter()
            .any(|w| w.world_id.ends_with(":sensor-tamper"))
    );

    // Physical presence cell reaches Known (corroborated by independent failure domains)
    let physical_cell = frame
        .knowledge_cells
        .iter()
        .find(|c| {
            c.claim_id.ends_with(":unknown-presence") && !c.claim_id.starts_with("claim:policy:")
        })
        .ok_or("missing physical presence cell")?;
    assert_eq!(physical_cell.knowledge_state, KnowledgeState::Known);

    // Meaningful delta between basis and result
    let delta = classify_reference_meaningful_delta(&basis, &result)?;
    assert!(
        delta.classes.contains(&MeaningfulDeltaClass::Contradiction),
        "contradiction resolution must be reported: {:?}",
        delta.classes
    );
    assert_eq!(delta.priority, DeltaPriority::Critical);
    assert!(delta.is_non_coalescible());
    delta.validate()?;

    harness.cleanup();
    Ok(())
}

#[test]
fn test_multi_sensor_tamper_partial_restoration() -> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("multi-tamper-partial")?;

    // Observation with tamper on both power:alpha and power:beta
    let obs_tamper_a = harness.observation(
        "multi-tamper-partial",
        "lane0",
        40,
        "power:alpha",
        MockSemanticLabel::TamperLike,
    )?;
    let obs_tamper_b = harness.observation(
        "multi-tamper-partial",
        "lane1",
        41,
        "power:beta",
        MockSemanticLabel::TamperLike,
    )?;
    // And restoration for power:alpha only
    let obs_restore_a = harness.observation(
        "multi-tamper-partial",
        "lane2",
        42,
        "power:alpha",
        MockSemanticLabel::IntegrityRestored,
    )?;

    let decision = evaluate_unknown_presence(
        EventId::parse("event:tamper:multi-partial")?,
        vec![obs_tamper_a, obs_tamper_b, obs_restore_a],
    )?;
    let receipt = publish_reference_event(&decision, &mut harness.objects, &mut harness.authority)?;
    let situation =
        compile_reference_situation(test_request(&decision, &receipt)?, &harness.authority)?;

    let frame = &situation.capsule.frame;

    // Sensor integrity is still Unknown because power:beta remains tampered
    let integrity_cell = frame
        .knowledge_cells
        .iter()
        .find(|c| c.claim_id.ends_with(":sensor-integrity"))
        .ok_or("missing sensor-integrity cell")?;
    assert_eq!(integrity_cell.knowledge_state, KnowledgeState::Unknown);
    assert_eq!(
        integrity_cell.hypothesis,
        Some(HypothesisDisposition::Disfavored)
    );
    assert_eq!(integrity_cell.contradictions.len(), 1);

    // Protected tamper world remains active
    assert!(
        frame
            .world_envelope
            .adversarial_residuals
            .iter()
            .any(|w| w.protected && w.world_id.ends_with(":sensor-tamper"))
    );

    harness.cleanup();
    Ok(())
}

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
    BatchId, BudgetVector, CanonicalDecode, CanonicalEncode, CanonicalEncoder, CapsuleId,
    CaptureInterval, ContractBasis, ContractBasisRegistryBytes, ContractError, DeltaPriority,
    EffectJournal, EventEvidence, EventHypothesis, EventId, EventKind, EventState, EvidenceClass,
    EvidenceDelta, EvidenceEdgeRelation, HypothesisDisposition, IdempotencyKey, KnowledgeState,
    MeaningfulDeltaClass, MissionId, ObjectId, ObligationId, OperationId, Plane, PrincipalId,
    ProbabilityInterval, ResourcePressure, SensorId, SessionId, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits, ObjectManifest, VerifiedObjectCatalog};
use fss_publication::AuthorityPublisher;
use fss_reference::{
    DeliveryPlan, MockModelScript, MockModelSpec, MockSemanticLabel, PrepareAlertParams,
    ReferenceError, ReferenceEventReceipt, ReferenceModelObservation, ReferencePolicyAction,
    ReferencePolicyDecision, ReferenceProjectionSpec, ReferenceSituationRequest, VirtualCameraSpec,
    classify_reference_meaningful_delta, compile_reference_situation, evaluate_unknown_presence,
    execute_mock_model, prepare_reference_alert, project_reference_situation,
    publish_reference_event, run_reference_capture, ReferenceSituation,
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
            capture_id: CapsuleId::parse(format!(
                "capture:tamper-stickiness:{test_name}:{lane}:{seed}"
            ))?,
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

fn force_publish_event(
    harness: &mut TestHarness,
    decision: &ReferencePolicyDecision,
    prior_generation: Option<u64>,
) -> Result<ReferenceEventReceipt, Box<dyn Error>> {
    for model_receipt in &decision.event.model_receipts {
        harness.objects.require_verified(*model_receipt)?;
    }
    let event_bytes = decision.event.canonical_bytes();
    let event_object_digest = harness.objects.put_verified(&event_bytes)?;
    let mut revision_encoder = CanonicalEncoder::new();
    revision_encoder.text("fss.canonical.v1");
    revision_encoder.text("fss.event_hypothesis.v1");
    decision.event.encode_canonical(&mut revision_encoder);
    let event_revision_digest = harness.objects.put_verified(&revision_encoder.finish())?;
    let event_manifest = ObjectManifest::new(
        "event-revision",
        decision.event.model_receipts.iter().copied(),
        Some(event_object_digest),
    )?;
    let event_root = harness.objects.publish_manifest(event_manifest)?.root;
    let event_name = decision.event.event_id.as_str();
    let object_id = ObjectId::parse(format!("object:event:{event_name}"))?;
    let delta = EvidenceDelta {
        delta_id: format!("delta:event:{event_name}:{}", decision.event.revision),
        family: "event_revision".to_owned(),
        object_id: object_id.clone(),
        prior_generation,
        new_generation: decision.event.revision,
        validity: decision.event.interval,
        plane: Plane::Authority,
        payload_digest: event_root,
        witness_digest: Some(event_revision_digest),
        operation_id: None,
    };
    let mut prior_events = Vec::new();
    for batch in harness.authority.batches() {
        for d in &batch.deltas {
            let relevant_delta = d.object_id == object_id
                && d.family == "event_revision"
                && d.new_generation < decision.event.revision;
            if !relevant_delta {
                continue;
            }
            let Ok(manifest) = harness.objects.published_manifest(d.payload_digest) else {
                continue;
            };
            let Some(payload) = manifest
                .metadata_digest()
                .or_else(|| manifest.children().first().copied())
            else {
                continue;
            };
            let Ok(bytes) = harness.objects.read_verified(payload) else {
                continue;
            };
            if let Ok(rev) = EventHypothesis::from_canonical_bytes(bytes) {
                prior_events.push(rev);
            }
        }
    }
    prior_events.sort_by_key(|e| e.revision);
    let lineage_tamper_status = fss_core::event::compute_sensor_tamper_status(
        prior_events.iter(),
        Some(&decision.event.evidence),
    );
    let tamper_delta = EvidenceDelta {
        delta_id: format!("delta:event:{event_name}:tamper:{}", decision.event.revision),
        family: "sensor_tamper_status".to_owned(),
        object_id: ObjectId::parse(format!("object:event:{event_name}:tamper"))?,
        prior_generation,
        new_generation: decision.event.revision,
        validity: decision.event.interval,
        plane: Plane::Authority,
        payload_digest: event_root,
        witness_digest: Some(lineage_tamper_status.canonical_digest()),
        operation_id: None,
    };
    let mut tamper_encoder = CanonicalEncoder::new();
    lineage_tamper_status.encode_canonical(&mut tamper_encoder);
    let _ = harness.objects.put_verified(&tamper_encoder.finish())?;
    let authority_anchor = {
        let mut publisher = AuthorityPublisher::new(&harness.objects, &mut harness.authority);
        let batch = publisher.prepare_batch(
            BatchId::parse(format!(
                "batch:event:{event_name}:{}",
                decision.event.revision
            ))?,
            vec![delta, tamper_delta],
            [event_root],
        )?;
        publisher.append(batch)?
    };
    Ok(ReferenceEventReceipt {
        event_root,
        event_object_digest,
        event_revision_digest,
        authority_anchor,
        lineage_tamper_status,
    })
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
    let basis_physical = basis
        .situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|c| {
            c.claim_id.ends_with(":unknown-presence") && !c.claim_id.starts_with("claim:policy:")
        })
        .ok_or("missing physical presence cell in basis")?;
    assert_ne!(basis_physical.knowledge_state, KnowledgeState::Known);

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
    let pub_err = publish_reference_event(
        &bypass_decision,
        &mut harness.objects,
        &mut harness.authority,
    );
    assert!(
        matches!(
            pub_err,
            Err(ReferenceError::Contract(ContractError::SensorIntegrityRisk))
        ),
        "publish_reference_event must reject bypass dropping unretired tamper: {pub_err:?}"
    );

    // Lineage stickiness holds in compilation: compile_reference_situation uses lineage open-tamper
    // status to cap physical presence to Unknown, keeping it from reaching Known (Item 3).
    let bypass_receipt = force_publish_event(&mut harness, &bypass_decision, Some(1))?;
    let mut request = test_request(&bypass_decision, &bypass_receipt)?;
    request.revision = 2;
    request.previous_anchor = Some(basis.situation.capsule.anchor.clone());
    request.created_at = TimestampNs(2_000);
    let result = project_reference_situation(
        compile_reference_situation(request, &harness.authority)?,
        &test_spec(10_000),
    )?;

    // By lineage stickiness, sensor-integrity cell remains present with open tamper
    let integrity_cell = result
        .situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|c| c.claim_id.ends_with(":sensor-integrity"))
        .ok_or("missing sensor-integrity cell in bypass result")?;
    assert_eq!(integrity_cell.knowledge_state, KnowledgeState::Unknown);
    assert!(!integrity_cell.contradictions.is_empty());

    // Physical presence must NOT become Known while prior tamper is unretired (Item 3)
    let bypass_physical_cell = result
        .situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|c| {
            c.claim_id.ends_with(":unknown-presence") && !c.claim_id.starts_with("claim:policy:")
        })
        .ok_or("missing physical presence cell in bypass result")?;
    assert_ne!(
        bypass_physical_cell.knowledge_state,
        KnowledgeState::Known,
        "bypass physical presence must not reach Known while prior tamper is unretired"
    );

    // Defense in depth: forged receipt defense (kills M3):
    // If a caller passes a forged receipt (e.g. defaulted status), compile_reference_situation
    // and prepare_reference_alert MUST both refuse it!
    let omitting_receipt = ReferenceEventReceipt {
        lineage_tamper_status: fss_core::SensorTamperStatus::default(),
        ..bypass_receipt.clone()
    };
    let mut omit_request = test_request(&bypass_decision, &omitting_receipt)?;
    omit_request.revision = 2;
    omit_request.previous_anchor = Some(basis.situation.capsule.anchor.clone());
    omit_request.created_at = TimestampNs(2_000);
    let forge_situation_err = compile_reference_situation(omit_request, &harness.authority);
    assert!(
        matches!(
            forge_situation_err,
            Err(ReferenceError::InvalidSpec("forged_event_receipt_tamper_status"))
        ),
        "forged event receipt must be refused by compile_reference_situation"
    );

    // Prepare alert with forged receipt must also be refused:
    let mut journal = EffectJournal::new();
    let alert_params = PrepareAlertParams {
        operation_id: OperationId::parse("op:alert:forged-receipt")?,
        obligation_id: ObligationId::parse("obligation:alert:forged-receipt")?,
        idempotency_key: IdempotencyKey::parse("idem-forged-test")?,
        channel: "security-ops".to_string(),
        decision: &bypass_decision,
        event_receipt: &omitting_receipt,
        authority: &harness.authority,
        now: TimestampNs(2_000),
    };
    let forge_alert_err = prepare_reference_alert(alert_params, &mut journal);
    assert!(
        matches!(
            forge_alert_err,
            Err(ReferenceError::InvalidSpec("forged_event_receipt_tamper_status"))
        ),
        "forged event receipt must be refused by prepare_reference_alert"
    );

    // Classifying the delta between basis and a situation where the sensor integrity cell was omitted:
    // The missing prior contradiction MUST NOT produce a coalescible High delta!
    // It MUST be classified as Contradiction and Critical priority.
    let mut modified_capsule = basis.situation.capsule.clone();
    modified_capsule
        .frame
        .knowledge_cells
        .retain(|c| !c.claim_id.ends_with(":sensor-integrity"));
    let modified_situation =
        ReferenceSituation::new(modified_capsule, basis.situation.proof_roots.clone());
    let modified_basis = project_reference_situation(modified_situation, &test_spec(10_000))?;
    let delta = classify_reference_meaningful_delta(&basis, &modified_basis)?;
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
        "lane0",
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
    let revised = basis_decision.event.supersede(
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
        std::slice::from_ref(&basis_decision.event),
    )?;
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
        compile_reference_situation(request, &harness.authority)?,
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

    // Rev 1: Tamper on both power:alpha (lane0) and power:beta (lane1)
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

    let decision_rev1 = evaluate_unknown_presence(
        EventId::parse("event:tamper:multi-partial")?,
        vec![obs_tamper_a, obs_tamper_b],
    )?;
    let receipt_rev1 =
        publish_reference_event(&decision_rev1, &mut harness.objects, &mut harness.authority)?;

    // Rev 2: Evidenced restoration on power:alpha only (same lane0, seed 42)
    let obs_restore_a = harness.observation(
        "multi-tamper-partial",
        "lane0",
        42,
        "power:alpha",
        MockSemanticLabel::IntegrityRestored,
    )?;
    let ReferencePolicyDecision {
        event: candidate,
        action,
    } = evaluate_unknown_presence(
        EventId::parse("event:tamper:multi-partial")?,
        vec![obs_restore_a],
    )?;
    let revised = decision_rev1.event.supersede(
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
        std::slice::from_ref(&decision_rev1.event),
    )?;
    let decision_rev2 = ReferencePolicyDecision {
        event: revised,
        action,
    };
    let receipt_rev2 =
        publish_reference_event(&decision_rev2, &mut harness.objects, &mut harness.authority)?;
    let mut request = test_request(&decision_rev2, &receipt_rev2)?;
    request.revision = 2;
    request.previous_anchor = Some(receipt_rev1.authority_anchor);
    let situation = compile_reference_situation(request, &harness.authority)?;

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

#[test]
fn test_corroborated_with_open_tamper_cannot_reach_known() -> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("corroborated-open-tamper")?;

    // Step 1: Rev 1 has tamper observation on power:gamma
    let obs_tamper = harness.observation(
        "corroborated-open-tamper",
        "lane2",
        52,
        "power:gamma",
        MockSemanticLabel::TamperLike,
    )?;
    let decision_rev1 = evaluate_unknown_presence(
        EventId::parse("event:tamper:corroborated-open-tamper")?,
        vec![obs_tamper],
    )?;
    let receipt_rev1 =
        publish_reference_event(&decision_rev1, &mut harness.objects, &mut harness.authority)?;

    // Step 2: Rev 2 has two person observations on power:alpha and power:beta
    let obs_person_a = harness.observation(
        "corroborated-open-tamper",
        "lane0",
        50,
        "power:alpha",
        MockSemanticLabel::PersonLike,
    )?;
    let obs_person_b = harness.observation(
        "corroborated-open-tamper",
        "lane1",
        51,
        "power:beta",
        MockSemanticLabel::PersonLike,
    )?;

    let ReferencePolicyDecision {
        event: candidate,
        action,
    } = evaluate_unknown_presence(
        EventId::parse("event:tamper:corroborated-open-tamper")?,
        vec![obs_person_a, obs_person_b],
    )?;

    // Craft revision 2 superseding rev1, with Corroborated state and omitting tamper
    let rev2 = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_string(),
        event_id: decision_rev1.event.event_id.clone(),
        revision: 2,
        supersedes: Some(decision_rev1.event.revision_digest()),
        state: EventState::Corroborated,
        kind: EventKind::UnknownPresence,
        interval: candidate.interval,
        uncertainty_reason: None,
        zone_ids: Vec::new(),
        track_ids: Vec::new(),
        probability: candidate.probability,
        evidence: candidate.evidence,
        model_receipts: candidate.model_receipts,
        decision_path: candidate.decision_path,
    };
    rev2.validate()?;
    let decision_rev2 = ReferencePolicyDecision {
        event: rev2,
        action,
    };

    // Force-publish to authority to verify situation compilation defense-in-depth against mutant M5
    let receipt_rev2 = force_publish_event(&mut harness, &decision_rev2, Some(1))?;
    let mut request = test_request(&decision_rev2, &receipt_rev2)?;
    request.revision = 2;
    request.previous_anchor = Some(receipt_rev1.authority_anchor);
    let situation = compile_reference_situation(request, &harness.authority)?;
    let physical_cell = situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|c| {
            c.claim_id.ends_with(":unknown-presence") && !c.claim_id.starts_with("claim:policy:")
        })
        .ok_or("missing physical presence cell")?;

    // Mutant M5 check: physical knowledge state must remain Unknown, NOT Known
    assert_eq!(physical_cell.knowledge_state, KnowledgeState::Unknown);
    assert_ne!(physical_cell.knowledge_state, KnowledgeState::Known);

    harness.cleanup();
    Ok(())
}

#[test]
fn test_restoration_with_no_prior_tamper_does_not_produce_known_integrity_cell()
-> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("restoration-no-prior-tamper")?;

    let obs_restore = harness.observation(
        "restoration-no-prior-tamper",
        "lane0",
        60,
        "power:alpha",
        MockSemanticLabel::IntegrityRestored,
    )?;

    let decision = evaluate_unknown_presence(
        EventId::parse("event:tamper:no-prior-tamper")?,
        vec![obs_restore],
    )?;

    // publish_reference_event must reject revision 1 containing an unevidenced restoration
    let pub_err = publish_reference_event(&decision, &mut harness.objects, &mut harness.authority);
    assert!(
        matches!(
            pub_err,
            Err(ReferenceError::Contract(ContractError::EvidenceRequired))
        ),
        "expected EvidenceRequired when publishing restoration with no prior tamper: {pub_err:?}"
    );

    // Force-publish to verify situation compilation produces NO integrity cell for revision 1
    let receipt = force_publish_event(&mut harness, &decision, None)?;
    let situation =
        compile_reference_situation(test_request(&decision, &receipt)?, &harness.authority)?;

    // Restoration with no prior tamper must NOT produce a Known/Supported integrity cell
    assert!(
        !situation
            .capsule
            .frame
            .knowledge_cells
            .iter()
            .any(|c| c.claim_id.ends_with(":sensor-integrity")),
        "sensor-integrity cell must be omitted when restoration has no prior tamper"
    );

    harness.cleanup();
    Ok(())
}

#[test]
fn test_pr4_pr5_restoration_retiring_nothing_yields_no_integrity_cell() -> Result<(), Box<dyn Error>> {
    let mut harness = TestHarness::new("pr4-pr5-retire-nothing")?;

    // Genesis: Tamper on cam-1
    let obs_tamper_1 = harness.observation(
        "pr4-pr5-tamper",
        "lane0",
        50,
        "power:alpha",
        MockSemanticLabel::TamperLike,
    )?;
    let decision_rev1 = evaluate_unknown_presence(
        EventId::parse("event:tamper:pr4-pr5")?,
        vec![obs_tamper_1],
    )?;
    let receipt_rev1 =
        publish_reference_event(&decision_rev1, &mut harness.objects, &mut harness.authority)?;

    // Revision 2: Has a restoration on cam-2 (which was never tampered!).
    // This restoration retires NOTHING because cam-2 was not tampered.
    let obs_restore_cam2 = harness.observation(
        "pr4-pr5-restore-cam2",
        "lane1",
        80,
        "power:beta",
        MockSemanticLabel::IntegrityRestored,
    )?;
    let ReferencePolicyDecision { event: cand2, action } = evaluate_unknown_presence(
        EventId::parse("event:tamper:pr4-pr5")?,
        vec![obs_restore_cam2],
    )?;
    let rev2 = decision_rev1.event.supersede(
        EventSupersedeParams {
            state: cand2.state,
            kind: cand2.kind,
            interval: cand2.interval,
            uncertainty_reason: cand2.uncertainty_reason,
            zone_ids: cand2.zone_ids,
            track_ids: cand2.track_ids,
            probability: cand2.probability,
            evidence: cand2.evidence,
            model_receipts: cand2.model_receipts,
            decision_path: cand2.decision_path,
        },
        std::slice::from_ref(&decision_rev1.event),
    )?;
    let decision_rev2 = ReferencePolicyDecision { event: rev2, action };
    let receipt_rev2 = force_publish_event(&mut harness, &decision_rev2, Some(1))?;
    let mut req2 = test_request(&decision_rev2, &receipt_rev2)?;
    req2.revision = 2;
    req2.previous_anchor = Some(receipt_rev1.authority_anchor.clone());
    let sit2 = compile_reference_situation(req2, &harness.authority)?;

    // PR5: The situation must NOT have a Known/Supported integrity cell because
    // the restoration retired nothing!
    assert!(
        !sit2
            .capsule
            .frame
            .knowledge_cells
            .iter()
            .any(|c| c.claim_id.ends_with(":sensor-integrity") && c.knowledge_state == KnowledgeState::Known),
        "sensor-integrity must NOT be Known when restoration retired nothing"
    );

    harness.cleanup();
    Ok(())
}

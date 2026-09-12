#![forbid(unsafe_code)]

//! Integration contract tests for INV-092 context selection invariants.
//!
//! INV-092: Context selection may remove redundancy but must not remove protected
//! high-loss worlds, contradictions, or required warnings.

use std::collections::BTreeSet;
use std::error::Error;

use fss_core::{
    ActionAffordance, AffordanceClass, BudgetVector, Completeness, CompressionTransformKind,
    ContentDigest, ContractBasis, ContractBasisRegistryBytes, ContractError, KnowledgeCell,
    KnowledgeState, LedgerAnchor, MissionId, ObligationId, PossibleWorld, PrincipalId,
    ProvenanceClass, ResourcePressure, SessionId, SituationCapsule, SituationFrame, TimestampNs,
    WorldEnvelope,
};
use fss_reference::{
    RedundancyRecord, ReferenceError, ReferenceProjectionSpec, ReferenceSituation,
    project_reference_situation,
};

fn test_basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(
        ContractBasisRegistryBytes::new(
            b"schemas",
            b"operations",
            b"views",
            b"capabilities",
            b"errors",
            b"costs",
            "fss-reference:inv092-contract-test",
        )
        .with_accepted_nightly("nightly-2026-08-31"),
    )
}

fn test_spec(target_tokens: u64) -> Result<ReferenceProjectionSpec, Box<dyn Error>> {
    let available = BudgetVector::builder()
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
        .build()?;

    let reserved = BudgetVector::builder()
        .latency_ms(100)
        .tokens(100)
        .bytes(1_000)
        .storage_operations(1)
        .build()?;

    Ok(ReferenceProjectionSpec {
        view_id: "AVIEW-INV092".to_owned(),
        available_resources: available,
        reserved_resources: reserved,
        pressure: ResourcePressure::Nominal,
        degraded_dimensions: BTreeSet::new(),
        target_tokens,
    })
}

fn build_probe_affordance(
    affordance_id: &str,
    target: &str,
    retained_worlds: BTreeSet<String>,
) -> Result<ActionAffordance, Box<dyn Error>> {
    let cost = BudgetVector::builder()
        .latency_ms(100)
        .tokens(10)
        .bytes(128)
        .cpu_millis(5)
        .accelerator_millis(2)
        .energy_millijoules(7)
        .privacy_exposure(0.1)
        .build()?;

    Ok(ActionAffordance {
        affordance_id: affordance_id.to_owned(),
        operation: "investigate".to_owned(),
        target: target.to_owned(),
        rationale: "Acquire corroborating evidence for candidate hypothesis.".to_owned(),
        class: AffordanceClass::Probe,
        supported_worlds: retained_worlds,
        unsafe_worlds: BTreeSet::new(),
        required_capabilities: BTreeSet::from(["capability:evidence.query".to_owned()]),
        cost,
        reversible: true,
        branch_predicate: None,
    })
}

#[test]
fn test_inv092_tiny_budget_fails_closed_never_drops_protected_world() -> Result<(), Box<dyn Error>>
{
    let anchor = LedgerAnchor::genesis("site:inv092:budget");
    let evidence_digest = ContentDigest::sha256(b"protected-world-evidence");

    let protected_world = PossibleWorld {
        world_id: "world:protected:high-loss".to_owned(),
        description: "A protected high-loss world must remain live under any budget.".to_owned(),
        claim_ids: BTreeSet::from(["claim:critical-hazard".to_owned()]),
        evidence: vec![evidence_digest],
        consequence_severity: 5,
        protected: true,
    };
    let optional_world = PossibleWorld {
        world_id: "world:optional:low-loss".to_owned(),
        description: "An optional low-loss possible world that may be omitted under tight budget."
            .to_owned(),
        claim_ids: BTreeSet::from(["claim:minor-observation".to_owned()]),
        evidence: vec![evidence_digest],
        consequence_severity: 2,
        protected: false,
    };

    let envelope = WorldEnvelope {
        envelope_id: "envelope:inv092:budget".to_owned(),
        objective_id: "objective:inv092:budget".to_owned(),
        anchor: anchor.clone(),
        nominal_claim_ids: BTreeSet::from(["claim:critical-hazard".to_owned()]),
        certified_core_claim_ids: BTreeSet::new(),
        alternatives: vec![protected_world, optional_world],
        adversarial_residuals: Vec::new(),
        common_invariants: BTreeSet::from(["invariant:preserve-critical".to_owned()]),
        coverage_boundary_handles: BTreeSet::from(["fss://coverage/inv092".to_owned()]),
    };

    let affordance = build_probe_affordance(
        "affordance:probe:critical",
        "fss://event/inv092/evidence",
        envelope.world_ids(),
    )?;

    let frame = SituationFrame {
        frame_id: "frame:inv092:budget".to_owned(),
        objective_id: "objective:inv092:budget".to_owned(),
        anchor: anchor.clone(),
        world_envelope: envelope,
        knowledge_cells: Vec::new(),
        now: vec!["Hazard condition evaluation in progress.".to_owned()],
        changed: Vec::new(),
        why: vec!["High-loss world identified by safety classifier.".to_owned()],
        unknown: vec!["Corroboration from secondary sensor pending.".to_owned()],
        at_risk: vec!["Immediate containment action required if active.".to_owned()],
        next: vec!["affordance:probe:critical".to_owned()],
        evidence_handles: BTreeSet::from([format!("fss://proof/{evidence_digest}")]),
    };

    let capsule = SituationCapsule {
        capsule_id: "situation:inv092:budget".to_owned(),
        revision: 1,
        contract_basis: test_basis(),
        mission_id: MissionId::parse("mission:inv092:budget")?,
        session_id: SessionId::parse("session:inv092:budget")?,
        principal_id: PrincipalId::parse("principal:inv092")?,
        anchor,
        previous_anchor: None,
        frame,
        obligations: vec![ObligationId::parse("obligation:inv092:budget")?],
        affordances: vec![affordance],
        completeness: Completeness::Partial,
        created_at: TimestampNs(1_000_000),
        mission_state: None,
    };
    capsule.validate()?;

    let situation = ReferenceSituation {
        capsule,
        proof_roots: BTreeSet::from([evidence_digest]),
    };

    // 1. Ample budget: protected world is retained in context pack.
    let ample_publication = project_reference_situation(situation.clone(), &test_spec(10_000)?)?;
    assert_eq!(
        ample_publication.verify()?,
        ample_publication.publication_digest
    );
    assert!(
        ample_publication
            .context_pack
            .items
            .iter()
            .any(|item| item.item_id == "context:world:world:protected:high-loss")
    );
    assert_eq!(
        ample_publication
            .compression_receipt
            .critical_preservation
            .omitted_critical_items,
        0
    );

    // 2. Tiny budget (target_tokens = 5): fails closed with BudgetExhausted.
    // It must NEVER drop the protected world to meet budget.
    let tiny_result = project_reference_situation(situation, &test_spec(5)?);
    assert!(matches!(
        tiny_result,
        Err(ReferenceError::Contract(ContractError::BudgetExhausted))
    ));

    Ok(())
}

#[test]
fn test_inv092_duplicate_contradiction_deduplicated_with_recorded_reason()
-> Result<(), Box<dyn Error>> {
    let anchor = LedgerAnchor::genesis("site:inv092:contradiction");
    let evidence_digest = ContentDigest::sha256(b"contradiction-evidence");
    let contra_digest_1 = ContentDigest::sha256(b"contradiction-digest-1");
    let contra_digest_2 = ContentDigest::sha256(b"contradiction-digest-2");

    let world = PossibleWorld {
        world_id: "world:inv092:contradiction".to_owned(),
        description: "Contradiction handling under INV-092.".to_owned(),
        claim_ids: BTreeSet::from(["claim:alpha".to_owned(), "claim:gamma".to_owned()]),
        evidence: vec![evidence_digest],
        consequence_severity: 4,
        protected: true,
    };

    let envelope = WorldEnvelope {
        envelope_id: "envelope:inv092:contradiction".to_owned(),
        objective_id: "objective:inv092:contradiction".to_owned(),
        anchor: anchor.clone(),
        nominal_claim_ids: BTreeSet::from(["claim:alpha".to_owned()]),
        certified_core_claim_ids: BTreeSet::new(),
        alternatives: vec![world],
        adversarial_residuals: Vec::new(),
        common_invariants: BTreeSet::from(["invariant:contradiction-retention".to_owned()]),
        coverage_boundary_handles: BTreeSet::from(["fss://coverage/contra".to_owned()]),
    };

    let affordance = build_probe_affordance(
        "affordance:probe:contra",
        "fss://event/inv092/contra",
        envelope.world_ids(),
    )?;

    // Cell Alpha and Cell Beta report the EXACT SAME contradiction statement and contradicting root.
    // Cell Beta is a duplicate contradiction of Cell Alpha.
    let cell_alpha = KnowledgeCell {
        claim_id: "claim:target:cam1".to_owned(),
        statement: "Subject identified as authorized operator".to_owned(),
        knowledge_state: KnowledgeState::Conflicted,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![evidence_digest],
        contradictions: vec![contra_digest_1],
        valid_until: None,
    };
    let cell_beta = KnowledgeCell {
        claim_id: "claim:target:cam2".to_owned(),
        statement: "Subject identified as authorized operator".to_owned(),
        knowledge_state: KnowledgeState::Conflicted,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![evidence_digest],
        contradictions: vec![contra_digest_1],
        valid_until: None,
    };

    // Cell Gamma reports a DISTINCT contradiction with a different statement and different root.
    let cell_gamma = KnowledgeCell {
        claim_id: "claim:perimeter:sensor3".to_owned(),
        statement: "Perimeter gate 3 lock status disputed".to_owned(),
        knowledge_state: KnowledgeState::Conflicted,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![evidence_digest],
        contradictions: vec![contra_digest_2],
        valid_until: None,
    };

    let frame = SituationFrame {
        frame_id: "frame:inv092:contradiction".to_owned(),
        objective_id: "objective:inv092:contradiction".to_owned(),
        anchor: anchor.clone(),
        world_envelope: envelope,
        knowledge_cells: vec![cell_alpha, cell_beta, cell_gamma],
        now: vec!["Contradiction resolution in progress.".to_owned()],
        changed: Vec::new(),
        why: vec!["Multiple sensor readings disagree on subject identity.".to_owned()],
        unknown: vec!["Biometric signature ambiguity unresolved.".to_owned()],
        at_risk: vec!["Unauthorized facility entry risk.".to_owned()],
        next: vec!["affordance:probe:contra".to_owned()],
        evidence_handles: BTreeSet::from([format!("fss://proof/{evidence_digest}")]),
    };

    let capsule = SituationCapsule {
        capsule_id: "situation:inv092:contradiction".to_owned(),
        revision: 1,
        contract_basis: test_basis(),
        mission_id: MissionId::parse("mission:inv092:contra")?,
        session_id: SessionId::parse("session:inv092:contra")?,
        principal_id: PrincipalId::parse("principal:inv092")?,
        anchor,
        previous_anchor: None,
        frame,
        obligations: vec![ObligationId::parse("obligation:inv092:contra")?],
        affordances: vec![affordance],
        completeness: Completeness::Partial,
        created_at: TimestampNs(2_000_000),
        mission_state: None,
    };
    capsule.validate()?;

    let situation = ReferenceSituation {
        capsule,
        proof_roots: BTreeSet::from([evidence_digest]),
    };

    let publication = project_reference_situation(situation, &test_spec(10_000)?)?;
    assert_eq!(publication.verify()?, publication.publication_digest);

    // Verify context pack items:
    // Retained representative for alpha/beta is present:
    assert!(
        publication
            .context_pack
            .items
            .iter()
            .any(|item| item.item_id == "context:contradiction:claim:target:cam1")
    );
    // Distinct contradiction gamma is preserved:
    assert!(
        publication
            .context_pack
            .items
            .iter()
            .any(|item| item.item_id == "context:contradiction:claim:perimeter:sensor3")
    );
    // Duplicate contradiction beta was NOT included:
    assert!(
        !publication
            .context_pack
            .items
            .iter()
            .any(|item| item.item_id == "context:contradiction:claim:target:cam2")
    );

    // Verify redundancy records:
    let redundancy_records = publication.redundancy_records();
    let contra_dedup = redundancy_records
        .iter()
        .find(|r| r.dropped_item_id == "context:contradiction:claim:target:cam2");
    assert!(contra_dedup.is_some());
    let contra_record: &RedundancyRecord = contra_dedup.ok_or(ContractError::NotFound)?;
    assert_eq!(
        contra_record.retained_item_id,
        "context:contradiction:claim:target:cam1"
    );
    assert_eq!(contra_record.kind, "contradiction");
    assert!(
        contra_record
            .reason
            .contains("retained earlier representative")
    );

    // Verify compression receipt contains Deduplicate transform:
    assert!(
        publication
            .compression_receipt
            .transforms
            .iter()
            .any(|t| t.kind == CompressionTransformKind::Deduplicate
                && t.scope == "contradiction:context:contradiction:claim:target:cam2")
    );

    // Invariant holds: critical preservation is completely lossless
    assert!(
        publication
            .compression_receipt
            .critical_preservation
            .is_lossless()
    );

    Ok(())
}

#[test]
fn test_inv092_warning_looking_redundant_is_preserved_while_exact_duplicate_is_deduplicated()
-> Result<(), Box<dyn Error>> {
    let anchor = LedgerAnchor::genesis("site:inv092:warnings");
    let evidence_digest = ContentDigest::sha256(b"warnings-evidence");

    let world = PossibleWorld {
        world_id: "world:inv092:warnings".to_owned(),
        description: "Warning preservation under INV-092.".to_owned(),
        claim_ids: BTreeSet::from(["claim:warning".to_owned()]),
        evidence: vec![evidence_digest],
        consequence_severity: 4,
        protected: true,
    };

    let envelope = WorldEnvelope {
        envelope_id: "envelope:inv092:warnings".to_owned(),
        objective_id: "objective:inv092:warnings".to_owned(),
        anchor: anchor.clone(),
        nominal_claim_ids: BTreeSet::from(["claim:warning".to_owned()]),
        certified_core_claim_ids: BTreeSet::new(),
        alternatives: vec![world],
        adversarial_residuals: Vec::new(),
        common_invariants: BTreeSet::from(["invariant:warnings".to_owned()]),
        coverage_boundary_handles: BTreeSet::from(["fss://coverage/warnings".to_owned()]),
    };

    let affordance = build_probe_affordance(
        "affordance:probe:warn",
        "fss://event/inv092/warn",
        envelope.world_ids(),
    )?;

    // Warning 1 and Warning 2 look syntactically similar (same prefix & domain pattern),
    // but refer to distinct sensors and quadrants. Both MUST be preserved.
    let warn_north = "Warning: Sensor-01 acoustic baseline deviation in sector North-Quadrant-A";
    let warn_south = "Warning: Sensor-02 acoustic baseline deviation in sector North-Quadrant-B";
    // Warning 3 is an EXACT duplicate of Warning 1. It MUST be deduplicated with a recorded reason.
    let warn_north_duplicate =
        "Warning: Sensor-01 acoustic baseline deviation in sector North-Quadrant-A";

    let frame = SituationFrame {
        frame_id: "frame:inv092:warnings".to_owned(),
        objective_id: "objective:inv092:warnings".to_owned(),
        anchor: anchor.clone(),
        world_envelope: envelope,
        knowledge_cells: Vec::new(),
        now: vec!["Acoustic anomaly monitoring in progress.".to_owned()],
        changed: Vec::new(),
        why: vec!["Multiple acoustic deviations detected across quadrants.".to_owned()],
        unknown: vec!["Vibration correlation pending.".to_owned()],
        at_risk: vec![
            warn_north.to_owned(),
            warn_south.to_owned(),
            warn_north_duplicate.to_owned(),
        ],
        next: vec!["affordance:probe:warn".to_owned()],
        evidence_handles: BTreeSet::from([format!("fss://proof/{evidence_digest}")]),
    };

    let capsule = SituationCapsule {
        capsule_id: "situation:inv092:warnings".to_owned(),
        revision: 1,
        contract_basis: test_basis(),
        mission_id: MissionId::parse("mission:inv092:warn")?,
        session_id: SessionId::parse("session:inv092:warn")?,
        principal_id: PrincipalId::parse("principal:inv092")?,
        anchor,
        previous_anchor: None,
        frame,
        obligations: vec![ObligationId::parse("obligation:inv092:warn")?],
        affordances: vec![affordance],
        completeness: Completeness::Partial,
        created_at: TimestampNs(3_000_000),
        mission_state: None,
    };
    capsule.validate()?;

    let situation = ReferenceSituation {
        capsule,
        proof_roots: BTreeSet::from([evidence_digest]),
    };

    let publication = project_reference_situation(situation, &test_spec(10_000)?)?;
    assert_eq!(publication.verify()?, publication.publication_digest);

    // Both distinct warnings MUST be present in context pack:
    let at_risk_items: Vec<_> = publication
        .context_pack
        .items
        .iter()
        .filter(|item| item.kind == "at_risk")
        .collect();

    // Exactly 2 distinct at-risk items (warn_north and warn_south), not 3:
    assert_eq!(at_risk_items.len(), 2);
    assert!(at_risk_items.iter().any(|item| item.content == warn_north));
    assert!(at_risk_items.iter().any(|item| item.content == warn_south));

    // Redundancy records must record the drop of the exact duplicate warning:
    let redundancy_records = publication.redundancy_records();
    let warn_north_id = format!(
        "context:at-risk:{}",
        ContentDigest::sha256(warn_north.as_bytes())
    );
    let warn_dedup = redundancy_records
        .iter()
        .find(|r| r.dropped_item_id == warn_north_id);
    assert!(warn_dedup.is_some());
    let warn_record: &RedundancyRecord = warn_dedup.ok_or(ContractError::NotFound)?;
    assert_eq!(warn_record.retained_item_id, warn_north_id);
    assert_eq!(warn_record.kind, "at_risk");

    // Syntactically similar warn_south was NOT deduplicated:
    let warn_south_id = format!(
        "context:at-risk:{}",
        ContentDigest::sha256(warn_south.as_bytes())
    );
    assert!(
        !redundancy_records
            .iter()
            .any(|r| r.dropped_item_id == warn_south_id)
    );

    // Critical preservation remains completely lossless:
    assert!(
        publication
            .compression_receipt
            .critical_preservation
            .is_lossless()
    );

    Ok(())
}

#[test]
fn test_inv092_planted_negative_verify_rejects_omitted_critical_item() -> Result<(), Box<dyn Error>>
{
    let anchor = LedgerAnchor::genesis("site:inv092:planted");
    let evidence_digest = ContentDigest::sha256(b"planted-negative-evidence");

    let protected_world = PossibleWorld {
        world_id: "world:inv092:planted".to_owned(),
        description: "Protected world for planted negative test.".to_owned(),
        claim_ids: BTreeSet::from(["claim:planted".to_owned()]),
        evidence: vec![evidence_digest],
        consequence_severity: 5,
        protected: true,
    };

    let envelope = WorldEnvelope {
        envelope_id: "envelope:inv092:planted".to_owned(),
        objective_id: "objective:inv092:planted".to_owned(),
        anchor: anchor.clone(),
        nominal_claim_ids: BTreeSet::from(["claim:planted".to_owned()]),
        certified_core_claim_ids: BTreeSet::new(),
        alternatives: vec![protected_world],
        adversarial_residuals: Vec::new(),
        common_invariants: BTreeSet::from(["invariant:planted".to_owned()]),
        coverage_boundary_handles: BTreeSet::from(["fss://coverage/planted".to_owned()]),
    };

    let affordance = build_probe_affordance(
        "affordance:probe:planted",
        "fss://event/inv092/planted",
        envelope.world_ids(),
    )?;

    let frame = SituationFrame {
        frame_id: "frame:inv092:planted".to_owned(),
        objective_id: "objective:inv092:planted".to_owned(),
        anchor: anchor.clone(),
        world_envelope: envelope,
        knowledge_cells: Vec::new(),
        now: vec!["Testing planted negative rejection.".to_owned()],
        changed: Vec::new(),
        why: vec!["Planted negative verification.".to_owned()],
        unknown: Vec::new(),
        at_risk: vec!["Critical alert requirement.".to_owned()],
        next: vec!["affordance:probe:planted".to_owned()],
        evidence_handles: BTreeSet::from([format!("fss://proof/{evidence_digest}")]),
    };

    let capsule = SituationCapsule {
        capsule_id: "situation:inv092:planted".to_owned(),
        revision: 1,
        contract_basis: test_basis(),
        mission_id: MissionId::parse("mission:inv092:planted")?,
        session_id: SessionId::parse("session:inv092:planted")?,
        principal_id: PrincipalId::parse("principal:inv092")?,
        anchor,
        previous_anchor: None,
        frame,
        obligations: vec![ObligationId::parse("obligation:inv092:planted")?],
        affordances: vec![affordance],
        completeness: Completeness::Partial,
        created_at: TimestampNs(4_000_000),
        mission_state: None,
    };
    capsule.validate()?;

    let situation = ReferenceSituation {
        capsule,
        proof_roots: BTreeSet::from([evidence_digest]),
    };

    let publication = project_reference_situation(situation, &test_spec(10_000)?)?;
    assert_eq!(publication.verify()?, publication.publication_digest);

    // Planted negative 1: Mutate publication to simulate omitting a critical item from critical_preservation
    let mut bad_preservation = publication.clone();
    bad_preservation
        .compression_receipt
        .critical_preservation
        .omitted_critical_items = 1;

    // Must fail closed (receipt validation fails with BudgetExhausted when critical preservation is not lossless):
    let verify_res1 = bad_preservation.verify();
    assert!(matches!(
        verify_res1,
        Err(ReferenceError::Contract(ContractError::BudgetExhausted))
    ));

    // Planted negative 2: Mutate publication to omit the required protected world from context_pack.items
    let mut missing_critical = publication;
    missing_critical
        .context_pack
        .items
        .retain(|item| item.item_id != "context:world:world:inv092:planted");

    // Must fail closed (DigestMismatch from pack verification or EvidenceRequired from missing required item):
    let verify_res2 = missing_critical.verify();
    assert!(verify_res2.is_err());

    Ok(())
}

#[test]
fn test_contradiction_dedup_must_not_drop_independent_sensor_evidence() -> Result<(), Box<dyn Error>>
{
    let anchor = LedgerAnchor::genesis("site:inv092:adv1");
    let evidence_cam1 = ContentDigest::sha256(b"cam1-raw-frame-evidence");
    let evidence_cam2 = ContentDigest::sha256(b"cam2-raw-frame-evidence");
    let contra_root = ContentDigest::sha256(b"door-badge-reader-contradiction");

    let world = PossibleWorld {
        world_id: "world:adv:1".to_owned(),
        description: "World 1".to_owned(),
        claim_ids: BTreeSet::from(["claim:cam1".to_owned()]),
        evidence: vec![evidence_cam1],
        consequence_severity: 4,
        protected: true,
    };
    let envelope = WorldEnvelope {
        envelope_id: "envelope:adv:1".to_owned(),
        objective_id: "objective:adv:1".to_owned(),
        anchor: anchor.clone(),
        nominal_claim_ids: BTreeSet::from(["claim:cam1".to_owned()]),
        certified_core_claim_ids: BTreeSet::new(),
        alternatives: vec![world],
        adversarial_residuals: Vec::new(),
        common_invariants: BTreeSet::new(),
        coverage_boundary_handles: BTreeSet::new(),
    };

    // Two independent cameras observe the same subject, contradicted by the badge reader.
    // Cam 1 has evidence_cam1; Cam 2 has evidence_cam2.
    let cell_cam1 = KnowledgeCell {
        claim_id: "claim:cam1".to_owned(),
        statement: "Subject identified as authorized personnel".to_owned(),
        knowledge_state: KnowledgeState::Conflicted,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![evidence_cam1],
        contradictions: vec![contra_root],
        valid_until: None,
    };
    let cell_cam2 = KnowledgeCell {
        claim_id: "claim:cam2".to_owned(),
        statement: "Subject identified as authorized personnel".to_owned(),
        knowledge_state: KnowledgeState::Conflicted,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![evidence_cam2],
        contradictions: vec![contra_root],
        valid_until: None,
    };

    let frame = SituationFrame {
        frame_id: "frame:adv:1".to_owned(),
        objective_id: "objective:adv:1".to_owned(),
        anchor: anchor.clone(),
        world_envelope: envelope,
        knowledge_cells: vec![cell_cam1, cell_cam2],
        now: vec!["Monitoring".to_owned()],
        changed: Vec::new(),
        why: Vec::new(),
        unknown: Vec::new(),
        at_risk: Vec::new(),
        next: Vec::new(),
        evidence_handles: BTreeSet::new(),
    };
    let capsule = SituationCapsule {
        capsule_id: "situation:adv:1".to_owned(),
        revision: 1,
        contract_basis: test_basis(),
        mission_id: MissionId::parse("mission:adv:1")?,
        session_id: SessionId::parse("session:adv:1")?,
        principal_id: PrincipalId::parse("principal:adv")?,
        anchor,
        previous_anchor: None,
        frame,
        obligations: Vec::new(),
        affordances: Vec::new(),
        completeness: Completeness::Partial,
        created_at: TimestampNs(1_000_000),
        mission_state: None,
    };
    let situation = ReferenceSituation {
        capsule,
        proof_roots: BTreeSet::from([evidence_cam1, evidence_cam2]),
    };

    let publ = project_reference_situation(situation, &test_spec(10_000)?)?;

    // Cam 2 was dropped as a duplicate of Cam 1!
    // INV-092 forbids dropping evidence that can affect consequential action.
    // The context pack must preserve Cam 2's evidence root in the retained basis or items:
    let contra_item = publ
        .context_pack
        .items
        .iter()
        .find(|item| item.kind == "contradiction")
        .expect("contradiction item missing");

    assert!(
        contra_item.basis.contains(&evidence_cam2.to_string()),
        "Independent sensor evidence for contradicted claim was dropped during deduplication!"
    );
    Ok(())
}

#[test]
fn test_contradiction_basis_must_include_positive_evidence() -> Result<(), Box<dyn Error>> {
    let anchor = LedgerAnchor::genesis("site:inv092:adv2");
    let evidence_digest = ContentDigest::sha256(b"positive-claim-evidence");
    let contra_digest = ContentDigest::sha256(b"counter-evidence");

    let cell = KnowledgeCell {
        claim_id: "claim:contra:basis".to_owned(),
        statement: "Perimeter fence intact".to_owned(),
        knowledge_state: KnowledgeState::Conflicted,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![evidence_digest],
        contradictions: vec![contra_digest],
        valid_until: None,
    };

    let world = PossibleWorld {
        world_id: "world:adv:2".to_owned(),
        description: "World 2".to_owned(),
        claim_ids: BTreeSet::from(["claim:contra:basis".to_owned()]),
        evidence: vec![evidence_digest],
        consequence_severity: 4,
        protected: true,
    };
    let envelope = WorldEnvelope {
        envelope_id: "envelope:adv:2".to_owned(),
        objective_id: "objective:adv:2".to_owned(),
        anchor: anchor.clone(),
        nominal_claim_ids: BTreeSet::from(["claim:contra:basis".to_owned()]),
        certified_core_claim_ids: BTreeSet::new(),
        alternatives: vec![world],
        adversarial_residuals: Vec::new(),
        common_invariants: BTreeSet::new(),
        coverage_boundary_handles: BTreeSet::new(),
    };
    let frame = SituationFrame {
        frame_id: "frame:adv:2".to_owned(),
        objective_id: "objective:adv:2".to_owned(),
        anchor: anchor.clone(),
        world_envelope: envelope,
        knowledge_cells: vec![cell],
        now: vec!["Monitoring".to_owned()],
        changed: Vec::new(),
        why: Vec::new(),
        unknown: Vec::new(),
        at_risk: Vec::new(),
        next: Vec::new(),
        evidence_handles: BTreeSet::new(),
    };
    let capsule = SituationCapsule {
        capsule_id: "situation:adv:2".to_owned(),
        revision: 1,
        contract_basis: test_basis(),
        mission_id: MissionId::parse("mission:adv:2")?,
        session_id: SessionId::parse("session:adv:2")?,
        principal_id: PrincipalId::parse("principal:adv")?,
        anchor,
        previous_anchor: None,
        frame,
        obligations: Vec::new(),
        affordances: Vec::new(),
        completeness: Completeness::Partial,
        created_at: TimestampNs(1_000_000),
        mission_state: None,
    };
    let situation = ReferenceSituation {
        capsule,
        proof_roots: BTreeSet::from([evidence_digest]),
    };

    let publ = project_reference_situation(situation, &test_spec(10_000)?)?;
    let contra_item = publ
        .context_pack
        .items
        .iter()
        .find(|item| item.item_id == "context:contradiction:claim:contra:basis")
        .ok_or(ContractError::NotFound)?;

    // Positive evidence MUST be preserved in the contradiction item's basis:
    assert!(
        contra_item.basis.contains(&evidence_digest.to_string()),
        "Contradiction context item basis failed to retain positive evidence!"
    );
    Ok(())
}

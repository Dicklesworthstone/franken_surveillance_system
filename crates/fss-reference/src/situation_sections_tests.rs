use std::collections::BTreeSet;
use std::error::Error;

use fss_core::{
    ActionAffordance, AffordanceClass, BudgetVector, Completeness, ContentDigest, ContractBasis,
    ContractBasisRegistryBytes, ContractError, Generation, HandoffId, KnowledgeCell,
    KnowledgeCellParams, KnowledgeState, KnowledgeStateBasis, LedgerAnchor, MissionId,
    ObligationId, PrincipalId, PrivacyGeneration, ProvenanceClass, REDACTED_STATEMENT_MARKER,
    ReconciliationBasis, RedactionMarker, RedactionReason, ResourcePressure, SessionId,
    SituationCapsule, SituationFrame, StaleBasis, TimestampNs, WorldEnvelope,
};

use crate::{
    ReferenceError, ReferenceProjectionSpec, ReferenceSituation, ReferenceSituationPublication,
    project_reference_situation, seal_reference_publication_handoff,
};

fn basis() -> ContractBasis {
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

fn situation(long_optional_why: bool) -> Result<ReferenceSituation, ContractError> {
    situation_with_cells(long_optional_why, Vec::new())
}

pub(crate) fn situation_with_cells(
    long_optional_why: bool,
    extra_cells: Vec<KnowledgeCell>,
) -> Result<ReferenceSituation, ContractError> {
    let anchor = LedgerAnchor::genesis("site:situation-sections");
    let evidence = ContentDigest::sha256(b"retained-evidence");
    let world = fss_core::PossibleWorld {
        world_id: "world:protected".to_owned(),
        description: "A protected high-loss world remains live.".to_owned(),
        claim_ids: BTreeSet::from(["claim:presence".to_owned()]),
        evidence: vec![evidence],
        consequence_severity: 5,
        protected: true,
    };
    let envelope = WorldEnvelope {
        envelope_id: "world-envelope:sections".to_owned(),
        objective_id: "objective:sections".to_owned(),
        anchor: anchor.clone(),
        nominal_claim_ids: BTreeSet::from(["claim:presence".to_owned()]),
        certified_core_claim_ids: BTreeSet::new(),
        alternatives: vec![world],
        adversarial_residuals: Vec::new(),
        common_invariants: BTreeSet::from(["invariant:no-blind-effect".to_owned()]),
        coverage_boundary_handles: BTreeSet::from(["fss://coverage/sections".to_owned()]),
    };
    let retained_worlds = envelope.world_ids();
    let affordance = ActionAffordance {
        affordance_id: "affordance:investigate".to_owned(),
        operation: "investigate".to_owned(),
        target: "fss://event/sections/evidence".to_owned(),
        rationale: "Acquire independent evidence.".to_owned(),
        class: AffordanceClass::Probe,
        supported_worlds: retained_worlds,
        unsafe_worlds: BTreeSet::new(),
        required_capabilities: BTreeSet::from(["capability:evidence.query".to_owned()]),
        cost: BudgetVector::builder()
            .latency_ms(100)
            .tokens(10)
            .bytes(128)
            .cpu_millis(5)
            .accelerator_millis(2)
            .energy_millijoules(7)
            .privacy_exposure(0.1)
            .build()?,
        reversible: true,
        branch_predicate: None,
    };
    let known = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:policy".to_owned(),
        statement: "Policy currently withholds an effect.".to_owned(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![evidence],
        contradictions: Vec::new(),
        valid_until: None,
        state_basis: None,
    })?;
    let conflicted = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:presence".to_owned(),
        statement: "Presence remains conflicted.".to_owned(),
        knowledge_state: KnowledgeState::Conflicted,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![evidence],
        contradictions: vec![ContentDigest::sha256(b"contradiction")],
        valid_until: None,
        state_basis: None,
    })?;
    let mut knowledge_cells = vec![known, conflicted];
    knowledge_cells.extend(extra_cells);
    let why = if long_optional_why {
        vec!["optional explanatory detail ".repeat(400)]
    } else {
        vec!["Two retained interpretations remain decision-relevant.".to_owned()]
    };
    let frame = SituationFrame {
        frame_id: "frame:sections".to_owned(),
        objective_id: "objective:sections".to_owned(),
        anchor: anchor.clone(),
        world_envelope: envelope,
        knowledge_cells,
        now: vec!["A candidate event is under investigation.".to_owned()],
        changed: vec!["A contradictory observation arrived.".to_owned()],
        why,
        unknown: vec!["Independent corroboration is still absent.".to_owned()],
        at_risk: vec!["An irreversible alert must remain blocked.".to_owned()],
        next: vec!["affordance:investigate".to_owned()],
        evidence_handles: BTreeSet::from([format!("fss://proof/{evidence}")]),
    };
    let capsule = SituationCapsule {
        capsule_id: "situation:sections".to_owned(),
        revision: 1,
        contract_basis: basis(),
        mission_id: MissionId::parse("mission:sections")?,
        session_id: SessionId::parse("session:sections")?,
        principal_id: PrincipalId::parse("principal:sections")?,
        anchor,
        previous_anchor: None,
        frame,
        obligations: vec![ObligationId::parse("obligation:sections")?],
        affordances: vec![affordance],
        completeness: Completeness::Partial,
        created_at: TimestampNs(1_000),
        mission_state: None,
    };
    capsule.validate()?;
    Ok(ReferenceSituation::new(capsule, BTreeSet::from([evidence])))
}

fn spec(target_tokens: u64) -> ReferenceProjectionSpec {
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
        pressure: ResourcePressure::Elevated,
        degraded_dimensions: BTreeSet::from(["model_calls".to_owned()]),
        target_tokens,
    }
}

#[test]
fn complete_sections_are_deterministic_and_cross_verified() -> Result<(), Box<dyn Error>> {
    let first = project_reference_situation(situation(false)?, &spec(10_000))?;
    let second = project_reference_situation(situation(false)?, &spec(10_000))?;

    assert_eq!(first, second);
    assert_eq!(first.verify()?, first.publication_digest);
    assert_eq!(first.resource_state.pressure, ResourcePressure::Elevated);
    assert_eq!(
        first.control_envelope.information_gathering_affordance_ids,
        BTreeSet::from(["affordance:investigate".to_owned()])
    );
    assert_eq!(
        first.compression_receipt.stop_reason,
        fss_core::CompressionStopReason::Complete
    );
    assert!(
        first
            .context_pack
            .items
            .iter()
            .any(|item| item.item_id == "context:obligation:obligation:sections")
    );
    assert!(
        first
            .context_pack
            .items
            .iter()
            .any(|item| item.item_id == "context:world:world:protected")
    );
    Ok(())
}

#[test]
fn hard_budget_cannot_omit_critical_semantics() -> Result<(), Box<dyn Error>> {
    assert!(matches!(
        project_reference_situation(situation(false)?, &spec(1)),
        Err(ReferenceError::Contract(ContractError::BudgetExhausted))
    ));
    Ok(())
}

#[test]
fn optional_omission_is_receipted_and_hydratable() -> Result<(), Box<dyn Error>> {
    let publication = project_reference_situation(situation(true)?, &spec(2_000))?;

    assert!(
        publication
            .compression_receipt
            .omitted_classes
            .contains("why")
    );
    assert!(
        publication
            .compression_receipt
            .critical_preservation
            .is_lossless()
    );
    assert!(!publication.compression_receipt.expansion_handles.is_empty());
    assert!(publication.context_pack.continuation.is_some());
    assert!(
        publication
            .context_pack
            .items
            .iter()
            .any(|item| item.kind == "contradiction")
    );
    assert!(
        publication
            .context_pack
            .items
            .iter()
            .any(|item| item.kind == "protected_world")
    );
    publication.verify()?;
    Ok(())
}

#[test]
fn handoff_root_covers_the_complete_publication() -> Result<(), Box<dyn Error>> {
    // A handoff needs a situation a compile path sealed; the fixture stands in for one.
    let mut sealed = situation(false)?;
    sealed.seal_effect_bindings()?;
    let publication = project_reference_situation(sealed, &spec(10_000))?;
    let handoff = seal_reference_publication_handoff(
        &publication,
        HandoffId::parse("handoff:sections")?,
        TimestampNs(2_000),
        TimestampNs(3_000),
    )?;

    assert_eq!(
        handoff.situation_capsule_root,
        publication.publication_digest
    );
    assert!(
        handoff
            .child_roots
            .contains(&publication.context_pack.pack_digest)
    );
    assert!(
        handoff
            .child_roots
            .contains(&publication.compression_receipt.receipt_digest())
    );
    handoff.verify()?;
    Ok(())
}

#[test]
fn redacted_cells_never_disclose_their_statement() -> Result<(), Box<dyn Error>> {
    let secret = "SECRET-alice-is-home";
    let mut reference = situation(false)?;
    reference
        .capsule
        .frame
        .knowledge_cells
        .push(KnowledgeCell::new(KnowledgeCellParams {
            claim_id: "claim:resident".to_owned(),
            statement: secret.to_owned(),
            knowledge_state: KnowledgeState::Redacted,
            provenance: ProvenanceClass::Observed,
            hypothesis: None,
            evidence: vec![ContentDigest::sha256(b"redacted-evidence")],
            contradictions: Vec::new(),
            valid_until: None,
            state_basis: Some(KnowledgeStateBasis::Redaction(RedactionMarker {
                reason: RedactionReason::PrivacyProjection,
                privacy_generation: PrivacyGeneration::parse("privacy:projection:v7")?,
            })),
        })?);

    let projected = project_reference_situation(reference, &spec(10_000))?;
    let epistemic = projected
        .context_pack
        .items
        .iter()
        .find(|item| item.item_id == "context:epistemic:claim:resident")
        .ok_or("redacted cell missing from the context pack")?;
    assert_eq!(epistemic.content, REDACTED_STATEMENT_MARKER);
    assert_eq!(epistemic.epistemic_state, KnowledgeState::Redacted);
    assert!(
        projected
            .context_pack
            .items
            .iter()
            .all(|item| !item.content.contains(secret))
    );
    assert!(!format!("{projected:?}").contains(secret));
    Ok(())
}

/// Builds a validated cell carrying the typed basis its state requires (`None` otherwise).
fn cell(
    claim_id: &str,
    statement: &str,
    knowledge_state: KnowledgeState,
) -> Result<KnowledgeCell, Box<dyn Error>> {
    let state_basis = match knowledge_state {
        KnowledgeState::Redacted => Some(KnowledgeStateBasis::Redaction(RedactionMarker {
            reason: RedactionReason::PrivacyProjection,
            privacy_generation: PrivacyGeneration::parse("privacy:projection:v7")?,
        })),
        KnowledgeState::Stale => Some(KnowledgeStateBasis::Stale(StaleBasis::OlderGeneration {
            valid_at: Generation(1),
            current: Generation(2),
        })),
        KnowledgeState::Indeterminate => Some(KnowledgeStateBasis::Reconciliation(
            ReconciliationBasis::occurred_or_not(ContentDigest::sha256(claim_id.as_bytes())),
        )),
        KnowledgeState::Known
        | KnowledgeState::Estimated
        | KnowledgeState::Unknown
        | KnowledgeState::Conflicted
        | KnowledgeState::NotObservable
        | KnowledgeState::NotApplicable => None,
    };
    Ok(KnowledgeCell::new(KnowledgeCellParams {
        claim_id: claim_id.to_owned(),
        statement: statement.to_owned(),
        knowledge_state,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![ContentDigest::sha256(claim_id.as_bytes())],
        contradictions: Vec::new(),
        valid_until: None,
        state_basis,
    })?)
}

/// Every knowledge state, spelled out so a new variant forces this test to be revisited.
const ALL_KNOWLEDGE_STATES: [KnowledgeState; 9] = [
    KnowledgeState::Known,
    KnowledgeState::Estimated,
    KnowledgeState::Unknown,
    KnowledgeState::Conflicted,
    KnowledgeState::Stale,
    KnowledgeState::NotObservable,
    KnowledgeState::Redacted,
    KnowledgeState::Indeterminate,
    KnowledgeState::NotApplicable,
];

#[test]
fn every_knowledge_state_cell_lands_in_an_explicit_context_item() -> Result<(), Box<dyn Error>> {
    let cells: Vec<KnowledgeCell> = ALL_KNOWLEDGE_STATES
        .iter()
        .map(|state| {
            cell(
                &format!("claim:state:{}", state.as_str()),
                &format!("A proposition whose knowledge state is {}.", state.as_str()),
                *state,
            )
        })
        .collect::<Result<_, _>>()?;
    let publication =
        project_reference_situation(situation_with_cells(false, cells.clone())?, &spec(10_000))?;
    publication.verify()?;
    assert_eq!(
        publication.compression_receipt.stop_reason,
        fss_core::CompressionStopReason::Complete
    );
    for cell in &cells {
        let carried = publication.context_pack.items.iter().any(|item| {
            item.basis.contains(cell.claim_id()) && item.epistemic_state == cell.knowledge_state()
        });
        assert!(
            carried,
            "{} cell {} vanished from the context pack without an omission or redundancy record",
            cell.knowledge_state().as_str(),
            cell.claim_id()
        );
    }
    let not_applicable = publication
        .context_pack
        .items
        .iter()
        .find(|item| item.item_id == "context:not_applicable:claim:state:not_applicable")
        .ok_or(ReferenceError::InvalidSpec("missing_not_applicable_item"))?;
    assert_eq!(not_applicable.kind, "not_applicable");
    assert_eq!(
        not_applicable.epistemic_state,
        KnowledgeState::NotApplicable
    );
    Ok(())
}

#[test]
fn over_budget_not_applicable_cell_is_a_receipted_hydratable_omission() -> Result<(), Box<dyn Error>>
{
    let long_statement = "not applicable lifecycle detail ".repeat(400);
    let publication = project_reference_situation(
        situation_with_cells(
            false,
            vec![cell(
                "claim:not-applicable",
                &long_statement,
                KnowledgeState::NotApplicable,
            )?],
        )?,
        &spec(2_000),
    )?;
    publication.verify()?;
    assert!(
        publication
            .compression_receipt
            .omitted_classes
            .contains("not_applicable"),
        "an omitted not_applicable cell must be named in the receipt's omitted classes"
    );
    let completeness = publication
        .compression_receipt
        .completeness
        .iter()
        .find(|entry| entry.domain == "not_applicable")
        .ok_or(ReferenceError::InvalidSpec(
            "missing_not_applicable_completeness",
        ))?;
    assert_eq!(completeness.state, Completeness::Bounded);
    assert_eq!(completeness.omitted_count, 1);
    assert!(
        publication
            .compression_receipt
            .expansion_handles
            .iter()
            .any(|handle| handle.purpose.contains("not_applicable"))
    );
    assert_eq!(
        publication.compression_receipt.stop_reason,
        fss_core::CompressionStopReason::TargetBudget
    );
    assert!(publication.context_pack.continuation.is_some());
    assert!(
        publication
            .compression_receipt
            .critical_preservation
            .is_lossless()
    );
    Ok(())
}

#[test]
fn duplicate_not_applicable_cells_are_deduplicated_with_redundancy_record()
-> Result<(), Box<dyn Error>> {
    let statement = "Door-lock telemetry does not apply to this camera-only zone.";
    let first = cell(
        "claim:not-applicable:a",
        statement,
        KnowledgeState::NotApplicable,
    )?;
    let mut params = first.to_params();
    params.claim_id = "claim:not-applicable:b".to_owned();
    let second = KnowledgeCell::new(params)?;
    let publication = project_reference_situation(
        situation_with_cells(false, vec![first, second])?,
        &spec(10_000),
    )?;
    publication.verify()?;
    assert!(
        publication
            .context_pack
            .items
            .iter()
            .any(|item| item.item_id == "context:not_applicable:claim:not-applicable:a")
    );
    assert!(
        publication.redundancy_records().iter().any(|record| {
            record.kind == "not_applicable"
                && record.dropped_item_id == "context:not_applicable:claim:not-applicable:b"
                && record.retained_item_id == "context:not_applicable:claim:not-applicable:a"
        }),
        "the dropped duplicate not_applicable cell must be receipted, not silently removed"
    );
    Ok(())
}

#[test]
fn indeterminate_cell_without_reconciliation_basis_is_refused() -> Result<(), Box<dyn Error>> {
    let params = KnowledgeCellParams {
        claim_id: "claim:basisless:indeterminate".to_string(),
        statement: "An indeterminate proposition carried without its typed basis.".to_string(),
        knowledge_state: KnowledgeState::Indeterminate,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![ContentDigest::sha256(b"basisless-evidence")],
        contradictions: Vec::new(),
        valid_until: None,
        state_basis: None,
    };
    assert_eq!(
        KnowledgeCell::new(params),
        Err(ContractError::ReconciliationBasisRequired)
    );
    Ok(())
}

#[test]
fn redacted_cell_without_marker_is_refused() -> Result<(), Box<dyn Error>> {
    let params = KnowledgeCellParams {
        claim_id: "claim:basisless:redacted".to_string(),
        statement: "A redacted proposition carried without its typed basis.".to_string(),
        knowledge_state: KnowledgeState::Redacted,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![ContentDigest::sha256(b"basisless-evidence")],
        contradictions: Vec::new(),
        valid_until: None,
        state_basis: None,
    };
    assert_eq!(
        KnowledgeCell::new(params),
        Err(ContractError::RedactionMarkerRequired)
    );
    Ok(())
}

#[test]
fn stale_cell_without_basis_is_refused() -> Result<(), Box<dyn Error>> {
    let params = KnowledgeCellParams {
        claim_id: "claim:basisless:stale".to_string(),
        statement: "A stale proposition carried without its typed basis.".to_string(),
        knowledge_state: KnowledgeState::Stale,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![ContentDigest::sha256(b"basisless-evidence")],
        contradictions: Vec::new(),
        valid_until: None,
        state_basis: None,
    };
    assert_eq!(
        KnowledgeCell::new(params),
        Err(ContractError::StaleBasisRequired)
    );
    Ok(())
}

/// A valid redacted cell whose withheld statement is `secret`; evidence is shared across calls.
pub(crate) fn withheld_cell(
    claim_id: &str,
    secret: &str,
    contradictions: Vec<ContentDigest>,
) -> Result<KnowledgeCell, Box<dyn Error>> {
    Ok(KnowledgeCell::new(KnowledgeCellParams {
        claim_id: claim_id.to_owned(),
        statement: secret.to_owned(),
        knowledge_state: KnowledgeState::Redacted,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![ContentDigest::sha256(b"shared-redacted-evidence")],
        contradictions,
        valid_until: None,
        state_basis: Some(KnowledgeStateBasis::Redaction(RedactionMarker {
            reason: RedactionReason::PrivacyProjection,
            privacy_generation: PrivacyGeneration::parse("privacy:projection:v7")?,
        })),
    })?)
}

/// Projects two redacted cells (`claim:r1`, `claim:r2`) that differ only in withheld content.
fn project_withheld_pair(
    first_secret: &str,
    second_secret: &str,
    contradictions: &[ContentDigest],
) -> Result<ReferenceSituationPublication, Box<dyn Error>> {
    let cells = vec![
        withheld_cell("claim:r1", first_secret, contradictions.to_vec())?,
        withheld_cell("claim:r2", second_secret, contradictions.to_vec())?,
    ];
    let publication =
        project_reference_situation(situation_with_cells(false, cells)?, &spec(10_000))?;
    publication.verify()?;
    Ok(publication)
}

fn item_ids(publication: &ReferenceSituationPublication) -> Vec<String> {
    publication
        .context_pack
        .items
        .iter()
        .map(|item| item.item_id.clone())
        .collect()
}

#[test]
fn deduplication_never_reveals_whether_withheld_statements_are_equal() -> Result<(), Box<dyn Error>>
{
    for contradictions in [
        Vec::new(),
        vec![ContentDigest::sha256(b"redacted-contradiction")],
    ] {
        let different = project_withheld_pair(
            "SECRET-alice-is-home",
            "SECRET-bob-is-away",
            &contradictions,
        )?;
        let same = project_withheld_pair(
            "SECRET-alice-is-home",
            "SECRET-alice-is-home",
            &contradictions,
        )?;

        assert_eq!(item_ids(&different), item_ids(&same));
        assert_eq!(
            different.context_pack.items.len(),
            same.context_pack.items.len()
        );
        assert_eq!(different.context_pack.items, same.context_pack.items);
        assert_eq!(different.redundancy_records(), same.redundancy_records());

        // Withheld statements are never asserted identical, so each claim keeps its own item.
        let ids = item_ids(&same);
        for claim in ["claim:r1", "claim:r2"] {
            assert!(ids.contains(&format!("context:epistemic:{claim}")));
            if !contradictions.is_empty() {
                assert!(ids.contains(&format!("context:contradiction:{claim}")));
            }
        }
    }
    Ok(())
}

#[test]
fn redacted_contradiction_item_never_discloses_its_statement() -> Result<(), Box<dyn Error>> {
    let secret = "SECRET-contradicted-resident";
    let publication = project_reference_situation(
        situation_with_cells(
            false,
            vec![withheld_cell(
                "claim:redacted-conflict",
                secret,
                vec![ContentDigest::sha256(b"redacted-contradiction")],
            )?],
        )?,
        &spec(10_000),
    )?;
    publication.verify()?;

    let contradiction = publication
        .context_pack
        .items
        .iter()
        .find(|item| item.item_id == "context:contradiction:claim:redacted-conflict")
        .ok_or("redacted contradiction missing from the context pack")?;
    assert_eq!(contradiction.content, REDACTED_STATEMENT_MARKER);
    assert!(
        publication
            .context_pack
            .items
            .iter()
            .all(|item| !item.content.contains(secret))
    );
    assert!(!format!("{publication:?}").contains(secret));
    Ok(())
}

#[test]
fn redaction_basis_on_known_cell_is_refused() -> Result<(), Box<dyn Error>> {
    let cell = withheld_cell(
        "claim:misattached:known",
        "SECRET-misattached-redaction",
        Vec::new(),
    )?;
    let mut params = cell.to_params();
    params.knowledge_state = KnowledgeState::Known;
    assert_eq!(
        KnowledgeCell::new(params),
        Err(ContractError::KnowledgeStateBasisMismatch)
    );
    Ok(())
}

#[test]
fn redaction_basis_on_stale_cell_is_refused() -> Result<(), Box<dyn Error>> {
    let cell = withheld_cell(
        "claim:misattached:stale",
        "SECRET-misattached-redaction",
        Vec::new(),
    )?;
    let mut params = cell.to_params();
    params.knowledge_state = KnowledgeState::Stale;
    assert_eq!(
        KnowledgeCell::new(params),
        Err(ContractError::StaleBasisRequired)
    );
    Ok(())
}

#![forbid(unsafe_code)]
//! FSS-205 property family: `KnowledgeCell` state/provenance/validity/
//! uncertainty core (WP-175 / agent cognitive layer).
//!
//! Deterministic properties over the cell's constitutional gates. Each
//! property emits one JSONL verdict line; assertions are the hard gate.
//! Reproduce: `cargo test -p fss-core --test knowledge_cell_property_family
//! -- --nocapture`.

use fss_core::{
    ContentDigest, ContractError, EvidenceOrigin, HypothesisDisposition, KnowledgeCell,
    KnowledgeCellParams, KnowledgeState, KnowledgeStateBasis, LedgerAnchor, ProvenanceClass,
    ReconciliationBasis, RedactionMarker, RedactionReason, StaleBasis, TimestampNs,
};

fn emit(property: &str, cases: u64) {
    println!(
        "{{\"family\":\"FSS-205\",\"property\":\"{property}\",\"cases\":{cases},\"verdict\":\"pass\"}}"
    );
}

const STATES: [KnowledgeState; 9] = [
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

const PROVENANCES: [ProvenanceClass; 7] = [
    ProvenanceClass::Observed,
    ProvenanceClass::Derived,
    ProvenanceClass::Predicted,
    ProvenanceClass::Remembered,
    ProvenanceClass::OperatorAsserted,
    ProvenanceClass::VendorClaimed,
    ProvenanceClass::Policy,
];

/// The registry meaning of which states assert present support — encoded
/// INDEPENDENTLY from `fss_core` so the property is a real oracle, not an
/// echo: KSTATE-001/002/004 name present evidence; every other state
/// reports it absent, withheld, outdated, unresolved, or meaningless.
fn oracle_asserts_present_support(state: KnowledgeState) -> bool {
    matches!(
        state,
        KnowledgeState::Known | KnowledgeState::Estimated | KnowledgeState::Conflicted
    )
}

fn basis_for(state: KnowledgeState) -> Option<KnowledgeStateBasis> {
    match state {
        KnowledgeState::Stale => {
            let mut valid_at = LedgerAnchor::genesis("site:property-family");
            valid_at.commit_sequence = 7;
            let mut current = valid_at.clone();
            current.commit_sequence = 9;
            Some(KnowledgeStateBasis::Stale(StaleBasis::OlderAnchor {
                valid_at: Box::new(valid_at),
                current: Box::new(current),
            }))
        }
        KnowledgeState::Redacted => Some(KnowledgeStateBasis::Redaction(RedactionMarker {
            reason: RedactionReason::PrivacyProjection,
            privacy_generation: fss_core::PrivacyGeneration::canonical_v1(),
        })),
        KnowledgeState::Indeterminate => Some(KnowledgeStateBasis::Reconciliation(
            ReconciliationBasis::occurred_or_not(ContentDigest::sha256(b"unresolved-root")),
        )),
        _ => None,
    }
}

fn params_for(
    state: KnowledgeState,
    provenance: ProvenanceClass,
    evidence_count: usize,
    contradictions: Vec<ContentDigest>,
) -> KnowledgeCellParams {
    KnowledgeCellParams {
        claim_id: format!("claim:family:{state:?}:{provenance:?}"),
        statement: format!("proposition under {state:?}/{provenance:?}"),
        knowledge_state: state,
        provenance,
        hypothesis: None,
        evidence: (0..evidence_count)
            .map(|i| ContentDigest::sha256(format!("evidence-{i}").as_bytes()))
            .collect(),
        contradictions,
        valid_until: Some(TimestampNs(10_000_000_000)),
        state_basis: basis_for(state),
    }
}

/// P1 ORTHOGONALITY: for every legal (state, provenance) pair, and both
/// hypothesis polarities, construction preserves every typed field
/// verbatim — knowledge state, provenance, hypothesis disposition, and
/// validity boundary never collapse into one another or into prose.
#[test]
fn p1_typed_fields_stay_orthogonal() -> Result<(), Box<dyn std::error::Error>> {
    let mut cases = 0u64;
    for state in STATES {
        for provenance in PROVENANCES {
            for hypothesis in [None, Some(HypothesisDisposition::Live)] {
                let mut params = params_for(state, provenance, 1, vec![]);
                params.hypothesis = hypothesis;
                let Ok(cell) = KnowledgeCell::new(params) else {
                    // Illegal combos are P2's subject; orthogonality is about
                    // preservation, so only legal cells are inspected here.
                    continue;
                };
                assert_eq!(cell.knowledge_state(), state);
                assert_eq!(cell.provenance(), provenance);
                assert_eq!(cell.hypothesis(), hypothesis);
                assert_eq!(cell.valid_until(), Some(TimestampNs(10_000_000_000)));
                cases += 1;
            }
        }
    }
    assert!(cases > 100, "cross-product must yield substantial coverage");
    emit("typed-field-orthogonality", cases);
    Ok(())
}

/// P2 EVIDENCE GATE: `validate` refuses an empty evidence list exactly when
/// the state is Known OR the provenance is evidence-bearing (Observed /
/// Derived) AND the state's registry meaning asserts present support.
#[test]
fn p2_evidence_gate_matches_registry_meaning() -> Result<(), Box<dyn std::error::Error>> {
    let mut cases = 0u64;
    for state in STATES {
        for provenance in PROVENANCES {
            let refusal = KnowledgeCell::new(params_for(state, provenance, 0, vec![])).is_err();
            let expected = state == KnowledgeState::Known
                || (matches!(
                    provenance,
                    ProvenanceClass::Observed | ProvenanceClass::Derived
                ) && oracle_asserts_present_support(state));
            assert_eq!(
                refusal, expected,
                "evidence gate mismatch at {state:?}/{provenance:?}"
            );
            // Supplying evidence never violates the evidence gate itself.
            let with_evidence = KnowledgeCell::new(params_for(state, provenance, 1, vec![]))
                .is_ok()
                || KnowledgeCell::new(params_for(state, provenance, 1, vec![]))
                    .err()
                    .is_some_and(|e| e != ContractError::EvidenceRequired);
            assert!(with_evidence, "evidence must satisfy the evidence gate");
            cases += 2;
        }
    }
    emit("evidence-gate", cases);
    Ok(())
}

/// P3 CONSTITUTIONAL AUTHORITY GATES: Predicted provenance can never carry
/// Known state (no model output is established fact), and laboratory taint
/// can never carry Known state (H4 sealed-lab boundary).
#[test]
fn p3_authority_gates() -> Result<(), Box<dyn std::error::Error>> {
    let mut cases = 0u64;
    for state in STATES {
        for provenance in PROVENANCES {
            let params = params_for(state, provenance, 1, vec![]);
            let err = KnowledgeCell::new(params).err();
            let predicted_known =
                provenance == ProvenanceClass::Predicted && state == KnowledgeState::Known;
            assert_eq!(
                err == Some(ContractError::PredictedKnownForbidden),
                predicted_known,
                "Predicted/Known gate at {state:?}/{provenance:?}"
            );
            // Laboratory taint: claim-id marker forces the H4 refusal for Known.
            let mut tainted = params_for(state, provenance, 1, vec![]);
            tainted.claim_id = "laboratory:tainted:claim".to_string();
            let tainted_err = KnowledgeCell::new(tainted).err();
            let lab_known = state == KnowledgeState::Known;
            assert_eq!(
                tainted_err == Some(ContractError::DerivedLayerAuthorityForbidden),
                lab_known,
                "H4 lab/Known gate at {state:?}/{provenance:?}"
            );
            cases += 2;
        }
    }
    emit("authority-gates", cases);
    Ok(())
}

/// P4 BASIS GATES: states whose registry meaning names a basis are refused
/// without one (with the state's own typed error); a wrong-kind basis on a
/// basis-bearing state surfaces the state's required-basis error; a stray
/// basis on a basis-free state is a `KnowledgeStateBasisMismatch`.
#[test]
fn p4_state_basis_gates() -> Result<(), Box<dyn std::error::Error>> {
    let mut cases = 0u64;
    for state in STATES {
        // One evidence item supplied: isolates the basis gate from the
        // evidence gate (Known and support-asserting Observed cells).
        let mut bare = params_for(state, ProvenanceClass::Observed, 1, vec![]);
        bare.state_basis = None;
        let err = KnowledgeCell::new(bare.clone()).err();
        let expected_missing = match state {
            KnowledgeState::Redacted => Some(ContractError::RedactionMarkerRequired),
            KnowledgeState::Stale => Some(ContractError::StaleBasisRequired),
            KnowledgeState::Indeterminate => Some(ContractError::ReconciliationBasisRequired),
            _ => None,
        };
        assert_eq!(
            err, expected_missing,
            "missing-basis outcome mismatch at {state:?}"
        );

        // Wrong-kind basis on a basis-bearing state: the state's own
        // required-basis error names the problem.
        if expected_missing.is_some() {
            let wrong_kind = match state {
                KnowledgeState::Redacted | KnowledgeState::Indeterminate => {
                    basis_for(KnowledgeState::Stale)
                }
                _ => basis_for(KnowledgeState::Redacted),
            };
            if let Some(wrong) = wrong_kind {
                let mut mismatched = bare.clone();
                mismatched.state_basis = Some(wrong);
                let got = KnowledgeCell::new(mismatched).err();
                assert_eq!(got, expected_missing, "wrong-kind basis at {state:?}");
            }
        }

        // Stray basis on a basis-free state: mismatch.
        if expected_missing.is_none()
            && let Some(stray) = basis_for(KnowledgeState::Stale)
        {
            let mut with_stray = bare;
            with_stray.state_basis = Some(stray);
            assert_eq!(
                KnowledgeCell::new(with_stray).err(),
                Some(ContractError::KnowledgeStateBasisMismatch),
                "stray basis must mismatch at {state:?}"
            );
        }
        cases += 3;
    }
    emit("state-basis-gates", cases);
    Ok(())
}

/// P5 EVIDENCE PROVENANCE STAMPING (fss-gefi6): references carry the
/// cell's provenance by default; positional re-stamping preserves digests
/// and counts; a length mismatch is refused; contradictions survive every
/// transition.
#[test]
fn p5_evidence_stamping_and_contradiction_preservation() -> Result<(), Box<dyn std::error::Error>> {
    let mut cases = 0u64;
    for provenance in PROVENANCES {
        let digests: Vec<ContentDigest> = (0..3)
            .map(|i| ContentDigest::sha256(format!("ev-{provenance:?}-{i}").as_bytes()))
            .collect();
        let contradictions: Vec<ContentDigest> = vec![
            ContentDigest::sha256(b"contra-1"),
            ContentDigest::sha256(b"contra-2"),
        ];
        let mut params = params_for(KnowledgeState::Estimated, provenance, 0, vec![]);
        params.evidence = digests.clone();
        params.contradictions = contradictions.clone();
        let cell = KnowledgeCell::new(params)?;

        // Default stamp: every reference is Produced(cell provenance).
        assert!(
            cell.evidence()
                .iter()
                .all(|r| r.origin == EvidenceOrigin::Produced(provenance))
        );
        assert_eq!(cell.evidence_digests(), digests);

        // Positional re-stamp: laboratory for the middle reference only.
        // (Length-mismatch check first: `with_evidence_origins` consumes.)
        let origins = [
            EvidenceOrigin::Produced(provenance),
            EvidenceOrigin::Laboratory,
            EvidenceOrigin::Produced(provenance),
        ];
        assert!(cell.clone().with_evidence_origins(&origins[..1]).is_err());
        let restamped = cell.with_evidence_origins(&origins)?;
        assert_eq!(restamped.evidence_digests(), digests);
        assert_eq!(restamped.evidence()[1].origin, EvidenceOrigin::Laboratory);
        // Contradictions survive construction and re-stamping.
        assert_eq!(restamped.contradictions(), contradictions.as_slice());
        cases += 5;
    }
    emit("evidence-stamping-contradiction-preservation", cases);
    Ok(())
}

/// P6 PREMISE GATING: an irreversible-effect premise requires Known state,
/// an authorizing provenance, no laboratory taint anywhere in the evidence,
/// no contradictions, and an unexpired validity boundary — exhaustively
/// over states, lab-tainted evidence, contradictions, and expiry.
#[test]
fn p6_irreversible_premise_gating() -> Result<(), Box<dyn std::error::Error>> {
    const NOW: TimestampNs = TimestampNs(5_000_000_000);
    let mut cases = 0u64;
    let base_digest = ContentDigest::sha256(b"premise-evidence");
    for state in STATES {
        for lab_origin in [false, true] {
            for with_contradiction in [false, true] {
                for expired in [false, true] {
                    let mut params = params_for(state, ProvenanceClass::Observed, 0, vec![]);
                    params.evidence = vec![base_digest];
                    params.valid_until =
                        Some(TimestampNs(if expired { 1 } else { 10_000_000_000 }));
                    let cell = KnowledgeCell::new(params)?;
                    let cell = if lab_origin {
                        cell.with_evidence_origins(&[EvidenceOrigin::Laboratory])?
                    } else {
                        cell
                    };
                    let cell = if with_contradiction {
                        let mut p = cell.to_params();
                        p.contradictions = vec![ContentDigest::sha256(b"contra")];
                        KnowledgeCell::new(p)?
                    } else {
                        cell
                    };
                    let premise = cell.is_irreversible_effect_premise(NOW);
                    let legal_premise = state == KnowledgeState::Known
                        && !lab_origin
                        && !with_contradiction
                        && !expired;
                    assert_eq!(
                        premise, legal_premise,
                        "premise gate mismatch at {state:?} lab={lab_origin} contra={with_contradiction} expired={expired}"
                    );
                    cases += 1;
                }
            }
        }
    }
    assert!(cases >= 9 * 8);
    emit("irreversible-premise-gating", cases);
    Ok(())
}

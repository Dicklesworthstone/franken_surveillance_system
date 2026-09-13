#![forbid(unsafe_code)]
//! Deterministic contract tests for AGT-LAYER-004: derived_beliefs (INV-069).
//!
//! Enforces:
//! 1. Row identity and typed protocol contract (AGT-LAYER-004, Cognition plane, pure Rust)
//! 2. Constitutional hard gates: never claim authority, never authorize effects
//! 3. Anchor pinning: site_lineage enforcement, exact anchor matching, and freshness validation (StaleAnchor)
//! 4. Deterministic rebuild: inputs reproduce identical derivation receipt and canonical digest
//! 5. Exact-equality planted negative tests: zero generation, zero receipt, missing anchor, stale anchor,
//!    forbidden Known state, invalid provenance, empty evidence, and excess bounds
//! 6. Security against OOM: decode_canonical bounds-checks lengths against remaining bytes and hard bounds
//!    before allocating with Vec::with_capacity
//! 7. Mutant R22 kill: decode_canonical calls validate()
//! 8. Zero unwrap, expect, or panic anywhere in test suite
//! 9. Review findings (fss-x4a.30.82.4): no public path yields a `known` derived cell (N1); the
//!    receipt must equal its recomputation (N2); freshness uses KSTATE-005 anchor order and
//!    zero state roots are refused (N3); evidence sets are strictly ascending and disjoint (N4)
//! 10. Decode bound mutants: evidence and contradiction caps (M6) and the contradictions
//!     remaining-bytes bound (M10) are each observable

use std::error::Error;

use fss_core::belief::BeliefInterval;
use fss_core::{
    AgentAbstractionLayer, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder,
    ContentDigest, ContractError, DerivationInputs, DerivedBelief, DerivedBeliefParams, Generation,
    KnowledgeState, LedgerAnchor, MAX_DERIVED_BELIEF_CONTRADICTIONS, MAX_DERIVED_BELIEF_EVIDENCE,
    Plane, ProvenanceClass, TimestampNs,
};

fn sample_anchor() -> LedgerAnchor {
    LedgerAnchor::genesis("site:us-east:primary")
}

fn sample_uncertainty() -> Result<BeliefInterval, Box<dyn Error>> {
    Ok(BeliefInterval::new(750_000, 920_000)?)
}

/// The sample anchor advanced to `epoch` (same site lineage and state root).
fn anchor_at_epoch(epoch: u64) -> LedgerAnchor {
    let mut anchor = sample_anchor();
    anchor.ledger_epoch = epoch;
    anchor
}

#[test]
fn test_derived_beliefs_row_properties() -> Result<(), Box<dyn Error>> {
    let layer = AgentAbstractionLayer::DerivedBeliefs;

    // 1. Exact normative stable ID
    assert_eq!(layer.id(), "AGT-LAYER-004");

    // 2. Exact normative schema name
    assert_eq!(layer.name(), "derived_beliefs");
    assert_eq!(format!("{layer}"), "derived_beliefs");

    // 3. Exact tower level (L3)
    assert_eq!(layer.tower_level(), 3);

    // 4. Exact normative owner
    assert_eq!(layer.owner(), "fss-perception/fss-association/fss-graph");

    // 5. Exact normative agent question
    assert_eq!(
        layer.agent_question(),
        "What entities, tracks, events, relations, and uncertainties are supported?"
    );

    // 6. Exact normative output
    assert_eq!(
        layer.output(),
        "Generation-pinned derived beliefs and graph/search projections with receipts."
    );

    // 7. Exact normative prohibition
    assert_eq!(
        layer.prohibition(),
        "Cannot authorize effects or certify absence beyond coverage."
    );

    // 8. Exact normative invariant (INV-069)
    assert_eq!(layer.invariant(), "INV-069");

    // 9. Semantic Plane: strictly Cognition plane
    assert_eq!(layer.plane(), Plane::Cognition);

    Ok(())
}

#[test]
fn test_derived_belief_construction_and_validation() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let uncertainty = sample_uncertainty()?;
    let evidence_root = ContentDigest::sha256(b"evidence_packet_001");
    let receipt = ContentDigest::sha256(b"graph_projection_receipt_v1");

    let belief = DerivedBelief::new(
        DerivedBeliefParams {
            belief_id: "belief:track:person:001".into(),
            anchor: anchor.clone(),
            generation: Generation(1),
            statement: "Track 001 classified as person in restricted perimeter".into(),
            knowledge_state: KnowledgeState::Estimated,
            provenance: ProvenanceClass::Derived,
            uncertainty,
            supporting_evidence: vec![evidence_root],
            contradictions: vec![],
            derivation_receipt: receipt,
        }
        .with_computed_receipt()?,
    )?;

    // Properties
    assert_eq!(belief.belief_id(), "belief:track:person:001");
    assert_eq!(belief.anchor(), &anchor);
    assert_eq!(belief.generation(), Generation(1));
    assert_eq!(belief.knowledge_state(), KnowledgeState::Estimated);
    assert_eq!(belief.provenance(), ProvenanceClass::Derived);
    assert_eq!(belief.layer(), AgentAbstractionLayer::DerivedBeliefs);
    assert_eq!(belief.plane(), Plane::Cognition);

    // Constitutional Hard Gates
    assert!(!belief.may_claim_authority());
    assert!(!belief.may_authorize_effects());
    assert!(belief.is_anchor_pinned());
    assert!(belief.is_anchor_pinned_to(&anchor));
    assert!(belief.is_rebuildable());

    // Validation passes
    belief.validate()?;

    Ok(())
}

#[test]
fn test_derived_belief_to_knowledge_cell_hard_gate() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let uncertainty = sample_uncertainty()?;
    let evidence_root = ContentDigest::sha256(b"evidence_packet_001");
    let receipt = ContentDigest::sha256(b"graph_projection_receipt_v1");
    let now = TimestampNs(1_000_000_000);

    let belief = DerivedBelief::new(
        DerivedBeliefParams {
            belief_id: "belief:track:vehicle:002".into(),
            anchor,
            generation: Generation(1),
            statement: "Vehicle track 002 speed estimated at 35km/h".into(),
            knowledge_state: KnowledgeState::Estimated,
            provenance: ProvenanceClass::Derived,
            uncertainty,
            supporting_evidence: vec![evidence_root],
            contradictions: vec![],
            derivation_receipt: receipt,
        }
        .with_computed_receipt()?,
    )?;

    let cell = belief.to_knowledge_cell(&sample_anchor())?;

    // The cell inherits the derived belief's attributes
    assert_eq!(cell.claim_id, "belief:track:vehicle:002");
    assert_eq!(cell.knowledge_state, KnowledgeState::Estimated);
    assert_eq!(cell.provenance, ProvenanceClass::Derived);
    assert_eq!(cell.evidence.len(), 1);

    // Constitutional Hard Gate: A derived proposition can NEVER be an irreversible-effect premise!
    assert!(
        !cell.is_irreversible_effect_premise(now),
        "Derived belief MUST NOT authorize an irreversible effect"
    );

    Ok(())
}

#[test]
fn test_planted_negative_derived_belief_known_forbidden() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let uncertainty = sample_uncertainty()?;
    let evidence_root = ContentDigest::sha256(b"evidence_packet_001");
    let receipt = ContentDigest::sha256(b"graph_projection_receipt_v1");

    // Derived belief attempting to claim Known state must fail closed (DerivedBeliefKnownForbidden)
    let res = DerivedBelief::new(DerivedBeliefParams {
        belief_id: "belief:illegal:known".into(),
        anchor,
        generation: Generation(1),
        statement: "Illegally upgrading derived belief to known state".into(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        uncertainty,
        supporting_evidence: vec![evidence_root],
        contradictions: vec![],
        derivation_receipt: receipt,
    });

    let Err(err) = res else {
        return Err("DerivedBelief must refuse KnowledgeState::Known".into());
    };
    assert_eq!(err, ContractError::DerivedBeliefKnownForbidden);

    Ok(())
}

#[test]
fn test_planted_negative_derived_belief_non_derived_provenance_forbidden()
-> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let uncertainty = sample_uncertainty()?;
    let evidence_root = ContentDigest::sha256(b"evidence_packet_001");
    let receipt = ContentDigest::sha256(b"graph_projection_receipt_v1");

    // Derived belief with Observed provenance must fail closed (KnowledgeStateBasisMismatch)
    let res = DerivedBelief::new(DerivedBeliefParams {
        belief_id: "belief:illegal:observed".into(),
        anchor,
        generation: Generation(1),
        statement: "Spoofing observed provenance on derived belief".into(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Observed,
        uncertainty,
        supporting_evidence: vec![evidence_root],
        contradictions: vec![],
        derivation_receipt: receipt,
    });

    let Err(err) = res else {
        return Err("DerivedBelief must refuse non-Derived provenance".into());
    };
    assert_eq!(err, ContractError::KnowledgeStateBasisMismatch);

    Ok(())
}

#[test]
fn test_planted_negative_derived_belief_empty_evidence_forbidden() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let uncertainty = sample_uncertainty()?;
    let receipt = ContentDigest::sha256(b"graph_projection_receipt_v1");

    // Derived belief with empty supporting evidence must fail closed (EvidenceRequired)
    let res = DerivedBelief::new(DerivedBeliefParams {
        belief_id: "belief:illegal:no_evidence".into(),
        anchor,
        generation: Generation(1),
        statement: "Unfounded derived belief with no evidence roots".into(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Derived,
        uncertainty,
        supporting_evidence: vec![],
        contradictions: vec![],
        derivation_receipt: receipt,
    });

    let Err(err) = res else {
        return Err("DerivedBelief must refuse empty supporting evidence".into());
    };
    assert_eq!(err, ContractError::EvidenceRequired);

    Ok(())
}

#[test]
fn test_planted_negative_derived_belief_missing_anchor_forbidden() -> Result<(), Box<dyn Error>> {
    let mut bad_anchor = sample_anchor();
    bad_anchor.site_lineage = "".into(); // Empty lineage = unanchored
    let uncertainty = sample_uncertainty()?;
    let evidence_root = ContentDigest::sha256(b"evidence_packet_001");
    let receipt = ContentDigest::sha256(b"graph_projection_receipt_v1");

    let res = DerivedBelief::new(DerivedBeliefParams {
        belief_id: "belief:illegal:no_anchor".into(),
        anchor: bad_anchor,
        generation: Generation(1),
        statement: "Floating derived belief with empty anchor lineage".into(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Derived,
        uncertainty,
        supporting_evidence: vec![evidence_root],
        contradictions: vec![],
        derivation_receipt: receipt,
    });

    let Err(err) = res else {
        return Err("DerivedBelief must refuse missing anchor".into());
    };
    assert_eq!(err, ContractError::DerivedBeliefMissingAnchor);

    Ok(())
}

#[test]
fn test_planted_negative_derived_belief_zero_generation_forbidden() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let uncertainty = sample_uncertainty()?;
    let evidence_root = ContentDigest::sha256(b"evidence_packet_001");
    let receipt = ContentDigest::sha256(b"graph_projection_receipt_v1");

    let res = DerivedBelief::new(DerivedBeliefParams {
        belief_id: "belief:track:zero_gen".into(),
        anchor,
        generation: Generation(0), // ILLEGAL: generation must be > 0
        statement: "Track with zero generation".into(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Derived,
        uncertainty,
        supporting_evidence: vec![evidence_root],
        contradictions: vec![],
        derivation_receipt: receipt,
    });

    let Err(err) = res else {
        return Err("DerivedBelief must refuse Generation(0)".into());
    };
    assert_eq!(err, ContractError::GenerationConflict);

    Ok(())
}

#[test]
fn test_planted_negative_derived_belief_zero_receipt_forbidden() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let uncertainty = sample_uncertainty()?;
    let evidence_root = ContentDigest::sha256(b"evidence_packet_001");
    let empty_input_digest = ContentDigest::sha256(b"");
    let zero_bytes_receipt = ContentDigest::new(fss_core::DigestAlgorithm::Sha256, [0u8; 32]);

    let res = DerivedBelief::new(DerivedBeliefParams {
        belief_id: "belief:track:zero_receipt".into(),
        anchor,
        generation: Generation(1),
        statement: "Track with all-zero derivation receipt".into(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Derived,
        uncertainty,
        supporting_evidence: vec![evidence_root],
        contradictions: vec![],
        derivation_receipt: zero_bytes_receipt,
    });

    let Err(err) = res else {
        return Err("DerivedBelief must refuse zero derivation receipt".into());
    };
    assert_eq!(err, ContractError::InvalidDigest);

    // sha256("") is a real, non-zero digest (premise): the all-zero rule does not catch it,
    // and it is not the recomputed receipt either, so it fails the receipt check instead.
    assert_ne!(empty_input_digest.bytes(), [0u8; 32]);
    let mut empty_digest_params = sealed_params("belief:track:zero_receipt")?;
    empty_digest_params.derivation_receipt = empty_input_digest;
    assert_eq!(
        expect_err(
            DerivedBelief::new(empty_digest_params),
            "sha256(\"\") receipt"
        )?,
        ContractError::DigestMismatch
    );

    // A genuine all-zero receipt is refused with the same exact error through decode.
    let mut zero_params = sealed_params("belief:track:zero_receipt")?;
    zero_params.derivation_receipt = zero_bytes_receipt;
    assert_eq!(
        expect_err(
            decode(&encode_params(&zero_params)?),
            "all-zero receipt via decode"
        )?,
        ContractError::InvalidDigest
    );

    Ok(())
}

#[test]
fn test_planted_negative_derived_belief_stale_anchor_fails() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let uncertainty = sample_uncertainty()?;
    let evidence_root = ContentDigest::sha256(b"evidence_packet_001");
    let receipt = ContentDigest::sha256(b"graph_projection_receipt_v1");

    let belief = DerivedBelief::new(
        DerivedBeliefParams {
            belief_id: "belief:track:stale_check".into(),
            anchor,
            generation: Generation(1),
            statement: "Track with stale check".into(),
            knowledge_state: KnowledgeState::Estimated,
            provenance: ProvenanceClass::Derived,
            uncertainty,
            supporting_evidence: vec![evidence_root],
            contradictions: vec![],
            derivation_receipt: receipt,
        }
        .with_computed_receipt()?,
    )?;

    // Stale anchor fails with exact error StaleAnchor
    let Err(err) = belief.validate_anchor_freshness(&anchor_at_epoch(1)) else {
        return Err("validate_anchor_freshness must refuse a stale anchor".into());
    };
    assert_eq!(err, ContractError::StaleAnchor);

    Ok(())
}

#[test]
fn test_derived_belief_rebuild_and_receipt_determinism() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let uncertainty = sample_uncertainty()?;
    let evidence_root = ContentDigest::sha256(b"evidence_packet_001");
    let contra_root = ContentDigest::sha256(b"contra_packet_002");

    let receipt = DerivedBelief::compute_derivation_receipt(&DerivationInputs {
        belief_id: "belief:track:rebuildable:001",
        anchor: &anchor,
        generation: Generation(5),
        statement: "Rebuildable derived proposition",
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Derived,
        uncertainty: &uncertainty,
        supporting_evidence: &[evidence_root],
        contradictions: &[contra_root],
    })?;

    let belief = DerivedBelief::new(DerivedBeliefParams {
        belief_id: "belief:track:rebuildable:001".into(),
        anchor: anchor.clone(),
        generation: Generation(5),
        statement: "Rebuildable derived proposition".into(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Derived,
        uncertainty,
        supporting_evidence: vec![evidence_root],
        contradictions: vec![contra_root],
        derivation_receipt: receipt,
    })?;

    // Anchor pinning checks
    assert!(belief.is_anchor_pinned());
    assert!(belief.is_anchor_pinned_to(&anchor));
    let mut other_anchor = anchor.clone();
    other_anchor.ledger_epoch = 999;
    assert!(!belief.is_anchor_pinned_to(&other_anchor));

    // Stale anchor check
    assert_eq!(
        belief.validate_anchor_freshness(&anchor_at_epoch(10)),
        Err(ContractError::StaleAnchor)
    );
    assert_eq!(belief.validate_anchor_freshness(&anchor), Ok(()));

    // Rebuildable check
    assert!(belief.is_rebuildable());

    // Dedicated test proving rebuild reproduces identical belief and digest
    let rebuilt = belief.rebuild()?;
    assert_eq!(belief, rebuilt);
    assert_eq!(belief.canonical_digest()?, rebuilt.canonical_digest()?);
    assert_eq!(belief.derivation_receipt(), rebuilt.derivation_receipt());
    // rebuild() recomputes the receipt from the inputs rather than copying it.
    assert_eq!(rebuilt.derivation_receipt(), receipt);
    assert_eq!(rebuilt.derivation_inputs(), belief.derivation_inputs());

    Ok(())
}

#[test]
fn test_security_derived_belief_decode_large_length_rejected_without_oom()
-> Result<(), Box<dyn Error>> {
    // Craft payload with u32::MAX supporting_evidence length
    let mut encoder = CanonicalEncoder::new();
    encoder.text("belief:attack:oom");
    sample_anchor().encode_canonical(&mut encoder);
    encoder.u64(1); // generation
    encoder.text("Statement");
    KnowledgeState::Estimated.encode_canonical(&mut encoder);
    ProvenanceClass::Derived.encode_canonical(&mut encoder);
    sample_uncertainty()?.encode_canonical(&mut encoder);
    encoder.u32(u32::MAX); // MALICIOUS LENGTH: requesting ~137 GB
    let payload = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&payload);
    let res = DerivedBelief::decode_canonical(&mut decoder);
    let Err(err) = res else {
        return Err("decode_canonical must reject u32::MAX length before allocating".into());
    };
    assert_eq!(err, ContractError::ArithmeticOverflow);

    // Also verify length exceeding remaining input / 33
    let mut encoder2 = CanonicalEncoder::new();
    encoder2.text("belief:attack:remaining");
    sample_anchor().encode_canonical(&mut encoder2);
    encoder2.u64(1);
    encoder2.text("Statement");
    KnowledgeState::Estimated.encode_canonical(&mut encoder2);
    ProvenanceClass::Derived.encode_canonical(&mut encoder2);
    sample_uncertainty()?.encode_canonical(&mut encoder2);
    encoder2.u32(100); // 100 digests require 3300 bytes, but payload ends here
    let payload2 = encoder2.finish();

    let mut decoder2 = CanonicalDecoder::new(&payload2);
    let res2 = DerivedBelief::decode_canonical(&mut decoder2);
    let Err(err2) = res2 else {
        return Err("decode_canonical must reject length exceeding available bytes".into());
    };
    assert_eq!(err2, ContractError::ArithmeticOverflow);

    Ok(())
}

#[test]
fn test_decode_canonical_validates_and_kills_mutant_r22() -> Result<(), Box<dyn Error>> {
    // Encode a structurally well-formed payload that has generation = 0 (violates validate())
    let mut encoder = CanonicalEncoder::new();
    encoder.text("belief:mutant:r22");
    sample_anchor().encode_canonical(&mut encoder);
    encoder.u64(0); // ILLEGAL Generation(0)
    encoder.text("Statement with generation 0");
    KnowledgeState::Estimated.encode_canonical(&mut encoder);
    ProvenanceClass::Derived.encode_canonical(&mut encoder);
    sample_uncertainty()?.encode_canonical(&mut encoder);
    encoder.u32(1); // 1 supporting evidence
    encoder.digest(ContentDigest::sha256(b"ev1"));
    encoder.u32(0); // 0 contradictions
    encoder.digest(ContentDigest::sha256(b"receipt1")); // non-zero receipt
    let payload = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&payload);
    let res = DerivedBelief::decode_canonical(&mut decoder);

    // If mutant R22 survives (validate() removed from decode_canonical), this returns Ok instead of Err
    let Err(err) = res else {
        return Err("decode_canonical must invoke validate() and reject Generation(0)".into());
    };
    assert_eq!(err, ContractError::GenerationConflict);

    Ok(())
}

#[test]
fn test_derived_belief_max_evidence_and_contradiction_bounds() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let uncertainty = sample_uncertainty()?;
    let receipt = ContentDigest::sha256(b"receipt");

    // Oversized supporting evidence: MAX + 1
    let mut excess_evidence = Vec::with_capacity(MAX_DERIVED_BELIEF_EVIDENCE + 1);
    for i in 0u32..=(MAX_DERIVED_BELIEF_EVIDENCE as u32) {
        excess_evidence.push(ContentDigest::sha256(&i.to_be_bytes()));
    }

    let res = DerivedBelief::new(DerivedBeliefParams {
        belief_id: "belief:excess:evidence".into(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Excess evidence test".into(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Derived,
        uncertainty: uncertainty.clone(),
        supporting_evidence: excess_evidence,
        contradictions: vec![],
        derivation_receipt: receipt,
    });
    let Err(err) = res else {
        return Err("must reject excess evidence".into());
    };
    assert_eq!(err, ContractError::ArithmeticOverflow);

    // Oversized contradictions: MAX + 1
    let mut excess_contra = Vec::with_capacity(MAX_DERIVED_BELIEF_CONTRADICTIONS + 1);
    for i in 0u32..=(MAX_DERIVED_BELIEF_CONTRADICTIONS as u32) {
        excess_contra.push(ContentDigest::sha256(&i.to_be_bytes()));
    }

    let res2 = DerivedBelief::new(DerivedBeliefParams {
        belief_id: "belief:excess:contra".into(),
        anchor,
        generation: Generation(1),
        statement: "Excess contra test".into(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Derived,
        uncertainty,
        supporting_evidence: vec![ContentDigest::sha256(b"ev1")],
        contradictions: excess_contra,
        derivation_receipt: receipt,
    });
    let Err(err2) = res2 else {
        return Err("must reject excess contradictions".into());
    };
    assert_eq!(err2, ContractError::ArithmeticOverflow);

    Ok(())
}

#[test]
fn test_derived_belief_canonical_roundtrip() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let uncertainty = sample_uncertainty()?;
    let evidence_root = ContentDigest::sha256(b"evidence_packet_001");
    let contra_root = ContentDigest::sha256(b"contra_packet_001");
    let receipt = ContentDigest::sha256(b"graph_projection_receipt_v1");

    let belief = DerivedBelief::new(
        DerivedBeliefParams {
            belief_id: "belief:track:person:001".into(),
            anchor,
            generation: Generation(2),
            statement: "Track 001 classified as person in restricted perimeter".into(),
            knowledge_state: KnowledgeState::Estimated,
            provenance: ProvenanceClass::Derived,
            uncertainty,
            supporting_evidence: vec![evidence_root],
            contradictions: vec![contra_root],
            derivation_receipt: receipt,
        }
        .with_computed_receipt()?,
    )?;

    let mut encoder = CanonicalEncoder::new();
    belief.encode_canonical(&mut encoder);
    let bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&bytes);
    let decoded = DerivedBelief::decode_canonical(&mut decoder)?;

    assert_eq!(belief, decoded);
    assert_eq!(belief.canonical_digest()?, decoded.canonical_digest()?);

    Ok(())
}

#[test]
fn test_derivation_receipt_encoding_order_is_pinned() -> Result<(), Box<dyn Error>> {
    // Independent oracle: re-encode the receipt fields by hand in the documented order
    // (domain tag, identity, anchor, generation, statement, state, provenance, uncertainty,
    // evidence, contradictions). Any reordering or dropped field changes the digest.
    let anchor = sample_anchor();
    let uncertainty = sample_uncertainty()?;
    let evidence = [
        ContentDigest::sha256(b"ev-a"),
        ContentDigest::sha256(b"ev-b"),
    ];
    let contradictions = [ContentDigest::sha256(b"contra-a")];
    let inputs = DerivationInputs {
        belief_id: "belief:pin:001",
        anchor: &anchor,
        generation: Generation(7),
        statement: "Pinned receipt layout",
        knowledge_state: KnowledgeState::Conflicted,
        provenance: ProvenanceClass::Derived,
        uncertainty: &uncertainty,
        supporting_evidence: &evidence,
        contradictions: &contradictions,
    };

    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.derived_belief.receipt.v1");
    encoder.text("belief:pin:001");
    anchor.encode_canonical(&mut encoder);
    encoder.u64(7);
    encoder.text("Pinned receipt layout");
    KnowledgeState::Conflicted.encode_canonical(&mut encoder);
    ProvenanceClass::Derived.encode_canonical(&mut encoder);
    uncertainty.encode_canonical(&mut encoder);
    encoder.u32(2);
    for digest in evidence {
        encoder.digest(digest);
    }
    encoder.u32(1);
    for digest in contradictions {
        encoder.digest(digest);
    }
    let expected = ContentDigest::sha256(&encoder.finish_checked()?);

    assert_eq!(
        DerivedBelief::compute_derivation_receipt(&inputs)?,
        expected
    );

    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Review findings N1-N6 and decode-bound mutants M6/M10 (fss-x4a.30.82.4).
// ---------------------------------------------------------------------------------------------

/// A valid parameter set whose receipt is sealed over its own inputs.
fn sealed_params(belief_id: &str) -> Result<DerivedBeliefParams, Box<dyn Error>> {
    Ok(DerivedBeliefParams {
        belief_id: belief_id.into(),
        anchor: sample_anchor(),
        generation: Generation(1),
        statement: "Sealed derived proposition".into(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Derived,
        uncertainty: sample_uncertainty()?,
        supporting_evidence: vec![ContentDigest::sha256(b"evidence_packet_001")],
        contradictions: vec![],
        derivation_receipt: ContentDigest::sha256(b"unsealed"),
    }
    .with_computed_receipt()?)
}

/// Hand-encodes a parameter set in the canonical `DerivedBelief` layout, bypassing validation.
fn encode_params(params: &DerivedBeliefParams) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(&params.belief_id);
    params.anchor.encode_canonical(&mut encoder);
    encoder.u64(params.generation.0);
    encoder.text(&params.statement);
    params.knowledge_state.encode_canonical(&mut encoder);
    params.provenance.encode_canonical(&mut encoder);
    params.uncertainty.encode_canonical(&mut encoder);
    encoder.u32(u32::try_from(params.supporting_evidence.len())?);
    for digest in &params.supporting_evidence {
        encoder.digest(*digest);
    }
    encoder.u32(u32::try_from(params.contradictions.len())?);
    for digest in &params.contradictions {
        encoder.digest(*digest);
    }
    encoder.digest(params.derivation_receipt);
    Ok(encoder.finish_checked()?)
}

fn encode_belief(belief: &DerivedBelief) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut encoder = CanonicalEncoder::new();
    belief.encode_canonical(&mut encoder);
    Ok(encoder.finish_checked()?)
}

fn decode(bytes: &[u8]) -> Result<DerivedBelief, ContractError> {
    DerivedBelief::decode_canonical(&mut CanonicalDecoder::new(bytes))
}

/// Returns the refusal, or fails the test if the operation unexpectedly succeeded.
fn expect_err<T: std::fmt::Debug>(
    result: Result<T, ContractError>,
    what: &str,
) -> Result<ContractError, Box<dyn Error>> {
    match result {
        Err(err) => Ok(err),
        Ok(value) => Err(format!("{what}: expected a refusal, got {value:?}").into()),
    }
}

/// Two distinct digests in ascending order.
fn ordered_pair(a: &[u8], b: &[u8]) -> (ContentDigest, ContentDigest) {
    let (x, y) = (ContentDigest::sha256(a), ContentDigest::sha256(b));
    if x < y { (x, y) } else { (y, x) }
}

fn zero_digest() -> ContentDigest {
    ContentDigest::new(fss_core::DigestAlgorithm::Sha256, [0u8; 32])
}

/// Encodes the fixed header (identity through uncertainty) of a `DerivedBelief` payload.
fn encode_header(encoder: &mut CanonicalEncoder, belief_id: &str) -> Result<(), Box<dyn Error>> {
    encoder.text(belief_id);
    sample_anchor().encode_canonical(encoder);
    encoder.u64(1);
    encoder.text("Statement");
    KnowledgeState::Estimated.encode_canonical(encoder);
    ProvenanceClass::Derived.encode_canonical(encoder);
    sample_uncertainty()?.encode_canonical(encoder);
    Ok(())
}

#[test]
fn test_n1_derived_belief_never_yields_effect_premise_in_any_state() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let now = TimestampNs(1_000_000_000);
    let states = [
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
    let mut converted = 0usize;
    for state in states {
        let mut params = sealed_params("belief:n1:state")?;
        params.knowledge_state = state;
        let params = params.with_computed_receipt()?;
        match DerivedBelief::new(params) {
            Err(err) => {
                assert_eq!(state, KnowledgeState::Known, "only `known` may be refused");
                assert_eq!(err, ContractError::DerivedBeliefKnownForbidden);
            }
            Ok(belief) => {
                let cell = belief.to_knowledge_cell(&anchor)?;
                assert_eq!(cell.knowledge_state, state);
                assert_eq!(cell.provenance, ProvenanceClass::Derived);
                assert!(
                    !cell.is_irreversible_effect_premise(now),
                    "{state:?} derived cell became an irreversible-effect premise"
                );
                converted += 1;
            }
        }
    }
    assert_eq!(converted, 8);
    Ok(())
}

#[test]
fn test_n1_planted_known_through_every_public_path_is_refused() -> Result<(), Box<dyn Error>> {
    // Public path 1: a parameter set whose receipt is honestly sealed over `known`.
    let mut known = sealed_params("belief:n1:known")?;
    known.knowledge_state = KnowledgeState::Known;
    let known = known.with_computed_receipt()?;
    assert_eq!(
        expect_err(DerivedBelief::new(known.clone()), "new(known)")?,
        ContractError::DerivedBeliefKnownForbidden
    );

    // Public path 2: canonical bytes carrying `known` with an internally consistent receipt.
    let payload = encode_params(&known)?;
    assert_eq!(
        expect_err(decode(&payload), "decode(known)")?,
        ContractError::DerivedBeliefKnownForbidden
    );
    assert_eq!(
        expect_err(
            DerivedBelief::decode_at_anchor(&mut CanonicalDecoder::new(&payload), &sample_anchor()),
            "decode_at_anchor(known)"
        )?,
        ContractError::DerivedBeliefKnownForbidden
    );

    // Public path 3: Generation(0) together with `known` (the struct-literal shape of the
    // review finding), through both constructor and decode.
    let mut zero_gen_known = known;
    zero_gen_known.generation = Generation(0);
    let zero_gen_known = zero_gen_known.with_computed_receipt()?;
    assert_eq!(
        expect_err(
            DerivedBelief::new(zero_gen_known.clone()),
            "new(gen0+known)"
        )?,
        ContractError::GenerationConflict
    );
    assert_eq!(
        expect_err(
            decode(&encode_params(&zero_gen_known)?),
            "decode(gen0+known)"
        )?,
        ContractError::GenerationConflict
    );

    // Field assignment and struct literals do not compile (compile_fail doctests on
    // DerivedBelief); post-construction mutation is covered by the in-crate unit tests.
    Ok(())
}

#[test]
fn test_n2_new_and_decode_refuse_receipt_that_differs_from_recomputation()
-> Result<(), Box<dyn Error>> {
    let mut forged = sealed_params("belief:n2:forged")?;
    forged.derivation_receipt = ContentDigest::sha256(b"forged_receipt");
    assert_eq!(
        expect_err(DerivedBelief::new(forged.clone()), "new(forged receipt)")?,
        ContractError::DigestMismatch
    );
    assert_eq!(
        expect_err(decode(&encode_params(&forged)?), "decode(forged receipt)")?,
        ContractError::DigestMismatch
    );

    // Flip one bit of the receipt inside an otherwise valid canonical encoding.
    let sealed = sealed_params("belief:n2:forged")?;
    let belief = DerivedBelief::new(sealed.clone())?;
    let mut bytes = encode_belief(&belief)?;
    assert_eq!(
        bytes,
        encode_params(&sealed)?,
        "hand encoder must match the canonical layout"
    );
    let Some(last) = bytes.last_mut() else {
        return Err("empty canonical encoding".into());
    };
    *last ^= 0x01;
    assert_eq!(
        expect_err(decode(&bytes), "decode(bit-flipped receipt)")?,
        ContractError::DigestMismatch
    );
    Ok(())
}

#[test]
fn test_n2_receipt_binds_every_derivation_input() -> Result<(), Box<dyn Error>> {
    let base = sealed_params("belief:n2:bind")?;
    let belief = DerivedBelief::new(base.clone())?;
    assert_eq!(
        belief.derivation_receipt(),
        DerivedBelief::compute_derivation_receipt(&base.derivation_inputs())?
    );

    // Changing any single input after sealing leaves a stale receipt behind.
    let mut variants = Vec::new();
    let mut v = base.clone();
    v.belief_id = "belief:n2:other".into();
    variants.push(("belief_id", v));
    let mut v = base.clone();
    v.anchor.commit_sequence = 1;
    variants.push(("anchor", v));
    let mut v = base.clone();
    v.generation = Generation(2);
    variants.push(("generation", v));
    let mut v = base.clone();
    v.statement = "A different statement".into();
    variants.push(("statement", v));
    let mut v = base.clone();
    v.knowledge_state = KnowledgeState::Conflicted;
    variants.push(("knowledge_state", v));
    let mut v = base.clone();
    v.uncertainty = BeliefInterval::new(700_000, 920_000)?;
    variants.push(("uncertainty", v));
    let mut v = base.clone();
    v.supporting_evidence = vec![ContentDigest::sha256(b"other_evidence")];
    variants.push(("supporting_evidence", v));
    let mut v = base;
    v.contradictions = vec![ContentDigest::sha256(b"late_contradiction")];
    variants.push(("contradictions", v));
    assert_eq!(variants.len(), 8);
    for (field, variant) in variants {
        assert_eq!(
            expect_err(DerivedBelief::new(variant), field)?,
            ContractError::DigestMismatch,
            "{field}"
        );
    }
    Ok(())
}

#[test]
fn test_n3_freshness_uses_full_anchor_order_and_state_root() -> Result<(), Box<dyn Error>> {
    let belief = DerivedBelief::new(sealed_params("belief:n3:fresh")?)?;
    let pinned = sample_anchor();
    assert_eq!(belief.validate_anchor_freshness(&pinned), Ok(()));

    // A newer commit in the same epoch makes the belief stale (KSTATE-005 order).
    let mut newer_commit = pinned.clone();
    newer_commit.commit_sequence += 1;
    assert_eq!(
        belief.validate_anchor_freshness(&newer_commit),
        Err(ContractError::StaleAnchor)
    );

    // Same position, different state root: a forked anchor, not the pinned one.
    let mut other_root = pinned.clone();
    other_root.state_root = ContentDigest::sha256(b"divergent_state_root");
    assert_eq!(
        belief.validate_anchor_freshness(&other_root),
        Err(ContractError::DerivedBeliefAnchorMismatch)
    );

    // Different site lineage: incomparable, refused.
    let mut other_site = pinned.clone();
    other_site.site_lineage = "site:eu-west:secondary".into();
    assert_eq!(
        belief.validate_anchor_freshness(&other_site),
        Err(ContractError::DerivedBeliefAnchorMismatch)
    );

    // A caller anchor with an all-zero state root anchors nothing.
    let mut zero_current = pinned.clone();
    zero_current.state_root = zero_digest();
    assert_eq!(
        belief.validate_anchor_freshness(&zero_current),
        Err(ContractError::DerivedBeliefMissingAnchor)
    );

    // The boundary enforces the same check: the cell conversion and anchored decode.
    assert_eq!(
        expect_err(
            belief.to_knowledge_cell(&newer_commit),
            "to_knowledge_cell(stale)"
        )?,
        ContractError::StaleAnchor
    );
    let bytes = encode_belief(&belief)?;
    assert_eq!(
        expect_err(
            DerivedBelief::decode_at_anchor(&mut CanonicalDecoder::new(&bytes), &newer_commit),
            "decode_at_anchor(stale)"
        )?,
        ContractError::StaleAnchor
    );
    assert_eq!(
        DerivedBelief::decode_at_anchor(&mut CanonicalDecoder::new(&bytes), &pinned)?,
        belief
    );
    Ok(())
}

#[test]
fn test_n3_future_epoch_anchor_is_never_fresh() -> Result<(), Box<dyn Error>> {
    let mut params = sealed_params("belief:n3:future")?;
    params.anchor.ledger_epoch = u64::MAX;
    let belief = DerivedBelief::new(params.with_computed_receipt()?)?;
    let current = sample_anchor();
    assert_eq!(
        belief.validate_anchor_freshness(&current),
        Err(ContractError::DerivedBeliefAnchorMismatch)
    );
    assert_eq!(
        expect_err(
            belief.to_knowledge_cell(&current),
            "to_knowledge_cell(future)"
        )?,
        ContractError::DerivedBeliefAnchorMismatch
    );
    Ok(())
}

#[test]
fn test_n3_zero_state_root_anchor_is_refused() -> Result<(), Box<dyn Error>> {
    let mut params = sealed_params("belief:n3:zero_root")?;
    params.anchor.state_root = zero_digest();
    let params = params.with_computed_receipt()?;
    assert_eq!(
        expect_err(DerivedBelief::new(params.clone()), "new(zero state root)")?,
        ContractError::DerivedBeliefMissingAnchor
    );
    assert_eq!(
        expect_err(decode(&encode_params(&params)?), "decode(zero state root)")?,
        ContractError::DerivedBeliefMissingAnchor
    );
    Ok(())
}

#[test]
fn test_n4_evidence_sets_are_strictly_ascending_and_disjoint() -> Result<(), Box<dyn Error>> {
    let (lo, hi) = ordered_pair(b"n4-a", b"n4-c");
    let other = ContentDigest::sha256(b"n4-support");
    let cases = [
        (
            "duplicate support [a,a]",
            vec![lo, lo],
            vec![],
            ContractError::DerivedBeliefDuplicateEvidence,
        ),
        (
            "duplicate contradictions",
            vec![lo],
            vec![hi, hi],
            ContractError::DerivedBeliefDuplicateEvidence,
        ),
        (
            "unordered support [c,a]",
            vec![hi, lo],
            vec![],
            ContractError::NonCanonicalOrdering,
        ),
        (
            "unordered contradictions",
            vec![other],
            vec![hi, lo],
            ContractError::NonCanonicalOrdering,
        ),
        (
            "support/contradiction overlap",
            vec![lo],
            vec![lo],
            ContractError::DerivedBeliefEvidenceOverlap,
        ),
        (
            "overlap in a larger set",
            vec![lo, hi],
            vec![hi],
            ContractError::DerivedBeliefEvidenceOverlap,
        ),
    ];
    for (label, support, contradictions, expected) in cases {
        let mut params = sealed_params("belief:n4:sets")?;
        params.supporting_evidence = support;
        params.contradictions = contradictions;
        let params = params.with_computed_receipt()?;
        assert_eq!(
            expect_err(DerivedBelief::new(params.clone()), label)?,
            expected,
            "{label}"
        );
        assert_eq!(
            expect_err(decode(&encode_params(&params)?), label)?,
            expected,
            "{label} via decode"
        );
    }

    // The strictly ascending spelling is accepted, so [a,c] has exactly one canonical digest.
    let mut ascending = sealed_params("belief:n4:sets")?;
    ascending.supporting_evidence = vec![lo, hi];
    ascending.contradictions = vec![other];
    let belief = DerivedBelief::new(ascending.with_computed_receipt()?)?;
    assert_eq!(belief.supporting_evidence(), &[lo, hi]);
    Ok(())
}

#[test]
fn test_decode_evidence_cap_enforced_before_reading_kills_m6() -> Result<(), Box<dyn Error>> {
    // 1025 well-formed digests are present, so the remaining-bytes bound passes and only the
    // hard cap can refuse the length. Without the cap, decode reads all 1025 digests and then
    // fails on the missing contradiction length with a different error (InvalidDigest).
    let over = u32::try_from(MAX_DERIVED_BELIEF_EVIDENCE + 1)?;
    let mut encoder = CanonicalEncoder::new();
    encode_header(&mut encoder, "belief:attack:evidence_cap")?;
    encoder.u32(over);
    for i in 0..over {
        encoder.digest(ContentDigest::sha256(&i.to_be_bytes()));
    }
    let payload = encoder.finish_checked()?;
    assert_eq!(
        expect_err(decode(&payload), "evidence over cap")?,
        ContractError::ArithmeticOverflow
    );
    Ok(())
}

#[test]
fn test_decode_contradiction_cap_enforced_before_reading() -> Result<(), Box<dyn Error>> {
    let over = u32::try_from(MAX_DERIVED_BELIEF_CONTRADICTIONS + 1)?;
    let mut encoder = CanonicalEncoder::new();
    encode_header(&mut encoder, "belief:attack:contradiction_cap")?;
    encoder.u32(1);
    encoder.digest(ContentDigest::sha256(b"ev1"));
    encoder.u32(over);
    for i in 0..over {
        encoder.digest(ContentDigest::sha256(&i.to_be_bytes()));
    }
    let payload = encoder.finish_checked()?;
    assert_eq!(
        expect_err(decode(&payload), "contradictions over cap")?,
        ContractError::ArithmeticOverflow
    );
    Ok(())
}

#[test]
fn test_decode_contradictions_remaining_bytes_bound_kills_m10() -> Result<(), Box<dyn Error>> {
    // 100 contradictions need 3300 bytes but the payload ends. Without the bound, decode tries
    // to read the first digest and fails with a different error (InvalidDigest).
    let mut encoder = CanonicalEncoder::new();
    encode_header(&mut encoder, "belief:attack:contradiction_remaining")?;
    encoder.u32(1);
    encoder.digest(ContentDigest::sha256(b"ev1"));
    encoder.u32(100);
    let payload = encoder.finish_checked()?;
    assert_eq!(
        expect_err(decode(&payload), "contradictions beyond remaining bytes")?,
        ContractError::ArithmeticOverflow
    );
    Ok(())
}

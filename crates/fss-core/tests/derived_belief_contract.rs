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

    let belief = DerivedBelief::new(DerivedBeliefParams {
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
    })?;

    // Properties
    assert_eq!(belief.belief_id, "belief:track:person:001");
    assert_eq!(belief.anchor, anchor);
    assert_eq!(belief.generation, Generation(1));
    assert_eq!(belief.knowledge_state, KnowledgeState::Estimated);
    assert_eq!(belief.provenance, ProvenanceClass::Derived);
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

    let belief = DerivedBelief::new(DerivedBeliefParams {
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
    })?;

    let cell = belief.to_knowledge_cell();

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
    let zero_receipt = ContentDigest::sha256(b"");
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

    // Non-zero digest succeeds
    assert_ne!(zero_receipt.bytes(), [0u8; 32]);

    Ok(())
}

#[test]
fn test_planted_negative_derived_belief_stale_anchor_fails() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let uncertainty = sample_uncertainty()?;
    let evidence_root = ContentDigest::sha256(b"evidence_packet_001");
    let receipt = ContentDigest::sha256(b"graph_projection_receipt_v1");

    let belief = DerivedBelief::new(DerivedBeliefParams {
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
    })?;

    // Stale anchor fails with exact error StaleAnchor
    let Err(err) = belief.validate_anchor_freshness(1) else {
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
        belief.validate_anchor_freshness(10),
        Err(ContractError::StaleAnchor)
    );
    assert!(belief.validate_anchor_freshness(0).is_ok());

    // Rebuildable check
    assert!(belief.is_rebuildable());

    // Dedicated test proving rebuild reproduces identical belief and digest
    let rebuilt = belief.rebuild()?;
    assert_eq!(belief, rebuilt);
    assert_eq!(belief.canonical_digest(), rebuilt.canonical_digest());
    assert_eq!(belief.derivation_receipt, rebuilt.derivation_receipt);

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

    let belief = DerivedBelief::new(DerivedBeliefParams {
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
    })?;

    let mut encoder = CanonicalEncoder::new();
    belief.encode_canonical(&mut encoder);
    let bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&bytes);
    let decoded = DerivedBelief::decode_canonical(&mut decoder)?;

    assert_eq!(belief, decoded);
    assert_eq!(belief.canonical_digest(), decoded.canonical_digest());

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

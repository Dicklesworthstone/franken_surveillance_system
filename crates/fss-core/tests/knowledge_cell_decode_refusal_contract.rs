#![forbid(unsafe_code)]
//! Invalid knowledge cells are unrepresentable outside `fss-core` (fss-nozug).
//!
//! `KnowledgeCell` fields are private and the only public constructor validates, so an invalid
//! cell could reach a caller only through decoded bytes. These are the public decode paths that
//! yield a `KnowledgeCell`:
//!
//! - `DerivedBelief::decode_canonical` / `DerivedBelief::decode_at_anchor`, then
//!   `DerivedBelief::to_knowledge_cell`;
//! - `H1SemanticSynopsis::from_canonical_bytes` / `decode_canonical`, then `to_knowledge_cells`;
//! - `SourceEvidenceRecord::from_canonical_bytes` / `decode_canonical`, then `to_knowledge_cell`;
//! - `H4LaboratoryExpansion::from_canonical_bytes`, then `to_knowledge_cell`.
//!
//! No public decode path yields a `SituationCapsule`, a `SituationFrame`, or a reference
//! situation, so a capsule can only hold cells from the validating constructor.
//!
//! The five invalid cells pinned at the capsule entry points before fss-nozug are: indeterminate
//! without a reconciliation basis, redacted without a marker, stale without a basis, a redaction
//! basis on a known cell, and a redaction basis on a stale cell. For each, hand-crafted
//! canonical bytes carrying that cell's knowledge state are refused by every path whose wire
//! carries a knowledge state (derived belief and H1), and no refusal discloses planted content.
//! The source-evidence and H4 wires carry no knowledge state and no basis: their cell state is
//! computed, so no bytes can encode these cells. For source evidence every computed cell is
//! proved valid, and a laboratory-tainted record (the case the removed unvalidated fallback
//! used to emit) is refused with a typed error; H4 always emits an estimated predicted cell
//! through `KnowledgeCell::new`.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Debug, Display};

use fss_core::{
    BeliefInterval, BudgetVector, CanonicalDecode, CanonicalDecoder, CanonicalEncode,
    CanonicalEncoder, Completeness, ContentDigest, ContractBasis, ContractBasisRegistryBytes,
    ContractError, DerivedBelief, DerivedBeliefParams, Generation, H1CellContext,
    H1SemanticSynopsis, H1SynopsisParams, HydrationError, KnowledgeState,
    LABORATORY_PROVENANCE_MARKER, LedgerAnchor, OmissionReason, ProvenanceClass,
    REDACTED_STATEMENT_MARKER, SourceCustody, SourceEvidenceClassification, SourceEvidenceParams,
    SourceEvidenceRecord, SynopsisClassification, SynopsisQuality, TimestampNs, WorldFact,
    WorldFactKind,
};

/// One of the five invalid cells.
struct InvalidCase {
    label: &'static str,
    state: KnowledgeState,
    /// Whether the invalid cell carries a redaction basis, so its statement is withheld.
    withheld: bool,
    /// The refusal of the derived-belief decode paths.
    derived_refusal: ContractError,
}

fn invalid_cases() -> [InvalidCase; 5] {
    [
        InvalidCase {
            label: "indeterminate-without-reconciliation-basis",
            state: KnowledgeState::Indeterminate,
            withheld: false,
            derived_refusal: ContractError::ReconciliationBasisRequired,
        },
        InvalidCase {
            label: "redacted-without-marker",
            state: KnowledgeState::Redacted,
            withheld: false,
            derived_refusal: ContractError::RedactionMarkerRequired,
        },
        InvalidCase {
            label: "stale-without-basis",
            state: KnowledgeState::Stale,
            withheld: false,
            derived_refusal: ContractError::StaleBasisRequired,
        },
        InvalidCase {
            label: "redaction-basis-on-known",
            state: KnowledgeState::Known,
            withheld: true,
            derived_refusal: ContractError::DerivedBeliefKnownForbidden,
        },
        InvalidCase {
            label: "redaction-basis-on-stale",
            state: KnowledgeState::Stale,
            withheld: true,
            derived_refusal: ContractError::StaleBasisRequired,
        },
    ]
}

/// Asserts that neither the `Debug` nor the `Display` form of `refusal` contains any `planted`
/// content. The output itself is never printed: on failure it would carry the planted text.
fn assert_no_disclosure<E: Debug + Display>(refusal: &E, planted: &[&str], what: &str) {
    let debug = format!("{refusal:?}");
    let display = refusal.to_string();
    for (index, content) in planted.iter().enumerate() {
        assert!(
            !debug.contains(content) && !display.contains(content),
            "{what}: the refusal disclosed planted content #{index}"
        );
    }
}

/// The canonical encoding of one text value (64-bit big-endian length prefix, then UTF-8).
fn encoded_text(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(value);
    Ok(encoder.finish_checked()?)
}

/// The canonical encoding of a one-element set count.
fn one_count() -> Vec<u8> {
    1u64.to_be_bytes().to_vec()
}

fn derived_anchor() -> LedgerAnchor {
    LedgerAnchor::genesis("site:decode-refusal")
}

/// Hand-crafted canonical `DerivedBelief` bytes carrying `state` and `statement`, laid out
/// field by field without validation.
fn derived_belief_bytes(state: KnowledgeState, statement: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let params = DerivedBeliefParams {
        belief_id: "belief:decode-refusal:001".into(),
        anchor: derived_anchor(),
        generation: Generation(1),
        statement: statement.into(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Derived,
        uncertainty: BeliefInterval::new(750_000, 920_000)?,
        supporting_evidence: vec![ContentDigest::sha256(b"decode_refusal_evidence")],
        contradictions: vec![],
        derivation_receipt: ContentDigest::sha256(b"unsealed"),
    }
    .with_computed_receipt()?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text(&params.belief_id);
    params.anchor.encode_canonical(&mut encoder);
    encoder.u64(params.generation.0);
    encoder.text(&params.statement);
    state.encode_canonical(&mut encoder);
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

#[test]
fn derived_belief_decode_paths_refuse_every_invalid_cell() -> Result<(), Box<dyn Error>> {
    // The honest encoding decodes and yields a valid cell, so each refusal below is caused by
    // the planted state alone.
    let honest = derived_belief_bytes(KnowledgeState::Estimated, "Honest derived proposition")?;
    let belief = DerivedBelief::decode_canonical(&mut CanonicalDecoder::new(&honest))?;
    belief.to_knowledge_cell(&derived_anchor())?.validate()?;

    for case in invalid_cases() {
        let secret = format!("SECRET-derived-{}", case.label);
        let statement = if case.withheld {
            format!("{REDACTED_STATEMENT_MARKER} {secret}")
        } else {
            secret.clone()
        };
        let bytes = derived_belief_bytes(case.state, &statement)?;
        let decoded = DerivedBelief::decode_canonical(&mut CanonicalDecoder::new(&bytes));
        let at_anchor =
            DerivedBelief::decode_at_anchor(&mut CanonicalDecoder::new(&bytes), &derived_anchor());
        for (what, result) in [
            ("decode_canonical", decoded),
            ("decode_at_anchor", at_anchor),
        ] {
            match result {
                Err(refusal) => {
                    assert_eq!(refusal, case.derived_refusal, "{}: {what}", case.label);
                    assert_no_disclosure(&refusal, &[secret.as_str()], case.label);
                }
                Ok(_) => {
                    return Err(format!("{}: {what} accepted an invalid cell", case.label).into());
                }
            }
        }
    }
    Ok(())
}

fn h1_anchor() -> LedgerAnchor {
    let mut anchor = LedgerAnchor::genesis("site:decode-refusal:h1");
    anchor.commit_sequence = 1;
    anchor
}

/// Valid H1 parameters whose only fact is `fact` and whose declared state set is `declared`.
fn h1_params(
    fact: WorldFact,
    declared: KnowledgeState,
) -> Result<H1SynopsisParams, Box<dyn Error>> {
    Ok(H1SynopsisParams {
        handle_id: "semantic-handle:sha256:decode-refusal".to_string(),
        subject_id: "evidence:decode-refusal".to_string(),
        subject_digest: ContentDigest::sha256(b"decode refusal subject"),
        semantic_type: "semantic_synopsis".to_string(),
        classification: SynopsisClassification::SemanticSynopsis,
        anchor: h1_anchor(),
        contract_basis: ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
            b"schemas",
            b"operations",
            b"views",
            b"capabilities",
            b"errors",
            b"costs",
            "fss/1",
        )),
        estimated_cost: BudgetVector::builder()
            .latency_ms(10)
            .tokens(128)
            .bytes(1024)
            .cpu_millis(2)
            .privacy_exposure(0.1)
            .build()?,
        required_capabilities: BTreeSet::from(["capability:hydrate:h1".to_string()]),
        privacy_class: "private:property".to_string(),
        published_at: TimestampNs(100),
        retention_until: TimestampNs(10_000),
        facts: vec![fact],
        knowledge_states: BTreeSet::from([declared]),
        provenance_classes: BTreeSet::from([ProvenanceClass::Observed]),
        contradictions: Vec::new(),
        quality: SynopsisQuality::new(
            Completeness::Complete,
            Some(BeliefInterval::new(800_000, 950_000)?),
            1_000_000,
            Some(ContentDigest::sha256(b"calibration-gen-1")),
        )?,
        omissions: BTreeSet::from([OmissionReason::PrivacyRedaction]),
    })
}

/// Rewrites the declared knowledge-state set of honest H1 bytes from `{from}` to `{to}`. The
/// set is located as a one-element state set followed by the one-element provenance set
/// `{observed}`, which occurs exactly once.
fn replace_declared_state(
    honest: &[u8],
    from: KnowledgeState,
    to: KnowledgeState,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let tail = [one_count(), encoded_text("observed")?].concat();
    let needle = [one_count(), encoded_text(from.as_str())?, tail.clone()].concat();
    let replacement = [one_count(), encoded_text(to.as_str())?, tail].concat();
    let positions: Vec<usize> = honest
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| *window == needle.as_slice())
        .map(|(index, _)| index)
        .collect();
    let [position] = positions.as_slice() else {
        return Err(format!("declared state set found {} times", positions.len()).into());
    };
    Ok([
        &honest[..*position],
        replacement.as_slice(),
        &honest[position + needle.len()..],
    ]
    .concat())
}

#[test]
fn h1_decode_paths_refuse_every_invalid_cell() -> Result<(), Box<dyn Error>> {
    for case in invalid_cases() {
        let secret = format!("SECRET-h1-{}", case.label);
        let fact_id = format!("fact:device:{}", case.label);
        // A withheld cell is encoded as a fact whose statement is the redaction marker; the
        // synopsis carries no projection, so its honest derived state is unknown.
        let (statement, honest_state) = if case.withheld {
            (
                REDACTED_STATEMENT_MARKER.to_string(),
                KnowledgeState::Unknown,
            )
        } else {
            (secret.clone(), KnowledgeState::Known)
        };
        let fact = WorldFact::new(
            fact_id.as_str(),
            WorldFactKind::Device,
            h1_anchor(),
            statement.as_str(),
            ProvenanceClass::Observed,
            ContentDigest::sha256(secret.as_bytes()),
            Generation(1),
        )?;
        let synopsis = H1SemanticSynopsis::new(h1_params(fact, honest_state)?)?;
        let honest = synopsis.to_canonical_bytes()?;
        let decoded = H1SemanticSynopsis::from_canonical_bytes(&honest)?;
        for cell in decoded.to_knowledge_cells(&H1CellContext::new(decoded.anchor().clone()))? {
            cell.validate()?;
        }

        let crafted = replace_declared_state(&honest, honest_state, case.state)?;
        let from_bytes = H1SemanticSynopsis::from_canonical_bytes(&crafted);
        let from_decoder =
            H1SemanticSynopsis::decode_canonical(&mut CanonicalDecoder::new(&crafted));
        for (what, result) in [
            ("from_canonical_bytes", from_bytes),
            ("decode_canonical", from_decoder),
        ] {
            match result {
                Err(refusal) => {
                    assert_no_disclosure(&refusal, &[secret.as_str(), fact_id.as_str()], case.label)
                }
                Ok(_) => {
                    return Err(format!("{}: {what} accepted an invalid cell", case.label).into());
                }
            }
        }
    }
    Ok(())
}

/// A laboratory-tainted fact claiming `known` used to fall back to an unvalidated cell; it is
/// now refused with the typed error wherever the cell is built.
#[test]
fn h1_laboratory_tainted_known_fact_is_refused_with_a_typed_error() -> Result<(), Box<dyn Error>> {
    let secret = "SECRET-h1-laboratory-planted";
    let fact = WorldFact::new(
        "fact:device:laboratory",
        WorldFactKind::Device,
        h1_anchor(),
        format!("{LABORATORY_PROVENANCE_MARKER} {secret}").as_str(),
        ProvenanceClass::Observed,
        ContentDigest::sha256(b"laboratory-fact-evidence"),
        Generation(1),
    );
    let fact = match fact {
        Ok(fact) => fact,
        Err(refusal) => {
            assert_no_disclosure(&refusal, &[secret], "WorldFact::new");
            return Ok(());
        }
    };
    match H1SemanticSynopsis::new(h1_params(fact, KnowledgeState::Known)?) {
        Err(refusal) => {
            assert_eq!(
                refusal,
                HydrationError::Contract(ContractError::DerivedLayerAuthorityForbidden)
            );
            assert_no_disclosure(&refusal, &[secret], "H1SemanticSynopsis::new");
            Ok(())
        }
        Ok(_) => Err("a laboratory-tainted known fact produced a synopsis".into()),
    }
}

fn source_params(
    evidence_id: &str,
    statement: &str,
    custody: SourceCustody,
    omission: Option<OmissionReason>,
) -> SourceEvidenceParams {
    SourceEvidenceParams {
        evidence_id: evidence_id.to_string(),
        anchor: LedgerAnchor::genesis("site:decode-refusal:source"),
        generation: Generation(1),
        statement: statement.to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::PhysicalSensorMeasurement,
        custody,
        omission,
        capsule: None,
        continuity_witness: None,
    }
}

fn retained() -> SourceCustody {
    SourceCustody::Retained {
        source_digest: ContentDigest::sha256(b"decode-refusal-source-bytes"),
        source_bytes: 1024,
        storage_handle: "cas/sha256/decode-refusal".to_string(),
    }
}

/// The source-evidence wire carries no knowledge state and no basis; every cell it can yield
/// after decode is valid, for every custody and omission combination the record admits.
#[test]
fn source_evidence_decode_yields_only_valid_cells() -> Result<(), Box<dyn Error>> {
    let omissions = [
        None,
        Some(OmissionReason::None),
        Some(OmissionReason::PrivacyRedaction),
        Some(OmissionReason::ResourcePressure),
        Some(OmissionReason::RetentionPolicy),
        Some(OmissionReason::CapabilityFiltered),
        Some(OmissionReason::TransientPreviewOnly),
        Some(OmissionReason::UpstreamMissing),
    ];
    let mut emitted = 0usize;
    for custody in [retained(), SourceCustody::NotRetained] {
        for omission in omissions {
            let Ok(record) = SourceEvidenceRecord::new(source_params(
                "source:packet:decode-refusal:0001",
                "Physical sensor reading",
                custody.clone(),
                omission,
            )) else {
                continue;
            };
            let decoded =
                SourceEvidenceRecord::from_canonical_bytes(&record.to_canonical_bytes()?)?;
            let via_decoder = SourceEvidenceRecord::decode_canonical(&mut CanonicalDecoder::new(
                &record.to_canonical_bytes()?,
            ))?;
            for source in [decoded, via_decoder] {
                let cell = source.to_knowledge_cell()?;
                cell.validate()?;
                emitted += 1;
            }
        }
    }
    assert!(
        emitted >= 6,
        "too few admitted records to cover the source-evidence wire: {emitted}"
    );
    Ok(())
}

/// A laboratory-tainted retained record (a `known` cell carrying the laboratory marker) used to
/// fall back to an unvalidated cell; every path now refuses it with the typed error.
#[test]
fn source_evidence_laboratory_tainted_record_is_refused_with_a_typed_error()
-> Result<(), Box<dyn Error>> {
    let secret = "SECRET-source-laboratory-planted";
    let statement = format!("{LABORATORY_PROVENANCE_MARKER} {secret}");
    let record = match SourceEvidenceRecord::new(source_params(
        "source:packet:decode-refusal:0002",
        &statement,
        retained(),
        None,
    )) {
        Ok(record) => record,
        Err(refusal) => {
            assert_no_disclosure(&refusal, &[secret], "SourceEvidenceRecord::new");
            return Ok(());
        }
    };
    let direct = record.to_knowledge_cell();
    let decoded = SourceEvidenceRecord::from_canonical_bytes(&record.to_canonical_bytes()?)?
        .to_knowledge_cell();
    for (what, result) in [("record", direct), ("decoded record", decoded)] {
        match result {
            Err(refusal) => {
                assert_eq!(
                    refusal,
                    ContractError::DerivedLayerAuthorityForbidden,
                    "{what}"
                );
                assert_no_disclosure(&refusal, &[secret], what);
            }
            Ok(_) => return Err(format!("{what}: a laboratory-tainted cell was emitted").into()),
        }
    }
    Ok(())
}

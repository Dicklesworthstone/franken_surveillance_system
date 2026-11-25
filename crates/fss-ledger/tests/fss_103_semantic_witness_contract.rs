#![forbid(unsafe_code)]
//! Contract and fault suite for `FSS-103` (`fss-x4a.9.10`):
//! Positive, negative, and hierarchical semantic ledger witnesses.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    BatchId, CaptureInterval, Completeness, ContentDigest, CoverageContinuity, CoverageStopReason,
    CoverageWitness, EvidenceDelta, LedgerAnchor, ObjectId, Plane, TimestampNs,
};
use fss_ledger::{
    EpochLedgerConfig, HierarchicalWitness, IncompleteTailPolicy, LedgerOracle,
    MAX_WITNESS_WIRE_BYTES, MerkleEpochLedger, NegativeWitness, OracleLimits, PositiveWitness,
    SEMANTIC_WITNESS_VERSION, SemanticWitness, WitnessError, WitnessGuidance,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> io::Result<Self> {
        let base = fs::canonicalize(std::env::temp_dir())?;
        for _ in 0..32 {
            let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!("fss-103-witness-{}-{n}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "temp dir namespace exhausted",
        ))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn d(label: &str) -> ContentDigest {
    ContentDigest::sha256(label.as_bytes())
}

fn make_delta(
    delta_id: &str,
    object_id: &str,
    prior_generation: Option<u64>,
    new_generation: u64,
    plane: Plane,
) -> Result<EvidenceDelta, Box<dyn std::error::Error>> {
    Ok(EvidenceDelta {
        delta_id: delta_id.to_owned(),
        family: "source_evidence".to_owned(),
        object_id: ObjectId::parse(object_id)?,
        prior_generation,
        new_generation,
        validity: CaptureInterval::new(TimestampNs(100), TimestampNs(200))?,
        plane,
        payload_digest: d(&format!("{object_id}:{new_generation}")),
        witness_digest: None,
        operation_id: None,
    })
}

fn coverage_for(anchor: LedgerAnchor, certified: bool) -> CoverageWitness {
    let domain: BTreeSet<String> = ["sensor:cam-1".to_owned(), "sensor:cam-2".to_owned()]
        .into_iter()
        .collect();
    let observed = if certified {
        domain.clone()
    } else {
        ["sensor:cam-1".to_owned()].into_iter().collect()
    };
    CoverageWitness {
        anchor,
        authorized_domain: domain,
        observed_domain: observed,
        excluded_domain: BTreeSet::new(),
        continuity: if certified {
            CoverageContinuity::Continuous
        } else {
            CoverageContinuity::Gapped
        },
        completeness: if certified {
            Completeness::Complete
        } else {
            Completeness::Partial
        },
        negative_predicate: "no_person_in_driveway".to_owned(),
        stop_reason: if certified {
            CoverageStopReason::Complete
        } else {
            CoverageStopReason::SourceGap
        },
        authorized_generation: 3,
        observed_generation: 3,
    }
}

#[test]
fn positive_negative_and_hierarchical_witnesses_verify_roundtrip_and_preserve_non_collapse()
-> TestResult {
    let mut oracle = LedgerOracle::new("site-fss-103", OracleLimits::CEILING)?;
    let obj_a = ObjectId::parse("obj:cam-a")?;
    let obj_b = ObjectId::parse("obj:cam-b")?;
    let obj_absent = ObjectId::parse("obj:ghost-x")?;

    let b1 = oracle.prepare_batch(
        BatchId::parse("batch:103-1")?,
        vec![make_delta("d1", "obj:cam-a", None, 1, Plane::Authority)?],
        vec![],
    )?;
    oracle.append(b1)?;
    let b2 = oracle.prepare_batch(
        BatchId::parse("batch:103-2")?,
        vec![make_delta("d2", "obj:cam-b", None, 1, Plane::Cognition)?],
        vec![],
    )?;
    oracle.append(b2)?;

    // 1. Positive witness at sequence 2.
    let pos_a = PositiveWitness::from_oracle(&oracle, 2, &obj_a)?;
    assert_eq!(pos_a.committed_sequence, 1);
    pos_a.verify_against_oracle(&oracle)?;

    // Positive witness for absent object fails closed with guidance.
    let abs_err = PositiveWitness::from_oracle(&oracle, 2, &obj_absent)
        .expect_err("positive witness for absent object must fail");
    assert!(matches!(abs_err, WitnessError::ObjectAbsent { .. }));
    assert_eq!(
        abs_err.guidance(),
        WitnessGuidance::IssueNegativeWitnessWithCoverage
    );

    // 2. Certified Negative witness at sequence 2.
    let anchor2 = oracle.head_anchor().clone();
    let neg_cert =
        NegativeWitness::from_oracle(&oracle, 2, &obj_absent, coverage_for(anchor2.clone(), true))?;
    assert!(neg_cert.certified);
    neg_cert.require_certified_absence()?;
    neg_cert.verify_against_oracle(&oracle)?;

    // Negative witness for present object fails closed.
    let pres_err =
        NegativeWitness::from_oracle(&oracle, 2, &obj_a, coverage_for(anchor2.clone(), true))
            .expect_err("negative witness for present object must fail");
    assert!(matches!(pres_err, WitnessError::ObjectPresent { .. }));
    assert_eq!(pres_err.guidance(), WitnessGuidance::IssuePositiveWitness);

    // 3. Uncertified Negative witness preserves gapped coverage honestly without inflation.
    let neg_uncert =
        NegativeWitness::from_oracle(&oracle, 2, &obj_absent, coverage_for(anchor2, false))?;
    assert!(!neg_uncert.certified);
    assert_eq!(
        neg_uncert.require_certified_absence(),
        Err(WitnessError::AbsenceNotCertified)
    );
    neg_uncert.verify_against_oracle(&oracle)?;

    // 4. Hierarchical composition is permutation-invariant and refuses uncertified inflation.
    let pos_b = PositiveWitness::from_oracle(&oracle, 2, &obj_b)?;
    let h1 = HierarchicalWitness::compose(
        "zone:driveway",
        vec![
            SemanticWitness::Positive(pos_a.clone()),
            SemanticWitness::Negative(neg_cert.clone()),
            SemanticWitness::Positive(pos_b.clone()),
        ],
        false,
    )?;
    let h2 = HierarchicalWitness::compose(
        "zone:driveway",
        vec![
            SemanticWitness::Positive(pos_b.clone()),
            SemanticWitness::Positive(pos_a.clone()),
            SemanticWitness::Negative(neg_cert.clone()),
        ],
        false,
    )?;
    assert_eq!(h1.witness_digest, h2.witness_digest);
    assert!(h1.all_negative_certified);
    assert_eq!(h1.height, 1);
    h1.verify_against_oracle(&oracle, false)?;

    // Nesting an uncertified negative child propagates all_negative_certified == false.
    let h_nested = HierarchicalWitness::compose(
        "site:all",
        vec![
            SemanticWitness::Hierarchical(h1.clone()),
            SemanticWitness::Negative(neg_uncert),
        ],
        false,
    )?;
    assert_eq!(h_nested.height, 2);
    assert!(!h_nested.all_negative_certified);
    h_nested.verify_against_oracle(&oracle, false)?;

    // Binary wire codec round-trip for nested hierarchy.
    let wrapped = SemanticWitness::Hierarchical(h_nested);
    let wire = wrapped.to_canonical_bytes()?;
    let decoded = SemanticWitness::from_canonical_bytes(&wire)?;
    assert_eq!(decoded, wrapped);

    // 5. Mixed anchors in hierarchy fail closed.
    let pos_at_1 = PositiveWitness::from_oracle(&oracle, 1, &obj_a)?;
    let mix_err = HierarchicalWitness::compose(
        "zone:mixed",
        vec![
            SemanticWitness::Positive(pos_at_1),
            SemanticWitness::Positive(pos_b),
        ],
        false,
    )
    .expect_err("mixed anchors in hierarchy must fail");
    assert_eq!(mix_err, WitnessError::MixedAnchorInHierarchy);
    assert_eq!(mix_err.guidance(), WitnessGuidance::SplitByExactAnchor);

    // 6. Cooperative cancellation refuses cleanly.
    assert_eq!(
        h1.verify_against_oracle(&oracle, true),
        Err(WitnessError::Cancelled)
    );

    // 7. Mutated public fields fail closed before wire serialization and before composition.
    let mut forged_pos = pos_a;
    forged_pos.committed_sequence = 0;
    assert_eq!(
        SemanticWitness::Positive(forged_pos.clone()).to_canonical_bytes(),
        Err(WitnessError::ChecksumMismatch)
    );
    assert_eq!(
        HierarchicalWitness::compose(
            "zone:tampered",
            vec![SemanticWitness::Positive(forged_pos)],
            false,
        ),
        Err(WitnessError::ChecksumMismatch)
    );

    let mut forged_neg = neg_cert;
    forged_neg.coverage = coverage_for(forged_neg.anchor.clone(), false);
    assert!(matches!(
        SemanticWitness::Negative(forged_neg).to_canonical_bytes(),
        Err(WitnessError::MalformedWire(_))
    ));

    emit_caplog(
        "fss103_positive_negative_hierarchical_oracle",
        "permutation_invariant_non_collapsed_and_mixed_anchor_refused",
        "permutation_invariant_non_collapsed_and_mixed_anchor_refused",
        "pass",
    );
    Ok(())
}

#[test]
fn merkle_backed_witnesses_and_hostile_wire_payloads_fail_closed() -> TestResult {
    let dir = TempDir::new()?;
    let mut merkle = MerkleEpochLedger::open(
        dir.0.join("epochs"),
        "site-merkle-103",
        EpochLedgerConfig::default(),
        IncompleteTailPolicy::Reject,
    )?;

    let obj_present = ObjectId::parse("obj:merkle-1")?;
    let obj_absent = ObjectId::parse("obj:merkle-missing")?;
    let batch = merkle.prepare_batch(
        BatchId::parse("batch:merkle-1")?,
        vec![make_delta(
            "dm1",
            "obj:merkle-1",
            None,
            1,
            Plane::Authority,
        )?],
        vec![],
    )?;
    merkle.append_batch(batch)?;

    // Merkle-backed positive inclusion witness + binary wire round-trip.
    let pos_m = PositiveWitness::from_merkle_ledger(&merkle, &obj_present)?;
    assert!(pos_m.merkle_proof.is_some());
    pos_m.verify_merkle_proof()?;
    let pos_wire = SemanticWitness::Positive(pos_m.clone()).to_canonical_bytes()?;
    assert_eq!(
        SemanticWitness::from_canonical_bytes(&pos_wire)?,
        SemanticWitness::Positive(pos_m)
    );

    // Merkle-backed negative non-inclusion witness + binary wire round-trip.
    let neg_m = NegativeWitness::from_merkle_ledger(
        &merkle,
        &obj_absent,
        coverage_for(merkle.head_anchor().clone(), true),
    )?;
    assert!(neg_m.merkle_proof.is_some());
    assert!(neg_m.certified);
    neg_m.verify_merkle_proof()?;
    let neg_wire = SemanticWitness::Negative(neg_m.clone()).to_canonical_bytes()?;
    assert_eq!(
        SemanticWitness::from_canonical_bytes(&neg_wire)?,
        SemanticWitness::Negative(neg_m)
    );

    // Hostile wire checks: bad magic, unsupported version, truncation, checksum flip, trailing,
    // and oversize buffer.
    let mut bad_magic = neg_wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        SemanticWitness::from_canonical_bytes(&bad_magic),
        Err(WitnessError::InvalidMagic)
    );

    let mut bad_ver = neg_wire.clone();
    bad_ver[8..12].copy_from_slice(&(SEMANTIC_WITNESS_VERSION + 1).to_be_bytes());
    assert_eq!(
        SemanticWitness::from_canonical_bytes(&bad_ver),
        Err(WitnessError::UnsupportedVersion {
            version: SEMANTIC_WITNESS_VERSION + 1
        })
    );

    assert!(matches!(
        SemanticWitness::from_canonical_bytes(&neg_wire[..neg_wire.len() - 6]),
        Err(WitnessError::MalformedWire(_))
    ));

    let mut flipped = neg_wire.clone();
    let end = flipped.len() - 1;
    flipped[end] ^= 0x04;
    assert_eq!(
        SemanticWitness::from_canonical_bytes(&flipped),
        Err(WitnessError::ChecksumMismatch)
    );

    let mut trailing = neg_wire;
    trailing.push(0xAB);
    assert!(matches!(
        SemanticWitness::from_canonical_bytes(&trailing),
        Err(WitnessError::MalformedWire(_))
    ));

    let huge = vec![0u8; MAX_WITNESS_WIRE_BYTES + 1];
    assert!(matches!(
        SemanticWitness::from_canonical_bytes(&huge),
        Err(WitnessError::BoundsExceeded { .. })
    ));

    emit_caplog(
        "fss103_merkle_backed_and_hostile_wire",
        "merkle_inclusion_non_inclusion_and_wire_refusals_verified",
        "merkle_inclusion_non_inclusion_and_wire_refusals_verified",
        "pass",
    );
    Ok(())
}

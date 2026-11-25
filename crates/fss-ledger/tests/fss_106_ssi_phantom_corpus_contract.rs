#![forbid(unsafe_code)]
//! Contract & fault tests for `FSS-106` (`fss-x4a.9.13`): negative-read phantom and SSI
//! write-skew adversarial schedule corpus composing `FSS-103`, `FSS-104`, `FSS-105`, and `LedgerOracle`.

use fss_core::TimestampNs;
use fss_ledger::{
    LEDGER_SSI_CORPUS_RECEIPT_DOMAIN, SSI_CORPUS_MAGIC, SSI_CORPUS_VERSION, ScheduleCorpusReceipt,
    ScheduleVerdict, SsiCorpusError, SsiCorpusRunner,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

#[test]
fn ssi_and_negative_phantom_corpus_passes_all_schedules_deterministically() -> TestResult {
    let r1 = SsiCorpusRunner::run_all_schedules(TimestampNs(1_700_000_106_000), false)?;
    let r2 = SsiCorpusRunner::run_all_schedules(TimestampNs(1_700_000_106_000), false)?;

    // Repeatable determinism: two cold runs produce bit-identical receipts & reproducer digests!
    assert_eq!(r1, r2);
    assert!(r1.all_passed());
    assert_eq!(r1.verdict, ScheduleVerdict::Passed);
    assert_eq!(r1.cases.len(), 6);
    assert_eq!(r1.total_permutations_tested, 15);
    assert_eq!(
        LEDGER_SSI_CORPUS_RECEIPT_DOMAIN,
        "fss.ledger_ssi_corpus_receipt.v1"
    );
    assert!(!r1.claim_scope.is_empty());
    assert!(r1.excluded_dimensions.len() >= 3);

    for case in &r1.cases {
        assert_eq!(
            case.verdict,
            ScheduleVerdict::Passed,
            "case {}",
            case.case_id
        );
        assert!(case.permutation_invariant, "case {}", case.case_id);
        assert!(case.permutations_tested >= 1);
    }

    // Binary wire codec round-trip (`FSSSSIC1` v1).
    let wire = r1.to_canonical_bytes()?;
    assert_eq!(&wire[..8], &SSI_CORPUS_MAGIC);
    assert_eq!(
        u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]),
        SSI_CORPUS_VERSION
    );
    let decoded = ScheduleCorpusReceipt::from_canonical_bytes(&wire)?;
    assert_eq!(decoded, r1);

    emit_caplog(
        "fss106_ssi_and_phantom_corpus_all_6_schedules",
        "all_6_schedules_15_permutations_deterministic_and_wire_verified",
        "all_6_schedules_15_permutations_deterministic_and_wire_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn ssi_corpus_cancel_and_hostile_wire_fail_closed() -> TestResult {
    assert_eq!(
        SsiCorpusRunner::run_all_schedules(TimestampNs(1_700_000_106_500), true),
        Err(SsiCorpusError::Cancelled)
    );

    let receipt = SsiCorpusRunner::run_all_schedules(TimestampNs(1_700_000_106_600), false)?;
    let wire = receipt.to_canonical_bytes()?;

    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        ScheduleCorpusReceipt::from_canonical_bytes(&bad_magic),
        Err(SsiCorpusError::InvalidMagic)
    );

    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&42_u32.to_be_bytes());
    assert_eq!(
        ScheduleCorpusReceipt::from_canonical_bytes(&bad_ver),
        Err(SsiCorpusError::UnsupportedVersion { version: 42 })
    );

    assert!(matches!(
        ScheduleCorpusReceipt::from_canonical_bytes(&wire[..wire.len() - 6]),
        Err(SsiCorpusError::MalformedWire(_))
    ));

    let mut bit_flip = wire.clone();
    let last = bit_flip.len() - 1;
    bit_flip[last] ^= 0x01;
    assert_eq!(
        ScheduleCorpusReceipt::from_canonical_bytes(&bit_flip),
        Err(SsiCorpusError::ChecksumMismatch)
    );

    let mut trailing = wire;
    trailing.push(0x99);
    assert!(matches!(
        ScheduleCorpusReceipt::from_canonical_bytes(&trailing),
        Err(SsiCorpusError::MalformedWire(_))
    ));

    // In-memory forged verdict downgrade/upgrade refuses verify_self!
    let mut forged = receipt;
    forged.verdict = ScheduleVerdict::Failed;
    forged.receipt_digest = forged.compute_digest()?;
    assert!(matches!(
        forged.verify_self(),
        Err(SsiCorpusError::MalformedWire(_))
    ));

    emit_caplog(
        "fss106_cancel_and_hostile_wire",
        "cancel_hostile_wire_and_forged_verdict_failed_closed",
        "cancel_hostile_wire_and_forged_verdict_failed_closed",
        "pass",
    );
    Ok(())
}

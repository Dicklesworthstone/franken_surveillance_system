//! Contract tests for audited doctor, sealed repair plan, and quarantine apply workflow.
//!
//! Ref: fss-x4a.9.21 / LEDGER-REPAIR-001

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, ObjectId, Plane, TimestampNs,
};
use fss_ledger::{
    CorruptionKind, DurableLedgerError, DurableReferenceLedger, IncompleteTailPolicy, Journal,
    JournalError, RepairError, apply, doctor, doctor_path, plan, plan_with_cut,
    quarantine_path_for,
};

static COUNTER: AtomicU64 = AtomicU64::new(1);

fn temp_path(name: &str) -> PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "fss-ledger-repair-{}-{name}-{id}.journal",
        std::process::id()
    ))
}

fn sample_delta(
    id: &str,
    object_suffix: &str,
    generation: u64,
) -> Result<EvidenceDelta, Box<dyn Error>> {
    Ok(EvidenceDelta {
        delta_id: format!("delta:{id}"),
        family: "sensor_capsule".to_owned(),
        object_id: ObjectId::parse(format!("object:sensor:{object_suffix}"))?,
        prior_generation: if generation > 1 {
            Some(generation - 1)
        } else {
            None
        },
        new_generation: generation,
        validity: CaptureInterval::new(
            TimestampNs(i128::from(100 * generation)),
            TimestampNs(i128::from(200 * generation)),
        )?,
        plane: Plane::Authority,
        payload_digest: ContentDigest::sha256(format!("payload-{id}").as_bytes()),
        witness_digest: Some(ContentDigest::sha256(format!("witness-{id}").as_bytes())),
        operation_id: None,
    })
}

/// Positive test: a journal with foreign trailing bytes is diagnosed with offset, length,
/// and digest; a sealed plan quarantines the bytes to a retained sidecar object, truncates,
/// and the journal reopens with the committed prefix intact and verify_storage green.
#[test]
fn test_audited_doctor_plan_apply_workflow_positive() -> Result<(), Box<dyn Error>> {
    let path = temp_path("positive");
    let _ = fs::remove_file(&path);

    let committed_len;
    let last_root;
    let foreign_bytes = b"CORRUPT_FOREIGN_TRAILING_PAYLOAD_UNPRODUCED_BY_WRITER_999";

    // 1. Create a journal with two committed batches
    {
        let mut ledger =
            DurableReferenceLedger::open(&path, "site-alpha", IncompleteTailPolicy::Reject)?;

        let delta1 = sample_delta("1", "alpha", 1)?;
        let batch1 = ledger.prepare_batch(
            BatchId::parse("batch:1")?,
            vec![delta1],
            [ContentDigest::sha256(b"child-1")],
        )?;
        ledger.append(batch1)?;

        let delta2 = sample_delta("2", "alpha", 2)?;
        let batch2 = ledger.prepare_batch(
            BatchId::parse("batch:2")?,
            vec![delta2],
            [ContentDigest::sha256(b"child-2")],
        )?;
        ledger.append(batch2)?;

        last_root = ledger.journal_root();
        committed_len = fs::metadata(&path)?.len();
        assert!(committed_len > 0, "committed length must be non-zero");

        ledger.verify_storage()?;
    }

    // 2. Append foreign trailing bytes that this writer could not have produced
    {
        let mut raw = OpenOptions::new().append(true).open(&path)?;
        raw.write_all(foreign_bytes)?;
        raw.sync_all()?;
    }

    // 3. Confirm that ordinary open under IncompleteTailPolicy::Truncate refuses the journal
    let truncate_open_res =
        DurableReferenceLedger::open(&path, "site-alpha", IncompleteTailPolicy::Truncate);
    match truncate_open_res {
        Err(DurableLedgerError::Journal(JournalError::Corrupt {
            kind: CorruptionKind::RecordMagic,
            ..
        })) => {}
        other => {
            let _ = fs::remove_file(&path);
            return Err(format!(
                "expected DurableReferenceLedger::open to fail with Corrupt(RecordMagic), got: {other:?}"
            )
            .into());
        }
    }

    let journal_truncate_res = Journal::open(&path, IncompleteTailPolicy::Truncate);
    match journal_truncate_res {
        Err(JournalError::Corrupt {
            kind: CorruptionKind::RecordMagic,
            ..
        }) => {}
        other => {
            let _ = fs::remove_file(&path);
            return Err(format!(
                "expected Journal::open to fail with Corrupt(RecordMagic), got: {other:?}"
            )
            .into());
        }
    }

    // 4. Run pure doctor inspection over journal bytes and file path
    let bytes = fs::read(&path)?;
    let report_from_bytes = doctor(&bytes)?;
    let report = doctor_path(&path)?;
    assert_eq!(report_from_bytes, report);

    assert_eq!(report.committed_len(), committed_len);
    assert_eq!(report.last_root(), last_root);
    assert_eq!(report.records_count(), 2);
    assert!(report.has_foreign_bytes());

    let foreign_range = report.foreign_range().ok_or("expected foreign range")?;
    let expected_foreign_digest = ContentDigest::sha256(foreign_bytes);
    assert_eq!(foreign_range.offset, committed_len);
    assert_eq!(foreign_range.length, foreign_bytes.len() as u64);
    assert_eq!(foreign_range.digest, expected_foreign_digest);

    assert_eq!(report.foreign_offset(), Some(committed_len));
    assert_eq!(report.foreign_length(), Some(foreign_bytes.len() as u64));
    assert_eq!(report.foreign_digest(), Some(expected_foreign_digest));

    // 5. Generate sealed repair plan
    let plan = plan(&path, &report)?;
    assert_eq!(plan.journal_path(), &path);
    assert_eq!(plan.committed_len(), committed_len);
    assert_eq!(plan.last_root(), last_root);
    assert_eq!(plan.foreign_offset(), committed_len);
    assert_eq!(plan.foreign_length(), foreign_bytes.len() as u64);
    assert_eq!(plan.foreign_digest(), expected_foreign_digest);
    assert_eq!(plan.cut_offset(), committed_len);
    plan.verify_seal()?;

    // 6. Apply repair: quarantine foreign bytes and truncate
    let receipt = apply(&plan)?;
    assert_eq!(receipt.journal_path(), &path);
    assert_eq!(receipt.committed_len(), committed_len);
    assert_eq!(receipt.last_root(), last_root);
    assert_eq!(receipt.quarantined_offset(), committed_len);
    assert_eq!(receipt.quarantined_length(), foreign_bytes.len() as u64);
    assert_eq!(receipt.quarantined_digest(), expected_foreign_digest);
    assert_eq!(receipt.truncated_to(), committed_len);
    assert_eq!(receipt.plan_seal(), plan.seal());

    // Verify sidecar file exists, is named by digest, and contains foreign bytes
    let expected_sidecar_path = quarantine_path_for(&path, expected_foreign_digest);
    assert_eq!(receipt.quarantine_path(), &expected_sidecar_path);
    assert!(
        expected_sidecar_path.exists(),
        "quarantine sidecar file must exist"
    );

    let sidecar_bytes = fs::read(&expected_sidecar_path)?;
    assert_eq!(sidecar_bytes, foreign_bytes);

    // Verify journal file on disk is truncated to committed_len
    let file_len_after_repair = fs::metadata(&path)?.len();
    assert_eq!(file_len_after_repair, committed_len);

    // 7. Verify journal reopens cleanly under Reject and verify_storage is green
    let mut reopened =
        DurableReferenceLedger::open(&path, "site-alpha", IncompleteTailPolicy::Reject)?;
    assert_eq!(reopened.batches().len(), 2);
    assert_eq!(reopened.journal_root(), last_root);

    let storage_root = reopened.verify_storage()?;
    assert_eq!(storage_root, last_root);

    // Verify journal continues to be fully functional by committing batch 3
    let delta3 = sample_delta("3", "alpha", 3)?;
    let batch3 = reopened.prepare_batch(
        BatchId::parse("batch:3")?,
        vec![delta3],
        [ContentDigest::sha256(b"child-3")],
    )?;
    reopened.append(batch3)?;
    assert_eq!(reopened.batches().len(), 3);
    reopened.verify_storage()?;

    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(expected_sidecar_path);
    Ok(())
}

/// Planted negative 1: a plan whose recorded digest does not match the bytes at apply time
/// must be refused, leaving the journal untouched.
#[test]
fn test_planted_negative_digest_mismatch_refused() -> Result<(), Box<dyn Error>> {
    let path = temp_path("digest-mismatch");
    let _ = fs::remove_file(&path);

    let foreign_v1 = b"ORIGINAL_FOREIGN_TRAILING_BYTES_ALPHA";
    let foreign_v2 = b"TAMPERED_FOREIGN_TRAILING_BYTES_OMEGA";

    {
        let mut ledger =
            DurableReferenceLedger::open(&path, "site-alpha", IncompleteTailPolicy::Reject)?;
        let delta = sample_delta("1", "alpha", 1)?;
        let batch = ledger.prepare_batch(
            BatchId::parse("batch:1")?,
            vec![delta],
            [ContentDigest::sha256(b"child-1")],
        )?;
        ledger.append(batch)?;
    }

    // Append foreign_v1
    {
        let mut raw = OpenOptions::new().append(true).open(&path)?;
        raw.write_all(foreign_v1)?;
        raw.sync_all()?;
    }

    let report = doctor_path(&path)?;
    let plan = plan(&path, &report)?;
    let expected_quarantine_v1 =
        quarantine_path_for(&path, report.foreign_digest().ok_or("digest")?);

    // Tamper with the trailing bytes on disk before apply
    let committed_len = report.committed_len();
    {
        let raw = OpenOptions::new().write(true).open(&path)?;
        raw.set_len(committed_len)?;
        raw.sync_all()?;
    }
    {
        let mut raw = OpenOptions::new().append(true).open(&path)?;
        raw.write_all(foreign_v2)?;
        raw.sync_all()?;
    }

    // apply() must refuse because the digest in the plan does not match disk
    let result = apply(&plan);
    match result {
        Err(RepairError::PlanDigestMismatch { expected, actual }) => {
            assert_eq!(expected, ContentDigest::sha256(foreign_v1));
            assert_eq!(actual, ContentDigest::sha256(foreign_v2));
        }
        other => {
            let _ = fs::remove_file(&path);
            let _ = fs::remove_file(&expected_quarantine_v1);
            return Err(format!("expected PlanDigestMismatch, got: {other:?}").into());
        }
    }

    // Confirm that journal was not truncated and no quarantine file was published
    let current_file_len = fs::metadata(&path)?.len();
    assert_eq!(
        current_file_len,
        committed_len + foreign_v2.len() as u64,
        "file must not have been truncated"
    );
    assert!(
        !expected_quarantine_v1.exists(),
        "sidecar must not exist when apply was refused"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

/// Planted negative 2: a plan whose cut is before committed_len must be refused.
#[test]
fn test_planted_negative_cut_before_committed_len_refused() -> Result<(), Box<dyn Error>> {
    let path = temp_path("cut-before-committed");
    let _ = fs::remove_file(&path);

    {
        let mut ledger =
            DurableReferenceLedger::open(&path, "site-alpha", IncompleteTailPolicy::Reject)?;
        let delta = sample_delta("1", "alpha", 1)?;
        let batch = ledger.prepare_batch(
            BatchId::parse("batch:1")?,
            vec![delta],
            [ContentDigest::sha256(b"child-1")],
        )?;
        ledger.append(batch)?;
    }

    {
        let mut raw = OpenOptions::new().append(true).open(&path)?;
        raw.write_all(b"foreign-junk")?;
        raw.sync_all()?;
    }

    let report = doctor_path(&path)?;
    let committed_len = report.committed_len();
    assert!(committed_len > 0);

    // Attempting plan_with_cut with cut = committed_len - 1 must fail
    let cut_too_early = plan_with_cut(&path, &report, committed_len - 1);
    match cut_too_early {
        Err(RepairError::CutBeforeCommittedLen {
            cut,
            committed_len: c_len,
        }) => {
            assert_eq!(cut, committed_len - 1);
            assert_eq!(c_len, committed_len);
        }
        other => {
            let _ = fs::remove_file(&path);
            return Err(format!(
                "expected CutBeforeCommittedLen for committed_len - 1, got: {other:?}"
            )
            .into());
        }
    }

    // Attempting plan_with_cut with cut = 0 must fail
    let cut_zero = plan_with_cut(&path, &report, 0);
    match cut_zero {
        Err(RepairError::CutBeforeCommittedLen {
            cut,
            committed_len: c_len,
        }) => {
            assert_eq!(cut, 0);
            assert_eq!(c_len, committed_len);
        }
        other => {
            let _ = fs::remove_file(&path);
            return Err(format!("expected CutBeforeCommittedLen for 0, got: {other:?}").into());
        }
    }

    let _ = fs::remove_file(&path);
    Ok(())
}

/// Planted negative 3: Truncate policy alone still refuses foreign bytes across multiple shapes.
#[test]
fn test_planted_negative_truncate_policy_alone_refuses_foreign_bytes() -> Result<(), Box<dyn Error>>
{
    let mut corrupt_version_88 = vec![0u8; 88];
    corrupt_version_88[..8].copy_from_slice(b"FSSJRN01");
    corrupt_version_88[8..10].copy_from_slice(&999u16.to_be_bytes());

    let junk_samples: &[(&str, &[u8])] = &[
        ("short-ascii", b"junk"),
        ("non-magic-4", &[0xFF, 0xFF, 0xFF, 0xFF]),
        ("non-magic-long", b"NON_MAGIC_PREFIX_EXTRA_BYTES_1234"),
        ("zeroes-16", &[0x00; 16]),
        ("corrupt-magic-prefix", b"FSS_JRN1_wrong_magic"),
        ("corrupt-version-full-header", &corrupt_version_88),
    ];

    for &(label, junk) in junk_samples {
        let path = temp_path(&format!("truncate-refuses-{label}"));
        let _ = fs::remove_file(&path);

        {
            let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
            journal.append(1, b"committed record payload")?;
        }

        {
            let mut raw = OpenOptions::new().append(true).open(&path)?;
            raw.write_all(junk)?;
            raw.sync_all()?;
        }

        let journal_res = Journal::open(&path, IncompleteTailPolicy::Truncate);
        assert!(
            matches!(journal_res, Err(JournalError::Corrupt { .. })),
            "Journal::open with Truncate on `{label}` must return Corrupt, got: {journal_res:?}"
        );

        let ledger_res =
            DurableReferenceLedger::open(&path, "site-alpha", IncompleteTailPolicy::Truncate);
        assert!(
            matches!(
                ledger_res,
                Err(DurableLedgerError::Journal(JournalError::Corrupt { .. }))
            ),
            "DurableReferenceLedger::open with Truncate on `{label}` must return Corrupt, got: {ledger_res:?}"
        );

        let _ = fs::remove_file(path);
    }

    Ok(())
}

/// Plan seal tampering: a sealed plan with modified parameters or seal must be refused.
#[test]
fn test_plan_seal_tampering_refused() -> Result<(), Box<dyn Error>> {
    let path = temp_path("seal-tamper");
    let _ = fs::remove_file(&path);

    {
        let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
        journal.append(1, b"test-record")?;
    }
    {
        let mut raw = OpenOptions::new().append(true).open(&path)?;
        raw.write_all(b"foreign-bytes")?;
        raw.sync_all()?;
    }

    let report = doctor_path(&path)?;
    let plan = plan(&path, &report)?;
    assert!(plan.verify_seal().is_ok());

    // Tamper with plan seal
    let tampered_plan = plan.with_seal_for_test(ContentDigest::sha256(b"fake-seal"));
    assert!(matches!(
        tampered_plan.verify_seal(),
        Err(RepairError::InvalidSeal { .. })
    ));
    assert!(matches!(
        apply(&tampered_plan),
        Err(RepairError::InvalidSeal { .. })
    ));

    let _ = fs::remove_file(&path);
    Ok(())
}

/// Clean journal without foreign trailing bytes reports no foreign bytes,
/// and attempting to create a repair plan fails with NoForeignBytes.
#[test]
fn test_clean_journal_reports_no_foreign_bytes() -> Result<(), Box<dyn Error>> {
    let path = temp_path("clean-journal");
    let _ = fs::remove_file(&path);

    {
        let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
        journal.append(1, b"first clean record")?;
        journal.append(2, b"second clean record")?;
    }

    let report = doctor_path(&path)?;
    assert_eq!(report.records_count(), 2);
    assert!(!report.has_foreign_bytes());
    assert_eq!(report.foreign_range(), None);
    assert_eq!(report.foreign_offset(), None);
    assert_eq!(report.foreign_length(), None);
    assert_eq!(report.foreign_digest(), None);

    let plan_res = plan(&path, &report);
    assert!(
        matches!(plan_res, Err(RepairError::NoForeignBytes)),
        "clean journal must reject plan with NoForeignBytes, got: {plan_res:?}"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

/// Repair of an empty journal that contains ONLY foreign trailing junk (0 committed records).
#[test]
fn test_empty_journal_with_foreign_junk_repaired_to_clean_empty() -> Result<(), Box<dyn Error>> {
    let path = temp_path("empty-with-junk");
    let _ = fs::remove_file(&path);

    let junk = b"NON_MAGIC_CORRUPT_BYTES_FROM_START";
    fs::write(&path, junk)?;

    let report = doctor_path(&path)?;
    assert_eq!(report.committed_len(), 0);
    assert_eq!(report.records_count(), 0);
    assert!(report.has_foreign_bytes());

    let fr = report.foreign_range().ok_or("foreign range expected")?;
    assert_eq!(fr.offset, 0);
    assert_eq!(fr.length, junk.len() as u64);
    assert_eq!(fr.digest, ContentDigest::sha256(junk));

    let plan = plan(&path, &report)?;
    let receipt = apply(&plan)?;

    assert_eq!(receipt.committed_len(), 0);
    assert_eq!(receipt.quarantined_offset(), 0);
    assert_eq!(receipt.quarantined_length(), junk.len() as u64);
    assert_eq!(receipt.truncated_to(), 0);
    assert_eq!(fs::metadata(&path)?.len(), 0);

    let sidecar_path = receipt.quarantine_path();
    assert!(sidecar_path.exists());
    assert_eq!(fs::read(sidecar_path)?, junk);

    // The truncated file can now be opened as a clean, empty journal
    let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
    journal.append(1, b"first record on repaired empty journal")?;
    assert!(journal.committed_len() > 0);

    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(sidecar_path);
    Ok(())
}

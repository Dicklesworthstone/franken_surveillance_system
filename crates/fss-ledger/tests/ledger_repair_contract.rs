//! Contract tests for audited doctor, sealed repair plan, and quarantine apply workflow.
//!
//! Ref: fss-x4a.9.21 / LEDGER-REPAIR-001

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, ObjectId, Plane, TimestampNs,
};
use fss_ledger::{
    CorruptionKind, DurableLedgerError, DurableReferenceLedger, IncompleteTailPolicy, Journal,
    JournalError, MAX_QUARANTINE_TEMP_ATTEMPTS, RepairError, apply, doctor, doctor_path, plan,
    plan_with_cut, quarantine_path_for, quarantine_temp_path_for,
};

/// Returns the journal path owned by exactly one test, named after that test's label.
///
/// The path lives under `CARGO_TARGET_TMPDIR` and is a pure function of the label, so no shared
/// counter or ambient state participates in naming. Every label must be unique in this file.
fn temp_path(label: &str) -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("ledger_repair_contract-{label}.journal"))
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
    let canonical_path = fs::canonicalize(&path)?;
    let plan = plan(&path, &report)?;
    assert_eq!(plan.journal_path(), &canonical_path);
    assert_eq!(plan.committed_len(), committed_len);
    assert_eq!(plan.last_root(), last_root);
    assert_eq!(plan.foreign_offset(), committed_len);
    assert_eq!(plan.foreign_length(), foreign_bytes.len() as u64);
    assert_eq!(plan.foreign_digest(), expected_foreign_digest);
    assert_eq!(plan.cut_offset(), committed_len);
    plan.verify_plan_digest()?;

    // 6. Apply repair: quarantine foreign bytes and truncate
    let receipt = apply(&plan)?;
    assert_eq!(receipt.journal_path(), &canonical_path);
    assert_eq!(receipt.committed_len(), committed_len);
    assert_eq!(receipt.last_root(), last_root);
    assert_eq!(receipt.quarantined_offset(), committed_len);
    assert_eq!(receipt.quarantined_length(), foreign_bytes.len() as u64);
    assert_eq!(receipt.quarantined_digest(), expected_foreign_digest);
    assert_eq!(receipt.truncated_to(), committed_len);
    assert_eq!(receipt.plan_digest(), plan.plan_digest());

    // Verify sidecar file exists, is named by digest, and contains foreign bytes
    let expected_sidecar_path = quarantine_path_for(plan.journal_path(), expected_foreign_digest);
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
    let expected_quarantine_v1 = quarantine_path_for(
        plan.journal_path(),
        report.foreign_digest().ok_or("digest")?,
    );

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

/// Plan digest: a repair plan computed by the planner has a valid, non-empty plan digest.
#[test]
fn test_plan_digest_verified_by_planner() -> Result<(), Box<dyn Error>> {
    let path = temp_path("digest-verify");
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
    assert!(plan.verify_plan_digest().is_ok());
    assert_ne!(plan.plan_digest(), ContentDigest::sha256(b""));

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

fn setup_journal_with_foreign_tail(
    path: &std::path::Path,
    foreign: &[u8],
) -> Result<(u64, ContentDigest), Box<dyn Error>> {
    let mut ledger =
        DurableReferenceLedger::open(path, "site-alpha", IncompleteTailPolicy::Reject)?;
    let delta = sample_delta("1", "alpha", 1)?;
    let batch = ledger.prepare_batch(
        BatchId::parse("batch:1")?,
        vec![delta],
        [ContentDigest::sha256(b"child-1")],
    )?;
    ledger.append(batch)?;
    let root = ledger.journal_root();
    drop(ledger);
    let committed_len = fs::metadata(path)?.len();

    let mut raw = OpenOptions::new().append(true).open(path)?;
    raw.write_all(foreign)?;
    raw.sync_all()?;

    Ok((committed_len, root))
}

/// Creates a fresh, test-owned scratch directory without shared process-global counters.
fn fresh_dir(label: &str) -> Result<PathBuf, Box<dyn Error>> {
    let base = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .or_else(|| std::option_env!("CARGO_TARGET_TMPDIR").map(PathBuf::from))
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!("fss-ledger-vddm8-{}-{label}", std::process::id()));
    match fs::remove_dir_all(&dir) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Returns the `{hex}` stem shared by the quarantine sidecar and its staging temp files.
fn quarantine_stem(qpath: &std::path::Path) -> Result<String, Box<dyn Error>> {
    let name = qpath
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("quarantine path has no UTF-8 file name")?;
    Ok(name
        .strip_suffix(".quarantine")
        .ok_or("quarantine path lacks .quarantine suffix")?
        .to_owned())
}

/// fss-vddm8: two independent repairers must not depend on shared process state.
///
/// Repairer A runs first. Repairer B then works in a directory where a crashed earlier process
/// with our PID left stale staging files for every attempt number that any process-global counter
/// could plausibly have reached. B's staging must start from its own first attempt, succeed, and
/// leave files it did not create untouched.
#[test]
fn test_independent_repairers_do_not_share_process_attempt_state() -> Result<(), Box<dyn Error>> {
    let dir_a = fresh_dir("independent-a")?;
    let dir_b = fresh_dir("independent-b")?;
    let foreign = b"FOREIGN_TAIL_VDDM8_INDEPENDENT";

    // Repairer A.
    let path_a = dir_a.join("a.journal");
    setup_journal_with_foreign_tail(&path_a, foreign)?;
    let report_a = doctor_path(&path_a)?;
    let receipt_a = apply(&plan(&path_a, &report_a)?)?;
    assert_eq!(fs::read(receipt_a.quarantine_path())?, foreign);

    // Repairer B, independent journal and directory, identical foreign bytes (same digest).
    let path_b = dir_b.join("b.journal");
    setup_journal_with_foreign_tail(&path_b, foreign)?;
    let report_b = doctor_path(&path_b)?;
    let plan_b = plan(&path_b, &report_b)?;
    let qpath_b = quarantine_path_for(
        plan_b.journal_path(),
        report_b.foreign_digest().ok_or("foreign digest")?,
    );
    let stem = quarantine_stem(&qpath_b)?;
    let pid = std::process::id();
    let stale: Vec<PathBuf> = (1..=256_u32)
        .map(|k| dir_b.join(format!("{stem}.tmp.{pid}.{k}")))
        .collect();
    for path in &stale {
        fs::write(path, b"stale-leftover-not-owned-by-this-repair")?;
    }

    let receipt_b = apply(&plan_b)?;
    assert_eq!(receipt_b.quarantine_path(), &qpath_b);
    assert_eq!(fs::read(&qpath_b)?, foreign);
    assert_eq!(fs::metadata(&path_b)?.len(), report_b.committed_len());
    for path in &stale {
        assert_eq!(
            fs::read(path)?,
            b"stale-leftover-not-owned-by-this-repair",
            "repair must never remove or overwrite a staging file it did not create: {}",
            path.display()
        );
    }
    let leftover_temps = fs::read_dir(&dir_b)?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp."))
        .count();
    assert_eq!(
        leftover_temps,
        stale.len(),
        "a successful repair must not leave its own staging file behind"
    );

    fs::remove_dir_all(&dir_a)?;
    fs::remove_dir_all(&dir_b)?;
    Ok(())
}

/// fss-vddm8: staging retries are bounded and exhaustion is a typed, non-destructive error.
#[test]
fn test_quarantine_staging_retry_is_bounded_and_typed() -> Result<(), Box<dyn Error>> {
    let dir = fresh_dir("exhausted")?;
    let foreign = b"FOREIGN_TAIL_VDDM8_EXHAUSTED";
    let path = dir.join("x.journal");
    let (committed_len, _) = setup_journal_with_foreign_tail(&path, foreign)?;
    let report = doctor_path(&path)?;
    let sealed = plan(&path, &report)?;
    let digest = report.foreign_digest().ok_or("foreign digest")?;
    let qpath = quarantine_path_for(sealed.journal_path(), digest);
    let stem = quarantine_stem(&qpath)?;
    let parent = sealed.journal_path().parent().ok_or("journal parent")?;
    assert_eq!(
        quarantine_temp_path_for(sealed.journal_path(), digest, 7),
        parent.join(format!("{stem}.tmp.{}.7", std::process::id())),
        "staging names are a pure function of journal, digest, pid, and per-call attempt"
    );

    let occupied: Vec<PathBuf> = (0..MAX_QUARANTINE_TEMP_ATTEMPTS)
        .map(|attempt| quarantine_temp_path_for(sealed.journal_path(), digest, attempt))
        .collect();
    for held in &occupied {
        fs::write(held, b"held-by-someone-else")?;
    }

    match apply(&sealed) {
        Err(RepairError::QuarantineTempExhausted {
            directory,
            attempts,
        }) => {
            assert_eq!(attempts, MAX_QUARANTINE_TEMP_ATTEMPTS);
            assert_eq!(directory.as_path(), parent);
        }
        other => return Err(format!("expected QuarantineTempExhausted, got {other:?}").into()),
    }
    assert_eq!(
        fs::metadata(&path)?.len(),
        committed_len + foreign.len() as u64,
        "exhaustion must leave the journal untouched"
    );
    assert!(!qpath.exists(), "no sidecar may be published on exhaustion");
    for held in &occupied {
        assert_eq!(fs::read(held)?, b"held-by-someone-else");
    }

    // Releasing one name lets the very same sealed plan complete.
    let last = occupied.last().ok_or("no staging names")?;
    fs::remove_file(last)?;
    let receipt = apply(&sealed)?;
    assert_eq!(fs::read(receipt.quarantine_path())?, foreign);
    assert_eq!(fs::metadata(&path)?.len(), committed_len);

    fs::remove_dir_all(&dir)?;
    Ok(())
}

/// fss-vddm8: concurrent repairs within one process stay correct without shared counters.
///
/// Several independent journals in one directory carry identical foreign tails, so every repairer
/// stages and publishes the same digest-named sidecar at the same time.
#[test]
fn test_concurrent_in_process_repairs_share_directory_and_digest() -> Result<(), Box<dyn Error>> {
    const REPAIRERS: usize = 4;
    let dir = fresh_dir("concurrent")?;
    let foreign = b"FOREIGN_TAIL_VDDM8_CONCURRENT";
    let mut prepared = Vec::with_capacity(REPAIRERS);
    for index in 0..REPAIRERS {
        let path = dir.join(format!("j{index}.journal"));
        let (committed_len, _) = setup_journal_with_foreign_tail(&path, foreign)?;
        let report = doctor_path(&path)?;
        let sealed = plan(&path, &report)?;
        prepared.push((path, committed_len, sealed));
    }

    let barrier = std::sync::Barrier::new(REPAIRERS);
    let outcomes = std::thread::scope(|scope| {
        let handles: Vec<_> = prepared
            .iter()
            .map(|(_, _, sealed)| {
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    apply(sealed)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(std::thread::ScopedJoinHandle::join)
            .collect::<Vec<_>>()
    });

    let mut sidecar: Option<PathBuf> = None;
    for (outcome, (path, committed_len, _)) in outcomes.into_iter().zip(&prepared) {
        let receipt = outcome.map_err(|_| "repair thread panicked")??;
        assert_eq!(fs::metadata(path)?.len(), *committed_len);
        assert_eq!(fs::read(receipt.quarantine_path())?, foreign);
        match &sidecar {
            None => sidecar = Some(receipt.quarantine_path().to_path_buf()),
            Some(existing) => assert_eq!(existing.as_path(), receipt.quarantine_path()),
        }
    }
    let leftover_temps = fs::read_dir(&dir)?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp."))
        .count();
    assert_eq!(
        leftover_temps, 0,
        "no staging file may survive a successful repair"
    );

    fs::remove_dir_all(&dir)?;
    Ok(())
}

/// Adversarial Finding 2: Cut offset past EOF is rejected rather than extending file.
#[test]
fn test_plan_cut_offset_past_eof_is_rejected() -> Result<(), Box<dyn Error>> {
    let path = temp_path("cut-past-eof");
    let _ = fs::remove_file(&path);
    let foreign = b"FOREIGN_TAIL_BYTES";
    setup_journal_with_foreign_tail(&path, foreign)?;

    let report = doctor_path(&path)?;
    let eof_plus_1000 = (report.committed_len() + foreign.len() as u64) + 1000;

    let plan_res = plan_with_cut(&path, &report, eof_plus_1000);
    assert!(
        matches!(plan_res, Err(RepairError::CutPastCommittedLen { .. })),
        "plan_with_cut past EOF must be rejected with CutPastCommittedLen, got: {plan_res:?}"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

/// Adversarial Finding 7: Partial cut leaving foreign corruption in journal is rejected.
#[test]
fn test_partial_cut_leaving_foreign_bytes_is_rejected() -> Result<(), Box<dyn Error>> {
    let path = temp_path("partial-cut");
    let _ = fs::remove_file(&path);
    let foreign = b"FOREIGN_TAIL_20_BYTES";
    setup_journal_with_foreign_tail(&path, foreign)?;

    let report = doctor_path(&path)?;
    let partial_cut = report.committed_len() + 10;

    let plan_res = plan_with_cut(&path, &report, partial_cut);
    assert!(
        matches!(plan_res, Err(RepairError::CutPastCommittedLen { .. })),
        "plan_with_cut with partial cut must be rejected, got: {plan_res:?}"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

/// Adversarial Finding 4: Existing quarantine file with conflicting content is not clobbered.
#[test]
fn test_existing_quarantine_file_with_conflicting_content_is_not_clobbered()
-> Result<(), Box<dyn Error>> {
    let path = temp_path("clobber-test");
    let _ = fs::remove_file(&path);
    let foreign = b"FOREIGN_TAIL_TO_QUARANTINE";
    setup_journal_with_foreign_tail(&path, foreign)?;

    let report = doctor_path(&path)?;
    let plan = plan(&path, &report)?;
    let expected_qpath = quarantine_path_for(
        plan.journal_path(),
        report.foreign_digest().ok_or("foreign digest")?,
    );

    let precious = b"PREEXISTING_PRECIOUS_DATA_DO_NOT_OVERWRITE";
    fs::write(&expected_qpath, precious)?;

    let receipt = apply(&plan);
    assert!(
        matches!(receipt, Err(RepairError::QuarantineFileConflict { .. })),
        "apply() must refuse to clobber conflicting quarantine file, got: {receipt:?}"
    );

    let contents = fs::read(&expected_qpath)?;
    assert_eq!(
        contents, precious,
        "pre-existing quarantine file content must be preserved"
    );

    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&expected_qpath);
    Ok(())
}

/// Adversarial Finding 4 (reuse): Existing quarantine file with identical content is reused.
#[test]
fn test_existing_quarantine_file_with_identical_content_is_reused() -> Result<(), Box<dyn Error>> {
    let path = temp_path("reuse-test");
    let _ = fs::remove_file(&path);
    let foreign = b"FOREIGN_TAIL_FOR_REUSE_TEST";
    setup_journal_with_foreign_tail(&path, foreign)?;

    let report = doctor_path(&path)?;
    let plan = plan(&path, &report)?;
    let expected_qpath = quarantine_path_for(
        plan.journal_path(),
        report.foreign_digest().ok_or("foreign digest")?,
    );

    // Pre-create identical file
    fs::write(&expected_qpath, foreign)?;

    let receipt = apply(&plan)?;
    assert_eq!(receipt.quarantine_path(), &expected_qpath);
    assert_eq!(fs::read(&expected_qpath)?, foreign);

    // Journal was safely truncated
    assert_eq!(fs::metadata(&path)?.len(), report.committed_len());

    let mut ledger =
        DurableReferenceLedger::open(&path, "site-alpha", IncompleteTailPolicy::Reject)?;
    ledger.verify_storage()?;

    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&expected_qpath);
    Ok(())
}

/// Adversarial Finding 5: Concurrent append or modification during apply is detected and refused.
#[test]
fn test_concurrent_modification_during_apply_is_detected_and_refused() -> Result<(), Box<dyn Error>>
{
    let path = temp_path("toctou-append");
    let _ = fs::remove_file(&path);
    let foreign = b"FOREIGN_BYTES_TOCTOU";
    setup_journal_with_foreign_tail(&path, foreign)?;

    let report = doctor_path(&path)?;
    let plan = plan(&path, &report)?;

    // Concurrently append data to the journal after planning
    {
        let mut raw = OpenOptions::new().append(true).open(&path)?;
        raw.write_all(b"_CONCURRENT_EXTRA_DATA")?;
        raw.sync_all()?;
    }

    let apply_res = apply(&plan);
    assert!(
        matches!(
            apply_res,
            Err(RepairError::FileLengthMismatch { .. } | RepairError::ConcurrentModification { .. })
        ),
        "concurrent append must be detected and refused, got: {apply_res:?}"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

/// Adversarial Finding 6: Path is canonicalized and device + inode are bound into the plan.
#[test]
fn test_plan_canonicalizes_path_and_binds_device_and_inode() -> Result<(), Box<dyn Error>> {
    let path = temp_path("canonical-dev-ino");
    let _ = fs::remove_file(&path);
    let foreign = b"FOREIGN_TAIL_CANONICAL";
    setup_journal_with_foreign_tail(&path, foreign)?;

    let report = doctor_path(&path)?;
    let plan = plan(&path, &report)?;

    assert!(plan.journal_path().is_absolute());
    let canonical = fs::canonicalize(&path)?;
    assert_eq!(plan.journal_path(), &canonical);

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(&canonical)?;
        assert_eq!(plan.journal_dev(), meta.dev());
        assert_eq!(plan.journal_ino(), meta.ino());
    }

    let _ = fs::remove_file(&path);
    let expected_qpath = quarantine_path_for(
        plan.journal_path(),
        report.foreign_digest().ok_or("foreign digest")?,
    );
    let _ = fs::remove_file(&expected_qpath);
    Ok(())
}

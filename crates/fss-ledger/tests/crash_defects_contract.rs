//! Contract tests for journal mutation detection, tail classification,
//! reconcile policy, and semantic verification defects (F1 - F5).
//!
//! Ref: fss-x4a.9.19 / LEDGER-CRASH-001

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fss_ledger::{
    AppendPhase, AppendReconciliation, CorruptionKind, DurableReferenceLedger,
    ERR_LEDGER_LENGTH_OVERFLOW_001, ExternalMutationKind, IncompleteTailPolicy, Journal,
    JournalError, recover_bytes,
};

/// Returns the journal path owned by exactly one test, named after that test's label.
///
/// The path lives under `CARGO_TARGET_TMPDIR` and is a pure function of the label, so no shared
/// counter or ambient state participates in naming. Every label must be unique in this file.
fn temp_journal(label: &str) -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("crash_defects_contract-{label}.journal"))
}

/// F1: Same-length in-place overwrite must be detected as ExternalMutation with ContentDivergence.
#[test]
fn test_same_length_overwrite_detected_as_external_mutation() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("same-length-mutation");
    let _ = fs::remove_file(&path);
    let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
    journal.append(1, b"first record")?;
    let len = fs::metadata(&path)?.len();

    // Overwrite the committed record in-place with different bytes of the exact same length
    {
        let mut raw = OpenOptions::new().write(true).open(&path)?;
        raw.seek(SeekFrom::Start(0))?;
        raw.write_all(&vec![0xAA; len as usize])?;
        raw.sync_all()?;
    }

    // append() must verify the committed trailer before appending and detect ContentDivergence
    let result = journal.append(2, b"second record");
    match result {
        Err(JournalError::ExternalMutation {
            kind: ExternalMutationKind::ContentDivergence,
            ..
        }) => {}
        other => {
            let _ = fs::remove_file(&path);
            return Err(
                format!("expected ExternalMutation with ContentDivergence, got {other:?}").into(),
            );
        }
    }

    let _ = fs::remove_file(path);
    Ok(())
}

fn scratch_record_bytes() -> Result<Vec<u8>, Box<dyn Error>> {
    let scratch_path = temp_journal("scratch-record");
    let _ = fs::remove_file(&scratch_path);
    let mut journal = Journal::open(&scratch_path, IncompleteTailPolicy::Reject)?;
    journal.append(
        1,
        b"scratch record payload that easily exceeds header length",
    )?;
    let bytes = fs::read(&scratch_path)?;
    let _ = fs::remove_file(&scratch_path);
    Ok(bytes)
}

/// F2: reconcile_pending must honor IncompleteTailPolicy under both Reject and Truncate
/// for realistic torn writes (k in {1, 4, 8, HEADER_LEN - 1}).
#[test]
fn test_reconcile_pending_with_trailing_tail_honors_tail_policy() -> Result<(), Box<dyn Error>> {
    const HEADER_LEN: usize = 8 + 2 + 8 + 2 + 4 + 32 + 32;
    let real_bytes = scratch_record_bytes()?;

    for &k in &[1, 4, 8, HEADER_LEN - 1] {
        let path = temp_journal(&format!("reconcile-tail-policy-{k}"));
        let _ = fs::remove_file(&path);
        let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
        journal.fail_after_phase(AppendPhase::CommitSync);

        // Append succeeds through CommitWrite, but CommitSync fails -> AppendIndeterminate
        let err = journal.append(1, b"committed body");
        match err {
            Err(JournalError::AppendIndeterminate { .. }) => {}
            other => {
                let _ = fs::remove_file(&path);
                return Err(format!("expected AppendIndeterminate, got {other:?}").into());
            }
        }

        // Extra torn bytes appended after the committed record using real record prefix bytes
        {
            let mut raw = OpenOptions::new().append(true).open(&path)?;
            raw.write_all(&real_bytes[..k])?;
            raw.sync_all()?;
        }

        // Under IncompleteTailPolicy::Reject, reconcile_pending should reject with IncompleteTail
        let reject_result = journal.reconcile_pending(IncompleteTailPolicy::Reject);
        match reject_result {
            Err(JournalError::IncompleteTail { .. }) => {}
            other => {
                let _ = fs::remove_file(&path);
                return Err(format!(
                    "expected IncompleteTail error under Reject policy for k={k}, got: {other:?}"
                )
                .into());
            }
        }

        // Under IncompleteTailPolicy::Truncate, reconcile_pending must truncate the trailing tail and commit the pending record
        let truncate_result = journal.reconcile_pending(IncompleteTailPolicy::Truncate)?;
        match truncate_result {
            AppendReconciliation::Committed(record) => {
                if record.sequence() != 1 || record.payload() != b"committed body" {
                    let _ = fs::remove_file(&path);
                    return Err("reconciled record mismatch".into());
                }
            }
            other => {
                let _ = fs::remove_file(&path);
                return Err(format!("expected Committed for k={k}, got {other:?}").into());
            }
        }

        let _ = fs::remove_file(path);
    }
    Ok(())
}

/// Arbitrary non-magic junk after the last commit trailer is Corrupt(RecordMagic) under BOTH
/// Reject and Truncate (Truncate must never discard bytes this writer could not have produced).
#[test]
fn test_arbitrary_non_magic_junk_after_commit_trailer_is_corrupt_under_both_policies()
-> Result<(), Box<dyn Error>> {
    let junk_samples: &[(&str, &[u8])] = &[
        ("short-4-bytes", b"junk"),
        ("non-magic-prefix", b"FSS_JRN1_wrong_magic"),
        ("arbitrary-ascii", b"arbitrary non-magic trailing junk"),
        ("raw-bytes-4", &[0xFF, 0xFF, 0xFF, 0xFF]),
        ("zeroes-16", &[0x00; 16]),
    ];

    for &(label, junk) in junk_samples {
        let path = temp_journal(&format!("junk-{label}"));
        let _ = fs::remove_file(&path);
        {
            let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
            journal.append(1, b"valid committed record")?;
        }
        {
            let mut raw = OpenOptions::new().append(true).open(&path)?;
            raw.write_all(junk)?;
            raw.sync_all()?;
        }

        // Under IncompleteTailPolicy::Reject, must be Corrupt(RecordMagic)
        let reject_res = Journal::open(&path, IncompleteTailPolicy::Reject);
        match reject_res {
            Err(JournalError::Corrupt {
                kind: CorruptionKind::RecordMagic,
                ..
            }) => {}
            other => {
                let _ = fs::remove_file(&path);
                return Err(format!(
                    "junk `{label}` under Reject must be Corrupt(RecordMagic), got: {other:?}"
                )
                .into());
            }
        }

        // Under IncompleteTailPolicy::Truncate, must ALSO be Corrupt(RecordMagic)
        // (Truncate must never discard bytes this writer could not have produced)
        let truncate_res = Journal::open(&path, IncompleteTailPolicy::Truncate);
        match truncate_res {
            Err(JournalError::Corrupt {
                kind: CorruptionKind::RecordMagic,
                ..
            }) => {}
            other => {
                let _ = fs::remove_file(&path);
                return Err(format!(
                    "junk `{label}` under Truncate must be Corrupt(RecordMagic), got: {other:?}"
                )
                .into());
            }
        }

        // Also test reconcile_pending with indeterminate append followed by non-magic junk
        let rpath = temp_journal(&format!("reconcile-junk-{label}"));
        let _ = fs::remove_file(&rpath);
        let mut rjournal = Journal::open(&rpath, IncompleteTailPolicy::Reject)?;
        rjournal.fail_after_phase(AppendPhase::CommitSync);
        let _ = rjournal.append(1, b"pending record");
        {
            let mut raw = OpenOptions::new().append(true).open(&rpath)?;
            raw.write_all(junk)?;
            raw.sync_all()?;
        }

        let r_reject = rjournal.reconcile_pending(IncompleteTailPolicy::Reject);
        assert!(
            matches!(
                r_reject,
                Err(JournalError::Corrupt {
                    kind: CorruptionKind::RecordMagic,
                    ..
                })
            ),
            "reconcile_pending under Reject on junk `{label}` must be Corrupt(RecordMagic), got: {r_reject:?}"
        );

        let r_truncate = rjournal.reconcile_pending(IncompleteTailPolicy::Truncate);
        assert!(
            matches!(
                r_truncate,
                Err(JournalError::Corrupt {
                    kind: CorruptionKind::RecordMagic,
                    ..
                })
            ),
            "reconcile_pending under Truncate on junk `{label}` must be Corrupt(RecordMagic), got: {r_truncate:?}"
        );

        let _ = fs::remove_file(path);
        let _ = fs::remove_file(rpath);
    }
    Ok(())
}

/// F3: verify_storage must perform full semantic batch verification equal to open().
#[test]
fn test_verify_storage_detects_corrupt_batch_semantics() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("verify-storage-corrupt");
    let _ = fs::remove_file(&path);
    {
        let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
        // Append valid journal framing with kind 1 (EVIDENCE_BATCH_RECORD_KIND), but payload is not a valid CBOR batch
        journal.append(1, b"NOT_A_VALID_CANONICAL_BATCH")?;
    }

    // Opening a handle on valid framing with invalid batch payload fails:
    let open_res = DurableReferenceLedger::open(&path, "test-site", IncompleteTailPolicy::Reject);
    if open_res.is_ok() {
        let _ = fs::remove_file(&path);
        return Err("open should fail on corrupt batch semantics".into());
    }

    // When an existing open durable handle exists and backing storage contains invalid batch semantics,
    // verify_storage must reject it rather than returning false-green
    let valid_path = temp_journal("verify-storage-valid");
    let _ = fs::remove_file(&valid_path);
    let mut ledger =
        DurableReferenceLedger::open(&valid_path, "test-site", IncompleteTailPolicy::Reject)?;

    // Replace backing file with the corrupt-batch file
    fs::copy(&path, &valid_path)?;
    let verify_res = ledger.verify_storage();
    if verify_res.is_ok() {
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&valid_path);
        return Err(
            "verify_storage must perform full semantic batch verification equal to open()".into(),
        );
    }

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(valid_path);
    Ok(())
}

/// F4: Suffix >= 8 bytes or < 8 bytes with invalid magic must be classified as Corrupt(RecordMagic), not IncompleteTail.
#[test]
fn test_incomplete_tail_requires_record_magic_when_bytes_present() -> Result<(), Box<dyn Error>> {
    let garbage = vec![0xEE; 16]; // 16 bytes, >= 8 bytes, invalid magic (< 88 bytes HEADER_LEN)
    let report = recover_bytes(&garbage);
    match report {
        Err(JournalError::Corrupt {
            kind: CorruptionKind::RecordMagic,
            ..
        }) => {}
        other => {
            return Err(format!(
                "16 bytes of garbage with invalid magic should be Corrupt(RecordMagic), got: {other:?}"
            )
            .into());
        }
    }

    // Short tail (< 8 bytes) with non-matching magic prefix must also be rejected as Corrupt(RecordMagic)
    let short_garbage = vec![0xFF; 4];
    let short_report = recover_bytes(&short_garbage);
    match short_report {
        Err(JournalError::Corrupt {
            kind: CorruptionKind::RecordMagic,
            ..
        }) => {}
        other => {
            return Err(format!(
                "4 bytes of garbage with invalid magic prefix should be Corrupt(RecordMagic), got: {other:?}"
            )
            .into());
        }
    }

    Ok(())
}

/// F5: Byte length overflow must return JournalError::LengthOverflow with stable error ID ERR_LEDGER_LENGTH_OVERFLOW_001.
#[test]
fn test_u64_length_overflow_reported_as_length_overflow() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("overflow");
    let _ = fs::remove_file(&path);
    let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
    journal.set_committed_len_for_test(u64::MAX - 10);

    let res = journal.check_append_capacity_for_test(100);
    match res {
        Err(JournalError::LengthOverflow) => {}
        other => {
            let _ = fs::remove_file(&path);
            return Err(format!("expected LengthOverflow, got {other:?}").into());
        }
    }

    if JournalError::LengthOverflow.stable_id() != Some(ERR_LEDGER_LENGTH_OVERFLOW_001) {
        let _ = fs::remove_file(&path);
        return Err("LengthOverflow must map to ERR_LEDGER_LENGTH_OVERFLOW_001".into());
    }

    if ERR_LEDGER_LENGTH_OVERFLOW_001 != "ERR-LEDGER-LENGTH-OVERFLOW-001" {
        let _ = fs::remove_file(&path);
        return Err("ERR_LEDGER_LENGTH_OVERFLOW_001 constant mismatch".into());
    }

    let _ = fs::remove_file(path);
    Ok(())
}

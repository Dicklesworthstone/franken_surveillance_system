#![forbid(unsafe_code)]
//! Contract tests for the content-addressed on-disk staging spool (FSS-017, fss-x4a.7.5).
//!
//! Every test owns one real directory under `CARGO_TARGET_TMPDIR`, named after the test, so no
//! shared counter or ambient state participates in naming.

use std::error::Error;
use std::fmt::Debug;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

use fss_core::{ContentDigest, DigestAlgorithm};
use fss_object::{
    CorruptObject, CorruptionKind, ForeignEntry, ForeignReason, InMemoryObjectStore,
    MAX_OBJECT_BYTES, MAX_STAGING_NAME_ATTEMPTS, ObjectError, ObjectLimits, OrphanedStaging,
    SPOOL_LOCK_FILE, SPOOL_OBJECT_HEADER_LEN, SPOOL_OBJECT_MAGIC, SPOOL_OBJECTS_DIR,
    SPOOL_STAGING_DIR, SpoolError, SpoolLimitViolation, SpoolLimits, SpoolObjectState,
    StageOutcome, StagePhase, StageReceipt, StagingSpool, VerifiedObjectCatalog,
};

type TestResult = Result<(), Box<dyn Error>>;

const HEADER: u64 = SPOOL_OBJECT_HEADER_LEN as u64;

/// Returns a not-yet-existing directory owned by exactly one test, named after that test.
fn fresh_root(test_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("staging_spool_contract")
        .join(test_name);
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(root)
}

fn limits(max_objects: usize, max_total_bytes: u64) -> SpoolLimits {
    SpoolLimits::new(max_objects, max_total_bytes, 4096, max_objects.max(64))
}

fn roomy() -> SpoolLimits {
    limits(64, 1 << 20)
}

fn expect_err<T: Debug>(result: Result<T, SpoolError>) -> Result<SpoolError, Box<dyn Error>> {
    match result {
        Ok(value) => Err(format!("expected a spool error, got {value:?}").into()),
        Err(error) => Ok(error),
    }
}

fn hex(digest: ContentDigest) -> String {
    digest.to_text().trim_start_matches("sha256:").to_owned()
}

fn object_file(root: &Path, digest: ContentDigest) -> PathBuf {
    root.join(SPOOL_OBJECTS_DIR).join(hex(digest))
}

fn staging_file(root: &Path, digest: ContentDigest, attempt: u32) -> PathBuf {
    root.join(SPOOL_STAGING_DIR)
        .join(format!("{}.{attempt}.tmp", hex(digest)))
}

fn dir_names(dir: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        names.push(entry?.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
}

fn truncate_to(path: &Path, len: u64) -> TestResult {
    OpenOptions::new().write(true).open(path)?.set_len(len)?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Ingest verification
// ---------------------------------------------------------------------------------------------

#[test]
fn stage_round_trips_and_is_staged_not_verified() -> TestResult {
    let root = fresh_root("stage_round_trips_and_is_staged_not_verified")?;
    let mut spool = StagingSpool::open(&root, roomy())?;
    assert!(spool.recovery_report().is_clean());

    let payload = b"sensor-capsule-payload-0001";
    let digest = ContentDigest::sha256(payload);
    let receipt = spool.stage(digest, payload)?;
    assert_eq!(
        receipt,
        StageReceipt {
            digest,
            payload_len: payload.len() as u64,
            outcome: StageOutcome::NewlyStaged,
            state: SpoolObjectState::Staged,
        }
    );
    assert_eq!(spool.read(digest)?, payload.to_vec());
    // Reading re-verifies but never promotes; staged is not verified.
    assert_eq!(spool.state(digest), Some(SpoolObjectState::Staged));
    assert_eq!(
        spool.require_verified(digest),
        Err(ObjectError::NotVerified(digest))
    );

    assert_eq!(spool.verify(digest)?, SpoolObjectState::Verified);
    spool.require_verified(digest)?;

    assert!(dir_names(&root.join(SPOOL_STAGING_DIR))?.is_empty());
    assert_eq!(dir_names(&root.join(SPOOL_OBJECTS_DIR))?, vec![hex(digest)]);
    assert_eq!(spool.object_count(), 1);
    assert_eq!(spool.occupied_bytes()?, payload.len() as u64);
    let raw = fs::read(object_file(&root, digest))?;
    assert_eq!(raw.len() as u64, HEADER + payload.len() as u64);
    assert_eq!(raw.get(..8), Some(&SPOOL_OBJECT_MAGIC[..]));
    Ok(())
}

#[test]
fn declared_digest_mismatch_is_rejected_before_any_write() -> TestResult {
    let root = fresh_root("declared_digest_mismatch_is_rejected_before_any_write")?;
    let mut spool = StagingSpool::open(&root, roomy())?;
    let payload = b"payload-actually-sent";
    let declared = ContentDigest::sha256(b"payload-the-caller-claimed");

    let error = expect_err(spool.stage(declared, payload))?;
    assert_eq!(
        error,
        SpoolError::DigestMismatch {
            declared,
            computed: ContentDigest::sha256(payload),
        }
    );
    assert_eq!(spool.object_count(), 0);
    assert_eq!(spool.state(declared), None);
    assert!(dir_names(&root.join(SPOOL_STAGING_DIR))?.is_empty());
    assert!(dir_names(&root.join(SPOOL_OBJECTS_DIR))?.is_empty());
    Ok(())
}

#[test]
fn non_sha256_declared_digest_is_rejected() -> TestResult {
    let root = fresh_root("non_sha256_declared_digest_is_rejected")?;
    let mut spool = StagingSpool::open(&root, roomy())?;
    let payload = b"payload";
    let declared = ContentDigest::new(
        DigestAlgorithm::Blake3,
        ContentDigest::sha256(payload).bytes(),
    );
    assert_eq!(
        expect_err(spool.stage(declared, payload))?,
        SpoolError::UnsupportedAlgorithm(DigestAlgorithm::Blake3)
    );
    assert!(dir_names(&root.join(SPOOL_OBJECTS_DIR))?.is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Missing objects and unindexed entries
// ---------------------------------------------------------------------------------------------

#[test]
fn read_of_missing_object_is_typed_missing() -> TestResult {
    let root = fresh_root("read_of_missing_object_is_typed_missing")?;
    let mut spool = StagingSpool::open(&root, roomy())?;
    let payload = b"never-staged";
    let digest = ContentDigest::sha256(payload);

    assert_eq!(expect_err(spool.read(digest))?, SpoolError::Missing(digest));
    assert_eq!(
        expect_err(spool.verify(digest))?,
        SpoolError::Missing(digest)
    );
    assert_eq!(
        spool.require_verified(digest),
        Err(ObjectError::Missing(digest))
    );
    assert_eq!(spool.state(digest), None);

    // A file planted after open is not indexed: still missing, and never overwritten by staging.
    let planted = object_file(&root, digest);
    fs::write(&planted, b"planted")?;
    assert_eq!(expect_err(spool.read(digest))?, SpoolError::Missing(digest));
    assert_eq!(
        expect_err(spool.stage(digest, payload))?,
        SpoolError::UnindexedEntry {
            path: planted.clone()
        }
    );
    assert_eq!(fs::read(&planted)?, b"planted".to_vec());
    assert!(dir_names(&root.join(SPOOL_STAGING_DIR))?.is_empty());
    Ok(())
}

#[test]
fn externally_deleted_object_is_vanished_not_served() -> TestResult {
    let root = fresh_root("externally_deleted_object_is_vanished_not_served")?;
    let mut spool = StagingSpool::open(&root, roomy())?;
    let digest = spool.stage_bytes(b"deleted-behind-our-back")?.digest;
    fs::remove_file(object_file(&root, digest))?;

    let expected = SpoolError::Corrupt {
        digest,
        kind: CorruptionKind::Vanished,
    };
    assert_eq!(expect_err(spool.read(digest))?, expected);
    assert_eq!(expect_err(spool.verify(digest))?, expected);
    assert_eq!(
        spool.state(digest),
        Some(SpoolObjectState::Corrupt(CorruptionKind::Vanished))
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Idempotent re-stage
// ---------------------------------------------------------------------------------------------

#[test]
fn restage_identical_bytes_is_idempotent() -> TestResult {
    let root = fresh_root("restage_identical_bytes_is_idempotent")?;
    let payload = b"idempotent-capsule-payload";
    let digest = ContentDigest::sha256(payload);
    {
        let mut spool = StagingSpool::open(&root, limits(1, 1024))?;
        assert_eq!(
            spool.stage(digest, payload)?.outcome,
            StageOutcome::NewlyStaged
        );
        let again = spool.stage(digest, payload)?;
        assert_eq!(again.outcome, StageOutcome::AlreadyPresent);
        assert_eq!(again.state, SpoolObjectState::Staged);
        assert_eq!(spool.object_count(), 1);
        assert_eq!(spool.occupied_bytes()?, payload.len() as u64);

        // Re-stage at the object-count bound still succeeds: it charges nothing new.
        spool.verify(digest)?;
        let verified_again = spool.stage(digest, payload)?;
        assert_eq!(verified_again.outcome, StageOutcome::AlreadyPresent);
        assert_eq!(verified_again.state, SpoolObjectState::Verified);
        assert_eq!(
            expect_err(spool.stage_bytes(b"new"))?,
            SpoolError::ObjectCountLimit {
                current: 1,
                maximum: 1,
            }
        );
        assert!(dir_names(&root.join(SPOOL_STAGING_DIR))?.is_empty());
    }

    // Idempotence survives reopen; verification is not persisted, so the object is Staged again.
    let mut spool = StagingSpool::open(&root, limits(1, 1024))?;
    assert_eq!(spool.recovery_report().admitted, vec![digest]);
    let reopened = spool.stage(digest, payload)?;
    assert_eq!(reopened.outcome, StageOutcome::AlreadyPresent);
    assert_eq!(reopened.state, SpoolObjectState::Staged);
    assert_eq!(dir_names(&root.join(SPOOL_OBJECTS_DIR))?, vec![hex(digest)]);
    assert!(dir_names(&root.join(SPOOL_STAGING_DIR))?.is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Corruption: digest mismatch, truncation, trailing bytes, foreign files
// ---------------------------------------------------------------------------------------------

#[test]
fn payload_bit_flip_is_detected_on_read_and_on_reopen() -> TestResult {
    let root = fresh_root("payload_bit_flip_is_detected_on_read_and_on_reopen")?;
    let payload = b"evidence-bytes-to-corrupt".to_vec();
    let digest = ContentDigest::sha256(&payload);
    let mut flipped = payload.clone();
    if let Some(last) = flipped.last_mut() {
        *last ^= 0x01;
    }
    let expected_kind = CorruptionKind::ContentDigestMismatch {
        computed: ContentDigest::sha256(&flipped),
    };
    let path = object_file(&root, digest);
    {
        let mut spool = StagingSpool::open(&root, roomy())?;
        spool.stage(digest, &payload)?;
        spool.verify(digest)?;
        let mut raw = fs::read(&path)?;
        if let Some(last) = raw.last_mut() {
            *last ^= 0x01;
        }
        fs::write(&path, &raw)?;

        let expected = SpoolError::Corrupt {
            digest,
            kind: expected_kind,
        };
        assert_eq!(expect_err(spool.read(digest))?, expected);
        // A previously verified object is re-hashed by the catalog, not trusted from state.
        assert_eq!(
            spool.require_verified(digest),
            Err(ObjectError::Corrupt(digest))
        );
        assert_eq!(expect_err(spool.verify(digest))?, expected);
        assert_eq!(
            spool.state(digest),
            Some(SpoolObjectState::Corrupt(expected_kind))
        );
    }

    let mut spool = StagingSpool::open(&root, roomy())?;
    let report = spool.recovery_report().clone();
    assert!(report.admitted.is_empty());
    assert_eq!(
        report.corrupt,
        vec![CorruptObject {
            digest,
            kind: expected_kind,
        }]
    );
    // Re-staging the original bytes never overwrites a corrupt object.
    let corrupt_bytes = fs::read(&path)?;
    assert_eq!(
        expect_err(spool.stage(digest, &payload))?,
        SpoolError::Corrupt {
            digest,
            kind: expected_kind,
        }
    );
    assert_eq!(fs::read(&path)?, corrupt_bytes);
    Ok(())
}

#[test]
fn truncated_object_is_detected_while_open_and_on_reopen() -> TestResult {
    let root = fresh_root("truncated_object_is_detected_while_open_and_on_reopen")?;
    let payload = vec![0x5a_u8; 100];
    let digest = ContentDigest::sha256(&payload);
    let path = object_file(&root, digest);
    let expected_kind = CorruptionKind::Truncated {
        expected_len: HEADER + 100,
        actual_len: HEADER + 99,
    };
    {
        let mut spool = StagingSpool::open(&root, roomy())?;
        spool.stage(digest, &payload)?;
        truncate_to(&path, HEADER + 99)?;
        assert_eq!(
            expect_err(spool.read(digest))?,
            SpoolError::Corrupt {
                digest,
                kind: expected_kind,
            }
        );
    }

    let spool = StagingSpool::open(&root, roomy())?;
    assert_eq!(
        spool.recovery_report().corrupt,
        vec![CorruptObject {
            digest,
            kind: expected_kind,
        }]
    );
    assert_eq!(
        spool.state(digest),
        Some(SpoolObjectState::Corrupt(expected_kind))
    );
    // Corrupt bytes still occupy disk and stay charged against the quota.
    assert_eq!(spool.occupied_bytes()?, HEADER + 99);
    assert_eq!(
        expect_err(spool.read(digest))?,
        SpoolError::Corrupt {
            digest,
            kind: expected_kind,
        }
    );
    Ok(())
}

#[test]
fn truncation_inside_the_header_is_truncation_not_foreign() -> TestResult {
    let root = fresh_root("truncation_inside_the_header_is_truncation_not_foreign")?;
    let cuts = [0_u64, 5, HEADER - 1];
    let mut digests = Vec::new();
    {
        let mut spool = StagingSpool::open(&root, roomy())?;
        for (index, cut) in cuts.iter().enumerate() {
            let digest = spool
                .stage_bytes(format!("header-cut-{index}").as_bytes())?
                .digest;
            truncate_to(&object_file(&root, digest), *cut)?;
            digests.push((digest, *cut));
        }
    }
    let spool = StagingSpool::open(&root, roomy())?;
    for (digest, cut) in digests {
        assert_eq!(
            spool.state(digest),
            Some(SpoolObjectState::Corrupt(CorruptionKind::Truncated {
                expected_len: HEADER,
                actual_len: cut,
            }))
        );
    }
    assert!(spool.recovery_report().admitted.is_empty());
    Ok(())
}

#[test]
fn trailing_bytes_are_rejected() -> TestResult {
    let root = fresh_root("trailing_bytes_are_rejected")?;
    let mut spool = StagingSpool::open(&root, roomy())?;
    let payload = b"exact-length";
    let digest = spool.stage_bytes(payload)?.digest;
    let path = object_file(&root, digest);
    let mut raw = fs::read(&path)?;
    raw.push(0);
    fs::write(&path, &raw)?;

    let expected_len = HEADER + payload.len() as u64;
    assert_eq!(
        expect_err(spool.read(digest))?,
        SpoolError::Corrupt {
            digest,
            kind: CorruptionKind::TrailingBytes {
                expected_len,
                actual_len: expected_len + 1,
            },
        }
    );
    Ok(())
}

#[test]
fn foreign_file_under_an_object_name_is_rejected_and_untouched() -> TestResult {
    let root = fresh_root("foreign_file_under_an_object_name_is_rejected_and_untouched")?;
    let payload = b"legitimate-payload";
    let digest = ContentDigest::sha256(payload);
    fs::create_dir_all(root.join(SPOOL_OBJECTS_DIR))?;
    let path = object_file(&root, digest);
    let foreign = vec![0x42_u8; SPOOL_OBJECT_HEADER_LEN + payload.len()];
    fs::write(&path, &foreign)?;

    let mut spool = StagingSpool::open(&root, roomy())?;
    let expected = SpoolError::Corrupt {
        digest,
        kind: CorruptionKind::ForeignFile,
    };
    assert_eq!(
        spool.recovery_report().corrupt,
        vec![CorruptObject {
            digest,
            kind: CorruptionKind::ForeignFile,
        }]
    );
    assert_eq!(expect_err(spool.read(digest))?, expected);
    assert_eq!(expect_err(spool.stage(digest, payload))?, expected);
    assert_eq!(fs::read(&path)?, foreign);
    Ok(())
}

#[test]
fn object_renamed_to_another_digest_is_name_digest_mismatch() -> TestResult {
    let root = fresh_root("object_renamed_to_another_digest_is_name_digest_mismatch")?;
    let original = ContentDigest::sha256(b"original-object");
    let impostor = ContentDigest::sha256(b"some-other-object");
    {
        let mut spool = StagingSpool::open(&root, roomy())?;
        spool.stage(original, b"original-object")?;
    }
    fs::rename(object_file(&root, original), object_file(&root, impostor))?;

    let spool = StagingSpool::open(&root, roomy())?;
    assert_eq!(spool.state(original), None);
    assert_eq!(
        spool.state(impostor),
        Some(SpoolObjectState::Corrupt(
            CorruptionKind::NameDigestMismatch { recorded: original }
        ))
    );
    Ok(())
}

#[test]
fn directory_at_an_object_name_is_not_a_regular_file() -> TestResult {
    let root = fresh_root("directory_at_an_object_name_is_not_a_regular_file")?;
    let payload = b"blocked-by-directory";
    let digest = ContentDigest::sha256(payload);
    fs::create_dir_all(object_file(&root, digest))?;

    let mut spool = StagingSpool::open(&root, roomy())?;
    assert_eq!(
        spool.state(digest),
        Some(SpoolObjectState::Corrupt(CorruptionKind::NotRegularFile))
    );
    assert_eq!(
        expect_err(spool.stage(digest, payload))?,
        SpoolError::Corrupt {
            digest,
            kind: CorruptionKind::NotRegularFile,
        }
    );
    Ok(())
}

#[test]
fn foreign_names_are_reported_never_admitted_or_deleted() -> TestResult {
    let root = fresh_root("foreign_names_are_reported_never_admitted_or_deleted")?;
    let digest = ContentDigest::sha256(b"x");
    let objects = root.join(SPOOL_OBJECTS_DIR);
    let staging = root.join(SPOOL_STAGING_DIR);
    fs::create_dir_all(&objects)?;
    fs::create_dir_all(&staging)?;
    fs::write(root.join("extra"), b"root clutter")?;
    fs::write(objects.join("notes.txt"), b"not an object")?;
    fs::write(objects.join(hex(digest).to_uppercase()), b"uppercase name")?;
    fs::write(staging.join("random.bin"), b"not a staging name")?;
    fs::create_dir_all(staging_file(&root, digest, 0))?;

    let mut spool = StagingSpool::open(&root, roomy())?;
    let expected = vec![
        ForeignEntry {
            path: PathBuf::from("extra"),
            reason: ForeignReason::UnexpectedRootEntry,
        },
        ForeignEntry {
            path: Path::new(SPOOL_STAGING_DIR).join(format!("{}.0.tmp", hex(digest))),
            reason: ForeignReason::NotRegularFile,
        },
        ForeignEntry {
            path: Path::new(SPOOL_STAGING_DIR).join("random.bin"),
            reason: ForeignReason::UnrecognizedName,
        },
        ForeignEntry {
            path: Path::new(SPOOL_OBJECTS_DIR).join(hex(digest).to_uppercase()),
            reason: ForeignReason::UnrecognizedName,
        },
        ForeignEntry {
            path: Path::new(SPOOL_OBJECTS_DIR).join("notes.txt"),
            reason: ForeignReason::UnrecognizedName,
        },
    ];
    assert_eq!(spool.recovery_report().foreign, expected);
    assert!(spool.recovery_report().admitted.is_empty());
    assert!(spool.recovery_report().orphaned_staging.is_empty());
    assert_eq!(spool.object_count(), 0);

    let discard = spool.discard_orphaned_staging()?;
    assert_eq!(discard.removed, 0);
    for entry in &expected {
        assert!(
            root.join(&entry.path).exists(),
            "{:?} was removed",
            entry.path
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Crash recovery
// ---------------------------------------------------------------------------------------------

#[test]
fn crash_after_staging_write_leaves_an_orphan_reopen_never_admits() -> TestResult {
    let root = fresh_root("crash_after_staging_write_leaves_an_orphan_reopen_never_admits")?;
    let payload = b"capsule-payload-interrupted-mid-ingest";
    let digest = ContentDigest::sha256(payload);
    {
        let mut spool = StagingSpool::open(&root, roomy())?;
        spool.inject_crash_after(StagePhase::AfterStagingWrite);
        assert_eq!(
            expect_err(spool.stage(digest, payload))?,
            SpoolError::InjectedCrash {
                phase: StagePhase::AfterStagingWrite,
            }
        );
        // The crashed instance fails closed for every operation.
        assert_eq!(expect_err(spool.read(digest))?, SpoolError::Poisoned);
        assert_eq!(expect_err(spool.stage_bytes(b"x"))?, SpoolError::Poisoned);
        assert_eq!(
            spool.require_verified(digest),
            Err(ObjectError::Unavailable(digest))
        );
    }

    // The leftover temp file is a complete, valid envelope, and still not an object.
    let orphan_path = staging_file(&root, digest, 0);
    let orphan_raw = fs::read(&orphan_path)?;
    let orphan_len = orphan_raw.len() as u64;
    assert_eq!(orphan_len, HEADER + payload.len() as u64);
    assert_eq!(orphan_raw.get(..8), Some(&SPOOL_OBJECT_MAGIC[..]));
    assert!(dir_names(&root.join(SPOOL_OBJECTS_DIR))?.is_empty());

    let mut spool = StagingSpool::open(&root, roomy())?;
    let report = spool.recovery_report().clone();
    assert!(!report.is_clean());
    assert!(report.admitted.is_empty());
    assert!(report.corrupt.is_empty());
    assert_eq!(
        report.orphaned_staging,
        vec![OrphanedStaging {
            path: Path::new(SPOOL_STAGING_DIR).join(format!("{}.0.tmp", hex(digest))),
            bytes: orphan_len,
            claimed_digest: digest,
        }]
    );
    assert_eq!(spool.state(digest), None);
    assert_eq!(expect_err(spool.read(digest))?, SpoolError::Missing(digest));
    assert_eq!(spool.occupied_bytes()?, orphan_len);

    // Retrying ingest skips the orphan's name and succeeds; the orphan stays charged.
    assert_eq!(
        spool.stage(digest, payload)?.outcome,
        StageOutcome::NewlyStaged
    );
    assert_eq!(fs::read(&orphan_path)?, orphan_raw);
    assert_eq!(spool.occupied_bytes()?, orphan_len + payload.len() as u64);

    let discard = spool.discard_orphaned_staging()?;
    assert_eq!(discard.removed, 1);
    assert_eq!(discard.released_bytes, orphan_len);
    assert_eq!(spool.orphaned_staging().count(), 0);
    assert!(dir_names(&root.join(SPOOL_STAGING_DIR))?.is_empty());
    assert_eq!(spool.occupied_bytes()?, payload.len() as u64);
    drop(spool);

    let spool = StagingSpool::open(&root, roomy())?;
    assert!(spool.recovery_report().is_clean());
    assert_eq!(spool.recovery_report().admitted, vec![digest]);
    assert_eq!(spool.read(digest)?, payload.to_vec());
    Ok(())
}

#[test]
fn crash_after_rename_is_reconciled_as_staged_on_reopen() -> TestResult {
    let root = fresh_root("crash_after_rename_is_reconciled_as_staged_on_reopen")?;
    let payload = b"renamed-but-not-indexed";
    let digest = ContentDigest::sha256(payload);
    {
        let mut spool = StagingSpool::open(&root, roomy())?;
        spool.inject_crash_after(StagePhase::AfterRename);
        assert_eq!(
            expect_err(spool.stage(digest, payload))?,
            SpoolError::InjectedCrash {
                phase: StagePhase::AfterRename,
            }
        );
        assert_eq!(spool.state(digest), None);
    }
    assert!(dir_names(&root.join(SPOOL_STAGING_DIR))?.is_empty());

    let mut spool = StagingSpool::open(&root, roomy())?;
    assert!(spool.recovery_report().is_clean());
    assert_eq!(spool.recovery_report().admitted, vec![digest]);
    assert_eq!(spool.state(digest), Some(SpoolObjectState::Staged));
    assert_eq!(spool.read(digest)?, payload.to_vec());
    assert_eq!(
        spool.stage(digest, payload)?.outcome,
        StageOutcome::AlreadyPresent
    );
    Ok(())
}

#[test]
fn second_open_of_the_same_root_is_locked() -> TestResult {
    let root = fresh_root("second_open_of_the_same_root_is_locked")?;
    let first = StagingSpool::open(&root, roomy())?;
    assert_eq!(
        expect_err(StagingSpool::open(&root, roomy()))?,
        SpoolError::Locked {
            path: root.join(SPOOL_LOCK_FILE),
        }
    );
    drop(first);
    let second = StagingSpool::open(&root, roomy())?;
    assert!(second.recovery_report().is_clean());
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Quotas and bounds: exactly at the bound, and bound + 1
// ---------------------------------------------------------------------------------------------

#[test]
fn byte_quota_admits_the_exact_bound_and_rejects_bound_plus_one() -> TestResult {
    let root = fresh_root("byte_quota_admits_the_exact_bound_and_rejects_bound_plus_one")?;
    {
        let mut spool = StagingSpool::open(&root, limits(8, 10))?;
        spool.stage_bytes(b"four")?;
        spool.stage_bytes(b"six666")?;
        assert_eq!(spool.occupied_bytes()?, 10);
        assert_eq!(
            expect_err(spool.stage_bytes(b"1"))?,
            SpoolError::ByteQuotaExceeded {
                current: 10,
                requested: 1,
                maximum: 10,
            }
        );
        assert_eq!(spool.object_count(), 2);
        assert!(dir_names(&root.join(SPOOL_STAGING_DIR))?.is_empty());
    }
    // The quota is recomputed from disk on reopen and still enforced.
    let mut spool = StagingSpool::open(&root, limits(8, 10))?;
    assert_eq!(spool.occupied_bytes()?, 10);
    assert_eq!(
        expect_err(spool.stage_bytes(b"1"))?,
        SpoolError::ByteQuotaExceeded {
            current: 10,
            requested: 1,
            maximum: 10,
        }
    );

    let single = fresh_root("byte_quota_admits_the_exact_bound_and_rejects_bound_plus_one_single")?;
    let mut spool = StagingSpool::open(&single, limits(8, 10))?;
    assert_eq!(
        expect_err(spool.stage_bytes(b"eleven-byte"))?,
        SpoolError::ByteQuotaExceeded {
            current: 0,
            requested: 11,
            maximum: 10,
        }
    );
    spool.stage_bytes(b"ten-bytes!")?;
    assert_eq!(spool.occupied_bytes()?, 10);
    Ok(())
}

#[test]
fn object_count_admits_the_exact_bound_and_rejects_bound_plus_one() -> TestResult {
    let root = fresh_root("object_count_admits_the_exact_bound_and_rejects_bound_plus_one")?;
    let mut spool = StagingSpool::open(&root, limits(2, 1024))?;
    spool.stage_bytes(b"first")?;
    spool.stage_bytes(b"second")?;
    assert_eq!(
        expect_err(spool.stage_bytes(b"third"))?,
        SpoolError::ObjectCountLimit {
            current: 2,
            maximum: 2,
        }
    );
    assert_eq!(dir_names(&root.join(SPOOL_OBJECTS_DIR))?.len(), 2);
    Ok(())
}

#[test]
fn per_object_bound_admits_the_exact_bound_and_rejects_bound_plus_one() -> TestResult {
    let root = fresh_root("per_object_bound_admits_the_exact_bound_and_rejects_bound_plus_one")?;
    let mut spool = StagingSpool::open(&root, SpoolLimits::new(8, 1 << 20, 32, 64))?;
    spool.stage_bytes(&[7_u8; 32])?;
    assert_eq!(
        expect_err(spool.stage_bytes(&[7_u8; 33]))?,
        SpoolError::ObjectTooLarge {
            length: 33,
            maximum: 32,
        }
    );
    Ok(())
}

#[test]
fn orphan_bytes_are_charged_until_discarded() -> TestResult {
    let root = fresh_root("orphan_bytes_are_charged_until_discarded")?;
    let orphan_payload = b"0123456789";
    {
        let mut spool = StagingSpool::open(&root, roomy())?;
        spool.inject_crash_after(StagePhase::AfterStagingWrite);
        expect_err(spool.stage_bytes(orphan_payload))?;
    }
    let orphan_len = HEADER + 10;
    let bound = orphan_len + 10;
    let mut spool = StagingSpool::open(&root, limits(8, bound))?;
    assert_eq!(spool.occupied_bytes()?, orphan_len);
    spool.stage_bytes(b"abcdefghij")?;
    assert_eq!(spool.occupied_bytes()?, bound);
    assert_eq!(
        expect_err(spool.stage_bytes(b"z"))?,
        SpoolError::ByteQuotaExceeded {
            current: bound,
            requested: 1,
            maximum: bound,
        }
    );
    let discard = spool.discard_orphaned_staging()?;
    assert_eq!(discard.released_bytes, orphan_len);
    spool.stage_bytes(b"z")?;
    assert_eq!(spool.occupied_bytes()?, 11);
    Ok(())
}

#[test]
fn scan_bound_admits_the_exact_bound_and_rejects_bound_plus_one() -> TestResult {
    let root = fresh_root("scan_bound_admits_the_exact_bound_and_rejects_bound_plus_one")?;
    let objects = root.join(SPOOL_OBJECTS_DIR);
    fs::create_dir_all(&objects)?;
    let scan_limits = SpoolLimits::new(2, 1024, 64, 3);
    for index in 0..3 {
        fs::write(objects.join(format!("junk-{index}")), b"j")?;
    }
    {
        let spool = StagingSpool::open(&root, scan_limits)?;
        assert_eq!(spool.recovery_report().foreign.len(), 3);
    }
    fs::write(objects.join("junk-3"), b"j")?;
    assert_eq!(
        expect_err(StagingSpool::open(&root, scan_limits))?,
        SpoolError::EntryLimit {
            directory: objects,
            maximum: 3,
        }
    );
    Ok(())
}

#[test]
fn staging_names_are_bounded() -> TestResult {
    let root = fresh_root("staging_names_are_bounded")?;
    let fits = b"one-name-left";
    let blocked = b"no-names-left";
    let fits_digest = ContentDigest::sha256(fits);
    let blocked_digest = ContentDigest::sha256(blocked);
    fs::create_dir_all(root.join(SPOOL_STAGING_DIR))?;
    for attempt in 0..MAX_STAGING_NAME_ATTEMPTS - 1 {
        fs::write(staging_file(&root, fits_digest, attempt), b"orphan")?;
    }
    for attempt in 0..MAX_STAGING_NAME_ATTEMPTS {
        fs::write(staging_file(&root, blocked_digest, attempt), b"orphan")?;
    }

    let mut spool = StagingSpool::open(&root, roomy())?;
    let orphan_count = (2 * MAX_STAGING_NAME_ATTEMPTS - 1) as usize;
    assert_eq!(spool.recovery_report().orphaned_staging.len(), orphan_count);
    assert_eq!(
        spool.stage(fits_digest, fits)?.outcome,
        StageOutcome::NewlyStaged
    );
    assert_eq!(
        expect_err(spool.stage(blocked_digest, blocked))?,
        SpoolError::StagingNamesExhausted {
            digest: blocked_digest,
            attempts: MAX_STAGING_NAME_ATTEMPTS,
        }
    );
    assert_eq!(spool.state(blocked_digest), None);
    // Orphans held by earlier owners are never overwritten.
    for attempt in 0..MAX_STAGING_NAME_ATTEMPTS {
        assert_eq!(
            fs::read(staging_file(&root, blocked_digest, attempt))?,
            b"orphan".to_vec()
        );
    }
    Ok(())
}

#[test]
fn invalid_limits_are_rejected_before_touching_disk() -> TestResult {
    let root = fresh_root("invalid_limits_are_rejected_before_touching_disk")?;
    assert_eq!(
        expect_err(StagingSpool::open(
            &root,
            SpoolLimits::new(1, 1, MAX_OBJECT_BYTES + 1, 1)
        ))?,
        SpoolError::InvalidLimits(SpoolLimitViolation::ObjectBoundAboveFormatMaximum {
            requested: MAX_OBJECT_BYTES + 1,
            maximum: MAX_OBJECT_BYTES,
        })
    );
    assert_eq!(
        expect_err(StagingSpool::open(&root, SpoolLimits::new(4, 1, 1, 3)))?,
        SpoolError::InvalidLimits(SpoolLimitViolation::ScanBoundBelowObjectBound {
            max_scan_entries: 3,
            max_objects: 4,
        })
    );
    assert!(!root.exists());

    // Exactly at each bound is admitted.
    drop(StagingSpool::open(
        &root,
        SpoolLimits::new(1, 1, MAX_OBJECT_BYTES, 1),
    )?);
    drop(StagingSpool::open(&root, SpoolLimits::new(4, 1, 1, 4))?);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Catalog boundary, determinism, and differential oracle
// ---------------------------------------------------------------------------------------------

#[test]
fn catalog_exposes_only_verified_objects() -> TestResult {
    let root = fresh_root("catalog_exposes_only_verified_objects")?;
    let mut spool = StagingSpool::open(&root, roomy())?;
    let staged = spool.stage_bytes(b"staged-child")?.digest;
    let verified = spool.stage_bytes(b"verified-child")?.digest;
    spool.verify(verified)?;
    let absent = ContentDigest::sha256(b"absent-child");

    assert_eq!(
        spool.require_verified(staged),
        Err(ObjectError::NotVerified(staged))
    );
    spool.require_verified(verified)?;
    assert_eq!(
        spool.require_all_verified(&[verified, staged]),
        Err(ObjectError::NotVerified(staged))
    );
    assert_eq!(
        spool.require_verified(absent),
        Err(ObjectError::Missing(absent))
    );
    Ok(())
}

#[test]
fn recovery_report_is_deterministic_across_roots() -> TestResult {
    let build = |name: &str| -> Result<(StagingSpool, PathBuf), Box<dyn Error>> {
        let root = fresh_root(name)?;
        {
            let mut spool = StagingSpool::open(&root, roomy())?;
            for payload in [b"zeta".as_slice(), b"alpha", b"mu"] {
                spool.stage_bytes(payload)?;
            }
            spool.inject_crash_after(StagePhase::AfterStagingWrite);
            expect_err(spool.stage_bytes(b"interrupted"))?;
        }
        let corrupt = object_file(&root, ContentDigest::sha256(b"mu"));
        truncate_to(&corrupt, 3)?;
        fs::write(root.join(SPOOL_OBJECTS_DIR).join("stray"), b"stray")?;
        Ok((StagingSpool::open(&root, roomy())?, root))
    };
    let (left, _) = build("recovery_report_is_deterministic_across_roots_left")?;
    let (right, _) = build("recovery_report_is_deterministic_across_roots_right")?;
    assert_eq!(left.recovery_report(), right.recovery_report());
    assert_eq!(left.occupied_bytes()?, right.occupied_bytes()?);

    let report = left.recovery_report();
    let mut sorted = report.admitted.clone();
    sorted.sort();
    assert_eq!(report.admitted, sorted);
    assert_eq!(report.admitted.len(), 2);
    assert_eq!(report.corrupt.len(), 1);
    assert_eq!(report.orphaned_staging.len(), 1);
    assert_eq!(report.foreign.len(), 1);
    Ok(())
}

#[derive(Debug, PartialEq)]
enum Verdict {
    Admitted(ContentDigest),
    CountLimit,
    ByteQuota,
    Other(String),
}

fn spool_verdict(result: Result<StageReceipt, SpoolError>) -> Verdict {
    match result {
        Ok(receipt) => Verdict::Admitted(receipt.digest),
        Err(SpoolError::ObjectCountLimit { .. }) => Verdict::CountLimit,
        Err(SpoolError::ByteQuotaExceeded { .. }) => Verdict::ByteQuota,
        Err(other) => Verdict::Other(other.to_string()),
    }
}

fn memory_verdict(result: Result<ContentDigest, ObjectError>) -> Verdict {
    match result {
        Ok(digest) => Verdict::Admitted(digest),
        Err(ObjectError::ObjectCountLimit { .. }) => Verdict::CountLimit,
        Err(ObjectError::ByteQuotaExceeded { .. }) => Verdict::ByteQuota,
        Err(other) => Verdict::Other(other.to_string()),
    }
}

#[test]
fn spool_matches_the_in_memory_oracle_on_identity_and_bounds() -> TestResult {
    let scenarios: [(&str, usize, u64, &[&[u8]]); 2] = [
        (
            "differential_count",
            3,
            20,
            &[b"aaaa", b"bbbbbbbb", b"aaaa", b"cccccccc", b"d", b"aaaa"],
        ),
        (
            "differential_bytes",
            8,
            10,
            &[b"12345", b"abcdef", b"abcde", b"12345", b"x"],
        ),
    ];
    for (name, max_objects, max_total_bytes, payloads) in scenarios {
        let root = fresh_root(&format!("spool_matches_the_in_memory_oracle_{name}"))?;
        let mut spool = StagingSpool::open(
            &root,
            SpoolLimits::new(max_objects, max_total_bytes, MAX_OBJECT_BYTES, 64),
        )?;
        let mut oracle = InMemoryObjectStore::new(ObjectLimits::new(max_objects, max_total_bytes));
        for payload in payloads {
            let expected = memory_verdict(oracle.stage(payload));
            let actual = spool_verdict(spool.stage_bytes(payload));
            assert_eq!(actual, expected, "{name}: payload {payload:?}");
            if let Verdict::Admitted(digest) = actual {
                oracle.verify(digest)?;
                spool.verify(digest)?;
                assert_eq!(spool.read(digest)?, oracle.read_verified(digest)?.to_vec());
            }
        }
        assert_eq!(spool.object_count(), oracle.object_count());
        assert_eq!(spool.occupied_bytes()?, oracle.total_bytes());
    }
    Ok(())
}

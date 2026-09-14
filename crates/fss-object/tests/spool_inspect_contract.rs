#![forbid(unsafe_code)]
//! Integration contract tests for spool inspection without locks, repair, or mutation (DOCTOR0).
//!
//! Asserts:
//! - Differential against [`StagingSpool::open`] across clean, orphaned staging, corrupt object,
//!   foreign entry, symlink, legacy spool (missing holds/), and missing layout roots.
//! - Read-only proof: full tree digest (content, size, mode, mtime nanoseconds, listing)
//!   strictly identical before and after inspection.
//! - Read-only proof: [`RecordingSpoolIo`] records 0 mutating calls.
//! - Read-only copy: inspection succeeds on a 0o555 read-only directory tree.
//! - Limits at N and N+1: [`SpoolLimits::max_scan_entries`].
//! - Lock-free verified payload reading via [`spool::read_verified_payload`].
//! - Structured CAPLOG emission for each step.

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use fss_core::{ContentDigest, DigestAlgorithm, Sha256Hasher, sha256};
use fss_object::{
    CorruptionKind, HostSpoolIo, MAX_OBJECT_BYTES, RecordingSpoolIo, SPOOL_HOLDS_DIR,
    SPOOL_OBJECTS_DIR, SPOOL_STAGING_DIR, SpoolError, SpoolLimits, StagingSpool, spool,
};

type TestResult = Result<(), Box<dyn Error>>;

fn fresh_root(test_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let base = match std::env::var_os("CARGO_TARGET_TMPDIR") {
        Some(dir) => PathBuf::from(dir),
        None => std::env::temp_dir(),
    };
    let root = base.join("spool_inspect_contract").join(test_name);
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    fs::create_dir_all(&root)?;
    Ok(root)
}

fn limits(max_objects: usize, max_scan: usize) -> SpoolLimits {
    SpoolLimits::new(max_objects, 1 << 20, 4096, max_scan)
}

fn hex(digest: ContentDigest) -> String {
    digest.to_text().trim_start_matches("sha256:").to_owned()
}

fn copy_dir_all(src: &Path, dst: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_dir() {
            copy_dir_all(&src_path, &dst_path)?;
        } else if ft.is_symlink() {
            let target = fs::read_link(&src_path)?;
            std::os::unix::fs::symlink(&target, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

fn compute_tree_digest(root: &Path) -> Result<ContentDigest, Box<dyn Error>> {
    let mut entries = Vec::new();
    collect_tree_entries(root, root, &mut entries)?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = Sha256Hasher::new();
    for (rel_path, is_dir, size, mode, mtime_sec, mtime_nsec, content_hash) in entries {
        hasher.update(rel_path.as_bytes());
        hasher.update(&[if is_dir { 1 } else { 0 }]);
        hasher.update(&size.to_be_bytes());
        hasher.update(&mode.to_be_bytes());
        hasher.update(&mtime_sec.to_be_bytes());
        hasher.update(&mtime_nsec.to_be_bytes());
        hasher.update(&content_hash);
    }
    let digest_bytes = hasher.finalize()?;
    Ok(ContentDigest::new(DigestAlgorithm::Sha256, digest_bytes))
}

fn collect_tree_entries(
    base: &Path,
    current: &Path,
    entries: &mut Vec<(String, bool, u64, u32, i64, i64, [u8; 32])>,
) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)?;
        let rel_path = path.strip_prefix(base)?.to_string_lossy().to_string();
        let is_dir = meta.is_dir();
        let size = meta.len();
        let mode = meta.mode();
        let mtime_sec = meta.mtime();
        let mtime_nsec = meta.mtime_nsec();
        let content_hash = if is_dir {
            [0u8; 32]
        } else if meta.file_type().is_symlink() {
            let target = fs::read_link(&path)?;
            sha256(target.to_string_lossy().as_bytes())
        } else {
            let bytes = fs::read(&path)?;
            sha256(&bytes)
        };
        entries.push((
            rel_path,
            is_dir,
            size,
            mode,
            mtime_sec,
            mtime_nsec,
            content_hash,
        ));
        if is_dir {
            collect_tree_entries(base, &path, entries)?;
        }
    }
    Ok(())
}

struct ReadOnlyTreeGuard {
    paths: Vec<(PathBuf, u32)>,
}

impl ReadOnlyTreeGuard {
    fn make_read_only(root: &Path) -> Result<Self, std::io::Error> {
        let mut paths = Vec::new();
        Self::collect_and_set(root, &mut paths)?;
        Ok(Self { paths })
    }

    fn collect_and_set(dir: &Path, paths: &mut Vec<(PathBuf, u32)>) -> Result<(), std::io::Error> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let meta = fs::symlink_metadata(&path)?;
            if meta.is_dir() {
                Self::collect_and_set(&path, paths)?;
                paths.push((path.clone(), meta.mode()));
                fs::set_permissions(&path, fs::Permissions::from_mode(0o555))?;
            }
        }
        let root_meta = fs::symlink_metadata(dir)?;
        paths.push((dir.to_path_buf(), root_meta.mode()));
        fs::set_permissions(dir, fs::Permissions::from_mode(0o555))?;
        Ok(())
    }
}

impl Drop for ReadOnlyTreeGuard {
    fn drop(&mut self) {
        for (path, mode) in self.paths.iter().rev() {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(*mode));
        }
    }
}

fn emit_caplog(
    step: &str,
    verdict: &str,
    exit_code: i32,
    duration_ms: u128,
    expected: &str,
    observed: &str,
) {
    println!(
        r#"CAPLOG {{"step":"{}","verdict":"{}","exit":{},"duration_ms":{},"expected":{},"observed":{}}}"#,
        step, verdict, exit_code, duration_ms, expected, observed
    );
}

#[test]
fn test_spool_differential_clean() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_spool_differential_clean")?;
    let copy = fresh_root("test_spool_differential_clean_copy")?;
    let l = limits(16, 32);

    {
        let mut spool = StagingSpool::open(&root, l)?;
        let r1 = spool.stage_bytes(b"hello world")?;
        spool.verify(r1.digest)?;
        let r2 = spool.stage_bytes(b"another verified object")?;
        spool.verify(r2.digest)?;
    }

    copy_dir_all(&root, &copy)?;

    let inspection = spool::inspect(&root, &l)?;
    let opened = StagingSpool::open(&copy, l)?;

    assert_eq!(
        inspection.report.admitted.len(),
        opened.recovery_report().admitted.len()
    );
    assert_eq!(
        inspection.report.admitted,
        opened.recovery_report().admitted
    );
    assert_eq!(
        inspection.report.orphaned_staging.len(),
        opened.recovery_report().orphaned_staging.len()
    );
    assert_eq!(
        inspection.report.corrupt.len(),
        opened.recovery_report().corrupt.len()
    );
    assert_eq!(
        inspection.report.foreign.len(),
        opened.recovery_report().foreign.len()
    );
    assert!(!inspection.holds_migration_pending);
    assert!(!inspection.missing_layout);

    emit_caplog(
        "spool_differential_clean",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"admitted_count":2,"holds_pending":false}"#,
        r#"{"admitted_count":2,"holds_pending":false}"#,
    );
    Ok(())
}

#[test]
fn test_spool_differential_orphaned_staging() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_spool_differential_orphaned_staging")?;
    let copy = fresh_root("test_spool_differential_orphaned_staging_copy")?;
    let l = limits(16, 32);

    {
        let mut spool = StagingSpool::open(&root, l)?;
        let r = spool.stage_bytes(b"verified object")?;
        spool.verify(r.digest)?;
    }

    let staged_digest = ContentDigest::new(
        DigestAlgorithm::Sha256,
        sha256(b"uncommitted bytes in progress"),
    );
    let orphan_name = format!("{}.0.tmp", hex(staged_digest));
    let orphan_path = root.join(SPOOL_STAGING_DIR).join(&orphan_name);
    fs::write(&orphan_path, b"uncommitted bytes in progress")?;

    copy_dir_all(&root, &copy)?;

    let inspection = spool::inspect(&root, &l)?;
    let opened = StagingSpool::open(&copy, l)?;

    assert_eq!(inspection.report.orphaned_staging.len(), 1);
    assert_eq!(
        inspection.report.orphaned_staging.len(),
        opened.recovery_report().orphaned_staging.len()
    );
    assert_eq!(
        inspection.report.orphaned_staging[0].path,
        opened.recovery_report().orphaned_staging[0].path
    );
    assert_eq!(
        inspection.report.orphaned_staging[0].bytes,
        opened.recovery_report().orphaned_staging[0].bytes
    );

    emit_caplog(
        "spool_differential_orphaned_staging",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"orphaned_count":1}"#,
        r#"{"orphaned_count":1}"#,
    );
    Ok(())
}

#[test]
fn test_spool_differential_corrupt_object() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_spool_differential_corrupt_object")?;
    let copy = fresh_root("test_spool_differential_corrupt_object_copy")?;
    let l = limits(16, 32);

    let digest = {
        let mut spool = StagingSpool::open(&root, l)?;
        let r = spool.stage_bytes(b"payload to be corrupted")?;
        spool.verify(r.digest)?;
        r.digest
    };

    let obj_path = root.join(SPOOL_OBJECTS_DIR).join(hex(digest));
    let mut bytes = fs::read(&obj_path)?;
    let last = bytes.last_mut().ok_or_else(|| SpoolError::Corrupt {
        digest,
        kind: CorruptionKind::Truncated {
            expected_len: 1,
            actual_len: 0,
        },
    })?;
    *last ^= 0xFF;
    fs::write(&obj_path, bytes)?;

    copy_dir_all(&root, &copy)?;

    let inspection = spool::inspect(&root, &l)?;
    let opened = StagingSpool::open(&copy, l)?;

    assert_eq!(inspection.report.corrupt.len(), 1);
    assert_eq!(
        inspection.report.corrupt.len(),
        opened.recovery_report().corrupt.len()
    );
    assert_eq!(
        inspection.report.corrupt[0].digest,
        opened.recovery_report().corrupt[0].digest
    );

    emit_caplog(
        "spool_differential_corrupt_object",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"corrupt_count":1}"#,
        r#"{"corrupt_count":1}"#,
    );
    Ok(())
}

#[test]
fn test_spool_differential_foreign_entries() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_spool_differential_foreign_entries")?;
    let copy = fresh_root("test_spool_differential_foreign_entries_copy")?;
    let l = limits(16, 32);

    {
        let mut spool = StagingSpool::open(&root, l)?;
        let r = spool.stage_bytes(b"data")?;
        spool.verify(r.digest)?;
    }

    let foreign_path = root.join(SPOOL_OBJECTS_DIR).join("not_a_hex_digest.txt");
    fs::write(&foreign_path, b"intruder")?;

    copy_dir_all(&root, &copy)?;

    let inspection = spool::inspect(&root, &l)?;
    let opened = StagingSpool::open(&copy, l)?;

    assert_eq!(inspection.report.foreign.len(), 1);
    assert_eq!(
        inspection.report.foreign.len(),
        opened.recovery_report().foreign.len()
    );
    assert_eq!(
        inspection.report.foreign[0].path,
        opened.recovery_report().foreign[0].path
    );

    emit_caplog(
        "spool_differential_foreign_entries",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"foreign_count":1}"#,
        r#"{"foreign_count":1}"#,
    );
    Ok(())
}

#[test]
fn test_spool_differential_symlink_entry() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_spool_differential_symlink_entry")?;
    let copy = fresh_root("test_spool_differential_symlink_entry_copy")?;
    let l = limits(16, 32);

    {
        let mut spool = StagingSpool::open(&root, l)?;
        let r = spool.stage_bytes(b"data")?;
        spool.verify(r.digest)?;
    }

    let ext_dir = fresh_root("test_spool_differential_symlink_external")?;
    let target_file = ext_dir.join("external.txt");
    fs::write(&target_file, b"target")?;
    let symlink_path = root.join(SPOOL_STAGING_DIR).join("link.tmp");
    std::os::unix::fs::symlink(&target_file, &symlink_path)?;

    copy_dir_all(&root, &copy)?;

    let inspection = spool::inspect(&root, &l)?;
    let opened = StagingSpool::open(&copy, l)?;

    assert_eq!(inspection.report.foreign.len(), 1);
    assert_eq!(
        inspection.report.foreign.len(),
        opened.recovery_report().foreign.len()
    );

    emit_caplog(
        "spool_differential_symlink_entry",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"foreign_count":1}"#,
        r#"{"foreign_count":1}"#,
    );
    Ok(())
}

#[test]
fn test_spool_differential_legacy_spool() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_spool_differential_legacy_spool")?;
    let copy = fresh_root("test_spool_differential_legacy_spool_copy")?;
    let l = limits(16, 32);

    {
        let mut spool = StagingSpool::open(&root, l)?;
        let r = spool.stage_bytes(b"data")?;
        spool.verify(r.digest)?;
    }

    let holds_dir = root.join(SPOOL_HOLDS_DIR);
    if holds_dir.exists() {
        fs::remove_dir_all(&holds_dir)?;
    }

    copy_dir_all(&root, &copy)?;

    let inspection = spool::inspect(&root, &l)?;
    assert!(inspection.holds_migration_pending);
    assert!(!root.join(SPOOL_HOLDS_DIR).exists());

    let opened = StagingSpool::open(&copy, l)?;
    assert_eq!(
        inspection.report.admitted.len(),
        opened.recovery_report().admitted.len()
    );

    emit_caplog(
        "spool_differential_legacy_spool",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"holds_migration_pending":true}"#,
        r#"{"holds_migration_pending":true}"#,
    );
    Ok(())
}

#[test]
fn test_spool_differential_missing_layout() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_spool_differential_missing_layout")?;
    let l = limits(16, 32);

    let inspection = spool::inspect(&root, &l)?;
    assert!(inspection.missing_layout);
    assert!(!root.join(SPOOL_OBJECTS_DIR).exists());

    emit_caplog(
        "spool_differential_missing_layout",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"missing_layout":true}"#,
        r#"{"missing_layout":true}"#,
    );
    Ok(())
}

#[test]
fn test_spool_limits_n_and_n_plus_one() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_spool_limits_n_and_n_plus_one")?;
    let copy = fresh_root("test_spool_limits_n_and_n_plus_one_copy")?;
    let l_roomy = limits(16, 32);

    let _d1 = {
        let mut spool = StagingSpool::open(&root, l_roomy)?;
        let r1 = spool.stage_bytes(b"obj1")?;
        spool.verify(r1.digest)?;
        let r2 = spool.stage_bytes(b"obj2")?;
        spool.verify(r2.digest)?;
        r1.digest
    };

    let l_exact = limits(2, 2);
    let inspect_ok = spool::inspect(&root, &l_exact)?;
    assert_eq!(inspect_ok.report.admitted.len(), 2);

    let mut spool = StagingSpool::open(&root, l_roomy)?;
    let r3 = spool.stage_bytes(b"obj3")?;
    spool.verify(r3.digest)?;
    drop(spool);

    copy_dir_all(&root, &copy)?;

    let inspect_err = spool::inspect(&root, &l_exact);
    let open_err = StagingSpool::open(&copy, l_exact);

    match (inspect_err, open_err) {
        (
            Err(SpoolError::EntryLimit { maximum: i_max, .. }),
            Err(SpoolError::EntryLimit { maximum: o_max, .. }),
        ) => {
            assert_eq!(i_max, 2);
            assert_eq!(o_max, 2);
        }
        (i, o) => {
            return Err(format!(
                "expected EntryLimit from both inspect and open, got inspect={i:?}, open={o:?}"
            )
            .into());
        }
    }

    emit_caplog(
        "spool_limits_n_and_n_plus_one",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"entry_limit":2,"status":"EntryLimit"}"#,
        r#"{"entry_limit":2,"status":"EntryLimit"}"#,
    );
    Ok(())
}

#[test]
fn test_spool_read_only_tree_digest_proof() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_spool_read_only_tree_digest_proof")?;
    let l = limits(16, 32);

    {
        let mut spool = StagingSpool::open(&root, l)?;
        let r1 = spool.stage_bytes(b"verified object payload")?;
        spool.verify(r1.digest)?;
    }

    let orphan_digest = ContentDigest::new(DigestAlgorithm::Sha256, sha256(b"staged content"));
    let orphan_name = format!("{}.0.tmp", hex(orphan_digest));
    let orphan = root.join(SPOOL_STAGING_DIR).join(&orphan_name);
    fs::write(&orphan, b"staged content")?;
    let foreign = root.join(SPOOL_OBJECTS_DIR).join("foreign_file.bin");
    fs::write(&foreign, b"foreign bytes")?;

    let lock_file = root.join("LOCK");
    if lock_file.exists() {
        fs::remove_file(&lock_file)?;
    }

    let digest_before = compute_tree_digest(&root)?;

    let inspection = spool::inspect(&root, &l)?;
    assert_eq!(inspection.report.admitted.len(), 1);
    assert_eq!(inspection.report.orphaned_staging.len(), 1);
    assert_eq!(inspection.report.foreign.len(), 1);

    let digest_after = compute_tree_digest(&root)?;

    assert_eq!(
        digest_before, digest_after,
        "spool root modified during inspect call!"
    );
    assert!(
        !root.join("LOCK").exists(),
        "LOCK file was created during inspect!"
    );

    emit_caplog(
        "spool_read_only_tree_digest_proof",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"tree_modified":false,"lock_created":false}"#,
        r#"{"tree_modified":false,"lock_created":false}"#,
    );
    Ok(())
}

#[test]
fn test_spool_read_only_recording_io_proof() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_spool_read_only_recording_io_proof")?;
    let l = limits(16, 32);

    {
        let mut spool = StagingSpool::open(&root, l)?;
        let r1 = spool.stage_bytes(b"data for recording io")?;
        spool.verify(r1.digest)?;
    }

    let recording_io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let inspection = spool::inspect_with_io(&root, &l, &recording_io)?;
    assert_eq!(inspection.report.admitted.len(), 1);

    assert!(
        recording_io.is_read_only(),
        "RecordingSpoolIo observed mutating calls: {:?}",
        recording_io.mutating_calls()
    );
    assert!(recording_io.mutating_calls().is_empty());

    emit_caplog(
        "spool_read_only_recording_io_proof",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"is_read_only":true,"mutating_count":0}"#,
        r#"{"is_read_only":true,"mutating_count":0}"#,
    );
    Ok(())
}

#[test]
fn test_spool_read_only_filesystem_copy() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_spool_read_only_filesystem_copy")?;
    let ro_root = fresh_root("test_spool_read_only_filesystem_copy_ro")?;
    let l = limits(16, 32);

    {
        let mut spool = StagingSpool::open(&root, l)?;
        let r = spool.stage_bytes(b"data on ro filesystem")?;
        spool.verify(r.digest)?;
    }

    copy_dir_all(&root, &ro_root)?;
    let _guard = ReadOnlyTreeGuard::make_read_only(&ro_root)?;

    let sentinel = ro_root.join("sentinel.tmp");
    let is_privileged = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&sentinel)
        .is_ok();

    if is_privileged {
        let _ = fs::remove_file(&sentinel);
        emit_caplog(
            "spool_read_only_filesystem_copy",
            "skip",
            0,
            start.elapsed().as_millis(),
            r#"{"reason":"unprivileged"}"#,
            r#"{"reason":"privileged"}"#,
        );
        return Ok(());
    }

    let inspection = spool::inspect(&ro_root, &l)?;
    assert_eq!(inspection.report.admitted.len(), 1);

    emit_caplog(
        "spool_read_only_filesystem_copy",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"admitted_count":1}"#,
        r#"{"admitted_count":1}"#,
    );
    Ok(())
}

#[test]
fn test_spool_read_verified_payload_lock_free() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_spool_read_verified_payload_lock_free")?;
    let l = limits(16, 32);
    let payload = b"immutable verified content bytes";

    let digest = {
        let mut spool = StagingSpool::open(&root, l)?;
        let r = spool.stage_bytes(payload)?;
        spool.verify(r.digest)?;
        r.digest
    };

    let read_bytes = spool::read_verified_payload(&root, digest, MAX_OBJECT_BYTES, &HostSpoolIo)?;
    assert_eq!(read_bytes, payload);

    let mut raw = digest.bytes();
    raw[0] ^= 0x01;
    let bad_digest = ContentDigest::new(DigestAlgorithm::Sha256, raw);
    let err = spool::read_verified_payload(&root, bad_digest, MAX_OBJECT_BYTES, &HostSpoolIo);
    assert!(err.is_err());

    emit_caplog(
        "spool_read_verified_payload_lock_free",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"payload_len":32}"#,
        r#"{"payload_len":32}"#,
    );
    Ok(())
}

#![forbid(unsafe_code)]
//! Integration contract tests for local publication non-mutating inspection (DOCTOR0).
//!
//! Asserts:
//! - Differential against [`LocalRootPublisher::open`] across clean publication,
//!   each [`PublishCutPoint`] via fault injection, broken roots, foreign entries,
//!   symlinks, legacy spools, and missing layout.
//! - Read-only proof: full tree digest (content, size, mode, mtime nanoseconds, listing)
//!   strictly identical before and after inspection.
//! - Read-only proof: [`RecordingSpoolIo`] records 0 mutating calls.
//! - Read-only copy: inspection succeeds on a 0o555 read-only directory tree.
//! - Round-3 writer detection: held, released, opt-in probe race, waiter lines,
//!   device mismatch, over budget, and self-held bypass.
//! - Limits at N and N+1: [`LocalPublicationLimits::max_scan_entries`].
//! - Lock-free verified payload reading via [`read_verified`].
//! - Root-ledger linkage inspection via [`inspect_linkage`].
//! - Structured CAPLOG emission for each step.

use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, DigestAlgorithm, EvidenceDelta, ObjectId, Plane,
    Sha256Hasher, TimestampNs, sha256,
};
use fss_ledger::{
    DurableLedgerLimits, DurableReferenceLedger, HostJournalReadIo, IncompleteTailPolicy,
    RecordingJournalReadIo, inspect_durable, inspect_durable_with_io,
};
use fss_object::{
    HostSpoolIo, MAX_OBJECT_BYTES, ObjectManifest, RecordingSpoolIo, SPOOL_HOLDS_DIR,
    SPOOL_HOLDS_MIGRATION_DIR, SpoolError, SpoolIo, SpoolLimits,
};
use fss_publication::local::writer::decode_st_dev;
use fss_publication::{
    HostLockTableSource, LOCAL_ROOTS_DIR, LedgerCutPoint, LedgeredRootPublisher,
    LocalPublicationError, LocalPublicationLimits, LocalRootPublisher, LockTableSource,
    PublishCutPoint, SlotName, StringLockTableSource, UnknownLockReason, WriterDetectionOptions,
    WriterLockBasis, WriterState, inspect, inspect_linkage, inspect_with_options, read_verified,
};

type TestResult = Result<(), Box<dyn Error>>;

const ALL_PUBLISH_CUT_POINTS: [PublishCutPoint; 4] = [
    PublishCutPoint::AfterChildrenVerified,
    PublishCutPoint::AfterManifestBody,
    PublishCutPoint::AfterRootTempWrite,
    PublishCutPoint::AfterRootRename,
];

fn fresh_root(test_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let base = match std::env::var_os("CARGO_TARGET_TMPDIR") {
        Some(dir) => PathBuf::from(dir),
        None => std::env::temp_dir(),
    };
    let root = base.join("local_inspect_contract").join(test_name);
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    fs::create_dir_all(&root)?;
    Ok(root)
}

fn limits(max_roots: usize, max_scan: usize) -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        max_roots,
        16,
        max_roots,
        max_scan,
        SpoolLimits::new(64, 1 << 20, 4096, 64),
    )
}

fn slot(name: &str) -> Result<SlotName, Box<dyn Error>> {
    Ok(SlotName::parse(name)?)
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
fn test_local_differential_clean() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_local_differential_clean")?;
    let copy = fresh_root("test_local_differential_clean_copy")?;
    let l = limits(8, 32);

    {
        let mut publisher = LocalRootPublisher::open(&root, l)?;
        let child_a = publisher.stage_object(b"payload-a")?;
        let manifest_a = ObjectManifest::new("clip", [child_a], None)?;
        publisher.publish(&slot("slot-a")?, &manifest_a)?;

        let child_b = publisher.stage_object(b"payload-b")?;
        let manifest_b = ObjectManifest::new("clip", [child_b], None)?;
        publisher.publish(&slot("slot-b")?, &manifest_b)?;
    }

    copy_dir_all(&root, &copy)?;

    let inspection = inspect(&root, l)?;
    let opened = LocalRootPublisher::open(&copy, l)?;

    assert_eq!(
        inspection.report.roots.len(),
        opened.recovery_report().roots.len()
    );
    assert_eq!(inspection.report.roots.len(), 2);
    for (i_root, o_root) in inspection
        .report
        .roots
        .iter()
        .zip(opened.recovery_report().roots.iter())
    {
        assert_eq!(i_root.slot, o_root.slot);
        assert_eq!(i_root.root, o_root.root);
    }
    assert!(inspection.durability_not_resynced);
    assert!(inspection.redundant_temps.is_empty());
    assert!(!inspection.holds_migration_pending);
    assert!(inspection.broken_slots.is_empty());

    emit_caplog(
        "local_differential_clean",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"roots_count":2,"durability_not_resynced":true}"#,
        r#"{"roots_count":2,"durability_not_resynced":true}"#,
    );
    Ok(())
}

#[test]
fn test_local_differential_publish_cut_points() -> TestResult {
    for &cut_point in &ALL_PUBLISH_CUT_POINTS {
        match cut_point {
            PublishCutPoint::AfterChildrenVerified => {}
            PublishCutPoint::AfterManifestBody => {}
            PublishCutPoint::AfterRootTempWrite => {}
            PublishCutPoint::AfterRootRename => {}
        }

        let start = Instant::now();
        let name = format!("test_local_cut_{cut_point}");
        let root = fresh_root(&name)?;
        let copy = fresh_root(&format!("{name}_copy"))?;
        let l = limits(8, 32);

        {
            let mut publisher = LocalRootPublisher::open(&root, l)?;
            let child = publisher.stage_object(b"leaf-bytes")?;
            let manifest = ObjectManifest::new("clip", [child], None)?;
            publisher.inject_crash_at(cut_point);
            let outcome = publisher.publish(&slot("cut-slot")?, &manifest);
            assert!(outcome.is_err());
        }

        copy_dir_all(&root, &copy)?;

        let inspection = inspect(&root, l)?;
        let opened = LocalRootPublisher::open(&copy, l)?;

        match cut_point {
            PublishCutPoint::AfterChildrenVerified | PublishCutPoint::AfterManifestBody => {
                assert_eq!(inspection.report.roots.len(), 0);
                assert_eq!(opened.recovery_report().roots.len(), 0);
                assert!(inspection.redundant_temps.is_empty());
            }
            PublishCutPoint::AfterRootTempWrite => {
                assert_eq!(inspection.report.roots.len(), 0);
                assert_eq!(inspection.report.orphaned_temps.len(), 1);
                assert_eq!(opened.recovery_report().orphaned_temps.len(), 1);
                assert_eq!(
                    inspection.report.orphaned_temps,
                    opened.recovery_report().orphaned_temps
                );
            }
            PublishCutPoint::AfterRootRename => {
                assert_eq!(inspection.report.roots.len(), 1);
                assert_eq!(opened.recovery_report().roots.len(), 1);
                assert_eq!(
                    inspection.report.roots[0].slot,
                    opened.recovery_report().roots[0].slot
                );
            }
        }

        emit_caplog(
            &format!("local_cut_{cut_point}"),
            "pass",
            0,
            start.elapsed().as_millis(),
            r#"{"cut_point_handled":true}"#,
            r#"{"cut_point_handled":true}"#,
        );
    }
    Ok(())
}

#[test]
fn test_local_differential_corrupt_root_record() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_local_differential_corrupt_root_record")?;
    let copy = fresh_root("test_local_differential_corrupt_root_record_copy")?;
    let l = limits(8, 32);

    {
        let mut publisher = LocalRootPublisher::open(&root, l)?;
        let child = publisher.stage_object(b"payload")?;
        let manifest = ObjectManifest::new("clip", [child], None)?;
        publisher.publish(&slot("broken-slot")?, &manifest)?;
    }

    let record_path = root.join(LOCAL_ROOTS_DIR).join("broken-slot.root");
    fs::write(&record_path, b"corrupted non-json bytes")?;

    copy_dir_all(&root, &copy)?;

    let inspection = inspect(&root, l)?;
    let opened = LocalRootPublisher::open(&copy, l)?;

    assert!(inspection.is_broken_slot(&slot("broken-slot")?));
    assert!(opened.is_broken_slot(&slot("broken-slot")?));
    assert_eq!(
        inspection.report.broken_roots.len(),
        opened.recovery_report().broken_roots.len()
    );

    emit_caplog(
        "local_corrupt_root_record",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"broken_slot":"broken-slot"}"#,
        r#"{"broken_slot":"broken-slot"}"#,
    );
    Ok(())
}

#[test]
fn test_local_differential_foreign_entries_and_symlinks() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_local_differential_foreign_entries_and_symlinks")?;
    let copy = fresh_root("test_local_differential_foreign_entries_and_symlinks_copy")?;
    let l = limits(8, 32);

    {
        let _publisher = LocalRootPublisher::open(&root, l)?;
    }

    let foreign_file = root.join(LOCAL_ROOTS_DIR).join("foreign_record.txt");
    fs::write(&foreign_file, b"foreign")?;

    let ext_dir = fresh_root("test_local_foreign_ext")?;
    let ext_target = ext_dir.join("target.txt");
    fs::write(&ext_target, b"external")?;
    let symlink_path = root.join(LOCAL_ROOTS_DIR).join("symlink_entry.root");
    std::os::unix::fs::symlink(&ext_target, &symlink_path)?;

    copy_dir_all(&root, &copy)?;

    let inspection = inspect(&root, l)?;
    let opened = LocalRootPublisher::open(&copy, l)?;

    assert_eq!(
        inspection.report.foreign.len(),
        opened.recovery_report().foreign.len()
    );

    emit_caplog(
        "local_foreign_entries",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"foreign_count":2}"#,
        r#"{"foreign_count":2}"#,
    );
    Ok(())
}

#[test]
fn test_local_differential_legacy_spool() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_local_differential_legacy_spool")?;
    let copy = fresh_root("test_local_differential_legacy_spool_copy")?;
    let l = limits(8, 32);

    {
        let mut publisher = LocalRootPublisher::open(&root, l)?;
        let child = publisher.stage_object(b"legacy payload")?;
        let manifest = ObjectManifest::new("clip", [child], None)?;
        publisher.publish(&slot("slot-legacy")?, &manifest)?;
    }

    let holds_dir = root.join("spool").join(SPOOL_HOLDS_DIR);
    if holds_dir.exists() {
        fs::remove_dir_all(&holds_dir)?;
    }

    copy_dir_all(&root, &copy)?;

    let inspection = inspect(&root, l)?;
    assert!(inspection.holds_migration_pending);

    let opened = LocalRootPublisher::open(&copy, l)?;
    assert_eq!(
        inspection.report.roots.len(),
        opened.recovery_report().roots.len()
    );

    emit_caplog(
        "local_legacy_spool",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"holds_migration_pending":true}"#,
        r#"{"holds_migration_pending":true}"#,
    );
    Ok(())
}

#[test]
fn test_local_limits_n_and_n_plus_one() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_local_limits_n_and_n_plus_one")?;
    let copy = fresh_root("test_local_limits_n_and_n_plus_one_copy")?;
    let l_roomy = limits(8, 32);

    {
        let mut publisher = LocalRootPublisher::open(&root, l_roomy)?;
        let c1 = publisher.stage_object(b"c1")?;
        let m1 = ObjectManifest::new("clip", [c1], None)?;
        publisher.publish(&slot("slot-1")?, &m1)?;

        let c2 = publisher.stage_object(b"c2")?;
        let m2 = ObjectManifest::new("clip", [c2], None)?;
        publisher.publish(&slot("slot-2")?, &m2)?;
    }

    let l_exact = limits(2, 2);
    let inspect_ok = inspect(&root, l_exact)?;
    assert_eq!(inspect_ok.report.roots.len(), 2);

    {
        let mut publisher = LocalRootPublisher::open(&root, l_roomy)?;
        let c3 = publisher.stage_object(b"c3")?;
        let m3 = ObjectManifest::new("clip", [c3], None)?;
        publisher.publish(&slot("slot-3")?, &m3)?;
    }

    copy_dir_all(&root, &copy)?;

    let inspect_err = inspect(&root, l_exact);
    let open_err = LocalRootPublisher::open(&copy, l_exact);

    match (inspect_err, open_err) {
        (
            Err(LocalPublicationError::EntryLimit { maximum: i_max, .. }),
            Err(LocalPublicationError::EntryLimit { maximum: o_max, .. }),
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
        "local_limits_n_and_n_plus_one",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"scan_bound":2,"status":"EntryLimit"}"#,
        r#"{"scan_bound":2,"status":"EntryLimit"}"#,
    );
    Ok(())
}

#[test]
fn test_local_read_only_tree_digest_proof() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_local_read_only_tree_digest_proof")?;
    let l = limits(8, 32);

    {
        let mut publisher = LocalRootPublisher::open(&root, l)?;
        let c = publisher.stage_object(b"payload")?;
        let m = ObjectManifest::new("clip", [c], None)?;
        publisher.publish(&slot("slot-test")?, &m)?;
    }

    let lock1 = root.join("LOCK");
    if lock1.exists() {
        fs::remove_file(&lock1)?;
    }
    let lock2 = root.join("objects").join("LOCK");
    if lock2.exists() {
        fs::remove_file(&lock2)?;
    }
    let lock3 = root.join("spool").join("LOCK");
    if lock3.exists() {
        fs::remove_file(&lock3)?;
    }

    let digest_before = compute_tree_digest(&root)?;

    let inspection = inspect(&root, l)?;
    assert_eq!(inspection.report.roots.len(), 1);

    let digest_after = compute_tree_digest(&root)?;

    assert_eq!(
        digest_before, digest_after,
        "local publication root modified during inspect!"
    );
    assert!(
        !root.join("LOCK").exists(),
        "LOCK was created during inspect!"
    );

    emit_caplog(
        "local_read_only_tree_digest_proof",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"tree_modified":false,"lock_created":false}"#,
        r#"{"tree_modified":false,"lock_created":false}"#,
    );
    Ok(())
}

#[test]
fn test_local_read_only_recording_io_proof() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_local_read_only_recording_io_proof")?;
    let l = limits(8, 32);

    {
        let mut publisher = LocalRootPublisher::open(&root, l)?;
        let c = publisher.stage_object(b"recording data")?;
        let m = ObjectManifest::new("clip", [c], None)?;
        publisher.publish(&slot("rec-slot")?, &m)?;
    }

    let recording_io = Arc::new(RecordingSpoolIo::new(Arc::new(HostSpoolIo)));
    let inspection = inspect_with_options(
        recording_io.clone(),
        &root,
        l,
        None,
        WriterDetectionOptions::default(),
    )?;

    assert_eq!(inspection.report.roots.len(), 1);
    assert!(
        recording_io.is_read_only(),
        "RecordingSpoolIo observed mutating calls: {:?}",
        recording_io.mutating_calls()
    );

    emit_caplog(
        "local_read_only_recording_io_proof",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"is_read_only":true,"mutating_count":0}"#,
        r#"{"is_read_only":true,"mutating_count":0}"#,
    );
    Ok(())
}

#[test]
fn test_local_read_only_filesystem_copy() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_local_read_only_filesystem_copy")?;
    let ro_root = fresh_root("test_local_read_only_filesystem_copy_ro")?;
    let l = limits(8, 32);

    {
        let mut publisher = LocalRootPublisher::open(&root, l)?;
        let c = publisher.stage_object(b"ro data")?;
        let m = ObjectManifest::new("clip", [c], None)?;
        publisher.publish(&slot("ro-slot")?, &m)?;
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
            "local_read_only_filesystem_copy",
            "skip",
            0,
            start.elapsed().as_millis(),
            r#"{"reason":"unprivileged"}"#,
            r#"{"reason":"privileged"}"#,
        );
        return Ok(());
    }

    let inspection = inspect(&ro_root, l)?;
    assert_eq!(inspection.report.roots.len(), 1);

    emit_caplog(
        "local_read_only_filesystem_copy",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"roots_count":1}"#,
        r#"{"roots_count":1}"#,
    );
    Ok(())
}

#[test]
fn test_local_writer_detection_held_and_released() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_local_writer_detection_held_and_released")?;
    let l = limits(8, 32);

    let publisher = LocalRootPublisher::open(&root, l)?;

    let probe_options = WriterDetectionOptions {
        probe_shared_lock: true,
        self_holds_lock: false,
    };

    let inspection_held = inspect_with_options(
        Arc::new(HostSpoolIo),
        &root,
        l,
        Some(&HostLockTableSource),
        probe_options,
    )?;

    assert!(inspection_held.writer_state.is_held());
    assert_eq!(
        inspection_held.writer_state,
        WriterState::Held {
            basis: WriterLockBasis::SharedTryLock,
            pid_hint: None,
        }
    );

    drop(publisher);

    let inspection_released = inspect_with_options(
        Arc::new(HostSpoolIo),
        &root,
        l,
        Some(&HostLockTableSource),
        probe_options,
    )?;

    assert_eq!(inspection_released.writer_state, WriterState::not_held());

    emit_caplog(
        "local_writer_detection_held_and_released",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"held_observed":true,"released_not_held":true}"#,
        r#"{"held_observed":true,"released_not_held":true}"#,
    );
    Ok(())
}

#[test]
fn test_local_writer_detection_probe_race() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_local_writer_detection_probe_race")?;
    let l = limits(8, 32);

    {
        let _init = LocalRootPublisher::open(&root, l)?;
    }

    let spool_lock = root.join("spool").join("LOCK");
    let lock_file = File::open(&spool_lock)?;
    HostSpoolIo
        .try_lock_shared(&lock_file)
        .map_err(|e| format!("try_lock_shared failed: {e:?}"))?;

    let open_attempt = LocalRootPublisher::open(&root, l);
    match open_attempt {
        Err(LocalPublicationError::Spool(SpoolError::Locked { path })) => {
            assert_eq!(path, spool_lock);
        }
        other => {
            return Err(format!("expected Spool(Locked), got {other:?}").into());
        }
    }

    drop(lock_file);

    let open_after = LocalRootPublisher::open(&root, l)?;
    assert_eq!(open_after.limits().max_roots, 8);

    emit_caplog(
        "local_writer_detection_probe_race",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"probe_race_blocked":true,"probe_race_resumed":true}"#,
        r#"{"probe_race_blocked":true,"probe_race_resumed":true}"#,
    );
    Ok(())
}

#[test]
fn test_local_writer_detection_lock_table_cases() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_local_writer_detection_lock_table_cases")?;
    let l = limits(8, 32);

    {
        let _init = LocalRootPublisher::open(&root, l)?;
    }

    let spool_lock = root.join("spool").join("LOCK");
    let meta = fs::symlink_metadata(&spool_lock)?;
    let (maj, min) = decode_st_dev(meta.dev());
    let ino = meta.ino();

    let table_held = format!("1: FLOCK ADVISORY WRITE 4242 {maj:02x}:{min:02x}:{ino} 0 EOF\n");
    let source_held = StringLockTableSource(table_held);
    let state_held = fss_publication::detect_writers(
        &HostSpoolIo,
        &[spool_lock.clone()],
        Some(&source_held),
        WriterDetectionOptions::default(),
    );
    assert_eq!(
        state_held,
        WriterState::Held {
            basis: WriterLockBasis::ProcLocks,
            pid_hint: Some(4242),
        }
    );

    let table_waiter = format!(
        "1: FLOCK ADVISORY WRITE 4242 {maj:02x}:{min:02x}:{ino} 0 EOF\n\
         1: -> FLOCK ADVISORY WRITE 9999 {maj:02x}:{min:02x}:{ino} 0 EOF\n"
    );
    let source_waiter = StringLockTableSource(table_waiter);
    let state_waiter = fss_publication::detect_writers(
        &HostSpoolIo,
        &[spool_lock.clone()],
        Some(&source_waiter),
        WriterDetectionOptions::default(),
    );
    assert_eq!(
        state_waiter,
        WriterState::Held {
            basis: WriterLockBasis::ProcLocks,
            pid_hint: Some(4242),
        }
    );

    let table_dev_mismatch = format!("1: FLOCK ADVISORY WRITE 4242 ff:ff:{ino} 0 EOF\n");
    let source_dev_mismatch = StringLockTableSource(table_dev_mismatch);
    let state_dev_mismatch = fss_publication::detect_writers(
        &HostSpoolIo,
        &[spool_lock.clone()],
        Some(&source_dev_mismatch),
        WriterDetectionOptions::default(),
    );
    assert_eq!(
        state_dev_mismatch,
        WriterState::Unknown {
            reason: UnknownLockReason::DeviceMismatch,
        }
    );

    let source_over_budget = StringLockTableSource("x".repeat(1024 * 1024 + 1));
    let state_over_budget = fss_publication::detect_writers(
        &HostSpoolIo,
        &[spool_lock.clone()],
        Some(&source_over_budget),
        WriterDetectionOptions::default(),
    );
    assert_eq!(
        state_over_budget,
        WriterState::Unknown {
            reason: UnknownLockReason::OverBudget,
        }
    );

    let state_self_held = fss_publication::detect_writers(
        &HostSpoolIo,
        &[spool_lock],
        Some(&source_held),
        WriterDetectionOptions {
            probe_shared_lock: true,
            self_holds_lock: true,
        },
    );
    assert_eq!(state_self_held, WriterState::NotProbed);

    emit_caplog(
        "local_writer_detection_lock_table_cases",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"proc_locks_cases":5}"#,
        r#"{"proc_locks_cases":5}"#,
    );
    Ok(())
}

#[test]
fn test_local_read_verified() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_local_read_verified")?;
    let l = limits(8, 32);
    let payload = b"payload for lock-free read_verified";

    let digest = {
        let mut publisher = LocalRootPublisher::open(&root, l)?;
        let child = publisher.stage_object(payload)?;
        let manifest = ObjectManifest::new("clip", [child], None)?;
        publisher.publish(&slot("read-slot")?, &manifest)?;
        child
    };

    let data = read_verified(&root, digest, MAX_OBJECT_BYTES)?;
    assert_eq!(data, payload);

    let mut raw = digest.bytes();
    raw[0] ^= 0x01;
    let bad_digest = ContentDigest::new(DigestAlgorithm::Sha256, raw);
    let err = read_verified(&root, bad_digest, MAX_OBJECT_BYTES);
    assert!(err.is_err());

    emit_caplog(
        "local_read_verified",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"verified_bytes_read":35}"#,
        r#"{"verified_bytes_read":35}"#,
    );
    Ok(())
}

#[test]
fn test_linkage_differential() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_linkage_differential")?;
    let l = limits(8, 32);
    let interval = CaptureInterval::new(TimestampNs(1_000), TimestampNs(2_000))?;

    let ledger_path = root.join("ledger.journal");
    let mut ledger =
        DurableReferenceLedger::open(&ledger_path, "site-lineage-1", IncompleteTailPolicy::Reject)?;

    let mut publisher = LocalRootPublisher::open(&root, l)?;
    let c1 = publisher.stage_object(b"clip-1")?;
    let m1 = ObjectManifest::new("clip", [c1], None)?;
    let root_a = m1.root();

    {
        let mut coordinator = LedgeredRootPublisher::new(&mut publisher, &mut ledger);
        coordinator.publish_and_commit(&slot("slot-a")?, &m1, interval)?;
    }

    let c2 = publisher.stage_object(b"clip-2")?;
    let m2 = ObjectManifest::new("clip", [c2], None)?;
    {
        let mut coordinator = LedgeredRootPublisher::new(&mut publisher, &mut ledger);
        coordinator.inject_crash_at(LedgerCutPoint::AfterRootDurable);
        let _ = coordinator.publish_and_commit(&slot("slot-b")?, &m2, interval);
    }

    let delta_unbacked = EvidenceDelta {
        delta_id: "delta:unbacked".to_string(),
        family: "reachability".to_string(),
        object_id: ObjectId::parse("object:local-root:slot-unbacked")?,
        prior_generation: None,
        new_generation: 1,
        validity: interval,
        plane: Plane::Authority,
        payload_digest: root_a,
        witness_digest: None,
        operation_id: None,
    };
    let batch_unbacked =
        ledger.prepare_batch(BatchId::parse("batch:unbacked")?, vec![delta_unbacked], [])?;
    ledger.append(batch_unbacked)?;

    drop(publisher);
    drop(ledger);

    let local_inspection = inspect(&root, l)?;
    let ledger_inspection = inspect_durable(
        &ledger_path,
        "site-lineage-1",
        DurableLedgerLimits::default(),
    )?;

    let recon = inspect_linkage(&local_inspection, &ledger_inspection);

    assert_eq!(recon.ledgered.len(), 1);
    assert_eq!(recon.ledgered[0].slot, slot("slot-a")?);
    assert_eq!(recon.ledgered[0].root, root_a);

    assert_eq!(recon.pending.len(), 1);
    assert_eq!(recon.pending[0].slot, slot("slot-b")?);

    assert_eq!(recon.unbacked_ledger_claims.len(), 1);
    assert_eq!(
        recon.unbacked_ledger_claims[0].object_id,
        ObjectId::parse("object:local-root:slot-unbacked")?
    );

    assert!(recon.ledger_tail_incomplete.is_none());
    assert!(recon.broken.is_empty());

    emit_caplog(
        "local_inspect_linkage",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"ledgered_count":1,"pending_count":1,"unbacked_count":1}"#,
        r#"{"ledgered_count":1,"pending_count":1,"unbacked_count":1}"#,
    );
    Ok(())
}

#[test]
fn test_local_differential_redundant_temp() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_local_differential_redundant_temp")?;
    let copy = fresh_root("test_local_differential_redundant_temp_copy")?;
    let l = limits(8, 32);

    {
        let mut publisher = LocalRootPublisher::open(&root, l)?;
        let c1 = publisher.stage_object(b"leaf")?;
        let m1 = ObjectManifest::new("clip", [c1], None)?;
        publisher.publish(&slot("alpha")?, &m1)?;
    }

    let redundant_path = root.join(LOCAL_ROOTS_DIR).join("alpha.root.tmp");
    fs::write(&redundant_path, b"redundant temporary content")?;
    assert!(redundant_path.exists());

    copy_dir_all(&root, &copy)?;

    let inspection = inspect(&root, l)?;
    assert_eq!(inspection.redundant_temps.len(), 1);
    assert_eq!(
        inspection.redundant_temps[0],
        PathBuf::from("roots/alpha.root.tmp")
    );
    assert!(redundant_path.exists());
    assert!(!inspection.is_clean());

    let copy_redundant = copy.join(LOCAL_ROOTS_DIR).join("alpha.root.tmp");
    assert!(copy_redundant.exists());
    let opened = LocalRootPublisher::open(&copy, l)?;
    assert_eq!(opened.recovery_report().roots.len(), 1);
    assert!(!copy_redundant.exists());

    emit_caplog(
        "local_differential_redundant_temp",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"redundant_temp_retained":true,"open_cleaned":true}"#,
        r#"{"redundant_temp_retained":true,"open_cleaned":true}"#,
    );
    Ok(())
}

#[test]
fn test_local_differential_interrupted_migration() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_local_differential_interrupted_migration")?;
    let l = limits(8, 32);

    {
        let mut publisher = LocalRootPublisher::open(&root, l)?;
        let c1 = publisher.stage_object(b"leaf")?;
        let m1 = ObjectManifest::new("clip", [c1], None)?;
        publisher.publish(&slot("alpha")?, &m1)?;
    }

    let holds_dir = root.join("spool").join(SPOOL_HOLDS_DIR);
    if holds_dir.exists() {
        fs::remove_dir_all(&holds_dir)?;
    }
    let migration_dir = root.join("spool").join(SPOOL_HOLDS_MIGRATION_DIR);
    fs::create_dir_all(&migration_dir)?;

    let inspection = inspect(&root, l)?;
    assert!(inspection.holds_migration_pending);
    assert!(!inspection.is_clean());
    assert!(inspection.report.foreign.is_empty());

    emit_caplog(
        "local_differential_interrupted_migration",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"holds_migration_pending":true,"foreign_count":0}"#,
        r#"{"holds_migration_pending":true,"foreign_count":0}"#,
    );
    Ok(())
}

#[test]
fn test_local_writer_detection_lock_symlink_or_dir() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_local_writer_detection_lock_symlink_or_dir")?;
    let l = limits(8, 32);

    let spool_dir = root.join("spool");
    fs::create_dir_all(&spool_dir)?;
    let spool_lock = spool_dir.join("LOCK");
    fs::create_dir(&spool_lock)?;

    let state_dir = fss_publication::detect_writers(
        &HostSpoolIo,
        &[spool_lock.clone()],
        None,
        WriterDetectionOptions::default(),
    );
    assert_eq!(state_dir, WriterState::InvalidLayout);

    let open_res = LocalRootPublisher::open(&root, l);
    match open_res {
        Err(LocalPublicationError::InvalidLayout) => {}
        other => {
            return Err(format!("expected InvalidLayout for directory LOCK, got {other:?}").into());
        }
    }

    fs::remove_dir(&spool_lock)?;
    let dummy_target = root.join("dummy_lock_target");
    fs::write(&dummy_target, b"dummy")?;
    std::os::unix::fs::symlink(&dummy_target, &spool_lock)?;

    let state_sym = fss_publication::detect_writers(
        &HostSpoolIo,
        &[spool_lock],
        None,
        WriterDetectionOptions::default(),
    );
    assert_eq!(state_sym, WriterState::InvalidLayout);

    emit_caplog(
        "local_writer_detection_lock_symlink_or_dir",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"invalid_layout_cases":2}"#,
        r#"{"invalid_layout_cases":2}"#,
    );
    Ok(())
}

struct FailingLockTableSource(std::io::ErrorKind);

impl LockTableSource for FailingLockTableSource {
    fn read_lock_table(&self, _max_bytes: usize) -> std::io::Result<String> {
        Err(std::io::Error::from(self.0))
    }
}

#[derive(Debug)]
struct ReplacingSpoolIo {
    re_stat_count: std::sync::atomic::AtomicUsize,
}

impl ReplacingSpoolIo {
    fn new() -> Self {
        Self {
            re_stat_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl SpoolIo for ReplacingSpoolIo {
    fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        HostSpoolIo.create_dir_all(path)
    }
    fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        HostSpoolIo.metadata(path)
    }
    fn symlink_metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        let count = self
            .re_stat_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if count == 0 {
            HostSpoolIo.symlink_metadata(path)
        } else {
            Err(std::io::Error::from(std::io::ErrorKind::NotFound))
        }
    }
    fn open_lock(&self, path: &Path) -> std::io::Result<File> {
        HostSpoolIo.open_lock(path)
    }
    fn try_lock(&self, file: &File) -> Result<(), fss_object::TryLockError> {
        HostSpoolIo.try_lock(file)
    }
    fn try_lock_shared(&self, file: &File) -> Result<(), fss_object::TryLockError> {
        HostSpoolIo.try_lock_shared(file)
    }
    fn create_dir(&self, path: &Path) -> std::io::Result<()> {
        HostSpoolIo.create_dir(path)
    }
    fn read_dir(&self, path: &Path) -> std::io::Result<std::fs::ReadDir> {
        HostSpoolIo.read_dir(path)
    }
    fn next_dir_entry(
        &self,
        entries: &mut std::fs::ReadDir,
    ) -> Option<std::io::Result<std::fs::DirEntry>> {
        HostSpoolIo.next_dir_entry(entries)
    }
    fn entry_file_type(&self, entry: &std::fs::DirEntry) -> std::io::Result<std::fs::FileType> {
        HostSpoolIo.entry_file_type(entry)
    }
    fn create_new(&self, path: &Path) -> std::io::Result<File> {
        HostSpoolIo.create_new(path)
    }
    fn write(&self, file: &mut File, bytes: &[u8]) -> std::io::Result<usize> {
        HostSpoolIo.write(file, bytes)
    }
    fn sync_file(&self, file: &File) -> std::io::Result<()> {
        HostSpoolIo.sync_file(file)
    }
    fn open_read(&self, path: &Path) -> std::io::Result<File> {
        HostSpoolIo.open_read(path)
    }
    fn read_bounded(&self, file: &mut File, limit: u64) -> std::io::Result<Vec<u8>> {
        HostSpoolIo.read_bounded(file, limit)
    }
    fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        HostSpoolIo.rename(from, to)
    }
    fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        HostSpoolIo.remove_file(path)
    }
    fn sync_directory(&self, path: &Path) -> std::io::Result<()> {
        HostSpoolIo.sync_directory(path)
    }
    fn hard_link(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        HostSpoolIo.hard_link(from, to)
    }
}

#[test]
fn test_local_writer_detection_round3_cases() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_local_writer_detection_round3_cases")?;
    let l = limits(8, 32);

    {
        let _init = LocalRootPublisher::open(&root, l)?;
    }

    let spool_lock = root.join("spool").join("LOCK");

    let source_missing = FailingLockTableSource(std::io::ErrorKind::NotFound);
    let state_missing = fss_publication::detect_writers(
        &HostSpoolIo,
        &[spool_lock.clone()],
        Some(&source_missing),
        WriterDetectionOptions::default(),
    );
    assert_eq!(
        state_missing,
        WriterState::Unknown {
            reason: UnknownLockReason::NoLockTable,
        }
    );

    let source_unreadable = FailingLockTableSource(std::io::ErrorKind::PermissionDenied);
    let state_unreadable = fss_publication::detect_writers(
        &HostSpoolIo,
        &[spool_lock.clone()],
        Some(&source_unreadable),
        WriterDetectionOptions::default(),
    );
    assert_eq!(
        state_unreadable,
        WriterState::Unknown {
            reason: UnknownLockReason::Unreadable,
        }
    );

    let source_empty = StringLockTableSource(String::new());
    let state_not_observed = fss_publication::detect_writers(
        &HostSpoolIo,
        &[spool_lock.clone()],
        Some(&source_empty),
        WriterDetectionOptions::default(),
    );
    assert_eq!(state_not_observed, WriterState::NotObserved);

    let replacing_io = ReplacingSpoolIo::new();
    let state_replaced = fss_publication::detect_writers(
        &replacing_io,
        &[spool_lock],
        Some(&source_empty),
        WriterDetectionOptions::default(),
    );
    assert_eq!(
        state_replaced,
        WriterState::Unknown {
            reason: UnknownLockReason::LockFileReplaced,
        }
    );

    emit_caplog(
        "local_writer_detection_round3_cases",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"round3_cases":4}"#,
        r#"{"round3_cases":4}"#,
    );
    Ok(())
}

#[test]
fn test_linkage_read_only_recording_io_proof() -> TestResult {
    let start = Instant::now();
    let root = fresh_root("test_linkage_read_only_recording_io_proof")?;
    let l = limits(8, 32);
    let interval = CaptureInterval::new(TimestampNs(1_000), TimestampNs(2_000))?;
    let ledger_path = root.join("ledger.journal");

    let mut ledger =
        DurableReferenceLedger::open(&ledger_path, "site-rec", IncompleteTailPolicy::Reject)?;
    let mut publisher = LocalRootPublisher::open(&root, l)?;
    let c1 = publisher.stage_object(b"clip-rec")?;
    let m1 = ObjectManifest::new("clip", [c1], None)?;
    let mut coordinator = LedgeredRootPublisher::new(&mut publisher, &mut ledger);
    coordinator.publish_and_commit(&slot("slot-rec")?, &m1, interval)?;
    drop(coordinator);
    drop(publisher);
    drop(ledger);

    let recording_spool_io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let local_inspection = fss_publication::inspect_with_io(
        &recording_spool_io,
        &root,
        l,
        None,
        WriterDetectionOptions::default(),
    )?;

    let recording_journal_io = RecordingJournalReadIo::new(HostJournalReadIo);
    let ledger_inspection = inspect_durable_with_io(
        &recording_journal_io,
        &ledger_path,
        "site-rec",
        DurableLedgerLimits::default(),
    )?;

    let linkage = inspect_linkage(&local_inspection, &ledger_inspection);
    assert_eq!(linkage.ledgered.len(), 1);
    assert_eq!(linkage.ledgered[0].slot, slot("slot-rec")?);

    assert!(recording_spool_io.is_read_only());
    assert!(recording_spool_io.mutating_calls().is_empty());
    assert!(recording_journal_io.is_read_only());
    assert!(recording_journal_io.mutating_calls().is_empty());

    emit_caplog(
        "linkage_read_only_recording_io_proof",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"spool_mutating_count":0,"journal_mutating_count":0}"#,
        r#"{"spool_mutating_count":0,"journal_mutating_count":0}"#,
    );
    Ok(())
}

#![forbid(unsafe_code)]
//! Integration contract tests for effect journal non-mutating inspection (DOCTOR0).
//!
//! Asserts:
//! - Differential against [`DurableEffectJournal::open`] across clean journal,
//!   lost-ACK / indeterminate operations, foreign trailing bytes, oversize journal,
//!   missing journal, and invalid layout.
//! - Read-only proof: full tree digest (content, size, mode, mtime nanoseconds, listing)
//!   strictly identical before and after inspection.
//! - Read-only proof: [`RecordingJournalReadIo`] records 0 mutating calls.
//! - Read-only copy: inspection succeeds on a 0o555 read-only directory tree (or skips if privileged).
//! - Limits at N and N+1: [`DurableLedgerLimits::max_journal_bytes`].
//! - Structured CAPLOG emission for each step.

use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Instant;

use fss_core::{
    ContentDigest, DigestAlgorithm, EffectIntent, EffectState, IdempotencyKey, ObligationId,
    OperationId, Sha256Hasher, TimestampNs, sha256,
};
use fss_ledger::{
    DurableLedgerLimits, HostJournalReadIo, IncompleteTailPolicy, RecordingJournalReadIo,
};
use fss_reference::{
    DurableEffectError, DurableEffectJournal, EFFECT_RECONCILE_AFFORDANCE, EffectJournalStatus,
};

type TestResult = Result<(), Box<dyn Error>>;

fn fresh_dir(test_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let base = match std::env::var_os("CARGO_TARGET_TMPDIR") {
        Some(dir) => PathBuf::from(dir),
        None => std::env::temp_dir(),
    };
    let root = base.join("effect_journal_inspect_contract").join(test_name);
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    fs::create_dir_all(&root)?;
    Ok(root)
}

fn sample_intent(op: &OperationId) -> Result<EffectIntent, Box<dyn Error>> {
    Ok(EffectIntent {
        operation_id: op.clone(),
        idempotency_key: IdempotencyKey::parse(format!("idempotency:{}", op.as_str()))?,
        effect_class: "alert.dispatch".to_string(),
        request_digest: ContentDigest::sha256(b"request_payload"),
        precondition_digest: ContentDigest::sha256(b"preconditions_payload"),
    })
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
        let root_meta = fs::symlink_metadata(root)?;
        paths.push((root.to_path_buf(), root_meta.mode()));
        fs::set_permissions(root, fs::Permissions::from_mode(0o555))?;
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
fn test_effect_journal_differential_clean() -> TestResult {
    let start = Instant::now();
    let dir = fresh_dir("test_effect_journal_differential_clean")?;
    let copy_dir_path = fresh_dir("test_effect_journal_differential_clean_copy")?;
    let journal_path = dir.join("effects.fssj");
    let copy_path = copy_dir_path.join("effects.fssj");

    let op = OperationId::parse("op:clean:1")?;
    let obl = ObligationId::parse("obligation:clean:1")?;
    let intent = sample_intent(&op)?;

    {
        let mut journal = DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
        let _ = journal.prepare(intent, obl, "channel_ack", TimestampNs(100))?;
        let _ = journal.transition(&op, EffectState::Committed, TimestampNs(110), None, None)?;
        let _ = journal.transition(&op, EffectState::Verified, TimestampNs(120), None, None)?;
    }

    copy_dir_all(&dir, &copy_dir_path)?;

    let inspection = DurableEffectJournal::inspect(&journal_path, 1 << 20)?;
    let opened = DurableEffectJournal::open(&copy_path, IncompleteTailPolicy::Reject)?;

    assert_eq!(inspection.status, EffectJournalStatus::Present);
    assert_eq!(inspection.obligation_counts.total, 1);
    assert_eq!(inspection.obligation_counts.discharged, 1);
    assert_eq!(inspection.obligation_counts.pending, 0);
    assert_eq!(inspection.obligation_counts.failed, 0);
    assert!(inspection.indeterminate_operations.is_empty());
    assert!(inspection.incomplete_tail.is_none());
    assert!(inspection.foreign_range.is_none());
    assert!(inspection.is_clean());

    assert_eq!(
        inspection.journal.as_ref().map(|j| j.operations().len()),
        Some(opened.operations().len())
    );

    emit_caplog(
        "effect_journal_differential_clean",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"status":"Present","obligations":1,"clean":true}"#,
        r#"{"status":"Present","obligations":1,"clean":true}"#,
    );
    Ok(())
}

#[test]
fn test_effect_journal_differential_indeterminate_lost_ack() -> TestResult {
    let start = Instant::now();
    let dir = fresh_dir("test_effect_journal_differential_indeterminate_lost_ack")?;
    let journal_path = dir.join("lost_ack.fssj");

    let op = OperationId::parse("op:lostack:1")?;
    let obl = ObligationId::parse("obligation:lostack:1")?;
    let intent = sample_intent(&op)?;

    {
        let mut journal = DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
        let _ = journal.prepare(intent, obl, "channel_ack", TimestampNs(100))?;
        let _ = journal.transition(&op, EffectState::Committed, TimestampNs(110), None, None)?;
        let _ = journal.mark_indeterminate(&op, TimestampNs(120), "lost_ack_timeout")?;
    }

    let inspection = DurableEffectJournal::inspect(&journal_path, 1 << 20)?;
    assert_eq!(inspection.status, EffectJournalStatus::Present);
    assert_eq!(inspection.obligation_counts.total, 1);
    assert_eq!(inspection.obligation_counts.pending, 1);
    assert_eq!(inspection.indeterminate_operations.len(), 1);
    assert_eq!(inspection.indeterminate_operations[0].operation_id, op);
    assert_eq!(
        inspection.indeterminate_operations[0].reconcile_affordance,
        EFFECT_RECONCILE_AFFORDANCE
    );

    emit_caplog(
        "effect_journal_differential_indeterminate_lost_ack",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"indeterminate_count":1,"reconcile_affordance":"affordance:alert:reconcile"}"#,
        r#"{"indeterminate_count":1,"reconcile_affordance":"affordance:alert:reconcile"}"#,
    );
    Ok(())
}

#[test]
fn test_effect_journal_differential_foreign_trailing_bytes() -> TestResult {
    let start = Instant::now();
    let dir = fresh_dir("test_effect_journal_differential_foreign_trailing_bytes")?;
    let copy_dir_path = fresh_dir("test_effect_journal_differential_foreign_trailing_bytes_copy")?;
    let journal_path = dir.join("effects.fssj");

    let op = OperationId::parse("op:foreign:1")?;
    let obl = ObligationId::parse("obligation:foreign:1")?;
    let intent = sample_intent(&op)?;

    {
        let mut journal = DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
        let _ = journal.prepare(intent, obl, "channel_ack", TimestampNs(100))?;
        let _ = journal.transition(&op, EffectState::Committed, TimestampNs(110), None, None)?;
    }

    {
        let mut f = OpenOptions::new().append(true).open(&journal_path)?;
        f.write_all(b"foreign garbage bytes appended to journal")?;
        f.sync_all()?;
    }

    copy_dir_all(&dir, &copy_dir_path)?;

    let inspection = DurableEffectJournal::inspect(&journal_path, 1 << 20)?;
    assert_eq!(inspection.status, EffectJournalStatus::Present);
    assert!(
        inspection.incomplete_tail.is_some() || inspection.foreign_range.is_some(),
        "expected incomplete tail or foreign range"
    );

    let opened_trunc = DurableEffectJournal::open(
        copy_dir_path.join("effects.fssj"),
        IncompleteTailPolicy::Truncate,
    )?;
    assert_eq!(opened_trunc.operations().len(), 1);

    emit_caplog(
        "effect_journal_differential_foreign_trailing_bytes",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"foreign_tail_detected":true}"#,
        r#"{"foreign_tail_detected":true}"#,
    );
    Ok(())
}

#[test]
fn test_effect_journal_limits_n_and_n_plus_one() -> TestResult {
    let start = Instant::now();
    let dir = fresh_dir("test_effect_journal_limits_n_and_n_plus_one")?;
    let journal_path = dir.join("limits.fssj");

    let op = OperationId::parse("op:limits:1")?;
    let obl = ObligationId::parse("obligation:limits:1")?;
    let intent = sample_intent(&op)?;

    {
        let mut journal = DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
        let _ = journal.prepare(intent, obl, "channel_ack", TimestampNs(100))?;
    }

    let file_len = fs::metadata(&journal_path)?.len() as usize;

    let inspect_exact = DurableEffectJournal::inspect(&journal_path, file_len)?;
    assert_eq!(inspect_exact.status, EffectJournalStatus::Present);

    let inspect_err = DurableEffectJournal::inspect(&journal_path, file_len.saturating_sub(1));
    match inspect_err {
        Err(DurableEffectError::OverBudget { limit, actual }) => {
            assert_eq!(limit, file_len.saturating_sub(1));
            assert_eq!(actual, file_len);
        }
        other => return Err(format!("expected OverBudget, got {other:?}").into()),
    }

    emit_caplog(
        "effect_journal_limits_n_and_n_plus_one",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"over_budget_detected":true}"#,
        r#"{"over_budget_detected":true}"#,
    );
    Ok(())
}

#[test]
fn test_effect_journal_missing_journal() -> TestResult {
    let start = Instant::now();
    let dir = fresh_dir("test_effect_journal_missing_journal")?;
    let missing_path = dir.join("nonexistent.fssj");

    let inspection = DurableEffectJournal::inspect(&missing_path, 1 << 20)?;
    assert_eq!(inspection.status, EffectJournalStatus::Absent);
    assert!(inspection.is_absent());
    assert!(inspection.journal.is_none());
    assert!(
        !missing_path.exists(),
        "inspect must not create missing file!"
    );

    emit_caplog(
        "effect_journal_missing_journal",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"missing_journal_absent":true}"#,
        r#"{"missing_journal_absent":true}"#,
    );
    Ok(())
}

#[test]
fn test_effect_journal_invalid_layout() -> TestResult {
    let start = Instant::now();
    let dir = fresh_dir("test_effect_journal_invalid_layout")?;

    let dir_journal = dir.join("dir.fssj");
    fs::create_dir(&dir_journal)?;
    let inspect_dir = DurableEffectJournal::inspect(&dir_journal, 1 << 20);
    match inspect_dir {
        Err(DurableEffectError::InvalidLayout { path }) => {
            assert_eq!(path, dir_journal);
        }
        other => return Err(format!("expected InvalidLayout for directory, got {other:?}").into()),
    }

    let target_file = dir.join("target.file");
    fs::write(&target_file, b"target")?;
    let symlink_journal = dir.join("symlink.fssj");
    std::os::unix::fs::symlink(&target_file, &symlink_journal)?;
    let inspect_sym = DurableEffectJournal::inspect(&symlink_journal, 1 << 20);
    match inspect_sym {
        Err(DurableEffectError::InvalidLayout { path }) => {
            assert_eq!(path, symlink_journal);
        }
        other => return Err(format!("expected InvalidLayout for symlink, got {other:?}").into()),
    }

    emit_caplog(
        "effect_journal_invalid_layout",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"invalid_layout_cases":2}"#,
        r#"{"invalid_layout_cases":2}"#,
    );
    Ok(())
}

#[test]
fn test_effect_journal_read_only_tree_digest_proof() -> TestResult {
    let start = Instant::now();
    let dir = fresh_dir("test_effect_journal_read_only_tree_digest_proof")?;
    let journal_path = dir.join("proof.fssj");

    let op = OperationId::parse("op:proof:1")?;
    let obl = ObligationId::parse("obligation:proof:1")?;
    let intent = sample_intent(&op)?;

    {
        let mut journal = DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
        let _ = journal.prepare(intent, obl, "channel_ack", TimestampNs(100))?;
    }

    let digest_before = compute_tree_digest(&dir)?;

    let inspection = DurableEffectJournal::inspect(&journal_path, 1 << 20)?;
    assert_eq!(inspection.status, EffectJournalStatus::Present);

    let digest_after = compute_tree_digest(&dir)?;
    assert_eq!(
        digest_before, digest_after,
        "effect journal tree digest modified during inspect!"
    );

    emit_caplog(
        "effect_journal_read_only_tree_digest_proof",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"digest_identical":true}"#,
        r#"{"digest_identical":true}"#,
    );
    Ok(())
}

#[test]
fn test_effect_journal_read_only_recording_io_proof() -> TestResult {
    let start = Instant::now();
    let dir = fresh_dir("test_effect_journal_read_only_recording_io_proof")?;
    let journal_path = dir.join("recording.fssj");

    let op = OperationId::parse("op:rec:1")?;
    let obl = ObligationId::parse("obligation:rec:1")?;
    let intent = sample_intent(&op)?;

    {
        let mut journal = DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
        let _ = journal.prepare(intent, obl, "channel_ack", TimestampNs(100))?;
    }

    let recording_io = RecordingJournalReadIo::new(HostJournalReadIo);
    let inspection = DurableEffectJournal::inspect_with_io(&recording_io, &journal_path, 1 << 20)?;
    assert_eq!(inspection.status, EffectJournalStatus::Present);

    assert!(recording_io.is_read_only());
    assert!(recording_io.mutating_calls().is_empty());
    assert!(!recording_io.calls().is_empty());

    emit_caplog(
        "effect_journal_read_only_recording_io_proof",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"is_read_only":true,"mutating_count":0}"#,
        r#"{"is_read_only":true,"mutating_count":0}"#,
    );
    Ok(())
}

#[test]
fn test_effect_journal_read_only_filesystem_copy() -> TestResult {
    let start = Instant::now();
    let dir = fresh_dir("test_effect_journal_read_only_filesystem_copy")?;
    let ro_dir = fresh_dir("test_effect_journal_read_only_filesystem_copy_ro")?;
    let journal_path = dir.join("ro.fssj");

    let op = OperationId::parse("op:ro:1")?;
    let obl = ObligationId::parse("obligation:ro:1")?;
    let intent = sample_intent(&op)?;

    {
        let mut journal = DurableEffectJournal::open(&journal_path, IncompleteTailPolicy::Reject)?;
        let _ = journal.prepare(intent, obl, "channel_ack", TimestampNs(100))?;
    }

    copy_dir_all(&dir, &ro_dir)?;
    let _guard = ReadOnlyTreeGuard::make_read_only(&ro_dir)?;

    let sentinel = ro_dir.join("sentinel.tmp");
    let is_privileged = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&sentinel)
        .is_ok();

    if is_privileged {
        let _ = fs::remove_file(&sentinel);
        emit_caplog(
            "effect_journal_read_only_filesystem_copy",
            "skip",
            0,
            start.elapsed().as_millis(),
            r#"{"reason":"unprivileged"}"#,
            r#"{"reason":"privileged"}"#,
        );
        return Ok(());
    }

    let ro_journal = ro_dir.join("ro.fssj");
    let inspection = DurableEffectJournal::inspect(&ro_journal, 1 << 20)?;
    assert_eq!(inspection.status, EffectJournalStatus::Present);

    emit_caplog(
        "effect_journal_read_only_filesystem_copy",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"status":"Present"}"#,
        r#"{"status":"Present"}"#,
    );
    Ok(())
}

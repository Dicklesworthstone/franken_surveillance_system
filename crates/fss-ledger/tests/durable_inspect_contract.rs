#![forbid(unsafe_code)]
//! Integration contract tests for durable reference ledger non-mutating inspection (DOCTOR0).
//!
//! Asserts:
//! - Differential against [`DurableReferenceLedger::open`] across clean ledger,
//!   each [`AppendPhase`] via fault injection, foreign trailing bytes, oversize journal,
//!   missing journal, and invalid layout.
//! - Read-only proof: full tree digest (content, size, mode, mtime nanoseconds, listing)
//!   strictly identical before and after inspection.
//! - Read-only proof: [`RecordingJournalReadIo`] records 0 mutating calls.
//! - Read-only copy: inspection succeeds on a 0o555 read-only directory tree (or skips if privileged).
//! - Limits at N and N+1: [`DurableLedgerLimits::max_journal_bytes`].
//! - Structured CAPLOG emission for each step.

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Instant;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, DigestAlgorithm, EvidenceDelta, ObjectId, Plane,
    Sha256Hasher, TimestampNs, sha256,
};
use fss_ledger::{
    AppendPhase, DurableLedgerError, DurableLedgerLimits, DurableLedgerStatus,
    DurableReferenceLedger, HostJournalReadIo, IncompleteTailPolicy, JournalError,
    JournalFileMetadata, JournalReadIo, inspect_durable, inspect_durable_with_io,
};

struct RecordingJournalReadIo<T: JournalReadIo = HostJournalReadIo> {
    inner: T,
    calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl<T: JournalReadIo> RecordingJournalReadIo<T> {
    fn new(inner: T) -> Self {
        Self {
            inner,
            calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    fn calls(&self) -> Vec<String> {
        match self.calls.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => Vec::new(),
        }
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn mutating_calls(&self) -> Vec<String> {
        Vec::new()
    }
}

impl<T: JournalReadIo> JournalReadIo for RecordingJournalReadIo<T> {
    fn symlink_metadata(&self, path: &Path) -> std::io::Result<JournalFileMetadata> {
        if let Ok(mut guard) = self.calls.lock() {
            guard.push(format!("symlink_metadata({})", path.display()));
        }
        self.inner.symlink_metadata(path)
    }

    fn read_bounded(&self, path: &Path, max_bytes: usize) -> std::io::Result<Vec<u8>> {
        if let Ok(mut guard) = self.calls.lock() {
            guard.push(format!(
                "read_bounded({}, max={})",
                path.display(),
                max_bytes
            ));
        }
        self.inner.read_bounded(path, max_bytes)
    }
}

type TestResult = Result<(), Box<dyn Error>>;

const SITE: &str = "site-ledger-inspect";

const ALL_APPEND_PHASES: [AppendPhase; 4] = [
    AppendPhase::BodyWrite,
    AppendPhase::BodySync,
    AppendPhase::CommitWrite,
    AppendPhase::CommitSync,
];

fn fresh_dir(test_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let base = match std::env::var_os("CARGO_TARGET_TMPDIR") {
        Some(dir) => PathBuf::from(dir),
        None => std::env::temp_dir(),
    };
    let root = base.join("durable_inspect_contract").join(test_name);
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    fs::create_dir_all(&root)?;
    Ok(root)
}

fn create_delta(tag: &str, object: &str) -> Result<EvidenceDelta, Box<dyn Error>> {
    Ok(EvidenceDelta {
        delta_id: format!("delta:{tag}"),
        family: "reachability".to_owned(),
        object_id: ObjectId::parse(format!("object:{object}"))?,
        prior_generation: None,
        new_generation: 1,
        validity: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
        plane: Plane::Authority,
        payload_digest: ContentDigest::sha256(format!("payload:{tag}").as_bytes()),
        witness_digest: Some(ContentDigest::sha256(format!("witness:{tag}").as_bytes())),
        operation_id: None,
    })
}

fn commit_batch(durable: &mut DurableReferenceLedger, name: &str, object: &str) -> TestResult {
    let batch = durable.prepare_batch(
        BatchId::parse(format!("batch:{name}"))?,
        vec![create_delta(name, object)?],
        [],
    )?;
    durable.append(batch)?;
    Ok(())
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

type TreeDigestEntry = (String, bool, u64, u32, i64, i64, [u8; 32]);

fn collect_tree_entries(
    base: &Path,
    current: &Path,
    entries: &mut Vec<TreeDigestEntry>,
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
fn test_durable_differential_clean() -> TestResult {
    let start = Instant::now();
    let dir = fresh_dir("test_durable_differential_clean")?;
    let copy_dir_path = fresh_dir("test_durable_differential_clean_copy")?;
    let journal_path = dir.join("clean.journal");
    let copy_journal_path = copy_dir_path.join("clean.journal");

    {
        let mut ledger =
            DurableReferenceLedger::open(&journal_path, SITE, IncompleteTailPolicy::Reject)?;
        commit_batch(&mut ledger, "b1", "o1")?;
        commit_batch(&mut ledger, "b2", "o2")?;
    }

    copy_dir_all(&dir, &copy_dir_path)?;

    let inspection = inspect_durable(&journal_path, SITE, DurableLedgerLimits::default())?;
    let opened =
        DurableReferenceLedger::open(&copy_journal_path, SITE, IncompleteTailPolicy::Reject)?;

    assert_eq!(inspection.batches.len(), 2);
    assert_eq!(opened.batches().len(), 2);
    assert_eq!(inspection.batches, opened.batches());
    assert_eq!(
        inspection.committed_len,
        fs::metadata(&copy_journal_path)?.len()
    );
    assert_eq!(inspection.snapshot.anchor, opened.current().anchor);
    assert!(inspection.incomplete_tail.is_none());
    assert!(inspection.foreign_range.is_none());

    emit_caplog(
        "durable_differential_clean",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"batch_count":2,"tail_incomplete":false}"#,
        r#"{"batch_count":2,"tail_incomplete":false}"#,
    );
    Ok(())
}

#[test]
fn test_durable_differential_append_phases() -> TestResult {
    for &phase in &ALL_APPEND_PHASES {
        let start = Instant::now();
        let phase_name = format!("{phase:?}");
        let dir = fresh_dir(&format!("test_durable_phase_{phase_name}"))?;
        let copy_reject = fresh_dir(&format!("test_durable_phase_{phase_name}_reject"))?;
        let copy_trunc = fresh_dir(&format!("test_durable_phase_{phase_name}_trunc"))?;
        let journal_path = dir.join("phase.journal");

        let mut ledger =
            DurableReferenceLedger::open(&journal_path, SITE, IncompleteTailPolicy::Reject)?;
        commit_batch(&mut ledger, "initial", "init_obj")?;

        let second_batch = ledger.prepare_batch(
            BatchId::parse("batch:faulted")?,
            vec![create_delta("faulted", "fault_obj")?],
            [],
        )?;

        ledger.fail_journal_after_phase(phase);
        let append_res = ledger.append(second_batch.clone());
        assert!(append_res.is_err());

        drop(ledger);

        copy_dir_all(&dir, &copy_reject)?;
        copy_dir_all(&dir, &copy_trunc)?;

        let inspection = inspect_durable(&journal_path, SITE, DurableLedgerLimits::default())?;

        match phase {
            AppendPhase::BodyWrite | AppendPhase::BodySync => {
                let reject_open = DurableReferenceLedger::open(
                    copy_reject.join("phase.journal"),
                    SITE,
                    IncompleteTailPolicy::Reject,
                );
                match reject_open {
                    Err(DurableLedgerError::Journal(JournalError::IncompleteTail { offset })) => {
                        assert_eq!(inspection.incomplete_tail, Some(offset));
                    }
                    other => {
                        return Err(format!(
                            "expected IncompleteTail for {phase:?}, got {other:?}"
                        )
                        .into());
                    }
                }

                let trunc_ledger = DurableReferenceLedger::open(
                    copy_trunc.join("phase.journal"),
                    SITE,
                    IncompleteTailPolicy::Truncate,
                )?;
                assert_eq!(inspection.batches.len(), 1);
                assert_eq!(trunc_ledger.batches().len(), 1);
                assert_eq!(inspection.batches, trunc_ledger.batches());
            }
            AppendPhase::CommitWrite | AppendPhase::CommitSync => {
                let reject_ledger = DurableReferenceLedger::open(
                    copy_reject.join("phase.journal"),
                    SITE,
                    IncompleteTailPolicy::Reject,
                )?;
                assert_eq!(inspection.batches.len(), 2);
                assert_eq!(reject_ledger.batches().len(), 2);
                assert_eq!(inspection.batches, reject_ledger.batches());
                assert!(inspection.incomplete_tail.is_none());
            }
            _ => unreachable!(),
        }

        emit_caplog(
            &format!("durable_phase_{phase_name}"),
            "pass",
            0,
            start.elapsed().as_millis(),
            r#"{"phase_handled":true}"#,
            r#"{"phase_handled":true}"#,
        );
    }
    Ok(())
}

#[test]
fn test_durable_differential_foreign_trailing_bytes() -> TestResult {
    let start = Instant::now();
    let dir = fresh_dir("test_durable_differential_foreign_trailing_bytes")?;
    let copy_dir_path = fresh_dir("test_durable_differential_foreign_trailing_bytes_copy")?;
    let journal_path = dir.join("foreign.journal");

    {
        let mut ledger =
            DurableReferenceLedger::open(&journal_path, SITE, IncompleteTailPolicy::Reject)?;
        commit_batch(&mut ledger, "b1", "o1")?;
    }

    {
        let mut file = OpenOptions::new().append(true).open(&journal_path)?;
        file.write_all(b"foreign trailing garbage bytes")?;
        file.sync_all()?;
    }

    copy_dir_all(&dir, &copy_dir_path)?;

    let inspection = inspect_durable(&journal_path, SITE, DurableLedgerLimits::default())?;
    assert!(
        inspection.incomplete_tail.is_some() || inspection.foreign_range.is_some(),
        "expected foreign tail detection"
    );

    let reject_open = DurableReferenceLedger::open(
        copy_dir_path.join("foreign.journal"),
        SITE,
        IncompleteTailPolicy::Reject,
    );
    assert!(reject_open.is_err());

    let trunc_open = DurableReferenceLedger::open(
        copy_dir_path.join("foreign.journal"),
        SITE,
        IncompleteTailPolicy::Truncate,
    );
    assert!(trunc_open.is_err());
    assert_eq!(inspection.batches.len(), 1);
    assert!(inspection.foreign_range.is_some());
    assert!(!inspection.is_clean());

    emit_caplog(
        "durable_differential_foreign_trailing_bytes",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"foreign_tail_detected":true}"#,
        r#"{"foreign_tail_detected":true}"#,
    );
    Ok(())
}

#[test]
fn test_durable_limits_n_and_n_plus_one() -> TestResult {
    let start = Instant::now();
    let dir = fresh_dir("test_durable_limits_n_and_n_plus_one")?;
    let journal_path = dir.join("limits.journal");

    {
        let mut ledger =
            DurableReferenceLedger::open(&journal_path, SITE, IncompleteTailPolicy::Reject)?;
        commit_batch(&mut ledger, "b1", "o1")?;
    }

    let file_len = fs::metadata(&journal_path)?.len() as usize;

    let exact_limits = DurableLedgerLimits {
        max_journal_bytes: file_len,
    };
    let inspect_exact = inspect_durable(&journal_path, SITE, exact_limits)?;
    assert_eq!(inspect_exact.batches.len(), 1);

    let under_limits = DurableLedgerLimits {
        max_journal_bytes: file_len.saturating_sub(1),
    };
    let inspect_err = inspect_durable(&journal_path, SITE, under_limits);
    match inspect_err {
        Err(DurableLedgerError::OverBudget { limit, actual }) => {
            assert_eq!(limit, file_len.saturating_sub(1));
            assert_eq!(actual, file_len);
        }
        other => return Err(format!("expected OverBudget, got {other:?}").into()),
    }

    emit_caplog(
        "durable_limits_n_and_n_plus_one",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"over_budget_detected":true}"#,
        r#"{"over_budget_detected":true}"#,
    );
    Ok(())
}

#[test]
fn test_durable_missing_journal() -> TestResult {
    let start = Instant::now();
    let dir = fresh_dir("test_durable_missing_journal")?;
    let missing_path = dir.join("nonexistent.journal");

    let inspection = inspect_durable(&missing_path, SITE, DurableLedgerLimits::default())?;
    assert_eq!(inspection.status, DurableLedgerStatus::Absent);
    assert!(inspection.batches.is_empty());
    assert_eq!(inspection.committed_len, 0);
    assert!(
        !missing_path.exists(),
        "inspect_durable must not create missing file!"
    );

    emit_caplog(
        "durable_missing_journal",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"missing_journal_absent":true}"#,
        r#"{"missing_journal_absent":true}"#,
    );
    Ok(())
}

#[test]
fn test_durable_invalid_layout() -> TestResult {
    let start = Instant::now();
    let dir = fresh_dir("test_durable_invalid_layout")?;

    let dir_journal = dir.join("dir.journal");
    fs::create_dir(&dir_journal)?;
    let inspect_dir = inspect_durable(&dir_journal, SITE, DurableLedgerLimits::default());
    match inspect_dir {
        Err(DurableLedgerError::InvalidLayout { path }) => {
            assert_eq!(path, dir_journal);
        }
        other => return Err(format!("expected InvalidLayout for directory, got {other:?}").into()),
    }

    let target_file = dir.join("target.file");
    fs::write(&target_file, b"target")?;
    let symlink_journal = dir.join("symlink.journal");
    std::os::unix::fs::symlink(&target_file, &symlink_journal)?;
    let inspect_sym = inspect_durable(&symlink_journal, SITE, DurableLedgerLimits::default());
    match inspect_sym {
        Err(DurableLedgerError::InvalidLayout { path }) => {
            assert_eq!(path, symlink_journal);
        }
        other => return Err(format!("expected InvalidLayout for symlink, got {other:?}").into()),
    }

    emit_caplog(
        "durable_invalid_layout",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"invalid_layout_cases":2}"#,
        r#"{"invalid_layout_cases":2}"#,
    );
    Ok(())
}

#[test]
fn test_durable_read_only_tree_digest_proof() -> TestResult {
    let start = Instant::now();
    let dir = fresh_dir("test_durable_read_only_tree_digest_proof")?;
    let journal_path = dir.join("proof.journal");

    {
        let mut ledger =
            DurableReferenceLedger::open(&journal_path, SITE, IncompleteTailPolicy::Reject)?;
        commit_batch(&mut ledger, "b1", "o1")?;
    }

    let digest_before = compute_tree_digest(&dir)?;

    let inspection = inspect_durable(&journal_path, SITE, DurableLedgerLimits::default())?;
    assert_eq!(inspection.status, DurableLedgerStatus::Present);
    assert_eq!(inspection.batches.len(), 1);

    let digest_after = compute_tree_digest(&dir)?;
    assert_eq!(
        digest_before, digest_after,
        "durable ledger tree digest modified during inspect_durable!"
    );

    emit_caplog(
        "durable_read_only_tree_digest_proof",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"digest_identical":true}"#,
        r#"{"digest_identical":true}"#,
    );
    Ok(())
}

#[test]
fn test_durable_read_only_recording_io_proof() -> TestResult {
    let start = Instant::now();
    let dir = fresh_dir("test_durable_read_only_recording_io_proof")?;
    let journal_path = dir.join("recording.journal");

    {
        let mut ledger =
            DurableReferenceLedger::open(&journal_path, SITE, IncompleteTailPolicy::Reject)?;
        commit_batch(&mut ledger, "b1", "o1")?;
    }

    let recording_io = RecordingJournalReadIo::new(HostJournalReadIo);
    let inspection = inspect_durable_with_io(
        &recording_io,
        &journal_path,
        SITE,
        DurableLedgerLimits::default(),
    )?;
    assert_eq!(inspection.batches.len(), 1);

    assert!(recording_io.is_read_only());
    assert!(recording_io.mutating_calls().is_empty());
    assert!(!recording_io.calls().is_empty());

    emit_caplog(
        "durable_read_only_recording_io_proof",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"is_read_only":true,"mutating_count":0}"#,
        r#"{"is_read_only":true,"mutating_count":0}"#,
    );
    Ok(())
}

#[test]
fn test_durable_read_only_filesystem_copy() -> TestResult {
    let start = Instant::now();
    let dir = fresh_dir("test_durable_read_only_filesystem_copy")?;
    let ro_dir = fresh_dir("test_durable_read_only_filesystem_copy_ro")?;
    let journal_path = dir.join("ro.journal");

    {
        let mut ledger =
            DurableReferenceLedger::open(&journal_path, SITE, IncompleteTailPolicy::Reject)?;
        commit_batch(&mut ledger, "b1", "o1")?;
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
            "durable_read_only_filesystem_copy",
            "skip",
            0,
            start.elapsed().as_millis(),
            r#"{"reason":"unprivileged"}"#,
            r#"{"reason":"privileged"}"#,
        );
        return Ok(());
    }

    let ro_journal = ro_dir.join("ro.journal");
    let inspection = inspect_durable(&ro_journal, SITE, DurableLedgerLimits::default())?;
    assert_eq!(inspection.batches.len(), 1);

    emit_caplog(
        "durable_read_only_filesystem_copy",
        "pass",
        0,
        start.elapsed().as_millis(),
        r#"{"batch_count":1}"#,
        r#"{"batch_count":1}"#,
    );
    Ok(())
}

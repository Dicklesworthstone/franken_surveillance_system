#![forbid(unsafe_code)]
//! Adversarial review remediation tests for fss-x4a.7.6 (review-568).

use std::error::Error;
use std::fs::{self, DirEntry, File, FileType, Metadata, ReadDir, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{
    FaultInjectingSpoolIo, HostSpoolIo, ObjectManifest, SpoolFaultPlan, SpoolIo, SpoolIoCall,
    SpoolLimits,
};
use fss_publication::{
    BlockReason, ClaimStatus, LedgeredRootPublisher, LocalPublicationError, LocalPublicationLimits,
    LocalPublicationState, LocalRootPublisher, PublicationClaims, ReferenceRole, RootLedgerState,
    SlotName,
};

type TestResult = Result<(), Box<dyn Error>>;

fn fresh_root(test_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("root_publication_review568")
        .join(test_name);
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(root)
}

fn test_limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(16, 16, 16, 64, SpoolLimits::new(64, 1 << 20, 4096, 64))
}

/// Finding 1: Recovery/reopen must reject root with corrupt or tombstoned transitive descendant.
#[test]
fn test_reopen_must_reject_root_with_corrupt_or_tombstoned_transitive_descendant() -> TestResult {
    let root = fresh_root(
        "test_reopen_must_reject_root_with_corrupt_or_tombstoned_transitive_descendant",
    )?;
    let limits = test_limits();

    // 1. Publish Slot B (child) and Slot A (parent referencing Slot B)
    let leaf_path = {
        let mut pub1 = LocalRootPublisher::open(&root, limits)?;
        let leaf = pub1.stage_object(b"leaf_data")?;
        let manifest_b = ObjectManifest::new("clip", [leaf], None)?;
        pub1.publish(&SlotName::parse("slot-b")?, &manifest_b)?;
        let manifest_a = ObjectManifest::new("archive", [manifest_b.root()], None)?;
        pub1.publish(&SlotName::parse("slot-a")?, &manifest_a)?;
        pub1.spool().object_path(leaf)
    };

    // 2. Corrupt the transitive leaf object in the spool
    {
        let mut bytes = fs::read(&leaf_path)?;
        let last = bytes.last_mut().ok_or("leaf object empty")?;
        *last ^= 0xFF;
        fs::write(&leaf_path, bytes)?;
    }

    // 3. Reopen publisher: Slot A must NOT be admitted as Durable
    let pub2 = LocalRootPublisher::open(&root, limits)?;
    let slot_a = SlotName::parse("slot-a")?;
    assert!(
        pub2.root(&slot_a).is_none(),
        "Slot A must be classified as broken because its transitive descendant in the closure is corrupt"
    );
    assert!(
        pub2.recovery_report().broken_roots.iter().any(|b| b
            .path
            .to_str()
            .unwrap_or("")
            .contains("slot-a")),
        "Recovery report must report Slot A as a broken root"
    );
    Ok(())
}

/// Finding 2: Visible roots can point to objects that are not yet durable.
#[test]
fn test_publish_rejects_child_root_that_is_only_visible_not_durable() -> TestResult {
    let root = fresh_root("test_publish_rejects_child_root_that_is_only_visible_not_durable")?;
    let limits = test_limits();

    // 1. Cleanly publish child slot-b
    let slot_b = SlotName::parse("slot-b")?;
    let (leaf, manifest_b) = {
        let mut publisher = LocalRootPublisher::open(&root, limits)?;
        let leaf = publisher.stage_object(b"leaf")?;
        let manifest_b = ObjectManifest::new("clip", [leaf], None)?;
        publisher.publish(&slot_b, &manifest_b)?;
        (leaf, manifest_b)
    };

    // 2. Reopen fresh publisher with FaultInjectingSpoolIo that fails SyncDirectory on recovery.
    // This leaves slot-b in Visible state (not promoted to Durable), while publisher remains unpoisoned.
    let plan = SpoolFaultPlan::new().fail(SpoolIoCall::SyncDirectory, 3, io::ErrorKind::Other);
    let fault_io = Arc::new(FaultInjectingSpoolIo::new(plan));
    let mut fresh =
        LocalRootPublisher::open_with_io(&root, limits, fault_io.clone() as Arc<dyn SpoolIo>)?;

    let root_b = fresh
        .root(&slot_b)
        .ok_or("slot-b root must be visible on fresh publisher")?;
    assert_eq!(
        root_b.state,
        LocalPublicationState::Visible,
        "slot-b must remain Visible when recovery directory sync fails"
    );
    assert!(!fresh.is_poisoned(), "fresh publisher must not be poisoned");

    // 3. Attempting to publish parent slot-a referencing slot-b must fail with ReferenceBlocked
    let manifest_a = ObjectManifest::new("archive", [manifest_b.root()], None)?;
    let slot_a = SlotName::parse("slot-a")?;

    match fresh.publish(&slot_a, &manifest_a) {
        Err(LocalPublicationError::ReferenceBlocked {
            object,
            role,
            reason,
        }) => {
            assert_eq!(object, manifest_b.root());
            assert_eq!(role, ReferenceRole::Child);
            assert_eq!(reason, BlockReason::NotVerified);
        }
        other => {
            return Err(
                format!("expected ReferenceBlocked on fresh publisher, got {other:?}").into(),
            );
        }
    }

    assert!(
        fault_io.all_fired(),
        "recovery SyncDirectory fault must fire"
    );

    // Furthermore, closure() must NOT descend into Slot B's children while Slot B is not Durable
    let closure_a = fresh.closure(manifest_a.root(), manifest_a.children());
    assert!(
        !closure_a.contains(&leaf),
        "closure() must not descend into Slot B while Slot B is not Durable"
    );
    drop(fresh);

    // 4. Settled publisher opened without faults promotes Slot B to Durable; parent publish succeeds
    let mut settled = LocalRootPublisher::open(&root, limits)?;
    assert_eq!(
        settled.root(&slot_b).ok_or("slot-b must exist")?.state,
        LocalPublicationState::Durable
    );
    settled.publish(&slot_a, &manifest_a)?;
    let closure_settled = settled.closure(manifest_a.root(), manifest_a.children());
    assert!(
        closure_settled.contains(&leaf),
        "closure() must descend into Slot B once Slot B is Durable"
    );

    Ok(())
}

/// Finding 3: Publication states conflation and completeness in PublicationClaims & RootLedgerState.
#[test]
fn test_staged_root_manifest_is_observable_and_not_collapsed_into_absent() -> TestResult {
    let root = fresh_root("test_staged_root_manifest_is_observable_and_not_collapsed_into_absent")?;
    let limits = test_limits();
    let mut publisher = LocalRootPublisher::open(&root, limits)?;

    // 1. PublicationClaims and ClaimStatus must support Claimed status for non-local lattice rungs
    let claims = PublicationClaims::new(
        LocalPublicationState::Durable,
        ClaimStatus::Claimed,
        ClaimStatus::Claimed,
        ClaimStatus::Claimed,
    );
    assert_eq!(claims.replicated, ClaimStatus::Claimed);
    assert_eq!(claims.protected, ClaimStatus::Claimed);
    assert_eq!(claims.retrievable, ClaimStatus::Claimed);

    // 2. A manifest staged for a slot must be observable as Staged, not None / Absent
    let leaf = publisher.stage_object(b"leaf")?;
    let manifest = ObjectManifest::new("test", [leaf], None)?;
    let slot = SlotName::parse("slot-test")?;
    publisher.stage_manifest(&slot, &manifest)?;

    let root_entry = publisher
        .root(&slot)
        .ok_or("staged root must be observable")?;
    assert_eq!(root_entry.state, LocalPublicationState::Staged);
    assert_eq!(root_entry.root, manifest.root());

    // 3. Ledger linkage must classify the staged slot as RootLedgerState::Staged
    let ledger_path = root.join("journal");
    let mut ledger =
        DurableReferenceLedger::open(&ledger_path, "site:one", IncompleteTailPolicy::Reject)?;
    let linkage = LedgeredRootPublisher::new(&mut publisher, &mut ledger);
    let state = linkage.state(&slot)?;
    assert_eq!(
        state,
        RootLedgerState::Staged {
            root: manifest.root()
        }
    );

    Ok(())
}

/// Recording IO implementation for verifying directory fsync calls.
#[derive(Debug)]
struct RecordingIo {
    inner: HostSpoolIo,
    calls: Arc<Mutex<Vec<String>>>,
}

impl RecordingIo {
    fn new(calls: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            inner: HostSpoolIo,
            calls,
        }
    }

    fn record(&self, call: String) {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push(call);
        }
    }
}

impl SpoolIo for RecordingIo {
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        self.inner.create_dir_all(path)
    }

    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.inner.metadata(path)
    }

    fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.inner.symlink_metadata(path)
    }

    fn open_lock(&self, path: &Path) -> io::Result<File> {
        self.inner.open_lock(path)
    }

    fn try_lock(&self, file: &File) -> Result<(), TryLockError> {
        self.inner.try_lock(file)
    }

    fn create_dir(&self, path: &Path) -> io::Result<()> {
        self.inner.create_dir(path)
    }

    fn read_dir(&self, path: &Path) -> io::Result<ReadDir> {
        self.inner.read_dir(path)
    }

    fn next_dir_entry(&self, entries: &mut ReadDir) -> Option<io::Result<DirEntry>> {
        self.inner.next_dir_entry(entries)
    }

    fn entry_file_type(&self, entry: &DirEntry) -> io::Result<FileType> {
        self.inner.entry_file_type(entry)
    }

    fn create_new(&self, path: &Path) -> io::Result<File> {
        self.record(format!("create_new:{}", path.display()));
        self.inner.create_new(path)
    }

    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write(file, bytes)
    }

    fn sync_file(&self, file: &File) -> io::Result<()> {
        self.inner.sync_file(file)
    }

    fn open_read(&self, path: &Path) -> io::Result<File> {
        self.inner.open_read(path)
    }

    fn read_bounded(&self, file: &mut File, limit: u64) -> io::Result<Vec<u8>> {
        self.inner.read_bounded(file, limit)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.record(format!("rename:{}->{}", from.display(), to.display()));
        self.inner.rename(from, to)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        self.record(format!("remove_file:{}", path.display()));
        self.inner.remove_file(path)
    }

    fn sync_directory(&self, path: &Path) -> io::Result<()> {
        self.record(format!("sync_directory:{}", path.display()));
        self.inner.sync_directory(path)
    }

    fn hard_link(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.record(format!("hard_link:{}->{}", from.display(), to.display()));
        self.inner.hard_link(from, to)
    }
}

/// Finding 4: Missing Parent Directory Fsync on Temporary File Creation.
#[test]
fn test_write_temp_must_sync_parent_directory_after_file_creation() -> TestResult {
    let root = fresh_root("test_write_temp_must_sync_parent_directory_after_file_creation")?;
    let limits = test_limits();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let io = Arc::new(RecordingIo::new(Arc::clone(&calls)));

    let mut publisher = LocalRootPublisher::open_with_io(&root, limits, io)?;
    let leaf = publisher.stage_object(b"data")?;
    let manifest = ObjectManifest::new("clip", [leaf], None)?;
    let slot = SlotName::parse("slot-test")?;

    // Clear calls recorded during open/staging
    if let Ok(mut lock) = calls.lock() {
        lock.clear();
    }

    publisher.publish(&slot, &manifest)?;

    let recorded = calls.lock().map_err(|_| "mutex poisoned")?.clone();
    let temp_create_idx = recorded
        .iter()
        .position(|c| c.starts_with("create_new:") && c.contains("roots") && c.contains(".tmp"))
        .ok_or("expected create_new on roots .tmp file")?;
    let commit_idx = recorded
        .iter()
        .position(|c| {
            (c.starts_with("rename:") || c.starts_with("hard_link:"))
                && c.contains("roots")
                && c.contains(".tmp")
        })
        .ok_or("expected rename or hard_link from roots .tmp file")?;

    // Assert that a sync_directory on roots directory occurred between temp create_new and commit
    let sync_dir_between = recorded[temp_create_idx..commit_idx]
        .iter()
        .any(|c| c.starts_with("sync_directory:") && c.contains("roots"));

    assert!(
        sync_dir_between,
        "write_temp must sync parent directory after temporary file creation and before rename; calls: {recorded:?}"
    );

    Ok(())
}

/// Finding 5: Pre-commit collision detection fails closed with InvalidLayout.
#[test]
fn test_publish_fails_with_invalid_layout_if_unindexed_file_exists_at_target_path() -> TestResult {
    let root = fresh_root(
        "test_publish_fails_with_invalid_layout_if_unindexed_file_exists_at_target_path",
    )?;
    let limits = test_limits();
    let slot = SlotName::parse("slot-conflict")?;
    let target_path = root.join("roots").join(format!("{slot}.root"));

    let mut publisher = LocalRootPublisher::open(&root, limits)?;
    let leaf = publisher.stage_object(b"leaf_data")?;
    let manifest = ObjectManifest::new("clip", [leaf], None)?;

    // Manually place an unindexed file at target_path
    fs::write(&target_path, b"unindexed_existing_file")?;

    // Publish must fail with InvalidLayout rather than overwriting the file
    let res = publisher.publish(&slot, &manifest);
    match res {
        Err(LocalPublicationError::InvalidLayout { path }) => {
            assert_eq!(path, target_path);
        }
        other => {
            return Err(format!("expected InvalidLayout error, got {other:?}").into());
        }
    }

    // The existing file must NOT be clobbered
    let content = fs::read(&target_path)?;
    assert_eq!(
        content, b"unindexed_existing_file",
        "Target file must retain its original contents and never be clobbered"
    );

    Ok(())
}

/// IO implementation that simulates a concurrent creator writing a file at `target_path`
/// during the TOCTOU window between pre-commit inspection and the commit point.
#[derive(Debug)]
struct ToctouConflictIo {
    inner: HostSpoolIo,
    target_path: PathBuf,
    conflict_bytes: Vec<u8>,
    conflict_created: AtomicBool,
}

impl ToctouConflictIo {
    fn new(target_path: PathBuf, conflict_bytes: Vec<u8>) -> Self {
        Self {
            inner: HostSpoolIo,
            target_path,
            conflict_bytes,
            conflict_created: AtomicBool::new(false),
        }
    }
}

impl SpoolIo for ToctouConflictIo {
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        self.inner.create_dir_all(path)
    }

    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.inner.metadata(path)
    }

    fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata> {
        let res = self.inner.symlink_metadata(path);
        if path == self.target_path
            && res.as_ref().err().map(|e| e.kind()) == Some(io::ErrorKind::NotFound)
        {
            // Inject conflicting file directly onto the host filesystem right after
            // the publisher verified that target_path was NotFound!
            fs::write(&self.target_path, &self.conflict_bytes)?;
            self.conflict_created.store(true, Ordering::SeqCst);
        }
        res
    }

    fn open_lock(&self, path: &Path) -> io::Result<File> {
        self.inner.open_lock(path)
    }

    fn try_lock(&self, file: &File) -> Result<(), TryLockError> {
        self.inner.try_lock(file)
    }

    fn create_dir(&self, path: &Path) -> io::Result<()> {
        self.inner.create_dir(path)
    }

    fn read_dir(&self, path: &Path) -> io::Result<ReadDir> {
        self.inner.read_dir(path)
    }

    fn next_dir_entry(&self, entries: &mut ReadDir) -> Option<io::Result<DirEntry>> {
        self.inner.next_dir_entry(entries)
    }

    fn entry_file_type(&self, entry: &DirEntry) -> io::Result<FileType> {
        self.inner.entry_file_type(entry)
    }

    fn create_new(&self, path: &Path) -> io::Result<File> {
        self.inner.create_new(path)
    }

    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write(file, bytes)
    }

    fn sync_file(&self, file: &File) -> io::Result<()> {
        self.inner.sync_file(file)
    }

    fn open_read(&self, path: &Path) -> io::Result<File> {
        self.inner.open_read(path)
    }

    fn read_bounded(&self, file: &mut File, limit: u64) -> io::Result<Vec<u8>> {
        self.inner.read_bounded(file, limit)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.inner.rename(from, to)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        self.inner.remove_file(path)
    }

    fn sync_directory(&self, path: &Path) -> io::Result<()> {
        self.inner.sync_directory(path)
    }
}

/// Finding 5: A target file created between inspection and commit (TOCTOU window)
/// must be refused with InvalidLayout and never clobbered.
#[test]
fn test_target_created_in_toctou_window_is_refused_and_never_clobbered() -> TestResult {
    let root = fresh_root("test_target_created_in_toctou_window_is_refused_and_never_clobbered")?;
    let limits = test_limits();
    let slot = SlotName::parse("slot-toctou")?;
    let target_path = root.join("roots").join(format!("{slot}.root"));
    let conflict_payload = b"concurrent_racing_process_data".to_vec();

    let io = Arc::new(ToctouConflictIo::new(
        target_path.clone(),
        conflict_payload.clone(),
    ));

    let mut publisher = LocalRootPublisher::open_with_io(&root, limits, io.clone())?;
    let leaf = publisher.stage_object(b"payload")?;
    let manifest = ObjectManifest::new("clip", [leaf], None)?;

    let res = publisher.publish(&slot, &manifest);
    assert!(
        io.conflict_created.load(Ordering::SeqCst),
        "the TOCTOU race injection must have triggered"
    );

    match res {
        Err(LocalPublicationError::InvalidLayout { path }) => {
            assert_eq!(path, target_path);
        }
        other => {
            return Err(format!("expected InvalidLayout error, got {other:?}").into());
        }
    }

    // The target file created in the TOCTOU window must NEVER be clobbered
    let disk_content = fs::read(&target_path)?;
    assert_eq!(
        disk_content, conflict_payload,
        "concurrent target file must retain its original contents and never be clobbered"
    );

    // The publisher must not be poisoned by a clean refusal
    assert!(!publisher.is_poisoned());

    // Temporary record must have been cleaned up
    let temp_path = root.join("roots").join(format!("{slot}.root.tmp"));
    assert!(
        !temp_path.exists(),
        "temporary record must be cleaned up on refusal"
    );

    Ok(())
}

/// Finding 6 / 7.6 follow-up: When reopening with a leftover temp root where the target already exists,
/// a failed remove_file must not be silently discarded; it must be recorded in orphan_temps
/// and reported in the recovery report.
#[test]
fn test_reopen_scan_records_failed_temp_removal_when_target_exists() -> TestResult {
    let root = fresh_root("test_reopen_scan_records_failed_temp_removal_when_target_exists")?;
    let limits = test_limits();

    let slot = SlotName::parse("slot-temp-fail")?;
    // 1. Cleanly publish the root
    {
        let mut publisher = LocalRootPublisher::open(&root, limits)?;
        let leaf = publisher.stage_object(b"payload")?;
        let manifest = ObjectManifest::new("clip", [leaf], None)?;
        publisher.publish(&slot, &manifest)?;
    }

    // 2. Create leftover temp file at roots/slot-temp-fail.root.tmp
    let temp_relative = PathBuf::from("roots").join(format!("{slot}.root.tmp"));
    let temp_path = root.join(&temp_relative);
    fs::write(&temp_path, b"leftover temp content")?;
    assert!(temp_path.exists());

    // 3. Reopen with FaultInjectingSpoolIo that fails RemoveFile
    let plan =
        SpoolFaultPlan::new().fail(SpoolIoCall::RemoveFile, 1, io::ErrorKind::PermissionDenied);
    let io = Arc::new(FaultInjectingSpoolIo::new(plan));
    let reopened = LocalRootPublisher::open_with_io(&root, limits, io)?;

    // The failed removal must be recorded in orphan_temps and recovery report
    let report = reopened.recovery_report();
    assert!(
        report.orphaned_temps.contains(&temp_relative),
        "recovery report must report the failed temp removal in orphaned_temps: {report:?}"
    );
    assert!(temp_path.exists(), "temp file must remain on disk");
    Ok(())
}

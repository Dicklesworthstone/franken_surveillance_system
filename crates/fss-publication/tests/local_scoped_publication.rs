#![forbid(unsafe_code)]
//! Scoped production opening preserves native recovery while retaining current authority.

use std::fs::{self, DirEntry, File, FileType, Metadata, ReadDir, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use fss_core::ContentDigest;
use fss_object::{HostSpoolIo, ObjectManifest, SpoolIo, SpoolLimits};
use fss_publication::{
    LocalPublicationLimits, LocalRootPublisher, ScopedPublicationIo, SlotName,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> io::Result<Self> {
        for _ in 0..16 {
            let ordinal = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "fss-scoped-publication-{label}-{}-{ordinal}",
                std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(io::ErrorKind::AlreadyExists, "fixture exhausted"))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        16,
        16,
        16,
        128,
        SpoolLimits::new(128, 1024 * 1024, 4096, 128),
    )
}

fn seed(root: &Path) -> TestResult<ContentDigest> {
    let mut owner = LocalRootPublisher::open(root, limits())?;
    let leaf = owner.stage_object(b"retained native original")?;
    let manifest = ObjectManifest::new("recording", [leaf], None)?;
    owner.publish(&SlotName::parse("recording")?, &manifest)?;
    Ok(leaf)
}

/// Test policy: real host I/O, an immutable root and a current, permanently revocable grant.
#[derive(Debug)]
struct Scope {
    root: PathBuf,
    live: AtomicBool,
    refused: AtomicBool,
    refuse_after_recovery: bool,
    checks: AtomicU64,
    calls: AtomicU64,
    releases: AtomicU64,
}
impl Scope {
    fn new(root: PathBuf, live: bool, refuse_after_recovery: bool) -> Arc<Self> {
        Arc::new(Self {
            root,
            live: AtomicBool::new(live),
            refused: AtomicBool::new(false),
            refuse_after_recovery,
            checks: AtomicU64::new(0),
            calls: AtomicU64::new(0),
            releases: AtomicU64::new(0),
        })
    }

    fn refuse(&self) -> io::Error {
        self.refused.store(true, Ordering::Release);
        io::Error::new(io::ErrorKind::PermissionDenied, "scoped authority refused")
    }

    fn gate(&self) -> io::Result<()> {
        if self.refused.load(Ordering::Acquire) || !self.live.load(Ordering::Acquire) {
            return Err(self.refuse());
        }
        self.calls.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    fn path(&self, path: &Path) -> io::Result<()> {
        if !path.starts_with(&self.root) || !path.is_absolute() {
            return Err(self.refuse());
        }
        self.gate()
    }
}
impl ScopedPublicationIo for Scope {
    fn check_scope(&self, root: &Path) -> io::Result<()> {
        let previous = self.checks.fetch_add(1, Ordering::AcqRel);
        if root != self.root || (self.refuse_after_recovery && previous != 0) {
            return Err(self.refuse());
        }
        self.gate()
    }
}

macro_rules! path_operations {
    ($(fn $name:ident(&self, $path:ident: &Path) -> $result:ty;)*) => {$ (
        fn $name(&self, $path: &Path) -> $result {
            self.path($path)?;
            HostSpoolIo.$name($path)
        }
    )*};
}
impl SpoolIo for Scope {
    path_operations! {
        fn create_dir_all(&self, path: &Path) -> io::Result<()>;
        fn create_dir(&self, path: &Path) -> io::Result<()>;
        fn metadata(&self, path: &Path) -> io::Result<Metadata>;
        fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata>;
        fn open_lock(&self, path: &Path) -> io::Result<File>;
        fn read_dir(&self, path: &Path) -> io::Result<ReadDir>;
        fn create_new(&self, path: &Path) -> io::Result<File>;
        fn open_read(&self, path: &Path) -> io::Result<File>;
        fn remove_file(&self, path: &Path) -> io::Result<()>;
        fn sync_directory(&self, path: &Path) -> io::Result<()>;
    }
    fn try_lock(&self, file: &File) -> Result<(), TryLockError> {
        self.gate().map_err(TryLockError::Error)?;
        HostSpoolIo.try_lock(file)
    }
    fn try_lock_shared(&self, file: &File) -> Result<(), TryLockError> {
        self.gate().map_err(TryLockError::Error)?;
        HostSpoolIo.try_lock_shared(file)
    }
    fn unlock(&self, file: &File) -> io::Result<()> {
        self.releases.fetch_add(1, Ordering::AcqRel);
        HostSpoolIo.unlock(file)
    }
    fn next_dir_entry(&self, entries: &mut ReadDir) -> Option<io::Result<DirEntry>> {
        if let Err(error) = self.gate() {
            return Some(Err(error));
        }
        HostSpoolIo.next_dir_entry(entries)
    }
    fn entry_file_type(&self, entry: &DirEntry) -> io::Result<FileType> {
        self.path(&entry.path())?;
        HostSpoolIo.entry_file_type(entry)
    }
    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
        self.gate()?;
        HostSpoolIo.write(file, bytes)
    }
    fn sync_file(&self, file: &File) -> io::Result<()> {
        self.gate()?;
        HostSpoolIo.sync_file(file)
    }
    fn read_bounded(&self, file: &mut File, limit: u64) -> io::Result<Vec<u8>> {
        self.gate()?;
        HostSpoolIo.read_bounded(file, limit)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.path(from)?;
        self.path(to)?;
        HostSpoolIo.rename(from, to)
    }
    fn hard_link(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.path(from)?;
        self.path(to)?;
        HostSpoolIo.hard_link(from, to)
    }
}

#[test]
fn current_authority_is_required_before_root_creation() -> TestResult {
    let directory = Directory::new("denied")?;
    let absent = directory.0.join("absent");
    let scope = Scope::new(absent.clone(), false, false);
    assert!(LocalRootPublisher::open_scoped(&absent, limits(), scope.clone()).is_err());
    assert!(!absent.exists());
    assert_eq!(scope.calls.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn scoped_open_cannot_select_another_root() -> TestResult {
    let directory = Directory::new("wrong-root")?;
    let allowed = directory.0.join("allowed");
    let forbidden = directory.0.join("forbidden");
    let scope = Scope::new(allowed, true, false);
    assert!(LocalRootPublisher::open_scoped(&forbidden, limits(), scope.clone()).is_err());
    assert!(!forbidden.exists());
    assert_eq!(scope.calls.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn failed_post_recovery_scope_check_releases_both_owner_locks() -> TestResult {
    let directory = Directory::new("post-open")?;
    seed(&directory.0)?;
    let scope = Scope::new(directory.0.clone(), true, true);
    assert!(LocalRootPublisher::open_scoped(&directory.0, limits(), scope.clone()).is_err());
    assert_eq!(scope.checks.load(Ordering::Acquire), 2);
    assert!(scope.calls.load(Ordering::Acquire) > 2);
    assert_eq!(scope.releases.load(Ordering::Acquire), 2);
    assert_eq!(LocalRootPublisher::open(&directory.0, limits())?.visible_roots().count(), 1);
    Ok(())
}

#[test]
fn capability_remains_attached_after_open_and_releases_after_revocation() -> TestResult {
    let directory = Directory::new("late-denial")?;
    let leaf = seed(&directory.0)?;
    let scope = Scope::new(directory.0.clone(), true, false);
    let owner = LocalRootPublisher::open_scoped(&directory.0, limits(), scope.clone())?;
    assert_eq!(owner.spool().read(leaf)?, b"retained native original");
    scope.live.store(false, Ordering::Release);
    assert!(owner.spool().read(leaf).is_err());
    scope.live.store(true, Ordering::Release);
    assert!(owner.spool().read(leaf).is_err());
    drop(owner);
    assert_eq!(scope.releases.load(Ordering::Acquire), 2);
    assert!(LocalRootPublisher::open(&directory.0, limits()).is_ok());
    Ok(())
}

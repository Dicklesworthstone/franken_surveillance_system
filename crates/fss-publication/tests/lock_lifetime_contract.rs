#![forbid(unsafe_code)]
#![cfg(unix)]
//! An inherited file description must not outlive its admitted writer ownership.
//! File::try_clone keeps exactly that description alive without a timing-dependent fork race.

use std::error::Error;
use std::fs::{self, DirEntry, File, FileType, Metadata, ReadDir, TryLockError};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use fss_core::ContentDigest;
use fss_object::{
    FaultInjectingSpoolIo, HostSpoolIo, RecordingSpoolIo, SPOOL_LOCK_FILE, SpoolError,
    SpoolFaultPlan, SpoolIo, SpoolIoCall, SpoolLimits, SpoolLock, SpoolObjectState, StagingSpool,
};
use fss_publication::{
    LOCAL_LOCK_FILE, LocalPublicationError, LocalPublicationLimits, LocalRootPublisher,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new(tag: &str) -> TestResult<Self> {
        for attempt in 0..100 {
            let root = std::env::temp_dir().join(format!(
                "fss-lock-lifetime-{tag}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => return Ok(Self(root)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("no unused lock fixture directory".into())
    }
}

impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug)]
struct RetainedFile {
    path: PathBuf,
    original: RawFd,
    _copy: File,
}

#[derive(Debug)]
struct RetainingIo {
    inner: Arc<dyn SpoolIo>,
    files: Mutex<Vec<RetainedFile>>,
    unlock_attempts: Mutex<Vec<PathBuf>>,
}

impl RetainingIo {
    fn new(inner: Arc<dyn SpoolIo>) -> Self {
        Self {
            inner,
            files: Mutex::new(Vec::new()),
            unlock_attempts: Mutex::new(Vec::new()),
        }
    }

    fn retained_paths(&self) -> TestResult<Vec<PathBuf>> {
        Ok(self
            .files
            .lock()
            .map_err(|_| "retained lock files poisoned")?
            .iter()
            .map(|entry| entry.path.clone())
            .collect())
    }

    fn attempts(&self) -> TestResult<Vec<PathBuf>> {
        Ok(self
            .unlock_attempts
            .lock()
            .map_err(|_| "unlock attempts poisoned")?
            .clone())
    }
}

impl SpoolIo for RetainingIo {
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
        let file = self.inner.open_lock(path)?;
        self.files
            .lock()
            .map_err(|_| io::Error::other("retained lock files poisoned"))?
            .push(RetainedFile {
                path: path.to_path_buf(),
                original: file.as_raw_fd(),
                _copy: file.try_clone()?,
            });
        Ok(file)
    }

    fn try_lock(&self, file: &File) -> Result<(), TryLockError> {
        self.inner.try_lock(file)
    }

    fn try_lock_shared(&self, file: &File) -> Result<(), TryLockError> {
        self.inner.try_lock_shared(file)
    }

    fn unlock(&self, file: &File) -> io::Result<()> {
        let path = self
            .files
            .lock()
            .map_err(|_| io::Error::other("retained lock files poisoned"))?
            .iter()
            .rev()
            .find(|entry| entry.original == file.as_raw_fd())
            .map(|entry| entry.path.clone())
            .ok_or_else(|| io::Error::other("unlock of an unrecorded descriptor"))?;
        self.unlock_attempts
            .lock()
            .map_err(|_| io::Error::other("unlock attempts poisoned"))?
            .push(path);
        self.inner.unlock(file)
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

    fn hard_link(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.inner.hard_link(from, to)
    }
}

fn spool_limits() -> SpoolLimits {
    SpoolLimits::new(8, 4096, 256, 64)
}

fn publication_limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(8, 8, 8, 64, spool_limits())
}

#[test]
fn dropped_publisher_releases_nested_spool_before_its_inherited_outer_lock() -> TestResult {
    let directory = OwnedDirectory::new("publisher")?;
    let recorded = Arc::new(RecordingSpoolIo::new(Arc::new(HostSpoolIo)));
    let io = Arc::new(RetainingIo::new(recorded.clone()));
    let publisher =
        LocalRootPublisher::open_with_io(&directory.0, publication_limits(), io.clone())?;
    let outer = directory.0.join(LOCAL_LOCK_FILE);
    let inner = publisher.spool().root().join(SPOOL_LOCK_FILE);
    assert_eq!(io.retained_paths()?, vec![outer.clone(), inner.clone()]);
    assert!(matches!(
        LocalRootPublisher::open(&directory.0, publication_limits()),
        Err(LocalPublicationError::Locked { .. })
    ));
    assert!(io.attempts()?.is_empty());
    drop(publisher);
    assert_eq!(io.attempts()?, vec![inner, outer]);
    assert_eq!(
        recorded
            .calls()
            .iter()
            .filter(|call| **call == SpoolIoCall::Unlock)
            .count(),
        2
    );

    // The old descriptions are still open, but their admitted ownership has ended.
    let reopened = LocalRootPublisher::open(&directory.0, publication_limits())?;
    drop(io);
    assert!(matches!(
        LocalRootPublisher::open(&directory.0, publication_limits()),
        Err(LocalPublicationError::Locked { .. })
    ));
    drop(reopened);
    drop(LocalRootPublisher::open(
        &directory.0,
        publication_limits(),
    )?);
    Ok(())
}

#[test]
fn dropped_spool_releases_inherited_lock_and_preserves_verified_payload() -> TestResult {
    let directory = OwnedDirectory::new("spool")?;
    let io = Arc::new(RetainingIo::new(Arc::new(HostSpoolIo)));
    let mut spool = StagingSpool::open_with_io(&directory.0, spool_limits(), io.clone())?;
    let bytes = b"retained custody survives writer replacement";
    let digest = ContentDigest::sha256(bytes);
    spool.stage(digest, bytes)?;
    assert_eq!(spool.verify(digest)?, SpoolObjectState::Verified);
    assert_eq!(spool.read(digest)?, bytes);
    assert!(matches!(
        StagingSpool::open(&directory.0, spool_limits()),
        Err(SpoolError::Locked { .. })
    ));
    drop(spool);
    assert_eq!(io.attempts()?, vec![directory.0.join(SPOOL_LOCK_FILE)]);
    let reopened = StagingSpool::open(&directory.0, spool_limits())?;
    assert_eq!(reopened.state(digest), Some(SpoolObjectState::Verified));
    assert_eq!(reopened.read(digest)?, bytes);
    drop(io);
    assert!(matches!(
        StagingSpool::open(&directory.0, spool_limits()),
        Err(SpoolError::Locked { .. })
    ));
    drop(reopened);
    Ok(())
}

#[test]
fn failed_opens_release_acquired_spool_and_publication_handles() -> TestResult {
    for publisher in [false, true] {
        let directory = OwnedDirectory::new(if publisher {
            "publisher-error"
        } else {
            "spool-error"
        })?;
        // ReadDir fails inside the nested spool after both locks have been acquired.
        let call = if publisher {
            SpoolIoCall::ReadDir
        } else {
            SpoolIoCall::CreateDir
        };
        let faults = Arc::new(FaultInjectingSpoolIo::new(SpoolFaultPlan::new().fail(
            call,
            1,
            io::ErrorKind::PermissionDenied,
        )));
        let io = Arc::new(RetainingIo::new(faults.clone()));
        if publisher {
            assert!(matches!(
                LocalRootPublisher::open_with_io(&directory.0, publication_limits(), io.clone()),
                Err(LocalPublicationError::Spool(_))
            ));
        } else {
            assert!(matches!(
                StagingSpool::open_with_io(&directory.0, spool_limits(), io.clone()),
                Err(SpoolError::Io {
                    kind: io::ErrorKind::PermissionDenied,
                    ..
                })
            ));
        }
        assert!(faults.all_fired());
        let mut paths = io.retained_paths()?;
        assert_eq!(paths.len(), if publisher { 2 } else { 1 });
        paths.reverse();
        assert_eq!(io.attempts()?, paths);
        assert_eq!(faults.calls(SpoolIoCall::Unlock), paths.len() as u64);
        if publisher {
            drop(LocalRootPublisher::open(
                &directory.0,
                publication_limits(),
            )?);
        } else {
            drop(StagingSpool::open(&directory.0, spool_limits())?);
        }
    }
    Ok(())
}

#[test]
fn failed_acquisition_never_unlocks_an_independent_live_owner() -> TestResult {
    let directory = OwnedDirectory::new("contender")?;
    let path = directory.0.join("LOCK");
    let owner_file = HostSpoolIo.open_lock(&path)?;
    let inherited = owner_file.try_clone()?;
    let owner = SpoolLock::try_acquire(owner_file, Arc::new(HostSpoolIo))?;
    let recorded = Arc::new(RecordingSpoolIo::new(Arc::new(HostSpoolIo)));
    assert!(matches!(
        SpoolLock::try_acquire(HostSpoolIo.open_lock(&path)?, recorded.clone()),
        Err(TryLockError::WouldBlock)
    ));
    assert!(!recorded.calls().contains(&SpoolIoCall::Unlock));
    let probe = HostSpoolIo.open_lock(&path)?;
    assert!(matches!(probe.try_lock(), Err(TryLockError::WouldBlock)));

    let denied = Arc::new(FaultInjectingSpoolIo::new(SpoolFaultPlan::new().fail(
        SpoolIoCall::TryLock,
        1,
        io::ErrorKind::PermissionDenied,
    )));
    assert!(matches!(
        SpoolLock::try_acquire(HostSpoolIo.open_lock(&path)?, denied.clone()),
        Err(TryLockError::Error(error)) if error.kind() == io::ErrorKind::PermissionDenied
    ));
    assert!(denied.all_fired());
    assert_eq!(denied.calls(SpoolIoCall::Unlock), 0);
    assert!(matches!(probe.try_lock(), Err(TryLockError::WouldBlock)));

    drop(owner);
    probe.try_lock()?;
    drop(inherited);
    let other = HostSpoolIo.open_lock(&path)?;
    assert!(matches!(other.try_lock(), Err(TryLockError::WouldBlock)));
    probe.unlock()?;
    Ok(())
}

#[test]
fn release_failures_preserve_successor_ownership_and_accounting() -> TestResult {
    for applied in [false, true] {
        let directory = OwnedDirectory::new(if applied {
            "release-applied"
        } else {
            "release-refused"
        })?;
        let path = directory.0.join("LOCK");
        let plan = if applied {
            SpoolFaultPlan::new().fail_after_applying(SpoolIoCall::Unlock, 1, io::ErrorKind::Other)
        } else {
            SpoolFaultPlan::new().fail(SpoolIoCall::Unlock, 1, io::ErrorKind::Other)
        };
        let faults = Arc::new(FaultInjectingSpoolIo::new(plan));
        let file = HostSpoolIo.open_lock(&path)?;
        let inherited = file.try_clone()?;
        let guard = SpoolLock::try_acquire(file, faults.clone())?;
        drop(guard);
        assert!(faults.all_fired());
        assert_eq!(faults.calls(SpoolIoCall::Unlock), 1);
        let successor = HostSpoolIo.open_lock(&path)?;
        if applied {
            successor.try_lock()?;
            drop(inherited);
        } else {
            assert!(matches!(
                successor.try_lock(),
                Err(TryLockError::WouldBlock)
            ));
            drop(inherited);
            successor.try_lock()?;
        }
        let other = HostSpoolIo.open_lock(&path)?;
        assert!(matches!(other.try_lock(), Err(TryLockError::WouldBlock)));
        successor.unlock()?;
    }
    Ok(())
}

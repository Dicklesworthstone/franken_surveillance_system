#![forbid(unsafe_code)]
//! One nonrenewable, current-authority I/O account for every selected recording archive.
//!
//! Native recovery may create verification holds, remove redundant root temporaries and fsync.
//! This membrane preserves that protocol while bounding its reads and filesystem calls. The
//! same account stays attached through later preflight, import and final source verification.

use std::fs::{DirEntry, File, FileType, Metadata, ReadDir, TryLockError};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use fss_object::{HostSpoolIo, SpoolIo};
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, ScopedPublicationIo};

const AUTHORITY: &str = "ERR-RTSP-CAMPAIGN-WATCH-AUTHORITY-001";
const LIMIT: &str = "ERR-RTSP-CAMPAIGN-WATCH-LIMIT-001";
const SOURCE: &str = "ERR-RTSP-IMPORT-SOURCE-001";
type Permit = dyn Fn(&Path) -> bool + Send + Sync;

/// Shared across owners and phases; opening another archive cannot reset these accounts.
pub(super) struct ArchiveReadBudget {
    maximum_bytes: u64,
    remaining_bytes: AtomicU64,
    maximum_operations: u64,
    remaining_operations: AtomicU64,
    failure: AtomicU8,
    permit: Arc<Permit>,
}
impl std::fmt::Debug for ArchiveReadBudget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ArchiveReadBudget(current authority, shared finite accounts)")
    }
}
impl ArchiveReadBudget {
    pub(super) fn new(
        maximum_read_bytes: u64,
        maximum_operations: u64,
        permit: Arc<Permit>,
    ) -> Arc<Self> {
        Arc::new(Self {
            maximum_bytes: maximum_read_bytes,
            remaining_bytes: AtomicU64::new(maximum_read_bytes),
            maximum_operations,
            remaining_operations: AtomicU64::new(maximum_operations),
            failure: AtomicU8::new(
                u8::from(maximum_read_bytes == 0 || maximum_operations == 0) * 2,
            ),
            permit,
        })
    }

    /// Observed bytes on successful reads. A failed read keeps its full reservation charged.
    pub(super) fn bytes_read(&self) -> u64 {
        self.maximum_bytes - self.remaining_bytes.load(Ordering::Acquire)
    }

    /// Admitted filesystem calls, excluding unconditional release of already-held locks.
    pub(super) fn operations(&self) -> u64 {
        self.maximum_operations - self.remaining_operations.load(Ordering::Acquire)
    }

    /// First refusal remains authoritative even if a native classifier catches its I/O error.
    pub(super) fn check(&self) -> Result<(), &'static str> {
        match self.failure.load(Ordering::Acquire) {
            1 => Err(AUTHORITY),
            2 => Err(LIMIT),
            _ => Ok(()),
        }
    }

    fn refuse(&self, kind: u8) -> io::Error {
        let _ = self
            .failure
            .compare_exchange(0, kind, Ordering::AcqRel, Ordering::Acquire);
        denied()
    }

    fn gate(&self, root: &Path, operation: bool) -> io::Result<()> {
        self.check().map_err(|_| denied())?;
        if !(self.permit)(root) {
            return Err(self.refuse(1));
        }
        if operation {
            self.remaining_operations
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                    remaining.checked_sub(1)
                })
                .map_err(|_| self.refuse(2))?;
        }
        Ok(())
    }

    fn reserve_read(&self, bytes: u64) -> io::Result<()> {
        self.remaining_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(bytes)
            })
            .map(|_| ())
            .map_err(|_| self.refuse(2))
    }
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "current scoped archive authority or resource account refused",
    )
}

#[derive(Debug)]
struct ArchiveIo {
    root: PathBuf,
    budget: Arc<ArchiveReadBudget>,
}
impl ArchiveIo {
    fn path(&self, path: &Path) -> io::Result<()> {
        self.budget.gate(&self.root, true)?;
        self.path_bound(path)
    }

    fn path_bound(&self, path: &Path) -> io::Result<()> {
        if !path.is_absolute()
            || !path.starts_with(&self.root)
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        {
            return Err(self.budget.refuse(1));
        }
        Ok(())
    }
}
impl ScopedPublicationIo for ArchiveIo {
    fn check_scope(&self, root: &Path) -> io::Result<()> {
        self.budget.gate(&self.root, false)?;
        if root != self.root {
            return Err(self.budget.refuse(1));
        }
        self.path_bound(root)
    }
}
impl SpoolIo for ArchiveIo {
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        self.path(path)?;
        HostSpoolIo.create_dir_all(path)
    }
    fn create_dir(&self, path: &Path) -> io::Result<()> {
        self.path(path)?;
        HostSpoolIo.create_dir(path)
    }
    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.path(path)?;
        HostSpoolIo.metadata(path)
    }
    fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.path(path)?;
        HostSpoolIo.symlink_metadata(path)
    }
    fn open_lock(&self, path: &Path) -> io::Result<File> {
        self.path(path)?;
        HostSpoolIo.open_lock(path)
    }
    fn try_lock(&self, file: &File) -> Result<(), TryLockError> {
        self.budget
            .gate(&self.root, true)
            .map_err(TryLockError::Error)?;
        HostSpoolIo.try_lock(file)
    }
    fn try_lock_shared(&self, file: &File) -> Result<(), TryLockError> {
        self.budget
            .gate(&self.root, true)
            .map_err(TryLockError::Error)?;
        HostSpoolIo.try_lock_shared(file)
    }
    fn unlock(&self, file: &File) -> io::Result<()> {
        // Cancellation or account exhaustion cannot strand ownership already acquired.
        HostSpoolIo.unlock(file)
    }
    fn read_dir(&self, path: &Path) -> io::Result<ReadDir> {
        self.path(path)?;
        HostSpoolIo.read_dir(path)
    }
    fn next_dir_entry(&self, entries: &mut ReadDir) -> Option<io::Result<DirEntry>> {
        if let Err(error) = self.budget.gate(&self.root, true) {
            return Some(Err(error));
        }
        HostSpoolIo.next_dir_entry(entries)
    }
    fn entry_file_type(&self, entry: &DirEntry) -> io::Result<FileType> {
        self.path(&entry.path())?;
        HostSpoolIo.entry_file_type(entry)
    }
    fn create_new(&self, path: &Path) -> io::Result<File> {
        self.path(path)?;
        HostSpoolIo.create_new(path)
    }
    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
        self.budget.gate(&self.root, true)?;
        HostSpoolIo.write(file, bytes)
    }
    fn sync_file(&self, file: &File) -> io::Result<()> {
        self.budget.gate(&self.root, true)?;
        HostSpoolIo.sync_file(file)
    }
    fn open_read(&self, path: &Path) -> io::Result<File> {
        self.path(path)?;
        HostSpoolIo.open_read(path)
    }
    fn read_bounded(&self, file: &mut File, limit: u64) -> io::Result<Vec<u8>> {
        self.budget.gate(&self.root, true)?;
        // Reserve before allocation/I/O. Successful short reads return the unused reservation;
        // an I/O failure can have consumed an unknown prefix, so its full reservation remains.
        self.budget.reserve_read(limit)?;
        let bytes = HostSpoolIo.read_bounded(file, limit)?;
        let actual = u64::try_from(bytes.len()).map_err(|_| self.budget.refuse(2))?;
        let unused = limit
            .checked_sub(actual)
            .ok_or_else(|| self.budget.refuse(2))?;
        self.budget
            .remaining_bytes
            .fetch_add(unused, Ordering::AcqRel);
        self.budget.gate(&self.root, false)?;
        Ok(bytes)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.path(from)?;
        self.path_bound(to)?;
        HostSpoolIo.rename(from, to)
    }
    fn remove_file(&self, path: &Path) -> io::Result<()> {
        self.path(path)?;
        HostSpoolIo.remove_file(path)
    }
    fn sync_directory(&self, path: &Path) -> io::Result<()> {
        self.path(path)?;
        HostSpoolIo.sync_directory(path)
    }
    fn hard_link(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.path(from)?;
        self.path_bound(to)?;
        HostSpoolIo.hard_link(from, to)
    }
}

pub(super) fn open_archive(
    path: &Path,
    limits: LocalPublicationLimits,
    budget: &Arc<ArchiveReadBudget>,
) -> Result<LocalRootPublisher, &'static str> {
    let io = Arc::new(ArchiveIo {
        root: path.to_path_buf(),
        budget: Arc::clone(budget),
    });
    let opened = LocalRootPublisher::open_scoped(path, limits, io).map_err(|_| SOURCE);
    budget.check()?;
    opened
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_core::ContentDigest;
    use fss_object::{ObjectManifest, SpoolLimits};
    use fss_publication::SlotName;
    use std::sync::atomic::AtomicBool;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct Directory(PathBuf);
    impl Directory {
        fn new(label: &str) -> io::Result<Self> {
            for _ in 0..16 {
                let ordinal = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "fss-campaign-archive-io-{label}-{}-{ordinal}",
                    std::process::id(),
                ));
                match std::fs::create_dir(&path) {
                    Ok(()) => return Ok(Self(path)),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
            }
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "fixture exhausted",
            ))
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
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

    fn seed(path: &Path) -> TestResult<ContentDigest> {
        let mut publisher = LocalRootPublisher::open(path, limits())?;
        let leaf = publisher.stage_object(&[0x72; 3000])?;
        let manifest = ObjectManifest::new("recording", [leaf], None)?;
        publisher.publish(&SlotName::parse("native-recording")?, &manifest)?;
        Ok(leaf)
    }

    #[test]
    fn one_read_account_covers_two_real_archive_owners() -> TestResult {
        let directory = Directory::new("aggregate-read")?;
        let first = directory.0.join("first");
        let second = directory.0.join("second");
        let leaf = seed(&first)?;
        seed(&second)?;
        let allowed = [first.clone(), second.clone()];
        let budget = ArchiveReadBudget::new(
            8192,
            10_000,
            Arc::new(move |root| allowed.iter().any(|path| path == root)),
        );
        let owner = open_archive(&first, limits(), &budget)?;
        let first_bytes = budget.bytes_read();
        assert!(first_bytes >= 3000);
        assert_eq!(open_archive(&second, limits(), &budget).err(), Some(LIMIT));
        assert!(budget.bytes_read() > first_bytes);
        assert!(budget.bytes_read() <= 8192);
        // Denial is shared with an owner opened before the later root exhausted the account.
        assert!(owner.spool().read(leaf).is_err());
        assert_eq!(budget.check(), Err(LIMIT));
        drop(owner);
        // Failed admission releases every acquired lock and preserves the native roots.
        assert_eq!(
            LocalRootPublisher::open(&first, limits())?
                .visible_roots()
                .count(),
            1
        );
        assert_eq!(
            LocalRootPublisher::open(&second, limits())?
                .visible_roots()
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn filesystem_operations_are_shared_across_archive_owners() -> TestResult {
        let directory = Directory::new("aggregate-operations")?;
        let first = directory.0.join("first");
        let second = directory.0.join("second");
        seed(&first)?;
        seed(&second)?;
        let allowed = [first.clone(), second.clone()];
        let permit: Arc<Permit> = Arc::new(move |root| allowed.iter().any(|path| path == root));
        let measured = ArchiveReadBudget::new(1024 * 1024, 10_000, Arc::clone(&permit));
        drop(open_archive(&first, limits(), &measured)?);
        let first_operations = measured.operations();
        assert!(first_operations > 1);

        let budget = ArchiveReadBudget::new(1024 * 1024, first_operations + 1, permit);
        let owner = open_archive(&first, limits(), &budget)?;
        assert_eq!(budget.operations(), first_operations);
        assert_eq!(open_archive(&second, limits(), &budget).err(), Some(LIMIT));
        assert_eq!(budget.operations(), first_operations + 1);
        drop(owner);
        assert_eq!(budget.operations(), first_operations + 1);
        assert!(LocalRootPublisher::open(&first, limits()).is_ok());
        assert!(LocalRootPublisher::open(&second, limits()).is_ok());
        Ok(())
    }

    #[test]
    fn late_authority_loss_blocks_reads_and_cannot_be_reset() -> TestResult {
        let directory = Directory::new("late-authority")?;
        let root = directory.0.join("recording");
        let leaf = seed(&root)?;
        let live = Arc::new(AtomicBool::new(true));
        let current = Arc::clone(&live);
        let allowed = root.clone();
        let budget = ArchiveReadBudget::new(
            1024 * 1024,
            10_000,
            Arc::new(move |root| root == allowed && current.load(Ordering::Acquire)),
        );
        let owner = open_archive(&root, limits(), &budget)?;
        let before = budget.bytes_read();
        assert_eq!(owner.spool().read(leaf)?, vec![0x72; 3000]);
        assert!(budget.bytes_read() > before);
        let before_denial = budget.bytes_read();
        live.store(false, Ordering::Release);
        assert!(owner.spool().read(leaf).is_err());
        assert_eq!(budget.check(), Err(AUTHORITY));
        assert_eq!(budget.bytes_read(), before_denial);
        live.store(true, Ordering::Release);
        assert!(owner.spool().read(leaf).is_err());
        assert_eq!(budget.check(), Err(AUTHORITY));
        drop(owner);
        assert!(LocalRootPublisher::open(&root, limits()).is_ok());
        Ok(())
    }

    #[test]
    fn denial_precedes_root_creation_and_outside_scope_io() -> TestResult {
        let directory = Directory::new("scope")?;
        let absent = directory.0.join("absent");
        let denied_budget = ArchiveReadBudget::new(1024, 100, Arc::new(|_| false));
        assert_eq!(
            open_archive(&absent, limits(), &denied_budget).err(),
            Some(AUTHORITY)
        );
        assert!(!absent.exists());
        assert_eq!(denied_budget.operations(), 0);
        let allowed = directory.0.join("allowed");
        let outside = directory.0.join("outside");
        let budget = ArchiveReadBudget::new(1024, 100, Arc::new(|_| true));
        let io = ArchiveIo {
            root: allowed,
            budget: Arc::clone(&budget),
        };
        assert!(io.create_dir_all(&outside).is_err());
        assert!(!outside.exists());
        assert_eq!(budget.check(), Err(AUTHORITY));
        Ok(())
    }

    #[test]
    fn read_reservation_refuses_before_reading_the_file() -> TestResult {
        use std::io::Seek;
        let directory = Directory::new("read-reservation")?;
        let path = directory.0.join("payload");
        std::fs::write(&path, [0x41; 1024])?;
        let budget = ArchiveReadBudget::new(64, 100, Arc::new(|_| true));
        let io = ArchiveIo {
            root: directory.0.clone(),
            budget: Arc::clone(&budget),
        };
        let mut file = io.open_read(&path)?;
        assert!(io.read_bounded(&mut file, 65).is_err());
        assert_eq!(file.stream_position()?, 0);
        assert_eq!(budget.bytes_read(), 0);
        assert_eq!(budget.check(), Err(LIMIT));
        Ok(())
    }

    #[test]
    fn authority_expiring_during_a_read_blocks_returning_the_bytes() -> TestResult {
        let directory = Directory::new("read-release")?;
        let path = directory.0.join("payload");
        std::fs::write(&path, [0x41; 32])?;
        let checks = Arc::new(AtomicU64::new(0));
        let current = Arc::clone(&checks);
        let budget = ArchiveReadBudget::new(
            1024,
            100,
            Arc::new(move |_| current.fetch_add(1, Ordering::AcqRel) < 2),
        );
        let io = ArchiveIo {
            root: directory.0.clone(),
            budget: Arc::clone(&budget),
        };
        let mut file = io.open_read(&path)?;
        assert!(io.read_bounded(&mut file, 64).is_err());
        assert_eq!(budget.bytes_read(), 32);
        assert_eq!(budget.check(), Err(AUTHORITY));
        assert_eq!(checks.load(Ordering::Acquire), 3);
        Ok(())
    }
}

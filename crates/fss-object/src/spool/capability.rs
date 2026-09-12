//! Explicit filesystem capability for the staging spool.
//!
//! [`StagingSpool`](super::StagingSpool) performs every filesystem call through one [`SpoolIo`]
//! value supplied when it opens. [`HostSpoolIo`] is the host filesystem. [`FaultInjectingSpoolIo`]
//! wraps it and fails a chosen call at a chosen occurrence with a chosen [`io::ErrorKind`], so
//! every I/O step of ingest, read, recovery, and cleanup can be driven into its failure path
//! deterministically. Neither implementation holds global state.

use std::fmt;
use std::fs::{self, DirEntry, File, FileType, Metadata, OpenOptions, ReadDir, TryLockError};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// One kind of filesystem call the spool makes through its [`SpoolIo`] capability.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SpoolIoCall {
    /// Creating the spool root and any missing parents.
    CreateDirAll,
    /// Reading metadata while following symlinks.
    Metadata,
    /// Reading metadata without following symlinks.
    SymlinkMetadata,
    /// Opening or creating the lock file.
    OpenLock,
    /// Taking the exclusive lock on the opened lock file.
    TryLock,
    /// Creating one spool subdirectory.
    CreateDir,
    /// Opening a directory listing.
    ReadDir,
    /// Advancing a directory listing by one entry.
    NextDirEntry,
    /// Reading the file type of one listed entry.
    EntryFileType,
    /// Creating a fresh staging file that must not already exist.
    CreateNew,
    /// One write into a staging file.
    Write,
    /// Fsyncing a staging file.
    SyncFile,
    /// Opening an object or staging file for reading.
    OpenRead,
    /// Reading an opened file up to a byte bound.
    Read,
    /// Renaming a staging file onto its object name.
    Rename,
    /// Removing a staging file.
    RemoveFile,
    /// Fsyncing a directory.
    SyncDirectory,
}

impl SpoolIoCall {
    /// Every call kind, in declaration order.
    pub const ALL: [Self; 17] = [
        Self::CreateDirAll,
        Self::Metadata,
        Self::SymlinkMetadata,
        Self::OpenLock,
        Self::TryLock,
        Self::CreateDir,
        Self::ReadDir,
        Self::NextDirEntry,
        Self::EntryFileType,
        Self::CreateNew,
        Self::Write,
        Self::SyncFile,
        Self::OpenRead,
        Self::Read,
        Self::Rename,
        Self::RemoveFile,
        Self::SyncDirectory,
    ];

    const fn index(self) -> usize {
        self as usize
    }
}

impl fmt::Display for SpoolIoCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CreateDirAll => "create_dir_all",
            Self::Metadata => "metadata",
            Self::SymlinkMetadata => "symlink_metadata",
            Self::OpenLock => "open_lock",
            Self::TryLock => "try_lock",
            Self::CreateDir => "create_dir",
            Self::ReadDir => "read_dir",
            Self::NextDirEntry => "next_dir_entry",
            Self::EntryFileType => "entry_file_type",
            Self::CreateNew => "create_new",
            Self::Write => "write",
            Self::SyncFile => "sync_file",
            Self::OpenRead => "open_read",
            Self::Read => "read",
            Self::Rename => "rename",
            Self::RemoveFile => "remove_file",
            Self::SyncDirectory => "sync_directory",
        })
    }
}

/// Filesystem authority the spool exercises. Every spool filesystem call goes through it.
///
/// Implementations must be deterministic for a given host state and must not consult ambient
/// global state. Each method corresponds to exactly one [`SpoolIoCall`].
pub trait SpoolIo: fmt::Debug + Send + Sync {
    /// Creates `path` and any missing parents.
    fn create_dir_all(&self, path: &Path) -> io::Result<()>;
    /// Reads metadata, following symlinks.
    fn metadata(&self, path: &Path) -> io::Result<Metadata>;
    /// Reads metadata without following symlinks.
    fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata>;
    /// Opens the lock file for read and write, creating it without truncation.
    fn open_lock(&self, path: &Path) -> io::Result<File>;
    /// Takes an exclusive, non-blocking lock on an opened lock file.
    fn try_lock(&self, file: &File) -> Result<(), TryLockError>;
    /// Creates one directory whose parent exists.
    fn create_dir(&self, path: &Path) -> io::Result<()>;
    /// Opens a directory listing.
    fn read_dir(&self, path: &Path) -> io::Result<ReadDir>;
    /// Advances a directory listing by one entry; `None` ends the listing.
    fn next_dir_entry(&self, entries: &mut ReadDir) -> Option<io::Result<DirEntry>>;
    /// Reads the file type of one listed entry without following symlinks.
    fn entry_file_type(&self, entry: &DirEntry) -> io::Result<FileType>;
    /// Creates a new file for writing; fails with `AlreadyExists` if the name is taken.
    fn create_new(&self, path: &Path) -> io::Result<File>;
    /// Writes a prefix of `bytes` and returns how many bytes were accepted.
    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize>;
    /// Fsyncs an open file's data and metadata.
    fn sync_file(&self, file: &File) -> io::Result<()>;
    /// Opens a file for reading.
    fn open_read(&self, path: &Path) -> io::Result<File>;
    /// Reads from the current position to end of file, stopping after `limit` bytes.
    fn read_bounded(&self, file: &mut File, limit: u64) -> io::Result<Vec<u8>>;
    /// Atomically renames `from` onto `to`.
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    /// Removes one file.
    fn remove_file(&self, path: &Path) -> io::Result<()>;
    /// Fsyncs a directory so entries created or renamed in it are durable.
    fn sync_directory(&self, path: &Path) -> io::Result<()>;
}

/// The host filesystem. [`StagingSpool::open`](super::StagingSpool::open) uses it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HostSpoolIo;

impl SpoolIo for HostSpoolIo {
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        fs::create_dir_all(path)
    }

    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        fs::metadata(path)
    }

    fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata> {
        fs::symlink_metadata(path)
    }

    fn open_lock(&self, path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
    }

    fn try_lock(&self, file: &File) -> Result<(), TryLockError> {
        file.try_lock()
    }

    fn create_dir(&self, path: &Path) -> io::Result<()> {
        fs::create_dir(path)
    }

    fn read_dir(&self, path: &Path) -> io::Result<ReadDir> {
        fs::read_dir(path)
    }

    fn next_dir_entry(&self, entries: &mut ReadDir) -> Option<io::Result<DirEntry>> {
        entries.next()
    }

    fn entry_file_type(&self, entry: &DirEntry) -> io::Result<FileType> {
        entry.file_type()
    }

    fn create_new(&self, path: &Path) -> io::Result<File> {
        OpenOptions::new().create_new(true).write(true).open(path)
    }

    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
        file.write(bytes)
    }

    fn sync_file(&self, file: &File) -> io::Result<()> {
        file.sync_all()
    }

    fn open_read(&self, path: &Path) -> io::Result<File> {
        File::open(path)
    }

    fn read_bounded(&self, file: &mut File, limit: u64) -> io::Result<Vec<u8>> {
        let mut raw = Vec::new();
        Read::by_ref(file).take(limit).read_to_end(&mut raw)?;
        Ok(raw)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }

    fn sync_directory(&self, path: &Path) -> io::Result<()> {
        File::open(path)?.sync_all()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    /// The call is not performed and fails.
    Error(io::ErrorKind),
    /// The call is performed on the host, then reported as failed.
    ErrorAfterApplying(io::ErrorKind),
    /// A write accepts at most this many bytes and reports success.
    ShortWrite(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FaultRule {
    call: SpoolIoCall,
    occurrence: u64,
    fault: Fault,
}

/// Deterministic set of one-shot faults, each keyed by call kind and 1-based occurrence.
///
/// Occurrences count every call of that kind made through one [`FaultInjectingSpoolIo`] since it
/// was constructed, including calls made while the spool opens. Occurrence `0` never fires.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SpoolFaultPlan {
    rules: Vec<FaultRule>,
}

impl SpoolFaultPlan {
    /// A plan that injects nothing; useful for counting calls.
    #[must_use]
    pub const fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Fails the `occurrence`-th `call` with `kind` without performing it.
    #[must_use]
    pub fn fail(self, call: SpoolIoCall, occurrence: u64, kind: io::ErrorKind) -> Self {
        self.with(call, occurrence, Fault::Error(kind))
    }

    /// Performs the `occurrence`-th `call` on the host, then reports it failed with `kind`.
    ///
    /// This models an ambiguous outcome: the effect happened but the caller was told otherwise.
    /// If the host call itself fails, its error is returned unchanged and the fault still counts
    /// as fired.
    #[must_use]
    pub fn fail_after_applying(
        self,
        call: SpoolIoCall,
        occurrence: u64,
        kind: io::ErrorKind,
    ) -> Self {
        self.with(call, occurrence, Fault::ErrorAfterApplying(kind))
    }

    /// Makes the `occurrence`-th write accept at most `accepted` bytes and report success.
    #[must_use]
    pub fn short_write(self, occurrence: u64, accepted: usize) -> Self {
        self.with(SpoolIoCall::Write, occurrence, Fault::ShortWrite(accepted))
    }

    /// Fails `times` consecutive `call`s with [`io::ErrorKind::Interrupted`], starting at the
    /// `first` occurrence, without performing them; later calls succeed unless another rule
    /// matches.
    ///
    /// This models a signal arriving before any byte is transferred, which is when POSIX reports
    /// `EINTR`: an interrupted call has no effect. Each interruption is one one-shot rule, so
    /// [`FaultInjectingSpoolIo::all_fired`] is true only once all `times` calls were made.
    #[must_use]
    pub fn interrupted(mut self, call: SpoolIoCall, first: u64, times: u64) -> Self {
        for offset in 0..times {
            self = self.fail(
                call,
                first.saturating_add(offset),
                io::ErrorKind::Interrupted,
            );
        }
        self
    }

    fn with(mut self, call: SpoolIoCall, occurrence: u64, fault: Fault) -> Self {
        self.rules.push(FaultRule {
            call,
            occurrence,
            fault,
        });
        self
    }
}

#[derive(Debug)]
struct ArmedRule {
    rule: FaultRule,
    fired: AtomicBool,
}

/// Host filesystem wrapped with a deterministic [`SpoolFaultPlan`].
///
/// Calls that match no rule are performed on the host. Every call is counted per
/// [`SpoolIoCall`], so a test can learn how many calls a spool operation makes and aim a fault at
/// any one of them. Counters and rules are per instance; nothing is shared between instances.
#[derive(Debug)]
pub struct FaultInjectingSpoolIo {
    host: HostSpoolIo,
    rules: Vec<ArmedRule>,
    calls: [AtomicU64; SpoolIoCall::ALL.len()],
}

impl FaultInjectingSpoolIo {
    /// Wraps the host filesystem with `plan`.
    #[must_use]
    pub fn new(plan: SpoolFaultPlan) -> Self {
        Self {
            host: HostSpoolIo,
            rules: plan
                .rules
                .into_iter()
                .map(|rule| ArmedRule {
                    rule,
                    fired: AtomicBool::new(false),
                })
                .collect(),
            calls: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    /// Number of `call` calls made so far, including failed ones.
    #[must_use]
    pub fn calls(&self, call: SpoolIoCall) -> u64 {
        self.calls
            .get(call.index())
            .map_or(0, |counter| counter.load(Ordering::SeqCst))
    }

    /// Number of planned faults that have fired.
    #[must_use]
    pub fn fired(&self) -> usize {
        self.rules
            .iter()
            .filter(|armed| armed.fired.load(Ordering::SeqCst))
            .count()
    }

    /// True when every planned fault has fired.
    #[must_use]
    pub fn all_fired(&self) -> bool {
        self.fired() == self.rules.len()
    }

    fn next_fault(&self, call: SpoolIoCall) -> Option<Fault> {
        let occurrence = self
            .calls
            .get(call.index())?
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1);
        self.rules.iter().find_map(|armed| {
            let matches = armed.rule.call == call && armed.rule.occurrence == occurrence;
            (matches
                && armed
                    .fired
                    .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok())
            .then_some(armed.rule.fault)
        })
    }

    fn intercept<T>(
        &self,
        call: SpoolIoCall,
        operation: impl FnOnce(&HostSpoolIo) -> io::Result<T>,
    ) -> io::Result<T> {
        match self.next_fault(call) {
            Some(Fault::Error(kind)) => Err(io::Error::from(kind)),
            Some(Fault::ErrorAfterApplying(kind)) => {
                operation(&self.host)?;
                Err(io::Error::from(kind))
            }
            // Short writes are only planned for `Write`, which does not use this helper.
            Some(Fault::ShortWrite(_)) | None => operation(&self.host),
        }
    }
}

impl SpoolIo for FaultInjectingSpoolIo {
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        self.intercept(SpoolIoCall::CreateDirAll, |host| host.create_dir_all(path))
    }

    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.intercept(SpoolIoCall::Metadata, |host| host.metadata(path))
    }

    fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.intercept(SpoolIoCall::SymlinkMetadata, |host| {
            host.symlink_metadata(path)
        })
    }

    fn open_lock(&self, path: &Path) -> io::Result<File> {
        self.intercept(SpoolIoCall::OpenLock, |host| host.open_lock(path))
    }

    fn try_lock(&self, file: &File) -> Result<(), TryLockError> {
        match self.next_fault(SpoolIoCall::TryLock) {
            Some(Fault::Error(kind)) => Err(TryLockError::Error(io::Error::from(kind))),
            Some(Fault::ErrorAfterApplying(kind)) => {
                self.host.try_lock(file)?;
                Err(TryLockError::Error(io::Error::from(kind)))
            }
            Some(Fault::ShortWrite(_)) | None => self.host.try_lock(file),
        }
    }

    fn create_dir(&self, path: &Path) -> io::Result<()> {
        self.intercept(SpoolIoCall::CreateDir, |host| host.create_dir(path))
    }

    fn read_dir(&self, path: &Path) -> io::Result<ReadDir> {
        self.intercept(SpoolIoCall::ReadDir, |host| host.read_dir(path))
    }

    fn next_dir_entry(&self, entries: &mut ReadDir) -> Option<io::Result<DirEntry>> {
        match self.next_fault(SpoolIoCall::NextDirEntry) {
            Some(Fault::Error(kind)) => Some(Err(io::Error::from(kind))),
            Some(Fault::ErrorAfterApplying(kind)) => {
                let _consumed = self.host.next_dir_entry(entries);
                Some(Err(io::Error::from(kind)))
            }
            Some(Fault::ShortWrite(_)) | None => self.host.next_dir_entry(entries),
        }
    }

    fn entry_file_type(&self, entry: &DirEntry) -> io::Result<FileType> {
        self.intercept(SpoolIoCall::EntryFileType, |host| {
            host.entry_file_type(entry)
        })
    }

    fn create_new(&self, path: &Path) -> io::Result<File> {
        self.intercept(SpoolIoCall::CreateNew, |host| host.create_new(path))
    }

    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
        match self.next_fault(SpoolIoCall::Write) {
            Some(Fault::Error(kind)) => Err(io::Error::from(kind)),
            Some(Fault::ErrorAfterApplying(kind)) => {
                self.host.write(file, bytes)?;
                Err(io::Error::from(kind))
            }
            Some(Fault::ShortWrite(accepted)) => {
                let prefix = bytes.get(..accepted.min(bytes.len())).unwrap_or_default();
                if prefix.is_empty() {
                    return Ok(0);
                }
                self.host.write(file, prefix)
            }
            None => self.host.write(file, bytes),
        }
    }

    fn sync_file(&self, file: &File) -> io::Result<()> {
        self.intercept(SpoolIoCall::SyncFile, |host| host.sync_file(file))
    }

    fn open_read(&self, path: &Path) -> io::Result<File> {
        self.intercept(SpoolIoCall::OpenRead, |host| host.open_read(path))
    }

    fn read_bounded(&self, file: &mut File, limit: u64) -> io::Result<Vec<u8>> {
        self.intercept(SpoolIoCall::Read, |host| host.read_bounded(file, limit))
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.intercept(SpoolIoCall::Rename, |host| host.rename(from, to))
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        self.intercept(SpoolIoCall::RemoveFile, |host| host.remove_file(path))
    }

    fn sync_directory(&self, path: &Path) -> io::Result<()> {
        self.intercept(SpoolIoCall::SyncDirectory, |host| host.sync_directory(path))
    }
}

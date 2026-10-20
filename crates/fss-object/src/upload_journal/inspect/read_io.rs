#![forbid(unsafe_code)]
//! Deny-all-mutations adapter whose reads spend actual scoped inspection authority.

use std::fmt;
use std::fs::{self, DirEntry, File, FileType, Metadata, OpenOptions, ReadDir, TryLockError};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use fss_core::{BudgetVector, RegionTree, RuntimeGrant, TimestampNs};
use fss_runtime::authority::AuthorityCx;

use crate::multipart::MultipartError;
use crate::spool::{SPOOL_HOLDS_DIR, SPOOL_OBJECTS_DIR, SPOOL_STAGING_DIR, SpoolIo};
use crate::upload_journal::io::FileIdentity;
use crate::upload_journal::persistence;

use super::admit;

pub(super) struct ReadAuthorityIo<'a> {
    authority: Mutex<&'a mut AuthorityCx>,
    tree: &'a RegionTree,
    now: TimestampNs,
    resource: &'a str,
    remaining_read: Mutex<u64>,
    directories: Vec<(PathBuf, File)>,
}

impl fmt::Debug for ReadAuthorityIo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadAuthorityIo").finish_non_exhaustive()
    }
}

impl<'a> ReadAuthorityIo<'a> {
    pub(super) fn new(
        authority: &'a mut AuthorityCx,
        tree: &'a RegionTree,
        now: TimestampNs,
        resource: &'a str,
        read_allowance: u64,
    ) -> Result<Self, MultipartError> {
        if !cfg!(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )) {
            return Err(persistence(
                "descriptor-bound upload inspection is unsupported on this host",
            ));
        }
        Ok(Self {
            authority: Mutex::new(authority),
            tree,
            now,
            resource,
            remaining_read: Mutex::new(read_allowance),
            directories: Vec::new(),
        })
    }

    fn debit(&self, bytes: u64, operations: u64) -> io::Result<()> {
        let mut authority = self
            .authority
            .lock()
            .map_err(|_| io::Error::other("inspection accounting poisoned"))?;
        admit(
            &authority,
            self.tree,
            self.now,
            self.resource,
            RuntimeGrant::ObserveStatus,
        )
        .map_err(io::Error::other)?;
        let mut cost = BudgetVector::ZERO;
        cost.bytes = bytes;
        cost.storage_operations = operations;
        authority
            .budget_mut(self.tree)
            .map_err(io::Error::other)?
            .spend_vector(&cost)
            .map_err(io::Error::other)
    }

    pub(super) fn pin_layout(
        &mut self,
        root: &Path,
        identities: &[(PathBuf, FileIdentity)],
    ) -> Result<(), MultipartError> {
        for path in [
            root.to_path_buf(),
            root.join(SPOOL_OBJECTS_DIR),
            root.join(SPOOL_STAGING_DIR),
            root.join(SPOOL_HOLDS_DIR),
        ] {
            let expected = identities
                .iter()
                .find(|(name, _)| *name == path)
                .map(|(_, identity)| *identity)
                .ok_or_else(|| persistence("inspection directory identity absent"))?;
            self.debit(0, 2).map_err(persistence)?;
            let opened = options(true)
                .open(self.path(&path, false).map_err(persistence)?)
                .map_err(persistence)?;
            if FileIdentity::from_metadata(&opened.metadata().map_err(persistence)?)
                .map_err(persistence)?
                != expected
            {
                return Err(persistence(
                    "upload inspection directory changed while opening",
                ));
            }
            self.directories.push((path, opened));
        }
        Ok(())
    }

    fn path(&self, path: &Path, include_directory: bool) -> io::Result<PathBuf> {
        for (name, directory) in self.directories.iter().rev() {
            if let Ok(relative) = path.strip_prefix(name)
                && (include_directory || !relative.as_os_str().is_empty())
            {
                return Ok(descriptor_path(directory)?.join(relative));
            }
        }
        Ok(path.to_path_buf())
    }
}

fn descriptor_path(file: &File) -> io::Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        Ok(PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd())))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = file;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "descriptor namespace unsupported",
        ))
    }
}

fn options(directory: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let (nofollow, directory_flag) = if cfg!(target_arch = "x86_64") {
            (0o400_000, 0o200_000)
        } else {
            (0o100_000, 0o40_000)
        };
        options.custom_flags(nofollow | 0o4_000 | if directory { directory_flag } else { 0 });
    }
    options
}

fn mutation() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "upload inspection cannot mutate or lock its journal",
    )
}

impl SpoolIo for ReadAuthorityIo<'_> {
    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.symlink_metadata(path)
    }
    fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.debit(0, 1)?;
        fs::symlink_metadata(self.path(path, false)?)
    }
    fn read_dir(&self, path: &Path) -> io::Result<ReadDir> {
        self.debit(0, 1)?;
        fs::read_dir(self.path(path, true)?)
    }
    fn next_dir_entry(&self, entries: &mut ReadDir) -> Option<io::Result<DirEntry>> {
        if let Err(error) = self.debit(0, 1) {
            return Some(Err(error));
        }
        entries.next()
    }
    fn entry_file_type(&self, entry: &DirEntry) -> io::Result<FileType> {
        self.debit(0, 1)?;
        entry.file_type()
    }
    fn open_read(&self, path: &Path) -> io::Result<File> {
        self.debit(0, 3)?;
        let path = self.path(path, false)?;
        let named = fs::symlink_metadata(&path)?;
        if !named.file_type().is_file() {
            return Err(io::Error::other(
                "inspection requires a regular object file",
            ));
        }
        let file = options(false).open(&path)?;
        if FileIdentity::from_metadata(&file.metadata()?)? != FileIdentity::from_metadata(&named)? {
            return Err(io::Error::other(
                "upload journal object identity changed before read",
            ));
        }
        Ok(file)
    }
    fn read_bounded(&self, file: &mut File, limit: u64) -> io::Result<Vec<u8>> {
        self.debit(0, 1)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file() {
            return Err(io::Error::other(
                "inspection requires a regular object file",
            ));
        }
        let amount = limit.min(metadata.len().saturating_add(1));
        let mut remaining = self
            .remaining_read
            .lock()
            .map_err(|_| io::Error::other("inspection read accounting poisoned"))?;
        if amount > *remaining {
            return Err(io::Error::other(
                "upload inspection read allowance exhausted",
            ));
        }
        self.debit(amount, 1)?;
        *remaining -= amount;
        drop(remaining);
        let mut bytes = Vec::new();
        Read::by_ref(file).take(amount).read_to_end(&mut bytes)?;
        Ok(bytes)
    }
    fn create_dir_all(&self, _: &Path) -> io::Result<()> {
        Err(mutation())
    }
    fn open_lock(&self, _: &Path) -> io::Result<File> {
        Err(mutation())
    }
    fn try_lock(&self, _: &File) -> Result<(), TryLockError> {
        Err(TryLockError::Error(mutation()))
    }
    fn try_lock_shared(&self, _: &File) -> Result<(), TryLockError> {
        Err(TryLockError::Error(mutation()))
    }
    fn unlock(&self, _: &File) -> io::Result<()> {
        Err(mutation())
    }
    fn create_dir(&self, _: &Path) -> io::Result<()> {
        Err(mutation())
    }
    fn create_new(&self, _: &Path) -> io::Result<File> {
        Err(mutation())
    }
    fn write(&self, _: &mut File, _: &[u8]) -> io::Result<usize> {
        Err(mutation())
    }
    fn sync_file(&self, _: &File) -> io::Result<()> {
        Err(mutation())
    }
    fn rename(&self, _: &Path, _: &Path) -> io::Result<()> {
        Err(mutation())
    }
    fn remove_file(&self, _: &Path) -> io::Result<()> {
        Err(mutation())
    }
    fn sync_directory(&self, _: &Path) -> io::Result<()> {
        Err(mutation())
    }
    fn hard_link(&self, _: &Path, _: &Path) -> io::Result<()> {
        Err(mutation())
    }
}

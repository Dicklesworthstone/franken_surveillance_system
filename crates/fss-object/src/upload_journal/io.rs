//! Local, owned read accounting around the caller's explicit spool I/O capability.

use std::fs::{DirEntry, File, FileType, Metadata, ReadDir, TryLockError};
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::SpoolIo;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FileIdentity {
    device: u64,
    inode: u64,
    directory: bool,
}

impl FileIdentity {
    pub(super) fn from_metadata(metadata: &Metadata) -> io::Result<Self> {
        if !metadata.file_type().is_file() && !metadata.file_type().is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal entry is not a regular file or directory",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                directory: metadata.is_dir(),
            })
        }
        #[cfg(not(unix))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "upload journal requires stable file identity on this platform",
            ))
        }
    }
}

#[derive(Debug)]
pub(super) struct BudgetedJournalIo {
    inner: Arc<dyn SpoolIo>,
    remaining: Mutex<u64>,
}

impl BudgetedJournalIo {
    pub(super) fn new(inner: Arc<dyn SpoolIo>, allowance: u64) -> Self {
        Self {
            inner,
            remaining: Mutex::new(allowance),
        }
    }

    fn reserve(&self, bytes: u64) -> io::Result<()> {
        let mut remaining = self
            .remaining
            .lock()
            .map_err(|_| io::Error::other("journal read accounting poisoned"))?;
        *remaining = remaining
            .checked_sub(bytes)
            .ok_or_else(|| io::Error::other("upload journal read allowance exhausted"))?;
        Ok(())
    }

    fn refund_unused(&self, bytes: u64) -> io::Result<()> {
        let mut remaining = self
            .remaining
            .lock()
            .map_err(|_| io::Error::other("journal read accounting poisoned"))?;
        *remaining = remaining
            .checked_add(bytes)
            .ok_or_else(|| io::Error::other("upload journal read accounting overflow"))?;
        Ok(())
    }
}

impl SpoolIo for BudgetedJournalIo {
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
        let opened = FileIdentity::from_metadata(&file.metadata()?)?;
        let named = FileIdentity::from_metadata(&self.inner.symlink_metadata(path)?)?;
        if opened != named || opened.directory {
            return Err(io::Error::other(
                "journal lock name does not identify the opened file",
            ));
        }
        Ok(file)
    }
    fn try_lock(&self, file: &File) -> Result<(), TryLockError> {
        self.inner.try_lock(file)
    }
    fn try_lock_shared(&self, file: &File) -> Result<(), TryLockError> {
        self.inner.try_lock_shared(file)
    }
    fn unlock(&self, file: &File) -> io::Result<()> {
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
        // Reserve before touching the file. A failed read can have consumed bytes, so its
        // reservation is never refunded. A successful short read refunds only proven unused work.
        self.reserve(limit)?;
        let bytes = self.inner.read_bounded(file, limit)?;
        let used = bytes.len() as u64;
        if used > limit {
            return Err(io::Error::other("spool I/O exceeded reserved journal read"));
        }
        self.refund_unused(limit - used)?;
        Ok(bytes)
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

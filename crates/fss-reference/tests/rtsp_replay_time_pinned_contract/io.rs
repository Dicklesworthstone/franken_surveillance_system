#![forbid(unsafe_code)]
//! A read-only host capability that records actual calls; optional rewrites model another owner.

use std::fs::{DirEntry, File, FileType, Metadata, ReadDir, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use fss_object::{HostSpoolIo, SpoolIo};

#[derive(Debug)]
pub struct Rewrite {
    pub when: PathBuf,
    pub occurrence: usize,
    pub target: PathBuf,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct ReadOnlyIo {
    pub calls: AtomicU64,
    pub read_bytes: AtomicU64,
    pub forbidden: AtomicU64,
    pub opened: Mutex<Vec<PathBuf>>,
    pub rewrite: Option<Rewrite>,
    pub rewritten: AtomicBool,
}

impl ReadOnlyIo {
    pub fn opened_count(&self, path: &Path) -> usize {
        self.opened
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|candidate| candidate.as_path() == path)
            .count()
    }

    fn call(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }

    fn refuse(&self) -> io::Error {
        self.forbidden.fetch_add(1, Ordering::SeqCst);
        io::Error::new(io::ErrorKind::PermissionDenied, "query attempted a write, lock or scan")
    }
}

impl SpoolIo for ReadOnlyIo {
    fn create_dir_all(&self, _: &Path) -> io::Result<()> {
        Err(self.refuse())
    }
    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.call();
        HostSpoolIo.metadata(path)
    }
    fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.call();
        HostSpoolIo.symlink_metadata(path)
    }
    fn open_lock(&self, _: &Path) -> io::Result<File> {
        Err(self.refuse())
    }
    fn try_lock(&self, _: &File) -> Result<(), TryLockError> {
        Err(TryLockError::Error(self.refuse()))
    }
    fn try_lock_shared(&self, _: &File) -> Result<(), TryLockError> {
        Err(TryLockError::Error(self.refuse()))
    }
    fn unlock(&self, _: &File) -> io::Result<()> {
        Err(self.refuse())
    }
    fn create_dir(&self, _: &Path) -> io::Result<()> {
        Err(self.refuse())
    }
    fn read_dir(&self, _: &Path) -> io::Result<ReadDir> {
        Err(self.refuse())
    }
    fn next_dir_entry(&self, _: &mut ReadDir) -> Option<io::Result<DirEntry>> {
        Some(Err(self.refuse()))
    }
    fn entry_file_type(&self, _: &DirEntry) -> io::Result<FileType> {
        Err(self.refuse())
    }
    fn create_new(&self, _: &Path) -> io::Result<File> {
        Err(self.refuse())
    }
    fn write(&self, _: &mut File, _: &[u8]) -> io::Result<usize> {
        Err(self.refuse())
    }
    fn sync_file(&self, _: &File) -> io::Result<()> {
        Err(self.refuse())
    }
    fn open_read(&self, path: &Path) -> io::Result<File> {
        self.call();
        self.opened
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(path.to_path_buf());
        if let Some(rewrite) = &self.rewrite
            && path == rewrite.when.as_path()
            && self.opened_count(path) == rewrite.occurrence
            && !self.rewritten.swap(true, Ordering::SeqCst)
        {
            // This test-only adversary uses a separate host capability. The query's
            // own supplied capability refuses every mutation method above/below.
            std::fs::write(&rewrite.target, &rewrite.bytes)?;
        }
        HostSpoolIo.open_read(path)
    }
    fn read_bounded(&self, file: &mut File, limit: u64) -> io::Result<Vec<u8>> {
        self.call();
        let bytes = HostSpoolIo.read_bounded(file, limit)?;
        self.read_bytes.fetch_add(bytes.len() as u64, Ordering::SeqCst);
        Ok(bytes)
    }
    fn rename(&self, _: &Path, _: &Path) -> io::Result<()> {
        Err(self.refuse())
    }
    fn remove_file(&self, _: &Path) -> io::Result<()> {
        Err(self.refuse())
    }
    fn sync_directory(&self, _: &Path) -> io::Result<()> {
        Err(self.refuse())
    }
    fn hard_link(&self, _: &Path, _: &Path) -> io::Result<()> {
        Err(self.refuse())
    }
}

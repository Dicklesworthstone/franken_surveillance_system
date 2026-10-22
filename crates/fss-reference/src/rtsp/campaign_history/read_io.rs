#![forbid(unsafe_code)]
//! A strictly non-mutating filesystem membrane with current Cx and one shared work account.

use std::fs::{DirEntry, File, FileType, Metadata, ReadDir, TryLockError};
use std::io;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use fss_geometry::WorkBudget;
use fss_object::{HostSpoolIo, SpoolIo};
use fss_publication::LockTableSource;

use super::{
    CampaignAuthority, CampaignHistoryError as Error, CampaignPin, STAGE_CAMPAIGN_HISTORY,
};
use crate::ReplayCx;

pub(super) fn check_read(
    authority: &dyn CampaignAuthority,
    pin: CampaignPin,
    root: &Path,
    cx: &ReplayCx,
) -> super::Result<()> {
    if cx.checkpoint(STAGE_CAMPAIGN_HISTORY).is_err()
        || !cx.io_authority().is_valid()
        || cx.root_dir() != root
        || !authority.permit_read(pin, root, cx.io_authority().principal())
    {
        return Err(Error::Denied);
    }
    Ok(())
}

pub(super) struct ReadIo<'a, 'budget> {
    pin: CampaignPin,
    root: &'a Path,
    authority: &'a dyn CampaignAuthority,
    cx: &'a ReplayCx,
    work: Mutex<&'a mut WorkBudget<'budget>>,
    bytes: &'a ReadAllowance,
    failure: AtomicU8,
}
impl std::fmt::Debug for ReadIo<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CampaignReadIo(scoped, read-only)")
    }
}
impl<'a, 'budget> ReadIo<'a, 'budget> {
    pub fn new(
        pin: CampaignPin,
        root: &'a Path,
        authority: &'a dyn CampaignAuthority,
        cx: &'a ReplayCx,
        work: &'a mut WorkBudget<'budget>,
        bytes: &'a ReadAllowance,
    ) -> Self {
        Self {
            pin,
            root,
            authority,
            cx,
            work: Mutex::new(work),
            bytes,
            failure: AtomicU8::new(0),
        }
    }
    pub fn error(&self) -> Option<Error> {
        match self.failure.load(Ordering::Acquire) {
            1 => Some(Error::Denied),
            2 => Some(Error::Limit),
            _ => None,
        }
    }
    fn denied() -> io::Error {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "read-only campaign authority refused",
        )
    }
    fn gate(&self, cost: u64) -> io::Result<()> {
        if check_read(self.authority, self.pin, self.root, self.cx).is_err() {
            self.failure.store(1, Ordering::Release);
            return Err(Self::denied());
        }
        let mut work = self.work.lock().map_err(|_| Self::denied())?;
        if let Err(error) = work.charge(cost) {
            let error = Error::from(error);
            self.failure.store(
                if error == Error::Denied { 1 } else { 2 },
                Ordering::Release,
            );
            return Err(Self::denied());
        }
        Ok(())
    }
    fn path(&self, path: &Path) -> io::Result<()> {
        self.gate(128)?;
        if !path.starts_with(self.root)
            || path.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            self.failure.store(1, Ordering::Release);
            return Err(Self::denied());
        }
        Ok(())
    }
}

impl SpoolIo for ReadIo<'_, '_> {
    fn create_dir_all(&self, _: &Path) -> io::Result<()> {
        Err(Self::denied())
    }
    fn create_dir(&self, _: &Path) -> io::Result<()> {
        Err(Self::denied())
    }
    fn create_new(&self, _: &Path) -> io::Result<File> {
        Err(Self::denied())
    }
    fn open_lock(&self, _: &Path) -> io::Result<File> {
        Err(Self::denied())
    }
    fn try_lock(&self, _: &File) -> Result<(), TryLockError> {
        Err(TryLockError::Error(Self::denied()))
    }
    fn try_lock_shared(&self, _: &File) -> Result<(), TryLockError> {
        Err(TryLockError::Error(Self::denied()))
    }
    fn unlock(&self, _: &File) -> io::Result<()> {
        Err(Self::denied())
    }
    fn write(&self, _: &mut File, _: &[u8]) -> io::Result<usize> {
        Err(Self::denied())
    }
    fn sync_file(&self, _: &File) -> io::Result<()> {
        Err(Self::denied())
    }
    fn rename(&self, _: &Path, _: &Path) -> io::Result<()> {
        Err(Self::denied())
    }
    fn remove_file(&self, _: &Path) -> io::Result<()> {
        Err(Self::denied())
    }
    fn sync_directory(&self, _: &Path) -> io::Result<()> {
        Err(Self::denied())
    }
    fn hard_link(&self, _: &Path, _: &Path) -> io::Result<()> {
        Err(Self::denied())
    }
    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.path(path)?;
        HostSpoolIo.metadata(path)
    }
    fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.path(path)?;
        HostSpoolIo.symlink_metadata(path)
    }
    fn read_dir(&self, path: &Path) -> io::Result<ReadDir> {
        self.path(path)?;
        HostSpoolIo.read_dir(path)
    }
    fn next_dir_entry(&self, entries: &mut ReadDir) -> Option<io::Result<DirEntry>> {
        if let Err(error) = self.gate(128) {
            return Some(Err(error));
        }
        HostSpoolIo.next_dir_entry(entries)
    }
    fn entry_file_type(&self, entry: &DirEntry) -> io::Result<FileType> {
        self.path(&entry.path())?;
        HostSpoolIo.entry_file_type(entry)
    }
    fn open_read(&self, path: &Path) -> io::Result<File> {
        self.path(path)?;
        HostSpoolIo.open_read(path)
    }
    fn read_bounded(&self, file: &mut File, limit: u64) -> io::Result<Vec<u8>> {
        let cost = limit
            .checked_mul(3)
            .and_then(|value| value.checked_add(256))
            .ok_or_else(Self::denied)?;
        self.gate(cost)?;
        if self.bytes.reserve(limit).is_err() {
            self.failure.store(2, Ordering::Release);
            return Err(Self::denied());
        }
        let bytes = HostSpoolIo.read_bounded(file, limit)?;
        self.bytes.settle(limit, bytes.len() as u64);
        self.gate(0)?;
        Ok(bytes)
    }
}

/// One whole-operation byte account, including inspection's root/object pre-scan and rereads.
pub(super) struct ReadAllowance {
    remaining: AtomicU64,
}
impl ReadAllowance {
    pub fn new(limit: u64) -> Self {
        Self {
            remaining: AtomicU64::new(limit),
        }
    }
    pub fn reserve(&self, bytes: u64) -> super::Result<()> {
        self.remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(bytes)
            })
            .map(|_| ())
            .map_err(|_| Error::Limit)
    }
    pub fn settle(&self, reserved: u64, actual: u64) {
        self.remaining
            .fetch_add(reserved.saturating_sub(actual), Ordering::AcqRel);
    }
}

/// Inspection need not acquire ambient procfs authority to verify an independently pinned prefix.
/// Writer state remains explicitly unknown, and the result cannot claim current/latest state.
#[derive(Debug)]
pub(super) struct NoLockTable;
impl LockTableSource for NoLockTable {
    fn read_lock_table(&self, _: usize) -> io::Result<String> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "writer state not observed",
        ))
    }
}

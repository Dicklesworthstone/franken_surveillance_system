#![forbid(unsafe_code)]
//! Bounded, cancellable read-only file/object I/O primitives for [`super::reader`].

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use fss_core::ContentDigest;
use fss_pack::{
    PACK_RECORD_HEADER_LEN, PACK_RECORD_MAGIC, PACK_RECORD_TRAILER_LEN, PackId,
    decode_record_header, verify_record_slice,
};

use super::types::{DeploymentReadError, corrupt};

/// Read-only in-memory location cache of objects inside `<objects>/packs/*.fssp`, built
/// strictly without acquiring `<root>/LOCK` or modifying any file.
#[derive(Clone, Debug, Default)]
pub(super) struct ReadonlyPackCatalog {
    locations: BTreeMap<ContentDigest, (PathBuf, u64, u64)>,
}

impl ReadonlyPackCatalog {
    pub(super) fn scan(objects_dir: &Path) -> Self {
        let mut locations = BTreeMap::new();
        let packs_dir = objects_dir.join("packs");
        let Ok(entries) = fs::read_dir(&packs_dir) else {
            return Self { locations };
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("fssp"))
            .collect();
        paths.sort();

        for (idx, path) in paths.into_iter().enumerate() {
            let pack_id = PackId::new(0, u64::try_from(idx).unwrap_or(0));
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if !meta.file_type().is_file() || meta.file_type().is_symlink() {
                continue;
            }
            let file_len = meta.len();
            let Ok(mut file) = File::open(&path) else {
                continue;
            };
            let mut offset = 0_u64;
            while offset.saturating_add(PACK_RECORD_HEADER_LEN as u64) <= file_len {
                let mut hdr_bytes = [0_u8; PACK_RECORD_HEADER_LEN];
                if file.read_exact(&mut hdr_bytes).is_err() || hdr_bytes[0..4] != PACK_RECORD_MAGIC
                {
                    break;
                }
                let Ok(hdr) = decode_record_header(pack_id, offset, &hdr_bytes) else {
                    break;
                };
                let rest_len = hdr
                    .payload_len
                    .saturating_add(PACK_RECORD_TRAILER_LEN as u64);
                let next_offset = offset
                    .saturating_add(PACK_RECORD_HEADER_LEN as u64)
                    .saturating_add(rest_len);
                if next_offset > file_len {
                    break;
                }
                locations
                    .entry(hdr.digest())
                    .or_insert_with(|| (path.clone(), offset, next_offset - offset));
                if file.seek(SeekFrom::Start(next_offset)).is_err() {
                    break;
                }
                offset = next_offset;
            }
        }
        Self { locations }
    }

    pub(super) fn read_verified(
        &self,
        digest: ContentDigest,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, DeploymentReadError> {
        let Some((path, offset, record_len)) = self.locations.get(&digest) else {
            return Ok(None);
        };
        let payload_bound =
            record_len.saturating_sub((PACK_RECORD_HEADER_LEN + PACK_RECORD_TRAILER_LEN) as u64);
        if payload_bound > max_bytes as u64 {
            return Err(corrupt(format!(
                "pack object {digest} exceeds max read bound {max_bytes}"
            )));
        }
        let mut file = File::open(path)
            .map_err(|err| corrupt(format!("packfile for {digest} unreadable: {err}")))?;
        file.seek(SeekFrom::Start(*offset))
            .map_err(|err| corrupt(format!("packfile seek for {digest} failed: {err}")))?;
        let mut rec = vec![0_u8; usize::try_from(*record_len).unwrap_or(0)];
        file.read_exact(&mut rec)
            .map_err(|err| corrupt(format!("packfile read for {digest} failed: {err}")))?;
        let (hdr, payload) = verify_record_slice(PackId::new(0, 0), *offset, &rec, None)
            .map_err(|err| corrupt(format!("pack object {digest} verification failed: {err}")))?;
        if hdr.digest() != digest {
            return Err(corrupt(format!("pack object digest mismatch for {digest}")));
        }
        Ok(Some(payload.to_vec()))
    }
}

/// Shared, non-replenishing payload-read allowance for synchronous metadata queries.
/// Counts bytes actually returned by bounded readers, excluding filesystem framing/syscalls.
#[derive(Clone, Debug)]
pub(crate) struct MetadataReadBudget {
    state: std::sync::Arc<std::sync::Mutex<(u64, u64, bool)>>,
    max_bytes: u64,
    max_objects: u64,
}

impl MetadataReadBudget {
    pub(crate) fn new(max_bytes: usize, max_objects: usize) -> Self {
        Self {
            state: Default::default(),
            max_bytes: max_bytes as u64,
            max_objects: max_objects as u64,
        }
    }
    pub(crate) fn allowance(&self, maximum: usize) -> io::Result<usize> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("metadata read budget poisoned"))?;
        let (bytes, objects, failed) = *state;
        if failed {
            return Err(io::Error::other("previous metadata read failed"));
        }
        if objects >= self.max_objects || bytes > self.max_bytes {
            return Err(io::Error::other("metadata read budget exhausted"));
        }
        // A zero-byte allowance can still verify an absent or empty payload, such as the
        // final effect journal. The bounded reader must reject any positive-length input;
        // this attempt still consumes an object read and never replenishes byte authority.
        state.1 += 1;
        Ok(maximum.min((self.max_bytes - bytes) as usize))
    }
    pub(crate) fn charge(&self, length: usize) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("metadata read budget poisoned"))?;
        let bytes = state
            .0
            .checked_add(length as u64)
            .ok_or_else(|| io::Error::other("metadata read budget exhausted"))?;
        let objects = state.1;
        if bytes > self.max_bytes || objects > self.max_objects {
            return Err(io::Error::other("metadata read budget exhausted"));
        }
        *state = (bytes, objects, state.2);
        Ok(())
    }
    pub(crate) fn consumed(&self) -> (u64, u64) {
        self.state
            .lock()
            .map_or((self.max_bytes, self.max_objects), |state| {
                (state.0, state.1)
            })
    }
    pub(crate) fn fail(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.2 = true;
        }
    }
    pub(crate) fn ensure_valid(&self) -> io::Result<()> {
        let state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("metadata read budget poisoned"))?;
        if state.2 {
            Err(io::Error::other("previous metadata read failed"))
        } else {
            Ok(())
        }
    }
}

/// Admission wrapper for the ordinary, unmetered ledger inspection path. It preserves the
/// native inspector's absent-file, invalid-layout, bound, and replay classifications.
pub(super) struct CancellableHistoryJournal<'a> {
    pub(super) cancelled: &'a (dyn Fn() -> bool + Sync),
}

impl CancellableHistoryJournal<'_> {
    fn admitted<T>(&self, read: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        if (self.cancelled)() {
            return Err(io::Error::other("retained read authority cancelled"));
        }
        let result = read();
        if (self.cancelled)() {
            return Err(io::Error::other("retained read authority cancelled"));
        }
        result
    }
}

impl fss_ledger::JournalReadIo for CancellableHistoryJournal<'_> {
    fn symlink_metadata(&self, path: &Path) -> io::Result<fss_ledger::JournalFileMetadata> {
        self.admitted(|| {
            fss_ledger::JournalReadIo::symlink_metadata(&fss_ledger::HostJournalReadIo, path)
        })
    }

    fn read_bounded(&self, path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
        self.admitted(|| {
            fss_ledger::JournalReadIo::read_bounded(&fss_ledger::HostJournalReadIo, path, maximum)
        })
    }
}

pub(super) struct Reader<'a> {
    pub(super) files_read: u64,
    pub(super) bytes_read: u64,
    pub(super) budget: Option<MetadataReadBudget>,
    pub(super) cancelled: Option<&'a dyn Fn() -> bool>,
    pub(super) pack_catalog: Option<&'a ReadonlyPackCatalog>,
}

impl Reader<'_> {
    pub(super) fn admit(&self) -> io::Result<()> {
        if self.cancelled.is_some_and(|cancelled| cancelled()) {
            if let Some(budget) = &self.budget {
                budget.fail();
            }
            return Err(io::Error::other("retained read authority cancelled"));
        }
        Ok(())
    }

    /// Reads at most `max` bytes from a regular, non-symlink file; `Ok(None)` when absent.
    pub(super) fn read_file(&mut self, path: &Path, max: usize) -> io::Result<Option<Vec<u8>>> {
        self.admit()?;
        let max = match &self.budget {
            Some(budget) => budget.allowance(max)?,
            None => max,
        };
        let metadata = fs::symlink_metadata(path);
        self.admit()?;
        let meta = match metadata {
            Ok(meta) => meta,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if !meta.file_type().is_file() {
            return Err(io::Error::other("not a regular file"));
        }
        if meta.len() > max as u64 {
            return Err(io::Error::other("file exceeds its read bound"));
        }
        self.admit()?;
        let opened = File::open(path);
        self.admit()?;
        let mut bytes = Vec::new();
        let read = opened?.take(max as u64 + 1).read_to_end(&mut bytes);
        self.admit()?;
        read?;
        if bytes.len() > max {
            return Err(io::Error::other("file exceeds its read bound"));
        }
        if let Some(budget) = &self.budget {
            budget.charge(bytes.len())?;
        }
        self.files_read += 1;
        self.bytes_read += bytes.len() as u64;
        Ok(Some(bytes))
    }

    pub(super) fn read_object(
        &mut self,
        objects: &Path,
        digest: ContentDigest,
        max: usize,
    ) -> Result<Vec<u8>, DeploymentReadError> {
        self.admit()
            .map_err(|_| corrupt("retained read authority cancelled"))?;
        let max = match &self.budget {
            Some(budget) => budget
                .allowance(max)
                .map_err(|_| corrupt("metadata read budget exhausted"))?,
            None => max,
        };
        let bytes = if let Some(catalog) = self.pack_catalog
            && let Some(pack_bytes) = catalog.read_verified(digest, max)?
        {
            self.admit()
                .map_err(|_| corrupt("retained read authority cancelled"))?;
            pack_bytes
        } else {
            let result = fss_publication::read_verified(objects, digest, max);
            self.admit()
                .map_err(|_| corrupt("retained read authority cancelled"))?;
            result.map_err(|error| {
                if let Some(budget) = &self.budget {
                    budget.fail();
                }
                DeploymentReadError::Corrupt {
                    reason: format!("spool object {digest} is unavailable or corrupt: {error}"),
                }
            })?
        };
        if let Some(budget) = &self.budget {
            budget
                .charge(bytes.len())
                .map_err(|_| corrupt("metadata read budget exhausted"))?;
        }
        self.files_read += 1;
        self.bytes_read += bytes.len() as u64;
        Ok(bytes)
    }
}

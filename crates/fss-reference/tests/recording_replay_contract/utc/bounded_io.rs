#![forbid(unsafe_code)]
//! Exercise the actual native reader against an oversized late-child replacement.

use super::*;
use std::fs::{DirEntry, File, FileType, Metadata, OpenOptions, ReadDir, TryLockError};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use fss_core::CanonicalEncode;
use fss_object::{HostSpoolIo, SPOOL_OBJECT_HEADER_LEN, SpoolIo};
use fss_reference::rtsp::recording::MAX_RECORDING_BYTES;

const LARGE_FILE_LENGTH: u64 = (MAX_RECORDING_BYTES + SPOOL_OBJECT_HEADER_LEN) as u64;

/// Observe the actual host read bound and returned byte count without replacing
/// the spool, archive parser, native verifier or any successful result.
#[derive(Debug, Default)]
struct LargeReadProbe {
    reads: Mutex<Vec<(u64, usize)>>,
}

impl SpoolIo for LargeReadProbe {
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        HostSpoolIo.create_dir_all(path)
    }
    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        HostSpoolIo.metadata(path)
    }
    fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata> {
        HostSpoolIo.symlink_metadata(path)
    }
    fn open_lock(&self, path: &Path) -> io::Result<File> {
        HostSpoolIo.open_lock(path)
    }
    fn try_lock(&self, file: &File) -> Result<(), TryLockError> {
        HostSpoolIo.try_lock(file)
    }
    fn try_lock_shared(&self, file: &File) -> Result<(), TryLockError> {
        HostSpoolIo.try_lock_shared(file)
    }
    fn unlock(&self, file: &File) -> io::Result<()> {
        HostSpoolIo.unlock(file)
    }
    fn create_dir(&self, path: &Path) -> io::Result<()> {
        HostSpoolIo.create_dir(path)
    }
    fn read_dir(&self, path: &Path) -> io::Result<ReadDir> {
        HostSpoolIo.read_dir(path)
    }
    fn next_dir_entry(&self, entries: &mut ReadDir) -> Option<io::Result<DirEntry>> {
        HostSpoolIo.next_dir_entry(entries)
    }
    fn entry_file_type(&self, entry: &DirEntry) -> io::Result<FileType> {
        HostSpoolIo.entry_file_type(entry)
    }
    fn create_new(&self, path: &Path) -> io::Result<File> {
        HostSpoolIo.create_new(path)
    }
    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
        HostSpoolIo.write(file, bytes)
    }
    fn sync_file(&self, file: &File) -> io::Result<()> {
        HostSpoolIo.sync_file(file)
    }
    fn open_read(&self, path: &Path) -> io::Result<File> {
        HostSpoolIo.open_read(path)
    }
    fn read_bounded(&self, file: &mut File, limit: u64) -> io::Result<Vec<u8>> {
        let selected = file.metadata()?.len() == LARGE_FILE_LENGTH;
        let bytes = HostSpoolIo.read_bounded(file, limit)?;
        if selected {
            self.reads
                .lock()
                .expect("probe lock")
                .push((limit, bytes.len()));
        }
        Ok(bytes)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        HostSpoolIo.rename(from, to)
    }
    fn remove_file(&self, path: &Path) -> io::Result<()> {
        HostSpoolIo.remove_file(path)
    }
    fn sync_directory(&self, path: &Path) -> io::Result<()> {
        HostSpoolIo.sync_directory(path)
    }
    fn hard_link(&self, from: &Path, to: &Path) -> io::Result<()> {
        HostSpoolIo.hard_link(from, to)
    }
}

#[test]
fn oversized_late_media_uses_only_the_remaining_native_allowance_and_never_falls_back() -> TestResult
{
    let source = rebuild_avc(fixture(915, true)?, |index, wire| {
        if index == 0 {
            stamp(wire, NTP_SECONDS, 0, 0, 7)?;
        }
        Ok(())
    })?;
    let original = source.prepare()?;
    let sealed = seal_avc("utc-hostile-late-child", &source, 1, 7)?;
    let mut owner_limits = limits();
    owner_limits.spool = SpoolLimits::new(128, 64 * 1024 * 1024, MAX_RECORDING_BYTES, 256);
    let probe = Arc::new(LargeReadProbe::default());
    let io: Arc<dyn SpoolIo> = probe.clone();
    let publisher = LocalRootPublisher::open_with_io(&sealed.root, owner_limits, io)?;
    let mut query = sealed.query();
    query.limits.max_source_bytes = MAX_RECORDING_BYTES as u64;
    let before = query_replay_time(&publisher, &query, &NeverCancel)?;
    assert_eq!(before.matches.len(), 1);

    let media_digest = ContentDigest::sha256(original.objects().media);
    let media_path = publisher.spool().object_path(media_digest);
    let original_envelope = std::fs::read(&media_path)?;
    // Published spool v1 uses a little-endian length at bytes12..20.
    // Preserve the exact recorded digest/name while simulating a hostile late replacement.
    assert_eq!(
        u64::from_le_bytes(original_envelope[12..20].try_into()?),
        original.objects().media.len() as u64
    );
    let mut hostile_header = original_envelope[..SPOOL_OBJECT_HEADER_LEN].to_vec();
    hostile_header[12..20].copy_from_slice(&(MAX_RECORDING_BYTES as u64).to_le_bytes());
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&media_path)?;
    file.write_all(&hostile_header)?;
    file.set_len(LARGE_FILE_LENGTH)?;
    drop(file);

    let refused = query_replay_time(&publisher, &query, &NeverCancel);
    let observations = probe.reads.lock().expect("probe lock").clone();
    // Restore before asserting, so an assertion failure does not leave oversized fixture data.
    std::fs::write(&media_path, &original_envelope)?;
    assert!(matches!(refused, Err(TimeError::Limit)));

    let already_read = original.manifest().canonical_bytes().len()
        + original.objects().index.len()
        + original.objects().source.len()
        + original.objects().initialization.len();
    let remaining = MAX_RECORDING_BYTES
        .checked_sub(already_read)
        .ok_or("fixture allowance")?;
    let actual_wire_limit = remaining + SPOOL_OBJECT_HEADER_LEN + 1;
    assert!(remaining < MAX_RECORDING_BYTES);
    assert_eq!(
        observations,
        vec![(actual_wire_limit as u64, actual_wire_limit)],
        "one remaining-budget read, with no second owner-maximum fallback"
    );
    let after = query_replay_time(&publisher, &query, &NeverCancel)?;
    assert_eq!(after.digest, before.digest);
    assert_eq!(after.index_digest, before.index_digest);
    assert_eq!(after.matches.len(), 1);
    Ok(())
}

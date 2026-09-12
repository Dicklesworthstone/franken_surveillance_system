//! Content-addressed on-disk staging spool (FSS-017).
//!
//! # Layout
//!
//! ```text
//! <root>/LOCK                         exclusive owner lock, held for the spool's lifetime
//! <root>/objects/<64 hex>             one enveloped object per SHA-256 payload digest
//! <root>/staging/<64 hex>.<n>.tmp     in-flight writes, never readable as objects
//! ```
//!
//! # Publication lattice
//!
//! The spool owns only the first rungs of the staged → verified → visible → durable → replicated
//! → protected → retrievable lattice. [`SpoolObjectState::Staged`] means the exact bytes were
//! digest-checked on ingest, read back, renamed into place, and their directories fsynced.
//! [`SpoolObjectState::Verified`] means a later explicit re-read rehashed them. Neither state is
//! visible or durable in the publication sense: no root names the object, and nothing here emits
//! a [`crate::PublicationReceipt`]. Root-last publication (FSS-018) consumes the spool only through
//! [`VerifiedObjectCatalog`], which refuses anything not verified.
//!
//! # Crash semantics
//!
//! Ingest is write → fsync → read-back → rename → fsync directories → index. A crash before the
//! rename leaves only a staging file. On reopen every staging file is classified as
//! [`OrphanedStaging`] and never admitted, even if its bytes happen to be a complete, valid
//! envelope. A crash after the rename leaves a complete object that reopen re-verifies and admits
//! as `Staged`. Every object file is rehashed on open; corrupt ones are indexed as
//! [`SpoolObjectState::Corrupt`] and refuse every read. Unrecognized entries are reported as
//! [`ForeignEntry`] and never read, admitted, or deleted.
//!
//! # I/O authority
//!
//! Every filesystem call goes through the explicit [`SpoolIo`] capability the spool was opened
//! with, scoped by the root path. [`StagingSpool::open`] uses [`HostSpoolIo`];
//! [`StagingSpool::open_with_io`] accepts any capability, including the deterministic
//! [`FaultInjectingSpoolIo`]. A failed step before the rename never admits an object: the
//! staging file is removed or, if removal fails, charged and listed as an orphan. A failed or
//! ambiguous step at or after the rename is reported as [`SpoolError::StageIndeterminate`]
//! whenever the object name may be occupied.

mod capability;
mod error;
mod format;

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fss_core::{ContentDigest, DigestAlgorithm};

use crate::{ObjectError, VerifiedObjectCatalog};

pub use capability::{FaultInjectingSpoolIo, HostSpoolIo, SpoolFaultPlan, SpoolIo, SpoolIoCall};
pub use error::{CorruptionKind, SpoolError, SpoolIoOperation, SpoolLimitViolation, StagePhase};
pub use format::{SPOOL_OBJECT_FORMAT_VERSION, SPOOL_OBJECT_HEADER_LEN, SPOOL_OBJECT_MAGIC};

/// Directory under the spool root holding enveloped objects.
pub const SPOOL_OBJECTS_DIR: &str = "objects";
/// Directory under the spool root holding in-flight staging files.
pub const SPOOL_STAGING_DIR: &str = "staging";
/// Lock file under the spool root.
pub const SPOOL_LOCK_FILE: &str = "LOCK";
/// Upper bound on distinct staging names tried for one digest.
pub const MAX_STAGING_NAME_ATTEMPTS: u32 = 16;
/// Consecutive [`io::ErrorKind::Interrupted`] write attempts at one buffer offset after which a
/// write loop gives up and returns a typed error instead of retrying.
///
/// `std::io::Write::write_all` retries `EINTR` without limit; the workspace forbids unbounded
/// retry, so the spool's staging write and the local publisher's record write retry an
/// interrupted attempt at most `MAX_INTERRUPTED_ATTEMPTS - 1` times at the same offset. A write
/// that accepts at least one byte resets the count, so a burst of signals during a long write is
/// absorbed at every offset while total work stays bounded by
/// `buffer_len * MAX_INTERRUPTED_ATTEMPTS` calls.
///
/// Eight is a deliberately small margin. An interrupted write has transferred nothing, so a
/// retry is always safe, and a single signal (for example `SIGCHLD` or a profiling timer)
/// interrupts at most one attempt; several coinciding signals are still absorbed. Eight
/// consecutive interruptions at the same offset mean the process is under a sustained signal
/// storm, and failing typed then is more useful to an operator than spinning.
pub const MAX_INTERRUPTED_ATTEMPTS: u32 = 8;

const STAGING_SUFFIX: &str = ".tmp";
const ROOT_SCAN_BOUND: usize = 64;
const DIGEST_HEX_LEN: usize = 64;

/// Resource bounds for one on-disk spool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpoolLimits {
    /// Maximum indexed objects, including objects found corrupt on open.
    pub max_objects: usize,
    /// Maximum charged bytes: object payloads, corrupt entries, and orphaned staging files.
    pub max_total_bytes: u64,
    /// Maximum payload bytes for one object; at most [`crate::MAX_OBJECT_BYTES`].
    pub max_object_bytes: usize,
    /// Maximum entries listed from the objects or staging directory on open.
    pub max_scan_entries: usize,
}

impl SpoolLimits {
    /// Creates explicit spool bounds. They are validated by [`StagingSpool::open`].
    #[must_use]
    pub const fn new(
        max_objects: usize,
        max_total_bytes: u64,
        max_object_bytes: usize,
        max_scan_entries: usize,
    ) -> Self {
        Self {
            max_objects,
            max_total_bytes,
            max_object_bytes,
            max_scan_entries,
        }
    }

    /// Checks that the bounds are mutually consistent.
    pub fn validate(self) -> Result<Self, SpoolError> {
        if self.max_object_bytes > crate::MAX_OBJECT_BYTES {
            return Err(SpoolError::InvalidLimits(
                SpoolLimitViolation::ObjectBoundAboveFormatMaximum {
                    requested: self.max_object_bytes,
                    maximum: crate::MAX_OBJECT_BYTES,
                },
            ));
        }
        if self.max_scan_entries < self.max_objects {
            return Err(SpoolError::InvalidLimits(
                SpoolLimitViolation::ScanBoundBelowObjectBound {
                    max_scan_entries: self.max_scan_entries,
                    max_objects: self.max_objects,
                },
            ));
        }
        Ok(self)
    }
}

impl Default for SpoolLimits {
    fn default() -> Self {
        Self {
            max_objects: 65_536,
            max_total_bytes: 512 * 1024 * 1024,
            max_object_bytes: crate::MAX_OBJECT_BYTES,
            max_scan_entries: 131_072,
        }
    }
}

/// Local custody state of one indexed spool object. None of these states is published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpoolObjectState {
    /// Bytes were digest-checked on ingest (or rehashed on reopen) and are in place on disk.
    Staged,
    /// A later explicit re-read rehashed the exact bytes in this spool session.
    Verified,
    /// The bytes under this name cannot be trusted; every read fails closed.
    Corrupt(CorruptionKind),
}

/// Whether one `stage` call wrote new bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StageOutcome {
    /// New bytes were written and indexed as `Staged`.
    NewlyStaged,
    /// Identical bytes were already indexed; nothing was written and no quota was charged.
    AlreadyPresent,
}

/// Receipt for one successful `stage` call. It is not a publication receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageReceipt {
    /// Content digest of the payload.
    pub digest: ContentDigest,
    /// Payload length in bytes.
    pub payload_len: u64,
    /// Whether this call wrote new bytes.
    pub outcome: StageOutcome,
    /// Object state after the call.
    pub state: SpoolObjectState,
}

/// Staging file left behind by an interrupted ingest. Never a valid object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrphanedStaging {
    /// Path relative to the spool root.
    pub path: PathBuf,
    /// On-disk size charged against the byte quota until discarded.
    pub bytes: u64,
    /// Digest named by the staging file name. Untrusted and never verified.
    pub claimed_digest: ContentDigest,
}

/// Why an entry found on open is outside the spool's contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForeignReason {
    /// An entry in the spool root other than the objects, staging, and lock entries.
    UnexpectedRootEntry,
    /// A name that does not follow the object or staging naming grammar.
    UnrecognizedName,
    /// A staging name held by a directory, symlink, or other non-regular file.
    NotRegularFile,
}

/// Entry found on open that the spool will never read, admit, or delete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForeignEntry {
    /// Path relative to the spool root.
    pub path: PathBuf,
    /// Classification.
    pub reason: ForeignReason,
}

/// Object found corrupt on open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CorruptObject {
    /// Digest claimed by the object file name.
    pub digest: ContentDigest,
    /// Classified corruption.
    pub kind: CorruptionKind,
}

/// Deterministic classification of every spool entry observed on open, sorted by name.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SpoolRecoveryReport {
    /// Objects rehashed successfully and admitted as `Staged`.
    pub admitted: Vec<ContentDigest>,
    /// Objects whose bytes failed verification.
    pub corrupt: Vec<CorruptObject>,
    /// Staging files left by interrupted ingests.
    pub orphaned_staging: Vec<OrphanedStaging>,
    /// Entries outside the spool contract.
    pub foreign: Vec<ForeignEntry>,
}

impl SpoolRecoveryReport {
    /// True when every observed entry was a valid admitted object.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.corrupt.is_empty() && self.orphaned_staging.is_empty() && self.foreign.is_empty()
    }
}

/// Receipt for discarding orphaned staging files.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscardReceipt {
    /// Number of orphaned staging files removed.
    pub removed: usize,
    /// Quota bytes released.
    pub released_bytes: u64,
}

#[derive(Clone, Copy, Debug)]
struct IndexedObject {
    state: SpoolObjectState,
}

enum ReadFailure {
    Corrupt {
        kind: CorruptionKind,
        file_len: u64,
    },
    Io {
        operation: SpoolIoOperation,
        kind: io::ErrorKind,
    },
}

/// Exclusive owner of one on-disk content-addressed staging spool.
#[derive(Debug)]
pub struct StagingSpool {
    io: Arc<dyn SpoolIo>,
    root: PathBuf,
    objects_dir: PathBuf,
    staging_dir: PathBuf,
    _lock: File,
    limits: SpoolLimits,
    index: BTreeMap<ContentDigest, IndexedObject>,
    orphans: BTreeMap<OsString, OrphanedStaging>,
    index_bytes: u64,
    orphan_bytes: u64,
    recovery: SpoolRecoveryReport,
    injected_crash: Option<StagePhase>,
    poisoned: bool,
}

impl StagingSpool {
    /// Opens or creates a spool, takes its exclusive lock, and classifies every entry.
    ///
    /// Every object file is rehashed. Corrupt objects are indexed as `Corrupt`, staging files as
    /// orphans, and unrecognized entries as foreign; see [`Self::recovery_report`]. Any I/O
    /// failure while classifying fails the open rather than admitting an unverified entry.
    pub fn open(root: impl AsRef<Path>, limits: SpoolLimits) -> Result<Self, SpoolError> {
        Self::open_with_io(root, limits, Arc::new(HostSpoolIo))
    }

    /// Opens or creates a spool whose every filesystem call goes through `io`.
    ///
    /// Otherwise identical to [`Self::open`], which passes [`HostSpoolIo`].
    pub fn open_with_io(
        root: impl AsRef<Path>,
        limits: SpoolLimits,
        io: Arc<dyn SpoolIo>,
    ) -> Result<Self, SpoolError> {
        let limits = limits.validate()?;
        let root = root.as_ref().to_path_buf();
        io.create_dir_all(&root)
            .map_err(|error| io_error(SpoolIoOperation::CreateDirectory, &root, &error))?;
        let root_metadata = io
            .metadata(&root)
            .map_err(|error| io_error(SpoolIoOperation::Inspect, &root, &error))?;
        if !root_metadata.is_dir() {
            return Err(SpoolError::InvalidLayout { path: root });
        }
        let lock = acquire_lock(io.as_ref(), &root)?;
        let objects_dir = root.join(SPOOL_OBJECTS_DIR);
        let staging_dir = root.join(SPOOL_STAGING_DIR);
        ensure_subdirectory(io.as_ref(), &objects_dir)?;
        ensure_subdirectory(io.as_ref(), &staging_dir)?;
        io.sync_directory(&root)
            .map_err(|error| io_error(SpoolIoOperation::SyncDirectory, &root, &error))?;

        let mut spool = Self {
            io,
            root,
            objects_dir,
            staging_dir,
            _lock: lock,
            limits,
            index: BTreeMap::new(),
            orphans: BTreeMap::new(),
            index_bytes: 0,
            orphan_bytes: 0,
            recovery: SpoolRecoveryReport::default(),
            injected_crash: None,
            poisoned: false,
        };
        spool.recover()?;
        Ok(spool)
    }

    /// Spool root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Configured bounds.
    #[must_use]
    pub const fn limits(&self) -> SpoolLimits {
        self.limits
    }

    /// Classification of every entry observed when this instance opened.
    #[must_use]
    pub const fn recovery_report(&self) -> &SpoolRecoveryReport {
        &self.recovery
    }

    /// Orphaned staging files still held, in name order, including staging files a failed ingest
    /// in this session could not remove.
    pub fn orphaned_staging(&self) -> impl Iterator<Item = &OrphanedStaging> {
        self.orphans.values()
    }

    /// Number of indexed objects, including corrupt ones.
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.index.len()
    }

    /// Bytes charged against the quota: indexed objects plus orphaned staging files.
    pub fn occupied_bytes(&self) -> Result<u64, SpoolError> {
        self.index_bytes
            .checked_add(self.orphan_bytes)
            .ok_or(SpoolError::AccountingOverflow)
    }

    /// Local state of one object, if indexed.
    #[must_use]
    pub fn state(&self, digest: ContentDigest) -> Option<SpoolObjectState> {
        self.index.get(&digest).map(|entry| entry.state)
    }

    /// Path an object with this digest occupies, whether or not it is present.
    #[must_use]
    pub fn object_path(&self, digest: ContentDigest) -> PathBuf {
        self.objects_dir.join(digest_hex(digest))
    }

    /// Stages `payload` under the digest the caller declares for it.
    ///
    /// The payload must hash to `declared`. Restaging identical bytes is idempotent: it re-reads
    /// and rehashes the stored object, writes nothing, and charges no quota. Restaging under a
    /// digest whose stored bytes are corrupt fails with [`SpoolError::Corrupt`] and never
    /// overwrites them.
    ///
    /// A failure before the rename admits nothing; a staging file that cannot be removed is
    /// charged and listed in [`Self::orphaned_staging`]. A failure at or after the rename that may
    /// leave the object in place returns [`SpoolError::StageIndeterminate`], charges the bytes
    /// when the object name is observed occupied, and poisons this instance.
    pub fn stage(
        &mut self,
        declared: ContentDigest,
        payload: &[u8],
    ) -> Result<StageReceipt, SpoolError> {
        self.require_live()?;
        if declared.algorithm() != DigestAlgorithm::Sha256 {
            return Err(SpoolError::UnsupportedAlgorithm(declared.algorithm()));
        }
        if payload.len() > self.limits.max_object_bytes {
            return Err(SpoolError::ObjectTooLarge {
                length: payload.len(),
                maximum: self.limits.max_object_bytes,
            });
        }
        let computed = ContentDigest::sha256(payload);
        if computed != declared {
            return Err(SpoolError::DigestMismatch { declared, computed });
        }
        let payload_len = payload.len() as u64;
        if self.index.contains_key(&declared) {
            return self.restage_existing(declared, payload);
        }

        if self.index.len() >= self.limits.max_objects {
            return Err(SpoolError::ObjectCountLimit {
                current: self.index.len(),
                maximum: self.limits.max_objects,
            });
        }
        let current = self.occupied_bytes()?;
        let quota_error = SpoolError::ByteQuotaExceeded {
            current,
            requested: payload_len,
            maximum: self.limits.max_total_bytes,
        };
        let next_total = current
            .checked_add(payload_len)
            .ok_or_else(|| quota_error.clone())?;
        if next_total > self.limits.max_total_bytes {
            return Err(quota_error);
        }
        let next_index_bytes = self
            .index_bytes
            .checked_add(payload_len)
            .ok_or(SpoolError::AccountingOverflow)?;

        let target = self.object_path(declared);
        match self.io.symlink_metadata(&target) {
            Ok(_) => return Err(SpoolError::UnindexedEntry { path: target }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(SpoolIoOperation::Inspect, &target, &error)),
        }

        let encoded = format::encode_object(declared, payload);
        let (staging_name, staging_path, mut file) = self.create_staging_file(declared)?;
        let write_result = self.write_staging(&mut file, &staging_path, &encoded);
        drop(file);
        if let Err(error) = write_result {
            self.abandon_staging(declared, staging_name, &staging_path);
            return Err(error);
        }
        self.crash_point(StagePhase::AfterStagingWrite)?;

        match read_object_file(
            self.io.as_ref(),
            &staging_path,
            declared,
            self.limits.max_object_bytes,
        ) {
            Ok(read_back) if read_back == payload => {}
            Ok(_) => {
                self.abandon_staging(declared, staging_name, &staging_path);
                return Err(SpoolError::DigestCollision(declared));
            }
            Err(ReadFailure::Corrupt { kind, .. }) => {
                self.abandon_staging(declared, staging_name, &staging_path);
                return Err(SpoolError::IngestReadback {
                    digest: declared,
                    kind,
                });
            }
            Err(ReadFailure::Io { operation, kind }) => {
                self.abandon_staging(declared, staging_name, &staging_path);
                return Err(SpoolError::Io {
                    operation,
                    path: staging_path,
                    kind,
                });
            }
        }

        if let Err(error) = self.io.rename(&staging_path, &target) {
            match self.io.symlink_metadata(&target) {
                Err(probe) if probe.kind() == io::ErrorKind::NotFound => {
                    self.abandon_staging(declared, staging_name, &staging_path);
                    return Err(io_error(SpoolIoOperation::Rename, &target, &error));
                }
                // The object name is occupied or unobservable after a rename that reported
                // failure: the rename may have taken effect, so the outcome is indeterminate.
                observed => {
                    if observed.is_ok() {
                        // Charged but not indexed; a reopen admits it with exactly this charge.
                        self.index_bytes = next_index_bytes;
                    }
                    return Err(self.indeterminate(declared, SpoolIoOperation::Rename, &error));
                }
            }
        }
        self.crash_point(StagePhase::AfterRename)?;

        if let Err(error) = self
            .io
            .sync_directory(&self.objects_dir)
            .and_then(|()| self.io.sync_directory(&self.staging_dir))
        {
            // The rename completed, so the bytes occupy the object name. Charged but not
            // indexed; a reopen admits them with exactly this charge.
            self.index_bytes = next_index_bytes;
            return Err(self.indeterminate(declared, SpoolIoOperation::SyncDirectory, &error));
        }

        self.index.insert(
            declared,
            IndexedObject {
                state: SpoolObjectState::Staged,
            },
        );
        self.index_bytes = next_index_bytes;
        Ok(StageReceipt {
            digest: declared,
            payload_len,
            outcome: StageOutcome::NewlyStaged,
            state: SpoolObjectState::Staged,
        })
    }

    /// Stages `payload` under its computed SHA-256 digest.
    pub fn stage_bytes(&mut self, payload: &[u8]) -> Result<StageReceipt, SpoolError> {
        self.stage(ContentDigest::sha256(payload), payload)
    }

    /// Re-reads and rehashes one object from disk and marks it `Verified`.
    ///
    /// A verification failure marks the object `Corrupt` for the rest of this session.
    pub fn verify(&mut self, digest: ContentDigest) -> Result<SpoolObjectState, SpoolError> {
        self.require_live()?;
        let result = self.load_indexed(digest);
        self.record_outcome(digest, &result);
        result?;
        self.state(digest).ok_or(SpoolError::Missing(digest))
    }

    /// Returns exact payload bytes after re-reading and rehashing them from disk.
    ///
    /// This never returns bytes that fail verification, whatever the recorded state. Reading
    /// does not change state; call [`Self::verify`] to promote an object to `Verified`.
    pub fn read(&self, digest: ContentDigest) -> Result<Vec<u8>, SpoolError> {
        self.require_live()?;
        self.load_indexed(digest)
    }

    /// Removes exactly the orphaned staging files classified on open.
    ///
    /// Foreign entries and anything not classified as an orphan are never touched. An orphan
    /// whose file type changed since open fails closed with [`SpoolError::InvalidLayout`].
    pub fn discard_orphaned_staging(&mut self) -> Result<DiscardReceipt, SpoolError> {
        self.require_live()?;
        let names: Vec<OsString> = self.orphans.keys().cloned().collect();
        let mut receipt = DiscardReceipt {
            removed: 0,
            released_bytes: 0,
        };
        for name in names {
            let path = self.staging_dir.join(&name);
            match self.io.symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_file() => {
                    match self.io.remove_file(&path) {
                        Ok(()) => {}
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => {
                            return Err(io_error(SpoolIoOperation::RemoveStaging, &path, &error));
                        }
                    }
                }
                Ok(_) => return Err(SpoolError::InvalidLayout { path }),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(io_error(SpoolIoOperation::Inspect, &path, &error)),
            }
            if let Some(orphan) = self.orphans.remove(&name) {
                self.orphan_bytes = self
                    .orphan_bytes
                    .checked_sub(orphan.bytes)
                    .ok_or(SpoolError::AccountingOverflow)?;
                receipt.removed += 1;
                receipt.released_bytes = receipt
                    .released_bytes
                    .checked_add(orphan.bytes)
                    .ok_or(SpoolError::AccountingOverflow)?;
            }
        }
        self.io.sync_directory(&self.staging_dir).map_err(|error| {
            io_error(SpoolIoOperation::SyncDirectory, &self.staging_dir, &error)
        })?;
        Ok(receipt)
    }

    /// Arms a one-shot crash point for the next `stage` call.
    ///
    /// When it fires, the call returns [`SpoolError::InjectedCrash`], leaves the disk exactly as
    /// a process death at that point would, and poisons this instance.
    #[doc(hidden)]
    pub fn inject_crash_after(&mut self, phase: StagePhase) {
        self.injected_crash = Some(phase);
    }

    fn require_live(&self) -> Result<(), SpoolError> {
        if self.poisoned {
            return Err(SpoolError::Poisoned);
        }
        Ok(())
    }

    fn crash_point(&mut self, phase: StagePhase) -> Result<(), SpoolError> {
        if self.injected_crash == Some(phase) {
            self.injected_crash = None;
            self.poisoned = true;
            return Err(SpoolError::InjectedCrash { phase });
        }
        Ok(())
    }

    /// Writes the whole envelope, resuming after partial writes, then fsyncs the file.
    ///
    /// A write that accepts zero bytes is a [`SpoolError::ShortWrite`]. An
    /// [`io::ErrorKind::Interrupted`] write transferred nothing, so it is retried at the same
    /// offset; the [`MAX_INTERRUPTED_ATTEMPTS`]-th consecutive interruption at one offset is
    /// returned as [`SpoolError::Io`] with [`SpoolIoOperation::WriteStaging`]. Any other error is
    /// returned at once. The loop is bounded: every iteration either advances by at least one byte
    /// or spends one of the interrupted attempts allowed at the current offset.
    fn write_staging(
        &self,
        file: &mut File,
        path: &Path,
        encoded: &[u8],
    ) -> Result<(), SpoolError> {
        let mut written = 0_usize;
        let mut interrupted = 0_u32;
        while let Some(rest) = encoded.get(written..).filter(|rest| !rest.is_empty()) {
            match self.io.write(file, rest) {
                Ok(0) => {
                    return Err(SpoolError::ShortWrite {
                        path: path.to_path_buf(),
                        written: written as u64,
                        expected: encoded.len() as u64,
                    });
                }
                // A capability claiming more than it was offered is clamped; read-back
                // verification still rejects bytes that did not land.
                Ok(accepted) => {
                    written = written.saturating_add(accepted.min(rest.len()));
                    interrupted = 0;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    interrupted = interrupted.saturating_add(1);
                    if interrupted >= MAX_INTERRUPTED_ATTEMPTS {
                        return Err(io_error(SpoolIoOperation::WriteStaging, path, &error));
                    }
                }
                Err(error) => {
                    return Err(io_error(SpoolIoOperation::WriteStaging, path, &error));
                }
            }
        }
        self.io
            .sync_file(file)
            .map_err(|error| io_error(SpoolIoOperation::SyncStaging, path, &error))
    }

    /// Removes a staging file whose ingest failed before rename.
    ///
    /// A file that cannot be removed stays on disk, so it is charged and listed exactly as a
    /// reopen would classify it. If even its size cannot be observed, accounting can no longer be
    /// exact and this instance is poisoned.
    fn abandon_staging(&mut self, digest: ContentDigest, name: OsString, path: &Path) {
        match self.io.remove_file(path) {
            Ok(()) => return,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return,
            Err(_) => {}
        }
        let bytes = match self.io.symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() => metadata.len(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return,
            Ok(_) | Err(_) => {
                self.poisoned = true;
                return;
            }
        };
        let Some(orphan_bytes) = self.orphan_bytes.checked_add(bytes) else {
            self.poisoned = true;
            return;
        };
        self.orphan_bytes = orphan_bytes;
        let orphan = OrphanedStaging {
            path: Path::new(SPOOL_STAGING_DIR).join(&name),
            bytes,
            claimed_digest: digest,
        };
        self.orphans.insert(name, orphan);
    }

    /// Poisons this instance after an ingest whose outcome cannot be determined.
    fn indeterminate(
        &mut self,
        digest: ContentDigest,
        operation: SpoolIoOperation,
        error: &io::Error,
    ) -> SpoolError {
        self.poisoned = true;
        SpoolError::StageIndeterminate {
            digest,
            operation,
            kind: error.kind(),
        }
    }

    fn restage_existing(
        &mut self,
        digest: ContentDigest,
        payload: &[u8],
    ) -> Result<StageReceipt, SpoolError> {
        let result = self.load_indexed(digest);
        self.record_corruption(digest, &result);
        let stored = result?;
        if stored != payload {
            return Err(SpoolError::DigestCollision(digest));
        }
        Ok(StageReceipt {
            digest,
            payload_len: payload.len() as u64,
            outcome: StageOutcome::AlreadyPresent,
            state: self.state(digest).ok_or(SpoolError::Missing(digest))?,
        })
    }

    fn record_outcome(&mut self, digest: ContentDigest, result: &Result<Vec<u8>, SpoolError>) {
        if result.is_ok()
            && let Some(entry) = self.index.get_mut(&digest)
        {
            entry.state = SpoolObjectState::Verified;
        }
        self.record_corruption(digest, result);
    }

    fn record_corruption(&mut self, digest: ContentDigest, result: &Result<Vec<u8>, SpoolError>) {
        if let Err(SpoolError::Corrupt { kind, .. }) = result
            && let Some(entry) = self.index.get_mut(&digest)
        {
            entry.state = SpoolObjectState::Corrupt(*kind);
        }
    }

    fn load_indexed(&self, digest: ContentDigest) -> Result<Vec<u8>, SpoolError> {
        let entry = self.index.get(&digest).ok_or(SpoolError::Missing(digest))?;
        if let SpoolObjectState::Corrupt(kind) = entry.state {
            return Err(SpoolError::Corrupt { digest, kind });
        }
        let path = self.object_path(digest);
        read_object_file(
            self.io.as_ref(),
            &path,
            digest,
            self.limits.max_object_bytes,
        )
        .map_err(|failure| match failure {
            ReadFailure::Corrupt { kind, .. } => SpoolError::Corrupt { digest, kind },
            ReadFailure::Io { operation, kind } => SpoolError::Io {
                operation,
                path,
                kind,
            },
        })
    }

    fn create_staging_file(
        &mut self,
        digest: ContentDigest,
    ) -> Result<(OsString, PathBuf, File), SpoolError> {
        for attempt in 0..MAX_STAGING_NAME_ATTEMPTS {
            let name = OsString::from(staging_file_name(digest, attempt));
            let candidate = self.staging_dir.join(&name);
            match self.io.create_new(&candidate) {
                Ok(file) => return Ok((name, candidate, file)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    // The create may have taken effect before failing; never leave the name
                    // untracked. Under the exclusive lock nothing else creates staging files.
                    self.abandon_staging(digest, name, &candidate);
                    return Err(io_error(
                        SpoolIoOperation::CreateStaging,
                        &candidate,
                        &error,
                    ));
                }
            }
        }
        Err(SpoolError::StagingNamesExhausted {
            digest,
            attempts: MAX_STAGING_NAME_ATTEMPTS,
        })
    }

    fn recover(&mut self) -> Result<(), SpoolError> {
        for (name, _) in scan_directory(self.io.as_ref(), &self.root, ROOT_SCAN_BOUND)? {
            if name == SPOOL_OBJECTS_DIR || name == SPOOL_STAGING_DIR || name == SPOOL_LOCK_FILE {
                continue;
            }
            self.recovery.foreign.push(ForeignEntry {
                path: PathBuf::from(&name),
                reason: ForeignReason::UnexpectedRootEntry,
            });
        }

        let staging_entries = scan_directory(
            self.io.as_ref(),
            &self.staging_dir,
            self.limits.max_scan_entries,
        )?;
        for (name, file_type) in staging_entries {
            let relative = Path::new(SPOOL_STAGING_DIR).join(&name);
            let Some(claimed_digest) = parse_staging_name(&name) else {
                self.recovery.foreign.push(ForeignEntry {
                    path: relative,
                    reason: ForeignReason::UnrecognizedName,
                });
                continue;
            };
            if !file_type.is_file() {
                self.recovery.foreign.push(ForeignEntry {
                    path: relative,
                    reason: ForeignReason::NotRegularFile,
                });
                continue;
            }
            let path = self.staging_dir.join(&name);
            let bytes = self
                .io
                .symlink_metadata(&path)
                .map_err(|error| io_error(SpoolIoOperation::Inspect, &path, &error))?
                .len();
            self.orphan_bytes = self
                .orphan_bytes
                .checked_add(bytes)
                .ok_or(SpoolError::AccountingOverflow)?;
            let orphan = OrphanedStaging {
                path: relative,
                bytes,
                claimed_digest,
            };
            self.recovery.orphaned_staging.push(orphan.clone());
            self.orphans.insert(name, orphan);
        }

        let object_entries = scan_directory(
            self.io.as_ref(),
            &self.objects_dir,
            self.limits.max_scan_entries,
        )?;
        for (name, file_type) in object_entries {
            let Some(digest) = parse_object_name(&name) else {
                self.recovery.foreign.push(ForeignEntry {
                    path: Path::new(SPOOL_OBJECTS_DIR).join(&name),
                    reason: ForeignReason::UnrecognizedName,
                });
                continue;
            };
            let (state, charged_bytes) = if file_type.is_file() {
                let path = self.objects_dir.join(&name);
                match read_object_file(
                    self.io.as_ref(),
                    &path,
                    digest,
                    self.limits.max_object_bytes,
                ) {
                    Ok(payload) => {
                        self.recovery.admitted.push(digest);
                        (SpoolObjectState::Staged, payload.len() as u64)
                    }
                    Err(ReadFailure::Corrupt { kind, file_len }) => {
                        (SpoolObjectState::Corrupt(kind), file_len)
                    }
                    Err(ReadFailure::Io { operation, kind }) => {
                        return Err(SpoolError::Io {
                            operation,
                            path,
                            kind,
                        });
                    }
                }
            } else {
                (SpoolObjectState::Corrupt(CorruptionKind::NotRegularFile), 0)
            };
            if let SpoolObjectState::Corrupt(kind) = state {
                self.recovery.corrupt.push(CorruptObject { digest, kind });
            }
            self.index_bytes = self
                .index_bytes
                .checked_add(charged_bytes)
                .ok_or(SpoolError::AccountingOverflow)?;
            self.index.insert(digest, IndexedObject { state });
        }
        Ok(())
    }
}

impl VerifiedObjectCatalog for StagingSpool {
    /// Requires an object verified in this session whose on-disk bytes still rehash correctly.
    ///
    /// `Staged` objects fail with [`ObjectError::NotVerified`]. An I/O failure or poisoned
    /// instance fails with [`ObjectError::Unavailable`] rather than a guessed verdict.
    fn require_verified(&self, digest: ContentDigest) -> Result<(), ObjectError> {
        if self.poisoned {
            return Err(ObjectError::Unavailable(digest));
        }
        let entry = self
            .index
            .get(&digest)
            .ok_or(ObjectError::Missing(digest))?;
        match entry.state {
            SpoolObjectState::Staged => return Err(ObjectError::NotVerified(digest)),
            SpoolObjectState::Corrupt(_) => return Err(ObjectError::Corrupt(digest)),
            SpoolObjectState::Verified => {}
        }
        match self.load_indexed(digest) {
            Ok(_) => Ok(()),
            Err(SpoolError::Corrupt { .. }) => Err(ObjectError::Corrupt(digest)),
            Err(SpoolError::Missing(_)) => Err(ObjectError::Missing(digest)),
            Err(_) => Err(ObjectError::Unavailable(digest)),
        }
    }
}

fn io_error(operation: SpoolIoOperation, path: &Path, error: &io::Error) -> SpoolError {
    SpoolError::Io {
        operation,
        path: path.to_path_buf(),
        kind: error.kind(),
    }
}

fn acquire_lock(io: &dyn SpoolIo, root: &Path) -> Result<File, SpoolError> {
    let path = root.join(SPOOL_LOCK_FILE);
    match io.symlink_metadata(&path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(SpoolError::InvalidLayout { path });
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error(SpoolIoOperation::Inspect, &path, &error)),
    }
    let file = io
        .open_lock(&path)
        .map_err(|error| io_error(SpoolIoOperation::OpenLock, &path, &error))?;
    match io.try_lock(&file) {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(SpoolError::Locked { path }),
        Err(TryLockError::Error(error)) => Err(io_error(SpoolIoOperation::Lock, &path, &error)),
    }
}

fn ensure_subdirectory(io: &dyn SpoolIo, path: &Path) -> Result<(), SpoolError> {
    match io.create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(io_error(SpoolIoOperation::CreateDirectory, path, &error)),
    }
    let metadata = io
        .symlink_metadata(path)
        .map_err(|error| io_error(SpoolIoOperation::Inspect, path, &error))?;
    if !metadata.file_type().is_dir() {
        return Err(SpoolError::InvalidLayout {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn scan_directory(
    io: &dyn SpoolIo,
    dir: &Path,
    bound: usize,
) -> Result<Vec<(OsString, fs::FileType)>, SpoolError> {
    let mut entries = io
        .read_dir(dir)
        .map_err(|error| io_error(SpoolIoOperation::ScanDirectory, dir, &error))?;
    let mut found = Vec::new();
    while let Some(entry) = io.next_dir_entry(&mut entries) {
        let entry =
            entry.map_err(|error| io_error(SpoolIoOperation::ScanDirectory, dir, &error))?;
        if found.len() >= bound {
            return Err(SpoolError::EntryLimit {
                directory: dir.to_path_buf(),
                maximum: bound,
            });
        }
        let file_type = io
            .entry_file_type(&entry)
            .map_err(|error| io_error(SpoolIoOperation::Inspect, &entry.path(), &error))?;
        found.push((entry.file_name(), file_type));
    }
    found.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(found)
}

fn read_object_file(
    io: &dyn SpoolIo,
    path: &Path,
    expected: ContentDigest,
    max_payload: usize,
) -> Result<Vec<u8>, ReadFailure> {
    let metadata = match io.symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(ReadFailure::Corrupt {
                kind: CorruptionKind::Vanished,
                file_len: 0,
            });
        }
        Err(error) => {
            return Err(ReadFailure::Io {
                operation: SpoolIoOperation::Inspect,
                kind: error.kind(),
            });
        }
    };
    if !metadata.file_type().is_file() {
        return Err(ReadFailure::Corrupt {
            kind: CorruptionKind::NotRegularFile,
            file_len: 0,
        });
    }
    let mut file = match io.open_read(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(ReadFailure::Corrupt {
                kind: CorruptionKind::Vanished,
                file_len: 0,
            });
        }
        Err(error) => {
            return Err(ReadFailure::Io {
                operation: SpoolIoOperation::ReadObject,
                kind: error.kind(),
            });
        }
    };
    let file_len = metadata.len();
    let bound = (SPOOL_OBJECT_HEADER_LEN + max_payload) as u64 + 1;
    let mut raw = io
        .read_bounded(&mut file, bound)
        .map_err(|error| ReadFailure::Io {
            operation: SpoolIoOperation::ReadObject,
            kind: error.kind(),
        })?;
    if let Err(kind) = format::verify_object_bytes(expected, &raw, max_payload) {
        return Err(ReadFailure::Corrupt { kind, file_len });
    }
    raw.drain(..SPOOL_OBJECT_HEADER_LEN);
    Ok(raw)
}

fn digest_hex(digest: ContentDigest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(DIGEST_HEX_LEN);
    for byte in digest.bytes() {
        hex.push(char::from(HEX[usize::from(byte >> 4)]));
        hex.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    hex
}

fn staging_file_name(digest: ContentDigest, attempt: u32) -> String {
    format!("{}.{attempt}{STAGING_SUFFIX}", digest_hex(digest))
}

fn parse_object_name(name: &OsStr) -> Option<ContentDigest> {
    let text = name.to_str()?;
    if text.len() != DIGEST_HEX_LEN {
        return None;
    }
    ContentDigest::parse(format!("sha256:{text}")).ok()
}

fn parse_staging_name(name: &OsStr) -> Option<ContentDigest> {
    let text = name.to_str()?;
    let (hex, attempt) = text.strip_suffix(STAGING_SUFFIX)?.rsplit_once('.')?;
    let parsed: u32 = attempt.parse().ok()?;
    if parsed >= MAX_STAGING_NAME_ATTEMPTS || parsed.to_string() != attempt {
        return None;
    }
    parse_object_name(OsStr::new(hex))
}

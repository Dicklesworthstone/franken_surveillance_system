//! Content-addressed on-disk staging spool (FSS-017).
//!
//! # Layout
//!
//! ```text
//! <root>/LOCK                         exclusive owner lock, held for the spool's lifetime
//! <root>/objects/<64 hex>             one enveloped object per SHA-256 payload digest
//! <root>/staging/<64 hex>.<n>.tmp     in-flight writes, never readable as objects
//! <root>/verified/<64 hex>            empty durable verification hold for one object
//! ```
//!
//! # Verification holds
//!
//! [`StagingSpool::verify`] places a durable, empty hold file named by the object digest before it
//! reports [`SpoolObjectState::Verified`], and nothing removes it. `Verified` itself stays a
//! per-session state (a reopen admits every object as `Staged` again), but a held object may back
//! a publication decision, so [`StagingSpool::discard_staged`] refuses it in every later session.
//! A hold whose object is gone is indexed as [`CorruptionKind::Vanished`]. A spool written before
//! holds existed has no `verified/` directory: nothing on disk says which of its objects were
//! verified, so the first open records a hold for every admitted object (building the directory
//! as `verified.tmp` and renaming it into place), and none of them can be discarded.
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

pub use capability::{
    FaultInjectingSpoolIo, HostSpoolIo, RecordingSpoolIo, SpoolFaultPlan, SpoolIo, SpoolIoCall,
};
pub use error::{CorruptionKind, SpoolError, SpoolIoOperation, SpoolLimitViolation, StagePhase};
pub use format::{
    SPOOL_OBJECT_FORMAT_VERSION, SPOOL_OBJECT_HEADER_LEN, SPOOL_OBJECT_MAGIC, encode_spool_object,
};

/// Directory under the spool root holding enveloped objects.
pub const SPOOL_OBJECTS_DIR: &str = "objects";
/// Directory under the spool root holding in-flight staging files.
pub const SPOOL_STAGING_DIR: &str = "staging";
/// Lock file under the spool root.
pub const SPOOL_LOCK_FILE: &str = "LOCK";
/// Directory under the spool root holding durable verification holds.
pub const SPOOL_HOLDS_DIR: &str = "verified";
/// Directory under the spool root in which holds are recorded for a spool written before holds
/// existed, renamed onto [`SPOOL_HOLDS_DIR`] once complete.
pub const SPOOL_HOLDS_MIGRATION_DIR: &str = "verified.tmp";
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
    /// Maximum entries listed from the objects, staging, or holds directory on open.
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
    /// A later explicit re-read rehashed the exact bytes in this spool session, and the object's
    /// durable verification hold is in place.
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

/// Result of inspecting a spool without taking locks or creating directories.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SpoolInspection {
    /// Deterministic recovery report embedded from classification.
    pub report: SpoolRecoveryReport,
    /// Whether the spool predates the holds directory and requires migration.
    pub holds_migration_pending: bool,
    /// Whether any required directory (objects or staging) is missing.
    pub missing_layout: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct SpoolClassification {
    pub(crate) report: SpoolRecoveryReport,
    pub(crate) index: BTreeMap<ContentDigest, IndexedObject>,
    pub(crate) orphans: BTreeMap<OsString, OrphanedStaging>,
    pub(crate) index_bytes: u64,
    pub(crate) orphan_bytes: u64,
    pub(crate) holds_migration_pending: bool,
    pub(crate) missing_layout: bool,
}

/// Receipt for discarding orphaned staging files.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscardReceipt {
    /// Number of orphaned staging files removed.
    pub removed: usize,
    /// Quota bytes released.
    pub released_bytes: u64,
}

/// Whether an object carries a durable verification hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Hold {
    /// No hold exists on disk.
    None,
    /// A hold may exist on disk but was not confirmed durable.
    Unconfirmed,
    /// A hold is durable on disk.
    Durable,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct IndexedObject {
    pub(crate) state: SpoolObjectState,
    /// Bytes this entry contributes to `index_bytes`, released exactly when it is discarded.
    pub(crate) charged: u64,
    /// Durable verification hold; any hold that is not `None` refuses discard.
    pub(crate) hold: Hold,
}

/// Why an object removal did not complete.
enum RemovalFailure {
    /// The entry is still present or was never touched; nothing changed.
    Settled(SpoolError),
    /// Whether the removal took effect is unknown.
    Indeterminate(SpoolError),
}

/// A failed read of one indexed object, keeping the observed length of a corrupt file.
enum ReadOutcome {
    Corrupt { kind: CorruptionKind, file_len: u64 },
    Spool(SpoolError),
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
    holds_dir: PathBuf,
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
        let holds_dir = root.join(SPOOL_HOLDS_DIR);
        let fresh = ensure_subdirectory(io.as_ref(), &objects_dir)?;
        ensure_subdirectory(io.as_ref(), &staging_dir)?;
        // A spool whose objects directory this open created cannot hold unheld verified objects,
        // so its holds directory is created directly. Any other spool without one predates holds.
        let legacy = if fresh {
            ensure_subdirectory(io.as_ref(), &holds_dir)?;
            false
        } else {
            match io.symlink_metadata(&holds_dir) {
                Ok(metadata) if metadata.file_type().is_dir() => false,
                Ok(_) => return Err(SpoolError::InvalidLayout { path: holds_dir }),
                Err(error) if error.kind() == io::ErrorKind::NotFound => true,
                Err(error) => {
                    return Err(io_error(SpoolIoOperation::Inspect, &holds_dir, &error));
                }
            }
        };
        io.sync_directory(&root)
            .map_err(|error| io_error(SpoolIoOperation::SyncDirectory, &root, &error))?;

        let classification = classify_spool(io.as_ref(), &root, &limits)?;
        if legacy {
            migrate_holds(
                io.as_ref(),
                &root,
                &holds_dir,
                &classification.report.admitted,
            )?;
        }

        let spool = Self {
            io,
            root,
            objects_dir,
            staging_dir,
            holds_dir,
            _lock: lock,
            limits,
            index: classification.index,
            orphans: classification.orphans,
            index_bytes: classification.index_bytes,
            orphan_bytes: classification.orphan_bytes,
            recovery: classification.report,
            injected_crash: None,
            poisoned: false,
        };
        spool.check_recovered_capacity()?;
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

    /// Digests of every indexed object, including corrupt ones, in ascending digest order.
    pub fn digests(&self) -> impl Iterator<Item = ContentDigest> + '_ {
        self.index.keys().copied()
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

        let encoded = encode_spool_object(declared, payload)?;
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
                charged: payload_len,
                hold: Hold::None,
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

    /// Re-reads and rehashes one object from disk, places its durable verification hold, and
    /// marks it `Verified`.
    ///
    /// A verification failure marks the object `Corrupt` for the rest of this session. If the
    /// bytes verify but the hold cannot be confirmed durable, the object stays `Staged` and
    /// [`SpoolError::HoldIndeterminate`] is returned; the object is then treated as held, and a
    /// later `verify` retries the hold.
    pub fn verify(&mut self, digest: ContentDigest) -> Result<SpoolObjectState, SpoolError> {
        self.require_live()?;
        self.load_indexed_recording(digest)?;
        let entry = *self.index.get(&digest).ok_or(SpoolError::Missing(digest))?;
        if entry.hold != Hold::Durable {
            let confirmed = self.place_hold(digest);
            if let Some(entry) = self.index.get_mut(&digest) {
                entry.hold = if confirmed.is_ok() {
                    Hold::Durable
                } else {
                    Hold::Unconfirmed
                };
            }
            confirmed?;
        }
        if let Some(entry) = self.index.get_mut(&digest) {
            entry.state = SpoolObjectState::Verified;
        }
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
    ///
    /// Every removal released from the quota is fsynced before this returns, including when a
    /// later orphan fails: a settled failure leaves the remaining orphans charged and listed. A
    /// removal whose effect cannot be observed, or a failed staging-directory fsync after
    /// removals, returns [`SpoolError::DiscardIndeterminate`] and poisons this instance, so a
    /// retry can never report an empty success for removals that may not be durable.
    pub fn discard_orphaned_staging(&mut self) -> Result<DiscardReceipt, SpoolError> {
        self.require_live()?;
        let names: Vec<OsString> = self.orphans.keys().cloned().collect();
        let mut receipt = DiscardReceipt {
            removed: 0,
            released_bytes: 0,
        };
        let mut failure = None;
        for name in names {
            let path = self.staging_dir.join(&name);
            match self.remove_orphan_file(&path) {
                Ok(()) => {}
                Err(RemovalFailure::Settled(error)) => {
                    failure = Some(error);
                    break;
                }
                Err(RemovalFailure::Indeterminate(error)) => {
                    self.poisoned = true;
                    return Err(error);
                }
            }
            if let Some(orphan) = self.orphans.remove(&name) {
                let released = self
                    .orphan_bytes
                    .checked_sub(orphan.bytes)
                    .and_then(|left| {
                        receipt
                            .released_bytes
                            .checked_add(orphan.bytes)
                            .map(|total| (left, total))
                    });
                let Some((left, total)) = released else {
                    self.poisoned = true;
                    return Err(SpoolError::AccountingOverflow);
                };
                self.orphan_bytes = left;
                receipt.released_bytes = total;
                receipt.removed += 1;
            }
        }
        if (failure.is_none() || receipt.removed > 0)
            && let Err(error) = self.io.sync_directory(&self.staging_dir)
        {
            self.poisoned = true;
            return Err(SpoolError::DiscardIndeterminate {
                path: self.staging_dir.clone(),
                operation: SpoolIoOperation::SyncDirectory,
                kind: error.kind(),
            });
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(receipt),
        }
    }

    /// Removes one orphaned staging file, classifying a failure as settled or indeterminate.
    fn remove_orphan_file(&self, path: &Path) -> Result<(), RemovalFailure> {
        match self.io.symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => {
                return Err(RemovalFailure::Settled(SpoolError::InvalidLayout {
                    path: path.to_path_buf(),
                }));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(RemovalFailure::Settled(io_error(
                    SpoolIoOperation::Inspect,
                    path,
                    &error,
                )));
            }
        }
        self.remove_confirmed(path, SpoolIoOperation::RemoveStaging)
    }

    /// Removes `path`. A reported failure counts as a removal only if the name is then observed
    /// free, as a settled failure only if it is observed still present, and otherwise as
    /// indeterminate.
    fn remove_confirmed(
        &self,
        path: &Path,
        operation: SpoolIoOperation,
    ) -> Result<(), RemovalFailure> {
        let error = match self.io.remove_file(path) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => error,
        };
        match self.io.symlink_metadata(path) {
            Err(probe) if probe.kind() == io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(RemovalFailure::Settled(io_error(operation, path, &error))),
            Err(probe) => Err(RemovalFailure::Indeterminate(
                SpoolError::DiscardIndeterminate {
                    path: path.to_path_buf(),
                    operation,
                    kind: probe.kind(),
                },
            )),
        }
    }

    /// Removes one `Staged` object and releases exactly the quota it was charged.
    ///
    /// This is the rollback step for a caller whose multi-object ingest failed part way: it
    /// removes one object that caller staged and never verified. A `Verified` object may already
    /// back a publication decision and a `Corrupt` one is evidence of tampering, so both are
    /// refused with [`SpoolError::NotDiscardable`] and left untouched. An object that carries a
    /// verification hold (it was verified in an earlier session, or its spool predates holds) is
    /// refused with [`SpoolError::VerificationHeld`] for the same reason.
    ///
    /// If the removal fails while the object name is still occupied, the object stays indexed and
    /// charged and [`SpoolError::Io`] with [`SpoolIoOperation::RemoveObject`] is returned. If the
    /// removal's effect cannot be observed, [`SpoolError::DiscardIndeterminate`] is returned. If
    /// the removal succeeds but the directory fsync fails, a crash could restore the object and a
    /// reopen would admit it as `Staged` again; that outcome is [`SpoolError::DiscardNotDurable`].
    /// Both uncertain outcomes poison this instance, which must be reopened to reconcile.
    pub fn discard_staged(&mut self, digest: ContentDigest) -> Result<u64, SpoolError> {
        self.require_live()?;
        let entry = *self.index.get(&digest).ok_or(SpoolError::Missing(digest))?;
        if entry.state != SpoolObjectState::Staged {
            return Err(SpoolError::NotDiscardable {
                digest,
                state: entry.state,
            });
        }
        if entry.hold != Hold::None {
            return Err(SpoolError::VerificationHeld { digest });
        }
        let next_index_bytes = self
            .index_bytes
            .checked_sub(entry.charged)
            .ok_or(SpoolError::AccountingOverflow)?;
        let path = self.object_path(digest);
        match self.remove_confirmed(&path, SpoolIoOperation::RemoveObject) {
            Ok(()) => {}
            Err(RemovalFailure::Settled(error)) => return Err(error),
            Err(RemovalFailure::Indeterminate(error)) => {
                self.poisoned = true;
                return Err(error);
            }
        }
        self.index.remove(&digest);
        self.index_bytes = next_index_bytes;
        if let Err(error) = self.io.sync_directory(&self.objects_dir) {
            self.poisoned = true;
            return Err(SpoolError::DiscardNotDurable {
                digest,
                kind: error.kind(),
            });
        }
        Ok(entry.charged)
    }

    /// Creates and fsyncs the durable verification hold for one object.
    ///
    /// An existing hold is kept: holds are only ever added. Any failure is
    /// [`SpoolError::HoldIndeterminate`], because the hold file may exist whatever was reported.
    fn place_hold(&self, digest: ContentDigest) -> Result<(), SpoolError> {
        let path = self.holds_dir.join(digest_hex(digest));
        let unconfirmed = |error: io::Error| SpoolError::HoldIndeterminate {
            digest,
            kind: error.kind(),
        };
        match self.io.create_new(&path) {
            Ok(file) => self.io.sync_file(&file).map_err(unconfirmed)?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(unconfirmed(error)),
        }
        self.io.sync_directory(&self.holds_dir).map_err(unconfirmed)
    }

    /// Fails closed when what recovery found exceeds the configured bounds.
    fn check_recovered_capacity(&self) -> Result<(), SpoolError> {
        let occupied_bytes = self.occupied_bytes()?;
        if self.index.len() > self.limits.max_objects
            || occupied_bytes > self.limits.max_total_bytes
        {
            return Err(SpoolError::RecoveredOverCapacity {
                objects: self.index.len(),
                max_objects: self.limits.max_objects,
                occupied_bytes,
                max_total_bytes: self.limits.max_total_bytes,
            });
        }
        Ok(())
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
        let stored = self.load_indexed_recording(digest)?;
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

    /// Loads one indexed object and records corruption it reveals for the rest of the session.
    ///
    /// A newly corrupt object is recharged at the file length observed on disk, exactly as a
    /// reopen would charge it, so accounting never drifts across reopen.
    fn load_indexed_recording(&mut self, digest: ContentDigest) -> Result<Vec<u8>, SpoolError> {
        let (kind, file_len) = match self.load_indexed_classified(digest) {
            Ok(payload) => return Ok(payload),
            Err(ReadOutcome::Spool(error)) => return Err(error),
            Err(ReadOutcome::Corrupt { kind, file_len }) => (kind, file_len),
        };
        if let Some(entry) = self.index.get(&digest).copied() {
            let recharged = self
                .index_bytes
                .checked_sub(entry.charged)
                .and_then(|rest| rest.checked_add(file_len));
            let Some(recharged) = recharged else {
                self.poisoned = true;
                return Err(SpoolError::AccountingOverflow);
            };
            self.index_bytes = recharged;
            self.index.insert(
                digest,
                IndexedObject {
                    state: SpoolObjectState::Corrupt(kind),
                    charged: file_len,
                    hold: entry.hold,
                },
            );
        }
        Err(SpoolError::Corrupt { digest, kind })
    }

    fn load_indexed(&self, digest: ContentDigest) -> Result<Vec<u8>, SpoolError> {
        self.load_indexed_classified(digest)
            .map_err(|outcome| match outcome {
                ReadOutcome::Spool(error) => error,
                ReadOutcome::Corrupt { kind, .. } => SpoolError::Corrupt { digest, kind },
            })
    }

    fn load_indexed_classified(&self, digest: ContentDigest) -> Result<Vec<u8>, ReadOutcome> {
        let entry = self
            .index
            .get(&digest)
            .ok_or(ReadOutcome::Spool(SpoolError::Missing(digest)))?;
        if let SpoolObjectState::Corrupt(kind) = entry.state {
            return Err(ReadOutcome::Spool(SpoolError::Corrupt { digest, kind }));
        }
        let path = self.object_path(digest);
        read_object_file(
            self.io.as_ref(),
            &path,
            digest,
            self.limits.max_object_bytes,
        )
        .map_err(|failure| match failure {
            ReadFailure::Corrupt { kind, file_len } => ReadOutcome::Corrupt { kind, file_len },
            ReadFailure::Io { operation, kind } => ReadOutcome::Spool(SpoolError::Io {
                operation,
                path,
                kind,
            }),
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
}

/// Records a hold for every admitted object of a spool written before holds existed.
fn migrate_holds(
    io: &dyn SpoolIo,
    root: &Path,
    holds_dir: &Path,
    admitted: &[ContentDigest],
) -> Result<(), SpoolError> {
    let staging = root.join(SPOOL_HOLDS_MIGRATION_DIR);
    ensure_subdirectory(io, &staging)?;
    let migrate_error = |path: &Path, error: &io::Error| SpoolError::Io {
        operation: SpoolIoOperation::MigrateHolds,
        path: path.to_path_buf(),
        kind: error.kind(),
    };
    for digest in admitted {
        let path = staging.join(digest_hex(*digest));
        match io.create_new(&path) {
            Ok(file) => io
                .sync_file(&file)
                .map_err(|error| migrate_error(&path, &error))?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(migrate_error(&path, &error)),
        }
    }
    io.sync_directory(&staging)
        .map_err(|error| migrate_error(&staging, &error))?;
    io.rename(&staging, holds_dir)
        .map_err(|error| migrate_error(holds_dir, &error))?;
    io.sync_directory(root)
        .map_err(|error| migrate_error(root, &error))
}

pub(crate) fn classify_spool(
    io: &dyn SpoolIo,
    root: &Path,
    limits: &SpoolLimits,
) -> Result<SpoolClassification, SpoolError> {
    let limits = limits.validate()?;
    let mut missing_layout = false;

    match io.symlink_metadata(root) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() {
                return Err(SpoolError::InvalidLayout {
                    path: root.to_path_buf(),
                });
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(SpoolClassification {
                report: SpoolRecoveryReport::default(),
                index: BTreeMap::new(),
                orphans: BTreeMap::new(),
                index_bytes: 0,
                orphan_bytes: 0,
                holds_migration_pending: false,
                missing_layout: true,
            });
        }
        Err(error) => return Err(io_error(SpoolIoOperation::Inspect, root, &error)),
    }

    let objects_dir = root.join(SPOOL_OBJECTS_DIR);
    let staging_dir = root.join(SPOOL_STAGING_DIR);
    let holds_dir = root.join(SPOOL_HOLDS_DIR);

    let objects_exists = match io.symlink_metadata(&objects_dir) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() {
                return Err(SpoolError::InvalidLayout { path: objects_dir });
            }
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(io_error(SpoolIoOperation::Inspect, &objects_dir, &error)),
    };

    let staging_exists = match io.symlink_metadata(&staging_dir) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() {
                return Err(SpoolError::InvalidLayout { path: staging_dir });
            }
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(io_error(SpoolIoOperation::Inspect, &staging_dir, &error)),
    };

    if !objects_exists || !staging_exists {
        missing_layout = true;
    }

    let (holds_exists, legacy) = if objects_exists {
        match io.symlink_metadata(&holds_dir) {
            Ok(metadata) => {
                if !metadata.file_type().is_dir() {
                    return Err(SpoolError::InvalidLayout { path: holds_dir });
                }
                (true, false)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => (false, true),
            Err(error) => return Err(io_error(SpoolIoOperation::Inspect, &holds_dir, &error)),
        }
    } else {
        (false, false)
    };

    let mut report = SpoolRecoveryReport::default();
    let mut index = BTreeMap::new();
    let mut orphans = BTreeMap::new();
    let mut index_bytes = 0_u64;
    let mut orphan_bytes = 0_u64;

    for (name, _) in scan_directory(io, root, ROOT_SCAN_BOUND)? {
        if name == SPOOL_OBJECTS_DIR
            || name == SPOOL_STAGING_DIR
            || name == SPOOL_LOCK_FILE
            || name == SPOOL_HOLDS_DIR
            || (legacy && name == SPOOL_HOLDS_MIGRATION_DIR)
        {
            continue;
        }
        report.foreign.push(ForeignEntry {
            path: PathBuf::from(&name),
            reason: ForeignReason::UnexpectedRootEntry,
        });
    }

    if staging_exists {
        let staging_entries = scan_directory(io, &staging_dir, limits.max_scan_entries)?;
        for (name, file_type) in staging_entries {
            let relative = Path::new(SPOOL_STAGING_DIR).join(&name);
            let Some(claimed_digest) = parse_staging_name(&name) else {
                report.foreign.push(ForeignEntry {
                    path: relative,
                    reason: ForeignReason::UnrecognizedName,
                });
                continue;
            };
            if !file_type.is_file() {
                report.foreign.push(ForeignEntry {
                    path: relative,
                    reason: ForeignReason::NotRegularFile,
                });
                continue;
            }
            let path = staging_dir.join(&name);
            let bytes = io
                .symlink_metadata(&path)
                .map_err(|error| io_error(SpoolIoOperation::Inspect, &path, &error))?
                .len();
            orphan_bytes = orphan_bytes
                .checked_add(bytes)
                .ok_or(SpoolError::AccountingOverflow)?;
            let orphan = OrphanedStaging {
                path: relative,
                bytes,
                claimed_digest,
            };
            report.orphaned_staging.push(orphan.clone());
            orphans.insert(name, orphan);
        }
    }

    if objects_exists {
        let object_entries = scan_directory(io, &objects_dir, limits.max_scan_entries)?;
        for (name, file_type) in object_entries {
            let Some(digest) = parse_object_name(&name) else {
                report.foreign.push(ForeignEntry {
                    path: Path::new(SPOOL_OBJECTS_DIR).join(&name),
                    reason: ForeignReason::UnrecognizedName,
                });
                continue;
            };
            let (state, charged_bytes) = if file_type.is_file() {
                let path = objects_dir.join(&name);
                match read_object_file(io, &path, digest, limits.max_object_bytes) {
                    Ok(payload) => {
                        report.admitted.push(digest);
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
                report.corrupt.push(CorruptObject { digest, kind });
            }
            index_bytes = index_bytes
                .checked_add(charged_bytes)
                .ok_or(SpoolError::AccountingOverflow)?;
            index.insert(
                digest,
                IndexedObject {
                    state,
                    charged: charged_bytes,
                    hold: Hold::None,
                },
            );
        }
    }

    if legacy {
        for digest in &report.admitted {
            if let Some(entry) = index.get_mut(digest) {
                entry.hold = Hold::Durable;
            }
        }
    } else if holds_exists {
        let entries = scan_directory(io, &holds_dir, limits.max_scan_entries)?;
        for (name, file_type) in entries {
            let relative = Path::new(SPOOL_HOLDS_DIR).join(&name);
            let Some(digest) = parse_object_name(&name) else {
                report.foreign.push(ForeignEntry {
                    path: relative,
                    reason: ForeignReason::UnrecognizedName,
                });
                continue;
            };
            if !file_type.is_file() {
                report.foreign.push(ForeignEntry {
                    path: relative,
                    reason: ForeignReason::NotRegularFile,
                });
            }
            if let Some(entry) = index.get_mut(&digest) {
                entry.hold = Hold::Durable;
                continue;
            }
            let kind = CorruptionKind::Vanished;
            report.corrupt.push(CorruptObject { digest, kind });
            index.insert(
                digest,
                IndexedObject {
                    state: SpoolObjectState::Corrupt(kind),
                    charged: 0,
                    hold: Hold::Durable,
                },
            );
        }
        report.corrupt.sort_by_key(|corrupt| corrupt.digest);
    }

    let occupied_bytes = index_bytes
        .checked_add(orphan_bytes)
        .ok_or(SpoolError::AccountingOverflow)?;
    if index.len() > limits.max_objects || occupied_bytes > limits.max_total_bytes {
        return Err(SpoolError::RecoveredOverCapacity {
            objects: index.len(),
            max_objects: limits.max_objects,
            occupied_bytes,
            max_total_bytes: limits.max_total_bytes,
        });
    }

    Ok(SpoolClassification {
        report,
        index,
        orphans,
        index_bytes,
        orphan_bytes,
        holds_migration_pending: legacy,
        missing_layout,
    })
}

/// Inspects an on-disk spool root without taking locks, creating directories, or repairing state.
pub fn inspect(
    root: impl AsRef<Path>,
    limits: &SpoolLimits,
) -> Result<SpoolInspection, SpoolError> {
    inspect_with_io(root.as_ref(), limits, &HostSpoolIo)
}

/// Inspects an on-disk spool root through the given I/O capability.
pub fn inspect_with_io(
    root: &Path,
    limits: &SpoolLimits,
    io: &dyn SpoolIo,
) -> Result<SpoolInspection, SpoolError> {
    let classification = classify_spool(io, root, limits)?;
    Ok(SpoolInspection {
        report: classification.report,
        holds_migration_pending: classification.holds_migration_pending,
        missing_layout: classification.missing_layout,
    })
}

/// Reads and verifies an object's payload directly from a spool root without taking locks or holds.
pub fn read_verified_payload(
    root: impl AsRef<Path>,
    digest: ContentDigest,
    max_payload: usize,
    io: &dyn SpoolIo,
) -> Result<Vec<u8>, SpoolError> {
    let path = root
        .as_ref()
        .join(SPOOL_OBJECTS_DIR)
        .join(digest_hex(digest));
    match read_object_file(io, &path, digest, max_payload) {
        Ok(payload) => Ok(payload),
        Err(ReadFailure::Corrupt { kind, .. }) => Err(SpoolError::Corrupt { digest, kind }),
        Err(ReadFailure::Io { operation, kind }) => Err(SpoolError::Io {
            operation,
            path,
            kind,
        }),
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

/// Creates `path` if missing and checks it is a real directory. Returns whether it was created.
fn ensure_subdirectory(io: &dyn SpoolIo, path: &Path) -> Result<bool, SpoolError> {
    let created = match io.create_dir(path) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(io_error(SpoolIoOperation::CreateDirectory, path, &error)),
    };
    let metadata = io
        .symlink_metadata(path)
        .map_err(|error| io_error(SpoolIoOperation::Inspect, path, &error))?;
    if !metadata.file_type().is_dir() {
        return Err(SpoolError::InvalidLayout {
            path: path.to_path_buf(),
        });
    }
    Ok(created)
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

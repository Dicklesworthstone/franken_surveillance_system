#![forbid(unsafe_code)]
//! Bounded, append-only multipart recovery records in an explicitly owned local spool.
//!
//! Every record binds its sequence, predecessor and canonical upload checkpoint. Opening
//! requires an independently retained minimum pin, verifies the entire contiguous chain and
//! rejects forks, corrupt records and semantic rewinds. A torn staging file is retained and
//! charged, but never treated as a committed record. An ambiguous append poisons this owner;
//! only a cold open can determine which complete records survived.
//!
//! This journal establishes local recovery custody. It does not prove that an archive object
//! is visible, replicated or retrievable, authenticate a provider, or detect rollback beyond
//! the caller's independently retained pin. The exclusive advisory lock coordinates cooperating
//! writers. Stable directory and lock identities are checked at the journal's I/O boundaries.

mod io;

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, DigestAlgorithm};

use crate::multipart::recovery::validate_checkpoint_transition;
use crate::multipart::{MultipartError, UploadJournal, UploadJournalPin};
use crate::spool::{
    SPOOL_HOLDS_DIR, SPOOL_LOCK_FILE, SPOOL_OBJECTS_DIR, SPOOL_STAGING_DIR, SpoolIo, SpoolLimits,
    StagingSpool,
};

use self::io::{BudgetedJournalIo, FileIdentity};

/// Domain of a sequence/predecessor/checkpoint journal record.
pub const UPLOAD_JOURNAL_RECORD_DOMAIN: &str = "fss.multipart_journal_record.v1";
const RECORD_OVERHEAD: usize = 8 + UPLOAD_JOURNAL_RECORD_DOMAIN.len() + 8 + 1 + 33 + 8;
const MAX_PATH_COMPONENTS: usize = 256;

/// Explicit storage and read-work bounds for one journal owner, including recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadJournalLimits {
    /// Maximum committed checkpoint records; no automatic pruning erases evidence.
    pub max_records: usize,
    /// Maximum canonical payload of one upload checkpoint, before the record envelope.
    pub max_checkpoint_bytes: usize,
    /// Maximum spool payload bytes, including record envelopes and orphaned staging.
    pub max_total_bytes: u64,
    /// Maximum bytes read over this handle's lifetime, including recovery and verification.
    /// Failed reads conservatively consume their whole reserved per-read allowance.
    pub max_read_bytes: u64,
}

impl Default for UploadJournalLimits {
    fn default() -> Self {
        Self {
            max_records: 4096,
            max_checkpoint_bytes: 512 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
            max_read_bytes: 256 * 1024 * 1024,
        }
    }
}

impl UploadJournalLimits {
    fn spool_limits(self) -> Result<SpoolLimits, MultipartError> {
        if self.max_records == 0
            || self.max_records > 65_536
            || self.max_checkpoint_bytes == 0
            || self.max_checkpoint_bytes > 16 * 1024 * 1024
            || self.max_total_bytes == 0
            || self.max_total_bytes > 1024 * 1024 * 1024
            || self.max_read_bytes == 0
        {
            return Err(persistence("invalid upload journal limits"));
        }
        Ok(SpoolLimits::new(
            self.max_records,
            self.max_total_bytes,
            self.max_checkpoint_bytes + RECORD_OVERHEAD,
            self.max_records.saturating_mul(2).saturating_add(16),
        ))
    }
}

/// Exclusive file-backed implementation of [`UploadJournal`].
///
/// The absolute root must contain only this journal's spool. Symlink components and changed
/// directory/lock identities are refused. Platforms without stable file identity are refused
/// rather than silently weakening ownership. Every filesystem operation uses the supplied I/O
/// capability; no provider transport or live runtime authority is reconstructed from disk.
#[derive(Debug)]
pub struct FileUploadJournal {
    spool: StagingSpool,
    io: Arc<BudgetedJournalIo>,
    limits: UploadJournalLimits,
    identities: Vec<(PathBuf, FileIdentity)>,
    pins: BTreeMap<u64, ContentDigest>,
    latest: Option<Vec<u8>>,
    poisoned: bool,
}

impl FileUploadJournal {
    /// Creates an empty journal, or admits an already initialized but entirely empty spool.
    /// Existing records or staging remnants are never overwritten or adopted as a new history.
    /// The parent directory must already exist; creation never leaves an unflushed parent chain.
    pub fn create(
        root: impl AsRef<Path>,
        limits: UploadJournalLimits,
        capability: Arc<dyn SpoolIo>,
    ) -> Result<Self, MultipartError> {
        let root = root.as_ref();
        let spool_limits = limits.spool_limits()?;
        let io = Arc::new(BudgetedJournalIo::new(capability, limits.max_read_bytes));
        let before = inspect_ancestors(io.as_ref(), root, false)?;
        let parent = root
            .parent()
            .ok_or_else(|| persistence("journal root requires an existing parent"))?;
        if !io
            .symlink_metadata(parent)
            .map_err(persistence)?
            .file_type()
            .is_dir()
        {
            return Err(persistence("upload journal parent is not a real directory"));
        }
        let spool =
            StagingSpool::open_with_io(root, spool_limits, io.clone()).map_err(persistence)?;
        verify_identities(io.as_ref(), &before)?;
        if spool.object_count() != 0 || !spool.recovery_report().is_clean() {
            return Err(persistence(
                "creating an upload journal requires an empty spool",
            ));
        }
        let identities = inspect_layout(io.as_ref(), root)?;
        // Persist the journal directory's name as well as the spool's internal entries.
        if let Some(parent) = root.parent() {
            io.sync_directory(parent).map_err(persistence)?;
        }
        verify_identities(io.as_ref(), &identities)?;
        Ok(Self {
            spool,
            io,
            limits,
            identities,
            pins: BTreeMap::new(),
            latest: None,
            poisoned: false,
        })
    }

    /// Reopens an existing journal at or after an independently retained exact minimum pin.
    ///
    /// All committed records, not just the latest snapshot, must form one canonical monotone
    /// history containing `minimum`. Missing directories are not initialized during recovery.
    /// Recognized orphaned staging is charged and retained; corrupt or foreign entries refuse.
    pub fn open(
        root: impl AsRef<Path>,
        limits: UploadJournalLimits,
        capability: Arc<dyn SpoolIo>,
        minimum: UploadJournalPin,
    ) -> Result<Self, MultipartError> {
        validate_pin(minimum)?;
        let root = root.as_ref();
        let spool_limits = limits.spool_limits()?;
        let io = Arc::new(BudgetedJournalIo::new(capability, limits.max_read_bytes));
        let identities = inspect_layout(io.as_ref(), root)?;
        let spool =
            StagingSpool::open_with_io(root, spool_limits, io.clone()).map_err(persistence)?;
        verify_identities(io.as_ref(), &identities)?;
        let report = spool.recovery_report();
        if !report.corrupt.is_empty() || !report.foreign.is_empty() {
            return Err(persistence(
                "upload journal contains corrupt or foreign entries",
            ));
        }
        let mut records = BTreeMap::new();
        let mut decoded_bytes = 0_u64;
        for digest in spool.digests() {
            let bytes = spool
                .read_bounded(digest, spool_limits.max_object_bytes)
                .map_err(persistence)?;
            decoded_bytes = decoded_bytes
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| persistence("upload journal size overflow"))?;
            if decoded_bytes > limits.max_total_bytes {
                return Err(persistence("upload journal exceeds total byte bound"));
            }
            let record = decode_record(&bytes, limits.max_checkpoint_bytes)?;
            if records.insert(record.sequence, (digest, record)).is_some() {
                return Err(persistence(
                    "upload journal has competing records at one sequence",
                ));
            }
        }
        let mut pins = BTreeMap::new();
        let mut previous: Option<UploadJournalPin> = None;
        let mut latest: Option<Vec<u8>> = None;
        for (sequence, (digest, record)) in records {
            let expected_sequence = previous.map_or(1, |pin| pin.sequence + 1);
            if sequence != expected_sequence || record.previous != previous.map(|pin| pin.root) {
                return Err(persistence(
                    "upload journal has a missing or mismatched predecessor",
                ));
            }
            validate_checkpoint_transition(latest.as_deref(), &record.checkpoint)?;
            pins.insert(sequence, digest);
            previous = Some(UploadJournalPin {
                sequence,
                root: digest,
            });
            latest = Some(record.checkpoint);
        }
        if pins.get(&minimum.sequence) != Some(&minimum.root) {
            return Err(persistence(
                "upload journal does not contain the independent minimum pin",
            ));
        }
        // An earlier owner may have exited after rename but before its directory fsync.
        // Re-establish the recovered prefix's durable names before allowing further effects.
        for name in [SPOOL_OBJECTS_DIR, SPOOL_STAGING_DIR, SPOOL_HOLDS_DIR] {
            io.sync_directory(&root.join(name)).map_err(persistence)?;
        }
        io.sync_directory(root).map_err(persistence)?;
        verify_identities(io.as_ref(), &identities)?;
        Ok(Self {
            spool,
            io,
            limits,
            identities,
            pins,
            latest,
            poisoned: false,
        })
    }

    /// Journal root whose exclusive lock remains held by this owner.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.spool.root()
    }

    /// An ambiguous persistence or live-identity failure requires a cold reopen.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Number of orphaned staging files retained without treating them as checkpoints.
    #[must_use]
    pub fn orphaned_staging_count(&self) -> usize {
        self.spool.orphaned_staging().count()
    }

    fn append_record(&mut self, checkpoint: &[u8]) -> Result<UploadJournalPin, MultipartError> {
        verify_identities(self.io.as_ref(), &self.identities)?;
        let previous = self.head();
        if let Some(pin) = previous {
            // A cached head is never enough to authorize the next durable write.
            self.spool.read(pin.root).map_err(persistence)?;
        }
        let sequence = previous.map_or(1, |pin| pin.sequence + 1);
        let bytes = encode_record(sequence, previous.map(|pin| pin.root), checkpoint)?;
        let digest = ContentDigest::sha256(&bytes);
        let receipt = self.spool.stage_bytes(&bytes).map_err(persistence)?;
        if receipt.digest != digest {
            return Err(persistence(
                "upload journal stage returned a different record",
            ));
        }
        self.spool.verify(digest).map_err(persistence)?;
        verify_identities(self.io.as_ref(), &self.identities)?;
        self.pins.insert(sequence, digest);
        self.latest = Some(checkpoint.to_vec());
        Ok(UploadJournalPin {
            sequence,
            root: digest,
        })
    }
}

impl UploadJournal for FileUploadJournal {
    fn head(&self) -> Option<UploadJournalPin> {
        self.pins
            .last_key_value()
            .map(|(&sequence, &root)| UploadJournalPin { sequence, root })
    }

    fn latest(&self) -> Option<&[u8]> {
        self.latest.as_deref()
    }

    fn contains(&self, pin: UploadJournalPin) -> bool {
        !pin.root.is_laboratory() && self.pins.get(&pin.sequence) == Some(&pin.root)
    }

    fn append(
        &mut self,
        expected: Option<UploadJournalPin>,
        checkpoint: &[u8],
    ) -> Result<UploadJournalPin, MultipartError> {
        if self.poisoned {
            return Err(persistence(
                "upload journal owner is poisoned; cold reopen required",
            ));
        }
        if expected != self.head() {
            return Err(persistence("upload journal expected head does not match"));
        }
        if self.pins.len() >= self.limits.max_records
            || checkpoint.len() > self.limits.max_checkpoint_bytes
        {
            return Err(persistence(
                "upload journal record or checkpoint bound exhausted",
            ));
        }
        validate_checkpoint_transition(self.latest(), checkpoint)?;
        // Validation and stale-head refusals above have performed no I/O. Once persistence
        // starts, even a refusal might follow a durable rename and must poison this handle.
        let result = self.append_record(checkpoint);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

struct Record {
    sequence: u64,
    previous: Option<ContentDigest>,
    checkpoint: Vec<u8>,
}

fn encode_record(
    sequence: u64,
    previous: Option<ContentDigest>,
    checkpoint: &[u8],
) -> Result<Vec<u8>, MultipartError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(UPLOAD_JOURNAL_RECORD_DOMAIN);
    encoder.u64(sequence);
    encoder.bool(previous.is_some());
    if let Some(root) = previous {
        encoder.digest(root);
    }
    encoder.bytes(checkpoint);
    encoder.finish_checked().map_err(persistence)
}

fn decode_record(bytes: &[u8], max_checkpoint_bytes: usize) -> Result<Record, MultipartError> {
    let mut decoder = CanonicalDecoder::new(bytes);
    if decoder.text().map_err(persistence)? != UPLOAD_JOURNAL_RECORD_DOMAIN {
        return Err(persistence("unknown upload journal record domain"));
    }
    let sequence = decoder.u64().map_err(persistence)?;
    let previous = if decoder.bool().map_err(persistence)? {
        Some(decoder.digest().map_err(persistence)?)
    } else {
        None
    };
    if sequence == 0 || (sequence == 1) != previous.is_none() {
        return Err(persistence(
            "invalid upload journal sequence or predecessor",
        ));
    }
    if let Some(root) = previous {
        validate_pin(UploadJournalPin {
            sequence: sequence - 1,
            root,
        })?;
    }
    let checkpoint = decoder.bytes().map_err(persistence)?;
    if checkpoint.len() > max_checkpoint_bytes {
        return Err(persistence(
            "upload checkpoint exceeds configured byte bound",
        ));
    }
    decoder.ensure_finished().map_err(persistence)?;
    if encode_record(sequence, previous, checkpoint)? != bytes {
        return Err(persistence("noncanonical upload journal record"));
    }
    Ok(Record {
        sequence,
        previous,
        checkpoint: checkpoint.to_vec(),
    })
}

fn validate_pin(pin: UploadJournalPin) -> Result<(), MultipartError> {
    if pin.sequence == 0
        || pin.root.algorithm() != DigestAlgorithm::Sha256
        || pin.root.is_laboratory()
        || pin.root.bytes() == [0; 32]
    {
        return Err(persistence("invalid independent upload journal pin"));
    }
    Ok(())
}

fn persistence(error: impl std::fmt::Display) -> MultipartError {
    MultipartError::Persistence(error.to_string())
}

fn inspect_ancestors(
    io: &dyn SpoolIo,
    root: &Path,
    must_exist: bool,
) -> Result<Vec<(PathBuf, FileIdentity)>, MultipartError> {
    if !root.is_absolute()
        || root.components().count() > MAX_PATH_COMPONENTS
        || root
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(persistence(
            "upload journal requires a bounded absolute path without parent traversal",
        ));
    }
    let mut identities = Vec::new();
    for path in root.ancestors() {
        match io.symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                identities.push((
                    path.to_path_buf(),
                    FileIdentity::from_metadata(&metadata).map_err(persistence)?,
                ));
            }
            Ok(_) => {
                return Err(persistence(
                    "upload journal ancestor is not a real directory",
                ));
            }
            Err(error) if !must_exist && error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(persistence(error)),
        }
    }
    Ok(identities)
}

fn inspect_layout(
    io: &dyn SpoolIo,
    root: &Path,
) -> Result<Vec<(PathBuf, FileIdentity)>, MultipartError> {
    let mut identities = inspect_ancestors(io, root, true)?;
    for name in [
        SPOOL_OBJECTS_DIR,
        SPOOL_STAGING_DIR,
        SPOOL_HOLDS_DIR,
        SPOOL_LOCK_FILE,
    ] {
        let path = root.join(name);
        let metadata = io.symlink_metadata(&path).map_err(persistence)?;
        let correct_kind = if name == SPOOL_LOCK_FILE {
            metadata.file_type().is_file()
        } else {
            metadata.file_type().is_dir()
        };
        if !correct_kind {
            return Err(persistence(
                "upload journal has an invalid directory or lock entry",
            ));
        }
        identities.push((
            path,
            FileIdentity::from_metadata(&metadata).map_err(persistence)?,
        ));
    }
    Ok(identities)
}

fn verify_identities(
    io: &dyn SpoolIo,
    expected: &[(PathBuf, FileIdentity)],
) -> Result<(), MultipartError> {
    for (path, identity) in expected {
        let metadata = io.symlink_metadata(path).map_err(persistence)?;
        if FileIdentity::from_metadata(&metadata).map_err(persistence)? != *identity {
            return Err(persistence(
                "upload journal directory or lock identity changed",
            ));
        }
    }
    Ok(())
}

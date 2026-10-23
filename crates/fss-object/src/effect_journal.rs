#![forbid(unsafe_code)]
//! Exclusive local custody for canonical runtime effect records.
//!
//! Each immutable record binds its sequence, predecessor, and original filesystem namespace.
//! Recovery requires an independently retained minimum pin and verifies the entire contiguous
//! chain. A copied namespace, replaced lock, corrupt object, fork, or missing predecessor refuses.
//! Any failure after persistence begins poisons the owner until cold recovery; it never authorizes
//! redispatch. Runtime effect semantics and authority revalidation remain in `fss-runtime`.
//!
//! Every filesystem boundary uses the supplied [`SpoolIo`] capability. The advisory lock excludes
//! cooperating writers; stable file identities require a supported platform. This reference
//! backend cannot detect rollback beyond the caller's independent pin or hostile filesystem
//! replacement inside a single system call.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_runtime::effect_journal::{EffectJournalPin, EffectJournalStore, EffectPersistenceError};

use crate::upload_journal::io::{BudgetedJournalIo, FileIdentity};
use crate::{
    SPOOL_HOLDS_DIR, SPOOL_LOCK_FILE, SPOOL_OBJECTS_DIR, SPOOL_STAGING_DIR, SpoolIo, SpoolLimits,
    StagingSpool,
};

/// Canonical envelope for one runtime-owned effect record in local custody.
pub const EFFECT_JOURNAL_RECORD_DOMAIN: &str = "fss.runtime_effect_journal_record.v1";
/// Original absolute path, directory, and lock identity of a local effect journal.
pub const EFFECT_JOURNAL_NAMESPACE_DOMAIN: &str = "fss.runtime_effect_journal_namespace.v1";
const RECORD_OVERHEAD: usize = 8 + EFFECT_JOURNAL_RECORD_DOMAIN.len() + 33 + 8 + 1 + 33 + 8;
const MAX_PATH_COMPONENTS: usize = 256;

/// Explicit storage and read-work ceilings; admission never prunes retained history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectJournalLimits {
    /// Maximum committed runtime records, at most 65,536.
    pub max_records: usize,
    /// Maximum bytes in one canonical runtime record, at most 512 KiB.
    pub max_record_bytes: usize,
    /// Maximum spool payload bytes, including record envelopes and orphaned staging.
    pub max_total_bytes: u64,
    /// Cumulative bytes read by this owner, including recovery and full-prefix revalidation
    /// before every append. Exhaustion refuses work and requires an explicitly budgeted reopen.
    pub max_read_bytes: u64,
}

impl Default for EffectJournalLimits {
    fn default() -> Self {
        Self {
            max_records: 4096,
            max_record_bytes: 512 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
            max_read_bytes: 256 * 1024 * 1024,
        }
    }
}

impl EffectJournalLimits {
    fn spool_limits(self) -> Result<SpoolLimits, EffectPersistenceError> {
        if self.max_records == 0
            || self.max_records > 65_536
            || self.max_record_bytes == 0
            || self.max_record_bytes > 512 * 1024
            || self.max_total_bytes == 0
            || self.max_total_bytes > 1024 * 1024 * 1024
            || self.max_read_bytes == 0
        {
            return Err(EffectPersistenceError::Capacity);
        }
        Ok(SpoolLimits::new(
            self.max_records,
            self.max_total_bytes,
            self.max_record_bytes + RECORD_OVERHEAD,
            self.max_records.saturating_mul(2).saturating_add(16),
        ))
    }
}

/// File-backed effect history whose exclusive spool lock lives as long as this owner.
///
/// Payloads remain opaque here: [`EffectJournalStore::records`] returns the verified sequence
/// for the runtime's own semantic replay. A successful append proves local custody only.
#[derive(Debug)]
pub struct FileEffectJournal {
    spool: StagingSpool,
    io: Arc<BudgetedJournalIo>,
    limits: EffectJournalLimits,
    identities: Vec<(PathBuf, FileIdentity)>,
    pins: BTreeMap<u64, ContentDigest>,
    records: Vec<Vec<u8>>,
    namespace: ContentDigest,
    poisoned: bool,
}

impl FileEffectJournal {
    /// Creates a new empty history, or admits an initialized but entirely empty spool.
    /// Existing records and staging remnants are never adopted as a fresh history. The parent
    /// must already exist and is synchronized before this method reports success.
    pub fn create(
        root: impl AsRef<Path>,
        limits: EffectJournalLimits,
        capability: Arc<dyn SpoolIo>,
    ) -> Result<Self, EffectPersistenceError> {
        let root = root.as_ref();
        let spool_limits = limits.spool_limits()?;
        let io = Arc::new(BudgetedJournalIo::new(capability, limits.max_read_bytes));
        let before = inspect_ancestors(io.as_ref(), root, false)?;
        let parent = root.parent().ok_or(EffectPersistenceError::InvalidHistory(
            "effect journal requires an existing parent",
        ))?;
        if !io.symlink_metadata(parent).map_err(storage)?.is_dir() {
            return Err(EffectPersistenceError::InvalidHistory(
                "effect journal parent is not a real directory",
            ));
        }
        let spool = StagingSpool::open_with_io(root, spool_limits, io.clone()).map_err(storage)?;
        verify_identities(io.as_ref(), &before)?;
        if spool.object_count() != 0 || !spool.recovery_report().is_clean() {
            return Err(EffectPersistenceError::InvalidHistory(
                "creating an effect journal requires an empty spool",
            ));
        }
        let identities = inspect_layout(io.as_ref(), root)?;
        io.sync_directory(parent).map_err(storage)?;
        verify_identities(io.as_ref(), &identities)?;
        let namespace = namespace_binding(root, &identities)?;
        Ok(Self {
            spool,
            io,
            limits,
            identities,
            pins: BTreeMap::new(),
            records: Vec::new(),
            namespace,
            poisoned: false,
        })
    }

    /// Opens complete history containing an independently retained minimum pin.
    ///
    /// Later committed records are retained, including an append whose response was lost. A
    /// missing root never creates new history. Incomplete staging remains charged and observable;
    /// it never becomes a record. All committed objects and their physical namespace are checked.
    pub fn open(
        root: impl AsRef<Path>,
        limits: EffectJournalLimits,
        capability: Arc<dyn SpoolIo>,
        minimum: EffectJournalPin,
    ) -> Result<Self, EffectPersistenceError> {
        validate_pin(minimum)?;
        let root = root.as_ref();
        let spool_limits = limits.spool_limits()?;
        let io = Arc::new(BudgetedJournalIo::new(capability, limits.max_read_bytes));
        let identities = inspect_layout(io.as_ref(), root)?;
        let namespace = namespace_binding(root, &identities)?;
        let spool = StagingSpool::open_with_io(root, spool_limits, io.clone()).map_err(storage)?;
        verify_identities(io.as_ref(), &identities)?;
        let report = spool.recovery_report();
        if !report.corrupt.is_empty() || !report.foreign.is_empty() {
            return Err(EffectPersistenceError::InvalidHistory(
                "effect journal contains corrupt or foreign entries",
            ));
        }
        let mut ordered = BTreeMap::new();
        for digest in spool.digests() {
            let bytes = spool
                .read_bounded(digest, spool_limits.max_object_bytes)
                .map_err(storage)?;
            let record = decode_record(&bytes, limits.max_record_bytes)?;
            if record.namespace != namespace {
                return Err(EffectPersistenceError::InvalidHistory(
                    "effect journal physical namespace changed",
                ));
            }
            if ordered.insert(record.sequence, (digest, record)).is_some() {
                return Err(EffectPersistenceError::InvalidHistory(
                    "effect journal has competing records at one sequence",
                ));
            }
        }
        let mut pins = BTreeMap::new();
        let mut records = Vec::with_capacity(ordered.len());
        let mut previous: Option<EffectJournalPin> = None;
        for (sequence, (root, record)) in ordered {
            if sequence != previous.map_or(1, |pin| pin.sequence + 1)
                || record.previous != previous.map(|pin| pin.root)
            {
                return Err(EffectPersistenceError::InvalidHistory(
                    "effect journal has a missing or mismatched predecessor",
                ));
            }
            pins.insert(sequence, root);
            records.push(record.payload);
            previous = Some(EffectJournalPin { sequence, root });
        }
        if pins.get(&minimum.sequence) != Some(&minimum.root) {
            return Err(EffectPersistenceError::PinMismatch);
        }
        // Cold recovery may find a renamed object whose original directory sync failed.
        // Synchronize those exact names before admitting new runtime work.
        for name in [SPOOL_OBJECTS_DIR, SPOOL_STAGING_DIR, SPOOL_HOLDS_DIR] {
            io.sync_directory(&root.join(name)).map_err(storage)?;
        }
        io.sync_directory(root).map_err(storage)?;
        verify_identities(io.as_ref(), &identities)?;
        Ok(Self {
            spool,
            io,
            limits,
            identities,
            pins,
            records,
            namespace,
            poisoned: false,
        })
    }

    /// Absolute root whose exclusive lock is held by this owner.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.spool.root()
    }

    /// Whether cold recovery is required before any new append can be admitted.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Original path and filesystem identity bound into every record.
    #[must_use]
    pub const fn namespace_binding(&self) -> ContentDigest {
        self.namespace
    }

    /// Incomplete staging files retained and charged without being replayed as committed records.
    #[must_use]
    pub fn orphaned_staging_count(&self) -> usize {
        self.spool.orphaned_staging().count()
    }

    fn persist(&mut self, payload: &[u8]) -> Result<EffectJournalPin, EffectPersistenceError> {
        verify_identities(self.io.as_ref(), &self.identities)?;
        // The cached spool index must still cover the entire committed namespace. An
        // unexpected object or foreign entry could make cold replay refuse even if all
        // previously pinned bytes remain intact. Stop listing after the first extra entry.
        let mut entries = self
            .io
            .read_dir(&self.spool.root().join(SPOOL_OBJECTS_DIR))
            .map_err(storage)?;
        let mut count = 0;
        while let Some(entry) = self.io.next_dir_entry(&mut entries) {
            let entry = entry.map_err(storage)?;
            count += 1;
            if count > self.pins.len()
                || !self.io.entry_file_type(&entry).map_err(storage)?.is_file()
            {
                return Err(EffectPersistenceError::InvalidHistory(
                    "effect journal committed entries changed",
                ));
            }
        }
        if count != self.pins.len() {
            return Err(EffectPersistenceError::InvalidHistory(
                "effect journal committed entries disappeared",
            ));
        }
        // A cached history cannot authorize a dispatch-bearing append when any earlier
        // record has disappeared or changed. Every pinned object is freshly rehashed;
        // the explicit owner read allowance bounds this work across all appends.
        for root in self.pins.values() {
            self.spool.read(*root).map_err(storage)?;
        }
        let previous = self.head();
        let sequence = previous.map_or(1, |pin| pin.sequence + 1);
        let bytes = encode_record(
            sequence,
            previous.map(|pin| pin.root),
            self.namespace,
            payload,
        )?;
        let digest = ContentDigest::sha256(&bytes);
        let receipt = self.spool.stage_bytes(&bytes).map_err(storage)?;
        if receipt.digest != digest {
            return Err(EffectPersistenceError::InvalidHistory(
                "effect journal stage returned a different record",
            ));
        }
        self.spool.verify(digest).map_err(storage)?;
        verify_identities(self.io.as_ref(), &self.identities)?;
        self.pins.insert(sequence, digest);
        self.records.push(payload.to_vec());
        Ok(EffectJournalPin {
            sequence,
            root: digest,
        })
    }
}

impl EffectJournalStore for FileEffectJournal {
    fn head(&self) -> Option<EffectJournalPin> {
        self.pins
            .last_key_value()
            .map(|(&sequence, &root)| EffectJournalPin { sequence, root })
    }

    fn records(&self) -> &[Vec<u8>] {
        &self.records
    }

    fn contains(&self, pin: EffectJournalPin) -> bool {
        !pin.root.is_laboratory() && self.pins.get(&pin.sequence) == Some(&pin.root)
    }

    fn reserve_capacity(
        &mut self,
        additional_records: usize,
        max_record_bytes: usize,
    ) -> Result<(), EffectPersistenceError> {
        if self.poisoned {
            return Err(EffectPersistenceError::Poisoned);
        }
        let count = self.pins.len().checked_add(additional_records);
        let bytes = max_record_bytes
            .checked_add(RECORD_OVERHEAD)
            .and_then(|n| n.checked_mul(additional_records))
            .and_then(|n| u64::try_from(n).ok())
            .and_then(|n| self.spool.occupied_bytes().ok()?.checked_add(n));
        if max_record_bytes > self.limits.max_record_bytes
            || count.is_none_or(|count| count > self.limits.max_records)
            || bytes.is_none_or(|bytes| bytes > self.limits.max_total_bytes)
        {
            return Err(EffectPersistenceError::Capacity);
        }
        Ok(())
    }

    fn append(
        &mut self,
        expected: Option<EffectJournalPin>,
        record: &[u8],
    ) -> Result<EffectJournalPin, EffectPersistenceError> {
        if self.poisoned {
            return Err(EffectPersistenceError::Poisoned);
        }
        if expected != self.head() {
            return Err(EffectPersistenceError::PinMismatch);
        }
        self.reserve_capacity(1, record.len())?;
        // Refusals above precede I/O. Any later failure could follow a durable object rename.
        let result = self.persist(record);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

struct Record {
    sequence: u64,
    previous: Option<ContentDigest>,
    namespace: ContentDigest,
    payload: Vec<u8>,
}

fn encode_record(
    sequence: u64,
    previous: Option<ContentDigest>,
    namespace: ContentDigest,
    payload: &[u8],
) -> Result<Vec<u8>, EffectPersistenceError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(EFFECT_JOURNAL_RECORD_DOMAIN);
    encoder.digest(namespace);
    encoder.u64(sequence);
    encoder.bool(previous.is_some());
    if let Some(previous) = previous {
        encoder.digest(previous);
    }
    encoder.bytes(payload);
    encoder.finish_checked().map_err(storage)
}

fn decode_record(bytes: &[u8], maximum: usize) -> Result<Record, EffectPersistenceError> {
    let mut decoder = CanonicalDecoder::new(bytes);
    if decoder.text().map_err(storage)? != EFFECT_JOURNAL_RECORD_DOMAIN {
        return Err(EffectPersistenceError::InvalidHistory(
            "unknown effect journal record domain",
        ));
    }
    let namespace = decoder.digest().map_err(storage)?;
    validate_pin(EffectJournalPin {
        sequence: 1,
        root: namespace,
    })?;
    let sequence = decoder.u64().map_err(storage)?;
    let previous = if decoder.bool().map_err(storage)? {
        Some(decoder.digest().map_err(storage)?)
    } else {
        None
    };
    if sequence == 0 || (sequence == 1) != previous.is_none() {
        return Err(EffectPersistenceError::InvalidHistory(
            "invalid effect journal sequence or predecessor",
        ));
    }
    if let Some(root) = previous {
        validate_pin(EffectJournalPin {
            sequence: sequence - 1,
            root,
        })?;
    }
    let payload = decoder.bytes().map_err(storage)?;
    if payload.len() > maximum {
        return Err(EffectPersistenceError::Capacity);
    }
    decoder.ensure_finished().map_err(storage)?;
    if encode_record(sequence, previous, namespace, payload)? != bytes {
        return Err(EffectPersistenceError::InvalidHistory(
            "noncanonical effect journal record",
        ));
    }
    Ok(Record {
        sequence,
        previous,
        namespace,
        payload: payload.to_vec(),
    })
}

fn validate_pin(pin: EffectJournalPin) -> Result<(), EffectPersistenceError> {
    if pin.sequence == 0
        || pin.root.algorithm() != DigestAlgorithm::Sha256
        || pin.root.is_laboratory()
        || pin.root.bytes() == [0; 32]
    {
        return Err(EffectPersistenceError::PinMismatch);
    }
    Ok(())
}

fn namespace_binding(
    root: &Path,
    identities: &[(PathBuf, FileIdentity)],
) -> Result<ContentDigest, EffectPersistenceError> {
    let canonical: PathBuf = root.components().collect();
    let directory = identities
        .iter()
        .find(|(path, _)| path == root)
        .map(|(_, identity)| *identity)
        .ok_or(EffectPersistenceError::InvalidHistory(
            "missing journal directory identity",
        ))?;
    let lock = identities
        .iter()
        .find(|(path, _)| *path == root.join(SPOOL_LOCK_FILE))
        .map(|(_, identity)| *identity)
        .ok_or(EffectPersistenceError::InvalidHistory(
            "missing journal lock identity",
        ))?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text(EFFECT_JOURNAL_NAMESPACE_DOMAIN);
    encoder.bytes(canonical.as_os_str().as_encoded_bytes());
    directory.encode(&mut encoder);
    lock.encode(&mut encoder);
    Ok(ContentDigest::sha256(
        &encoder.finish_checked().map_err(storage)?,
    ))
}

fn inspect_ancestors(
    io: &dyn SpoolIo,
    root: &Path,
    must_exist: bool,
) -> Result<Vec<(PathBuf, FileIdentity)>, EffectPersistenceError> {
    if !root.is_absolute()
        || root.components().count() > MAX_PATH_COMPONENTS
        || root
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(EffectPersistenceError::InvalidHistory(
            "effect journal requires a bounded absolute path without parent traversal",
        ));
    }
    let mut identities = Vec::new();
    for path in root.ancestors() {
        match io.symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_dir() => identities.push((
                path.to_path_buf(),
                FileIdentity::from_metadata(&metadata).map_err(storage)?,
            )),
            Ok(_) => {
                return Err(EffectPersistenceError::InvalidHistory(
                    "effect journal ancestor is not a real directory",
                ));
            }
            Err(error) if !must_exist && error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(storage(error)),
        }
    }
    Ok(identities)
}

fn inspect_layout(
    io: &dyn SpoolIo,
    root: &Path,
) -> Result<Vec<(PathBuf, FileIdentity)>, EffectPersistenceError> {
    let mut identities = inspect_ancestors(io, root, true)?;
    for name in [
        SPOOL_OBJECTS_DIR,
        SPOOL_STAGING_DIR,
        SPOOL_HOLDS_DIR,
        SPOOL_LOCK_FILE,
    ] {
        let path = root.join(name);
        let metadata = io.symlink_metadata(&path).map_err(storage)?;
        let correct_kind = if name == SPOOL_LOCK_FILE {
            metadata.file_type().is_file()
        } else {
            metadata.file_type().is_dir()
        };
        if !correct_kind {
            return Err(EffectPersistenceError::InvalidHistory(
                "effect journal has an invalid directory or lock entry",
            ));
        }
        identities.push((
            path,
            FileIdentity::from_metadata(&metadata).map_err(storage)?,
        ));
    }
    Ok(identities)
}

fn verify_identities(
    io: &dyn SpoolIo,
    expected: &[(PathBuf, FileIdentity)],
) -> Result<(), EffectPersistenceError> {
    for (path, identity) in expected {
        let metadata = io.symlink_metadata(path).map_err(storage)?;
        if FileIdentity::from_metadata(&metadata).map_err(storage)? != *identity {
            return Err(EffectPersistenceError::InvalidHistory(
                "effect journal directory or lock identity changed",
            ));
        }
    }
    Ok(())
}

fn storage(error: impl std::fmt::Display) -> EffectPersistenceError {
    EffectPersistenceError::Storage(error.to_string())
}

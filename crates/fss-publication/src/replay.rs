#![forbid(unsafe_code)]
//! Canonical Replay Bundle v1 Reader/Writer (FSS-019).
//!
//! A replay bundle is a versioned, content-addressed, self-verifying envelope that captures
//! all deterministic inputs required to reconstruct or verify an authority history:
//!
//! - A published manifest root or state root.
//! - Deployment lineage, seeds, and generation coordinates.
//! - An injected packet/delivery fault schedule.
//! - An ordered [`EvidenceDeltaBatch`] history.
//! - Verified object payloads for every referenced capsule, delta payload, witness, and child root.
//!
//! # Verification Guarantee
//!
//! [`ReplayBundleReader`] verifies every byte before exposing anything:
//! 1. Envelope magic and format version are checked.
//! 2. The 33-byte trailer checksum is verified against SHA-256 of all preceding bytes.
//! 3. All string lengths and collection sizes are bounded.
//! 4. Every batch is decoded, verified for canonical ordering, verified against its computed
//!    digest, and checked for anchor sequence continuity (`prior == prev.successor`).
//! 5. Every object payload is rehashed to match its declared [`ContentDigest`].
//! 6. **Manifest Closure**: every object digest referenced by any delta in the batch history
//!    (payload, witness, or child root) is proved to exist in the object catalog.
//! 7. The manifest root must be verified in the object catalog or match the final state root.
//!
//! Any corruption, truncation, missing dependency, or reordering causes an immediate typed
//! [`ReplayBundleError`]. Partial replays are strictly impossible.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Write as _};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use fss_core::{
    BatchId, ContentDigest, ContractError, DigestAlgorithm, EvidenceDeltaBatch, LedgerAnchor,
    ObjectId, Plane,
};
use fss_ledger::{
    BatchCodecError, CommitReceipt, LedgerOracle, OracleError, OracleLimits, decode_batch,
    encode_batch,
};
use fss_object::{SpoolError, StageReceipt, StagingSpool};

/// Registered digest domain for replay bundles.
pub const REPLAY_BUNDLE_DOMAIN: &str = "fss.replay_bundle.v1";

/// Format magic bytes: ASCII `FSSREP01`.
pub const REPLAY_BUNDLE_MAGIC: [u8; 8] = *b"FSSREP01";

/// Format version 1.
pub const REPLAY_BUNDLE_FORMAT_VERSION: u16 = 1;

/// Hard ceiling for batches in one replay bundle.
pub const MAX_REPLAY_BATCHES: usize = 1_024;

/// Hard ceiling for distinct objects in one replay bundle.
pub const MAX_REPLAY_OBJECTS: usize = 4_096;

/// Maximum payload size for one object (16 MB).
pub const MAX_REPLAY_OBJECT_BYTES: usize = 16 * 1024 * 1024;

/// Maximum total size of a serialized replay bundle (64 MB).
pub const MAX_REPLAY_TOTAL_BYTES: usize = 64 * 1024 * 1024;

/// Maximum UTF-8 length for text fields.
pub const MAX_REPLAY_TEXT_BYTES: usize = 4_096;

/// Maximum fault directives in the fault schedule.
pub const MAX_REPLAY_FAULT_DIRECTIVES: usize = 1_024;

/// Maximum reorder window in the fault schedule.
pub const MAX_REPLAY_FAULT_REORDER_WINDOW: usize = 256;

/// Length of the trailer checksum record: 1 byte algorithm tag + 32 bytes SHA-256.
pub const REPLAY_TRAILER_LEN: usize = 33;

/// Upper bound on distinct staging names tried when writing a replay bundle.
///
/// Each write owns its own attempt sequence `0..MAX_REPLAY_TEMP_ATTEMPTS`; no
/// process-global state participates in staging names. `create_new` guarantees that a name held
/// by a concurrent writer or left behind by an interrupted one is never opened, overwritten, or
/// removed by this call.
pub const MAX_REPLAY_TEMP_ATTEMPTS: u32 = 16;

/// Computes the deterministic staging path used by `attempt` while writing a replay bundle.
///
/// The name is `.tmp.replay.{digest-hex}.{pid}.{attempt}` in the target directory.
/// It is a pure function of its inputs and the current process id and never consults shared mutable state.
#[must_use]
pub fn replay_temp_path_for(target_path: &Path, digest: ContentDigest, attempt: u32) -> PathBuf {
    sibling_path(
        target_path,
        format!(
            ".tmp.replay.{}.{}.{attempt}",
            digest_hex(digest),
            std::process::id()
        ),
    )
}

fn digest_hex(digest: ContentDigest) -> String {
    let mut hex = String::with_capacity(64);
    for byte in digest.bytes() {
        let _ = write!(&mut hex, "{byte:02x}");
    }
    hex
}

fn sibling_path(target_path: &Path, file_name: String) -> PathBuf {
    let parent = target_path.parent().unwrap_or_else(|| Path::new("."));
    if parent.as_os_str().is_empty() {
        PathBuf::from(file_name)
    } else {
        parent.join(file_name)
    }
}

/// Creates a fresh staging file for atomic bundle publication with a bounded `create_new` retry.
///
/// A name that already exists belongs to someone else (a concurrent writer or an interrupted
/// earlier write) and is skipped, never opened or removed. When every bounded name is taken the
/// call fails with [`ReplayBundleError::ReplayTempExhausted`] before the target file is touched.
fn create_replay_temp(
    target_path: &Path,
    digest: ContentDigest,
) -> Result<(PathBuf, File), ReplayBundleError> {
    for attempt in 0..MAX_REPLAY_TEMP_ATTEMPTS {
        let candidate = replay_temp_path_for(target_path, digest, attempt);
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&candidate)
        {
            Ok(file) => return Ok((candidate, file)),
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {}
            Err(err) => {
                return Err(ReplayBundleError::Io {
                    operation: "create_temp_file",
                    kind: err.kind(),
                });
            }
        }
    }
    Err(ReplayBundleError::ReplayTempExhausted {
        directory: target_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf(),
        attempts: MAX_REPLAY_TEMP_ATTEMPTS,
    })
}

/// Configurable limits for validating replay bundles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayBundleLimits {
    /// Maximum batches allowed in one bundle.
    pub max_batches: usize,
    /// Maximum referenced objects allowed.
    pub max_objects: usize,
    /// Maximum payload bytes for one object.
    pub max_object_bytes: usize,
    /// Maximum total bundle bytes.
    pub max_total_bytes: usize,
    /// Maximum text bytes for string fields.
    pub max_text_bytes: usize,
    /// Maximum directives in fault schedule.
    pub max_fault_directives: usize,
    /// Maximum reorder window in fault schedule.
    pub max_fault_reorder_window: usize,
}

impl Default for ReplayBundleLimits {
    fn default() -> Self {
        Self {
            max_batches: MAX_REPLAY_BATCHES,
            max_objects: MAX_REPLAY_OBJECTS,
            max_object_bytes: MAX_REPLAY_OBJECT_BYTES,
            max_total_bytes: MAX_REPLAY_TOTAL_BYTES,
            max_text_bytes: MAX_REPLAY_TEXT_BYTES,
            max_fault_directives: MAX_REPLAY_FAULT_DIRECTIVES,
            max_fault_reorder_window: MAX_REPLAY_FAULT_REORDER_WINDOW,
        }
    }
}

/// Action to apply to a specific packet sequence in a replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayFaultAction {
    /// Deliver without modification.
    Pass,
    /// Drop the packet entirely.
    Drop,
    /// Delay packet delivery by a specified tick count.
    Delay {
        /// Ticks to delay.
        ticks: u32,
    },
    /// Duplicate the packet.
    Duplicate {
        /// Number of extra copies.
        copies: u8,
    },
    /// Corrupt the packet payload.
    Corrupt {
        /// Mutation tag indicating corruption type (e.g. 1 for bit flip).
        mutation_tag: u8,
    },
}

/// One scheduled fault directive at a specific source sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayFaultDirective {
    /// Source sequence this directive targets.
    pub source_sequence: u64,
    /// Fault action to apply.
    pub action: ReplayFaultAction,
}

/// Injected fault schedule recorded in the replay bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayFaultSchedule {
    /// Random seed used for stochastic decisions.
    pub seed: u64,
    /// Reorder window size.
    pub reorder_window: usize,
    /// Explicit ordered sequence of fault directives.
    pub directives: Vec<ReplayFaultDirective>,
}

impl ReplayFaultSchedule {
    /// Creates a deterministic fault schedule with no explicit directives.
    #[must_use]
    pub const fn empty(seed: u64, reorder_window: usize) -> Self {
        Self {
            seed,
            reorder_window,
            directives: Vec::new(),
        }
    }

    /// Creates a deterministic fault schedule with explicit directives.
    pub fn new(
        seed: u64,
        reorder_window: usize,
        directives: Vec<ReplayFaultDirective>,
    ) -> Result<Self, ReplayBundleError> {
        if reorder_window > MAX_REPLAY_FAULT_REORDER_WINDOW {
            return Err(ReplayBundleError::BoundExceeded("fault_reorder_window"));
        }
        if directives.len() > MAX_REPLAY_FAULT_DIRECTIVES {
            return Err(ReplayBundleError::BoundExceeded("fault_directives"));
        }
        Ok(Self {
            seed,
            reorder_window,
            directives,
        })
    }
}

/// Generation coordinates and seed metadata for the replay environment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayMetadata {
    /// Deployment lineage for authority anchors.
    pub site_lineage: String,
    /// Simulation or execution seed.
    pub seed: u64,
    /// Schema registry generation.
    pub schema_generation: u64,
    /// Policy generation.
    pub policy_generation: u64,
    /// Model generation.
    pub model_generation: u64,
    /// Device registry generation.
    pub device_generation: u64,
}

impl ReplayMetadata {
    /// Validates metadata field bounds.
    pub fn validate(&self, limits: &ReplayBundleLimits) -> Result<(), ReplayBundleError> {
        if self.site_lineage.is_empty() || self.site_lineage.len() > limits.max_text_bytes {
            return Err(ReplayBundleError::BoundExceeded("site_lineage"));
        }
        Ok(())
    }
}

/// One verified immutable object payload in the replay bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayObject {
    /// Logical object identity.
    pub object_id: ObjectId,
    /// Content digest of payload bytes.
    pub digest: ContentDigest,
    /// Owning architectural plane.
    pub plane: Plane,
    /// Raw object bytes.
    pub payload: Vec<u8>,
}

impl ReplayObject {
    /// Constructs a verified object entry, hashing the payload.
    pub fn new(object_id: ObjectId, plane: Plane, payload: Vec<u8>) -> Self {
        let digest = ContentDigest::sha256(&payload);
        Self {
            object_id,
            digest,
            plane,
            payload,
        }
    }

    /// Constructs an object entry from pre-hashed digest and payload, verifying match.
    pub fn with_digest(
        object_id: ObjectId,
        digest: ContentDigest,
        plane: Plane,
        payload: Vec<u8>,
    ) -> Result<Self, ReplayBundleError> {
        let computed = ContentDigest::sha256(&payload);
        if computed != digest {
            return Err(ReplayBundleError::ObjectDigestMismatch {
                object_id,
                expected: digest,
                computed,
            });
        }
        Ok(Self {
            object_id,
            digest,
            plane,
            payload,
        })
    }
}

/// Receipt returned after durable publication of a replay bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayBundleReceipt {
    /// Content digest of the complete bundle body.
    pub bundle_digest: ContentDigest,
    /// Manifest root digest referenced by the bundle.
    pub manifest_root: ContentDigest,
    /// Number of batches recorded.
    pub batch_count: usize,
    /// Number of verified objects recorded.
    pub object_count: usize,
    /// Total bytes written.
    pub total_bytes: usize,
}

/// Typed errors emitted during replay bundle encoding, decoding, or execution.
#[derive(Debug)]
pub enum ReplayBundleError {
    /// Unexpected end of file or buffer.
    UnexpectedEof,
    /// Invalid magic bytes.
    InvalidMagic([u8; 8]),
    /// Unsupported format version.
    UnsupportedVersion(u16),
    /// A bounded limit was exceeded.
    BoundExceeded(&'static str),
    /// String field is not valid UTF-8.
    InvalidUtf8,
    /// Invalid discriminator or enum tag.
    InvalidTag {
        /// Field name.
        field: &'static str,
        /// Invalid byte tag.
        tag: u8,
    },
    /// Extra unconsumed bytes remained before the trailer.
    TrailingBytes,
    /// Trailer checksum does not match computed SHA-256 over preceding bytes.
    ChecksumMismatch {
        /// Expected checksum from trailer.
        expected: ContentDigest,
        /// Computed SHA-256 over body.
        computed: ContentDigest,
    },
    /// A batch computed digest does not match its declared batch digest.
    BatchDigestMismatch {
        /// Batch identity.
        batch_id: BatchId,
        /// Declared digest.
        expected: ContentDigest,
        /// Computed digest.
        computed: ContentDigest,
    },
    /// Batch sequence is discontinuous.
    BatchDiscontinuousAnchor {
        /// Sequence number of the disconnected batch.
        sequence: u64,
        /// Expected basis anchor.
        expected: Box<LedgerAnchor>,
        /// Actual basis anchor found.
        actual: Box<LedgerAnchor>,
    },
    /// Batch deltas or children are not in canonical order.
    BatchNonCanonicalOrder(BatchId),
    /// Batch successor sequence does not advance by exactly one.
    BatchSequenceInvalid {
        /// Expected successor sequence.
        expected: u64,
        /// Actual successor sequence.
        actual: u64,
    },
    /// Batch site lineage does not match bundle metadata.
    BatchLineageMismatch {
        /// Expected site lineage.
        expected: String,
        /// Actual site lineage.
        actual: String,
    },
    /// An object payload does not match its declared content digest.
    ObjectDigestMismatch {
        /// Object identity.
        object_id: ObjectId,
        /// Expected digest.
        expected: ContentDigest,
        /// Computed digest.
        computed: ContentDigest,
    },
    /// Duplicate object digest in object catalog.
    DuplicateObject(ContentDigest),
    /// An object referenced by a delta or batch child is missing from the bundle.
    BrokenManifestClosure {
        /// Missing object digest.
        missing_digest: ContentDigest,
    },
    /// The bundle contains zero batches.
    EmptyBundle,
    /// Filesystem or I/O failure.
    Io {
        /// Operation being performed.
        operation: &'static str,
        /// I/O error kind.
        kind: ErrorKind,
    },
    /// Core contract violation.
    Contract(ContractError),
    /// Ledger oracle replay failure.
    Oracle(OracleError),
    /// Staging spool failure.
    Spool(SpoolError),
    /// Batch codec failure.
    BatchCodec(BatchCodecError),
    /// Every bounded staging name for atomic bundle write already exists.
    ReplayTempExhausted {
        /// Directory in which staging was attempted.
        directory: PathBuf,
        /// Number of distinct staging names tried.
        attempts: u32,
    },
}

impl fmt::Display for ReplayBundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => formatter.write_str("replay bundle unexpected EOF"),
            Self::InvalidMagic(bytes) => {
                write!(formatter, "replay bundle invalid magic: {bytes:?}")
            }
            Self::UnsupportedVersion(version) => {
                write!(formatter, "replay bundle unsupported version {version}")
            }
            Self::BoundExceeded(field) => {
                write!(formatter, "replay bundle bound exceeded: {field}")
            }
            Self::InvalidUtf8 => formatter.write_str("replay bundle invalid UTF-8 string"),
            Self::InvalidTag { field, tag } => {
                write!(
                    formatter,
                    "replay bundle invalid tag {tag} for field {field}"
                )
            }
            Self::TrailingBytes => formatter.write_str("replay bundle has trailing bytes"),
            Self::ChecksumMismatch { expected, computed } => {
                write!(
                    formatter,
                    "replay bundle checksum mismatch: expected {expected}, computed {computed}"
                )
            }
            Self::BatchDigestMismatch {
                batch_id,
                expected,
                computed,
            } => {
                write!(
                    formatter,
                    "batch {batch_id} digest mismatch: declared {expected}, computed {computed}"
                )
            }
            Self::BatchDiscontinuousAnchor {
                sequence,
                expected,
                actual,
            } => {
                write!(
                    formatter,
                    "batch sequence {sequence} discontinuous: expected basis {expected:?}, got {actual:?}"
                )
            }
            Self::BatchNonCanonicalOrder(id) => {
                write!(formatter, "batch {id} entries are not canonically ordered")
            }
            Self::BatchSequenceInvalid { expected, actual } => {
                write!(
                    formatter,
                    "batch sequence invalid: expected {expected}, got {actual}"
                )
            }
            Self::BatchLineageMismatch { expected, actual } => {
                write!(
                    formatter,
                    "batch lineage mismatch: expected {expected}, got {actual}"
                )
            }
            Self::ObjectDigestMismatch {
                object_id,
                expected,
                computed,
            } => {
                write!(
                    formatter,
                    "object {object_id} digest mismatch: declared {expected}, computed {computed}"
                )
            }
            Self::DuplicateObject(digest) => {
                write!(formatter, "duplicate object digest in catalog: {digest}")
            }
            Self::BrokenManifestClosure { missing_digest } => {
                write!(
                    formatter,
                    "broken manifest closure: referenced object {missing_digest} is missing from bundle"
                )
            }
            Self::EmptyBundle => formatter.write_str("replay bundle contains zero batches"),
            Self::Io { operation, kind } => {
                write!(
                    formatter,
                    "replay bundle I/O error during {operation}: {kind:?}"
                )
            }
            Self::Contract(error) => write!(formatter, "replay bundle contract error: {error}"),
            Self::Oracle(error) => write!(formatter, "replay oracle error: {error}"),
            Self::Spool(error) => write!(formatter, "replay spool error: {error}"),
            Self::BatchCodec(error) => write!(formatter, "replay batch codec error: {error}"),
            Self::ReplayTempExhausted {
                directory,
                attempts,
            } => write!(
                formatter,
                "could not stage replay bundle in {}: all {attempts} bounded staging names already exist; inspect stale *.tmp.* files from interrupted writes",
                directory.display()
            ),
        }
    }
}

impl Error for ReplayBundleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::Oracle(error) => Some(error),
            Self::Spool(error) => Some(error),
            Self::BatchCodec(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ContractError> for ReplayBundleError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

impl From<OracleError> for ReplayBundleError {
    fn from(error: OracleError) -> Self {
        Self::Oracle(error)
    }
}

impl From<SpoolError> for ReplayBundleError {
    fn from(error: SpoolError) -> Self {
        Self::Spool(error)
    }
}

impl From<BatchCodecError> for ReplayBundleError {
    fn from(error: BatchCodecError) -> Self {
        Self::BatchCodec(error)
    }
}

/// A validated, self-verifying replay bundle containing complete causal history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayBundle {
    manifest_root: ContentDigest,
    metadata: ReplayMetadata,
    fault_schedule: ReplayFaultSchedule,
    batches: Vec<EvidenceDeltaBatch>,
    objects: Vec<ReplayObject>,
    objects_by_digest: BTreeMap<ContentDigest, usize>,
}

impl ReplayBundle {
    /// Constructs and validates a new `ReplayBundle`.
    ///
    /// Validates all bounds, batch sequence continuity, object digests, and manifest closure.
    pub fn new(
        manifest_root: ContentDigest,
        metadata: ReplayMetadata,
        fault_schedule: ReplayFaultSchedule,
        batches: Vec<EvidenceDeltaBatch>,
        objects: Vec<ReplayObject>,
    ) -> Result<Self, ReplayBundleError> {
        Self::new_with_limits(
            manifest_root,
            metadata,
            fault_schedule,
            batches,
            objects,
            &ReplayBundleLimits::default(),
        )
    }

    /// Constructs and validates a new `ReplayBundle` with explicit limits.
    pub fn new_with_limits(
        manifest_root: ContentDigest,
        metadata: ReplayMetadata,
        fault_schedule: ReplayFaultSchedule,
        batches: Vec<EvidenceDeltaBatch>,
        objects: Vec<ReplayObject>,
        limits: &ReplayBundleLimits,
    ) -> Result<Self, ReplayBundleError> {
        metadata.validate(limits)?;

        if fault_schedule.reorder_window > limits.max_fault_reorder_window {
            return Err(ReplayBundleError::BoundExceeded("fault_reorder_window"));
        }
        if fault_schedule.directives.len() > limits.max_fault_directives {
            return Err(ReplayBundleError::BoundExceeded("fault_directives"));
        }

        if batches.is_empty() {
            return Err(ReplayBundleError::EmptyBundle);
        }
        if batches.len() > limits.max_batches {
            return Err(ReplayBundleError::BoundExceeded("batches"));
        }
        if objects.len() > limits.max_objects {
            return Err(ReplayBundleError::BoundExceeded("objects"));
        }

        // Validate batch sequence continuity
        for (idx, batch) in batches.iter().enumerate() {
            if !batch.is_canonically_ordered() {
                return Err(ReplayBundleError::BatchNonCanonicalOrder(
                    batch.batch_id.clone(),
                ));
            }
            if batch.computed_digest() != batch.batch_digest {
                return Err(ReplayBundleError::BatchDigestMismatch {
                    batch_id: batch.batch_id.clone(),
                    expected: batch.batch_digest,
                    computed: batch.computed_digest(),
                });
            }
            if batch.basis_anchor.site_lineage != metadata.site_lineage {
                return Err(ReplayBundleError::BatchLineageMismatch {
                    expected: metadata.site_lineage.clone(),
                    actual: batch.basis_anchor.site_lineage.clone(),
                });
            }
            if batch.new_anchor.site_lineage != metadata.site_lineage {
                return Err(ReplayBundleError::BatchLineageMismatch {
                    expected: metadata.site_lineage.clone(),
                    actual: batch.new_anchor.site_lineage.clone(),
                });
            }
            let expected_seq = batch.basis_anchor.commit_sequence + 1;
            if batch.new_anchor.commit_sequence != expected_seq {
                return Err(ReplayBundleError::BatchSequenceInvalid {
                    expected: expected_seq,
                    actual: batch.new_anchor.commit_sequence,
                });
            }
            if idx > 0 {
                let prev_anchor = &batches[idx - 1].new_anchor;
                if &batch.basis_anchor != prev_anchor {
                    return Err(ReplayBundleError::BatchDiscontinuousAnchor {
                        sequence: batch.new_anchor.commit_sequence,
                        expected: Box::new(prev_anchor.clone()),
                        actual: Box::new(batch.basis_anchor.clone()),
                    });
                }
            }
        }

        // Validate objects, hashing payloads, and index by digest
        let mut objects_by_digest = BTreeMap::new();
        for (idx, obj) in objects.iter().enumerate() {
            if obj.payload.len() > limits.max_object_bytes {
                return Err(ReplayBundleError::BoundExceeded("object_payload"));
            }
            let computed = ContentDigest::sha256(&obj.payload);
            if computed != obj.digest {
                return Err(ReplayBundleError::ObjectDigestMismatch {
                    object_id: obj.object_id.clone(),
                    expected: obj.digest,
                    computed,
                });
            }
            if objects_by_digest.insert(obj.digest, idx).is_some() {
                return Err(ReplayBundleError::DuplicateObject(obj.digest));
            }
        }

        // Verify Manifest Closure: every digest referenced in batches must exist in objects
        for batch in &batches {
            for delta in &batch.deltas {
                if !objects_by_digest.contains_key(&delta.payload_digest) {
                    return Err(ReplayBundleError::BrokenManifestClosure {
                        missing_digest: delta.payload_digest,
                    });
                }
                if let Some(witness) = delta.witness_digest
                    && !objects_by_digest.contains_key(&witness)
                {
                    return Err(ReplayBundleError::BrokenManifestClosure {
                        missing_digest: witness,
                    });
                }
            }
            for child in &batch.children {
                if !objects_by_digest.contains_key(child) {
                    return Err(ReplayBundleError::BrokenManifestClosure {
                        missing_digest: *child,
                    });
                }
            }
        }

        // Verify manifest root: must exist in objects or match state root of final batch
        let final_state_root = batches
            .last()
            .map(|b| b.new_anchor.state_root)
            .ok_or(ReplayBundleError::EmptyBundle)?;
        if manifest_root != final_state_root && !objects_by_digest.contains_key(&manifest_root) {
            return Err(ReplayBundleError::BrokenManifestClosure {
                missing_digest: manifest_root,
            });
        }

        Ok(Self {
            manifest_root,
            metadata,
            fault_schedule,
            batches,
            objects,
            objects_by_digest,
        })
    }

    /// Manifest root digest.
    #[must_use]
    pub const fn manifest_root(&self) -> ContentDigest {
        self.manifest_root
    }

    /// Replay environment metadata.
    #[must_use]
    pub const fn metadata(&self) -> &ReplayMetadata {
        &self.metadata
    }

    /// Deployment lineage.
    #[must_use]
    pub fn site_lineage(&self) -> &str {
        &self.metadata.site_lineage
    }

    /// Fault schedule.
    #[must_use]
    pub const fn fault_schedule(&self) -> &ReplayFaultSchedule {
        &self.fault_schedule
    }

    /// Ordered batches in canonical sequence.
    #[must_use]
    pub fn batches(&self) -> &[EvidenceDeltaBatch] {
        &self.batches
    }

    /// Verified immutable objects in the catalog.
    #[must_use]
    pub fn objects(&self) -> &[ReplayObject] {
        &self.objects
    }

    /// Retrieves an object entry by its content digest.
    #[must_use]
    pub fn object_by_digest(&self, digest: &ContentDigest) -> Option<&ReplayObject> {
        let idx = self.objects_by_digest.get(digest)?;
        self.objects.get(*idx)
    }

    /// SHA-256 digest over the canonical serialized body (excluding trailer).
    pub fn digest(&self) -> Result<ContentDigest, ReplayBundleError> {
        self.digest_with_limits(&ReplayBundleLimits::default())
    }

    /// SHA-256 digest over the canonical serialized body with explicit limits (excluding trailer).
    pub fn digest_with_limits(
        &self,
        limits: &ReplayBundleLimits,
    ) -> Result<ContentDigest, ReplayBundleError> {
        let body = ReplayBundleWriter::to_body_bytes(self, limits)?;
        Ok(ContentDigest::sha256(&body))
    }

    /// Replays the ordered batch history through a [`LedgerOracle`].
    ///
    /// The oracle's head anchor must match the basis anchor of the first batch in the bundle.
    /// Returns the receipt for the final committed batch.
    pub fn replay_through_oracle(
        &self,
        oracle: &mut LedgerOracle,
    ) -> Result<CommitReceipt, ReplayBundleError> {
        let first_batch = self.batches.first().ok_or(ReplayBundleError::EmptyBundle)?;
        if oracle.head_anchor() != &first_batch.basis_anchor {
            return Err(ReplayBundleError::BatchDiscontinuousAnchor {
                sequence: first_batch.basis_anchor.commit_sequence,
                expected: Box::new(oracle.head_anchor().clone()),
                actual: Box::new(first_batch.basis_anchor.clone()),
            });
        }

        let mut last_receipt = None;
        for batch in &self.batches {
            let staged = oracle.stage(batch.clone())?;
            let receipt = oracle.commit(staged)?;
            last_receipt = Some(receipt);
        }

        last_receipt.ok_or(ReplayBundleError::EmptyBundle)
    }

    /// Creates a fresh [`LedgerOracle`] at the basis anchor of the first batch,
    /// replays every batch in sequence, and returns the oracle.
    pub fn replay(&self) -> Result<LedgerOracle, ReplayBundleError> {
        let first_batch = self.batches.first().ok_or(ReplayBundleError::EmptyBundle)?;
        let limits = OracleLimits::new(MAX_REPLAY_BATCHES + 1, MAX_REPLAY_OBJECTS + 1)?;
        let mut oracle = LedgerOracle::new(&self.metadata.site_lineage, limits)?;

        // If the bundle doesn't start at genesis, we use rebuild or stage
        if first_batch.basis_anchor != *oracle.head_anchor() {
            return Err(ReplayBundleError::BatchDiscontinuousAnchor {
                sequence: first_batch.basis_anchor.commit_sequence,
                expected: Box::new(oracle.head_anchor().clone()),
                actual: Box::new(first_batch.basis_anchor.clone()),
            });
        }

        for batch in &self.batches {
            let staged = oracle.stage(batch.clone())?;
            oracle.commit(staged)?;
        }

        Ok(oracle)
    }

    /// Stages and verifies all referenced object payloads into an explicit [`StagingSpool`].
    pub fn spool_objects(
        &self,
        spool: &mut StagingSpool,
    ) -> Result<Vec<StageReceipt>, ReplayBundleError> {
        let mut receipts = Vec::with_capacity(self.objects.len());
        for obj in &self.objects {
            let receipt = spool.stage_bytes(&obj.payload)?;
            spool.verify(receipt.digest)?;
            receipts.push(receipt);
        }
        Ok(receipts)
    }
}

/// Serializes replay bundles into the canonical v1 binary format and writes them crash-safely.
pub struct ReplayBundleWriter;

impl ReplayBundleWriter {
    /// Encodes a replay bundle into binary bytes.
    pub fn to_bytes(bundle: &ReplayBundle) -> Result<Vec<u8>, ReplayBundleError> {
        Self::to_bytes_with_limits(bundle, &ReplayBundleLimits::default())
    }

    /// Encodes a replay bundle with explicit limits.
    pub fn to_bytes_with_limits(
        bundle: &ReplayBundle,
        limits: &ReplayBundleLimits,
    ) -> Result<Vec<u8>, ReplayBundleError> {
        let body = Self::to_body_bytes(bundle, limits)?;
        let body_digest = ContentDigest::sha256(&body);

        let mut out = body;
        // Trailer: algorithm tag 1 (SHA-256) + 32 bytes digest
        out.push(1);
        out.extend_from_slice(&body_digest.bytes());

        if out.len() > limits.max_total_bytes {
            return Err(ReplayBundleError::BoundExceeded("total_bytes"));
        }

        Ok(out)
    }

    /// Writes a replay bundle atomically and crash-safely to a file path.
    ///
    /// Uses an atomic temporary file write in the same directory, syncs data to disk,
    /// and atomically renames to the final destination. If writing fails, cleans up the
    /// temporary file and leaves the target file untouched.
    pub fn write_to_path(
        path: &Path,
        bundle: &ReplayBundle,
    ) -> Result<ReplayBundleReceipt, ReplayBundleError> {
        Self::write_to_path_with_limits(path, bundle, &ReplayBundleLimits::default())
    }

    /// Writes a replay bundle atomically with explicit limits.
    pub fn write_to_path_with_limits(
        path: &Path,
        bundle: &ReplayBundle,
        limits: &ReplayBundleLimits,
    ) -> Result<ReplayBundleReceipt, ReplayBundleError> {
        let bytes = Self::to_bytes_with_limits(bundle, limits)?;
        let body_len = bytes.len() - REPLAY_TRAILER_LEN;
        let bundle_digest = ContentDigest::sha256(&bytes[..body_len]);

        let (temp_path, mut file) = create_replay_temp(path, bundle_digest)?;

        let write_res = (|| -> Result<(), ReplayBundleError> {
            file.write_all(&bytes).map_err(|e| ReplayBundleError::Io {
                operation: "write_temp_file",
                kind: e.kind(),
            })?;
            file.sync_all().map_err(|e| ReplayBundleError::Io {
                operation: "sync_temp_file",
                kind: e.kind(),
            })?;
            drop(file);
            fs::rename(&temp_path, path).map_err(|e| ReplayBundleError::Io {
                operation: "rename_temp_file",
                kind: e.kind(),
            })?;
            Ok(())
        })();

        if let Err(err) = write_res {
            let _ = fs::remove_file(&temp_path);
            return Err(err);
        }

        Ok(ReplayBundleReceipt {
            bundle_digest,
            manifest_root: bundle.manifest_root,
            batch_count: bundle.batches.len(),
            object_count: bundle.objects.len(),
            total_bytes: bytes.len(),
        })
    }

    fn to_body_bytes(
        bundle: &ReplayBundle,
        limits: &ReplayBundleLimits,
    ) -> Result<Vec<u8>, ReplayBundleError> {
        if bundle.batches.is_empty() {
            return Err(ReplayBundleError::EmptyBundle);
        }
        if bundle.batches.len() > limits.max_batches {
            return Err(ReplayBundleError::BoundExceeded("batches"));
        }
        if bundle.objects.len() > limits.max_objects {
            return Err(ReplayBundleError::BoundExceeded("objects"));
        }
        if bundle.fault_schedule.directives.len() > limits.max_fault_directives {
            return Err(ReplayBundleError::BoundExceeded("fault_directives"));
        }
        if bundle.fault_schedule.reorder_window > limits.max_fault_reorder_window {
            return Err(ReplayBundleError::BoundExceeded("fault_reorder_window"));
        }

        let mut out = Vec::new();

        // Magic and version
        out.extend_from_slice(&REPLAY_BUNDLE_MAGIC);
        out.extend_from_slice(&REPLAY_BUNDLE_FORMAT_VERSION.to_be_bytes());

        // Manifest root digest (1 byte algorithm tag 1 for SHA-256 + 32 bytes)
        out.push(1);
        out.extend_from_slice(&bundle.manifest_root.bytes());

        // Metadata
        encode_text(&mut out, &bundle.metadata.site_lineage, limits)?;
        out.extend_from_slice(&bundle.metadata.seed.to_be_bytes());
        out.extend_from_slice(&bundle.metadata.schema_generation.to_be_bytes());
        out.extend_from_slice(&bundle.metadata.policy_generation.to_be_bytes());
        out.extend_from_slice(&bundle.metadata.model_generation.to_be_bytes());
        out.extend_from_slice(&bundle.metadata.device_generation.to_be_bytes());

        // Fault schedule
        out.extend_from_slice(&bundle.fault_schedule.seed.to_be_bytes());
        out.extend_from_slice(&(bundle.fault_schedule.reorder_window as u32).to_be_bytes());
        out.extend_from_slice(&(bundle.fault_schedule.directives.len() as u32).to_be_bytes());
        for directive in &bundle.fault_schedule.directives {
            out.extend_from_slice(&directive.source_sequence.to_be_bytes());
            match directive.action {
                ReplayFaultAction::Pass => out.push(0),
                ReplayFaultAction::Drop => out.push(1),
                ReplayFaultAction::Delay { ticks } => {
                    out.push(2);
                    out.extend_from_slice(&ticks.to_be_bytes());
                }
                ReplayFaultAction::Duplicate { copies } => {
                    out.push(3);
                    out.push(copies);
                }
                ReplayFaultAction::Corrupt { mutation_tag } => {
                    out.push(4);
                    out.push(mutation_tag);
                }
            }
        }

        // Batches
        out.extend_from_slice(&(bundle.batches.len() as u32).to_be_bytes());
        for batch in &bundle.batches {
            let encoded = encode_batch(batch)?;
            out.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
            out.extend_from_slice(&encoded);
        }

        // Objects
        out.extend_from_slice(&(bundle.objects.len() as u32).to_be_bytes());
        for obj in &bundle.objects {
            encode_text(&mut out, obj.object_id.as_str(), limits)?;
            out.push(1); // algorithm SHA-256
            out.extend_from_slice(&obj.digest.bytes());
            out.push(match obj.plane {
                Plane::Authority => 0,
                Plane::Cognition => 1,
                Plane::Effect => 2,
            });
            if obj.payload.len() > limits.max_object_bytes {
                return Err(ReplayBundleError::BoundExceeded("object_payload"));
            }
            out.extend_from_slice(&(obj.payload.len() as u32).to_be_bytes());
            out.extend_from_slice(&obj.payload);
        }

        Ok(out)
    }
}

/// Reads and verifies replay bundles from binary bytes or file paths.
pub struct ReplayBundleReader;

impl ReplayBundleReader {
    /// Reads and verifies a replay bundle from a byte slice with default limits.
    pub fn from_bytes(bytes: &[u8]) -> Result<ReplayBundle, ReplayBundleError> {
        Self::from_bytes_with_limits(bytes, &ReplayBundleLimits::default())
    }

    /// Reads and verifies a replay bundle from a byte slice with explicit limits.
    pub fn from_bytes_with_limits(
        bytes: &[u8],
        limits: &ReplayBundleLimits,
    ) -> Result<ReplayBundle, ReplayBundleError> {
        if bytes.len() > limits.max_total_bytes {
            return Err(ReplayBundleError::BoundExceeded("total_bytes"));
        }
        if bytes.len() < REPLAY_TRAILER_LEN + 8 + 2 + 33 {
            return Err(ReplayBundleError::UnexpectedEof);
        }

        // Trailer verification
        let body_len = bytes.len() - REPLAY_TRAILER_LEN;
        let body = &bytes[..body_len];
        let trailer = &bytes[body_len..];

        let trailer_alg = trailer[0];
        if trailer_alg != 1 {
            return Err(ReplayBundleError::InvalidTag {
                field: "trailer_algorithm",
                tag: trailer_alg,
            });
        }
        let mut expected_bytes = [0_u8; 32];
        expected_bytes.copy_from_slice(&trailer[1..33]);
        let expected_digest = ContentDigest::new(DigestAlgorithm::Sha256, expected_bytes);
        let computed_digest = ContentDigest::sha256(body);

        if computed_digest != expected_digest {
            return Err(ReplayBundleError::ChecksumMismatch {
                expected: expected_digest,
                computed: computed_digest,
            });
        }

        let mut cursor = 0;

        // Magic
        let magic = read_exact_array::<8>(body, &mut cursor)?;
        if magic != REPLAY_BUNDLE_MAGIC {
            return Err(ReplayBundleError::InvalidMagic(magic));
        }

        // Version
        let version = read_u16(body, &mut cursor)?;
        if version != REPLAY_BUNDLE_FORMAT_VERSION {
            return Err(ReplayBundleError::UnsupportedVersion(version));
        }

        // Manifest root digest
        let root_alg = read_u8(body, &mut cursor)?;
        if root_alg != 1 {
            return Err(ReplayBundleError::InvalidTag {
                field: "manifest_root_algorithm",
                tag: root_alg,
            });
        }
        let root_bytes = read_exact_array::<32>(body, &mut cursor)?;
        let manifest_root = ContentDigest::new(DigestAlgorithm::Sha256, root_bytes);

        // Metadata
        let site_lineage = read_text(body, &mut cursor, limits)?;
        let seed = read_u64(body, &mut cursor)?;
        let schema_generation = read_u64(body, &mut cursor)?;
        let policy_generation = read_u64(body, &mut cursor)?;
        let model_generation = read_u64(body, &mut cursor)?;
        let device_generation = read_u64(body, &mut cursor)?;

        let metadata = ReplayMetadata {
            site_lineage,
            seed,
            schema_generation,
            policy_generation,
            model_generation,
            device_generation,
        };

        // Fault schedule
        let fault_seed = read_u64(body, &mut cursor)?;
        let reorder_window = read_u32(body, &mut cursor)? as usize;
        if reorder_window > limits.max_fault_reorder_window {
            return Err(ReplayBundleError::BoundExceeded("fault_reorder_window"));
        }
        let directive_count = read_u32(body, &mut cursor)? as usize;
        if directive_count > limits.max_fault_directives {
            return Err(ReplayBundleError::BoundExceeded("fault_directives"));
        }
        let mut directives = Vec::with_capacity(directive_count);
        for _ in 0..directive_count {
            let source_sequence = read_u64(body, &mut cursor)?;
            let action_tag = read_u8(body, &mut cursor)?;
            let action = match action_tag {
                0 => ReplayFaultAction::Pass,
                1 => ReplayFaultAction::Drop,
                2 => {
                    let ticks = read_u32(body, &mut cursor)?;
                    ReplayFaultAction::Delay { ticks }
                }
                3 => {
                    let copies = read_u8(body, &mut cursor)?;
                    ReplayFaultAction::Duplicate { copies }
                }
                4 => {
                    let mutation_tag = read_u8(body, &mut cursor)?;
                    ReplayFaultAction::Corrupt { mutation_tag }
                }
                other => {
                    return Err(ReplayBundleError::InvalidTag {
                        field: "fault_action",
                        tag: other,
                    });
                }
            };
            directives.push(ReplayFaultDirective {
                source_sequence,
                action,
            });
        }
        let fault_schedule = ReplayFaultSchedule {
            seed: fault_seed,
            reorder_window,
            directives,
        };

        // Batches
        let batch_count = read_u32(body, &mut cursor)? as usize;
        if batch_count == 0 {
            return Err(ReplayBundleError::EmptyBundle);
        }
        if batch_count > limits.max_batches {
            return Err(ReplayBundleError::BoundExceeded("batches"));
        }
        let mut batches = Vec::with_capacity(batch_count);
        for _ in 0..batch_count {
            let batch_bytes_len = read_u32(body, &mut cursor)? as usize;
            let batch_bytes = read_slice(body, &mut cursor, batch_bytes_len)?;
            let batch = decode_batch(batch_bytes)?;
            batches.push(batch);
        }

        // Objects
        let object_count = read_u32(body, &mut cursor)? as usize;
        if object_count > limits.max_objects {
            return Err(ReplayBundleError::BoundExceeded("objects"));
        }
        let mut objects = Vec::with_capacity(object_count);
        for _ in 0..object_count {
            let object_id_str = read_text(body, &mut cursor, limits)?;
            let object_id = ObjectId::parse(object_id_str)?;
            let digest_alg = read_u8(body, &mut cursor)?;
            if digest_alg != 1 {
                return Err(ReplayBundleError::InvalidTag {
                    field: "object_digest_algorithm",
                    tag: digest_alg,
                });
            }
            let digest_bytes = read_exact_array::<32>(body, &mut cursor)?;
            let digest = ContentDigest::new(DigestAlgorithm::Sha256, digest_bytes);
            let plane_tag = read_u8(body, &mut cursor)?;
            let plane = match plane_tag {
                0 => Plane::Authority,
                1 => Plane::Cognition,
                2 => Plane::Effect,
                other => {
                    return Err(ReplayBundleError::InvalidTag {
                        field: "plane",
                        tag: other,
                    });
                }
            };
            let payload_len = read_u32(body, &mut cursor)? as usize;
            if payload_len > limits.max_object_bytes {
                return Err(ReplayBundleError::BoundExceeded("object_payload"));
            }
            let payload = read_slice(body, &mut cursor, payload_len)?.to_vec();
            objects.push(ReplayObject {
                object_id,
                digest,
                plane,
                payload,
            });
        }

        if cursor != body.len() {
            return Err(ReplayBundleError::TrailingBytes);
        }

        ReplayBundle::new_with_limits(
            manifest_root,
            metadata,
            fault_schedule,
            batches,
            objects,
            limits,
        )
    }

    /// Reads and verifies a replay bundle directly from a file path.
    pub fn read_from_path(path: &Path) -> Result<ReplayBundle, ReplayBundleError> {
        Self::read_from_path_with_limits(path, &ReplayBundleLimits::default())
    }

    /// Reads and verifies a replay bundle directly from a file path with explicit limits.
    pub fn read_from_path_with_limits(
        path: &Path,
        limits: &ReplayBundleLimits,
    ) -> Result<ReplayBundle, ReplayBundleError> {
        let mut file = File::open(path).map_err(|e| ReplayBundleError::Io {
            operation: "open_file",
            kind: e.kind(),
        })?;
        let metadata = file.metadata().map_err(|e| ReplayBundleError::Io {
            operation: "file_metadata",
            kind: e.kind(),
        })?;
        if metadata.len() as usize > limits.max_total_bytes {
            return Err(ReplayBundleError::BoundExceeded("total_bytes"));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)
            .map_err(|e| ReplayBundleError::Io {
                operation: "read_file",
                kind: e.kind(),
            })?;
        Self::from_bytes_with_limits(&bytes, limits)
    }
}

fn encode_text(
    out: &mut Vec<u8>,
    text: &str,
    limits: &ReplayBundleLimits,
) -> Result<(), ReplayBundleError> {
    if text.len() > limits.max_text_bytes {
        return Err(ReplayBundleError::BoundExceeded("text"));
    }
    out.extend_from_slice(&(text.len() as u32).to_be_bytes());
    out.extend_from_slice(text.as_bytes());
    Ok(())
}

fn read_u8(buf: &[u8], cursor: &mut usize) -> Result<u8, ReplayBundleError> {
    if *cursor + 1 > buf.len() {
        return Err(ReplayBundleError::UnexpectedEof);
    }
    let val = buf[*cursor];
    *cursor += 1;
    Ok(val)
}

fn read_u16(buf: &[u8], cursor: &mut usize) -> Result<u16, ReplayBundleError> {
    if *cursor + 2 > buf.len() {
        return Err(ReplayBundleError::UnexpectedEof);
    }
    let val = u16::from_be_bytes([buf[*cursor], buf[*cursor + 1]]);
    *cursor += 2;
    Ok(val)
}

fn read_u32(buf: &[u8], cursor: &mut usize) -> Result<u32, ReplayBundleError> {
    if *cursor + 4 > buf.len() {
        return Err(ReplayBundleError::UnexpectedEof);
    }
    let val = u32::from_be_bytes([
        buf[*cursor],
        buf[*cursor + 1],
        buf[*cursor + 2],
        buf[*cursor + 3],
    ]);
    *cursor += 4;
    Ok(val)
}

fn read_u64(buf: &[u8], cursor: &mut usize) -> Result<u64, ReplayBundleError> {
    if *cursor + 8 > buf.len() {
        return Err(ReplayBundleError::UnexpectedEof);
    }
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&buf[*cursor..*cursor + 8]);
    let val = u64::from_be_bytes(bytes);
    *cursor += 8;
    Ok(val)
}

fn read_exact_array<const N: usize>(
    buf: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], ReplayBundleError> {
    if *cursor + N > buf.len() {
        return Err(ReplayBundleError::UnexpectedEof);
    }
    let mut arr = [0_u8; N];
    arr.copy_from_slice(&buf[*cursor..*cursor + N]);
    *cursor += N;
    Ok(arr)
}

fn read_slice<'a>(
    buf: &'a [u8],
    cursor: &mut usize,
    len: usize,
) -> Result<&'a [u8], ReplayBundleError> {
    if *cursor + len > buf.len() {
        return Err(ReplayBundleError::UnexpectedEof);
    }
    let slice = &buf[*cursor..*cursor + len];
    *cursor += len;
    Ok(slice)
}

fn read_text(
    buf: &[u8],
    cursor: &mut usize,
    limits: &ReplayBundleLimits,
) -> Result<String, ReplayBundleError> {
    let len = read_u32(buf, cursor)? as usize;
    if len > limits.max_text_bytes {
        return Err(ReplayBundleError::BoundExceeded("text"));
    }
    let slice = read_slice(buf, cursor, len)?;
    String::from_utf8(slice.to_vec()).map_err(|_| ReplayBundleError::InvalidUtf8)
}

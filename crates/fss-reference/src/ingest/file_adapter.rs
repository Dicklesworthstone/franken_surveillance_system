//! File ingest adapter (`ADP-FILE-001`) transforming recorded files into [`SensorCapsule`]s.
//!
//! # Architecture & Determinism
//!
//! Conforms to `ADP-FILE-001` ("bounded media import") under `GATE-010`.
//! Opens the source through the explicit [`ReplayIoAuthority`] held by the [`ReplayCx`] without
//! following symlinks, reads at most `max_file_bytes + 1` bytes from the open handle into one
//! buffer, computes the SHA-256 custody digest over exactly the bytes read, sniffs the stream
//! format, splits access units or frames with first-party pure Rust splitters, constructs
//! immutable [`SensorCapsule`]s, and stages and commits them root-last into
//! [`ReferenceDeployment`].
//!
//! Every capacity limit (spool bytes and objects, per-object size, the [`ObjectManifest`]
//! 16,384-child cap, the capsule batch size including its `file_import` delta, and the journal
//! record size) is checked before the first object is staged, because staged objects are held
//! and cannot be discarded. Partitioning one import into several batches is out of scope here;
//! an import that does not fit is refused with a typed error naming the limit.
//!
//! # Time Truth Discipline
//!
//! Files carry no live or trusted hardware clock.
//! - The ingest receive time is read from the [`VirtualClock`] the caller hands the adapter; it
//!   never defaults to a constant and never reads the host wall clock.
//! - Without an operator [`CaptureHint`], capture time is unknown: the interval is the full
//!   window `[TimestampNs(0), receive_time]` with [`ClockBasis::Estimated`] and the label
//!   `"unknown"`.
//! - With an operator [`CaptureHint`], each interval is `start + i / fps +/- u` with
//!   [`ClockBasis::Estimated`] and the label `"operator_assumption"`. A negative hint start is
//!   refused typed, never clamped.
//! - File import never emits a `ContinuityWitness` or a `CoverageWitness`; an absence query over
//!   an imported window is not certifiable.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use fss_core::identity::{
    AdapterCapabilities, AdapterIdentity, AdapterKind, CredentialMethod, IsolationMode,
};
use fss_core::{
    AdapterGeneration, AdapterId, BatchId, CanonicalDecode, CanonicalDecoder, CanonicalEncode,
    CanonicalEncoder, CapsuleId, CaptureInterval, ClockBasis, ContentDigest, ContractError,
    EvidenceDelta, EvidenceDeltaBatch, LedgerAnchor, ObjectId, Plane, SensorCapsule, SensorId,
    SensorSourceBytesSpec, StreamId, TimestampNs,
};
use fss_object::{
    MAX_MANIFEST_CHILDREN, MAX_OBJECT_BYTES, ObjectError, ObjectManifest, SpoolError,
};
use fss_publication::{LocalPublicationError, SlotName};

use crate::VirtualClock;
use crate::adapter_replay::{ReplayCx, ReplayIoAuthority};
use crate::error::ReferenceError;
use crate::ingest::annexb::{AnnexBError, AnnexBLimits, split_annexb};
use crate::ingest::mjpeg::{JpegSplitError, MjpegLimits, split_jpeg_stream};
use crate::reference_deployment::{
    FAMILY_FILE_IMPORT, FAMILY_FILE_IMPORT_MANIFEST, FAMILY_SENSOR_CAPSULE, ReferenceDeployment,
};

/// Canonical schema domain for [`FileImportManifest`].
pub const FILE_IMPORT_MANIFEST_SCHEMA: &str = "fss.file_import.manifest.v1";

/// Canonical digest domain for [`FileIngestLimits::canonical_digest`].
pub const FILE_INGEST_LIMITS_DOMAIN: &str = "fss.file_ingest.limits.v1";

/// Canonical digest domain for [`compute_import_identity`].
pub const FILE_IMPORT_IDENTITY_DOMAIN: &str = "fss.file_import.identity.v1";

/// Digest domain of a capsule's stored custody bytes; equal to the domain of
/// [`SensorCapsule::metadata_digest`], so the spool digest of the stored bytes is the metadata
/// digest recorded in the ledger.
pub const SENSOR_CAPSULE_CUSTODY_DOMAIN: &str = "fss.sensor_capsule.metadata.v1";

/// Registered adapter identity for `ADP-FILE-001`.
pub const ADP_FILE_ROW_ID: &str = "ADP-FILE-001";

/// Standard adapter generation for `ADP-FILE-001`.
pub const ADP_FILE_GENERATION: &str = "gen:fss1:adapters-v1";

/// Capture-time label when no operator capture hint was supplied.
pub const CAPTURE_TIME_UNKNOWN: &str = "unknown";

/// Capture-time label when an operator capture hint was supplied.
pub const CAPTURE_TIME_OPERATOR_ASSUMPTION: &str = "operator_assumption";

/// Earliest instant of the unknown capture window (the epoch of [`TimestampNs`]).
pub const UNKNOWN_CAPTURE_EARLIEST: TimestampNs = TimestampNs(0);

/// Stage name for stat checkpoint.
pub const STAGE_STAT: &str = "file_adapter:stat";
/// Stage name for reading checkpoint.
pub const STAGE_READ: &str = "file_adapter:read";
/// Stage name for splitting checkpoint.
pub const STAGE_SPLIT: &str = "file_adapter:split";
/// Stage name for capacity verification checkpoint.
pub const STAGE_CAPACITY: &str = "file_adapter:capacity";
/// Stage name for object staging checkpoint.
pub const STAGE_STAGE: &str = "file_adapter:stage";
/// Stage name for capsule batch commit checkpoint.
pub const STAGE_COMMIT_CAPSULES: &str = "file_adapter:commit_capsules";
/// Stage name for root publication checkpoint.
pub const STAGE_PUBLISH_ROOT: &str = "file_adapter:publish_root";
/// Stage name for final manifest batch commit checkpoint.
pub const STAGE_COMMIT_MANIFEST: &str = "file_adapter:commit_manifest";

/// Default chunk size: 16 MiB.
pub const DEFAULT_CHUNK_BYTES: u64 = 16 * 1024 * 1024;
/// Maximum allowed deltas or children per ledger batch.
pub const MAX_BATCH_DELTAS: usize = 16_384;

/// Recognized file format types from format sniffing.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DetectedFileFormat {
    /// H.264 Annex-B byte elementary stream with 3-byte or 4-byte start codes.
    AnnexB,
    /// Single JPEG image or concatenated MJPEG frame stream starting with SOI (`0xFFD8`).
    JpegStream,
    /// Recorded RTP session (`#!rtpplay1.0` header).
    RtpPlay,
}

impl DetectedFileFormat {
    /// Canonical string identifier for this detected format.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AnnexB => "annexb",
            Self::JpegStream => "mjpeg",
            Self::RtpPlay => "rtpplay",
        }
    }

    /// Converts this detected format to a [`FileFormatHint`].
    #[must_use]
    pub const fn into_hint(self) -> FileFormatHint {
        match self {
            Self::AnnexB => FileFormatHint::AnnexB,
            Self::JpegStream => FileFormatHint::JpegStream,
            Self::RtpPlay => FileFormatHint::RtpPlay,
        }
    }
}

/// User-provided format hint for format verification.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FileFormatHint {
    /// Expected format is H.264 Annex-B.
    AnnexB,
    /// Expected format is JPEG or MJPEG.
    JpegStream,
    /// Expected format is rtpplay packet capture.
    RtpPlay,
}

impl FileFormatHint {
    /// Canonical string representation of the hint.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AnnexB => "annexb",
            Self::JpegStream => "mjpeg",
            Self::RtpPlay => "rtpplay",
        }
    }
}

/// Operator-declared capture timing assumption.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CaptureHint {
    /// Nominal capture start timestamp; never negative.
    pub start_ns: TimestampNs,
    /// Symmetric timestamp uncertainty in nanoseconds (`+/- uncertainty_ns`).
    pub uncertainty_ns: u64,
    /// Nominal assumed frame rate in frames per second (e.g. 30.0).
    pub assumed_fps: f64,
}

impl CaptureHint {
    /// Constructs and validates a new capture hint.
    ///
    /// # Errors
    /// [`FileIngestError::NegativeCaptureHintStart`] for a negative start (never clamped) and
    /// [`FileIngestError::InvalidCaptureHint`] for a non-finite or non-positive frame rate.
    pub fn new(
        start_ns: TimestampNs,
        uncertainty_ns: u64,
        assumed_fps: f64,
    ) -> Result<Self, FileIngestError> {
        let hint = Self {
            start_ns,
            uncertainty_ns,
            assumed_fps,
        };
        hint.validate_shape()?;
        Ok(hint)
    }

    fn validate_shape(&self) -> Result<(), FileIngestError> {
        if self.start_ns < TimestampNs(0) {
            return Err(FileIngestError::NegativeCaptureHintStart {
                start_ns: self.start_ns,
            });
        }
        if self.assumed_fps <= 0.0 || !self.assumed_fps.is_finite() {
            return Err(FileIngestError::InvalidCaptureHint {
                detail: "assumed_fps must be finite and strictly positive".to_string(),
            });
        }
        Ok(())
    }
}

/// Operational bounds and limits for file ingestion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileIngestLimits {
    /// Maximum file size in bytes admitted for reading.
    pub max_file_bytes: u64,
    /// Chunk size for chunked custody objects; nonzero and at most the spool object maximum.
    pub chunk_bytes: u64,
    /// Maximum number of segments (access units or frames) allowed.
    pub max_segments: usize,
    /// Annex-B elementary stream scanner limits.
    pub annexb_limits: AnnexBLimits,
    /// MJPEG / JPEG stream scanner limits.
    pub mjpeg_limits: MjpegLimits,
}

impl Default for FileIngestLimits {
    fn default() -> Self {
        Self::standard()
    }
}

impl FileIngestLimits {
    /// Standard reference limits for file ingestion.
    ///
    /// `max_segments` is one below [`MAX_BATCH_DELTAS`] because the capsule batch also carries
    /// the `file_import` generation-1 delta and its custody child.
    #[must_use]
    pub fn standard() -> Self {
        Self {
            max_file_bytes: 512 * 1024 * 1024, // 512 MiB
            chunk_bytes: DEFAULT_CHUNK_BYTES,
            max_segments: MAX_BATCH_DELTAS - 1,
            annexb_limits: AnnexBLimits::default(),
            mjpeg_limits: MjpegLimits::default(),
        }
    }

    /// Computes the domain-separated canonical digest of these limits.
    #[must_use]
    pub fn canonical_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.canonical.v1");
        encoder.text(FILE_INGEST_LIMITS_DOMAIN);
        encoder.u64(self.max_file_bytes);
        encoder.u64(self.chunk_bytes);
        encoder.u64(self.max_segments as u64);
        encoder.u64(self.annexb_limits.max_input_bytes as u64);
        encoder.u64(self.annexb_limits.max_nal_bytes as u64);
        encoder.u64(self.annexb_limits.max_nals as u64);
        encoder.u64(self.annexb_limits.max_aus as u64);
        encoder.u64(self.mjpeg_limits.max_input_bytes as u64);
        encoder.u64(self.mjpeg_limits.max_frames as u64);
        encoder.u64(self.mjpeg_limits.max_frame_bytes as u64);
        ContentDigest::sha256(&encoder.finish())
    }
}

/// Request parameters for importing a file into [`ReferenceDeployment`].
///
/// There is deliberately no receive-time field: the receive time comes from the
/// [`VirtualClock`] passed to [`FileIngestAdapter::ingest`].
#[derive(Clone, Debug)]
pub struct FileIngestRequest {
    /// Source file path to import.
    pub path: PathBuf,
    /// Optional format hint to cross-check against detected format.
    pub format_hint: Option<FileFormatHint>,
    /// Operational limits for this import.
    pub limits: FileIngestLimits,
    /// Target sensor identifier for constructed capsules.
    pub sensor_id: SensorId,
    /// Target stream identifier for constructed capsules.
    pub stream_id: StreamId,
    /// Optional operator capture timing hint.
    pub capture_hint: Option<CaptureHint>,
}

impl FileIngestRequest {
    /// Constructs a basic file ingest request with standard limits.
    pub fn new(path: impl Into<PathBuf>, sensor_id: SensorId, stream_id: StreamId) -> Self {
        Self {
            path: path.into(),
            format_hint: None,
            limits: FileIngestLimits::standard(),
            sensor_id,
            stream_id,
            capture_hint: None,
        }
    }

    /// Sets an optional format hint.
    #[must_use]
    pub fn with_format_hint(mut self, hint: FileFormatHint) -> Self {
        self.format_hint = Some(hint);
        self
    }

    /// Sets explicit ingest limits.
    #[must_use]
    pub fn with_limits(mut self, limits: FileIngestLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Sets an optional capture timing hint.
    #[must_use]
    pub fn with_capture_hint(mut self, hint: CaptureHint) -> Self {
        self.capture_hint = Some(hint);
        self
    }
}

/// Outcome classification for file ingestion.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FileIngestOutcome {
    /// Newly imported and ledgered file.
    New,
    /// Resumed prior incomplete import that committed missing batches.
    Resumed,
    /// Already complete import; returned without appending duplicate batches.
    IdempotentExisting,
}

impl FileIngestOutcome {
    /// Canonical text representation of outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Resumed => "resumed",
            Self::IdempotentExisting => "idempotent_existing",
        }
    }
}

/// Source segment span within the imported file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentSpan {
    /// 0-based segment index.
    pub segment_index: usize,
    /// Starting byte offset in the source file.
    pub offset: u64,
    /// Byte length of the segment.
    pub len: u64,
    /// SHA-256 digest of the raw segment bytes.
    pub segment_sha256: ContentDigest,
    /// Capsule identifier assigned to this segment.
    pub capsule_id: CapsuleId,
    /// True if there was an omission, truncation, or gap before this segment.
    pub gap_before: bool,
}

impl CanonicalEncode for SegmentSpan {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.segment_index as u64);
        encoder.u64(self.offset);
        encoder.u64(self.len);
        encoder.digest(self.segment_sha256);
        self.capsule_id.encode_canonical(encoder);
        encoder.bool(self.gap_before);
    }
}

/// Omitted / unparsed byte span recorded during ingestion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileOmissionSpan {
    /// Starting byte offset in source file.
    pub offset: u64,
    /// Byte length of omitted data.
    pub len: u64,
    /// Descriptive reason for omission.
    pub reason: String,
}

impl CanonicalEncode for FileOmissionSpan {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.offset);
        encoder.u64(self.len);
        encoder.text(&self.reason);
    }
}

/// Immutable file import manifest binding input custody to derived sensor capsules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileImportManifest {
    /// SHA-256 custody digest of exactly the bytes read from the input file.
    pub input_sha256: ContentDigest,
    /// Number of bytes read from the input file (the length of the custody buffer).
    pub input_bytes: u64,
    /// Detected format string.
    pub format: String,
    /// Sniffer detector evidence explanation.
    pub detector_evidence: String,
    /// Chunk size in bytes used for chunked custody.
    pub chunk_bytes: u64,
    /// Ordered list of chunk content digests (concatenation yields original file).
    pub ordered_chunks: Vec<ContentDigest>,
    /// Per-segment byte spans and checksums.
    pub segment_spans: Vec<SegmentSpan>,
    /// Omitted byte spans.
    pub omission_spans: Vec<FileOmissionSpan>,
    /// Capsule identifiers produced by this import in order.
    pub capsule_ids: Vec<CapsuleId>,
    /// Canonical digest of the limits applied during import.
    pub limits_digest: ContentDigest,
    /// Adapter identifier string.
    pub adapter_id: String,
    /// Adapter generation string.
    pub adapter_generation: String,
    /// Roots of partitioned child manifest parts (always empty: partitioning is out of scope).
    pub part_roots: Vec<ContentDigest>,
    /// Time truth label (`"unknown"` or `"operator_assumption"`).
    pub capture_time_label: String,
}

impl CanonicalEncode for FileImportManifest {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.digest(self.input_sha256);
        encoder.u64(self.input_bytes);
        encoder.text(&self.format);
        encoder.text(&self.detector_evidence);
        encoder.u64(self.chunk_bytes);
        encoder.u64(self.ordered_chunks.len() as u64);
        for c in &self.ordered_chunks {
            encoder.digest(*c);
        }
        encoder.u64(self.segment_spans.len() as u64);
        for s in &self.segment_spans {
            s.encode_canonical(encoder);
        }
        encoder.u64(self.omission_spans.len() as u64);
        for o in &self.omission_spans {
            o.encode_canonical(encoder);
        }
        encoder.u64(self.capsule_ids.len() as u64);
        for cid in &self.capsule_ids {
            cid.encode_canonical(encoder);
        }
        encoder.digest(self.limits_digest);
        encoder.text(&self.adapter_id);
        encoder.text(&self.adapter_generation);
        encoder.u64(self.part_roots.len() as u64);
        for pr in &self.part_roots {
            encoder.digest(*pr);
        }
        encoder.text(&self.capture_time_label);
    }
}

impl FileImportManifest {
    /// Computes the domain-separated canonical digest of this manifest.
    #[must_use]
    pub fn canonical_digest(&self) -> ContentDigest {
        CanonicalEncode::canonical_digest(self, FILE_IMPORT_MANIFEST_SCHEMA)
    }

    /// Serializes this manifest to canonical bytes under its schema domain.
    ///
    /// The SHA-256 of these bytes is [`Self::canonical_digest`], so the spool digest of the
    /// staged manifest is the digest recorded in the ledger.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.canonical.v1");
        encoder.text(FILE_IMPORT_MANIFEST_SCHEMA);
        self.encode_canonical(&mut encoder);
        encoder.finish()
    }
}

/// Receipt returned upon completing or verifying a file import.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileIngestReceipt {
    /// Lifecycle outcome of the import operation.
    pub outcome: FileIngestOutcome,
    /// Canonical deterministic import identity.
    pub import_identity: ContentDigest,
    /// SHA-256 custody digest of exactly the bytes read.
    pub input_sha256: ContentDigest,
    /// Number of bytes read.
    pub input_bytes: u64,
    /// Detected format.
    pub format: DetectedFileFormat,
    /// Number of sensor capsules produced.
    pub capsule_count: usize,
    /// Sensor capsules of this import; for a resumed or existing import, the capsules already
    /// held in custody (with their original receive time).
    pub capsules: Vec<SensorCapsule>,
    /// Receive time of the capsules, read from the virtual clock of the first import attempt.
    pub receive_time: TimestampNs,
    /// Root digest of the published import slot manifest.
    pub import_root: ContentDigest,
    /// Digest of the staged [`FileImportManifest`].
    pub manifest_digest: ContentDigest,
    /// Staged [`FileImportManifest`] metadata object.
    pub manifest: FileImportManifest,
    /// Published root slot name (`fi-<id>`).
    pub root_slot: SlotName,
    /// Current canonical authority anchor after commits.
    pub authority_anchor: LedgerAnchor,
    /// Batch identifiers committed by this import, or found in the ledger for an existing one.
    pub batch_ids: Vec<BatchId>,
    /// Number of chunk objects in the file.
    pub chunk_count: usize,
    /// Number of deduplicated chunk objects.
    pub unique_chunk_count: usize,
    /// Size of each chunk in bytes.
    pub chunk_bytes: u64,
    /// Capture time truth classification label.
    pub capture_time_label: &'static str,
    /// Always `false`: file import emits no coverage witness.
    pub absence_certifiable: bool,
}

/// Typed deterministic error enum for file ingestion.
#[derive(Debug)]
pub enum FileIngestError {
    /// Specified path is a symbolic link.
    SymlinkNotAllowed {
        /// The path of the rejected symlink.
        path: PathBuf,
    },
    /// Specified path is not a regular file.
    NotRegularFile {
        /// The path of the rejected non-regular file.
        path: PathBuf,
    },
    /// The path named a different file when opened than when it was inspected.
    SourceChangedDuringOpen {
        /// The path whose target changed.
        path: PathBuf,
    },
    /// The explicit I/O authority of the context has been revoked.
    IoAuthorityRevoked,
    /// Input file is zero bytes.
    EmptyFile {
        /// The path of the empty file.
        path: PathBuf,
    },
    /// Input file exceeds maximum configured size.
    FileTooLarge {
        /// The path of the oversized file.
        path: PathBuf,
        /// Observed length: the stat length of the open handle, or, when the bounded read
        /// overran the limit, the number of bytes read (a lower bound on the true length).
        len: u64,
        /// Maximum allowed file length in bytes.
        max: u64,
    },
    /// Required new objects or bytes exceed available spool capacity.
    SpoolCapacityExceeded {
        /// Name of the exceeded limit.
        limit: &'static str,
        /// Required count or byte quantity.
        required: u64,
        /// Available capacity before breach.
        available: u64,
    },
    /// The import does not fit a manifest, batch, object, or journal-record limit. Checked
    /// before any staging; partitioning an import into several batches is not supported.
    ImportCapacityExceeded {
        /// Name of the exceeded limit.
        limit: &'static str,
        /// Required count or byte quantity.
        required: u64,
        /// Maximum allowed by the limit.
        maximum: u64,
    },
    /// The chunk size is zero or larger than one spool object may be.
    InvalidChunkSize {
        /// Requested chunk size in bytes.
        chunk_bytes: u64,
        /// Largest admissible chunk size in bytes.
        maximum: u64,
    },
    /// Format hint provided by caller conflicts with sniffed format.
    FormatConflict {
        /// Format hint passed in request.
        hint: FileFormatHint,
        /// Format detected by format sniffer.
        detected: DetectedFileFormat,
    },
    /// File content did not match any recognized media signature.
    UnknownFormat {
        /// Path to unrecognized file.
        path: PathBuf,
    },
    /// Detected format is not currently supported for splitting.
    UnsupportedFormat {
        /// Detected unsupported format.
        format: DetectedFileFormat,
    },
    /// Capture hint interval starts after ingest arrival time.
    CaptureHintAfterReceive {
        /// Declared capture hint start time.
        hint_start: TimestampNs,
        /// Ingest arrival time.
        receive_time: TimestampNs,
    },
    /// Capture hint start is negative; refused, never clamped.
    NegativeCaptureHintStart {
        /// Declared capture hint start time.
        start_ns: TimestampNs,
    },
    /// The virtual clock reads before the epoch, so the unknown capture window is empty.
    ReceiveTimeBeforeEpoch {
        /// Receive time read from the virtual clock.
        receive_time: TimestampNs,
    },
    /// Invalid parameters in capture hint.
    InvalidCaptureHint {
        /// Detail describing why the capture hint was invalid.
        detail: String,
    },
    /// The import identity already has ledger history whose content differs from this plan.
    ImportPlanConflict {
        /// Batch ID in conflict.
        batch_id: BatchId,
        /// Conflict detail message.
        detail: String,
    },
    /// Stored capsule custody bytes do not decode to the capsule they are recorded as.
    CorruptCapsuleCustody {
        /// Digest of the stored bytes.
        digest: ContentDigest,
        /// Decode or binding failure detail.
        detail: String,
    },
    /// Segment source checksum did not match the reassembled chunk slice.
    SegmentDigestMismatch {
        /// Index of the mismatched segment.
        segment_index: usize,
        /// Expected content digest from parsing.
        expected: ContentDigest,
        /// Actual reassembled segment digest.
        actual: ContentDigest,
    },
    /// Segment index was out of bounds for the manifest.
    SegmentIndexOutOfBounds {
        /// Requested segment index.
        index: usize,
        /// Total available segments in manifest.
        count: usize,
    },
    /// Source segment was malformed or could not be sliced.
    CorruptSegment {
        /// Malformation detail.
        detail: String,
    },
    /// A canonical encoding step failed.
    Encoding {
        /// Encoder failure detail.
        detail: String,
    },
    /// Cooperative cancellation was signaled at the named stage.
    CancellationRequested {
        /// Pipeline stage where cancellation was requested.
        stage: &'static str,
    },
    /// Low-level filesystem I/O error.
    Io(std::io::Error),
    /// Reference deployment or publication error.
    Reference(ReferenceError),
    /// Core contract error.
    Contract(ContractError),
    /// Annex-B stream splitting error.
    AnnexB(AnnexBError),
    /// MJPEG stream splitting error.
    Mjpeg(JpegSplitError),
    /// Local publication error.
    LocalPublication(LocalPublicationError),
    /// Spool object error.
    Spool(SpoolError),
    /// Manifest object model error.
    Object(ObjectError),
}

impl std::fmt::Display for FileIngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SymlinkNotAllowed { path } => {
                write!(f, "symlink not allowed: {}", path.display())
            }
            Self::NotRegularFile { path } => {
                write!(f, "not a regular file: {}", path.display())
            }
            Self::SourceChangedDuringOpen { path } => {
                write!(
                    f,
                    "source changed between inspection and open: {}",
                    path.display()
                )
            }
            Self::IoAuthorityRevoked => write!(f, "replay I/O authority has been revoked"),
            Self::EmptyFile { path } => {
                write!(f, "input file is empty: {}", path.display())
            }
            Self::FileTooLarge { path, len, max } => {
                write!(
                    f,
                    "file {} size {} exceeds limit {}",
                    path.display(),
                    len,
                    max
                )
            }
            Self::SpoolCapacityExceeded {
                limit,
                required,
                available,
            } => {
                write!(
                    f,
                    "spool capacity exceeded for {limit}: required {required} > available {available}"
                )
            }
            Self::ImportCapacityExceeded {
                limit,
                required,
                maximum,
            } => {
                write!(
                    f,
                    "import does not fit {limit}: required {required} > maximum {maximum}"
                )
            }
            Self::InvalidChunkSize {
                chunk_bytes,
                maximum,
            } => {
                write!(
                    f,
                    "chunk size {chunk_bytes} must be in 1..={maximum} (spool object maximum)"
                )
            }
            Self::FormatConflict { hint, detected } => {
                write!(f, "format conflict: hint {hint:?} != detected {detected:?}")
            }
            Self::UnknownFormat { path } => {
                write!(f, "unknown file format: {}", path.display())
            }
            Self::UnsupportedFormat { format } => {
                write!(f, "unsupported format for splitting: {format:?}")
            }
            Self::CaptureHintAfterReceive {
                hint_start,
                receive_time,
            } => {
                write!(
                    f,
                    "capture hint start {hint_start:?} > receive time {receive_time:?}"
                )
            }
            Self::NegativeCaptureHintStart { start_ns } => {
                write!(f, "capture hint start {start_ns:?} is negative")
            }
            Self::ReceiveTimeBeforeEpoch { receive_time } => {
                write!(f, "receive time {receive_time:?} is before the epoch")
            }
            Self::InvalidCaptureHint { detail } => {
                write!(f, "invalid capture hint: {detail}")
            }
            Self::ImportPlanConflict { batch_id, detail } => {
                write!(
                    f,
                    "import plan conflict for {}: {}",
                    batch_id.as_str(),
                    detail
                )
            }
            Self::CorruptCapsuleCustody { digest, detail } => {
                write!(f, "corrupt capsule custody {digest}: {detail}")
            }
            Self::SegmentDigestMismatch {
                segment_index,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "segment {segment_index} digest mismatch: expected {expected} != actual {actual}"
                )
            }
            Self::SegmentIndexOutOfBounds { index, count } => {
                write!(f, "segment index {index} out of bounds (count {count})")
            }
            Self::CorruptSegment { detail } => {
                write!(f, "corrupt segment: {detail}")
            }
            Self::Encoding { detail } => write!(f, "canonical encoding failed: {detail}"),
            Self::CancellationRequested { stage } => {
                write!(f, "cancellation requested at stage {stage}")
            }
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Reference(e) => write!(f, "reference error: {e}"),
            Self::Contract(e) => write!(f, "contract error: {e}"),
            Self::AnnexB(e) => write!(f, "Annex-B error: {e:?}"),
            Self::Mjpeg(e) => write!(f, "MJPEG error: {e:?}"),
            Self::LocalPublication(e) => write!(f, "local publication error: {e}"),
            Self::Spool(e) => write!(f, "spool error: {e}"),
            Self::Object(e) => write!(f, "object error: {e}"),
        }
    }
}

impl std::error::Error for FileIngestError {}

impl From<std::io::Error> for FileIngestError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<ReferenceError> for FileIngestError {
    fn from(e: ReferenceError) -> Self {
        Self::Reference(e)
    }
}

impl From<ContractError> for FileIngestError {
    fn from(e: ContractError) -> Self {
        Self::Contract(e)
    }
}

impl From<AnnexBError> for FileIngestError {
    fn from(e: AnnexBError) -> Self {
        Self::AnnexB(e)
    }
}

impl From<JpegSplitError> for FileIngestError {
    fn from(e: JpegSplitError) -> Self {
        Self::Mjpeg(e)
    }
}

impl From<LocalPublicationError> for FileIngestError {
    fn from(e: LocalPublicationError) -> Self {
        Self::LocalPublication(e)
    }
}

impl From<SpoolError> for FileIngestError {
    fn from(e: SpoolError) -> Self {
        Self::Spool(e)
    }
}

impl From<ObjectError> for FileIngestError {
    fn from(e: ObjectError) -> Self {
        Self::Object(e)
    }
}

/// Sniffs the format from file bytes.
pub fn sniff_format(bytes: &[u8]) -> Result<(DetectedFileFormat, &'static str), FileIngestError> {
    if bytes.is_empty() {
        return Err(FileIngestError::EmptyFile {
            path: PathBuf::new(),
        });
    }

    // Check JPEG SOI: 0xFF, 0xD8
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xD8 {
        return Ok((DetectedFileFormat::JpegStream, "jpeg_soi"));
    }

    // Check rtpplay: starts with "#!rtpplay1.0"
    if bytes.starts_with(b"#!rtpplay1.0") {
        return Ok((DetectedFileFormat::RtpPlay, "rtpplay_magic"));
    }

    // Check Annex-B start code: 0x00, 0x00, 0x01 or 0x00, 0x00, 0x00, 0x01
    // Scan up to first 64 bytes for a start code preceded only by zeros
    let scan_window = bytes.len().min(64);
    let mut leading_zeros = 0;
    while leading_zeros < scan_window && bytes[leading_zeros] == 0x00 {
        leading_zeros += 1;
    }
    if leading_zeros >= 2 && leading_zeros < bytes.len() && bytes[leading_zeros] == 0x01 {
        return Ok((DetectedFileFormat::AnnexB, "annexb_start_code"));
    }

    Err(FileIngestError::UnknownFormat {
        path: PathBuf::new(),
    })
}

/// Computes the deterministic import identity for a file import.
#[must_use]
pub fn compute_import_identity(
    input_sha256: ContentDigest,
    detected_format: DetectedFileFormat,
    limits_digest: ContentDigest,
    adapter_generation: &str,
    sensor_id: &SensorId,
    stream_id: &StreamId,
) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.canonical.v1");
    encoder.text(FILE_IMPORT_IDENTITY_DOMAIN);
    encoder.digest(input_sha256);
    encoder.text(detected_format.as_str());
    encoder.digest(limits_digest);
    encoder.text(adapter_generation);
    sensor_id.encode_canonical(&mut encoder);
    stream_id.encode_canonical(&mut encoder);
    ContentDigest::sha256(&encoder.finish())
}

/// Returns the bytes stored in custody for `capsule`.
///
/// They are the canonical encoding under [`SENSOR_CAPSULE_CUSTODY_DOMAIN`], so their SHA-256
/// (the spool object digest) equals [`SensorCapsule::metadata_digest`].
#[must_use]
pub fn capsule_custody_bytes(capsule: &SensorCapsule) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.canonical.v1");
    encoder.text(SENSOR_CAPSULE_CUSTODY_DOMAIN);
    capsule.encode_canonical(&mut encoder);
    encoder.finish()
}

/// Decodes capsule custody bytes written by [`capsule_custody_bytes`].
///
/// # Errors
/// [`FileIngestError::CorruptCapsuleCustody`] when the domain prefix is wrong, the capsule does
/// not decode, trailing bytes remain, or the decoded capsule's metadata digest is not the
/// digest of the bytes.
pub fn decode_capsule_custody_bytes(bytes: &[u8]) -> Result<SensorCapsule, FileIngestError> {
    let digest = ContentDigest::sha256(bytes);
    let corrupt = |detail: String| FileIngestError::CorruptCapsuleCustody { digest, detail };
    let mut decoder = CanonicalDecoder::new(bytes);
    let canonical = decoder.text().map_err(|e| corrupt(e.to_string()))?;
    let domain = decoder.text().map_err(|e| corrupt(e.to_string()))?;
    if canonical != "fss.canonical.v1" || domain != SENSOR_CAPSULE_CUSTODY_DOMAIN {
        return Err(corrupt(format!(
            "unexpected domain prefix {canonical:?}/{domain:?}"
        )));
    }
    let capsule =
        SensorCapsule::decode_canonical(&mut decoder).map_err(|e| corrupt(e.to_string()))?;
    decoder
        .ensure_finished()
        .map_err(|e| corrupt(e.to_string()))?;
    if capsule.metadata_digest() != digest {
        return Err(corrupt(
            "metadata digest of the decoded capsule differs from the stored digest".to_string(),
        ));
    }
    Ok(capsule)
}

/// Builds the default [`AdapterIdentity`] for `ADP-FILE-001`.
pub fn default_adapter_identity() -> Result<AdapterIdentity, ContractError> {
    let adapter_id = AdapterId::parse("adp:file-001")?;
    let generation = AdapterGeneration::parse(ADP_FILE_GENERATION)?;
    let capabilities = AdapterCapabilities::STREAMING.union(AdapterCapabilities::SNAPSHOT);
    let identity = AdapterIdentity {
        adapter_id,
        generation,
        adapter_kind: AdapterKind::FileArchive,
        protocol_profile: "file_archive:bounded_import".to_string(),
        isolation_mode: IsolationMode::NativePureRust,
        credential_method: CredentialMethod::None,
        capabilities,
        max_bandwidth_bytes_per_sec: 100 * 1024 * 1024,
        max_buffer_frames: 1024,
        request_timeout_ns: 10_000_000_000,
    };
    identity.verify()?;
    Ok(identity)
}

/// Opens `path` for reading through `io` without following a symlink.
///
/// The path is inspected with `lstat` and refused when it is a symlink or not a regular file.
/// The file is then opened and the OPEN handle is stat-ed: it must be a regular file with the
/// same device and inode as the inspected path, so a path swapped for a symlink (or any other
/// file) between inspection and open is refused rather than followed. Returns the handle and
/// the handle's stat length.
fn open_source_nofollow(
    io: &ReplayIoAuthority,
    path: &Path,
) -> Result<(File, u64), FileIngestError> {
    if !io.is_valid() {
        return Err(FileIngestError::IoAuthorityRevoked);
    }
    let inspected = fs::symlink_metadata(path)?;
    if inspected.file_type().is_symlink() {
        return Err(FileIngestError::SymlinkNotAllowed {
            path: path.to_path_buf(),
        });
    }
    if !inspected.file_type().is_file() {
        return Err(FileIngestError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    let file = File::open(path)?;
    let opened = file.metadata()?;
    if !opened.file_type().is_file() {
        return Err(FileIngestError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    if opened.dev() != inspected.dev() || opened.ino() != inspected.ino() {
        return Err(FileIngestError::SourceChangedDuringOpen {
            path: path.to_path_buf(),
        });
    }
    Ok((file, opened.len()))
}

/// Reads at most `max_bytes + 1` bytes from `file`, so a result longer than `max_bytes` proves
/// the source is over the limit without reading it all.
fn read_at_most(file: File, max_bytes: u64, stat_len: u64) -> Result<Vec<u8>, std::io::Error> {
    let capacity = usize::try_from(stat_len.min(max_bytes)).unwrap_or(0);
    let mut buffer = Vec::with_capacity(capacity);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn require_within(limit: &'static str, required: u64, maximum: u64) -> Result<(), FileIngestError> {
    if required > maximum {
        return Err(FileIngestError::ImportCapacityExceeded {
            limit,
            required,
            maximum,
        });
    }
    Ok(())
}

fn delta_key(delta: &EvidenceDelta) -> (&str, &str, u64, &str) {
    (
        delta.family.as_str(),
        delta.object_id.as_str(),
        delta.new_generation,
        delta.delta_id.as_str(),
    )
}

/// Canonical form of a batch body, in the order `append_batch` commits it.
fn canonical_body(
    deltas: &[EvidenceDelta],
    children: &[ContentDigest],
) -> (Vec<EvidenceDelta>, Vec<ContentDigest>) {
    let mut deltas = deltas.to_vec();
    deltas.sort_by(|left, right| delta_key(left).cmp(&delta_key(right)));
    let mut children = children.to_vec();
    children.sort_unstable();
    children.dedup();
    (deltas, children)
}

/// Compares the content (not merely the presence) of a committed batch with a planned one.
fn batch_content_matches(
    existing: &EvidenceDeltaBatch,
    deltas: &[EvidenceDelta],
    children: &[ContentDigest],
) -> bool {
    let (planned_deltas, planned_children) = canonical_body(deltas, children);
    let (existing_deltas, existing_children) = canonical_body(&existing.deltas, &existing.children);
    planned_deltas == existing_deltas && planned_children == existing_children
}

/// Length of the journal record the batch would occupy if appended at `anchor`.
fn encoded_batch_len(
    anchor: &LedgerAnchor,
    batch_id: &BatchId,
    deltas: &[EvidenceDelta],
    children: &[ContentDigest],
) -> Result<u64, FileIngestError> {
    let (deltas, children) = canonical_body(deltas, children);
    let mut candidate = EvidenceDeltaBatch {
        batch_id: batch_id.clone(),
        basis_anchor: anchor.clone(),
        new_anchor: anchor.clone(),
        deltas,
        children,
        batch_digest: ContentDigest::sha256(b""),
    };
    candidate.batch_digest = candidate.computed_digest();
    let encoded = fss_ledger::encode_batch(&candidate).map_err(|e| FileIngestError::Encoding {
        detail: format!("{e:?}"),
    })?;
    Ok(encoded.len() as u64)
}

struct SegmentCandidate {
    offset: usize,
    end: usize,
    gap_before: bool,
}

struct ScannedSegments {
    segment_spans: Vec<SegmentSpan>,
    omission_spans: Vec<FileOmissionSpan>,
    capsules: Vec<SensorCapsule>,
}

/// Pure Rust file ingest adapter implementing `ADP-FILE-001`.
pub struct FileIngestAdapter;

impl FileIngestAdapter {
    /// Ingests a media file into [`ReferenceDeployment`].
    ///
    /// `clock` supplies the receive time of every capsule; `cx` supplies the I/O authority and
    /// cooperative cancellation.
    ///
    /// # Errors
    /// Every refusal is typed; see [`FileIngestError`]. No capacity refusal happens after the
    /// first object is staged.
    pub fn ingest(
        request: FileIngestRequest,
        clock: &VirtualClock,
        cx: &ReplayCx,
        deployment: &mut ReferenceDeployment,
    ) -> Result<FileIngestReceipt, FileIngestError> {
        // Step 1: cancellation, limits, and time truth checks before any I/O.
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(FileIngestError::CancellationRequested { stage: STAGE_STAT });
        }

        let max_object_bytes = deployment
            .limits()
            .spool_object_max_bytes
            .min(deployment.publisher().spool().limits().max_object_bytes as u64)
            .min(MAX_OBJECT_BYTES as u64);
        let chunk_bytes = request.limits.chunk_bytes;
        if chunk_bytes == 0 || chunk_bytes > max_object_bytes {
            return Err(FileIngestError::InvalidChunkSize {
                chunk_bytes,
                maximum: max_object_bytes,
            });
        }
        let chunk_size =
            usize::try_from(chunk_bytes).map_err(|_| FileIngestError::InvalidChunkSize {
                chunk_bytes,
                maximum: max_object_bytes,
            })?;

        let receive_time = clock.now();
        if receive_time < UNKNOWN_CAPTURE_EARLIEST {
            return Err(FileIngestError::ReceiveTimeBeforeEpoch { receive_time });
        }
        if let Some(hint) = &request.capture_hint {
            hint.validate_shape()?;
            if hint.start_ns > receive_time {
                return Err(FileIngestError::CaptureHintAfterReceive {
                    hint_start: hint.start_ns,
                    receive_time,
                });
            }
        }
        let capture_time_label = if request.capture_hint.is_some() {
            CAPTURE_TIME_OPERATOR_ASSUMPTION
        } else {
            CAPTURE_TIME_UNKNOWN
        };

        // Step 2: open through the I/O authority without following symlinks; stat the handle.
        let (source, stat_len) = open_source_nofollow(cx.io_authority(), &request.path)?;
        if stat_len > request.limits.max_file_bytes {
            return Err(FileIngestError::FileTooLarge {
                path: request.path.clone(),
                len: stat_len,
                max: request.limits.max_file_bytes,
            });
        }
        let spool_max_bytes = deployment.limits().spool_total_max_bytes;
        if stat_len > spool_max_bytes {
            return Err(FileIngestError::SpoolCapacityExceeded {
                limit: "spool_total_max_bytes",
                required: stat_len,
                available: spool_max_bytes,
            });
        }

        // Step 3: bounded single-buffer read; custody covers exactly the bytes read.
        cx.reach_stage(STAGE_READ);
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(FileIngestError::CancellationRequested { stage: STAGE_READ });
        }
        let file_bytes = read_at_most(source, request.limits.max_file_bytes, stat_len)?;
        let read_len = file_bytes.len() as u64;
        if read_len > request.limits.max_file_bytes {
            return Err(FileIngestError::FileTooLarge {
                path: request.path.clone(),
                len: read_len,
                max: request.limits.max_file_bytes,
            });
        }
        if file_bytes.is_empty() {
            return Err(FileIngestError::EmptyFile {
                path: request.path.clone(),
            });
        }
        let input_bytes = read_len;
        let input_sha256 = ContentDigest::sha256(&file_bytes);

        // Step 4: format sniffing.
        let (detected_format, detector_evidence) = match sniff_format(&file_bytes) {
            Ok(res) => res,
            Err(FileIngestError::UnknownFormat { .. }) => {
                return Err(FileIngestError::UnknownFormat {
                    path: request.path.clone(),
                });
            }
            Err(e) => return Err(e),
        };
        if let Some(hint) = request.format_hint
            && hint != detected_format.into_hint()
        {
            return Err(FileIngestError::FormatConflict {
                hint,
                detected: detected_format,
            });
        }
        if detected_format == DetectedFileFormat::RtpPlay {
            return Err(FileIngestError::UnsupportedFormat {
                format: DetectedFileFormat::RtpPlay,
            });
        }

        // Step 5: import identity.
        let limits_digest = request.limits.canonical_digest();
        let import_identity = compute_import_identity(
            input_sha256,
            detected_format,
            limits_digest,
            ADP_FILE_GENERATION,
            &request.sensor_id,
            &request.stream_id,
        );
        let import_identity_hex: String = import_identity
            .bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let import_slot = SlotName::parse(&format!("fi-{import_identity_hex}"))
            .map_err(|_| ContractError::InvalidIdentifier)?;
        let capsule_batch_id =
            BatchId::parse(format!("batch:file-import:{import_identity_hex}:c0"))?;
        let manifest_batch_id =
            BatchId::parse(format!("batch:file-import:{import_identity_hex}:manifest"))?;

        // Step 6: split into segments and capsules.
        cx.reach_stage(STAGE_SPLIT);
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(FileIngestError::CancellationRequested { stage: STAGE_SPLIT });
        }
        let mut scanned = Self::scan_media(
            &file_bytes,
            detected_format,
            &request,
            &import_identity_hex,
            receive_time,
            cx,
        )?;
        require_within(
            "max_segments",
            scanned.capsules.len() as u64,
            request.limits.max_segments as u64,
        )?;

        // Step 7: an earlier attempt for this identity fixes the capsules (and their receive
        // time); the plan adopts them after checking they are the capsules this plan derives.
        let existing_capsule_batch = deployment
            .ledger()
            .batches()
            .iter()
            .find(|b| b.batch_id == capsule_batch_id)
            .cloned();
        let existing_manifest_batch = deployment
            .ledger()
            .batches()
            .iter()
            .find(|b| b.batch_id == manifest_batch_id)
            .cloned();
        if let Some(existing) = &existing_capsule_batch {
            scanned.capsules = Self::adopt_existing_capsules(
                existing,
                &scanned.capsules,
                request.capture_hint.as_ref(),
                deployment,
            )?;
        } else if let Some(existing) = &existing_manifest_batch {
            return Err(FileIngestError::ImportPlanConflict {
                batch_id: existing.batch_id.clone(),
                detail: "manifest batch exists without its capsule batch".to_string(),
            });
        }
        let capsule_receive_time = scanned
            .capsules
            .first()
            .map_or(receive_time, |c| c.receive_time);

        // Step 8: chunking and object planning (no staging yet).
        let mut ordered_chunks = Vec::new();
        let mut chunk_slices = Vec::new();
        for chunk in file_bytes.chunks(chunk_size) {
            let digest = ContentDigest::sha256(chunk);
            ordered_chunks.push(digest);
            chunk_slices.push((digest, chunk));
        }
        let chunk_count = ordered_chunks.len();
        let dedup_chunk_digests: Vec<ContentDigest> = ordered_chunks
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let unique_chunk_count = dedup_chunk_digests.len();

        let mut capsule_encodings = Vec::with_capacity(scanned.capsules.len());
        for capsule in &scanned.capsules {
            let bytes = capsule_custody_bytes(capsule);
            let digest = ContentDigest::sha256(&bytes);
            if digest != capsule.metadata_digest() {
                return Err(FileIngestError::CorruptCapsuleCustody {
                    digest,
                    detail: "custody bytes do not hash to the capsule metadata digest".to_string(),
                });
            }
            capsule_encodings.push((digest, bytes));
        }

        // Step 9: typed count limits, checked before any manifest is built or object staged.
        let limits = *deployment.limits();
        let manifest_cap = MAX_MANIFEST_CHILDREN.min(limits.manifest_children_max) as u64;
        let batch_cap = limits.batch_entries_max as u64;
        let capsule_count = scanned.capsules.len() as u64;
        require_within(
            "custody_manifest_children",
            unique_chunk_count as u64,
            manifest_cap,
        )?;
        require_within("capsule_batch_deltas", capsule_count + 1, batch_cap)?;
        require_within("capsule_batch_children", capsule_count + 1, batch_cap)?;
        let mut slot_children: BTreeSet<ContentDigest> =
            dedup_chunk_digests.iter().copied().collect();
        slot_children.extend(capsule_encodings.iter().map(|(d, _)| *d));
        // + custody manifest + import manifest (metadata child).
        let slot_child_count = slot_children.len() as u64 + 2;
        require_within("import_manifest_children", slot_child_count, manifest_cap)?;
        require_within("root_reachability_children", slot_child_count, batch_cap)?;

        // Step 10: manifests and the planned batches.
        let custody_manifest = ObjectManifest::new("custody", dedup_chunk_digests.clone(), None)?;
        let custody_manifest_bytes = custody_manifest.canonical_bytes();
        let custody_manifest_digest = ContentDigest::sha256(&custody_manifest_bytes);
        slot_children.insert(custody_manifest_digest);

        let capsule_ids: Vec<CapsuleId> = scanned
            .capsules
            .iter()
            .map(|c| c.capsule_id.clone())
            .collect();
        let import_manifest = FileImportManifest {
            input_sha256,
            input_bytes,
            format: detected_format.as_str().to_string(),
            detector_evidence: detector_evidence.to_string(),
            chunk_bytes,
            ordered_chunks,
            segment_spans: scanned.segment_spans.clone(),
            omission_spans: scanned.omission_spans.clone(),
            capsule_ids,
            limits_digest,
            adapter_id: ADP_FILE_ROW_ID.to_string(),
            adapter_generation: ADP_FILE_GENERATION.to_string(),
            part_roots: Vec::new(),
            capture_time_label: capture_time_label.to_string(),
        };
        let manifest_bytes = import_manifest.canonical_bytes();
        let manifest_digest = import_manifest.canonical_digest();

        let import_slot_manifest =
            ObjectManifest::new(import_slot.as_str(), slot_children, Some(manifest_digest))?;
        let import_slot_manifest_bytes = import_slot_manifest.canonical_bytes();
        let import_root = import_slot_manifest.root();

        let overall_validity = match (
            scanned.capsules.iter().map(|c| c.capture.earliest).min(),
            scanned.capsules.iter().map(|c| c.capture.latest).max(),
        ) {
            (Some(earliest), Some(latest)) => CaptureInterval::new(earliest, latest)?,
            _ => CaptureInterval::new(UNKNOWN_CAPTURE_EARLIEST, capsule_receive_time)?,
        };

        let import_object_id =
            ObjectId::parse(format!("object:file-import:{import_identity_hex}"))?;
        let mut capsule_deltas = Vec::with_capacity(scanned.capsules.len() + 1);
        let mut capsule_batch_children = Vec::with_capacity(scanned.capsules.len() + 1);
        capsule_deltas.push(EvidenceDelta {
            delta_id: format!("delta:file-import:{import_identity_hex}:init"),
            family: FAMILY_FILE_IMPORT.to_string(),
            object_id: import_object_id.clone(),
            prior_generation: None,
            new_generation: 1,
            validity: overall_validity,
            plane: Plane::Authority,
            payload_digest: custody_manifest_digest,
            witness_digest: None,
            operation_id: None,
        });
        capsule_batch_children.push(custody_manifest_digest);
        for (capsule, (meta_digest, _)) in scanned.capsules.iter().zip(&capsule_encodings) {
            capsule_deltas.push(EvidenceDelta {
                delta_id: format!("delta:capsule:{}", capsule.capsule_id.as_str()),
                family: FAMILY_SENSOR_CAPSULE.to_string(),
                object_id: ObjectId::parse(format!(
                    "object:capsule:{}",
                    capsule.capsule_id.as_str()
                ))?,
                prior_generation: None,
                new_generation: 1,
                validity: capsule.capture,
                plane: Plane::Authority,
                payload_digest: *meta_digest,
                witness_digest: None,
                operation_id: None,
            });
            capsule_batch_children.push(*meta_digest);
        }

        let manifest_object_id =
            ObjectId::parse(format!("object:file-import-manifest:{import_identity_hex}"))?;
        let final_deltas = vec![
            EvidenceDelta {
                delta_id: format!("delta:file-import:{import_identity_hex}:complete"),
                family: FAMILY_FILE_IMPORT.to_string(),
                object_id: import_object_id,
                prior_generation: Some(1),
                new_generation: 2,
                validity: overall_validity,
                plane: Plane::Authority,
                payload_digest: manifest_digest,
                witness_digest: Some(import_root),
                operation_id: None,
            },
            EvidenceDelta {
                delta_id: format!("delta:manifest:{import_identity_hex}"),
                family: FAMILY_FILE_IMPORT_MANIFEST.to_string(),
                object_id: manifest_object_id,
                prior_generation: None,
                new_generation: 1,
                validity: overall_validity,
                plane: Plane::Authority,
                payload_digest: manifest_digest,
                witness_digest: Some(import_root),
                operation_id: None,
            },
        ];
        let final_children = vec![manifest_digest, import_root];

        // Step 11: compare the plan's content with any existing history for this identity.
        if let Some(existing) = &existing_capsule_batch
            && !batch_content_matches(existing, &capsule_deltas, &capsule_batch_children)
        {
            return Err(FileIngestError::ImportPlanConflict {
                batch_id: existing.batch_id.clone(),
                detail: "committed capsule batch differs from this import plan".to_string(),
            });
        }
        if let Some(existing) = &existing_manifest_batch
            && !batch_content_matches(existing, &final_deltas, &final_children)
        {
            return Err(FileIngestError::ImportPlanConflict {
                batch_id: existing.batch_id.clone(),
                detail: "committed manifest batch differs from this import plan (manifest, \
                         capture-time label, or import root)"
                    .to_string(),
            });
        }
        let visible_root = deployment
            .publisher()
            .root(&import_slot)
            .map(|visible| visible.root);
        if let Some(existing_root) = visible_root
            && existing_root != import_root
        {
            return Err(FileIngestError::ImportPlanConflict {
                batch_id: manifest_batch_id,
                detail: format!(
                    "slot {} holds root {existing_root}, plan derives {import_root}",
                    import_slot.as_str()
                ),
            });
        }

        if let (Some(existing_capsules), Some(existing_manifest), Some(existing_root)) = (
            &existing_capsule_batch,
            &existing_manifest_batch,
            visible_root,
        ) {
            return Ok(FileIngestReceipt {
                outcome: FileIngestOutcome::IdempotentExisting,
                import_identity,
                input_sha256,
                input_bytes,
                format: detected_format,
                capsule_count: scanned.capsules.len(),
                capsules: scanned.capsules,
                receive_time: capsule_receive_time,
                import_root: existing_root,
                manifest_digest,
                manifest: import_manifest,
                root_slot: import_slot,
                authority_anchor: deployment.current_anchor().clone(),
                batch_ids: vec![
                    existing_capsules.batch_id.clone(),
                    existing_manifest.batch_id.clone(),
                ],
                chunk_count,
                unique_chunk_count,
                chunk_bytes,
                capture_time_label,
                absence_certifiable: false,
            });
        }
        let resumed = existing_capsule_batch.is_some() || visible_root.is_some();

        // Step 12: byte-size limits and spool capacity, still before the first stage.
        cx.reach_stage(STAGE_CAPACITY);
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(FileIngestError::CancellationRequested {
                stage: STAGE_CAPACITY,
            });
        }
        let mut candidate_objects: Vec<(ContentDigest, &[u8])> = Vec::new();
        for (digest, slice) in &chunk_slices {
            candidate_objects.push((*digest, slice));
        }
        candidate_objects.push((custody_manifest_digest, &custody_manifest_bytes));
        for (digest, bytes) in &capsule_encodings {
            candidate_objects.push((*digest, bytes.as_slice()));
        }
        candidate_objects.push((manifest_digest, &manifest_bytes));
        candidate_objects.push((import_root, &import_slot_manifest_bytes));
        for (_, bytes) in &candidate_objects {
            require_within(
                "spool_object_max_bytes",
                bytes.len() as u64,
                max_object_bytes,
            )?;
        }
        let anchor = deployment.current_anchor().clone();
        let journal_max = u64::from(limits.journal_record_max_bytes);
        if existing_capsule_batch.is_none() {
            let capsule_record_len = encoded_batch_len(
                &anchor,
                &capsule_batch_id,
                &capsule_deltas,
                &capsule_batch_children,
            )?;
            require_within(
                "capsule_batch_journal_record_bytes",
                capsule_record_len,
                journal_max,
            )?;
        }
        let manifest_record_len =
            encoded_batch_len(&anchor, &manifest_batch_id, &final_deltas, &final_children)?;
        require_within(
            "manifest_batch_journal_record_bytes",
            manifest_record_len,
            journal_max,
        )?;

        let mut seen_digests = BTreeSet::new();
        let mut new_bytes: u64 = 0;
        let mut new_objects: usize = 0;
        for (digest, slice) in &candidate_objects {
            if seen_digests.insert(*digest)
                && deployment.publisher().spool().state(*digest).is_none()
            {
                new_bytes = new_bytes.saturating_add(slice.len() as u64);
                new_objects = new_objects.saturating_add(1);
            }
        }
        let occupied_bytes = deployment.publisher().spool().occupied_bytes()?;
        let current_obj_count = deployment.publisher().spool().object_count();
        let spool_limits = deployment.publisher().spool().limits();
        let available_bytes = spool_limits.max_total_bytes.saturating_sub(occupied_bytes);
        if new_bytes > available_bytes {
            return Err(FileIngestError::SpoolCapacityExceeded {
                limit: "max_total_bytes",
                required: new_bytes,
                available: available_bytes,
            });
        }
        if current_obj_count.saturating_add(new_objects) > spool_limits.max_objects {
            return Err(FileIngestError::SpoolCapacityExceeded {
                limit: "max_objects",
                required: current_obj_count.saturating_add(new_objects) as u64,
                available: spool_limits.max_objects as u64,
            });
        }

        // Step 13: stage and verify every object, then the import slot manifest.
        cx.reach_stage(STAGE_STAGE);
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(FileIngestError::CancellationRequested { stage: STAGE_STAGE });
        }
        for (_, slice) in &chunk_slices {
            deployment.publisher_mut().stage_object(slice)?;
        }
        deployment
            .publisher_mut()
            .stage_object(&custody_manifest_bytes)?;
        for (_, bytes) in &capsule_encodings {
            deployment.publisher_mut().stage_object(bytes)?;
        }
        deployment.publisher_mut().stage_object(&manifest_bytes)?;
        for (digest, _) in &candidate_objects {
            if *digest != import_root {
                deployment.publisher_mut().verify_object(*digest)?;
            }
        }
        if visible_root.is_none() {
            deployment
                .publisher_mut()
                .stage_manifest(&import_slot, &import_slot_manifest)?;
        }

        // Step 14: capsule batch (file_import generation 1 = in progress).
        cx.reach_stage(STAGE_COMMIT_CAPSULES);
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(FileIngestError::CancellationRequested {
                stage: STAGE_COMMIT_CAPSULES,
            });
        }
        deployment.append_batch(
            capsule_batch_id.clone(),
            capsule_deltas,
            capsule_batch_children,
            cx,
        )?;

        // Step 15: publish the import root last and ledger its reachability.
        cx.reach_stage(STAGE_PUBLISH_ROOT);
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(FileIngestError::CancellationRequested {
                stage: STAGE_PUBLISH_ROOT,
            });
        }
        deployment.publish_and_commit(&import_slot, &import_slot_manifest, overall_validity, cx)?;

        // Step 16: manifest batch (file_import generation 2 = complete).
        cx.reach_stage(STAGE_COMMIT_MANIFEST);
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(FileIngestError::CancellationRequested {
                stage: STAGE_COMMIT_MANIFEST,
            });
        }
        let final_anchor =
            deployment.append_batch(manifest_batch_id.clone(), final_deltas, final_children, cx)?;

        Ok(FileIngestReceipt {
            outcome: if resumed {
                FileIngestOutcome::Resumed
            } else {
                FileIngestOutcome::New
            },
            import_identity,
            input_sha256,
            input_bytes,
            format: detected_format,
            capsule_count: scanned.capsules.len(),
            capsules: scanned.capsules,
            receive_time: capsule_receive_time,
            import_root,
            manifest_digest,
            manifest: import_manifest,
            root_slot: import_slot,
            authority_anchor: final_anchor,
            batch_ids: vec![capsule_batch_id, manifest_batch_id],
            chunk_count,
            unique_chunk_count,
            chunk_bytes,
            capture_time_label,
            absence_certifiable: false,
        })
    }

    /// Loads the capsules an earlier attempt committed for this identity and checks that they
    /// are exactly the capsules this plan derives, apart from the receive time fixed by that
    /// attempt (and the unknown capture window that follows from it).
    fn adopt_existing_capsules(
        existing: &EvidenceDeltaBatch,
        planned: &[SensorCapsule],
        hint: Option<&CaptureHint>,
        deployment: &ReferenceDeployment,
    ) -> Result<Vec<SensorCapsule>, FileIngestError> {
        let conflict = |detail: String| FileIngestError::ImportPlanConflict {
            batch_id: existing.batch_id.clone(),
            detail,
        };
        let mut by_sequence = BTreeMap::new();
        for delta in existing
            .deltas
            .iter()
            .filter(|d| d.family == FAMILY_SENSOR_CAPSULE)
        {
            let bytes = deployment.publisher().spool().read(delta.payload_digest)?;
            let capsule = decode_capsule_custody_bytes(&bytes)?;
            if capsule.metadata_digest() != delta.payload_digest {
                return Err(conflict(format!(
                    "stored capsule does not match delta {}",
                    delta.delta_id
                )));
            }
            by_sequence.insert(capsule.sequence, capsule);
        }
        if by_sequence.len() != planned.len() {
            return Err(conflict(format!(
                "committed batch holds {} capsules, plan derives {}",
                by_sequence.len(),
                planned.len()
            )));
        }
        let mut adopted = Vec::with_capacity(planned.len());
        for (index, (plan, (_, have))) in planned.iter().zip(by_sequence).enumerate() {
            let expected_capture = Self::compute_capture_interval(index, hint, have.receive_time)
                .map_err(|e| conflict(format!("capsule {index}: {e}")))?;
            let same = have.capsule_id == plan.capsule_id
                && have.sensor_id == plan.sensor_id
                && have.stream_id == plan.stream_id
                && have.sequence == plan.sequence
                && have.clock_basis == plan.clock_basis
                && have.source_digest == plan.source_digest
                && have.source_bytes == plan.source_bytes
                && have.frame_count == plan.frame_count
                && have.gap_before == plan.gap_before
                && have.capture == expected_capture;
            if !same {
                return Err(conflict(format!(
                    "committed capsule {index} differs from this import plan"
                )));
            }
            adopted.push(have);
        }
        Ok(adopted)
    }

    /// Helper scanning media bytes using either Annex-B or MJPEG splitter.
    fn scan_media(
        file_bytes: &[u8],
        format: DetectedFileFormat,
        request: &FileIngestRequest,
        import_identity_hex: &str,
        receive_time: TimestampNs,
        cx: &ReplayCx,
    ) -> Result<ScannedSegments, FileIngestError> {
        let mut omission_spans = Vec::new();
        let mut candidates = Vec::new();

        match format {
            DetectedFileFormat::AnnexB => {
                let scan = split_annexb(file_bytes, request.limits.annexb_limits, cx)?;
                for o in &scan.omission_spans {
                    omission_spans.push(FileOmissionSpan {
                        offset: o.offset as u64,
                        len: o.len as u64,
                        reason: "annexb_omission".to_string(),
                    });
                }
                for p in &scan.padding_spans {
                    omission_spans.push(FileOmissionSpan {
                        offset: p.offset as u64,
                        len: p.len as u64,
                        reason: "annexb_padding".to_string(),
                    });
                }
                let mut last_segment_end: usize = 0;
                for au in &scan.access_units {
                    let gap_before =
                        au.span.offset > last_segment_end || au.undecodable_without_parameter_sets;
                    last_segment_end = au.span.end();
                    candidates.push(SegmentCandidate {
                        offset: au.span.offset,
                        end: au.span.end(),
                        gap_before,
                    });
                }
            }
            DetectedFileFormat::JpegStream => {
                let scan = split_jpeg_stream(file_bytes, &request.limits.mjpeg_limits, Some(cx))?;
                for o in &scan.omissions {
                    omission_spans.push(FileOmissionSpan {
                        offset: o.start_offset as u64,
                        len: o.len() as u64,
                        reason: format!("{:?}", o.reason),
                    });
                }
                let mut last_segment_end: usize = 0;
                let mut prev_was_truncated = false;
                for frame in &scan.frames {
                    // A truncated frame (no EOI) is omitted, and the next capsule has a gap.
                    if frame.is_truncated {
                        prev_was_truncated = true;
                        continue;
                    }
                    let gap_before = frame.start_offset > last_segment_end || prev_was_truncated;
                    last_segment_end = frame.end_offset;
                    prev_was_truncated = false;
                    candidates.push(SegmentCandidate {
                        offset: frame.start_offset,
                        end: frame.end_offset,
                        gap_before,
                    });
                }
            }
            DetectedFileFormat::RtpPlay => {
                return Err(FileIngestError::UnsupportedFormat {
                    format: DetectedFileFormat::RtpPlay,
                });
            }
        }

        let mut segment_spans = Vec::with_capacity(candidates.len());
        let mut capsules = Vec::with_capacity(candidates.len());
        for (index, candidate) in candidates.iter().enumerate() {
            let source = file_bytes
                .get(candidate.offset..candidate.end)
                .ok_or_else(|| FileIngestError::CorruptSegment {
                    detail: format!("segment {index} span out of bounds"),
                })?;
            let capsule_id = CapsuleId::parse(format!("capsule:{import_identity_hex}:{index:06}"))?;
            let capsule = Self::build_capsule(
                index,
                capsule_id.clone(),
                request,
                request.capture_hint.as_ref(),
                receive_time,
                source,
                candidate.gap_before,
            )?;
            segment_spans.push(SegmentSpan {
                segment_index: index,
                offset: candidate.offset as u64,
                len: source.len() as u64,
                segment_sha256: capsule.source_digest,
                capsule_id,
                gap_before: candidate.gap_before,
            });
            capsules.push(capsule);
        }

        Ok(ScannedSegments {
            segment_spans,
            omission_spans,
            capsules,
        })
    }

    fn build_capsule(
        index: usize,
        capsule_id: CapsuleId,
        request: &FileIngestRequest,
        hint: Option<&CaptureHint>,
        receive_time: TimestampNs,
        source: &[u8],
        gap_before: bool,
    ) -> Result<SensorCapsule, FileIngestError> {
        let capture = Self::compute_capture_interval(index, hint, receive_time)?;
        let spec = SensorSourceBytesSpec {
            capsule_id,
            sensor_id: request.sensor_id.clone(),
            stream_id: request.stream_id.clone(),
            sequence: index as u64,
            capture,
            receive_time,
            clock_basis: ClockBasis::Estimated,
            source,
            frame_count: 1,
            gap_before,
        };
        Ok(SensorCapsule::from_source_bytes(spec)?)
    }

    /// Computes the capture interval under the time-truth discipline.
    fn compute_capture_interval(
        index: usize,
        hint: Option<&CaptureHint>,
        receive_time: TimestampNs,
    ) -> Result<CaptureInterval, FileIngestError> {
        match hint {
            Some(h) => {
                h.validate_shape()?;
                let frame_ns = ((index as f64) * 1_000_000_000.0 / h.assumed_fps).round() as i128;
                let center = h.start_ns.0.saturating_add(frame_ns);
                let uncertainty = i128::from(h.uncertainty_ns);
                let earliest = TimestampNs(center.saturating_sub(uncertainty));
                let latest = TimestampNs(center.saturating_add(uncertainty));
                if earliest > receive_time {
                    return Err(FileIngestError::CaptureHintAfterReceive {
                        hint_start: h.start_ns,
                        receive_time,
                    });
                }
                Ok(CaptureInterval::new(earliest, latest)?)
            }
            None => {
                if receive_time < UNKNOWN_CAPTURE_EARLIEST {
                    return Err(FileIngestError::ReceiveTimeBeforeEpoch { receive_time });
                }
                Ok(CaptureInterval::new(
                    receive_time,
                    receive_time,
                )?)
            }
        }
    }

    /// Reassembles and verifies the raw source segment bytes from the chunked custody objects.
    ///
    /// # Errors
    /// Typed refusals for an out-of-range index, a zero chunk size, a zero-length or
    /// overflowing segment span, a missing chunk, and a digest mismatch.
    pub fn fetch_segment_bytes(
        manifest: &FileImportManifest,
        deployment: &ReferenceDeployment,
        segment_index: usize,
    ) -> Result<Vec<u8>, FileIngestError> {
        let segment = manifest.segment_spans.get(segment_index).ok_or(
            FileIngestError::SegmentIndexOutOfBounds {
                index: segment_index,
                count: manifest.segment_spans.len(),
            },
        )?;
        if manifest.chunk_bytes == 0 {
            return Err(FileIngestError::InvalidChunkSize {
                chunk_bytes: 0,
                maximum: MAX_OBJECT_BYTES as u64,
            });
        }
        if segment.len == 0 {
            return Err(FileIngestError::CorruptSegment {
                detail: format!("segment {segment_index} has zero length"),
            });
        }
        let span_error = || FileIngestError::CorruptSegment {
            detail: format!("segment {segment_index} span does not fit the address space"),
        };
        let end_offset_u64 = segment
            .offset
            .checked_add(segment.len)
            .ok_or_else(span_error)?;
        let chunk_size = usize::try_from(manifest.chunk_bytes).map_err(|_| span_error())?;
        let start_offset = usize::try_from(segment.offset).map_err(|_| span_error())?;
        let end_offset = usize::try_from(end_offset_u64).map_err(|_| span_error())?;
        let segment_len = end_offset - start_offset;

        let first_chunk = start_offset / chunk_size;
        let last_chunk = (end_offset - 1) / chunk_size;
        let mut assembled = Vec::with_capacity(segment_len);
        for chunk_idx in first_chunk..=last_chunk {
            let chunk_digest = *manifest.ordered_chunks.get(chunk_idx).ok_or_else(|| {
                FileIngestError::CorruptSegment {
                    detail: format!("chunk index {chunk_idx} out of bounds"),
                }
            })?;
            let chunk_data = deployment.publisher().spool().read(chunk_digest)?;
            let chunk_start = chunk_idx.checked_mul(chunk_size).ok_or_else(span_error)?;
            let chunk_end = chunk_start.saturating_add(chunk_data.len());
            let slice_start = start_offset.max(chunk_start) - chunk_start;
            let slice_end = end_offset.min(chunk_end).saturating_sub(chunk_start);
            if slice_start < slice_end {
                let piece = chunk_data
                    .get(slice_start..slice_end)
                    .ok_or_else(span_error)?;
                assembled.extend_from_slice(piece);
            }
        }

        if assembled.len() != segment_len {
            return Err(FileIngestError::CorruptSegment {
                detail: "assembled segment length mismatch".to_string(),
            });
        }
        let computed_digest = ContentDigest::sha256(&assembled);
        if computed_digest != segment.segment_sha256 {
            return Err(FileIngestError::SegmentDigestMismatch {
                segment_index,
                expected: segment.segment_sha256,
                actual: computed_digest,
            });
        }
        Ok(assembled)
    }
}

/// Reassembles and verifies the raw source segment bytes from the chunked custody objects in
/// the deployment spool.
///
/// # Errors
/// See [`FileIngestAdapter::fetch_segment_bytes`].
pub fn fetch_segment_bytes(
    manifest: &FileImportManifest,
    deployment: &ReferenceDeployment,
    segment_index: usize,
) -> Result<Vec<u8>, FileIngestError> {
    FileIngestAdapter::fetch_segment_bytes(manifest, deployment, segment_index)
}

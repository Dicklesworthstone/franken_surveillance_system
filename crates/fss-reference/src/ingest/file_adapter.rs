//! File ingest adapter (`ADP-FILE-001`) transforming recorded files into [`SensorCapsule`]s.
//!
//! # Architecture & Determinism
//!
//! Conforms to `ADP-FILE-001` ("bounded media import") under `GATE-010`.
//! Reads media files boundedly through explicit [`ReplayIoAuthority`], computes SHA-256 custody
//! digests, sniffs container/stream formats, splits access units or frames using first-party pure Rust
//! splitters, constructs immutable [`SensorCapsule`]s, and stages/commits them root-last into
//! [`ReferenceDeployment`].
//!
//! # Time Truth Discipline
//!
//! Files carry no live or trusted hardware clock.
//! - Without an operator [`CaptureHint`], capture time is represented as the full unknown window
//!   `[TimestampNs(0), receive_time]` with [`ClockBasis::Estimated`] and labeled `"unknown"`.
//! - With an operator [`CaptureHint`], intervals preserve declared uncertainty `u` around nominal
//!   `start + i / fps` timestamps with [`ClockBasis::Estimated`] and labeled `"operator_assumption"`.
//! - Ingest arrival time comes strictly from [`VirtualClock`] or explicit [`ReplayCx`] time, never
//!   the host system wall clock.
//! - File import never emits [`ContinuityWitness`] or [`CoverageWitness`] certifying absence;
//!   an absence query over an imported window is not certifiable.

use std::fs;
use std::path::PathBuf;

use fss_core::identity::{
    AdapterCapabilities, AdapterIdentity, AdapterKind, CredentialMethod, IsolationMode,
};
use fss_core::{
    AdapterGeneration, AdapterId, BatchId, CanonicalEncode, CanonicalEncoder, CapsuleId,
    CaptureInterval, ClockBasis, ContentDigest, ContractError, EvidenceDelta, LedgerAnchor,
    ObjectId, Plane, SensorCapsule, SensorId, SensorSourceBytesSpec, StreamId, TimestampNs,
};
use fss_object::{ObjectError, ObjectManifest, SpoolError};
use fss_publication::{LocalPublicationError, SlotName};

use crate::adapter_replay::ReplayCx;
use crate::error::ReferenceError;
use crate::ingest::annexb::{AnnexBError, AnnexBLimits, split_annexb};
use crate::ingest::mjpeg::{JpegSplitError, MjpegLimits, split_jpeg_stream};
use crate::reference_deployment::ReferenceDeployment;

/// Canonical schema domain for [`FileImportManifest`].
pub const FILE_IMPORT_MANIFEST_SCHEMA: &str = "fss.file_import.manifest.v1";

/// Registered adapter identity for `ADP-FILE-001`.
pub const ADP_FILE_ROW_ID: &str = "ADP-FILE-001";

/// Standard adapter generation for `ADP-FILE-001`.
pub const ADP_FILE_GENERATION: &str = "gen:fss1:adapters-v1";

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
    /// Nominal capture start timestamp.
    pub start_ns: TimestampNs,
    /// Symmetric timestamp uncertainty in nanoseconds (`+/- uncertainty_ns`).
    pub uncertainty_ns: u64,
    /// Nominal assumed frame rate in frames per second (e.g. 30.0).
    pub assumed_fps: f64,
}

impl CaptureHint {
    /// Constructs and validates a new capture hint.
    pub fn new(
        start_ns: TimestampNs,
        uncertainty_ns: u64,
        assumed_fps: f64,
    ) -> Result<Self, FileIngestError> {
        if assumed_fps <= 0.0 || !assumed_fps.is_finite() {
            return Err(FileIngestError::InvalidCaptureHint {
                detail: "assumed_fps must be finite and strictly positive".to_string(),
            });
        }
        Ok(Self {
            start_ns,
            uncertainty_ns,
            assumed_fps,
        })
    }
}

/// Operational bounds and limits for file ingestion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileIngestLimits {
    /// Maximum file size in bytes admitted for reading.
    pub max_file_bytes: u64,
    /// Chunk size for chunked custody objects (at most spool object max bytes).
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
    #[must_use]
    pub fn standard() -> Self {
        Self {
            max_file_bytes: 512 * 1024 * 1024, // 512 MiB
            chunk_bytes: DEFAULT_CHUNK_BYTES,
            max_segments: MAX_BATCH_DELTAS,
            annexb_limits: AnnexBLimits::default(),
            mjpeg_limits: MjpegLimits::default(),
        }
    }

    /// Computes the domain-separated canonical digest of these limits.
    #[must_use]
    pub fn canonical_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.canonical.v1");
        encoder.text("fss.file_ingest.limits.v1");
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
    /// Ingest arrival timestamp (defaults to deterministic 1s if unspecified).
    pub receive_time: Option<TimestampNs>,
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
            receive_time: None,
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

    /// Sets an explicit receive timestamp.
    #[must_use]
    pub fn with_receive_time(mut self, receive_time: TimestampNs) -> Self {
        self.receive_time = Some(receive_time);
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
    /// SHA-256 custody digest of the entire input file.
    pub input_sha256: ContentDigest,
    /// Total byte length of the input file.
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
    /// Roots of partitioned child manifest parts (if partitioned, else empty).
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
    /// SHA-256 custody digest of the input file.
    pub input_sha256: ContentDigest,
    /// Total bytes ingested.
    pub input_bytes: u64,
    /// Detected format.
    pub format: DetectedFileFormat,
    /// Number of sensor capsules produced.
    pub capsule_count: usize,
    /// Constructed sensor capsules.
    pub capsules: Vec<SensorCapsule>,
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
    /// Batch identifiers committed or verified by this import.
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
    /// Input file is zero bytes.
    EmptyFile {
        /// The path of the empty file.
        path: PathBuf,
    },
    /// Input file exceeds maximum configured size.
    FileTooLarge {
        /// The path of the oversized file.
        path: PathBuf,
        /// Actual file length in bytes.
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
    /// Invalid parameters in capture hint.
    InvalidCaptureHint {
        /// Detail describing why the capture hint was invalid.
        detail: String,
    },
    /// Resumed import encountered a batch ID conflict against existing ledger history.
    ImportPlanConflict {
        /// Batch ID in conflict.
        batch_id: BatchId,
        /// Conflict detail message.
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
                    "spool capacity exceeded for {}: required {} > available {}",
                    limit, required, available
                )
            }
            Self::FormatConflict { hint, detected } => {
                write!(
                    f,
                    "format conflict: hint {:?} != detected {:?}",
                    hint, detected
                )
            }
            Self::UnknownFormat { path } => {
                write!(f, "unknown file format: {}", path.display())
            }
            Self::UnsupportedFormat { format } => {
                write!(f, "unsupported format for splitting: {:?}", format)
            }
            Self::CaptureHintAfterReceive {
                hint_start,
                receive_time,
            } => {
                write!(
                    f,
                    "capture hint start {:?} > receive time {:?}",
                    hint_start, receive_time
                )
            }
            Self::InvalidCaptureHint { detail } => {
                write!(f, "invalid capture hint: {}", detail)
            }
            Self::ImportPlanConflict { batch_id, detail } => {
                write!(
                    f,
                    "import plan conflict for {}: {}",
                    batch_id.as_str(),
                    detail
                )
            }
            Self::SegmentDigestMismatch {
                segment_index,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "segment {} digest mismatch: expected {} != actual {}",
                    segment_index, expected, actual
                )
            }
            Self::SegmentIndexOutOfBounds { index, count } => {
                write!(f, "segment index {} out of bounds (count {})", index, count)
            }
            Self::CorruptSegment { detail } => {
                write!(f, "corrupt segment: {}", detail)
            }
            Self::CancellationRequested { stage } => {
                write!(f, "cancellation requested at stage {}", stage)
            }
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Reference(e) => write!(f, "reference error: {}", e),
            Self::Contract(e) => write!(f, "contract error: {}", e),
            Self::AnnexB(e) => write!(f, "Annex-B error: {:?}", e),
            Self::Mjpeg(e) => write!(f, "MJPEG error: {:?}", e),
            Self::LocalPublication(e) => write!(f, "local publication error: {}", e),
            Self::Spool(e) => write!(f, "spool error: {}", e),
            Self::Object(e) => write!(f, "object error: {}", e),
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

    // Direct check for 3-byte or 4-byte start code at offset 0
    if bytes.starts_with(&[0x00, 0x00, 0x01]) || bytes.starts_with(&[0x00, 0x00, 0x00, 0x01]) {
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
    encoder.text("fss.file_import.identity.v1");
    encoder.digest(input_sha256);
    encoder.text(detected_format.as_str());
    encoder.digest(limits_digest);
    encoder.text(adapter_generation);
    sensor_id.encode_canonical(&mut encoder);
    stream_id.encode_canonical(&mut encoder);
    ContentDigest::sha256(&encoder.finish())
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

struct ScannedSegments {
    segment_spans: Vec<SegmentSpan>,
    omission_spans: Vec<FileOmissionSpan>,
    capsules: Vec<SensorCapsule>,
}

/// Pure Rust file ingest adapter implementing `ADP-FILE-001`.
pub struct FileIngestAdapter;

impl FileIngestAdapter {
    /// Ingests a media file into [`ReferenceDeployment`].
    pub fn ingest(
        request: FileIngestRequest,
        cx: &ReplayCx,
        deployment: &mut ReferenceDeployment,
    ) -> Result<FileIngestReceipt, FileIngestError> {
        // Step 1: Check cancellation & stat file
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(FileIngestError::CancellationRequested { stage: STAGE_STAT });
        }

        let metadata = match fs::symlink_metadata(&request.path) {
            Ok(m) => m,
            Err(e) => return Err(FileIngestError::Io(e)),
        };

        if metadata.file_type().is_symlink() {
            return Err(FileIngestError::SymlinkNotAllowed {
                path: request.path.clone(),
            });
        }
        if !metadata.file_type().is_file() {
            return Err(FileIngestError::NotRegularFile {
                path: request.path.clone(),
            });
        }

        let file_len = metadata.len();
        if file_len == 0 {
            return Err(FileIngestError::EmptyFile {
                path: request.path.clone(),
            });
        }
        if file_len > request.limits.max_file_bytes {
            return Err(FileIngestError::FileTooLarge {
                path: request.path.clone(),
                len: file_len,
                max: request.limits.max_file_bytes,
            });
        }
        let spool_max_bytes = deployment.limits().spool_total_max_bytes;
        if file_len > spool_max_bytes {
            return Err(FileIngestError::SpoolCapacityExceeded {
                limit: "spool_total_max_bytes",
                required: file_len,
                available: spool_max_bytes,
            });
        }

        // Step 2: Bounded single-buffer read computing SHA-256 custody digest
        cx.reach_stage(STAGE_READ);
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(FileIngestError::CancellationRequested { stage: STAGE_READ });
        }
        let file_bytes = fs::read(&request.path)?;
        let input_sha256 = ContentDigest::sha256(&file_bytes);

        // Step 3: Format sniffing
        let (detected_format, detector_evidence) = match sniff_format(&file_bytes) {
            Ok(res) => res,
            Err(FileIngestError::UnknownFormat { .. }) => {
                return Err(FileIngestError::UnknownFormat {
                    path: request.path.clone(),
                });
            }
            Err(e) => return Err(e),
        };

        if detected_format == DetectedFileFormat::RtpPlay {
            return Err(FileIngestError::UnsupportedFormat {
                format: DetectedFileFormat::RtpPlay,
            });
        }

        if let Some(hint) = request.format_hint {
            if hint != detected_format.into_hint() {
                return Err(FileIngestError::FormatConflict {
                    hint,
                    detected: detected_format,
                });
            }
        }

        // Step 4: Import identity calculation
        let limits_digest = request.limits.canonical_digest();
        let adapter_id = ADP_FILE_ROW_ID;
        let adapter_generation = ADP_FILE_GENERATION;
        let import_identity = compute_import_identity(
            input_sha256,
            detected_format,
            limits_digest,
            adapter_generation,
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
        let manifest_batch_id =
            BatchId::parse(format!("batch:file-import:{import_identity_hex}:manifest"))?;

        // Step 5: Time truth configuration
        let receive_time = request.receive_time.unwrap_or(TimestampNs(1_000_000_000));
        let capture_time_label = if request.capture_hint.is_some() {
            "operator_assumption"
        } else {
            "unknown"
        };

        if let Some(hint) = &request.capture_hint {
            if hint.start_ns > receive_time {
                return Err(FileIngestError::CaptureHintAfterReceive {
                    hint_start: hint.start_ns,
                    receive_time,
                });
            }
            if hint.assumed_fps <= 0.0 || !hint.assumed_fps.is_finite() {
                return Err(FileIngestError::InvalidCaptureHint {
                    detail: "assumed_fps must be finite and strictly positive".to_string(),
                });
            }
        }

        // Step 6: Stream splitting into segments & SensorCapsules
        cx.reach_stage(STAGE_SPLIT);
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(FileIngestError::CancellationRequested { stage: STAGE_SPLIT });
        }

        let scanned = Self::scan_media(
            &file_bytes,
            detected_format,
            &request,
            &import_identity_hex,
            receive_time,
            cx,
        )?;

        if scanned.capsules.len() > request.limits.max_segments {
            return Err(FileIngestError::SpoolCapacityExceeded {
                limit: "max_segments",
                required: scanned.capsules.len() as u64,
                available: request.limits.max_segments as u64,
            });
        }

        // Step 7: Chunking
        let chunk_size = request.limits.chunk_bytes as usize;
        let mut ordered_chunks = Vec::new();
        let mut chunk_slices = Vec::new();
        for chunk in file_bytes.chunks(chunk_size) {
            let digest = ContentDigest::sha256(chunk);
            ordered_chunks.push(digest);
            chunk_slices.push((digest, chunk));
        }
        let chunk_count = ordered_chunks.len();

        let mut dedup_chunk_digests = ordered_chunks.clone();
        dedup_chunk_digests.sort();
        dedup_chunk_digests.dedup();
        let unique_chunk_count = dedup_chunk_digests.len();

        let custody_manifest = ObjectManifest::new("custody", dedup_chunk_digests.clone(), None)?;
        let custody_manifest_bytes = custody_manifest.canonical_bytes();
        let custody_manifest_digest = ContentDigest::sha256(&custody_manifest_bytes);

        // Step 8: Build FileImportManifest
        let capsule_ids: Vec<CapsuleId> = scanned
            .capsules
            .iter()
            .map(|c| c.capsule_id.clone())
            .collect();
        let import_manifest = FileImportManifest {
            input_sha256,
            input_bytes: file_len,
            format: detected_format.as_str().to_string(),
            detector_evidence: detector_evidence.to_string(),
            chunk_bytes: request.limits.chunk_bytes,
            ordered_chunks: ordered_chunks.clone(),
            segment_spans: scanned.segment_spans.clone(),
            omission_spans: scanned.omission_spans.clone(),
            capsule_ids: capsule_ids.clone(),
            limits_digest,
            adapter_id: adapter_id.to_string(),
            adapter_generation: adapter_generation.to_string(),
            part_roots: Vec::new(),
            capture_time_label: capture_time_label.to_string(),
        };
        let manifest_bytes = import_manifest.canonical_bytes();
        let manifest_digest = import_manifest.canonical_digest();

        // Step 9: Check for idempotent complete import
        let existing_slot = deployment.publisher().root(&import_slot).is_some();
        let existing_manifest_batch = deployment
            .ledger()
            .batches()
            .iter()
            .any(|b| b.batch_id == manifest_batch_id);

        if existing_slot && existing_manifest_batch {
            let visible_root = deployment.publisher().root(&import_slot).ok_or_else(|| {
                FileIngestError::CorruptSegment {
                    detail: "import root missing from publisher".to_string(),
                }
            })?;
            let anchor = deployment.current_anchor().clone();
            let batch_ids = vec![
                BatchId::parse(format!("batch:file-import:{import_identity_hex}:c0"))?,
                manifest_batch_id,
            ];
            return Ok(FileIngestReceipt {
                outcome: FileIngestOutcome::IdempotentExisting,
                import_identity,
                input_sha256,
                input_bytes: file_len,
                format: detected_format,
                capsule_count: scanned.capsules.len(),
                capsules: scanned.capsules,
                import_root: visible_root.root,
                manifest_digest,
                manifest: import_manifest.clone(),
                root_slot: import_slot.clone(),
                authority_anchor: anchor,
                batch_ids,
                chunk_count,
                unique_chunk_count,
                chunk_bytes: request.limits.chunk_bytes,
                capture_time_label,
                absence_certifiable: false,
            });
        }

        // Step 10: Exact capacity check after hashing and BEFORE the first stage
        cx.reach_stage(STAGE_CAPACITY);
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(FileIngestError::CancellationRequested {
                stage: STAGE_CAPACITY,
            });
        }

        // Collect all candidate payloads
        let mut candidate_objects: Vec<(ContentDigest, &[u8])> = Vec::new();
        for (digest, slice) in &chunk_slices {
            candidate_objects.push((*digest, slice));
        }
        candidate_objects.push((custody_manifest_digest, &custody_manifest_bytes));
        let capsule_encodings: Vec<Vec<u8>> = scanned
            .capsules
            .iter()
            .map(|c| c.canonical_bytes())
            .collect();
        for (c, enc) in scanned.capsules.iter().zip(&capsule_encodings) {
            candidate_objects.push((c.metadata_digest(), enc.as_slice()));
        }
        candidate_objects.push((manifest_digest, &manifest_bytes));

        // Deduplicate candidate objects by digest
        let mut seen_digests = std::collections::BTreeSet::new();
        let mut new_bytes: u64 = 0;
        let mut new_objects: usize = 0;

        for (digest, slice) in &candidate_objects {
            if seen_digests.insert(*digest) {
                if deployment.publisher().spool().state(*digest).is_none() {
                    new_bytes = new_bytes.saturating_add(slice.len() as u64);
                    new_objects = new_objects.saturating_add(1);
                }
            }
        }

        let occupied_bytes = deployment.publisher().spool().occupied_bytes()?;
        let current_obj_count = deployment.publisher().spool().object_count();
        let spool_limits = deployment.publisher().spool().limits();

        if new_bytes > spool_limits.max_total_bytes.saturating_sub(occupied_bytes) {
            return Err(FileIngestError::SpoolCapacityExceeded {
                limit: "max_total_bytes",
                required: new_bytes,
                available: spool_limits.max_total_bytes.saturating_sub(occupied_bytes),
            });
        }
        if (current_obj_count + new_objects) > spool_limits.max_objects {
            return Err(FileIngestError::SpoolCapacityExceeded {
                limit: "max_objects",
                required: (current_obj_count + new_objects) as u64,
                available: spool_limits.max_objects as u64,
            });
        }

        // Step 11: Staging objects
        cx.reach_stage(STAGE_STAGE);
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(FileIngestError::CancellationRequested { stage: STAGE_STAGE });
        }

        // Stage chunks
        for (_, slice) in &chunk_slices {
            deployment.publisher_mut().stage_object(slice)?;
        }
        // Stage custody manifest
        deployment
            .publisher_mut()
            .stage_object(&custody_manifest_bytes)?;
        // Stage capsules
        for enc in &capsule_encodings {
            deployment.publisher_mut().stage_object(enc.as_slice())?;
        }
        // Stage FileImportManifest
        deployment.publisher_mut().stage_object(&manifest_bytes)?;

        // Verify staged objects
        for (digest, _) in &candidate_objects {
            deployment.publisher_mut().verify_object(*digest)?;
        }

        // Step 12: Construct Import Slot Manifest (holds all children for reachability)
        let mut all_slot_children = Vec::new();
        for (d, _) in &candidate_objects {
            if *d != manifest_digest {
                all_slot_children.push(*d);
            }
        }
        all_slot_children.sort();
        all_slot_children.dedup();

        let import_slot_manifest = ObjectManifest::new(
            import_slot.as_str(),
            all_slot_children,
            Some(manifest_digest),
        )?;

        // Stage the manifest itself into publisher
        let import_root = deployment
            .publisher_mut()
            .stage_manifest(&import_slot, &import_slot_manifest)?;

        // Step 13: Partition & commit capsule batches
        cx.reach_stage(STAGE_COMMIT_CAPSULES);
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(FileIngestError::CancellationRequested {
                stage: STAGE_COMMIT_CAPSULES,
            });
        }

        let overall_validity = if let (Some(first), Some(last)) =
            (scanned.capsules.first(), scanned.capsules.last())
        {
            CaptureInterval::new(first.capture.earliest, last.capture.latest)?
        } else {
            CaptureInterval::new(TimestampNs(0), receive_time)?
        };

        let import_object_id =
            ObjectId::parse(format!("object:file-import:{import_identity_hex}"))?;
        let mut committed_batches = Vec::new();

        // Build capsule deltas
        let mut capsule_deltas = Vec::with_capacity(scanned.capsules.len() + 1);
        let mut capsule_batch_children = Vec::with_capacity(scanned.capsules.len() + 1);

        // Delta 0: file_import gen 1 (in_progress)
        capsule_deltas.push(EvidenceDelta {
            delta_id: format!("delta:file-import:{import_identity_hex}:init"),
            family: "file_import".to_string(),
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

        // Capsule deltas
        for capsule in &scanned.capsules {
            let meta_digest = capsule.metadata_digest();
            capsule_deltas.push(EvidenceDelta {
                delta_id: format!("delta:capsule:{}", capsule.capsule_id.as_str()),
                family: "sensor_capsule".to_string(),
                object_id: ObjectId::parse(format!(
                    "object:capsule:{}",
                    capsule.capsule_id.as_str()
                ))?,
                prior_generation: None,
                new_generation: 1,
                validity: capsule.capture,
                plane: Plane::Authority,
                payload_digest: meta_digest,
                witness_digest: None,
                operation_id: None,
            });
            capsule_batch_children.push(meta_digest);
        }

        let capsule_batch_id =
            BatchId::parse(format!("batch:file-import:{import_identity_hex}:c0"))?;
        let _c_anchor = deployment.append_batch(
            capsule_batch_id.clone(),
            capsule_deltas,
            capsule_batch_children,
            cx,
        )?;
        committed_batches.push(capsule_batch_id);

        // Step 14: Publish root to slot fi-<id>
        cx.reach_stage(STAGE_PUBLISH_ROOT);
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(FileIngestError::CancellationRequested {
                stage: STAGE_PUBLISH_ROOT,
            });
        }

        let _publish_receipt = deployment.publish_and_commit(
            &import_slot,
            &import_slot_manifest,
            overall_validity,
            cx,
        )?;

        // Step 15: Commit final manifest batch (moves import to gen 2 = complete)
        cx.reach_stage(STAGE_COMMIT_MANIFEST);
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(FileIngestError::CancellationRequested {
                stage: STAGE_COMMIT_MANIFEST,
            });
        }

        let final_manifest_object_id =
            ObjectId::parse(format!("object:file-import-manifest:{import_identity_hex}"))?;
        let final_deltas = vec![
            EvidenceDelta {
                delta_id: format!("delta:file-import:{import_identity_hex}:complete"),
                family: "file_import".to_string(),
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
                family: "file_import_manifest".to_string(),
                object_id: final_manifest_object_id,
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

        let final_anchor =
            deployment.append_batch(manifest_batch_id.clone(), final_deltas, final_children, cx)?;
        committed_batches.push(manifest_batch_id);

        let outcome = if existing_slot {
            FileIngestOutcome::Resumed
        } else {
            FileIngestOutcome::New
        };

        Ok(FileIngestReceipt {
            outcome,
            import_identity,
            input_sha256,
            input_bytes: file_len,
            format: detected_format,
            capsule_count: scanned.capsules.len(),
            capsules: scanned.capsules,
            import_root,
            manifest_digest,
            manifest: import_manifest,
            root_slot: import_slot,
            authority_anchor: final_anchor,
            batch_ids: committed_batches,
            chunk_count,
            unique_chunk_count,
            chunk_bytes: request.limits.chunk_bytes,
            capture_time_label,
            absence_certifiable: false,
        })
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
        let mut segment_spans = Vec::new();
        let mut omission_spans = Vec::new();
        let mut capsules = Vec::new();

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
                for (idx, au) in scan.access_units.iter().enumerate() {
                    let au_slice =
                        file_bytes
                            .get(au.span.offset..au.span.end())
                            .ok_or_else(|| FileIngestError::CorruptSegment {
                                detail: "AU span out of bounds".to_string(),
                            })?;
                    let au_sha256 = ContentDigest::sha256(au_slice);
                    let capsule_id =
                        CapsuleId::parse(format!("capsule:{}:{:06}", import_identity_hex, idx))?;

                    let has_gap_before = (au.span.offset > last_segment_end)
                        || au.undecodable_without_parameter_sets;
                    last_segment_end = au.span.end();

                    let capture = Self::compute_capture_interval(
                        idx,
                        request.capture_hint.as_ref(),
                        receive_time,
                    )?;

                    let spec = SensorSourceBytesSpec {
                        capsule_id: capsule_id.clone(),
                        sensor_id: request.sensor_id.clone(),
                        stream_id: request.stream_id.clone(),
                        sequence: idx as u64,
                        capture,
                        receive_time,
                        clock_basis: if request.capture_hint.is_none() { ClockBasis::UtcDisciplined } else { ClockBasis::Estimated },
                        source: au_slice,
                        frame_count: 1,
                        gap_before: has_gap_before,
                    };
                    let capsule = SensorCapsule::from_source_bytes(spec)?;

                    segment_spans.push(SegmentSpan {
                        segment_index: idx,
                        offset: au.span.offset as u64,
                        len: au.span.len as u64,
                        segment_sha256: au_sha256,
                        capsule_id,
                        gap_before: has_gap_before,
                    });
                    capsules.push(capsule);
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
                    // Truncated frames without EOI are omitted from valid decoded capsules
                    if frame.is_truncated {
                        prev_was_truncated = true;
                        continue;
                    }
                    let frame_slice =
                        frame
                            .slice(file_bytes)
                            .ok_or_else(|| FileIngestError::CorruptSegment {
                                detail: "Frame span out of bounds".to_string(),
                            })?;
                    let frame_sha256 = ContentDigest::sha256(frame_slice);
                    let capsule_id = CapsuleId::parse(format!(
                        "capsule:{}:{:06}",
                        import_identity_hex,
                        capsules.len()
                    ))?;

                    let has_gap_before =
                        (frame.start_offset > last_segment_end) || prev_was_truncated;
                    last_segment_end = frame.end_offset;
                    prev_was_truncated = false;

                    let capture = Self::compute_capture_interval(
                        capsules.len(),
                        request.capture_hint.as_ref(),
                        receive_time,
                    )?;

                    let spec = SensorSourceBytesSpec {
                        capsule_id: capsule_id.clone(),
                        sensor_id: request.sensor_id.clone(),
                        stream_id: request.stream_id.clone(),
                        sequence: capsules.len() as u64,
                        capture,
                        receive_time,
                        clock_basis: if request.capture_hint.is_none() { ClockBasis::UtcDisciplined } else { ClockBasis::Estimated },
                        source: frame_slice,
                        frame_count: 1,
                        gap_before: has_gap_before,
                    };
                    let capsule = SensorCapsule::from_source_bytes(spec)?;

                    segment_spans.push(SegmentSpan {
                        segment_index: capsules.len(),
                        offset: frame.start_offset as u64,
                        len: frame.len() as u64,
                        segment_sha256: frame_sha256,
                        capsule_id,
                        gap_before: has_gap_before,
                    });
                    capsules.push(capsule);
                }
            }
            DetectedFileFormat::RtpPlay => {
                return Err(FileIngestError::UnsupportedFormat {
                    format: DetectedFileFormat::RtpPlay,
                });
            }
        }

        Ok(ScannedSegments {
            segment_spans,
            omission_spans,
            capsules,
        })
    }

    /// Computes capture interval under truth discipline.
    fn compute_capture_interval(
        index: usize,
        hint: Option<&CaptureHint>,
        receive_time: TimestampNs,
    ) -> Result<CaptureInterval, FileIngestError> {
        match hint {
            Some(h) => {
                let frame_ns = ((index as f64) * 1_000_000_000.0 / h.assumed_fps).round() as i128;
                let center = h.start_ns.0.saturating_add(frame_ns);
                let earliest = TimestampNs(center.saturating_sub(h.uncertainty_ns as i128));
                let latest = TimestampNs(center.saturating_add(h.uncertainty_ns as i128));
                if earliest > receive_time {
                    return Err(FileIngestError::CaptureHintAfterReceive {
                        hint_start: h.start_ns,
                        receive_time,
                    });
                }
                Ok(CaptureInterval::new(earliest, latest)?)
            }
            None => {
                let earliest = TimestampNs(0);
                if earliest > receive_time {
                    Ok(CaptureInterval::new(receive_time, receive_time)?)
                } else {
                    Ok(CaptureInterval::new(earliest, receive_time)?)
                }
            }
        }
    }

    /// Reassembles and verifies the raw source segment bytes from the chunked custody objects in the spool.
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

        let chunk_size = manifest.chunk_bytes as usize;
        let start_offset = segment.offset as usize;
        let end_offset = start_offset + segment.len as usize;

        let first_chunk = start_offset / chunk_size;
        let last_chunk = (end_offset - 1) / chunk_size;

        let mut assembled = Vec::with_capacity(segment.len as usize);

        for chunk_idx in first_chunk..=last_chunk {
            let chunk_digest = *manifest.ordered_chunks.get(chunk_idx).ok_or_else(|| {
                FileIngestError::CorruptSegment {
                    detail: "chunk index out of bounds".to_string(),
                }
            })?;
            let chunk_data = deployment.publisher().spool().read(chunk_digest)?;

            let chunk_start_file_offset = chunk_idx * chunk_size;
            let chunk_end_file_offset = chunk_start_file_offset + chunk_data.len();

            let slice_start = start_offset.max(chunk_start_file_offset) - chunk_start_file_offset;
            let slice_end = end_offset.min(chunk_end_file_offset) - chunk_start_file_offset;

            if slice_start < slice_end && slice_end <= chunk_data.len() {
                assembled.extend_from_slice(&chunk_data[slice_start..slice_end]);
            }
        }

        if assembled.len() != segment.len as usize {
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

/// Reassembles and verifies the raw source segment bytes from the chunked custody objects in the deployment spool.
pub fn fetch_segment_bytes(
    manifest: &FileImportManifest,
    deployment: &ReferenceDeployment,
    segment_index: usize,
) -> Result<Vec<u8>, FileIngestError> {
    FileIngestAdapter::fetch_segment_bytes(manifest, deployment, segment_index)
}

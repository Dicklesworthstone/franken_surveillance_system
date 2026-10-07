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
//! - `receive_time` is a hard upper bound on capture: a capture interval can never end after its
//!   bytes were received. A hint whose start lies after `receive_time`
//!   ([`FileIngestError::CaptureHintAfterReceive`]) or whose interval for any frame would end
//!   after it, `start + i / fps + u > receive_time`
//!   ([`FileIngestError::CaptureHintLatestAfterReceive`]), is an operator-assumption error and is
//!   refused before anything is staged or any batch is appended. It is never clamped: clamping
//!   would silently rewrite an operator-supplied fact (owner decision, fss-roeq0). An interval
//!   ending exactly at `receive_time` is admitted. Both refusals carry
//!   `ERR-INGEST-CAPTURE-HINT-AFTER-RECEIVE-001`.
//! - Ingest arrival time comes strictly from [`VirtualClock`] or explicit [`ReplayCx`] time, never
//!   the host system wall clock.
//! - File import never emits [`ContinuityWitness`] or [`CoverageWitness`] certifying absence;
//!   an absence query over an imported window is not certifiable.
//!
//! # Recorded RTP
//!
//! [`FileIngestAdapter::ingest_file`] is the generic routing entry: a sniffed `#!rtpplay1.0`
//! recording is delegated to the recorded-RTP import (`rtpdump::import`), whose source capsules
//! are per recorded access unit, and returns [`FileImport::RecordedRtp`]. Packets are never
//! interpreted without the owner's binding ([`FileIngestRequest::rtp_binding`]: generation,
//! SSRC, payload type, packetization mode), which is never guessed from the capture; its absence
//! is [`FileIngestError::RtpBindingRequired`]. The receive time is required as for every format.
//! [`FileIngestAdapter::ingest`] keeps its media-only receipt type and refuses RTP as
//! [`FileIngestError::UnsupportedFormat`].
//!
//! # Acquisition lifecycle
//!
//! Each import drives one core `AcquisitionSession` ([`super::file_session`]); a completed import
//! retains its transition history in its completing ledger batch, and
//! [`FileIngestReceipt::absence_certifiable`] is the core absence gate over that session.
//!
//! # Commit order, partition and resume (fss-2h5zq.23 round 3)
//!
//! Every object is staged and verified first (capacity, including the import slot's manifest
//! body, is checked before the first stage). Then the capsule batches
//! `batch:file-import:<id>:c0..c<K-1>` are appended in order (the first creates the import
//! object at generation 1); the partition holds at most
//! `min(FileIngestLimits::max_batch_deltas, batch_entries_max)` deltas per batch and splits a
//! batch further when its journal record would exceed `journal_record_max_bytes`. Then slot
//! `fi-<id>` is published root-last and ledgered, and finally `batch:file-import:<id>:manifest`
//! moves the import object to generation 2. Only that last batch makes an import complete.
//! When the payload closure exceeds one root, independently ledgered `fi-<id>-p<ordinal>`
//! parts are published between the capsule batches and the metadata-only aggregate. Their
//! exact roots are typed references in `FileImportManifest::part_roots`, not native children
//! whose recursive expansion would recreate the oversized batch. Admission includes every
//! part and the completion batch before staging; unchanged flat imports keep their bytes.
//!
//! A fault before `c0` leaves no committed batch. A fault after `c<j>` leaves an incomplete
//! import (generation 1, no manifest batch) that doctor lists and that re-running the same
//! import completes as `resumed`: committed batches are skipped by identity, a slot root already
//! durable from the interrupted attempt is reused, and an orphaned temporary root record of
//! exactly this plan is discarded before publication is redone. Cancellation is polled before
//! every batch. The fault campaign is `tests/file_ingest_fault_contract.rs`.
//!
//! # Source path authority (fss-n62w2)
//!
//! The source is an operator-named recording, and it may live anywhere the operator points: it
//! is deliberately NOT confined to the I/O authority's `root_dir`, which scopes the adapter's
//! own scratch and ledger directories, not the media it imports. Confining it would refuse the
//! intended use (importing a recording from a removable drive or an export directory). The read
//! is instead gated by the explicit I/O authority: [`open_admitted_source`] refuses a revoked or
//! finalized [`ReplayIoAuthority`] before it opens anything, and a path is only ever opened
//! after `symlink_metadata` admitted it as a regular, non-symlink file.
//!
//! That check-then-open sequence is not trusted by itself. On Linux x86_64/aarch64 the open uses
//! `O_NOFOLLOW | O_NONBLOCK` (a symlink swapped in after the check is refused by the kernel, and
//! a FIFO swapped in cannot block the open), and on every Unix the opened handle is `fstat`ed and
//! must still be a regular file with the admitted `(dev, ino)` identity. Every byte read and the
//! post-read size check use that handle, never the path again.

mod retry;

use std::fs;
use std::path::{Path, PathBuf};

use fss_core::identity::{
    AdapterCapabilities, AdapterIdentity, AdapterKind, CredentialMethod, IsolationMode,
};
use fss_core::{
    AcquisitionError, AdapterGeneration, AdapterId, BatchId, CanonicalEncode, CanonicalEncoder,
    CapsuleId, CaptureInterval, ClockBasis, ContentDigest, ContractError, EvidenceDelta,
    EvidenceDeltaBatch, LedgerAnchor, ObjectId, Plane, SensorCapsule, SensorId,
    SensorSourceBytesSpec, StreamId, TimestampNs,
};
use fss_ledger::DurableLedgerError;
use fss_object::{ObjectError, ObjectManifest, SpoolError};
use fss_publication::{LocalPublicationError, LocalPublicationState, SlotName};

use crate::adapter_replay::ReplayCx;
use crate::error::ReferenceError;
use crate::ingest::annexb::{AnnexBError, AnnexBLimits, SourceSpan, split_annexb};
use crate::ingest::file_publication::FilePublicationPlan;
use crate::ingest::file_session::{
    AcquisitionRetention, FileAcquisitionHistory, FileSessionDriver, FileSourceFacts,
};
use crate::ingest::hevc_annexb::split_hevc_annexb;
use crate::ingest::mjpeg::{JpegSplitError, MjpegLimits, split_jpeg_stream};
use crate::ingest::rtpdump::import::{RtpFileImportReceipt, RtpImportError, import_rtp_snapshot};
use crate::ingest::rtpdump::replay::RtpReplayConfig;
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
    /// H.265/HEVC Annex-B byte elementary stream (same framing, two-byte NAL headers).
    Hevc,
    /// Single JPEG image or concatenated MJPEG frame stream starting with SOI (`0xFFD8`).
    JpegStream,
    /// Recorded RTP session (`#!rtpplay1.0` header).
    RtpPlay,
    /// Indexed (non-fragmented) ISO-BMFF/MP4 file with one `avc1` H.264 video track.
    Mp4Avc,
}

impl DetectedFileFormat {
    /// Canonical string identifier for this detected format.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AnnexB => "annexb",
            Self::Hevc => "hevc",
            Self::JpegStream => "mjpeg",
            Self::RtpPlay => "rtpplay",
            Self::Mp4Avc => "mp4avc",
        }
    }

    /// Converts this detected format to a [`FileFormatHint`].
    #[must_use]
    pub const fn into_hint(self) -> FileFormatHint {
        match self {
            Self::AnnexB => FileFormatHint::AnnexB,
            Self::Hevc => FileFormatHint::Hevc,
            Self::JpegStream => FileFormatHint::JpegStream,
            Self::RtpPlay => FileFormatHint::RtpPlay,
            Self::Mp4Avc => FileFormatHint::Mp4Avc,
        }
    }
}

/// User-provided format hint for format verification.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FileFormatHint {
    /// Expected format is H.264 Annex-B.
    AnnexB,
    /// Expected format is H.265/HEVC Annex-B. Required when the stream's first NAL unit header
    /// is a valid header of both codecs.
    Hevc,
    /// Expected format is JPEG or MJPEG.
    JpegStream,
    /// Expected format is rtpplay packet capture.
    RtpPlay,
    /// Expected format is an indexed MP4 file with one H.264 (`avc1`) video track.
    Mp4Avc,
}

impl FileFormatHint {
    /// Canonical string representation of the hint.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AnnexB => "annexb",
            Self::Hevc => "hevc",
            Self::JpegStream => "mjpeg",
            Self::RtpPlay => "rtpplay",
            Self::Mp4Avc => "mp4avc",
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
    /// Chunk size for chunked custody objects. Must be at most the deployment's spool object
    /// bound (`spool_object_max_bytes`, and the spool's own `max_object_bytes`); a larger value
    /// is refused as [`FileIngestError::InvalidLimits`] before the file is opened, whatever the
    /// file's length.
    pub chunk_bytes: u64,
    /// Maximum number of segments (access units or frames) allowed.
    pub max_segments: usize,
    /// Annex-B elementary stream scanner limits.
    pub annexb_limits: AnnexBLimits,
    /// MJPEG / JPEG stream scanner limits.
    pub mjpeg_limits: MjpegLimits,
    /// Maximum deltas (and children) per capsule batch (fss-2h5zq.23 round 3 partition knob).
    ///
    /// The effective bound is the smaller of this knob and the deployment's
    /// `batch_entries_max`; a batch is split further when its journal record would exceed
    /// `journal_record_max_bytes`. Part of the import identity through the limits digest, so a
    /// resumed import reproduces the same partition.
    pub max_batch_deltas: usize,
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
            max_batch_deltas: MAX_BATCH_DELTAS,
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
        // The batch knob is encoded only when it differs from the default, so every import made
        // before the knob existed keeps its identity. Injective: a default knob encodes nothing,
        // any other value appends one trailing field that the default encoding never has.
        if self.max_batch_deltas != MAX_BATCH_DELTAS {
            encoder.text("max_batch_deltas");
            encoder.u64(self.max_batch_deltas as u64);
        }
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
    /// Ingest arrival timestamp. Required: an import without it is refused
    /// ([`FileIngestError::MissingReceiveTime`]); none is invented.
    pub receive_time: Option<TimestampNs>,
    /// Owner binding for a recorded-RTP (`#!rtpplay1.0`) source: stream generation, SSRC,
    /// payload type, packetization mode and replay bounds. Required to route such a file through
    /// [`FileIngestAdapter::ingest_file`]; never derived from the capture. Ignored for other
    /// formats.
    pub rtp_binding: Option<RtpReplayConfig>,
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
            rtp_binding: None,
        }
    }

    /// Sets the owner binding for a recorded-RTP source.
    #[must_use]
    pub fn with_rtp_binding(mut self, binding: RtpReplayConfig) -> Self {
        self.rtp_binding = Some(binding);
        self
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

/// Omission reason prefix of MP4 container structure: box headers and metadata, other tracks'
/// bytes inside `mdat`, and the `avcC` parameter sets.
pub const MP4_STRUCTURE_REASON_PREFIX: &str = "mp4_";
/// Omission reason prefix of one `avcC` parameter-set NAL payload, completed by
/// `nal_length_bytes=N` (the sample NAL length-field size the decoder needs).
pub const MP4_PARAMETER_SET_REASON_PREFIX: &str = "mp4_avc_parameter_set:nal_length_bytes=";

impl FileOmissionSpan {
    /// True for MP4 container structure, which is accounted byte for byte but is not lost or
    /// unparsed media: no source gap, omission or time-reliability downgrade follows from it.
    #[must_use]
    pub fn is_container_structure(&self) -> bool {
        self.reason.starts_with(MP4_STRUCTURE_REASON_PREFIX)
    }
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
    /// The core absence gate over this import's acquisition session: always `false`, because a
    /// file session never reaches `ContinuityVerified` (and file import emits no coverage witness).
    pub absence_certifiable: bool,
    /// The acquisition lifecycle retained in the completing batch (fss-2h5zq.25).
    pub acquisition: AcquisitionRetention,
}

/// A failed import and the acquisition history the attempt reached.
#[derive(Debug)]
pub struct FileIngestFailure {
    /// The import error.
    pub error: FileIngestError,
    /// The concluded (never retained) acquisition history; `None` when the request was refused
    /// at admission, before an acquisition session was requested (stat, read, format, identity,
    /// deletion and receive-time refusals).
    pub acquisition: Option<FileAcquisitionHistory>,
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
    /// The file opened at the path is not the file admitted by the earlier `symlink_metadata`
    /// check (a different `(dev, ino)` identity): the path was replaced between the check and
    /// the open, and nothing is read from it.
    SourceChanged {
        /// The path whose file changed.
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
    /// An Annex-B stream whose first NAL unit header is a valid header of both H.264 and H.265
    /// was imported without an explicit codec; the adapter never guesses between them.
    AmbiguousAnnexBCodec {
        /// The first two bytes after the first start code.
        first_nal_header: [u8; 2],
    },
    /// A recorded-RTP (`#!rtpplay1.0`) file was routed without the owner's stream binding
    /// ([`FileIngestRequest::rtp_binding`]); packets are never interpreted under a guessed SSRC,
    /// payload type or packetization mode.
    RtpBindingRequired {},
    /// The recorded-RTP import refused or failed; partial publication is not reclassified.
    RecordedRtp(Box<RtpImportError>),
    /// The MP4 demuxer refused the file (fragmented, encrypted, external media, non-`avc1`,
    /// several video tracks, malformed tables or NAL framing, or a bound). Nothing is retained.
    Mp4Refused {
        /// The demuxer's typed, non-disclosing refusal.
        refusal: fss_container::demux::DemuxError,
    },
    /// Detected format is not supported by this entrypoint (recorded RTP through
    /// [`FileIngestAdapter::ingest`], whose receipt type is media-only; use
    /// [`FileIngestAdapter::ingest_file`]).
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
    /// The capture hint would make a frame's capture interval end after ingest arrival time
    /// (`start + i / fps + uncertainty > receive_time`); refused, never clamped (fss-roeq0).
    CaptureHintLatestAfterReceive {
        /// Declared capture hint start time.
        hint_start: TimestampNs,
        /// Index of the first segment whose interval would end after `receive_time`.
        segment_index: usize,
        /// Latest capture time the hint implies for that segment.
        capture_latest: TimestampNs,
        /// Ingest arrival time.
        receive_time: TimestampNs,
    },
    /// Invalid parameters in capture hint.
    InvalidCaptureHint {
        /// Detail describing why the capture hint was invalid.
        detail: String,
    },
    /// No explicit receive time was supplied; fabricated precision is refused.
    MissingReceiveTime {},
    /// Request limits are invalid (e.g. zero chunk size).
    InvalidLimits {
        /// Detail describing the invalid limit.
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
    /// A custody chunk behind the segment cannot be read back intact: the spool refused it
    /// (for example `SpoolError::Corrupt` after the stored bytes were altered). The segment's
    /// evidence is unavailable, never silently substituted.
    CustodyUnavailable {
        /// Index of the requested segment.
        segment_index: usize,
        /// Index of the chunk in the manifest's ordered chunk list.
        chunk_index: usize,
        /// Content digest the chunk is expected to have.
        chunk: ContentDigest,
        /// Spool refusal for the chunk read.
        source: Box<SpoolError>,
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
    /// A committed deletion record names this import: its evidence is `deleted`
    /// (`ERR-EVIDENCE-DELETED-001`), and a deleted import identity is never re-imported.
    EvidenceDeleted {
        /// Deleted import identity.
        import_identity: ContentDigest,
        /// Sealed deletion plan that deleted it.
        plan_digest: ContentDigest,
    },
    /// Cooperative cancellation was signaled at the named stage.
    CancellationRequested {
        /// Pipeline stage where cancellation was requested.
        stage: &'static str,
    },
    /// The core acquisition lifecycle refused a transition or witness.
    Acquisition(Box<AcquisitionError>),
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
            Self::SourceChanged { path } => {
                write!(
                    f,
                    "source file changed between admission and open: {}",
                    path.display()
                )
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
            Self::AmbiguousAnnexBCodec { first_nal_header } => {
                write!(
                    f,
                    "Annex-B stream is ambiguous between H.264 and H.265 (first NAL header {:02x}{:02x}); declare the media format explicitly: annexb (H.264) or hevc (H.265)",
                    first_nal_header[0], first_nal_header[1]
                )
            }
            Self::RtpBindingRequired {} => write!(
                f,
                "recorded RTP requires the owner's stream binding (generation, SSRC, payload \
                 type, packetization mode); none is guessed from the capture"
            ),
            Self::RecordedRtp(e) => write!(f, "{e}"),
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
            Self::CaptureHintLatestAfterReceive {
                hint_start,
                segment_index,
                capture_latest,
                receive_time,
            } => {
                write!(
                    f,
                    "capture hint start {:?} puts segment {} capture latest {:?} after receive time {:?}",
                    hint_start, segment_index, capture_latest, receive_time
                )
            }
            Self::InvalidCaptureHint { detail } => {
                write!(f, "invalid capture hint: {}", detail)
            }
            Self::MissingReceiveTime {} => {
                write!(
                    f,
                    "no explicit receive_time supplied; refusing to fabricate precision"
                )
            }
            Self::InvalidLimits { detail } => {
                write!(f, "invalid ingest limits: {}", detail)
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
            Self::CustodyUnavailable {
                segment_index,
                chunk_index,
                chunk,
                source,
            } => {
                write!(
                    f,
                    "segment {segment_index} custody unavailable: chunk {chunk_index} ({chunk}) \
                     refused by the spool: {source}"
                )
            }
            Self::SegmentIndexOutOfBounds { index, count } => {
                write!(f, "segment index {} out of bounds (count {})", index, count)
            }
            Self::CorruptSegment { detail } => {
                write!(f, "corrupt segment: {}", detail)
            }
            Self::EvidenceDeleted {
                import_identity,
                plan_digest,
            } => write!(
                f,
                "import {import_identity} was deleted under deletion plan {plan_digest}; its \
                 evidence is deleted and the identity is never reused"
            ),
            Self::CancellationRequested { stage } => {
                write!(f, "cancellation requested at stage {}", stage)
            }
            Self::Acquisition(e) => write!(f, "acquisition lifecycle refusal: {}", e),
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Reference(e) => write!(f, "reference error: {}", e),
            Self::Contract(e) => write!(f, "contract error: {}", e),
            Self::AnnexB(e) => write!(f, "Annex-B error: {:?}", e),
            Self::Mp4Refused { refusal } => write!(f, "MP4 demux refused the file: {refusal:?}"),
            Self::Mjpeg(e) => write!(f, "MJPEG error: {:?}", e),
            Self::LocalPublication(e) => write!(f, "local publication error: {}", e),
            Self::Spool(e) => write!(f, "spool error: {}", e),
            Self::Object(e) => write!(f, "object error: {}", e),
        }
    }
}

impl std::error::Error for FileIngestError {}

impl FileIngestError {
    /// Registered stable identity (registries/ERRORS.md) of media-format and capture-hint
    /// time-truth refusals; other import failures carry no registered identity yet.
    #[must_use]
    pub fn stable_id(&self) -> Option<&'static str> {
        match self {
            Self::AmbiguousAnnexBCodec { .. } => Some("ERR-INGEST-FORMAT-AMBIGUOUS-001"),
            Self::FormatConflict { .. } => Some("ERR-INGEST-FORMAT-CONFLICT-001"),
            Self::Mp4Refused { .. } => Some("ERR-INGEST-MP4-REFUSED-001"),
            Self::EvidenceDeleted { .. } => Some("ERR-EVIDENCE-DELETED-001"),
            Self::CaptureHintAfterReceive { .. } | Self::CaptureHintLatestAfterReceive { .. } => {
                Some("ERR-INGEST-CAPTURE-HINT-AFTER-RECEIVE-001")
            }
            _ => None,
        }
    }
}

impl From<std::io::Error> for FileIngestError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<AcquisitionError> for FileIngestError {
    fn from(e: AcquisitionError) -> Self {
        Self::Acquisition(Box::new(e))
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
///
/// An Annex-B stream is H.264 (`annexb`) unless its first NAL unit header is only plausible as
/// H.265 (`hevc`); see [`sniff_format_with_hint`] for the exact rule. A header plausible as both
/// is [`FileIngestError::AmbiguousAnnexBCodec`]: the codec must then be declared explicitly.
pub fn sniff_format(bytes: &[u8]) -> Result<(DetectedFileFormat, &'static str), FileIngestError> {
    sniff_format_with_hint(bytes, None)
}

/// Top-level ISO-BMFF boxes as `(start, end, type)`. Parsing stops at the first malformed
/// header; any bytes after it form one `????` pseudo-box, so the result always tiles the input.
fn top_level_boxes(bytes: &[u8]) -> Vec<(usize, usize, [u8; 4])> {
    let mut boxes = Vec::new();
    let mut at = 0_usize;
    while at < bytes.len() {
        let field = |offset: usize, len: usize| {
            bytes
                .get(at + offset..at + offset + len)
                .map(|b| b.iter().fold(0_u64, |n, byte| (n << 8) | u64::from(*byte)))
        };
        let kind: Option<[u8; 4]> = bytes
            .get(at + 4..at + 8)
            .and_then(|b| <[u8; 4]>::try_from(b).ok());
        let end = match (field(0, 4), kind) {
            (Some(0), Some(_)) => Some(bytes.len()),
            (Some(1), Some(_)) => field(8, 8)
                .filter(|size| *size >= 16)
                .and_then(|size| usize::try_from(size).ok())
                .and_then(|size| at.checked_add(size)),
            (Some(size), Some(_)) if size >= 8 => usize::try_from(size)
                .ok()
                .and_then(|size| at.checked_add(size)),
            _ => None,
        };
        match (end.filter(|end| *end <= bytes.len()), kind) {
            (Some(end), Some(kind)) => {
                boxes.push((at, end, kind));
                at = end;
            }
            _ => {
                boxes.push((at, bytes.len(), *b"????"));
                break;
            }
        }
    }
    boxes
}

/// Printable box type, or its hexadecimal bytes when not printable ASCII.
fn box_kind_text(kind: [u8; 4]) -> String {
    if kind.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
        kind.iter().map(|b| char::from(*b)).collect()
    } else {
        kind.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Codec plausibility of an Annex-B stream's first NAL unit header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AnnexBCodecEvidence {
    H264,
    Hevc,
    Both,
    Neither,
}

/// Classifies the first NAL unit header. H.264: `forbidden_zero_bit` 0 and a type that opens
/// real streams, with the `nal_ref_idc` the standard requires (non-IDR slice: any; IDR slice,
/// SPS, PPS: non-zero; SEI, access unit delimiter: zero). H.265: `forbidden_zero_bit` 0,
/// `nuh_layer_id` 0, `nuh_temporal_id_plus1` non-zero and a VPS, SPS, PPS, access unit
/// delimiter, prefix SEI or IRAP slice type. Every usual H.264 first byte (`0x09`, `0x06`,
/// `0x67`, `0x27`, `0x47`, `0x68`, `0x65`, `0x25`, `0x41`, `0x21`, `0x01`) fails the H.265
/// test, so existing H.264 imports are unaffected; an IDR_N_LP-first H.265 stream (`0x28 0x01`,
/// also an H.264 PPS header) is `Both`.
fn annexb_codec_evidence(header: &[u8]) -> AnnexBCodecEvidence {
    let h264 = header.first().is_some_and(|&byte| {
        let reference = (byte >> 5) & 0x03;
        byte & 0x80 == 0
            && match byte & 0x1f {
                1 => true,
                5 | 7 | 8 => reference != 0,
                6 | 9 => reference == 0,
                _ => false,
            }
    });
    let hevc = match header {
        [first, second, ..] => {
            let nal_unit_type = (first >> 1) & 0x3f;
            first & 0x80 == 0
                && first & 0x01 == 0
                && second >> 3 == 0
                && second & 0x07 != 0
                && matches!(nal_unit_type, 16..=21 | 32..=35 | 39)
        }
        _ => false,
    };
    match (h264, hevc) {
        (true, false) => AnnexBCodecEvidence::H264,
        (false, true) => AnnexBCodecEvidence::Hevc,
        (true, true) => AnnexBCodecEvidence::Both,
        (false, false) => AnnexBCodecEvidence::Neither,
    }
}

/// Sniffs the format, resolving the Annex-B codec against an operator hint.
///
/// Without a hint an Annex-B stream is `hevc` only when its first header is plausible solely as
/// H.265, and `annexb` (H.264, unchanged behaviour) otherwise; a header plausible as both is
/// [`FileIngestError::AmbiguousAnnexBCodec`]. An explicit `annexb` or `hevc` hint decides an
/// ambiguous or uninformative header, but contradicting a header plausible only as the other
/// codec is [`FileIngestError::FormatConflict`].
pub fn sniff_format_with_hint(
    bytes: &[u8],
    hint: Option<FileFormatHint>,
) -> Result<(DetectedFileFormat, &'static str), FileIngestError> {
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

    // ISO-BMFF: the first box is `ftyp`. The demuxer, not the sniffer, decides support.
    if bytes.get(4..8) == Some(b"ftyp".as_slice()) {
        return Ok((DetectedFileFormat::Mp4Avc, "mp4_ftyp"));
    }

    // Check Annex-B start code: 0x00, 0x00, 0x01 or 0x00, 0x00, 0x00, 0x01
    // Scan up to first 64 bytes for a start code preceded only by zeros
    let scan_window = bytes.len().min(64);
    let mut leading_zeros = 0;
    while leading_zeros < scan_window && bytes[leading_zeros] == 0x00 {
        leading_zeros += 1;
    }
    if leading_zeros >= 2 && leading_zeros < bytes.len() && bytes[leading_zeros] == 0x01 {
        let header = bytes.get(leading_zeros + 1..).unwrap_or_default();
        return resolve_annexb_codec(annexb_codec_evidence(header), header, hint);
    }

    Err(FileIngestError::UnknownFormat {
        path: PathBuf::new(),
    })
}

fn resolve_annexb_codec(
    evidence: AnnexBCodecEvidence,
    header: &[u8],
    hint: Option<FileFormatHint>,
) -> Result<(DetectedFileFormat, &'static str), FileIngestError> {
    use AnnexBCodecEvidence::{Both, H264, Hevc, Neither};
    const H264_EVIDENCE: &str = "annexb_start_code";
    const HEVC_EVIDENCE: &str = "hevc_nal_header";
    const DECLARED_HEVC_EVIDENCE: &str = "annexb_start_code:operator_declared_hevc";
    match (hint, evidence) {
        (None, H264 | Neither) | (Some(FileFormatHint::AnnexB), H264 | Neither | Both) => {
            Ok((DetectedFileFormat::AnnexB, H264_EVIDENCE))
        }
        (None | Some(FileFormatHint::Hevc), Hevc) => Ok((DetectedFileFormat::Hevc, HEVC_EVIDENCE)),
        (Some(FileFormatHint::Hevc), Both | Neither) => {
            Ok((DetectedFileFormat::Hevc, DECLARED_HEVC_EVIDENCE))
        }
        (None, Both) => Err(FileIngestError::AmbiguousAnnexBCodec {
            first_nal_header: [
                header.first().copied().unwrap_or_default(),
                header.get(1).copied().unwrap_or_default(),
            ],
        }),
        (Some(hint), Hevc) => Err(FileIngestError::FormatConflict {
            hint,
            detected: DetectedFileFormat::Hevc,
        }),
        (Some(hint), H264 | Neither | Both) => Err(FileIngestError::FormatConflict {
            hint,
            detected: DetectedFileFormat::AnnexB,
        }),
    }
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

/// Linux open(2) flag bits for the architectures that apply them. They are NOT uniform: x86_64
/// uses `asm-generic/fcntl.h`, while aarch64 overrides O_DIRECTORY/O_NOFOLLOW/O_DIRECT/O_LARGEFILE in
/// `arch/arm64/include/uapi/asm/fcntl.h` (there `1 << 17` is O_LARGEFILE and `1 << 16` O_DIRECT).
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod open_flags {
    pub const O_NONBLOCK: i32 = 0o4_000;
    pub const O_NOFOLLOW: i32 = 0o400_000;
}
/// See the x86_64 table; values from the arm64 UAPI `asm/fcntl.h`.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod open_flags {
    pub const O_NONBLOCK: i32 = 0o4_000;
    pub const O_NOFOLLOW: i32 = 0o100_000;
}

/// Opens the operator-named source `path` for a bounded read, under the explicit I/O authority of
/// `cx`, as the very file `admitted` (its earlier `symlink_metadata`) described.
///
/// The path is not confined to `cx.root_dir()` (see the module's "Source path authority"
/// section). Refusals, before any byte is read:
/// - a revoked or finalized I/O authority: [`FileIngestError::CancellationRequested`] at
///   [`STAGE_READ`], without opening the path;
/// - `admitted` is not a regular, non-symlink file: [`FileIngestError::SymlinkNotAllowed`] or
///   [`FileIngestError::NotRegularFile`];
/// - a symlink now at the path (refused by `O_NOFOLLOW` on Linux x86_64/aarch64):
///   [`FileIngestError::SymlinkNotAllowed`];
/// - the opened handle is not a regular file: [`FileIngestError::NotRegularFile`];
/// - the opened handle's `(dev, ino)` differs from `admitted` (the path was replaced after the
///   check): [`FileIngestError::SourceChanged`], or `SymlinkNotAllowed` when the replacement is a
///   symlink.
///
/// # Errors
/// The typed refusals above, or [`FileIngestError::Io`] for any other open failure.
pub fn open_admitted_source(
    cx: &ReplayCx,
    path: &Path,
    admitted: &fs::Metadata,
) -> Result<fs::File, FileIngestError> {
    if !cx.io_authority().is_valid() {
        return Err(FileIngestError::CancellationRequested { stage: STAGE_READ });
    }
    if admitted.file_type().is_symlink() {
        return Err(FileIngestError::SymlinkNotAllowed {
            path: path.to_path_buf(),
        });
    }
    if !admitted.file_type().is_file() {
        return Err(FileIngestError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    // A refusal is reported as a symlink refusal when the path now holds a symlink, whatever the
    // platform's errno for a refused `O_NOFOLLOW` open.
    let now_symlink = || fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink());
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Per-architecture Linux UAPI bits (see `open_flags`). No foreign runtime or unsafe
        // syscall wrapper is added.
        options.custom_flags(open_flags::O_NONBLOCK | open_flags::O_NOFOLLOW);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(_) if now_symlink() => {
            return Err(FileIngestError::SymlinkNotAllowed {
                path: path.to_path_buf(),
            });
        }
        Err(error) => return Err(FileIngestError::Io(error)),
    };
    let opened = file.metadata()?;
    if !opened.file_type().is_file() {
        return Err(FileIngestError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (opened.dev(), opened.ino()) != (admitted.dev(), admitted.ino()) {
            return Err(if now_symlink() {
                FileIngestError::SymlinkNotAllowed {
                    path: path.to_path_buf(),
                }
            } else {
                FileIngestError::SourceChanged {
                    path: path.to_path_buf(),
                }
            });
        }
    }
    Ok(file)
}

/// The largest object the deployment's spool admits: the smaller of the deployment limit and the
/// spool's own bound. Every object an import stages must fit it.
fn spool_object_bound(deployment: &ReferenceDeployment) -> u64 {
    let spool =
        u64::try_from(deployment.publisher().spool().limits().max_object_bytes).unwrap_or(u64::MAX);
    deployment.limits().spool_object_max_bytes.min(spool)
}

/// Root of `slot` once its record was renamed into place (`Visible` or `Durable`). A manifest
/// that is only staged in this session is not a visible root.
fn visible_slot_root(deployment: &ReferenceDeployment, slot: &SlotName) -> Option<ContentDigest> {
    deployment
        .publisher()
        .root(slot)
        .filter(|root| root.state != LocalPublicationState::Staged)
        .map(|root| root.root)
}

/// One planned capsule batch `batch:file-import:<identity>:c<k>`.
struct PlannedBatch {
    batch_id: BatchId,
    deltas: Vec<EvidenceDelta>,
    children: Vec<ContentDigest>,
}

/// Journal-record length of a batch holding `entries`, measured with `batch_id` against the
/// current anchor. Anchor successors differ only in fixed-width fields, so the length equals the
/// length of the batch that would actually be appended under that identifier.
fn planned_record_len(
    batch_id: &BatchId,
    entries: &[(EvidenceDelta, ContentDigest)],
    anchor: &LedgerAnchor,
) -> Result<usize, FileIngestError> {
    let mut children: Vec<ContentDigest> = entries.iter().map(|(_, child)| *child).collect();
    children.sort_unstable();
    children.dedup();
    let mut candidate = EvidenceDeltaBatch {
        batch_id: batch_id.clone(),
        basis_anchor: anchor.clone(),
        new_anchor: anchor.clone(),
        deltas: entries.iter().map(|(delta, _)| delta.clone()).collect(),
        children,
        batch_digest: ContentDigest::sha256(b""),
    };
    candidate.batch_digest = candidate.computed_digest();
    fss_ledger::encode_batch(&candidate)
        .map(|encoded| encoded.len())
        .map_err(|error| {
            ReferenceError::DurableLedger(Box::new(DurableLedgerError::Codec(error))).into()
        })
}

/// Appends `group` to `out`, halving it until every part's journal record fits `record_max`.
fn fit_record(
    group: &[(EvidenceDelta, ContentDigest)],
    probe_id: &BatchId,
    record_max: usize,
    anchor: &LedgerAnchor,
    out: &mut Vec<Vec<(EvidenceDelta, ContentDigest)>>,
) -> Result<(), FileIngestError> {
    let len = planned_record_len(probe_id, group, anchor)?;
    if len <= record_max {
        out.push(group.to_vec());
        return Ok(());
    }
    if group.len() <= 1 {
        return Err(FileIngestError::SpoolCapacityExceeded {
            limit: "journal_record_max_bytes",
            required: len as u64,
            available: record_max as u64,
        });
    }
    let (left, right) = group.split_at(group.len() / 2);
    fit_record(left, probe_id, record_max, anchor, out)?;
    fit_record(right, probe_id, record_max, anchor, out)
}

/// Deterministic partition of the capsule-phase entries into batches `c0..c<K-1>`
/// (fss-2h5zq.23 round 3): consecutive groups of at most `max_entries` deltas (each entry
/// contributes one delta and one child), each split further until its journal record is at most
/// `record_max` bytes. Record lengths are measured with the longest identifier this plan can
/// assign, so the partition never depends on the digit count of `k`.
fn plan_capsule_batches(
    entries: Vec<(EvidenceDelta, ContentDigest)>,
    max_entries: usize,
    record_max: usize,
    anchor: &LedgerAnchor,
    import_identity_hex: &str,
) -> Result<Vec<PlannedBatch>, FileIngestError> {
    if max_entries == 0 {
        return Err(FileIngestError::InvalidLimits {
            detail: "max_batch_deltas must be strictly positive".to_string(),
        });
    }
    let probe_id = BatchId::parse(format!(
        "batch:file-import:{import_identity_hex}:c{}",
        entries.len()
    ))?;
    let mut groups = Vec::new();
    for group in entries.chunks(max_entries) {
        fit_record(group, &probe_id, record_max, anchor, &mut groups)?;
    }
    groups
        .into_iter()
        .enumerate()
        .map(|(k, group)| {
            let mut children: Vec<ContentDigest> = group.iter().map(|(_, child)| *child).collect();
            children.sort_unstable();
            children.dedup();
            Ok(PlannedBatch {
                batch_id: BatchId::parse(format!("batch:file-import:{import_identity_hex}:c{k}"))?,
                deltas: group.into_iter().map(|(delta, _)| delta).collect(),
                children,
            })
        })
        .collect()
}

/// Check the completing batch before staging any byte. Its acquisition records and witnesses
/// are not capsule entries and cannot be split without inventing an intermediate completion.
fn check_commit_admission(
    deployment: &ReferenceDeployment,
    batch_id: &BatchId,
    deltas: &[EvidenceDelta],
    children: &[ContentDigest],
    publication: &FilePublicationPlan,
    capsules: &[PlannedBatch],
    cx: &ReplayCx,
) -> Result<(), FileIngestError> {
    let history: std::collections::BTreeMap<_, _> = deployment
        .ledger()
        .batches()
        .iter()
        .map(|batch| (batch.batch_id.as_str(), batch))
        .collect();
    let all_capsules_committed = capsules
        .iter()
        .all(|batch| history.contains_key(batch.batch_id.as_str()));
    let last_capsule_sequence = capsules
        .iter()
        .filter_map(|batch| history.get(batch.batch_id.as_str()))
        .map(|batch| batch.new_anchor.commit_sequence)
        .max();
    let mut gap = false;
    let mut previous = last_capsule_sequence;
    // The aggregate identity is the completion witness. Every ledgered publication must be a
    // prefix following all capsule authority, never an out-of-order root borrowed from elsewhere.
    let aggregate_root = deltas
        .iter()
        .find(|delta| delta.family == "file_import")
        .and_then(|delta| delta.witness_digest)
        .ok_or_else(|| FileIngestError::CorruptSegment {
            detail: "completing import has no root witness".to_owned(),
        })?;
    for (slot, root) in publication
        .parts()
        .iter()
        .map(|part| (part.slot(), part.manifest().root()))
        .chain(std::iter::once((publication.slot(), aggregate_root)))
    {
        cx.checkpoint("file_adapter:publication_admission")
            .map_err(|_| FileIngestError::CancellationRequested {
                stage: "file_adapter:publication_admission",
            })?;
        let id = format!("batch:local-root:{slot}");
        let Some(stored) = history.get(id.as_str()) else {
            gap = true;
            continue;
        };
        if gap
            || !all_capsules_committed
            || previous.is_none_or(|sequence| stored.new_anchor.commit_sequence <= sequence)
            || !deployment.publisher().root(slot).is_some_and(|visible| {
                visible.state == LocalPublicationState::Durable && visible.root == root
            })
        {
            return Err(FileIngestError::ImportPlanConflict {
                batch_id: stored.batch_id.clone(),
                detail:
                    "published roots are damaged or not an ordered prefix after capsule authority"
                        .to_owned(),
            });
        }
        // A retry must not silently repair a lost body behind already-committed custody.
        let _retained_body = deployment.publisher().spool().read(root)?;
        previous = Some(stored.new_anchor.commit_sequence);
    }
    let maximum = deployment.limits().batch_entries_max;
    let required = deltas.len().max(children.len());
    if required > maximum {
        return Err(FileIngestError::SpoolCapacityExceeded {
            limit: "batch_entries_max",
            required: required as u64,
            available: maximum as u64,
        });
    }
    let mut children = children.to_vec();
    children.sort_unstable();
    children.dedup();
    let mut deltas = deltas.to_vec();
    deltas.sort_by(|left, right| {
        (
            left.family.as_str(),
            left.object_id.as_str(),
            left.new_generation,
            left.delta_id.as_str(),
        )
            .cmp(&(
                right.family.as_str(),
                right.object_id.as_str(),
                right.new_generation,
                right.delta_id.as_str(),
            ))
    });
    let anchor = deployment.current_anchor().clone();
    let mut batch = EvidenceDeltaBatch {
        batch_id: batch_id.clone(),
        basis_anchor: anchor.clone(),
        new_anchor: anchor,
        deltas,
        children,
        batch_digest: ContentDigest::sha256(b""),
    };
    batch.batch_digest = batch.computed_digest();
    let encoded = fss_ledger::encode_batch(&batch).map_err(|error| {
        ReferenceError::DurableLedger(Box::new(DurableLedgerError::Codec(error)))
    })?;
    let maximum = u64::from(deployment.limits().journal_record_max_bytes);
    if encoded.len() as u64 > maximum {
        return Err(FileIngestError::SpoolCapacityExceeded {
            limit: "journal_record_max_bytes",
            required: encoded.len() as u64,
            available: maximum,
        });
    }
    Ok(())
}

/// Appends one planned import batch. The deployment skips a batch already committed with
/// identical content; a committed batch with different content under the same planned identity
/// is reported as [`FileIngestError::ImportPlanConflict`], never overwritten.
fn append_planned_batch(
    deployment: &mut ReferenceDeployment,
    batch_id: BatchId,
    deltas: Vec<EvidenceDelta>,
    children: Vec<ContentDigest>,
    cx: &ReplayCx,
) -> Result<LedgerAnchor, FileIngestError> {
    match deployment.append_batch(batch_id.clone(), deltas, children, cx) {
        Ok(anchor) => Ok(anchor),
        Err(ReferenceError::DurableLedger(error))
            if matches!(*error, DurableLedgerError::BatchIdConflict { .. }) =>
        {
            Err(FileIngestError::ImportPlanConflict {
                batch_id,
                detail: error.to_string(),
            })
        }
        Err(error) => Err(error.into()),
    }
}

struct ScannedSegments {
    segment_spans: Vec<SegmentSpan>,
    omission_spans: Vec<FileOmissionSpan>,
    capsules: Vec<SensorCapsule>,
    truncated_frames: usize,
}

impl ScannedSegments {
    fn source_facts(&self) -> FileSourceFacts {
        FileSourceFacts {
            segments: self.segment_spans.len(),
            omitted_spans: self
                .omission_spans
                .iter()
                .filter(|o| o.reason != "annexb_padding")
                .count(),
            truncated_frames: self.truncated_frames,
            gapped_segments: self.segment_spans.iter().filter(|s| s.gap_before).count(),
        }
    }
}

/// Pure Rust file ingest adapter implementing `ADP-FILE-001`.
pub struct FileIngestAdapter;

/// Result of the generic routing entry [`FileIngestAdapter::ingest_file`].
#[derive(Debug)]
pub enum FileImport {
    /// A media file split into frame/access-unit segments.
    Media(Box<FileIngestReceipt>),
    /// A recorded-RTP session: original-file custody, access-unit capsules and the import report.
    RecordedRtp(Box<RtpFileImportReceipt>),
}

/// Whether a sniffed recorded-RTP file is routed or refused by the calling entrypoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RtpRoute {
    Refuse,
    Import,
}

impl FileIngestAdapter {
    /// Ingests a media file into [`ReferenceDeployment`].
    pub fn ingest(
        request: FileIngestRequest,
        cx: &ReplayCx,
        deployment: &mut ReferenceDeployment,
    ) -> Result<FileIngestReceipt, FileIngestError> {
        Self::ingest_with_session(request, cx, deployment).map_err(|failure| failure.error)
    }

    /// Generic routing entry: sniffs the file and imports it by its detected format. Media files
    /// follow [`Self::ingest`]; a `#!rtpplay1.0` recording is delegated to the recorded-RTP import
    /// with the request's owner binding (refused as [`FileIngestError::RtpBindingRequired`]
    /// without it) and the explicit receive time. The file is read once, bounded by
    /// `max_file_bytes`; the delegated import sees exactly the sniffed bytes.
    pub fn ingest_file(
        request: FileIngestRequest,
        cx: &ReplayCx,
        deployment: &mut ReferenceDeployment,
    ) -> Result<FileImport, FileIngestError> {
        let mut driver = None;
        Self::ingest_driven(request, cx, deployment, &mut driver, RtpRoute::Import)
    }

    /// Ingests a media file and, on failure, returns the acquisition history the attempt reached,
    /// concluded through the core session (`Failed`, `Cancelled` or `Indeterminate`).
    pub fn ingest_with_session(
        request: FileIngestRequest,
        cx: &ReplayCx,
        deployment: &mut ReferenceDeployment,
    ) -> Result<FileIngestReceipt, Box<FileIngestFailure>> {
        let mut driver = None;
        match Self::ingest_driven(request, cx, deployment, &mut driver, RtpRoute::Refuse) {
            Ok(FileImport::Media(receipt)) => Ok(*receipt),
            // `RtpRoute::Refuse` never imports recorded RTP; kept typed rather than unreachable.
            Ok(FileImport::RecordedRtp(_)) => Err(Box::new(FileIngestFailure {
                error: FileIngestError::UnsupportedFormat {
                    format: DetectedFileFormat::RtpPlay,
                },
                acquisition: None,
            })),
            Err(error) => {
                let acquisition = driver.take().map(|d| d.conclude_error(&error));
                Err(Box::new(FileIngestFailure { error, acquisition }))
            }
        }
    }

    fn ingest_driven(
        request: FileIngestRequest,
        cx: &ReplayCx,
        deployment: &mut ReferenceDeployment,
        driver: &mut Option<FileSessionDriver>,
        rtp: RtpRoute,
    ) -> Result<FileImport, FileIngestError> {
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
        if request.limits.chunk_bytes == 0 {
            return Err(FileIngestError::InvalidLimits {
                detail: "chunk_bytes must be strictly positive".to_string(),
            });
        }
        // Every custody chunk is one spool object: a chunk size above the spool's object bound
        // would fail mid-staging, so it is refused here, before the file is opened (fss-n62w2).
        let object_bound = spool_object_bound(deployment);
        if request.limits.chunk_bytes > object_bound {
            return Err(FileIngestError::InvalidLimits {
                detail: format!(
                    "chunk_bytes {} exceeds the spool object bound {object_bound}",
                    request.limits.chunk_bytes
                ),
            });
        }
        if request.limits.max_file_bytes == 0 {
            return Err(FileIngestError::InvalidLimits {
                detail: "max_file_bytes must be strictly positive".to_string(),
            });
        }
        if request.limits.max_batch_deltas == 0 {
            return Err(FileIngestError::InvalidLimits {
                detail: "max_batch_deltas must be strictly positive".to_string(),
            });
        }
        // Bounded read: never read past the admitted limit even if the file grew
        // after the stat check (review-2036: the read must be bounded, not fs::read).
        // The open is authorized by the I/O authority and bound to the admitted file identity
        // (fss-n62w2); the read and the post-read size check use the handle, never the path.
        let file = open_admitted_source(cx, &request.path, &metadata)?;
        let mut file_bytes = Vec::with_capacity(
            usize::try_from(file.metadata()?.len().min(request.limits.max_file_bytes))
                .unwrap_or(usize::MAX),
        );
        {
            use std::io::Read;
            let mut handle = (&file).take(request.limits.max_file_bytes);
            handle.read_to_end(&mut file_bytes)?;
        }
        let stat_len = file.metadata()?.len();
        if stat_len > request.limits.max_file_bytes {
            return Err(FileIngestError::FileTooLarge {
                path: request.path.clone(),
                len: stat_len,
                max: request.limits.max_file_bytes,
            });
        }
        // Custody covers exactly the bytes read, not the first stat: a file that shrank or grew
        // in between is recorded by its read length (and refused when it read empty).
        let file_len = file_bytes.len() as u64;
        if file_len == 0 {
            return Err(FileIngestError::EmptyFile {
                path: request.path.clone(),
            });
        }
        let input_sha256 = ContentDigest::sha256(&file_bytes);

        // Step 3: Format sniffing
        let (detected_format, detector_evidence) =
            match sniff_format_with_hint(&file_bytes, request.format_hint) {
                Ok(res) => res,
                Err(FileIngestError::UnknownFormat { .. }) => {
                    return Err(FileIngestError::UnknownFormat {
                        path: request.path.clone(),
                    });
                }
                Err(e) => return Err(e),
            };

        if detected_format == DetectedFileFormat::RtpPlay {
            if rtp == RtpRoute::Refuse {
                return Err(FileIngestError::UnsupportedFormat {
                    format: DetectedFileFormat::RtpPlay,
                });
            }
            // A hint naming another format conflicts with the sniffed recording.
            if let Some(hint) = request.format_hint
                && hint != FileFormatHint::RtpPlay
            {
                return Err(FileIngestError::FormatConflict {
                    hint,
                    detected: detected_format,
                });
            }
            let binding = request
                .rtp_binding
                .ok_or(FileIngestError::RtpBindingRequired {})?;
            if request.receive_time.is_none() {
                return Err(FileIngestError::MissingReceiveTime {});
            }
            let receipt = import_rtp_snapshot(&request, binding, &file_bytes, cx, deployment)
                .map_err(|e| FileIngestError::RecordedRtp(Box::new(e)))?;
            return Ok(FileImport::RecordedRtp(Box::new(receipt)));
        }

        if let Some(hint) = request.format_hint
            && hint != detected_format.into_hint()
        {
            return Err(FileIngestError::FormatConflict {
                hint,
                detected: detected_format,
            });
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
        // A deleted identity is never re-imported: its ledger identities are permanent.
        super::retained::refuse_deleted(deployment, import_identity)?;
        let manifest_batch_id =
            BatchId::parse(format!("batch:file-import:{import_identity_hex}:manifest"))?;

        // Step 5: Time truth configuration
        let receive_time = request
            .receive_time
            .ok_or(FileIngestError::MissingReceiveTime {})?;
        // Acquisition lifecycle: Requested -> Authenticated (CredentialMethod::None).
        let session = driver.insert(FileSessionDriver::open(
            import_identity,
            &import_identity_hex,
            receive_time,
        )?);
        let capture_time_label = if request.capture_hint.is_some() {
            "operator_assumption"
        } else {
            "unknown"
        };

        if let Some(hint) = &request.capture_hint {
            if hint.start_ns < TimestampNs(0) {
                return Err(FileIngestError::InvalidCaptureHint {
                    detail: format!(
                        "capture hint start_ns must be non-negative, got {}",
                        hint.start_ns.0
                    ),
                });
            }
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
            // Segment 0's interval ends at `start + uncertainty`; refuse it before the adapter
            // accepts. Later segments are checked as their intervals are computed, still before
            // anything is staged (fss-roeq0).
            Self::compute_capture_interval(0, Some(hint), receive_time)?;
        }
        // The request is admissible: AdapterAccepted.
        session.accept()?;

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
        // No observable continuity and no decode: Degraded, invalidating absence.
        session.degrade(scanned.source_facts())?;

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
        let mut import_manifest = FileImportManifest {
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

        // Step 9: Deterministic batch plan (fss-2h5zq.23 round 3). Pure: nothing is staged or
        // appended here, so every refusal below leaves the deployment untouched.
        let capsule_encodings: Vec<(ContentDigest, Vec<u8>)> = scanned
            .capsules
            .iter()
            .map(|c| {
                let bytes = c.canonical_bytes();
                (ContentDigest::sha256(&bytes), bytes)
            })
            .collect();
        let overall_validity = if let (Some(first), Some(last)) =
            (scanned.capsules.first(), scanned.capsules.last())
        {
            CaptureInterval::new(first.capture.earliest, last.capture.latest)?
        } else {
            CaptureInterval::new(TimestampNs(0), receive_time)?
        };
        let import_object_id =
            ObjectId::parse(format!("object:file-import:{import_identity_hex}"))?;

        // Plan the complete custody closure, including end-of-source records, before the
        // metadata digest or a retry receipt is constructed. Proposing a closing is pure and
        // does not change the session; its transition is adopted only after final commit.
        let closing = driver
            .as_ref()
            .ok_or_else(|| FileIngestError::CorruptSegment {
                detail: "acquisition session missing".to_string(),
            })?
            .propose_end_of_file()?;
        let closure_bound = deployment
            .limits()
            .manifest_children_max
            .min(deployment.limits().batch_entries_max);
        let publication = FilePublicationPlan::new(
            import_identity,
            ordered_chunks
                .iter()
                .copied()
                .chain(std::iter::once(custody_manifest_digest))
                .chain(capsule_encodings.iter().map(|(digest, _)| *digest))
                .chain(closing.object_bytes().map(|(digest, _)| digest)),
            closure_bound,
        )?;
        import_manifest.part_roots = publication.part_roots();
        let import_slot_manifest = publication.root_manifest(&import_manifest)?;
        let manifest_bytes = import_manifest.canonical_bytes();
        let manifest_digest = import_manifest.canonical_digest();

        // Entry 0: file_import gen 1 (in_progress); then one sensor_capsule delta per capsule.
        // Each entry carries the one batch child that holds its payload.
        let mut planned_entries = Vec::with_capacity(scanned.capsules.len() + 1);
        planned_entries.push((
            EvidenceDelta {
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
            },
            custody_manifest_digest,
        ));
        for (capsule, (payload_digest, _)) in scanned.capsules.iter().zip(&capsule_encodings) {
            planned_entries.push((
                EvidenceDelta {
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
                    payload_digest: *payload_digest,
                    witness_digest: None,
                    operation_id: None,
                },
                *payload_digest,
            ));
        }
        let capsule_batches = plan_capsule_batches(
            planned_entries,
            request
                .limits
                .max_batch_deltas
                .min(deployment.limits().batch_entries_max),
            deployment.limits().journal_record_max_bytes as usize,
            deployment.current_anchor(),
            &import_identity_hex,
        )?;
        let mut planned_batch_ids: Vec<BatchId> = capsule_batches
            .iter()
            .map(|batch| batch.batch_id.clone())
            .collect();
        planned_batch_ids.push(manifest_batch_id.clone());

        // Step 10: Admit retries against retained authority before any staging or append.
        // The import identity does not include capture hints or receive time. Reconstructing
        // a receipt from this request alone could therefore silently rebind committed evidence.
        let existing_slot = visible_slot_root(deployment, &import_slot).is_some();
        if let Some(retained) = retry::preflight(
            deployment,
            &capsule_batches,
            &manifest_batch_id,
            import_identity,
            &import_manifest,
            cx,
        )? {
            let anchor = deployment.current_anchor().clone();
            // This attempt appends nothing; the receipt carries the retained history.
            *driver = None;
            let acquisition = AcquisitionRetention::open(deployment, import_identity)?;
            return Ok(FileImport::Media(Box::new(FileIngestReceipt {
                outcome: FileIngestOutcome::IdempotentExisting,
                import_identity,
                input_sha256,
                input_bytes: file_len,
                format: detected_format,
                capsule_count: scanned.capsules.len(),
                capsules: scanned.capsules,
                import_root: retained.import_root(),
                manifest_digest: retained.manifest_digest(),
                manifest: retained.manifest().clone(),
                root_slot: import_slot.clone(),
                authority_anchor: anchor,
                batch_ids: planned_batch_ids,
                chunk_count,
                unique_chunk_count,
                chunk_bytes: request.limits.chunk_bytes,
                capture_time_label,
                absence_certifiable: acquisition
                    .history()
                    .is_some_and(|h| h.absence_claim().is_ok()),
                acquisition,
            })));
        }

        // A resumed import whose first capsule batch an earlier attempt committed is already
        // partially published: a failure from here on leaves completion indeterminate, never
        // "failed".
        let capsule_batch_committed = deployment
            .ledger()
            .batches()
            .iter()
            .any(|b| planned_batch_ids.first() == Some(&b.batch_id));
        if capsule_batch_committed && let Some(session) = driver.as_mut() {
            session.mark_capsules_committed();
        }

        let final_manifest_object_id =
            ObjectId::parse(format!("object:file-import-manifest:{import_identity_hex}"))?;
        let mut final_deltas = vec![
            EvidenceDelta {
                delta_id: format!("delta:file-import:{import_identity_hex}:complete"),
                family: "file_import".to_string(),
                object_id: import_object_id,
                prior_generation: Some(1),
                new_generation: 2,
                validity: overall_validity,
                plane: Plane::Authority,
                payload_digest: manifest_digest,
                witness_digest: Some(import_slot_manifest.root()),
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
                witness_digest: Some(import_slot_manifest.root()),
                operation_id: None,
            },
        ];
        let mut final_children = vec![manifest_digest, import_slot_manifest.root()];
        // The acquisition history (ending end_of_file_source) completes with the import.
        let (acquisition_deltas, acquisition_children) =
            closing.deltas(&import_identity_hex, overall_validity)?;
        final_deltas.extend(acquisition_deltas);
        final_children.extend(acquisition_children);

        // Step 11: Exact capacity check after hashing and BEFORE the first stage
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
        for (digest, enc) in &capsule_encodings {
            candidate_objects.push((*digest, enc.as_slice()));
        }
        candidate_objects.push((manifest_digest, &manifest_bytes));

        publication.preflight_unstaged(
            deployment,
            &import_manifest,
            overall_validity,
            candidate_objects
                .iter()
                .copied()
                .filter(|(digest, _)| *digest != manifest_digest)
                .chain(closing.object_bytes())
                .map(|(digest, bytes)| (digest, bytes.len())),
            cx,
        )?;
        check_commit_admission(
            deployment,
            &manifest_batch_id,
            &final_deltas,
            &final_children,
            &publication,
            &capsule_batches,
            cx,
        )?;

        // Step 12: Staging objects
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
        for (_, enc) in &capsule_encodings {
            deployment.publisher_mut().stage_object(enc.as_slice())?;
        }
        // Stage FileImportManifest
        deployment.publisher_mut().stage_object(&manifest_bytes)?;

        // Stage the retained acquisition records and witnesses
        for (_, bytes) in closing.object_bytes() {
            deployment.stage_payload(bytes)?;
        }

        // Verify staged objects. After a reopen they are `Staged` again, so a resumed import
        // re-verifies them before any prepare or publish.
        for (digest, _) in candidate_objects
            .iter()
            .copied()
            .chain(closing.object_bytes())
        {
            deployment.publisher_mut().verify_object(digest)?;
        }

        // Step 13: Stage the import slot manifest (holds all children for reachability). A slot
        // already visible with exactly this root (checked above) is not restaged: the publisher
        // refuses to stage into a visible slot, and `publish_and_commit` re-verifies it instead.
        let import_root = if visible_slot_root(deployment, &import_slot).is_some() {
            import_slot_manifest.root()
        } else {
            deployment
                .publisher_mut()
                .stage_manifest(&import_slot, &import_slot_manifest)?
        };

        // Step 14: Commit the planned capsule batches c0..c<K-1> in order. A batch already in
        // the ledger with identical content is skipped by `append_batch` (no journal I/O); one
        // with different content is an `ImportPlanConflict`. Cancellation is polled before every
        // batch, so a cancelled import stops between batches as a recognizably incomplete import
        // (import object at generation 1, no manifest batch) that a re-import completes.
        let mut resumed = existing_slot;
        let mut committed_batches = Vec::with_capacity(planned_batch_ids.len());
        for batch in capsule_batches {
            cx.reach_stage(STAGE_COMMIT_CAPSULES);
            if cx.is_cancelled() {
                cx.drain_and_finalize();
                return Err(FileIngestError::CancellationRequested {
                    stage: STAGE_COMMIT_CAPSULES,
                });
            }
            if deployment
                .ledger()
                .batches()
                .iter()
                .any(|b| b.batch_id == batch.batch_id)
            {
                resumed = true;
            }
            append_planned_batch(
                deployment,
                batch.batch_id.clone(),
                batch.deltas,
                batch.children,
                cx,
            )?;
            committed_batches.push(batch.batch_id);
            if let Some(session) = driver.as_mut() {
                session.mark_capsules_committed();
            }
        }

        // Step 15: Publish root to slot fi-<id>
        cx.reach_stage(STAGE_PUBLISH_ROOT);
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(FileIngestError::CancellationRequested {
                stage: STAGE_PUBLISH_ROOT,
            });
        }

        if publication.parts().is_empty() {
            // A crash after the temporary root record was written leaves it orphaned, and the
            // publisher refuses to publish over it. It is discarded only when it is byte-identical
            // to the record this publication writes (the crashed attempt of exactly this plan), as
            // `discard_orphaned_root_temp_for` documents; any other temp is kept and refused.
            if visible_slot_root(deployment, &import_slot).is_none() {
                deployment
                    .publisher_mut()
                    .discard_orphaned_root_temp_for(&import_slot, &import_slot_manifest)?;
            }
            let _publish_receipt = deployment.publish_and_commit(
                &import_slot,
                &import_slot_manifest,
                overall_validity,
                cx,
            )?;
        } else {
            // Each durable part is independently ledgered. The aggregate is published last;
            // an interruption leaves generation 1 and an exact retry reuses the part prefix.
            publication.publish(deployment, &import_manifest, overall_validity, cx)?;
        }

        // Step 16: Commit final manifest batch (moves import to gen 2 = complete)
        cx.reach_stage(STAGE_COMMIT_MANIFEST);
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(FileIngestError::CancellationRequested {
                stage: STAGE_COMMIT_MANIFEST,
            });
        }

        let final_anchor = append_planned_batch(
            deployment,
            manifest_batch_id.clone(),
            final_deltas,
            final_children,
            cx,
        )?;
        committed_batches.push(manifest_batch_id);
        let history = driver
            .take()
            .ok_or_else(|| FileIngestError::CorruptSegment {
                detail: "acquisition session missing".to_string(),
            })?
            .commit_end_of_file(closing);
        let absence_certifiable = history.absence_claim().is_ok();

        let outcome = if resumed {
            FileIngestOutcome::Resumed
        } else {
            FileIngestOutcome::New
        };

        Ok(FileImport::Media(Box::new(FileIngestReceipt {
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
            absence_certifiable,
            acquisition: AcquisitionRetention::Recorded(Box::new(history)),
        })))
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
        let mut truncated_frames = 0_usize;

        match format {
            DetectedFileFormat::AnnexB => {
                let scan = split_annexb(file_bytes, request.limits.annexb_limits, cx)?;
                return Self::annexb_segments(
                    file_bytes,
                    &scan.omission_spans,
                    &scan.padding_spans,
                    scan.access_units
                        .iter()
                        .map(|au| (au.span, au.undecodable_without_parameter_sets)),
                    request,
                    import_identity_hex,
                    receive_time,
                );
            }
            DetectedFileFormat::Hevc => {
                let scan = split_hevc_annexb(file_bytes, request.limits.annexb_limits, cx)?;
                return Self::annexb_segments(
                    file_bytes,
                    &scan.omission_spans,
                    &scan.padding_spans,
                    scan.access_units
                        .iter()
                        .map(|au| (au.span, au.undecodable_without_parameter_sets)),
                    request,
                    import_identity_hex,
                    receive_time,
                );
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
                        truncated_frames += 1;
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
                        clock_basis: ClockBasis::Estimated,
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
            DetectedFileFormat::Mp4Avc => {
                return Self::mp4_segments(
                    file_bytes,
                    request,
                    import_identity_hex,
                    receive_time,
                    cx,
                );
            }
        }

        Ok(ScannedSegments {
            segment_spans,
            omission_spans,
            capsules,
            truncated_frames,
        })
    }

    /// One segment per Annex-B access unit (H.264 or H.265): exact spans, capsules, and a gap
    /// before any access unit that follows omitted bytes or precedes the stream's parameter sets.
    fn annexb_segments(
        file_bytes: &[u8],
        omissions: &[SourceSpan],
        padding: &[SourceSpan],
        access_units: impl Iterator<Item = (SourceSpan, bool)>,
        request: &FileIngestRequest,
        import_identity_hex: &str,
        receive_time: TimestampNs,
    ) -> Result<ScannedSegments, FileIngestError> {
        let mut segment_spans = Vec::new();
        let mut omission_spans = Vec::new();
        let mut capsules = Vec::new();
        for o in omissions {
            omission_spans.push(FileOmissionSpan {
                offset: o.offset as u64,
                len: o.len as u64,
                reason: "annexb_omission".to_string(),
            });
        }
        for p in padding {
            omission_spans.push(FileOmissionSpan {
                offset: p.offset as u64,
                len: p.len as u64,
                reason: "annexb_padding".to_string(),
            });
        }

        let mut last_segment_end: usize = 0;
        for (idx, (span, undecodable)) in access_units.enumerate() {
            let au_slice = file_bytes.get(span.offset..span.end()).ok_or_else(|| {
                FileIngestError::CorruptSegment {
                    detail: "AU span out of bounds".to_string(),
                }
            })?;
            let au_sha256 = ContentDigest::sha256(au_slice);
            let capsule_id =
                CapsuleId::parse(format!("capsule:{}:{:06}", import_identity_hex, idx))?;

            let has_gap_before = (span.offset > last_segment_end) || undecodable;
            last_segment_end = span.end();

            let capture =
                Self::compute_capture_interval(idx, request.capture_hint.as_ref(), receive_time)?;

            let spec = SensorSourceBytesSpec {
                capsule_id: capsule_id.clone(),
                sensor_id: request.sensor_id.clone(),
                stream_id: request.stream_id.clone(),
                sequence: idx as u64,
                capture,
                receive_time,
                clock_basis: ClockBasis::Estimated,
                source: au_slice,
                frame_count: 1,
                gap_before: has_gap_before,
            };
            let capsule = SensorCapsule::from_source_bytes(spec)?;

            segment_spans.push(SegmentSpan {
                segment_index: idx,
                offset: span.offset as u64,
                len: span.len as u64,
                segment_sha256: au_sha256,
                capsule_id,
                gap_before: has_gap_before,
            });
            capsules.push(capsule);
        }
        Ok(ScannedSegments {
            segment_spans,
            omission_spans,
            capsules,
            truncated_frames: 0,
        })
    }

    /// One segment per `avc1` sample, in decode order, with the sample's exact length-prefixed
    /// bytes. Every other byte is a typed container-structure span: each `avcC` parameter-set
    /// NAL payload (read back verbatim by the decoder) and, split at top-level box boundaries,
    /// the remaining box bytes (`mp4_box:<type>`, including other tracks' data in `mdat`).
    /// Samples are complete by construction (the demuxer refuses the whole file otherwise), so
    /// no sample carries a source gap; samples stored out of decode order are refused.
    fn mp4_segments(
        file_bytes: &[u8],
        request: &FileIngestRequest,
        import_identity_hex: &str,
        receive_time: TimestampNs,
        cx: &ReplayCx,
    ) -> Result<ScannedSegments, FileIngestError> {
        use fss_container::demux::{
            AvcMp4, DemuxError, DemuxLimits, MAX_MP4_INPUT_BYTES, MAX_MP4_SAMPLES,
        };
        let limits = DemuxLimits {
            maximum_input_bytes: MAX_MP4_INPUT_BYTES,
            maximum_samples: request.limits.max_segments.clamp(1, MAX_MP4_SAMPLES),
            ..DemuxLimits::default()
        };
        let mp4 = AvcMp4::parse_with_checkpoint(file_bytes, None, limits, &mut || {
            cx.checkpoint(STAGE_SPLIT)
                .map_err(|_| DemuxError::Cancelled)
        })
        .map_err(|refusal| match refusal {
            DemuxError::Cancelled => FileIngestError::CancellationRequested { stage: STAGE_SPLIT },
            refusal => FileIngestError::Mp4Refused { refusal },
        })?;
        let parameter_reason = format!(
            "{MP4_PARAMETER_SET_REASON_PREFIX}{}",
            mp4.nal_length_bytes()
        );
        // Claimed ranges: samples (Some(index)) and parameter sets (None), in file order.
        let mut claimed: Vec<(usize, usize, Option<usize>)> = mp4
            .parameter_sets()
            .iter()
            .map(|range| (range.start, range.end, None))
            .collect();
        let mut previous_end = 0_usize;
        for sample in mp4.samples() {
            if sample.source.start < previous_end {
                return Err(FileIngestError::Mp4Refused {
                    refusal: DemuxError::Layout,
                });
            }
            previous_end = sample.source.end;
            claimed.push((sample.source.start, sample.source.end, Some(sample.index)));
        }
        claimed.sort_unstable();
        let boxes = top_level_boxes(file_bytes);
        let mut omission_spans = Vec::new();
        let mut cursor = 0_usize;
        let structure = |from: usize, to: usize, spans: &mut Vec<FileOmissionSpan>| {
            for &(start, end, kind) in &boxes {
                let (lo, hi) = (from.max(start), to.min(end));
                if lo < hi {
                    spans.push(FileOmissionSpan {
                        offset: lo as u64,
                        len: (hi - lo) as u64,
                        reason: format!("mp4_box:{}", box_kind_text(kind)),
                    });
                }
            }
        };
        for &(start, end, sample) in &claimed {
            if start < cursor {
                return Err(FileIngestError::Mp4Refused {
                    refusal: DemuxError::Layout,
                });
            }
            structure(cursor, start, &mut omission_spans);
            if sample.is_none() {
                omission_spans.push(FileOmissionSpan {
                    offset: start as u64,
                    len: (end - start) as u64,
                    reason: parameter_reason.clone(),
                });
            }
            cursor = end;
        }
        structure(cursor, file_bytes.len(), &mut omission_spans);
        let accounted = omission_spans.iter().map(|span| span.len).sum::<u64>()
            + mp4
                .samples()
                .iter()
                .map(|sample| sample.source.len() as u64)
                .sum::<u64>();
        if accounted != file_bytes.len() as u64 {
            return Err(FileIngestError::Mp4Refused {
                refusal: DemuxError::Layout,
            });
        }

        let mut segment_spans = Vec::with_capacity(mp4.samples().len());
        let mut capsules = Vec::with_capacity(mp4.samples().len());
        for sample in mp4.samples() {
            let idx = sample.index;
            let bytes = file_bytes.get(sample.source.clone()).ok_or_else(|| {
                FileIngestError::CorruptSegment {
                    detail: "MP4 sample span out of bounds".to_string(),
                }
            })?;
            let capsule_id =
                CapsuleId::parse(format!("capsule:{}:{:06}", import_identity_hex, idx))?;
            let capture =
                Self::compute_capture_interval(idx, request.capture_hint.as_ref(), receive_time)?;
            let capsule = SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
                capsule_id: capsule_id.clone(),
                sensor_id: request.sensor_id.clone(),
                stream_id: request.stream_id.clone(),
                sequence: idx as u64,
                capture,
                receive_time,
                clock_basis: ClockBasis::Estimated,
                source: bytes,
                frame_count: 1,
                gap_before: false,
            })?;
            segment_spans.push(SegmentSpan {
                segment_index: idx,
                offset: sample.source.start as u64,
                len: sample.source.len() as u64,
                segment_sha256: ContentDigest::sha256(bytes),
                capsule_id,
                gap_before: false,
            });
            capsules.push(capsule);
        }
        Ok(ScannedSegments {
            segment_spans,
            omission_spans,
            capsules,
            truncated_frames: 0,
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
                // Receive time bounds capture: refuse, never clamp (fss-roeq0).
                if latest > receive_time {
                    return Err(FileIngestError::CaptureHintLatestAfterReceive {
                        hint_start: h.start_ns,
                        segment_index: index,
                        capture_latest: latest,
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

        // Span metadata is untrusted input here (a manifest read back from custody): every
        // bound is checked, so a malformed span is a typed refusal, never a panic.
        let corrupt = |detail: &str| FileIngestError::CorruptSegment {
            detail: detail.to_string(),
        };
        let chunk_size = usize::try_from(manifest.chunk_bytes)
            .ok()
            .filter(|size| *size > 0)
            .ok_or_else(|| corrupt("manifest chunk size must be strictly positive"))?;
        let start_offset =
            usize::try_from(segment.offset).map_err(|_| corrupt("segment offset out of range"))?;
        let segment_len = usize::try_from(segment.len)
            .ok()
            .filter(|len| *len > 0)
            .ok_or_else(|| corrupt("segment length must be strictly positive"))?;
        let end_offset = start_offset
            .checked_add(segment_len)
            .filter(|end| (*end as u64) <= manifest.input_bytes)
            .ok_or_else(|| corrupt("segment span exceeds the imported file"))?;

        let first_chunk = start_offset / chunk_size;
        let last_chunk = (end_offset - 1) / chunk_size;

        let mut assembled = Vec::with_capacity(segment_len);

        for chunk_idx in first_chunk..=last_chunk {
            let chunk_digest = *manifest
                .ordered_chunks
                .get(chunk_idx)
                .ok_or_else(|| corrupt("chunk index out of bounds"))?;
            let chunk_data =
                deployment
                    .publisher()
                    .spool()
                    .read(chunk_digest)
                    .map_err(|source| FileIngestError::CustodyUnavailable {
                        segment_index,
                        chunk_index: chunk_idx,
                        chunk: chunk_digest,
                        source: Box::new(source),
                    })?;

            let chunk_start_file_offset = chunk_idx
                .checked_mul(chunk_size)
                .ok_or_else(|| corrupt("chunk offset out of range"))?;
            let chunk_end_file_offset = chunk_start_file_offset.saturating_add(chunk_data.len());

            let slice_start = start_offset.max(chunk_start_file_offset) - chunk_start_file_offset;
            let slice_end = end_offset
                .min(chunk_end_file_offset)
                .saturating_sub(chunk_start_file_offset);

            if slice_start < slice_end
                && let Some(bytes) = chunk_data.get(slice_start..slice_end)
            {
                assembled.extend_from_slice(bytes);
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

/// Reassembles and verifies the raw source segment bytes from the chunked custody objects in the deployment spool.
pub fn fetch_segment_bytes(
    manifest: &FileImportManifest,
    deployment: &ReferenceDeployment,
    segment_index: usize,
) -> Result<Vec<u8>, FileIngestError> {
    FileIngestAdapter::fetch_segment_bytes(manifest, deployment, segment_index)
}

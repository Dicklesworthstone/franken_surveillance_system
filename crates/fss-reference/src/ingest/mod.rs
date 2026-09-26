//! Ingest adapters and stream framing utilities.
//!
//! Provides deterministic stream framing, marker validation, and source custody accounting
//! for incoming media streams before decode or cognition processing.

/// Opt-in activity/sentinel sampling with exact source-linked inclusion and skip receipts.
pub mod activity;
/// Complete, restart-reproducible detector/tracker reports over retained recordings.
pub mod analysis;
pub mod annexb;
/// Owner, approval-gated adoption of a site calibration per camera, retained as authority.
pub mod calibration_adoption;
/// Cross-camera association of tracked objects via time and geometry gates.
pub mod cross_camera;
/// Explicit model-output decoding and source-linked detector proposals.
pub mod detections;
/// Zone-gated event generation from confirmed tracks into the event plane.
pub mod eventgen;
pub mod file_adapter;
/// Deterministic scene-model foreground detection on decoded luma planes.
pub mod foreground;
/// Geometric (frustum and scene-mesh occlusion) visibility of owner ground-plane zones.
pub mod ground_visibility;
/// Bounded H.265/HEVC Annex-B access-unit splitting with exact source spans.
pub mod hevc_annexb;
/// Exact frozen-model execution on retained decoded frames and durable model outputs.
pub mod inference;
pub mod mjpeg;
/// Offline source-preserving conversion of exact tensor weights into recorded models.
pub mod model_import;
/// Bounded, source-gap-aware pixel-change measurements over recorded frames.
pub mod pixel_change;
/// Owner-declared, approval-gated per-sensor privacy masks applied at retained decode.
pub mod privacy_mask;
/// Two-sensor ground-zone entries associated under explicit gates into corroborated events.
pub mod recorded_corroboration;
/// Retained per-(sensor, zone, interval) coverage witnesses of the recorded pipelines.
pub mod recorded_coverage;
/// Canonical JPEG decoding and durable source-linked luma publications.
pub mod recorded_decode;
/// Durable unresolved event candidates from exact replayed analysis reports.
pub mod recorded_event;
/// Model-free decode→foreground→Kalman→zone candidates with exact-approval publication.
pub mod recorded_watch;
/// Bounded recording-to-model-to-analysis execution with verified restart reuse.
pub mod recording_pipeline;
/// Restart-safe recovery and verified reads of completed file imports.
pub mod retained;
/// Bounded recorded-RTP framing and source-preserving ingest.
pub mod rtpdump;
/// Owner site calibration: atlas localization, joint refinement, digest-bound record.
pub mod site_calibration;
/// Opt-in decode refusals as typed coverage gaps with IDR/IRAP resumption.
pub mod tolerant_decode;
/// Constant-velocity Kalman filter tracker with IoU-based data association.
pub mod tracker;
/// Bounded, history-linked, single-camera association of detector proposals.
pub mod tracking;

pub use annexb::{
    AnnexBAccessUnit, AnnexBError, AnnexBLimits, AnnexBNal, AnnexBScan, CEILING_MAX_NAL_BYTES,
    DEFAULT_MAX_AUS, DEFAULT_MAX_INPUT_BYTES, DEFAULT_MAX_NAL_BYTES, DEFAULT_MAX_NALS, SourceSpan,
    split_annexb,
};
pub use file_adapter::{
    ADP_FILE_GENERATION, ADP_FILE_ROW_ID, CaptureHint, DEFAULT_CHUNK_BYTES, DetectedFileFormat,
    FILE_IMPORT_MANIFEST_SCHEMA, FileFormatHint, FileImportManifest, FileIngestAdapter,
    FileIngestError, FileIngestLimits, FileIngestOutcome, FileIngestReceipt, FileIngestRequest,
    FileOmissionSpan, MAX_BATCH_DELTAS, SegmentSpan, compute_import_identity,
    default_adapter_identity, fetch_segment_bytes, sniff_format, sniff_format_with_hint,
};
pub use hevc_annexb::{HEVC_AU_GROUPING, HevcAccessUnit, HevcNal, HevcScan, split_hevc_annexb};
pub use mjpeg::{
    JpegFinding, JpegFrameSpan, JpegProcess, JpegScan, JpegSofInfo, JpegSplitError, MjpegLimits,
    OmissionReason, OmissionSpan, split_jpeg_stream,
};
pub use retained::{RetainedFileImport, RetainedReadLimits};

/// Native JPEG RGB through privacy projection, resize and frozen neural graph execution.
pub mod rgb_inference;

/// Actual RGB dense heads to complete source-space, privacy-screened detector proposals.
pub mod rgb_detections;

/// Source-bound RGB class trajectories and observed image-zone events.
pub mod rgb_tracking;

/// Native, explicit-authority HTTP MJPEG with raw-read custody backpressure.
pub mod http_camera;

/// Durable original HTTP reads and exact, source-verified cold prefix recovery.
pub mod http_archive;

/// Source-closed RGB perception evidence with actual native replay after restart.
pub mod rgb_evidence;

/// Opt-in decodable synthetic MJPEG sources with bounded fragmentation and custody.
pub mod virtual_mjpeg;

/// Durable original RGB evidence and exact native replay after a cold restart.
pub mod rgb_archive;

/// Exact retained HTTP prefixes through the native HTTP/MJPEG parsers, without invented EOF.
pub mod http_replay;

/// Explicit native recording with durable-before-parse custody and cold-replay completion.
pub mod http_recording;

/// Exclusive durable HTTP recording through native RGB inference, anonymous tracks and zones.
pub mod http_rgb_recording;

/// Digest-pinned offline RGB detector packages loaded only through verification.
pub mod rgb_package;

/// Retained recordings through a verified RGB detector package into source-space proposals.
pub mod package_detect;

/// Detection cascade: cheap-gate-selected frames through a verified detector package.
pub mod detector_cascade;

/// Retained package detections tracked into unresolved recorded events (report/prepare/publish).
pub mod package_event;

/// Opt-in, source-bound visual-degradation screening before recorded watch publication.
pub mod sensor_health;

/// Live native results released only after source-closed detector evidence is ledgered.
pub mod http_rgb_evidence;

/// Cold native detector/temporal replay checked against exact HTTP evidence pins.
pub mod http_rgb_evidence_replay;

/// Durable ordered HTTP/RGB history with complete temporal replay configuration.
pub mod http_rgb_history;

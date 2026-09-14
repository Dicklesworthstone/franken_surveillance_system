//! Ingest adapters and stream framing utilities.
//!
//! Provides deterministic stream framing, marker validation, and source custody accounting
//! for incoming media streams before decode or cognition processing.

pub mod annexb;
pub mod file_adapter;
pub mod mjpeg;

pub use annexb::{
    AnnexBAccessUnit, AnnexBError, AnnexBLimits, AnnexBNal, AnnexBScan, CEILING_MAX_NAL_BYTES,
    DEFAULT_MAX_AUS, DEFAULT_MAX_INPUT_BYTES, DEFAULT_MAX_NAL_BYTES, DEFAULT_MAX_NALS, SourceSpan,
    split_annexb,
};
pub use file_adapter::{
    ADP_FILE_GENERATION, ADP_FILE_ROW_ID, CAPTURE_TIME_OPERATOR_ASSUMPTION, CAPTURE_TIME_UNKNOWN,
    CaptureHint, DEFAULT_CHUNK_BYTES, DetectedFileFormat, FILE_IMPORT_IDENTITY_DOMAIN,
    FILE_IMPORT_MANIFEST_SCHEMA, FILE_INGEST_LIMITS_DOMAIN, FileFormatHint, FileImportManifest,
    FileIngestAdapter, FileIngestError, FileIngestLimits, FileIngestOutcome, FileIngestReceipt,
    FileIngestRequest, FileOmissionSpan, MAX_BATCH_DELTAS, SENSOR_CAPSULE_CUSTODY_DOMAIN,
    SegmentSpan, UNKNOWN_CAPTURE_EARLIEST, capsule_custody_bytes, compute_import_identity,
    decode_capsule_custody_bytes, default_adapter_identity, fetch_segment_bytes, sniff_format,
};
pub use mjpeg::{
    JpegFinding, JpegFrameSpan, JpegProcess, JpegScan, JpegSofInfo, JpegSplitError, MjpegLimits,
    OmissionReason, OmissionSpan, split_jpeg_stream,
};

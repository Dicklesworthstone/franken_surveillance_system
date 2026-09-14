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
    compute_import_identity, default_adapter_identity, sniff_format, CaptureHint,
    DetectedFileFormat, FileFormatHint, FileImportManifest, FileIngestAdapter, FileIngestError,
    FileIngestLimits, FileIngestOutcome, FileIngestReceipt, FileIngestRequest, FileOmissionSpan,
    SegmentSpan, ADP_FILE_GENERATION, ADP_FILE_ROW_ID, DEFAULT_CHUNK_BYTES,
    FILE_IMPORT_MANIFEST_SCHEMA,
};
pub use mjpeg::{
    JpegFinding, JpegFrameSpan, JpegProcess, JpegScan, JpegSofInfo, JpegSplitError, MjpegLimits,
    OmissionReason, OmissionSpan, split_jpeg_stream,
};

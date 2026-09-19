//! Ingest adapters and stream framing utilities.
//!
//! Provides deterministic stream framing, marker validation, and source custody accounting
//! for incoming media streams before decode or cognition processing.

pub mod annexb;
pub mod file_adapter;
pub mod mjpeg;
/// Restart-safe recovery and verified reads of completed file imports.
pub mod retained;
/// Canonical JPEG decoding and durable source-linked luma publications.
pub mod recorded_decode;
/// Bounded, source-gap-aware pixel-change measurements over recorded frames.
pub mod pixel_change;
/// Exact frozen-model execution on retained decoded frames and durable model outputs.
pub mod inference;
/// Explicit model-output decoding and source-linked detector proposals.
pub mod detections;
/// Bounded, history-linked, single-camera association of detector proposals.
pub mod tracking;
/// Bounded recorded-RTP framing and source-preserving ingest.
pub mod rtpdump;

pub use annexb::{
    AnnexBAccessUnit, AnnexBError, AnnexBLimits, AnnexBNal, AnnexBScan, CEILING_MAX_NAL_BYTES,
    DEFAULT_MAX_AUS, DEFAULT_MAX_INPUT_BYTES, DEFAULT_MAX_NAL_BYTES, DEFAULT_MAX_NALS, SourceSpan,
    split_annexb,
};
pub use file_adapter::{
    ADP_FILE_GENERATION, ADP_FILE_ROW_ID, CaptureHint, DEFAULT_CHUNK_BYTES, DetectedFileFormat,
    FILE_IMPORT_MANIFEST_SCHEMA, FileFormatHint, FileImportManifest, FileIngestAdapter,
    FileIngestError, FileIngestLimits, FileIngestOutcome, FileIngestReceipt, FileIngestRequest,
    FileOmissionSpan, SegmentSpan, compute_import_identity, default_adapter_identity,
    fetch_segment_bytes, sniff_format,
};
pub use mjpeg::{
    JpegFinding, JpegFrameSpan, JpegScan, JpegSofInfo, JpegSplitError, MjpegLimits,
    OmissionReason, OmissionSpan, split_jpeg_stream,
    JpegProcess,
};
pub use retained::{RetainedFileImport, RetainedReadLimits};

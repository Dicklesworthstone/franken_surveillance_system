//! Ingest adapters and stream framing utilities.
//!
//! Provides deterministic stream framing, marker validation, and source custody accounting
//! for incoming media streams before decode or cognition processing.

pub mod annexb;
pub mod mjpeg;

pub use annexb::{
    AnnexBAccessUnit, AnnexBError, AnnexBLimits, AnnexBNal, AnnexBScan, CEILING_MAX_NAL_BYTES,
    DEFAULT_MAX_AUS, DEFAULT_MAX_INPUT_BYTES, DEFAULT_MAX_NAL_BYTES, DEFAULT_MAX_NALS, SourceSpan,
    split_annexb,
};
pub use mjpeg::{
    JpegFinding, JpegFrameSpan, JpegProcess, JpegScan, JpegSofInfo, JpegSplitError, MjpegLimits,
    OmissionReason, OmissionSpan, split_jpeg_stream,
};

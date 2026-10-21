#![forbid(unsafe_code)]
//! Whole-recording, motion-independent native detector bursts.
//!
//! Sampling depends only on the retained source coordinates and an explicit finite allowance.
//! Quiet footage can therefore reach the same verified detector as foreground-selected footage.
//! Each completed contiguous burst is an ordinary package-detection report; separate bursts
//! never form one continuous track. Unsampled segments and budget-skipped bursts establish
//! neither absence nor coverage, and computation grants no event or effect authority.
//!
//! One source-read allowance, pixel account, JPEG budget, and detection-head budget cover the
//! complete operation. MJPEG reads only admitted frames. AVC/HEVC decode the requested range
//! once, including the tail after the last inference, while converting only selected frames to
//! RGB. A source/decode gap, missing selected picture, cancellation, or resource refusal rejects
//! the whole computation. Existing short sentinel schedules and report bytes are unchanged.

mod execution;
mod plan;
mod recipe;
mod report;
/// Source-closed aggregate retention and exact native recomputation.
pub mod retained;

pub use execution::run_long_sentinel_detection;
pub use plan::{
    LongSentinelConfig, LongSentinelLimits, LongSentinelPlan, LongSentinelRange,
    LongSentinelRequest, LongSentinelReservation, MAX_LONG_SENTINEL_PIXEL_SAMPLES,
    MAX_LONG_SENTINEL_REPORT_BYTES, MAX_LONG_SENTINEL_SOURCE_CHUNK_BYTES,
};
pub use report::{LongSentinelReport, LongSentinelUsage};

/// Versioned whole-recording report; child package reports retain their own existing schema.
pub const LONG_SENTINEL_REPORT_SCHEMA: &str = "fss.long_sentinel_detection_report.v1";
/// Exact source-coordinate sampling and strict execution policy.
pub const LONG_SENTINEL_POLICY: &str = "fss.long_sentinel_policy.v1:relative-segment-period:whole-burst-prefix:motion-independent:strict-whole-video-drain:separate-pre-admitted-video-axes:selected-only-jpeg:pre-admitted-jpeg-raster:no-gap-bridging";

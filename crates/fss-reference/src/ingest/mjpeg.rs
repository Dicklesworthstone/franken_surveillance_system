//! Bounded MJPEG and JPEG frame splitter.
//!
//! Provides deterministic marker-aware framing (`SOI` `0xFFD8` .. `EOI` `0xFFD9`),
//! exact source custody spans, byte-stuffing (`0xFF00`) and restart marker (`0xFFD0`..=`0xFFD7`)
//! handling, and typed refusals for truncation, garbage, dimension limits, and oversize streams.
//!
//! Conforms to ITU-T T.81 (ISO/IEC 10918-1) marker segmentation rules without external dependencies.

use crate::adapter_replay::{ReplayAdapterError, ReplayCx};

/// Bounded limits enforced during MJPEG and JPEG stream scanning.
///
/// Every limit is checked before or during scanning to prevent unbounded memory allocation
/// or CPU expenditure on hostile or malformed inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MjpegLimits {
    /// Maximum total bytes in the input buffer.
    pub max_input_bytes: usize,
    /// Maximum byte length permitted for a single frame.
    pub max_frame_bytes: usize,
    /// Maximum number of frames permitted in a single stream scan.
    pub max_frames: usize,
    /// Maximum number of marker segments permitted per frame.
    pub max_marker_segments_per_frame: usize,
    /// Maximum width or height permitted in pixels (rejects at SOF read before any decode allocation).
    pub max_dimension: u32,
}

impl Default for MjpegLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024 * 1024, // 64 MiB
            max_frame_bytes: 16 * 1024 * 1024, // 16 MiB
            max_frames: 10_000,
            max_marker_segments_per_frame: 256,
            max_dimension: 16384,
        }
    }
}

/// JPEG encoding process identified by the Start of Frame (SOFn) marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JpegProcess {
    /// Baseline DCT (SOF0, 0xFFC0).
    Baseline,
    /// Extended Sequential DCT, Huffman coding (SOF1, 0xFFC1).
    ExtendedSequential,
    /// Progressive DCT, Huffman coding (SOF2, 0xFFC2).
    Progressive,
    /// Lossless sequential, Huffman coding (SOF3, 0xFFC3).
    Lossless,
    /// Differential sequential DCT, Huffman coding (SOF5, 0xFFC5).
    DifferentialSequential,
    /// Differential progressive DCT, Huffman coding (SOF6, 0xFFC6).
    DifferentialProgressive,
    /// Differential lossless, Huffman coding (SOF7, 0xFFC7).
    DifferentialLossless,
    /// Other SOFn marker code (e.g. arithmetic coding SOF9..SOF15).
    Other(u8),
}

impl JpegProcess {
    /// Identifies the JPEG process from a SOFn marker code byte (the byte following `0xFF`).
    #[must_use]
    pub const fn from_sof_marker(marker: u8) -> Self {
        match marker {
            0xC0 => Self::Baseline,
            0xC1 => Self::ExtendedSequential,
            0xC2 => Self::Progressive,
            0xC3 => Self::Lossless,
            0xC5 => Self::DifferentialSequential,
            0xC6 => Self::DifferentialProgressive,
            0xC7 => Self::DifferentialLossless,
            other => Self::Other(other),
        }
    }

    /// Returns `true` if this process is standard baseline DCT (SOF0).
    #[must_use]
    pub const fn is_baseline(&self) -> bool {
        matches!(self, Self::Baseline)
    }

    /// Returns `true` if this process is progressive DCT (SOF2).
    #[must_use]
    pub const fn is_progressive(&self) -> bool {
        matches!(self, Self::Progressive)
    }
}

/// Metadata extracted from a Start of Frame (SOFn) marker segment without full decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JpegSofInfo {
    /// Process family inferred from marker code.
    pub process: JpegProcess,
    /// Raw SOFn marker byte (e.g. `0xC0` for SOF0).
    pub marker: u8,
    /// Sample precision in bits per sample (typically 8, or 12 for high-bit-depth JPEG).
    pub precision: u8,
    /// Image height in pixels (number of lines, big-endian u16).
    pub height: u16,
    /// Image width in pixels (samples per line, big-endian u16).
    pub width: u16,
    /// Number of image components in frame (e.g. 1 for grayscale, 3 for YCbCr, 4 for CMYK).
    pub components: u8,
}

/// Exact byte span of a single JPEG frame in the input stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JpegFrameSpan {
    /// 0-based index of this frame within the stream.
    pub frame_index: usize,
    /// Byte offset of the first SOI byte (`0xFF`) in the stream.
    pub start_offset: usize,
    /// Byte offset immediately following the last byte of this frame.
    ///
    /// For complete frames, this includes the terminating EOI (`0xFFD9`).
    /// For truncated frames, this is the position where the frame ended or stream terminated.
    pub end_offset: usize,
    /// Frame header metadata, if an SOFn segment was encountered.
    pub sof: Option<JpegSofInfo>,
    /// Restart interval in MCUs specified by DRI (`0xFFDD`), or 0 if none.
    pub restart_interval: u16,
    /// Whether the frame completed with a terminating `0xFFD9` (EOI) marker.
    pub has_eoi: bool,
    /// Whether the frame was truncated before a valid EOI marker was observed.
    pub is_truncated: bool,
    /// Count of marker segments parsed in this frame.
    pub marker_count: usize,
}

impl JpegFrameSpan {
    /// Byte length of this frame span.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end_offset.saturating_sub(self.start_offset)
    }

    /// Returns `true` if the byte span is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the exact slice of source bytes for this frame from the original input.
    #[must_use]
    pub fn slice<'a>(&self, bytes: &'a [u8]) -> Option<&'a [u8]> {
        bytes.get(self.start_offset..self.end_offset)
    }
}

/// Categorized reason for an omission span in the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OmissionReason {
    /// Non-JPEG bytes preceding the first SOI marker in the stream.
    GarbageBeforeFirstSoi,
    /// Non-JPEG bytes or transport framing between two adjacent JPEG frames.
    GarbageBetweenFrames,
    /// Non-JPEG bytes trailing the last EOI marker in the stream.
    TrailingGarbage,
}

/// Record of an omitted (non-frame) byte span in the input stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmissionSpan {
    /// Start byte offset of omitted data (inclusive).
    pub start_offset: usize,
    /// End byte offset of omitted data (exclusive).
    pub end_offset: usize,
    /// Categorized reason for this omission.
    pub reason: OmissionReason,
}

impl OmissionSpan {
    /// Byte length of the omitted span.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end_offset.saturating_sub(self.start_offset)
    }

    /// Returns `true` if the omitted span is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the omitted byte slice from the input stream.
    #[must_use]
    pub fn slice<'a>(&self, bytes: &'a [u8]) -> Option<&'a [u8]> {
        bytes.get(self.start_offset..self.end_offset)
    }
}

/// Typed findings emitted during stream scanning for non-fatal anomalies, omissions, and truncations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JpegFinding {
    /// Garbage bytes detected before the first SOI marker.
    GarbageBeforeFirstSoi {
        /// Start byte offset of garbage data (inclusive).
        start_offset: usize,
        /// End byte offset of garbage data (exclusive).
        end_offset: usize,
    },
    /// Garbage bytes detected between two consecutive frames.
    GarbageBetweenFrames {
        /// 0-based index of the frame immediately preceding this garbage span.
        preceding_frame_index: usize,
        /// Start byte offset of garbage data (inclusive).
        start_offset: usize,
        /// End byte offset of garbage data (exclusive).
        end_offset: usize,
    },
    /// Garbage bytes detected after the final EOI marker.
    TrailingGarbage {
        /// Start byte offset of trailing garbage (inclusive).
        start_offset: usize,
        /// End byte offset of trailing garbage (exclusive).
        end_offset: usize,
    },
    /// Frame truncated without a terminating EOI marker.
    TruncatedFrame {
        /// 0-based index of the truncated frame.
        frame_index: usize,
        /// Start byte offset of truncated frame in input.
        start_offset: usize,
        /// End byte offset where data ended.
        end_offset: usize,
    },
    /// Marker segment declared with an empty or sub-minimal payload length (< 2).
    ZeroLengthMarkerSegment {
        /// 0-based frame index containing the segment.
        frame_index: usize,
        /// Marker code byte.
        marker: u8,
        /// Byte offset of marker in input.
        offset: usize,
    },
    /// SOF marker declared with 0 components.
    ZeroComponents {
        /// 0-based frame index containing the SOF.
        frame_index: usize,
        /// Byte offset of SOF marker in input.
        offset: usize,
    },
    /// Multiple SOF markers encountered in a single frame.
    DuplicateSof {
        /// 0-based frame index containing duplicate SOF.
        frame_index: usize,
        /// Byte offset of duplicate SOF marker in input.
        offset: usize,
    },
}

impl JpegFinding {
    /// Returns `true` if this finding represents a frame truncation.
    #[must_use]
    pub const fn is_truncation(&self) -> bool {
        matches!(self, Self::TruncatedFrame { .. })
    }

    /// Returns `true` if this finding represents an omitted byte span.
    #[must_use]
    pub const fn is_omission(&self) -> bool {
        matches!(
            self,
            Self::GarbageBeforeFirstSoi { .. }
                | Self::GarbageBetweenFrames { .. }
                | Self::TrailingGarbage { .. }
        )
    }
}

/// Result of scanning a JPEG or MJPEG stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JpegScan {
    /// All detected frame spans (complete and truncated).
    pub frames: Vec<JpegFrameSpan>,
    /// All omitted byte spans (inter-frame garbage, headers, trailing bytes).
    pub omissions: Vec<OmissionSpan>,
    /// Typed findings recorded during scanning.
    pub findings: Vec<JpegFinding>,
    /// Total bytes scanned in the input buffer.
    pub total_bytes_scanned: usize,
}

impl JpegScan {
    /// Total count of frames detected (including truncated frames).
    #[must_use]
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    /// Count of valid, non-truncated frames with EOI.
    #[must_use]
    pub fn valid_frame_count(&self) -> usize {
        self.frames
            .iter()
            .filter(|f| !f.is_truncated && f.has_eoi)
            .count()
    }

    /// Returns `true` if any frame in the stream was truncated.
    #[must_use]
    pub fn has_truncation(&self) -> bool {
        self.frames.iter().any(|f| f.is_truncated)
    }

    /// Returns `true` if any omissions were recorded.
    #[must_use]
    pub fn has_omissions(&self) -> bool {
        !self.omissions.is_empty()
    }
}

/// Typed errors returned when a JPEG/MJPEG stream violates invariant limits or cannot be split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JpegSplitError {
    /// Input buffer contained no SOI marker (`0xFFD8`).
    NoSoi,
    /// A marker segment declared a 16-bit length exceeding the available remaining bytes.
    MarkerLengthOverflow {
        /// Byte offset of the offending marker prefix.
        offset: usize,
        /// Offending marker byte code.
        marker: u8,
        /// Declared segment length in bytes.
        length: usize,
        /// Available remaining bytes in input buffer.
        available: usize,
    },
    /// Stream exceeded the configured maximum frame count limit.
    TooManyFrames {
        /// Number of frames observed when limit was hit.
        count: usize,
        /// Configured frame count limit.
        limit: usize,
    },
    /// A single frame exceeded the configured maximum frame byte limit.
    FrameTooLarge {
        /// 0-based frame index that exceeded the limit.
        frame_index: usize,
        /// Size of frame observed in bytes.
        size: usize,
        /// Configured maximum frame size in bytes.
        limit: usize,
    },
    /// A single frame exceeded the configured maximum marker segment count.
    TooManyMarkerSegments {
        /// 0-based frame index exceeding segment count.
        frame_index: usize,
        /// Observed marker segment count.
        count: usize,
        /// Configured marker segment count limit.
        limit: usize,
    },
    /// Frame width or height exceeded the configured maximum dimension limit.
    DimensionLimit {
        /// Observed frame width in pixels.
        width: u16,
        /// Observed frame height in pixels.
        height: u16,
        /// Configured maximum dimension in pixels.
        max_dimension: u32,
    },
    /// Total input buffer size exceeded the configured maximum input limit.
    InputOversized {
        /// Observed input size in bytes.
        size: usize,
        /// Configured maximum input limit in bytes.
        limit: usize,
    },
    /// Cooperative cancellation was requested during splitting.
    CancellationRequested,
}

impl std::fmt::Display for JpegSplitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSoi => write!(f, "no SOI (0xFFD8) marker found in input stream"),
            Self::MarkerLengthOverflow {
                offset,
                marker,
                length,
                available,
            } => {
                write!(
                    f,
                    "marker 0xFF{:02X} at offset {} declares length {} exceeding available {} bytes",
                    marker, offset, length, available
                )
            }
            Self::TooManyFrames { count, limit } => {
                write!(
                    f,
                    "frame count {} exceeds maximum frame limit {}",
                    count, limit
                )
            }
            Self::FrameTooLarge {
                frame_index,
                size,
                limit,
            } => {
                write!(
                    f,
                    "frame {} size {} bytes exceeds maximum frame byte limit {}",
                    frame_index, size, limit
                )
            }
            Self::TooManyMarkerSegments {
                frame_index,
                count,
                limit,
            } => {
                write!(
                    f,
                    "frame {} marker segment count {} exceeds limit {}",
                    frame_index, count, limit
                )
            }
            Self::DimensionLimit {
                width,
                height,
                max_dimension,
            } => {
                write!(
                    f,
                    "frame dimensions {}x{} exceed maximum dimension limit {}",
                    width, height, max_dimension
                )
            }
            Self::InputOversized { size, limit } => {
                write!(
                    f,
                    "input stream size {} bytes exceeds maximum limit {}",
                    size, limit
                )
            }
            Self::CancellationRequested => {
                write!(f, "cancellation requested during JPEG stream split")
            }
        }
    }
}

impl std::error::Error for JpegSplitError {}

impl From<ReplayAdapterError> for JpegSplitError {
    fn from(_err: ReplayAdapterError) -> Self {
        Self::CancellationRequested
    }
}

/// Finds the first SOI marker (`0xFF, 0xD8`), skipping any leading `0xFF` fill bytes.
fn find_soi(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i + 1 < bytes.len() {
        if bytes[i] == 0xFF {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] == 0xFF {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == 0xD8 {
                return Some(i);
            }
            i = j;
        } else {
            i += 1;
        }
    }
    None
}

/// Splits a raw byte stream into discrete JPEG frames with exact source spans and omissions.
///
/// Walks the marker segments according to ITU-T T.81:
/// - Detects `SOI` (`0xFFD8`) and `EOI` (`0xFFD9`) markers.
/// - Skips marker segments with 16-bit lengths, checking bounds before memory allocation.
/// - Extracts width, height, precision, components, and process from `SOFn` without decoding.
/// - Skips entropy-coded segments after `SOS` (`0xFFDA`), treating `0xFF00` as byte stuffing
///   and `0xFFD0`..=`0xFFD7` as restart markers.
/// - Records non-frame bytes between frames or before the first frame as omission spans.
/// - Flags a truncated final frame without an `EOI` as `is_truncated: true` with a typed finding.
///
/// # Errors
///
/// Returns typed [`JpegSplitError`] if:
/// - Input size exceeds `limits.max_input_bytes` ([`JpegSplitError::InputOversized`]).
/// - No `SOI` marker exists anywhere in the input ([`JpegSplitError::NoSoi`]).
/// - Any marker segment length overflows available bytes ([`JpegSplitError::MarkerLengthOverflow`]).
/// - Frame count exceeds `limits.max_frames` ([`JpegSplitError::TooManyFrames`]).
/// - Any single frame exceeds `limits.max_frame_bytes` ([`JpegSplitError::FrameTooLarge`]).
/// - Marker segment count per frame exceeds limit ([`JpegSplitError::TooManyMarkerSegments`]).
/// - Any frame dimension exceeds `limits.max_dimension` ([`JpegSplitError::DimensionLimit`]).
/// - Cancellation is requested via `cx` ([`JpegSplitError::CancellationRequested`]).
pub fn split_jpeg_stream(
    bytes: &[u8],
    limits: &MjpegLimits,
    cx: Option<&ReplayCx>,
) -> Result<JpegScan, JpegSplitError> {
    if bytes.len() > limits.max_input_bytes {
        return Err(JpegSplitError::InputOversized {
            size: bytes.len(),
            limit: limits.max_input_bytes,
        });
    }

    let first_soi = match find_soi(bytes, 0) {
        Some(pos) => pos,
        None => return Err(JpegSplitError::NoSoi),
    };

    let mut frames = Vec::new();
    let mut omissions = Vec::new();
    let mut findings = Vec::new();

    if first_soi > 0 {
        omissions.push(OmissionSpan {
            start_offset: 0,
            end_offset: first_soi,
            reason: OmissionReason::GarbageBeforeFirstSoi,
        });
        findings.push(JpegFinding::GarbageBeforeFirstSoi {
            start_offset: 0,
            end_offset: first_soi,
        });
    }

    let mut current_pos = first_soi;

    while current_pos < bytes.len() {
        if let Some(cx_ref) = cx {
            cx_ref.checkpoint("split_jpeg_stream")?;
        }

        if frames.len() >= limits.max_frames {
            return Err(JpegSplitError::TooManyFrames {
                count: frames.len() + 1,
                limit: limits.max_frames,
            });
        }

        let frame_index = frames.len();
        let frame_start = current_pos;

        // Skip SOI marker: 0xFF..0xFF 0xD8
        while current_pos < bytes.len() && bytes[current_pos] == 0xFF {
            current_pos += 1;
        }
        if current_pos < bytes.len() && bytes[current_pos] == 0xD8 {
            current_pos += 1;
        }

        let mut sof: Option<JpegSofInfo> = None;
        let mut restart_interval: u16 = 0;
        let mut has_eoi = false;
        let mut is_truncated = false;
        let mut marker_count: usize = 0;

        // Marker loop for the current frame
        while current_pos < bytes.len() {
            if current_pos.saturating_sub(frame_start) > limits.max_frame_bytes {
                return Err(JpegSplitError::FrameTooLarge {
                    frame_index,
                    size: current_pos.saturating_sub(frame_start),
                    limit: limits.max_frame_bytes,
                });
            }

            if let Some(cx_ref) = cx {
                cx_ref.checkpoint("split_jpeg_stream")?;
            }

            // Scan until next 0xFF
            while current_pos < bytes.len() && bytes[current_pos] != 0xFF {
                current_pos += 1;
            }

            if current_pos >= bytes.len() {
                is_truncated = true;
                break;
            }

            let marker_prefix = current_pos;

            // Skip fill bytes of 0xFF
            while current_pos < bytes.len() && bytes[current_pos] == 0xFF {
                current_pos += 1;
            }

            if current_pos >= bytes.len() {
                is_truncated = true;
                break;
            }

            let marker_code = bytes[current_pos];
            current_pos += 1;

            if marker_code == 0x00 {
                // Stray stuffing byte outside ECS, continue scan
                continue;
            }

            if marker_code == 0xD8 {
                // New SOI encountered without EOI for current frame: current frame was truncated!
                is_truncated = true;
                current_pos = marker_prefix;
                break;
            }

            if marker_code == 0xD9 {
                // EOI marker terminates this frame
                has_eoi = true;
                is_truncated = false;
                break;
            }

            if marker_code == 0x01 || (0xD0..=0xD7).contains(&marker_code) {
                // Standalone markers without length: TEM (0x01), RST0..RST7 (0xD0..0xD7)
                marker_count += 1;
                continue;
            }

            // Marker with length
            marker_count += 1;
            if marker_count > limits.max_marker_segments_per_frame {
                return Err(JpegSplitError::TooManyMarkerSegments {
                    frame_index,
                    count: marker_count,
                    limit: limits.max_marker_segments_per_frame,
                });
            }

            if current_pos + 2 > bytes.len() {
                return Err(JpegSplitError::MarkerLengthOverflow {
                    offset: marker_prefix,
                    marker: marker_code,
                    length: 0,
                    available: bytes.len().saturating_sub(marker_prefix),
                });
            }

            let declared_length =
                u16::from_be_bytes([bytes[current_pos], bytes[current_pos + 1]]) as usize;

            if declared_length < 2 {
                findings.push(JpegFinding::ZeroLengthMarkerSegment {
                    frame_index,
                    marker: marker_code,
                    offset: marker_prefix,
                });
                current_pos += 2;
                continue;
            }

            if current_pos + declared_length > bytes.len() {
                return Err(JpegSplitError::MarkerLengthOverflow {
                    offset: marker_prefix,
                    marker: marker_code,
                    length: declared_length,
                    available: bytes.len().saturating_sub(current_pos),
                });
            }

            let is_sof = matches!(
                marker_code,
                0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF
            );

            if is_sof {
                if sof.is_some() {
                    findings.push(JpegFinding::DuplicateSof {
                        frame_index,
                        offset: marker_prefix,
                    });
                } else if declared_length >= 8 {
                    let precision = bytes[current_pos + 2];
                    let height =
                        u16::from_be_bytes([bytes[current_pos + 3], bytes[current_pos + 4]]);
                    let width =
                        u16::from_be_bytes([bytes[current_pos + 5], bytes[current_pos + 6]]);
                    let components = bytes[current_pos + 7];

                    if (width as u32) > limits.max_dimension
                        || (height as u32) > limits.max_dimension
                    {
                        return Err(JpegSplitError::DimensionLimit {
                            width,
                            height,
                            max_dimension: limits.max_dimension,
                        });
                    }

                    if components == 0 {
                        findings.push(JpegFinding::ZeroComponents {
                            frame_index,
                            offset: marker_prefix,
                        });
                    }

                    sof = Some(JpegSofInfo {
                        process: JpegProcess::from_sof_marker(marker_code),
                        marker: marker_code,
                        precision,
                        height,
                        width,
                        components,
                    });
                }
                current_pos += declared_length;
            } else if marker_code == 0xDD {
                // DRI (Define Restart Interval)
                if declared_length >= 4 {
                    restart_interval =
                        u16::from_be_bytes([bytes[current_pos + 2], bytes[current_pos + 3]]);
                }
                current_pos += declared_length;
            } else if marker_code == 0xDA {
                // SOS (Start of Scan)
                current_pos += declared_length;

                // Scan Entropy Coded Segment (ECS)
                while current_pos < bytes.len() {
                    if current_pos.saturating_sub(frame_start) > limits.max_frame_bytes {
                        return Err(JpegSplitError::FrameTooLarge {
                            frame_index,
                            size: current_pos.saturating_sub(frame_start),
                            limit: limits.max_frame_bytes,
                        });
                    }

                    if let Some(cx_ref) = cx
                        && current_pos % 65536 == 0
                    {
                        cx_ref.checkpoint("split_jpeg_stream")?;
                    }

                    if bytes[current_pos] != 0xFF {
                        current_pos += 1;
                        continue;
                    }

                    let ecs_ff = current_pos;
                    current_pos += 1;

                    while current_pos < bytes.len() && bytes[current_pos] == 0xFF {
                        current_pos += 1;
                    }

                    if current_pos >= bytes.len() {
                        is_truncated = true;
                        break;
                    }

                    let ecs_marker = bytes[current_pos];
                    current_pos += 1;

                    if ecs_marker == 0x00 {
                        // Byte stuffing: 0xFF00 represents raw 0xFF in entropy stream
                        continue;
                    }

                    if (0xD0..=0xD7).contains(&ecs_marker) {
                        // Restart marker inside ECS
                        continue;
                    }

                    // Any other marker ends the ECS
                    current_pos = ecs_ff;
                    break;
                }

                if current_pos >= bytes.len() && !has_eoi {
                    is_truncated = true;
                    break;
                }
            } else {
                // All other marker segments with length (DHT, DQT, APPn, COM, etc.)
                current_pos += declared_length;
            }
        }

        let frame_end = current_pos;
        let frame_size = frame_end.saturating_sub(frame_start);
        if frame_size > limits.max_frame_bytes {
            return Err(JpegSplitError::FrameTooLarge {
                frame_index,
                size: frame_size,
                limit: limits.max_frame_bytes,
            });
        }

        if is_truncated {
            findings.push(JpegFinding::TruncatedFrame {
                frame_index,
                start_offset: frame_start,
                end_offset: frame_end,
            });
        }

        frames.push(JpegFrameSpan {
            frame_index,
            start_offset: frame_start,
            end_offset: frame_end,
            sof,
            restart_interval,
            has_eoi,
            is_truncated,
            marker_count,
        });

        if is_truncated {
            // If the frame was truncated because of a new SOI mid-stream, we loop to process that SOI;
            // if it was truncated by reaching EOF, current_pos == bytes.len() and loop terminates.
            continue;
        }

        // Search for the next frame's SOI
        if current_pos < bytes.len() {
            match find_soi(bytes, current_pos) {
                Some(next_soi) => {
                    if next_soi > current_pos {
                        omissions.push(OmissionSpan {
                            start_offset: current_pos,
                            end_offset: next_soi,
                            reason: OmissionReason::GarbageBetweenFrames,
                        });
                        findings.push(JpegFinding::GarbageBetweenFrames {
                            preceding_frame_index: frame_index,
                            start_offset: current_pos,
                            end_offset: next_soi,
                        });
                    }
                    current_pos = next_soi;
                }
                None => {
                    omissions.push(OmissionSpan {
                        start_offset: current_pos,
                        end_offset: bytes.len(),
                        reason: OmissionReason::TrailingGarbage,
                    });
                    findings.push(JpegFinding::TrailingGarbage {
                        start_offset: current_pos,
                        end_offset: bytes.len(),
                    });
                    current_pos = bytes.len();
                }
            }
        }
    }

    Ok(JpegScan {
        frames,
        omissions,
        findings,
        total_bytes_scanned: bytes.len(),
    })
}

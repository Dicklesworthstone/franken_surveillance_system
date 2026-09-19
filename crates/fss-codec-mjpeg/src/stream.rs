#![forbid(unsafe_code)]
//! Incremental framing of a contiguous concatenation of complete JPEG images.
//!
//! Segment lengths protect embedded marker-like metadata bytes. Entropy stuffing
//! and restart markers are handled structurally; only `decode_luma` validates
//! coding tables, coefficients and reconstructed samples. This is not HTTP/UVC.

use crate::{
    ComponentInterpretation, DecodeBudget, DecodeError, DecodeLimits, DecodedLuma, decode_luma,
};
use fss_core::ContentDigest;

/// Exact owner-resolved input stream. Neither field establishes access or custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamBasis {
    /// Retained source/capture-stream record, not a generated camera timestamp.
    pub source: [u8; 32],
    /// Nonzero owner-issued generation; discontinuities require another generation.
    pub generation: u64,
}

/// Narrowable framing limits; one frame is buffered, never a complete live stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FramingLimits {
    /// Maximum bytes in an individual frame, with a hard ceiling of 16 MiB.
    pub maximum_frame_bytes: usize,
    /// Maximum non-restart markers per frame, with a hard ceiling of 4096.
    pub maximum_markers: usize,
}
impl Default for FramingLimits {
    fn default() -> Self {
        Self {
            maximum_frame_bytes: 16 * 1024 * 1024,
            maximum_markers: 4096,
        }
    }
}

/// Terminal framing failures. Restart requires explicit owner reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FramingError {
    /// Invalid basis or configured limits.
    InvalidInput,
    /// The caller attempted to replay, omit or reorder stream bytes.
    OffsetMismatch,
    /// Invalid structural marker, marker length, or missing scan.
    Malformed,
    /// A reserved marker has no admitted structural interpretation.
    UnsupportedMarker,
    /// End of source before the buffered image was complete.
    Truncated,
    /// Frame, marker, allocation, absolute offset or ordinal limit.
    Limit,
    /// The owner ended or aborted this stream.
    Closed,
    /// A previous failure latched; do not resume from a guessed offset.
    Poisoned,
    /// The shared decoding work/cancellation boundary failed.
    Work(DecodeError),
}
impl std::fmt::Display for FramingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid JPEG stream configuration",
            Self::OffsetMismatch => "JPEG stream input offset mismatch",
            Self::Malformed => "malformed JPEG stream framing",
            Self::UnsupportedMarker => "unsupported JPEG structural marker",
            Self::Truncated => "JPEG stream ended within a frame",
            Self::Limit => "JPEG framing resource or sequence limit",
            Self::Closed => "JPEG stream is closed",
            Self::Poisoned => "JPEG stream has a prior terminal failure",
            Self::Work(_) => "JPEG stream work interrupted",
        })
    }
}
impl std::error::Error for FramingError {}

/// An input failure with the exact consumed prefix, never a successful partial frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamFailure {
    /// Root failure for this call. The first failure remains on the stream.
    pub error: FramingError,
    /// Bytes accepted from this call's slice, excluding its unconsumed suffix.
    pub consumed: usize,
    /// Absolute next source offset; includes any rejected structural marker read.
    pub next_offset: u64,
}
impl std::fmt::Display for StreamFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.error, f)
    }
}
impl std::error::Error for StreamFailure {}

/// One complete framed byte range. It is NOT yet a validated decoded image.
pub struct FramedJpeg {
    basis: StreamBasis,
    ordinal: u64,
    range: [u64; 2],
    bytes: Vec<u8>,
    digest: [u8; 32],
    markers: usize,
}
impl std::fmt::Debug for FramedJpeg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FramedJpeg")
            .field("ordinal", &self.ordinal)
            .field("byte_count", &self.bytes.len())
            .finish_non_exhaustive()
    }
}
impl FramedJpeg {
    /// Exact source generation supplied at construction.
    pub fn basis(&self) -> StreamBasis {
        self.basis
    }
    /// One-based frame ordinal within this stream generation.
    pub fn ordinal(&self) -> u64 {
        self.ordinal
    }
    /// Half-open source-byte range, including SOI and EOI, without skipped bytes.
    pub fn byte_range(&self) -> [u64; 2] {
        self.range
    }
    /// Original encoded bytes, unchanged by framing.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Actual encoded-byte hash; not independent authentication of the input source.
    pub fn encoded_sha256(&self) -> [u8; 32] {
        self.digest
    }
    /// Non-restart marker count, including SOI/EOI.
    pub fn markers(&self) -> usize {
        self.markers
    }
    /// Validate/decode the complete frame using the existing native decoder.
    pub fn decode(
        &self,
        interpretation: ComponentInterpretation,
        limits: DecodeLimits,
        budget: &mut DecodeBudget<'_>,
    ) -> Result<DecodedLuma, DecodeError> {
        decode_luma(&self.bytes, self.digest, interpretation, limits, budget)
    }
}

/// One streaming step stops immediately after one frame; retain the input suffix.
#[derive(Debug)]
pub struct StreamStep {
    /// Exact accepted prefix of the supplied slice. Nonempty input always progresses.
    pub consumed: usize,
    /// Complete source frame, or None when more bytes are required.
    pub frame: Option<FramedJpeg>,
}

/// Explicit clean source termination, not a capture-continuity or coverage witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamEnd {
    /// Exact source record and generation.
    pub basis: StreamBasis,
    /// Complete framed images; zero is allowed for an explicitly empty source.
    pub frames: u64,
    /// Total accepted bytes from offset zero; every byte belongs to a framed image.
    pub bytes: u64,
}

/// Retained incomplete bytes returned by abort; never implicitly decoded or concealed.
pub struct DiscardedFragment {
    /// Exact owner-resolved source generation.
    pub basis: StreamBasis,
    /// Half-open range for these buffered bytes.
    pub byte_range: [u64; 2],
    /// First terminal failure, or None for an explicit operator abort.
    pub reason: Option<FramingError>,
    bytes: Vec<u8>,
}
impl DiscardedFragment {
    /// Original partial source bytes for custody/reconciliation, not a complete frame.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl std::fmt::Debug for DiscardedFragment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscardedFragment")
            .field("byte_count", &self.bytes.len())
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Start,
    Soi,
    MarkerPrefix,
    MarkerCode,
    LengthHigh(u8),
    LengthLow(u8, u8),
    Payload { remaining: usize, scan: bool },
    Entropy,
    EntropyCode { fill: bool },
}

/// Single-owner incremental framer, without threads, I/O, time reads or callbacks.
///
/// Any failure latches before subsequent input. `abort` returns buffered source
/// bytes even after cancellation, without needing more allocation or work budget.
/// Completed earlier frames stay valid framing results when a later frame fails;
/// stream completion is a separate explicit `finish` outcome.
pub struct JpegStream {
    basis: StreamBasis,
    limits: FramingLimits,
    phase: Phase,
    offset: u64,
    start: u64,
    completed: u64,
    markers: usize,
    scanned: bool,
    buffered: Vec<u8>,
    failure: Option<FramingError>,
    closed: bool,
}
impl std::fmt::Debug for JpegStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JpegStream")
            .field("frames", &self.completed)
            .field("buffered_bytes", &self.buffered.len())
            .field("failure", &self.failure)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}
impl JpegStream {
    /// Open a new contiguous stream at byte offset zero; no input is scanned for sync.
    pub fn new(basis: StreamBasis, limits: FramingLimits) -> Result<Self, FramingError> {
        if basis.source == [0; 32]
            || basis.generation == 0
            || !(1..=16 * 1024 * 1024).contains(&limits.maximum_frame_bytes)
            || !(1..=4096).contains(&limits.maximum_markers)
        {
            return Err(FramingError::InvalidInput);
        }
        Ok(Self {
            basis,
            limits,
            phase: Phase::Start,
            offset: 0,
            start: 0,
            completed: 0,
            markers: 0,
            scanned: false,
            buffered: Vec::new(),
            failure: None,
            closed: false,
        })
    }
    /// Exact required offset of the next contiguous input byte.
    pub fn next_offset(&self) -> u64 {
        self.offset
    }
    /// Successful framing count, independent of downstream decode acceptance.
    pub fn completed_frames(&self) -> u64 {
        self.completed
    }
    /// First latched failure; no new input is allowed after it.
    pub fn failure(&self) -> Option<FramingError> {
        self.failure
    }
    /// Current retained incomplete-frame size; never a count of hidden emitted frames.
    pub fn buffered_bytes(&self) -> usize {
        self.buffered.len()
    }

    /// Consume at most one image from an exact-offset input prefix.
    ///
    /// Stop immediately after EOI. The caller must keep `input[step.consumed..]`
    /// and submit it at `next_offset`; no bytes of the next image are inspected.
    /// `None` on empty input is not a clean source end; call `finish` explicitly.
    pub fn push(
        &mut self,
        expected_offset: u64,
        input: &[u8],
        budget: &mut DecodeBudget<'_>,
    ) -> Result<StreamStep, StreamFailure> {
        if self.closed {
            return Err(self.error(FramingError::Closed, 0));
        }
        if self.failure.is_some() {
            return Err(self.error(FramingError::Poisoned, 0));
        }
        if expected_offset != self.offset {
            return Err(self.fail(FramingError::OffsetMismatch, 0));
        }
        if let Err(e) = budget.charge(0) {
            return Err(self.fail(FramingError::Work(e), 0));
        }
        for (index, &byte) in input.iter().enumerate() {
            if let Err(e) = budget.charge(4) {
                return Err(self.fail(FramingError::Work(e), index));
            }
            if self.buffered.len() == self.limits.maximum_frame_bytes {
                return Err(self.fail(FramingError::Limit, index));
            }
            let Some(next) = self.offset.checked_add(1) else {
                return Err(self.fail(FramingError::Limit, index));
            };
            if self.buffered.try_reserve(1).is_err() {
                return Err(self.fail(FramingError::Limit, index));
            }
            self.buffered.push(byte);
            self.offset = next;
            let complete = match self.accept(byte) {
                Ok(value) => value,
                Err(e) => return Err(self.fail(e, index + 1)),
            };
            if complete {
                let Some(ordinal) = self.completed.checked_add(1) else {
                    return Err(self.fail(FramingError::Limit, index + 1));
                };
                if let Err(e) = budget.charge(self.buffered.len() as u64) {
                    return Err(self.fail(FramingError::Work(e), index + 1));
                }
                let digest = ContentDigest::sha256(&self.buffered).bytes();
                if let Err(e) = budget.charge(0) {
                    return Err(self.fail(FramingError::Work(e), index + 1));
                }
                let frame = FramedJpeg {
                    basis: self.basis,
                    ordinal,
                    range: [self.start, self.offset],
                    bytes: std::mem::take(&mut self.buffered),
                    digest,
                    markers: self.markers,
                };
                self.completed = ordinal;
                self.start = self.offset;
                self.markers = 0;
                self.scanned = false;
                self.phase = Phase::Start;
                return Ok(StreamStep {
                    consumed: index + 1,
                    frame: Some(frame),
                });
            }
        }
        if let Err(e) = budget.charge(0) {
            return Err(self.fail(FramingError::Work(e), input.len()));
        }
        Ok(StreamStep {
            consumed: input.len(),
            frame: None,
        })
    }

    /// End only exactly between frames. Network disconnect is not implied clean EOF.
    pub fn finish(&mut self, budget: &mut DecodeBudget<'_>) -> Result<StreamEnd, StreamFailure> {
        if self.closed {
            return Err(self.error(FramingError::Closed, 0));
        }
        if self.failure.is_some() {
            return Err(self.error(FramingError::Poisoned, 0));
        }
        if let Err(e) = budget.charge(0) {
            return Err(self.fail(FramingError::Work(e), 0));
        }
        if self.phase != Phase::Start || !self.buffered.is_empty() {
            return Err(self.fail(FramingError::Truncated, 0));
        }
        self.closed = true;
        Ok(StreamEnd {
            basis: self.basis,
            frames: self.completed,
            bytes: self.offset,
        })
    }

    /// Latch closure and recover unexposed buffered bytes; works after cancellation.
    /// Repeated aborts return an empty fragment without replaying prior source bytes.
    pub fn abort(&mut self) -> DiscardedFragment {
        self.closed = true;
        let fragment = DiscardedFragment {
            basis: self.basis,
            byte_range: [self.start, self.offset],
            reason: self.failure,
            bytes: std::mem::take(&mut self.buffered),
        };
        self.start = self.offset;
        fragment
    }
    fn error(&self, error: FramingError, consumed: usize) -> StreamFailure {
        StreamFailure {
            error,
            consumed,
            next_offset: self.offset,
        }
    }
    fn fail(&mut self, error: FramingError, consumed: usize) -> StreamFailure {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
        self.error(error, consumed)
    }
    fn marker(&mut self, code: u8) -> Result<bool, FramingError> {
        if code == 0 || code == 0xd8 || (0xd0..=0xd7).contains(&code) {
            return Err(FramingError::Malformed);
        }
        self.markers += 1;
        if self.markers > self.limits.maximum_markers {
            return Err(FramingError::Limit);
        }
        if code == 0xd9 {
            return if self.scanned {
                Ok(true)
            } else {
                Err(FramingError::Malformed)
            };
        }
        if code == 1 {
            self.phase = Phase::MarkerPrefix;
            return Ok(false);
        }
        if code < 0xc0 {
            return Err(FramingError::UnsupportedMarker);
        }
        self.phase = Phase::LengthHigh(code);
        Ok(false)
    }
    fn accept(&mut self, byte: u8) -> Result<bool, FramingError> {
        self.phase = match self.phase {
            Phase::Start => {
                if byte != 255 {
                    return Err(FramingError::Malformed);
                }
                Phase::Soi
            }
            Phase::Soi => {
                if byte != 0xd8 {
                    return Err(FramingError::Malformed);
                }
                self.markers = 1;
                Phase::MarkerPrefix
            }
            Phase::MarkerPrefix => {
                if byte != 255 {
                    return Err(FramingError::Malformed);
                }
                Phase::MarkerCode
            }
            Phase::MarkerCode => {
                if byte == 255 {
                    Phase::MarkerCode
                } else {
                    return self.marker(byte);
                }
            }
            Phase::LengthHigh(marker) => Phase::LengthLow(marker, byte),
            Phase::LengthLow(marker, high) => {
                let length = usize::from(u16::from_be_bytes([high, byte]));
                let remaining = length.checked_sub(2).ok_or(FramingError::Malformed)?;
                let scan = marker == 0xda;
                if remaining == 0 {
                    if scan {
                        self.scanned = true;
                        Phase::Entropy
                    } else {
                        Phase::MarkerPrefix
                    }
                } else {
                    Phase::Payload { remaining, scan }
                }
            }
            Phase::Payload { remaining, scan } => {
                if remaining == 1 {
                    if scan {
                        self.scanned = true;
                        Phase::Entropy
                    } else {
                        Phase::MarkerPrefix
                    }
                } else {
                    Phase::Payload {
                        remaining: remaining - 1,
                        scan,
                    }
                }
            }
            Phase::Entropy => {
                if byte == 255 {
                    Phase::EntropyCode { fill: false }
                } else {
                    Phase::Entropy
                }
            }
            Phase::EntropyCode { fill } => match byte {
                255 => Phase::EntropyCode { fill: true },
                0 if !fill => Phase::Entropy,
                0 => return Err(FramingError::Malformed),
                0xd0..=0xd7 => Phase::Entropy,
                _ => return self.marker(byte),
            },
        };
        Ok(false)
    }
}

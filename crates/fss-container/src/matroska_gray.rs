#![forbid(unsafe_code)]
//! Bounded Matroska framing around unchanged packed grayscale pixels.
//!
//! This module creates only small headers. The owner validates and writes exactly
//! [`FrameFraming::payload_bytes`] screened, top-down eight-bit samples after each
//! prefix. There is no color conversion, padding, codec, allocation, or I/O here.
//! Source custody, privacy, pixel hashing, cumulative budgets, display ordering,
//! cancellation, partial-write fencing and durable completion remain with the owner.
//!
//! Uniform playback uses an explicit rational cadence, unrelated to capture intervals or UTC.
//! Frame `n` starts at `floor(n * 1_000_000_000 * denominator / numerator)` ns.
//! Each duration is the difference of consecutive boundaries, so fractional frame
//! periods do not accumulate rounding drift. A finite Cluster holds each frame;
//! its absolute timestamp avoids the Block header's signed 16-bit relative limit.
//! The separate timed configuration uses caller-validated half-open intervals and a declared
//! clip duration. Gaps remain timestamp holes; this does not promise black-frame rendering.

#[path = "matroska_gray/ebml.rs"]
mod ebml;

use ebml::{Buffer, element_len, unsigned_len};

/// Frozen container, sample, timing and bounded-construction profile.
pub const PROFILE: &str = "fss/matroska-gray/1;matroska4-read2;V_UNCOMPRESSED-Y800;gray8-full-range;packed-top-down;timestamp-scale-1ns;absolute-rational-floor;duration-before-block;one-cluster-per-frame;no-lacing-audio-tags-cues;unknown-segment-size";
/// Explicit-interval profile, with a known positive Segment duration in nanoseconds.
pub const TIMED_PROFILE: &str = "fss/matroska-gray-timed/1;matroska4-read2;V_UNCOMPRESSED-Y800;gray8-full-range;packed-top-down;timestamp-scale-1ns;explicit-half-open-intervals;declared-clip-duration;duration-before-block;one-cluster-per-frame;no-lacing-audio-tags-cues;unknown-segment-size";
/// Largest exact integer nanosecond duration admitted by the binary64 Duration field.
pub const MAX_TIMED_DURATION_NS: u64 = 1 << 53;
/// Maximum positive dimension on either axis.
pub const MAX_DIMENSION: u32 = 4096;
/// Maximum unchanged sample bytes in one frame.
pub const MAX_PIXELS: usize = 4_194_304;
/// Maximum frames in one admitted derivative; ordinals are zero-based.
pub const MAX_FRAMES: u64 = 1024;
/// Maximum supplied numerator or denominator, before rational normalization.
pub const MAX_RATE_COMPONENT: u32 = 1_000_000;

const NS_PER_SECOND: u128 = 1_000_000_000;
const APP: &[u8] = b"fss.matroska_gray.v1";

/// Payload-free refusal without pixels, source identifiers or filesystem paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatroskaGrayError {
    /// A playback-rate component is zero or above the explicit profile bound.
    InvalidRate,
    /// A dimension is zero, too large, or produces too many sample bytes.
    InvalidDimensions,
    /// The requested zero-based ordinal is outside 0..1024.
    FrameLimit,
    /// A checked rational boundary or positive duration is unrepresentable.
    Timeline,
    /// The bounded EBML layout cannot be represented in its fixed storage.
    Layout,
}

impl std::fmt::Display for MatroskaGrayError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRate => "invalid bounded Matroska playback rate",
            Self::InvalidDimensions => "invalid bounded Matroska frame dimensions",
            Self::FrameLimit => "Matroska frame ordinal exceeds the profile limit",
            Self::Timeline => "Matroska playback timeline is unrepresentable",
            Self::Layout => "Matroska framing exceeds its bounded layout",
        })
    }
}
impl std::error::Error for MatroskaGrayError {}

/// An operator-selected frames-per-second ratio, stored in lowest terms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlaybackRate {
    numerator: u32,
    denominator: u32,
}

impl PlaybackRate {
    /// Validate both supplied components before reducing their greatest common divisor.
    pub fn new(numerator: u32, denominator: u32) -> Result<Self, MatroskaGrayError> {
        if !(1..=MAX_RATE_COMPONENT).contains(&numerator)
            || !(1..=MAX_RATE_COMPONENT).contains(&denominator)
        {
            return Err(MatroskaGrayError::InvalidRate);
        }
        let (mut divisor, mut remainder) = (numerator, denominator);
        while remainder != 0 {
            (divisor, remainder) = (remainder, divisor % remainder);
        }
        Ok(Self {
            numerator: numerator / divisor,
            denominator: denominator / divisor,
        })
    }

    /// Reduced frames-per-second numerator.
    #[must_use]
    pub const fn numerator(self) -> u32 {
        self.numerator
    }

    /// Reduced frames-per-second denominator.
    #[must_use]
    pub const fn denominator(self) -> u32 {
        self.denominator
    }

    fn boundary(self, ordinal: u64) -> Result<u64, MatroskaGrayError> {
        let numerator = u128::from(ordinal)
            .checked_mul(NS_PER_SECOND)
            .and_then(|value| value.checked_mul(u128::from(self.denominator)))
            .ok_or(MatroskaGrayError::Timeline)?;
        u64::try_from(numerator / u128::from(self.numerator))
            .map_err(|_| MatroskaGrayError::Timeline)
    }
}

/// One immutable grayscale track and its explicit playback cadence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrayMatroskaConfig {
    dimensions: [u32; 2],
    rate: PlaybackRate,
    pixels: usize,
}

impl GrayMatroskaConfig {
    /// Admit tightly packed gray8 dimensions without allocating image storage.
    pub fn new(dimensions: [u32; 2], rate: PlaybackRate) -> Result<Self, MatroskaGrayError> {
        let pixels = checked_pixels(dimensions)?;
        Ok(Self {
            dimensions,
            rate,
            pixels,
        })
    }

    /// Width and height of every frame in this single-track derivative.
    #[must_use]
    pub const fn dimensions(self) -> [u32; 2] {
        self.dimensions
    }

    /// Playback cadence selected by the owner; not inferred source timing.
    #[must_use]
    pub const fn rate(self) -> PlaybackRate {
        self.rate
    }

    /// Build the complete EBML header, open Segment, Info and single video TrackEntry.
    ///
    /// The Segment has unknown size so the owner can stream without seeking or rewriting
    /// previously hashed bytes. Every later Cluster has its complete finite size.
    pub fn initialization(self) -> Result<Initialization, MatroskaGrayError> {
        initialization(self.dimensions, None)
    }

    /// Frame one zero-based output ordinal without reading or copying any pixels.
    ///
    /// Write the returned prefix followed immediately by exactly `payload_bytes()`
    /// samples. There is no trailer. Calls are stateless; the owner must enforce order,
    /// shape consistency, byte/work ceilings, and failure fencing before publication.
    pub fn frame(self, ordinal: u64) -> Result<FrameFraming, MatroskaGrayError> {
        if ordinal >= MAX_FRAMES {
            return Err(MatroskaGrayError::FrameLimit);
        }
        let timestamp_ns = self.rate.boundary(ordinal)?;
        let end_ns = self
            .rate
            .boundary(ordinal.checked_add(1).ok_or(MatroskaGrayError::Timeline)?)?;
        frame_framing(self.pixels, timestamp_ns, end_ns)
    }
}

/// One immutable grayscale track with explicit frame intervals inside a known clip duration.
///
/// The owner converts source rational intervals to nanoseconds, validates their order and
/// coverage, and writes each admitted frame unchanged. Leading, internal and trailing gaps
/// are retained as timestamp holes without adding pictures to the file. Player behavior
/// during those holes, including whether it holds a prior frame, is outside this contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimedGrayMatroskaConfig {
    dimensions: [u32; 2],
    duration_ns: u64,
    pixels: usize,
}

impl TimedGrayMatroskaConfig {
    /// Admit tightly packed gray8 dimensions and an exactly representable clip duration.
    pub fn new(dimensions: [u32; 2], duration_ns: u64) -> Result<Self, MatroskaGrayError> {
        let pixels = checked_pixels(dimensions)?;
        if !(1..=MAX_TIMED_DURATION_NS).contains(&duration_ns) {
            return Err(MatroskaGrayError::Timeline);
        }
        Ok(Self {
            dimensions,
            duration_ns,
            pixels,
        })
    }

    /// Width and height of every unchanged frame.
    #[must_use]
    pub const fn dimensions(self) -> [u32; 2] {
        self.dimensions
    }

    /// Exclusive clip end, measured from the caller's rebased timeline origin.
    #[must_use]
    pub const fn duration_ns(self) -> u64 {
        self.duration_ns
    }

    /// Declare the complete clip duration before any frame, including trailing gaps.
    pub fn initialization(self) -> Result<Initialization, MatroskaGrayError> {
        initialization(self.dimensions, Some(self.duration_ns))
    }

    /// Frame a caller-selected positive half-open interval inside the declared clip.
    ///
    /// The ordinal bounds the number of pictures; it does not synthesize a timestamp.
    /// Calls are stateless. The writer must enforce increasing, nonoverlapping intervals,
    /// stable dimensions, exact payload lengths, cumulative limits and failure fencing.
    pub fn frame(
        self,
        ordinal: u64,
        start_ns: u64,
        end_ns: u64,
    ) -> Result<FrameFraming, MatroskaGrayError> {
        if ordinal >= MAX_FRAMES {
            return Err(MatroskaGrayError::FrameLimit);
        }
        if end_ns > self.duration_ns {
            return Err(MatroskaGrayError::Timeline);
        }
        frame_framing(self.pixels, start_ns, end_ns)
    }
}

fn checked_pixels(dimensions: [u32; 2]) -> Result<usize, MatroskaGrayError> {
    if dimensions
        .iter()
        .any(|dimension| !(1..=MAX_DIMENSION).contains(dimension))
    {
        return Err(MatroskaGrayError::InvalidDimensions);
    }
    let pixels = usize::try_from(u64::from(dimensions[0]) * u64::from(dimensions[1]))
        .map_err(|_| MatroskaGrayError::InvalidDimensions)?;
    if pixels > MAX_PIXELS {
        return Err(MatroskaGrayError::InvalidDimensions);
    }
    Ok(pixels)
}

fn initialization(
    dimensions: [u32; 2],
    duration_ns: Option<u64>,
) -> Result<Initialization, MatroskaGrayError> {
    let mut header = Buffer::<64>::new();
    header.unsigned(&[0x42, 0x86], 1)?; // EBMLVersion
    header.unsigned(&[0x42, 0xf7], 1)?; // EBMLReadVersion
    header.unsigned(&[0x42, 0xf2], 4)?; // EBMLMaxIDLength
    header.unsigned(&[0x42, 0xf3], 8)?; // EBMLMaxSizeLength
    header.element(&[0x42, 0x82], b"matroska")?;
    header.unsigned(&[0x42, 0x87], 4)?; // DocTypeVersion
    header.unsigned(&[0x42, 0x85], 2)?; // DocTypeReadVersion

    let mut bytes = Buffer::<256>::new();
    bytes.element(&[0x1a, 0x45, 0xdf, 0xa3], header.bytes())?;
    bytes.append(&[0x18, 0x53, 0x80, 0x67])?;
    bytes.append(&[0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])?;

    let mut info = Buffer::<64>::new();
    info.unsigned(&[0x2a, 0xd7, 0xb1], 1)?; // TimestampScale: nanoseconds
    if let Some(duration_ns) = duration_ns {
        // RFC 9559 §5.1.2.10: Duration is positive floating-point Segment ticks.
        // TimestampScale is 1 ns; the timed constructor bounds every integer to <=2^53.
        // RFC 8794 §7/7.3 requires big-endian IEEE 754 storage for Float Elements.
        info.element(&[0x44, 0x89], &(duration_ns as f64).to_be_bytes())?;
    }
    info.element(&[0x4d, 0x80], APP)?; // MuxingApp
    info.element(&[0x57, 0x41], APP)?; // WritingApp
    bytes.element(&[0x15, 0x49, 0xa9, 0x66], info.bytes())?;

    let mut colour = Buffer::<16>::new();
    colour.unsigned(&[0x55, 0xb2], 8)?; // BitsPerChannel
    colour.unsigned(&[0x55, 0xb9], 2)?; // Range: full sample range, no scaling
    let mut video = Buffer::<64>::new();
    video.unsigned(&[0x9a], 2)?; // FlagInterlaced: progressive
    video.unsigned(&[0xb0], u64::from(dimensions[0]))?;
    video.unsigned(&[0xba], u64::from(dimensions[1]))?;
    video.element(&[0x2e, 0xb5, 0x24], b"Y800")?;
    video.element(&[0x55, 0xb0], colour.bytes())?;

    let mut track = Buffer::<128>::new();
    track.unsigned(&[0xd7], 1)?; // TrackNumber, matching every Block header
    track.unsigned(&[0x73, 0xc5], 1)?; // TrackUID, local to this unlinked Segment
    track.unsigned(&[0x83], 1)?; // TrackType: video
    track.unsigned(&[0x9c], 0)?; // FlagLacing: no lacing
    track.element(&[0x86], b"V_UNCOMPRESSED")?;
    track.element(&[0xe0], video.bytes())?;
    let mut tracks = Buffer::<160>::new();
    tracks.element(&[0xae], track.bytes())?;
    bytes.element(&[0x16, 0x54, 0xae, 0x6b], tracks.bytes())?;
    Ok(Initialization { bytes })
}

fn frame_framing(
    pixels: usize,
    timestamp_ns: u64,
    end_ns: u64,
) -> Result<FrameFraming, MatroskaGrayError> {
    let duration_ns = end_ns
        .checked_sub(timestamp_ns)
        .filter(|duration| *duration > 0)
        .ok_or(MatroskaGrayError::Timeline)?;
    let block_size = pixels.checked_add(4).ok_or(MatroskaGrayError::Layout)?;
    let group_size = unsigned_len(1, duration_ns)?
        .checked_add(element_len(1, block_size)?)
        .ok_or(MatroskaGrayError::Layout)?;
    let cluster_size = unsigned_len(1, timestamp_ns)?
        .checked_add(element_len(1, group_size)?)
        .ok_or(MatroskaGrayError::Layout)?;

    let mut prefix = Buffer::<64>::new();
    prefix.header(&[0x1f, 0x43, 0xb6, 0x75], cluster_size)?;
    prefix.unsigned(&[0xe7], timestamp_ns)?;
    prefix.header(&[0xa0], group_size)?;
    prefix.unsigned(&[0x9b], duration_ns)?;
    prefix.header(&[0xa1], block_size)?;
    // Track 1, relative timestamp zero, reserved/invisible/lacing flags zero.
    // No ReferenceBlock is present: every unchanged frame is independently decodable.
    prefix.append(&[0x81, 0x00, 0x00, 0x00])?;
    Ok(FrameFraming {
        prefix,
        payload_bytes: pixels,
        timestamp_ns,
        duration_ns,
        end_ns,
    })
}

/// Complete initialization bytes held in 256 bytes of fixed storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Initialization {
    bytes: Buffer<256>,
}
impl Initialization {
    /// EBML header through TrackEntry, preceding the first Cluster.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.bytes.bytes()
    }
}
impl AsRef<[u8]> for Initialization {
    fn as_ref(&self) -> &[u8] {
        self.bytes()
    }
}

/// Complete finite Cluster framing, followed by the owner's unchanged sample slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameFraming {
    prefix: Buffer<64>,
    payload_bytes: usize,
    timestamp_ns: u64,
    duration_ns: u64,
    end_ns: u64,
}
impl FrameFraming {
    /// Fixed-storage metadata to write immediately before the frame's samples.
    #[must_use]
    pub fn prefix(&self) -> &[u8] {
        self.prefix.bytes()
    }
    /// Exact required sample count, with no row padding or hidden planes.
    #[must_use]
    pub const fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }
    /// Start of this frame on the generated playback timeline, in nanoseconds.
    #[must_use]
    pub const fn timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }
    /// Positive duration of this unchanged frame in nanoseconds.
    #[must_use]
    pub const fn duration_ns(&self) -> u64 {
        self.duration_ns
    }
    /// Exclusive end of this frame on the generated playback timeline, in nanoseconds.
    #[must_use]
    pub const fn end_ns(&self) -> u64 {
        self.end_ns
    }
}

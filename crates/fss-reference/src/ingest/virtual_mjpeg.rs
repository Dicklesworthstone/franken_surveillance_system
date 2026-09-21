#![forbid(unsafe_code)]
//! Opt-in synthetic MJPEG capture through the existing source/delivery custody path.
//!
//! Uses the existing first-party fixture encoder, not a second codec implementation.
//! A block-aligned rectangle is synthetic scene truth, never a person, calibration,
//! independently witnessed presence, or effect authority. Legacy PRNG sources are unchanged.

use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};

use fss_core::{CapsuleId, CaptureInterval, ContentDigest, SensorId, TimestampNs};
use fss_ledger::DurableReferenceLedger;
use fss_object::InMemoryObjectStore;

use crate::{DeliveryPlan, ReferenceCapture, ReferenceError, SourcePacket, VirtualCameraSpec,
    VirtualClock, MAX_VIRTUAL_PACKET_BYTES, MAX_VIRTUAL_PACKETS};
use crate::media_fixture::jpeg::{CustomMarker, JpegConfig, JpegError, Subsampling, encode_jpeg};

mod scene;
#[cfg(test)]
mod tests;

/// Maximum axis for one non-interruptible call to the existing fixture encoder.
pub const MAX_SCENE_DIMENSION: u16 = 256;
/// Maximum rendered pixels per complete synthetic session, across all its frames.
pub const MAX_SCENE_PIXELS: u64 = 8 * 1024 * 1024;
/// Maximum retained compressed source bytes per generated session.
pub const MAX_SCENE_BYTES: usize = 16 * 1024 * 1024;
/// Hard bound for one complete encoded frame including its synthetic recipe.
pub const MAX_SCENE_FRAME_BYTES: usize = 64 * 1024;

/// Explicit opt-in scene/timeline. `frame_count` is NOT a packet count.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MjpegCameraSpec {
    /// Stable synthetic capture identity; never reused for different capture content.
    pub capture_id: CapsuleId,
    /// Configured synthetic sensor identity, bound into each JPEG's recipe.
    pub sensor_id: SensorId,
    /// Scene phase and recipe seed; equal complete inputs replay identically.
    pub seed: u64,
    /// Number of complete JPEG frames, from one through 4096.
    pub frame_count: u32,
    /// Width in pixels: a multiple of eight, from 24 through 256.
    pub width: u16,
    /// Height in pixels: a multiple of eight, from 24 through 256.
    pub height: u16,
    /// Initial virtual-clock reading required by this specification.
    pub start_ns: i128,
    /// Nominal spacing between FRAMES, never between fragments of a frame.
    pub period_ns: u64,
    /// Conservative capture uncertainty on every frame and all its fragments.
    pub uncertainty_ns: u64,
    /// Maximum fragment length, from one through MAX_VIRTUAL_PACKET_BYTES.
    pub packet_bytes: usize,
    /// Initial background-only frames; may equal frame_count for a quiet fixture.
    pub warmup_frames: u32,
}
impl MjpegCameraSpec {
    /// Validate allocation, scene, frame, and nominal timeline bounds before generation.
    pub fn validate(&self) -> Result<(), MjpegSourceError> {
        if self.frame_count == 0 || self.frame_count > 4096 || self.warmup_frames > self.frame_count {
            return Err(MjpegSourceError::InvalidSpec("frame_count or warmup_frames"));
        }
        if [self.width, self.height].iter().any(|d| *d < 24 || *d > MAX_SCENE_DIMENSION || *d % 8 != 0) {
            return Err(MjpegSourceError::InvalidSpec("dimensions must be bounded multiples of eight"));
        }
        if self.packet_bytes == 0 || self.packet_bytes > MAX_VIRTUAL_PACKET_BYTES || self.period_ns == 0 {
            return Err(MjpegSourceError::InvalidSpec("packet_bytes or period_ns"));
        }
        if self.rendered_pixels() > MAX_SCENE_PIXELS {
            return Err(MjpegSourceError::Limit("aggregate rendered pixels"));
        }
        self.start_ns.checked_add(i128::from(self.frame_count - 1) * i128::from(self.period_ns))
            .and_then(|end| end.checked_add(i128::from(self.uncertainty_ns)))
            .ok_or(MjpegSourceError::InvalidSpec("nominal capture timeline overflow"))?;
        Ok(())
    }
    /// Planned pixel allowance. This measures scene size, not CPU cycles or time.
    pub fn rendered_pixels(&self) -> u64 {
        u64::from(self.width) * u64::from(self.height) * u64::from(self.frame_count)
    }
}

/// Explicit work and cancellation context; unsuccessful reserved work is not refunded.
#[derive(Debug)]
pub struct MjpegSourceBudget<'a> {
    remaining: u64,
    reserved: u64,
    cancellation: &'a AtomicBool,
}
impl<'a> MjpegSourceBudget<'a> {
    /// One unit reserves one rendered pixel; dimensions independently bound encoder work.
    pub fn new(pixel_allowance: u64, cancellation: &'a AtomicBool) -> Self {
        Self { remaining: pixel_allowance, reserved: 0, cancellation }
    }
    /// Reserved pixel units, including work in frames subsequently refused or cancelled.
    pub fn reserved(&self) -> u64 { self.reserved }
    fn check(&self) -> Result<(), MjpegSourceError> {
        if self.cancellation.load(Ordering::Acquire) { Err(MjpegSourceError::Cancelled) } else { Ok(()) }
    }
    fn reserve(&mut self, pixels: u64) -> Result<(), MjpegSourceError> {
        self.check()?;
        if pixels > self.remaining { return Err(MjpegSourceError::BudgetExhausted); }
        self.remaining -= pixels;
        self.reserved += pixels;
        Ok(())
    }
}

/// Refusal never publishes partly generated media or advances the caller's clock.
#[derive(Debug)]
pub enum MjpegSourceError {
    /// Invalid scene dimensions, timeline or fragmentation specification.
    InvalidSpec(&'static str),
    /// A hard aggregate or per-frame bound was reached; nothing is silently truncated.
    Limit(&'static str),
    /// Owner cancellation observed before result publication.
    Cancelled,
    /// Caller pixel allowance is insufficient.
    BudgetExhausted,
    /// Existing virtual clock refused a timeline transition.
    Clock(Box<ReferenceError>),
    /// Existing first-party JPEG encoder refused the supplied pixels.
    Encode(Box<JpegError>),
}
impl std::fmt::Display for MjpegSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSpec(why) => write!(f, "invalid virtual MJPEG specification: {why}"),
            Self::Limit(why) => write!(f, "virtual MJPEG capacity exceeded: {why}"),
            Self::Cancelled => f.write_str("virtual MJPEG generation cancelled"),
            Self::BudgetExhausted => f.write_str("virtual MJPEG pixel allowance exhausted"),
            Self::Clock(err) => write!(f, "virtual MJPEG clock failure: {err}"),
            Self::Encode(err) => write!(f, "virtual MJPEG encode failure: {err}"),
        }
    }
}
impl std::error::Error for MjpegSourceError {}
impl From<ReferenceError> for MjpegSourceError {
    fn from(err: ReferenceError) -> Self { Self::Clock(Box::new(err)) }
}
impl From<JpegError> for MjpegSourceError {
    fn from(err: JpegError) -> Self { Self::Encode(Box::new(err)) }
}

/// Pixel rectangle in the synthetic recipe, not a detector or tracking result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyntheticRectangle {
    /// Left pixel coordinate, inclusive.
    pub x: u16,
    /// Top pixel coordinate, inclusive.
    pub y: u16,
    /// Rectangle width in pixels.
    pub width: u16,
    /// Rectangle height in pixels.
    pub height: u16,
}

/// Exact mapping from one complete JPEG to immutable source packet fragments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MjpegFrameSpan {
    /// Zero-based complete-frame ordinal.
    pub frame_index: u32,
    /// Conservative frame interval, copied unchanged to every fragment.
    pub capture: CaptureInterval,
    /// Zero-based packet range with exclusive end, not transport arrival positions.
    pub packet_range: Range<usize>,
    /// SHA-256 of the complete JPEG, including its recipe metadata and EOI.
    pub encoded_digest: ContentDigest,
    /// Digest of the synthetic recipe embedded verbatim in the JPEG COM segment.
    pub recipe_digest: ContentDigest,
    /// Optional rendered foreground; None means a deliberately background-only frame.
    pub rectangle: Option<SyntheticRectangle>,
}

/// Immutable source truth constructed only after complete bounded generation succeeds.
#[derive(Debug)]
pub struct GeneratedMjpegSource {
    capture_spec: VirtualCameraSpec,
    clock: VirtualClock,
    frames: Vec<MjpegFrameSpan>,
    packets: Vec<SourcePacket>,
}
impl GeneratedMjpegSource {
    /// Exact pre-delivery packets; no transport fault can rewrite these bytes.
    pub fn packets(&self) -> &[SourcePacket] { &self.packets }
    /// Ordered complete-frame mappings and synthetic recipes.
    pub fn frames(&self) -> &[MjpegFrameSpan] { &self.frames }
    /// Reassembles one complete retained source frame, bounded by MAX_SCENE_FRAME_BYTES.
    pub fn frame_bytes(&self, index: usize) -> Option<Vec<u8>> {
        let span = self.frames.get(index)?;
        Some(self.packets.get(span.packet_range.clone())?.iter()
            .flat_map(|packet| packet.bytes.iter().copied()).collect())
    }
    /// Publish through the SAME root-last source/delivery/authority implementation as
    /// the PRNG source. Plan validation precedes storage; a publication failure may
    /// retain unreachable staged objects, but does not rewrite any source bytes.
    pub fn publish(self, plan: &DeliveryPlan, objects: &mut InMemoryObjectStore,
        ledger: &mut DurableReferenceLedger) -> Result<ReferenceCapture, ReferenceError> {
        plan.validate_against(self.capture_spec.packet_count)?;
        crate::capture::publish_reference_packets(&self.capture_spec, self.packets,
            self.clock, plan, objects, ledger)
    }
}

/// Render complete self-contained baseline grayscale JPEGs and fragment them into
/// source packets. The clock advances once per frame, not once per packet. Polls
/// cancellation per rendered row and fragment and before/after each encoder call.
/// One bounded (at most 256x256) encoder call is the longest non-interruptible step.
/// No external codec, process, file or network is used. Clock mutation is committed
/// only after every frame/fragment has passed all bounds and the final cancellation check.
pub fn generate_mjpeg_source(spec: &MjpegCameraSpec, clock: &mut VirtualClock,
    budget: &mut MjpegSourceBudget<'_>) -> Result<GeneratedMjpegSource, MjpegSourceError> {
    budget.check()?;
    spec.validate()?;
    if clock.now() != TimestampNs(spec.start_ns) {
        return Err(MjpegSourceError::InvalidSpec("clock must begin at the declared start"));
    }
    if spec.rendered_pixels() > budget.remaining { return Err(MjpegSourceError::BudgetExhausted); }
    let mut staged_clock = clock.clone();
    let mut packets = Vec::new();
    let mut frames = Vec::with_capacity(spec.frame_count as usize);
    let mut total_bytes = 0_usize;
    for index in 0..spec.frame_count {
        budget.check()?;
        if index > 0 { staged_clock.advance(spec.period_ns)?; }
        let capture = staged_clock.read_interval(spec.uncertainty_ns)?;
        let rectangle = scene::rectangle(spec, index);
        let pixels = scene::render(spec, rectangle, budget)?;
        let recipe = scene::recipe(spec, index, capture, rectangle);
        if recipe.len() > 4096 { return Err(MjpegSourceError::Limit("recipe metadata")); }
        let recipe_digest = ContentDigest::sha256(&recipe);
        let config = JpegConfig { quality: 100, subsampling: Subsampling::Grayscale,
            restart_interval: 0, custom_markers: vec![CustomMarker { marker: 0xfe, payload: recipe }] };
        let jpeg = encode_jpeg(u32::from(spec.width), u32::from(spec.height), &pixels, &config)?;
        budget.check()?;
        if jpeg.len() > MAX_SCENE_FRAME_BYTES { return Err(MjpegSourceError::Limit("encoded frame")); }
        total_bytes = total_bytes.checked_add(jpeg.len()).ok_or(MjpegSourceError::Limit("total bytes"))?;
        if total_bytes > MAX_SCENE_BYTES { return Err(MjpegSourceError::Limit("total bytes")); }
        let fragments = jpeg.len().div_ceil(spec.packet_bytes);
        if packets.len() + fragments > MAX_VIRTUAL_PACKETS as usize {
            return Err(MjpegSourceError::Limit("source packets"));
        }
        let start = packets.len();
        for bytes in jpeg.chunks(spec.packet_bytes) {
            budget.check()?;
            packets.push(SourcePacket { sensor_id: spec.sensor_id.clone(), sequence: packets.len() as u64 + 1,
                capture, bytes: bytes.to_vec(), digest: ContentDigest::sha256(bytes) });
        }
        frames.push(MjpegFrameSpan { frame_index: index, capture, packet_range: start..packets.len(),
            encoded_digest: ContentDigest::sha256(&jpeg), recipe_digest, rectangle });
    }
    budget.check()?;
    let capture_spec = VirtualCameraSpec { capture_id: spec.capture_id.clone(), sensor_id: spec.sensor_id.clone(),
        seed: spec.seed, packet_count: packets.len() as u32, packet_bytes: spec.packet_bytes,
        start_ns: spec.start_ns, period_ns: spec.period_ns, uncertainty_ns: spec.uncertainty_ns };
    // This private specification supplies legacy publication identity/count only. Its
    // packet_bytes is the explicit MJPEG cap, not a promise of padded final fragments.
    let generated = GeneratedMjpegSource { capture_spec, clock: staged_clock.clone(), frames, packets };
    *clock = staged_clock;
    Ok(generated)
}

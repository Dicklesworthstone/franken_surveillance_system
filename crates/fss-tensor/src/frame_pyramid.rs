#![forbid(unsafe_code)]
//! Shared multi-scale frame pyramids, cache-friendly tiling, and optional accelerator isolation
//! behind deterministic scalar truth (`DOC-054`, bead `fss-x4a.5.54`).
//!
//! Core invariants:
//! - One decoded frame generates a shared, generation-pinned [`FramePyramid`] (level 0 full-res
//!   + exact integer 2x box-filtered levels 1..=L) backed directly by [`FramePool`] (`FSS-119`) so
//!   detectors, trackers, and preview consumers never redundantly downsample the same frame.
//! - [`TilePlan`] partitions `[0..width) x [0..height)` into bounded cache-sized tiles with
//!   explicit overlap/halo clamping, zero out-of-bounds spans, and exact coverage verification.
//! - [`adjudicate_accelerator_against_scalar`] isolates any optional hardware/accelerator candidate behind
//!   pinned scalar reference outputs and registered max-abs-delta tolerances; unavailability,
//!   timeout, stale generation, or numerical divergence falls back explicitly to scalar truth
//!   (never silently promoting an unverified accelerator result).

use core::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, Generation, TimestampNs,
};

use crate::dtype::DType;
use crate::frame_pool::{FrameDescriptor, FrameLease, FramePool, FramePoolError, FrameSlotId};

/// Registered digest domain for canonical frame pyramid + accelerator gate receipts
/// (`SCHEMA-DOMAIN-TENSOR-FRAME-PYRAMID-001`).
pub const FRAME_PYRAMID_RECEIPT_DOMAIN: &str = "fss.tensor.frame_pyramid_receipt.v1";

/// Canonical binary format version for [`FramePyramidReceipt`].
pub const FRAME_PYRAMID_FORMAT_VERSION: u32 = 1;

/// Maximum levels in one shared multi-scale pyramid (`1..=6`, i.e., up to 1/32x scale).
pub const MAX_PYRAMID_LEVELS: usize = 6;

/// Maximum tiles admitted in one bounded cache-tiling plan.
pub const MAX_TILES_PER_PLAN: usize = 4_096;

/// One level in a shared generation-pinned [`FramePyramid`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PyramidLevelEntry {
    /// Zero-based scale level (`0` = base resolution, `k` = `1 / 2^k` scale).
    pub level: u8,
    /// Level width in pixels (`>= 1`).
    pub width: u32,
    /// Level height in pixels (`>= 1`).
    pub height: u32,
    /// Exact pooled slot ID holding the immutable level bytes in [`FramePool`].
    pub slot_id: FrameSlotId,
    /// Exact SHA-256 content digest of the scalar level plane bytes.
    pub level_digest: ContentDigest,
}

/// Shared multi-scale pyramid built in one pass and pinned to one [`FramePool`] generation.
#[derive(Debug)]
pub struct FramePyramid {
    generation: Generation,
    channels: u8,
    source_evidence_digest: ContentDigest,
    levels: Vec<(PyramidLevelEntry, FrameLease)>,
}

/// Typed fail-closed refusal for pyramid, tiling, and accelerator isolation operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FramePyramidError {
    /// Invalid geometry, level count, channel count, or tile dimensions.
    InvalidConfiguration(&'static str),
    /// Base input bytes did not match `width * height * channels`.
    ByteLengthMismatch {
        /// Expected byte length.
        expected: usize,
        /// Supplied byte length.
        actual: usize,
    },
    /// Checked geometry or tile count arithmetic overflowed.
    ArithmeticOverflow,
    /// Tile plan exceeded `MAX_TILES_PER_PLAN`.
    TileLimitExceeded {
        /// Computed tile count.
        tiles: usize,
        /// Configured ceiling.
        max: usize,
    },
    /// Underlying frame pool refused level admission or lease acquisition.
    Pool(FramePoolError),
    /// Cooperative cancellation observed before completing pyramid construction.
    Cancelled,
}

impl fmt::Display for FramePyramidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(why) => write!(f, "invalid frame pyramid config: {why}"),
            Self::ByteLengthMismatch { expected, actual } => {
                write!(
                    f,
                    "pyramid base byte length mismatch: expected {expected}, got {actual}"
                )
            }
            Self::ArithmeticOverflow => write!(f, "frame pyramid arithmetic overflow"),
            Self::TileLimitExceeded { tiles, max } => {
                write!(f, "tile plan count {tiles} exceeds limit {max}")
            }
            Self::Pool(err) => write!(f, "frame pyramid pool error: {err}"),
            Self::Cancelled => write!(f, "frame pyramid construction cancelled"),
        }
    }
}

impl std::error::Error for FramePyramidError {}

/// Exact integer 2x box-filter downsample of an interleaved 8-bit plane (`(a+b+c+d+2)>>2`,
/// replicating the edge sample on odd dimensions). Deterministic scalar reference kernel.
pub fn downsample_2x_box_u8(
    src: &[u8],
    width: u32,
    height: u32,
    channels: u8,
) -> Result<(u32, u32, Vec<u8>), FramePyramidError> {
    if width == 0 || height == 0 || !(1..=4).contains(&channels) {
        return Err(FramePyramidError::InvalidConfiguration(
            "invalid_plane_shape",
        ));
    }
    let w = width as usize;
    let h = height as usize;
    let c = usize::from(channels);
    let expected = w
        .checked_mul(h)
        .and_then(|v| v.checked_mul(c))
        .ok_or(FramePyramidError::ArithmeticOverflow)?;
    if src.len() != expected {
        return Err(FramePyramidError::ByteLengthMismatch {
            expected,
            actual: src.len(),
        });
    }
    let dst_w = width.div_ceil(2);
    let dst_h = height.div_ceil(2);
    let dst_len = (dst_w as usize)
        .checked_mul(dst_h as usize)
        .and_then(|v| v.checked_mul(c))
        .ok_or(FramePyramidError::ArithmeticOverflow)?;
    let mut dst = vec![0_u8; dst_len];

    for dy in 0..(dst_h as usize) {
        let sy0 = dy * 2;
        let sy1 = (sy0 + 1).min(h - 1);
        for dx in 0..(dst_w as usize) {
            let sx0 = dx * 2;
            let sx1 = (sx0 + 1).min(w - 1);
            let dst_base = (dy * (dst_w as usize) + dx) * c;
            let p00 = (sy0 * w + sx0) * c;
            let p01 = (sy0 * w + sx1) * c;
            let p10 = (sy1 * w + sx0) * c;
            let p11 = (sy1 * w + sx1) * c;
            for ch in 0..c {
                let sum = u16::from(src[p00 + ch])
                    + u16::from(src[p01 + ch])
                    + u16::from(src[p10 + ch])
                    + u16::from(src[p11 + ch]);
                dst[dst_base + ch] = ((sum + 2) >> 2) as u8;
            }
        }
    }
    Ok((dst_w, dst_h, dst))
}

impl FramePyramid {
    /// Builds a shared `levels`-deep multi-scale pyramid directly inside `pool` so multiple
    /// consumers can acquire zero-copy leases on any scale level without redundant downsampling.
    pub fn build_in_pool(
        pool: &mut FramePool,
        base_descriptor: FrameDescriptor,
        base_bytes: Vec<u8>,
        level_count: usize,
        now_ns: TimestampNs,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<Self, FramePyramidError> {
        if is_cancelled() {
            return Err(FramePyramidError::Cancelled);
        }
        if base_descriptor.dtype != DType::U8 {
            return Err(FramePyramidError::InvalidConfiguration(
                "only_u8_pyramid_supported",
            ));
        }
        if level_count == 0 || level_count > MAX_PYRAMID_LEVELS {
            return Err(FramePyramidError::InvalidConfiguration(
                "invalid_level_count",
            ));
        }
        let expected = base_descriptor
            .expected_byte_len()
            .map_err(FramePyramidError::Pool)?;
        if base_bytes.len() != expected {
            return Err(FramePyramidError::ByteLengthMismatch {
                expected,
                actual: base_bytes.len(),
            });
        }
        // Validate frame_seq scaling upfront so pool admission cannot overflow mid-pyramid.
        let _ = base_descriptor
            .frame_seq
            .checked_mul(16)
            .and_then(|v| v.checked_add((level_count - 1) as u64))
            .ok_or(FramePyramidError::ArithmeticOverflow)?;

        // Precompute all downsampled levels cleanly before mutating the pool so cancellation or
        // error never leaves half a pyramid admitted in `pool`.
        let mut level_buffers: Vec<(u32, u32, Vec<u8>)> = Vec::with_capacity(level_count);
        level_buffers.push((base_descriptor.width, base_descriptor.height, base_bytes));
        for _ in 1..level_count {
            if is_cancelled() {
                return Err(FramePyramidError::Cancelled);
            }
            let Some((prev_w, prev_h, prev_buf)) = level_buffers.last() else {
                break;
            };
            let next = downsample_2x_box_u8(prev_buf, *prev_w, *prev_h, base_descriptor.channels)?;
            level_buffers.push(next);
        }

        if is_cancelled() {
            return Err(FramePyramidError::Cancelled);
        }

        let mut admitted: Vec<(PyramidLevelEntry, FrameLease)> = Vec::with_capacity(level_count);
        for (idx, (w, h, buf)) in level_buffers.into_iter().enumerate() {
            let desc = FrameDescriptor {
                width: w,
                height: h,
                channels: base_descriptor.channels,
                dtype: DType::U8,
                generation: base_descriptor.generation,
                frame_seq: base_descriptor
                    .frame_seq
                    .checked_mul(16)
                    .and_then(|v| v.checked_add(idx as u64))
                    .ok_or(FramePyramidError::ArithmeticOverflow)?,
                source_evidence_digest: base_descriptor.source_evidence_digest,
            };
            match pool.admit_frame(desc, buf, now_ns, || false) {
                Ok(lease) => {
                    let entry = PyramidLevelEntry {
                        level: idx as u8,
                        width: w,
                        height: h,
                        slot_id: lease.slot_id(),
                        level_digest: lease.frame_digest(),
                    };
                    admitted.push((entry, lease));
                }
                Err(err) => {
                    // Roll back every already-admitted pyramid level cleanly so zero leases leak!
                    for (_, prev_lease) in admitted {
                        let _ = pool.release_lease(prev_lease, now_ns);
                    }
                    return Err(FramePyramidError::Pool(err));
                }
            }
        }

        Ok(Self {
            generation: base_descriptor.generation,
            channels: base_descriptor.channels,
            source_evidence_digest: base_descriptor.source_evidence_digest,
            levels: admitted,
        })
    }

    /// Number of scale levels in this pyramid.
    #[must_use]
    pub fn level_count(&self) -> usize {
        self.levels.len()
    }

    /// Metadata of scale level `level`.
    #[must_use]
    pub fn level_entry(&self, level: usize) -> Option<PyramidLevelEntry> {
        self.levels.get(level).map(|(e, _)| *e)
    }

    /// Read-only zero-copy slice of scale level `level`.
    #[must_use]
    pub fn level_bytes(&self, level: usize) -> Option<&[u8]> {
        self.levels.get(level).map(|(_, l)| l.bytes())
    }

    /// Acquires an additional shared zero-copy [`FrameLease`] for consumer fan-out at `level`.
    pub fn share_level(
        &self,
        pool: &mut FramePool,
        level: usize,
        is_cancelled: impl FnMut() -> bool,
    ) -> Result<FrameLease, FramePyramidError> {
        let (entry, _) = self
            .levels
            .get(level)
            .ok_or(FramePyramidError::InvalidConfiguration(
                "level_out_of_bounds",
            ))?;
        pool.acquire_lease(entry.slot_id, self.generation, is_cancelled)
            .map_err(FramePyramidError::Pool)
    }

    /// Releases every internal pyramid level lease back to `pool` cleanly.
    pub fn release_all(
        self,
        pool: &mut FramePool,
        now_ns: TimestampNs,
    ) -> Result<(), FramePyramidError> {
        if self
            .levels
            .iter()
            .any(|(_, lease)| lease.pool_id() != pool.policy().pool_id)
        {
            return Err(FramePyramidError::Pool(FramePoolError::PoolMismatch));
        }
        for (_, lease) in self.levels {
            pool.release_lease(lease, now_ns)
                .map_err(FramePyramidError::Pool)?;
        }
        Ok(())
    }

    /// Seals a canonical witness receipt for this pyramid, its verified [`TilePlan`], and an
    /// associated accelerator gate decision.
    pub fn receipt(
        &self,
        tile_plan: &TilePlan,
        gate_decision: AcceleratorGateDecision,
    ) -> Result<FramePyramidReceipt, FramePyramidError> {
        if !tile_plan.verify_exact_coverage() {
            return Err(FramePyramidError::InvalidConfiguration(
                "invalid_tile_plan_coverage",
            ));
        }
        let matches_level_geometry = self
            .levels
            .iter()
            .any(|(e, _)| e.width == tile_plan.image_width && e.height == tile_plan.image_height);
        if !matches_level_geometry {
            return Err(FramePyramidError::InvalidConfiguration(
                "tile_plan_geometry_mismatch",
            ));
        }
        if tile_plan.tiles.len() > MAX_TILES_PER_PLAN {
            return Err(FramePyramidError::TileLimitExceeded {
                tiles: tile_plan.tiles.len(),
                max: MAX_TILES_PER_PLAN,
            });
        }
        let level_digests: Vec<ContentDigest> =
            self.levels.iter().map(|(e, _)| e.level_digest).collect();
        let mut r = FramePyramidReceipt {
            format_version: FRAME_PYRAMID_FORMAT_VERSION,
            generation: self.generation,
            channels: self.channels,
            source_evidence_digest: self.source_evidence_digest,
            level_digests,
            tile_count: tile_plan.tiles.len() as u32,
            gate_decision,
            receipt_digest: ContentDigest::sha256(b"pending"),
        };
        r.receipt_digest = r.computed_digest();
        Ok(r)
    }
}

/// One cache-sized spatial tile covering `[x..x+width) x [y..y+height)` with clamped halo bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TileRegion {
    /// Core non-overlapping tile origin X.
    pub core_x: u32,
    /// Core non-overlapping tile origin Y.
    pub core_y: u32,
    /// Core tile width (`>= 1`).
    pub core_width: u32,
    /// Core tile height (`>= 1`).
    pub core_height: u32,
    /// Clamped halo read origin X (`<= core_x`).
    pub halo_x: u32,
    /// Clamped halo read origin Y (`<= core_y`).
    pub halo_y: u32,
    /// Clamped halo read width (`>= core_width`, within image bounds).
    pub halo_width: u32,
    /// Clamped halo read height (`>= core_height`, within image bounds).
    pub halo_height: u32,
}

/// Deterministic cache-friendly spatial tiling plan covering an entire image with zero gaps.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TilePlan {
    /// Image width.
    pub image_width: u32,
    /// Image height.
    pub image_height: u32,
    /// Nominal tile width.
    pub tile_width: u32,
    /// Nominal tile height.
    pub tile_height: u32,
    /// Halo/overlap pixels on each side (clamped to image boundaries).
    pub halo_px: u32,
    /// Ordered row-major tiles partitioning the image cleanly.
    pub tiles: Vec<TileRegion>,
}

impl TilePlan {
    /// Builds a bounded row-major cache-tiling plan covering `[0..image_width) x [0..image_height)`.
    pub fn build(
        image_width: u32,
        image_height: u32,
        tile_width: u32,
        tile_height: u32,
        halo_px: u32,
    ) -> Result<Self, FramePyramidError> {
        if image_width == 0 || image_height == 0 || tile_width == 0 || tile_height == 0 {
            return Err(FramePyramidError::InvalidConfiguration(
                "zero_tile_or_image_dim",
            ));
        }
        let cols = image_width.div_ceil(tile_width) as usize;
        let rows = image_height.div_ceil(tile_height) as usize;
        let total = cols
            .checked_mul(rows)
            .ok_or(FramePyramidError::ArithmeticOverflow)?;
        if total > MAX_TILES_PER_PLAN {
            return Err(FramePyramidError::TileLimitExceeded {
                tiles: total,
                max: MAX_TILES_PER_PLAN,
            });
        }
        let mut tiles = Vec::with_capacity(total);
        for row in 0..rows {
            let core_y = (row as u32).saturating_mul(tile_height);
            let core_h = tile_height.min(image_height - core_y);
            let halo_y = core_y.saturating_sub(halo_px);
            let halo_y_end = core_y
                .saturating_add(core_h)
                .saturating_add(halo_px)
                .min(image_height);
            for col in 0..cols {
                let core_x = (col as u32).saturating_mul(tile_width);
                let core_w = tile_width.min(image_width - core_x);
                let halo_x = core_x.saturating_sub(halo_px);
                let halo_x_end = core_x
                    .saturating_add(core_w)
                    .saturating_add(halo_px)
                    .min(image_width);
                tiles.push(TileRegion {
                    core_x,
                    core_y,
                    core_width: core_w,
                    core_height: core_h,
                    halo_x,
                    halo_y,
                    halo_width: halo_x_end - halo_x,
                    halo_height: halo_y_end - halo_y,
                });
            }
        }
        Ok(Self {
            image_width,
            image_height,
            tile_width,
            tile_height,
            halo_px,
            tiles,
        })
    }

    /// Verifies exact non-overlapping row-major core tile coverage of `[0..image_width) x
    /// [0..image_height)` and that every halo rectangle encloses its core tile strictly within
    /// `[0..image_width] x [0..image_height]`.
    #[must_use]
    pub fn verify_exact_coverage(&self) -> bool {
        if self.image_width == 0
            || self.image_height == 0
            || self.tile_width == 0
            || self.tile_height == 0
            || self.tiles.is_empty()
        {
            return false;
        }
        let cols = self.image_width.div_ceil(self.tile_width) as usize;
        let rows = self.image_height.div_ceil(self.tile_height) as usize;
        let Some(expected_count) = cols.checked_mul(rows) else {
            return false;
        };
        if self.tiles.len() != expected_count {
            return false;
        }
        let mut area: u64 = 0;
        for (idx, t) in self.tiles.iter().enumerate() {
            let row = idx / cols;
            let col = idx % cols;
            let expected_x = (col as u32).saturating_mul(self.tile_width);
            let expected_y = (row as u32).saturating_mul(self.tile_height);
            let expected_w = self
                .tile_width
                .min(self.image_width.saturating_sub(expected_x));
            let expected_h = self
                .tile_height
                .min(self.image_height.saturating_sub(expected_y));
            if t.core_x != expected_x
                || t.core_y != expected_y
                || t.core_width != expected_w
                || t.core_height != expected_h
                || t.core_width == 0
                || t.core_height == 0
                || t.halo_x > t.core_x
                || t.halo_y > t.core_y
                || t.halo_x.saturating_add(t.halo_width) > self.image_width
                || t.halo_y.saturating_add(t.halo_height) > self.image_height
                || t.halo_x.saturating_add(t.halo_width) < t.core_x.saturating_add(t.core_width)
                || t.halo_y.saturating_add(t.halo_height) < t.core_y.saturating_add(t.core_height)
            {
                return false;
            }
            area = area.saturating_add(u64::from(t.core_width) * u64::from(t.core_height));
        }
        area == u64::from(self.image_width) * u64::from(self.image_height)
    }
}

/// Optional isolated accelerator execution outcome before scalar truth adjudication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcceleratorCandidate<'a> {
    /// No optional accelerator host available on this device/target.
    Unavailable,
    /// Optional accelerator timed out or faulted and was quarantined.
    FaultedOrTimedOut,
    /// Optional accelerator produced candidate bytes tagged with its pinned generation.
    Candidate {
        /// Generation pinned by the accelerator run.
        generation: Generation,
        /// Candidate output bytes to verify against scalar truth.
        bytes: &'a [u8],
    },
}

/// Explicit non-collapsed verdict from [`adjudicate_accelerator_against_scalar`].
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AcceleratorGateDecision {
    /// Accelerator candidate matched scalar truth within registered `max_abs_delta` tolerance.
    AdmittedWithinTolerance,
    /// No accelerator available; scalar reference truth used directly.
    FallbackScalarUnavailable,
    /// Accelerator faulted/timed out; isolated & fell back to scalar truth.
    FallbackScalarFaulted,
    /// Accelerator stale generation or length/numerical divergence quarantined; scalar truth used.
    QuarantinedDivergenceFallbackScalar,
}

impl CanonicalEncode for AcceleratorGateDecision {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self {
            Self::AdmittedWithinTolerance => 1,
            Self::FallbackScalarUnavailable => 2,
            Self::FallbackScalarFaulted => 3,
            Self::QuarantinedDivergenceFallbackScalar => 4,
        });
    }
}

impl CanonicalDecode for AcceleratorGateDecision {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::AdmittedWithinTolerance),
            2 => Ok(Self::FallbackScalarUnavailable),
            3 => Ok(Self::FallbackScalarFaulted),
            4 => Ok(Self::QuarantinedDivergenceFallbackScalar),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Adjudicates an optional accelerator candidate against deterministic scalar reference bytes.
/// Always returns `(decision, max_observed_abs_delta, authoritative_bytes)` where any unavailable,
/// faulted, stale-generation, length-mismatched, or out-of-tolerance candidate falls back cleanly
/// to `scalar_reference`.
#[must_use]
pub fn adjudicate_accelerator_against_scalar<'a>(
    expected_generation: Generation,
    scalar_reference: &'a [u8],
    candidate: AcceleratorCandidate<'a>,
    max_abs_delta: u8,
) -> (AcceleratorGateDecision, u8, &'a [u8]) {
    match candidate {
        AcceleratorCandidate::Unavailable => (
            AcceleratorGateDecision::FallbackScalarUnavailable,
            0,
            scalar_reference,
        ),
        AcceleratorCandidate::FaultedOrTimedOut => (
            AcceleratorGateDecision::FallbackScalarFaulted,
            0,
            scalar_reference,
        ),
        AcceleratorCandidate::Candidate { generation, bytes } => {
            if expected_generation.0 == 0
                || generation != expected_generation
                || bytes.len() != scalar_reference.len()
            {
                return (
                    AcceleratorGateDecision::QuarantinedDivergenceFallbackScalar,
                    u8::MAX,
                    scalar_reference,
                );
            }
            let mut max_delta: u8 = 0;
            for (&s, &c) in scalar_reference.iter().zip(bytes.iter()) {
                let d = s.abs_diff(c);
                if d > max_delta {
                    max_delta = d;
                }
            }
            if max_delta > max_abs_delta {
                (
                    AcceleratorGateDecision::QuarantinedDivergenceFallbackScalar,
                    max_delta,
                    scalar_reference,
                )
            } else {
                (
                    AcceleratorGateDecision::AdmittedWithinTolerance,
                    max_delta,
                    bytes,
                )
            }
        }
    }
}

/// Canonical, content-addressed receipt binding a shared [`FramePyramid`], [`TilePlan`], and
/// optional accelerator gate adjudication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FramePyramidReceipt {
    /// Format version (`FRAME_PYRAMID_FORMAT_VERSION`).
    pub format_version: u32,
    /// Pinned frame generation.
    pub generation: Generation,
    /// Channel count (`1..=4`).
    pub channels: u8,
    /// Upstream source evidence digest.
    pub source_evidence_digest: ContentDigest,
    /// Ordered scale-level content digests (`level 0..L-1`).
    pub level_digests: Vec<ContentDigest>,
    /// Tile count planned for cache-friendly execution.
    pub tile_count: u32,
    /// Explicit accelerator gate adjudication result.
    pub gate_decision: AcceleratorGateDecision,
    /// Domain-separated SHA-256 digest over all fields above.
    pub receipt_digest: ContentDigest,
}

impl FramePyramidReceipt {
    /// Recomputes the exact domain-separated SHA-256 digest over all canonical fields.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(FRAME_PYRAMID_RECEIPT_DOMAIN);
        encoder.u32(self.format_version);
        encoder.u64(self.generation.0);
        encoder.u8(self.channels);
        encoder.digest(self.source_evidence_digest);
        encoder.u64(self.level_digests.len() as u64);
        for d in &self.level_digests {
            encoder.digest(*d);
        }
        encoder.u32(self.tile_count);
        self.gate_decision.encode_canonical(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Returns `true` iff `receipt_digest` matches [`Self::computed_digest`].
    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.receipt_digest == self.computed_digest()
    }
}

impl CanonicalEncode for FramePyramidReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.format_version);
        encoder.u64(self.generation.0);
        encoder.u8(self.channels);
        encoder.digest(self.source_evidence_digest);
        encoder.u64(self.level_digests.len() as u64);
        for d in &self.level_digests {
            encoder.digest(*d);
        }
        encoder.u32(self.tile_count);
        self.gate_decision.encode_canonical(encoder);
        encoder.digest(self.receipt_digest);
    }
}

impl CanonicalDecode for FramePyramidReceipt {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let format_version = decoder.u32()?;
        if format_version != FRAME_PYRAMID_FORMAT_VERSION {
            return Err(ContractError::InvalidIdentifier);
        }
        let generation = Generation(decoder.u64()?);
        let channels = decoder.u8()?;
        let source_evidence_digest = decoder.digest()?;
        let level_count =
            usize::try_from(decoder.u64()?).map_err(|_| ContractError::InvalidIdentifier)?;
        if generation.0 == 0
            || !(1..=4).contains(&channels)
            || level_count == 0
            || level_count > MAX_PYRAMID_LEVELS
        {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut level_digests = Vec::with_capacity(level_count);
        for _ in 0..level_count {
            level_digests.push(decoder.digest()?);
        }
        let tile_count = decoder.u32()?;
        if tile_count == 0 || tile_count as usize > MAX_TILES_PER_PLAN {
            return Err(ContractError::InvalidIdentifier);
        }
        let gate_decision = AcceleratorGateDecision::decode_canonical(decoder)?;
        let receipt_digest = decoder.digest()?;

        let receipt = Self {
            format_version,
            generation,
            channels,
            source_evidence_digest,
            level_digests,
            tile_count,
            gate_decision,
            receipt_digest,
        };
        if !receipt.verify_digest() {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(receipt)
    }
}

#![forbid(unsafe_code)]
//! Native, cached source-luma to pinhole rectification. No decoder or calibration
//! estimator is implied. Imported pixels, masks and lens parameters need admission
//! by their existing owners; this module performs no I/O or external effects.

mod model;
pub use model::LensDistortion;

use crate::localization::{ImageIdentity, LocalizationError};
use crate::localization::native::GrayImage;
use crate::TwinError;
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, PinholeIntrinsics, WorkBudget};

/// Maximum logical pixels in either input or output (the native extractor limit).
pub const MAX_RECTIFICATION_PIXELS: usize = 4_194_304;
const MAX_STORAGE: usize = 64 * 1024 * 1024;
const ONE: u32 = 65_536;
const INVALID: u32 = u32::MAX;
const ALGORITHM: &[u8] = b"fss/rectification/reference/1;pixel-edge;no-optical-rotation;backward-map;nearest-q16;positive-footprint;bilinear-q32-half-up;luma-expand-before-interpolation";

/// Non-disclosing rectification failure; no error returns a partial usable image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RectificationError {
    /// Malformed image, layout, mask or pixel observation.
    InvalidInput,
    /// Nonfinite/out-of-range lens coefficients or a missing model identity.
    InvalidModel,
    /// The sufficient whole-domain non-folding check could not admit this model.
    NonInvertibleModel,
    /// Source pixels, mask, calibration or image mode do not match.
    BasisMismatch,
    /// Input, table, allocation or output exceeds a hard bound.
    Limit,
    /// A finite numerical result could not be established.
    Numeric,
    /// Explicit work exhaustion/cancellation or another geometry failure.
    Geometry(GeometryError),
}
impl From<GeometryError> for RectificationError {
    fn from(error: GeometryError) -> Self { Self::Geometry(error) }
}
impl From<TwinError> for RectificationError {
    fn from(error: TwinError) -> Self {
        match error { TwinError::Geometry(e) => Self::Geometry(e), _ => Self::Numeric }
    }
}
impl std::fmt::Display for RectificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid rectification image or mask",
            Self::InvalidModel => "invalid rectification model",
            Self::NonInvertibleModel => "lens model not admitted over declared domain",
            Self::BasisMismatch => "rectification source basis mismatch",
            Self::Limit => "rectification limit exceeded",
            Self::Numeric => "rectification numeric failure",
            Self::Geometry(_) => "rectification geometry or work failure",
        })
    }
}
impl std::error::Error for RectificationError {}

/// Explicit transfer from decoded luma values to the full-range grayscale output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LumaRange {
    /// Samples already range over 0..255.
    Full,
    /// Nominal video luma 16..235, clamped then expanded to 0..255 with integer rounding.
    Video,
}
impl LumaRange {
    fn sample(self, value: u8) -> u64 {
        match self {
            Self::Full => u64::from(value),
            Self::Video => (u64::from(value.saturating_sub(16).min(219))*255 + 109)/219,
        }
    }
}

/// Owner-supplied frozen lens and source-mode basis. Does not certify accuracy.
/// Source and target share the same optical axes/center; target intrinsics may
/// crop or resize, but there is no silently rotated virtual camera.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RectificationSpec {
    /// Intrinsics on the original distorted pixel-edge grid.
    pub source: PinholeIntrinsics,
    /// Intrinsics of the resulting undistorted pinhole image.
    pub target: PinholeIntrinsics,
    /// Exact supported forward lens family and coefficient ordering.
    pub distortion: LensDistortion,
    /// Largest admitted undistorted normalized radius, in 1e-6..=64.
    pub maximum_radius: f64,
    /// Exact source image-domain identity (crop/rotation/stabilization included by owner).
    pub source_domain: [u8; 32],
    /// Exact admitted lens/calibration identity; not an authorization token.
    pub calibration: [u8; 32],
    /// Decoded source luma encoding, checked again on every frame.
    pub range: LumaRange,
}

/// Provenance of one original, possibly row-padded decoded source-luma plane.
/// It is deliberately not a `GrayImage`: raw distorted pixels cannot enter the
/// pinhole-only localization API through this type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawFrameIdentity {
    /// Original source/stream/PTS exposure identity. Rectification never replaces it.
    pub exposure: [u8; 32],
    /// Hash of the entire supplied plane, including explicitly present row padding.
    pub storage: [u8; 32],
    /// Hash of the width*height 0/1 source allowed-pixel mask.
    pub allowed_mask: [u8; 32],
    /// Exact raw source image domain.
    pub image_domain: [u8; 32],
    /// Exact calibration identity expected by the compiled plan.
    pub calibration: [u8; 32],
    /// Source logical width and height.
    pub dimensions: [u32; 2],
    /// Bytes per row, including padding; the slice must contain stride*height bytes.
    pub row_stride: u32,
    /// Source luma encoding; no implicit video-range conversion.
    pub range: LumaRange,
}

/// Borrowed source storage validated without treating its pixels as pinhole data.
pub struct RawGrayFrame<'a> {
    identity: RawFrameIdentity,
    storage: &'a [u8],
    allowed: &'a [u8],
}
impl std::fmt::Debug for RawGrayFrame<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawGrayFrame").field("dimensions", &self.identity.dimensions).finish_non_exhaustive()
    }
}
impl<'a> RawGrayFrame<'a> {
    /// Check complete layout, source bytes and mask before making them readable.
    pub fn new(identity: RawFrameIdentity, storage: &'a [u8], allowed: &'a [u8],
        budget: &mut WorkBudget<'_>) -> Result<Self, RectificationError> {
        budget.charge(0)?;
        let count = pixel_count(identity.dimensions)?;
        if [identity.exposure, identity.storage, identity.allowed_mask, identity.image_domain,
            identity.calibration].contains(&[0; 32]) { return Err(RectificationError::BasisMismatch); }
        if identity.row_stride < identity.dimensions[0] || identity.row_stride > 65_536 {
            return Err(RectificationError::InvalidInput);
        }
        let span = (identity.row_stride as usize).checked_mul(identity.dimensions[1] as usize)
            .ok_or(RectificationError::Limit)?;
        if span > MAX_STORAGE { return Err(RectificationError::Limit); }
        if span != storage.len() || count != allowed.len() { return Err(RectificationError::InvalidInput); }
        budget.charge((span + count*2) as u64)?;
        if ContentDigest::sha256(storage).bytes() != identity.storage
            || ContentDigest::sha256(allowed).bytes() != identity.allowed_mask {
            return Err(RectificationError::BasisMismatch);
        }
        for row in allowed.chunks(identity.dimensions[0] as usize) {
            budget.charge(0)?;
            if row.iter().any(|value| *value > 1) { return Err(RectificationError::InvalidInput); }
        }
        Ok(Self { identity, storage, allowed })
    }
    /// Unchanged source identity, never a newly claimed independent exposure.
    pub fn identity(&self) -> RawFrameIdentity { self.identity }
}

/// Complete geometric table accounting, independent of frame-specific privacy masks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapCoverage {
    /// Number of output samples with an in-source interpolation position.
    pub mapped: usize,
    /// Output samples beyond the explicitly admitted lens radius.
    pub outside_lens_domain: usize,
    /// Output samples outside the closed source pixel-center rectangle.
    pub outside_source: usize,
}

/// Immutable Q16 backward-sampling map, reusable across frames of one exact mode.
/// It stores eight bytes per target pixel and performs no per-frame trigonometry.
pub struct RectificationPlan {
    spec: RectificationSpec,
    map: Vec<u8>,
    map_digest: [u8; 32],
    output_domain: [u8; 32],
    coverage: MapCoverage,
}
impl std::fmt::Debug for RectificationPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RectificationPlan").field("coverage", &self.coverage).finish_non_exhaustive()
    }
}
impl RectificationPlan {
    /// Build a complete map after whole-domain lens admission. Outside-domain
    /// samples are unavailable, never border-replicated or silently extrapolated.
    pub fn compile(spec: RectificationSpec, budget: &mut WorkBudget<'_>) -> Result<Self, RectificationError> {
        budget.charge(0)?;
        let count = pixel_count(spec.target.dimensions())?;
        pixel_count(spec.source.dimensions())?;
        if spec.source_domain == [0; 32] || spec.calibration == [0; 32]
            || !spec.maximum_radius.is_finite() || !(1e-6..=64.0).contains(&spec.maximum_radius) {
            return Err(RectificationError::InvalidModel);
        }
        spec.distortion.validate(spec.maximum_radius, budget)?;
        let mut map = Vec::new();
        budget.charge((count*8) as u64)?;
        map.try_reserve_exact(count*8).map_err(|_| RectificationError::Limit)?;
        let [w,h] = spec.target.dimensions();
        let source_dimensions = spec.source.dimensions();
        let mut coverage = MapCoverage { mapped: 0, outside_lens_domain: 0, outside_source: 0 };
        for row in 0..h { for column in 0..w {
            budget.charge(96)?;
            let source = model::source_pixel(spec, [f64::from(column)+0.5, f64::from(row)+0.5])?;
            let sample = match source {
                None => { coverage.outside_lens_domain += 1; [INVALID; 2] }
                Some(pixel) => {
                    let indices = [pixel[0]-0.5, pixel[1]-0.5];
                    if (0..2).any(|i| indices[i] < 0.0 || indices[i] > f64::from(source_dimensions[i]-1)) {
                        coverage.outside_source += 1;
                        [INVALID; 2]
                    } else {
                        coverage.mapped += 1;
                        indices.map(|value| (value*f64::from(ONE)).round() as u32)
                    }
                }
            };
            for coordinate in sample { map.extend_from_slice(&coordinate.to_le_bytes()); }
        }}
        budget.charge(map.len() as u64)?;
        let map_digest = ContentDigest::sha256(&map).bytes();
        let mut basis = Vec::new();
        basis.try_reserve_exact(512).map_err(|_| RectificationError::Limit)?;
        basis.extend_from_slice(ALGORITHM);
        basis.extend_from_slice(&spec.source_domain);
        basis.extend_from_slice(&spec.calibration);
        for camera in [spec.source, spec.target] {
            for n in camera.dimensions() { basis.extend_from_slice(&n.to_le_bytes()); }
            for value in camera.focal_lengths().into_iter().chain(camera.principal_point()) { float(&mut basis, value); }
        }
        spec.distortion.encode(&mut basis);
        float(&mut basis, spec.maximum_radius);
        basis.push(match spec.range { LumaRange::Full => 0, LumaRange::Video => 1 });
        basis.extend_from_slice(&map_digest);
        budget.charge(basis.len() as u64)?;
        let output_domain = ContentDigest::sha256(&basis).bytes();
        budget.charge(0)?;
        Ok(Self { spec, map, map_digest, output_domain, coverage })
    }
    /// Exact model inputs, including target pinhole intrinsics.
    pub fn spec(&self) -> RectificationSpec { self.spec }
    /// Actual table identity; floating-point map construction is not universally bit-identical.
    pub fn map_digest(&self) -> [u8; 32] { self.map_digest }
    /// Derived image domain binds source mode, calibration, lens, output grid and actual map.
    pub fn output_domain(&self) -> [u8; 32] { self.output_domain }
    /// Geometric map scope only; not sensor coverage or physical accuracy.
    pub fn coverage(&self) -> MapCoverage { self.coverage }
    /// Continuous forward-lens source coordinate for a target pixel-edge location.
    /// No source-image clipping or quantization is applied; `None` is outside lens scope.
    pub fn source_pixel(&self, pixel: [f64; 2]) -> Result<Option<[f64; 2]>, RectificationError> {
        model::source_pixel(self.spec, pixel)
    }
    /// Exact quantized source position used by a target raster sample, in pixel-edge coordinates.
    /// `None` means the plan has no usable source sample there.
    pub fn sampling_position(&self, column: u32, row: u32) -> Result<Option<[f64; 2]>, RectificationError> {
        let [w,h] = self.spec.target.dimensions();
        if column >= w || row >= h { return Err(RectificationError::InvalidInput); }
        let offset = (row as usize*w as usize + column as usize)*8;
        let pair = decode_pair(&self.map[offset..offset+8]);
        Ok((pair[0] != INVALID).then(|| pair.map(|q| f64::from(q)/f64::from(ONE)+0.5)))
    }
    /// Rectify a complete admitted source plane. A positive-weight masked source
    /// sample invalidates the output before any contributing pixel values are read.
    /// The image and mask are published together only after complete success.
    pub fn apply(&self, source: &RawGrayFrame<'_>, budget: &mut WorkBudget<'_>)
        -> Result<RectifiedFrame, RectificationError> {
        budget.charge(0)?;
        let id = source.identity;
        if id.dimensions != self.spec.source.dimensions() || id.image_domain != self.spec.source_domain
            || id.calibration != self.spec.calibration || id.range != self.spec.range {
            return Err(RectificationError::BasisMismatch);
        }
        let count = self.map.len()/8;
        budget.charge((count*2) as u64)?;
        let mut pixels = filled(count)?;
        let mut allowed = filled(count)?;
        let [width,height] = id.dimensions.map(|x| x as usize);
        let mut visible = 0;
        let mut privacy_rejected = 0;
        for (out, encoded) in self.map.chunks_exact(8).enumerate() {
            budget.charge(32)?;
            let [xq,yq] = decode_pair(encoded);
            if xq == INVALID { continue; }
            let x0 = (xq/ONE) as usize;
            let y0 = (yq/ONE) as usize;
            let x1 = (x0+1).min(width-1);
            let y1 = (y0+1).min(height-1);
            let dx = u64::from(xq % ONE);
            let dy = u64::from(yq % ONE);
            let a = u64::from(ONE)-dx;
            let b = u64::from(ONE)-dy;
            let taps = [(x0,y0,a*b), (x1,y0,dx*b), (x0,y1,a*dy), (x1,y1,dx*dy)];
            if taps.iter().any(|&(x,y,weight)| weight != 0 && source.allowed[y*width+x] == 0) {
                privacy_rejected += 1;
                continue;
            }
            let mut sum = 0_u64;
            for (x,y,weight) in taps {
                if weight != 0 { sum += weight*id.range.sample(source.storage[y*id.row_stride as usize+x]); }
            }
            pixels[out] = ((sum + (1_u64<<31)) >> 32) as u8;
            allowed[out] = 1;
            visible += 1;
        }
        budget.charge((count*2) as u64)?;
        let identity = ImageIdentity { exposure: id.exposure, pixels: ContentDigest::sha256(&pixels).bytes(),
            image_domain: self.output_domain, dimensions: self.spec.target.dimensions() };
        let mask_digest = ContentDigest::sha256(&allowed).bytes();
        budget.charge(0)?;
        Ok(RectifiedFrame { identity, pixels, allowed, receipt: RectificationReceipt {
            source: id, output: identity, map_digest: self.map_digest, allowed_mask: mask_digest,
            coverage: self.coverage, allowed_pixels: visible, privacy_rejected,
        } })
    }
}

/// Lineage and scope for one computed frame; no field establishes source custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RectificationReceipt {
    /// Exact unchanged raw source exposure, storage, mode, mask and layout.
    pub source: RawFrameIdentity,
    /// Exact derived pixel and image-domain identity, retaining original exposure.
    pub output: ImageIdentity,
    /// Actual sampling-table identity.
    pub map_digest: [u8; 32],
    /// Exact derived full-range pinhole allowed mask.
    pub allowed_mask: [u8; 32],
    /// Static geometric unavailable-sample accounting.
    pub coverage: MapCoverage,
    /// Valid output samples after source-mask footprint projection.
    pub allowed_pixels: usize,
    /// Geometrically mapped samples refused by the source privacy mask.
    pub privacy_rejected: usize,
}

/// Owned image and mask with an immutable source-to-derived receipt.
pub struct RectifiedFrame {
    identity: ImageIdentity,
    pixels: Vec<u8>,
    allowed: Vec<u8>,
    receipt: RectificationReceipt,
}
impl std::fmt::Debug for RectifiedFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RectifiedFrame").field("dimensions", &self.identity.dimensions).finish_non_exhaustive()
    }
}
impl RectifiedFrame {
    /// Source-preserving pinhole image identity.
    pub fn identity(&self) -> ImageIdentity { self.identity }
    /// Full-range grayscale pixels; unavailable pixels are exactly zero.
    pub fn pixels(&self) -> &[u8] { &self.pixels }
    /// A 0/1 mask; zero pixels must not be used as scene observations.
    pub fn allowed(&self) -> &[u8] { &self.allowed }
    /// Source and actual computation bindings plus complete output-scope accounting.
    pub fn receipt(&self) -> RectificationReceipt { self.receipt }
    /// Borrow the existing native extractor's checked pinhole input type.
    pub fn as_gray_image(&self, budget: &mut WorkBudget<'_>) -> Result<GrayImage<'_>, LocalizationError> {
        GrayImage::new(self.identity, &self.pixels, &self.allowed, budget)
    }
}

fn pixel_count(dimensions: [u32; 2]) -> Result<usize, RectificationError> {
    if dimensions.iter().any(|n| *n == 0 || *n > 4096) { return Err(RectificationError::Limit); }
    let count = dimensions[0] as usize*dimensions[1] as usize;
    if count > MAX_RECTIFICATION_PIXELS { return Err(RectificationError::Limit); }
    Ok(count)
}
fn filled(count: usize) -> Result<Vec<u8>, RectificationError> {
    let mut output = Vec::new();
    output.try_reserve_exact(count).map_err(|_| RectificationError::Limit)?;
    output.resize(count, 0);
    Ok(output)
}
fn decode_pair(bytes: &[u8]) -> [u32; 2] {
    [u32::from_le_bytes([bytes[0],bytes[1],bytes[2],bytes[3]]),
     u32::from_le_bytes([bytes[4],bytes[5],bytes[6],bytes[7]])]
}
fn float(bytes: &mut Vec<u8>, value: f64) {
    bytes.extend_from_slice(&(if value == 0.0 { 0 } else { value.to_bits() }).to_le_bytes());
}

#![forbid(unsafe_code)]
//! Native grayscale HOG and learned linear classification over source-linked pixels.
//!
//! The fixed recipe is 64x128 / 16x16 blocks / 8x8 cells and stride / 9 unsigned
//! orientation bins, square-root gamma, Gaussian block weighting and L2-Hys.
//! Block/cell order and normalization follow the OpenCV CPU descriptor convention;
//! this scalar recipe uses f64 atan2 and accumulation, so it is NOT bit-identical
//! to OpenCV's approximate/SIMD math. A score is a model margin, not a probability.
//! See models/OPENCV_HOG_LICENSE.txt for the upstream algorithm notice.
//!
//! Privacy is checked before gradient samples are read. A denied center or any
//! denied gradient neighbor invalidates the block, and hence every using window.
//! Missing/private windows never become negative classifications. No threads, I/O,
//! model download, identity recognition, custody publication or effect authority.

use crate::foreground::ForegroundSource;
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, WorkBudget};

/// Fixed detector window in full-range grayscale pixels.
pub const HOG_WINDOW: [u32; 2] = [64, 128];
/// Number of normalized features in one window, excluding the classifier intercept.
pub const HOG_FEATURES: usize = 3780;
/// Exact number of little-endian F32 parameters, with the intercept last.
pub const HOG_PARAMETERS: usize = HOG_FEATURES + 1;
/// Hard logical-pixel ceiling; dimensions are separately bounded to 4096.
pub const MAX_HOG_PIXELS: usize = 4_194_304;
const RECIPE: &[u8] = b"fss/hog-gray/1;win64x128;block16;stride8;cell8;bins9-unsigned;gamma-sqrt;reflect101;gaussian-center8-sigma4;xy-major;f64-atan2-accumulate;hys-0.2-eps3.6-0.001;f32-descriptor;f64-score";

/// Non-disclosing errors; a refused operation returns no partial feature cache.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HogError {
    /// Invalid source, mask, profile, window coordinate or model shape.
    InvalidInput,
    /// Supplied bytes do not match their independently supplied identity.
    DigestMismatch,
    /// Nonfinite or out-of-range learned model coefficient.
    InvalidWeight,
    /// Complete input/output/allocation limit exceeded; never top-k truncation.
    Limit,
    /// Caller cancellation or deterministic work exhaustion.
    Work(GeometryError),
}
impl From<GeometryError> for HogError {
    fn from(error: GeometryError) -> Self { Self::Work(error) }
}
impl std::fmt::Display for HogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid HOG input or profile",
            Self::DigestMismatch => "HOG source or model digest mismatch",
            Self::InvalidWeight => "invalid HOG learned coefficient",
            Self::Limit => "HOG complete-output or allocation limit",
            Self::Work(_) => "HOG work interrupted",
        })
    }
}
impl std::error::Error for HogError {}

/// Exact feature recipe identity; changing preprocessing changes model generation.
pub fn hog_recipe_digest() -> [u8; 32] { ContentDigest::sha256(RECIPE).bytes() }

/// Frozen learned weights for this precise descriptor. Loading does not authenticate
/// the supplied provenance, license, class vocabulary or task-quality claims.
pub struct HogModel {
    weights: Vec<f32>,
    weights_digest: [u8; 32],
    provenance: [u8; 32],
    digest: [u8; 32],
}
impl std::fmt::Debug for HogModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HogModel").field("digest", &self.digest).finish_non_exhaustive()
    }
}
impl HogModel {
    /// Import exactly 3781 little-endian F32 values, intercept last. No weights
    /// are guessed, downloaded or filled in. The owner retains the source object
    /// and its separate provenance/license record; this is not model activation.
    pub fn from_f32_le(bytes: &[u8], expected: [u8; 32], provenance: [u8; 32],
        budget: &mut WorkBudget<'_>) -> Result<Self, HogError> {
        budget.charge(1)?;
        if bytes.len() != HOG_PARAMETERS * 4 || expected == [0; 32] || provenance == [0; 32] {
            return Err(HogError::InvalidInput);
        }
        budget.charge(bytes.len() as u64)?;
        if ContentDigest::sha256(bytes).bytes() != expected { return Err(HogError::DigestMismatch); }
        let mut weights = reserve(HOG_PARAMETERS)?;
        for word in bytes.as_chunks::<4>().0 {
            budget.charge(1)?;
            let value = f32::from_le_bytes([word[0], word[1], word[2], word[3]]);
            if !value.is_finite() || value.abs() > 1e6 { return Err(HogError::InvalidWeight); }
            weights.push(value);
        }
        let mut identity = [0_u8; 96];
        identity[..32].copy_from_slice(&hog_recipe_digest());
        identity[32..64].copy_from_slice(&expected);
        identity[64..].copy_from_slice(&provenance);
        budget.charge(128)?;
        let digest = ContentDigest::sha256(&identity).bytes();
        budget.charge(0)?;
        Ok(Self { weights, weights_digest: expected, provenance, digest })
    }
    /// Recipe, exact learned weights and provenance bound together.
    pub fn digest(&self) -> [u8; 32] { self.digest }
    /// Identity of the unchanged original F32LE weight object.
    pub fn weights_digest(&self) -> [u8; 32] { self.weights_digest }
    /// Owner-supplied provenance/license record, not authentication or qualification.
    pub fn provenance(&self) -> [u8; 32] { self.provenance }
}

/// Borrowed, verified tightly packed full-range luma and a separate 0/1 mask.
/// A hash check reads source bytes for integrity; feature computation reads no
/// intensity unless its complete gradient footprint is permitted.
pub struct HogFrame<'a> {
    source: ForegroundSource,
    pixels: &'a [u8],
    allowed: &'a [u8],
    mask_digest: [u8; 32],
}
impl std::fmt::Debug for HogFrame<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HogFrame").field("dimensions", &self.source.image.dimensions).finish_non_exhaustive()
    }
}
impl<'a> HogFrame<'a> {
    /// Validate complete shape, permission bytes and pixel identity before inference.
    /// The caller, not this constructor, establishes custody and access authority.
    pub fn new(source: ForegroundSource, pixels: &'a [u8], allowed: &'a [u8],
        budget: &mut WorkBudget<'_>) -> Result<Self, HogError> {
        budget.charge(1)?;
        let count = pixel_count(source.image.dimensions)?;
        if source.camera == 0 || source.clock == 0 || source.capture[0] > source.capture[1]
            || [source.image.exposure, source.image.pixels, source.image.image_domain,
                source.calibration].contains(&[0; 32]) || pixels.len() != count || allowed.len() != count {
            return Err(HogError::InvalidInput);
        }
        budget.charge(count as u64 * 3)?;
        if allowed.iter().any(|n| *n > 1) { return Err(HogError::InvalidInput); }
        if ContentDigest::sha256(pixels).bytes() != source.image.pixels { return Err(HogError::DigestMismatch); }
        let mask_digest = ContentDigest::sha256(allowed).bytes();
        budget.charge(0)?;
        Ok(Self { source, pixels, allowed, mask_digest })
    }
    /// Exact unchanged frame provenance and capture interval.
    pub fn source(&self) -> ForegroundSource { self.source }
    /// Exact permission generation; zero-valued pixels do not imply denial.
    pub fn mask_digest(&self) -> [u8; 32] { self.mask_digest }
}

#[derive(Clone, Copy, Default)]
struct Gradient { votes: [f64; 2], bin: usize, allowed: bool }
struct Block { values: [f32; 36], allowed: bool }

/// Reusable normalized block cache for one actual image, without model or class
/// decisions. All blocks use the image's original border context, not crop borders.
pub struct HogLevel {
    source: ForegroundSource,
    mask: [u8; 32],
    blocks_x: usize,
    blocks_y: usize,
    blocks: Vec<Block>,
}
impl std::fmt::Debug for HogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HogLevel").field("blocks", &self.blocks.len()).finish_non_exhaustive()
    }
}
impl HogLevel {
    /// Compute every stride-8 block once. Mask-invalid blocks are explicit unknowns,
    /// not zero-feature negative detections. Cancellation refuses the complete cache.
    pub fn compute(frame: &HogFrame<'_>, budget: &mut WorkBudget<'_>) -> Result<Self, HogError> {
        budget.charge(1)?;
        let [width, height] = frame.source.image.dimensions.map(|n| n as usize);
        let nx = if width < 16 { 0 } else { (width - 16) / 8 + 1 };
        let ny = if height < 16 { 0 } else { (height - 16) / 8 + 1 };
        let mut blocks = reserve(nx * ny)?;
        // Small images are valid but cannot supply the declared detection window.
        if nx != 0 && ny != 0 {
            budget.charge((width * height) as u64)?;
            let mut gradients = reserve(width * height)?;
            for y in 0..height {
                for x in 0..width {
                    budget.charge(32)?;
                    let indices = [y * width + x,
                        y * width + reflect_prev(x, width), y * width + reflect_next(x, width),
                        reflect_prev(y, height) * width + x, reflect_next(y, height) * width + x];
                    if indices.iter().any(|i| frame.allowed[*i] == 0) {
                        gradients.push(Gradient::default());
                        continue;
                    }
                    let dx = f64::from(frame.pixels[indices[2]]).sqrt() - f64::from(frame.pixels[indices[1]]).sqrt();
                    let dy = f64::from(frame.pixels[indices[4]]).sqrt() - f64::from(frame.pixels[indices[3]]).sqrt();
                    let magnitude = (dx * dx + dy * dy).sqrt();
                    let mut angle = dy.atan2(dx);
                    if angle < 0.0 { angle += std::f64::consts::TAU; }
                    let position = angle * (9.0 / std::f64::consts::PI) - 0.5;
                    let lower = position.floor();
                    let fraction = position - lower;
                    let bin = (lower as i32).rem_euclid(9) as usize;
                    gradients.push(Gradient { votes: [magnitude * (1.0 - fraction), magnitude * fraction], bin, allowed: true });
                }
            }
            for by in 0..ny { for bx in 0..nx {
                budget.charge(8192)?;
                blocks.push(histogram(&gradients, width, bx * 8, by * 8));
            }}
        }
        budget.charge(0)?;
        Ok(Self { source: frame.source, mask: frame.mask_digest, blocks_x: nx, blocks_y: ny, blocks })
    }
    /// Original actual image and source basis used for these features.
    pub fn source(&self) -> ForegroundSource { self.source }
    /// Permission-mask identity includes the gradient halo requirements.
    pub fn mask_digest(&self) -> [u8; 32] { self.mask }
    fn window(&self, origin: [u32; 2]) -> Result<[usize; 2], HogError> {
        let [x, y] = origin.map(|n| n as usize);
        if x % 8 != 0 || y % 8 != 0 || x / 8 + 7 > self.blocks_x || y / 8 + 15 > self.blocks_y {
            return Err(HogError::InvalidInput);
        }
        Ok([x / 8, y / 8])
    }
    /// Full fixed-length descriptor at a stride-8-aligned 64x128 window.
    /// None means a required pixel/gradient halo is denied; no partial descriptor.
    pub fn descriptor(&self, origin: [u32; 2], budget: &mut WorkBudget<'_>)
        -> Result<Option<[f32; HOG_FEATURES]>, HogError> {
        budget.charge(HOG_FEATURES as u64)?;
        let [x, y] = self.window(origin)?;
        let mut result = [0.0; HOG_FEATURES];
        for bx in 0..7 { for by in 0..15 {
            budget.charge(1)?;
            let block = &self.blocks[(y + by) * self.blocks_x + x + bx];
            if !block.allowed { return Ok(None); }
            let start = (bx * 15 + by) * 36;
            result[start..start + 36].copy_from_slice(&block.values);
        }}
        budget.charge(0)?;
        Ok(Some(result))
    }
    /// Evaluate actual learned coefficients; intercept plus dot product in f64.
    /// None remains unobservable, and a negative margin is not scene-absence evidence.
    pub fn score(&self, model: &HogModel, origin: [u32; 2], budget: &mut WorkBudget<'_>)
        -> Result<Option<f64>, HogError> {
        budget.charge(HOG_FEATURES as u64 * 2)?;
        let [x, y] = self.window(origin)?;
        let mut score = f64::from(model.weights[HOG_FEATURES]);
        for bx in 0..7 { for by in 0..15 {
            budget.charge(1)?;
            let block = &self.blocks[(y + by) * self.blocks_x + x + bx];
            if !block.allowed { return Ok(None); }
            let start = (bx * 15 + by) * 36;
            for (feature, weight) in block.values.iter().zip(&model.weights[start..start + 36]) {
                score += f64::from(*feature) * f64::from(*weight);
            }
        }}
        budget.charge(0)?;
        Ok(Some(score))
    }
}

fn histogram(gradients: &[Gradient], width: usize, x: usize, y: usize) -> Block {
    let mut hist = [0.0_f64; 36];
    for ix in 0..16 { for iy in 0..16 {
        let gradient = gradients[(y + iy) * width + x + ix];
        if !gradient.allowed { return Block { values: [0.0; 36], allowed: false }; }
        let cx = (ix as f64 + 0.5) / 8.0 - 0.5;
        let cy = (iy as f64 + 0.5) / 8.0 - 0.5;
        let x0 = cx.floor() as i32; let y0 = cy.floor() as i32;
        let fx = cx - f64::from(x0); let fy = cy - f64::from(y0);
        let dx = ix as f64 - 8.0; let dy = iy as f64 - 8.0;
        let gaussian = (-(dx * dx + dy * dy) / 32.0).exp();
        for (cellx, wx) in [(x0, 1.0 - fx), (x0 + 1, fx)] {
            for (celly, wy) in [(y0, 1.0 - fy), (y0 + 1, fy)] {
                if !(0..2).contains(&cellx) || !(0..2).contains(&celly) { continue; }
                let offset = (cellx as usize * 2 + celly as usize) * 9;
                let weight = gaussian * wx * wy;
                hist[offset + gradient.bin] += gradient.votes[0] * weight;
                hist[offset + (gradient.bin + 1) % 9] += gradient.votes[1] * weight;
            }
        }
    }}
    let scale = 1.0 / (hist.iter().map(|v| v * v).sum::<f64>().sqrt() + 3.6);
    for value in &mut hist { *value = (*value * scale).min(0.2); }
    let scale = 1.0 / (hist.iter().map(|v| v * v).sum::<f64>().sqrt() + 0.001);
    Block { values: hist.map(|v| (v * scale) as f32), allowed: true }
}
fn reflect_prev(n: usize, size: usize) -> usize { if n == 0 { usize::from(size > 1) } else { n - 1 } }
fn reflect_next(n: usize, size: usize) -> usize { if n + 1 == size { size.saturating_sub(2) } else { n + 1 } }
fn pixel_count(dimensions: [u32; 2]) -> Result<usize, HogError> {
    if dimensions.iter().any(|n| *n == 0 || *n > 4096) { return Err(HogError::InvalidInput); }
    let count = dimensions[0] as usize * dimensions[1] as usize;
    if count > MAX_HOG_PIXELS { return Err(HogError::Limit); }
    Ok(count)
}
fn reserve<T>(count: usize) -> Result<Vec<T>, HogError> {
    let mut values = Vec::new();
    values.try_reserve_exact(count).map_err(|_| HogError::Limit)?;
    Ok(values)
}

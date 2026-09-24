#![forbid(unsafe_code)]
//! Complete multiscale learned HOG scanning over owner-supplied source pixels.
//!
//! Every scheduled window survives as scored, suppressed, or unobservable. The
//! caller selects scales and thresholds explicitly; this is not model activation,
//! a calibrated probability, person identity, coverage, or absence evidence.

mod resize;

use crate::foreground::ForegroundSource;
use crate::hog::{
    HOG_WINDOW, HogError, HogFrame, HogLevel, HogModel, MAX_HOG_PIXELS, hog_recipe_digest,
};
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;

/// Maximum explicitly selected pyramid levels; no automatic scale search.
pub const MAX_SCAN_LEVELS: usize = 16;
/// Hard complete-window ceiling, including private and below-threshold windows.
pub const MAX_SCAN_WINDOWS: usize = 16_384;
/// Hard above-threshold ceiling BEFORE suppression, not a top-k output limit.
pub const MAX_SCAN_CANDIDATES: usize = 1024;

/// Exact resized grid. Actual source/grid ratios determine coordinate mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanLevel {
    /// Width and height, each 1..4096, with at most MAX_HOG_PIXELS samples.
    pub dimensions: [u32; 2],
}
/// Frozen scan/ranking policy, not a learned or silently activated deployment default.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ScanPolicy {
    /// Pixel step on each resized grid; positive multiples of the block stride 8.
    pub stride: [u32; 2],
    /// Inclusive raw linear margin gate; never a probability or class-confidence claim.
    pub minimum_margin: f64,
    /// Suppress when source-box IoU is at least this many millionths, 1..1,000,000.
    pub suppression_iou_ppm: u32,
    /// Complete scheduled windows, including all denied and negative windows.
    pub maximum_windows: usize,
    /// Complete above-threshold windows before suppression; overflow refuses the scan.
    pub maximum_candidates: usize,
}
impl ScanPolicy {
    fn validate(self) -> Result<(), HogError> {
        if self
            .stride
            .iter()
            .any(|v| *v == 0 || *v > 4096 || *v % 8 != 0)
            || !self.minimum_margin.is_finite()
            || self.minimum_margin.abs() > 1e10
            || !(1..=1_000_000).contains(&self.suppression_iou_ppm)
            || !(1..=MAX_SCAN_WINDOWS).contains(&self.maximum_windows)
            || !(1..=MAX_SCAN_CANDIDATES).contains(&self.maximum_candidates)
        {
            return Err(HogError::InvalidInput);
        }
        Ok(())
    }
}
/// Explicit fate of a window; suppression does not erase its actual margin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowDisposition {
    /// A required pixel or gradient neighbor is private. No margin was computed.
    Unobservable,
    /// A valid model margin was below the explicit gate; not scene absence.
    BelowThreshold,
    /// Retained after deterministic overlap suppression; still an uncalibrated proposal.
    Selected,
    /// Overlaps the named selected window under the explicit source-box IoU rule.
    Suppressed {
        /// Stable report-local window ID, not a track or physical entity ID.
        by: u64,
    },
}
/// An actual window on a declared grid, with conservative full-source image bounds.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ScoredWindow {
    /// One-based ordinal in canonical level and row-major origin order.
    pub id: u64,
    /// Zero-based ordinal of the source-bound level receipt.
    pub level: usize,
    /// Upper-left corner of the 64x128 window on that level's grid.
    pub origin: [u32; 2],
    /// Floor-rounded lower pixel-edge corner on the original image.
    pub source_min: [u32; 2],
    /// Ceil-rounded exclusive upper pixel-edge corner on the original image.
    pub source_max: [u32; 2],
    /// None only when required pixels are unobservable; never replaced with zero.
    pub margin: Option<f64>,
    /// Selection or explicit suppression/omission explanation.
    pub disposition: WindowDisposition,
}
/// Binds the actual resampled image and mask to the original exposure, not a new exposure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanLevelReceipt {
    /// Actual grid dimensions; even too-small zero-window levels remain present.
    pub dimensions: [u32; 2],
    /// Exact derived pixels/domain, retaining original camera, calibration, time and exposure.
    pub source: ForegroundSource,
    /// Actual permission mask after checking all nonzero interpolation contributors.
    pub mask_digest: [u8; 32],
    /// Number of scheduled windows on this level, including private windows.
    pub windows: usize,
}
/// Privately constructed complete scan. No partial report escapes a refused operation.
#[derive(Debug)]
pub struct HogScan {
    source: ForegroundSource,
    mask: [u8; 32],
    model: [u8; 32],
    generation: [u8; 32],
    policy: ScanPolicy,
    levels: Vec<ScanLevelReceipt>,
    windows: Vec<ScoredWindow>,
    digest: [u8; 32],
}
impl HogScan {
    /// Exact original source and capture basis, not the resampled pixel identity.
    pub fn source(&self) -> ForegroundSource {
        self.source
    }
    /// Original full-image permission identity.
    pub fn mask_digest(&self) -> [u8; 32] {
        self.mask
    }
    /// Actual learned coefficients, native recipe and owner-provided provenance identity.
    pub fn model_digest(&self) -> [u8; 32] {
        self.model
    }
    /// Complete model/scale/preprocessing/threshold/suppression generation.
    pub fn generation(&self) -> [u8; 32] {
        self.generation
    }
    /// Exact normalized settings used for this scan.
    pub fn policy(&self) -> ScanPolicy {
        self.policy
    }
    /// All declared grids in descending pixel-count/dimension order.
    pub fn levels(&self) -> &[ScanLevelReceipt] {
        &self.levels
    }
    /// Every window, not only positives or survivors.
    pub fn windows(&self) -> &[ScoredWindow] {
        &self.windows
    }
    /// Selected proposals in stable report order. Alternatives remain in windows().
    pub fn selected(&self) -> impl Iterator<Item = &ScoredWindow> {
        self.windows
            .iter()
            .filter(|w| w.disposition == WindowDisposition::Selected)
    }
    /// Complete internal derivation fingerprint; not a durable ledger publication.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Scan actual luma with exact local learned weights. One grid/cache is live at a time.
///
/// Grid sizes and origins are exhaustive only within the explicit schedule. Missing
/// scales, negative margins and suppressed windows cannot supply negative evidence.
/// Native HOG/OpenCV numerical differences still require independent model validation.
#[allow(clippy::too_many_arguments)]
pub fn scan_hog(
    source: ForegroundSource,
    pixels: &[u8],
    allowed: &[u8],
    model: &HogModel,
    levels: &[ScanLevel],
    mut policy: ScanPolicy,
    budget: &mut WorkBudget<'_>,
) -> Result<HogScan, HogError> {
    budget.charge(1)?;
    policy.validate()?;
    if policy.minimum_margin == 0.0 {
        policy.minimum_margin = 0.0;
    }
    if !(1..=MAX_SCAN_LEVELS).contains(&levels.len()) {
        return Err(HogError::Limit);
    }
    let original = HogFrame::new(source, pixels, allowed, budget)?;
    let mut ordered = reserve(levels.len())?;
    ordered.extend_from_slice(levels);
    budget.charge((levels.len() * levels.len()) as u64)?;
    ordered.sort_unstable_by_key(|l| {
        std::cmp::Reverse((
            u64::from(l.dimensions[0]) * u64::from(l.dimensions[1]),
            l.dimensions,
        ))
    });
    let mut total = 0_usize;
    for (i, level) in ordered.iter().enumerate() {
        count(level.dimensions)?;
        if i > 0 && ordered[i - 1] == *level {
            return Err(HogError::InvalidInput);
        }
        total = total
            .checked_add(window_count(level.dimensions, policy.stride))
            .ok_or(HogError::Limit)?;
        if total > policy.maximum_windows {
            return Err(HogError::Limit);
        }
    }
    let generation = generation(model, &ordered, policy, budget)?;
    let mut receipts = reserve(ordered.len())?;
    let mut windows = reserve(total)?;
    let mut positives = reserve(policy.maximum_candidates)?;
    for (index, level) in ordered.iter().enumerate() {
        budget.charge(1)?;
        let resized = if level.dimensions == source.image.dimensions {
            None
        } else {
            Some(resize::resample(
                source,
                pixels,
                allowed,
                level.dimensions,
                budget,
            )?)
        };
        // This verification also binds zeroed denied pixels and the new image domain.
        let derived = resized
            .as_ref()
            .map(|r| HogFrame::new(r.source, &r.pixels, &r.allowed, budget))
            .transpose()?;
        let frame = derived.as_ref().unwrap_or(&original);
        let n = window_count(level.dimensions, policy.stride);
        receipts.push(ScanLevelReceipt {
            dimensions: level.dimensions,
            source: frame.source(),
            mask_digest: frame.mask_digest(),
            windows: n,
        });
        if n == 0 {
            continue;
        }
        let cache = HogLevel::compute(frame, budget)?;
        for y in (0..=level.dimensions[1] - HOG_WINDOW[1]).step_by(policy.stride[1] as usize) {
            for x in (0..=level.dimensions[0] - HOG_WINDOW[0]).step_by(policy.stride[0] as usize) {
                budget.charge(16)?;
                let margin = cache.score(model, [x, y], budget)?;
                if margin.is_some_and(|v| !v.is_finite()) {
                    return Err(HogError::InvalidWeight);
                }
                let disposition = match margin {
                    None => WindowDisposition::Unobservable,
                    Some(value) if value < policy.minimum_margin => {
                        WindowDisposition::BelowThreshold
                    }
                    Some(_) => {
                        if positives.len() == policy.maximum_candidates {
                            return Err(HogError::Limit);
                        }
                        positives.push(windows.len());
                        WindowDisposition::Selected
                    }
                };
                let (source_min, source_max) =
                    source_bounds([x, y], level.dimensions, source.image.dimensions);
                windows.push(ScoredWindow {
                    id: windows.len() as u64 + 1,
                    level: index,
                    origin: [x, y],
                    source_min,
                    source_max,
                    margin,
                    disposition,
                });
            }
        }
    }
    budget.charge((positives.len() * positives.len()) as u64)?;
    // Stable source-grid order breaks equal margins, independent of supplied scale order.
    positives.sort_unstable_by(|a, b| {
        windows[*b]
            .margin
            .unwrap_or(f64::NEG_INFINITY)
            .total_cmp(&windows[*a].margin.unwrap_or(f64::NEG_INFINITY))
            .then_with(|| a.cmp(b))
    });
    for (position, &candidate) in positives.iter().enumerate() {
        for &kept in &positives[..position] {
            budget.charge(16)?;
            if windows[kept].disposition == WindowDisposition::Selected
                && overlaps(
                    windows[candidate],
                    windows[kept],
                    policy.suppression_iou_ppm,
                )
            {
                windows[candidate].disposition = WindowDisposition::Suppressed {
                    by: windows[kept].id,
                };
                break;
            }
        }
    }
    let mut report = HogScan {
        source,
        mask: original.mask_digest(),
        model: model.digest(),
        generation,
        policy,
        levels: receipts,
        windows,
        digest: [0; 32],
    };
    report.digest = report_digest(&report, budget)?;
    budget.charge(0)?;
    Ok(report)
}

fn count(dimensions: [u32; 2]) -> Result<usize, HogError> {
    if dimensions.iter().any(|n| *n == 0 || *n > 4096) {
        return Err(HogError::InvalidInput);
    }
    let n = dimensions[0] as usize * dimensions[1] as usize;
    if n > MAX_HOG_PIXELS {
        return Err(HogError::Limit);
    }
    Ok(n)
}
fn window_count(dimensions: [u32; 2], stride: [u32; 2]) -> usize {
    if dimensions[0] < HOG_WINDOW[0] || dimensions[1] < HOG_WINDOW[1] {
        return 0;
    }
    ((dimensions[0] - HOG_WINDOW[0]) / stride[0] + 1) as usize
        * ((dimensions[1] - HOG_WINDOW[1]) / stride[1] + 1) as usize
}
fn source_bounds(origin: [u32; 2], grid: [u32; 2], source: [u32; 2]) -> ([u32; 2], [u32; 2]) {
    let mut min = [0; 2];
    let mut max = [0; 2];
    for axis in 0..2 {
        let divisor = u64::from(grid[axis]);
        min[axis] = (u64::from(origin[axis]) * u64::from(source[axis]) / divisor) as u32;
        max[axis] = (u64::from(origin[axis] + HOG_WINDOW[axis]) * u64::from(source[axis]))
            .div_ceil(divisor) as u32;
    }
    (min, max)
}
fn overlaps(a: ScoredWindow, b: ScoredWindow, threshold: u32) -> bool {
    let intersection = (0..2)
        .map(|i| {
            u64::from(
                a.source_max[i]
                    .min(b.source_max[i])
                    .saturating_sub(a.source_min[i].max(b.source_min[i])),
            )
        })
        .product::<u64>();
    let area = |w: ScoredWindow| {
        (0..2)
            .map(|i| u64::from(w.source_max[i] - w.source_min[i]))
            .product::<u64>()
    };
    let union = area(a) + area(b) - intersection;
    intersection * 1_000_000 >= union * u64::from(threshold)
}
fn reserve<T>(n: usize) -> Result<Vec<T>, HogError> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| HogError::Limit)?;
    Ok(v)
}
fn put(bytes: &mut Vec<u8>, n: u64) {
    bytes.extend_from_slice(&n.to_le_bytes());
}
fn encode_source(bytes: &mut Vec<u8>, source: ForegroundSource) {
    for id in [
        source.image.exposure,
        source.image.pixels,
        source.image.image_domain,
        source.calibration,
    ] {
        bytes.extend_from_slice(&id);
    }
    for n in [
        source.camera,
        source.clock,
        source.capture[0],
        source.capture[1],
        u64::from(source.image.dimensions[0]),
        u64::from(source.image.dimensions[1]),
    ] {
        put(bytes, n);
    }
}
fn generation(
    model: &HogModel,
    levels: &[ScanLevel],
    p: ScanPolicy,
    budget: &mut WorkBudget<'_>,
) -> Result<[u8; 32], HogError> {
    let mut bytes = reserve(1024)?;
    bytes.extend_from_slice(b"fss/hog-scan/generation/1\0bilinear-centers-rational-half-up;nonzero-permission;floor-ceil-source-box;inclusive-iou;score-desc-id-ties\0");
    bytes.extend_from_slice(&hog_recipe_digest());
    bytes.extend_from_slice(&model.digest());
    for n in [
        u64::from(p.stride[0]),
        u64::from(p.stride[1]),
        p.minimum_margin.to_bits(),
        u64::from(p.suppression_iou_ppm),
        p.maximum_windows as u64,
        p.maximum_candidates as u64,
        levels.len() as u64,
    ] {
        put(&mut bytes, n);
    }
    for level in levels {
        for n in level.dimensions {
            put(&mut bytes, u64::from(n));
        }
    }
    budget.charge(bytes.len() as u64)?;
    Ok(ContentDigest::sha256(&bytes).bytes())
}
fn report_digest(report: &HogScan, budget: &mut WorkBudget<'_>) -> Result<[u8; 32], HogError> {
    let size = 512 + report.levels.len() * 224 + report.windows.len() * 96;
    budget.charge(size as u64)?;
    let mut bytes = reserve(size)?;
    bytes.extend_from_slice(b"fss/hog-scan/report/1\0");
    bytes.extend_from_slice(&report.generation);
    bytes.extend_from_slice(&report.mask);
    encode_source(&mut bytes, report.source);
    put(&mut bytes, report.levels.len() as u64);
    for level in &report.levels {
        budget.charge(1)?;
        encode_source(&mut bytes, level.source);
        bytes.extend_from_slice(&level.mask_digest);
        put(&mut bytes, level.windows as u64);
    }
    put(&mut bytes, report.windows.len() as u64);
    for window in &report.windows {
        budget.charge(1)?;
        put(&mut bytes, window.id);
        put(&mut bytes, window.level as u64);
        for n in window
            .origin
            .into_iter()
            .chain(window.source_min)
            .chain(window.source_max)
        {
            put(&mut bytes, u64::from(n));
        }
        bytes.push(u8::from(window.margin.is_some()));
        if let Some(value) = window.margin {
            put(&mut bytes, value.to_bits());
        }
        match window.disposition {
            WindowDisposition::Unobservable => bytes.push(0),
            WindowDisposition::BelowThreshold => bytes.push(1),
            WindowDisposition::Selected => bytes.push(2),
            WindowDisposition::Suppressed { by } => {
                bytes.push(3);
                put(&mut bytes, by);
            }
        }
    }
    budget.charge(bytes.len() as u64)?;
    Ok(ContentDigest::sha256(&bytes).bytes())
}

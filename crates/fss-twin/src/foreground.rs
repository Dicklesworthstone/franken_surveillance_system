#![forbid(unsafe_code)]
//! Source-bound changed-region proposals for a fixed camera, not semantic detections.
//!
//! The owner selects reference exposures. A frozen envelope never learns a stopped
//! target away. All comparisons are conditional on that background and image mode;
//! no unchanged pixel, empty result, or filtered component certifies absence.

use crate::localization::ImageIdentity;
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, WorkBudget};

/// Hard image/workspace bound shared with native rectification.
pub const MAX_FOREGROUND_PIXELS: usize = 4_194_304;
/// A baseline uses at least three and at most 31 distinct source exposures.
pub const MAX_BACKGROUND_FRAMES: usize = 31;
/// Complete retained-component ceiling; overflow is an error, never top-k pruning.
pub const MAX_FOREGROUND_REGIONS: usize = 4096;

/// Errors expose no partial result or private pixel values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForegroundError {
    /// Invalid policy, shape, mask, source record or capture interval.
    InvalidInput,
    /// Camera, calibration, clock, image domain, or exact pixel digest differs.
    BasisMismatch,
    /// Reference exposures overlap or a query reuses reference evidence.
    ReusedExposure,
    /// Query is not after reference capture, or exceeds baseline validity.
    OutsideValidity,
    /// Image, complete-region or allocation limit exceeded.
    Limit,
    /// Owner cancellation or exhausted deterministic work allowance.
    Geometry(GeometryError),
}
impl From<GeometryError> for ForegroundError {
    fn from(value: GeometryError) -> Self {
        Self::Geometry(value)
    }
}
impl std::fmt::Display for ForegroundError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid foreground input",
            Self::BasisMismatch => "foreground basis mismatch",
            Self::ReusedExposure => "foreground exposure reused",
            Self::OutsideValidity => "foreground baseline not valid at capture",
            Self::Limit => "foreground complete-output or allocation limit",
            Self::Geometry(_) => "foreground work interrupted",
        })
    }
}
impl std::error::Error for ForegroundError {}

/// Source and calibration basis for actual pixels, not a detector confidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForegroundSource {
    /// Pixel-edge, full-range grayscale image with its exact image-domain chain.
    pub image: ImageIdentity,
    /// Owner-resolved physical camera handle, nonzero.
    pub camera: u64,
    /// Exact admitted calibration/content generation; nonzero, not authority.
    pub calibration: [u8; 32],
    /// Common capture-clock identity; nonzero.
    pub clock: u64,
    /// Inclusive possible capture times, not receive times.
    pub capture: [u64; 2],
}

/// Verified borrowed image. Mask bytes are 0/1; no intensity is read where denied.
pub struct ForegroundFrame<'a> {
    source: ForegroundSource,
    pixels: &'a [u8],
    allowed: &'a [u8],
    mask_digest: [u8; 32],
}
impl std::fmt::Debug for ForegroundFrame<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForegroundFrame").finish_non_exhaustive()
    }
}
impl<'a> ForegroundFrame<'a> {
    /// Bind tightly packed full-range luma and exact dimensions. No decode occurs.
    /// Hashes identify supplied bytes; source custody and access remain external.
    pub fn new(
        source: ForegroundSource,
        pixels: &'a [u8],
        allowed: &'a [u8],
        budget: &mut WorkBudget<'_>,
    ) -> Result<Self, ForegroundError> {
        budget.charge(0)?;
        let [w, h] = source.image.dimensions;
        if w == 0 || h == 0 || w > 4096 || h > 4096 {
            return Err(ForegroundError::InvalidInput);
        }
        let count = (w as usize)
            .checked_mul(h as usize)
            .ok_or(ForegroundError::Limit)?;
        if count > MAX_FOREGROUND_PIXELS {
            return Err(ForegroundError::Limit);
        }
        if pixels.len() != count
            || allowed.len() != count
            || source.camera == 0
            || source.clock == 0
            || source.capture[0] > source.capture[1]
            || [
                source.image.exposure,
                source.image.pixels,
                source.image.image_domain,
                source.calibration,
            ]
            .contains(&[0; 32])
        {
            return Err(ForegroundError::InvalidInput);
        }
        budget.charge(count as u64 * 3)?;
        if allowed.iter().any(|b| *b > 1) {
            return Err(ForegroundError::InvalidInput);
        }
        if ContentDigest::sha256(pixels).bytes() != source.image.pixels {
            return Err(ForegroundError::BasisMismatch);
        }
        let mask_digest = ContentDigest::sha256(allowed).bytes();
        budget.charge(0)?;
        Ok(Self {
            source,
            pixels,
            allowed,
            mask_digest,
        })
    }
    /// Original immutable source basis, including capture interval.
    pub fn source(&self) -> ForegroundSource {
        self.source
    }
    /// Complete allowed-mask identity, including newly exposed unknown regions.
    pub fn mask_digest(&self) -> [u8; 32] {
        self.mask_digest
    }
}

/// Explicit baseline selection assumption, not automatic scene learning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackgroundPolicy {
    /// Nonzero source record explaining why these references may form a baseline.
    pub selection_evidence: [u8; 32],
    /// Reference/query validity on the declared capture clock.
    pub validity: [u64; 2],
    /// Maximum observed per-pixel range admitted as stable, 0..=254.
    pub maximum_spread: u8,
}

/// Frozen per-pixel luma envelope. Unknown/variable/private pixels are not background.
/// There is deliberately no online update, timeout adaptation or auto-rebaseline.
pub struct BackgroundModel {
    digest: [u8; 32],
    sources: Vec<(ForegroundSource, [u8; 32])>,
    policy: BackgroundPolicy,
    lower: Vec<u8>,
    upper: Vec<u8>,
    known: Vec<u8>,
    known_pixels: usize,
}
impl std::fmt::Debug for BackgroundModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackgroundModel")
            .field("references", &self.sources.len())
            .field("known_pixels", &self.known_pixels)
            .finish_non_exhaustive()
    }
}
impl BackgroundModel {
    /// Compile an immutable envelope from 3..=31 ordered, disjoint exposures.
    /// All references must permit a pixel and agree within the selected spread.
    /// The selection record is retained; it is not authenticated or judged here.
    pub fn build(
        frames: &[ForegroundFrame<'_>],
        policy: BackgroundPolicy,
        budget: &mut WorkBudget<'_>,
    ) -> Result<Self, ForegroundError> {
        budget.charge(0)?;
        if !(3..=MAX_BACKGROUND_FRAMES).contains(&frames.len()) {
            return Err(ForegroundError::Limit);
        }
        if policy.selection_evidence == [0; 32]
            || policy.validity[0] > policy.validity[1]
            || policy.maximum_spread == 255
        {
            return Err(ForegroundError::InvalidInput);
        }
        let first = frames[0].source;
        let mut sources = reserve(frames.len())?;
        for (i, frame) in frames.iter().enumerate() {
            budget.charge(16 + i as u64)?;
            if !same_mode(first, frame.source) {
                return Err(ForegroundError::BasisMismatch);
            }
            if frames[..i]
                .iter()
                .any(|f| f.source.image.exposure == frame.source.image.exposure)
                || (i > 0 && frames[i - 1].source.capture[1] >= frame.source.capture[0])
            {
                return Err(ForegroundError::ReusedExposure);
            }
            if frame.source.capture[0] < policy.validity[0]
                || frame.source.capture[1] > policy.validity[1]
            {
                return Err(ForegroundError::OutsideValidity);
            }
            sources.push((frame.source, frame.mask_digest));
        }
        let count = frames[0].pixels.len();
        budget.charge(count as u64 * 3)?;
        let mut lower = filled(count, 0_u8)?;
        let mut upper = filled(count, 0_u8)?;
        let mut known = filled(count, 0_u8)?;
        let mut known_pixels = 0;
        for i in 0..count {
            budget.charge(frames.len() as u64 * 3)?;
            // Check every permission before any intensity enters this pixel's model.
            if frames.iter().any(|f| f.allowed[i] == 0) {
                continue;
            }
            let lo = frames
                .iter()
                .map(|f| f.pixels[i])
                .min()
                .ok_or(ForegroundError::InvalidInput)?;
            let hi = frames
                .iter()
                .map(|f| f.pixels[i])
                .max()
                .ok_or(ForegroundError::InvalidInput)?;
            if hi - lo <= policy.maximum_spread {
                lower[i] = lo;
                upper[i] = hi;
                known[i] = 1;
                known_pixels += 1;
            }
        }
        let mut bytes = reserve(256 + frames.len() * 200)?;
        bytes.extend_from_slice(b"fss/frozen-background/reference/1\0");
        bytes.extend_from_slice(&policy.selection_evidence);
        for t in policy.validity {
            integer(&mut bytes, t);
        }
        bytes.push(policy.maximum_spread);
        integer(&mut bytes, sources.len() as u64);
        for (source, mask) in &sources {
            source_bytes(&mut bytes, *source);
            bytes.extend_from_slice(mask);
        }
        budget.charge(count as u64 * 3 + bytes.len() as u64)?;
        for values in [&lower, &upper, &known] {
            bytes.extend_from_slice(&ContentDigest::sha256(values).bytes());
        }
        let digest = ContentDigest::sha256(&bytes).bytes();
        budget.charge(0)?;
        Ok(Self {
            digest,
            sources,
            policy,
            lower,
            upper,
            known,
            known_pixels,
        })
    }
    /// Versioned local derivation fingerprint, not a registered durable schema.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Every reference source and mask, in capture order.
    pub fn sources(&self) -> &[(ForegroundSource, [u8; 32])] {
        &self.sources
    }
    /// Explicit unchanged background policy, including temporal validity.
    pub fn policy(&self) -> BackgroundPolicy {
        self.policy
    }
    /// Count of pixels with an admitted envelope, not physical coverage.
    pub fn known_pixels(&self) -> usize {
        self.known_pixels
    }

    /// Compare actual pixels and extract all retained four-connected changed regions.
    /// Broad lighting/motion changes are flagged, never normalized away as harmless.
    pub fn detect(
        &self,
        frame: &ForegroundFrame<'_>,
        policy: ForegroundPolicy,
        budget: &mut WorkBudget<'_>,
    ) -> Result<ForegroundReport, ForegroundError> {
        budget.charge(0)?;
        if !same_mode(self.sources[0].0, frame.source) {
            return Err(ForegroundError::BasisMismatch);
        }
        if self
            .sources
            .iter()
            .any(|s| s.0.image.exposure == frame.source.image.exposure)
        {
            return Err(ForegroundError::ReusedExposure);
        }
        let end = self
            .sources
            .last()
            .ok_or(ForegroundError::InvalidInput)?
            .0
            .capture[1];
        if frame.source.capture[0] <= end
            || frame.source.capture[0] < self.policy.validity[0]
            || frame.source.capture[1] > self.policy.validity[1]
        {
            return Err(ForegroundError::OutsideValidity);
        }
        policy.validate()?;
        let count = self.known.len();
        budget.charge(count as u64 * 6)?;
        let mut states = filled(count, 0_u8)?;
        let mut labels = filled(count, 0_u32)?;
        let mut comparable = 0;
        let mut changed = 0;
        for (i, state) in states.iter_mut().enumerate() {
            budget.charge(1)?;
            if self.known[i] == 0 || frame.allowed[i] == 0 {
                continue;
            }
            comparable += 1;
            let value = frame.pixels[i];
            *state = if self.lower[i].saturating_sub(value) > policy.minimum_change {
                2
            } else if value.saturating_sub(self.upper[i]) > policy.minimum_change {
                3
            } else {
                1
            };
            if *state >= 2 {
                changed += 1;
            }
        }
        let mut queue = reserve(changed)?;
        let mut regions = reserve(policy.maximum_regions)?;
        let [width, height] = frame.source.image.dimensions.map(|x| x as usize);
        let mut small_components = 0;
        let mut small_pixels = 0;
        for seed in 0..count {
            budget.charge(1)?;
            if states[seed] < 2 || labels[seed] != 0 {
                continue;
            }
            let id = seed as u32 + 1;
            labels[seed] = id;
            queue.clear();
            queue.push(seed as u32);
            let mut cursor = 0;
            let mut min = [width as u32, height as u32];
            let mut max = [0_u32; 2];
            let mut brighter = 0;
            let mut darker = 0;
            let mut touches_unknown = false;
            let mut touches_edge = false;
            while cursor < queue.len() {
                budget.charge(8)?;
                let i = queue[cursor] as usize;
                cursor += 1;
                let (x, y) = (i % width, i / width);
                min[0] = min[0].min(x as u32);
                min[1] = min[1].min(y as u32);
                max[0] = max[0].max(x as u32 + 1);
                max[1] = max[1].max(y as u32 + 1);
                brighter += usize::from(states[i] == 3);
                darker += usize::from(states[i] == 2);
                touches_edge |= x == 0 || y == 0 || x + 1 == width || y + 1 == height;
                // Lazy subtraction is required at the top/left edge (no unsigned underflow).
                let neighbors = [
                    (x > 0).then(|| i - 1),
                    (x + 1 < width).then_some(i + 1),
                    (y > 0).then(|| i - width),
                    (y + 1 < height).then_some(i + width),
                ];
                for neighbor in neighbors.into_iter().flatten() {
                    touches_unknown |= states[neighbor] == 0;
                    if states[neighbor] >= 2 && labels[neighbor] == 0 {
                        labels[neighbor] = id;
                        queue.push(neighbor as u32);
                    }
                }
            }
            if queue.len() < policy.minimum_area {
                small_components += 1;
                small_pixels += queue.len();
            } else {
                if regions.len() == policy.maximum_regions {
                    return Err(ForegroundError::Limit);
                }
                regions.push(ForegroundRegion {
                    id,
                    area: queue.len(),
                    min,
                    max,
                    brighter,
                    darker,
                    touches_unknown,
                    touches_edge,
                });
            }
        }
        let assessment = if comparable == 0 {
            FrameAssessment::NoComparablePixels
        } else if changed == 0 {
            FrameAssessment::NoAboveThresholdChange
        } else if changed as u64 * 1000
            >= comparable as u64 * u64::from(policy.widespread_per_mille)
        {
            FrameAssessment::WidespreadChange
        } else {
            FrameAssessment::LocalChange
        };
        // Canonical labels include even size-filtered components; omissions remain inspectable.
        budget.charge(count as u64 * 6)?;
        let mut label_bytes = reserve(count * 4)?;
        for label in &labels {
            label_bytes.extend_from_slice(&label.to_le_bytes());
        }
        let mut bytes = reserve(512)?;
        bytes.extend_from_slice(b"fss/foreground-regions/reference/1\0");
        bytes.extend_from_slice(&self.digest);
        source_bytes(&mut bytes, frame.source);
        bytes.extend_from_slice(&frame.mask_digest);
        bytes.push(policy.minimum_change);
        integer(&mut bytes, policy.minimum_area as u64);
        integer(&mut bytes, policy.maximum_regions as u64);
        integer(&mut bytes, u64::from(policy.widespread_per_mille));
        bytes.extend_from_slice(&ContentDigest::sha256(&states).bytes());
        bytes.extend_from_slice(&ContentDigest::sha256(&label_bytes).bytes());
        let digest = ContentDigest::sha256(&bytes).bytes();
        budget.charge(0)?;
        Ok(ForegroundReport {
            digest,
            baseline: self.digest,
            source: frame.source,
            mask: frame.mask_digest,
            policy,
            states,
            labels,
            regions,
            comparable,
            changed,
            small_components,
            small_pixels,
            assessment,
        })
    }
}

/// All settings are part of the report identity, not implicit deployment defaults.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForegroundPolicy {
    /// Strict distance outside the learned luma envelope, 1..=254.
    pub minimum_change: u8,
    /// Retain components with at least this many pixels. Smaller ones remain in labels.
    pub minimum_area: usize,
    /// Entire retained-region ceiling, 1..=4096; not permission to truncate.
    pub maximum_regions: usize,
    /// Changed/comparable fraction that flags a broad disturbance, 1..=1000.
    pub widespread_per_mille: u16,
}
impl ForegroundPolicy {
    fn validate(self) -> Result<(), ForegroundError> {
        if self.minimum_change == 0
            || self.minimum_change == 255
            || self.minimum_area == 0
            || self.minimum_area > MAX_FOREGROUND_PIXELS
            || !(1..=MAX_FOREGROUND_REGIONS).contains(&self.maximum_regions)
            || !(1..=1000).contains(&self.widespread_per_mille)
        {
            return Err(ForegroundError::InvalidInput);
        }
        Ok(())
    }
}
/// These classifications are about compared pixels, never scene absence or threat.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameAssessment {
    /// All pixels are masked or unknown in the selected background.
    NoComparablePixels,
    /// Comparable pixels remain within the declared threshold; not a clear scene.
    NoAboveThresholdChange,
    /// Local appearance differences may include targets, shadows, foliage or noise.
    LocalChange,
    /// Broad appearance change; lighting, camera movement and occlusion are unresolved.
    WidespreadChange,
}
/// A four-connected appearance component, not a person, body, contact or identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForegroundRegion {
    /// First row-major member index + 1. Local to this report/exposure only.
    pub id: u32,
    /// Exact number of changed pixels, not the rectangle's area.
    pub area: usize,
    /// Inclusive integer pixel lower corner.
    pub min: [u32; 2],
    /// Exclusive integer upper corner. Pixel-edge crop bounds are [min,max).
    pub max: [u32; 2],
    /// Number of brighter pixels outside the reference envelope.
    pub brighter: usize,
    /// Number of darker pixels outside the reference envelope.
    pub darker: usize,
    /// Component abuts denied or unknown pixels; silhouette/contact may be truncated.
    pub touches_unknown: bool,
    /// Component abuts the image border; silhouette/contact may be truncated.
    pub touches_edge: bool,
}
/// Immutable image-derived proposals retaining raw evidence scope and size omissions.
pub struct ForegroundReport {
    digest: [u8; 32],
    baseline: [u8; 32],
    source: ForegroundSource,
    mask: [u8; 32],
    policy: ForegroundPolicy,
    states: Vec<u8>,
    labels: Vec<u32>,
    regions: Vec<ForegroundRegion>,
    comparable: usize,
    changed: usize,
    small_components: usize,
    small_pixels: usize,
    assessment: FrameAssessment,
}
impl std::fmt::Debug for ForegroundReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForegroundReport")
            .field("assessment", &self.assessment)
            .field("regions", &self.regions.len())
            .finish_non_exhaustive()
    }
}
impl ForegroundReport {
    /// Local derivation identity binding inputs, policy and complete pixel labels.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Exact frozen reference model used.
    pub fn baseline_digest(&self) -> [u8; 32] {
        self.baseline
    }
    /// Actual query source/calibration/capture basis.
    pub fn source(&self) -> ForegroundSource {
        self.source
    }
    /// Complete current permission-mask identity.
    pub fn mask_digest(&self) -> [u8; 32] {
        self.mask
    }
    /// Settings including size-selection and complete-output bounds.
    pub fn policy(&self) -> ForegroundPolicy {
        self.policy
    }
    /// Every size-admitted component in seed order, no top-k pruning.
    pub fn regions(&self) -> &[ForegroundRegion] {
        &self.regions
    }
    /// Pixel classes: 0 unavailable, 1 within envelope, 2 darker, 3 brighter.
    pub fn pixel_states(&self) -> &[u8] {
        &self.states
    }
    /// Row-major component IDs, including size-omitted components; 0 is not changed.
    pub fn component_labels(&self) -> &[u32] {
        &self.labels
    }
    /// Number compared under both current permission and stable baseline.
    pub fn comparable_pixels(&self) -> usize {
        self.comparable
    }
    /// Changed pixels BEFORE size filtering, including omitted components.
    pub fn changed_pixels(&self) -> usize {
        self.changed
    }
    /// Components omitted only by the explicit minimum-area policy.
    pub fn small_component_count(&self) -> usize {
        self.small_components
    }
    /// Changed pixels in those omitted components; never relabeled unchanged.
    pub fn small_component_pixels(&self) -> usize {
        self.small_pixels
    }
    /// Local change, broad disturbance, unobservable, or no threshold exceedance.
    pub fn assessment(&self) -> FrameAssessment {
        self.assessment
    }
}
fn same_mode(a: ForegroundSource, b: ForegroundSource) -> bool {
    a.camera == b.camera
        && a.calibration == b.calibration
        && a.clock == b.clock
        && a.image.image_domain == b.image.image_domain
        && a.image.dimensions == b.image.dimensions
}
fn reserve<T>(count: usize) -> Result<Vec<T>, ForegroundError> {
    let mut v = Vec::new();
    v.try_reserve_exact(count)
        .map_err(|_| ForegroundError::Limit)?;
    Ok(v)
}
fn filled<T: Clone>(count: usize, value: T) -> Result<Vec<T>, ForegroundError> {
    let mut v = reserve(count)?;
    v.resize(count, value);
    Ok(v)
}
fn integer(b: &mut Vec<u8>, n: u64) {
    b.extend_from_slice(&n.to_le_bytes());
}
fn source_bytes(b: &mut Vec<u8>, source: ForegroundSource) {
    for id in [
        source.image.exposure,
        source.image.pixels,
        source.image.image_domain,
        source.calibration,
    ] {
        b.extend_from_slice(&id);
    }
    for n in source.image.dimensions {
        b.extend_from_slice(&n.to_le_bytes());
    }
    for n in [
        source.camera,
        source.clock,
        source.capture[0],
        source.capture[1],
    ] {
        integer(b, n);
    }
}

/// Source rectification, masked model crops and explicit contact-result preparation.
pub mod pipeline;

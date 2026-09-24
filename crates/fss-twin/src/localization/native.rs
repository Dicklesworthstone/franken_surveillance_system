#![forbid(unsafe_code)]
//! Original scalar FAST-9 / oriented binary-patch extraction over supplied pixels.
//! This is not ORB compatibility, a decoder, an undistorter, or a learned model.

use super::{
    BinaryDescriptor, CameraLocalization, FeatureFrame, ImageFeature, ImageIdentity,
    LocalizationAtlas, LocalizationCamera, LocalizationError, MAX_IMAGE_FEATURES, MatchOptions,
};
use crate::PropertyTwin;
use fss_core::ContentDigest;
use fss_geometry::{PoseSolverOptions, WorkBudget};

const RADIUS: usize = 16;
const CIRCLE: [(isize, isize); 16] = [
    (0, -3),
    (1, -3),
    (2, -2),
    (3, -1),
    (3, 0),
    (3, 1),
    (2, 2),
    (1, 3),
    (0, 3),
    (-1, 3),
    (-2, 2),
    (-3, 1),
    (-3, 0),
    (-3, -1),
    (-2, -2),
    (-1, -3),
];

/// Fingerprint of the exact descriptor construction, independent of feature ranking.
pub fn descriptor_domain() -> [u8; 32] {
    ContentDigest::sha256(b"fss/fast9-oriented-brief256/reference/1;pixel-edge;moment-disk8;mean3;lcg1664525+1013904223-seed731;pair-square10;nearest-away").bytes()
}

/// Borrowed, validated, tightly packed grayscale image and allowed-pixel mask.
/// The mask must be 0/1; a descriptor's entire 33x33 footprint must be allowed.
pub struct GrayImage<'a> {
    identity: ImageIdentity,
    pixels: &'a [u8],
    allowed: &'a [u8],
    mask_digest: [u8; 32],
    width: usize,
    height: usize,
}
impl std::fmt::Debug for GrayImage<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrayImage")
            .field("dimensions", &self.identity.dimensions)
            .finish_non_exhaustive()
    }
}
impl<'a> GrayImage<'a> {
    /// Verify exact source-pixel digest and mask shape before any feature extraction.
    /// Image-domain conversion and permission to read the pixels belong to the owner.
    pub fn new(
        identity: ImageIdentity,
        pixels: &'a [u8],
        allowed: &'a [u8],
        budget: &mut WorkBudget<'_>,
    ) -> Result<Self, LocalizationError> {
        budget.charge(0)?;
        identity.validate()?;
        let [width, height] = identity.dimensions.map(|n| n as usize);
        let count = width.checked_mul(height).ok_or(LocalizationError::Limit)?;
        if width > 4096 || height > 4096 || count > 4_194_304 {
            return Err(LocalizationError::Limit);
        }
        if count != pixels.len() || count != allowed.len() {
            return Err(LocalizationError::InvalidInput);
        }
        budget.charge((count as u64) * 3)?;
        if allowed.iter().any(|x| *x > 1) {
            return Err(LocalizationError::InvalidInput);
        }
        if ContentDigest::sha256(pixels).bytes() != identity.pixels {
            return Err(LocalizationError::BasisMismatch);
        }
        let mask_digest = ContentDigest::sha256(allowed).bytes();
        budget.charge(0)?;
        Ok(Self {
            identity,
            pixels,
            allowed,
            mask_digest,
            width,
            height,
        })
    }
    /// Original source/image-domain identities, with verified pixel digest.
    pub fn identity(&self) -> ImageIdentity {
        self.identity
    }
}

/// Explicit bounded detection/selection settings; these do not change descriptor bits.
#[derive(Clone, Copy, Debug)]
pub struct ExtractionOptions {
    /// Strict FAST-9 intensity contrast threshold; 1..=254.
    pub threshold: u8,
    /// Maximum selected features; 1..=512.
    pub maximum_features: usize,
    /// Minimum Euclidean separation of selected pixel centers; 1..=128.
    pub separation: u16,
}
impl Default for ExtractionOptions {
    fn default() -> Self {
        Self {
            threshold: 20,
            maximum_features: 512,
            separation: 6,
        }
    }
}
/// Selection statistics, not a statement of physical observability or completeness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeatureSelection {
    /// Exact exclusion-mask bytes identity.
    pub mask_digest: [u8; 32],
    /// Exact detector threshold used for this selection.
    pub threshold: u8,
    /// Requested output ceiling, retained for reproduction.
    pub maximum_features: usize,
    /// Requested pixel-center separation, retained for reproduction.
    pub separation: u16,
    /// Number of fully allowed patch centers tested.
    pub tested_centers: usize,
    /// Number of FAST responses surviving local nonmaximum suppression.
    pub local_maxima: usize,
    /// Final selected feature count.
    pub selected: usize,
    /// Local maxima excluded by tile quota, spacing, or requested output limit.
    pub omitted: usize,
}
/// Selected image features and their explicit selection scope.
#[derive(Debug)]
pub struct ExtractedFrame {
    /// Actual descriptors and pixel observations, ready for atlas matching.
    pub frame: FeatureFrame,
    /// Input-mask identity and selection accounting.
    pub selection: FeatureSelection,
}
#[derive(Clone, Copy)]
struct Corner {
    score: u8,
    index: usize,
}

/// Extract native features, retaining spatial diversity through an 8x8 tile grid.
/// Eight strongest local maxima per tile form a bounded candidate reservoir.
/// Full sorting uses score then source pixel index; omissions remain counted.
pub fn extract_gray(
    image: &GrayImage<'_>,
    options: ExtractionOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<ExtractedFrame, LocalizationError> {
    budget.charge(0)?;
    if options.threshold == 0
        || options.threshold == 255
        || options.maximum_features == 0
        || options.maximum_features > MAX_IMAGE_FEATURES
        || !(1..=128).contains(&options.separation)
    {
        return Err(LocalizationError::InvalidInput);
    }
    let (w, h) = (image.width, image.height);
    budget.charge((w * h) as u64 * 3)?;
    let mut scores = super::allocated(w * h, 0_u8)?;
    let stride = w + 1;
    let mut excluded = super::allocated((w + 1) * (h + 1), 0_u32)?;
    for y in 0..h {
        budget.charge(w as u64)?;
        let mut row = 0_u32;
        for x in 0..w {
            row += u32::from(image.allowed[y * w + x] == 0);
            excluded[(y + 1) * stride + x + 1] = excluded[y * stride + x + 1] + row;
        }
    }
    let mut tested_centers = 0;
    if w > 2 * RADIUS && h > 2 * RADIUS {
        for y in RADIUS..h - RADIUS {
            for x in RADIUS..w - RADIUS {
                budget.charge(1)?;
                let (l, r, t, b) = (x - RADIUS, x + RADIUS + 1, y - RADIUS, y + RADIUS + 1);
                if excluded[b * stride + r] + excluded[t * stride + l]
                    != excluded[t * stride + r] + excluded[b * stride + l]
                {
                    continue;
                }
                budget.charge(320)?;
                tested_centers += 1;
                let score = fast_score(image, x, y);
                if score > options.threshold {
                    scores[y * w + x] = score;
                }
            }
        }
    }
    let mut tiles = [[Corner { score: 0, index: 0 }; 8]; 64];
    let mut local_maxima = 0;
    for y in 1..h.saturating_sub(1) {
        for x in 1..w.saturating_sub(1) {
            budget.charge(1)?;
            let index = y * w + x;
            let score = scores[index];
            if score == 0 {
                continue;
            }
            let mut maximum = true;
            for yy in y - 1..=y + 1 {
                for xx in x - 1..=x + 1 {
                    let other = yy * w + xx;
                    if scores[other] > score || (scores[other] == score && other < index) {
                        maximum = false;
                    }
                }
            }
            if !maximum {
                continue;
            }
            local_maxima += 1;
            let tile = (y * 8 / h) * 8 + x * 8 / w;
            let candidate = Corner { score, index };
            for slot in 0..8 {
                budget.charge(1)?;
                if better(candidate, tiles[tile][slot]) {
                    for j in (slot + 1..8).rev() {
                        tiles[tile][j] = tiles[tile][j - 1];
                    }
                    tiles[tile][slot] = candidate;
                    break;
                }
            }
        }
    }
    let mut candidates = Vec::new();
    candidates
        .try_reserve_exact(512)
        .map_err(|_| LocalizationError::Limit)?;
    for tile in tiles {
        for corner in tile {
            if corner.score > 0 {
                candidates.push(corner);
            }
        }
    }
    budget.charge(5120)?;
    candidates.sort_by(|a, b| b.score.cmp(&a.score).then(a.index.cmp(&b.index)));
    let mut features: Vec<ImageFeature> = Vec::new();
    features
        .try_reserve_exact(options.maximum_features)
        .map_err(|_| LocalizationError::Limit)?;
    for corner in candidates {
        if features.len() == options.maximum_features {
            break;
        }
        let (x, y) = (corner.index % w, corner.index / w);
        let mut separated = true;
        for feature in &features {
            budget.charge(1)?;
            let dx = (x as f64 + 0.5) - feature.pixel[0];
            let dy = (y as f64 + 0.5) - feature.pixel[1];
            if dx * dx + dy * dy < f64::from(options.separation).powi(2) {
                separated = false;
                break;
            }
        }
        if !separated {
            continue;
        }
        let descriptor = describe(image, x, y, budget)?;
        features.push(ImageFeature {
            id: corner.index as u64 + 1,
            pixel: [x as f64 + 0.5, y as f64 + 0.5],
            descriptor,
        });
    }
    let selected = features.len();
    let frame = FeatureFrame::new(image.identity, descriptor_domain(), features, budget)?;
    budget.charge(0)?;
    Ok(ExtractedFrame {
        frame,
        selection: FeatureSelection {
            mask_digest: image.mask_digest,
            threshold: options.threshold,
            maximum_features: options.maximum_features,
            separation: options.separation,
            tested_centers,
            local_maxima,
            selected,
            omitted: local_maxima - selected,
        },
    })
}
fn better(a: Corner, b: Corner) -> bool {
    a.score > b.score || (a.score == b.score && a.index < b.index)
}

fn fast_score(image: &GrayImage<'_>, x: usize, y: usize) -> u8 {
    let center = i16::from(image.pixels[y * image.width + x]);
    let d: [i16; 16] = std::array::from_fn(|i| {
        let (dx, dy) = CIRCLE[i];
        i16::from(
            image.pixels[(y as isize + dy) as usize * image.width + (x as isize + dx) as usize],
        ) - center
    });
    let mut strongest = 0_i16;
    for start in 0..16 {
        let mut bright = 255_i16;
        let mut dark = 255_i16;
        for k in 0..9 {
            let delta = d[(start + k) % 16];
            bright = bright.min(delta);
            dark = dark.min(-delta);
        }
        strongest = strongest.max(bright).max(dark);
    }
    strongest as u8
}
fn mean3(image: &GrayImage<'_>, x: usize, y: usize) -> i64 {
    let mut sum = 0;
    for yy in y - 1..=y + 1 {
        for xx in x - 1..=x + 1 {
            sum += i64::from(image.pixels[yy * image.width + xx]);
        }
    }
    sum
}
fn describe(
    image: &GrayImage<'_>,
    x: usize,
    y: usize,
    budget: &mut WorkBudget<'_>,
) -> Result<BinaryDescriptor, LocalizationError> {
    budget.charge(8192)?;
    let mut mx = 0_i64;
    let mut my = 0_i64;
    for dy in -8_i32..=8 {
        for dx in -8_i32..=8 {
            if dx * dx + dy * dy <= 64 {
                let value = mean3(image, (x as i32 + dx) as usize, (y as i32 + dy) as usize);
                mx += i64::from(dx) * value;
                my += i64::from(dy) * value;
            }
        }
    }
    let angle = (my as f64).atan2(mx as f64);
    let (sin, cos) = angle.sin_cos();
    let mut state = 731_u32;
    let mut words = [0_u64; 4];
    for bit in 0..256 {
        let pair: [i32; 4] = std::array::from_fn(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state % 21) as i32 - 10
        });
        let sample = |dx: i32, dy: i32| {
            let xx = x as i32 + (cos * f64::from(dx) - sin * f64::from(dy)).round() as i32;
            let yy = y as i32 + (sin * f64::from(dx) + cos * f64::from(dy)).round() as i32;
            mean3(image, xx as usize, yy as usize)
        };
        if sample(pair[0], pair[1]) < sample(pair[2], pair[3]) {
            words[bit / 64] |= 1_u64 << (bit % 64);
        }
    }
    budget.charge(0)?;
    Ok(BinaryDescriptor(words))
}

/// Integer-center reference observation; no silent snapping of subpixel SfM points.
#[derive(Clone, Copy, Debug)]
pub struct ReferencePixel {
    /// Nonzero image-local reference-feature identity.
    pub id: u64,
    /// Zero-based integer source column.
    pub column: u32,
    /// Zero-based integer source row.
    pub row: u32,
}
/// Describe explicit reference pixels using the identical native descriptor.
/// Out-of-image, masked, or insufficient-border observations fail the whole request.
pub fn describe_reference_pixels(
    image: &GrayImage<'_>,
    points: &[ReferencePixel],
    budget: &mut WorkBudget<'_>,
) -> Result<FeatureFrame, LocalizationError> {
    budget.charge(0)?;
    if points.len() > MAX_IMAGE_FEATURES {
        return Err(LocalizationError::Limit);
    }
    let mut features = Vec::new();
    features
        .try_reserve_exact(points.len())
        .map_err(|_| LocalizationError::Limit)?;
    for point in points {
        let (x, y) = (point.column as usize, point.row as usize);
        if x < RADIUS
            || y < RADIUS
            || x >= image.width.saturating_sub(RADIUS)
            || y >= image.height.saturating_sub(RADIUS)
        {
            return Err(LocalizationError::InvalidInput);
        }
        for yy in y - RADIUS..=y + RADIUS {
            budget.charge((2 * RADIUS + 1) as u64)?;
            if image.allowed[yy * image.width + x - RADIUS..=yy * image.width + x + RADIUS]
                .contains(&0)
            {
                return Err(LocalizationError::InvalidInput);
            }
        }
        features.push(ImageFeature {
            id: point.id,
            pixel: [x as f64 + 0.5, y as f64 + 0.5],
            descriptor: describe(image, x, y, budget)?,
        });
    }
    FeatureFrame::new(image.identity, descriptor_domain(), features, budget)
}

/// Options for the composed raw-grayscale to camera-pose operation.
#[derive(Clone, Copy, Debug, Default)]
pub struct ImageLocalizationOptions {
    /// Bounded feature selection policy.
    pub extraction: ExtractionOptions,
    /// Distinct-physical-point descriptor matching policy.
    pub matching: MatchOptions,
    /// Existing robust fixed-map camera solver policy.
    pub solving: PoseSolverOptions,
}
/// Coupled image-selection and camera-localization outcome.
#[derive(Debug)]
pub struct ImageLocalization {
    /// Explicit feature-selection scope, including omitted candidates and mask.
    pub selection: FeatureSelection,
    /// Match decisions and all admitted pose hypotheses.
    pub localization: CameraLocalization,
}
/// Extract, match, and estimate pose without a foreign runtime or supplied query matches.
pub fn localize_gray_frame(
    atlas: &LocalizationAtlas,
    twin: &PropertyTwin,
    image: &GrayImage<'_>,
    camera: LocalizationCamera,
    options: ImageLocalizationOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<ImageLocalization, LocalizationError> {
    budget.charge(0)?;
    if image.identity.dimensions != camera.intrinsics.dimensions()
        || image.identity.image_domain != camera.image_domain
    {
        return Err(LocalizationError::BasisMismatch);
    }
    if atlas.basis != twin.basis()
        || atlas.twin_digest != twin.digest()
        || atlas.descriptor_domain != descriptor_domain()
    {
        return Err(LocalizationError::BasisMismatch);
    }
    if atlas
        .references
        .iter()
        .any(|r| r.frame.identity.exposure == image.identity.exposure)
    {
        return Err(LocalizationError::ReferenceExposure);
    }
    let extracted = extract_gray(image, options.extraction, budget)?;
    let localization = atlas.localize(
        twin,
        &extracted.frame,
        camera,
        options.matching,
        options.solving,
        budget,
    )?;
    Ok(ImageLocalization {
        selection: extracted.selection,
        localization,
    })
}

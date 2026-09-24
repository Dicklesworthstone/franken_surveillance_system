#![forbid(unsafe_code)]
//! Bounded real-image descriptor atlas and image-to-map camera localization.
//!
//! The caller supplies authorized static landmark/map associations. Matching does
//! not establish their physical accuracy, independence, or calibration authority.

use crate::PropertyTwin;
use fss_core::ContentDigest;
use fss_geometry::{
    Correspondence, GeometryBasis, GeometryError, PinholeIntrinsics, PoseSearch, PoseSolverOptions,
    WorkBudget, estimate_camera_pose,
};

/// Largest feature set admitted for one image (also bounds PnP observations).
pub const MAX_IMAGE_FEATURES: usize = 512;
/// Largest admitted reference map; observations may share a landmark across views.
pub const MAX_ATLAS_LANDMARKS: usize = 4096;
/// Largest admitted number of distinct reference exposures.
pub const MAX_ATLAS_REFERENCES: usize = 64;

/// Non-disclosing errors at the localization boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalizationError {
    /// Invalid, duplicate, dangling, or nonfinite input.
    InvalidInput,
    /// Property, revision, image mode, or descriptor generation differs.
    BasisMismatch,
    /// Reference exposure is being reused as a purported new localization input.
    ReferenceExposure,
    /// A fixed count or allocation ceiling was exceeded.
    Limit,
    /// Geometry failure, including cancellation and exhausted work budget.
    Geometry(GeometryError),
}
impl From<GeometryError> for LocalizationError {
    fn from(error: GeometryError) -> Self {
        Self::Geometry(error)
    }
}
impl std::fmt::Display for LocalizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid localization input",
            Self::BasisMismatch => "localization basis mismatch",
            Self::ReferenceExposure => "localization reuses a reference exposure",
            Self::Limit => "localization limit exceeded",
            Self::Geometry(_) => "localization geometry operation failed",
        })
    }
}
impl std::error::Error for LocalizationError {}

/// Algorithm-specific 256-bit descriptor. Debug deliberately omits image content.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BinaryDescriptor(
    /// Four descriptor words; their bit interpretation is algorithm-generation specific.
    pub [u64; 4],
);
impl BinaryDescriptor {
    /// Exact Hamming distance, in 0..=256.
    pub fn distance(self, other: Self) -> u16 {
        self.0
            .iter()
            .zip(other.0)
            .map(|(a, b)| (a ^ b).count_ones() as u16)
            .sum()
    }
}
impl std::fmt::Debug for BinaryDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BinaryDescriptor").finish_non_exhaustive()
    }
}

/// Immutable image provenance supplied by the owner; hashes are not authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageIdentity {
    /// Canonical source exposure identity, including original source/PTS/stream.
    pub exposure: [u8; 32],
    /// Digest of the exact image pixels used to produce these descriptors.
    pub pixels: [u8; 32],
    /// Intrinsics/distortion/crop/resize/pixel-origin chain identity.
    pub image_domain: [u8; 32],
    /// Width and height of the undistorted pixel-edge image.
    pub dimensions: [u32; 2],
}
impl ImageIdentity {
    fn validate(self) -> Result<(), LocalizationError> {
        if [self.exposure, self.pixels, self.image_domain].contains(&[0; 32])
            || self.dimensions.iter().any(|x| *x == 0 || *x > 65536)
        {
            return Err(LocalizationError::InvalidInput);
        }
        Ok(())
    }
}

/// One image-local feature; coordinates use pixel centers (column+0.5,row+0.5).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ImageFeature {
    /// Nonzero image-local identity, independent of a world landmark identity.
    pub id: u64,
    /// Observed position on the exact undistorted pixel-edge image grid.
    pub pixel: [f64; 2],
    /// Descriptor in the frame's exact declared algorithm generation.
    pub descriptor: BinaryDescriptor,
}

/// Validated immutable image features, also accepting separately admitted extractors.
#[derive(Clone)]
pub struct FeatureFrame {
    identity: ImageIdentity,
    descriptor_domain: [u8; 32],
    features: Vec<ImageFeature>,
}
impl std::fmt::Debug for FeatureFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeatureFrame")
            .field("feature_count", &self.features.len())
            .finish_non_exhaustive()
    }
}
impl FeatureFrame {
    /// Validate the complete input before exposing it, then order by image-local ID.
    pub fn new(
        identity: ImageIdentity,
        descriptor_domain: [u8; 32],
        mut features: Vec<ImageFeature>,
        budget: &mut WorkBudget<'_>,
    ) -> Result<Self, LocalizationError> {
        budget.charge(0)?;
        identity.validate()?;
        if descriptor_domain == [0; 32] {
            return Err(LocalizationError::InvalidInput);
        }
        if features.len() > MAX_IMAGE_FEATURES {
            return Err(LocalizationError::Limit);
        }
        for (i, point) in features.iter().enumerate() {
            budget.charge(1)?;
            if point.id == 0
                || (0..2).any(|a| {
                    !point.pixel[a].is_finite()
                        || point.pixel[a] < 0.0
                        || point.pixel[a] >= f64::from(identity.dimensions[a])
                })
            {
                return Err(LocalizationError::InvalidInput);
            }
            for other in &features[..i] {
                budget.charge(1)?;
                if point.id == other.id || point.pixel == other.pixel {
                    return Err(LocalizationError::InvalidInput);
                }
            }
        }
        budget.charge(features.len() as u64 * 10)?;
        features.sort_by_key(|point| point.id);
        Ok(Self {
            identity,
            descriptor_domain,
            features,
        })
    }
    /// Original source/image-domain identities.
    pub fn identity(&self) -> ImageIdentity {
        self.identity
    }
    /// Exact descriptor algorithm/generation, not a model name string.
    pub fn descriptor_domain(&self) -> [u8; 32] {
        self.descriptor_domain
    }
    /// Complete selected feature set; detection completeness is not claimed.
    pub fn features(&self) -> &[ImageFeature] {
        &self.features
    }
}

/// One static physical point in the imported property's local frame.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AtlasLandmark {
    /// Nonzero map-local landmark handle, resolved by the owner from persistent IDs.
    pub id: u64,
    /// Nonzero physical-point group; aliases must be consolidated before import.
    pub physical_group: u64,
    /// Zero-based feature ordinal in the exact PropertyTwin.
    pub feature: u32,
    /// Position in property source units, not implicitly metres.
    pub world: [f64; 3],
    /// Supporting reconstruction/measurement record, retained without authentication.
    pub evidence: [u8; 32],
    /// Per-axis absolute map error, or unknown; PnP remains a fixed-map fit.
    pub error: Option<[f64; 3]>,
}
/// An owner-selected reference exposure whose features have static map bindings.
#[derive(Clone, Debug)]
pub struct AtlasReference {
    /// Nonzero local reference-view handle.
    pub id: u64,
    /// Features and source identity; one record per physical exposure.
    pub frame: FeatureFrame,
}
/// Explicit producer-supplied image-feature to map-point association.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtlasBinding {
    /// Atlas landmark handle.
    pub landmark: u64,
    /// Reference-view handle.
    pub reference: u64,
    /// Image-local feature handle within that reference view.
    pub image_feature: u64,
}

/// Frozen atlas pinned to the exact imported twin and descriptor generation.
pub struct LocalizationAtlas {
    basis: GeometryBasis,
    twin_digest: [u8; 32],
    digest: [u8; 32],
    descriptor_domain: [u8; 32],
    landmarks: Vec<AtlasLandmark>,
    references: Vec<AtlasReference>,
    bindings: Vec<AtlasBinding>,
    samples: Vec<(usize, BinaryDescriptor)>,
}
impl std::fmt::Debug for LocalizationAtlas {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalizationAtlas")
            .field("landmarks", &self.landmarks.len())
            .field("references", &self.references.len())
            .finish_non_exhaustive()
    }
}
impl LocalizationAtlas {
    /// Validate all associations, including repeated physical groups and exposures.
    /// Multiple views of one landmark improve matching but never its support count.
    pub fn new(
        twin: &PropertyTwin,
        mut landmarks: Vec<AtlasLandmark>,
        mut references: Vec<AtlasReference>,
        mut bindings: Vec<AtlasBinding>,
        budget: &mut WorkBudget<'_>,
    ) -> Result<Self, LocalizationError> {
        budget.charge(0)?;
        if landmarks.is_empty() || references.is_empty() || bindings.is_empty() {
            return Err(LocalizationError::InvalidInput);
        }
        if landmarks.len() > MAX_ATLAS_LANDMARKS
            || references.len() > MAX_ATLAS_REFERENCES
            || bindings.len() > MAX_ATLAS_REFERENCES * MAX_IMAGE_FEATURES
        {
            return Err(LocalizationError::Limit);
        }
        budget.charge((landmarks.len() + references.len() + bindings.len()) as u64 * 16)?;
        landmarks.sort_by_key(|point| point.id);
        references.sort_by_key(|view| view.id);
        bindings.sort_by_key(|b| (b.landmark, b.reference, b.image_feature));
        for (i, point) in landmarks.iter().enumerate() {
            if point.id == 0
                || point.physical_group == 0
                || point.evidence == [0; 32]
                || twin.features().get(point.feature as usize).is_none()
                || point.world.iter().any(|x| !x.is_finite() || x.abs() > 1e12)
                || point
                    .error
                    .is_some_and(|e| e.iter().any(|x| !x.is_finite() || *x < 0.0 || *x > 1e12))
            {
                return Err(LocalizationError::InvalidInput);
            }
            for other in &landmarks[..i] {
                budget.charge(1)?;
                if point.id == other.id
                    || point.physical_group == other.physical_group
                    || point.world == other.world
                {
                    return Err(LocalizationError::InvalidInput);
                }
            }
        }
        let descriptor_domain = references[0].frame.descriptor_domain;
        for (i, view) in references.iter().enumerate() {
            budget.charge(1)?;
            if view.id == 0 || view.frame.descriptor_domain != descriptor_domain {
                return Err(LocalizationError::BasisMismatch);
            }
            for other in &references[..i] {
                budget.charge(1)?;
                if view.id == other.id
                    || view.frame.identity.exposure == other.frame.identity.exposure
                {
                    return Err(LocalizationError::InvalidInput);
                }
            }
        }
        let mut used_points = allocated(landmarks.len(), false)?;
        let mut used_views = allocated(references.len(), false)?;
        let mut used_features = allocated(references.len() * MAX_IMAGE_FEATURES, false)?;
        let mut samples = Vec::new();
        samples
            .try_reserve_exact(bindings.len())
            .map_err(|_| LocalizationError::Limit)?;
        let mut previous = None;
        for binding in &bindings {
            budget.charge(32)?;
            let p = landmarks
                .binary_search_by_key(&binding.landmark, |p| p.id)
                .map_err(|_| LocalizationError::InvalidInput)?;
            let r = references
                .binary_search_by_key(&binding.reference, |r| r.id)
                .map_err(|_| LocalizationError::InvalidInput)?;
            let f = references[r]
                .frame
                .features
                .binary_search_by_key(&binding.image_feature, |f| f.id)
                .map_err(|_| LocalizationError::InvalidInput)?;
            let key = (binding.landmark, binding.reference);
            let slot = r * MAX_IMAGE_FEATURES + f;
            if previous == Some(key) || used_features[slot] {
                return Err(LocalizationError::InvalidInput);
            }
            previous = Some(key);
            used_points[p] = true;
            used_views[r] = true;
            used_features[slot] = true;
            samples.push((p, references[r].frame.features[f].descriptor));
        }
        if used_points.contains(&false) || used_views.contains(&false) {
            return Err(LocalizationError::InvalidInput);
        }
        let mut atlas = Self {
            basis: twin.basis(),
            twin_digest: twin.digest(),
            digest: [0; 32],
            descriptor_domain,
            landmarks,
            references,
            bindings,
            samples,
        };
        atlas.digest = atlas.fingerprint(budget)?;
        budget.charge(0)?;
        Ok(atlas)
    }
    /// Content identity of the normalized typed atlas, not a new durable wire schema.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Exact immutable twin input identity.
    pub fn twin_digest(&self) -> [u8; 32] {
        self.twin_digest
    }
    /// All map points, including their unknown/declared errors and source handles.
    pub fn landmarks(&self) -> &[AtlasLandmark] {
        &self.landmarks
    }
    /// Original explicit map associations in canonical order.
    pub fn bindings(&self) -> &[AtlasBinding] {
        &self.bindings
    }
    /// Original reference exposure records, not synthetic independent evidence.
    pub fn references(&self) -> &[AtlasReference] {
        &self.references
    }

    /// Match against distinct physical landmarks, then require mutual nearest matches.
    /// Every query feature receives an accepted match or an explicit rejection.
    pub fn match_frame(
        &self,
        twin: &PropertyTwin,
        query: &FeatureFrame,
        options: MatchOptions,
        budget: &mut WorkBudget<'_>,
    ) -> Result<MatchReport, LocalizationError> {
        budget.charge(0)?;
        if twin.basis() != self.basis
            || twin.digest() != self.twin_digest
            || query.descriptor_domain != self.descriptor_domain
        {
            return Err(LocalizationError::BasisMismatch);
        }
        if options.maximum_distance > 256 || !(1..100).contains(&options.ratio_percent) {
            return Err(LocalizationError::InvalidInput);
        }
        let n = self.landmarks.len();
        let qn = query.features.len();
        budget.charge((n * qn) as u64)?;
        let mut distances = allocated(n * qn, 257_u16)?;
        for (q, feature) in query.features.iter().enumerate() {
            for &(p, descriptor) in &self.samples {
                budget.charge(4)?;
                let distance = feature.descriptor.distance(descriptor);
                let cell = &mut distances[q * n + p];
                *cell = (*cell).min(distance);
            }
        }
        let mut reverse = allocated(n, None)?;
        for p in 0..n {
            let mut best = 257;
            for q in 0..qn {
                budget.charge(1)?;
                let d = distances[q * n + p];
                if d < best {
                    best = d;
                    reverse[p] = Some(q);
                } else if d == best {
                    reverse[p] = None;
                }
            }
        }
        let mut decisions = Vec::new();
        let mut correspondences = Vec::new();
        decisions
            .try_reserve_exact(qn)
            .map_err(|_| LocalizationError::Limit)?;
        correspondences
            .try_reserve_exact(qn)
            .map_err(|_| LocalizationError::Limit)?;
        for (q, feature) in query.features.iter().enumerate() {
            let mut first = (257_u16, 0_usize);
            let mut second = 257_u16;
            for p in 0..n {
                budget.charge(1)?;
                let d = distances[q * n + p];
                if d < first.0 {
                    second = first.0;
                    first = (d, p);
                } else {
                    second = second.min(d);
                }
            }
            let rejection = if first.0 > options.maximum_distance {
                Some(MatchRejection::TooDistant)
            } else if second == 257
                || first.0 == second
                || u32::from(first.0) * 100 >= u32::from(second) * u32::from(options.ratio_percent)
            {
                Some(MatchRejection::Ambiguous)
            } else if reverse[first.1] != Some(q) {
                Some(MatchRejection::NonMutual)
            } else {
                None
            };
            let landmark = if rejection.is_none() {
                let point = self.landmarks[first.1];
                correspondences.push(Correspondence {
                    landmark: point.id,
                    physical_group: point.physical_group,
                    world: point.world,
                    pixel: feature.pixel,
                });
                Some(point.id)
            } else {
                None
            };
            decisions.push(MatchDecision {
                image_feature: feature.id,
                landmark,
                rejection,
                distance: first.0,
                runner_up_distance: (second != 257).then_some(second),
            });
        }
        budget.charge(qn as u64 * 10)?;
        correspondences.sort_by_key(|point| point.landmark);
        Ok(MatchReport {
            atlas: self.digest,
            query: query.identity,
            decisions,
            correspondences,
        })
    }

    /// Match a new image and feed actual 2D-to-3D matches into the existing solver.
    /// Geometric failures retain the match report; cancellation/budget errors do not
    /// publish a successful partial result. No candidate is activated automatically.
    pub fn localize(
        &self,
        twin: &PropertyTwin,
        query: &FeatureFrame,
        camera: LocalizationCamera,
        matching: MatchOptions,
        solving: PoseSolverOptions,
        budget: &mut WorkBudget<'_>,
    ) -> Result<CameraLocalization, LocalizationError> {
        budget.charge(0)?;
        if query.identity.dimensions != camera.intrinsics.dimensions()
            || query.identity.image_domain != camera.image_domain
        {
            return Err(LocalizationError::BasisMismatch);
        }
        if self
            .references
            .iter()
            .any(|r| r.frame.identity.exposure == query.identity.exposure)
        {
            return Err(LocalizationError::ReferenceExposure);
        }
        let matches = self.match_frame(twin, query, matching, budget)?;
        let outcome = if matches.correspondences.len() < 6.max(solving.minimum_inliers) {
            LocalizationOutcome::InsufficientMatches
        } else {
            match estimate_camera_pose(
                self.basis,
                camera.intrinsics,
                &matches.correspondences,
                solving,
                budget,
            ) {
                Ok(search) => LocalizationOutcome::Candidates(Box::new(search)),
                Err(
                    e @ (GeometryError::Cancelled
                    | GeometryError::BudgetExhausted
                    | GeometryError::LimitExceeded),
                ) => return Err(e.into()),
                Err(error) => LocalizationOutcome::GeometricFailure(error),
            }
        };
        budget.charge(0)?;
        Ok(CameraLocalization { matches, outcome })
    }

    fn fingerprint(&self, budget: &mut WorkBudget<'_>) -> Result<[u8; 32], LocalizationError> {
        let count: usize = self.references.iter().map(|r| r.frame.features.len()).sum();
        let capacity = 128
            + self.landmarks.len() * 128
            + self.references.len() * 160
            + count * 64
            + self.bindings.len() * 24;
        budget.charge(capacity as u64)?;
        let mut b = Vec::new();
        b.try_reserve_exact(capacity)
            .map_err(|_| LocalizationError::Limit)?;
        b.extend_from_slice(b"fss/localization-atlas/reference/1\0");
        b.extend_from_slice(&self.twin_digest);
        b.extend_from_slice(&self.descriptor_domain);
        integer(&mut b, self.landmarks.len() as u64);
        for p in &self.landmarks {
            budget.charge(0)?;
            integer(&mut b, p.id);
            integer(&mut b, p.physical_group);
            integer(&mut b, u64::from(p.feature));
            for x in p.world {
                float(&mut b, x);
            }
            b.extend_from_slice(&p.evidence);
            b.push(u8::from(p.error.is_some()));
            if let Some(error) = p.error {
                for x in error {
                    float(&mut b, x);
                }
            }
        }
        integer(&mut b, self.references.len() as u64);
        for r in &self.references {
            budget.charge(0)?;
            integer(&mut b, r.id);
            for hash in [
                r.frame.identity.exposure,
                r.frame.identity.pixels,
                r.frame.identity.image_domain,
            ] {
                b.extend_from_slice(&hash);
            }
            for n in r.frame.identity.dimensions {
                integer(&mut b, u64::from(n));
            }
            integer(&mut b, r.frame.features.len() as u64);
            for f in &r.frame.features {
                integer(&mut b, f.id);
                for x in f.pixel {
                    float(&mut b, x);
                }
                for word in f.descriptor.0 {
                    integer(&mut b, word);
                }
            }
        }
        integer(&mut b, self.bindings.len() as u64);
        for v in &self.bindings {
            integer(&mut b, v.landmark);
            integer(&mut b, v.reference);
            integer(&mut b, v.image_feature);
        }
        Ok(ContentDigest::sha256(&b).bytes())
    }
}
fn allocated<T: Clone>(count: usize, value: T) -> Result<Vec<T>, LocalizationError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| LocalizationError::Limit)?;
    result.resize(count, value);
    Ok(result)
}
fn integer(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}
fn float(bytes: &mut Vec<u8>, value: f64) {
    integer(bytes, if value == 0.0 { 0 } else { value.to_bits() });
}

/// Conservative descriptor matching thresholds, not probability thresholds.
#[derive(Clone, Copy, Debug)]
pub struct MatchOptions {
    /// Maximum accepted Hamming distance, in 0..=256.
    pub maximum_distance: u16,
    /// Strict best/second-distinct-landmark ratio, in integer percent (1..99).
    pub ratio_percent: u8,
}
impl Default for MatchOptions {
    fn default() -> Self {
        Self {
            maximum_distance: 64,
            ratio_percent: 80,
        }
    }
}
/// Reason an image feature did not become a geometric correspondence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchRejection {
    /// Nearest landmark exceeds the absolute descriptor threshold.
    TooDistant,
    /// Tied, weak, or absent distinct-landmark runner-up.
    Ambiguous,
    /// The landmark prefers another query feature, or multiple query features tie.
    NonMutual,
}
/// Complete per-query match decision; rejected image features remain visible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatchDecision {
    /// Image-local input identity.
    pub image_feature: u64,
    /// Matched physical landmark only on acceptance.
    pub landmark: Option<u64>,
    /// Explicit reason on rejection.
    pub rejection: Option<MatchRejection>,
    /// Distance to best physical landmark.
    pub distance: u16,
    /// Distance to second distinct landmark, not another view of the first.
    pub runner_up_distance: Option<u16>,
}
/// Coupled input identities, complete decisions, and solver-ready correspondences.
#[derive(Debug)]
pub struct MatchReport {
    /// Exact normalized atlas digest.
    pub atlas: [u8; 32],
    /// Exact query source and image-domain basis.
    pub query: ImageIdentity,
    /// Every selected query feature, including failures.
    pub decisions: Vec<MatchDecision>,
    /// One correspondence per accepted physical landmark, in identity order.
    pub correspondences: Vec<Correspondence>,
}
/// Localization outcome under fixed, externally supplied intrinsics and map geometry.
#[derive(Debug)]
pub enum LocalizationOutcome {
    /// Descriptor matches do not satisfy the solver's support count.
    InsufficientMatches,
    /// Matching completed but bounded geometry could not admit a pose.
    GeometricFailure(GeometryError),
    /// All distinct passing modes returned by the bounded existing solver.
    Candidates(Box<PoseSearch>),
}
/// Candidate result, never a calibration activation or physical accuracy certificate.
#[derive(Debug)]
pub struct CameraLocalization {
    /// All descriptor decisions and actual solver inputs.
    pub matches: MatchReport,
    /// Retained solver outcome; map errors remain attached to the atlas.
    pub outcome: LocalizationOutcome,
}

/// Owner-resolved image mode. Domain equality is checked before fitting.
#[derive(Clone, Copy, Debug)]
pub struct LocalizationCamera {
    /// Fixed undistorted pinhole intrinsics; not estimated by descriptor matching.
    pub intrinsics: PinholeIntrinsics,
    /// Exact image-domain chain identity expected on the query features.
    pub image_domain: [u8; 32],
}

/// Native grayscale extraction and the composed pixel-to-camera-pose path.
pub mod native;

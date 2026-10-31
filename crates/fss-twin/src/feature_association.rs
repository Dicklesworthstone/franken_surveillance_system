#![forbid(unsafe_code)]
//! Bounded, source-pinned feature association between two overlapping camera views.
//!
//! Descriptors use the existing localization matcher's absolute Hamming and strict
//! best/runner-up rules, here required in BOTH directions. The full feature set
//! participates before nominal epipolar gating: geometry never erases a descriptor
//! competitor to manufacture uniqueness. Every Cartesian pair and every selected
//! image feature receives a disposition. A selected pair is a conditional common
//! stationary-point hypothesis, not object identity or a persistent track merge.
//!
//! Inputs are owner-resolved snapshots, not authenticated custody. Pixel/mask and
//! image-domain hashes do not grant permission or establish calibration accuracy.
//! Native fusion retains the exact twin, camera errors, capture hull and nominal
//! occlusion conflicts. Its covariance covers only the declared pixel noise; it
//! excludes correspondence, calibration, clock, motion and shared-mode errors.

use crate::localization::{FeatureFrame, ImageFeature, LocalizationError};
use crate::multiview::{
    CommonPointMotion, FusedScenePoint, FusionError, FusionInput, FusionRequest, fuse_scene_point,
};
use crate::{ContactObservation, PropertyTwin, TrackingCamera, TwinError};
use fss_core::{CanonicalEncoder, ContentDigest};
use fss_geometry::triangulation::{TriangulationError, TriangulationOptions, triangulate};
use fss_geometry::{GeometryError, WorkBudget};

/// Hard feature ceiling per view; the complete pair table has at most 16,384 rows.
pub const MAX_ASSOCIATION_FEATURES: usize = 128;

/// Exact source snapshot and the explicit mapping into one nominal rig camera.
#[derive(Clone, Debug)]
pub struct FeatureView {
    /// Complete selected feature set and original exposure, pixels and descriptor domain.
    pub frame: FeatureFrame,
    /// Nominal camera, common clock, validity and unmodified calibration error declaration.
    pub camera: TrackingCamera,
    /// Digest of original source bytes, separate from the decoded pixel digest.
    pub source_digest: [u8; 32],
    /// Digest of the exact allowed-pixel mask used by extraction.
    pub allowed_mask_digest: [u8; 32],
    /// Expected exact undistorted image-domain digest; must match the feature frame.
    /// This is separate from the camera's owner-resolved numeric image-domain handle.
    pub image_domain_digest: [u8; 32],
    /// Evidence or explicit owner assumption mapping this source image to this camera mode.
    pub mapping_basis: [u8; 32],
    /// Owner-resolved privacy namespace; it is not an access grant.
    pub privacy_domain: u64,
    /// Exact common-clock evidence or declared alignment assumption.
    pub clock_evidence: [u8; 32],
    /// Complete earliest/latest capture interval on the camera's shared clock.
    pub capture: [u64; 2],
    /// Explicit isotropic pixel-noise assumption, independent of all deterministic bounds.
    pub sigma_pixels: f64,
}

/// Explicit static-point hypothesis, source basis and bounded matching policy.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AssociationOptions {
    /// Evidence or explicit assumption that common features are stationary over the capture hull.
    pub association_basis: [u8; 32],
    /// Exact owner-supplied camera-rig identity; it does not activate its calibration.
    pub camera_rig_digest: [u8; 32],
    /// Both source views must belong to this nonzero privacy namespace.
    pub privacy_domain: u64,
    /// Both cameras must use this nonzero common capture-clock generation.
    pub clock: u64,
    /// Both views must name this exact common-clock evidence/assumption.
    pub clock_evidence: [u8; 32],
    /// Reference time in the full capture hull, not an arrival timestamp.
    pub reference_time_ns: u64,
    /// Maximum FULL capture hull, including uncertainty; at most one second.
    pub max_capture_span_ns: u64,
    /// Inclusive descriptor Hamming threshold in 0..=256.
    pub maximum_hamming_distance: u16,
    /// Strict best/runner-up ratio in BOTH directions, in integer percent 1..=99.
    /// Missing runner-up or equal best distances are always ambiguous.
    pub ratio_percent: u8,
    /// Inclusive nominal epipolar distance gate in each image, in 0..=10,000 pixels.
    pub maximum_epipolar_distance_pixels: f64,
    /// Existing native point solver policy. Two views and zero outliers are required.
    pub triangulation: TriangulationOptions,
}

/// Independent descriptor disposition for one row of the complete pair table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorDecision {
    /// Pair exceeds the absolute Hamming threshold.
    TooDistant,
    /// Mutual nearest candidates fail a strict ratio, tie, or have no runner-up.
    Ambiguous,
    /// At least one endpoint prefers another descriptor.
    NonMutual,
    /// Unique mutual nearest descriptors pass the strict ratio in both directions.
    Candidate,
}

/// Nominal geometric disposition, independent of the descriptor disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EpipolarDecision {
    /// Both directed point-to-line distances are within the explicit gate.
    Passed,
    /// At least one directed distance exceeds the gate.
    OutsideGate,
    /// Coincident centers or an epipole/degenerate line leave this test undefined.
    Unobservable,
}

/// One Cartesian pair in canonical camera/feature order; no pair is silently pruned.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PairDecision {
    /// Image-local feature IDs, corresponding to the report's canonical view order.
    pub features: [u64; 2],
    /// Actual 256-bit descriptor distance.
    pub hamming_distance: u16,
    /// Descriptor decision before geometric screening.
    pub descriptor: DescriptorDecision,
    /// Independent nominal epipolar decision.
    pub epipolar: EpipolarDecision,
    /// Directed point-to-epipolar-line distance in each canonical view, or undefined.
    pub epipolar_distance_pixels: Option<[f64; 2]>,
    /// Index of a selected conditional point hypothesis, including any geometric refusal.
    pub hypothesis: Option<usize>,
}

/// Why one selected image feature did or did not produce a point hypothesis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeatureDisposition {
    /// The other view contains no selected features.
    NoCounterpart,
    /// The best descriptor exceeds the absolute Hamming threshold.
    TooDistant,
    /// At least one direction has a tied, weak, or missing runner-up.
    Ambiguous,
    /// The preferred counterpart favors another feature.
    NonMutual,
    /// A descriptor candidate falls outside the nominal epipolar gate.
    EpipolarRejected,
    /// A descriptor candidate has undefined nominal epipolar geometry.
    EpipolarUnobservable,
    /// A conditional hypothesis was attempted; inspect it for the native solver outcome.
    Selected,
}

/// Complete per-feature outcome, retaining every equal nearest descriptor candidate.
#[derive(Clone, Debug, PartialEq)]
pub struct FeatureOutcome {
    /// Logical camera identity in the report's canonical view order.
    pub camera: u64,
    /// Image-local feature identity.
    pub feature: u64,
    /// All equal nearest features in the other view, in ascending feature-ID order.
    pub nearest_features: Vec<u64>,
    /// Best Hamming distance, or no counterpart.
    pub best_distance: Option<u16>,
    /// Second candidate's distance, including an equal-best tie, or no runner-up.
    pub runner_up_distance: Option<u16>,
    /// Explicit selection outcome.
    pub disposition: FeatureDisposition,
    /// Index of the attempted point hypothesis, when selected.
    pub hypothesis: Option<usize>,
}

/// Native geometric result for a descriptor/epipolar-selected pair.
#[derive(Clone, Debug)]
pub enum FeatureHypothesisOutcome {
    /// Conditional source-linked point, covariance and nominal mesh diagnostics.
    Fused(Box<FusedScenePoint>),
    /// Weak, behind-camera, contradictory or otherwise refused geometry; never a guessed point.
    Refused(FusionError),
}

/// One automatically selected common-feature hypothesis, never a physical identity assertion.
#[derive(Clone, Debug)]
pub struct FeatureHypothesis {
    /// Image-local feature IDs in canonical view order.
    pub features: [u64; 2],
    /// Versioned hash binding this pair to all original inputs and assumptions.
    pub evidence: [u8; 32],
    /// Native geometric result, including explicit refusals.
    pub outcome: FeatureHypothesisOutcome,
}

/// Immutable complete result of one bounded two-view matching operation.
#[derive(Clone, Debug)]
pub struct FeatureAssociation {
    views: [FeatureView; 2],
    options: AssociationOptions,
    evidence: [u8; 32],
    capture_hull: [u64; 2],
    pairs: Vec<PairDecision>,
    features: Vec<FeatureOutcome>,
    hypotheses: Vec<FeatureHypothesis>,
}
impl FeatureAssociation {
    /// Exact unmodified source snapshots, sorted by logical camera identity.
    pub fn views(&self) -> &[FeatureView; 2] {
        &self.views
    }
    /// Exact source assumptions and matching policy used.
    pub fn options(&self) -> AssociationOptions {
        self.options
    }
    /// Canonical input/configuration identity, not an authentication or accuracy certificate.
    pub fn evidence(&self) -> [u8; 32] {
        self.evidence
    }
    /// Full earliest/latest capture hull including both timestamp uncertainties.
    pub fn capture_hull(&self) -> [u64; 2] {
        self.capture_hull
    }
    /// Complete Cartesian pair table, ordered by first then second feature identity.
    pub fn pairs(&self) -> &[PairDecision] {
        &self.pairs
    }
    /// Every feature in canonical camera/feature order, including unmatched ones.
    pub fn features(&self) -> &[FeatureOutcome] {
        &self.features
    }
    /// All attempted point hypotheses, with geometric refusals preserved.
    pub fn hypotheses(&self) -> &[FeatureHypothesis] {
        &self.hypotheses
    }
}

/// Whole-operation refusal. Work/cancellation failures never return a partial report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssociationError {
    /// Invalid source identity, camera, pixel-noise assumption or input numeric range.
    InvalidInput,
    /// Invalid matching/triangulation policy or missing hypothesis/rig basis.
    InvalidOptions,
    /// The input exceeds a hard feature/allocation bound.
    Limit,
    /// Different property, descriptor or clock bases were offered.
    Basis,
    /// Two views refer to one logical camera.
    DuplicateCamera,
    /// Two views reuse the exact source exposure identity.
    DuplicateExposure,
    /// Exact image-domain pin or dimensions do not match the camera's qualified image mode.
    ImageDomain,
    /// Privacy namespaces do not agree with the requested namespace.
    PrivacyDomain,
    /// Capture interval, full hull, reference time or camera validity is inadmissible.
    CaptureWindow,
    /// Underlying geometry/work refusal; exhaustion and cancellation are atomic.
    Geometry(GeometryError),
}
impl From<GeometryError> for AssociationError {
    fn from(error: GeometryError) -> Self {
        Self::Geometry(error)
    }
}
impl std::fmt::Display for AssociationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "feature.association.invalid_input",
            Self::InvalidOptions => "feature.association.invalid_options",
            Self::Limit => "feature.association.limit",
            Self::Basis => "feature.association.basis",
            Self::DuplicateCamera => "feature.association.duplicate_camera",
            Self::DuplicateExposure => "feature.association.duplicate_exposure",
            Self::ImageDomain => "feature.association.image_domain",
            Self::PrivacyDomain => "feature.association.privacy_domain",
            Self::CaptureWindow => "feature.association.capture_window",
            Self::Geometry(GeometryError::Cancelled) => "feature.association.cancelled",
            Self::Geometry(GeometryError::BudgetExhausted) => "feature.association.budget",
            Self::Geometry(_) => "feature.association.geometry",
        })
    }
}
impl std::error::Error for AssociationError {}

/// Match two complete bounded feature sets and attempt native static-point fusion.
///
/// Empty feature sets produce explicit no-support reports. Descriptor ratio tests
/// require a distinct runner-up in each view, including when only one candidate is
/// inside the geometric gate. No ambiguous pair is chosen by ID or floating-point
/// residual. The operation is O(N*M + N*N + M*M + H*(I+T)), N,M<=128, H<=min(N,M),
/// with T imported triangles and I the bounded native solver iterations. All work
/// is charged and any work/cancellation failure discards the entire pending result.
pub fn associate_features(
    twin: &PropertyTwin,
    mut views: [&FeatureView; 2],
    options: AssociationOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<FeatureAssociation, AssociationError> {
    budget.charge(0)?;
    budget.charge(512)?;
    validate_options(options, budget)?;
    if views[0].camera.camera > views[1].camera.camera {
        views.swap(0, 1);
    }
    let capture_hull = validate_views(twin, views, options)?;
    let a = views[0].frame.features();
    let b = views[1].frame.features();
    budget.charge((a.len() * b.len()) as u64)?;
    let mut distances = reserved(a.len() * b.len())?;
    for left in a {
        for right in b {
            budget.charge(4)?;
            distances.push(left.descriptor.distance(right.descriptor));
        }
    }
    let mut nearest_a = reserved(a.len())?;
    for i in 0..a.len() {
        nearest_a.push(nearest(
            (0..b.len()).map(|j| distances[i * b.len() + j]),
            budget,
        )?);
    }
    let mut nearest_b = reserved(b.len())?;
    for j in 0..b.len() {
        nearest_b.push(nearest(
            (0..a.len()).map(|i| distances[i * b.len() + j]),
            budget,
        )?);
    }
    let lines_a_in_b = epipolar_lines(views[0], views[1], budget)?;
    let lines_b_in_a = epipolar_lines(views[1], views[0], budget)?;
    let evidence = association_evidence(twin, views, options, budget)?;
    let mut pairs = reserved(distances.len())?;
    let mut hypotheses = reserved(a.len().min(b.len()))?;
    for (i, left) in a.iter().enumerate() {
        for (j, right) in b.iter().enumerate() {
            budget.charge(32)?;
            let distance = distances[i * b.len() + j];
            let descriptor = descriptor_decision(distance, nearest_a[i], nearest_b[j], options);
            let epipolar_distance_pixels = match (lines_b_in_a[j], lines_a_in_b[i]) {
                (Some(line_a), Some(line_b)) => {
                    let result = [
                        line_distance(line_a, left.pixel),
                        line_distance(line_b, right.pixel),
                    ];
                    result.iter().all(|d| d.is_finite()).then_some(result)
                }
                _ => None,
            };
            let epipolar = match epipolar_distance_pixels {
                Some(d)
                    if d.iter()
                        .all(|x| *x <= options.maximum_epipolar_distance_pixels) =>
                {
                    EpipolarDecision::Passed
                }
                Some(_) => EpipolarDecision::OutsideGate,
                None => EpipolarDecision::Unobservable,
            };
            let mut row = PairDecision {
                features: [left.id, right.id],
                hamming_distance: distance,
                descriptor,
                epipolar,
                epipolar_distance_pixels,
                hypothesis: None,
            };
            if descriptor == DescriptorDecision::Candidate && epipolar == EpipolarDecision::Passed {
                row.hypothesis = Some(hypotheses.len());
                hypotheses.push(fuse_pair(
                    twin,
                    views,
                    [left, right],
                    options,
                    evidence,
                    hypotheses.len() as u64 + 1,
                    budget,
                )?);
            }
            pairs.push(row);
        }
    }
    let features = feature_outcomes(
        views,
        &distances,
        [&nearest_a, &nearest_b],
        &pairs,
        options,
        budget,
    )?;
    let snapshots = [copy_view(views[0], budget)?, copy_view(views[1], budget)?];
    budget.charge(0)?;
    Ok(FeatureAssociation {
        views: snapshots,
        options,
        evidence,
        capture_hull,
        pairs,
        features,
        hypotheses,
    })
}

fn reserved<T>(count: usize) -> Result<Vec<T>, AssociationError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| AssociationError::Limit)?;
    Ok(result)
}

fn validate_options(
    options: AssociationOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<(), AssociationError> {
    if [
        options.association_basis,
        options.camera_rig_digest,
        options.clock_evidence,
    ]
    .contains(&[0; 32])
        || options.privacy_domain == 0
        || options.clock == 0
        || options.max_capture_span_ns > 1_000_000_000
        || options.maximum_hamming_distance > 256
        || !(1..100).contains(&options.ratio_percent)
        || !options.maximum_epipolar_distance_pixels.is_finite()
        || !(0.0..=10_000.0).contains(&options.maximum_epipolar_distance_pixels)
        || options.triangulation.min_views != 2
        || options.triangulation.max_outliers != 0
    {
        return Err(AssociationError::InvalidOptions);
    }
    // The native solver validates policy before checking support, even for empty input.
    // Reuse that owner rather than allowing empty reports to bypass its policy validation.
    match triangulate(&[], options.triangulation, budget) {
        Err(TriangulationError::InsufficientViews) => Ok(()),
        Err(TriangulationError::Geometry(GeometryError::Cancelled)) => {
            Err(GeometryError::Cancelled.into())
        }
        Err(TriangulationError::Geometry(GeometryError::BudgetExhausted)) => {
            Err(GeometryError::BudgetExhausted.into())
        }
        _ => Err(AssociationError::InvalidOptions),
    }
}

fn validate_views(
    twin: &PropertyTwin,
    views: [&FeatureView; 2],
    options: AssociationOptions,
) -> Result<[u64; 2], AssociationError> {
    if views[0].camera.camera == views[1].camera.camera {
        return Err(AssociationError::DuplicateCamera);
    }
    if views[0].frame.identity().exposure == views[1].frame.identity().exposure {
        return Err(AssociationError::DuplicateExposure);
    }
    if views[0].frame.descriptor_domain() != views[1].frame.descriptor_domain() {
        return Err(AssociationError::Basis);
    }
    let mut hull = [u64::MAX, 0];
    for view in views {
        if view.frame.features().len() > MAX_ASSOCIATION_FEATURES {
            return Err(AssociationError::Limit);
        }
        let c = view.camera;
        if [
            view.source_digest,
            view.allowed_mask_digest,
            view.image_domain_digest,
            view.mapping_basis,
        ]
        .contains(&[0; 32])
            || c.camera == 0
            || c.calibration == 0
            || c.image_domain == 0
            || !view.sigma_pixels.is_finite()
            || !(1e-3..=1e3).contains(&view.sigma_pixels)
            || c.pose
                .center()
                .iter()
                .any(|x| !x.is_finite() || x.abs() > 1e12)
            || c.error.is_some_and(|error| !error.valid_for(c.intrinsics))
        {
            return Err(AssociationError::InvalidInput);
        }
        if c.geometry != twin.basis()
            || c.clock != options.clock
            || view.clock_evidence != options.clock_evidence
        {
            return Err(AssociationError::Basis);
        }
        if view.privacy_domain != options.privacy_domain {
            return Err(AssociationError::PrivacyDomain);
        }
        if view.frame.identity().image_domain != view.image_domain_digest
            || view.frame.identity().dimensions != c.intrinsics.dimensions()
        {
            return Err(AssociationError::ImageDomain);
        }
        if view.capture[0] > view.capture[1]
            || c.validity[0] > c.validity[1]
            || view.capture[0] < c.validity[0]
            || view.capture[1] > c.validity[1]
        {
            return Err(AssociationError::CaptureWindow);
        }
        hull[0] = hull[0].min(view.capture[0]);
        hull[1] = hull[1].max(view.capture[1]);
    }
    if hull[1] - hull[0] > options.max_capture_span_ns
        || !(hull[0]..=hull[1]).contains(&options.reference_time_ns)
    {
        return Err(AssociationError::CaptureWindow);
    }
    Ok(hull)
}

#[derive(Clone, Copy)]
struct Nearest {
    best: u16,
    second: u16,
    first: Option<usize>,
}
impl Nearest {
    fn unambiguous(self, ratio: u8) -> bool {
        self.first.is_some()
            && self.second <= 256
            && self.best != self.second
            && u32::from(self.best) * 100 < u32::from(self.second) * u32::from(ratio)
    }
}
fn nearest(
    distances: impl Iterator<Item = u16>,
    budget: &mut WorkBudget<'_>,
) -> Result<Nearest, AssociationError> {
    let mut result = Nearest {
        best: 257,
        second: 257,
        first: None,
    };
    for (index, distance) in distances.enumerate() {
        budget.charge(1)?;
        if distance < result.best {
            result.second = result.best;
            result.best = distance;
            result.first = Some(index);
        } else {
            result.second = result.second.min(distance);
        }
    }
    Ok(result)
}
fn descriptor_decision(
    distance: u16,
    a: Nearest,
    b: Nearest,
    options: AssociationOptions,
) -> DescriptorDecision {
    if distance > options.maximum_hamming_distance {
        DescriptorDecision::TooDistant
    } else if distance != a.best || distance != b.best {
        DescriptorDecision::NonMutual
    } else if !a.unambiguous(options.ratio_percent) || !b.unambiguous(options.ratio_percent) {
        DescriptorDecision::Ambiguous
    } else {
        DescriptorDecision::Candidate
    }
}

fn epipolar_lines(
    from: &FeatureView,
    to: &FeatureView,
    budget: &mut WorkBudget<'_>,
) -> Result<Vec<Option<[f64; 3]>>, AssociationError> {
    let mut lines = reserved(from.frame.features().len())?;
    let a = from.camera.pose.center();
    let b = to.camera.pose.center();
    let baseline = std::array::from_fn::<_, 3, _>(|i| a[i] - b[i]);
    let length = baseline[0].hypot(baseline[1]).hypot(baseline[2]);
    for feature in from.frame.features() {
        budget.charge(128)?;
        if length <= 1e-12 || !length.is_finite() {
            lines.push(None);
            continue;
        }
        let baseline = baseline.map(|x| x / length);
        let ray = from
            .camera
            .pose
            .ray(from.camera.intrinsics, feature.pixel)?
            .direction();
        let normal = [
            baseline[1] * ray[2] - baseline[2] * ray[1],
            baseline[2] * ray[0] - baseline[0] * ray[2],
            baseline[0] * ray[1] - baseline[1] * ray[0],
        ];
        let rotation = to.camera.pose.rotation();
        let n = rotation.map(|row| row[0] * normal[0] + row[1] * normal[1] + row[2] * normal[2]);
        let [fx, fy] = to.camera.intrinsics.focal_lengths();
        let [cx, cy] = to.camera.intrinsics.principal_point();
        let line = [n[0] / fx, n[1] / fy, n[2] - n[0] * cx / fx - n[1] * cy / fy];
        let norm = line[0].hypot(line[1]);
        let line = (norm > 1e-14 && norm.is_finite()).then(|| line.map(|x| x / norm));
        lines.push(line.filter(|l| l.iter().all(|x| x.is_finite())));
    }
    Ok(lines)
}
fn line_distance(line: [f64; 3], pixel: [f64; 2]) -> f64 {
    (line[0] * pixel[0] + line[1] * pixel[1] + line[2]).abs()
}

fn fuse_pair(
    twin: &PropertyTwin,
    views: [&FeatureView; 2],
    features: [&ImageFeature; 2],
    options: AssociationOptions,
    association: [u8; 32],
    handle: u64,
    budget: &mut WorkBudget<'_>,
) -> Result<FeatureHypothesis, AssociationError> {
    budget.charge(1024)?;
    let ids = features.map(|f| f.id);
    let evidence = linked_evidence(b"fss.cross_camera_feature_pair.v1", association, ids)?;
    let mut inputs = reserved(2)?;
    for index in 0..2 {
        let view = views[index];
        let feature = features[index];
        let observation_evidence = linked_evidence(
            b"fss.cross_camera_feature_observation.v1",
            evidence,
            [view.camera.camera, feature.id],
        )?;
        inputs.push(FusionInput {
            camera: view.camera,
            privacy_domain: view.privacy_domain,
            sigma_pixels: view.sigma_pixels,
            observation: ContactObservation {
                evidence: observation_evidence,
                // Query-local common-feature hypothesis and single-exposure handles only.
                // Exact source exposure identities remain in the immutable view snapshots/hash.
                track: handle,
                camera: view.camera.camera,
                exposure: 1,
                image_domain: view.camera.image_domain,
                clock: view.camera.clock,
                capture: view.capture,
                pixel_min: feature.pixel,
                pixel_max: feature.pixel,
                visible_contact: true,
            },
        });
    }
    let request = FusionRequest {
        association_evidence: evidence,
        privacy_domain: options.privacy_domain,
        reference_time_ns: options.reference_time_ns,
        max_capture_span_ns: options.max_capture_span_ns,
        motion: CommonPointMotion::Static,
        triangulation: options.triangulation,
    };
    let outcome = match fuse_scene_point(twin, &inputs, request, budget) {
        Ok(point) => FeatureHypothesisOutcome::Fused(Box::new(point)),
        Err(FusionError::Twin(TwinError::Limit)) => return Err(AssociationError::Limit),
        Err(
            FusionError::Twin(TwinError::Geometry(error))
            | FusionError::Triangulation(TriangulationError::Geometry(error)),
        ) if matches!(
            error,
            GeometryError::Cancelled
                | GeometryError::BudgetExhausted
                | GeometryError::LimitExceeded
        ) =>
        {
            return Err(error.into());
        }
        Err(error) => FeatureHypothesisOutcome::Refused(error),
    };
    Ok(FeatureHypothesis {
        features: ids,
        evidence,
        outcome,
    })
}

fn feature_outcomes(
    views: [&FeatureView; 2],
    distances: &[u16],
    nearest: [&[Nearest]; 2],
    pairs: &[PairDecision],
    options: AssociationOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<Vec<FeatureOutcome>, AssociationError> {
    let counts = views.map(|v| v.frame.features().len());
    let mut result = reserved(counts[0] + counts[1])?;
    for side in 0..2 {
        for (index, feature) in views[side].frame.features().iter().enumerate() {
            let n = nearest[side][index];
            let mut nearest_features = reserved(counts[1 - side])?;
            for (other, candidate) in views[1 - side].frame.features().iter().enumerate() {
                budget.charge(1)?;
                let pair_index = if side == 0 {
                    index * counts[1] + other
                } else {
                    other * counts[1] + index
                };
                if distances[pair_index] == n.best {
                    nearest_features.push(candidate.id);
                }
            }
            let row = n.first.map(|other| {
                &pairs[if side == 0 {
                    index * counts[1] + other
                } else {
                    other * counts[1] + index
                }]
            });
            let disposition = if n.first.is_none() {
                FeatureDisposition::NoCounterpart
            } else if n.best > options.maximum_hamming_distance {
                FeatureDisposition::TooDistant
            } else if !n.unambiguous(options.ratio_percent) {
                FeatureDisposition::Ambiguous
            } else if let Some(row) = row {
                match row.descriptor {
                    DescriptorDecision::TooDistant => FeatureDisposition::TooDistant,
                    DescriptorDecision::Ambiguous => FeatureDisposition::Ambiguous,
                    DescriptorDecision::NonMutual => FeatureDisposition::NonMutual,
                    DescriptorDecision::Candidate => match row.epipolar {
                        EpipolarDecision::OutsideGate => FeatureDisposition::EpipolarRejected,
                        EpipolarDecision::Unobservable => FeatureDisposition::EpipolarUnobservable,
                        EpipolarDecision::Passed => FeatureDisposition::Selected,
                    },
                }
            } else {
                FeatureDisposition::NoCounterpart
            };
            result.push(FeatureOutcome {
                camera: views[side].camera.camera,
                feature: feature.id,
                nearest_features,
                best_distance: (n.best <= 256).then_some(n.best),
                runner_up_distance: (n.second <= 256).then_some(n.second),
                disposition,
                hypothesis: row.and_then(|r| r.hypothesis),
            });
        }
    }
    Ok(result)
}

fn copy_view(
    view: &FeatureView,
    budget: &mut WorkBudget<'_>,
) -> Result<FeatureView, AssociationError> {
    let mut features = reserved(view.frame.features().len())?;
    features.extend_from_slice(view.frame.features());
    let frame = FeatureFrame::new(
        view.frame.identity(),
        view.frame.descriptor_domain(),
        features,
        budget,
    )
    .map_err(|e| match e {
        LocalizationError::Geometry(e) => AssociationError::Geometry(e),
        LocalizationError::Limit => AssociationError::Limit,
        _ => AssociationError::InvalidInput,
    })?;
    Ok(FeatureView {
        frame,
        camera: view.camera,
        source_digest: view.source_digest,
        allowed_mask_digest: view.allowed_mask_digest,
        image_domain_digest: view.image_domain_digest,
        mapping_basis: view.mapping_basis,
        privacy_domain: view.privacy_domain,
        clock_evidence: view.clock_evidence,
        capture: view.capture,
        sigma_pixels: view.sigma_pixels,
    })
}

fn linked_evidence(
    domain: &[u8],
    parent: [u8; 32],
    ids: [u64; 2],
) -> Result<[u8; 32], AssociationError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.bytes(domain);
    encoder.bytes(&parent);
    for id in ids {
        encoder.u64(id);
    }
    finish_digest(encoder)
}
fn finish_digest(encoder: CanonicalEncoder) -> Result<[u8; 32], AssociationError> {
    Ok(ContentDigest::sha256(
        &encoder
            .finish_checked()
            .map_err(|_| AssociationError::Limit)?,
    )
    .bytes())
}
fn floats(encoder: &mut CanonicalEncoder, values: impl IntoIterator<Item = f64>) {
    for value in values {
        encoder.u64(if value == 0.0 { 0 } else { value.to_bits() });
    }
}
fn association_evidence(
    twin: &PropertyTwin,
    views: [&FeatureView; 2],
    options: AssociationOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<[u8; 32], AssociationError> {
    budget.charge(
        4096 + (views[0].frame.features().len() + views[1].frame.features().len()) as u64 * 128,
    )?;
    let mut encoder = CanonicalEncoder::new();
    encoder.bytes(b"fss.cross_camera_feature_association.v1");
    encoder.bytes(&twin.digest());
    for digest in [
        options.association_basis,
        options.camera_rig_digest,
        options.clock_evidence,
    ] {
        encoder.bytes(&digest);
    }
    for value in [
        options.privacy_domain,
        options.clock,
        options.reference_time_ns,
        options.max_capture_span_ns,
    ] {
        encoder.u64(value);
    }
    encoder.u32(u32::from(options.maximum_hamming_distance));
    encoder.u8(options.ratio_percent);
    floats(&mut encoder, [options.maximum_epipolar_distance_pixels]);
    let t = options.triangulation;
    for count in [t.min_views, t.max_outliers, t.max_iterations] {
        encoder.u64(count as u64);
    }
    floats(
        &mut encoder,
        [
            t.max_reprojection_pixels,
            t.min_ray_angle_radians,
            t.max_distance,
            t.max_condition_number,
        ],
    );
    for view in views {
        let identity = view.frame.identity();
        for digest in [
            view.source_digest,
            view.allowed_mask_digest,
            view.image_domain_digest,
            view.mapping_basis,
            view.clock_evidence,
            identity.exposure,
            identity.pixels,
            identity.image_domain,
            view.frame.descriptor_domain(),
        ] {
            encoder.bytes(&digest);
        }
        for dimension in identity.dimensions {
            encoder.u32(dimension);
        }
        let c = view.camera;
        // Process-local GeometryBasis handles are checked against the twin and retained in
        // snapshots. The evidence hash uses the durable twin/rig digests instead of those handles.
        for value in [
            view.privacy_domain,
            view.capture[0],
            view.capture[1],
            c.camera,
            c.calibration,
            c.image_domain,
            c.clock,
            c.validity[0],
            c.validity[1],
        ] {
            encoder.u64(value);
        }
        for dimension in c.intrinsics.dimensions() {
            encoder.u32(dimension);
        }
        floats(&mut encoder, c.pose.rotation().into_iter().flatten());
        floats(&mut encoder, c.pose.translation());
        floats(&mut encoder, c.intrinsics.focal_lengths());
        floats(&mut encoder, c.intrinsics.principal_point());
        floats(&mut encoder, [view.sigma_pixels]);
        encoder.bool(c.error.is_some());
        if let Some(error) = c.error {
            floats(&mut encoder, error.centre);
            floats(&mut encoder, [error.rotation_entry]);
            floats(&mut encoder, error.focal);
            floats(&mut encoder, error.principal);
        }
        encoder.u64(view.frame.features().len() as u64);
        for feature in view.frame.features() {
            encoder.u64(feature.id);
            floats(&mut encoder, feature.pixel);
            for word in feature.descriptor.0 {
                encoder.u64(word);
            }
        }
    }
    finish_digest(encoder)
}

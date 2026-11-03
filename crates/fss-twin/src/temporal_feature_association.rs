#![forbid(unsafe_code)]
//! Complete feature correspondence graphs across repeated, staggered camera exposures.
//!
//! A descriptor link is a conditional common-feature hypothesis, never physical
//! identity. All frame-pair descriptors participate before any motion fit. Static
//! epipolar gates are deliberately absent: a moving point need not lie on another
//! exposure's static epipolar line. A connected component is fitted only when it
//! contains at most one feature per exposure and every direct pair supports it.
//! Missing links, conflicting cycles, ties and native geometric refusals remain
//! visible. No point is promoted to a static landmark or persistent track.
//!
//! Source snapshots are owner-resolved inputs, not authenticated custody. The
//! constant-velocity model and exact nominal capture midpoints are assumptions;
//! full capture intervals, camera errors, masks and source identities are retained.
//! A component uses the unchanged requested scene time. Extrapolation is refused,
//! never hidden by clamping that time to the component's smaller observation range.

use crate::feature_association::{DescriptorDecision, FeatureView};
use crate::localization::{FeatureFrame, LocalizationError};
use crate::multiview::FusionInput;
use crate::multiview_motion::{
    FusedSceneMotion, MotionFusionError, MotionFusionRequest, fuse_scene_motion,
};
use crate::{ContactObservation, PropertyTwin, TwinError};
use fss_core::{CanonicalEncoder, ContentDigest};
use fss_geometry::temporal_triangulation::{
    MAX_TEMPORAL_SPAN_NS, TemporalTriangulationError, TemporalTriangulationOptions,
    triangulate_motion,
};
use fss_geometry::{GeometryError, WorkBudget};

/// Four through sixteen distinct original exposures in one bounded operation.
pub const MAX_TEMPORAL_EXPOSURES: usize = 16;
/// Two through eight distinct logical cameras, each with one fixed mode/snapshot.
pub const MAX_TEMPORAL_CAMERAS: usize = 8;
/// Maximum selected features in any original exposure; no implicit truncation.
pub const MAX_TEMPORAL_FEATURES_PER_VIEW: usize = 128;
/// Complete selected inventory across every exposure, including unmatched features.
pub const MAX_TEMPORAL_FEATURES: usize = 256;
/// Complete Cartesian frame-pair inventory at sixteen evenly populated exposures.
pub const MAX_TEMPORAL_PAIR_ROWS: usize = 30_720;

/// Explicit constant-velocity hypothesis, common clock and bounded matching policy.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TemporalAssociationOptions {
    /// Nonzero evidence/assumption for constant motion over the complete capture hull.
    pub association_basis: [u8; 32],
    /// Exact immutable camera-rig digest; not an activation or calibration certificate.
    pub camera_rig_digest: [u8; 32],
    /// Shared owner-resolved privacy namespace, never an access grant.
    pub privacy_domain: u64,
    /// Shared nonzero capture-clock generation.
    pub clock: u64,
    /// Exact synchronization evidence or explicitly declared alignment assumption.
    pub clock_evidence: [u8; 32],
    /// Common output time. Each fitted component must bracket it without extrapolation.
    pub reference_time_ns: u64,
    /// Maximum complete capture hull, including uncertainty, in 1..=60 seconds.
    pub max_capture_span_ns: u64,
    /// Maximum width of any capture interval; zero requires exact capture times.
    pub max_capture_uncertainty_ns: u64,
    /// Inclusive Hamming distance threshold in 0..=256.
    pub maximum_hamming_distance: u16,
    /// Strict best/runner-up ratio in both directions, in integer percent 1..=99.
    /// A tied nearest neighbor or absent runner-up is always ambiguous.
    pub ratio_percent: u8,
    /// Existing native joint position/velocity fitting policy, retaining all inputs.
    pub triangulation: TemporalTriangulationOptions,
}

/// One original image feature in the canonical exposure inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct TemporalFeature {
    /// Index into [`TemporalFeatureAssociation::views`], not an independent sensor ID.
    pub view: usize,
    /// Logical fixed camera, which may occur in several original exposures.
    pub camera: u64,
    /// Original image-local feature identity.
    pub feature: u64,
}

/// Exact location in the complete frame-pair and Cartesian decision inventories.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct TemporalPairReference {
    /// Index into [`TemporalFeatureAssociation::pairs`].
    pub pair: usize,
    /// Cartesian row index into [`TemporalViewPair::pairs`].
    pub decision: usize,
}

/// One Cartesian descriptor comparison; no geometric prefilter erases competitors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TemporalPairDecision {
    /// Original feature IDs in the enclosing pair's canonical view order.
    pub features: [u64; 2],
    /// Actual complete 256-bit descriptor distance.
    pub hamming_distance: u16,
    /// Candidate means strict unique mutual nearest neighbors, not physical identity.
    pub descriptor: DescriptorDecision,
}

/// Complete descriptor outcome for one feature against one other exposure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemporalFeatureDisposition {
    /// The other original exposure has no admitted features.
    NoCounterpart,
    /// Even the nearest descriptor exceeds the declared absolute threshold.
    TooDistant,
    /// A tie, missing runner-up or failed strict ratio prevents selection.
    Ambiguous,
    /// The nearest feature prefers another feature in the reverse direction.
    NonMutual,
    /// A descriptor link was selected; its component may still refuse geometry.
    Selected,
}

/// Every selected image feature receives one outcome per other exposure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemporalFeatureOutcome {
    /// Canonical source exposure index.
    pub view: usize,
    /// Original image-local feature identity.
    pub feature: u64,
    /// Every tied nearest feature in the other exposure, in feature-ID order.
    pub nearest_features: Vec<u64>,
    /// Actual best distance, or unavailable when the other exposure is empty.
    pub best_distance: Option<u16>,
    /// Actual runner-up, including equality on ties; absent means insufficient support.
    pub runner_up_distance: Option<u16>,
    /// Complete descriptor outcome, without a stationary-scene geometry assumption.
    pub disposition: TemporalFeatureDisposition,
    /// Selected Cartesian row index in the enclosing [`TemporalViewPair`], if any.
    pub selected_pair: Option<usize>,
}

/// Immutable complete comparison of two distinct original exposures.
#[derive(Clone, Debug)]
pub struct TemporalViewPair {
    views: [usize; 2],
    evidence: [u8; 32],
    pairs: Vec<TemporalPairDecision>,
    features: Vec<TemporalFeatureOutcome>,
}
impl TemporalViewPair {
    /// Original source indices in canonical increasing order; cameras may be equal.
    pub fn views(&self) -> [usize; 2] {
        self.views
    }
    /// Versioned link to the complete original scene inputs and these two exposures.
    pub fn evidence(&self) -> [u8; 32] {
        self.evidence
    }
    /// Complete Cartesian table, ordered by first then second original feature ID.
    pub fn pairs(&self) -> &[TemporalPairDecision] {
        &self.pairs
    }
    /// All features from both views, including every equal nearest alternative.
    pub fn features(&self) -> &[TemporalFeatureOutcome] {
        &self.features
    }
}

/// Explicit joint outcome for a connected component of selected descriptor links.
#[derive(Clone, Debug)]
pub enum TemporalComponentOutcome {
    /// An isolated feature has no selected descriptor link.
    Unmatched,
    /// A selected-link cycle connects different features in the same exposure.
    ExposureConflict {
        /// Every repeated canonical exposure index, in increasing order.
        views: Vec<usize>,
    },
    /// Direct pair support is missing. Transitivity is not treated as correspondence.
    IncompletePairSupport {
        /// Every missing selected link's exact Cartesian decision, in canonical order.
        pairs: Vec<TemporalPairReference>,
    },
    /// A closed component has fewer than four original feature observations.
    InsufficientObservations,
    /// A closed component has fewer than two distinct logical cameras.
    InsufficientCameras,
    /// Conditional joint position/velocity fit, retaining every source and mesh diagnostic.
    Fused(Box<FusedSceneMotion>),
    /// Complete correspondence support failed time, observability or native geometry gates.
    Refused(MotionFusionError),
}

/// Complete source-linked correspondence component, including unresolved ones.
#[derive(Clone, Debug)]
pub struct TemporalFeatureComponent {
    members: Vec<TemporalFeature>,
    links: Vec<TemporalPairReference>,
    evidence: [u8; 32],
    capture_hull: [u64; 2],
    nominal_time_range_ns: [u64; 2],
    requested_scene_time_ns: u64,
    outcome: TemporalComponentOutcome,
}
impl TemporalFeatureComponent {
    /// Every connected feature in canonical exposure/feature order.
    pub fn members(&self) -> &[TemporalFeature] {
        &self.members
    }
    /// Every selected descriptor link in this component, including conflicting cycles.
    pub fn links(&self) -> &[TemporalPairReference] {
        &self.links
    }
    /// Versioned identity of the full scene, exact members, links and timing assumptions.
    pub fn evidence(&self) -> [u8; 32] {
        self.evidence
    }
    /// Full original capture hull, not the intersection of timestamp intervals.
    pub fn capture_hull(&self) -> [u64; 2] {
        self.capture_hull
    }
    /// Earliest/latest integer capture midpoint used by the nominal motion model.
    pub fn nominal_time_range_ns(&self) -> [u64; 2] {
        self.nominal_time_range_ns
    }
    /// Unchanged global scene time, even when this component cannot bracket it.
    pub fn requested_scene_time_ns(&self) -> u64 {
        self.requested_scene_time_ns
    }
    /// Complete correspondence or motion-fit outcome.
    pub fn outcome(&self) -> &TemporalComponentOutcome {
        &self.outcome
    }
}

/// Immutable complete temporal scene graph, not a tracker or identity assignment.
#[derive(Clone, Debug)]
pub struct TemporalFeatureAssociation {
    views: Vec<FeatureView>,
    options: TemporalAssociationOptions,
    evidence: [u8; 32],
    capture_hull: [u64; 2],
    pairs: Vec<TemporalViewPair>,
    components: Vec<TemporalFeatureComponent>,
}
impl TemporalFeatureAssociation {
    /// Complete original snapshots ordered by camera, capture interval and exposure digest.
    pub fn views(&self) -> &[FeatureView] {
        &self.views
    }
    /// Original constant-velocity, descriptor, timing and geometry policy.
    pub fn options(&self) -> TemporalAssociationOptions {
        self.options
    }
    /// Exact original input/configuration identity; never authority or physical truth.
    pub fn evidence(&self) -> [u8; 32] {
        self.evidence
    }
    /// Complete original capture hull, including every empty or unmatched source view.
    pub fn capture_hull(&self) -> [u64; 2] {
        self.capture_hull
    }
    /// All unordered exposure pairs, in increasing first/second source-index order.
    pub fn pairs(&self) -> &[TemporalViewPair] {
        &self.pairs
    }
    /// Every selected-link component, including unmatched singleton features.
    pub fn components(&self) -> &[TemporalFeatureComponent] {
        &self.components
    }
}

/// Whole-operation failure. Budget/cancellation never return a partial scene graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemporalAssociationError {
    /// Nonfinite, missing or out-of-profile matching/motion policy.
    InvalidOptions,
    /// Invalid count, source declaration or pixel/calibration-error assumption.
    InvalidInput,
    /// Mixed twin, clock, descriptor space or changed repeated-camera snapshot/mapping.
    Basis,
    /// Inputs do not share the declared privacy namespace.
    PrivacyDomain,
    /// A feature frame does not match its declared image domain or camera dimensions.
    ImageDomain,
    /// Capture validity, uncertainty, full hull or requested global time is inadmissible.
    CaptureWindow,
    /// An original exposure digest was reused, including under a different camera alias.
    DuplicateExposure,
    /// A hard representation/allocation bound was exceeded; no truncation is performed.
    Limit,
    /// Native work, cooperative cancellation or numeric failure.
    Geometry(GeometryError),
}
impl From<GeometryError> for TemporalAssociationError {
    fn from(error: GeometryError) -> Self {
        Self::Geometry(error)
    }
}
impl std::fmt::Display for TemporalAssociationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidOptions => "invalid temporal feature association options",
            Self::InvalidInput => "invalid temporal feature association input",
            Self::Basis => "incompatible temporal feature basis or repeated camera snapshot",
            Self::PrivacyDomain => "incompatible temporal feature privacy domain",
            Self::ImageDomain => "temporal feature image-domain mismatch",
            Self::CaptureWindow => "inadmissible temporal feature capture window",
            Self::DuplicateExposure => "duplicate original temporal feature exposure",
            Self::Limit => "temporal feature association limit exceeded",
            Self::Geometry(GeometryError::Cancelled) => "temporal feature association cancelled",
            Self::Geometry(GeometryError::BudgetExhausted) => {
                "temporal feature association work budget exhausted"
            }
            Self::Geometry(GeometryError::LimitExceeded) => {
                "temporal feature association geometry limit exceeded"
            }
            Self::Geometry(_) => "temporal feature association geometry failure",
        })
    }
}
impl std::error::Error for TemporalAssociationError {}

#[derive(Clone, Copy)]
struct Node {
    view: usize,
    feature: usize,
}
#[derive(Clone, Copy)]
struct Link {
    nodes: [usize; 2],
    reference: TemporalPairReference,
}

/// Automatically associate moving-feature observations and attempt native motion fits.
///
/// All views, even empty ones, are validated before the complete descriptor graph.
/// Repeated encoded bytes/pixels are allowed across distinct original exposures;
/// they never become evidence of independent sensors. Repeated logical cameras
/// require identical camera/mode, image-domain and mapping snapshots.
///
/// Complete graph work is bounded by 30,720 descriptor rows, 3,840 per-pair feature
/// outcomes (including all nearest ties), 1,920 selected links and 256 components.
/// All allocations/work are bounded and use one caller budget. Real work exhaustion
/// or cancellation discards the pending report; expected geometry refusals retain it.
pub fn associate_temporal_features(
    twin: &PropertyTwin,
    views: &[FeatureView],
    options: TemporalAssociationOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<TemporalFeatureAssociation, TemporalAssociationError> {
    budget.charge(0)?;
    validate_options(options, budget)?;
    if !(4..=MAX_TEMPORAL_EXPOSURES).contains(&views.len()) {
        return Err(TemporalAssociationError::InvalidInput);
    }
    budget.charge(512 * views.len() as u64)?;
    let mut ordered = reserved(views.len())?;
    ordered.extend(views);
    ordered.sort_by_key(|v| (v.camera.camera, v.capture, v.frame.identity().exposure));
    let capture_hull = validate_views(twin, &ordered, options, budget)?;
    let evidence = scene_evidence(twin, &ordered, options, budget)?;
    let mut nodes = reserved(MAX_TEMPORAL_FEATURES)?;
    let mut offsets = [0; MAX_TEMPORAL_EXPOSURES];
    for (index, view) in ordered.iter().enumerate() {
        offsets[index] = nodes.len();
        for feature in 0..view.frame.features().len() {
            budget.charge(1)?;
            nodes.push(Node {
                view: index,
                feature,
            });
        }
    }
    let mut parents = reserved(nodes.len())?;
    parents.extend(0..nodes.len());
    let mut pairs = reserved(views.len() * (views.len() - 1) / 2)?;
    let mut links = reserved((views.len() - 1) * nodes.len() / 2)?;
    for left in 0..ordered.len() {
        for right in left + 1..ordered.len() {
            let pair = match_pair(&ordered, [left, right], options, evidence, budget)?;
            let width = ordered[right].frame.features().len();
            for (decision, row) in pair.pairs.iter().enumerate() {
                budget.charge(1)?;
                if row.descriptor == DescriptorDecision::Candidate {
                    let endpoints = [
                        offsets[left] + decision / width,
                        offsets[right] + decision % width,
                    ];
                    let a = root(&parents, endpoints[0], budget)?;
                    let b = root(&parents, endpoints[1], budget)?;
                    parents[a.max(b)] = a.min(b);
                    links.push(Link {
                        nodes: endpoints,
                        reference: TemporalPairReference {
                            pair: pairs.len(),
                            decision,
                        },
                    });
                }
            }
            pairs.push(pair);
        }
    }
    let mut roots = reserved(nodes.len())?;
    for node in 0..nodes.len() {
        roots.push(root(&parents, node, budget)?);
    }
    let mut components = reserved(nodes.len())?;
    for first in 0..nodes.len() {
        if roots[first] != first {
            continue;
        }
        budget.charge((nodes.len() + links.len()) as u64)?;
        let mut group = reserved(nodes.len())?;
        group.extend((0..nodes.len()).filter(|&n| roots[n] == first));
        let mut component_links = reserved(links.len())?;
        component_links.extend(
            links
                .iter()
                .filter(|l| roots[l.nodes[0]] == first)
                .map(|l| l.reference),
        );
        components.push(component(
            twin,
            &ordered,
            &nodes,
            &group,
            component_links,
            &pairs,
            options,
            evidence,
            components.len() as u64 + 1,
            budget,
        )?);
    }
    let mut snapshots = reserved(ordered.len())?;
    for view in &ordered {
        snapshots.push(copy_view(view, budget)?);
    }
    budget.charge(0)?;
    Ok(TemporalFeatureAssociation {
        views: snapshots,
        options,
        evidence,
        capture_hull,
        pairs,
        components,
    })
}

fn reserved<T>(count: usize) -> Result<Vec<T>, TemporalAssociationError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| TemporalAssociationError::Limit)?;
    Ok(values)
}

fn validate_options(
    options: TemporalAssociationOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<(), TemporalAssociationError> {
    budget.charge(512)?;
    if [
        options.association_basis,
        options.camera_rig_digest,
        options.clock_evidence,
    ]
    .contains(&[0; 32])
        || options.privacy_domain == 0
        || options.clock == 0
        || options.max_capture_span_ns == 0
        || i128::from(options.max_capture_span_ns) > MAX_TEMPORAL_SPAN_NS
        || options.max_capture_uncertainty_ns > options.max_capture_span_ns
        || options.maximum_hamming_distance > 256
        || !(1..100).contains(&options.ratio_percent)
    {
        return Err(TemporalAssociationError::InvalidOptions);
    }
    // Validate the actual native solver policy even when every source is masked/empty.
    match triangulate_motion(&[], options.triangulation, budget) {
        Err(TemporalTriangulationError::InsufficientObservations) => Ok(()),
        Err(TemporalTriangulationError::Geometry(error)) => Err(error.into()),
        _ => Err(TemporalAssociationError::InvalidOptions),
    }
}

fn validate_views(
    twin: &PropertyTwin,
    views: &[&FeatureView],
    options: TemporalAssociationOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<[u64; 2], TemporalAssociationError> {
    let mut total = 0_usize;
    let mut cameras = 0_usize;
    let mut hull = [u64::MAX, 0];
    let descriptor_domain = views[0].frame.descriptor_domain();
    for (index, view) in views.iter().enumerate() {
        budget.charge(128)?;
        if view.frame.features().len() > MAX_TEMPORAL_FEATURES_PER_VIEW {
            return Err(TemporalAssociationError::Limit);
        }
        total += view.frame.features().len();
        if total > MAX_TEMPORAL_FEATURES {
            return Err(TemporalAssociationError::Limit);
        }
        let camera = view.camera;
        if [
            view.source_digest,
            view.allowed_mask_digest,
            view.image_domain_digest,
            view.mapping_basis,
        ]
        .contains(&[0; 32])
            || [camera.camera, camera.calibration, camera.image_domain].contains(&0)
            || !view.sigma_pixels.is_finite()
            || !(1e-3..=1e3).contains(&view.sigma_pixels)
            || camera
                .pose
                .center()
                .iter()
                .any(|v| !v.is_finite() || v.abs() > 1e12)
            || camera
                .error
                .is_some_and(|e| !e.valid_for(camera.intrinsics))
        {
            return Err(TemporalAssociationError::InvalidInput);
        }
        if camera.geometry != twin.basis()
            || camera.clock != options.clock
            || view.clock_evidence != options.clock_evidence
            || view.frame.descriptor_domain() != descriptor_domain
        {
            return Err(TemporalAssociationError::Basis);
        }
        if view.privacy_domain != options.privacy_domain {
            return Err(TemporalAssociationError::PrivacyDomain);
        }
        if view.frame.identity().image_domain != view.image_domain_digest
            || view.frame.identity().dimensions != camera.intrinsics.dimensions()
        {
            return Err(TemporalAssociationError::ImageDomain);
        }
        if view.capture[0] > view.capture[1]
            || camera.validity[0] > camera.validity[1]
            || view.capture[0] < camera.validity[0]
            || view.capture[1] > camera.validity[1]
            || view.capture[1] - view.capture[0] > options.max_capture_uncertainty_ns
        {
            return Err(TemporalAssociationError::CaptureWindow);
        }
        for previous in &views[..index] {
            budget.charge(8)?;
            if previous.frame.identity().exposure == view.frame.identity().exposure {
                return Err(TemporalAssociationError::DuplicateExposure);
            }
            if previous.camera.camera == camera.camera
                && (previous.camera != camera
                    || previous.image_domain_digest != view.image_domain_digest
                    || previous.mapping_basis != view.mapping_basis)
            {
                return Err(TemporalAssociationError::Basis);
            }
        }
        if index == 0 || views[index - 1].camera.camera != camera.camera {
            cameras += 1;
        }
        hull[0] = hull[0].min(view.capture[0]);
        hull[1] = hull[1].max(view.capture[1]);
    }
    if !(2..=MAX_TEMPORAL_CAMERAS).contains(&cameras) {
        return Err(TemporalAssociationError::InvalidInput);
    }
    if hull[1] - hull[0] > options.max_capture_span_ns
        || !(hull[0]..=hull[1]).contains(&options.reference_time_ns)
    {
        return Err(TemporalAssociationError::CaptureWindow);
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
) -> Result<Nearest, TemporalAssociationError> {
    let mut value = Nearest {
        best: 257,
        second: 257,
        first: None,
    };
    for (index, distance) in distances.enumerate() {
        budget.charge(1)?;
        if distance < value.best {
            value.second = value.best;
            value.best = distance;
            value.first = Some(index);
        } else {
            value.second = value.second.min(distance);
        }
    }
    Ok(value)
}
fn decision(
    distance: u16,
    a: Nearest,
    b: Nearest,
    options: TemporalAssociationOptions,
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

fn match_pair(
    views: &[&FeatureView],
    indices: [usize; 2],
    options: TemporalAssociationOptions,
    scene: [u8; 32],
    budget: &mut WorkBudget<'_>,
) -> Result<TemporalViewPair, TemporalAssociationError> {
    let frames = indices.map(|i| views[i].frame.features());
    let [a, b] = frames.map(|features| features.len());
    budget.charge(512 + (a * b) as u64)?;
    let mut distances = reserved(a * b)?;
    for left in frames[0] {
        for right in frames[1] {
            budget.charge(4)?;
            distances.push(left.descriptor.distance(right.descriptor));
        }
    }
    let mut nearest_a = reserved(a)?;
    let mut nearest_b = reserved(b)?;
    for i in 0..a {
        nearest_a.push(nearest((0..b).map(|j| distances[i * b + j]), budget)?);
    }
    for j in 0..b {
        nearest_b.push(nearest((0..a).map(|i| distances[i * b + j]), budget)?);
    }
    let mut pairs = reserved(a * b)?;
    for (i, left) in frames[0].iter().enumerate() {
        for (j, right) in frames[1].iter().enumerate() {
            budget.charge(16)?;
            let distance = distances[i * b + j];
            pairs.push(TemporalPairDecision {
                features: [left.id, right.id],
                hamming_distance: distance,
                descriptor: decision(distance, nearest_a[i], nearest_b[j], options),
            });
        }
    }
    let mut features = reserved(a + b)?;
    let closest = [&nearest_a, &nearest_b];
    for side in 0..2 {
        for (index, feature) in frames[side].iter().enumerate() {
            let n = closest[side][index];
            let mut nearest_features = reserved(frames[1 - side].len())?;
            let row_index = |other| {
                if side == 0 {
                    index * b + other
                } else {
                    other * b + index
                }
            };
            for (other, candidate) in frames[1 - side].iter().enumerate() {
                budget.charge(1)?;
                if distances[row_index(other)] == n.best {
                    nearest_features.push(candidate.id);
                }
            }
            let row = n.first.map(row_index);
            let disposition = if n.first.is_none() {
                TemporalFeatureDisposition::NoCounterpart
            } else if n.best > options.maximum_hamming_distance {
                TemporalFeatureDisposition::TooDistant
            } else if !n.unambiguous(options.ratio_percent) {
                TemporalFeatureDisposition::Ambiguous
            } else if let Some(row) = row {
                match pairs[row].descriptor {
                    DescriptorDecision::TooDistant => TemporalFeatureDisposition::TooDistant,
                    DescriptorDecision::Ambiguous => TemporalFeatureDisposition::Ambiguous,
                    DescriptorDecision::NonMutual => TemporalFeatureDisposition::NonMutual,
                    DescriptorDecision::Candidate => TemporalFeatureDisposition::Selected,
                }
            } else {
                TemporalFeatureDisposition::NoCounterpart
            };
            features.push(TemporalFeatureOutcome {
                view: indices[side],
                feature: feature.id,
                nearest_features,
                best_distance: (n.best <= 256).then_some(n.best),
                runner_up_distance: (n.second <= 256).then_some(n.second),
                disposition,
                selected_pair: row
                    .filter(|&r| pairs[r].descriptor == DescriptorDecision::Candidate),
            });
        }
    }
    let evidence = linked_evidence(
        b"fss.temporal_feature_pair.v1",
        scene,
        indices.map(|i| i as u64),
    )?;
    Ok(TemporalViewPair {
        views: indices,
        evidence,
        pairs,
        features,
    })
}

fn root(
    parents: &[usize],
    mut node: usize,
    budget: &mut WorkBudget<'_>,
) -> Result<usize, TemporalAssociationError> {
    while parents[node] != node {
        budget.charge(1)?;
        node = parents[node];
    }
    Ok(node)
}

#[allow(clippy::too_many_arguments)]
fn component(
    twin: &PropertyTwin,
    views: &[&FeatureView],
    nodes: &[Node],
    group: &[usize],
    links: Vec<TemporalPairReference>,
    pairs: &[TemporalViewPair],
    options: TemporalAssociationOptions,
    scene: [u8; 32],
    handle: u64,
    budget: &mut WorkBudget<'_>,
) -> Result<TemporalFeatureComponent, TemporalAssociationError> {
    budget.charge(256 * group.len() as u64)?;
    let mut members = reserved(group.len())?;
    let mut repeated = reserved(group.len())?;
    let mut hull = [u64::MAX, 0];
    let mut nominal = [u64::MAX, 0];
    for &index in group {
        let node = nodes[index];
        let view = views[node.view];
        if members
            .last()
            .is_some_and(|m: &TemporalFeature| m.view == node.view)
            && repeated.last() != Some(&node.view)
        {
            repeated.push(node.view);
        }
        members.push(TemporalFeature {
            view: node.view,
            camera: view.camera.camera,
            feature: view.frame.features()[node.feature].id,
        });
        hull[0] = hull[0].min(view.capture[0]);
        hull[1] = hull[1].max(view.capture[1]);
        let midpoint = view.capture[0] + (view.capture[1] - view.capture[0]) / 2;
        nominal[0] = nominal[0].min(midpoint);
        nominal[1] = nominal[1].max(midpoint);
    }
    let evidence = component_evidence(
        scene,
        &members,
        &links,
        hull,
        nominal,
        options.reference_time_ns,
        budget,
    )?;
    let outcome = if members.len() == 1 {
        TemporalComponentOutcome::Unmatched
    } else if !repeated.is_empty() {
        TemporalComponentOutcome::ExposureConflict { views: repeated }
    } else {
        let mut missing = reserved(group.len() * (group.len() - 1) / 2)?;
        for (i, &left) in group.iter().enumerate() {
            for &right in &group[i + 1..] {
                budget.charge(8)?;
                let a = nodes[left];
                let b = nodes[right];
                let pair = a.view * (2 * views.len() - a.view - 1) / 2 + b.view - a.view - 1;
                let decision = a.feature * views[b.view].frame.features().len() + b.feature;
                if pairs[pair].pairs[decision].descriptor != DescriptorDecision::Candidate {
                    missing.push(TemporalPairReference { pair, decision });
                }
            }
        }
        if !missing.is_empty() {
            TemporalComponentOutcome::IncompletePairSupport { pairs: missing }
        } else if members.len() < 4 {
            TemporalComponentOutcome::InsufficientObservations
        } else if members.first().map(|v| v.camera) == members.last().map(|v| v.camera) {
            TemporalComponentOutcome::InsufficientCameras
        } else {
            fuse_component(twin, views, nodes, group, options, evidence, handle, budget)?
        }
    };
    Ok(TemporalFeatureComponent {
        members,
        links,
        evidence,
        capture_hull: hull,
        nominal_time_range_ns: nominal,
        requested_scene_time_ns: options.reference_time_ns,
        outcome,
    })
}

#[allow(clippy::too_many_arguments)]
fn fuse_component(
    twin: &PropertyTwin,
    views: &[&FeatureView],
    nodes: &[Node],
    group: &[usize],
    options: TemporalAssociationOptions,
    evidence: [u8; 32],
    handle: u64,
    budget: &mut WorkBudget<'_>,
) -> Result<TemporalComponentOutcome, TemporalAssociationError> {
    let mut inputs = reserved(group.len())?;
    for &index in group {
        budget.charge(512)?;
        let node = nodes[index];
        let view = views[node.view];
        let feature = view.frame.features()[node.feature];
        inputs.push(FusionInput {
            camera: view.camera,
            privacy_domain: view.privacy_domain,
            sigma_pixels: view.sigma_pixels,
            observation: ContactObservation {
                evidence: linked_evidence(
                    b"fss.temporal_feature_observation.v1",
                    evidence,
                    [node.view as u64, feature.id],
                )?,
                // Query-local handles only; the original exposure digest stays in the source snapshot/hash.
                track: handle,
                camera: view.camera.camera,
                exposure: node.view as u64 + 1,
                image_domain: view.camera.image_domain,
                clock: view.camera.clock,
                capture: view.capture,
                pixel_min: feature.pixel,
                pixel_max: feature.pixel,
                visible_contact: true,
            },
        });
    }
    let request = MotionFusionRequest {
        association_evidence: evidence,
        privacy_domain: options.privacy_domain,
        reference_time_ns: options.reference_time_ns,
        max_capture_span_ns: options.max_capture_span_ns,
        max_capture_uncertainty_ns: options.max_capture_uncertainty_ns,
        triangulation: options.triangulation,
    };
    match fuse_scene_motion(twin, &inputs, request, budget) {
        Ok(motion) => Ok(TemporalComponentOutcome::Fused(Box::new(motion))),
        Err(MotionFusionError::Twin(TwinError::Limit)) => Err(TemporalAssociationError::Limit),
        Err(
            MotionFusionError::Twin(TwinError::Geometry(error))
            | MotionFusionError::Triangulation(TemporalTriangulationError::Geometry(error)),
        ) if matches!(
            error,
            GeometryError::Cancelled
                | GeometryError::BudgetExhausted
                | GeometryError::LimitExceeded
        ) =>
        {
            Err(error.into())
        }
        Err(error) => Ok(TemporalComponentOutcome::Refused(error)),
    }
}

fn copy_view(
    view: &FeatureView,
    budget: &mut WorkBudget<'_>,
) -> Result<FeatureView, TemporalAssociationError> {
    let mut features = reserved(view.frame.features().len())?;
    features.extend_from_slice(view.frame.features());
    let frame = FeatureFrame::new(
        view.frame.identity(),
        view.frame.descriptor_domain(),
        features,
        budget,
    )
    .map_err(|error| match error {
        LocalizationError::Geometry(error) => TemporalAssociationError::Geometry(error),
        LocalizationError::Limit => TemporalAssociationError::Limit,
        _ => TemporalAssociationError::InvalidInput,
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

fn floats(encoder: &mut CanonicalEncoder, values: impl IntoIterator<Item = f64>) {
    for value in values {
        encoder.u64(if value == 0.0 { 0 } else { value.to_bits() });
    }
}
fn finish(encoder: CanonicalEncoder) -> Result<[u8; 32], TemporalAssociationError> {
    Ok(ContentDigest::sha256(
        &encoder
            .finish_checked()
            .map_err(|_| TemporalAssociationError::Limit)?,
    )
    .bytes())
}
fn linked_evidence(
    domain: &[u8],
    parent: [u8; 32],
    ids: [u64; 2],
) -> Result<[u8; 32], TemporalAssociationError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.bytes(domain);
    encoder.bytes(&parent);
    for id in ids {
        encoder.u64(id);
    }
    finish(encoder)
}
fn scene_evidence(
    twin: &PropertyTwin,
    views: &[&FeatureView],
    options: TemporalAssociationOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<[u8; 32], TemporalAssociationError> {
    budget.charge(
        4096 + views.len() as u64 * 2048
            + views
                .iter()
                .map(|v| v.frame.features().len() as u64)
                .sum::<u64>()
                * 128,
    )?;
    let mut encoder = CanonicalEncoder::new();
    encoder.bytes(b"fss.temporal_feature_association.v1");
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
        options.max_capture_uncertainty_ns,
    ] {
        encoder.u64(value);
    }
    encoder.u32(u32::from(options.maximum_hamming_distance));
    encoder.u8(options.ratio_percent);
    let t = options.triangulation;
    encoder.u64(t.max_iterations as u64);
    floats(
        &mut encoder,
        [
            t.max_reprojection_pixels,
            t.max_distance,
            t.max_speed,
            t.max_condition_number,
        ],
    );
    encoder.u64(views.len() as u64);
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
        // Durable twin/rig identities bind the checked, retained process-local geometry handles.
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
    finish(encoder)
}
fn component_evidence(
    scene: [u8; 32],
    members: &[TemporalFeature],
    links: &[TemporalPairReference],
    hull: [u64; 2],
    nominal: [u64; 2],
    reference: u64,
    budget: &mut WorkBudget<'_>,
) -> Result<[u8; 32], TemporalAssociationError> {
    budget.charge(512 + members.len() as u64 * 32 + links.len() as u64 * 16)?;
    let mut encoder = CanonicalEncoder::new();
    encoder.bytes(b"fss.temporal_feature_component.v1");
    encoder.bytes(&scene);
    for value in hull.into_iter().chain(nominal).chain([reference]) {
        encoder.u64(value);
    }
    encoder.u64(members.len() as u64);
    for member in members {
        encoder.u64(member.view as u64);
        encoder.u64(member.camera);
        encoder.u64(member.feature);
    }
    encoder.u64(links.len() as u64);
    for link in links {
        encoder.u64(link.pair as u64);
        encoder.u64(link.decision as u64);
    }
    finish(encoder)
}

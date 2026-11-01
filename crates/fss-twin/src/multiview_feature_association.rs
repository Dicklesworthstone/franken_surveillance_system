#![forbid(unsafe_code)]
//! Complete bounded cross-camera feature graphs and joint static-point hypotheses.
//!
//! Every camera pair uses the unchanged symmetric descriptor/epipolar matcher.
//! Connected selected links are hypotheses, not transitive identity assertions:
//! a joint solve requires one feature per camera and a selected link for EVERY
//! pair of members. Conflicting cycles and open chains retain their entire graph
//! and all original pair outcomes; no edge or alternative is greedily discarded.
//!
//! Exact source snapshots are owner-resolved inputs, not authenticated custody.
//! Static-scene, clock and mapping assumptions remain explicit. The requested
//! scene time is retained; each subset's nominal solve time is its clamp into
//! that subset's FULL capture hull. This is valid only under the declared static
//! assumption over the complete scene hull. Native point uncertainty remains
//! conditional on fixed cameras and independent pixel noise, not correspondence,
//! calibration, map, clock or physical-identity accuracy.

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_geometry::triangulation::TriangulationError;
use fss_geometry::{GeometryError, WorkBudget};

use crate::feature_association::{
    AssociationError, AssociationOptions, DescriptorDecision, EpipolarDecision, FeatureAssociation,
    FeatureView, MAX_ASSOCIATION_FEATURES, associate_features,
};
use crate::localization::{FeatureFrame, LocalizationError};
use crate::multiview::{
    CommonPointMotion, FusedScenePoint, FusionError, FusionInput, FusionRequest, fuse_scene_point,
};
use crate::{ContactObservation, PropertyTwin, TwinError};

/// At least three and at most eight distinct nominal cameras participate.
pub const MAX_MULTIVIEW_CAMERAS: usize = 8;
/// Complete selected feature inventory across all views, including unmatched features.
pub const MAX_MULTIVIEW_FEATURES: usize = 256;
/// Maximum sum of Cartesian pair tables for eight views and 256 total features.
pub const MAX_MULTIVIEW_PAIR_ROWS: usize = 28_672;

/// One image-local feature in an exact logical camera; never a physical identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SceneFeature {
    /// Logical camera handle from the immutable view snapshot.
    pub camera: u64,
    /// Image-local feature ID from that view's complete selected inventory.
    pub feature: u64,
}

/// Exact location in the complete, canonically ordered camera-pair diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PairReference {
    /// Index into [`MultiFeatureAssociation::pairs`].
    pub pair: usize,
    /// Index into that pair's [`FeatureAssociation::pairs`] table.
    pub decision: usize,
}

/// Unmodified native two-view analysis, with its explicitly derived subset time.
#[derive(Clone, Debug)]
pub struct MultiViewPair {
    requested_scene_time_ns: u64,
    report: FeatureAssociation,
}
impl MultiViewPair {
    /// Camera IDs in increasing order, matching the underlying pair report.
    pub fn cameras(&self) -> [u64; 2] {
        self.report.views().each_ref().map(|v| v.camera.camera)
    }
    /// Original requested scene time, not silently replaced by the subset time.
    pub fn requested_scene_time_ns(&self) -> u64 {
        self.requested_scene_time_ns
    }
    /// Requested time clamped into this pair's complete capture hull.
    pub fn solve_time_ns(&self) -> u64 {
        self.report.options().reference_time_ns
    }
    /// Every pair decision, feature outcome and two-view reconstruction/refusal.
    pub fn report(&self) -> &FeatureAssociation {
        &self.report
    }
}

/// Joint disposition for a connected component of selected two-view links.
#[derive(Clone, Debug)]
pub enum ComponentOutcome {
    /// An isolated feature has no selected link; its pair diagnostics remain available.
    Unmatched,
    /// A cycle connects different features from the same camera. No one is chosen.
    CameraConflict {
        /// Every repeated logical camera, in increasing order.
        cameras: Vec<u64>,
    },
    /// A chain lacks complete direct pair support. Transitivity is not substituted.
    IncompleteCycleSupport {
        /// Every absent selected link, retaining its exact descriptor/epipolar decision.
        pairs: Vec<PairReference>,
    },
    /// One conditional point fitted to ALL component views, with no outlier removal.
    Fused(Box<FusedScenePoint>),
    /// Complete correspondence support still failed the native geometry solver.
    Refused(FusionError),
}

/// Complete connected hypothesis, including unresolved or geometrically refused ones.
#[derive(Clone, Debug)]
pub struct FeatureComponent {
    members: Vec<SceneFeature>,
    links: Vec<PairReference>,
    evidence: [u8; 32],
    capture_hull: [u64; 2],
    requested_scene_time_ns: u64,
    solve_time_ns: u64,
    outcome: ComponentOutcome,
}
impl FeatureComponent {
    /// Every connected feature, in increasing camera/feature order.
    pub fn members(&self) -> &[SceneFeature] {
        &self.members
    }
    /// All selected pair links in this component, including conflicting cycles.
    pub fn links(&self) -> &[PairReference] {
        &self.links
    }
    /// Versioned identity binding the full scene basis, members, links and subset time.
    pub fn evidence(&self) -> [u8; 32] {
        self.evidence
    }
    /// Complete earliest/latest capture hull of the member views.
    pub fn capture_hull(&self) -> [u64; 2] {
        self.capture_hull
    }
    /// Original scene time; it can lie outside this component's smaller capture hull.
    pub fn requested_scene_time_ns(&self) -> u64 {
        self.requested_scene_time_ns
    }
    /// Explicit derived subset reference, clamped into its complete capture hull.
    /// Only `Fused` and `Refused` outcomes actually invoke the joint solver.
    pub fn solve_time_ns(&self) -> u64 {
        self.solve_time_ns
    }
    /// Unmatched, conflicting, incomplete, reconstructed or native geometry refusal.
    pub fn outcome(&self) -> &ComponentOutcome {
        &self.outcome
    }
}

/// Immutable scene-wide correspondence graph, retaining every source and decision.
#[derive(Clone, Debug)]
pub struct MultiFeatureAssociation {
    views: Vec<FeatureView>,
    options: AssociationOptions,
    evidence: [u8; 32],
    capture_hull: [u64; 2],
    pairs: Vec<MultiViewPair>,
    components: Vec<FeatureComponent>,
}
impl MultiFeatureAssociation {
    /// Exact complete source snapshots in increasing logical-camera order.
    pub fn views(&self) -> &[FeatureView] {
        &self.views
    }
    /// Original requested scene policy, including its unchanged reference time.
    pub fn options(&self) -> AssociationOptions {
        self.options
    }
    /// Input/configuration identity, not custody, calibration or physical-identity authority.
    pub fn evidence(&self) -> [u8; 32] {
        self.evidence
    }
    /// Full capture hull over all views, including views with no features.
    pub fn capture_hull(&self) -> [u64; 2] {
        self.capture_hull
    }
    /// All camera pairs, in increasing first-camera then second-camera order.
    pub fn pairs(&self) -> &[MultiViewPair] {
        &self.pairs
    }
    /// All selected-link components, ordered by their first camera/feature member.
    /// Isolated features appear as explicit unmatched singleton components.
    pub fn components(&self) -> &[FeatureComponent] {
        &self.components
    }
}

#[derive(Clone, Copy)]
struct Node {
    view: usize,
    feature: usize,
}
#[derive(Clone, Copy)]
struct Link {
    nodes: [usize; 2],
    reference: PairReference,
}

fn reserved<T>(count: usize) -> Result<Vec<T>, AssociationError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| AssociationError::Limit)?;
    Ok(result)
}

/// Analyze three through eight camera views without forcing ambiguous correspondence.
///
/// The complete pair matcher validates EVERY source view, even when its feature set
/// is empty. All scene-wide count/capture bounds are checked before pair expansion.
/// The original two-view policy requires min_views=2 and max_outliers=0. Each closed
/// component instead requires all of its distinct cameras in the joint solve.
///
/// Work is bounded by the complete native pair analyses plus O(F^2 + F*L) graph
/// work and bounded native joint solves, where F<=256 and L<=896 selected links.
/// All work/cancellation failures discard the entire pending result. Geometry
/// refusals preserve pair/component diagnostics; no view is silently dropped.
pub fn associate_multiview_features(
    twin: &PropertyTwin,
    views: &[FeatureView],
    options: AssociationOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<MultiFeatureAssociation, AssociationError> {
    budget.charge(0)?;
    if views.len() < 3 {
        return Err(AssociationError::InvalidInput);
    }
    if views.len() > MAX_MULTIVIEW_CAMERAS {
        return Err(AssociationError::Limit);
    }
    budget.charge(256 * views.len() as u64)?;
    let mut ordered = reserved(views.len())?;
    ordered.extend(views);
    ordered.sort_by_key(|v| v.camera.camera);
    let mut total = 0_usize;
    let mut capture_hull = [u64::MAX, 0];
    for (i, view) in ordered.iter().enumerate() {
        let count = view.frame.features().len();
        if count > MAX_ASSOCIATION_FEATURES {
            return Err(AssociationError::Limit);
        }
        total = total.checked_add(count).ok_or(AssociationError::Limit)?;
        if total > MAX_MULTIVIEW_FEATURES {
            return Err(AssociationError::Limit);
        }
        if i > 0 && ordered[i - 1].camera.camera == view.camera.camera {
            return Err(AssociationError::DuplicateCamera);
        }
        if view.capture[0] > view.capture[1] {
            return Err(AssociationError::CaptureWindow);
        }
        capture_hull[0] = capture_hull[0].min(view.capture[0]);
        capture_hull[1] = capture_hull[1].max(view.capture[1]);
    }
    if options.max_capture_span_ns > 1_000_000_000
        || capture_hull[1] - capture_hull[0] > options.max_capture_span_ns
        || !(capture_hull[0]..=capture_hull[1]).contains(&options.reference_time_ns)
    {
        return Err(AssociationError::CaptureWindow);
    }
    let mut pair_rows = 0_usize;
    let mut link_bound = 0_usize;
    for (i, left) in ordered.iter().enumerate() {
        for right in &ordered[i + 1..] {
            let a = left.frame.features().len();
            let b = right.frame.features().len();
            pair_rows += a * b;
            link_bound += a.min(b);
        }
    }
    if pair_rows > MAX_MULTIVIEW_PAIR_ROWS {
        return Err(AssociationError::Limit);
    }
    budget.charge((total * 128 + pair_rows) as u64)?;
    let mut nodes = reserved(total)?;
    let mut offsets = reserved(ordered.len())?;
    for (i, view) in ordered.iter().enumerate() {
        offsets.push(nodes.len());
        nodes.extend((0..view.frame.features().len()).map(|feature| Node { view: i, feature }));
    }
    let mut parents = reserved(total)?;
    parents.extend(0..total);
    let mut links = reserved(link_bound)?;
    let mut pairs = reserved(views.len() * (views.len() - 1) / 2)?;
    for (i, left) in ordered.iter().enumerate() {
        for (j, right) in ordered.iter().enumerate().skip(i + 1) {
            let hull = [
                left.capture[0].min(right.capture[0]),
                left.capture[1].max(right.capture[1]),
            ];
            let pair_options = AssociationOptions {
                reference_time_ns: options.reference_time_ns.clamp(hull[0], hull[1]),
                ..options
            };
            let report = associate_features(twin, [left, right], pair_options, budget)?;
            for (decision, row) in report.pairs().iter().enumerate() {
                budget.charge(1)?;
                if row.descriptor == DescriptorDecision::Candidate
                    && row.epipolar == EpipolarDecision::Passed
                {
                    let width = right.frame.features().len();
                    let ends = [offsets[i] + decision / width, offsets[j] + decision % width];
                    let a = root(&parents, ends[0], budget)?;
                    let b = root(&parents, ends[1], budget)?;
                    parents[a.max(b)] = a.min(b);
                    links.push(Link {
                        nodes: ends,
                        reference: PairReference {
                            pair: pairs.len(),
                            decision,
                        },
                    });
                }
            }
            pairs.push(MultiViewPair {
                requested_scene_time_ns: options.reference_time_ns,
                report,
            });
        }
    }
    let evidence = scene_evidence(options, capture_hull, &pairs, budget)?;
    let mut roots = reserved(total)?;
    let mut groups = reserved(total)?;
    groups.resize_with(total, Vec::new);
    for i in 0..total {
        let r = root(&parents, i, budget)?;
        roots.push(r);
        groups[r]
            .try_reserve(1)
            .map_err(|_| AssociationError::Limit)?;
        groups[r].push(i);
    }
    let mut components = reserved(total)?;
    for (r, group) in groups.iter().enumerate().filter(|(_, g)| !g.is_empty()) {
        let mut selected = reserved(links.len().min(group.len() * (group.len() - 1) / 2))?;
        for link in &links {
            budget.charge(1)?;
            if roots[link.nodes[0]] == r {
                selected.push(link.reference);
            }
        }
        components.push(component(
            twin,
            &ordered,
            &nodes,
            group,
            selected,
            &pairs,
            options,
            evidence,
            components.len() as u64 + 1,
            budget,
        )?);
    }
    let mut snapshots = reserved(ordered.len())?;
    for view in ordered {
        snapshots.push(copy_view(view, budget)?);
    }
    budget.charge(0)?;
    Ok(MultiFeatureAssociation {
        views: snapshots,
        options,
        evidence,
        capture_hull,
        pairs,
        components,
    })
}

fn root(
    parents: &[usize],
    mut node: usize,
    budget: &mut WorkBudget<'_>,
) -> Result<usize, AssociationError> {
    loop {
        budget.charge(1)?;
        if parents[node] == node {
            return Ok(node);
        }
        node = parents[node];
    }
}

#[allow(clippy::too_many_arguments)]
fn component(
    twin: &PropertyTwin,
    views: &[&FeatureView],
    nodes: &[Node],
    group: &[usize],
    links: Vec<PairReference>,
    pairs: &[MultiViewPair],
    options: AssociationOptions,
    scene: [u8; 32],
    handle: u64,
    budget: &mut WorkBudget<'_>,
) -> Result<FeatureComponent, AssociationError> {
    budget.charge(256 * group.len() as u64)?;
    let mut members = reserved(group.len())?;
    let mut repeated = reserved(group.len())?;
    let mut hull = [u64::MAX, 0];
    for &index in group {
        let node = nodes[index];
        let view = views[node.view];
        let camera = view.camera.camera;
        if members
            .last()
            .is_some_and(|m: &SceneFeature| m.camera == camera)
            && repeated.last() != Some(&camera)
        {
            repeated.push(camera);
        }
        members.push(SceneFeature {
            camera,
            feature: view.frame.features()[node.feature].id,
        });
        hull[0] = hull[0].min(view.capture[0]);
        hull[1] = hull[1].max(view.capture[1]);
    }
    let solve_time_ns = options.reference_time_ns.clamp(hull[0], hull[1]);
    let evidence = component_evidence(scene, &members, &links, hull, solve_time_ns, budget)?;
    let outcome = if members.len() == 1 {
        ComponentOutcome::Unmatched
    } else if !repeated.is_empty() {
        ComponentOutcome::CameraConflict { cameras: repeated }
    } else {
        let mut missing = reserved(group.len() * (group.len() - 1) / 2)?;
        for (i, &left) in group.iter().enumerate() {
            for &right in &group[i + 1..] {
                budget.charge(8)?;
                let a = nodes[left];
                let b = nodes[right];
                // Nodes and camera-pair reports have the same canonical ordering.
                let pair = a.view * (2 * views.len() - a.view - 1) / 2 + b.view - a.view - 1;
                let decision = a.feature * views[b.view].frame.features().len() + b.feature;
                let row = &pairs[pair].report.pairs()[decision];
                if row.descriptor != DescriptorDecision::Candidate
                    || row.epipolar != EpipolarDecision::Passed
                {
                    missing.push(PairReference { pair, decision });
                }
            }
        }
        if missing.is_empty() {
            fuse_component(
                twin,
                views,
                nodes,
                group,
                options,
                evidence,
                solve_time_ns,
                handle,
                budget,
            )?
        } else {
            ComponentOutcome::IncompleteCycleSupport { pairs: missing }
        }
    };
    Ok(FeatureComponent {
        members,
        links,
        evidence,
        capture_hull: hull,
        requested_scene_time_ns: options.reference_time_ns,
        solve_time_ns,
        outcome,
    })
}

#[allow(clippy::too_many_arguments)]
fn fuse_component(
    twin: &PropertyTwin,
    views: &[&FeatureView],
    nodes: &[Node],
    group: &[usize],
    options: AssociationOptions,
    evidence: [u8; 32],
    reference_time_ns: u64,
    handle: u64,
    budget: &mut WorkBudget<'_>,
) -> Result<ComponentOutcome, AssociationError> {
    let mut inputs = reserved(group.len())?;
    for &index in group {
        budget.charge(512)?;
        let node = nodes[index];
        let view = views[node.view];
        let feature = view.frame.features()[node.feature];
        let mut encoder = CanonicalEncoder::new();
        encoder.bytes(b"fss.multiview_feature_observation.v1");
        encoder.bytes(&evidence);
        encoder.u64(view.camera.camera);
        encoder.u64(feature.id);
        inputs.push(FusionInput {
            camera: view.camera,
            privacy_domain: view.privacy_domain,
            sigma_pixels: view.sigma_pixels,
            observation: ContactObservation {
                evidence: finish(encoder)?,
                // Query-local component and exposure handles, never durable track identity.
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
    let mut triangulation = options.triangulation;
    triangulation.min_views = group.len();
    // Pair policy already requires zero outliers; repeat the invariant at the joint boundary.
    triangulation.max_outliers = 0;
    let request = FusionRequest {
        association_evidence: evidence,
        privacy_domain: options.privacy_domain,
        reference_time_ns,
        max_capture_span_ns: options.max_capture_span_ns,
        motion: CommonPointMotion::Static,
        triangulation,
    };
    match fuse_scene_point(twin, &inputs, request, budget) {
        Ok(point) => Ok(ComponentOutcome::Fused(Box::new(point))),
        Err(FusionError::Twin(TwinError::Limit)) => Err(AssociationError::Limit),
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
            Err(error.into())
        }
        Err(error) => Ok(ComponentOutcome::Refused(error)),
    }
}

fn copy_view(
    view: &FeatureView,
    budget: &mut WorkBudget<'_>,
) -> Result<FeatureView, AssociationError> {
    budget.charge(view.frame.features().len() as u64 * 64)?;
    let mut features = reserved(view.frame.features().len())?;
    features.extend_from_slice(view.frame.features());
    let frame = FeatureFrame::new(
        view.frame.identity(),
        view.frame.descriptor_domain(),
        features,
        budget,
    )
    .map_err(|error| match error {
        LocalizationError::Geometry(error) => AssociationError::Geometry(error),
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

fn scene_evidence(
    options: AssociationOptions,
    hull: [u64; 2],
    pairs: &[MultiViewPair],
    budget: &mut WorkBudget<'_>,
) -> Result<[u8; 32], AssociationError> {
    budget.charge(256 + pairs.len() as u64 * 128)?;
    let mut encoder = CanonicalEncoder::new();
    encoder.bytes(b"fss.multiview_feature_association.v1");
    encoder.u64(options.reference_time_ns);
    encoder.u64(hull[0]);
    encoder.u64(hull[1]);
    encoder.u64(pairs.len() as u64);
    // Every view appears in a pair even when empty. These exact input digests bind
    // all source/camera/mask/domain data, twin/rig pins and every policy field.
    // The original global reference is included above because subset times differ.
    for pair in pairs {
        encoder.bytes(&pair.report.evidence());
        encoder.u64(pair.solve_time_ns());
    }
    finish(encoder)
}

fn component_evidence(
    scene: [u8; 32],
    members: &[SceneFeature],
    links: &[PairReference],
    hull: [u64; 2],
    solve_time_ns: u64,
    budget: &mut WorkBudget<'_>,
) -> Result<[u8; 32], AssociationError> {
    budget.charge(256 + members.len() as u64 * 32 + links.len() as u64 * 32)?;
    let mut encoder = CanonicalEncoder::new();
    encoder.bytes(b"fss.multiview_feature_component.v1");
    encoder.bytes(&scene);
    for n in [hull[0], hull[1], solve_time_ns, members.len() as u64] {
        encoder.u64(n);
    }
    for member in members {
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

fn finish(encoder: CanonicalEncoder) -> Result<[u8; 32], AssociationError> {
    Ok(ContentDigest::sha256(
        &encoder
            .finish_checked()
            .map_err(|_| AssociationError::Limit)?,
    )
    .bytes())
}

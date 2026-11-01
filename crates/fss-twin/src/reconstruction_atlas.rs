#![forbid(unsafe_code)]
//! Explicitly admitted reconstructed features become reusable, unactivated map landmarks.
//!
//! This producer accepts only immutable native association results. It copies their actual
//! solved positions and reference descriptors; callers cannot supply replacement coordinates.
//! A capture-window stationarity assumption is insufficient: every selected point separately
//! declares enduring static support, its twin feature and its distinct physical-point group.
//! Those declarations remain assumptions, not authentication or calibration certificates.

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_geometry::triangulation::TriangulationResidual;
use fss_geometry::{GeometryError, WorkBudget};

use crate::PropertyTwin;
use crate::atlas_archive::ReferenceProvenance;
use crate::feature_association::{FeatureAssociation, FeatureHypothesisOutcome, FeatureView};
use crate::localization::{
    AtlasBinding, AtlasLandmark, AtlasReference, ImageIdentity, LocalizationAtlas,
    LocalizationError,
};
use crate::multiview::{CommonPointMotion, FusedScenePoint};
use crate::multiview_feature_association::{
    ComponentOutcome, MAX_MULTIVIEW_CAMERAS, MAX_MULTIVIEW_FEATURES, MultiFeatureAssociation,
    SceneFeature,
};

/// Pair matching admits at most 128 hypotheses; multiview inventories are bounded more tightly.
pub const MAX_RECONSTRUCTED_LANDMARKS: usize = 128;
/// Canonical support/geometry identity of one explicitly admitted landmark.
pub const LANDMARK_DOMAIN: &str = "fss.reconstruction_atlas_landmark.v1";
/// Canonical identity of the complete producer inventory and its resulting atlas.
pub const RECEIPT_DOMAIN: &str = "fss.reconstruction_atlas_receipt.v1";
const MAX_RECEIPT_BYTES: usize = 2 * 1024 * 1024;

/// Native immutable source of candidate points; neither variant grants custody or authority.
#[derive(Clone, Copy, Debug)]
pub enum Reconstruction<'a> {
    /// Automatically matched two-camera features and all selected geometric outcomes.
    Pair(&'a FeatureAssociation),
    /// Complete multi-camera graph, including unmatched and unresolved components.
    Multiview(&'a MultiFeatureAssociation),
}

/// Exact kind of native association retained by the producer receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconstructionKind {
    /// Two-camera native matching.
    Pair,
    /// Three-through-eight-camera native complete-cycle matching.
    Multiview,
}

/// Explicit static-map interpretation of an existing, exactly pinned candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LandmarkSelection {
    /// Exact pair-hypothesis or multiview-component evidence digest.
    pub hypothesis: [u8; 32],
    /// Nonzero map-local ID chosen by the owner, never derived as physical identity.
    pub landmark: u64,
    /// Nonzero explicitly distinct physical-point group; aliases must be consolidated.
    pub physical_group: u64,
    /// Existing zero-based feature ordinal of the exact immutable property twin.
    pub feature: u32,
    /// Evidence or explicit assumption supporting enduring static use beyond the capture hull.
    pub enduring_static_basis: [u8; 32],
}

/// Owner-provided identity of a complete reference recipe, not proof of its custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceSource {
    /// Original logical camera; archive reference IDs preserve this handle.
    pub camera: u64,
    /// Exact source record binding source/PTS, rig pose, image conversion and selection.
    pub source_record: [u8; 32],
}

/// Bounded explicit admission, with one source record for EVERY original input view.
#[derive(Clone, Copy, Debug)]
pub struct AtlasBuildRequest<'a> {
    /// Exact entire association identity, including unselected inputs and alternatives.
    pub association_evidence: [u8; 32],
    /// One through 128 explicit point selections; input order has no semantic effect.
    pub selections: &'a [LandmarkSelection],
    /// Complete input-view source records; input order has no semantic effect.
    pub references: &'a [ReferenceSource],
}

/// Eligibility is reported for every native candidate, including those not selected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtlasCandidateDisposition {
    /// Complete native point with no nominal occlusion conflict; still requires a declaration.
    Eligible,
    /// Native triangulation refused this candidate.
    Refused,
    /// No selected counterpart exists for this original image feature.
    Unmatched,
    /// A connected component repeats a logical camera.
    CameraConflict,
    /// A connected component lacks complete direct correspondence support.
    IncompleteCycleSupport,
    /// A fitted point conflicts with the imported nominal opaque geometry.
    NominalOcclusionConflict,
}

/// Complete candidate admission disposition in canonical association order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtlasCandidateDecision {
    /// Original native candidate evidence, not a synthetic landmark identity.
    pub hypothesis: [u8; 32],
    /// All source-camera/image-feature members, without pruning.
    pub members: Vec<SceneFeature>,
    /// Full member capture hull, including original uncertainty.
    pub capture_hull: [u64; 2],
    /// Native subset solve time; no producer timestamp replacement occurs.
    pub solve_time_ns: u64,
    /// Native eligibility, independent of the owner's selection.
    pub disposition: AtlasCandidateDisposition,
    /// Explicitly admitted landmark handle, or an unselected candidate.
    pub selected_landmark: Option<u64>,
}

/// Source lineage for all original inputs, even views with no admitted landmark bindings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtlasSourceRecord {
    /// Original logical camera and archive reference handle.
    pub camera: u64,
    /// Owner-pinned complete recipe record.
    pub source_record: [u8; 32],
    /// Original encoded source digest from the native association.
    pub source_digest: [u8; 32],
    /// Exact original exposure and actual feature-grid pixels/domain/dimensions.
    pub frame: ImageIdentity,
    /// Exact native descriptor construction/generation.
    pub descriptor_domain: [u8; 32],
    /// Actual full allowed-pixel mask for this reference grid.
    pub allowed_mask: [u8; 32],
    /// Complete selected feature count, including unbound features in copied frames.
    pub feature_count: usize,
    /// Whether this complete frame participates in at least one admitted binding.
    pub included: bool,
}

/// Exact solved geometry and all source bindings supporting one admitted landmark.
#[derive(Clone, Debug, PartialEq)]
pub struct AtlasLandmarkAdmission {
    /// Explicit support, physical-group and feature declarations.
    pub selection: LandmarkSelection,
    /// Canonical identity of this declaration, its actual point and source records.
    pub evidence: [u8; 32],
    /// Every camera/image-feature association used by the selected native point.
    pub members: Vec<SceneFeature>,
    /// Unmodified solved world position in property source units.
    pub position: [f64; 3],
    /// Conditional pixel-noise covariance only; never promoted to absolute map error.
    pub pixel_noise_covariance: [[f64; 3]; 3],
    /// Native information-matrix condition diagnostic.
    pub condition_number: f64,
    /// Native root-mean-square reprojection residual.
    pub rms_reprojection_pixels: f64,
    /// Native maximum parallax angle.
    pub max_ray_angle_radians: f64,
    /// Every original geometric view residual; all members must be inliers.
    pub residuals: Vec<TriangulationResidual>,
    /// Original full member capture hull.
    pub capture_hull: [u64; 2],
    /// Original native point reference time.
    pub solve_time_ns: u64,
}

/// Complete producer record; its digest commits every field except the digest itself.
#[derive(Clone, Debug)]
pub struct AtlasBuildReceipt {
    /// Pair or multiview source contract.
    pub kind: ReconstructionKind,
    /// Exact immutable property package, not only its numeric revision handle.
    pub twin_digest: [u8; 32],
    /// Entire native association, including every nonselected alternative.
    pub association_evidence: [u8; 32],
    /// Original scene time, distinct from smaller subset solve times.
    pub requested_scene_time_ns: u64,
    /// Original global full capture hull, including empty feature views.
    pub capture_hull: [u64; 2],
    /// Complete source inventory in camera order.
    pub sources: Vec<AtlasSourceRecord>,
    /// Complete candidate inventory in native association order.
    pub candidates: Vec<AtlasCandidateDecision>,
    /// Actual admitted landmarks in landmark-ID order.
    pub landmarks: Vec<AtlasLandmarkAdmission>,
    /// Semantic atlas identity; archive/provenance encoding is a subsequent operation.
    pub atlas_digest: [u8; 32],
    digest: [u8; 32],
}
impl AtlasBuildReceipt {
    /// Canonical complete producer record identity, without effect authority.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Fully validated producer result; no I/O, durable publication or activation has occurred.
#[derive(Debug)]
pub struct ReconstructedAtlas {
    atlas: LocalizationAtlas,
    references: Vec<ReferenceProvenance>,
    receipt: AtlasBuildReceipt,
}
impl ReconstructedAtlas {
    /// Native atlas ready for the unchanged matching/localization or archive APIs.
    pub fn atlas(&self) -> &LocalizationAtlas {
        &self.atlas
    }
    /// Complete included source records in archive reference-ID order.
    pub fn references(&self) -> &[ReferenceProvenance] {
        &self.references
    }
    /// Whole input/admission/output lineage, including unused views and candidates.
    pub fn receipt(&self) -> &AtlasBuildReceipt {
        &self.receipt
    }
}

/// Whole-operation refusal; no successful partial atlas is returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconstructionAtlasError {
    /// Missing/invalid declarations, source records or twin feature ordinals.
    InvalidRequest,
    /// Exact scene evidence or property basis differs.
    BasisMismatch,
    /// A selected evidence pin is absent from this entire native association.
    SelectionMismatch,
    /// A selected native candidate is unmatched, conflicting, incomplete or refused.
    IneligibleSelection,
    /// A selected solved point has a nominal opaque-geometry contradiction.
    OcclusionConflict,
    /// Repeated landmark, physical group, candidate, reference or member association.
    Alias,
    /// A fixed count/allocation/serialization limit was exceeded.
    Limit,
    /// Native atlas or bounded geometry failure, including cancellation and exhausted work.
    Localization(LocalizationError),
}
impl From<LocalizationError> for ReconstructionAtlasError {
    fn from(error: LocalizationError) -> Self {
        Self::Localization(error)
    }
}
impl From<GeometryError> for ReconstructionAtlasError {
    fn from(error: GeometryError) -> Self {
        Self::Localization(error.into())
    }
}
impl std::fmt::Display for ReconstructionAtlasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidRequest => "invalid reconstructed-atlas declaration",
            Self::BasisMismatch => "reconstructed-atlas scene or property basis differs",
            Self::SelectionMismatch => "selected reconstruction is unavailable",
            Self::IneligibleSelection => "selected reconstruction cannot support an atlas point",
            Self::OcclusionConflict => "selected reconstruction conflicts with nominal geometry",
            Self::Alias => "reconstructed-atlas declarations contain an alias",
            Self::Limit => "reconstructed-atlas resource limit exceeded",
            Self::Localization(_) => "reconstructed-atlas validation or bounded work failed",
        })
    }
}
impl std::error::Error for ReconstructionAtlasError {}
type Result<T> = std::result::Result<T, ReconstructionAtlasError>;

impl<'a> Reconstruction<'a> {
    fn views(self) -> &'a [FeatureView] {
        match self {
            Self::Pair(value) => value.views(),
            Self::Multiview(value) => value.views(),
        }
    }
    fn evidence(self) -> [u8; 32] {
        match self {
            Self::Pair(value) => value.evidence(),
            Self::Multiview(value) => value.evidence(),
        }
    }
}
struct Candidate<'a> {
    decision: AtlasCandidateDecision,
    point: Option<&'a FusedScenePoint>,
}
fn reserved<T>(count: usize) -> Result<Vec<T>> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| ReconstructionAtlasError::Limit)?;
    Ok(result)
}
fn eligible(point: &FusedScenePoint) -> AtlasCandidateDisposition {
    if point.has_nominal_occlusion_conflict() {
        AtlasCandidateDisposition::NominalOcclusionConflict
    } else {
        AtlasCandidateDisposition::Eligible
    }
}
fn candidates<'a>(
    reconstruction: Reconstruction<'a>,
    work: &mut WorkBudget<'_>,
) -> Result<Vec<Candidate<'a>>> {
    let count = match reconstruction {
        Reconstruction::Pair(value) => value.hypotheses().len(),
        Reconstruction::Multiview(value) => value.components().len(),
    };
    if count > MAX_MULTIVIEW_FEATURES {
        return Err(ReconstructionAtlasError::Limit);
    }
    work.charge(count as u64 * 256)?;
    let mut result = reserved(count)?;
    match reconstruction {
        Reconstruction::Pair(value) => {
            for hypothesis in value.hypotheses() {
                work.charge(1)?;
                let (point, disposition) = match &hypothesis.outcome {
                    FeatureHypothesisOutcome::Fused(point) => {
                        (Some(point.as_ref()), eligible(point))
                    }
                    FeatureHypothesisOutcome::Refused(_) => {
                        (None, AtlasCandidateDisposition::Refused)
                    }
                };
                let members = value
                    .views()
                    .iter()
                    .zip(hypothesis.features)
                    .map(|(view, feature)| SceneFeature {
                        camera: view.camera.camera,
                        feature,
                    })
                    .collect();
                result.push(Candidate {
                    decision: AtlasCandidateDecision {
                        hypothesis: hypothesis.evidence,
                        members,
                        capture_hull: value.capture_hull(),
                        solve_time_ns: value.options().reference_time_ns,
                        disposition,
                        selected_landmark: None,
                    },
                    point,
                });
            }
        }
        Reconstruction::Multiview(value) => {
            for component in value.components() {
                work.charge(1)?;
                let (point, disposition) = match component.outcome() {
                    ComponentOutcome::Fused(point) => (Some(point.as_ref()), eligible(point)),
                    ComponentOutcome::Refused(_) => (None, AtlasCandidateDisposition::Refused),
                    ComponentOutcome::Unmatched => (None, AtlasCandidateDisposition::Unmatched),
                    ComponentOutcome::CameraConflict { .. } => {
                        (None, AtlasCandidateDisposition::CameraConflict)
                    }
                    ComponentOutcome::IncompleteCycleSupport { .. } => {
                        (None, AtlasCandidateDisposition::IncompleteCycleSupport)
                    }
                };
                result.push(Candidate {
                    decision: AtlasCandidateDecision {
                        hypothesis: component.evidence(),
                        members: component.members().to_vec(),
                        capture_hull: component.capture_hull(),
                        solve_time_ns: component.solve_time_ns(),
                        disposition,
                        selected_landmark: None,
                    },
                    point,
                });
            }
        }
    }
    Ok(result)
}

/// Admit exact native reconstructed points as explicitly declared static map support.
///
/// Every input source record is required, every selected member binding is preserved, and
/// all nonselected candidates remain in the receipt. Complete participating feature frames
/// are copied unchanged. Absolute map error stays unknown regardless of conditional covariance.
/// The caller must retain the referenced source records and revalidate custody/privacy before
/// publishing the resulting archive or producer receipt. This pure function does neither.
pub fn build_reconstruction_atlas(
    twin: &PropertyTwin,
    request: &AtlasBuildRequest<'_>,
    reconstruction: Reconstruction<'_>,
    work: &mut WorkBudget<'_>,
) -> Result<ReconstructedAtlas> {
    work.charge(0)?;
    let views = reconstruction.views();
    if request.selections.is_empty() || request.references.len() != views.len() {
        return Err(ReconstructionAtlasError::InvalidRequest);
    }
    if request.selections.len() > MAX_RECONSTRUCTED_LANDMARKS
        || !(2..=MAX_MULTIVIEW_CAMERAS).contains(&views.len())
        || views
            .iter()
            .map(|v| v.frame.features().len())
            .sum::<usize>()
            > MAX_MULTIVIEW_FEATURES
    {
        return Err(ReconstructionAtlasError::Limit);
    }
    if request.association_evidence == [0; 32]
        || request.association_evidence != reconstruction.evidence()
        || views
            .iter()
            .any(|view| view.camera.geometry != twin.basis())
    {
        return Err(ReconstructionAtlasError::BasisMismatch);
    }
    work.charge((views.len() + request.selections.len()) as u64 * 128)?;
    let mut reference_sources = reserved(request.references.len())?;
    reference_sources.extend_from_slice(request.references);
    reference_sources.sort_by_key(|r| r.camera);
    for (index, (source, view)) in reference_sources.iter().zip(views).enumerate() {
        work.charge(1)?;
        if source.camera == 0
            || source.camera != view.camera.camera
            || source.source_record == [0; 32]
        {
            return Err(ReconstructionAtlasError::InvalidRequest);
        }
        for previous in &reference_sources[..index] {
            work.charge(1)?;
            if source.camera == previous.camera || source.source_record == previous.source_record {
                return Err(ReconstructionAtlasError::Alias);
            }
        }
    }
    let mut selections = reserved(request.selections.len())?;
    selections.extend_from_slice(request.selections);
    selections.sort_by_key(|selection| selection.landmark);
    for (index, selection) in selections.iter().enumerate() {
        work.charge(1)?;
        if selection.landmark == 0
            || selection.physical_group == 0
            || selection.hypothesis == [0; 32]
            || selection.enduring_static_basis == [0; 32]
            || twin.features().get(selection.feature as usize).is_none()
        {
            return Err(ReconstructionAtlasError::InvalidRequest);
        }
        for previous in &selections[..index] {
            work.charge(1)?;
            if selection.landmark == previous.landmark
                || selection.physical_group == previous.physical_group
                || selection.hypothesis == previous.hypothesis
            {
                return Err(ReconstructionAtlasError::Alias);
            }
        }
    }
    let mut candidates = candidates(reconstruction, work)?;
    let mut landmarks = reserved(selections.len())?;
    let mut admissions = reserved(selections.len())?;
    let mut bindings = reserved(MAX_MULTIVIEW_FEATURES)?;
    let mut used_views = vec![false; views.len()];
    for selection in selections {
        work.charge(candidates.len() as u64)?;
        let candidate = candidates
            .iter_mut()
            .find(|candidate| candidate.decision.hypothesis == selection.hypothesis)
            .ok_or(ReconstructionAtlasError::SelectionMismatch)?;
        match candidate.decision.disposition {
            AtlasCandidateDisposition::Eligible => (),
            AtlasCandidateDisposition::NominalOcclusionConflict => {
                return Err(ReconstructionAtlasError::OcclusionConflict);
            }
            _ => return Err(ReconstructionAtlasError::IneligibleSelection),
        }
        let point = candidate
            .point
            .ok_or(ReconstructionAtlasError::IneligibleSelection)?;
        if point.twin_digest() != twin.digest() || point.geometry() != twin.basis() {
            return Err(ReconstructionAtlasError::BasisMismatch);
        }
        let members = &candidate.decision.members;
        if point.request().motion != CommonPointMotion::Static
            || point.inputs().len() != members.len()
            || point.estimate().residuals.len() != members.len()
            || point
                .estimate()
                .residuals
                .iter()
                .zip(members)
                .any(|(r, member)| !r.inlier || r.camera != member.camera)
        {
            return Err(ReconstructionAtlasError::IneligibleSelection);
        }
        work.charge(members.len() as u64 * 256 + 512)?;
        for member in members {
            let view_index = views
                .binary_search_by_key(&member.camera, |v| v.camera.camera)
                .map_err(|_| ReconstructionAtlasError::BasisMismatch)?;
            let view = &views[view_index];
            if view
                .frame
                .features()
                .binary_search_by_key(&member.feature, |feature| feature.id)
                .is_err()
            {
                return Err(ReconstructionAtlasError::SelectionMismatch);
            }
            if bindings.iter().any(|binding: &AtlasBinding| {
                binding.reference == member.camera && binding.image_feature == member.feature
            }) {
                return Err(ReconstructionAtlasError::Alias);
            }
            used_views[view_index] = true;
            bindings.push(AtlasBinding {
                landmark: selection.landmark,
                reference: member.camera,
                image_feature: member.feature,
            });
        }
        let estimate = point.estimate();
        let mut admission = AtlasLandmarkAdmission {
            selection,
            evidence: [0; 32],
            members: members.clone(),
            position: estimate.position,
            pixel_noise_covariance: estimate.pixel_noise_covariance,
            condition_number: estimate.condition_number,
            rms_reprojection_pixels: estimate.rms_reprojection_pixels,
            max_ray_angle_radians: estimate.max_ray_angle_radians,
            residuals: estimate.residuals.clone(),
            capture_hull: point.capture_hull(),
            solve_time_ns: point.request().reference_time_ns,
        };
        admission.evidence = landmark_digest(
            twin.digest(),
            request.association_evidence,
            &admission,
            &reference_sources,
            work,
        )?;
        landmarks.push(AtlasLandmark {
            id: selection.landmark,
            physical_group: selection.physical_group,
            feature: selection.feature,
            world: estimate.position,
            evidence: admission.evidence,
            error: None,
        });
        admissions.push(admission);
        candidate.decision.selected_landmark = Some(selection.landmark);
    }
    let mut references = reserved(views.len())?;
    let mut provenance = reserved(views.len())?;
    let mut sources = reserved(views.len())?;
    for ((view, source), included) in views.iter().zip(reference_sources).zip(used_views) {
        work.charge(view.frame.features().len() as u64 * 64 + 256)?;
        sources.push(AtlasSourceRecord {
            camera: view.camera.camera,
            source_record: source.source_record,
            source_digest: view.source_digest,
            frame: view.frame.identity(),
            descriptor_domain: view.frame.descriptor_domain(),
            allowed_mask: view.allowed_mask_digest,
            feature_count: view.frame.features().len(),
            included,
        });
        if included {
            references.push(AtlasReference {
                id: view.camera.camera,
                frame: view.frame.clone(),
            });
            provenance.push(ReferenceProvenance {
                reference: view.camera.camera,
                source_record: source.source_record,
                allowed_mask: view.allowed_mask_digest,
            });
        }
    }
    let atlas = LocalizationAtlas::new(twin, landmarks, references, bindings, work)?;
    let (kind, time, capture_hull) = match reconstruction {
        Reconstruction::Pair(value) => (
            ReconstructionKind::Pair,
            value.options().reference_time_ns,
            value.capture_hull(),
        ),
        Reconstruction::Multiview(value) => (
            ReconstructionKind::Multiview,
            value.options().reference_time_ns,
            value.capture_hull(),
        ),
    };
    let mut receipt = AtlasBuildReceipt {
        kind,
        twin_digest: twin.digest(),
        association_evidence: request.association_evidence,
        requested_scene_time_ns: time,
        capture_hull,
        sources,
        candidates: candidates
            .into_iter()
            .map(|candidate| candidate.decision)
            .collect(),
        landmarks: admissions,
        atlas_digest: atlas.digest(),
        digest: [0; 32],
    };
    receipt.digest = receipt_digest(&receipt, work)?;
    work.charge(0)?;
    Ok(ReconstructedAtlas {
        atlas,
        references: provenance,
        receipt,
    })
}

fn floats(e: &mut CanonicalEncoder, values: impl IntoIterator<Item = f64>) {
    for value in values {
        e.u64(if value == 0.0 { 0 } else { value.to_bits() });
    }
}
fn members(e: &mut CanonicalEncoder, values: &[SceneFeature]) {
    e.u64(values.len() as u64);
    for member in values {
        e.u64(member.camera);
        e.u64(member.feature);
    }
}
fn admission(e: &mut CanonicalEncoder, value: &AtlasLandmarkAdmission) {
    let selection = value.selection;
    e.bytes(&selection.hypothesis);
    e.u64(selection.landmark);
    e.u64(selection.physical_group);
    e.u32(selection.feature);
    e.bytes(&selection.enduring_static_basis);
    members(e, &value.members);
    floats(e, value.position);
    floats(e, value.pixel_noise_covariance.into_iter().flatten());
    floats(
        e,
        [
            value.condition_number,
            value.rms_reprojection_pixels,
            value.max_ray_angle_radians,
        ],
    );
    e.u64(value.residuals.len() as u64);
    for residual in &value.residuals {
        e.u64(residual.camera);
        e.bool(residual.inlier);
        e.bool(residual.pixels.is_some());
        if let Some(pixels) = residual.pixels {
            floats(e, [pixels]);
        }
    }
    for time in value.capture_hull {
        e.u64(time);
    }
    e.u64(value.solve_time_ns);
}
fn finish(e: CanonicalEncoder, work: &mut WorkBudget<'_>) -> Result<[u8; 32]> {
    let bytes = e.finish();
    if bytes.len() > MAX_RECEIPT_BYTES {
        return Err(ReconstructionAtlasError::Limit);
    }
    work.charge(bytes.len() as u64)?;
    Ok(ContentDigest::sha256(&bytes).bytes())
}
fn landmark_digest(
    twin: [u8; 32],
    association: [u8; 32],
    value: &AtlasLandmarkAdmission,
    sources: &[ReferenceSource],
    work: &mut WorkBudget<'_>,
) -> Result<[u8; 32]> {
    work.charge(4096 + value.members.len() as u64 * 256)?;
    let mut e = CanonicalEncoder::new();
    e.text(LANDMARK_DOMAIN);
    e.text("derived_static_landmark_with_unknown_absolute_error_no_effect_authority");
    e.bytes(&twin);
    e.bytes(&association);
    admission(&mut e, value);
    for member in &value.members {
        let source = sources
            .binary_search_by_key(&member.camera, |source| source.camera)
            .map_err(|_| ReconstructionAtlasError::InvalidRequest)?;
        e.bytes(&sources[source].source_record);
    }
    finish(e, work)
}
fn receipt_digest(receipt: &AtlasBuildReceipt, work: &mut WorkBudget<'_>) -> Result<[u8; 32]> {
    work.charge(
        4096 + receipt.sources.len() as u64 * 1024
            + receipt.candidates.len() as u64 * 2048
            + receipt.landmarks.len() as u64 * 4096,
    )?;
    let mut e = CanonicalEncoder::new();
    e.text(RECEIPT_DOMAIN);
    e.text("derived_atlas_unknown_absolute_error_no_calibration_activation");
    e.u8(match receipt.kind {
        ReconstructionKind::Pair => 0,
        ReconstructionKind::Multiview => 1,
    });
    e.bytes(&receipt.twin_digest);
    e.bytes(&receipt.association_evidence);
    e.u64(receipt.requested_scene_time_ns);
    for time in receipt.capture_hull {
        e.u64(time);
    }
    e.u64(receipt.sources.len() as u64);
    for source in &receipt.sources {
        e.u64(source.camera);
        for digest in [
            source.source_record,
            source.source_digest,
            source.frame.exposure,
            source.frame.pixels,
            source.frame.image_domain,
            source.descriptor_domain,
            source.allowed_mask,
        ] {
            e.bytes(&digest);
        }
        for dimension in source.frame.dimensions {
            e.u32(dimension);
        }
        e.u64(source.feature_count as u64);
        e.bool(source.included);
    }
    e.u64(receipt.candidates.len() as u64);
    for candidate in &receipt.candidates {
        e.bytes(&candidate.hypothesis);
        members(&mut e, &candidate.members);
        for time in candidate.capture_hull {
            e.u64(time);
        }
        e.u64(candidate.solve_time_ns);
        e.u8(match candidate.disposition {
            AtlasCandidateDisposition::Eligible => 0,
            AtlasCandidateDisposition::Refused => 1,
            AtlasCandidateDisposition::Unmatched => 2,
            AtlasCandidateDisposition::CameraConflict => 3,
            AtlasCandidateDisposition::IncompleteCycleSupport => 4,
            AtlasCandidateDisposition::NominalOcclusionConflict => 5,
        });
        e.bool(candidate.selected_landmark.is_some());
        if let Some(landmark) = candidate.selected_landmark {
            e.u64(landmark);
        }
    }
    e.u64(receipt.landmarks.len() as u64);
    for value in &receipt.landmarks {
        e.bytes(&value.evidence);
        admission(&mut e, value);
    }
    e.bytes(&receipt.atlas_digest);
    finish(e, work)
}

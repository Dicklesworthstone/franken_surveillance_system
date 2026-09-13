#![forbid(unsafe_code)]
//! Import evaluated property geometry without executing authoring software.
//!
//! The neutral interchange is a bounded, checksummed input, not a calibration
//! certificate or authority to publish a world revision. Coordinates are local
//! right-handed Z-up source units. Scale evidence never silently rescales them.

mod wire;
mod interval;
mod tracking;
mod track_motion;
mod navigation;

pub use navigation::{MAX_NAVIGATION_TRIANGLES, MovementClass, NavigationError, NavigationProfile,
    RouteOutcome, RouteQuery, RouteSearch, SupportLocation, SupportNetwork, SurfaceRoute};

pub use interval::{Bounds3, Interval};
pub use tracking::{ContactHypothesis, ContactObservation, ContactProjection, ProjectionError,
    ProjectionOptions, ProjectionQuality, TrackingCamera, project_contact};
pub use track_motion::{MotionFitOptions, PropagatedPosition, WorldMotion, WorldMotionMode,
    fit_world_motion, propagate_motion};

use fss_geometry::{GeometryBasis, GeometryError, IndexedTriangle, TriangleMesh};

pub use wire::{ImportExpectation, ImportLimits, import_twin};

/// Stable non-disclosing failures at the twin boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TwinError {
    /// Byte, record, output, or allocation ceiling exceeded.
    Limit,
    /// Unsupported, truncated, noncanonical, or inconsistent interchange.
    Format,
    /// Whole-package or trailer checksum mismatch.
    Digest,
    /// A source, property, camera, clock, or generation does not match.
    Basis,
    /// A name, index, geometry role, or reference is invalid.
    Reference,
    /// A numerical value is invalid or an interval is unobservable.
    Numeric,
    /// The requested transition is not supported by these observations.
    Unobservable,
    /// Bounded geometry kernel failure, including cancellation and budget exhaustion.
    Geometry(GeometryError),
}

impl From<GeometryError> for TwinError {
    fn from(error: GeometryError) -> Self { Self::Geometry(error) }
}
impl std::fmt::Display for TwinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Limit => "twin limit exceeded",
            Self::Format => "invalid twin interchange",
            Self::Digest => "twin digest mismatch",
            Self::Basis => "twin basis mismatch",
            Self::Reference => "invalid twin reference",
            Self::Numeric => "invalid twin numeric input",
            Self::Unobservable => "twin observation does not determine this result",
            Self::Geometry(_) => "twin geometry operation failed",
        })
    }
}
impl std::error::Error for TwinError {}

/// Descriptive surface category; it is not a movement permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SurfaceKind {
    /// Unclassified surface; no pedestrian preference may be assumed.
    Unknown,
    /// Explicitly classified pedestrian path.
    PedestrianPath,
    /// Grass or lawn, not automatically forbidden to a person.
    Grass,
    /// Stair surface; connectivity still requires geometry checks.
    Stairs,
    /// Elevated deck or platform.
    Deck,
    /// Structure or other non-route feature.
    Structure,
}

/// Scale assertion retained from the source; neither variant verifies geometry.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ScaleEvidence {
    /// No metric scale is established.
    Relative,
    /// Estimated metres per source unit, with optional absolute error in that factor.
    Estimated {
        /// Nominal conversion, not applied to imported vertices.
        metres_per_unit: f64,
        /// Absolute uncertainty in the conversion factor, or unknown.
        error: Option<f64>,
    },
    /// Producer-declared measured anchor; FSS still needs its qualification evidence.
    MeasuredAnchor {
        /// Producer-declared conversion based on its anchor.
        metres_per_unit: f64,
        /// Absolute uncertainty in the conversion factor, or unknown.
        error: Option<f64>,
    },
}

/// Stable feature identity, independent of editable object and triangle identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TwinFeature {
    /// Producer's stable feature ID, not a display label.
    pub id: String,
    /// Declared category, not inferred from material colour or name.
    pub surface: SurfaceKind,
}

/// One current evaluated object or instance in the frozen source revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TwinObject {
    /// Stable object or revision-bound instance identity.
    pub id: String,
    /// Ordinal of its feature in this exact package.
    pub feature: u32,
    /// Explicit contact-support role.
    pub support: bool,
    /// Explicit optical-occluder role, independent of support.
    pub opaque: bool,
}

/// Frozen input geometry with checked byte identity and retained semantic mapping.
///
/// Construction is possible only through the complete validating importer.
/// This type does not mean the scene is measured, current, or fit for security use.
pub struct PropertyTwin {
    pub(crate) mesh: TriangleMesh,
    pub(crate) features: Vec<TwinFeature>,
    pub(crate) objects: Vec<TwinObject>,
    pub(crate) vertices: Vec<[f64; 3]>,
    pub(crate) triangles: Vec<IndexedTriangle>,
    pub(crate) triangle_objects: Vec<u32>,
    pub(crate) digest: [u8; 32],
    pub(crate) source: [u8; 32],
    pub(crate) scope: String,
    pub(crate) epoch: String,
    pub(crate) scale: ScaleEvidence,
    pub(crate) geometry_error: Option<f64>,
}

impl std::fmt::Debug for PropertyTwin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PropertyTwin").field("features", &self.features.len())
            .field("triangles", &self.triangles.len()).finish_non_exhaustive()
    }
}
impl PropertyTwin {
    /// Scalar geometry with the same exact owner-resolved basis.
    pub fn mesh(&self) -> &TriangleMesh { &self.mesh }
    /// Owner-resolved process-local property/revision, not persistent authority.
    pub fn basis(&self) -> GeometryBasis { self.mesh.basis() }
    /// SHA-256 of all interchange bytes, including the trailer.
    pub fn digest(&self) -> [u8; 32] { self.digest }
    /// Claimed exact saved authoring-file identity.
    pub fn source_scene_digest(&self) -> [u8; 32] { self.source }
    /// Export scene/view-layer/frame and policy binding, supplied by the producer.
    pub fn evaluation_scope(&self) -> &str { &self.scope }
    /// Producer's observation-epoch description; unknown stays explicit text.
    pub fn observation_epoch(&self) -> &str { &self.epoch }
    /// Metric scale evidence without converting source coordinates.
    pub fn scale(&self) -> ScaleEvidence { self.scale }
    /// Claimed geometric error in source units, or unknown (not zero).
    pub fn geometry_error(&self) -> Option<f64> { self.geometry_error }
    /// Features in canonical ID order.
    pub fn features(&self) -> &[TwinFeature] { &self.features }
    /// Current objects in canonical ID order.
    pub fn objects(&self) -> &[TwinObject] { &self.objects }
    /// Read-only evaluated vertices in the declared source coordinate frame.
    pub fn vertices(&self) -> &[[f64; 3]] { &self.vertices }
    /// Read-only triangle table; feature handles are one-based feature ordinals.
    pub fn triangles(&self) -> &[IndexedTriangle] { &self.triangles }
    /// Resolve a triangle to its original object and feature, preserving instances.
    pub fn triangle_identity(&self, triangle: usize) -> Option<(&TwinObject, &TwinFeature)> {
        let object = self.objects.get(*self.triangle_objects.get(triangle)? as usize)?;
        Some((object, self.features.get(object.feature as usize)?))
    }
}

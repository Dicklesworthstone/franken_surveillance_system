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

/// Failure modes for evaluated-twin queries and imports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TwinError {
    /// A configured twin limit (size, breadth, or work) was exceeded.
    Limit,
    /// The twin interchange input is not a valid bounded package.
    Format,
    /// The package digest does not match the declared twin identity.
    Digest,
    /// The package was built against a different geometry basis.
    Basis,
    /// A referenced twin element (feature, object, or surface) does not exist.
    Reference,
    /// A numeric input to a twin computation is out of its valid range.
    Numeric,
    /// The twin observation does not determine the requested result.
    Unobservable,
    /// An underlying geometry operation failed; the cause is preserved.
    Geometry(GeometryError),
}
impl From<GeometryError> for TwinError { fn from(error: GeometryError) -> Self { Self::Geometry(error) } }
impl std::fmt::Display for TwinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Limit => "twin limit exceeded", Self::Format => "invalid twin interchange",
            Self::Digest => "twin digest mismatch", Self::Basis => "twin basis mismatch",
            Self::Reference => "invalid twin reference", Self::Numeric => "invalid twin numeric input",
            Self::Unobservable => "twin observation does not determine this result",
            Self::Geometry(_) => "twin geometry operation failed",
        })
    }
}
impl std::error::Error for TwinError {}

/// Physical support surface classification used for route and support queries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SurfaceKind {
    /// Surface present in the source geometry without an asserted class.
    Unknown,
    /// Walkable path intended for pedestrian transit.
    PedestrianPath,
    /// Grass or other soft landscaped ground.
    Grass,
    /// Stairway steps; transit cost differs from flat ground.
    Stairs,
    /// Built deck or platform surface.
    Deck,
    /// Building or structure surface, not treated as navigable ground.
    Structure,
}
/// Scale evidence carried by an evaluated twin, from weakest to strongest.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ScaleEvidence {
    /// Only relative geometry is asserted; source units are not metres.
    Relative,
    /// Scale was estimated with a declared metres-per-unit factor and optional error.
    Estimated {
        /// Conversion factor from source units to metres.
        metres_per_unit: f64,
        /// Declared relative error of the factor, when quantified.
        error: Option<f64>,
    },
    /// Scale anchored by a measured reference with a declared factor and optional error.
    MeasuredAnchor {
        /// Conversion factor from source units to metres.
        metres_per_unit: f64,
        /// Declared relative error of the factor, when quantified.
        error: Option<f64>,
    },
}
/// Named semantic feature attached to a twin surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TwinFeature {
    /// Stable feature identifier from the source evaluation.
    pub id: String,
    /// Surface class the feature is attached to.
    pub surface: SurfaceKind,
}
/// Semantic object bound to a mesh triangle region.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TwinObject {
    /// Stable object identifier from the source evaluation.
    pub id: String,
    /// Index into the twin's feature list for the attached feature.
    pub feature: u32,
    /// Whether the object provides physical support for tracked entities.
    pub support: bool,
    /// Whether the object occludes observations behind it.
    pub opaque: bool,
}

/// Evaluated property geometry imported from a bounded, checksummed neutral package.
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
        f.debug_struct("PropertyTwin").field("features", &self.features.len()).field("triangles", &self.triangles.len()).finish_non_exhaustive()
    }
}
impl PropertyTwin {
    /// Returns the evaluated triangle mesh in local source units.
    pub fn mesh(&self) -> &TriangleMesh { &self.mesh }
    /// Returns the geometry basis revision the mesh was evaluated against.
    pub fn basis(&self) -> GeometryBasis { self.mesh.basis() }
    /// Returns the package digest that pins this twin's exact content.
    pub fn digest(&self) -> [u8; 32] { self.digest }
    /// Returns the digest of the source scene the package was exported from.
    pub fn source_scene_digest(&self) -> [u8; 32] { self.source }
    /// Returns the evaluation scope declaration from the package.
    pub fn evaluation_scope(&self) -> &str { &self.scope }
    /// Returns the observation epoch the evaluation was taken in.
    pub fn observation_epoch(&self) -> &str { &self.epoch }
    /// Returns the scale evidence associated with the source units.
    pub fn scale(&self) -> ScaleEvidence { self.scale }
    /// Returns the declared geometry error metric, when quantified.
    pub fn geometry_error(&self) -> Option<f64> { self.geometry_error }
    /// Returns the semantic features attached to twin surfaces.
    pub fn features(&self) -> &[TwinFeature] { &self.features }
    /// Returns the semantic objects bound to mesh regions.
    pub fn objects(&self) -> &[TwinObject] { &self.objects }
    /// Returns the mesh vertex positions in local source units.
    pub fn vertices(&self) -> &[[f64; 3]] { &self.vertices }
    /// Returns the mesh triangle index list.
    pub fn triangles(&self) -> &[IndexedTriangle] { &self.triangles }
    /// Resolves a triangle to its bound object and feature, if fully linked.
    pub fn triangle_identity(&self, triangle: usize) -> Option<(&TwinObject, &TwinFeature)> {
        let object = self.objects.get(*self.triangle_objects.get(triangle)? as usize)?;
        Some((object, self.features.get(object.feature as usize)?))
    }
}

pub mod localization;
pub mod focal_localization;
pub mod radial_localization;
pub mod validated_registration;
pub mod validated_radial_registration;
pub mod atlas_archive;
pub mod stream;
pub mod route_frontier;
pub mod frontier_handoff;
pub mod handoff_summary;
pub mod observed_handoff;
pub mod monitored_handoff;
pub mod rectification;
pub mod association;
pub mod association_hypotheses;
pub mod foreground;
pub mod mjpeg;
pub mod calibration_monitor;
pub mod calibration_gate;

/// Source-linked sensor-health screening and bounded semantic-analysis admission.
pub mod screening;

/// Native JPEG/stream decoding composed with foreground, health and sentinel admission.
pub mod screened_mjpeg;

/// Anonymous, source-linked image trajectories without a metric twin or identity claim.
pub mod image_tracking;

/// Source-pair Kalman motion estimates over exact current anonymous tracking receipts.
pub mod image_motion;

mod foreground_tracking;

/// Source-linked image-zone occupancy, transitions and sampled dwell without effect authority.
pub mod image_zones;

/// Native HOG features and immutable learned classification over permitted image pixels.
pub mod hog;

/// Complete multiscale learned detection with source-linked scores and suppression.
pub mod hog_scan;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TwinError { Limit, Format, Digest, Basis, Reference, Numeric, Unobservable, Geometry(GeometryError) }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SurfaceKind { Unknown, PedestrianPath, Grass, Stairs, Deck, Structure }
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ScaleEvidence {
    Relative,
    Estimated { metres_per_unit: f64, error: Option<f64> },
    MeasuredAnchor { metres_per_unit: f64, error: Option<f64> },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TwinFeature { pub id: String, pub surface: SurfaceKind }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TwinObject { pub id: String, pub feature: u32, pub support: bool, pub opaque: bool }

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
    pub fn mesh(&self) -> &TriangleMesh { &self.mesh }
    pub fn basis(&self) -> GeometryBasis { self.mesh.basis() }
    pub fn digest(&self) -> [u8; 32] { self.digest }
    pub fn source_scene_digest(&self) -> [u8; 32] { self.source }
    pub fn evaluation_scope(&self) -> &str { &self.scope }
    pub fn observation_epoch(&self) -> &str { &self.epoch }
    pub fn scale(&self) -> ScaleEvidence { self.scale }
    pub fn geometry_error(&self) -> Option<f64> { self.geometry_error }
    pub fn features(&self) -> &[TwinFeature] { &self.features }
    pub fn objects(&self) -> &[TwinObject] { &self.objects }
    pub fn vertices(&self) -> &[[f64; 3]] { &self.vertices }
    pub fn triangles(&self) -> &[IndexedTriangle] { &self.triangles }
    pub fn triangle_identity(&self, triangle: usize) -> Option<(&TwinObject, &TwinFeature)> {
        let object = self.objects.get(*self.triangle_objects.get(triangle)? as usize)?;
        Some((object, self.features.get(object.feature as usize)?))
    }
}

pub mod localization;
pub mod focal_localization;
pub mod validated_registration;
pub mod atlas_archive;
pub mod stream;
pub mod route_frontier;
pub mod observed_handoff;
pub mod monitored_handoff;
pub mod rectification;
pub mod association;
pub mod association_hypotheses;
pub mod foreground;
pub mod mjpeg;
pub mod calibration_monitor;
pub mod calibration_gate;

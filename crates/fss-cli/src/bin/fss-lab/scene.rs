#![forbid(unsafe_code)]
//! Synthetic property scene that makes the `sneaky` coverage gap physical (fss-2h5zq.55).
//!
//! The scene is a ground plane, a house box and one fence segment, built here as an fss-twin
//! `FSSTWIN1` package and loaded through the same neutral importer the twin uses
//! (`import_scene_mesh`, which calls `fss_twin::import_twin` against the exact package and
//! source-scene digests). It is generated first-party in code rather than committed as a fixture
//! because every byte is a function of a handful of documented numbers, and the planted
//! counterfactual needs a second package with the fence moved. No-Claim: this synthetic scene is
//! not a model of any real property, and its relative units are not metres.
//!
//! Two calibrated pinhole poses stand for `cam-front` and `cam-side`. The intruder path crosses
//! one ground zone per tick, and every (zone, camera) pair is assessed with the reference
//! ground-visibility machinery (`assess_ground_zone`: grid sampling, pinhole frustum and mesh
//! occlusion). With the reference fence:
//!
//! * `zone:front-walk` (tick 2) is fully visible from `cam-front` and hidden from `cam-side`
//!   behind the house;
//! * `zone:side-passage` (tick 3) is behind `cam-front` (outside its frustum) and hidden from
//!   `cam-side` behind the fence, so no camera observes it: that is the coverage gap.
//!
//! Moving the fence out of `cam-side`'s sight line (the counterfactual) makes the side passage
//! fully visible from `cam-side`, and the gap disappears.

use std::collections::BTreeSet;

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_geometry::{GeometryError, PinholeIntrinsics, RigidPose};
use fss_reference::ingest::ground_visibility::{
    CameraPose, NotVisibleCause, SceneMesh, VISIBILITY_POLICY, VisibilityCamera, VisibilityPolicy,
    ZoneVisibility, assess_ground_zone, import_scene_mesh, rectangle,
};

use crate::scenario::ScenarioError;

/// Digest domain of the lab scene's source identity, camera pose digests and coverage basis
/// (`SCHEMA-DOMAIN-LAB-GEOMETRIC-COVERAGE-001`).
pub const GEOMETRIC_COVERAGE_DOMAIN: &str = "fss.lab.geometric_coverage.v1";

/// Decoded image mode shared by both virtual cameras.
pub const IMAGE_DIMENSIONS: [u32; 2] = [640, 480];
/// `[fx, fy, cx, cy]` of both virtual cameras, in pixels.
const INTRINSICS: [f64; 4] = [400.0, 400.0, 320.0, 240.0];
/// Opaque ground plane half extent (it is the support surface every zone lies on).
const GROUND_HALF_EXTENT: f64 = 40.0;
/// House box `[x0, y0, x1, y1, height]`.
const HOUSE: [f64; 5] = [-6.0, 0.0, 6.0, 10.0, 5.0];

/// One vertical fence panel along `y`, from `x0` to `x1`, `height` tall.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Fence {
    /// West end.
    pub x0: f64,
    /// East end.
    pub x1: f64,
    /// Northing of the panel.
    pub y: f64,
    /// Panel height.
    pub height: f64,
}

/// The fence placements a lab run may use.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LabScene {
    /// The fence panel.
    pub fence: Fence,
}

impl LabScene {
    /// The `sneaky` scene: the fence stands between `cam-side` and the side passage.
    pub const REFERENCE: Self = Self {
        fence: Fence {
            x0: 7.0,
            x1: 14.0,
            y: 11.0,
            height: 2.5,
        },
    };

    /// The planted counterfactual: the same fence moved east, out of `cam-side`'s sight line.
    #[cfg(test)]
    pub const FENCE_MOVED: Self = Self {
        fence: Fence {
            x0: 16.0,
            x1: 23.0,
            y: 11.0,
            height: 2.5,
        },
    };
}

/// One virtual camera's calibrated pose: optical centre and downward pitch (`sin`, `cos`) of a
/// camera heading south (`-y`).
struct CameraMount {
    camera: &'static str,
    center: [f64; 3],
    pitch: [f64; 2],
}

const CAMERAS: [CameraMount; 2] = [
    // On the house front wall, looking south over the front walk (pitch 3-4-5, ~36.9 degrees).
    CameraMount {
        camera: "cam-front",
        center: [0.0, -0.5, 3.0],
        pitch: [0.6, 0.8],
    },
    // On a post north-east of the house, looking south along the side passage (7-24-25).
    CameraMount {
        camera: "cam-side",
        center: [10.0, 16.0, 3.0],
        pitch: [0.28, 0.96],
    },
];

/// One ground zone the intruder path crosses, at one tick: `[x, y, width, height]`.
struct PathStep {
    zone: &'static str,
    tick: u64,
    rect: [f64; 4],
}

const INTRUDER_PATH: [PathStep; 2] = [
    PathStep {
        zone: "zone:front-walk",
        tick: 2,
        rect: [-2.0, -10.0, 4.0, 4.0],
    },
    PathStep {
        zone: "zone:side-passage",
        tick: 3,
        rect: [8.0, 2.0, 4.0, 6.0],
    },
];

impl CameraMount {
    fn pose(&self) -> Result<CameraPose, ScenarioError> {
        let [s, c] = self.pitch;
        // World-to-camera rows: image right (west), image down, optical axis (south, pitched
        // down); a proper rotation for s^2 + c^2 = 1.
        let rotation = [[-1.0, 0.0, 0.0], [0.0, s, -c], [0.0, -c, -s]];
        let [fx, fy, cx, cy] = INTRINSICS;
        let [width, height] = IMAGE_DIMENSIONS;
        let geometry = |e: GeometryError| ScenarioError::Geometry(e.to_string());
        Ok(CameraPose {
            intrinsics: PinholeIntrinsics::new(width, height, fx, fy, cx, cy).map_err(geometry)?,
            pose: RigidPose::from_center(rotation, self.center).map_err(geometry)?,
        })
    }
}

/// One camera's geometric view of one path zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CameraView {
    /// Camera name.
    pub camera: &'static str,
    /// Reference ground-visibility result.
    pub visibility: ZoneVisibility,
}

impl CameraView {
    /// `visible`, `occluded`, `outside_frustum` or `privacy_masked`.
    #[must_use]
    pub fn state(&self) -> &'static str {
        match self.visibility.cause() {
            None => "visible",
            Some(NotVisibleCause::Occluded) => "occluded",
            Some(NotVisibleCause::OutsideFrustum) => "outside_frustum",
            Some(NotVisibleCause::PrivacyMasked) => "privacy_masked",
        }
    }
}

/// Geometric coverage of one path zone at one tick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZoneCoverage {
    /// Zone identifier.
    pub zone: &'static str,
    /// Scenario tick at which the intruder path crosses the zone.
    pub tick: u64,
    /// Every camera's view, in camera order.
    pub views: Vec<CameraView>,
}

impl ZoneCoverage {
    /// Whether at least one camera observes the zone.
    #[must_use]
    pub fn observed(&self) -> bool {
        self.views.iter().any(|view| view.visibility.observable())
    }

    /// Whether `camera` observes the zone.
    #[must_use]
    pub fn observable_from(&self, camera: &str) -> bool {
        self.views
            .iter()
            .any(|view| view.camera == camera && view.visibility.observable())
    }

    /// `cam-side occluded, cam-front outside_frustum`-style cause list.
    #[must_use]
    pub fn causes(&self) -> String {
        self.views
            .iter()
            .map(|view| format!("{} {}", view.camera, view.state()))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// The scene's geometric coverage of the intruder path, with its exact basis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeometricCoverage {
    /// SHA-256 of the exact imported `FSSTWIN1` package (the occlusion mesh).
    pub mesh_digest: ContentDigest,
    /// Source-scene identity the package declares (the canonical scene parameters).
    pub source_scene_digest: ContentDigest,
    /// Per camera, the digest of its exact intrinsics and pose bits.
    pub pose_digests: Vec<(&'static str, ContentDigest)>,
    /// Visibility policy the zones were sampled under.
    pub policy: VisibilityPolicy,
    /// Basis digest: mesh, poses, policy and zone geometry together.
    pub basis_digest: ContentDigest,
    /// Path zones in tick order.
    pub zones: Vec<ZoneCoverage>,
    /// Digest of the retained `CoverageWitness` built from the visible zones, once staged.
    pub witness_digest: Option<ContentDigest>,
}

impl GeometricCoverage {
    /// Imports the scene through the twin importer and assesses every path zone from every
    /// camera. Deterministic: equal scenes give equal results.
    pub fn assess(scene: &LabScene) -> Result<Self, ScenarioError> {
        let source_scene_digest = source_scene_digest(scene);
        let package = twin_package(scene, source_scene_digest)?;
        let mesh_digest = ContentDigest::sha256(&package);
        let twin = import_scene_mesh(&package, mesh_digest, source_scene_digest)
            .map_err(|e| ScenarioError::Geometry(e.to_string()))?;
        let mesh = SceneMesh {
            mesh: twin.mesh(),
            package_digest: mesh_digest,
        };
        let policy = VisibilityPolicy::default();
        let mut poses = Vec::with_capacity(CAMERAS.len());
        let mut pose_digests = Vec::with_capacity(CAMERAS.len());
        for mount in &CAMERAS {
            let pose = mount.pose()?;
            pose_digests.push((mount.camera, pose_digest(mount.camera, &pose)));
            poses.push((mount.camera, pose));
        }
        let mut zones = Vec::with_capacity(INTRUDER_PATH.len());
        for step in &INTRUDER_PATH {
            let [x, y, width, height] = step.rect;
            let polygon = rectangle(x, y, width, height);
            let mut views = Vec::with_capacity(poses.len());
            for (camera, pose) in &poses {
                let visibility = assess_ground_zone(
                    VisibilityCamera::Pose(pose),
                    IMAGE_DIMENSIONS,
                    &polygon,
                    Some(mesh),
                    policy,
                )
                .map_err(|e| ScenarioError::Geometry(e.to_string()))?;
                views.push(CameraView { camera, visibility });
            }
            zones.push(ZoneCoverage {
                zone: step.zone,
                tick: step.tick,
                views,
            });
        }
        let basis_digest = basis_digest(mesh_digest, &pose_digests, policy);
        Ok(Self {
            mesh_digest,
            source_scene_digest,
            pose_digests,
            policy,
            basis_digest,
            zones,
            witness_digest: None,
        })
    }

    /// The path zone crossed at `tick`, if any.
    #[must_use]
    pub fn zone_at(&self, tick: u64) -> Option<&ZoneCoverage> {
        self.zones.iter().find(|zone| zone.tick == tick)
    }

    /// Every path zone (the authorized coverage domain).
    #[must_use]
    pub fn authorized_domain(&self) -> BTreeSet<String> {
        self.zones.iter().map(|zone| zone.zone.to_owned()).collect()
    }

    /// Path zones at least one camera observes (the observed coverage domain).
    #[must_use]
    pub fn observed_domain(&self) -> BTreeSet<String> {
        self.zones
            .iter()
            .filter(|zone| zone.observed())
            .map(|zone| zone.zone.to_owned())
            .collect()
    }

    /// Path zones no camera observes, in tick order.
    pub fn uncovered(&self) -> impl Iterator<Item = &ZoneCoverage> {
        self.zones.iter().filter(|zone| !zone.observed())
    }

    /// Renders the `geometric_coverage` report object.
    pub fn render_json(&self, output: &mut String) {
        output.push('{');
        push_field(output, "basis_digest", &self.basis_digest.to_string(), true);
        push_field(output, "mesh_digest", &self.mesh_digest.to_string(), false);
        push_field(
            output,
            "source_scene_digest",
            &self.source_scene_digest.to_string(),
            false,
        );
        output.push_str(",\"poses\":[");
        for (index, (camera, digest)) in self.pose_digests.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            output.push('{');
            push_field(output, "camera", camera, true);
            push_field(output, "pose_digest", &digest.to_string(), false);
            output.push('}');
        }
        output.push(']');
        push_field(output, "policy", VISIBILITY_POLICY, false);
        push_number(output, "grid", u64::from(self.policy.grid));
        push_number(
            output,
            "threshold_ppm",
            u64::from(self.policy.threshold_ppm),
        );
        output.push_str(",\"zones\":[");
        for (index, zone) in self.zones.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            output.push('{');
            push_field(output, "zone", zone.zone, true);
            push_number(output, "tick", zone.tick);
            push_field(
                output,
                "state",
                if zone.observed() {
                    "observed"
                } else {
                    "not_observable"
                },
                false,
            );
            output.push_str(",\"cameras\":[");
            for (view_index, view) in zone.views.iter().enumerate() {
                if view_index > 0 {
                    output.push(',');
                }
                let v = &view.visibility;
                output.push('{');
                push_field(output, "camera", view.camera, true);
                push_field(output, "state", view.state(), false);
                push_number(output, "samples", u64::from(v.samples));
                push_number(output, "visible", u64::from(v.visible));
                push_number(output, "outside_frustum", u64::from(v.outside_frustum));
                push_number(output, "occluded", u64::from(v.occluded));
                push_number(
                    output,
                    "visible_fraction_ppm",
                    u64::from(v.visible_fraction_ppm()),
                );
                push_field(output, "claim", v.claim(), false);
                output.push('}');
            }
            output.push_str("]}");
        }
        output.push(']');
        output.push_str(",\"coverage_witness\":{");
        output.push_str("\"digest\":");
        match self.witness_digest {
            Some(digest) => push_string(output, &digest.to_string()),
            None => output.push_str("null"),
        }
        push_set(output, "authorized_domain", &self.authorized_domain());
        push_set(output, "observed_domain", &self.observed_domain());
        output.push_str("}}");
    }
}

/// Canonical scene parameters: the synthetic scene has no authoring file, so its source identity
/// is the digest of the numbers it is built from.
fn source_scene_digest(scene: &LabScene) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(GEOMETRIC_COVERAGE_DOMAIN);
    e.text("source_scene");
    e.u64(GROUND_HALF_EXTENT.to_bits());
    for value in HOUSE {
        e.u64(value.to_bits());
    }
    let Fence { x0, x1, y, height } = scene.fence;
    for value in [x0, x1, y, height] {
        e.u64(value.to_bits());
    }
    ContentDigest::sha256(&e.finish())
}

fn pose_digest(camera: &str, pose: &CameraPose) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(GEOMETRIC_COVERAGE_DOMAIN);
    e.text("pose");
    e.text(camera);
    e.u32(IMAGE_DIMENSIONS[0]);
    e.u32(IMAGE_DIMENSIONS[1]);
    for bits in pose.parameter_bits() {
        e.u64(bits);
    }
    ContentDigest::sha256(&e.finish())
}

fn basis_digest(
    mesh: ContentDigest,
    poses: &[(&'static str, ContentDigest)],
    policy: VisibilityPolicy,
) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(GEOMETRIC_COVERAGE_DOMAIN);
    e.text("basis");
    e.digest(mesh);
    e.u64(poses.len() as u64);
    for (camera, digest) in poses {
        e.text(camera);
        e.digest(*digest);
    }
    e.text(VISIBILITY_POLICY);
    e.u32(policy.grid);
    e.u32(policy.threshold_ppm);
    e.u64(INTRUDER_PATH.len() as u64);
    for step in &INTRUDER_PATH {
        e.text(step.zone);
        e.u64(step.tick);
        for value in step.rect {
            e.u64(value.to_bits());
        }
    }
    ContentDigest::sha256(&e.finish())
}

fn wire_text(out: &mut Vec<u8>, value: &str) -> Result<(), ScenarioError> {
    let length = u16::try_from(value.len())
        .map_err(|_| ScenarioError::Geometry("scene text is too long".to_owned()))?;
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn wire_count(out: &mut Vec<u8>, value: usize) -> Result<(), ScenarioError> {
    let count = u32::try_from(value)
        .map_err(|_| ScenarioError::Geometry("scene count is too large".to_owned()))?;
    out.extend_from_slice(&count.to_le_bytes());
    Ok(())
}

/// The scene as an fss-twin `FSSTWIN1` package (relative scale, Z up, ground at `z = 0`).
///
/// Features and objects, sorted by id: `fence` (structure), `ground` (grass, the support
/// surface) and `house` (structure); every surface is opaque.
fn twin_package(scene: &LabScene, source: ContentDigest) -> Result<Vec<u8>, ScenarioError> {
    let g = GROUND_HALF_EXTENT;
    let [hx0, hy0, hx1, hy1, hh] = HOUSE;
    let Fence { x0, x1, y, height } = scene.fence;
    let vertices: [[f64; 3]; 16] = [
        [-g, -g, 0.0],
        [g, -g, 0.0],
        [g, g, 0.0],
        [-g, g, 0.0],
        [hx0, hy0, 0.0],
        [hx1, hy0, 0.0],
        [hx1, hy1, 0.0],
        [hx0, hy1, 0.0],
        [hx0, hy0, hh],
        [hx1, hy0, hh],
        [hx1, hy1, hh],
        [hx0, hy1, hh],
        [x0, y, 0.0],
        [x1, y, 0.0],
        [x1, y, height],
        [x0, y, height],
    ];
    // `[a, b, c, object]`; objects: 0 fence, 1 ground, 2 house.
    let triangles: [[u32; 4]; 14] = [
        [0, 1, 2, 1],
        [0, 2, 3, 1],
        // House walls (south, east, north, west) and roof.
        [4, 5, 9, 2],
        [4, 9, 8, 2],
        [5, 6, 10, 2],
        [5, 10, 9, 2],
        [6, 7, 11, 2],
        [6, 11, 10, 2],
        [7, 4, 8, 2],
        [7, 8, 11, 2],
        [8, 9, 10, 2],
        [8, 10, 11, 2],
        // Fence panel.
        [12, 13, 14, 0],
        [12, 14, 15, 0],
    ];
    let features: [(&str, u8); 3] = [("fence", 5), ("ground", 2), ("house", 5)];
    // `(id, feature, support, opaque)`.
    let objects: [(&str, u32, u8, u8); 3] =
        [("fence", 0, 0, 1), ("ground", 1, 1, 1), ("house", 2, 0, 1)];

    let mut body = source.bytes().to_vec();
    wire_text(&mut body, "fss-lab/sneaky/Z-up")?;
    wire_text(&mut body, "synthetic")?;
    // Relative scale: no metric claim.
    body.push(0);
    for value in [0.0_f64, -1.0, -1.0] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    wire_count(&mut body, features.len())?;
    wire_count(&mut body, objects.len())?;
    wire_count(&mut body, vertices.len())?;
    wire_count(&mut body, triangles.len())?;
    for (id, surface) in features {
        wire_text(&mut body, id)?;
        body.push(surface);
    }
    for (id, feature, support, opaque) in objects {
        wire_text(&mut body, id)?;
        body.extend_from_slice(&feature.to_le_bytes());
        body.extend_from_slice(&[support, opaque]);
    }
    for vertex in &vertices {
        for value in vertex {
            body.extend_from_slice(&value.to_le_bytes());
        }
    }
    for triangle in &triangles {
        for value in triangle {
            body.extend_from_slice(&value.to_le_bytes());
        }
    }
    let mut package = b"FSSTWIN1".to_vec();
    package.extend_from_slice(&(body.len() as u64).to_le_bytes());
    package.extend_from_slice(&body);
    let trailer = ContentDigest::sha256(&package).bytes();
    package.extend_from_slice(&trailer);
    Ok(package)
}

fn push_field(output: &mut String, key: &str, value: &str, first: bool) {
    if !first {
        output.push(',');
    }
    push_string(output, key);
    output.push(':');
    push_string(output, value);
}

fn push_number(output: &mut String, key: &str, value: u64) {
    output.push(',');
    push_string(output, key);
    output.push(':');
    output.push_str(&value.to_string());
}

fn push_set(output: &mut String, key: &str, values: &BTreeSet<String>) {
    output.push(',');
    push_string(output, key);
    output.push_str(":[");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_string(output, value);
    }
    output.push(']');
}

/// Every string this module renders is a fixed identifier, digest or policy label with no
/// character that needs escaping; escape anyway so the output is always valid JSON.
fn push_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            value if value.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{:04x}", u32::from(value));
            }
            value => output.push(value),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use super::{GeometricCoverage, LabScene};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn counts(
        coverage: &GeometricCoverage,
        zone: &str,
        camera: &str,
    ) -> Result<(u32, u32, u32, u32), Box<dyn std::error::Error>> {
        let view = coverage
            .zones
            .iter()
            .find(|z| z.zone == zone)
            .and_then(|z| z.views.iter().find(|v| v.camera == camera))
            .ok_or("missing view")?;
        let v = &view.visibility;
        Ok((v.samples, v.visible, v.outside_frustum, v.occluded))
    }

    #[test]
    fn the_reference_scene_hides_the_side_passage_from_every_camera() -> TestResult {
        let coverage = GeometricCoverage::assess(&LabScene::REFERENCE)?;
        // Front walk: all 64 samples visible from cam-front, all hidden behind the house from
        // cam-side.
        assert_eq!(
            counts(&coverage, "zone:front-walk", "cam-front")?,
            (64, 64, 0, 0)
        );
        assert_eq!(
            counts(&coverage, "zone:front-walk", "cam-side")?,
            (64, 0, 0, 64)
        );
        // Side passage: behind cam-front, behind the fence for cam-side.
        assert_eq!(
            counts(&coverage, "zone:side-passage", "cam-front")?,
            (64, 0, 64, 0)
        );
        assert_eq!(
            counts(&coverage, "zone:side-passage", "cam-side")?,
            (64, 0, 0, 64)
        );
        let uncovered: Vec<&str> = coverage.uncovered().map(|zone| zone.zone).collect();
        assert_eq!(uncovered, ["zone:side-passage"]);
        let gap = coverage.zone_at(3).ok_or("no zone at tick 3")?;
        assert_eq!(gap.causes(), "cam-front outside_frustum, cam-side occluded");
        assert_eq!(
            coverage.observed_domain().into_iter().collect::<Vec<_>>(),
            ["zone:front-walk"]
        );
        assert_eq!(coverage.authorized_domain().len(), 2);
        assert!(coverage.zone_at(0).is_none());
        Ok(())
    }

    #[test]
    fn moving_the_fence_opens_the_side_passage_to_cam_side() -> TestResult {
        let reference = GeometricCoverage::assess(&LabScene::REFERENCE)?;
        let moved = GeometricCoverage::assess(&LabScene::FENCE_MOVED)?;
        assert_eq!(
            counts(&moved, "zone:side-passage", "cam-side")?,
            (64, 64, 0, 0)
        );
        // Nothing else changes: the house still hides the front walk, cam-front still faces
        // away from the side passage.
        assert_eq!(
            counts(&moved, "zone:front-walk", "cam-side")?,
            (64, 0, 0, 64)
        );
        assert_eq!(
            counts(&moved, "zone:side-passage", "cam-front")?,
            (64, 0, 64, 0)
        );
        assert_eq!(moved.uncovered().count(), 0);
        assert_eq!(moved.observed_domain(), moved.authorized_domain());
        // The basis binds the mesh: same poses, different mesh and basis digests.
        assert_eq!(moved.pose_digests, reference.pose_digests);
        assert_ne!(moved.mesh_digest, reference.mesh_digest);
        assert_ne!(moved.source_scene_digest, reference.source_scene_digest);
        assert_ne!(moved.basis_digest, reference.basis_digest);
        Ok(())
    }

    #[test]
    fn assessment_is_deterministic() -> TestResult {
        let first = GeometricCoverage::assess(&LabScene::REFERENCE)?;
        let second = GeometricCoverage::assess(&LabScene::REFERENCE)?;
        assert_eq!(first, second);
        let mut a = String::new();
        let mut b = String::new();
        first.render_json(&mut a);
        second.render_json(&mut b);
        assert_eq!(a, b);
        Ok(())
    }
}

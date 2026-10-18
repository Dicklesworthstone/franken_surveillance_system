#![forbid(unsafe_code)]
//! Strict owner-authored camera-rig input for spatial fusion.
//!
//! This bounded control JSON resolves nominal camera placements into the existing
//! `TrackingCamera` contract. It is not a calibration activation or a source/clock
//! certificate. Every camera remains `error: None`, and the exact twin, source,
//! property basis, evaluation scope and image mode must agree before any fusion.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_geometry::{GeometryBasis, GeometryError, PinholeIntrinsics, RigidPose, WorkBudget};
use fss_twin::{PropertyTwin, TrackingCamera};

use crate::json_input::{MAX_INPUT_BYTES, Value, parse};

/// Bounded control-document contract. Later formats must migrate explicitly.
pub const SCENE_RIG_SCHEMA: &str = "fss.scene_camera_rig.v1";
/// Maximum explicitly bound cameras in one property rig.
pub const MAX_SCENE_CAMERAS: usize = 64;

/// Stable, content-free refusal categories for a scene camera rig.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SceneRigError {
    /// Invalid schema, unknown/missing field, or wrong field type.
    Format,
    /// Input exceeds an explicit camera, byte, text, or allocation bound.
    Limit,
    /// Property revision, twin digest, source digest, or scope does not match.
    Basis,
    /// Two rows would bind one sensor or one authored camera more than once.
    Duplicate,
    /// Invalid dimensions, matrix, generation, or clock interval.
    Numeric,
    /// Lens model or calibration status is outside the admitted nominal subset.
    Unsupported,
    /// The underlying geometry budget, cancellation, or validation failed.
    Geometry(GeometryError),
}

impl SceneRigError {
    /// Stable error identity, without imported text or private camera labels.
    pub const fn stable_id(self) -> &'static str {
        match self {
            Self::Format => "scene.rig.format",
            Self::Limit => "scene.rig.limit",
            Self::Basis => "scene.rig.basis_mismatch",
            Self::Duplicate => "scene.rig.duplicate_binding",
            Self::Numeric => "scene.rig.numeric",
            Self::Unsupported => "scene.rig.unsupported",
            Self::Geometry(GeometryError::Cancelled) => "scene.rig.cancelled",
            Self::Geometry(GeometryError::BudgetExhausted) => "scene.rig.budget",
            Self::Geometry(_) => "scene.rig.geometry",
        }
    }
}

impl std::fmt::Display for SceneRigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.stable_id())
    }
}
impl std::error::Error for SceneRigError {}
impl From<GeometryError> for SceneRigError {
    fn from(value: GeometryError) -> Self {
        Self::Geometry(value)
    }
}

/// An explicit owner binding from one authored scene camera to one sensor mode.
#[derive(Clone, Debug, PartialEq)]
pub struct SceneRigCamera {
    /// Stable identity of the source scene object, distinct from the sensor ID.
    pub source_object_id: String,
    /// Nominal camera placement in the exact imported twin's frame.
    pub camera: TrackingCamera,
    /// Owner-declared domain; it does not grant cross-camera access authority.
    pub privacy_domain: u64,
}

/// Immutable rig admitted against one existing, independently pinned property twin.
#[derive(Clone, Debug)]
pub struct SceneRig {
    cameras: Vec<SceneRigCamera>,
    digest: ContentDigest,
    source_scene_digest: ContentDigest,
    twin_digest: ContentDigest,
    geometry_basis: (u64, u64),
    evaluation_scope: String,
}

impl SceneRig {
    /// Parse a strict JSON value without opening paths or activating a generation.
    ///
    /// Input object order is irrelevant. Camera order is canonicalized by sensor
    /// identity, with duplicate sensor or authored-object bindings refused.
    pub fn from_document(
        document: &Value,
        twin: &PropertyTwin,
        budget: &mut WorkBudget<'_>,
    ) -> Result<Self, SceneRigError> {
        budget.charge(0)?;
        let top = object(
            document,
            &[
                "schema",
                "source_scene_digest",
                "twin_digest",
                "geometry_basis",
                "coordinate_frame",
                "evaluation_scope",
                "cameras",
            ],
        )?;
        if text(field(top, "schema")?, 64)? != SCENE_RIG_SCHEMA {
            return Err(SceneRigError::Format);
        }
        if text(field(top, "coordinate_frame")?, 64)? != "RH_Z_UP" {
            return Err(SceneRigError::Unsupported);
        }
        let scope = text(field(top, "evaluation_scope")?, 2048)?;
        let source_scene_digest = digest(field(top, "source_scene_digest")?)?;
        let twin_digest = digest(field(top, "twin_digest")?)?;
        let basis = object(field(top, "geometry_basis")?, &["property", "revision"])?;
        let property = identity(field(basis, "property")?)?;
        let revision = identity(field(basis, "revision")?)?;
        let geometry = GeometryBasis::new(property, revision)?;
        if geometry != twin.basis()
            || source_scene_digest.bytes() != twin.source_scene_digest()
            || twin_digest.bytes() != twin.digest()
            || scope != twin.evaluation_scope()
        {
            return Err(SceneRigError::Basis);
        }
        let rows = field(top, "cameras")?
            .array()
            .ok_or(SceneRigError::Format)?;
        if rows.is_empty() || rows.len() > MAX_SCENE_CAMERAS {
            return Err(SceneRigError::Limit);
        }
        // Reserve work before allocation. This includes bounded labels, matrices,
        // sorting, canonical encoding and the final SHA-256 walk.
        budget.charge(8192 + 4096 * rows.len() as u64)?;
        let mut cameras = Vec::new();
        cameras
            .try_reserve_exact(rows.len())
            .map_err(|_| SceneRigError::Limit)?;
        let mut sensor_ids = BTreeSet::new();
        let mut object_ids = BTreeSet::new();
        for row in rows {
            budget.charge(0)?;
            let camera = read_camera(row, geometry)?;
            if !sensor_ids.insert(camera.camera.camera)
                || !object_ids.insert(camera.source_object_id.clone())
            {
                return Err(SceneRigError::Duplicate);
            }
            cameras.push(camera);
        }
        cameras.sort_by_key(|c| c.camera.camera);
        let mut encoder = CanonicalEncoder::new();
        encoder.text(SCENE_RIG_SCHEMA);
        encoder.digest(source_scene_digest);
        encoder.digest(twin_digest);
        encoder.u64(property);
        encoder.u64(revision);
        encoder.text("RH_Z_UP");
        encoder.text(scope);
        encoder.u64(cameras.len() as u64);
        for row in &cameras {
            encode_camera(&mut encoder, row);
        }
        let bytes = encoder.finish_checked().map_err(|_| SceneRigError::Limit)?;
        let semantic_digest = ContentDigest::sha256(&bytes);
        budget.charge(0)?;
        Ok(Self {
            cameras,
            digest: semantic_digest,
            source_scene_digest,
            twin_digest,
            geometry_basis: (property, revision),
            evaluation_scope: scope.to_owned(),
        })
    }

    /// Camera snapshots, deterministically sorted by nonzero sensor identity.
    pub fn cameras(&self) -> &[SceneRigCamera] {
        &self.cameras
    }
    /// One explicitly declared camera; a missing binding is not inferred.
    pub fn camera(&self, id: u64) -> Option<&SceneRigCamera> {
        self.cameras
            .binary_search_by_key(&id, |c| c.camera.camera)
            .ok()
            .map(|i| &self.cameras[i])
    }
    /// Canonical typed-input digest, invariant to JSON formatting and row ordering.
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Exact source file identity copied from the verified native twin.
    pub fn source_scene_digest(&self) -> ContentDigest {
        self.source_scene_digest
    }
    /// Exact complete FSSTWIN1 package identity.
    pub fn twin_digest(&self) -> ContentDigest {
        self.twin_digest
    }
    /// Evaluated source scope; must match the native twin byte-for-byte.
    pub fn evaluation_scope(&self) -> &str {
        &self.evaluation_scope
    }
    /// Owner-resolved `(property, revision)` handles assigned to this exact twin.
    pub fn geometry_basis(&self) -> (u64, u64) {
        self.geometry_basis
    }
    /// World convention shared by every accepted camera and native mesh.
    pub const fn coordinate_frame(&self) -> &'static str {
        "RH_Z_UP"
    }
}

/// Bounded UTF-8/JSON entry point with duplicate-key refusal and no filesystem I/O.
pub fn parse_scene_rig(
    bytes: &[u8],
    twin: &PropertyTwin,
    budget: &mut WorkBudget<'_>,
) -> Result<SceneRig, SceneRigError> {
    budget.charge(0)?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(SceneRigError::Limit);
    }
    budget.charge(bytes.len() as u64)?;
    let input = std::str::from_utf8(bytes).map_err(|_| SceneRigError::Format)?;
    let value = parse(input).map_err(|_| SceneRigError::Format)?;
    SceneRig::from_document(&value, twin, budget)
}

fn field<'a>(object: &'a BTreeMap<String, Value>, key: &str) -> Result<&'a Value, SceneRigError> {
    object.get(key).ok_or(SceneRigError::Format)
}

fn object<'a>(
    value: &'a Value,
    keys: &[&str],
) -> Result<&'a BTreeMap<String, Value>, SceneRigError> {
    let fields = value.object().ok_or(SceneRigError::Format)?;
    if fields.len() != keys.len() || fields.keys().any(|k| !keys.contains(&k.as_str())) {
        return Err(SceneRigError::Format);
    }
    Ok(fields)
}

fn text(value: &Value, limit: usize) -> Result<&str, SceneRigError> {
    let s = value.text().ok_or(SceneRigError::Format)?;
    if s.is_empty() || s.len() > limit {
        return Err(SceneRigError::Limit);
    }
    if s.trim() != s || s.chars().any(char::is_control) {
        return Err(SceneRigError::Format);
    }
    Ok(s)
}

fn unsigned(value: &Value) -> Result<u64, SceneRigError> {
    if !matches!(value, Value::Number(_)) {
        return Err(SceneRigError::Format);
    }
    value
        .integer()
        .and_then(|v| u64::try_from(v).ok())
        .ok_or(SceneRigError::Numeric)
}

fn identity(value: &Value) -> Result<u64, SceneRigError> {
    let id = unsigned(value)?;
    if id == 0 {
        Err(SceneRigError::Numeric)
    } else {
        Ok(id)
    }
}

fn number(value: &Value) -> Result<f64, SceneRigError> {
    let Value::Number(s) = value else {
        return Err(SceneRigError::Format);
    };
    let n: f64 = s.parse().map_err(|_| SceneRigError::Numeric)?;
    if !n.is_finite() || n.abs() > 1e12 {
        return Err(SceneRigError::Numeric);
    }
    Ok(if n == 0.0 { 0.0 } else { n })
}

fn vector(value: &Value) -> Result<[f64; 3], SceneRigError> {
    let a = value
        .array()
        .filter(|a| a.len() == 3)
        .ok_or(SceneRigError::Format)?;
    Ok([number(&a[0])?, number(&a[1])?, number(&a[2])?])
}

fn digest(value: &Value) -> Result<ContentDigest, SceneRigError> {
    let d = ContentDigest::parse(text(value, 71)?).map_err(|_| SceneRigError::Format)?;
    if d.algorithm() != DigestAlgorithm::Sha256 || d.bytes() == [0; 32] {
        return Err(SceneRigError::Format);
    }
    Ok(d)
}

fn read_camera(value: &Value, geometry: GeometryBasis) -> Result<SceneRigCamera, SceneRigError> {
    let fields = object(
        value,
        &[
            "camera",
            "calibration",
            "image_domain",
            "clock",
            "privacy_domain",
            "validity_ns",
            "source_object_id",
            "image_model",
            "world_to_camera",
            "intrinsics",
            "error",
            "status",
        ],
    )?;
    if text(field(fields, "image_model")?, 64)? != "undistorted_pinhole"
        || text(field(fields, "status")?, 64)? != "authored_nominal"
        || !matches!(field(fields, "error")?, Value::Null)
    {
        return Err(SceneRigError::Unsupported);
    }
    let validity = field(fields, "validity_ns")?
        .array()
        .filter(|a| a.len() == 2)
        .ok_or(SceneRigError::Format)?;
    let validity = [unsigned(&validity[0])?, unsigned(&validity[1])?];
    if validity[0] > validity[1] {
        return Err(SceneRigError::Numeric);
    }
    let extrinsics = object(
        field(fields, "world_to_camera")?,
        &["rotation", "translation"],
    )?;
    let rotation = field(extrinsics, "rotation")?
        .array()
        .filter(|a| a.len() == 3)
        .ok_or(SceneRigError::Format)?;
    let pose = RigidPose::new(
        [
            vector(&rotation[0])?,
            vector(&rotation[1])?,
            vector(&rotation[2])?,
        ],
        vector(field(extrinsics, "translation")?)?,
    )?;
    let intrinsics = object(
        field(fields, "intrinsics")?,
        &["width", "height", "fx", "fy", "cx", "cy"],
    )?;
    let width = u32::try_from(unsigned(field(intrinsics, "width")?)?)
        .map_err(|_| SceneRigError::Numeric)?;
    let height = u32::try_from(unsigned(field(intrinsics, "height")?)?)
        .map_err(|_| SceneRigError::Numeric)?;
    let intrinsics = PinholeIntrinsics::new(
        width,
        height,
        number(field(intrinsics, "fx")?)?,
        number(field(intrinsics, "fy")?)?,
        number(field(intrinsics, "cx")?)?,
        number(field(intrinsics, "cy")?)?,
    )?;
    Ok(SceneRigCamera {
        source_object_id: text(field(fields, "source_object_id")?, 256)?.to_owned(),
        privacy_domain: identity(field(fields, "privacy_domain")?)?,
        camera: TrackingCamera {
            geometry,
            camera: identity(field(fields, "camera")?)?,
            calibration: identity(field(fields, "calibration")?)?,
            image_domain: identity(field(fields, "image_domain")?)?,
            clock: identity(field(fields, "clock")?)?,
            validity,
            pose,
            intrinsics,
            error: None,
        },
    })
}

fn encode_camera(e: &mut CanonicalEncoder, row: &SceneRigCamera) {
    let c = row.camera;
    e.text(&row.source_object_id);
    for id in [
        c.camera,
        c.calibration,
        c.image_domain,
        c.clock,
        row.privacy_domain,
        c.validity[0],
        c.validity[1],
    ] {
        e.u64(id);
    }
    e.text("undistorted_pinhole");
    e.text("authored_nominal");
    e.bool(false); // The authored rig does not quantify calibration error.
    for v in c
        .pose
        .rotation()
        .into_iter()
        .flatten()
        .chain(c.pose.translation())
    {
        e.u64(if v == 0.0 { 0 } else { v.to_bits() });
    }
    for v in c.intrinsics.dimensions() {
        e.u32(v);
    }
    for v in c
        .intrinsics
        .focal_lengths()
        .into_iter()
        .chain(c.intrinsics.principal_point())
    {
        e.u64(if v == 0.0 { 0 } else { v.to_bits() });
    }
}

#[cfg(test)]
#[path = "scene_rig/tests.rs"]
mod tests;

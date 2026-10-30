#![forbid(unsafe_code)]
//! Strict, source-pinned local input. Pins are caller assertions, not fetched custody.

use std::collections::{BTreeMap, BTreeSet};
use fss_cli::json_input::Value;
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_geometry::{PinholeIntrinsics, RigidPose};
use fss_geometry::temporal_alignment::{ClockAlignmentPair, MAX_CLOCK_OFFSET_HYPOTHESES};
use fss_geometry::temporal_triangulation::{
    MAX_TEMPORAL_VIEWS, TemporalTriangulationOptions, TimedCalibratedView,
};
use fss_geometry::temporal_validation::IntervalCalibratedView;
use fss_geometry::triangulation::CalibratedView;
use super::{Result, failure};

pub const SCHEMA: &str = "fss.clock_alignment_query.v1";
#[derive(Clone)]
pub struct Camera {
    pub id: u64,
    pub clock: u64,
    pub calibration: ContentDigest,
    pub image_domain: ContentDigest,
    pub pose: RigidPose,
    pub intrinsics: PinholeIntrinsics,
}
pub struct Source {
    pub camera: u64,
    pub clock: u64,
    pub validation: bool,
    pub capture: [i128; 2],
    pub exposure: String,
    pub source: ContentDigest,
    pub evidence: ContentDigest,
}
pub struct Query {
    pub world: ContentDigest,
    pub association: ContentDigest,
    pub cameras: [Camera; 2],
    pub pair: ClockAlignmentPair,
    pub training: Vec<TimedCalibratedView>,
    pub validation: Vec<IntervalCalibratedView>,
    pub sources: Vec<Source>,
    pub offsets: Vec<i128>,
    pub options: TemporalTriangulationOptions,
}
fn fields<'a>(value: &'a Value, keys: &[&str]) -> Result<&'a BTreeMap<String, Value>> {
    let map = value.object().ok_or_else(|| failure("input", "expected object"))?;
    if map.len() != keys.len() || keys.iter().any(|key| !map.contains_key(*key)) {
        return Err(failure("input", "missing or unknown object field"));
    }
    Ok(map)
}
fn field<'a>(map: &'a BTreeMap<String, Value>, key: &str) -> Result<&'a Value> {
    map.get(key).ok_or_else(|| failure("input", "missing object field"))
}
fn text(value: &Value) -> Result<&str> {
    value.text().ok_or_else(|| failure("input", "expected string"))
}
pub fn digest(value: &str) -> Result<ContentDigest> {
    let digest = ContentDigest::parse(value).map_err(|_| failure("input", "invalid digest"))?;
    if digest.algorithm() != DigestAlgorithm::Sha256 {
        return Err(failure("input", "only SHA-256 pins are admitted"));
    }
    Ok(digest)
}
fn pin(value: &Value) -> Result<ContentDigest> { digest(text(value)?) }
fn integer(value: &Value) -> Result<i128> {
    value.integer().ok_or_else(|| failure("input", "expected exact integer"))
}
fn positive(value: &Value) -> Result<u64> {
    u64::try_from(integer(value)?).ok().filter(|v| *v != 0)
        .ok_or_else(|| failure("input", "expected positive bounded integer"))
}
fn number(value: &Value) -> Result<f64> {
    let Value::Number(text) = value else { return Err(failure("input", "expected numeric value")); };
    text.parse::<f64>().ok().filter(|v| v.is_finite())
        .ok_or_else(|| failure("input", "nonfinite or invalid numeric value"))
}
fn array(value: &Value, limit: usize) -> Result<&[Value]> {
    value.array().filter(|v| !v.is_empty() && v.len() <= limit)
        .ok_or_else(|| failure("input", "empty or oversized array"))
}
fn vector<const N: usize>(value: &Value) -> Result<[f64; N]> {
    let values = array(value, N)?;
    if values.len() != N { return Err(failure("input", "wrong vector length")); }
    let mut result = [0.0; N];
    for (slot, value) in result.iter_mut().zip(values) { *slot = number(value)?; }
    Ok(result)
}
fn camera(value: &Value) -> Result<Camera> {
    let f = fields(value, &["id", "clock", "calibration_digest", "image_domain", "intrinsics", "rotation", "center"])?;
    let k = fields(field(f, "intrinsics")?, &["width", "height", "fx", "fy", "cx", "cy"])?;
    let dimension = |name| -> Result<u32> {
        u32::try_from(positive(field(k, name)?)?).map_err(|_| failure("input", "image dimension overflow"))
    };
    let intrinsics = PinholeIntrinsics::new(dimension("width")?, dimension("height")?,
        number(field(k, "fx")?)?, number(field(k, "fy")?)?,
        number(field(k, "cx")?)?, number(field(k, "cy")?)?)
        .map_err(|_| failure("input", "invalid camera intrinsics"))?;
    let rows = array(field(f, "rotation")?, 3)?;
    if rows.len() != 3 { return Err(failure("input", "rotation needs three rows")); }
    let rotation = [vector(&rows[0])?, vector(&rows[1])?, vector(&rows[2])?];
    let pose = RigidPose::from_center(rotation, vector(field(f, "center")?)?)
        .map_err(|_| failure("input", "invalid camera pose"))?;
    Ok(Camera {
        id: positive(field(f, "id")?)?, clock: positive(field(f, "clock")?)?,
        calibration: pin(field(f, "calibration_digest")?)?, image_domain: pin(field(f, "image_domain")?)?,
        pose, intrinsics,
    })
}

pub fn query(value: &Value) -> Result<Query> {
    let f = fields(value, &["schema", "world_basis", "association_evidence", "reference_camera",
        "target_camera", "offsets_ns", "fit_options", "training", "validation"])?;
    if text(field(f, "schema")?)? != SCHEMA { return Err(failure("input", "unsupported query schema")); }
    let cameras = [camera(field(f, "reference_camera")?)?, camera(field(f, "target_camera")?)?];
    let pair = ClockAlignmentPair {
        reference_camera: cameras[0].id, target_camera: cameras[1].id,
        reference_clock: cameras[0].clock, target_clock: cameras[1].clock,
    };
    if pair.reference_camera == pair.target_camera || pair.reference_clock == pair.target_clock {
        return Err(failure("input", "two distinct cameras and clock generations are required"));
    }
    let o = fields(field(f, "fit_options")?, &["max_reprojection_pixels", "max_distance",
        "max_speed", "max_condition_number", "max_iterations"])?;
    let options = TemporalTriangulationOptions {
        max_reprojection_pixels: number(field(o, "max_reprojection_pixels")?)?,
        max_distance: number(field(o, "max_distance")?)?, max_speed: number(field(o, "max_speed")?)?,
        max_condition_number: number(field(o, "max_condition_number")?)?,
        max_iterations: usize::try_from(positive(field(o, "max_iterations")?)?)
            .map_err(|_| failure("input", "iteration bound overflow"))?,
    };
    let offsets = array(field(f, "offsets_ns")?, MAX_CLOCK_OFFSET_HYPOTHESES)?
        .iter().map(integer).collect::<Result<Vec<_>>>()?;
    let mut training = Vec::new();
    let mut validation = Vec::new();
    let mut sources = Vec::new();
    let mut exposures = BTreeSet::new();
    let mut source_membership = BTreeSet::new();
    let mut evidence_membership = BTreeSet::new();
    for (is_validation, name) in [(false, "training"), (true, "validation")] {
        for row in array(field(f, name)?, MAX_TEMPORAL_VIEWS)? {
            let time_field = if is_validation { "capture_interval_ns" } else { "capture_ns" };
            let r = fields(row, &["camera", "clock", time_field, "pixel", "sigma_pixels",
                "exposure", "source_digest", "evidence_digest"])?;
            let id = positive(field(r, "camera")?)?;
            let camera = cameras.iter().find(|c| c.id == id)
                .ok_or_else(|| failure("input", "observation camera is outside selected scope"))?;
            if positive(field(r, "clock")?)? != camera.clock {
                return Err(failure("input", "observation clock generation mismatch"));
            }
            let exposure = text(field(r, "exposure")?)?;
            if exposure.is_empty() || exposure.len() > 256 || exposure.trim() != exposure
                || exposure.chars().any(char::is_control)
            { return Err(failure("input", "invalid exposure label")); }
            let source = pin(field(r, "source_digest")?)?;
            let evidence = pin(field(r, "evidence_digest")?)?;
            if !exposures.insert((id, exposure.to_owned()))
                || !source_membership.insert((id, source))
                || !evidence_membership.insert(evidence)
            { return Err(failure("input", "reused source, evidence or exposure membership")); }
            let capture = if is_validation {
                let bounds = array(field(r, time_field)?, 2)?;
                if bounds.len() != 2 { return Err(failure("input", "capture interval needs two bounds")); }
                [integer(&bounds[0])?, integer(&bounds[1])?]
            } else { [integer(field(r, time_field)?)?; 2] };
            let view = CalibratedView {
                camera: id, pose: camera.pose, intrinsics: camera.intrinsics,
                pixel: vector(field(r, "pixel")?)?, sigma_pixels: number(field(r, "sigma_pixels")?)?,
            };
            if is_validation { validation.push(IntervalCalibratedView { view, capture_interval_ns: capture }); }
            else { training.push(TimedCalibratedView { view, capture_time_ns: capture[0] }); }
            sources.push(Source { camera: id, clock: camera.clock, validation: is_validation,
                capture, exposure: exposure.to_owned(), source, evidence });
        }
    }
    sources.sort_by(|a, b| (a.camera, a.capture, &a.exposure).cmp(&(b.camera, b.capture, &b.exposure)));
    Ok(Query { world: pin(field(f, "world_basis")?)?, association: pin(field(f, "association_evidence")?)?,
        cameras, pair, training, validation, sources, offsets, options })
}

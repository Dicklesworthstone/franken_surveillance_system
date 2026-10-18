#![forbid(unsafe_code)]
//! Strict bounded owner-input decoding. JSON is an interchange, not evidence authority.

use std::collections::{BTreeMap, BTreeSet};

use fss_cli::json_input::Value;
use fss_cli::scene_rig::SceneRig;
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_geometry::{
    GeometryBasis, temporal_triangulation::TemporalTriangulationOptions,
    triangulation::TriangulationOptions,
};
use fss_twin::{ContactObservation, multiview::FusionInput};

use super::{Result, input_error};

pub(super) const MAX_HYPOTHESES: usize = 64;
const MAX_OBSERVATIONS: usize = 128;
const MAX_TOTAL_OBSERVATIONS: usize = 2048;

pub(super) struct Query {
    pub privacy_domain: u64,
    pub clock: u64,
    pub clock_evidence: ContentDigest,
    pub reference_time_ns: u64,
    pub hypotheses: Vec<Hypothesis>,
}

pub(super) struct Hypothesis {
    pub id: String,
    pub association_evidence: ContentDigest,
    pub max_capture_span_ns: u64,
    pub motion: Motion,
    pub observations: Vec<Observation>,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Motion {
    Static(TriangulationOptions),
    Linear {
        velocity: [f64; 3],
        evidence: ContentDigest,
        options: TriangulationOptions,
    },
    InferLinear {
        max_capture_uncertainty_ns: u64,
        options: TemporalTriangulationOptions,
    },
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Observation {
    pub source_digest: ContentDigest,
    pub input: FusionInput,
}

fn fields<'a>(value: &'a Value, allowed: &[&str]) -> Result<&'a BTreeMap<String, Value>> {
    let fields = value
        .object()
        .ok_or_else(|| input_error("expected a JSON object"))?;
    if fields.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(input_error("unknown input field"));
    }
    Ok(fields)
}
fn required<'a>(fields: &'a BTreeMap<String, Value>, key: &'static str) -> Result<&'a Value> {
    fields
        .get(key)
        .ok_or_else(|| input_error(format!("missing field {key}")))
}
fn integer(value: &Value) -> Result<u64> {
    value
        .integer()
        .and_then(|n| u64::try_from(n).ok())
        .ok_or_else(|| input_error("expected an exact nonnegative integer"))
}
fn nonzero(value: &Value) -> Result<u64> {
    let n = integer(value)?;
    if n == 0 {
        return Err(input_error("identity must be nonzero"));
    }
    Ok(n)
}
fn real(value: &Value) -> Result<f64> {
    let Value::Number(text) = value else {
        return Err(input_error("expected a finite JSON number"));
    };
    text.parse::<f64>()
        .ok()
        .filter(|n| n.is_finite() && n.abs() <= 1e12)
        .ok_or_else(|| input_error("number must be finite and within the numeric bound"))
}
fn text(value: &Value) -> Result<&str> {
    value.text().ok_or_else(|| input_error("expected a string"))
}
fn fixed<const N: usize>(value: &Value) -> Result<[f64; N]> {
    let array = value
        .array()
        .filter(|a| a.len() == N)
        .ok_or_else(|| input_error("invalid numeric vector length"))?;
    let mut result = [0.0; N];
    for (a, b) in result.iter_mut().zip(array) {
        *a = real(b)?;
    }
    Ok(result)
}
fn interval(value: &Value) -> Result<[u64; 2]> {
    let array = value
        .array()
        .filter(|a| a.len() == 2)
        .ok_or_else(|| input_error("expected a capture interval"))?;
    let times = [integer(&array[0])?, integer(&array[1])?];
    if times[0] > times[1] {
        return Err(input_error("capture interval is reversed"));
    }
    Ok(times)
}
fn digest(value: &Value) -> Result<ContentDigest> {
    let value = ContentDigest::parse(text(value)?)
        .map_err(|_| input_error("expected a sha256 content digest"))?;
    if value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32] {
        return Err(input_error("expected a nonzero sha256 content digest"));
    }
    Ok(value)
}

/// Only obtain import expectations here. The shared rig reader validates all fields after import.
pub(super) fn twin_expectation(value: &Value) -> Result<([u8; 32], [u8; 32], GeometryBasis)> {
    let top = value
        .object()
        .ok_or_else(|| input_error("camera rig must be an object"))?;
    let basis = fields(required(top, "geometry_basis")?, &["property", "revision"])?;
    let basis = GeometryBasis::new(
        nonzero(required(basis, "property")?)?,
        nonzero(required(basis, "revision")?)?,
    )
    .map_err(|_| input_error("invalid property geometry basis"))?;
    Ok((
        digest(required(top, "twin_digest")?)?.bytes(),
        digest(required(top, "source_scene_digest")?)?.bytes(),
        basis,
    ))
}

pub(super) fn query(value: &Value, rig_digest: ContentDigest, rig: &SceneRig) -> Result<Query> {
    let top = fields(
        value,
        &[
            "schema",
            "camera_rig_digest",
            "privacy_domain",
            "clock",
            "clock_evidence",
            "reference_time_ns",
            "hypotheses",
        ],
    )?;
    if text(required(top, "schema")?)? != "fss.scene_fusion_query.v1" {
        return Err(input_error(
            "unsupported query schema; expected fss.scene_fusion_query.v1",
        ));
    }
    if digest(required(top, "camera_rig_digest")?)? != rig_digest {
        return Err(input_error(
            "camera rig bytes do not match the query's pinned digest",
        ));
    }
    let privacy_domain = nonzero(required(top, "privacy_domain")?)?;
    let clock = nonzero(required(top, "clock")?)?;
    let clock_evidence = digest(required(top, "clock_evidence")?)?;
    let reference_time_ns = integer(required(top, "reference_time_ns")?)?;
    let rows = required(top, "hypotheses")?
        .array()
        .filter(|a| !a.is_empty() && a.len() <= MAX_HYPOTHESES)
        .ok_or_else(|| input_error("query requires 1..=64 complete hypotheses"))?;
    let mut ids = BTreeSet::new();
    let mut total = 0;
    let mut hypotheses = Vec::new();
    for row in rows {
        let row = fields(
            row,
            &[
                "id",
                "association_evidence",
                "max_capture_span_ns",
                "motion",
                "triangulation",
                "observations",
            ],
        )?;
        let id = text(required(row, "id")?)?;
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'-' | b'_' | b'.'))
            || !ids.insert(id)
        {
            return Err(input_error(
                "hypothesis IDs must be unique bounded ASCII identifiers",
            ));
        }
        let motion = motion(required(row, "motion")?, row.get("triangulation"))?;
        let max_capture_span_ns = integer(required(row, "max_capture_span_ns")?)?;
        if max_capture_span_ns
            > if matches!(motion, Motion::InferLinear { .. }) {
                60_000_000_000
            } else {
                1_000_000_000
            }
        {
            return Err(input_error(
                "capture-span allowance exceeds the selected motion profile",
            ));
        }
        let sources = required(row, "observations")?
            .array()
            .filter(|a| !a.is_empty() && a.len() <= MAX_OBSERVATIONS)
            .ok_or_else(|| {
                input_error("hypothesis requires 1..=128 complete source observations")
            })?;
        if !matches!(motion, Motion::InferLinear { .. }) && sources.len() > 32 {
            return Err(input_error(
                "point fusion permits at most 32 camera observations",
            ));
        }
        total += sources.len();
        if total > MAX_TOTAL_OBSERVATIONS {
            return Err(input_error("query exceeds 2048 source observations"));
        }
        let mut observations = Vec::new();
        for source in sources {
            let source = fields(
                source,
                &[
                    "source_digest",
                    "evidence_digest",
                    "camera",
                    "track",
                    "exposure",
                    "image_domain",
                    "capture_ns",
                    "pixel_min",
                    "pixel_max",
                    "visible_contact",
                    "sigma_pixels",
                ],
            )?;
            let camera_id = nonzero(required(source, "camera")?)?;
            let camera = rig
                .camera(camera_id)
                .ok_or_else(|| input_error("observation names no camera in this rig"))?;
            if camera.privacy_domain != privacy_domain || camera.camera.clock != clock {
                return Err(input_error(
                    "observation camera does not share the requested privacy domain and clock",
                ));
            }
            let image_domain = nonzero(required(source, "image_domain")?)?;
            if camera.camera.image_domain != image_domain {
                return Err(input_error(
                    "observation image domain differs from the camera rig; rectification or a new rig is required",
                ));
            }
            observations.push(Observation {
                source_digest: digest(required(source, "source_digest")?)?,
                input: FusionInput {
                    camera: camera.camera,
                    privacy_domain,
                    sigma_pixels: real(required(source, "sigma_pixels")?)?,
                    observation: ContactObservation {
                        evidence: digest(required(source, "evidence_digest")?)?.bytes(),
                        track: nonzero(required(source, "track")?)?,
                        camera: camera_id,
                        exposure: nonzero(required(source, "exposure")?)?,
                        image_domain,
                        clock,
                        capture: interval(required(source, "capture_ns")?)?,
                        pixel_min: fixed(required(source, "pixel_min")?)?,
                        pixel_max: fixed(required(source, "pixel_max")?)?,
                        visible_contact: required(source, "visible_contact")?
                            .boolean()
                            .ok_or_else(|| {
                                input_error("visible_contact must be explicitly true or false")
                            })?,
                    },
                },
            });
        }
        observations.sort_by_key(|o| {
            let v = o.input.observation;
            (v.camera, v.capture, v.exposure, v.evidence)
        });
        hypotheses.push(Hypothesis {
            id: id.to_owned(),
            association_evidence: digest(required(row, "association_evidence")?)?,
            max_capture_span_ns,
            motion,
            observations,
        });
    }
    hypotheses.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(Query {
        privacy_domain,
        clock,
        clock_evidence,
        reference_time_ns,
        hypotheses,
    })
}

fn motion(value: &Value, options: Option<&Value>) -> Result<Motion> {
    let object = value
        .object()
        .ok_or_else(|| input_error("motion must be an object"))?;
    match text(required(object, "kind")?)? {
        "static" => {
            fields(value, &["kind"])?;
            Ok(Motion::Static(point_options(options)?))
        }
        "linear" => {
            let o = fields(value, &["kind", "velocity_per_second", "evidence"])?;
            Ok(Motion::Linear {
                velocity: fixed(required(o, "velocity_per_second")?)?,
                evidence: digest(required(o, "evidence")?)?,
                options: point_options(options)?,
            })
        }
        "infer_linear" => {
            let o = fields(value, &["kind", "max_capture_uncertainty_ns"])?;
            let max_capture_uncertainty_ns = integer(required(o, "max_capture_uncertainty_ns")?)?;
            if max_capture_uncertainty_ns > 60_000_000_000 {
                return Err(input_error(
                    "capture uncertainty allowance exceeds sixty seconds",
                ));
            }
            Ok(Motion::InferLinear {
                max_capture_uncertainty_ns,
                options: temporal_options(options)?,
            })
        }
        _ => Err(input_error(
            "motion kind must be static, linear, or infer_linear",
        )),
    }
}
fn point_options(value: Option<&Value>) -> Result<TriangulationOptions> {
    let mut options = TriangulationOptions::default();
    if let Some(value) = value {
        for (key, value) in fields(
            value,
            &[
                "min_views",
                "max_outliers",
                "max_reprojection_pixels",
                "min_ray_angle_radians",
                "max_distance",
                "max_condition_number",
                "max_iterations",
            ],
        )? {
            match key.as_str() {
                "min_views" => {
                    options.min_views = usize::try_from(integer(value)?)
                        .map_err(|_| input_error("view count overflow"))?
                }
                "max_outliers" => {
                    options.max_outliers = usize::try_from(integer(value)?)
                        .map_err(|_| input_error("outlier count overflow"))?
                }
                "max_reprojection_pixels" => options.max_reprojection_pixels = real(value)?,
                "min_ray_angle_radians" => options.min_ray_angle_radians = real(value)?,
                "max_distance" => options.max_distance = real(value)?,
                "max_condition_number" => options.max_condition_number = real(value)?,
                "max_iterations" => {
                    options.max_iterations = usize::try_from(integer(value)?)
                        .map_err(|_| input_error("iteration count overflow"))?
                }
                _ => unreachable!("checked keys"),
            }
        }
    }
    Ok(options)
}
fn temporal_options(value: Option<&Value>) -> Result<TemporalTriangulationOptions> {
    let mut options = TemporalTriangulationOptions::default();
    if let Some(value) = value {
        for (key, value) in fields(
            value,
            &[
                "max_reprojection_pixels",
                "max_distance",
                "max_speed",
                "max_condition_number",
                "max_iterations",
            ],
        )? {
            match key.as_str() {
                "max_reprojection_pixels" => options.max_reprojection_pixels = real(value)?,
                "max_distance" => options.max_distance = real(value)?,
                "max_speed" => options.max_speed = real(value)?,
                "max_condition_number" => options.max_condition_number = real(value)?,
                "max_iterations" => {
                    options.max_iterations = usize::try_from(integer(value)?)
                        .map_err(|_| input_error("iteration count overflow"))?
                }
                _ => unreachable!("checked keys"),
            }
        }
    }
    Ok(options)
}

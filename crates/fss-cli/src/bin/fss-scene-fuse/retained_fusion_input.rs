#![forbid(unsafe_code)]
//! Strict retained-observation selection and the pure source-to-scene transformation.
//!
//! This module never authenticates public data shapes. The command obtains bindings from the
//! sealed package owner and revalidates that owner before releasing a report. Source intervals,
//! dimensions and detector rows cannot be supplied by the query. Feature correspondence, camera
//! placement, source-image applicability and clock alignment remain explicit assumptions.

use std::collections::{BTreeMap, BTreeSet};

use fss_cli::json_input::{self, Value};
use fss_cli::json_output::{array, object, string};
use fss_cli::retained_continuity_query::parse_selection;
use fss_cli::retained_handoff_contract::{
    PackageHandoffBinding, PackageHandoffObservation, PackageHandoffRequest, camera_generation,
};
use fss_cli::scene_rig::SceneRig;
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_twin::{ContactObservation, multiview::FusionInput};

use super::{
    Result,
    input::{self, Hypothesis, Motion, Observation, Query},
    input_error,
};

pub(super) const SCHEMA: &str = "fss.scene_fusion_retained_query.v1";
const MAX_SOURCES: usize = 32;
const MAX_HYPOTHESES: usize = 64;
const MAX_OBSERVATIONS: usize = 128;
const MAX_TOTAL_OBSERVATIONS: usize = 2048;
const OBSERVATION_DOMAIN: &str = "fss.retained_scene_feature_observation.v1";

#[derive(Clone)]
struct CameraBinding {
    selection: String,
    camera: u64,
    camera_generation: ContentDigest,
    calibration: ContentDigest,
    image_domain: u64,
    mapping_basis: ContentDigest,
    image_domain_basis: ContentDigest,
}

#[derive(Clone)]
struct Feature {
    selection: String,
    segment: u64,
    detection_row: u64,
    capsule_digest: ContentDigest,
    pixel_min: [f64; 2],
    pixel_max: [f64; 2],
    visible_contact: bool,
    sigma_pixels: f64,
    contact_basis: ContentDigest,
}

struct SelectedHypothesis {
    id: String,
    association_evidence: ContentDigest,
    max_capture_span_ns: u64,
    motion: Motion,
    observations: Vec<Feature>,
}

/// Validated immutable selection; constructing this value grants no source authority.
pub(super) struct Parsed {
    /// Exact source-owner request, without an unrelated handoff-planning objective.
    pub request: PackageHandoffRequest,
    rig_semantic_digest: ContentDigest,
    privacy_domain: u64,
    clock: u64,
    reference_time_ns: u64,
    camera_bindings: BTreeMap<String, CameraBinding>,
    hypotheses: Vec<SelectedHypothesis>,
    declarations: String,
}

impl Parsed {
    /// Complete strict input, including feature, source-to-rig and image-domain assumptions.
    pub(super) fn declarations_json(&self) -> &str {
        &self.declarations
    }

    /// Query-local aliases have no durable identity meaning. Original digests stay in bindings.
    pub(super) fn track_aliases_json(&self) -> String {
        array(
            &self
                .camera_bindings
                .iter()
                .enumerate()
                .map(|(index, (id, binding))| {
                    object(&[
                        ("selection", string(id)),
                        ("track", string(&(index as u64 + 1).to_string())),
                        ("camera", string(&binding.camera.to_string())),
                        ("exposure_recipe", string("retained_segment_plus_one")),
                    ])
                })
                .collect::<Vec<_>>(),
        )
    }
}

fn fields<'a>(value: &'a Value, keys: &[&str]) -> Result<&'a BTreeMap<String, Value>> {
    let fields = value
        .object()
        .ok_or_else(|| input_error("expected a retained-fusion object"))?;
    if fields.keys().any(|key| !keys.contains(&key.as_str())) {
        return Err(input_error("unknown retained-fusion field"));
    }
    Ok(fields)
}

fn required<'a>(fields: &'a BTreeMap<String, Value>, key: &str) -> Result<&'a Value> {
    fields
        .get(key)
        .ok_or_else(|| input_error(format!("missing retained-fusion field {key}")))
}

fn text(value: &Value) -> Result<&str> {
    value
        .text()
        .ok_or_else(|| input_error("expected a retained-fusion string"))
}

fn id(value: &Value, maximum: usize) -> Result<String> {
    let value = text(value)?;
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":_.-".contains(&byte))
    {
        return Err(input_error("invalid retained-fusion identifier"));
    }
    Ok(value.to_owned())
}

fn unsigned(value: &Value) -> Result<u64> {
    let literal = match value {
        Value::Number(value) | Value::Text(value) => value,
        _ => return Err(input_error("expected an exact nonnegative integer")),
    };
    if literal.is_empty()
        || !literal.bytes().all(|byte| byte.is_ascii_digit())
        || (literal.len() > 1 && literal.starts_with('0'))
    {
        return Err(input_error("expected an exact nonnegative integer"));
    }
    literal
        .parse()
        .map_err(|_| input_error("retained-fusion integer exceeds u64"))
}

fn nonzero(value: &Value) -> Result<u64> {
    let value = unsigned(value)?;
    if value == 0 {
        Err(input_error("retained-fusion identity must be nonzero"))
    } else {
        Ok(value)
    }
}

fn digest(value: &Value) -> Result<ContentDigest> {
    let value = ContentDigest::parse(text(value)?)
        .map_err(|_| input_error("invalid retained-fusion digest"))?;
    if value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32] {
        return Err(input_error("expected a nonzero SHA-256 content digest"));
    }
    Ok(value)
}

fn real(value: &Value) -> Result<f64> {
    let Value::Number(value) = value else {
        return Err(input_error("expected a finite JSON number"));
    };
    let value = value
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite() && value.abs() <= 1e12)
        .ok_or_else(|| input_error("retained-fusion number exceeds its finite bound"))?;
    Ok(if value == 0.0 { 0.0 } else { value })
}

fn pixel(value: &Value) -> Result<[f64; 2]> {
    let values = list(value, 2)?;
    if values.len() != 2 {
        return Err(input_error(
            "feature pixel requires exactly two coordinates",
        ));
    }
    Ok([real(&values[0])?, real(&values[1])?])
}

fn list(value: &Value, maximum: usize) -> Result<&[Value]> {
    value
        .array()
        .filter(|values| !values.is_empty() && values.len() <= maximum)
        .ok_or_else(|| input_error("retained-fusion array is empty or exceeds its bound"))
}

fn json(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.clone(),
        Value::Text(value) => string(value),
        Value::Array(values) => array(&values.iter().map(json).collect::<Vec<_>>()),
        Value::Object(fields) => object(
            &fields
                .iter()
                .map(|(key, value)| (key.as_str(), json(value)))
                .collect::<Vec<_>>(),
        ),
    }
}

/// Parse before any source is read. Source facts, arbitrary paths and replacement timestamps
/// are not part of this grammar. Solver policies reuse the existing scene-query owner.
pub(super) fn parse(bytes: &[u8], rig_digest: ContentDigest, rig: &SceneRig) -> Result<Parsed> {
    if bytes.len() > json_input::MAX_INPUT_BYTES {
        return Err(input_error("retained-fusion input exceeds 1 MiB"));
    }
    let document = json_input::parse(
        std::str::from_utf8(bytes)
            .map_err(|_| input_error("retained-fusion input is not UTF-8"))?,
    )
    .map_err(|_| input_error("malformed retained-fusion JSON"))?;
    let top = fields(
        &document,
        &[
            "schema",
            "session",
            "generation",
            "clock_evidence",
            "camera_rig_digest",
            "privacy_domain",
            "clock",
            "reference_time_ns",
            "selections",
            "camera_bindings",
            "hypotheses",
        ],
    )?;
    if text(required(top, "schema")?)? != SCHEMA
        || digest(required(top, "camera_rig_digest")?)? != rig_digest
    {
        return Err(input_error(
            "retained-fusion schema or exact camera-rig pin mismatch",
        ));
    }
    let privacy_domain = nonzero(required(top, "privacy_domain")?)?;
    let clock = nonzero(required(top, "clock")?)?;
    let reference_time_ns = unsigned(required(top, "reference_time_ns")?)?;
    let mut request = PackageHandoffRequest {
        session: id(required(top, "session")?, 256)?,
        generation: digest(required(top, "generation")?)?,
        clock: digest(required(top, "clock_evidence")?)?,
        cost_unit: "retained_scene_source_selection".into(),
        birth_cost: 0,
        end_cost: 0,
        k: 1,
        selections: list(required(top, "selections")?, MAX_SOURCES)?
            .iter()
            .map(|value| parse_selection(value).map_err(input_error))
            .collect::<Result<_>>()?,
        transitions: Vec::new(),
    };
    request
        .validate()
        .map_err(|_| input_error("invalid retained source selections"))?;
    request
        .selections
        .sort_by(|left, right| left.id.cmp(&right.id));
    let selected: BTreeMap<_, _> = request
        .selections
        .iter()
        .map(|selection| (selection.id.as_str(), selection))
        .collect();
    let mut camera_bindings = BTreeMap::new();
    for value in list(required(top, "camera_bindings")?, MAX_SOURCES)? {
        let row = fields(
            value,
            &[
                "selection",
                "camera",
                "camera_generation",
                "calibration",
                "image_domain",
                "mapping_basis",
                "image_domain_basis",
            ],
        )?;
        let binding = CameraBinding {
            selection: id(required(row, "selection")?, 256)?,
            camera: nonzero(required(row, "camera")?)?,
            camera_generation: digest(required(row, "camera_generation")?)?,
            calibration: digest(required(row, "calibration")?)?,
            image_domain: nonzero(required(row, "image_domain")?)?,
            mapping_basis: digest(required(row, "mapping_basis")?)?,
            image_domain_basis: digest(required(row, "image_domain_basis")?)?,
        };
        let source = selected
            .get(binding.selection.as_str())
            .ok_or_else(|| input_error("camera mapping names no selected source"))?;
        let camera = rig
            .camera(binding.camera)
            .ok_or_else(|| input_error("camera mapping names no camera in the rig"))?;
        if binding.calibration != source.calibration
            || binding.image_domain != camera.camera.image_domain
            || camera.privacy_domain != privacy_domain
            || camera.camera.clock != clock
            || camera_bindings
                .insert(binding.selection.clone(), binding)
                .is_some()
        {
            return Err(input_error(
                "duplicate or incompatible source-to-camera mapping",
            ));
        }
    }
    if camera_bindings.len() != selected.len() {
        return Err(input_error(
            "every selected source requires exactly one camera mapping",
        ));
    }
    let mut hypotheses = Vec::new();
    let mut ids = BTreeSet::new();
    let mut used = BTreeSet::new();
    let mut total = 0_usize;
    for value in list(required(top, "hypotheses")?, MAX_HYPOTHESES)? {
        let row = fields(
            value,
            &[
                "id",
                "association_evidence",
                "max_capture_span_ns",
                "motion",
                "triangulation",
                "observations",
            ],
        )?;
        let id = id(required(row, "id")?, 128)?;
        if !ids.insert(id.clone()) {
            return Err(input_error("duplicate retained-fusion hypothesis ID"));
        }
        let motion = input::motion(required(row, "motion")?, row.get("triangulation"))?;
        let max_capture_span_ns = unsigned(required(row, "max_capture_span_ns")?)?;
        let infer_motion = matches!(motion, Motion::InferLinear { .. });
        if max_capture_span_ns
            > if infer_motion {
                60_000_000_000
            } else {
                1_000_000_000
            }
        {
            return Err(input_error(
                "capture span exceeds the selected motion profile",
            ));
        }
        let mut observations = Vec::new();
        let mut original_rows = BTreeSet::new();
        for value in list(
            required(row, "observations")?,
            if infer_motion { MAX_OBSERVATIONS } else { 32 },
        )? {
            total += 1;
            if total > MAX_TOTAL_OBSERVATIONS {
                return Err(input_error(
                    "retained-fusion query exceeds 2048 observations",
                ));
            }
            let feature = feature(value)?;
            let mapping = camera_bindings
                .get(&feature.selection)
                .ok_or_else(|| input_error("feature names no mapped source selection"))?;
            let camera = rig
                .camera(mapping.camera)
                .ok_or_else(|| input_error("feature camera is unavailable"))?;
            if !camera.camera.intrinsics.contains(feature.pixel_min)
                || !camera.camera.intrinsics.contains(feature.pixel_max)
                || !original_rows.insert((
                    feature.selection.clone(),
                    feature.segment,
                    feature.detection_row,
                ))
            {
                return Err(input_error(
                    "feature is outside the image or reuses a source row",
                ));
            }
            used.insert(feature.selection.clone());
            observations.push(feature);
        }
        hypotheses.push(SelectedHypothesis {
            id,
            association_evidence: digest(required(row, "association_evidence")?)?,
            max_capture_span_ns,
            motion,
            observations,
        });
    }
    if used.len() != selected.len() {
        return Err(input_error(
            "each selected source must contribute a declared feature",
        ));
    }
    hypotheses.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(Parsed {
        request,
        rig_semantic_digest: rig.digest(),
        privacy_domain,
        clock,
        reference_time_ns,
        camera_bindings,
        hypotheses,
        declarations: json(&document),
    })
}

fn feature(value: &Value) -> Result<Feature> {
    let row = fields(
        value,
        &[
            "selection",
            "segment",
            "detection_row",
            "capsule_digest",
            "pixel_min",
            "pixel_max",
            "visible_contact",
            "sigma_pixels",
            "contact_basis",
        ],
    )?;
    let feature = Feature {
        selection: id(required(row, "selection")?, 256)?,
        segment: unsigned(required(row, "segment")?)?,
        detection_row: unsigned(required(row, "detection_row")?)?,
        capsule_digest: digest(required(row, "capsule_digest")?)?,
        pixel_min: pixel(required(row, "pixel_min")?)?,
        pixel_max: pixel(required(row, "pixel_max")?)?,
        visible_contact: required(row, "visible_contact")?
            .boolean()
            .ok_or_else(|| input_error("visible_contact requires an explicit boolean"))?,
        sigma_pixels: real(required(row, "sigma_pixels")?)?,
        contact_basis: digest(required(row, "contact_basis")?)?,
    };
    if feature
        .pixel_min
        .iter()
        .zip(feature.pixel_max)
        .any(|(lo, hi)| *lo > hi)
        || !(1e-3..=1e3).contains(&feature.sigma_pixels)
        || feature.segment == u64::MAX
    {
        return Err(input_error(
            "invalid feature rectangle, noise, or source segment",
        ));
    }
    Ok(feature)
}

/// Convert descriptive bindings from the sealed source owner into the existing native query.
/// Passing caller-made public bindings tests this transformation; it does not establish custody.
pub(super) fn build_query(
    parsed: &Parsed,
    bindings: &[PackageHandoffBinding],
    rig: &SceneRig,
) -> Result<Query> {
    if rig.digest() != parsed.rig_semantic_digest
        || bindings.len() != parsed.request.selections.len()
    {
        return Err(input_error(
            "retained scene rig or complete source set changed",
        ));
    }
    let mut sources = BTreeMap::new();
    let mut by_camera = BTreeMap::new();
    let mut by_sensor = BTreeMap::new();
    for binding in bindings {
        let mapping = parsed
            .camera_bindings
            .get(&binding.id)
            .ok_or_else(|| input_error("unselected source binding"))?;
        let selection = parsed
            .request
            .selections
            .iter()
            .find(|s| s.id == binding.id)
            .ok_or_else(|| input_error("unselected source binding"))?;
        let camera = rig
            .camera(mapping.camera)
            .ok_or_else(|| input_error("bound scene camera is unavailable"))?;
        if sources.insert(binding.id.as_str(), binding).is_some()
            || binding.report_digest != selection.report_digest
            || binding.track != selection.track
            || binding.label != selection.label
            || binding.tracking != selection.tracking
            || binding.alignment != selection.alignment
            || binding.import_identity != selection.alignment.import_identity
            || binding.stream_id != selection.alignment.stream_id
            || binding.clock_basis != selection.alignment.clock_basis
            || binding.calibration != mapping.calibration
            || binding.camera_generation != mapping.camera_generation
            || binding.dimensions != camera.camera.intrinsics.dimensions()
            || binding.camera_generation
                != camera_generation(&binding.sensor_id, &binding.stream_id, binding.dimensions)
                    .map_err(|_| input_error("invalid source camera generation"))?
            || binding.observations.is_empty()
            || binding.observations.len() > 64
        {
            return Err(input_error(
                "retained source does not match its exact camera mapping",
            ));
        }
        let identity = (
            binding.sensor_id.as_str(),
            binding.stream_id.as_str(),
            binding.import_identity,
            binding.camera_generation,
            binding.calibration,
        );
        // A physical source cannot count as several scene cameras. One camera also cannot
        // silently change import/stream mode underneath segment-derived exposure aliases.
        if by_camera
            .insert(mapping.camera, identity)
            .is_some_and(|old| old != identity)
            || by_sensor
                .insert(binding.sensor_id.as_str(), mapping.camera)
                .is_some_and(|old| old != mapping.camera)
        {
            return Err(input_error(
                "source-to-camera mapping is not consistent and one-to-one",
            ));
        }
    }
    let aliases: BTreeMap<_, _> = parsed
        .camera_bindings
        .keys()
        .enumerate()
        .map(|(index, id)| (id.as_str(), index as u64 + 1))
        .collect();
    let mut hypotheses = Vec::new();
    for hypothesis in &parsed.hypotheses {
        let mut observations = Vec::new();
        let mut exposures = BTreeSet::new();
        for feature in &hypothesis.observations {
            let binding = sources
                .get(feature.selection.as_str())
                .ok_or_else(|| input_error("selected retained source is unavailable"))?;
            let mapping = parsed
                .camera_bindings
                .get(&feature.selection)
                .ok_or_else(|| input_error("selected camera mapping is unavailable"))?;
            let camera = rig
                .camera(mapping.camera)
                .ok_or_else(|| input_error("selected scene camera is unavailable"))?;
            let mut matches = binding.observations.iter().filter(|observation| {
                observation.segment == feature.segment
                    && observation.detection_row == feature.detection_row
                    && observation.capsule_digest == feature.capsule_digest
            });
            let source = matches
                .next()
                .ok_or_else(|| input_error("exact retained feature row is unavailable"))?;
            if matches.next().is_some() || !exposures.insert((mapping.camera, source.segment)) {
                return Err(input_error("retained feature reuses a camera exposure"));
            }
            let [x0, y0, x1, y1] = source.bounds.map(|value| f64::from(value) / 256.0);
            let aligned = binding
                .alignment
                .align(source.capture)
                .map_err(|_| input_error("source capture cannot be conservatively aligned"))?;
            if aligned != source.aligned_capture
                || aligned[0] < 0
                || source.class_index != binding.class_index
                || x0 >= x1
                || y0 >= y1
                || feature.pixel_min[0] < x0
                || feature.pixel_min[1] < y0
                || feature.pixel_max[0] > x1
                || feature.pixel_max[1] > y1
            {
                return Err(input_error(
                    "feature leaves its retained detector bounds or capture basis",
                ));
            }
            let capture = [
                u64::try_from(aligned[0])
                    .map_err(|_| input_error("negative aligned capture is unsupported"))?,
                u64::try_from(aligned[1])
                    .map_err(|_| input_error("negative aligned capture is unsupported"))?,
            ];
            let track = *aliases
                .get(feature.selection.as_str())
                .ok_or_else(|| input_error("query-local track alias is unavailable"))?;
            let exposure = source
                .segment
                .checked_add(1)
                .ok_or_else(|| input_error("source exposure alias overflow"))?;
            observations.push(Observation {
                source_digest: source.source_digest,
                input: FusionInput {
                    camera: camera.camera,
                    privacy_domain: parsed.privacy_domain,
                    sigma_pixels: feature.sigma_pixels,
                    observation: ContactObservation {
                        evidence: observation_digest(parsed, binding, source, mapping, feature)?
                            .bytes(),
                        track,
                        camera: mapping.camera,
                        exposure,
                        image_domain: mapping.image_domain,
                        clock: parsed.clock,
                        capture,
                        pixel_min: feature.pixel_min,
                        pixel_max: feature.pixel_max,
                        visible_contact: feature.visible_contact,
                    },
                },
            });
        }
        observations.sort_by_key(|value| {
            let o = value.input.observation;
            (o.camera, o.capture, o.exposure, o.evidence)
        });
        hypotheses.push(Hypothesis {
            id: hypothesis.id.clone(),
            association_evidence: hypothesis.association_evidence,
            max_capture_span_ns: hypothesis.max_capture_span_ns,
            motion: hypothesis.motion,
            observations,
        });
    }
    Ok(Query {
        privacy_domain: parsed.privacy_domain,
        clock: parsed.clock,
        clock_evidence: parsed.request.clock,
        reference_time_ns: parsed.reference_time_ns,
        hypotheses,
    })
}

fn observation_digest(
    parsed: &Parsed,
    binding: &PackageHandoffBinding,
    source: &PackageHandoffObservation,
    mapping: &CameraBinding,
    feature: &Feature,
) -> Result<ContentDigest> {
    let mut e = CanonicalEncoder::new();
    e.text(OBSERVATION_DOMAIN);
    for digest in [
        parsed.rig_semantic_digest,
        parsed.request.clock,
        binding.alignment.basis,
        binding.report_digest,
        binding.analysis_digest,
        binding.record_digest,
        binding.retained_root,
        binding.import_identity,
        binding.import_root,
        binding.track,
        binding.camera_generation,
        binding.calibration,
        binding.model,
        binding.privacy_binding,
        source.capsule_digest,
        source.source_digest,
        source.inference_identity,
        source.output_digest,
        source.detection_report_digest,
        mapping.mapping_basis,
        mapping.image_domain_basis,
        feature.contact_basis,
    ] {
        e.digest(digest);
    }
    e.u64(parsed.clock);
    e.u64(parsed.privacy_domain);
    e.text(binding.clock_basis.as_str());
    for value in binding.alignment.offset_ns {
        e.i128(i128::from(value));
    }
    e.u64(source.segment);
    e.u64(source.detection_row);
    e.u64(source.class_index);
    e.u32(source.score_bits);
    for value in source.bounds {
        e.u32(value);
    }
    for value in source.capture {
        e.i128(value);
    }
    for value in source.aligned_capture {
        e.i128(i128::from(value));
    }
    e.bool(source.confirmed);
    e.u64(mapping.camera);
    e.u64(mapping.image_domain);
    for value in feature.pixel_min.into_iter().chain(feature.pixel_max) {
        e.u64(value.to_bits());
    }
    e.u64(feature.sigma_pixels.to_bits());
    e.bool(feature.visible_contact);
    let bytes = e
        .finish_checked()
        .map_err(|_| input_error("retained feature identity exceeds encoding bound"))?;
    Ok(ContentDigest::sha256(&bytes))
}

#[cfg(test)]
#[path = "retained_fusion_input_tests.rs"]
mod tests;

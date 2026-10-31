#![forbid(unsafe_code)]
//! Exact local-image declarations. No file path or source authority is read from JSON.

use std::collections::BTreeMap;

use fss_cli::json_input::{self, Value};
use fss_cli::json_output::{array, object, string};
use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_twin::feature_association::AssociationOptions;
use fss_twin::localization::native::ExtractionOptions;

use super::super::{Result, input as fusion_input, input_error};

pub(super) const SCHEMA: &str = "fss.scene_feature_match_query.v1";

#[derive(Clone, Copy)]
pub(super) enum Mask {
    AllAllowed,
    File(ContentDigest),
}

#[derive(Clone, Copy)]
pub(super) struct View {
    pub camera: u64,
    pub source_digest: ContentDigest,
    pub image_domain_digest: ContentDigest,
    pub mapping_basis: ContentDigest,
    pub capture: [u64; 2],
    pub sigma_pixels: f64,
    pub interpretation: ComponentInterpretation,
    pub mask: Mask,
}

pub(super) struct Query {
    pub views: [View; 2],
    pub extraction: ExtractionOptions,
    pub matching: AssociationOptions,
    pub declarations: String,
}

fn fields<'a>(value: &'a Value, allowed: &[&str]) -> Result<&'a BTreeMap<String, Value>> {
    let fields = value
        .object()
        .ok_or_else(|| input_error("expected a matching object"))?;
    if fields.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(input_error("unknown matching field"));
    }
    Ok(fields)
}
fn get<'a>(fields: &'a BTreeMap<String, Value>, key: &str) -> Result<&'a Value> {
    fields
        .get(key)
        .ok_or_else(|| input_error(format!("missing matching field {key}")))
}
fn text(value: &Value) -> Result<&str> {
    value
        .text()
        .ok_or_else(|| input_error("expected a matching string"))
}
fn unsigned(value: &Value, minimum: u64, maximum: u64) -> Result<u64> {
    let literal = match value {
        Value::Number(s) | Value::Text(s) => s,
        _ => return Err(input_error("expected an exact unsigned integer")),
    };
    if literal.is_empty()
        || !literal.bytes().all(|b| b.is_ascii_digit())
        || (literal.len() > 1 && literal.starts_with('0'))
    {
        return Err(input_error("expected a canonical unsigned integer"));
    }
    literal
        .parse::<u64>()
        .ok()
        .filter(|n| (minimum..=maximum).contains(n))
        .ok_or_else(|| input_error("matching integer exceeds its bound"))
}
fn digest(value: &Value) -> Result<ContentDigest> {
    let d =
        ContentDigest::parse(text(value)?).map_err(|_| input_error("invalid matching digest"))?;
    if d.algorithm() != DigestAlgorithm::Sha256 || d.bytes() == [0; 32] {
        return Err(input_error("matching requires a nonzero SHA-256 pin"));
    }
    Ok(d)
}
fn real(value: &Value, minimum: f64, maximum: f64) -> Result<f64> {
    let Value::Number(s) = value else {
        return Err(input_error("expected a finite JSON number"));
    };
    s.parse::<f64>()
        .ok()
        .filter(|n| n.is_finite() && (minimum..=maximum).contains(n))
        .map(|n| if n == 0.0 { 0.0 } else { n })
        .ok_or_else(|| input_error("matching number exceeds its finite bound"))
}
fn view(value: &Value) -> Result<View> {
    let row = fields(
        value,
        &[
            "camera",
            "source_digest",
            "image_domain_digest",
            "mapping_basis",
            "capture_ns",
            "sigma_pixels",
            "component_interpretation",
            "mask",
        ],
    )?;
    let times = get(row, "capture_ns")?
        .array()
        .filter(|a| a.len() == 2)
        .ok_or_else(|| input_error("capture_ns requires both full interval endpoints"))?;
    let capture = [
        unsigned(&times[0], 0, u64::MAX)?,
        unsigned(&times[1], 0, u64::MAX)?,
    ];
    if capture[0] > capture[1] {
        return Err(input_error("capture interval is reversed"));
    }
    let mask = fields(get(row, "mask")?, &["kind", "digest"])?;
    let mask = match text(get(mask, "kind")?)? {
        "all_allowed" if mask.len() == 1 => Mask::AllAllowed,
        "file" if mask.len() == 2 => Mask::File(digest(get(mask, "digest")?)?),
        _ => {
            return Err(input_error(
                "mask must explicitly select all_allowed or a pinned mask file",
            ));
        }
    };
    let interpretation = match text(get(row, "component_interpretation")?)? {
        "grayscale" => ComponentInterpretation::Grayscale,
        "ycbcr" => ComponentInterpretation::YCbCr,
        _ => {
            return Err(input_error(
                "component interpretation must be grayscale or ycbcr",
            ));
        }
    };
    Ok(View {
        camera: unsigned(get(row, "camera")?, 1, u64::MAX)?,
        source_digest: digest(get(row, "source_digest")?)?,
        image_domain_digest: digest(get(row, "image_domain_digest")?)?,
        mapping_basis: digest(get(row, "mapping_basis")?)?,
        capture,
        sigma_pixels: real(get(row, "sigma_pixels")?, 0.001, 1000.0)?,
        interpretation,
        mask,
    })
}

fn json(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(v) => v.to_string(),
        Value::Number(v) => v.clone(),
        Value::Text(v) => string(v),
        Value::Array(v) => array(&v.iter().map(json).collect::<Vec<_>>()),
        Value::Object(v) => object(
            &v.iter()
                .map(|(k, v)| (k.as_str(), json(v)))
                .collect::<Vec<_>>(),
        ),
    }
}

pub(super) fn parse(bytes: &[u8], rig_digest: ContentDigest) -> Result<Query> {
    let value = json_input::parse(
        std::str::from_utf8(bytes).map_err(|_| input_error("matching query must be UTF-8"))?,
    )
    .map_err(|_| input_error("malformed matching query"))?;
    let top = fields(
        &value,
        &[
            "schema",
            "camera_rig_digest",
            "privacy_domain",
            "clock",
            "clock_evidence",
            "association_basis",
            "reference_time_ns",
            "max_capture_span_ns",
            "motion",
            "left",
            "right",
            "extraction",
            "matching",
            "triangulation",
        ],
    )?;
    if text(get(top, "schema")?)? != SCHEMA || digest(get(top, "camera_rig_digest")?)? != rig_digest
    {
        return Err(input_error(
            "matching schema or exact rig document pin differs",
        ));
    }
    if text(get(top, "motion")?)? != "static_during_capture_hull" {
        return Err(input_error(
            "automatic image matching requires an explicit static-scene assumption",
        ));
    }
    let extraction = fields(
        get(top, "extraction")?,
        &["threshold", "maximum_features", "separation"],
    )?;
    let extraction = ExtractionOptions {
        threshold: unsigned(get(extraction, "threshold")?, 1, 254)? as u8,
        maximum_features: unsigned(get(extraction, "maximum_features")?, 1, 128)? as usize,
        separation: unsigned(get(extraction, "separation")?, 1, 128)? as u16,
    };
    let policy = fields(
        get(top, "matching")?,
        &[
            "maximum_hamming_distance",
            "ratio_percent",
            "maximum_epipolar_distance_pixels",
        ],
    )?;
    let motion = Value::Object(BTreeMap::from([(
        "kind".into(),
        Value::Text("static".into()),
    )]));
    if let Some(triangulation) = top.get("triangulation").and_then(Value::object) {
        for (key, minimum, maximum) in [
            ("min_views", 2, 2),
            ("max_outliers", 0, 0),
            ("max_iterations", 1, 32),
        ] {
            if let Some(value) = triangulation.get(key) {
                unsigned(value, minimum, maximum)?;
            }
        }
    }
    let fusion_input::Motion::Static(triangulation) =
        fusion_input::motion(&motion, top.get("triangulation"))?
    else {
        return Err(input_error("unsupported matching motion policy"));
    };
    if triangulation.min_views != 2 || triangulation.max_outliers != 0 {
        return Err(input_error(
            "two-view matching requires both views with no omitted camera",
        ));
    }
    let matching = AssociationOptions {
        association_basis: digest(get(top, "association_basis")?)?.bytes(),
        camera_rig_digest: rig_digest.bytes(),
        privacy_domain: unsigned(get(top, "privacy_domain")?, 1, u64::MAX)?,
        clock: unsigned(get(top, "clock")?, 1, u64::MAX)?,
        clock_evidence: digest(get(top, "clock_evidence")?)?.bytes(),
        reference_time_ns: unsigned(get(top, "reference_time_ns")?, 0, u64::MAX)?,
        max_capture_span_ns: unsigned(get(top, "max_capture_span_ns")?, 0, 1_000_000_000)?,
        maximum_hamming_distance: unsigned(get(policy, "maximum_hamming_distance")?, 0, 256)?
            as u16,
        ratio_percent: unsigned(get(policy, "ratio_percent")?, 1, 99)? as u8,
        maximum_epipolar_distance_pixels: real(
            get(policy, "maximum_epipolar_distance_pixels")?,
            0.000001,
            1000.0,
        )?,
        triangulation,
    };
    let views = [view(get(top, "left")?)?, view(get(top, "right")?)?];
    if views[0].camera == views[1].camera || views[0].source_digest == views[1].source_digest {
        return Err(input_error(
            "matching requires two distinct cameras and original image byte identities",
        ));
    }
    Ok(Query {
        views,
        extraction,
        matching,
        declarations: json(&value),
    })
}

#[cfg(test)]
#[path = "input_tests.rs"]
mod tests;

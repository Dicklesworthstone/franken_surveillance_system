#![forbid(unsafe_code)]
//! Strict retained selections and a pure source-to-rig binding adapter.
//!
//! Parsing and binding do not authenticate custody. The CLI constructs each
//! `ResolvedFrame` only from the sealed retained-feature owner, then revalidates
//! that owner after geometry. No source capture time, image size, privacy mask,
//! decoded pixels or feature coordinates can be supplied by this query.

use std::collections::{BTreeMap, BTreeSet};

use fss_cli::json_input::{self, Value};
use fss_cli::json_output::{array, object, string};
use fss_cli::retained_handoff_contract::PackageClockAlignment;
use fss_cli::scene_rig::SceneRig;
use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::{
    CanonicalEncode, ClockBasis, ContentDigest, DigestAlgorithm, SensorCapsule, SensorId, StreamId,
};
use fss_twin::feature_association::{AssociationOptions, FeatureView};
use fss_twin::localization::FeatureFrame;
use fss_twin::localization::native::ExtractionOptions;
use fss_twin::rectification::{RectificationReceipt, RectificationSpec};

use super::super::{Result, input as fusion_input, input_error};
use super::images::{self, ImageDeclaration};

pub(super) const SCHEMA: &str = "fss.scene_feature_match_retained_query.v1";
pub(super) const SCHEMA_V2: &str = "fss.scene_feature_match_retained_query.v2";
pub(super) const MAX_VIDEO_SEGMENTS: usize = 64;

/// Exact identities selected before the source owner opens a retained recording.
#[derive(Clone, Debug)]
pub(super) struct SourcePins {
    pub import_identity: ContentDigest,
    pub segment: usize,
    pub capsule_digest: ContentDigest,
    pub encoded_source_digest: ContentDigest,
    pub sensor_id: String,
}

/// Decoder selection is explicit; no query can request an external decoder.
#[derive(Clone, Debug)]
pub(super) enum Source {
    Jpeg {
        pins: SourcePins,
        interpretation: ComponentInterpretation,
    },
    H264 {
        pins: SourcePins,
        first_segment: usize,
        segment_count: usize,
    },
    H265 {
        pins: SourcePins,
        first_segment: usize,
        segment_count: usize,
    },
}

impl Source {
    pub(super) fn pins(&self) -> &SourcePins {
        match self {
            Self::Jpeg { pins, .. } | Self::H264 { pins, .. } | Self::H265 { pins, .. } => pins,
        }
    }

    fn range(&self) -> (&'static str, u64, u64) {
        match self {
            Self::Jpeg { pins, .. } => ("jpeg", pins.segment as u64, 1),
            Self::H264 {
                first_segment,
                segment_count,
                ..
            } => ("h264", *first_segment as u64, *segment_count as u64),
            Self::H265 {
                first_segment,
                segment_count,
                ..
            } => ("h265", *first_segment as u64, *segment_count as u64),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct View {
    pub camera: u64,
    pub image: ImageDeclaration,
    pub mapping_basis: ContentDigest,
    pub sigma_pixels: f64,
    pub source: Source,
    pub alignment: PackageClockAlignment,
}

pub(super) struct Query {
    pub version: u8,
    pub views: [View; 2],
    pub extraction: ExtractionOptions,
    pub matching: AssociationOptions,
    pub declarations: String,
}

/// Shared strict policy and complete declarations for explicit retained query shapes.
pub(super) struct Header {
    pub version: u8,
    pub document: Value,
    pub extraction: ExtractionOptions,
    pub matching: AssociationOptions,
    pub declarations: String,
}

/// Borrowed immutable snapshot supplied exclusively by the sealed source owner.
/// Public fields make the adapter testable; this type itself confers no custody.
pub(super) struct ResolvedFrame<'a> {
    pub capsule: &'a SensorCapsule,
    pub import_identity: ContentDigest,
    pub segment: u64,
    pub dimensions: [u32; 2],
    pub exposure: ContentDigest,
    pub luma: ContentDigest,
    pub frame: &'a FeatureFrame,
    pub allowed_mask_digest: [u8; 32],
    pub codec: &'a str,
    pub range_start: u64,
    pub range_count: u64,
    pub rectification: Option<(RectificationSpec, RectificationReceipt)>,
}

pub(super) fn fields<'a>(
    value: &'a Value,
    allowed: &[&str],
) -> Result<&'a BTreeMap<String, Value>> {
    let fields = value
        .object()
        .ok_or_else(|| input_error("expected a retained matching object"))?;
    if fields.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(input_error("unknown retained matching field"));
    }
    Ok(fields)
}

pub(super) fn get<'a>(fields: &'a BTreeMap<String, Value>, key: &str) -> Result<&'a Value> {
    fields
        .get(key)
        .ok_or_else(|| input_error(format!("missing retained matching field {key}")))
}

pub(super) fn text(value: &Value) -> Result<&str> {
    value
        .text()
        .ok_or_else(|| input_error("expected a retained matching string"))
}

pub(super) fn unsigned(value: &Value, minimum: u64, maximum: u64) -> Result<u64> {
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
        .ok_or_else(|| input_error("retained matching integer exceeds its bound"))
}

fn index(value: &Value) -> Result<usize> {
    usize::try_from(unsigned(value, 0, u64::MAX)?)
        .map_err(|_| input_error("source segment is outside the native index range"))
}

fn signed(value: &Value) -> Result<i64> {
    let literal = match value {
        Value::Number(s) | Value::Text(s) => s,
        _ => return Err(input_error("expected an exact clock offset integer")),
    };
    let digits = literal.strip_prefix('-').unwrap_or(literal);
    if digits.is_empty()
        || !digits.bytes().all(|b| b.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
        || literal == "-0"
    {
        return Err(input_error("expected a canonical clock offset integer"));
    }
    literal
        .parse::<i64>()
        .map_err(|_| input_error("clock offset is outside i64"))
}

pub(super) fn is_pin(digest: ContentDigest) -> bool {
    digest.algorithm() == DigestAlgorithm::Sha256 && digest.bytes() != [0; 32]
}

pub(super) fn digest(value: &Value) -> Result<ContentDigest> {
    let value = ContentDigest::parse(text(value)?)
        .map_err(|_| input_error("invalid retained matching digest"))?;
    if !is_pin(value) {
        return Err(input_error(
            "retained matching requires nonzero SHA-256 pins",
        ));
    }
    Ok(value)
}

pub(super) fn real(value: &Value, minimum: f64, maximum: f64) -> Result<f64> {
    let Value::Number(literal) = value else {
        return Err(input_error("expected a finite JSON number"));
    };
    literal
        .parse::<f64>()
        .ok()
        .filter(|n| n.is_finite() && (minimum..=maximum).contains(n))
        .map(|n| if n == 0.0 { 0.0 } else { n })
        .ok_or_else(|| input_error("retained matching number exceeds its finite bound"))
}

fn bounded_identity(value: &Value) -> Result<&str> {
    let value = text(value)?;
    if value.is_empty() || value.len() > 256 {
        return Err(input_error(
            "source identity exceeds the bounded selection profile",
        ));
    }
    Ok(value)
}

fn source(value: &Value) -> Result<Source> {
    let row = value
        .object()
        .ok_or_else(|| input_error("expected an exact retained source selection"))?;
    let codec = text(get(row, "codec")?)?;
    let keys: &[&str] = match codec {
        "jpeg" => &[
            "codec",
            "import_identity",
            "segment",
            "capsule_digest",
            "encoded_source_digest",
            "sensor_id",
            "component_interpretation",
        ],
        "h264" | "h265" => &[
            "codec",
            "import_identity",
            "segment",
            "capsule_digest",
            "encoded_source_digest",
            "sensor_id",
            "first_segment",
            "segment_count",
        ],
        _ => {
            return Err(input_error(
                "retained matching supports only jpeg, h264 and h265",
            ));
        }
    };
    let row = fields(value, keys)?;
    let sensor_id = SensorId::parse(bounded_identity(get(row, "sensor_id")?)?)
        .map_err(|_| input_error("invalid source sensor identity"))?;
    let pins = SourcePins {
        import_identity: digest(get(row, "import_identity")?)?,
        segment: index(get(row, "segment")?)?,
        capsule_digest: digest(get(row, "capsule_digest")?)?,
        encoded_source_digest: digest(get(row, "encoded_source_digest")?)?,
        sensor_id: sensor_id.as_str().to_owned(),
    };
    if codec == "jpeg" {
        let interpretation = match text(get(row, "component_interpretation")?)? {
            "grayscale" => ComponentInterpretation::Grayscale,
            "ycbcr" => ComponentInterpretation::YCbCr,
            _ => {
                return Err(input_error(
                    "JPEG interpretation must be grayscale or ycbcr",
                ));
            }
        };
        return Ok(Source::Jpeg {
            pins,
            interpretation,
        });
    }
    let first_segment = index(get(row, "first_segment")?)?;
    let segment_count =
        unsigned(get(row, "segment_count")?, 1, MAX_VIDEO_SEGMENTS as u64)? as usize;
    let end = first_segment
        .checked_add(segment_count)
        .ok_or_else(|| input_error("retained video range overflows"))?;
    if !(first_segment..end).contains(&pins.segment) {
        return Err(input_error(
            "selected video segment is outside its complete decode range",
        ));
    }
    Ok(if codec == "h264" {
        Source::H264 {
            pins,
            first_segment,
            segment_count,
        }
    } else {
        Source::H265 {
            pins,
            first_segment,
            segment_count,
        }
    })
}

fn alignment(value: &Value) -> Result<PackageClockAlignment> {
    let row = fields(
        value,
        &[
            "import_identity",
            "stream_id",
            "clock_basis",
            "offset_ns",
            "basis",
        ],
    )?;
    let stream = StreamId::parse(bounded_identity(get(row, "stream_id")?)?)
        .map_err(|_| input_error("invalid original stream identity"))?;
    let offsets = get(row, "offset_ns")?
        .array()
        .filter(|values| values.len() == 2)
        .ok_or_else(|| input_error("clock offset requires both interval endpoints"))?;
    let alignment = PackageClockAlignment {
        import_identity: digest(get(row, "import_identity")?)?,
        stream_id: stream.as_str().to_owned(),
        clock_basis: ClockBasis::parse(text(get(row, "clock_basis")?)?)
            .map_err(|_| input_error("unknown original clock basis"))?,
        offset_ns: [signed(&offsets[0])?, signed(&offsets[1])?],
        basis: digest(get(row, "basis")?)?,
    };
    alignment
        .validate()
        .map_err(|_| input_error("invalid retained clock alignment"))?;
    Ok(alignment)
}

pub(super) fn parse_view(value: &Value, version: u8) -> Result<View> {
    let image_key = match version {
        1 => "image_domain_digest",
        2 => "image",
        _ => {
            return Err(input_error(
                "unsupported retained image declaration version",
            ));
        }
    };
    let row = fields(
        value,
        &[
            "camera",
            image_key,
            "mapping_basis",
            "sigma_pixels",
            "source",
            "alignment",
        ],
    )?;
    let source = source(get(row, "source")?)?;
    let alignment = alignment(get(row, "alignment")?)?;
    if source.pins().import_identity != alignment.import_identity {
        return Err(input_error(
            "source and clock mapping select different imports",
        ));
    }
    Ok(View {
        camera: unsigned(get(row, "camera")?, 1, u64::MAX)?,
        image: if version == 1 {
            ImageDeclaration::Pinhole(digest(get(row, image_key)?)?)
        } else {
            images::parse(get(row, image_key)?)?
        },
        mapping_basis: digest(get(row, "mapping_basis")?)?,
        sigma_pixels: real(get(row, "sigma_pixels")?, 0.001, 1000.0)?,
        source,
        alignment,
    })
}

pub(super) fn json(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.clone(),
        Value::Text(value) => string(value),
        Value::Array(values) => array(&values.iter().map(json).collect::<Vec<_>>()),
        Value::Object(values) => object(
            &values
                .iter()
                .map(|(key, value)| (key.as_str(), json(value)))
                .collect::<Vec<_>>(),
        ),
    }
}

/// Admit the common header under an explicit schema and source-selection field shape.
/// Both commands retain the same pair policy; a joint component uses all of its cameras.
pub(super) fn parse_header(
    bytes: &[u8],
    schemas: [&str; 2],
    view_keys: &[&str],
    rig_digest: ContentDigest,
) -> Result<Header> {
    let value = json_input::parse(
        std::str::from_utf8(bytes)
            .map_err(|_| input_error("retained matching query must be UTF-8"))?,
    )
    .map_err(|_| input_error("malformed retained matching query"))?;
    let allowed: Vec<_> = [
        "schema",
        "camera_rig_digest",
        "privacy_domain",
        "clock",
        "clock_evidence",
        "association_basis",
        "reference_time_ns",
        "max_capture_span_ns",
        "motion",
        "extraction",
        "matching",
        "triangulation",
    ]
    .into_iter()
    .chain(view_keys.iter().copied())
    .collect();
    let top = fields(&value, &allowed)?;
    let version = match text(get(top, "schema")?)? {
        value if value == schemas[0] => 1,
        value if value == schemas[1] => 2,
        _ => return Err(input_error("unsupported exact retained matching schema")),
    };
    if digest(get(top, "camera_rig_digest")?)? != rig_digest {
        return Err(input_error(
            "retained matching schema or exact rig document pin differs",
        ));
    }
    if text(get(top, "motion")?)? != "static_during_capture_hull" {
        return Err(input_error(
            "retained matching requires an explicit static-scene assumption",
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
        return Err(input_error("unsupported retained matching motion policy"));
    };
    if triangulation.min_views != 2 || triangulation.max_outliers != 0 {
        return Err(input_error(
            "two-view retained matching requires both views with no omitted camera",
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
    let declarations = json(&value);
    Ok(Header {
        version,
        document: value,
        extraction,
        matching,
        declarations,
    })
}

pub(super) fn validate_distinct_declarations(views: &[View]) -> Result<()> {
    let mut cameras = BTreeSet::new();
    let mut sensors = BTreeSet::new();
    let mut sources = BTreeSet::new();
    let mut capsules = BTreeSet::new();
    for view in views {
        let pins = view.source.pins();
        if !cameras.insert(view.camera)
            || !sensors.insert(pins.sensor_id.as_str())
            || !sources.insert(pins.encoded_source_digest)
            || !capsules.insert(pins.capsule_digest)
        {
            return Err(input_error(
                "retained matching requires distinct cameras, physical sensors and original sources",
            ));
        }
    }
    Ok(())
}

/// Admit exact selections and assumptions; the supplied digest pins the original rig bytes.
pub(super) fn parse(bytes: &[u8], rig_digest: ContentDigest) -> Result<Query> {
    let header = parse_header(bytes, [SCHEMA, SCHEMA_V2], &["left", "right"], rig_digest)?;
    let top = header
        .document
        .object()
        .ok_or_else(|| input_error("expected a retained matching object"))?;
    let views = [
        parse_view(get(top, "left")?, header.version)?,
        parse_view(get(top, "right")?, header.version)?,
    ];
    validate_distinct_declarations(&views)?;
    Ok(Query {
        version: header.version,
        views,
        extraction: header.extraction,
        matching: header.matching,
        declarations: header.declarations,
    })
}

/// Check exact metadata pins before decoding or publishing any derived JPEG.
/// The owner must independently authenticate the capsule and its retained import.
pub(super) fn validate_capsule(view: &View, capsule: &SensorCapsule) -> Result<[u64; 2]> {
    let pins = view.source.pins();
    let capsule_bytes = capsule
        .try_canonical_bytes()
        .map_err(|_| input_error("retained capsule cannot be canonically encoded"))?;
    if pins.import_identity != view.alignment.import_identity
        || ContentDigest::sha256(&capsule_bytes) != pins.capsule_digest
        || capsule.source_digest != pins.encoded_source_digest
        || capsule.sensor_id.as_str() != pins.sensor_id
        || capsule.stream_id.as_str() != view.alignment.stream_id
        || capsule.clock_basis != view.alignment.clock_basis
    {
        return Err(input_error(
            "retained frame does not match its exact source selection",
        ));
    }
    let aligned = view
        .alignment
        .align([capsule.capture.earliest.0, capsule.capture.latest.0])
        .map_err(|_| input_error("retained capture cannot be conservatively aligned"))?;
    Ok([
        u64::try_from(aligned[0])
            .map_err(|_| input_error("negative aligned capture is unsupported"))?,
        u64::try_from(aligned[1])
            .map_err(|_| input_error("negative aligned capture is unsupported"))?,
    ])
}

pub(super) fn bind_view(
    matching: AssociationOptions,
    maximum_features: usize,
    view: &View,
    resolved: &ResolvedFrame<'_>,
    rig: &SceneRig,
) -> Result<FeatureView> {
    bind_source_view(
        ViewBindingPolicy {
            privacy_domain: matching.privacy_domain,
            clock: matching.clock,
            clock_evidence: matching.clock_evidence,
            maximum_features,
        },
        view,
        resolved,
        rig,
    )
}

/// Common source/rig checks independent of static or moving-feature association policy.
#[derive(Clone, Copy)]
pub(super) struct ViewBindingPolicy {
    pub privacy_domain: u64,
    pub clock: u64,
    pub clock_evidence: [u8; 32],
    pub maximum_features: usize,
}

pub(super) fn bind_source_view(
    policy: ViewBindingPolicy,
    view: &View,
    resolved: &ResolvedFrame<'_>,
    rig: &SceneRig,
) -> Result<FeatureView> {
    let camera = rig
        .camera(view.camera)
        .ok_or_else(|| input_error("selected scene camera is unavailable"))?;
    let capture = validate_capsule(view, resolved.capsule)?;
    if resolved.import_identity != view.source.pins().import_identity
        || resolved.segment != view.source.pins().segment as u64
        || view.source.range() != (resolved.codec, resolved.range_start, resolved.range_count)
    {
        return Err(input_error(
            "retained decoder selection differs from its requested source",
        ));
    }
    let identity = resolved.frame.identity();
    if camera.privacy_domain != policy.privacy_domain
        || camera.camera.clock != policy.clock
        || identity.exposure != resolved.exposure.bytes()
        || !is_pin(resolved.exposure)
        || !is_pin(resolved.luma)
        || resolved.allowed_mask_digest == [0; 32]
        || resolved.frame.features().len() > policy.maximum_features
    {
        return Err(input_error(
            "retained feature, privacy, clock or image mode does not match its rig binding",
        ));
    }
    let image_domain = images::bind(view.image, camera.camera.intrinsics, resolved)?;
    if capture[0] < camera.camera.validity[0] || capture[1] > camera.camera.validity[1] {
        return Err(input_error(
            "full aligned capture leaves the declared camera validity",
        ));
    }
    Ok(FeatureView {
        frame: resolved.frame.clone(),
        camera: camera.camera,
        source_digest: resolved.capsule.source_digest.bytes(),
        allowed_mask_digest: resolved.allowed_mask_digest,
        image_domain_digest: image_domain.bytes(),
        mapping_basis: view.mapping_basis.bytes(),
        privacy_domain: camera.privacy_domain,
        clock_evidence: policy.clock_evidence,
        capture,
        sigma_pixels: view.sigma_pixels,
    })
}

/// Bind complete native features and source intervals without accepting source-data overrides.
pub(super) fn bind(
    query: &Query,
    resolved: [ResolvedFrame<'_>; 2],
    rig: &SceneRig,
) -> Result<[FeatureView; 2]> {
    let [left, right] = resolved;
    if left.capsule.sensor_id == right.capsule.sensor_id
        || left.capsule.source_digest == right.capsule.source_digest
        || left.exposure == right.exposure
        || query.views[0].camera == query.views[1].camera
        || left.frame.descriptor_domain() != right.frame.descriptor_domain()
    {
        return Err(input_error(
            "retained views reuse a physical source or incompatible descriptor space",
        ));
    }
    let left = bind_view(
        query.matching,
        query.extraction.maximum_features,
        &query.views[0],
        &left,
        rig,
    )?;
    let right = bind_view(
        query.matching,
        query.extraction.maximum_features,
        &query.views[1],
        &right,
        rig,
    )?;
    let hull = [
        left.capture[0].min(right.capture[0]),
        left.capture[1].max(right.capture[1]),
    ];
    if hull[1] - hull[0] > query.matching.max_capture_span_ns
        || !(hull[0]..=hull[1]).contains(&query.matching.reference_time_ns)
    {
        return Err(input_error(
            "full aligned capture hull exceeds the matching interval policy",
        ));
    }
    Ok([left, right])
}

#[cfg(test)]
#[path = "input_tests.rs"]
mod tests;

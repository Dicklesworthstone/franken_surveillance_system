#![forbid(unsafe_code)]
//! Bounded vendor scene descriptions from ONVIF `metadatastream.xsd`.
//!
//! This projection follows Frame/Object/Appearance/Shape/Class/Transformation in
//! <https://www.onvif.org/ver10/schema/metadatastream.xsd> and the coordinate
//! primitives in <https://www.onvif.org/ver10/schema/onvif.xsd>. It neither
//! authenticates a source nor supplies calibration, tracking, identity or absence
//! authority. Object IDs are local vendor claims, not FSS entity identities.

use std::collections::BTreeSet;
use std::fmt;

use super::events::{EventDocument, timestamp, unknown_attributes};
use super::{SCHEMA_NS, WireError, required, scalar, unique, xml};

/// Maximum analytics frames across all VideoAnalytics sections in one document.
pub const MAX_ANALYTICS_FRAMES: usize = 128;
/// Maximum object descriptions in one analytics frame.
pub const MAX_ANALYTICS_OBJECTS_PER_FRAME: usize = 128;
/// Maximum object descriptions across a complete metadata document.
pub const MAX_ANALYTICS_OBJECTS: usize = 512;
/// Maximum class candidates in one present Class group.
pub const MAX_ANALYTICS_CLASSES: usize = 16;
/// Maximum bytes in an accepted decimal/scientific numeric lexical value.
pub const MAX_ANALYTICS_NUMBER_BYTES: usize = 64;
/// Absolute coordinate/transform ceiling of this bounded projection subset.
pub const MAX_ANALYTICS_COORDINATE: f64 = 1_000_000_000.0;

const MAX_LABEL_BYTES: usize = 256;
const MAX_OBJECT_ID_BYTES: usize = 64;

/// Finite, bounded vendor number retaining its accepted decimal/scientific spelling.
///
/// XML whitespace surrounding legacy scalar element content is removed. Equality and
/// canonical projection preserve the remaining spelling, including negative zero.
/// Numeric access is only a convenience approximation, never a calibration or confidence
/// certificate. No arithmetic or coordinate conversion is performed by this parser.
#[derive(Clone, Eq, PartialEq)]
pub struct AnalyticsNumber {
    lexical: String,
    bits: u64,
}

impl AnalyticsNumber {
    /// Accepted decimal/scientific spelling, excluding legacy scalar element padding.
    pub fn as_str(&self) -> &str {
        &self.lexical
    }

    /// Finite binary64 approximation of the vendor assertion.
    pub fn as_f64(&self) -> f64 {
        f64::from_bits(self.bits)
    }
}

impl fmt::Debug for AnalyticsNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AnalyticsNumber([untrusted coordinate or likelihood])")
    }
}

/// Vendor-coordinate vector; the surrounding transformation remains separate.
#[derive(Clone, Eq, PartialEq)]
pub struct AnalyticsVector {
    /// Untransformed horizontal coordinate.
    pub x: AnalyticsNumber,
    /// Untransformed vertical coordinate.
    pub y: AnalyticsNumber,
    /// Extra attributes retained in source but not interpreted.
    pub unsupported_extensions: usize,
}

/// Vendor rectangle with no inferred axis orientation, pixel grid or world units.
#[derive(Clone, Eq, PartialEq)]
pub struct AnalyticsBoundingBox {
    /// Vendor left boundary.
    pub left: AnalyticsNumber,
    /// Vendor top boundary.
    pub top: AnalyticsNumber,
    /// Vendor right boundary.
    pub right: AnalyticsNumber,
    /// Vendor bottom boundary.
    pub bottom: AnalyticsNumber,
    /// Extra attributes retained in source but not interpreted.
    pub unsupported_extensions: usize,
}

/// Explicit optional translation/scale; absence is preserved, not filled with defaults.
#[derive(Clone, Eq, PartialEq)]
pub struct AnalyticsTransformation {
    /// Optional vendor translation.
    pub translate: Option<AnalyticsVector>,
    /// Optional vendor scale, including a possible reflected coordinate axis.
    pub scale: Option<AnalyticsVector>,
    /// Extra attributes/children, including unsupported transform extensions.
    pub unsupported_extensions: usize,
}

/// The supported coarse shape; polygons remain opaque source content.
#[derive(Clone, Eq, PartialEq)]
pub struct AnalyticsShape {
    /// Required coarse bounding box in the vendor's current coordinate system.
    pub bounding_box: AnalyticsBoundingBox,
    /// Required vendor center of gravity, not a world-space location.
    pub center_of_gravity: AnalyticsVector,
    /// Additional shape primitives, attributes and extensions not interpreted.
    pub unsupported_extensions: usize,
}

/// Original class representation. These two forms have different missing-value semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalyticsClassFormat {
    /// Legacy ClassCandidate with required Type and Likelihood children.
    LegacyCandidate,
    /// Modern Type text with an optional Likelihood attribute.
    Type,
}

/// An uninterpreted vendor class label and its optional asserted likelihood.
#[derive(Clone, Eq, PartialEq)]
pub struct AnalyticsClassCandidate {
    /// Wire representation, preserved in the projection.
    pub format: AnalyticsClassFormat,
    /// Bounded vendor label; no vocabulary mapping or biometric feature activation.
    pub label: String,
    /// Vendor claim in [0,1]; absence is distinct from zero or a default confidence.
    pub likelihood: Option<AnalyticsNumber>,
    /// Uninterpreted attributes/children on this candidate and its scalar fields.
    pub unsupported_extensions: usize,
}

/// A present classification group; empty and missing remain different.
#[derive(Clone, Eq, PartialEq)]
pub struct AnalyticsClass {
    /// All candidates in source order, without ranking, normalization or coalescing.
    pub candidates: Vec<AnalyticsClassCandidate>,
    /// Unknown class fields/attributes, retained as opaque source content.
    pub unsupported_extensions: usize,
}

/// Bounded non-biometric appearance projection.
#[derive(Clone, Eq, PartialEq)]
pub struct AnalyticsAppearance {
    /// Object-relative transformation, separate from the frame's transformation.
    pub transformation: Option<AnalyticsTransformation>,
    /// Optional coarse shape; inferred/nonvisible vendor objects may omit it.
    pub shape: Option<AnalyticsShape>,
    /// Optional vendor classifications.
    pub class: Option<AnalyticsClass>,
    /// Opaque appearance content, including face/body/plate/identity/images/URLs.
    pub unsupported_extensions: usize,
}

/// One vendor object occurrence. No cross-frame tracking or identity merge is inferred.
#[derive(Clone, Eq, PartialEq)]
pub struct AnalyticsObject {
    /// Bounded signed-integer ObjectId lexical value, required by this subset.
    pub object_id: String,
    /// Optional appearance; missing is not an empty detection.
    pub appearance: Option<AnalyticsAppearance>,
    /// Uninterpreted object attributes/children, including UUID, Parent and Behaviour.
    pub unsupported_extensions: usize,
}

/// One vendor analytics frame. Empty frames never create a CoverageWitness.
#[derive(Clone, Eq, PartialEq)]
pub struct AnalyticsFrame {
    /// Device-asserted UTC lexical value, untrusted as a capture clock.
    pub utc_time: String,
    /// Optional analytics module name, not an authenticated source identity.
    pub source: Option<String>,
    /// Optional frame-coordinate transformation, not an FSS calibration certificate.
    pub transformation: Option<AnalyticsTransformation>,
    /// Object occurrences in original order, without cross-frame deduplication.
    pub objects: Vec<AnalyticsObject>,
    /// Uninterpreted frame fields/attributes, including PTZ, image and ObjectTree content.
    pub unsupported_extensions: usize,
}

impl AnalyticsTransformation {
    fn has_unsupported_content(&self) -> bool {
        self.unsupported_extensions != 0
            || self
                .translate
                .as_ref()
                .is_some_and(|v| v.unsupported_extensions != 0)
            || self
                .scale
                .as_ref()
                .is_some_and(|v| v.unsupported_extensions != 0)
    }
}

impl AnalyticsAppearance {
    fn has_unsupported_content(&self) -> bool {
        self.unsupported_extensions != 0
            || self
                .transformation
                .as_ref()
                .is_some_and(AnalyticsTransformation::has_unsupported_content)
            || self.shape.as_ref().is_some_and(|shape| {
                shape.unsupported_extensions != 0
                    || shape.bounding_box.unsupported_extensions != 0
                    || shape.center_of_gravity.unsupported_extensions != 0
            })
            || self.class.as_ref().is_some_and(|class| {
                class.unsupported_extensions != 0
                    || class
                        .candidates
                        .iter()
                        .any(|value| value.unsupported_extensions != 0)
            })
    }
}

impl AnalyticsFrame {
    /// Whether any of this frame's content was retained but not interpreted.
    pub fn has_unsupported_content(&self) -> bool {
        self.unsupported_extensions != 0
            || self
                .transformation
                .as_ref()
                .is_some_and(AnalyticsTransformation::has_unsupported_content)
            || self.objects.iter().any(|object| {
                object.unsupported_extensions != 0
                    || object
                        .appearance
                        .as_ref()
                        .is_some_and(AnalyticsAppearance::has_unsupported_content)
            })
    }
}

macro_rules! redacted_debug {
    ($($type:ty),+ $(,)?) => {
        $(impl fmt::Debug for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($type), "([untrusted vendor metadata])"))
            }
        })+
    };
}
redacted_debug!(
    AnalyticsVector,
    AnalyticsBoundingBox,
    AnalyticsTransformation,
    AnalyticsShape,
    AnalyticsClassCandidate,
    AnalyticsClass,
    AnalyticsAppearance,
    AnalyticsObject,
);

impl fmt::Debug for AnalyticsFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnalyticsFrame")
            .field("objects", &self.objects.len())
            .field("unsupported_content", &self.has_unsupported_content())
            .finish_non_exhaustive()
    }
}

pub(super) fn parse_section(
    doc: &xml::Document,
    section: usize,
    result: &mut EventDocument,
    object_count: &mut usize,
) -> Result<(), WireError> {
    whitespace(doc, section)?;
    result.unsupported_sections += doc.attribute_count(section);
    for child in doc.child_ids(section) {
        if doc.named(child, SCHEMA_NS, "Frame") {
            if result.analytics_frames.len() == MAX_ANALYTICS_FRAMES {
                return Err(WireError::AnalyticsLimitExceeded);
            }
            result
                .analytics_frames
                .push(frame(doc, child, object_count)?);
        } else {
            result.unsupported_sections += 1;
        }
    }
    Ok(())
}

fn frame(
    doc: &xml::Document,
    id: usize,
    object_count: &mut usize,
) -> Result<AnalyticsFrame, WireError> {
    whitespace(doc, id)?;
    let utc_time = doc
        .attribute(id, "", "UtcTime")
        .ok_or(WireError::MissingField)?;
    timestamp(utc_time)?;
    let source = doc
        .attribute(id, "", "Source")
        .map(|value| label(value, true))
        .transpose()?;
    let transformation = unique(doc, id, SCHEMA_NS, "Transformation")?
        .map(|child| transformation(doc, child))
        .transpose()?;
    let mut result = AnalyticsFrame {
        utc_time: utc_time.to_owned(),
        source,
        transformation,
        objects: Vec::new(),
        unsupported_extensions: unknown_attributes(doc, id, &["UtcTime", "Source"]),
    };
    let mut identities = BTreeSet::new();
    for child in doc.child_ids(id) {
        if doc.named(child, SCHEMA_NS, "Object") {
            if result.objects.len() == MAX_ANALYTICS_OBJECTS_PER_FRAME
                || *object_count == MAX_ANALYTICS_OBJECTS
            {
                return Err(WireError::AnalyticsLimitExceeded);
            }
            let object = object(doc, child)?;
            // XML integers have equivalent spellings (+001 and 1). Preserve the
            // original spelling but refuse ambiguous duplicates in this frame.
            if !identities.insert(integer_key(&object.object_id)?) {
                return Err(WireError::DuplicateField);
            }
            result.objects.push(object);
            *object_count += 1;
        } else if !doc.named(child, SCHEMA_NS, "Transformation") {
            result.unsupported_extensions += 1;
        }
    }
    Ok(result)
}

fn object(doc: &xml::Document, id: usize) -> Result<AnalyticsObject, WireError> {
    whitespace(doc, id)?;
    let object_id = doc
        .attribute(id, "", "ObjectId")
        .ok_or(WireError::MissingField)?;
    integer_key(object_id)?;
    Ok(AnalyticsObject {
        object_id: object_id.to_owned(),
        appearance: unique(doc, id, SCHEMA_NS, "Appearance")?
            .map(|child| appearance(doc, child))
            .transpose()?,
        unsupported_extensions: unknown_attributes(doc, id, &["ObjectId"])
            + unknown_children(doc, id, &["Appearance"]),
    })
}

fn appearance(doc: &xml::Document, id: usize) -> Result<AnalyticsAppearance, WireError> {
    whitespace(doc, id)?;
    Ok(AnalyticsAppearance {
        transformation: unique(doc, id, SCHEMA_NS, "Transformation")?
            .map(|child| transformation(doc, child))
            .transpose()?,
        shape: unique(doc, id, SCHEMA_NS, "Shape")?
            .map(|child| shape(doc, child))
            .transpose()?,
        class: unique(doc, id, SCHEMA_NS, "Class")?
            .map(|child| classes(doc, child))
            .transpose()?,
        unsupported_extensions: doc.attribute_count(id)
            + unknown_children(doc, id, &["Transformation", "Shape", "Class"]),
    })
}

fn transformation(doc: &xml::Document, id: usize) -> Result<AnalyticsTransformation, WireError> {
    whitespace(doc, id)?;
    Ok(AnalyticsTransformation {
        translate: unique(doc, id, SCHEMA_NS, "Translate")?
            .map(|child| vector(doc, child))
            .transpose()?,
        scale: unique(doc, id, SCHEMA_NS, "Scale")?
            .map(|child| vector(doc, child))
            .transpose()?,
        unsupported_extensions: doc.attribute_count(id)
            + unknown_children(doc, id, &["Translate", "Scale"]),
    })
}

fn shape(doc: &xml::Document, id: usize) -> Result<AnalyticsShape, WireError> {
    whitespace(doc, id)?;
    Ok(AnalyticsShape {
        bounding_box: bounding_box(doc, required(doc, id, SCHEMA_NS, "BoundingBox")?)?,
        center_of_gravity: vector(doc, required(doc, id, SCHEMA_NS, "CenterOfGravity")?)?,
        unsupported_extensions: doc.attribute_count(id)
            + unknown_children(doc, id, &["BoundingBox", "CenterOfGravity"]),
    })
}

fn vector(doc: &xml::Document, id: usize) -> Result<AnalyticsVector, WireError> {
    empty_element(doc, id)?;
    Ok(AnalyticsVector {
        x: attribute_number(doc, id, "x")?,
        y: attribute_number(doc, id, "y")?,
        unsupported_extensions: unknown_attributes(doc, id, &["x", "y"]),
    })
}

fn bounding_box(doc: &xml::Document, id: usize) -> Result<AnalyticsBoundingBox, WireError> {
    empty_element(doc, id)?;
    Ok(AnalyticsBoundingBox {
        left: attribute_number(doc, id, "left")?,
        top: attribute_number(doc, id, "top")?,
        right: attribute_number(doc, id, "right")?,
        bottom: attribute_number(doc, id, "bottom")?,
        unsupported_extensions: unknown_attributes(doc, id, &["left", "top", "right", "bottom"]),
    })
}

fn classes(doc: &xml::Document, id: usize) -> Result<AnalyticsClass, WireError> {
    whitespace(doc, id)?;
    let mut result = AnalyticsClass {
        candidates: Vec::new(),
        unsupported_extensions: doc.attribute_count(id),
    };
    for child in doc.child_ids(id) {
        let format = if doc.named(child, SCHEMA_NS, "ClassCandidate") {
            AnalyticsClassFormat::LegacyCandidate
        } else if doc.named(child, SCHEMA_NS, "Type") {
            AnalyticsClassFormat::Type
        } else {
            result.unsupported_extensions += 1;
            continue;
        };
        if result.candidates.len() == MAX_ANALYTICS_CLASSES {
            return Err(WireError::AnalyticsLimitExceeded);
        }
        let candidate = match format {
            AnalyticsClassFormat::LegacyCandidate => {
                whitespace(doc, child)?;
                let label_id = required(doc, child, SCHEMA_NS, "Type")?;
                let likelihood_id = required(doc, child, SCHEMA_NS, "Likelihood")?;
                AnalyticsClassCandidate {
                    format,
                    label: label(doc.leaf_text(label_id)?, false)?,
                    likelihood: Some(number(scalar(doc, likelihood_id)?, true)?),
                    unsupported_extensions: doc.attribute_count(child)
                        + doc.attribute_count(label_id)
                        + doc.attribute_count(likelihood_id)
                        + unknown_children(doc, child, &["Type", "Likelihood"]),
                }
            }
            AnalyticsClassFormat::Type => AnalyticsClassCandidate {
                format,
                label: label(doc.leaf_text(child)?, false)?,
                likelihood: doc
                    .attribute(child, "", "Likelihood")
                    .map(|value| number(value, true))
                    .transpose()?,
                unsupported_extensions: unknown_attributes(doc, child, &["Likelihood"]),
            },
        };
        result.candidates.push(candidate);
    }
    // Candidates may be hierarchical/multi-label and need not sum to one.
    // No renormalization, ranking, synonym mapping or deduplication is performed.
    Ok(result)
}

fn attribute_number(
    doc: &xml::Document,
    id: usize,
    name: &str,
) -> Result<AnalyticsNumber, WireError> {
    number(
        doc.attribute(id, "", name).ok_or(WireError::MissingField)?,
        false,
    )
}

fn number(value: &str, likelihood: bool) -> Result<AnalyticsNumber, WireError> {
    if value.is_empty() || value.len() > MAX_ANALYTICS_NUMBER_BYTES {
        return Err(WireError::InvalidField);
    }
    let bytes = value.as_bytes();
    let negative = bytes[0] == b'-';
    let mut at = usize::from(matches!(bytes[0], b'+' | b'-'));
    let mut digits = Vec::with_capacity(value.len());
    while bytes.get(at).is_some_and(u8::is_ascii_digit) {
        digits.push(bytes[at]);
        at += 1;
    }
    let integral_digits = digits.len();
    if bytes.get(at) == Some(&b'.') {
        at += 1;
        while bytes.get(at).is_some_and(u8::is_ascii_digit) {
            digits.push(bytes[at]);
            at += 1;
        }
    }
    if digits.is_empty() {
        return Err(WireError::InvalidField);
    }
    let mut exponent = 0_i32;
    if bytes
        .get(at)
        .is_some_and(|byte| matches!(*byte, b'e' | b'E'))
    {
        at += 1;
        let exponent_negative = bytes.get(at) == Some(&b'-');
        if bytes
            .get(at)
            .is_some_and(|byte| matches!(*byte, b'+' | b'-'))
        {
            at += 1;
        }
        let start = at;
        while bytes.get(at).is_some_and(u8::is_ascii_digit) {
            exponent = exponent
                .checked_mul(10)
                .and_then(|n| n.checked_add(i32::from(bytes[at] - b'0')))
                .ok_or(WireError::InvalidField)?;
            if exponent > 4096 {
                return Err(WireError::InvalidField);
            }
            at += 1;
        }
        if at == start {
            return Err(WireError::InvalidField);
        }
        if exponent_negative {
            exponent = -exponent;
        }
    }
    if at != bytes.len() {
        return Err(WireError::InvalidField);
    }
    let numeric = value.parse::<f64>().map_err(|_| WireError::InvalidField)?;
    if !numeric.is_finite() || numeric.abs() > MAX_ANALYTICS_COORDINATE {
        return Err(WireError::InvalidField);
    }
    if let Some(first) = digits.iter().position(|digit| *digit != b'0') {
        // Check decimal bounds before binary rounding can turn 1.000...001 into
        // an apparently legal probability, or underflow a nonzero value to zero.
        let places = integral_digits as i32 - first as i32 + exponent;
        let maximum_places = if likelihood { 1 } else { 10 };
        let exceeds = places > maximum_places
            || (places == maximum_places
                && (digits[first] > b'1' || digits[first + 1..].iter().any(|d| *d != b'0')));
        if exceeds || numeric == 0.0 || (likelihood && negative) {
            return Err(WireError::InvalidField);
        }
    }
    Ok(AnalyticsNumber {
        lexical: value.to_owned(),
        bits: numeric.to_bits(),
    })
}

fn label(value: &str, empty: bool) -> Result<String, WireError> {
    if (!empty && value.is_empty())
        || value.len() > MAX_LABEL_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(WireError::InvalidField);
    }
    Ok(value.to_owned())
}

fn integer_key(value: &str) -> Result<String, WireError> {
    if value.is_empty() || value.len() > MAX_OBJECT_ID_BYTES {
        return Err(WireError::InvalidField);
    }
    let negative = value.starts_with('-');
    let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(WireError::InvalidField);
    }
    let significant = digits.trim_start_matches('0');
    Ok(if significant.is_empty() {
        "0".to_owned()
    } else if negative {
        format!("-{significant}")
    } else {
        significant.to_owned()
    })
}

fn whitespace(doc: &xml::Document, id: usize) -> Result<(), WireError> {
    if !doc.only_whitespace(id) {
        return Err(WireError::InvalidField);
    }
    Ok(())
}

fn empty_element(doc: &xml::Document, id: usize) -> Result<(), WireError> {
    whitespace(doc, id)?;
    if doc.child_ids(id).next().is_some() {
        return Err(WireError::InvalidField);
    }
    Ok(())
}

fn unknown_children(doc: &xml::Document, id: usize, known: &[&str]) -> usize {
    doc.child_ids(id)
        .filter(|child| !known.iter().any(|name| doc.named(*child, SCHEMA_NS, name)))
        .count()
}

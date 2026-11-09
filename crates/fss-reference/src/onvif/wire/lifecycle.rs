#![forbid(unsafe_code)]
//! Additive ONVIF ObjectTree and Behaviour interpretation over original metadata XML.
//!
//! This does not change the frozen event-v1 or analytics-v2 parsers or encodings. The
//! normative grammar is `onvif/specs` `wsdl/ver10/schema/metadatastream.xsd`, version
//! 25.12, blob `ba3726fef2d3424486883079f9a520ee069698f0`. Its endpoint elements are
//! lowercase `from`/`to`, unlike the uppercase examples in the Analytics specification.
//! Rename has one endpoint on each side; Merge has at least two from and one to;
//! Split has one from and at least two to. Delete carries an ObjectId reference.
//!
//! These are local vendor claims, never physical identity, absence, coverage, or
//! authority. UUIDs are retained as unsupported claims and are never matched. Idle
//! and Removed are separate behaviours; neither deletes an object. Appearance and
//! Transformation belong to the independently frozen analytics interpretation, not
//! this lifecycle overlay. Unknown fields remain in the original source and produce
//! explicit unsupported flags rather than silently becoming lifecycle evidence.

use std::fmt;

use super::events::{timestamp, unknown_attributes};
use super::{
    MAX_ANALYTICS_FRAMES, MAX_ANALYTICS_OBJECTS, MAX_ANALYTICS_OBJECTS_PER_FRAME, MAX_SOAP_BYTES,
    SCHEMA_NS, WireError, analytics_object_key, unique, xml,
};

/// Independent interpretation generation; existing retained source generations stay frozen.
pub const LIFECYCLE_PARSER_GENERATION: &str = "gen:fss1:onvif-vendor-lifecycle-v1";
/// Maximum recognized lifecycle operations across a complete XML document.
pub const MAX_LIFECYCLE_OPERATIONS: usize = 1024;
/// Maximum object and operation endpoint references across a complete XML document.
pub const MAX_LIFECYCLE_REFERENCES: usize = 2048;
/// Hard conservative parse-work reservation, not elapsed time or instruction measurement.
pub const MAX_LIFECYCLE_PARSE_WORK_UNITS: u64 = 4 * 1024 * 1024;
/// Maximum decoded bytes in a module name or opaque vendor UUID.
pub const MAX_LIFECYCLE_LABEL_BYTES: usize = 256;

/// Nonrenewing shape and work allowance for one complete source document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleParseLimits {
    /// Maximum typed frames, across every VideoAnalytics section.
    pub max_frames: usize,
    /// Maximum original Object descriptions, including unsupported references.
    pub max_objects: usize,
    /// Maximum recognized Rename, Split, Merge and Delete nodes.
    pub max_operations: usize,
    /// Maximum references, including the one reference in every Object description.
    pub max_references: usize,
    /// Complete quote must fit before the bounded XML parser allocates or runs.
    pub max_work_units: u64,
}

impl Default for LifecycleParseLimits {
    fn default() -> Self {
        Self {
            max_frames: MAX_ANALYTICS_FRAMES,
            max_objects: MAX_ANALYTICS_OBJECTS,
            max_operations: MAX_LIFECYCLE_OPERATIONS,
            max_references: MAX_LIFECYCLE_REFERENCES,
            max_work_units: MAX_LIFECYCLE_PARSE_WORK_UNITS,
        }
    }
}

impl LifecycleParseLimits {
    /// Refuse invalid allowances before reading or interpreting any input bytes.
    pub fn validate(self) -> Result<(), LifecycleWireError> {
        if !(1..=MAX_ANALYTICS_FRAMES).contains(&self.max_frames)
            || !(1..=MAX_ANALYTICS_OBJECTS).contains(&self.max_objects)
            || !(1..=MAX_LIFECYCLE_OPERATIONS).contains(&self.max_operations)
            || !(1..=MAX_LIFECYCLE_REFERENCES).contains(&self.max_references)
            || !(1..=MAX_LIFECYCLE_PARSE_WORK_UNITS).contains(&self.max_work_units)
        {
            return Err(LifecycleWireError::Limit);
        }
        Ok(())
    }
}

/// Conservative nonrefundable work quote available before parsing or source hydration.
///
/// The fixed XML owner bounds input at 256 KiB, 4096 nodes, depth 32 and 32 attributes
/// per element. This quote reserves eight units per input byte plus 128 per possible
/// node (at most one node per three input bytes) for XML and overlay traversal/copies.
/// Units describe a bounded reservation, not processor instructions. The full quote is
/// consumed even for empty results; callers must debit it from their shared request
/// allowance on every parse/revalidation pass. Oversized lengths return `None`.
#[must_use]
pub fn lifecycle_parse_work_bound(byte_len: usize) -> Option<u64> {
    if byte_len > MAX_SOAP_BYTES {
        return None;
    }
    let bytes = u64::try_from(byte_len).ok()?;
    let possible_nodes = u64::try_from((byte_len / 3).min(4096)).ok()?;
    bytes
        .checked_mul(8)?
        .checked_add(possible_nodes.checked_mul(128)?)?
        .checked_add(1)
}

/// Payload-free refusal; no successful partial document escapes any failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleWireError {
    /// Invalid XML or an invalid known grammar/scalar field.
    Wire(WireError),
    /// A declared frame, object, operation, reference, or work bound was exceeded.
    Limit,
    /// The caller withdrew cooperative admission.
    Cancelled,
}

impl LifecycleWireError {
    /// Stable failure identity without source text or private values.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Wire(_) => "onvif.lifecycle.invalid_xml",
            Self::Limit => "onvif.lifecycle.parse_limit",
            Self::Cancelled => "onvif.lifecycle.parse_cancelled",
        }
    }
}

impl fmt::Display for LifecycleWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for LifecycleWireError {}
impl From<WireError> for LifecycleWireError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

/// Exact decoded reference lexemes, with no physical or cross-module identity meaning.
#[derive(Clone, Eq, PartialEq)]
pub struct LifecycleReference {
    /// Optional bounded XML integer; absence is supported by the ONVIF schema and
    /// remains explicitly unsupported for this integer-only relationship projection.
    pub object_id: Option<String>,
    /// Original optional vendor UUID, retained opaquely and never used for matching.
    pub uuid: Option<String>,
    /// Other attributes or endpoint children left in the original XML.
    pub unsupported_extensions: usize,
}

impl LifecycleReference {
    /// Whether this reference contains only the supported integer claim.
    #[must_use]
    pub fn is_supported(&self) -> bool {
        self.object_id.is_some() && self.uuid.is_none() && self.unsupported_extensions == 0
    }
}
impl fmt::Debug for LifecycleReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LifecycleReference")
            .field("integer_present", &self.object_id.is_some())
            .field("opaque_uuid_present", &self.uuid.is_some())
            .field("unsupported_extensions", &self.unsupported_extensions)
            .finish_non_exhaustive()
    }
}

/// Explicit vendor behaviours. Both flags may be present and neither is Delete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleBehaviour {
    /// Vendor says the object became idle; no observation of physical stillness is implied.
    pub idle: bool,
    /// Vendor marks a removal location; this does not delete the referenced ID.
    pub removed: bool,
    /// Uninterpreted behaviour/flag attributes and descendants.
    pub unsupported_extensions: usize,
}

/// An original Object occurrence, preserving its position among all frame children.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleObject {
    /// Zero-based Object ordinal within this frame, matching analytics-v2 where accepted.
    pub object_index: usize,
    /// Zero-based original frame child position, including non-Object children.
    pub frame_child_index: usize,
    /// Local vendor reference, with unsupported/missing integer claims preserved.
    pub reference: LifecycleReference,
    /// Missing and present-empty Behaviour remain distinct.
    pub behaviour: Option<LifecycleBehaviour>,
    /// Uninterpreted object children. Appearance is interpreted only by analytics-v2.
    pub unsupported_extensions: usize,
}

impl LifecycleObject {
    /// Whether any lifecycle-relevant source material could not be interpreted.
    #[must_use]
    pub fn has_unsupported_content(&self) -> bool {
        !self.reference.is_supported()
            || self.unsupported_extensions != 0
            || self
                .behaviour
                .is_some_and(|value| value.unsupported_extensions != 0)
    }
}

/// Known ObjectTree operation, always a vendor claim rather than an identity decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleOperationKind {
    /// One local reference is renamed to another.
    Rename,
    /// One reference is split into at least two local references.
    Split,
    /// At least two references are merged into one local reference.
    Merge,
    /// One reference is explicitly removed from the vendor analytics memory.
    Delete,
}
impl LifecycleOperationKind {
    /// Stable lowercase wire/report discriminator.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rename => "rename",
            Self::Split => "split",
            Self::Merge => "merge",
            Self::Delete => "delete",
        }
    }
}

/// Original operation occurrence. Unknown siblings are not coalesced or reordered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleOperation {
    /// Zero-based recognized operation ordinal in this frame's sole ObjectTree.
    pub operation_index: usize,
    /// Zero-based original ObjectTree child position, including uninterpreted nodes.
    pub tree_child_index: usize,
    /// Vendor operation type.
    pub kind: LifecycleOperationKind,
    /// Original from references in source order. Delete has exactly one entry here.
    pub from: Vec<LifecycleReference>,
    /// Original to references in source order. Delete has no entries here.
    pub to: Vec<LifecycleReference>,
    /// Operation attributes/children outside the admitted grammar.
    pub unsupported_extensions: usize,
}
impl LifecycleOperation {
    /// Whether the full operation has the supported integer-only meaning.
    #[must_use]
    pub fn has_unsupported_content(&self) -> bool {
        self.unsupported_extensions != 0
            || self
                .from
                .iter()
                .chain(&self.to)
                .any(|value| !value.is_supported())
    }
}

/// Original frame-local lifecycle declarations. UTC and Source remain vendor strings.
#[derive(Clone, Eq, PartialEq)]
pub struct LifecycleFrame {
    /// Zero-based Frame ordinal across all VideoAnalytics sections in this document.
    pub frame_index: usize,
    /// Original MetadataStream child position of the enclosing VideoAnalytics section.
    pub section_index: usize,
    /// Original child position within that VideoAnalytics section, including extensions.
    pub section_child_index: usize,
    /// Original accepted UTC lexical value, never a trusted clock binding.
    pub utc_time: String,
    /// Original optional analytics module name; missing/empty values stay distinct.
    pub source: Option<String>,
    /// Original Object occurrences, never coalesced by matching ID spellings.
    pub objects: Vec<LifecycleObject>,
    /// Known lifecycle operations in original document order.
    pub operations: Vec<LifecycleOperation>,
    /// Position of the original ObjectTree, including a present-empty ObjectTree.
    pub object_tree_child_index: Option<usize>,
    /// Unknown frame fields/attributes and ObjectTree attributes/unknown children.
    pub unsupported_extensions: usize,
}
impl LifecycleFrame {
    /// Unknown lifecycle semantics, excluding Appearance/Transformation interpreted
    /// separately by the frozen analytics parser. Consumers must retain those flags too.
    #[must_use]
    pub fn has_unsupported_content(&self) -> bool {
        self.unsupported_extensions != 0
            || self
                .objects
                .iter()
                .any(LifecycleObject::has_unsupported_content)
            || self
                .operations
                .iter()
                .any(LifecycleOperation::has_unsupported_content)
    }
}
impl fmt::Debug for LifecycleFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LifecycleFrame")
            .field("frame_index", &self.frame_index)
            .field("section_index", &self.section_index)
            .field("section_child_index", &self.section_child_index)
            .field("objects", &self.objects.len())
            .field("operations", &self.operations.len())
            .field("unsupported_content", &self.has_unsupported_content())
            .finish_non_exhaustive()
    }
}

/// Complete additive interpretation of one original MetadataStream document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleDocument {
    /// Every typed frame, including empty and lifecycle-only frames.
    pub frames: Vec<LifecycleFrame>,
    /// Outer/section attributes or unknown/nonanalytics sections, including Event.
    pub unsupported_sections: usize,
    /// Number of known lifecycle operation occurrences across all frames.
    pub operation_count: usize,
    /// Number of original object and operation references, including unsupported ones.
    pub reference_count: usize,
    /// Full nonrefundable preflight quote consumed by this complete parse.
    pub work_units: u64,
}
impl LifecycleDocument {
    /// Whether any source-level or lifecycle-level semantics remain uninterpreted.
    #[must_use]
    pub fn has_unsupported_content(&self) -> bool {
        self.unsupported_sections != 0
            || self
                .frames
                .iter()
                .any(LifecycleFrame::has_unsupported_content)
    }
}

/// Interpret one complete MetadataStream without changing existing parser acceptance.
///
/// The callback is checked before/after the independently bounded XML parse, for each
/// traversed section/frame/object/operation/reference, and immediately before success.
/// Refusal returns no partial document. SOAP PullMessages is outside this additive subset.
pub fn parse_metadata_lifecycle_document<F: FnMut() -> bool>(
    bytes: &[u8],
    limits: LifecycleParseLimits,
    mut admitted: F,
) -> Result<LifecycleDocument, LifecycleWireError> {
    limits.validate()?;
    let work_units = lifecycle_parse_work_bound(bytes.len())
        .ok_or(LifecycleWireError::Wire(WireError::InputTooLarge))?;
    if work_units > limits.max_work_units {
        return Err(LifecycleWireError::Limit);
    }
    let mut parser = Parser {
        limits,
        admitted: &mut admitted,
        objects: 0,
        operations: 0,
        references: 0,
    };
    parser.checkpoint()?;
    let doc = xml::Document::parse(bytes)?;
    parser.checkpoint()?;
    let root = doc.root();
    if !doc.named(root, SCHEMA_NS, "MetadataStream") {
        return Err(WireError::UnexpectedResponse.into());
    }
    whitespace(&doc, root)?;
    let mut result = LifecycleDocument {
        frames: Vec::new(),
        unsupported_sections: doc.attribute_count(root),
        operation_count: 0,
        reference_count: 0,
        work_units,
    };
    for (section_index, section) in doc.child_ids(root).enumerate() {
        parser.checkpoint()?;
        if !doc.named(section, SCHEMA_NS, "VideoAnalytics") {
            result.unsupported_sections += 1;
            continue;
        }
        whitespace(&doc, section)?;
        result.unsupported_sections += doc.attribute_count(section);
        for (section_child_index, child) in doc.child_ids(section).enumerate() {
            parser.checkpoint()?;
            if doc.named(child, SCHEMA_NS, "Frame") {
                if result.frames.len() == limits.max_frames {
                    return Err(LifecycleWireError::Limit);
                }
                let frame = parser.frame(
                    &doc,
                    child,
                    result.frames.len(),
                    section_index,
                    section_child_index,
                )?;
                push(&mut result.frames, frame)?;
            } else {
                result.unsupported_sections += 1;
            }
        }
    }
    parser.checkpoint()?;
    result.operation_count = parser.operations;
    result.reference_count = parser.references;
    Ok(result)
}

struct Parser<'a, F> {
    limits: LifecycleParseLimits,
    admitted: &'a mut F,
    objects: usize,
    operations: usize,
    references: usize,
}

impl<F: FnMut() -> bool> Parser<'_, F> {
    fn checkpoint(&mut self) -> Result<(), LifecycleWireError> {
        if !(self.admitted)() {
            return Err(LifecycleWireError::Cancelled);
        }
        Ok(())
    }

    fn frame(
        &mut self,
        doc: &xml::Document,
        id: usize,
        frame_index: usize,
        section_index: usize,
        section_child_index: usize,
    ) -> Result<LifecycleFrame, LifecycleWireError> {
        self.checkpoint()?;
        whitespace(doc, id)?;
        let utc_time = doc
            .attribute(id, "", "UtcTime")
            .ok_or(WireError::MissingField)?;
        timestamp(utc_time)?;
        let source = doc.attribute(id, "", "Source").map(label).transpose()?;
        // Duplicate known containers never become a partial successful interpretation.
        unique(doc, id, SCHEMA_NS, "Transformation")?;
        unique(doc, id, SCHEMA_NS, "ObjectTree")?;
        let mut result = LifecycleFrame {
            frame_index,
            section_index,
            section_child_index,
            utc_time: utc_time.to_owned(),
            source,
            objects: Vec::new(),
            operations: Vec::new(),
            object_tree_child_index: None,
            unsupported_extensions: unknown_attributes(doc, id, &["UtcTime", "Source"]),
        };
        for (frame_child_index, child) in doc.child_ids(id).enumerate() {
            self.checkpoint()?;
            if doc.named(child, SCHEMA_NS, "Object") {
                if self.objects == self.limits.max_objects
                    || result.objects.len() == MAX_ANALYTICS_OBJECTS_PER_FRAME
                {
                    return Err(LifecycleWireError::Limit);
                }
                let object = self.object(doc, child, result.objects.len(), frame_child_index)?;
                self.objects += 1;
                push(&mut result.objects, object)?;
            } else if doc.named(child, SCHEMA_NS, "ObjectTree") {
                result.object_tree_child_index = Some(frame_child_index);
                whitespace(doc, child)?;
                result.unsupported_extensions += doc.attribute_count(child);
                for (tree_child_index, operation) in doc.child_ids(child).enumerate() {
                    self.checkpoint()?;
                    let kind = match doc.expanded_name(operation) {
                        (SCHEMA_NS, "Rename") => LifecycleOperationKind::Rename,
                        (SCHEMA_NS, "Split") => LifecycleOperationKind::Split,
                        (SCHEMA_NS, "Merge") => LifecycleOperationKind::Merge,
                        (SCHEMA_NS, "Delete") => LifecycleOperationKind::Delete,
                        _ => {
                            result.unsupported_extensions += 1;
                            continue;
                        }
                    };
                    if self.operations == self.limits.max_operations {
                        return Err(LifecycleWireError::Limit);
                    }
                    let operation = self.operation(
                        doc,
                        operation,
                        kind,
                        result.operations.len(),
                        tree_child_index,
                    )?;
                    self.operations += 1;
                    push(&mut result.operations, operation)?;
                }
            } else if !doc.named(child, SCHEMA_NS, "Transformation") {
                result.unsupported_extensions += 1;
            }
        }
        Ok(result)
    }

    fn object(
        &mut self,
        doc: &xml::Document,
        id: usize,
        object_index: usize,
        frame_child_index: usize,
    ) -> Result<LifecycleObject, LifecycleWireError> {
        self.checkpoint()?;
        whitespace(doc, id)?;
        unique(doc, id, SCHEMA_NS, "Appearance")?;
        let behaviour_id = unique(doc, id, SCHEMA_NS, "Behaviour")?;
        let reference = self.reference(doc, id, false)?;
        let behaviour = behaviour_id
            .map(|child| self.behaviour(doc, child))
            .transpose()?;
        let mut unsupported_extensions = 0;
        for child in doc.child_ids(id) {
            self.checkpoint()?;
            if !doc.named(child, SCHEMA_NS, "Appearance")
                && !doc.named(child, SCHEMA_NS, "Behaviour")
            {
                unsupported_extensions += 1;
            }
        }
        Ok(LifecycleObject {
            object_index,
            frame_child_index,
            reference,
            behaviour,
            unsupported_extensions,
        })
    }

    fn behaviour(
        &mut self,
        doc: &xml::Document,
        id: usize,
    ) -> Result<LifecycleBehaviour, LifecycleWireError> {
        self.checkpoint()?;
        whitespace(doc, id)?;
        unique(doc, id, SCHEMA_NS, "Idle")?;
        unique(doc, id, SCHEMA_NS, "Removed")?;
        let mut result = LifecycleBehaviour {
            idle: false,
            removed: false,
            unsupported_extensions: doc.attribute_count(id),
        };
        for child in doc.child_ids(id) {
            self.checkpoint()?;
            if doc.named(child, SCHEMA_NS, "Idle") || doc.named(child, SCHEMA_NS, "Removed") {
                whitespace(doc, child)?;
                result.idle |= doc.named(child, SCHEMA_NS, "Idle");
                result.removed |= doc.named(child, SCHEMA_NS, "Removed");
                result.unsupported_extensions +=
                    doc.attribute_count(child) + doc.child_ids(child).count();
            } else {
                result.unsupported_extensions += 1;
            }
        }
        Ok(result)
    }

    fn operation(
        &mut self,
        doc: &xml::Document,
        id: usize,
        kind: LifecycleOperationKind,
        operation_index: usize,
        tree_child_index: usize,
    ) -> Result<LifecycleOperation, LifecycleWireError> {
        self.checkpoint()?;
        whitespace(doc, id)?;
        let mut result = LifecycleOperation {
            operation_index,
            tree_child_index,
            kind,
            from: Vec::new(),
            to: Vec::new(),
            unsupported_extensions: 0,
        };
        if kind == LifecycleOperationKind::Delete {
            push(&mut result.from, self.reference(doc, id, true)?)?;
            return Ok(result);
        }
        result.unsupported_extensions = doc.attribute_count(id);
        let mut to_started = false;
        for child in doc.child_ids(id) {
            self.checkpoint()?;
            if doc.named(child, SCHEMA_NS, "from") {
                if to_started {
                    return Err(WireError::InvalidField.into());
                }
                push(&mut result.from, self.reference(doc, child, true)?)?;
            } else if doc.named(child, SCHEMA_NS, "to") {
                to_started = true;
                push(&mut result.to, self.reference(doc, child, true)?)?;
            } else {
                result.unsupported_extensions += 1;
            }
        }
        let valid = match kind {
            LifecycleOperationKind::Rename => result.from.len() == 1 && result.to.len() == 1,
            LifecycleOperationKind::Split => result.from.len() == 1 && result.to.len() >= 2,
            LifecycleOperationKind::Merge => result.from.len() >= 2 && result.to.len() == 1,
            LifecycleOperationKind::Delete => false,
        };
        if !valid {
            return Err(WireError::InvalidField.into());
        }
        Ok(result)
    }

    fn reference(
        &mut self,
        doc: &xml::Document,
        id: usize,
        endpoint: bool,
    ) -> Result<LifecycleReference, LifecycleWireError> {
        self.checkpoint()?;
        if self.references == self.limits.max_references {
            return Err(LifecycleWireError::Limit);
        }
        whitespace(doc, id)?;
        let object_id = doc
            .attribute(id, "", "ObjectId")
            .map(|value| {
                analytics_object_key(value)?;
                Ok::<_, WireError>(value.to_owned())
            })
            .transpose()?;
        let uuid = doc.attribute(id, "", "UUID").map(label).transpose()?;
        self.references += 1;
        Ok(LifecycleReference {
            object_id,
            uuid,
            unsupported_extensions: unknown_attributes(doc, id, &["ObjectId", "UUID"])
                + if endpoint {
                    doc.child_ids(id).count()
                } else {
                    0
                },
        })
    }
}

fn whitespace(doc: &xml::Document, id: usize) -> Result<(), WireError> {
    if !doc.only_whitespace(id) {
        return Err(WireError::InvalidField);
    }
    Ok(())
}

fn label(value: &str) -> Result<String, WireError> {
    if value.len() > MAX_LIFECYCLE_LABEL_BYTES || value.chars().any(char::is_control) {
        return Err(WireError::InvalidField);
    }
    Ok(value.to_owned())
}

fn push<T>(values: &mut Vec<T>, value: T) -> Result<(), LifecycleWireError> {
    values
        .try_reserve(1)
        .map_err(|_| LifecycleWireError::Limit)?;
    values.push(value);
    Ok(())
}

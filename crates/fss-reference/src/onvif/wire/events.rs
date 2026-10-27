#![forbid(unsafe_code)]
//! Bounded ONVIF event metadata projection (FSS-046).
//!
//! ONVIF Core section 9 and `metadatastream.xsd` define the input grammar.
//! These are vendor-derived claims, never corroborated observations, absence
//! witnesses, trusted capture clocks, biometric authority, or effect requests.
//! Complex values and unsupported stream sections remain explicitly unparsed;
//! a retaining caller must keep the complete source bytes for later hydration.

use std::fmt;

use super::{SCHEMA_NS, SOAP_NS, UtcDateTime, WireError, required, response, scalar, unique, xml};

const EVENTS_NS: &str = "http://www.onvif.org/ver10/events/wsdl";
const NOTIFICATION_NS: &str = "http://docs.oasis-open.org/wsn/b-2";
const CONCRETE_SET: &str = "http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet";
const CONCRETE: &str = "http://docs.oasis-open.org/wsn/t-1/TopicExpression/Concrete";

/// Maximum number of notification messages in a complete input document.
pub const MAX_EVENT_NOTIFICATIONS: usize = 128;
/// Maximum combined simple and complex items per Source, Key, or Data group.
pub const MAX_EVENT_ITEMS: usize = 64;
/// Maximum UTF-8 bytes in one vendor-provided simple value.
pub const MAX_EVENT_VALUE_BYTES: usize = 1024;
const MAX_ITEM_NAME_BYTES: usize = 128;
const MAX_TOPIC_BYTES: usize = 2048;
const MAX_TOPIC_PARTS: usize = 16;

/// The observed transport container; neither form proves live continuity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventDocumentFormat {
    /// A complete SOAP 1.2 PullMessagesResponse.
    PullMessages,
    /// A complete ONVIF MetadataStream document, such as a recorded RTP payload.
    MetadataStream,
}

/// Device-declared property lifecycle. Missing is distinct from Changed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PropertyOperation {
    /// Initial state supplied by the device.
    Initialized,
    /// An existing property changed.
    Changed,
    /// The device removed the named property.
    Deleted,
}

/// A concrete topic with its namespace resolved independently of prefix spelling.
#[derive(Clone, Eq, PartialEq)]
pub struct EventTopic {
    /// Exact namespace of the topic tree, including vendor namespaces.
    pub namespace: String,
    /// Ordered local names of the concrete path; never an XPath or filter.
    pub path: Vec<String>,
}

/// One uninterpreted, tainted vendor value. Names do not authorize operations.
#[derive(Clone, Eq, PartialEq)]
pub struct SimpleItem {
    /// Device-provided item name.
    pub name: String,
    /// Exact XML-decoded value; no inference of boolean, identity, or authority.
    pub value: String,
}

/// A present item group. An absent group is represented separately by Option.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct EventItems {
    /// Bounded simple values, in original source order.
    pub simple_items: Vec<SimpleItem>,
    /// Complex item names whose XML values require source hydration.
    pub element_items: Vec<String>,
    /// Extension children and attributes retained in source but not interpreted.
    pub unsupported_extensions: usize,
}

/// One notification, always attributed to the vendor rather than FSS perception.
#[derive(Clone, Eq, PartialEq)]
pub struct EventNotification {
    /// Namespace-resolved concrete topic; a topic never grants a capability.
    pub topic: EventTopic,
    /// Validated device-declared UTC lexical value, not a trusted capture time.
    pub utc_time: String,
    /// Optional property lifecycle; pure events need not declare one.
    pub property_operation: Option<PropertyOperation>,
    /// Optional source tokens; source absence is not an empty token set.
    pub source: Option<EventItems>,
    /// Optional property-key items.
    pub key: Option<EventItems>,
    /// Optional event values.
    pub data: Option<EventItems>,
    /// Uninterpreted wrapper/message fields and attributes, including endpoint references.
    pub unsupported_extensions: usize,
}

/// Complete bounded event projection with explicit unsupported-content accounting.
#[derive(Clone, Eq, PartialEq)]
pub struct EventDocument {
    /// Observed source container.
    pub format: EventDocumentFormat,
    /// Device-declared PullPoint time; absent in MetadataStream.
    pub current_time: Option<String>,
    /// Device-declared subscription expiry; absent in MetadataStream.
    pub termination_time: Option<String>,
    /// All accepted notifications, without deduplication or reordering.
    pub notifications: Vec<EventNotification>,
    /// Stream sections and response extension fields/attributes not interpreted here.
    pub unsupported_sections: usize,
}

impl EventDocument {
    /// Whether any source content remains outside the typed event projection.
    /// False does not certify coverage, absence, or Profile M conformance.
    #[must_use]
    pub fn has_unsupported_content(&self) -> bool {
        self.unsupported_sections != 0
            || self.notifications.iter().any(|notification| {
                notification.unsupported_extensions != 0
                    || [
                        notification.source.as_ref(),
                        notification.key.as_ref(),
                        notification.data.as_ref(),
                    ]
                    .into_iter()
                    .flatten()
                    .any(|items| {
                        !items.element_items.is_empty() || items.unsupported_extensions != 0
                    })
            })
    }
}

impl fmt::Debug for EventTopic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventTopic")
            .field("parts", &self.path.len())
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for SimpleItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SimpleItem([untrusted metadata])")
    }
}
impl fmt::Debug for EventItems {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventItems")
            .field("simple_items", &self.simple_items.len())
            .field("element_items", &self.element_items.len())
            .field("unsupported_extensions", &self.unsupported_extensions)
            .finish()
    }
}
impl fmt::Debug for EventNotification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventNotification")
            .field("property_operation", &self.property_operation)
            .field("unsupported_extensions", &self.unsupported_extensions)
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for EventDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventDocument")
            .field("format", &self.format)
            .field("notifications", &self.notifications.len())
            .field("unsupported_content", &self.has_unsupported_content())
            .finish_non_exhaustive()
    }
}

/// Parse a complete PullMessages SOAP response or MetadataStream XML document.
///
/// The existing XML parser bounds bytes, depth, attributes, nodes and text and
/// refuses DTDs/external entities. This subset requires explicit UTC `Z` times
/// (1970–9999, up to nine fractional digits) and concrete topics. It does not
/// flatten missing groups, unknown property operations, or complex item values.
pub fn parse_event_document(bytes: &[u8]) -> Result<EventDocument, WireError> {
    let doc = xml::Document::parse(bytes)?;
    let root = doc.root();
    if doc.named(root, SOAP_NS, "Envelope") {
        drop(doc);
        let (doc, root) = response(bytes, EVENTS_NS, "PullMessagesResponse")?;
        let current = scalar(&doc, required(&doc, root, EVENTS_NS, "CurrentTime")?)?;
        let termination = scalar(&doc, required(&doc, root, EVENTS_NS, "TerminationTime")?)?;
        timestamp(current)?;
        timestamp(termination)?;
        let mut result = EventDocument {
            format: EventDocumentFormat::PullMessages,
            current_time: Some(current.to_owned()),
            termination_time: Some(termination.to_owned()),
            notifications: Vec::new(),
            unsupported_sections: doc.attribute_count(root),
        };
        for child in doc.child_ids(root) {
            if doc.named(child, NOTIFICATION_NS, "NotificationMessage") {
                push_notification(&doc, child, &mut result)?;
            } else if !doc.named(child, EVENTS_NS, "CurrentTime")
                && !doc.named(child, EVENTS_NS, "TerminationTime")
            {
                result.unsupported_sections += 1;
            }
        }
        return Ok(result);
    }
    if !doc.named(root, SCHEMA_NS, "MetadataStream") || !doc.only_whitespace(root) {
        return Err(WireError::UnexpectedResponse);
    }
    let mut result = EventDocument {
        format: EventDocumentFormat::MetadataStream,
        current_time: None,
        termination_time: None,
        notifications: Vec::new(),
        unsupported_sections: doc.attribute_count(root),
    };
    for section in doc.child_ids(root) {
        if doc.named(section, SCHEMA_NS, "Event") {
            result.unsupported_sections += doc.attribute_count(section);
            if !doc.only_whitespace(section) {
                return Err(WireError::InvalidField);
            }
            for child in doc.child_ids(section) {
                if doc.named(child, NOTIFICATION_NS, "NotificationMessage") {
                    push_notification(&doc, child, &mut result)?;
                } else {
                    result.unsupported_sections += 1;
                }
            }
        } else {
            // VideoAnalytics, PTZ, extensions, and vendor additions retain their
            // bytes but cannot masquerade as interpreted event observations.
            result.unsupported_sections += 1;
        }
    }
    Ok(result)
}

fn push_notification(
    doc: &xml::Document,
    id: usize,
    result: &mut EventDocument,
) -> Result<(), WireError> {
    if result.notifications.len() == MAX_EVENT_NOTIFICATIONS {
        return Err(WireError::EventLimitExceeded);
    }
    result.notifications.push(notification(doc, id)?);
    Ok(())
}

fn notification(doc: &xml::Document, id: usize) -> Result<EventNotification, WireError> {
    let topic_id = required(doc, id, NOTIFICATION_NS, "Topic")?;
    let container = required(doc, id, NOTIFICATION_NS, "Message")?;
    let message = required(doc, container, SCHEMA_NS, "Message")?;
    // The accepted subset has exactly one ONVIF message in each notification.
    // Refuse extra payloads rather than publishing a deceptively partial message.
    if doc.child_ids(container).count() != 1 {
        return Err(WireError::UnexpectedResponse);
    }
    let utc_time = doc
        .attribute(message, "", "UtcTime")
        .ok_or(WireError::MissingField)?;
    timestamp(utc_time)?;
    let property_operation = match doc.attribute(message, "", "PropertyOperation") {
        None => None,
        Some("Initialized") => Some(PropertyOperation::Initialized),
        Some("Changed") => Some(PropertyOperation::Changed),
        Some("Deleted") => Some(PropertyOperation::Deleted),
        Some(_) => return Err(WireError::InvalidField),
    };
    let mut unsupported_extensions = doc.child_ids(id).count() - 2
        + doc.attribute_count(id)
        + doc.attribute_count(container)
        + unknown_attributes(doc, topic_id, &["Dialect"])
        + unknown_attributes(doc, message, &["UtcTime", "PropertyOperation"]);
    for child in doc.child_ids(message) {
        if !["Source", "Key", "Data"]
            .into_iter()
            .any(|name| doc.named(child, SCHEMA_NS, name))
        {
            unsupported_extensions += 1;
        }
    }
    Ok(EventNotification {
        topic: topic(doc, topic_id)?,
        utc_time: utc_time.to_owned(),
        property_operation,
        source: group(doc, message, "Source")?,
        key: group(doc, message, "Key")?,
        data: group(doc, message, "Data")?,
        unsupported_extensions,
    })
}

fn topic(doc: &xml::Document, id: usize) -> Result<EventTopic, WireError> {
    match doc.attribute(id, "", "Dialect") {
        Some(CONCRETE_SET | CONCRETE) => {}
        _ => return Err(WireError::UnsupportedEventContent),
    }
    let text = scalar(doc, id)?;
    if text.is_empty() || text.len() > MAX_TOPIC_BYTES {
        return Err(WireError::InvalidField);
    }
    let mut parts = text.split('/');
    let first = parts.next().ok_or(WireError::InvalidField)?;
    let (namespace, first_local) = doc.resolve_qname(id, first)?;
    if namespace.is_empty() {
        return Err(WireError::InvalidField);
    }
    let mut path = vec![first_local.to_owned()];
    for part in parts {
        if path.len() == MAX_TOPIC_PARTS || part.is_empty() {
            return Err(WireError::InvalidField);
        }
        let (_, local) = doc.resolve_qname(id, part)?;
        if part.contains(':') && doc.resolve_qname(id, part)?.0 != namespace {
            return Err(WireError::UnsupportedEventContent);
        }
        path.push(local.to_owned());
    }
    Ok(EventTopic {
        namespace: namespace.to_owned(),
        path,
    })
}

fn group(doc: &xml::Document, message: usize, name: &str) -> Result<Option<EventItems>, WireError> {
    let Some(id) = unique(doc, message, SCHEMA_NS, name)? else {
        return Ok(None);
    };
    if !doc.only_whitespace(id) {
        return Err(WireError::InvalidField);
    }
    let mut result = EventItems {
        unsupported_extensions: doc.attribute_count(id),
        ..EventItems::default()
    };
    let mut names = std::collections::BTreeSet::new();
    for child in doc.child_ids(id) {
        let simple = doc.named(child, SCHEMA_NS, "SimpleItem");
        let complex = doc.named(child, SCHEMA_NS, "ElementItem");
        if !simple && !complex {
            result.unsupported_extensions += 1;
            continue;
        }
        if names.len() == MAX_EVENT_ITEMS {
            return Err(WireError::ItemLimitExceeded);
        }
        let name = doc
            .attribute(child, "", "Name")
            .ok_or(WireError::MissingField)?;
        bounded_text(name, MAX_ITEM_NAME_BYTES, false)?;
        if !names.insert(name.to_owned()) {
            return Err(WireError::DuplicateField);
        }
        if simple {
            result.unsupported_extensions += unknown_attributes(doc, child, &["Name", "Value"]);
            if doc.child_ids(child).next().is_some() || !doc.only_whitespace(child) {
                return Err(WireError::InvalidField);
            }
            let value = doc
                .attribute(child, "", "Value")
                .ok_or(WireError::MissingField)?;
            bounded_text(value, MAX_EVENT_VALUE_BYTES, true)?;
            result.simple_items.push(SimpleItem {
                name: name.to_owned(),
                value: value.to_owned(),
            });
        } else {
            result.unsupported_extensions += unknown_attributes(doc, child, &["Name"]);
            if doc.child_ids(child).count() != 1 || !doc.only_whitespace(child) {
                return Err(WireError::InvalidField);
            }
            result.element_items.push(name.to_owned());
        }
    }
    Ok(Some(result))
}

fn unknown_attributes(doc: &xml::Document, id: usize, known: &[&str]) -> usize {
    doc.attribute_count(id)
        - known
            .iter()
            .filter(|name| doc.attribute(id, "", name).is_some())
            .count()
}

fn bounded_text(value: &str, max: usize, empty: bool) -> Result<(), WireError> {
    if (!empty && value.is_empty()) || value.len() > max || value.chars().any(char::is_control) {
        return Err(WireError::InvalidField);
    }
    Ok(())
}

fn timestamp(value: &str) -> Result<(), WireError> {
    let bytes = value.as_bytes();
    if !(20..=30).contains(&bytes.len())
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || bytes.last() != Some(&b'Z')
    {
        return Err(WireError::InvalidField);
    }
    if bytes.len() > 20
        && (bytes[19] != b'.'
            || bytes.len() == 21
            || !bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit))
    {
        return Err(WireError::InvalidField);
    }
    let number = |start: usize, end: usize| -> Result<u16, WireError> {
        let digits = &bytes[start..end];
        if !digits.iter().all(u8::is_ascii_digit) {
            return Err(WireError::InvalidField);
        }
        digits.iter().try_fold(0_u16, |n, digit| {
            n.checked_mul(10)
                .and_then(|n| n.checked_add(u16::from(*digit - b'0')))
                .ok_or(WireError::InvalidField)
        })
    };
    UtcDateTime::new(
        number(0, 4)?,
        number(5, 7)? as u8,
        number(8, 10)? as u8,
        number(11, 13)? as u8,
        number(14, 16)? as u8,
        number(17, 19)? as u8,
    )?;
    Ok(())
}

#![forbid(unsafe_code)]
//! Bounded ONVIF real-time PullPoint message construction and parsing.
//!
//! Contracts: ONVIF event.wsdl, WS-BaseNotification 1.3 and WS-Addressing 1.0.
//! Subscription creation/renewal/deletion changes remote transient state. The
//! caller must own that explicit capability; these bytes grant no authority.
//! Reported subscription clocks are vendor claims, never capture-time truth.

use std::fmt;

use super::{
    EventDocument, EventDocumentFormat, MAX_EVENT_NOTIFICATIONS, MAX_URI_BYTES, OnvifOperation,
    SOAP_NS, SoapRequest, WireError, events, parse_boolean, required, response_with_addressing,
    scalar, unique, uri_text, xml,
};

const EVENTS_NS: &str = "http://www.onvif.org/ver10/events/wsdl";
const NOTIFICATION_NS: &str = "http://docs.oasis-open.org/wsn/b-2";
pub(super) const ADDRESSING_NS: &str = "http://www.w3.org/2005/08/addressing";
pub(super) const ANONYMOUS: &str = "http://www.w3.org/2005/08/addressing/anonymous";

pub(super) const CREATE_RESPONSE: &str =
    "http://www.onvif.org/ver10/events/wsdl/EventPortType/CreatePullPointSubscriptionResponse";
pub(super) const PULL_RESPONSE: &str =
    "http://www.onvif.org/ver10/events/wsdl/PullPointSubscription/PullMessagesResponse";
const RENEW_RESPONSE: &str =
    "http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/RenewResponse";
const UNSUBSCRIBE_RESPONSE: &str =
    "http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/UnsubscribeResponse";

/// Maximum requested lease, independently of any device-reported longer lease.
pub const MAX_PULL_POINT_LIFETIME_SECONDS: u32 = 3600;
/// Maximum blocking interval requested in a single PullMessages operation.
pub const MAX_PULL_TIMEOUT_SECONDS: u32 = 30;
/// Complete endpoint-reference parameter count; no tail is silently omitted.
pub const MAX_REFERENCE_PARAMETERS: usize = 8;
const MAX_PARAMETER_BYTES: usize = 1024;
const MAX_PARAMETER_NAMESPACES: usize = 64;

/// Parsed lease times. Both strings are exact device-declared UTC values; the
/// interval is a conservative whole-second difference, not an owned clock.
#[derive(Clone, Eq, PartialEq)]
pub struct PullPointLease {
    current_time: String,
    termination_time: String,
    seconds: u32,
}

impl PullPointLease {
    /// Exact device-reported current time.
    #[must_use]
    pub fn current_time(&self) -> &str {
        &self.current_time
    }

    /// Exact device-reported expiry.
    #[must_use]
    pub fn termination_time(&self) -> &str {
        &self.termination_time
    }

    /// Floor of the device-reported expiry minus its current time. This cannot
    /// extend the independently owned monotonic deadline or prove continuity.
    #[must_use]
    pub const fn lease_seconds(&self) -> u32 {
        self.seconds
    }
}

impl fmt::Debug for PullPointLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PullPointLease")
            .field("reported_seconds", &self.seconds)
            .finish_non_exhaustive()
    }
}

/// A fully parsed subscription endpoint reference. Private fields prevent
/// callers from injecting unparsed XML into subsequent subscription headers.
/// The returned address must pass independent owner route validation before I/O.
#[derive(Clone, Eq, PartialEq)]
pub struct PullPointSubscription {
    endpoint: String,
    reference_parameters: Vec<String>,
    lease: PullPointLease,
}

impl PullPointSubscription {
    /// Untrusted endpoint address, including any subscription query component.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Exact device-reported current time.
    #[must_use]
    pub fn current_time(&self) -> &str {
        self.lease.current_time()
    }

    /// Exact device-reported expiry.
    #[must_use]
    pub fn termination_time(&self) -> &str {
        self.lease.termination_time()
    }

    /// Conservative whole-second device-reported lease interval.
    #[must_use]
    pub const fn lease_seconds(&self) -> u32 {
        self.lease.lease_seconds()
    }

    /// Number of complete scalar reference parameters copied to request headers.
    #[must_use]
    pub fn reference_parameter_count(&self) -> usize {
        self.reference_parameters.len()
    }
}

impl fmt::Debug for PullPointSubscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PullPointSubscription")
            .field("reference_parameters", &self.reference_parameters.len())
            .field("lease", &self.lease)
            .finish_non_exhaustive()
    }
}

/// Request an explicitly finite, unfiltered pull subscription. No consumer
/// callback URI, push delivery, filter language, or remote policy is installed.
pub fn create_pull_point_request(
    endpoint: &str,
    lifetime_seconds: u32,
) -> Result<SoapRequest, WireError> {
    lifetime(lifetime_seconds)?;
    addressed_request(
        OnvifOperation::CreatePullPointSubscription,
        endpoint,
        &[],
        &format!(
            "<tev:CreatePullPointSubscription><tev:InitialTerminationTime>PT{lifetime_seconds}S</tev:InitialTerminationTime></tev:CreatePullPointSubscription>"
        ),
    )
}

/// Pull up to the exact bounded message limit. The caller must reserve separate
/// time and authority for cleanup; device timeout never extends that deadline.
pub fn pull_messages_request(
    subscription: &PullPointSubscription,
    timeout_seconds: u32,
    message_limit: u16,
) -> Result<SoapRequest, WireError> {
    if !(1..=MAX_PULL_TIMEOUT_SECONDS).contains(&timeout_seconds)
        || message_limit == 0
        || usize::from(message_limit) > MAX_EVENT_NOTIFICATIONS
    {
        return Err(WireError::InvalidField);
    }
    addressed_request(
        OnvifOperation::PullMessages,
        subscription.endpoint(),
        &subscription.reference_parameters,
        &format!(
            "<tev:PullMessages><tev:Timeout>PT{timeout_seconds}S</tev:Timeout><tev:MessageLimit>{message_limit}</tev:MessageLimit></tev:PullMessages>"
        ),
    )
}

/// Request a finite replacement expiry. Construction alone neither renews a
/// lease nor authorizes a longer live session.
pub fn renew_pull_point_request(
    subscription: &PullPointSubscription,
    lifetime_seconds: u32,
) -> Result<SoapRequest, WireError> {
    lifetime(lifetime_seconds)?;
    addressed_request(
        OnvifOperation::RenewPullPoint,
        subscription.endpoint(),
        &subscription.reference_parameters,
        &format!(
            "<wsnt:Renew><wsnt:TerminationTime>PT{lifetime_seconds}S</wsnt:TerminationTime></wsnt:Renew>"
        ),
    )
}

/// Delete exactly the acquired remote transient subscription. A lost response
/// remains indeterminate; no destructor performs hidden network cleanup.
pub fn unsubscribe_pull_point_request(
    subscription: &PullPointSubscription,
) -> Result<SoapRequest, WireError> {
    addressed_request(
        OnvifOperation::UnsubscribePullPoint,
        subscription.endpoint(),
        &subscription.reference_parameters,
        "<wsnt:Unsubscribe/>",
    )
}

fn lifetime(seconds: u32) -> Result<(), WireError> {
    if !(1..=MAX_PULL_POINT_LIFETIME_SECONDS).contains(&seconds) {
        return Err(WireError::InvalidField);
    }
    Ok(())
}

fn addressed_request(
    operation: OnvifOperation,
    endpoint: &str,
    parameters: &[String],
    content: &str,
) -> Result<SoapRequest, WireError> {
    // URI routing is independently constrained by the transport. This check
    // admits bounded URI text only; XML escaping cannot grant network authority.
    if endpoint.is_empty()
        || endpoint.len() > MAX_URI_BYTES
        || !endpoint.starts_with("http://") && !endpoint.starts_with("https://")
        || endpoint
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
        || endpoint.bytes().any(|byte| b"<\">\\#".contains(&byte))
    {
        return Err(WireError::InvalidField);
    }
    let action = operation.action();
    let endpoint = escaped(endpoint);
    let parameters = parameters.concat();
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><s:Envelope xmlns:s=\"{SOAP_NS}\" xmlns:tev=\"{EVENTS_NS}\" xmlns:wsnt=\"{NOTIFICATION_NS}\" xmlns:wsa=\"{ADDRESSING_NS}\"><s:Header><wsa:Action s:mustUnderstand=\"1\">{action}</wsa:Action><wsa:To s:mustUnderstand=\"1\">{endpoint}</wsa:To><wsa:ReplyTo><wsa:Address>{ANONYMOUS}</wsa:Address></wsa:ReplyTo>{parameters}</s:Header><s:Body>{content}</s:Body></s:Envelope>"
    ).into_bytes();
    if body.len() > super::MAX_SOAP_BYTES {
        return Err(WireError::InputTooLarge);
    }
    Ok(SoapRequest {
        action,
        body,
        username_token: false,
    })
}

/// Parse a successful CreatePullPointSubscriptionResponse without following its
/// endpoint. Scalar reference parameters are preserved with in-scope namespace
/// bindings; complex or attributed parameters are explicitly unsupported.
/// Uninterpreted endpoint-reference children are refused, never silently dropped.
pub fn parse_pull_point_subscription(bytes: &[u8]) -> Result<PullPointSubscription, WireError> {
    let (doc, root) = response_with_addressing(
        bytes,
        EVENTS_NS,
        "CreatePullPointSubscriptionResponse",
        Some(CREATE_RESPONSE),
    )?;
    exact_children(
        &doc,
        root,
        &[
            (EVENTS_NS, "SubscriptionReference"),
            (NOTIFICATION_NS, "CurrentTime"),
            (NOTIFICATION_NS, "TerminationTime"),
        ],
    )?;
    let reference = required(&doc, root, EVENTS_NS, "SubscriptionReference")?;
    exact_children(
        &doc,
        reference,
        &[
            (ADDRESSING_NS, "Address"),
            (ADDRESSING_NS, "ReferenceParameters"),
        ],
    )?;
    let address = required(&doc, reference, ADDRESSING_NS, "Address")?;
    if doc.attribute_count(address) != 0 {
        return Err(WireError::UnsupportedEventContent);
    }
    let endpoint = uri_text(&doc, address)?.to_owned();
    let mut reference_parameters = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    if let Some(parameters) = unique(&doc, reference, ADDRESSING_NS, "ReferenceParameters")? {
        if doc.attribute_count(parameters) != 0 || !doc.only_whitespace(parameters) {
            return Err(WireError::UnsupportedEventContent);
        }
        for id in doc.child_ids(parameters) {
            if reference_parameters.len() == MAX_REFERENCE_PARAMETERS {
                return Err(WireError::ItemLimitExceeded);
            }
            let (namespace, local) = doc.expanded_name(id);
            if !names.insert((namespace.to_owned(), local.to_owned())) {
                return Err(WireError::DuplicateField);
            }
            reference_parameters.push(reference_parameter(&doc, id)?);
        }
    }
    Ok(PullPointSubscription {
        endpoint,
        reference_parameters,
        lease: parse_lease(&doc, root, NOTIFICATION_NS)?,
    })
}

/// Require a PullMessages SOAP response, refusing MetadataStream as a live
/// transport response. Ordered notifications and unsupported accounting remain
/// the same cognition projection as owner-supplied metadata imports.
pub fn parse_pull_messages_response(bytes: &[u8]) -> Result<EventDocument, WireError> {
    let document = events::parse_event_document_addressed(bytes)?;
    if document.format != EventDocumentFormat::PullMessages {
        return Err(WireError::UnexpectedResponse);
    }
    Ok(document)
}

/// Parse the renewed device-declared lease. WS-BaseNotification permits a
/// missing CurrentTime; this bounded lane requires it instead of consulting an
/// ambient clock or inventing a remaining interval.
pub fn parse_renew_response(bytes: &[u8]) -> Result<PullPointLease, WireError> {
    let (doc, root) = response_with_addressing(
        bytes,
        NOTIFICATION_NS,
        "RenewResponse",
        Some(RENEW_RESPONSE),
    )?;
    exact_children(
        &doc,
        root,
        &[
            (NOTIFICATION_NS, "CurrentTime"),
            (NOTIFICATION_NS, "TerminationTime"),
        ],
    )?;
    parse_lease(&doc, root, NOTIFICATION_NS)
}

/// Require the exact empty UnsubscribeResponse. Only this successful protocol
/// observation permits the caller to report acknowledged remote cleanup.
pub fn parse_unsubscribe_response(bytes: &[u8]) -> Result<(), WireError> {
    let (doc, root) = response_with_addressing(
        bytes,
        NOTIFICATION_NS,
        "UnsubscribeResponse",
        Some(UNSUBSCRIBE_RESPONSE),
    )?;
    exact_children(&doc, root, &[])
}

/// Validate an explicitly supplied response relationship against the exact
/// request identity before release. Some ONVIF devices omit RelatesTo; absence
/// is tolerated, but a present mismatch, duplicate or non-reply relationship
/// is refused. This never substitutes for route or authentication validation.
pub fn validate_relates_to(bytes: &[u8], expected_id: &str) -> Result<(), WireError> {
    reply_relationship(bytes, expected_id, false)
}

/// Require one explicit namespace-correct reply relationship for durable control custody.
/// Unlike the compatibility validator, an omitted Header or RelatesTo is refused.
/// This proves correlation to the retained logical request, never server identity.
pub fn require_relates_to(bytes: &[u8], expected_id: &str) -> Result<(), WireError> {
    reply_relationship(bytes, expected_id, true)
}

fn reply_relationship(
    bytes: &[u8],
    expected_id: &str,
    require_explicit: bool,
) -> Result<(), WireError> {
    message_id(expected_id)?;
    let doc = xml::Document::parse(bytes)?;
    let root = doc.root();
    if !doc.named(root, SOAP_NS, "Envelope") || !doc.only_whitespace(root) {
        return Err(WireError::UnexpectedEnvelope);
    }
    let header = unique(&doc, root, SOAP_NS, "Header")?;
    if let Some(header) = header {
        if let Some(field) = unique(&doc, header, ADDRESSING_NS, "RelatesTo")? {
            if relates_to(&doc, field)? != expected_id {
                return Err(WireError::UnexpectedResponse);
            }
            return Ok(());
        }
    }
    if require_explicit {
        return Err(WireError::UnexpectedResponse);
    }
    Ok(())
}

pub(super) fn message_id(id: &str) -> Result<(), WireError> {
    if id.len() > 256
        || id.len() <= 4
        || !id.starts_with("urn:")
        || !id[4..].bytes().any(|byte| byte.is_ascii_alphanumeric())
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":._-".contains(&byte))
    {
        return Err(WireError::InvalidField);
    }
    Ok(())
}

pub(super) fn relates_to(doc: &xml::Document, id: usize) -> Result<&str, WireError> {
    if let Some(kind) = doc.attribute(id, "", "RelationshipType") {
        if kind != "http://www.w3.org/2005/08/addressing/reply" {
            return Err(WireError::UnsupportedHeader);
        }
    }
    let value = scalar(doc, id)?;
    message_id(value)?;
    Ok(value)
}

fn exact_children(
    doc: &xml::Document,
    root: usize,
    allowed: &[(&str, &str)],
) -> Result<(), WireError> {
    if !doc.only_whitespace(root) || doc.attribute_count(root) != 0 {
        return Err(WireError::UnsupportedEventContent);
    }
    for child in doc.child_ids(root) {
        if !allowed
            .iter()
            .any(|(namespace, name)| doc.named(child, namespace, name))
        {
            return Err(WireError::UnsupportedEventContent);
        }
    }
    Ok(())
}

fn reference_parameter(doc: &xml::Document, id: usize) -> Result<String, WireError> {
    // Replaying a scalar with inherited base/language/space semantics stripped
    // could change its meaning. This subset refuses such endpoint references.
    if doc.has_xml_context(id) {
        return Err(WireError::UnsupportedEventContent);
    }
    let (namespace, local) = doc.expanded_name(id);
    // These namespaces name active SOAP/addressing/security headers, not opaque
    // device routing tokens. Refuse attempts to inject a second control header.
    if namespace.is_empty()
        || [
            SOAP_NS,
            ADDRESSING_NS,
            "http://www.w3.org/XML/1998/namespace",
        ]
        .contains(&namespace)
        || namespace.starts_with("http://docs.oasis-open.org/wss/")
    {
        return Err(WireError::UnsupportedHeader);
    }
    let marked = doc.attribute(id, ADDRESSING_NS, "IsReferenceParameter");
    if doc.attribute_count(id) != usize::from(marked.is_some())
        || marked.is_some_and(|value| parse_boolean(value) != Ok(true))
    {
        return Err(WireError::UnsupportedEventContent);
    }
    let value = doc
        .leaf_text(id)
        .map_err(|_| WireError::UnsupportedEventContent)?;
    if value.len() > MAX_PARAMETER_BYTES || value.chars().any(char::is_control) {
        return Err(WireError::InvalidField);
    }
    let bindings = doc.in_scope_namespaces(id);
    if bindings.len() > MAX_PARAMETER_NAMESPACES {
        return Err(WireError::XmlLimitExceeded);
    }
    let fresh_prefix = |stem: &str| {
        let mut prefix = stem.to_owned();
        while bindings.iter().any(|(candidate, _)| candidate == &prefix) {
            prefix.push('_');
        }
        prefix
    };
    let parameter_prefix = fresh_prefix("fssref");
    let addressing_prefix = fresh_prefix("fssaddr");
    let mut result = format!(
        "<{parameter_prefix}:{local} xmlns:{parameter_prefix}=\"{}\" xmlns:{addressing_prefix}=\"{ADDRESSING_NS}\" {addressing_prefix}:IsReferenceParameter=\"true\"",
        escaped(namespace),
    );
    // Keep even currently unused bindings: an opaque scalar can itself be a
    // QName. Rebinding its original prefix would silently alter its meaning.
    for (prefix, namespace) in bindings {
        let name = if prefix.is_empty() {
            "xmlns".to_owned()
        } else {
            format!("xmlns:{prefix}")
        };
        result.push_str(&format!(" {name}=\"{}\"", escaped(&namespace)));
    }
    result.push('>');
    result.push_str(&escaped(value));
    result.push_str(&format!("</{parameter_prefix}:{local}>"));
    Ok(result)
}

fn parse_lease(
    doc: &xml::Document,
    root: usize,
    namespace: &str,
) -> Result<PullPointLease, WireError> {
    let current_id = required(doc, root, namespace, "CurrentTime")?;
    let termination_id = required(doc, root, namespace, "TerminationTime")?;
    if doc.attribute_count(current_id) != 0 || doc.attribute_count(termination_id) != 0 {
        return Err(WireError::UnsupportedEventContent);
    }
    let current = scalar(doc, current_id)?;
    let termination = scalar(doc, termination_id)?;
    let remaining = utc_nanos(termination)?
        .checked_sub(utc_nanos(current)?)
        .ok_or(WireError::InvalidField)?;
    let seconds: u32 = (remaining / 1_000_000_000)
        .try_into()
        .map_err(|_| WireError::InvalidField)?;
    if seconds == 0 {
        return Err(WireError::InvalidField);
    }
    Ok(PullPointLease {
        current_time: current.to_owned(),
        termination_time: termination.to_owned(),
        seconds,
    })
}

fn utc_nanos(value: &str) -> Result<u128, WireError> {
    events::timestamp(value)?;
    // The shared timestamp validator establishes ASCII digits and real Gregorian
    // calendar dates before this arithmetic. u128 covers the full 1970..9999 range.
    let bytes = value.as_bytes();
    let number = |start: usize, end: usize| -> u64 {
        bytes[start..end]
            .iter()
            .fold(0, |acc, byte| acc * 10 + u64::from(*byte - b'0'))
    };
    let year = number(0, 4);
    let month = number(5, 7);
    let before_year = |year: u64| {
        let prior = year - 1;
        prior * 365 + prior / 4 - prior / 100 + prior / 400
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [
        31_u64,
        28 + u64::from(leap),
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let days = before_year(year) - before_year(1970)
        + month_days[..month as usize - 1].iter().sum::<u64>()
        + number(8, 10)
        - 1;
    let seconds = days * 86_400 + number(11, 13) * 3600 + number(14, 16) * 60 + number(17, 19);
    let fraction = if bytes.len() > 20 {
        let digits = bytes.len() - 21;
        number(20, bytes.len() - 1) * 10_u64.pow(9 - digits as u32)
    } else {
        0
    };
    Ok(u128::from(seconds) * 1_000_000_000 + u128::from(fraction))
}

fn escaped(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

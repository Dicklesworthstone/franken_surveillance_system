#![forbid(unsafe_code)]
//! Pure, bounded webhook disclosure profiles. Encoding creates no dispatch authority.
//!
//! The original reference profile retains its byte identity. Event metadata requires a
//! distinct approved route and is derived only from the exact canonical revision supplied
//! by the alert owner; the live ledger, policy, health and effect gates remain outside here.

use std::collections::BTreeSet;
use std::fmt::{self, Write};
use std::net::{IpAddr, SocketAddr};

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncoder, ContentDigest, DigestAlgorithm,
    EffectIntent, EventHypothesis,
};

/// Complete HTTP request allowance, unchanged for the reference profile and retained wire.
pub const MAX_REQUEST_BYTES: usize = 4096;
/// Independent pre-decode bound; the event owner's own count/string bounds also apply.
pub const MAX_METADATA_REVISION_BYTES: usize = 128 * 1024;
/// Versioned metadata disclosure document, distinct from the original reference-only body.
pub const EVENT_METADATA_SCHEMA: &str = "fss.webhook_event_metadata.v1";
const METADATA_ROUTE_DOMAIN: &str = "fss.http_webhook_event_metadata_route.v1";

/// Exact, versioned content disclosed to the approved relay.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum WebhookDisclosureProfile {
    /// Original fixed text and opaque reference digests; exact legacy route/request encoding.
    #[default]
    ReferencesV1,
    /// Declared event metadata, with a separate explicit disclosure approval handle.
    EventMetadataV1,
}
impl WebhookDisclosureProfile {
    /// Stable CLI/MCP and durable-plan spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReferencesV1 => "references-v1",
            Self::EventMetadataV1 => "event-metadata-v1",
        }
    }
    /// Unknown profiles never fall back to a wider or narrower interpretation.
    pub fn parse(value: &str) -> Result<Self, WebhookProfileError> {
        match value {
            "references-v1" => Ok(Self::ReferencesV1),
            "event-metadata-v1" => Ok(Self::EventMetadataV1),
            _ => Err(WebhookProfileError::Configuration),
        }
    }
    /// A handle is evidence for the live authority, not a grant by itself.
    /// Reject irrelevant approvals as well as absent, zero or non-SHA-256 approvals.
    pub fn validate(
        self,
        metadata_approval: Option<ContentDigest>,
    ) -> Result<(), WebhookProfileError> {
        match (self, metadata_approval) {
            (Self::ReferencesV1, None) => Ok(()),
            (Self::EventMetadataV1, Some(approval))
                if approval.algorithm() == DigestAlgorithm::Sha256
                    && approval.bytes() != [0; 32] =>
            {
                Ok(())
            }
            _ => Err(WebhookProfileError::Configuration),
        }
    }
}

/// Payload-free pure input/representation refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebhookProfileError {
    /// Unsupported route/profile or missing/inapplicable explicit approval.
    Configuration,
    /// The revision bytes are not the exact valid canonical event named by the plan.
    EventRevision,
    /// The complete input or escaped HTTP request exceeds the fixed allowance.
    Limit,
    /// A bounded output allocation was refused.
    Allocation,
}
impl fmt::Display for WebhookProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "webhook disclosure refused: {self:?}")
    }
}
impl std::error::Error for WebhookProfileError {}

pub(crate) fn route_digest(
    peer: SocketAddr,
    target: &str,
    plaintext_approval: ContentDigest,
    profile: WebhookDisclosureProfile,
    metadata_approval: Option<ContentDigest>,
) -> Result<ContentDigest, WebhookProfileError> {
    profile.validate(metadata_approval)?;
    if peer.port() == 0
        || peer.ip().is_unspecified()
        || peer.ip().is_multicast()
        || matches!(peer.ip(), IpAddr::V4(ip) if ip.is_broadcast())
        || !target.starts_with('/')
        || target.starts_with("//")
        || target.len() > 1024
        || !target
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._~-".contains(&b))
        || target.split('/').any(|part| part == "." || part == "..")
        || plaintext_approval.bytes() == [0; 32]
    {
        return Err(WebhookProfileError::Configuration);
    }
    let mut encoder = CanonicalEncoder::new();
    encoder.text(match profile {
        WebhookDisclosureProfile::ReferencesV1 => {
            "fss.http-webhook-route.v1:explicit-plaintext:json-references"
        }
        WebhookDisclosureProfile::EventMetadataV1 => METADATA_ROUTE_DOMAIN,
    });
    encoder.text(&peer.to_string());
    encoder.text(target);
    encoder.digest(plaintext_approval);
    if let Some(approval) = metadata_approval {
        encoder.text(profile.as_str());
        encoder.digest(approval);
    }
    Ok(ContentDigest::sha256(
        &encoder
            .finish_checked()
            .map_err(|_| WebhookProfileError::Configuration)?,
    ))
}

pub(crate) struct RequestFields<'a> {
    pub intent: &'a EffectIntent,
    pub event_root: ContentDigest,
    pub event_revision_digest: ContentDigest,
    pub event_revision_encoding: &'a [u8],
}

pub(crate) fn hex(value: ContentDigest) -> String {
    value
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct Output(String);
impl Output {
    fn new() -> Result<Self, WebhookProfileError> {
        let mut text = String::new();
        text.try_reserve_exact(MAX_REQUEST_BYTES)
            .map_err(|_| WebhookProfileError::Allocation)?;
        Ok(Self(text))
    }
    fn string(&mut self, text: &str) -> fmt::Result {
        self.write_char('"')?;
        for ch in text.chars() {
            match ch {
                '"' => self.write_str("\\\"")?,
                '\\' => self.write_str("\\\\")?,
                '\u{0000}'..='\u{001f}' | '\u{007f}' | '\u{2028}' | '\u{2029}' => {
                    write!(self, "\\u{:04x}", u32::from(ch))?
                }
                other => self.write_char(other)?,
            }
        }
        self.write_char('"')
    }
    fn optional_string(&mut self, text: Option<&str>) -> fmt::Result {
        match text {
            Some(text) => self.string(text),
            None => self.write_str("null"),
        }
    }
}
impl Write for Output {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if text.len() > MAX_REQUEST_BYTES.saturating_sub(self.0.len()) {
            return Err(fmt::Error);
        }
        self.0.push_str(text);
        Ok(())
    }
}

fn event(fields: &RequestFields<'_>) -> Result<EventHypothesis, WebhookProfileError> {
    let bytes = fields.event_revision_encoding;
    if bytes.len() > MAX_METADATA_REVISION_BYTES {
        return Err(WebhookProfileError::Limit);
    }
    if ContentDigest::sha256(bytes) != fields.event_revision_digest {
        return Err(WebhookProfileError::EventRevision);
    }
    let mut decoder = CanonicalDecoder::new(bytes);
    let decoded = (|| {
        if decoder.text()? != "fss.canonical.v1" || decoder.text()? != EventHypothesis::SCHEMA {
            return Err(fss_core::ContractError::DigestMismatch);
        }
        let event = EventHypothesis::decode_canonical(&mut decoder)?;
        decoder.ensure_finished()?;
        event.validate()?;
        if event.revision_digest() != fields.event_revision_digest {
            return Err(fss_core::ContractError::DigestMismatch);
        }
        Ok(event)
    })();
    decoded.map_err(|_| WebhookProfileError::EventRevision)
}

fn metadata(out: &mut Output, event: &EventHypothesis) -> fmt::Result {
    out.write_str(",\"disclosure_profile\":\"event-metadata-v1\",\"event\":{\"id\":")?;
    out.string(event.event_id.as_str())?;
    write!(
        out,
        ",\"revision\":{},\"kind\":\"{}\",\"lifecycle\":\"{}\",\"declared_interval_ns\":{{\"earliest\":\"{}\",\"latest\":\"{}\"}},\"zone_ids\":[",
        event.revision,
        event.kind.as_str(),
        event.state.as_str(),
        event.interval.earliest.0,
        event.interval.latest.0
    )?;
    for (index, zone) in event.zone_ids.iter().enumerate() {
        if index != 0 {
            out.write_char(',')?
        }
        out.string(zone)?;
    }
    out.write_str("],\"uncertainty_reason\":")?;
    out.optional_string(event.uncertainty_reason.as_deref())?;
    write!(
        out,
        ",\"declared_probability\":{{\"lower\":{},\"upper\":{},\"calibration_generation\":",
        event.probability.lower, event.probability.upper
    )?;
    out.optional_string(
        event
            .probability
            .calibration_generation
            .map(ContentDigest::to_text)
            .as_deref(),
    )?;
    write!(
        out,
        ",\"calibration_claim\":\"{}\"}}",
        if event.probability.calibration_generation.is_some() {
            "generation_declared_not_reverified"
        } else {
            "uncalibrated"
        }
    )?;
    let support = event
        .evidence
        .iter()
        .filter(|edge| edge.counts_as_support())
        .count();
    let contradiction = event
        .evidence
        .iter()
        .filter(|edge| edge.counts_as_contradiction())
        .count();
    let domains: BTreeSet<_> = event
        .evidence
        .iter()
        .filter(|edge| edge.counts_as_support())
        .map(|edge| edge.failure_domain.as_str())
        .collect();
    let tamper = event
        .evidence
        .iter()
        .filter(|edge| edge.reports_sensor_tamper())
        .count();
    let restoration = event
        .evidence
        .iter()
        .filter(|edge| edge.reports_integrity_restoration())
        .count();
    write!(
        out,
        ",\"evidence_counts\":{{\"supporting\":{support},\"contradicting\":{contradiction},\"neutral\":{},\"distinct_supporting_failure_domains\":{}}},\"sensor_health\":{{\"current\":\"unknown\",\"basis\":\"this_revision_only\",\"tamper_reports\":{tamper},\"integrity_restorations\":{restoration}}},\"decision_fingerprint\":\"{}\",\"policy_generation\":\"{}\",\"decision_abstained\":{},\"physical_truth_claim\":\"not_claimed\"}}",
        event.evidence.len() - support - contradiction,
        domains.len(),
        event.decision_path.fingerprint.to_text(),
        event.decision_path.policy_generation.to_text(),
        event.decision_path.abstained
    )
}

pub(crate) fn request(
    fields: &RequestFields<'_>,
    peer: SocketAddr,
    target: &str,
    profile: WebhookDisclosureProfile,
) -> Result<Vec<u8>, WebhookProfileError> {
    let parsed = match profile {
        WebhookDisclosureProfile::ReferencesV1 => None,
        WebhookDisclosureProfile::EventMetadataV1 => Some(event(fields)?),
    };
    let operation = hex(ContentDigest::sha256(
        fields.intent.operation_id.as_str().as_bytes(),
    ));
    let key = hex(ContentDigest::sha256(
        fields.intent.idempotency_key.as_str().as_bytes(),
    ));
    let mut body = Output::new()?;
    write!(body, "{{\"schema\":\"{}\",\"text\":\"{}\",\"operation_sha256\":\"{}\",\"request_sha256\":\"{}\",\"precondition_sha256\":\"{}\",\"event_root_sha256\":\"{}\",\"event_revision_sha256\":\"{}\"",
        if parsed.is_some() { EVENT_METADATA_SCHEMA } else { "fss.webhook-alert.v1" },
        if parsed.is_some() { "FSS retained event metadata; inspect linked evidence before action." } else { "FSS policy-authorized alert; inspect linked event evidence." },
        operation, hex(fields.intent.request_digest), hex(fields.intent.precondition_digest), hex(fields.event_root), hex(fields.event_revision_digest))
        .map_err(|_| WebhookProfileError::Limit)?;
    if let Some(event) = parsed {
        metadata(&mut body, &event).map_err(|_| WebhookProfileError::Limit)?
    }
    body.write_char('}')
        .map_err(|_| WebhookProfileError::Limit)?;
    let mut request = Output::new()?;
    write!(request, "POST {target} HTTP/1.1\r\nHost: {peer}\r\nContent-Type: application/json\r\nIdempotency-Key: {key}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.0.len(), body.0)
        .map_err(|_| WebhookProfileError::Limit)?;
    Ok(request.0.into_bytes())
}

#[cfg(test)]
#[path = "profile/tests.rs"]
mod tests;

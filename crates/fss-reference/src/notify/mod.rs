#![forbid(unsafe_code)]
//! Production TLS 1.3 HMAC-signed webhooks, multi-channel relays (ntfy, Pushover, SMTP-over-TLS),
//! and idempotent escalation policies for Franken Surveillance System.
//!
//! Uses first-party pure-Rust RFC 8446 TLS 1.3 (`TLS_CHACHA20_POLY1305_SHA256`, `x25519`,
//! `ed25519`), strict fail-closed X.509 verification (`ERR-NOTIFY-TLS-CERT-001`), vault-only
//! credential loading via `fss_vault::{SecretStore, SecretAccessCx}`, and the `AGENTS.md`
//! idempotent effect machine (`Prepared -> Committed -> AdapterAccepted | Indeterminate | Failed`).

use core::fmt;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, DigestAlgorithm, EventId, IdempotencyKey,
    OperationId, TimestampNs,
};

/// Pure-Rust RFC 8032 Ed25519 keygen, signing, verification, and FIPS 180-4 SHA-512.
pub mod ed25519;
/// Idempotent durable effect driver, escalation policies, and secret-free JSONL audit records.
pub mod escalation;
/// Production TLS 1.3 ntfy and Pushover notification relays.
pub mod relays;
/// Production SMTP-over-TLS (`SMTPS` implicit TLS 1.3 and `STARTTLS` upgrade) email relay.
pub mod smtp;
/// First-party pure-Rust RFC 8446 TLS 1.3 client & loopback server transport.
pub mod tls13;
/// Production HMAC-SHA256 signed HTTPS webhook adapter and bounded HTTP/1.1-over-TLS codec.
pub mod webhook;
/// Pure-Rust RFC 7748 X25519 scalar multiplication and $GF(2^{255}-19)$ arithmetic.
pub mod x25519;
/// Strict bounded X.509 v3 DER parser, PEM bundle loader, Ed25519 cert builder, and verifier.
pub mod x509;

#[cfg(test)]
mod tests;

pub use x509::ERR_NOTIFY_TLS_CERT_001;

/// Stable error code for post-write indeterminate delivery outcomes and resend refusals.
pub const ERR_NOTIFY_INDETERMINATE_001: &str = "ERR-NOTIFY-INDETERMINATE-001";
/// Stable error code for disclosure profile or H3 visual redaction refusals.
pub const ERR_NOTIFY_DISCLOSURE_001: &str = "ERR-NOTIFY-DISCLOSURE-001";
/// Stable error code when plaintext `http://` is refused in production mode.
pub const ERR_NOTIFY_PLAINTEXT_REFUSED_001: &str = "ERR-NOTIFY-PLAINTEXT-REFUSED-001";
/// Stable error code when an HTTP 3xx redirect is refused fail-closed.
pub const ERR_NOTIFY_REDIRECT_REFUSED_001: &str = "ERR-NOTIFY-REDIRECT-REFUSED-001";
/// Stable error code for vault secret fetch or scope mismatch refusals.
pub const ERR_NOTIFY_VAULT_001: &str = "ERR-NOTIFY-VAULT-001";
/// Stable error code for deadline expiration or cancellation before send.
pub const ERR_NOTIFY_TIMEOUT_001: &str = "ERR-NOTIFY-TIMEOUT-001";
/// Stable error code for DNS/TCP/HTTP/SMTP configuration or pre-send transport failures.
pub const ERR_NOTIFY_TRANSPORT_001: &str = "ERR-NOTIFY-TRANSPORT-001";
/// Stable error code for invalid or unauthorized escalation policy transitions.
pub const ERR_NOTIFY_ESCALATION_001: &str = "ERR-NOTIFY-ESCALATION-001";

/// Canonical digest domain for [`DnsResolutionReceipt`].
pub const NOTIFY_DNS_RESOLUTION_DOMAIN: &str = "fss.notify.dns_resolution.v1";
/// Canonical digest domain for [`H3VisualAttachment`].
pub const NOTIFY_H3_VISUAL_ATTACHMENT_DOMAIN: &str = "fss.notify.h3_visual_attachment.v1";
/// Canonical digest domain for [`DeliveryObservation`] and [`DeliveryReceipt`].
pub const NOTIFY_DELIVERY_OBSERVATION_DOMAIN: &str = "fss.notify.delivery_observation.v1";
/// Canonical digest domain for [`webhook::HttpsWebhookTarget`].
pub const NOTIFY_WEBHOOK_ROUTE_DOMAIN: &str = "fss.notify.webhook_route.v1";
/// Canonical digest domain for multi-channel relay targets (`ntfy`, `Pushover`, `SMTP`).
pub const NOTIFY_RELAY_ROUTE_DOMAIN: &str = "fss.notify.relay_route.v1";
/// Canonical digest domain for [`escalation::EscalationPolicy`].
pub const NOTIFY_ESCALATION_POLICY_DOMAIN: &str = "fss.notify.escalation_policy.v1";
/// Canonical digest domain for [`escalation::EscalationLineage`].
pub const NOTIFY_ESCALATION_LINEAGE_DOMAIN: &str = "fss.notify.escalation_lineage.v1";
/// Canonical digest domain binding complete notification payloads and their routes.
///
/// The retired v1 domain omitted event metadata. Existing journal intents retain their original
/// digest; they are never reinterpreted or automatically dispatched under this v2 contract.
pub const NOTIFY_EFFECT_REQUEST_DOMAIN: &str = "fss.notify.effect_request.v2";

/// Required privacy redaction transform marker for H3 visual notification attachments.
pub const REQUIRED_H3_REDACTION_TRANSFORM: &str = "transform:bounding_box_redact";
/// Required unmasked-access refusal marker on H3 visual receipts.
pub const REQUIRED_H3_UNMASKED_ACCESS: &str = "refused";
/// Maximum permitted JPEG byte length for an H3 privacy-masked visual attachment (128 KiB).
pub const MAX_VISUAL_ATTACHMENT_BYTES: usize = 128 * 1024;
/// Maximum HTTP request byte bound for non-visual requests (16 KiB).
pub const MAX_TEXT_REQUEST_BYTES: usize = 16 * 1024;
/// Maximum HTTP request byte bound for visual-enabled requests (256 KiB).
pub const MAX_VISUAL_REQUEST_BYTES: usize = 256 * 1024;
/// Maximum HTTP response header + body bytes retained from a relay (16 KiB).
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024;

/// Versioned notification disclosure profile governing outbound content exposure.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DisclosureProfile {
    /// Emits opaque reference digests only; zero event metadata and zero image bytes.
    #[default]
    ReferencesV1,
    /// Emits bounded event metadata under explicit approval; refuses visual attachments.
    EventMetadataV1,
    /// Emits bounded event metadata plus a verified pre-redacted H3 JPEG thumbnail.
    EventMetadataVisualV1,
}

impl DisclosureProfile {
    /// Returns the stable machine-readable profile spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReferencesV1 => "references-v1",
            Self::EventMetadataV1 => "event-metadata-v1",
            Self::EventMetadataVisualV1 => "event-metadata-visual-v1",
        }
    }

    /// Parses an exact disclosure profile string without falling back.
    pub fn parse(value: &str) -> Result<Self, NotifyError> {
        match value {
            "references-v1" => Ok(Self::ReferencesV1),
            "event-metadata-v1" => Ok(Self::EventMetadataV1),
            "event-metadata-visual-v1" => Ok(Self::EventMetadataVisualV1),
            _ => Err(NotifyError::disclosure(format!(
                "unknown disclosure profile '{value}'"
            ))),
        }
    }

    /// Validates explicit non-zero SHA-256 disclosure approvals required by this profile.
    pub fn validate_approvals(
        self,
        metadata_approval: Option<ContentDigest>,
        visual_approval: Option<ContentDigest>,
    ) -> Result<(), NotifyError> {
        let ok =
            |d: ContentDigest| d.algorithm() == DigestAlgorithm::Sha256 && d.bytes() != [0_u8; 32];
        match (self, metadata_approval, visual_approval) {
            (Self::ReferencesV1, None, None) => Ok(()),
            (Self::EventMetadataV1, Some(m), None) if ok(m) => Ok(()),
            (Self::EventMetadataVisualV1, Some(m), Some(v)) if ok(m) && ok(v) => Ok(()),
            _ => Err(NotifyError::disclosure(format!(
                "disclosure profile '{}' missing required non-zero approval digest(s)",
                self.as_str()
            ))),
        }
    }
}

/// Verified pre-redacted H3 privacy-masked JPEG thumbnail permitted ONLY under
/// [`DisclosureProfile::EventMetadataVisualV1`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H3VisualAttachment {
    /// Canonical receipt digest under [`NOTIFY_H3_VISUAL_ATTACHMENT_DOMAIN`].
    pub receipt_digest: ContentDigest,
    /// Retained import identity containing the source frame.
    pub source_import_id: ContentDigest,
    /// Verified retained source capsule digest.
    pub source_capsule_digest: ContentDigest,
    /// Authenticated sensor identifier from the retained capsule.
    pub sensor_id: String,
    /// Canonical active privacy-mask binding digest (must be non-zero).
    pub privacy_mask_binding_digest: ContentDigest,
    /// Applied redaction transform (must equal [`REQUIRED_H3_REDACTION_TRANSFORM`]).
    pub applied_redaction_transform: String,
    /// Policy marker confirming unmasked access is refused (`"refused"`).
    pub unmasked_access: String,
    /// Encoded thumbnail width in pixels.
    pub width: u32,
    /// Encoded thumbnail height in pixels.
    pub height: u32,
    /// SHA-256 digest of `jpeg_bytes`.
    pub output_jpeg_sha256: ContentDigest,
    /// Privacy-masked baseline JPEG payload bytes (`SOI..EOI`).
    pub jpeg_bytes: Vec<u8>,
}

impl H3VisualAttachment {
    /// Constructs and seals a verified pre-redacted H3 visual attachment.
    #[allow(clippy::too_many_arguments)]
    pub fn build_redacted(
        source_import_id: ContentDigest,
        source_capsule_digest: ContentDigest,
        sensor_id: impl Into<String>,
        privacy_mask_binding_digest: ContentDigest,
        width: u32,
        height: u32,
        jpeg_bytes: Vec<u8>,
    ) -> Result<Self, NotifyError> {
        let sensor_id = sensor_id.into();
        let output_jpeg_sha256 = ContentDigest::sha256(&jpeg_bytes);
        let applied_redaction_transform = REQUIRED_H3_REDACTION_TRANSFORM.to_owned();
        let unmasked_access = REQUIRED_H3_UNMASKED_ACCESS.to_owned();
        let receipt_digest = Self::compute_digest(
            source_import_id,
            source_capsule_digest,
            &sensor_id,
            privacy_mask_binding_digest,
            &applied_redaction_transform,
            &unmasked_access,
            width,
            height,
            output_jpeg_sha256,
        );
        let att = Self {
            receipt_digest,
            source_import_id,
            source_capsule_digest,
            sensor_id,
            privacy_mask_binding_digest,
            applied_redaction_transform,
            unmasked_access,
            width,
            height,
            output_jpeg_sha256,
            jpeg_bytes,
        };
        att.verify()?;
        Ok(att)
    }

    /// Recomputes and verifies all redaction, JPEG framing, size, and receipt digest invariants.
    pub fn verify(&self) -> Result<(), NotifyError> {
        if self.sensor_id.is_empty() || self.sensor_id.len() > 128 {
            return Err(NotifyError::disclosure("H3 attachment sensor_id invalid"));
        }
        if self.privacy_mask_binding_digest.bytes() == [0_u8; 32] {
            return Err(NotifyError::disclosure(
                "H3 attachment missing privacy_mask_binding_digest",
            ));
        }
        if self.applied_redaction_transform != REQUIRED_H3_REDACTION_TRANSFORM {
            return Err(NotifyError::disclosure(
                "H3 attachment missing transform:bounding_box_redact",
            ));
        }
        if self.unmasked_access != REQUIRED_H3_UNMASKED_ACCESS {
            return Err(NotifyError::disclosure(
                "H3 attachment unmasked_access must be 'refused'",
            ));
        }
        if self.width == 0 || self.height == 0 || self.width > 1280 || self.height > 1280 {
            return Err(NotifyError::disclosure(
                "H3 attachment dimensions out of bounds",
            ));
        }
        if self.jpeg_bytes.len() < 4
            || self.jpeg_bytes.len() > MAX_VISUAL_ATTACHMENT_BYTES
            || !self.jpeg_bytes.starts_with(&[0xff, 0xd8])
            || !self.jpeg_bytes.ends_with(&[0xff, 0xd9])
        {
            return Err(NotifyError::disclosure(
                "H3 attachment payload is not a bounded JPEG",
            ));
        }
        if ContentDigest::sha256(&self.jpeg_bytes) != self.output_jpeg_sha256 {
            return Err(NotifyError::disclosure(
                "H3 attachment JPEG SHA-256 mismatch",
            ));
        }
        let expected = Self::compute_digest(
            self.source_import_id,
            self.source_capsule_digest,
            &self.sensor_id,
            self.privacy_mask_binding_digest,
            &self.applied_redaction_transform,
            &self.unmasked_access,
            self.width,
            self.height,
            self.output_jpeg_sha256,
        );
        if self.receipt_digest != expected {
            return Err(NotifyError::disclosure(
                "H3 attachment receipt_digest mismatch",
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn compute_digest(
        source_import_id: ContentDigest,
        source_capsule_digest: ContentDigest,
        sensor_id: &str,
        privacy_mask_binding_digest: ContentDigest,
        applied_redaction_transform: &str,
        unmasked_access: &str,
        width: u32,
        height: u32,
        output_jpeg_sha256: ContentDigest,
    ) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text(NOTIFY_H3_VISUAL_ATTACHMENT_DOMAIN);
        enc.digest(source_import_id);
        enc.digest(source_capsule_digest);
        enc.text(sensor_id);
        enc.digest(privacy_mask_binding_digest);
        enc.text(applied_redaction_transform);
        enc.text(unmasked_access);
        enc.u32(width);
        enc.u32(height);
        enc.digest(output_jpeg_sha256);
        ContentDigest::sha256(&enc.finish())
    }
}

/// Bounded event metadata disclosed only under `event-metadata-v1` or `event-metadata-visual-v1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotifyEventMetadata {
    /// Canonical event identifier.
    pub event_id: EventId,
    /// Event revision number.
    pub revision: u64,
    /// Stable event kind label (e.g., `"unknown_presence"`).
    pub kind: String,
    /// Stable lifecycle label (e.g., `"corroborated"`).
    pub lifecycle: String,
    /// Bounded zone identifiers implicated by the event.
    pub zone_ids: Vec<String>,
    /// Short bounded human-readable summary.
    pub summary: String,
}

/// Outbound notification payload carrying canonical references plus optional gated metadata/visuals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotifyPayload {
    /// Immutable effect operation identity.
    pub operation_id: OperationId,
    /// Immutable idempotency key for this exact dispatch attempt.
    pub idempotency_key: IdempotencyKey,
    /// Canonical event manifest root digest.
    pub event_root: ContentDigest,
    /// Canonical event revision digest.
    pub event_revision_digest: ContentDigest,
    /// Stable channel identity bound in the effect intent.
    pub channel: String,
    /// Optional event metadata (strictly omitted on wire under `references-v1`).
    pub event_metadata: Option<NotifyEventMetadata>,
    /// Optional pre-redacted H3 JPEG attachment (permitted ONLY under `event-metadata-visual-v1`).
    pub visual_attachment: Option<H3VisualAttachment>,
}

impl NotifyPayload {
    /// Enforces strict disclosure rules against `profile` before any network I/O.
    pub fn validate_for_profile(&self, profile: DisclosureProfile) -> Result<(), NotifyError> {
        match profile {
            DisclosureProfile::ReferencesV1 => {
                if self.visual_attachment.is_some() {
                    return Err(NotifyError::disclosure(
                        "references-v1 refuses visual attachments",
                    ));
                }
                Ok(())
            }
            DisclosureProfile::EventMetadataV1 => {
                if self.event_metadata.is_none() {
                    return Err(NotifyError::disclosure(
                        "event-metadata-v1 requires event_metadata",
                    ));
                }
                if self.visual_attachment.is_some() {
                    return Err(NotifyError::disclosure(
                        "event-metadata-v1 refuses visual attachments",
                    ));
                }
                Ok(())
            }
            DisclosureProfile::EventMetadataVisualV1 => {
                if self.event_metadata.is_none() {
                    return Err(NotifyError::disclosure(
                        "event-metadata-visual-v1 requires event_metadata",
                    ));
                }
                let Some(att) = &self.visual_attachment else {
                    return Err(NotifyError::disclosure(
                        "event-metadata-visual-v1 requires verified H3VisualAttachment",
                    ));
                };
                att.verify()
            }
        }
    }
}

/// Explicit DNS resolution witness captured before opening a TCP connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsResolutionReceipt {
    /// Target hostname resolved (lower-cased).
    pub hostname: String,
    /// Target port bound into socket addresses.
    pub port: u16,
    /// Ordered resolved socket addresses.
    pub resolved_addrs: Vec<SocketAddr>,
    /// Explicit timestamp at which DNS resolution completed.
    pub resolved_at_ns: TimestampNs,
    /// Canonical SHA-256 digest under [`NOTIFY_DNS_RESOLUTION_DOMAIN`].
    pub resolution_digest: ContentDigest,
}

impl DnsResolutionReceipt {
    /// Builds and seals a canonical DNS resolution receipt.
    pub fn new(
        hostname: impl Into<String>,
        port: u16,
        resolved_addrs: Vec<SocketAddr>,
        resolved_at_ns: TimestampNs,
    ) -> Result<Self, NotifyError> {
        let hostname = hostname.into().to_ascii_lowercase();
        if hostname.is_empty() || resolved_addrs.is_empty() {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_TRANSPORT_001,
                "DNS resolved zero addresses",
            ));
        }
        let mut enc = CanonicalEncoder::new();
        enc.text(NOTIFY_DNS_RESOLUTION_DOMAIN);
        enc.text(&hostname);
        enc.u32(u32::from(port));
        enc.u64(resolved_addrs.len() as u64);
        for addr in &resolved_addrs {
            enc.text(&addr.to_string());
        }
        resolved_at_ns.encode_canonical(&mut enc);
        Ok(Self {
            hostname,
            port,
            resolved_addrs,
            resolved_at_ns,
            resolution_digest: ContentDigest::sha256(&enc.finish()),
        })
    }
}

/// Explicit DNS resolution authority trait.
pub trait DnsResolver {
    /// Resolves `(hostname, port)` and returns a sealed [`DnsResolutionReceipt`].
    fn resolve(
        &self,
        hostname: &str,
        port: u16,
        now: TimestampNs,
    ) -> Result<DnsResolutionReceipt, NotifyError>;
}

/// Host resolver backed by `std::net::ToSocketAddrs`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn resolve(
        &self,
        hostname: &str,
        port: u16,
        now: TimestampNs,
    ) -> Result<DnsResolutionReceipt, NotifyError> {
        let mut addrs: Vec<SocketAddr> = (hostname, port)
            .to_socket_addrs()
            .map_err(|_| {
                NotifyError::pre_send(
                    ERR_NOTIFY_TRANSPORT_001,
                    format!("DNS resolution failed for '{hostname}'"),
                )
            })?
            .collect();
        addrs.sort_by_key(ToString::to_string);
        addrs.dedup();
        DnsResolutionReceipt::new(hostname, port, addrs, now)
    }
}

/// Deterministic pinned resolver mapping explicit hostnames to fixed socket addresses.
#[derive(Clone, Debug, Default)]
pub struct PinnedDnsResolver {
    entries: Vec<(String, SocketAddr)>,
}

impl PinnedDnsResolver {
    /// Creates an empty pinned resolver.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Registers a deterministic mapping from `hostname` to `addr`.
    #[must_use]
    pub fn with_entry(mut self, hostname: impl Into<String>, addr: SocketAddr) -> Self {
        self.entries
            .push((hostname.into().to_ascii_lowercase(), addr));
        self
    }
}

impl DnsResolver for PinnedDnsResolver {
    fn resolve(
        &self,
        hostname: &str,
        port: u16,
        now: TimestampNs,
    ) -> Result<DnsResolutionReceipt, NotifyError> {
        let lower = hostname.to_ascii_lowercase();
        let addrs: Vec<SocketAddr> = self
            .entries
            .iter()
            .filter(|(h, _)| *h == lower)
            .map(|(_, a)| *a)
            .collect();
        if addrs.is_empty() {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_TRANSPORT_001,
                format!("pinned DNS missing '{hostname}'"),
            ));
        }
        DnsResolutionReceipt::new(lower, port, addrs, now)
    }
}

/// Explicit cooperative deadline and cancellation boundary for network dispatch.
#[derive(Clone)]
pub struct NotifyDeadlineCx<'a> {
    started_at: Instant,
    timeout: Duration,
    logical_now: TimestampNs,
    cancelled_reason: Option<String>,
    cancellation_probe: Option<&'a (dyn Fn() -> bool + Sync)>,
}

impl fmt::Debug for NotifyDeadlineCx<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotifyDeadlineCx")
            .field("started_at", &self.started_at)
            .field("timeout", &self.timeout)
            .field("logical_now", &self.logical_now)
            .field("cancelled_reason", &self.cancelled_reason)
            .field("has_cancellation_probe", &self.cancellation_probe.is_some())
            .finish()
    }
}

impl<'a> NotifyDeadlineCx<'a> {
    /// Creates a new deadline context with explicit logical timestamp and bounded wall timeout.
    pub fn new(logical_now: TimestampNs, timeout: Duration) -> Result<Self, NotifyError> {
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_TRANSPORT_001,
                "timeout must be within 1ns..=60s",
            ));
        }
        Ok(Self {
            started_at: Instant::now(),
            timeout,
            logical_now,
            cancelled_reason: None,
            cancellation_probe: None,
        })
    }

    /// Marks this context cancelled with an explicit non-secret reason.
    #[must_use]
    pub fn with_cancelled(mut self, reason: impl Into<String>) -> Self {
        self.cancelled_reason = Some(reason.into());
        self
    }

    /// Borrows the existing request owner's live cancellation probe.
    ///
    /// The owner must keep the probe alive until dispatch returns and keep it true once
    /// cancelled. This introduces no independent cancellation tree or effect authority.
    #[must_use]
    pub fn with_cancellation_probe(mut self, probe: &'a (dyn Fn() -> bool + Sync)) -> Self {
        self.cancellation_probe = Some(probe);
        self
    }

    /// Returns the explicit logical timestamp for certificate validity and receipts.
    #[must_use]
    pub const fn now(&self) -> TimestampNs {
        self.logical_now
    }

    /// Checks cancellation and returns remaining wall-clock budget before deadline.
    pub fn remaining(&self, post_write: bool) -> Result<Duration, NotifyError> {
        if let Some(reason) = &self.cancelled_reason {
            return Err(if post_write {
                NotifyError::indeterminate(format!("cancelled after send: {reason}"))
            } else {
                NotifyError::pre_send(ERR_NOTIFY_TIMEOUT_001, format!("cancelled: {reason}"))
            });
        }
        if self.cancellation_probe.is_some_and(|probe| probe()) {
            return Err(if post_write {
                NotifyError::indeterminate("request owner cancelled after send")
            } else {
                NotifyError::pre_send(
                    ERR_NOTIFY_TIMEOUT_001,
                    "request owner cancelled before send",
                )
            });
        }
        match self.timeout.checked_sub(self.started_at.elapsed()) {
            Some(rem) if !rem.is_zero() => Ok(rem),
            _ => Err(if post_write {
                NotifyError::indeterminate("deadline expired after request bytes were written")
            } else {
                NotifyError::pre_send(ERR_NOTIFY_TIMEOUT_001, "notification deadline expired")
            }),
        }
    }
}

/// Bounded transport ceilings for outbound notification adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NotifyLimits {
    /// Maximum outbound request bytes.
    pub max_request_bytes: usize,
    /// Maximum inbound response bytes.
    pub max_response_bytes: usize,
}

impl Default for NotifyLimits {
    fn default() -> Self {
        Self {
            max_request_bytes: MAX_VISUAL_REQUEST_BYTES,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }
}

/// Secret-free delivery observation bound into every accepted delivery receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryObservation {
    /// Immutable operation identity.
    pub operation_id: OperationId,
    /// Immutable idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// Logical relay kind (`"https_webhook"`, `"ntfy"`, `"pushover"`, `"smtp_tls"`).
    pub relay_kind: String,
    /// Canonical route digest (contains zero secret bytes).
    pub route_digest: ContentDigest,
    /// Bound DNS resolution witness recorded prior to TCP connect.
    pub dns_receipt: DnsResolutionReceipt,
    /// Verified peer leaf certificate SPKI SHA-256 digest.
    pub tls_peer_spki_sha256: ContentDigest,
    /// Verified peer leaf certificate DER SHA-256 digest.
    pub tls_peer_cert_sha256: ContentDigest,
    /// Disclosure profile enforced on the wire.
    pub disclosure_profile: DisclosureProfile,
    /// Optional H3 visual attachment receipt digest if visual disclosure occurred.
    pub visual_receipt_digest: Option<ContentDigest>,
    /// HTTP status code or SMTP final reply code (`250`).
    pub protocol_status: u16,
    /// SHA-256 digest of the redacted/non-secret canonical request structure.
    pub request_digest: ContentDigest,
    /// Timestamp at which the relay acceptance was observed.
    pub observed_at_ns: TimestampNs,
    /// Canonical observation digest under [`NOTIFY_DELIVERY_OBSERVATION_DOMAIN`].
    pub observation_digest: ContentDigest,
}

impl DeliveryObservation {
    /// Seals a new secret-free delivery observation with its canonical digest.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn seal(
        operation_id: OperationId,
        idempotency_key: IdempotencyKey,
        relay_kind: impl Into<String>,
        route_digest: ContentDigest,
        dns_receipt: DnsResolutionReceipt,
        tls_peer_spki_sha256: ContentDigest,
        tls_peer_cert_sha256: ContentDigest,
        disclosure_profile: DisclosureProfile,
        visual_receipt_digest: Option<ContentDigest>,
        protocol_status: u16,
        request_digest: ContentDigest,
        observed_at_ns: TimestampNs,
    ) -> Self {
        let relay_kind = relay_kind.into();
        let mut enc = CanonicalEncoder::new();
        enc.text(NOTIFY_DELIVERY_OBSERVATION_DOMAIN);
        operation_id.encode_canonical(&mut enc);
        idempotency_key.encode_canonical(&mut enc);
        enc.text(&relay_kind);
        enc.digest(route_digest);
        enc.digest(dns_receipt.resolution_digest);
        enc.digest(tls_peer_spki_sha256);
        enc.digest(tls_peer_cert_sha256);
        enc.text(disclosure_profile.as_str());
        enc.bool(visual_receipt_digest.is_some());
        if let Some(vis) = visual_receipt_digest {
            enc.digest(vis);
        }
        enc.u32(u32::from(protocol_status));
        enc.digest(request_digest);
        observed_at_ns.encode_canonical(&mut enc);
        Self {
            operation_id,
            idempotency_key,
            relay_kind,
            route_digest,
            dns_receipt,
            tls_peer_spki_sha256,
            tls_peer_cert_sha256,
            disclosure_profile,
            visual_receipt_digest,
            protocol_status,
            request_digest,
            observed_at_ns,
            observation_digest: ContentDigest::sha256(&enc.finish()),
        }
    }
}

/// Receipt returned when an outbound relay accepts a notification over verified TLS 1.3.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryReceipt {
    /// Complete secret-free network, DNS, TLS, and protocol observation.
    pub observation: DeliveryObservation,
    /// Optional non-secret relay message identifier returned by the server.
    pub remote_message_id: Option<String>,
}

/// Unified secret-free error taxonomy for all notification transports and escalation policies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotifyError {
    /// Stable FSS error code (e.g., `ERR-NOTIFY-TLS-CERT-001`, `ERR-NOTIFY-INDETERMINATE-001`).
    pub code: &'static str,
    /// Non-secret refusal detail.
    pub detail: String,
    /// True iff this error occurred strictly BEFORE any outbound request byte hit the wire.
    pub pre_send: bool,
    /// Optional DNS resolution receipt captured before failure.
    pub dns_receipt: Option<Box<DnsResolutionReceipt>>,
}

impl NotifyError {
    /// Constructs a pre-send failure (safe to classify as `EffectState::Failed`).
    #[must_use]
    pub fn pre_send(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            pre_send: true,
            dns_receipt: None,
        }
    }
    /// Constructs a disclosure-policy refusal (`ERR-NOTIFY-DISCLOSURE-001`, pre-send).
    #[must_use]
    pub fn disclosure(detail: impl Into<String>) -> Self {
        Self::pre_send(ERR_NOTIFY_DISCLOSURE_001, detail)
    }
    /// Constructs a TLS certificate/signature refusal (`ERR-NOTIFY-TLS-CERT-001`, pre-send).
    #[must_use]
    pub fn tls_cert(detail: impl Into<String>) -> Self {
        Self::pre_send(ERR_NOTIFY_TLS_CERT_001, detail)
    }
    /// Constructs a post-send indeterminate refusal (`ERR-NOTIFY-INDETERMINATE-001`).
    #[must_use]
    pub fn indeterminate(detail: impl Into<String>) -> Self {
        Self {
            code: ERR_NOTIFY_INDETERMINATE_001,
            detail: detail.into(),
            pre_send: false,
            dns_receipt: None,
        }
    }
    /// Attaches a captured [`DnsResolutionReceipt`] to this error without altering its class.
    #[must_use]
    pub fn with_dns_receipt(mut self, receipt: DnsResolutionReceipt) -> Self {
        self.dns_receipt = Some(Box::new(receipt));
        self
    }
    /// Returns `true` iff no application request bytes were written to the network before failure.
    #[must_use]
    pub const fn is_pre_send_failure(&self) -> bool {
        self.pre_send
    }
}

impl fmt::Display for NotifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}
impl std::error::Error for NotifyError {}

#[must_use]
pub(crate) fn encode_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

#[must_use]
pub(crate) fn encode_base64_std(bytes: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let (a, b, c) = (
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        );
        out.push(char::from(ALPHA[usize::from(a >> 2)]));
        out.push(char::from(ALPHA[usize::from(((a & 0x03) << 4) | (b >> 4))]));
        out.push(if chunk.len() > 1 {
            char::from(ALPHA[usize::from(((b & 0x0f) << 2) | (c >> 6))])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(ALPHA[usize::from(c & 0x3f)])
        } else {
            '='
        });
    }
    out
}

pub(crate) fn push_json_str(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use core::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

pub(crate) fn validate_header_text(
    field: &str,
    value: &str,
    max_len: usize,
) -> Result<(), NotifyError> {
    if value.is_empty() || value.len() > max_len {
        return Err(NotifyError::pre_send(
            ERR_NOTIFY_TRANSPORT_001,
            format!("{field} length outside 1..={max_len}"),
        ));
    }
    if value.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(NotifyError::pre_send(
            ERR_NOTIFY_TRANSPORT_001,
            format!("{field} contains control bytes"),
        ));
    }
    Ok(())
}

#![forbid(unsafe_code)]
//! Production HMAC-SHA256 signed HTTPS webhook adapter and bounded HTTP/1.1-over-TLS 1.3 client.
//!
//! Plaintext `http://` targets are refused (`ERR-NOTIFY-PLAINTEXT-REFUSED-001`), HTTP 3xx
//! redirects are refused fail-closed (`ERR-NOTIFY-REDIRECT-REFUSED-001`), and HMAC keys are
//! loaded exclusively via `fss_vault::{SecretStore, SecretAccessCx}` (`AdapterFamily::AlertWebhook`).

use core::fmt;
use std::io;
use std::net::TcpStream;

use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest};
use fss_vault::{
    AdapterFamily, EntropySource, SecretAccessCx, SecretId, SecretScope, SecretStore,
    constant_time_eq, hmac_sha256,
};
use zeroize::Zeroizing;

use super::tls13::{Tls13Error, Tls13Stream};
use super::x509::{TlsTrustPolicy, VerifiedPeerCert};
use super::{
    DeliveryObservation, DeliveryReceipt, DisclosureProfile, DnsResolutionReceipt, DnsResolver,
    ERR_NOTIFY_PLAINTEXT_REFUSED_001, ERR_NOTIFY_REDIRECT_REFUSED_001, ERR_NOTIFY_TRANSPORT_001,
    ERR_NOTIFY_VAULT_001, NOTIFY_WEBHOOK_ROUTE_DOMAIN, NotifyDeadlineCx, NotifyError, NotifyLimits,
    NotifyPayload, encode_base64_std, encode_hex_lower, push_json_str,
};

/// Parsed validated HTTPS URL components (never holds embedded userinfo credentials).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedHttpsUrl {
    /// Lower-cased target hostname or IP literal.
    pub host: String,
    /// Explicit or default (`443`) TCP port.
    pub port: u16,
    /// Absolute request target path (starts with `/`, no whitespace or control bytes).
    pub path: String,
}

impl ValidatedHttpsUrl {
    /// Parses a strict `https://host[:port][/path]` URL, refusing plaintext `http://` and credentials.
    pub fn parse_production(raw_url: &str) -> Result<Self, NotifyError> {
        if raw_url.is_empty()
            || raw_url.len() > 2048
            || raw_url.bytes().any(|b| b <= 0x20 || b >= 0x7f)
        {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_TRANSPORT_001,
                "invalid HTTPS URL bytes or length",
            ));
        }
        if raw_url.starts_with("http://") || raw_url.starts_with("HTTP://") {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_PLAINTEXT_REFUSED_001,
                "plaintext http:// URLs are refused in production mode (https:// required)",
            ));
        }
        let rest = raw_url
            .strip_prefix("https://")
            .or_else(|| raw_url.strip_prefix("HTTPS://"))
            .ok_or_else(|| {
                NotifyError::pre_send(ERR_NOTIFY_TRANSPORT_001, "URL scheme must be https://")
            })?;
        if rest.contains('#') {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_TRANSPORT_001,
                "URL fragments refused",
            ));
        }
        let (authority, path_part) = rest
            .find('/')
            .map_or((rest, "/"), |i| (&rest[..i], &rest[i..]));
        if authority.contains('@') {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_TRANSPORT_001,
                "embedded URL credentials forbidden",
            ));
        }
        let (host, port) = parse_authority(authority)?;
        if path_part.starts_with("//") || path_part.split('/').any(|s| s == "." || s == "..") {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_TRANSPORT_001,
                "ambiguous URL path refused",
            ));
        }
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port,
            path: path_part.to_owned(),
        })
    }

    /// Formats the HTTP/1.1 `Host` header value.
    #[must_use]
    pub fn host_header(&self) -> String {
        let h = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == 443 {
            h
        } else {
            format!("{h}:{}", self.port)
        }
    }
}

fn parse_authority(authority: &str) -> Result<(&str, u16), NotifyError> {
    if authority.is_empty() {
        return Err(NotifyError::pre_send(
            ERR_NOTIFY_TRANSPORT_001,
            "empty URL authority",
        ));
    }
    if let Some(after) = authority.strip_prefix('[') {
        let close = after.find(']').ok_or_else(|| {
            NotifyError::pre_send(ERR_NOTIFY_TRANSPORT_001, "unterminated IPv6 host")
        })?;
        let rem = &after[close + 1..];
        let port = if rem.is_empty() {
            443
        } else if let Some(p) = rem.strip_prefix(':') {
            parse_port(p)?
        } else {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_TRANSPORT_001,
                "malformed IPv6 authority",
            ));
        };
        return Ok((&after[..close], port));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, parse_port(p)?),
        None => (authority, 443),
    };
    if host.is_empty()
        || host.len() > 253
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return Err(NotifyError::pre_send(
            ERR_NOTIFY_TRANSPORT_001,
            "invalid URL hostname",
        ));
    }
    Ok((host, port))
}

fn parse_port(s: &str) -> Result<u16, NotifyError> {
    let port = s
        .parse::<u16>()
        .map_err(|_| NotifyError::pre_send(ERR_NOTIFY_TRANSPORT_001, "invalid TCP port"))?;
    if port == 0 {
        return Err(NotifyError::pre_send(
            ERR_NOTIFY_TRANSPORT_001,
            "TCP port 0 refused",
        ));
    }
    Ok(port)
}

/// Validated production HTTPS webhook target holding only the non-secret vault [`SecretId`].
#[derive(Clone, Eq, PartialEq)]
pub struct HttpsWebhookTarget {
    /// Non-secret operator target identifier.
    pub target_id: String,
    /// Validated HTTPS endpoint URL.
    pub url: ValidatedHttpsUrl,
    /// Vault secret identifier for the HMAC-SHA256 signing key.
    pub hmac_secret_id: SecretId,
    /// Exact vault scope (`AdapterFamily::AlertWebhook`) bound to this target.
    pub secret_scope: SecretScope,
    /// Explicit TLS 1.3 certificate trust policy.
    pub tls_trust: TlsTrustPolicy,
    /// Enforced disclosure profile.
    pub disclosure_profile: DisclosureProfile,
    /// Explicit metadata disclosure approval, if required.
    pub metadata_approval: Option<ContentDigest>,
    /// Explicit visual disclosure approval, if required.
    pub visual_approval: Option<ContentDigest>,
    /// Canonical route digest under [`NOTIFY_WEBHOOK_ROUTE_DOMAIN`].
    pub route_digest: ContentDigest,
}

impl HttpsWebhookTarget {
    /// Constructs and validates a production HTTPS HMAC-signed webhook target.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target_id: impl Into<String>,
        https_url: &str,
        hmac_secret_id: SecretId,
        tls_trust: TlsTrustPolicy,
        disclosure_profile: DisclosureProfile,
        metadata_approval: Option<ContentDigest>,
        visual_approval: Option<ContentDigest>,
    ) -> Result<Self, NotifyError> {
        let target_id = target_id.into();
        if target_id.is_empty() || target_id.len() > 128 {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_TRANSPORT_001,
                "webhook target_id invalid",
            ));
        }
        let url = ValidatedHttpsUrl::parse_production(https_url)?;
        disclosure_profile.validate_approvals(metadata_approval, visual_approval)?;
        let endpoint_scope = format!("https://{}:{}{}", url.host, url.port, url.path);
        let secret_scope =
            SecretScope::new(AdapterFamily::AlertWebhook, &target_id, &endpoint_scope).map_err(
                |_| NotifyError::pre_send(ERR_NOTIFY_VAULT_001, "invalid AlertWebhook SecretScope"),
            )?;
        let mut enc = CanonicalEncoder::new();
        enc.text(NOTIFY_WEBHOOK_ROUTE_DOMAIN);
        enc.text(&target_id);
        enc.text(&url.host);
        enc.u32(u32::from(url.port));
        enc.text(&url.path);
        hmac_secret_id.encode_canonical(&mut enc);
        enc.text(disclosure_profile.as_str());
        if let Some(m) = metadata_approval {
            enc.digest(m);
        }
        if let Some(v) = visual_approval {
            enc.digest(v);
        }
        Ok(Self {
            target_id,
            url,
            hmac_secret_id,
            secret_scope,
            tls_trust,
            disclosure_profile,
            metadata_approval,
            visual_approval,
            route_digest: ContentDigest::sha256(&enc.finish()),
        })
    }
}

impl fmt::Debug for HttpsWebhookTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpsWebhookTarget")
            .field("target_id", &self.target_id)
            .field("host", &self.url.host)
            .field("port", &self.url.port)
            .field("hmac_secret_id", &self.hmac_secret_id)
            .field("disclosure_profile", &self.disclosure_profile)
            .field("route_digest", &self.route_digest)
            .finish()
    }
}

/// Computes `X-FSS-Signature-256` (`sha256=<hex>`) over `"{timestamp_unix_s}.{delivery_id}.{body}"`.
#[must_use]
pub fn compute_webhook_signature(
    secret_key: &[u8],
    timestamp_unix_s: i64,
    delivery_id: &str,
    body: &[u8],
) -> String {
    let prefix = format!("{timestamp_unix_s}.{delivery_id}.");
    let mut input = Zeroizing::new(Vec::with_capacity(prefix.len() + body.len()));
    input.extend_from_slice(prefix.as_bytes());
    input.extend_from_slice(body);
    format!(
        "sha256={}",
        encode_hex_lower(&hmac_sha256(secret_key, &input))
    )
}

/// Constant-time verification of an incoming `X-FSS-Signature-256` webhook header.
#[must_use]
pub fn verify_webhook_signature(
    secret_key: &[u8],
    timestamp_unix_s: i64,
    delivery_id: &str,
    body: &[u8],
    signature_header: &str,
) -> bool {
    let expected = compute_webhook_signature(secret_key, timestamp_unix_s, delivery_id, body);
    constant_time_eq(expected.as_bytes(), signature_header.as_bytes())
}

/// Dispatches an HMAC-SHA256 signed HTTPS webhook over pure-Rust RFC 8446 TLS 1.3.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_https_webhook(
    target: &HttpsWebhookTarget,
    payload: &NotifyPayload,
    vault: &dyn SecretStore,
    secret_cx: &SecretAccessCx,
    dns: &dyn DnsResolver,
    deadline: &NotifyDeadlineCx,
    limits: NotifyLimits,
    entropy: &mut dyn EntropySource,
) -> Result<DeliveryReceipt, NotifyError> {
    target
        .disclosure_profile
        .validate_approvals(target.metadata_approval, target.visual_approval)?;
    payload.validate_for_profile(target.disclosure_profile)?;
    if secret_cx.scope() != &target.secret_scope {
        return Err(NotifyError::pre_send(
            ERR_NOTIFY_VAULT_001,
            "SecretAccessCx scope mismatch",
        ));
    }
    let fetched = vault
        .fetch(secret_cx, &target.hmac_secret_id)
        .map_err(|err| {
            NotifyError::pre_send(
                ERR_NOTIFY_VAULT_001,
                format!("vault fetch failed ({})", err.error_id()),
            )
        })?;

    let body = build_webhook_json_body(payload, target.disclosure_profile)?;
    let ts_s = i64::try_from(deadline.now().0.div_euclid(1_000_000_000))
        .map_err(|_| NotifyError::pre_send(ERR_NOTIFY_TRANSPORT_001, "timestamp out of range"))?;
    let delivery_id = payload.operation_id.as_str();
    let sig = compute_webhook_signature(
        fetched.secret().as_slice(),
        ts_s,
        delivery_id,
        body.as_bytes(),
    );
    drop(fetched);

    let extra_headers = [
        (
            "Content-Type",
            Zeroizing::new("application/json".to_owned()),
        ),
        ("X-FSS-Timestamp", Zeroizing::new(ts_s.to_string())),
        ("X-FSS-Delivery-Id", Zeroizing::new(delivery_id.to_owned())),
        ("X-FSS-Signature-256", Zeroizing::new(sig)),
        (
            "Idempotency-Key",
            Zeroizing::new(payload.idempotency_key.as_str().to_owned()),
        ),
    ];
    let request_digest = ContentDigest::sha256(body.as_bytes());
    let reply = send_tls_http_request(
        &target.url,
        "POST",
        &extra_headers,
        body.as_bytes(),
        &target.tls_trust,
        dns,
        deadline,
        limits,
        entropy,
    )?;
    classify_http_delivery(
        payload,
        "https_webhook",
        target.route_digest,
        target.disclosure_profile,
        request_digest,
        deadline.now(),
        reply,
    )
}

pub(crate) fn build_webhook_json_body(
    payload: &NotifyPayload,
    profile: DisclosureProfile,
) -> Result<String, NotifyError> {
    let mut out = String::with_capacity(512);
    out.push_str("{\"schema\":");
    push_json_str(
        &mut out,
        match profile {
            DisclosureProfile::ReferencesV1 => "fss.notify.webhook.references.v1",
            DisclosureProfile::EventMetadataV1 => "fss.notify.webhook.event_metadata.v1",
            DisclosureProfile::EventMetadataVisualV1 => {
                "fss.notify.webhook.event_metadata_visual.v1"
            }
        },
    );
    out.push_str(",\"disclosure_profile\":");
    push_json_str(&mut out, profile.as_str());
    out.push_str(",\"operation_id\":");
    push_json_str(&mut out, payload.operation_id.as_str());
    out.push_str(",\"idempotency_key\":");
    push_json_str(&mut out, payload.idempotency_key.as_str());
    out.push_str(",\"channel\":");
    push_json_str(&mut out, &payload.channel);
    out.push_str(",\"event_root\":");
    push_json_str(&mut out, &payload.event_root.to_text());
    out.push_str(",\"event_revision_digest\":");
    push_json_str(&mut out, &payload.event_revision_digest.to_text());

    if matches!(
        profile,
        DisclosureProfile::EventMetadataV1 | DisclosureProfile::EventMetadataVisualV1
    ) {
        let meta = payload
            .event_metadata
            .as_ref()
            .ok_or_else(|| NotifyError::disclosure("missing event metadata"))?;
        out.push_str(",\"event\":{\"event_id\":");
        push_json_str(&mut out, meta.event_id.as_str());
        out.push_str(",\"revision\":");
        out.push_str(&meta.revision.to_string());
        out.push_str(",\"kind\":");
        push_json_str(&mut out, &meta.kind);
        out.push_str(",\"lifecycle\":");
        push_json_str(&mut out, &meta.lifecycle);
        out.push_str(",\"zone_ids\":[");
        for (idx, zone) in meta.zone_ids.iter().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            push_json_str(&mut out, zone);
        }
        out.push_str("],\"summary\":");
        push_json_str(&mut out, &meta.summary);
        out.push_str(",\"physical_truth_claim\":\"not_claimed\"}");
    }
    if profile == DisclosureProfile::EventMetadataVisualV1 {
        let vis = payload
            .visual_attachment
            .as_ref()
            .ok_or_else(|| NotifyError::disclosure("missing H3 attachment"))?;
        vis.verify()?;
        out.push_str(",\"visual\":{\"h3_receipt_digest\":");
        push_json_str(&mut out, &vis.receipt_digest.to_text());
        out.push_str(",\"privacy_mask_binding_digest\":");
        push_json_str(&mut out, &vis.privacy_mask_binding_digest.to_text());
        out.push_str(",\"applied_redaction_transform\":");
        push_json_str(&mut out, &vis.applied_redaction_transform);
        out.push_str(&format!(
            ",\"width\":{},\"height\":{},\"content_type\":\"image/jpeg\",\"jpeg_base64\":",
            vis.width, vis.height
        ));
        push_json_str(&mut out, &encode_base64_std(&vis.jpeg_bytes));
        out.push('}');
    }
    out.push('}');
    Ok(out)
}

pub(crate) struct TlsHttpReply {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) dns_receipt: DnsResolutionReceipt,
    pub(crate) peer_cert: VerifiedPeerCert,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn send_tls_http_request(
    url: &ValidatedHttpsUrl,
    method: &str,
    headers: &[(&str, Zeroizing<String>)],
    body: &[u8],
    tls_trust: &TlsTrustPolicy,
    dns: &dyn DnsResolver,
    deadline: &NotifyDeadlineCx,
    limits: NotifyLimits,
    entropy: &mut dyn EntropySource,
) -> Result<TlsHttpReply, NotifyError> {
    let mut wire = Zeroizing::new(Vec::with_capacity(512 + body.len()));
    wire.extend_from_slice(
        format!(
            "{method} {} HTTP/1.1\r\nHost: {}\r\n",
            url.path,
            url.host_header()
        )
        .as_bytes(),
    );
    for (name, val) in headers {
        wire.extend_from_slice(name.as_bytes());
        wire.extend_from_slice(b": ");
        wire.extend_from_slice(val.as_bytes());
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(
        format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    wire.extend_from_slice(body);
    if wire.len() > limits.max_request_bytes {
        return Err(NotifyError::pre_send(
            ERR_NOTIFY_TRANSPORT_001,
            "HTTP request exceeds max_request_bytes",
        ));
    }

    let rem = deadline.remaining(false)?;
    let dns_receipt = dns.resolve(&url.host, url.port, deadline.now())?;
    let tcp = TcpStream::connect_timeout(&dns_receipt.resolved_addrs[0], rem).map_err(|_| {
        NotifyError::pre_send(ERR_NOTIFY_TRANSPORT_001, "TCP connect failed")
            .with_dns_receipt(dns_receipt.clone())
    })?;
    configure_socket_timeouts(
        &tcp,
        deadline
            .remaining(false)
            .map_err(|e| e.with_dns_receipt(dns_receipt.clone()))?,
    )
    .map_err(|e| e.with_dns_receipt(dns_receipt.clone()))?;

    let mut tls = Tls13Stream::connect_client(tcp, &url.host, tls_trust, deadline.now(), entropy)
        .map_err(|err| map_tls_error(err, false).with_dns_receipt(dns_receipt.clone()))?;
    let peer_cert = tls
        .verified_peer_cert()
        .cloned()
        .ok_or_else(|| NotifyError::tls_cert("missing verified peer cert"))?;
    configure_socket_timeouts(
        tls.get_ref(),
        deadline
            .remaining(false)
            .map_err(|e| e.with_dns_receipt(dns_receipt.clone()))?,
    )
    .map_err(|e| e.with_dns_receipt(dns_receipt.clone()))?;

    // Point of no return: any failure after writing application bytes is strictly Indeterminate.
    tls.write_application_data(&wire)
        .map_err(|err| map_tls_error(err, true).with_dns_receipt(dns_receipt.clone()))?;
    drop(wire);

    let (status, resp_headers) = read_http_response(&mut tls, deadline, limits.max_response_bytes)
        .map_err(|e| e.with_dns_receipt(dns_receipt.clone()))?;
    let _ = tls.close_notify();

    if (300..400).contains(&status) {
        return Err(NotifyError {
            code: ERR_NOTIFY_REDIRECT_REFUSED_001,
            detail: format!("HTTP redirect status {status} refused fail-closed"),
            pre_send: false,
            dns_receipt: Some(Box::new(dns_receipt)),
        });
    }
    Ok(TlsHttpReply {
        status,
        headers: resp_headers,
        dns_receipt,
        peer_cert,
    })
}

pub(crate) fn configure_socket_timeouts(
    stream: &TcpStream,
    timeout: std::time::Duration,
) -> Result<(), NotifyError> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_| NotifyError::pre_send(ERR_NOTIFY_TRANSPORT_001, "set_read_timeout failed"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|_| NotifyError::pre_send(ERR_NOTIFY_TRANSPORT_001, "set_write_timeout failed"))
}

pub(crate) fn map_tls_error(err: Tls13Error, post_write: bool) -> NotifyError {
    if let Some(code) = err.cert_error_code() {
        return NotifyError::pre_send(code, err.to_string());
    }
    if post_write {
        return NotifyError::indeterminate(format!("post-write TLS failure: {err}"));
    }
    NotifyError::pre_send(
        ERR_NOTIFY_TRANSPORT_001,
        format!("TLS handshake failed: {err}"),
    )
}

fn read_http_response(
    tls: &mut Tls13Stream<TcpStream>,
    deadline: &NotifyDeadlineCx,
    max_bytes: usize,
) -> Result<(u16, Vec<(String, String)>), NotifyError> {
    let mut raw = Vec::new();
    let mut buf = [0_u8; 4096];
    let header_end = loop {
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if raw.len() >= max_bytes {
            return Err(NotifyError::indeterminate(
                "HTTP response headers exceeded limit",
            ));
        }
        let rem = deadline.remaining(true)?;
        let _ = tls.get_ref().set_read_timeout(Some(rem));
        let cap = (max_bytes - raw.len()).min(buf.len());
        match tls.read_application_data(&mut buf[..cap]) {
            Ok(0) => return Err(NotifyError::indeterminate("socket closed mid-response")),
            Ok(n) => raw.extend_from_slice(&buf[..n]),
            Err(Tls13Error::Io(e)) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => {
                return Err(NotifyError::indeterminate(format!(
                    "post-write read error: {err}"
                )));
            }
        }
    };
    let head = std::str::from_utf8(&raw[..header_end - 4])
        .map_err(|_| NotifyError::indeterminate("non-UTF-8 HTTP headers"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| NotifyError::indeterminate("missing HTTP status line"))?;
    let mut parts = status_line.split_whitespace();
    let ver = parts
        .next()
        .ok_or_else(|| NotifyError::indeterminate("malformed HTTP status line"))?;
    if ver != "HTTP/1.1" && ver != "HTTP/1.0" {
        return Err(NotifyError::indeterminate("unsupported HTTP version"));
    }
    let status = parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| NotifyError::indeterminate("invalid HTTP status"))?;

    let mut headers = Vec::new();
    let mut content_length: Option<usize> = None;
    for line in lines {
        let (k, v) = line
            .split_once(':')
            .ok_or_else(|| NotifyError::indeterminate("malformed HTTP header"))?;
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim().to_owned();
        if key == "content-length" {
            content_length = Some(
                val.parse::<usize>()
                    .map_err(|_| NotifyError::indeterminate("bad Content-Length"))?,
            );
        }
        headers.push((key, val));
    }
    if let Some(expected) = content_length {
        if expected > max_bytes {
            return Err(NotifyError::indeterminate(
                "HTTP response body exceeds limit",
            ));
        }
        let mut received = raw.len() - header_end;
        while received < expected {
            let rem = deadline.remaining(true)?;
            let _ = tls.get_ref().set_read_timeout(Some(rem));
            let need = (expected - received).min(buf.len());
            match tls.read_application_data(&mut buf[..need]) {
                Ok(0) => {
                    return Err(NotifyError::indeterminate(
                        "socket closed before Content-Length completed",
                    ));
                }
                Ok(n) => received += n,
                Err(Tls13Error::Io(e)) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => {
                    return Err(NotifyError::indeterminate(format!(
                        "HTTP body read error: {err}"
                    )));
                }
            }
        }
    }
    Ok((status, headers))
}

pub(crate) fn classify_http_delivery(
    payload: &NotifyPayload,
    relay_kind: &str,
    route_digest: ContentDigest,
    profile: DisclosureProfile,
    request_digest: ContentDigest,
    now: fss_core::TimestampNs,
    reply: TlsHttpReply,
) -> Result<DeliveryReceipt, NotifyError> {
    if (200..300).contains(&reply.status) {
        let remote_id = reply
            .headers
            .iter()
            .find(|(k, _)| k == "x-request-id" || k == "x-message-id")
            .map(|(_, v)| v.clone());
        let observation = DeliveryObservation::seal(
            payload.operation_id.clone(),
            payload.idempotency_key.clone(),
            relay_kind,
            route_digest,
            reply.dns_receipt,
            reply.peer_cert.leaf_spki_sha256,
            reply.peer_cert.leaf_cert_sha256,
            profile,
            payload.visual_attachment.as_ref().map(|v| v.receipt_digest),
            reply.status,
            request_digest,
            now,
        );
        return Ok(DeliveryReceipt {
            observation,
            remote_message_id: remote_id,
        });
    }
    if (400..500).contains(&reply.status) {
        return Err(NotifyError::pre_send(
            ERR_NOTIFY_TRANSPORT_001,
            format!("{relay_kind} rejected HTTP {}", reply.status),
        )
        .with_dns_receipt(reply.dns_receipt));
    }
    Err(
        NotifyError::indeterminate(format!("{relay_kind} ambiguous HTTP {}", reply.status))
            .with_dns_receipt(reply.dns_receipt),
    )
}

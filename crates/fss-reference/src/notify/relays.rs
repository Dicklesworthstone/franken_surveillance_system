#![forbid(unsafe_code)]
//! First-class TLS 1.3 multi-channel notification relays: **ntfy** and **Pushover**.
//!
//! All credentials (ntfy bearer tokens, Pushover app token & user key) are fetched exclusively
//! through `fss_vault::{SecretStore, SecretAccessCx}` under [`AdapterFamily::AlertRelay`],
//! wrapped in [`Zeroizing`], and never appear in configs, receipts, errors, or logs.

use core::fmt;

use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest};
use fss_vault::{AdapterFamily, EntropySource, SecretAccessCx, SecretId, SecretScope, SecretStore};
use zeroize::Zeroizing;

use super::webhook::{ValidatedHttpsUrl, classify_http_delivery, send_tls_http_request};
use super::x509::TlsTrustPolicy;
use super::{
    DeliveryReceipt, DisclosureProfile, DnsResolver, ERR_NOTIFY_TRANSPORT_001,
    ERR_NOTIFY_VAULT_001, NOTIFY_RELAY_ROUTE_DOMAIN, NotifyDeadlineCx, NotifyError, NotifyLimits,
    NotifyPayload, encode_base64_std, push_json_str, validate_header_text,
};

/// Validated production **ntfy** TLS 1.3 relay target.
///
/// Stores only the non-secret [`SecretId`] for the bearer token, never raw token bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct NtfyTarget {
    /// Non-secret operator target identifier (e.g., `"ntfy-oncall"`).
    pub target_id: String,
    /// Validated HTTPS publish URL (`https://<host>[:port]/<topic>`).
    pub url: ValidatedHttpsUrl,
    /// Validated ntfy topic slug (`1..=64` ASCII `[A-Za-z0-9_-]`).
    pub topic: String,
    /// Vault secret identifier holding the ntfy bearer token.
    pub bearer_secret_id: SecretId,
    /// Exact vault scope (`AdapterFamily::AlertRelay`) bound to this target.
    pub secret_scope: SecretScope,
    /// Explicit TLS 1.3 certificate trust policy.
    pub tls_trust: TlsTrustPolicy,
    /// Enforced disclosure profile.
    pub disclosure_profile: DisclosureProfile,
    /// Explicit metadata disclosure approval, if required by profile.
    pub metadata_approval: Option<ContentDigest>,
    /// Explicit visual disclosure approval, if required by profile.
    pub visual_approval: Option<ContentDigest>,
    /// ntfy message priority (`1..=5`, default `4` = high).
    pub priority: u8,
    /// Bounded non-secret ntfy emoji/tag tokens (`0..=8`).
    pub tags: Vec<String>,
    /// Canonical route digest under [`NOTIFY_RELAY_ROUTE_DOMAIN`].
    pub route_digest: ContentDigest,
}

impl NtfyTarget {
    /// Constructs and validates an HTTPS TLS 1.3 ntfy relay target.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target_id: impl Into<String>,
        server_https_url: &str,
        topic: impl Into<String>,
        bearer_secret_id: SecretId,
        tls_trust: TlsTrustPolicy,
        disclosure_profile: DisclosureProfile,
        metadata_approval: Option<ContentDigest>,
        visual_approval: Option<ContentDigest>,
        priority: u8,
        tags: Vec<String>,
    ) -> Result<Self, NotifyError> {
        let target_id = target_id.into();
        let topic = topic.into();
        if target_id.is_empty() || target_id.len() > 128 {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_TRANSPORT_001,
                "ntfy target_id length outside 1..=128",
            ));
        }
        if topic.is_empty()
            || topic.len() > 64
            || !topic
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_TRANSPORT_001,
                "ntfy topic must be 1..=64 ASCII [A-Za-z0-9_-]",
            ));
        }
        if !(1..=5).contains(&priority) {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_TRANSPORT_001,
                "ntfy priority must be in 1..=5",
            ));
        }
        if tags.len() > 8 {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_TRANSPORT_001,
                "ntfy tags count exceeds maximum of 8",
            ));
        }
        for tag in &tags {
            validate_header_text("ntfy tag", tag, 32)?;
            if tag.contains(',') {
                return Err(NotifyError::pre_send(
                    ERR_NOTIFY_TRANSPORT_001,
                    "ntfy tag must not contain ','",
                ));
            }
        }
        disclosure_profile.validate_approvals(metadata_approval, visual_approval)?;
        let base = ValidatedHttpsUrl::parse_production(server_https_url)?;
        let full_path = if base.path == "/" {
            format!("/{topic}")
        } else {
            format!("{}/{topic}", base.path.trim_end_matches('/'))
        };
        let url = ValidatedHttpsUrl {
            host: base.host,
            port: base.port,
            path: full_path,
        };
        let endpoint_scope = format!("https://{}:{}{}", url.host, url.port, url.path);
        let secret_scope = SecretScope::new(AdapterFamily::AlertRelay, &target_id, &endpoint_scope)
            .map_err(|_| {
                NotifyError::pre_send(
                    ERR_NOTIFY_VAULT_001,
                    "failed to construct AlertRelay SecretScope for ntfy",
                )
            })?;
        let mut enc = CanonicalEncoder::new();
        enc.text(NOTIFY_RELAY_ROUTE_DOMAIN);
        enc.text("ntfy");
        enc.text(&target_id);
        enc.text(&url.host);
        enc.u32(u32::from(url.port));
        enc.text(&url.path);
        bearer_secret_id.encode_canonical(&mut enc);
        enc.text(disclosure_profile.as_str());
        enc.u8(priority);
        let route_digest = ContentDigest::sha256(&enc.finish());
        Ok(Self {
            target_id,
            url,
            topic,
            bearer_secret_id,
            secret_scope,
            tls_trust,
            disclosure_profile,
            metadata_approval,
            visual_approval,
            priority,
            tags,
            route_digest,
        })
    }
}

impl fmt::Debug for NtfyTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtfyTarget")
            .field("target_id", &self.target_id)
            .field("host", &self.url.host)
            .field("port", &self.url.port)
            .field("topic", &self.topic)
            .field("bearer_secret_id", &self.bearer_secret_id)
            .field("disclosure_profile", &self.disclosure_profile)
            .field("route_digest", &self.route_digest)
            .finish()
    }
}

/// Dispatches an ntfy notification over pure-Rust RFC 8446 TLS 1.3 with vault Bearer auth.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_ntfy(
    target: &NtfyTarget,
    payload: &NotifyPayload,
    vault: &dyn SecretStore,
    secret_cx: &SecretAccessCx,
    dns: &dyn DnsResolver,
    deadline: &NotifyDeadlineCx<'_>,
    limits: NotifyLimits,
    entropy: &mut dyn EntropySource,
) -> Result<DeliveryReceipt, NotifyError> {
    let _ = deadline.remaining(false)?;
    target
        .disclosure_profile
        .validate_approvals(target.metadata_approval, target.visual_approval)?;
    payload.validate_for_profile(target.disclosure_profile)?;
    if secret_cx.scope() != &target.secret_scope {
        return Err(NotifyError::pre_send(
            ERR_NOTIFY_VAULT_001,
            "SecretAccessCx scope does not match ntfy AlertRelay scope",
        ));
    }
    let fetched = vault
        .fetch(secret_cx, &target.bearer_secret_id)
        .map_err(|err| {
            NotifyError::pre_send(
                ERR_NOTIFY_VAULT_001,
                format!("ntfy bearer vault fetch failed ({})", err.error_id()),
            )
        })?;
    let token_str = std::str::from_utf8(fetched.secret().as_slice()).map_err(|_| {
        NotifyError::pre_send(
            ERR_NOTIFY_VAULT_001,
            "ntfy bearer token must be valid UTF-8",
        )
    })?;
    validate_header_text("ntfy bearer token", token_str, 1024)?;
    let auth_header = Zeroizing::new(format!("Bearer {token_str}"));
    drop(fetched);

    let (title, message) = format_relay_text(payload, target.disclosure_profile)?;
    validate_header_text("ntfy Title", &title, 256)?;

    let mut headers = vec![
        ("Authorization", auth_header),
        ("Title", Zeroizing::new(title)),
        ("Priority", Zeroizing::new(target.priority.to_string())),
        (
            "X-Idempotency-Key",
            Zeroizing::new(payload.idempotency_key.as_str().to_owned()),
        ),
        (
            "X-FSS-Operation-Id",
            Zeroizing::new(payload.operation_id.as_str().to_owned()),
        ),
    ];
    if !target.tags.is_empty() {
        headers.push(("Tags", Zeroizing::new(target.tags.join(","))));
    }

    let body_bytes: Vec<u8> =
        if target.disclosure_profile == DisclosureProfile::EventMetadataVisualV1 {
            let Some(vis) = &payload.visual_attachment else {
                return Err(NotifyError::disclosure(
                    "ntfy event-metadata-visual-v1 requires verified H3VisualAttachment",
                ));
            };
            vis.verify()?;
            validate_header_text("ntfy X-Message", &message, 512)?;
            headers.push(("Content-Type", Zeroizing::new("image/jpeg".to_owned())));
            headers.push(("X-Filename", Zeroizing::new("redacted-h3.jpg".to_owned())));
            headers.push(("X-Message", Zeroizing::new(message)));
            headers.push((
                "X-FSS-H3-Receipt",
                Zeroizing::new(vis.receipt_digest.to_text()),
            ));
            vis.jpeg_bytes.clone()
        } else {
            headers.push((
                "Content-Type",
                Zeroizing::new("text/plain; charset=utf-8".to_owned()),
            ));
            message.into_bytes()
        };

    let request_digest = ContentDigest::sha256(&body_bytes);
    let reply = send_tls_http_request(
        &target.url,
        "POST",
        &headers,
        &body_bytes,
        &target.tls_trust,
        dns,
        deadline,
        limits,
        entropy,
    )?;

    classify_http_delivery(
        payload,
        "ntfy",
        target.route_digest,
        target.disclosure_profile,
        request_digest,
        deadline.now(),
        reply,
    )
}

/// Validated production **Pushover** TLS 1.3 relay target.
///
/// Stores only non-secret vault [`SecretId`]s for the Pushover application token and user key.
#[derive(Clone, Eq, PartialEq)]
pub struct PushoverTarget {
    /// Non-secret operator target identifier (e.g., `"pushover-primary"`).
    pub target_id: String,
    /// Validated HTTPS Pushover API endpoint URL (e.g., `https://api.pushover.net/1/messages.json`).
    pub url: ValidatedHttpsUrl,
    /// Vault secret identifier holding the Pushover application API token.
    pub app_token_secret_id: SecretId,
    /// Vault secret identifier holding the Pushover destination user/group key.
    pub user_key_secret_id: SecretId,
    /// Exact vault scope (`AdapterFamily::AlertRelay`) bound to both secrets.
    pub secret_scope: SecretScope,
    /// Explicit TLS 1.3 certificate trust policy.
    pub tls_trust: TlsTrustPolicy,
    /// Enforced disclosure profile.
    pub disclosure_profile: DisclosureProfile,
    /// Explicit metadata disclosure approval, if required by profile.
    pub metadata_approval: Option<ContentDigest>,
    /// Explicit visual disclosure approval, if required by profile.
    pub visual_approval: Option<ContentDigest>,
    /// Pushover message priority (`-2..=2`).
    pub priority: i8,
    /// Canonical route digest under [`NOTIFY_RELAY_ROUTE_DOMAIN`].
    pub route_digest: ContentDigest,
}

impl PushoverTarget {
    /// Constructs and validates an HTTPS TLS 1.3 Pushover relay target.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target_id: impl Into<String>,
        endpoint_https_url: &str,
        app_token_secret_id: SecretId,
        user_key_secret_id: SecretId,
        tls_trust: TlsTrustPolicy,
        disclosure_profile: DisclosureProfile,
        metadata_approval: Option<ContentDigest>,
        visual_approval: Option<ContentDigest>,
        priority: i8,
    ) -> Result<Self, NotifyError> {
        let target_id = target_id.into();
        if target_id.is_empty() || target_id.len() > 128 {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_TRANSPORT_001,
                "pushover target_id length outside 1..=128",
            ));
        }
        if !(-2..=2).contains(&priority) {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_TRANSPORT_001,
                "pushover priority must be in -2..=2",
            ));
        }
        disclosure_profile.validate_approvals(metadata_approval, visual_approval)?;
        let url = ValidatedHttpsUrl::parse_production(endpoint_https_url)?;
        let endpoint_scope = format!("https://{}:{}{}", url.host, url.port, url.path);
        let secret_scope = SecretScope::new(AdapterFamily::AlertRelay, &target_id, &endpoint_scope)
            .map_err(|_| {
                NotifyError::pre_send(
                    ERR_NOTIFY_VAULT_001,
                    "failed to construct AlertRelay SecretScope for Pushover",
                )
            })?;
        let mut enc = CanonicalEncoder::new();
        enc.text(NOTIFY_RELAY_ROUTE_DOMAIN);
        enc.text("pushover");
        enc.text(&target_id);
        enc.text(&url.host);
        enc.u32(u32::from(url.port));
        enc.text(&url.path);
        app_token_secret_id.encode_canonical(&mut enc);
        user_key_secret_id.encode_canonical(&mut enc);
        enc.text(disclosure_profile.as_str());
        enc.u8((priority + 2) as u8);
        let route_digest = ContentDigest::sha256(&enc.finish());
        Ok(Self {
            target_id,
            url,
            app_token_secret_id,
            user_key_secret_id,
            secret_scope,
            tls_trust,
            disclosure_profile,
            metadata_approval,
            visual_approval,
            priority,
            route_digest,
        })
    }
}

impl fmt::Debug for PushoverTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushoverTarget")
            .field("target_id", &self.target_id)
            .field("host", &self.url.host)
            .field("port", &self.url.port)
            .field("app_token_secret_id", &self.app_token_secret_id)
            .field("user_key_secret_id", &self.user_key_secret_id)
            .field("disclosure_profile", &self.disclosure_profile)
            .field("route_digest", &self.route_digest)
            .finish()
    }
}

/// Dispatches a Pushover notification over pure-Rust RFC 8446 TLS 1.3 using vault credentials.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_pushover(
    target: &PushoverTarget,
    payload: &NotifyPayload,
    vault: &dyn SecretStore,
    secret_cx: &SecretAccessCx,
    dns: &dyn DnsResolver,
    deadline: &NotifyDeadlineCx<'_>,
    limits: NotifyLimits,
    entropy: &mut dyn EntropySource,
) -> Result<DeliveryReceipt, NotifyError> {
    let _ = deadline.remaining(false)?;
    target
        .disclosure_profile
        .validate_approvals(target.metadata_approval, target.visual_approval)?;
    payload.validate_for_profile(target.disclosure_profile)?;
    if secret_cx.scope() != &target.secret_scope {
        return Err(NotifyError::pre_send(
            ERR_NOTIFY_VAULT_001,
            "SecretAccessCx scope does not match Pushover AlertRelay scope",
        ));
    }

    let app_fetched = vault
        .fetch(secret_cx, &target.app_token_secret_id)
        .map_err(|err| {
            NotifyError::pre_send(
                ERR_NOTIFY_VAULT_001,
                format!("pushover app_token fetch failed ({})", err.error_id()),
            )
        })?;
    let user_fetched = vault
        .fetch(secret_cx, &target.user_key_secret_id)
        .map_err(|err| {
            NotifyError::pre_send(
                ERR_NOTIFY_VAULT_001,
                format!("pushover user_key fetch failed ({})", err.error_id()),
            )
        })?;
    let app_token = std::str::from_utf8(app_fetched.secret().as_slice()).map_err(|_| {
        NotifyError::pre_send(
            ERR_NOTIFY_VAULT_001,
            "pushover app_token must be valid UTF-8",
        )
    })?;
    let user_key = std::str::from_utf8(user_fetched.secret().as_slice()).map_err(|_| {
        NotifyError::pre_send(
            ERR_NOTIFY_VAULT_001,
            "pushover user_key must be valid UTF-8",
        )
    })?;

    let (title, message) = format_relay_text(payload, target.disclosure_profile)?;
    let timestamp_s = i64::try_from(deadline.now().0.div_euclid(1_000_000_000)).map_err(|_| {
        NotifyError::pre_send(ERR_NOTIFY_TRANSPORT_001, "timestamp outside Unix seconds")
    })?;

    // Compute canonical non-secret request digest BEFORE mixing in vault credentials.
    let mut non_secret_enc = CanonicalEncoder::new();
    non_secret_enc.text("pushover-logical-message");
    non_secret_enc.text(&title);
    non_secret_enc.text(&message);
    non_secret_enc.u8((target.priority + 2) as u8);
    non_secret_enc.text(&timestamp_s.to_string());
    if let Some(vis) = &payload.visual_attachment {
        non_secret_enc.digest(vis.receipt_digest);
    }
    let request_digest = ContentDigest::sha256(&non_secret_enc.finish());

    let mut json = Zeroizing::new(String::with_capacity(512));
    json.push('{');
    json.push_str("\"token\":");
    push_json_str(&mut json, app_token);
    json.push_str(",\"user\":");
    push_json_str(&mut json, user_key);
    json.push_str(",\"title\":");
    push_json_str(&mut json, &title);
    json.push_str(",\"message\":");
    push_json_str(&mut json, &message);
    json.push_str(",\"priority\":");
    json.push_str(&target.priority.to_string());
    json.push_str(",\"timestamp\":");
    json.push_str(&timestamp_s.to_string());
    if target.disclosure_profile == DisclosureProfile::EventMetadataVisualV1 {
        let Some(vis) = &payload.visual_attachment else {
            return Err(NotifyError::disclosure(
                "pushover event-metadata-visual-v1 requires verified H3VisualAttachment",
            ));
        };
        vis.verify()?;
        json.push_str(",\"attachment_type\":\"image/jpeg\",\"attachment_base64\":");
        push_json_str(&mut json, &encode_base64_std(&vis.jpeg_bytes));
        json.push_str(",\"h3_receipt_digest\":");
        push_json_str(&mut json, &vis.receipt_digest.to_text());
    }
    json.push('}');
    drop(app_fetched);
    drop(user_fetched);

    let headers = [
        (
            "Content-Type",
            Zeroizing::new("application/json".to_owned()),
        ),
        (
            "X-Idempotency-Key",
            Zeroizing::new(payload.idempotency_key.as_str().to_owned()),
        ),
    ];
    let reply = send_tls_http_request(
        &target.url,
        "POST",
        &headers,
        json.as_bytes(),
        &target.tls_trust,
        dns,
        deadline,
        limits,
        entropy,
    )?;
    drop(json);

    classify_http_delivery(
        payload,
        "pushover",
        target.route_digest,
        target.disclosure_profile,
        request_digest,
        deadline.now(),
        reply,
    )
}

/// Formats non-secret title and message text strictly obeying [`DisclosureProfile`].
pub(crate) fn format_relay_text(
    payload: &NotifyPayload,
    profile: DisclosureProfile,
) -> Result<(String, String), NotifyError> {
    match profile {
        DisclosureProfile::ReferencesV1 => Ok((
            "FSS Policy Alert Reference".to_owned(),
            format!(
                "FSS policy-authorized alert; inspect linked event evidence. op={} root={} rev={}",
                payload.operation_id.as_str(),
                payload.event_root.to_text(),
                payload.event_revision_digest.to_text(),
            ),
        )),
        DisclosureProfile::EventMetadataV1 | DisclosureProfile::EventMetadataVisualV1 => {
            let Some(meta) = &payload.event_metadata else {
                return Err(NotifyError::disclosure(
                    "metadata disclosure profile requires NotifyEventMetadata",
                ));
            };
            let zones = if meta.zone_ids.is_empty() {
                "none".to_owned()
            } else {
                meta.zone_ids.join(",")
            };
            Ok((
                format!("FSS Alert: {} ({})", meta.kind, meta.lifecycle),
                format!(
                    "event={} rev={} kind={} lifecycle={} zones=[{}] summary={} physical_truth_claim=not_claimed op={}",
                    meta.event_id.as_str(),
                    meta.revision,
                    meta.kind,
                    meta.lifecycle,
                    zones,
                    meta.summary,
                    payload.operation_id.as_str(),
                ),
            ))
        }
    }
}

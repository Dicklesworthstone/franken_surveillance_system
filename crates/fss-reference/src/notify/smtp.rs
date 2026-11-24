#![forbid(unsafe_code)]
//! First-class SMTP-over-TLS (`SMTPS` implicit TLS 1.3 and `STARTTLS` upgrade) email relay.
//!
//! Credentials (`AUTH PLAIN`) are loaded exclusively via `fss_vault::{SecretStore, SecretAccessCx}`
//! under [`AdapterFamily::AlertRelay`] and are NEVER sent before RFC 8446 TLS 1.3 verification.

use core::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest};
use fss_vault::{AdapterFamily, EntropySource, SecretAccessCx, SecretId, SecretScope, SecretStore};
use zeroize::Zeroizing;

use super::relays::format_relay_text;
use super::tls13::{Tls13Error, Tls13Stream};
use super::webhook::{configure_socket_timeouts, map_tls_error};
use super::x509::TlsTrustPolicy;
use super::{
    DeliveryObservation, DeliveryReceipt, DisclosureProfile, DnsResolver, ERR_NOTIFY_TRANSPORT_001,
    ERR_NOTIFY_VAULT_001, NOTIFY_RELAY_ROUTE_DOMAIN, NotifyDeadlineCx, NotifyError, NotifyLimits,
    NotifyPayload, encode_base64_std, encode_hex_lower, validate_header_text,
};

/// SMTP transport security mode (both modes strictly enforce RFC 8446 TLS 1.3 before `AUTH`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmtpSecurityMode {
    /// Implicit TLS 1.3 immediately upon TCP connect (typically port 465 / SMTPS).
    ImplicitTls,
    /// Cleartext greeting + `EHLO` + mandatory `STARTTLS` upgrade to TLS 1.3 before `AUTH`.
    StartTls,
}

impl SmtpSecurityMode {
    /// Returns the canonical machine-readable mode name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ImplicitTls => "smtps_implicit_tls13",
            Self::StartTls => "smtp_starttls_tls13",
        }
    }
}

/// Validated production SMTP-over-TLS email target holding only non-secret vault [`SecretId`]s.
#[derive(Clone, Eq, PartialEq)]
pub struct SmtpTlsTarget {
    /// Non-secret operator target identifier.
    pub target_id: String,
    /// SMTP server hostname (matched against X.509 SAN/CN).
    pub host: String,
    /// SMTP server TCP port.
    pub port: u16,
    /// Implicit TLS vs mandatory `STARTTLS` upgrade.
    pub security_mode: SmtpSecurityMode,
    /// Client domain sent in `EHLO`.
    pub client_ehlo_domain: String,
    /// RFC 5321 envelope sender address.
    pub from_address: String,
    /// Bounded list of RFC 5321 recipient addresses (`1..=8`).
    pub to_addresses: Vec<String>,
    /// Vault secret identifier for the SMTP `AUTH PLAIN` username.
    pub username_secret_id: SecretId,
    /// Vault secret identifier for the SMTP `AUTH PLAIN` password.
    pub password_secret_id: SecretId,
    /// Exact vault scope (`AdapterFamily::AlertRelay`) bound to SMTP credentials.
    pub secret_scope: SecretScope,
    /// Explicit TLS 1.3 certificate trust policy.
    pub tls_trust: TlsTrustPolicy,
    /// Enforced disclosure profile.
    pub disclosure_profile: DisclosureProfile,
    /// Explicit metadata disclosure approval, if required.
    pub metadata_approval: Option<ContentDigest>,
    /// Explicit visual disclosure approval, if required.
    pub visual_approval: Option<ContentDigest>,
    /// Canonical route digest under [`NOTIFY_RELAY_ROUTE_DOMAIN`].
    pub route_digest: ContentDigest,
}

impl SmtpTlsTarget {
    /// Constructs and validates an SMTP-over-TLS email relay target.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target_id: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        security_mode: SmtpSecurityMode,
        client_ehlo_domain: impl Into<String>,
        from_address: impl Into<String>,
        to_addresses: Vec<String>,
        username_secret_id: SecretId,
        password_secret_id: SecretId,
        tls_trust: TlsTrustPolicy,
        disclosure_profile: DisclosureProfile,
        metadata_approval: Option<ContentDigest>,
        visual_approval: Option<ContentDigest>,
    ) -> Result<Self, NotifyError> {
        let (target_id, host) = (target_id.into(), host.into().to_ascii_lowercase());
        let (client_ehlo_domain, from_address) = (client_ehlo_domain.into(), from_address.into());
        if target_id.is_empty() || target_id.len() > 128 {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_TRANSPORT_001,
                "smtp target_id invalid",
            ));
        }
        if host.is_empty()
            || host.len() > 253
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            || port == 0
        {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_TRANSPORT_001,
                "invalid SMTP host or port",
            ));
        }
        validate_header_text("client_ehlo_domain", &client_ehlo_domain, 128)?;
        validate_email_address("from_address", &from_address)?;
        if to_addresses.is_empty() || to_addresses.len() > 8 {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_TRANSPORT_001,
                "SMTP to_addresses must be 1..=8",
            ));
        }
        for rcpt in &to_addresses {
            validate_email_address("to_address", rcpt)?;
        }
        disclosure_profile.validate_approvals(metadata_approval, visual_approval)?;
        let scheme = match security_mode {
            SmtpSecurityMode::ImplicitTls => "smtps",
            SmtpSecurityMode::StartTls => "smtp+starttls",
        };
        let secret_scope = SecretScope::new(
            AdapterFamily::AlertRelay,
            &target_id,
            format!("{scheme}://{host}:{port}"),
        )
        .map_err(|_| NotifyError::pre_send(ERR_NOTIFY_VAULT_001, "invalid SMTP SecretScope"))?;

        let mut enc = CanonicalEncoder::new();
        enc.text(NOTIFY_RELAY_ROUTE_DOMAIN);
        enc.text("smtp_tls");
        enc.text(&target_id);
        enc.text(&host);
        enc.u32(u32::from(port));
        enc.text(security_mode.as_str());
        enc.text(&from_address);
        enc.u64(to_addresses.len() as u64);
        for rcpt in &to_addresses {
            enc.text(rcpt);
        }
        username_secret_id.encode_canonical(&mut enc);
        password_secret_id.encode_canonical(&mut enc);
        enc.text(disclosure_profile.as_str());
        Ok(Self {
            target_id,
            host,
            port,
            security_mode,
            client_ehlo_domain,
            from_address,
            to_addresses,
            username_secret_id,
            password_secret_id,
            secret_scope,
            tls_trust,
            disclosure_profile,
            metadata_approval,
            visual_approval,
            route_digest: ContentDigest::sha256(&enc.finish()),
        })
    }
}

impl fmt::Debug for SmtpTlsTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpTlsTarget")
            .field("target_id", &self.target_id)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("security_mode", &self.security_mode)
            .field("username_secret_id", &self.username_secret_id)
            .field("password_secret_id", &self.password_secret_id)
            .field("disclosure_profile", &self.disclosure_profile)
            .field("route_digest", &self.route_digest)
            .finish()
    }
}

/// Dispatches an email alert over SMTPS implicit TLS 1.3 or mandatory `STARTTLS` upgrade.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_smtp_tls(
    target: &SmtpTlsTarget,
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
            "SecretAccessCx scope mismatch for SMTP",
        ));
    }
    let user_fetched = vault
        .fetch(secret_cx, &target.username_secret_id)
        .map_err(|e| {
            NotifyError::pre_send(
                ERR_NOTIFY_VAULT_001,
                format!("SMTP username fetch failed ({})", e.error_id()),
            )
        })?;
    let pass_fetched = vault
        .fetch(secret_cx, &target.password_secret_id)
        .map_err(|e| {
            NotifyError::pre_send(
                ERR_NOTIFY_VAULT_001,
                format!("SMTP password fetch failed ({})", e.error_id()),
            )
        })?;
    let auth_plain_cmd = build_auth_plain_command(
        user_fetched.secret().as_slice(),
        pass_fetched.secret().as_slice(),
    )?;
    drop(user_fetched);
    drop(pass_fetched);

    let rfc5322 = build_rfc5322_message(target, payload)?;
    if rfc5322.len() > limits.max_request_bytes {
        return Err(NotifyError::pre_send(
            ERR_NOTIFY_TRANSPORT_001,
            "SMTP message exceeds max_request_bytes",
        ));
    }
    let request_digest = ContentDigest::sha256(&rfc5322);

    let rem = deadline.remaining(false)?;
    let dns_receipt = dns.resolve(&target.host, target.port, deadline.now())?;
    let mut tcp =
        TcpStream::connect_timeout(&dns_receipt.resolved_addrs[0], rem).map_err(|_| {
            NotifyError::pre_send(ERR_NOTIFY_TRANSPORT_001, "SMTP TCP connect failed")
                .with_dns_receipt(dns_receipt.clone())
        })?;
    configure_socket_timeouts(
        &tcp,
        deadline
            .remaining(false)
            .map_err(|e| e.with_dns_receipt(dns_receipt.clone()))?,
    )
    .map_err(|e| e.with_dns_receipt(dns_receipt.clone()))?;

    let mut tls = match target.security_mode {
        SmtpSecurityMode::ImplicitTls => {
            let mut s = Tls13Stream::connect_client(
                tcp,
                &target.host,
                &target.tls_trust,
                deadline.now(),
                entropy,
            )
            .map_err(|e| map_tls_error(e, false).with_dns_receipt(dns_receipt.clone()))?;
            let (code, _) = read_tls_smtp_reply(&mut s, deadline, false)
                .map_err(|e| e.with_dns_receipt(dns_receipt.clone()))?;
            if code != 220 {
                return Err(NotifyError::pre_send(
                    ERR_NOTIFY_TRANSPORT_001,
                    format!("SMTPS banner {code}"),
                )
                .with_dns_receipt(dns_receipt));
            }
            s
        }
        SmtpSecurityMode::StartTls => {
            let (c0, _) = read_plain_smtp_reply(&mut tcp, deadline)
                .map_err(|e| e.with_dns_receipt(dns_receipt.clone()))?;
            if c0 != 220 {
                return Err(NotifyError::pre_send(
                    ERR_NOTIFY_TRANSPORT_001,
                    format!("SMTP banner {c0}"),
                )
                .with_dns_receipt(dns_receipt));
            }
            write_plain_cmd(&mut tcp, &format!("EHLO {}\r\n", target.client_ehlo_domain))
                .map_err(|e| e.with_dns_receipt(dns_receipt.clone()))?;
            let (c1, ehlo) = read_plain_smtp_reply(&mut tcp, deadline)
                .map_err(|e| e.with_dns_receipt(dns_receipt.clone()))?;
            if c1 != 250 || !ehlo.to_ascii_uppercase().contains("STARTTLS") {
                return Err(NotifyError::pre_send(
                    ERR_NOTIFY_TRANSPORT_001,
                    "SMTP server lacks STARTTLS",
                )
                .with_dns_receipt(dns_receipt));
            }
            write_plain_cmd(&mut tcp, "STARTTLS\r\n")
                .map_err(|e| e.with_dns_receipt(dns_receipt.clone()))?;
            let (c2, _) = read_plain_smtp_reply(&mut tcp, deadline)
                .map_err(|e| e.with_dns_receipt(dns_receipt.clone()))?;
            if c2 != 220 {
                return Err(NotifyError::pre_send(
                    ERR_NOTIFY_TRANSPORT_001,
                    format!("STARTTLS refused ({c2})"),
                )
                .with_dns_receipt(dns_receipt));
            }
            Tls13Stream::connect_client(
                tcp,
                &target.host,
                &target.tls_trust,
                deadline.now(),
                entropy,
            )
            .map_err(|e| map_tls_error(e, false).with_dns_receipt(dns_receipt.clone()))?
        }
    };
    let peer_cert = tls
        .verified_peer_cert()
        .cloned()
        .ok_or_else(|| NotifyError::tls_cert("missing SMTP peer cert"))?;

    // Post-TLS EHLO + AUTH PLAIN + MAIL FROM + RCPT TO + DATA
    expect_tls_cmd(
        &mut tls,
        format!("EHLO {}\r\n", target.client_ehlo_domain).as_bytes(),
        &[250],
        ERR_NOTIFY_TRANSPORT_001,
        deadline,
    )
    .map_err(|e| e.with_dns_receipt(dns_receipt.clone()))?;
    let auth_res = expect_tls_cmd(
        &mut tls,
        auth_plain_cmd.as_bytes(),
        &[235],
        ERR_NOTIFY_VAULT_001,
        deadline,
    );
    drop(auth_plain_cmd);
    auth_res.map_err(|e| e.with_dns_receipt(dns_receipt.clone()))?;
    expect_tls_cmd(
        &mut tls,
        format!("MAIL FROM:<{}>\r\n", target.from_address).as_bytes(),
        &[250],
        ERR_NOTIFY_TRANSPORT_001,
        deadline,
    )
    .map_err(|e| e.with_dns_receipt(dns_receipt.clone()))?;
    for rcpt in &target.to_addresses {
        expect_tls_cmd(
            &mut tls,
            format!("RCPT TO:<{rcpt}>\r\n").as_bytes(),
            &[250, 251],
            ERR_NOTIFY_TRANSPORT_001,
            deadline,
        )
        .map_err(|e| e.with_dns_receipt(dns_receipt.clone()))?;
    }
    expect_tls_cmd(
        &mut tls,
        b"DATA\r\n",
        &[354],
        ERR_NOTIFY_TRANSPORT_001,
        deadline,
    )
    .map_err(|e| e.with_dns_receipt(dns_receipt.clone()))?;

    // Point of no return: writing DATA body + `\r\n.\r\n` commits the email to the relay.
    send_tls_cmd(&mut tls, &dot_stuff_rfc5321(&rfc5322), deadline, true)
        .map_err(|e| e.with_dns_receipt(dns_receipt.clone()))?;
    let (final_code, final_text) = read_tls_smtp_reply(&mut tls, deadline, true)
        .map_err(|e| e.with_dns_receipt(dns_receipt.clone()))?;
    let _ = send_tls_cmd(&mut tls, b"QUIT\r\n", deadline, true);
    let _ = tls.close_notify();

    if final_code != 250 {
        if (500..600).contains(&final_code) {
            return Err(NotifyError::pre_send(
                ERR_NOTIFY_TRANSPORT_001,
                format!("SMTP DATA rejected ({final_code})"),
            )
            .with_dns_receipt(dns_receipt));
        }
        return Err(
            NotifyError::indeterminate(format!("SMTP DATA ambiguous ({final_code})"))
                .with_dns_receipt(dns_receipt),
        );
    }
    let observation = DeliveryObservation::seal(
        payload.operation_id.clone(),
        payload.idempotency_key.clone(),
        "smtp_tls",
        target.route_digest,
        dns_receipt,
        peer_cert.leaf_spki_sha256,
        peer_cert.leaf_cert_sha256,
        target.disclosure_profile,
        payload.visual_attachment.as_ref().map(|v| v.receipt_digest),
        final_code,
        request_digest,
        deadline.now(),
    );
    Ok(DeliveryReceipt {
        observation,
        remote_message_id: final_text
            .lines()
            .next()
            .map(|l| l.trim().chars().take(96).collect()),
    })
}

pub(crate) fn build_rfc5322_message(
    target: &SmtpTlsTarget,
    payload: &NotifyPayload,
) -> Result<Vec<u8>, NotifyError> {
    let (subject, text_body) = format_relay_text(payload, target.disclosure_profile)?;
    validate_header_text("SMTP Subject", &subject, 256)?;
    let msg_id = format!(
        "<{}@{}>",
        payload.idempotency_key.as_str().replace(':', "."),
        target.client_ehlo_domain
    );
    let mut out = format!(
        "From: <{}>\r\nTo: {}\r\nSubject: {subject}\r\nMessage-ID: {msg_id}\r\nX-FSS-Operation-Id: {}\r\nX-FSS-Idempotency-Key: {}\r\nMIME-Version: 1.0\r\n",
        target.from_address,
        target.to_addresses.join(", "),
        payload.operation_id.as_str(),
        payload.idempotency_key.as_str(),
    );
    if target.disclosure_profile == DisclosureProfile::EventMetadataVisualV1 {
        let vis = payload
            .visual_attachment
            .as_ref()
            .ok_or_else(|| NotifyError::disclosure("SMTP visual requires H3 attachment"))?;
        vis.verify()?;
        let boundary = format!(
            "fss-boundary-{}",
            &encode_hex_lower(&vis.receipt_digest.bytes())[..24]
        );
        out.push_str(&format!(
            "Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{text_body}\r\n--{boundary}\r\nContent-Type: image/jpeg; name=\"redacted-h3.jpg\"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"redacted-h3.jpg\"\r\nX-FSS-H3-Receipt: {}\r\n\r\n",
            vis.receipt_digest.to_text(),
        ));
        for chunk in encode_base64_std(&vis.jpeg_bytes).as_bytes().chunks(76) {
            if let Ok(line) = std::str::from_utf8(chunk) {
                out.push_str(line);
                out.push_str("\r\n");
            }
        }
        out.push_str(&format!("--{boundary}--\r\n"));
    } else {
        out.push_str(&format!(
            "Content-Type: text/plain; charset=utf-8\r\n\r\n{text_body}\r\n"
        ));
    }
    Ok(out.into_bytes())
}

fn build_auth_plain_command(user: &[u8], pass: &[u8]) -> Result<Zeroizing<String>, NotifyError> {
    if user.is_empty()
        || pass.is_empty()
        || user.contains(&0)
        || pass.contains(&0)
        || user.len() > 256
        || pass.len() > 512
    {
        return Err(NotifyError::pre_send(
            ERR_NOTIFY_VAULT_001,
            "invalid SMTP AUTH PLAIN credentials",
        ));
    }
    let mut raw = Zeroizing::new(Vec::with_capacity(2 + user.len() + pass.len()));
    raw.push(0);
    raw.extend_from_slice(user);
    raw.push(0);
    raw.extend_from_slice(pass);
    let b64 = Zeroizing::new(encode_base64_std(&raw));
    Ok(Zeroizing::new(format!("AUTH PLAIN {}\r\n", b64.as_str())))
}

fn dot_stuff_rfc5321(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.len() + 32);
    let mut line_start = true;
    for &b in msg {
        if line_start && b == b'.' {
            out.push(b'.');
        }
        out.push(b);
        line_start = b == b'\n';
    }
    if !out.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

fn validate_email_address(field: &str, addr: &str) -> Result<(), NotifyError> {
    validate_header_text(field, addr, 254)?;
    if addr.contains('<') || addr.contains('>') || addr.contains(' ') || addr.contains(',') {
        return Err(NotifyError::pre_send(
            ERR_NOTIFY_TRANSPORT_001,
            format!("invalid email in {field}"),
        ));
    }
    let Some((local, domain)) = addr.split_once('@') else {
        return Err(NotifyError::pre_send(
            ERR_NOTIFY_TRANSPORT_001,
            format!("missing '@' in {field}"),
        ));
    };
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        return Err(NotifyError::pre_send(
            ERR_NOTIFY_TRANSPORT_001,
            format!("malformed email in {field}"),
        ));
    }
    Ok(())
}

fn write_plain_cmd(tcp: &mut TcpStream, cmd: &str) -> Result<(), NotifyError> {
    tcp.write_all(cmd.as_bytes())
        .map_err(|_| NotifyError::pre_send(ERR_NOTIFY_TRANSPORT_001, "SMTP write failed"))?;
    tcp.flush()
        .map_err(|_| NotifyError::pre_send(ERR_NOTIFY_TRANSPORT_001, "SMTP flush failed"))
}

fn send_tls_cmd(
    tls: &mut Tls13Stream<TcpStream>,
    data: &[u8],
    deadline: &NotifyDeadlineCx,
    post_write: bool,
) -> Result<(), NotifyError> {
    let _ = tls
        .get_ref()
        .set_write_timeout(Some(deadline.remaining(post_write)?));
    tls.write_application_data(data)
        .map_err(|e| map_tls_error(e, post_write))
}

fn expect_tls_cmd(
    tls: &mut Tls13Stream<TcpStream>,
    data: &[u8],
    expected: &[u16],
    err_code: &'static str,
    deadline: &NotifyDeadlineCx,
) -> Result<String, NotifyError> {
    send_tls_cmd(tls, data, deadline, false)?;
    let (code, text) = read_tls_smtp_reply(tls, deadline, false)?;
    if !expected.contains(&code) {
        return Err(NotifyError::pre_send(
            err_code,
            format!("unexpected SMTP reply {code}"),
        ));
    }
    Ok(text)
}

fn read_plain_smtp_reply(
    tcp: &mut TcpStream,
    deadline: &NotifyDeadlineCx,
) -> Result<(u16, String), NotifyError> {
    read_smtp_reply_generic(deadline, false, |buf, rem| {
        let _ = tcp.set_read_timeout(Some(rem));
        tcp.read(buf)
            .map_err(|_| NotifyError::pre_send(ERR_NOTIFY_TRANSPORT_001, "SMTP read failed"))
    })
}

fn read_tls_smtp_reply(
    tls: &mut Tls13Stream<TcpStream>,
    deadline: &NotifyDeadlineCx,
    post_write: bool,
) -> Result<(u16, String), NotifyError> {
    read_smtp_reply_generic(deadline, post_write, |buf, rem| {
        let _ = tls.get_ref().set_read_timeout(Some(rem));
        match tls.read_application_data(buf) {
            Ok(n) => Ok(n),
            Err(Tls13Error::Io(e)) if e.kind() == io::ErrorKind::Interrupted => Ok(usize::MAX),
            Err(err) => Err(map_tls_error(err, post_write)),
        }
    })
}

fn read_smtp_reply_generic(
    deadline: &NotifyDeadlineCx,
    post_write: bool,
    mut read_fn: impl FnMut(&mut [u8], Duration) -> Result<usize, NotifyError>,
) -> Result<(u16, String), NotifyError> {
    const MAX_SMTP_REPLY: usize = 8192;
    let (mut raw, mut chunk) = (Vec::new(), [0_u8; 512]);
    loop {
        if let Some((code, text)) = try_parse_complete_smtp_reply(&raw)? {
            return Ok((code, text));
        }
        if raw.len() >= MAX_SMTP_REPLY {
            return Err(if post_write {
                NotifyError::indeterminate("SMTP reply exceeded 8 KiB")
            } else {
                NotifyError::pre_send(ERR_NOTIFY_TRANSPORT_001, "SMTP reply exceeded 8 KiB")
            });
        }
        let rem = deadline.remaining(post_write)?;
        let cap = (MAX_SMTP_REPLY - raw.len()).min(chunk.len());
        match read_fn(&mut chunk[..cap], rem)? {
            usize::MAX => {}
            0 => {
                return Err(if post_write {
                    NotifyError::indeterminate("SMTP EOF after DATA")
                } else {
                    NotifyError::pre_send(ERR_NOTIFY_TRANSPORT_001, "unexpected SMTP EOF")
                });
            }
            n => raw.extend_from_slice(&chunk[..n]),
        }
    }
}

fn try_parse_complete_smtp_reply(raw: &[u8]) -> Result<Option<(u16, String)>, NotifyError> {
    let (mut pos, mut lines, mut final_code) = (0, Vec::new(), None);
    while let Some(rel) = raw[pos..].windows(2).position(|w| w == b"\r\n") {
        let line = std::str::from_utf8(&raw[pos..pos + rel])
            .map_err(|_| NotifyError::indeterminate("non-UTF-8 SMTP reply"))?;
        pos += rel + 2;
        if line.len() < 3 || !line.as_bytes()[0..3].iter().all(u8::is_ascii_digit) {
            return Err(NotifyError::indeterminate("malformed SMTP reply code"));
        }
        let code: u16 = line[0..3]
            .parse()
            .map_err(|_| NotifyError::indeterminate("invalid SMTP code"))?;
        let sep = line.as_bytes().get(3).copied().unwrap_or(b' ');
        lines.push(line.to_owned());
        if sep == b' ' {
            final_code = Some(code);
            break;
        }
        if sep != b'-' {
            return Err(NotifyError::indeterminate("invalid SMTP separator"));
        }
    }
    Ok(final_code.map(|c| (c, lines.join("\n"))))
}

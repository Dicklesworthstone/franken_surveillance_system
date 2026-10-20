#![forbid(unsafe_code)]
//! Nonblocking local projection of already-durable native media windows.
//! One capture owner pumps a fixed amount of socket work between native polls.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};

use fss_cli::agent_json::{object, string};
use fss_core::ContentDigest;
use fss_reference::rtsp::preview::{
    PreviewAuthority, PreviewError, PreviewHub, PreviewMetadata, PreviewScope, SubscriberId,
};
use fss_reference::rtsp::recording::PreparedRecording;

use super::super::authentication::{Entropy, SecretError};
use super::super::plan::live_preview::{
    CLIENT_LEASE_NS, IO_BYTES, MAX_HEADER_BYTES, MAX_SUBSCRIPTIONS, PreviewPlan,
};

const PAGE: &[u8] = include_bytes!("preview/index.html");
const SCRIPT: &[u8] = include_bytes!("preview/preview.js");
const STYLE: &[u8] = include_bytes!("preview/preview.css");
const MAX_RESPONSE_BYTES: usize = 16 * 1024;

pub(super) trait GatewayAuthority: PreviewAuthority {
    fn now(&self) -> Result<u64, PreviewError>;
    fn secret(&self) -> Result<(), SecretError>;
}

enum Body {
    Bytes(Vec<u8>),
    Window {
        id: SubscriberId,
        sequence: u64,
        length: usize,
    },
}

struct Response {
    header: Vec<u8>,
    header_offset: usize,
    body: Body,
    offset: usize,
}

struct Client {
    socket: TcpStream,
    expires_at_ns: u64,
    request: Vec<u8>,
    response: Option<Response>,
}

pub(super) struct Gateway {
    listener: Option<TcpListener>,
    clients: Vec<Client>,
    hub: PreviewHub,
    scope: PreviewScope,
    plan: PreviewPlan,
    host: String,
    token: String,
    accepted: u64,
    read_bytes: u64,
    written_bytes: u64,
    dropped_clients: u64,
    last_refusal: Option<&'static str>,
}

impl Gateway {
    pub(super) fn open(
        plan: &PreviewPlan,
        scope: PreviewScope,
        authority: &impl GatewayAuthority,
    ) -> Result<Self, &'static str> {
        let now = authority.now().map_err(PreviewError::as_str)?;
        let hub = PreviewHub::new(scope.clone(), plan.limits, now, authority)
            .map_err(PreviewError::as_str)?;
        // This entropy owner has its own disclosure scope, never a camera credential lease.
        let check = || authority.secret();
        let mut entropy = Entropy::open(&check).map_err(|_| "preview_entropy_unavailable")?;
        let random = entropy
            .next(&check)
            .map_err(|_| "preview_entropy_unavailable")?;
        drop(entropy);
        let token: String = random.iter().map(|b| format!("{b:02x}")).collect();
        authority.now().map_err(PreviewError::as_str)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, plan.port))
            .map_err(|_| "preview_bind_refused")?;
        authority.now().map_err(PreviewError::as_str)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| "preview_nonblocking_refused")?;
        authority.now().map_err(PreviewError::as_str)?;
        let address = listener
            .local_addr()
            .map_err(|_| "preview_address_refused")?;
        authority.now().map_err(PreviewError::as_str)?;
        Ok(Self {
            listener: Some(listener),
            clients: Vec::new(),
            hub,
            scope,
            plan: plan.clone(),
            host: address.to_string(),
            token,
            accepted: 0,
            read_bytes: 0,
            written_bytes: 0,
            dropped_clients: 0,
            last_refusal: None,
        })
    }

    /// Only the operator sink receives this ephemeral disclosure capability.
    pub(super) fn operator_url(&self) -> String {
        format!("http://{}/#{}", self.host, self.token)
    }

    pub(super) fn stage(
        &mut self,
        recording: &PreparedRecording,
        authority: &impl GatewayAuthority,
    ) {
        let result = authority
            .now()
            .and_then(|now| self.hub.stage(recording, now, authority));
        if let Err(error) = result {
            self.refuse(error);
        }
    }

    pub(super) fn publish(&mut self, root: ContentDigest, authority: &impl GatewayAuthority) {
        let result = authority
            .now()
            .and_then(|now| self.hub.publish_durable(root, now, authority));
        if let Err(error) = result {
            self.refuse(error);
        }
    }

    fn refuse(&mut self, error: PreviewError) {
        self.last_refusal = Some(error.as_str());
        // Scope and authority failures invalidate every old window and subscriber.
        self.close();
    }

    pub(super) fn pump(&mut self, authority: &impl GatewayAuthority) {
        if self.listener.is_none() {
            return;
        }
        if let Err(error) = self.pump_inner(authority) {
            self.refuse(error);
        }
    }

    fn pump_inner(&mut self, authority: &impl GatewayAuthority) -> Result<(), PreviewError> {
        let now = authority.now()?;
        authority.checkpoint(&self.scope, now)?;
        // At most two accepts and one bounded read/write per client per native step.
        for _ in 0..2 {
            if self.clients.len() >= self.plan.limits.max_clients
                || self.accepted >= MAX_SUBSCRIPTIONS
            {
                break;
            }
            authority.now()?;
            let Some(listener) = &self.listener else {
                break;
            };
            let accepted = listener.accept();
            authority.now()?;
            match accepted {
                Ok((socket, peer)) => {
                    self.accepted += 1;
                    if !peer.ip().is_loopback() {
                        self.dropped_clients += 1;
                        continue;
                    }
                    authority.now()?;
                    let configured = socket.set_nonblocking(true);
                    authority.now()?;
                    if configured.is_err() {
                        self.dropped_clients += 1;
                        continue;
                    }
                    self.clients.push(Client {
                        socket,
                        expires_at_ns: now
                            .saturating_add(CLIENT_LEASE_NS)
                            .min(self.scope.expires_at_ns),
                        request: Vec::new(),
                        response: None,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => break,
                Err(_) => return Err(PreviewError::Closed),
            }
        }
        let mut index = 0;
        while index < self.clients.len() {
            // Temporarily remove the owner, never clone a socket or media allocation.
            let mut client = self.clients.swap_remove(index);
            let keep = self.client_step(&mut client, authority).unwrap_or(false);
            if keep {
                self.clients.insert(index, client);
                index += 1;
            } else {
                if let Some(Response {
                    body: Body::Window { id, .. },
                    ..
                }) = &client.response
                {
                    self.hub.disconnect(*id);
                }
                self.dropped_clients += 1;
            }
        }
        if self.written_bytes >= self.plan.limits.max_total_bytes
            || (self.accepted >= MAX_SUBSCRIPTIONS && self.clients.is_empty())
        {
            self.last_refusal = Some("preview_traffic_or_connection_budget");
            self.close();
        }
        Ok(())
    }

    fn client_step(
        &mut self,
        client: &mut Client,
        authority: &impl GatewayAuthority,
    ) -> Result<bool, PreviewError> {
        let now = authority.now()?;
        if now >= client.expires_at_ns {
            return Ok(false);
        }
        if client.response.is_none() {
            let remaining = MAX_HEADER_BYTES.saturating_sub(client.request.len());
            if remaining == 0 {
                return Ok(false);
            }
            let mut bytes = [0; MAX_HEADER_BYTES];
            authority.now()?;
            let received = client.socket.read(&mut bytes[..remaining]);
            if let Ok(count) = received {
                self.read_bytes = self.read_bytes.saturating_add(count as u64);
                client.request.extend_from_slice(&bytes[..count]);
            }
            let now = authority.now()?;
            match received {
                Ok(0) => return Ok(false),
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    return Ok(true);
                }
                Err(_) => return Ok(false),
            }
            if client.request.windows(4).any(|w| w == b"\r\n\r\n") {
                client.response =
                    Some(self.route(&client.request, client.expires_at_ns, now, authority));
                client.request.clear();
            }
            return Ok(true);
        }
        let remaining = self
            .plan
            .limits
            .max_total_bytes
            .saturating_sub(self.written_bytes);
        let quota = IO_BYTES.min(usize::try_from(remaining).unwrap_or(usize::MAX));
        if quota == 0 {
            return Ok(false);
        }
        let response = client.response.as_mut().ok_or(PreviewError::Closed)?;
        let now = authority.now()?;
        if now >= client.expires_at_ns {
            return Ok(false);
        }
        let (written, offered) = if response.header_offset < response.header.len() {
            let end = response.header.len().min(response.header_offset + quota);
            let result = client
                .socket
                .write(&response.header[response.header_offset..end]);
            if let Ok(count) = result {
                response.header_offset += count;
            }
            (result, false)
        } else {
            match &response.body {
                Body::Bytes(bytes) => {
                    if response.offset >= bytes.len() {
                        return Ok(false);
                    }
                    let end = bytes.len().min(response.offset + quota);
                    let result = client.socket.write(&bytes[response.offset..end]);
                    if let Ok(count) = result {
                        response.offset += count;
                    }
                    (result, false)
                }
                Body::Window {
                    id,
                    sequence,
                    length,
                } => {
                    if response.offset >= *length {
                        return Ok(false);
                    }
                    let chunk =
                        self.hub
                            .chunk(*id, *sequence, response.offset, quota, now, authority)?;
                    (client.socket.write(chunk), true)
                }
            }
        };
        // Actual bytes remain charged even if a post-write check is refused.
        if let Ok(count) = written {
            self.written_bytes = self.written_bytes.saturating_add(count as u64);
        }
        let observed_after = authority.now();
        let completed_at = observed_after.as_ref().copied().unwrap_or(now);
        if offered && let Body::Window { id, sequence, .. } = &response.body {
            match &written {
                Ok(count) => {
                    self.hub
                        .advance(*id, *sequence, *count, completed_at, authority)?;
                    response.offset += count;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    self.hub
                        .advance(*id, *sequence, 0, completed_at, authority)?;
                }
                Err(_) => {} // An uncertain output never refunds the outstanding offer.
            }
        }
        observed_after?;
        match written {
            Ok(0) => Ok(false),
            Ok(_) => Ok(true),
            Err(error) => Ok(matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            )),
        }
    }

    fn route(
        &mut self,
        request: &[u8],
        expires: u64,
        now: u64,
        authority: &impl GatewayAuthority,
    ) -> Response {
        let path = match parse_request(request, &self.host, &self.token) {
            Ok(path) => path,
            Err(status) => {
                return bytes_response(status, "text/plain; charset=utf-8", b"request refused\n");
            }
        };
        match path {
            "/" => bytes_response(200, "text/html; charset=utf-8", PAGE),
            "/preview.js" => bytes_response(200, "text/javascript; charset=utf-8", SCRIPT),
            "/preview.css" => bytes_response(200, "text/css; charset=utf-8", STYLE),
            "/api/manifest" => match self.hub.latest(now, authority) {
                Ok(latest) => {
                    let report = object(&[
                        ("schema", string("fss.live-preview.v1")),
                        (
                            "state",
                            string(if latest.is_some() { "ready" } else { "waiting" }),
                        ),
                        ("privacy", string("explicit-local-unredacted")),
                        ("capture_time", string("unknown")),
                        (
                            "latest",
                            latest.as_ref().map_or_else(|| "null".into(), metadata_json),
                        ),
                        ("status", self.report()),
                    ]);
                    bytes_response(200, "application/json", report.as_bytes())
                }
                Err(_) => bytes_response(410, "text/plain", b"preview unavailable\n"),
            },
            _ => {
                let selected = path
                    .strip_prefix("/api/window/")
                    .filter(|s| {
                        !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit())
                    })
                    .and_then(|s| s.parse::<u64>().ok());
                let Some(sequence) = selected else {
                    return bytes_response(404, "text/plain", b"unavailable\n");
                };
                let Ok(meta) = self.hub.metadata(sequence, now, authority) else {
                    return bytes_response(404, "text/plain", b"window unavailable\n");
                };
                let Ok(id) = self.hub.subscribe_at(sequence, expires, now, authority) else {
                    return bytes_response(429, "text/plain", b"viewer budget exhausted\n");
                };
                let extra = format!(
                    "X-FSS-Recording-Root: {}\r\nX-FSS-Window-Sequence: {}\r\n",
                    meta.root.to_text(),
                    sequence
                );
                Response {
                    header: headers(200, "video/mp4", meta.body_bytes(), &extra),
                    header_offset: 0,
                    body: Body::Window {
                        id,
                        sequence,
                        length: meta.body_bytes(),
                    },
                    offset: 0,
                }
            }
        }
    }

    pub(super) fn report(&self) -> String {
        let status = self.hub.status();
        object(&[
            ("enabled", "true".into()),
            ("listening", self.listener.is_some().to_string()),
            ("accepted_connections", self.accepted.to_string()),
            ("active_connections", self.clients.len().to_string()),
            ("closed_connections", self.dropped_clients.to_string()),
            ("received_bytes", self.read_bytes.to_string()),
            ("sent_bytes", self.written_bytes.to_string()),
            ("queued_fragments", status.queued_fragments.to_string()),
            ("queued_bytes", status.queued_bytes.to_string()),
            ("candidate_bytes", status.candidate_bytes.to_string()),
            ("published_windows", status.published.to_string()),
            ("skipped_windows", status.skipped.to_string()),
            ("evicted_windows", status.evicted.to_string()),
            ("payload_charged_bytes", status.charged_bytes.to_string()),
            ("payload_written_bytes", status.written_bytes.to_string()),
            (
                "last_refusal",
                self.last_refusal.map_or_else(|| "null".into(), string),
            ),
        ])
    }

    pub(super) fn close(&mut self) {
        self.listener = None;
        self.dropped_clients = self
            .dropped_clients
            .saturating_add(self.clients.len() as u64);
        self.clients.clear();
        self.hub.close();
        self.token.clear();
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.close();
    }
}

fn metadata_json(meta: &PreviewMetadata) -> String {
    object(&[
        ("sequence", meta.sequence.to_string()),
        ("root", string(&meta.root.to_text())),
        (
            "initialization_digest",
            string(&meta.initialization_digest.to_text()),
        ),
        ("media_digest", string(&meta.media_digest.to_text())),
        (
            "initialization_bytes",
            meta.initialization_bytes.to_string(),
        ),
        ("media_bytes", meta.media_bytes.to_string()),
        ("samples", meta.samples.to_string()),
        ("decode_start", meta.decode_interval.start.to_string()),
        ("decode_end", meta.decode_interval.end.to_string()),
        ("time_scale", meta.time_scale.to_string()),
        ("codec", string(meta.codec.as_str())),
        ("mime", string(&meta.mime)),
    ])
}

fn headers(status: u16, mime: &str, length: usize, extra: &str) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        410 => "Gone",
        429 => "Too Many Requests",
        _ => "Bad Request",
    };
    format!("HTTP/1.1 {status} {reason}\r\nContent-Type: {mime}\r\nContent-Length: {length}\r\n\
Connection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\
Referrer-Policy: no-referrer\r\nCross-Origin-Resource-Policy: same-origin\r\n\
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; media-src blob:; base-uri 'none'; frame-ancestors 'none'\r\n\
{extra}\r\n").into_bytes()
}

fn bytes_response(status: u16, mime: &str, bytes: &[u8]) -> Response {
    let bytes = if bytes.len() <= MAX_RESPONSE_BYTES {
        bytes
    } else {
        b"response bound exceeded\n"
    };
    Response {
        header: headers(status, mime, bytes.len(), ""),
        header_offset: 0,
        body: Body::Bytes(bytes.to_vec()),
        offset: 0,
    }
}

/// Reject duplicate headers, bodies, pipelining, rebinding and cross-site reads.
fn parse_request<'a>(bytes: &'a [u8], host: &str, token: &str) -> Result<&'a str, u16> {
    let text = std::str::from_utf8(bytes).map_err(|_| 400u16)?;
    if !text.ends_with("\r\n\r\n") || text[..text.len() - 4].contains("\r\n\r\n") {
        return Err(400);
    }
    let mut lines = text[..text.len() - 4].split("\r\n");
    let mut first = lines.next().ok_or(400u16)?.split(' ');
    if first.next() != Some("GET") {
        return Err(400);
    }
    let path = first.next().ok_or(400u16)?;
    if first.next() != Some("HTTP/1.1")
        || first.next().is_some()
        || !path.starts_with('/')
        || path.contains(['?', '#', '%'])
        || path.bytes().any(|b| b <= 0x20 || b == 0x7f)
    {
        return Err(400);
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut host_ok = false;
    let mut read_ok = false;
    let mut token_ok = false;
    for line in lines {
        if seen.len() >= 64 {
            return Err(400);
        }
        let (key, value) = line.split_once(':').ok_or(400u16)?;
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(400);
        }
        let key = key.to_ascii_lowercase();
        if !seen.insert(key.clone()) {
            return Err(400);
        }
        if value.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            return Err(400);
        }
        let value = value.trim_matches([' ', '\t']);
        match key.as_str() {
            "host" => host_ok = value == host,
            "origin" if value != format!("http://{host}") => return Err(403),
            "sec-fetch-site" if !matches!(value, "same-origin" | "none") => return Err(403),
            "x-fss-read" => read_ok = value == "1",
            "x-fss-preview" => token_ok = token_matches(value, token),
            "content-length" | "transfer-encoding" => return Err(400),
            _ => {}
        }
    }
    if !host_ok {
        return Err(403);
    }
    if path.starts_with("/api/") && (!read_ok || !token_ok) {
        return Err(403);
    }
    Ok(path)
}

fn token_matches(value: &str, expected: &str) -> bool {
    if value.len() != 32 || expected.len() != 32 {
        return false;
    }
    value
        .bytes()
        .zip(expected.bytes())
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[cfg(test)]
#[path = "preview/tests.rs"]
mod tests;

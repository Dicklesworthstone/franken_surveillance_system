#![forbid(unsafe_code)]
//! Sans-IO RTSP/1.0 message and interleaved-frame parser.
//!
//! Implements bounded, incremental wire-format parsing of RTSP/1.0 requests,
//! responses, headers, and interleaved binary frames (`$`). Performs zero I/O
//! and never handles or stores credentials.

use std::fmt;

/// Default maximum line length in bytes for start lines and header lines (4 KiB).
pub const DEFAULT_MAX_LINE_BYTES: usize = 4096;

/// Default maximum number of headers in one RTSP message (128).
pub const DEFAULT_MAX_HEADERS: usize = 128;

/// Default maximum body length in bytes (1 MiB).
pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;

/// Default maximum interleaved binary payload length in bytes (64 KiB).
pub const DEFAULT_MAX_INTERLEAVED_BYTES: usize = 65536;

/// Hard limits for bounded RTSP parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtspLimits {
    /// Maximum line length for start lines and headers.
    pub max_line_bytes: usize,
    /// Maximum number of headers per message.
    pub max_headers: usize,
    /// Maximum body payload length in bytes.
    pub max_body_bytes: usize,
    /// Maximum interleaved frame payload length in bytes.
    pub max_interleaved_bytes: usize,
}

impl Default for RtspLimits {
    fn default() -> Self {
        Self {
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
            max_headers: DEFAULT_MAX_HEADERS,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_interleaved_bytes: DEFAULT_MAX_INTERLEAVED_BYTES,
        }
    }
}

/// Typed error returned when RTSP wire parsing fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RtspError {
    /// Start line (request or status line) is malformed or invalid.
    MalformedStartLine(String),
    /// A header line or total header count exceeded configured limits.
    HeaderLimit(String),
    /// Content-Length header is missing, negative, non-numeric, or invalid.
    BadContentLength(String),
    /// Body length exceeded configured maximum limit.
    BodyLimit(String),
    /// Transport header format or parameters are malformed.
    BadTransport(String),
    /// Interleaved frame payload length exceeded configured limit.
    BadInterleavedLength(String),
    /// Base64 decoding failed.
    BadBase64(String),
    /// Method is recognized by RTSP specification but unsupported by this parser.
    Unsupported {
        /// The unsupported RTSP method name.
        method: String,
    },
    /// Input bytes are not valid UTF-8 where text is expected.
    Utf8(String),
}

impl fmt::Display for RtspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedStartLine(msg) => write!(f, "malformed start line: {msg}"),
            Self::HeaderLimit(msg) => write!(f, "header limit exceeded: {msg}"),
            Self::BadContentLength(msg) => write!(f, "bad Content-Length header: {msg}"),
            Self::BodyLimit(msg) => write!(f, "body limit exceeded: {msg}"),
            Self::BadTransport(msg) => write!(f, "bad Transport header: {msg}"),
            Self::BadInterleavedLength(msg) => write!(f, "bad interleaved length: {msg}"),
            Self::BadBase64(msg) => write!(f, "bad base64: {msg}"),
            Self::Unsupported { method } => write!(f, "unsupported RTSP method: {method}"),
            Self::Utf8(msg) => write!(f, "invalid UTF-8: {msg}"),
        }
    }
}

impl std::error::Error for RtspError {}

/// Standard RTSP 1.0 method supported by the parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RtspMethod {
    /// Query server capabilities.
    Options,
    /// Retrieve presentation or media description (typically SDP).
    Describe,
    /// Allocate transport mechanism for a media stream.
    Setup,
    /// Start data transmission on one or all streams.
    Play,
    /// Temporarily halt stream delivery.
    Pause,
    /// Stop stream delivery and release associated resources.
    Teardown,
    /// Retrieve parameter values or keep session alive.
    GetParameter,
}

impl RtspMethod {
    /// Return the canonical uppercase string representation of this method.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Options => "OPTIONS",
            Self::Describe => "DESCRIBE",
            Self::Setup => "SETUP",
            Self::Play => "PLAY",
            Self::Pause => "PAUSE",
            Self::Teardown => "TEARDOWN",
            Self::GetParameter => "GET_PARAMETER",
        }
    }

    /// Parse an RTSP method token.
    ///
    /// Returns `Ok(RtspMethod)` for supported methods.
    /// Returns `Err(RtspError::Unsupported { method })` for standard but unsupported methods
    /// (ANNOUNCE, RECORD, REDIRECT, SET_PARAMETER).
    /// Returns `Err(RtspError::MalformedStartLine)` for unknown method tokens.
    pub fn parse_token(token: &str) -> Result<Self, RtspError> {
        match token {
            "OPTIONS" => Ok(Self::Options),
            "DESCRIBE" => Ok(Self::Describe),
            "SETUP" => Ok(Self::Setup),
            "PLAY" => Ok(Self::Play),
            "PAUSE" => Ok(Self::Pause),
            "TEARDOWN" => Ok(Self::Teardown),
            "GET_PARAMETER" => Ok(Self::GetParameter),
            "ANNOUNCE" | "RECORD" | "REDIRECT" | "SET_PARAMETER" => Err(RtspError::Unsupported {
                method: token.to_string(),
            }),
            _ => Err(RtspError::MalformedStartLine(format!(
                "unrecognized RTSP method token '{token}'"
            ))),
        }
    }
}

/// A parsed single header field name/value pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtspHeader {
    /// Canonical or verbatim header name.
    pub name: String,
    /// Trimmed header value string.
    pub value: String,
}

/// Collection of headers with case-insensitive name matching.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RtspHeaders {
    raw: Vec<RtspHeader>,
}

impl RtspHeaders {
    /// Create a new empty header collection.
    pub fn new() -> Self {
        Self { raw: Vec::new() }
    }

    /// Add a header name and value to the collection.
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.raw.push(RtspHeader {
            name: name.into(),
            value: value.into(),
        });
    }

    /// Retrieve the first header value matching `name` case-insensitively.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.raw
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    /// Number of headers in the collection.
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    /// Whether the collection contains no headers.
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// Iterator over all header name/value pairs.
    pub fn iter(&self) -> impl Iterator<Item = &RtspHeader> {
        self.raw.iter()
    }

    /// Parse the `CSeq` sequence number header if present.
    pub fn cseq(&self) -> Option<Result<u32, RtspError>> {
        self.get("CSeq").map(|v| {
            v.trim().parse::<u32>().map_err(|_| {
                RtspError::MalformedStartLine(format!("invalid CSeq integer value '{v}'"))
            })
        })
    }

    /// Parse the `Content-Length` header if present.
    pub fn content_length(&self) -> Option<Result<usize, RtspError>> {
        self.get("Content-Length").map(|v| {
            let trimmed = v.trim();
            if trimmed.is_empty() || trimmed.starts_with('-') || trimmed.starts_with('+') {
                return Err(RtspError::BadContentLength(format!(
                    "invalid Content-Length format '{v}'"
                )));
            }
            trimmed.parse::<usize>().map_err(|_| {
                RtspError::BadContentLength(format!("invalid Content-Length integer '{v}'"))
            })
        })
    }

    /// Retrieve the `Content-Type` header value if present.
    pub fn content_type(&self) -> Option<&str> {
        self.get("Content-Type")
    }

    /// Retrieve the raw `Session` header identifier (before any `;timeout=`).
    pub fn session_id(&self) -> Option<&str> {
        self.get("Session")
            .map(|v| v.split(';').next().map(str::trim).unwrap_or(""))
    }

    /// Parse timeout in seconds from the `Session` header if present (e.g. `timeout=60`).
    pub fn session_timeout(&self) -> Option<u64> {
        let val = self.get("Session")?;
        for param in val.split(';') {
            let param = param.trim();
            if let Some(rest) = param.strip_prefix("timeout=")
                && let Ok(secs) = rest.trim().parse::<u64>()
            {
                return Some(secs);
            }
        }
        None
    }

    /// Parse the `Transport` header into typed representation if present.
    pub fn transport(&self) -> Option<Result<RtspTransport, RtspError>> {
        self.get("Transport").map(RtspTransport::parse)
    }

    /// Retrieve the `Range` header value if present.
    pub fn range(&self) -> Option<&str> {
        self.get("Range")
    }

    /// Retrieve the `RTP-Info` header value if present.
    pub fn rtp_info(&self) -> Option<&str> {
        self.get("RTP-Info")
    }

    /// Retrieve the `Public` allowed methods header value if present.
    pub fn public(&self) -> Option<&str> {
        self.get("Public")
    }

    /// Extract authentication scheme from `WWW-Authenticate` header (e.g. "Digest" or "Basic").
    ///
    /// Challenge parameters (realm, nonce, etc.) are NOT retained (AGENTS.md security boundary).
    pub fn www_authenticate_scheme(&self) -> Option<String> {
        let val = self.get("WWW-Authenticate")?.trim();
        if val.is_empty() {
            return None;
        }
        let scheme = val.split_whitespace().next().unwrap_or(val);
        Some(scheme.to_string())
    }
}

/// Parsed RTSP `Transport` header parameters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtspTransport {
    /// Transport profile, e.g. "RTP/AVP/TCP" or "RTP/AVP".
    pub profile: String,
    /// Unicast delivery mode.
    pub unicast: bool,
    /// TCP interleaved channel range: `(rtp_channel, rtcp_channel)`.
    pub interleaved: Option<(u8, u8)>,
    /// UDP client port range: `(rtp_port, rtcp_port)`.
    pub client_port: Option<(u16, u16)>,
    /// UDP server port range: `(rtp_port, rtcp_port)`.
    pub server_port: Option<(u16, u16)>,
    /// Optional mode directive, e.g. "PLAY" or "RECORD".
    pub mode: Option<String>,
}

impl RtspTransport {
    /// Parse a `Transport` header string into structured representation.
    pub fn parse(input: &str) -> Result<Self, RtspError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(RtspError::BadTransport(
                "empty Transport header".to_string(),
            ));
        }

        let mut parts = trimmed.split(';');
        let profile = match parts.next() {
            Some(p) if !p.trim().is_empty() => p.trim().to_string(),
            _ => {
                return Err(RtspError::BadTransport(
                    "missing transport profile".to_string(),
                ));
            }
        };

        let mut unicast = false;
        let mut interleaved = None;
        let mut client_port = None;
        let mut server_port = None;
        let mut mode = None;

        for part in parts {
            let part = part.trim();
            if part.eq_ignore_ascii_case("unicast") {
                unicast = true;
            } else if part.eq_ignore_ascii_case("multicast") {
                unicast = false;
            } else if let Some(val) = part.strip_prefix("interleaved=") {
                interleaved = Some(Self::parse_u8_range(val)?);
            } else if let Some(val) = part.strip_prefix("client_port=") {
                client_port = Some(Self::parse_u16_range(val)?);
            } else if let Some(val) = part.strip_prefix("server_port=") {
                server_port = Some(Self::parse_u16_range(val)?);
            } else if let Some(val) = part.strip_prefix("mode=") {
                mode = Some(val.trim_matches('"').to_string());
            }
        }

        Ok(Self {
            profile,
            unicast,
            interleaved,
            client_port,
            server_port,
            mode,
        })
    }

    fn parse_u8_range(val: &str) -> Result<(u8, u8), RtspError> {
        let val = val.trim();
        if let Some((first, second)) = val.split_once('-') {
            let a = first.trim().parse::<u8>().map_err(|_| {
                RtspError::BadTransport(format!("invalid interleaved channel '{first}'"))
            })?;
            let b = second.trim().parse::<u8>().map_err(|_| {
                RtspError::BadTransport(format!("invalid interleaved channel '{second}'"))
            })?;
            Ok((a, b))
        } else {
            let a = val.parse::<u8>().map_err(|_| {
                RtspError::BadTransport(format!("invalid interleaved channel '{val}'"))
            })?;
            let b = a.saturating_add(1);
            Ok((a, b))
        }
    }

    fn parse_u16_range(val: &str) -> Result<(u16, u16), RtspError> {
        let val = val.trim();
        if let Some((first, second)) = val.split_once('-') {
            let a = first
                .trim()
                .parse::<u16>()
                .map_err(|_| RtspError::BadTransport(format!("invalid port '{first}'")))?;
            let b = second
                .trim()
                .parse::<u16>()
                .map_err(|_| RtspError::BadTransport(format!("invalid port '{second}'")))?;
            Ok((a, b))
        } else {
            let a = val
                .parse::<u16>()
                .map_err(|_| RtspError::BadTransport(format!("invalid port '{val}'")))?;
            let b = a.saturating_add(1);
            Ok((a, b))
        }
    }
}

/// Parsed RTSP/1.0 request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtspRequest {
    /// RTSP request method.
    pub method: RtspMethod,
    /// Request URI (e.g. `rtsp://127.0.0.1:8554/live`).
    pub uri: String,
    /// RTSP protocol version string, typically `"RTSP/1.0"`.
    pub version: String,
    /// Request headers.
    pub headers: RtspHeaders,
    /// Request body payload bytes.
    pub body: Vec<u8>,
}

/// Parsed RTSP/1.0 response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtspResponse {
    /// RTSP protocol version string, typically `"RTSP/1.0"`.
    pub version: String,
    /// Numeric HTTP/RTSP status code (e.g. 200, 401, 404).
    pub status_code: u16,
    /// Reason phrase string (e.g. "OK", "Unauthorized").
    pub reason: String,
    /// Response headers.
    pub headers: RtspHeaders,
    /// Response body payload bytes.
    pub body: Vec<u8>,
}

/// Events produced by the sans-IO RTSP parser across incoming byte chunks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RtspEvent {
    /// Complete RTSP request received.
    Request(RtspRequest),
    /// Complete RTSP response received.
    Response(RtspResponse),
    /// 401 Unauthorized response received with WWW-Authenticate header.
    ///
    /// The scheme (e.g. "Digest" or "Basic") is provided.
    /// Challenge parameters (realm, nonce, qop) are discarded (security boundary).
    AuthRequired {
        /// Authentication scheme (e.g. "Digest" or "Basic").
        scheme: String,
    },
    /// Interleaved binary frame (`$` prefix) carrying media or control data.
    Interleaved {
        /// Channel index (e.g. 0 for RTP, 1 for RTCP).
        channel: u8,
        /// Frame payload byte span.
        span: Vec<u8>,
    },
}

/// Sans-IO incremental RTSP/1.0 message and interleaved-frame parser.
#[derive(Clone, Debug)]
pub struct RtspParser {
    buffer: Vec<u8>,
    limits: RtspLimits,
}

impl Default for RtspParser {
    fn default() -> Self {
        Self::new()
    }
}

impl RtspParser {
    /// Create a new incremental RTSP parser with default operational limits.
    pub fn new() -> Self {
        Self::with_limits(RtspLimits::default())
    }

    /// Create a new incremental RTSP parser with explicit operational limits.
    pub fn with_limits(limits: RtspLimits) -> Self {
        Self {
            buffer: Vec::new(),
            limits,
        }
    }

    /// Returns the number of unconsumed bytes currently held in the internal buffer.
    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }

    /// Feed an arbitrary chunk of incoming wire bytes into the sans-IO parser.
    ///
    /// Yields zero, one, or multiple complete `RtspEvent` items that were assembled
    /// from the accumulated byte stream.
    pub fn feed(&mut self, incoming: &[u8]) -> Result<Vec<RtspEvent>, RtspError> {
        self.buffer.extend_from_slice(incoming);
        let mut events = Vec::new();

        loop {
            // Trim leading CRLF / whitespace outside of framing
            self.trim_leading_crlf();
            if self.buffer.is_empty() {
                break;
            }

            // Case 1: Interleaved binary frame starting with '$' (0x24)
            if self.buffer[0] == b'$' {
                if self.buffer.len() < 4 {
                    // Need at least 4 bytes: '$', channel (1), length (2)
                    break;
                }
                let channel = self.buffer[1];
                let payload_len = u16::from_be_bytes([self.buffer[2], self.buffer[3]]) as usize;

                if payload_len > self.limits.max_interleaved_bytes {
                    return Err(RtspError::BadInterleavedLength(format!(
                        "interleaved length {payload_len} exceeds limit {}",
                        self.limits.max_interleaved_bytes
                    )));
                }

                let total_frame_len = 4 + payload_len;
                if self.buffer.len() < total_frame_len {
                    // Incomplete frame, await more bytes
                    break;
                }

                let span = self.buffer[4..total_frame_len].to_vec();
                self.buffer.drain(..total_frame_len);
                events.push(RtspEvent::Interleaved { channel, span });
                continue;
            }

            // Case 2: Text RTSP message (Request or Response)
            let header_boundary = match self.find_header_boundary() {
                Some(boundary) => boundary,
                None => {
                    // Check if headers exceed maximum allowable size without terminator
                    let max_header_block = self
                        .limits
                        .max_line_bytes
                        .saturating_mul(self.limits.max_headers);
                    if self.buffer.len() > max_header_block {
                        return Err(RtspError::HeaderLimit(
                            "header block exceeded maximum capacity without terminator".to_string(),
                        ));
                    }
                    // Await more data
                    break;
                }
            };

            let header_bytes = &self.buffer[..header_boundary.start_of_body];
            let header_text = match std::str::from_utf8(header_bytes) {
                Ok(text) => text,
                Err(err) => {
                    return Err(RtspError::Utf8(format!(
                        "invalid UTF-8 in message headers: {err}"
                    )));
                }
            };

            let (start_line_str, headers) = self.parse_headers(header_text)?;
            let start_line = start_line_str.to_string();

            // Determine body length from Content-Length header
            let content_len = match headers.content_length() {
                Some(Ok(len)) => {
                    if len > self.limits.max_body_bytes {
                        return Err(RtspError::BodyLimit(format!(
                            "Content-Length {len} exceeds limit {}",
                            self.limits.max_body_bytes
                        )));
                    }
                    len
                }
                Some(Err(err)) => return Err(err),
                None => 0,
            };

            let total_msg_len = header_boundary.start_of_body + content_len;
            if self.buffer.len() < total_msg_len {
                // Incomplete body, await more data
                break;
            }

            let body = self.buffer[header_boundary.start_of_body..total_msg_len].to_vec();
            self.buffer.drain(..total_msg_len);

            // Classify as request or response
            let event = self.build_event(&start_line, headers, body)?;
            events.push(event);
        }

        Ok(events)
    }

    fn trim_leading_crlf(&mut self) {
        let mut trim_len = 0;
        for &b in &self.buffer {
            if b == b'\r' || b == b'\n' {
                trim_len += 1;
            } else {
                break;
            }
        }
        if trim_len > 0 {
            self.buffer.drain(..trim_len);
        }
    }

    fn find_header_boundary(&self) -> Option<HeaderBoundary> {
        let len = self.buffer.len();
        if len < 4 {
            // Check for \n\n if len >= 2
            if len >= 2 {
                for i in 0..len - 1 {
                    if self.buffer[i] == b'\n' && self.buffer[i + 1] == b'\n' {
                        return Some(HeaderBoundary {
                            start_of_body: i + 2,
                        });
                    }
                }
            }
            return None;
        }

        for i in 0..len - 3 {
            if self.buffer[i] == b'\r'
                && self.buffer[i + 1] == b'\n'
                && self.buffer[i + 2] == b'\r'
                && self.buffer[i + 3] == b'\n'
            {
                return Some(HeaderBoundary {
                    start_of_body: i + 4,
                });
            }
            if self.buffer[i] == b'\n' && self.buffer[i + 1] == b'\n' {
                return Some(HeaderBoundary {
                    start_of_body: i + 2,
                });
            }
        }

        // Check tail for \n\n
        if self.buffer[len - 2] == b'\n' && self.buffer[len - 1] == b'\n' {
            return Some(HeaderBoundary { start_of_body: len });
        }

        None
    }

    fn parse_headers<'a>(&self, header_text: &'a str) -> Result<(&'a str, RtspHeaders), RtspError> {
        let mut lines = header_text.split('\n');
        let start_line = match lines.next() {
            Some(line) => line.trim_end_matches('\r').trim(),
            None => {
                return Err(RtspError::MalformedStartLine(
                    "empty message without start line".to_string(),
                ));
            }
        };

        if start_line.is_empty() {
            return Err(RtspError::MalformedStartLine(
                "empty start line".to_string(),
            ));
        }

        if start_line.len() > self.limits.max_line_bytes {
            return Err(RtspError::HeaderLimit(format!(
                "start line length {} exceeds limit {}",
                start_line.len(),
                self.limits.max_line_bytes
            )));
        }

        let mut headers = RtspHeaders::new();
        for raw_line in lines {
            let line = raw_line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }
            if line.len() > self.limits.max_line_bytes {
                return Err(RtspError::HeaderLimit(format!(
                    "header line length {} exceeds limit {}",
                    line.len(),
                    self.limits.max_line_bytes
                )));
            }
            if headers.len() >= self.limits.max_headers {
                return Err(RtspError::HeaderLimit(format!(
                    "header count exceeded limit {}",
                    self.limits.max_headers
                )));
            }

            if let Some((name, val)) = line.split_once(':') {
                let name = name.trim();
                let val = val.trim();
                if name.is_empty() {
                    return Err(RtspError::MalformedStartLine(
                        "header missing field name".to_string(),
                    ));
                }
                headers.insert(name, val);
            } else {
                return Err(RtspError::MalformedStartLine(format!(
                    "header line missing colon separator: '{line}'"
                )));
            }
        }

        Ok((start_line, headers))
    }

    fn build_event(
        &self,
        start_line: &str,
        headers: RtspHeaders,
        body: Vec<u8>,
    ) -> Result<RtspEvent, RtspError> {
        if start_line.starts_with("RTSP/") {
            // Status line: RTSP/1.0 <status_code> <reason>
            let mut parts = start_line.split_whitespace();
            let version = parts.next().unwrap_or("").to_string();
            let status_token = parts.next().ok_or_else(|| {
                RtspError::MalformedStartLine("missing status code in status line".to_string())
            })?;
            let status_code = status_token.parse::<u16>().map_err(|_| {
                RtspError::MalformedStartLine(format!(
                    "invalid status code integer '{status_token}'"
                ))
            })?;
            let reason = parts.collect::<Vec<_>>().join(" ");

            // Check for 401 Unauthorized with WWW-Authenticate header
            if status_code == 401
                && let Some(scheme) = headers.www_authenticate_scheme()
            {
                return Ok(RtspEvent::AuthRequired { scheme });
            }

            Ok(RtspEvent::Response(RtspResponse {
                version,
                status_code,
                reason,
                headers,
                body,
            }))
        } else {
            // Request line: <METHOD> <URI> <VERSION>
            let mut parts = start_line.split_whitespace();
            let method_token = parts.next().ok_or_else(|| {
                RtspError::MalformedStartLine("missing method in request line".to_string())
            })?;
            let uri = parts.next().ok_or_else(|| {
                RtspError::MalformedStartLine("missing URI in request line".to_string())
            })?;
            let version = parts.next().ok_or_else(|| {
                RtspError::MalformedStartLine("missing version in request line".to_string())
            })?;

            if !version.starts_with("RTSP/") {
                return Err(RtspError::MalformedStartLine(format!(
                    "invalid protocol version '{version}'"
                )));
            }

            let method = RtspMethod::parse_token(method_token)?;

            Ok(RtspEvent::Request(RtspRequest {
                method,
                uri: uri.to_string(),
                version: version.to_string(),
                headers,
                body,
            }))
        }
    }
}

struct HeaderBoundary {
    start_of_body: usize,
}

#![forbid(unsafe_code)]
//! Sans-IO RTSP/1.0 message and interleaved-frame parser.
//!
//! Implements bounded, incremental wire-format parsing of RTSP/1.0 requests,
//! responses, headers, and interleaved binary frames (`$`). Performs zero I/O
//! and never handles or stores credentials.
//!
//! Every [`RtspError`] carries only a typed reason plus byte offsets or lengths.
//! No error value ever carries input text or tokens, so an error can be logged
//! or displayed without echoing credential material that arrived on the wire.

use std::fmt;
use std::num::{IntErrorKind, ParseIntError};

/// Redaction marker substituted for sensitive authentication header values.
pub const REDACTED_CREDENTIAL: &str = "[REDACTED]";

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

/// Why a numeric header value (`CSeq`, `Content-Length`) was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum NumericFault {
    /// The value is empty.
    Empty,
    /// The value carries an explicit sign (`+` or `-`).
    Signed,
    /// The value contains a byte that is not a decimal digit.
    NotAnInteger,
    /// The value does not fit the target integer type.
    Overflow,
}

impl NumericFault {
    fn from_parse(err: &ParseIntError) -> Self {
        match err.kind() {
            IntErrorKind::Empty => Self::Empty,
            IntErrorKind::PosOverflow | IntErrorKind::NegOverflow => Self::Overflow,
            _ => Self::NotAnInteger,
        }
    }
}

/// A refused numeric header value: a typed reason plus the raw value length in bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct HeaderValueFault {
    /// Why the value was refused.
    pub kind: NumericFault,
    /// Length in bytes of the raw (untrimmed) header value.
    pub value_len: usize,
}

/// A declared length that exceeded a configured limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct LengthLimit {
    /// Length declared on the wire, in bytes.
    pub declared: usize,
    /// Configured maximum, in bytes.
    pub limit: usize,
}

/// Why a start line (or a header line that cannot be a header) was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum StartLineFault {
    /// The start line is empty.
    Empty,
    /// The request line has no method token.
    MissingMethod,
    /// The request line has no URI token.
    MissingUri,
    /// The request line has no version token.
    MissingVersion,
    /// The status line has no status-code token.
    MissingStatusCode,
    /// The status-code token is not a decimal `u16`.
    InvalidStatusCode {
        /// Length in bytes of the refused token.
        token_len: usize,
    },
    /// The method token is not an RTSP/1.0 method.
    UnknownMethod {
        /// Length in bytes of the refused token.
        token_len: usize,
    },
    /// A header line has an empty field name.
    HeaderMissingName {
        /// Byte offset of the header line within the message.
        offset: usize,
    },
    /// A header line has no `:` separator.
    HeaderMissingColon {
        /// Byte offset of the header line within the message.
        offset: usize,
    },
}

/// Which header bound was exceeded.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum HeaderLimitFault {
    /// The start line is longer than `max_line_bytes`.
    StartLineTooLong {
        /// Start-line length in bytes.
        len: usize,
        /// Configured maximum, in bytes.
        limit: usize,
    },
    /// A header line is longer than `max_line_bytes`.
    HeaderLineTooLong {
        /// Byte offset of the header line within the message.
        offset: usize,
        /// Header-line length in bytes.
        len: usize,
        /// Configured maximum, in bytes.
        limit: usize,
    },
    /// The message has more than `max_headers` headers.
    TooManyHeaders {
        /// Byte offset of the first header line beyond the limit.
        offset: usize,
        /// Configured maximum header count.
        limit: usize,
    },
    /// More than `max_line_bytes * max_headers` bytes arrived without a header terminator.
    UnterminatedHeaderBlock {
        /// Bytes buffered when the bound was hit.
        buffered: usize,
        /// Configured maximum header-block size, in bytes.
        limit: usize,
    },
}

/// Two `Content-Length` headers in one message declared different lengths.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ContentLengthConflict {
    /// Length declared by the first `Content-Length` header.
    pub first: usize,
    /// Length declared by the conflicting `Content-Length` header.
    pub second: usize,
    /// Byte offset of the conflicting header line within the message.
    pub offset: usize,
}

/// A header that may appear only once appeared again.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DuplicateHeader {
    /// Byte offset of the duplicate header line within the message.
    pub offset: usize,
}

/// Why a `Transport` header was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TransportFault {
    /// The header value is empty.
    Empty,
    /// A transport specification has no profile.
    MissingProfile,
    /// An `interleaved=` channel is not a decimal `u8`.
    InvalidChannel {
        /// Length in bytes of the refused token.
        value_len: usize,
    },
    /// An `interleaved=a-b` range has `a > b`.
    ReversedChannelRange,
    /// `interleaved=255` leaves no companion RTCP channel.
    ChannelWithoutCompanion,
    /// A `client_port=` or `server_port=` port is not a decimal `u16`.
    InvalidPort {
        /// Length in bytes of the refused token.
        value_len: usize,
    },
    /// A port range `a-b` has `a > b`.
    ReversedPortRange,
    /// Port 65535 leaves no companion RTCP port.
    PortWithoutCompanion,
}

/// Whether a message is a request or a response.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum MessageKind {
    /// A request (`METHOD URI RTSP/1.0`).
    Request,
    /// A response (`RTSP/1.0 NNN reason`).
    Response,
}

/// A protocol version other than `RTSP/1.0`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct VersionFault {
    /// Which kind of start line carried the version.
    pub kind: MessageKind,
    /// Length in bytes of the refused version token.
    pub token_len: usize,
}

/// Where URI userinfo (`user:password@`) was found and refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum UserinfoSite {
    /// The request-line URI.
    RequestUri,
    /// The `Content-Base` header.
    ContentBase,
    /// The `Content-Location` header.
    ContentLocation,
    /// The `Location` header.
    Location,
    /// A `url=` parameter of the `RTP-Info` header.
    RtpInfo {
        /// Zero-based index of the `url=` parameter within the header value.
        entry: usize,
    },
}

/// Where a NUL byte was found and refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum NulSite {
    /// The start line.
    StartLine,
    /// A header line.
    HeaderLine {
        /// Byte offset of the header line within the message.
        offset: usize,
    },
    /// The request-line URI.
    Uri,
}

/// Position of an invalid UTF-8 sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Utf8Fault {
    /// Byte offset up to which the input was valid UTF-8.
    pub valid_up_to: usize,
    /// Length of the invalid sequence, or `None` if the input ended mid-sequence.
    pub error_len: Option<usize>,
}

impl Utf8Fault {
    pub(crate) fn from_utf8_error(err: &std::str::Utf8Error) -> Self {
        Self {
            valid_up_to: err.valid_up_to(),
            error_len: err.error_len(),
        }
    }
}

/// RTSP methods that are recognized but deliberately not supported by this parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum UnsupportedMethod {
    /// `ANNOUNCE`.
    Announce,
    /// `RECORD`.
    Record,
    /// `REDIRECT`.
    Redirect,
    /// `SET_PARAMETER`.
    SetParameter,
}

impl UnsupportedMethod {
    /// Return the canonical uppercase method name.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Announce => "ANNOUNCE",
            Self::Record => "RECORD",
            Self::Redirect => "REDIRECT",
            Self::SetParameter => "SET_PARAMETER",
        }
    }
}

/// Why the parser lost message framing and refuses all input until [`RtspParser::reset`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PoisonCause {
    /// The header block was not valid UTF-8, so its `Content-Length` cannot be trusted.
    InvalidUtf8Headers,
    /// `Content-Length` was unparsable, signed, overflowing, folded, or conflicting.
    AmbiguousContentLength,
    /// `Content-Length` declared a body above `max_body_bytes`.
    BodyLimit,
    /// The header block exceeded its bound without a terminator.
    UnterminatedHeaderBlock,
}

/// Authentication scheme named by a `WWW-Authenticate` or `Proxy-Authenticate` challenge.
///
/// Holds no raw token: the scheme is classified and every challenge parameter
/// (realm, nonce, opaque, and any token68) is discarded.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AuthScheme {
    /// RFC 7617 `Basic`.
    Basic,
    /// RFC 7616 `Digest`.
    Digest,
    /// Any other syntactically valid scheme token (not retained).
    Other,
}

impl AuthScheme {
    fn from_token(token: &str) -> Self {
        if token.eq_ignore_ascii_case("basic") {
            Self::Basic
        } else if token.eq_ignore_ascii_case("digest") {
            Self::Digest
        } else {
            Self::Other
        }
    }
}

/// Typed error returned when RTSP wire parsing fails.
///
/// Every variant carries only a typed reason plus byte offsets or lengths; never input text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RtspError {
    /// Start line (request or status line) is malformed or invalid.
    MalformedStartLine(StartLineFault),
    /// A header line or total header count exceeded configured limits.
    HeaderLimit(HeaderLimitFault),
    /// Content-Length header is empty, signed, non-numeric, or overflowing.
    BadContentLength(HeaderValueFault),
    /// Conflicting duplicate Content-Length headers were received.
    DuplicateContentLength(ContentLengthConflict),
    /// Body length exceeded configured maximum limit.
    BodyLimit(LengthLimit),
    /// Transport header format or parameters are malformed.
    BadTransport(TransportFault),
    /// Interleaved frame payload length exceeded configured limit.
    BadInterleavedLength(LengthLimit),
    /// Mandatory CSeq header is missing.
    MissingCSeq,
    /// CSeq header value is malformed or non-numeric.
    BadCSeq(HeaderValueFault),
    /// Duplicate CSeq header was received.
    DuplicateCSeq(DuplicateHeader),
    /// Unsupported protocol version (only RTSP/1.0 is supported).
    UnsupportedVersion(VersionFault),
    /// A URI carries forbidden userinfo credentials.
    UserinfoNotPermitted(UserinfoSite),
    /// Input contains forbidden NUL byte.
    NulByte(NulSite),
    /// Obsolete line folding (continuation line starting with whitespace) is not permitted.
    LineFoldingNotPermitted,
    /// Method is recognized by RTSP specification but unsupported by this parser.
    Unsupported {
        /// The unsupported RTSP method.
        method: UnsupportedMethod,
    },
    /// Header bytes are not valid UTF-8.
    Utf8(Utf8Fault),
    /// Framing was lost earlier; the parser refuses all input until [`RtspParser::reset`].
    Poisoned(PoisonCause),
}

impl fmt::Display for RtspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedStartLine(fault) => write!(f, "malformed start line: {fault:?}"),
            Self::HeaderLimit(fault) => write!(f, "header limit exceeded: {fault:?}"),
            Self::BadContentLength(fault) => write!(f, "bad Content-Length header: {fault:?}"),
            Self::DuplicateContentLength(conflict) => {
                write!(f, "conflicting duplicate Content-Length: {conflict:?}")
            }
            Self::BodyLimit(limit) => write!(f, "body limit exceeded: {limit:?}"),
            Self::BadTransport(fault) => write!(f, "bad Transport header: {fault:?}"),
            Self::BadInterleavedLength(limit) => write!(f, "bad interleaved length: {limit:?}"),
            Self::MissingCSeq => write!(f, "missing mandatory CSeq header"),
            Self::BadCSeq(fault) => write!(f, "bad CSeq header: {fault:?}"),
            Self::DuplicateCSeq(dup) => write!(f, "duplicate CSeq header: {dup:?}"),
            Self::UnsupportedVersion(fault) => write!(f, "unsupported protocol version: {fault:?}"),
            Self::UserinfoNotPermitted(site) => {
                write!(f, "userinfo in URI not permitted: {site:?}")
            }
            Self::NulByte(site) => write!(f, "NUL byte not permitted: {site:?}"),
            Self::LineFoldingNotPermitted => write!(f, "obsolete line folding not permitted"),
            Self::Unsupported { method } => {
                write!(f, "unsupported RTSP method: {}", method.as_str())
            }
            Self::Utf8(fault) => write!(f, "invalid UTF-8 in message headers: {fault:?}"),
            Self::Poisoned(cause) => write!(f, "parser poisoned until reset: {cause:?}"),
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
    /// Returns `Err(RtspError::MalformedStartLine(StartLineFault::UnknownMethod { .. }))` for
    /// unknown method tokens; the token itself is never retained.
    pub fn parse_token(token: &str) -> Result<Self, RtspError> {
        let unsupported = |method: UnsupportedMethod| -> Result<Self, RtspError> {
            Err(RtspError::Unsupported { method })
        };
        match token {
            "OPTIONS" => Ok(Self::Options),
            "DESCRIBE" => Ok(Self::Describe),
            "SETUP" => Ok(Self::Setup),
            "PLAY" => Ok(Self::Play),
            "PAUSE" => Ok(Self::Pause),
            "TEARDOWN" => Ok(Self::Teardown),
            "GET_PARAMETER" => Ok(Self::GetParameter),
            "ANNOUNCE" => unsupported(UnsupportedMethod::Announce),
            "RECORD" => unsupported(UnsupportedMethod::Record),
            "REDIRECT" => unsupported(UnsupportedMethod::Redirect),
            "SET_PARAMETER" => unsupported(UnsupportedMethod::SetParameter),
            _ => Err(RtspError::MalformedStartLine(
                StartLineFault::UnknownMethod {
                    token_len: token.len(),
                },
            )),
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
        self.get("CSeq").map(parse_cseq)
    }

    /// Parse the `Content-Length` header if present.
    pub fn content_length(&self) -> Option<Result<usize, RtspError>> {
        self.get("Content-Length")
            .map(|v| parse_content_length(v).map_err(RtspError::BadContentLength))
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

    /// Classify the authentication scheme of a `WWW-Authenticate` header in this collection.
    ///
    /// Challenge parameters (realm, nonce, etc.) are NOT retained (AGENTS.md security boundary).
    /// The parser itself never stores `WWW-Authenticate`, so this only sees headers that a
    /// caller inserted directly.
    pub fn www_authenticate_scheme(&self) -> Option<AuthScheme> {
        let val = self.get("WWW-Authenticate")?;
        extract_auth_scheme(val)
    }
}

fn parse_cseq(value: &str) -> Result<u32, RtspError> {
    value.trim().parse::<u32>().map_err(|err| {
        RtspError::BadCSeq(HeaderValueFault {
            kind: NumericFault::from_parse(&err),
            value_len: value.len(),
        })
    })
}

fn parse_content_length(value: &str) -> Result<usize, HeaderValueFault> {
    let trimmed = value.trim();
    let fault = |kind: NumericFault| HeaderValueFault {
        kind,
        value_len: value.len(),
    };
    if trimmed.is_empty() {
        return Err(fault(NumericFault::Empty));
    }
    if trimmed.starts_with('-') || trimmed.starts_with('+') {
        return Err(fault(NumericFault::Signed));
    }
    trimmed
        .parse::<usize>()
        .map_err(|err| fault(NumericFault::from_parse(&err)))
}

/// Classify the authentication scheme token of a challenge header value.
///
/// Returns `None` when the first token is not a valid RFC 7235 scheme token.
/// The token itself is never returned: `Basic` and `Digest` are recognized
/// case-insensitively and every other valid token becomes [`AuthScheme::Other`].
pub fn extract_auth_scheme(header_val: &str) -> Option<AuthScheme> {
    let trimmed = header_val.trim();
    if trimmed.is_empty() {
        return None;
    }
    let first_token = trimmed.split_whitespace().next()?;
    let candidate = first_token.trim_end_matches(',').trim_end_matches(';');
    if candidate.is_empty()
        || candidate.contains('=')
        || candidate.contains('"')
        || candidate.contains(',')
    {
        return None;
    }
    let is_valid = candidate.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '!' | '#'
                    | '$'
                    | '%'
                    | '&'
                    | '\''
                    | '*'
                    | '+'
                    | '-'
                    | '.'
                    | '^'
                    | '_'
                    | '`'
                    | '|'
                    | '~'
            )
    });
    if is_valid {
        Some(AuthScheme::from_token(candidate))
    } else {
        None
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
            return Err(RtspError::BadTransport(TransportFault::Empty));
        }

        for alt in trimmed.split(',') {
            let alt = alt.trim();
            if alt.is_empty() {
                continue;
            }
            if let Ok(transport) = Self::parse_single_spec(alt) {
                return Ok(transport);
            }
        }

        let first = trimmed.split(',').next().unwrap_or(trimmed).trim();
        Self::parse_single_spec(first)
    }

    fn parse_single_spec(input: &str) -> Result<Self, RtspError> {
        let mut parts = input.split(';');
        let profile = match parts.next() {
            Some(p) if !p.trim().is_empty() => p.trim().to_string(),
            _ => {
                return Err(RtspError::BadTransport(TransportFault::MissingProfile));
            }
        };

        let mut unicast = false;
        let mut interleaved = None;
        let mut client_port = None;
        let mut server_port = None;
        let mut mode = None;

        for part in parts {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if part.eq_ignore_ascii_case("unicast") {
                unicast = true;
            } else if part.eq_ignore_ascii_case("multicast") {
                unicast = false;
            } else if let Some((k, v)) = part.split_once('=') {
                let k = k.trim();
                let v = v.trim();
                if k.eq_ignore_ascii_case("interleaved") {
                    interleaved = Some(Self::parse_u8_range(v)?);
                } else if k.eq_ignore_ascii_case("client_port") {
                    client_port = Some(Self::parse_u16_range(v)?);
                } else if k.eq_ignore_ascii_case("server_port") {
                    server_port = Some(Self::parse_u16_range(v)?);
                } else if k.eq_ignore_ascii_case("mode") {
                    mode = Some(v.trim_matches('"').to_string());
                }
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
        let channel = |token: &str| {
            token.trim().parse::<u8>().map_err(|_| {
                RtspError::BadTransport(TransportFault::InvalidChannel {
                    value_len: token.len(),
                })
            })
        };
        if let Some((first, second)) = val.split_once('-') {
            let a = channel(first)?;
            let b = channel(second)?;
            if a > b {
                return Err(RtspError::BadTransport(
                    TransportFault::ReversedChannelRange,
                ));
            }
            Ok((a, b))
        } else {
            let a = channel(val)?;
            if a == 255 {
                return Err(RtspError::BadTransport(
                    TransportFault::ChannelWithoutCompanion,
                ));
            }
            let b = a + 1;
            Ok((a, b))
        }
    }

    fn parse_u16_range(val: &str) -> Result<(u16, u16), RtspError> {
        let val = val.trim();
        let port = |token: &str| {
            token.trim().parse::<u16>().map_err(|_| {
                RtspError::BadTransport(TransportFault::InvalidPort {
                    value_len: token.len(),
                })
            })
        };
        if let Some((first, second)) = val.split_once('-') {
            let a = port(first)?;
            let b = port(second)?;
            if a > b {
                return Err(RtspError::BadTransport(TransportFault::ReversedPortRange));
            }
            Ok((a, b))
        } else {
            let a = port(val)?;
            if a == 65535 {
                return Err(RtspError::BadTransport(
                    TransportFault::PortWithoutCompanion,
                ));
            }
            let b = a + 1;
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
    /// Response headers (challenge headers are never stored).
    pub headers: RtspHeaders,
    /// Response body payload bytes.
    pub body: Vec<u8>,
    /// Typed marker for an authentication challenge presented on the response.
    pub auth_challenge: Option<AuthScheme>,
}

/// Events produced by the sans-IO RTSP parser across incoming byte chunks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RtspEvent {
    /// Complete RTSP request received.
    Request(RtspRequest),
    /// Complete RTSP response received.
    Response(RtspResponse),
    /// 401 or 407 response carrying a `WWW-Authenticate` or `Proxy-Authenticate` challenge.
    ///
    /// Only the typed scheme is surfaced; challenge parameters (realm, nonce, qop) are
    /// discarded (security boundary). The complete response (status, CSeq, Session and
    /// body) is kept; its `auth_challenge` equals `Some(scheme)`.
    AuthRequired {
        /// Typed authentication scheme.
        scheme: AuthScheme,
        /// The challenged response.
        response: RtspResponse,
    },
    /// Interleaved binary frame (`$` prefix) carrying media or control data.
    Interleaved {
        /// Channel index (e.g. 0 for RTP, 1 for RTCP).
        channel: u8,
        /// Frame payload byte span.
        span: Vec<u8>,
    },
}

/// Content-Length as declared by a header block that failed to parse.
enum DeclaredBody {
    /// No Content-Length header: the message has no body.
    Absent,
    /// Exactly one valid length (repeated identical headers allowed).
    Exact(usize),
    /// Unparsable, signed, overflowing, folded, or conflicting lengths.
    Ambiguous,
}

/// Sans-IO incremental RTSP/1.0 message and interleaved-frame parser.
#[derive(Clone, Debug)]
pub struct RtspParser {
    buffer: Vec<u8>,
    limits: RtspLimits,
    pending_error: Option<RtspError>,
    discard_body_remaining: usize,
    poisoned: Option<PoisonCause>,
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
            pending_error: None,
            discard_body_remaining: 0,
            poisoned: None,
        }
    }

    /// Reset parser state: clear buffered data, pending errors, discard counters and poison.
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.pending_error = None;
        self.discard_body_remaining = 0;
        self.poisoned = None;
    }

    /// Returns the number of unconsumed bytes currently held in the internal buffer.
    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }

    /// Returns why the parser is poisoned, or `None` while it still has message framing.
    pub fn poisoned(&self) -> Option<PoisonCause> {
        self.poisoned
    }

    fn declared_body_length(header_text: &str) -> DeclaredBody {
        let mut declared: Option<usize> = None;
        let mut previous_was_content_length = false;
        for raw_line in header_text.split('\n').skip(1) {
            let line = raw_line.trim_end_matches('\r');
            let folded = line.starts_with([' ', '\t']);
            // A continuation line after Content-Length: a peer that honours obsolete folding
            // reads a different length, so no single valid length exists.
            if folded && previous_was_content_length {
                return DeclaredBody::Ambiguous;
            }
            let content_length_value = line.split_once(':').and_then(|(name, value)| {
                name.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then_some(value)
            });
            previous_was_content_length = content_length_value.is_some();
            let Some(value) = content_length_value else {
                continue;
            };
            if folded {
                return DeclaredBody::Ambiguous;
            }
            let Ok(len) = parse_content_length(value) else {
                return DeclaredBody::Ambiguous;
            };
            match declared {
                Some(prev) if prev != len => return DeclaredBody::Ambiguous,
                _ => declared = Some(len),
            }
        }
        declared.map_or(DeclaredBody::Absent, DeclaredBody::Exact)
    }

    fn discard_message_with_declared_body(&mut self, header_end: usize, declared_body: usize) {
        let total = header_end.saturating_add(declared_body);
        if self.buffer.len() >= total {
            self.buffer.drain(..total);
            self.discard_body_remaining = 0;
        } else {
            let available = self.buffer.len();
            self.discard_body_remaining = total.saturating_sub(available);
            self.buffer.clear();
        }
    }

    fn recover_from_header_error(&mut self, header_end: usize, declared: DeclaredBody) {
        match declared {
            DeclaredBody::Absent => self.discard_message_with_declared_body(header_end, 0),
            DeclaredBody::Exact(len) if len <= self.limits.max_body_bytes => {
                self.discard_message_with_declared_body(header_end, len);
            }
            DeclaredBody::Exact(_) => self.poison(PoisonCause::BodyLimit),
            DeclaredBody::Ambiguous => self.poison(PoisonCause::AmbiguousContentLength),
        }
    }

    fn poison(&mut self, cause: PoisonCause) {
        self.buffer.clear();
        self.discard_body_remaining = 0;
        self.poisoned = Some(cause);
    }

    fn fail(
        &mut self,
        events: Vec<RtspEvent>,
        err: RtspError,
    ) -> Result<Vec<RtspEvent>, RtspError> {
        if !events.is_empty() {
            self.pending_error = Some(err);
            return Ok(events);
        }
        Err(err)
    }

    /// Feed an arbitrary chunk of incoming wire bytes into the sans-IO parser.
    ///
    /// Yields zero, one, or multiple complete `RtspEvent` items that were assembled
    /// from the accumulated byte stream. If an error occurs after one or more events
    /// have already been assembled, the events are returned first and the error is
    /// surfaced on the subsequent call. Incoming bytes are appended to the buffer
    /// first so that surfacing a pending error does not discard newly fed chunks
    /// (unless the parser is poisoned, see below).
    ///
    /// # Buffer state after each error kind
    ///
    /// Message-level errors are raised after the complete message (headers and
    /// `Content-Length` body) was framed and drained. The buffer holds exactly the
    /// bytes that follow the refused message and parsing resumes with them:
    /// `MalformedStartLine` (start-line faults), `UnsupportedVersion`, `Unsupported`,
    /// `MissingCSeq`, `BadCSeq`, `BadTransport`, `UserinfoNotPermitted` on the request
    /// URI, and `NulByte` on the URI.
    ///
    /// Header-level errors are raised while parsing the header block: `HeaderLimit`
    /// (line length or header count), `NulByte`, `LineFoldingNotPermitted`,
    /// `DuplicateCSeq`, `MalformedStartLine` (header without name or colon), and
    /// `UserinfoNotPermitted` on a header. The header block is drained and, when the
    /// block declares exactly one valid `Content-Length` within `max_body_bytes`,
    /// exactly that many body bytes are discarded as well, across later feeds if
    /// they have not arrived yet. Parsing then resumes with the next message. When no
    /// single valid length exists (unparsable, signed, overflowing, folded, followed
    /// by a folded continuation line, or conflicting `Content-Length`), or the declared length is above
    /// `max_body_bytes`, the parser is poisoned instead.
    ///
    /// Framing errors leave no trustworthy message boundary. The buffer is cleared
    /// and the parser is poisoned: `Utf8` (header block is not UTF-8),
    /// `BadContentLength`, `DuplicateContentLength`, `BodyLimit`, and
    /// `HeaderLimit(UnterminatedHeaderBlock)`.
    ///
    /// `BadInterleavedLength`: the frame declares a single valid 16-bit length, so
    /// exactly the 4-byte prefix plus that payload are discarded (across later feeds
    /// if needed) and parsing resumes after the frame.
    ///
    /// Poisoned: every later call discards its input, surfaces any pending error
    /// once, and then returns `Poisoned(cause)` until [`RtspParser::reset`]. A
    /// poisoned parser never yields events, so bytes that followed a lost boundary
    /// can never be parsed as a message.
    pub fn feed(&mut self, incoming: &[u8]) -> Result<Vec<RtspEvent>, RtspError> {
        if let Some(cause) = self.poisoned {
            if let Some(err) = self.pending_error.take() {
                return Err(err);
            }
            return Err(RtspError::Poisoned(cause));
        }
        self.buffer.extend_from_slice(incoming);
        if let Some(err) = self.pending_error.take() {
            return Err(err);
        }

        if self.discard_body_remaining > 0 {
            let to_discard = self.buffer.len().min(self.discard_body_remaining);
            self.buffer.drain(..to_discard);
            self.discard_body_remaining -= to_discard;
            if self.discard_body_remaining > 0 {
                return Ok(Vec::new());
            }
        }

        let mut events = Vec::new();

        loop {
            // Trim leading CRLF outside of framing
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
                    // The frame declares one valid length: discard exactly this frame.
                    self.discard_message_with_declared_body(4, payload_len);
                    let err = RtspError::BadInterleavedLength(LengthLimit {
                        declared: payload_len,
                        limit: self.limits.max_interleaved_bytes,
                    });
                    return self.fail(events, err);
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
                    let max_header_block = self
                        .limits
                        .max_line_bytes
                        .saturating_mul(self.limits.max_headers);
                    if self.buffer.len() > max_header_block {
                        let buffered = self.buffer.len();
                        self.poison(PoisonCause::UnterminatedHeaderBlock);
                        let err =
                            RtspError::HeaderLimit(HeaderLimitFault::UnterminatedHeaderBlock {
                                buffered,
                                limit: max_header_block,
                            });
                        return self.fail(events, err);
                    }
                    // Await more data
                    break;
                }
            };

            let header_bytes = &self.buffer[..header_boundary.start_of_body];
            let header_text = match std::str::from_utf8(header_bytes) {
                Ok(text) => text,
                Err(utf8_err) => {
                    let err = RtspError::Utf8(Utf8Fault::from_utf8_error(&utf8_err));
                    self.poison(PoisonCause::InvalidUtf8Headers);
                    return self.fail(events, err);
                }
            };

            let (start_line_str, headers, auth_scheme) = match self.parse_headers(header_text) {
                Ok(res) => res,
                Err(err) => {
                    let declared_body = Self::declared_body_length(header_text);
                    self.recover_from_header_error(header_boundary.start_of_body, declared_body);
                    return self.fail(events, err);
                }
            };
            let start_line = start_line_str.to_string();

            // Determine body length from Content-Length header
            let content_len = match headers.content_length() {
                Some(Ok(len)) => {
                    if len > self.limits.max_body_bytes {
                        self.poison(PoisonCause::BodyLimit);
                        let err = RtspError::BodyLimit(LengthLimit {
                            declared: len,
                            limit: self.limits.max_body_bytes,
                        });
                        return self.fail(events, err);
                    }
                    len
                }
                Some(Err(err)) => {
                    self.poison(PoisonCause::AmbiguousContentLength);
                    return self.fail(events, err);
                }
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
            let event = match self.build_event(&start_line, headers, auth_scheme, body) {
                Ok(ev) => ev,
                Err(err) => return self.fail(events, err),
            };
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
        if len < 2 {
            return None;
        }

        let mut i = 0;
        while i < len {
            if i + 3 < len
                && self.buffer[i] == b'\r'
                && self.buffer[i + 1] == b'\n'
                && self.buffer[i + 2] == b'\r'
                && self.buffer[i + 3] == b'\n'
            {
                return Some(HeaderBoundary {
                    start_of_body: i + 4,
                });
            }
            if i + 1 < len && self.buffer[i] == b'\n' && self.buffer[i + 1] == b'\n' {
                return Some(HeaderBoundary {
                    start_of_body: i + 2,
                });
            }
            i += 1;
        }

        None
    }

    fn parse_headers<'a>(
        &self,
        header_text: &'a str,
    ) -> Result<(&'a str, RtspHeaders, Option<AuthScheme>), RtspError> {
        let mut lines = header_text.split('\n');
        let raw_start_line = lines.next().unwrap_or("");
        let start_line = raw_start_line.trim_end_matches('\r').trim();

        if start_line.is_empty() {
            return Err(RtspError::MalformedStartLine(StartLineFault::Empty));
        }

        if start_line.contains('\0') {
            return Err(RtspError::NulByte(NulSite::StartLine));
        }

        if start_line.len() > self.limits.max_line_bytes {
            return Err(RtspError::HeaderLimit(HeaderLimitFault::StartLineTooLong {
                len: start_line.len(),
                limit: self.limits.max_line_bytes,
            }));
        }

        let mut headers = RtspHeaders::new();
        let mut seen_cseq = false;
        let mut seen_content_length: Option<usize> = None;
        let mut auth_scheme: Option<AuthScheme> = None;
        let mut next_offset = raw_start_line.len() + 1;

        for raw_line in lines {
            let offset = next_offset;
            next_offset = next_offset.saturating_add(raw_line.len() + 1);
            let line = raw_line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }

            if line.contains('\0') {
                return Err(RtspError::NulByte(NulSite::HeaderLine { offset }));
            }

            if line.len() > self.limits.max_line_bytes {
                return Err(RtspError::HeaderLimit(
                    HeaderLimitFault::HeaderLineTooLong {
                        offset,
                        len: line.len(),
                        limit: self.limits.max_line_bytes,
                    },
                ));
            }

            // Line folding check: obsolete line folding is not permitted (RFC 7230 deprecates it)
            if line.starts_with(' ') || line.starts_with('\t') {
                return Err(RtspError::LineFoldingNotPermitted);
            }

            if headers.len() >= self.limits.max_headers {
                return Err(RtspError::HeaderLimit(HeaderLimitFault::TooManyHeaders {
                    offset,
                    limit: self.limits.max_headers,
                }));
            }

            let Some((name, val)) = line.split_once(':') else {
                return Err(RtspError::MalformedStartLine(
                    StartLineFault::HeaderMissingColon { offset },
                ));
            };
            let name = name.trim();
            let val = val.trim();
            if name.is_empty() {
                return Err(RtspError::MalformedStartLine(
                    StartLineFault::HeaderMissingName { offset },
                ));
            }

            // Check duplicate CSeq
            if name.eq_ignore_ascii_case("cseq") {
                if seen_cseq {
                    return Err(RtspError::DuplicateCSeq(DuplicateHeader { offset }));
                }
                seen_cseq = true;
            }

            // Check duplicate and conflicting Content-Length
            if name.eq_ignore_ascii_case("content-length") {
                let parsed_len = parse_content_length(val).map_err(RtspError::BadContentLength)?;
                match seen_content_length {
                    Some(prev_len) if prev_len != parsed_len => {
                        return Err(RtspError::DuplicateContentLength(ContentLengthConflict {
                            first: prev_len,
                            second: parsed_len,
                            offset,
                        }));
                    }
                    _ => seen_content_length = Some(parsed_len),
                }
            }

            // Never retain credential material in headers (AGENTS.md security boundary)
            if name.eq_ignore_ascii_case("authorization")
                || name.eq_ignore_ascii_case("proxy-authorization")
            {
                headers.insert(name, REDACTED_CREDENTIAL);
                continue;
            }

            // WWW-Authenticate and Proxy-Authenticate: classify the scheme, discard all
            // parameters, never keep in headers
            if name.eq_ignore_ascii_case("www-authenticate")
                || name.eq_ignore_ascii_case("proxy-authenticate")
            {
                if auth_scheme.is_none() {
                    auth_scheme = extract_auth_scheme(val);
                }
                continue;
            }

            // Forbid userinfo in every URI-bearing header
            if let Some(site) = uri_header_site(name)
                && has_userinfo(val)
            {
                return Err(RtspError::UserinfoNotPermitted(site));
            }
            if name.eq_ignore_ascii_case("rtp-info")
                && let Some(entry) = rtp_info_userinfo_entry(val)
            {
                return Err(RtspError::UserinfoNotPermitted(UserinfoSite::RtpInfo {
                    entry,
                }));
            }

            headers.insert(name, val);
        }

        Ok((start_line, headers, auth_scheme))
    }

    fn build_event(
        &self,
        start_line: &str,
        headers: RtspHeaders,
        auth_scheme: Option<AuthScheme>,
        body: Vec<u8>,
    ) -> Result<RtspEvent, RtspError> {
        if start_line.starts_with("RTSP/") {
            // Status line: RTSP/1.0 <status_code> <reason>
            let mut parts = start_line.split_whitespace();
            let version = parts.next().unwrap_or("");
            if version != "RTSP/1.0" {
                return Err(RtspError::UnsupportedVersion(VersionFault {
                    kind: MessageKind::Response,
                    token_len: version.len(),
                }));
            }

            let status_token = parts.next().ok_or(RtspError::MalformedStartLine(
                StartLineFault::MissingStatusCode,
            ))?;
            let status_code = status_token.parse::<u16>().map_err(|_| {
                RtspError::MalformedStartLine(StartLineFault::InvalidStatusCode {
                    token_len: status_token.len(),
                })
            })?;
            let reason = parts.collect::<Vec<_>>().join(" ");

            // Mandatory CSeq validation
            let cseq_raw = headers.get("CSeq").ok_or(RtspError::MissingCSeq)?;
            parse_cseq(cseq_raw)?;
            validate_transport(&headers)?;

            let response = RtspResponse {
                version: version.to_string(),
                status_code,
                reason,
                headers,
                body,
                auth_challenge: auth_scheme,
            };
            if (status_code == 401 || status_code == 407)
                && let Some(scheme) = auth_scheme
            {
                return Ok(RtspEvent::AuthRequired { scheme, response });
            }
            Ok(RtspEvent::Response(response))
        } else {
            // Request line: <METHOD> <URI> <VERSION>
            let mut parts = start_line.split_whitespace();
            let method_token = parts
                .next()
                .ok_or(RtspError::MalformedStartLine(StartLineFault::MissingMethod))?;
            let uri = parts
                .next()
                .ok_or(RtspError::MalformedStartLine(StartLineFault::MissingUri))?;
            let version = parts.next().ok_or(RtspError::MalformedStartLine(
                StartLineFault::MissingVersion,
            ))?;

            if version != "RTSP/1.0" {
                return Err(RtspError::UnsupportedVersion(VersionFault {
                    kind: MessageKind::Request,
                    token_len: version.len(),
                }));
            }

            // URI security checks: NUL bytes and userinfo
            if uri.contains('\0') {
                return Err(RtspError::NulByte(NulSite::Uri));
            }
            if has_userinfo(uri) {
                return Err(RtspError::UserinfoNotPermitted(UserinfoSite::RequestUri));
            }

            let method = RtspMethod::parse_token(method_token)?;

            // Mandatory CSeq validation
            let cseq_raw = headers.get("CSeq").ok_or(RtspError::MissingCSeq)?;
            parse_cseq(cseq_raw)?;
            validate_transport(&headers)?;

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

/// A `Transport` header that is present must parse, so its raw value never reaches an
/// event unvalidated.
fn validate_transport(headers: &RtspHeaders) -> Result<(), RtspError> {
    match headers.transport() {
        Some(Err(err)) => Err(err),
        _ => Ok(()),
    }
}

/// Headers whose whole value is a URI and must never carry userinfo.
fn uri_header_site(name: &str) -> Option<UserinfoSite> {
    if name.eq_ignore_ascii_case("content-base") {
        Some(UserinfoSite::ContentBase)
    } else if name.eq_ignore_ascii_case("content-location") {
        Some(UserinfoSite::ContentLocation)
    } else if name.eq_ignore_ascii_case("location") {
        Some(UserinfoSite::Location)
    } else {
        None
    }
}

/// Index of the first `url=` parameter of an `RTP-Info` value that carries userinfo.
///
/// Every `url=` occurrence is checked up to the next `;`, so a comma inside a URL cannot
/// hide userinfo from the scan.
fn rtp_info_userinfo_entry(value: &str) -> Option<usize> {
    let lower = value.to_ascii_lowercase();
    let mut entry = 0;
    let mut search_from = 0;
    while let Some(found) = lower[search_from..].find("url=") {
        let start = search_from + found + 4;
        let rest = &value[start..];
        let url = rest
            .split(';')
            .next()
            .unwrap_or(rest)
            .trim()
            .trim_matches('"');
        if has_userinfo(url) {
            return Some(entry);
        }
        entry += 1;
        search_from = start;
    }
    None
}

/// Whether a URI (absolute `scheme://` or network-path `//`) carries userinfo in its authority.
pub(crate) fn has_userinfo(uri: &str) -> bool {
    let s = uri.split('#').next().unwrap_or(uri);
    let s = s.split('?').next().unwrap_or(s);
    if let Some(pos) = s.find("://") {
        let after_scheme = &s[pos + 3..];
        let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
        authority.contains('@')
    } else if let Some(after_slashes) = s.strip_prefix("//") {
        let authority = after_slashes.split('/').next().unwrap_or(after_slashes);
        authority.contains('@')
    } else {
        false
    }
}

struct HeaderBoundary {
    start_of_body: usize,
}

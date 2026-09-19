#![forbid(unsafe_code)]
//! Bounded HTTP/1 response framing for an already authorized MJPEG GET.
//! Consumes supplied plaintext bytes only; no socket, authentication or clock.

mod fields;
use crate::stream::StreamBasis;
use crate::{DecodeBudget, DecodeError};
use fss_core::ContentDigest;

/// Framing declared by a successful GET response, not inferred from JPEG bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyFraming {
    /// Exact declared entity length.
    Length(u64),
    /// HTTP/1.1 chunked coding, without additional transfer codings.
    Chunked,
    /// No explicit length; only owner-reported EOF terminates the body.
    UntilEof,
}
/// Narrowable work and storage limits for one response generation.
#[derive(Clone, Copy, Debug)]
pub struct HttpLimits {
    /// Header/trailer block bound each, 4..=32768 bytes.
    pub header_bytes: usize,
    /// Body bytes returned per event, 1..=65536.
    pub fragment_bytes: usize,
    /// Largest declared chunk, 1..=16 MiB.
    pub chunk_bytes: u64,
    /// Entire entity budget, 1..=1 TiB; rotate the owner session at its limit.
    pub entity_bytes: u64,
    /// Entire wire-response budget, 1..=4 TiB, including all framing overhead.
    pub wire_bytes: u64,
    /// Maximum nonzero chunks, 1..=one million.
    pub chunks: u64,
}
impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            header_bytes: 32768,
            fragment_bytes: 16384,
            chunk_bytes: 16 * 1024 * 1024,
            entity_bytes: 1 << 40,
            wire_bytes: 1 << 42,
            chunks: 1_000_000,
        }
    }
}
/// Non-disclosing terminal failures. No retry resumes a failed parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpError {
    /// Invalid owner basis or limit configuration.
    Configuration,
    /// Invalid status/header/chunk syntax, conflicting lengths or forbidden trailers.
    Malformed,
    /// Unsupported protocol version, coding, interim response or representation.
    Unsupported,
    /// Final response is not 200; redirects and authentication are never followed.
    Status(u16),
    /// Bytes were repeated, skipped or reordered.
    Offset,
    /// A declared count, allocation or full-stream ceiling was exceeded.
    Limit,
    /// EOF before explicit framing completed.
    Truncated,
    /// Owner already finished this response, or its body is complete.
    Closed,
    /// An earlier error latched.
    Poisoned,
    /// Shared caller work or cancellation failure.
    Work(DecodeError),
}
impl From<DecodeError> for HttpError {
    fn from(e: DecodeError) -> Self {
        Self::Work(e)
    }
}
impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Configuration => "invalid HTTP response configuration",
            Self::Malformed => "malformed HTTP response framing",
            Self::Unsupported => "unsupported HTTP response",
            Self::Status(_) => "HTTP response status is not admitted",
            Self::Offset => "HTTP response offset mismatch",
            Self::Limit => "HTTP response limit",
            Self::Truncated => "incomplete HTTP response",
            Self::Closed => "HTTP response closed",
            Self::Poisoned => "HTTP response has a prior failure",
            Self::Work(_) => "HTTP response work interrupted",
        })
    }
}
impl std::error::Error for HttpError {}
/// Exact accepted prefix on failure; an unconsumed suffix remains caller-owned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpFailure {
    /// Cause of this call's failure.
    pub error: HttpError,
    /// Accepted bytes of this call, including a malformed buffered suffix.
    pub consumed: usize,
    /// Next absolute plaintext-wire offset.
    pub next_offset: u64,
}
impl std::fmt::Display for HttpFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.error, f)
    }
}
impl std::error::Error for HttpFailure {}
/// Original response bytes. Debug never prints header values, cookies or pixels.
pub struct WireSpan {
    start: u64,
    bytes: Vec<u8>,
}
impl WireSpan {
    /// Half-open absolute plaintext-wire range, not TCP/TLS packet offsets.
    pub fn range(&self) -> [u64; 2] {
        [self.start, self.start + self.bytes.len() as u64]
    }
    /// Exact bytes for authorized custody; this object does not itself persist them.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl std::fmt::Debug for WireSpan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireSpan")
            .field("range", &self.range())
            .finish_non_exhaustive()
    }
}
/// Frozen source relationship after the complete response header passes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpHeadIdentity {
    /// Original response stream identity, resolved by its owner.
    pub wire: StreamBasis,
    /// Derived dechunked-entity identity, distinct from the plaintext response.
    pub entity: StreamBasis,
    /// Complete raw response header digest.
    pub header_sha256: [u8; 32],
    /// Exact declared framing; does not imply the body is already complete.
    pub framing: BodyFraming,
}
/// Complete admitted header, retained verbatim without executing metadata.
pub struct ResponseHead {
    identity: HttpHeadIdentity,
    raw: WireSpan,
    content_type: std::ops::Range<usize>,
}
impl ResponseHead {
    /// Frozen basis and declared transfer framing.
    pub fn identity(&self) -> HttpHeadIdentity {
        self.identity
    }
    /// Content-Type value with only surrounding HTTP OWS removed.
    pub fn content_type(&self) -> &str {
        // Construction validates this exact range as ASCII; no lossy conversion.
        std::str::from_utf8(&self.raw.bytes[self.content_type.clone()]).unwrap_or("")
    }
    /// Raw status line and complete headers, including final CRLF.
    pub fn raw(&self) -> &WireSpan {
        &self.raw
    }
}
impl std::fmt::Debug for ResponseHead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseHead")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}
/// A direct, byte-identical transfer-decoding map, not a source authentication proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntityMapping {
    /// Complete response-header/source binding.
    pub head: HttpHeadIdentity,
    /// Absolute plaintext-response range contributing these bytes.
    pub wire_range: [u64; 2],
    /// Half-open corresponding range in the dechunked entity, beginning at zero.
    pub entity_range: [u64; 2],
    /// One-based chunk ordinal, or None for identity transfer.
    pub chunk: Option<u64>,
    /// SHA-256 of these exact unchanged bytes, not of the whole response.
    pub sha256: [u8; 32],
}
/// One entity fragment; later invalid framing cannot create whole-response success.
#[derive(Debug)]
pub struct EntityData {
    mapping: EntityMapping,
    raw: WireSpan,
}
impl EntityData {
    /// Exact wire/entity correspondence, including chunk identity.
    pub fn mapping(&self) -> EntityMapping {
        self.mapping
    }
    /// Bytes ready for the existing multipart parser, still source-owned here.
    pub fn bytes(&self) -> &[u8] {
        self.raw.bytes()
    }
    /// Original plaintext-response bytes with their wire range.
    pub fn raw(&self) -> &WireSpan {
        &self.raw
    }
}
/// Transfer overhead is retained separately, never mixed into JPEG bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlKind {
    /// Chunk size and bounded uninterpreted extensions; zero denotes final chunk.
    ChunkHeader {
        /// Monotonic chunk sequence in transfer order, starting at one.
        ordinal: u64,
        /// Declared chunk-data byte count; zero only on the terminal header.
        length: u64,
    },
    /// Mandatory CRLF after a nonzero chunk's data.
    ChunkEnd,
    /// Complete bounded trailer block; no trailer overwrites header semantics.
    Trailers,
}
/// Source-preserving transfer-overhead record.
#[derive(Debug)]
pub struct HttpControl {
    /// Kind of transfer bytes consumed.
    pub kind: ControlKind,
    /// Exact original bytes, not interpreted vendor times or credentials.
    pub raw: WireSpan,
}
/// One push returns at most one event and stops before the caller-owned suffix.
#[derive(Debug)]
pub enum HttpEvent {
    /// Complete validated 200 response header.
    Head(ResponseHead),
    /// Entity bytes with an exact source map; whole-message completion is separate.
    Data(EntityData),
    /// Chunk framing or trailers retained for original-byte custody.
    Control(HttpControl),
}
/// Bounded progress; zero input may yield no event, never implicit EOF.
#[derive(Debug)]
pub struct HttpStep {
    /// Input bytes consumed, not necessarily the entire supplied slice.
    pub consumed: usize,
    /// One completed source record or None when more bytes are needed.
    pub event: Option<HttpEvent>,
}
/// A close-delimited disconnect is not the same evidence as an explicit length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpTermination {
    /// Declared length or zero chunk plus trailers was completely consumed.
    ExplicitFraming,
    /// Caller reported EOF; HTTP alone cannot distinguish truncation in this mode.
    CloseDelimitedEof,
}
/// Terminal byte accounting, not an acquisition/coverage or durability certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpEnd {
    /// Exact source and response-header binding.
    pub head: HttpHeadIdentity,
    /// Consumed plaintext response bytes, excluding a caller-owned next response.
    pub wire_bytes: u64,
    /// Transfer-decoded entity bytes.
    pub entity_bytes: u64,
    /// Nonzero HTTP chunks consumed, zero for identity transfer.
    pub chunks: u64,
    /// Evidence for termination, separate from multipart/JPEG validation.
    pub termination: HttpTermination,
}
/// Allocation-free recovery of unexposed bytes after failure or explicit abort.
#[derive(Debug)]
pub struct HttpRemainder {
    /// Original source scope.
    pub basis: StreamBasis,
    /// First terminal cause, or None for owner abandonment.
    pub reason: Option<HttpError>,
    /// Exact next unconsumed plaintext offset.
    pub next_offset: u64,
    /// Incomplete/unexposed header, size line, CRLF or trailer bytes.
    pub pending: WireSpan,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Head,
    Fixed(u64),
    UntilEof,
    Size,
    Chunk(u64),
    ChunkEnd,
    Trailers,
    Complete,
    Closed,
}
/// Single-owner response parser for GET only. No redirects, authentication or I/O.
/// Any error latches; the caller must retain all previously returned wire records.
pub struct HttpResponseStream {
    basis: StreamBasis,
    limits: HttpLimits,
    phase: Phase,
    offset: u64,
    entity_offset: u64,
    buffer: Vec<u8>,
    buffer_start: u64,
    line_start: usize,
    chunks: u64,
    head: Option<HttpHeadIdentity>,
    failure: Option<HttpError>,
}
impl std::fmt::Debug for HttpResponseStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpResponseStream")
            .field("offset", &self.offset)
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}
impl HttpResponseStream {
    /// Start one already-authorized response at plaintext offset zero.
    pub fn new(basis: StreamBasis, limits: HttpLimits) -> Result<Self, HttpError> {
        if basis.source == [0; 32]
            || basis.generation == 0
            || !(4..=32768).contains(&limits.header_bytes)
            || !(1..=65536).contains(&limits.fragment_bytes)
            || !(1..=16 * 1024 * 1024).contains(&limits.chunk_bytes)
            || !(1..=1 << 40).contains(&limits.entity_bytes)
            || !(1..=1 << 42).contains(&limits.wire_bytes)
            || !(1..=1_000_000).contains(&limits.chunks)
        {
            return Err(HttpError::Configuration);
        }
        Ok(Self {
            basis,
            limits,
            phase: Phase::Head,
            offset: 0,
            entity_offset: 0,
            buffer: Vec::new(),
            buffer_start: 0,
            line_start: 0,
            chunks: 0,
            head: None,
            failure: None,
        })
    }
    /// Next required absolute response offset; retries/gaps are refused.
    pub fn next_offset(&self) -> u64 {
        self.offset
    }
    /// Accepted transfer-decoded length, not the wire byte count.
    pub fn entity_offset(&self) -> u64 {
        self.entity_offset
    }
    /// True only after explicit framing; close-delimited streams need EOF.
    pub fn body_complete(&self) -> bool {
        self.phase == Phase::Complete
    }
    /// First latched failure, including cancellation.
    pub fn failure(&self) -> Option<HttpError> {
        self.failure
    }
    /// Consume through the next header/control/data record. Retain the input suffix.
    pub fn push(
        &mut self,
        offset: u64,
        bytes: &[u8],
        budget: &mut DecodeBudget<'_>,
    ) -> Result<HttpStep, HttpFailure> {
        let mut consumed = 0;
        let result = self.advance(offset, bytes, &mut consumed, budget);
        match result {
            Ok(event) => Ok(HttpStep { consumed, event }),
            Err(error) => {
                if self.failure.is_none() {
                    self.failure = Some(error);
                }
                Err(HttpFailure {
                    error,
                    consumed,
                    next_offset: self.offset,
                })
            }
        }
    }
    fn advance(
        &mut self,
        offset: u64,
        bytes: &[u8],
        consumed: &mut usize,
        budget: &mut DecodeBudget<'_>,
    ) -> Result<Option<HttpEvent>, HttpError> {
        budget.charge(0)?;
        if self.failure.is_some() {
            return Err(HttpError::Poisoned);
        }
        if offset != self.offset {
            return Err(HttpError::Offset);
        }
        if matches!(self.phase, Phase::Complete | Phase::Closed) {
            return Err(HttpError::Closed);
        }
        while *consumed < bytes.len() {
            if let Phase::Fixed(remaining) | Phase::Chunk(remaining) = self.phase {
                let chunk = matches!(self.phase, Phase::Chunk(_));
                let n = (bytes.len() - *consumed)
                    .min(self.limits.fragment_bytes)
                    .min(remaining.min(usize::MAX as u64) as usize);
                return self
                    .emit_data(
                        &bytes[*consumed..*consumed + n],
                        consumed,
                        Some((remaining, chunk)),
                        budget,
                    )
                    .map(Some);
            }
            if self.phase == Phase::UntilEof {
                let n = (bytes.len() - *consumed).min(self.limits.fragment_bytes);
                return self
                    .emit_data(&bytes[*consumed..*consumed + n], consumed, None, budget)
                    .map(Some);
            }
            budget.charge(4)?;
            if self.offset == self.limits.wire_bytes {
                return Err(HttpError::Limit);
            }
            let limit = if matches!(self.phase, Phase::Size | Phase::ChunkEnd) {
                4096
            } else {
                self.limits.header_bytes
            };
            if self.buffer.len() == limit {
                return Err(HttpError::Limit);
            }
            self.buffer.try_reserve(1).map_err(|_| HttpError::Limit)?;
            let b = bytes[*consumed];
            self.buffer.push(b);
            self.offset += 1;
            *consumed += 1;
            let len = self.buffer.len();
            if self.phase == Phase::ChunkEnd {
                if self.buffer.as_slice() != b"\r" && self.buffer.as_slice() != b"\r\n" {
                    return Err(HttpError::Malformed);
                }
                if len == 2 {
                    budget.charge(0)?;
                    self.phase = Phase::Size;
                    return Ok(Some(HttpEvent::Control(HttpControl {
                        kind: ControlKind::ChunkEnd,
                        raw: self.take_buffer(),
                    })));
                }
                continue;
            }
            if (b == b'\n' && (len < 2 || self.buffer[len - 2] != b'\r'))
                || (len >= 2 && self.buffer[len - 2] == b'\r' && b != b'\n')
            {
                return Err(HttpError::Malformed);
            }
            if len - self.line_start > 4096 {
                return Err(HttpError::Limit);
            }
            if b != b'\n' {
                continue;
            }
            let blank = len - self.line_start == 2;
            self.line_start = len;
            if self.phase == Phase::Size {
                budget.charge(len as u64 * 4)?;
                let length = fields::chunk_size(&self.buffer)?;
                if length > self.limits.chunk_bytes
                    || length > self.limits.entity_bytes - self.entity_offset
                    || (length != 0 && self.chunks == self.limits.chunks)
                {
                    return Err(HttpError::Limit);
                }
                budget.charge(0)?;
                if length != 0 {
                    self.chunks += 1;
                }
                self.phase = if length == 0 {
                    Phase::Trailers
                } else {
                    Phase::Chunk(length)
                };
                let ordinal = if length == 0 {
                    self.chunks + 1
                } else {
                    self.chunks
                };
                return Ok(Some(HttpEvent::Control(HttpControl {
                    kind: ControlKind::ChunkHeader { ordinal, length },
                    raw: self.take_buffer(),
                })));
            }
            if !blank {
                continue;
            }
            budget.charge(len as u64 * 4)?;
            if self.phase == Phase::Head {
                let (framing, content_type) = fields::head(&self.buffer)?;
                if matches!(framing,BodyFraming::Length(n) if n>self.limits.entity_bytes) {
                    return Err(HttpError::Limit);
                }
                let header_sha256 = ContentDigest::sha256(&self.buffer).bytes();
                let mut id = [0_u8; 100];
                id[..28].copy_from_slice(b"fss/http-mjpeg-entity/ref/1\0");
                id[28..60].copy_from_slice(&self.basis.source);
                id[60..68].copy_from_slice(&self.basis.generation.to_le_bytes());
                id[68..].copy_from_slice(&header_sha256);
                let identity = HttpHeadIdentity {
                    wire: self.basis,
                    entity: StreamBasis {
                        source: ContentDigest::sha256(&id).bytes(),
                        generation: self.basis.generation,
                    },
                    header_sha256,
                    framing,
                };
                budget.charge(0)?;
                self.head = Some(identity);
                self.phase = match framing {
                    BodyFraming::Length(0) => Phase::Complete,
                    BodyFraming::Length(n) => Phase::Fixed(n),
                    BodyFraming::Chunked => Phase::Size,
                    BodyFraming::UntilEof => Phase::UntilEof,
                };
                return Ok(Some(HttpEvent::Head(ResponseHead {
                    identity,
                    content_type,
                    raw: self.take_buffer(),
                })));
            }
            fields::trailers(&self.buffer)?;
            budget.charge(0)?;
            self.phase = Phase::Complete;
            return Ok(Some(HttpEvent::Control(HttpControl {
                kind: ControlKind::Trailers,
                raw: self.take_buffer(),
            })));
        }
        Ok(None)
    }
    fn emit_data(
        &mut self,
        input: &[u8],
        consumed: &mut usize,
        remaining: Option<(u64, bool)>,
        budget: &mut DecodeBudget<'_>,
    ) -> Result<HttpEvent, HttpError> {
        let n = input.len() as u64;
        if n > self.limits.entity_bytes - self.entity_offset
            || n > self.limits.wire_bytes - self.offset
        {
            return Err(HttpError::Limit);
        }
        budget.charge(n * 3)?;
        let head = self.head.ok_or(HttpError::Malformed)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(input.len())
            .map_err(|_| HttpError::Limit)?;
        bytes.extend_from_slice(input);
        let mapping = EntityMapping {
            head,
            wire_range: [self.offset, self.offset + n],
            entity_range: [self.entity_offset, self.entity_offset + n],
            chunk: remaining.filter(|(_, chunk)| *chunk).map(|_| self.chunks),
            sha256: ContentDigest::sha256(input).bytes(),
        };
        budget.charge(0)?;
        let raw = WireSpan {
            start: self.offset,
            bytes,
        };
        self.offset += n;
        self.entity_offset += n;
        *consumed += input.len();
        self.buffer_start = self.offset;
        if let Some((left, chunk)) = remaining {
            self.phase = match (left - n, chunk) {
                (0, true) => Phase::ChunkEnd,
                (0, false) => Phase::Complete,
                (n, true) => Phase::Chunk(n),
                (n, false) => Phase::Fixed(n),
            };
        }
        Ok(HttpEvent::Data(EntityData { mapping, raw }))
    }
    fn take_buffer(&mut self) -> WireSpan {
        let span = WireSpan {
            start: self.buffer_start,
            bytes: std::mem::take(&mut self.buffer),
        };
        self.buffer_start = self.offset;
        self.line_start = 0;
        span
    }
    /// Report actual EOF or explicit body termination. A zero-length push is not EOF.
    /// Close-delimited EOF stays distinguished because loss cannot be ruled out by HTTP.
    pub fn finish(&mut self, budget: &mut DecodeBudget<'_>) -> Result<HttpEnd, HttpError> {
        let result = (|| {
            budget.charge(0)?;
            if self.failure.is_some() {
                return Err(HttpError::Poisoned);
            }
            let termination = match self.phase {
                Phase::Complete => HttpTermination::ExplicitFraming,
                Phase::UntilEof => HttpTermination::CloseDelimitedEof,
                Phase::Closed => return Err(HttpError::Closed),
                _ => return Err(HttpError::Truncated),
            };
            let head = self.head.ok_or(HttpError::Truncated)?;
            self.phase = Phase::Closed;
            Ok(HttpEnd {
                head,
                wire_bytes: self.offset,
                entity_bytes: self.entity_offset,
                chunks: self.chunks,
                termination,
            })
        })();
        if let Err(error) = result
            && self.failure.is_none()
        {
            self.failure = Some(error);
        }
        result
    }
    /// Consume the parser and recover every unexposed byte without work or allocation.
    pub fn abort(self) -> HttpRemainder {
        HttpRemainder {
            basis: self.basis,
            reason: self.failure,
            next_offset: self.offset,
            pending: WireSpan {
                start: self.buffer_start,
                bytes: self.buffer,
            },
        }
    }
}

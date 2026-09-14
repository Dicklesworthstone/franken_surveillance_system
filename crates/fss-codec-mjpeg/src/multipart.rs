#![forbid(unsafe_code)]
//! Incremental JPEG parts from a dechunked HTTP multipart/x-mixed-replace entity.
//! This parses supplied bytes, not HTTP headers, sockets, credentials or timestamps.

use crate::{ComponentInterpretation, DecodeBudget, DecodeError, DecodeLimits, DecodedLuma, decode_luma};
use crate::stream::StreamBasis;
use fss_core::ContentDigest;

const LINE_SLACK: usize = 144;

/// Complete-input and buffering limits, never a permission to drop a frame.
#[derive(Clone, Copy, Debug)]
pub struct MultipartLimits {
    /// Encoded JPEG ceiling, 4..=16 MiB; delimiter lookahead is separately bounded.
    pub frame_bytes: usize,
    /// Complete part-header block ceiling, 4..=16 KiB.
    pub header_bytes: usize,
    /// Preamble and epilogue ceiling each, 0..=64 KiB.
    pub wrapper_bytes: usize,
}
impl Default for MultipartLimits {
    fn default() -> Self { Self { frame_bytes: 16*1024*1024, header_bytes: 16384, wrapper_bytes: 4096 } }
}

/// Stable failures; raw headers or image bytes are never included in error messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MultipartError {
    /// Invalid scope, limits, media type, boundary or unsupported parameter syntax.
    Configuration,
    /// Malformed boundary/header, duplicated field or inconsistent content length.
    Malformed,
    /// A part declares a non-JPEG type or an unsupported encoding.
    Unsupported,
    /// Input offsets are repeated, skipped or reordered.
    Offset,
    /// Resource, byte, header or ordinal ceiling exceeded.
    Limit,
    /// EOF before an explicit closing boundary; completed earlier parts are separate.
    Truncated,
    /// An earlier failure latched; no silent resynchronization is possible.
    Poisoned,
    /// Explicitly finished or aborted parser cannot accept more input.
    Closed,
    /// Owner work/cancellation boundary failed.
    Work(DecodeError),
}
impl From<DecodeError> for MultipartError { fn from(e: DecodeError) -> Self { Self::Work(e) } }
impl std::fmt::Display for MultipartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Configuration => "invalid multipart configuration",
            Self::Malformed => "malformed multipart JPEG entity",
            Self::Unsupported => "unsupported multipart part representation",
            Self::Offset => "multipart input offset mismatch",
            Self::Limit => "multipart resource limit",
            Self::Truncated => "multipart entity lacks complete termination",
            Self::Poisoned => "multipart parser has a prior failure",
            Self::Closed => "multipart parser is closed",
            Self::Work(_) => "multipart work interrupted",
        })
    }
}
impl std::error::Error for MultipartError {}

/// A failed input call reports its accepted prefix, not a partial successful part.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MultipartFailure {
    /// Current failure; the parser retains the first terminal cause separately.
    pub error: MultipartError,
    /// Accepted bytes from this call, excluding the caller-owned suffix.
    pub consumed: usize,
    /// Absolute next offset within the dechunked entity, NOT network packet bytes.
    pub next_offset: u64,
}
impl std::fmt::Display for MultipartFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { std::fmt::Display::fmt(&self.error, f) }
}
impl std::error::Error for MultipartFailure {}

/// Coupled source ranges and actual byte identities, not an authentication receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MultipartReceipt {
    /// Owner-resolved entity source and generation.
    pub basis: StreamBasis,
    /// One-based part ordinal, never used to infer capture time.
    pub ordinal: u64,
    /// Exact original Content-Type field-value bytes supplied at construction.
    pub content_type_sha256: [u8; 32],
    /// Opening delimiter range; adjacent part receipts intentionally share delimiters.
    pub opening_range: [u64; 2],
    /// Complete raw header block, including its terminating blank line.
    pub headers_range: [u64; 2],
    /// JPEG payload only; CRLF belonging to the following boundary is excluded.
    pub jpeg_range: [u64; 2],
    /// Following delimiter, including preceding CRLF and optional ending CRLF.
    pub closing_range: [u64; 2],
    /// Source-declared length when present, checked against actual payload bytes.
    pub declared_length: Option<usize>,
    /// Exact compressed payload identity.
    pub encoded_sha256: [u8; 32],
    /// Exact header block identity; vendor timestamp text is not interpreted.
    pub headers_sha256: [u8; 32],
    /// Whether the following delimiter explicitly ends the multipart entity.
    pub closes_entity: bool,
}

/// Delimited JPEG bytes, NOT a claim that entropy or pixels have been validated.
pub struct MultipartFrame {
    receipt: MultipartReceipt,
    opening: Vec<u8>,
    headers: Vec<u8>,
    storage: Vec<u8>,
    jpeg_len: usize,
}
impl std::fmt::Debug for MultipartFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultipartFrame").field("ordinal", &self.receipt.ordinal)
            .field("bytes", &self.jpeg_len).finish_non_exhaustive()
    }
}
impl MultipartFrame {
    /// Exact body-source ranges and identities.
    pub fn receipt(&self) -> MultipartReceipt { self.receipt }
    /// Original JPEG payload, excluding MIME encapsulation.
    pub fn bytes(&self) -> &[u8] { &self.storage[..self.jpeg_len] }
    /// Original opening delimiter, including transport padding when supplied.
    pub fn opening_bytes(&self) -> &[u8] { &self.opening }
    /// Complete bounded raw headers for authorized custody, never executable metadata.
    pub fn headers(&self) -> &[u8] { &self.headers }
    /// Original following delimiter; this is shared with the next part when not final.
    pub fn closing_bytes(&self) -> &[u8] { &self.storage[self.jpeg_len..] }
    /// Invoke complete native JPEG validation; framing alone never supplies pixels.
    pub fn decode(&self, interpretation: ComponentInterpretation, limits: DecodeLimits,
        budget: &mut DecodeBudget<'_>) -> Result<DecodedLuma, DecodeError> {
        decode_luma(self.bytes(), self.receipt.encoded_sha256, interpretation, limits, budget)
    }
}

/// One push stops immediately after one following delimiter, leaving its suffix unread.
#[derive(Debug)]
pub struct MultipartStep {
    /// Consumed input prefix; nonempty accepted input always makes progress.
    pub consumed: usize,
    /// One completed part or a request for more bytes.
    pub frame: Option<MultipartFrame>,
}
/// An exact retained byte span, not a coverage or durable-custody witness.
pub struct MultipartSpan { start: u64, bytes: Vec<u8> }
impl MultipartSpan {
    /// Absolute half-open entity-body range.
    pub fn range(&self) -> [u64; 2] { [self.start, self.start + self.bytes.len() as u64] }
    /// Exact original source bytes, without metadata interpretation.
    pub fn bytes(&self) -> &[u8] { &self.bytes }
}
impl std::fmt::Debug for MultipartSpan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultipartSpan").field("bytes", &self.bytes.len()).finish_non_exhaustive()
    }
}
/// Explicit EOF after a closing delimiter. A disconnect must not be supplied as clean EOF.
#[derive(Debug)]
pub struct MultipartEnd {
    /// Original entity identity.
    pub basis: StreamBasis,
    /// Delimited parts, independent of later JPEG decoder acceptance.
    pub frames: u64,
    /// Total consumed dechunked entity bytes.
    pub bytes: u64,
    /// Retained bounded preamble, not silently discarded source content.
    pub preamble: MultipartSpan,
    /// Retained bounded epilogue, not another JPEG frame.
    pub epilogue: MultipartSpan,
}
/// EOF can terminate the final delimiter without CRLF, as permitted by MIME syntax.
#[derive(Debug)]
pub struct MultipartFinish {
    /// Final part only when EOF itself completed its closing delimiter.
    pub frame: Option<MultipartFrame>,
    /// Clean explicit entity termination, never a live-camera health claim.
    pub end: MultipartEnd,
}
/// Allocation-free source recovery after failure or explicit abandonment.
#[derive(Debug)]
pub struct MultipartRemainder {
    /// Source basis, unchanged even on error.
    pub basis: StreamBasis,
    /// First latched failure; None means an explicit operator abort.
    pub reason: Option<MultipartError>,
    /// Exact next unconsumed entity offset.
    pub next_offset: u64,
    /// Preamble, opening delimiter, header block, and current phase bytes.
    /// Opening delimiters may also occur in the last successfully emitted frame.
    pub spans: [MultipartSpan; 4],
}

#[derive(Clone, Copy, PartialEq)]
enum Phase { Preamble, Headers, Body, Epilogue, Closed }

/// Single-owner, bounded multipart JPEG parser over already dechunked entity bytes.
/// Both length-declared and delimiter-terminated parts are supported. Ambiguous
/// boundary prefixes are refused, never repaired by guessed Content-Length values.
pub struct MultipartStream {
    basis: StreamBasis,
    boundary: Vec<u8>,
    content_type: [u8; 32],
    limits: MultipartLimits,
    phase: Phase,
    offset: u64,
    buffer_start: u64,
    buffer: Vec<u8>,
    line_start: usize,
    preamble: Vec<u8>,
    opening: Vec<u8>,
    opening_range: [u64; 2],
    headers: Vec<u8>,
    headers_start: u64,
    declared_length: Option<usize>,
    completed: u64,
    failure: Option<MultipartError>,
}
impl std::fmt::Debug for MultipartStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultipartStream").field("frames", &self.completed)
            .field("buffered_bytes", &self.buffer.len()).field("failure", &self.failure).finish_non_exhaustive()
    }
}
impl MultipartStream {
    /// Supply the admitted HTTP Content-Type field VALUE, not a full response header.
    /// No boundary is inferred from body bytes. Quoted boundary values are supported.
    pub fn new(basis: StreamBasis, content_type: &str, limits: MultipartLimits,
        budget: &mut DecodeBudget<'_>) -> Result<Self, MultipartError> {
        budget.charge(0)?;
        if basis.source == [0; 32] || basis.generation == 0
            || !(4..=16*1024*1024).contains(&limits.frame_bytes)
            || !(4..=16384).contains(&limits.header_bytes) || limits.wrapper_bytes > 65536 {
            return Err(MultipartError::Configuration);
        }
        let boundary = parse_content_type(content_type, budget)?;
        let content_type = ContentDigest::sha256(content_type.as_bytes()).bytes();
        budget.charge(0)?;
        Ok(Self { basis, boundary, content_type, limits, phase: Phase::Preamble, offset: 0,
            buffer_start: 0, buffer: Vec::new(), line_start: 0, preamble: Vec::new(),
            opening: Vec::new(), opening_range: [0; 2], headers: Vec::new(), headers_start: 0,
            declared_length: None, completed: 0, failure: None })
    }
    /// Exact required next dechunked-body offset.
    pub fn next_offset(&self) -> u64 { self.offset }
    /// Successfully delimited parts, not successful downstream decodes.
    pub fn completed_frames(&self) -> u64 { self.completed }
    /// First terminal failure. A new owner generation is required after a gap.
    pub fn failure(&self) -> Option<MultipartError> { self.failure }

    /// Accept at most one part from a contiguous input prefix. An empty chunk is not EOF.
    pub fn push(&mut self, expected_offset: u64, input: &[u8], budget: &mut DecodeBudget<'_>)
        -> Result<MultipartStep, MultipartFailure> {
        self.active(0)?;
        if expected_offset != self.offset { return Err(self.fail(MultipartError::Offset, 0)); }
        if let Err(e) = budget.charge(0) { return Err(self.fail(e.into(), 0)); }
        for (i, &byte) in input.iter().enumerate() {
            if let Err(e) = budget.charge(8) { return Err(self.fail(e.into(), i)); }
            let ceiling = match self.phase {
                Phase::Preamble => self.limits.wrapper_bytes + LINE_SLACK,
                Phase::Headers => self.limits.header_bytes,
                Phase::Body => self.declared_length.unwrap_or(self.limits.frame_bytes) + LINE_SLACK,
                Phase::Epilogue => self.limits.wrapper_bytes,
                Phase::Closed => return Err(self.fail(MultipartError::Closed, i)),
            };
            if self.buffer.len() >= ceiling || self.offset == u64::MAX || self.buffer.try_reserve(1).is_err() {
                return Err(self.fail(MultipartError::Limit, i));
            }
            self.buffer.push(byte); self.offset += 1;
            match self.process_byte(byte, budget) {
                Ok(Some(frame)) => return Ok(MultipartStep { consumed: i+1, frame: Some(frame) }),
                Ok(None) => (),
                Err(e) => return Err(self.fail(e, i+1)),
            }
        }
        if let Err(e) = budget.charge(0) { return Err(self.fail(e.into(), input.len())); }
        Ok(MultipartStep { consumed: input.len(), frame: None })
    }
    fn process_byte(&mut self, byte: u8, budget: &mut DecodeBudget<'_>)
        -> Result<Option<MultipartFrame>, MultipartError> {
        if self.phase == Phase::Epilogue { return Ok(None); }
        let n = self.buffer.len();
        if self.phase == Phase::Headers && n-self.line_start > 1024 { return Err(MultipartError::Limit); }
        if byte != b'\n' { return Ok(None); }
        if n < 2 || self.buffer[n-2] != b'\r' {
            return if self.phase == Phase::Headers { Err(MultipartError::Malformed) } else { Ok(None) };
        }
        let line = &self.buffer[self.line_start..n-2];
        if self.phase == Phase::Headers {
            if line.is_empty() {
                budget.charge(self.buffer.len() as u64 + 2048)?;
                self.declared_length = parse_headers(&self.buffer, self.limits.frame_bytes)?;
                self.headers = std::mem::take(&mut self.buffer);
                self.buffer_start = self.offset; self.phase = Phase::Body; self.line_start = 0;
                return Ok(None);
            }
        } else {
            budget.charge(LINE_SLACK as u64)?;
            if let Some(closed) = boundary_line(line, &self.boundary)? {
                if self.phase == Phase::Preamble {
                    if closed { return Err(MultipartError::Malformed); }
                    let begin = self.line_start.saturating_sub(2);
                    if begin > self.limits.wrapper_bytes { return Err(MultipartError::Limit); }
                    let preamble = copy(&self.buffer[..begin])?;
                    let opening = copy(&self.buffer[begin..])?;
                    budget.charge(0)?;
                    self.preamble = preamble; self.opening = opening;
                    self.opening_range = [begin as u64, self.offset];
                    self.headers_start = self.offset; self.buffer_start = self.offset;
                    self.buffer.clear(); self.phase = Phase::Headers; self.line_start = 0;
                    return Ok(None);
                }
                return self.emit(closed, budget).map(Some);
            }
        }
        self.line_start = n;
        Ok(None)
    }
    fn emit(&mut self, closed: bool, budget: &mut DecodeBudget<'_>) -> Result<MultipartFrame, MultipartError> {
        let len = self.line_start.checked_sub(2).ok_or(MultipartError::Malformed)?;
        if len < 4 || len > self.limits.frame_bytes || self.declared_length.is_some_and(|n| n != len)
            || self.buffer[..2] != [255,216] || self.buffer[len-2..len] != [255,217] {
            return Err(MultipartError::Malformed);
        }
        let ordinal = self.completed.checked_add(1).ok_or(MultipartError::Limit)?;
        let boundary_start = self.buffer_start.checked_add(len as u64).ok_or(MultipartError::Limit)?;
        budget.charge((len + self.headers.len() + LINE_SLACK) as u64)?;
        let next_opening = copy(&self.buffer[len..])?;
        let receipt = MultipartReceipt { basis: self.basis, ordinal, content_type_sha256: self.content_type,
            opening_range: self.opening_range, headers_range: [self.headers_start, self.buffer_start],
            jpeg_range: [self.buffer_start, boundary_start], closing_range: [boundary_start, self.offset],
            declared_length: self.declared_length, encoded_sha256: ContentDigest::sha256(&self.buffer[..len]).bytes(),
            headers_sha256: ContentDigest::sha256(&self.headers).bytes(), closes_entity: closed };
        budget.charge(0)?;
        let result = MultipartFrame { receipt, opening: std::mem::replace(&mut self.opening, next_opening),
            headers: std::mem::take(&mut self.headers), storage: std::mem::take(&mut self.buffer), jpeg_len: len };
        self.completed = ordinal; self.opening_range = receipt.closing_range;
        self.headers_start = self.offset; self.buffer_start = self.offset; self.line_start = 0;
        self.declared_length = None;
        self.phase = if closed { Phase::Epilogue } else { Phase::Headers };
        Ok(result)
    }
    /// Declare source EOF. A final close-delimiter without CRLF is accepted here.
    /// Until this returns successfully, no whole-entity completion is established.
    pub fn finish(&mut self, budget: &mut DecodeBudget<'_>) -> Result<MultipartFinish, MultipartFailure> {
        self.active(0)?;
        if let Err(e) = budget.charge(0) { return Err(self.fail(e.into(), 0)); }
        let frame = if self.phase == Phase::Body {
            if self.buffer.len()-self.line_start > LINE_SLACK { return Err(self.fail(MultipartError::Truncated, 0)); }
            match boundary_line(&self.buffer[self.line_start..], &self.boundary) {
                Ok(Some(true)) => match self.emit(true, budget) {
                    Ok(frame) => Some(frame), Err(e) => return Err(self.fail(e, 0)),
                },
                Err(e) => return Err(self.fail(e, 0)),
                _ => return Err(self.fail(MultipartError::Truncated, 0)),
            }
        } else if self.phase == Phase::Epilogue { None }
        else { return Err(self.fail(MultipartError::Truncated, 0)); };
        // No fallible work follows possible final-frame publication into this result.
        self.phase = Phase::Closed;
        Ok(MultipartFinish { frame, end: MultipartEnd { basis: self.basis, frames: self.completed,
            bytes: self.offset, preamble: MultipartSpan { start: 0, bytes: std::mem::take(&mut self.preamble) },
            epilogue: MultipartSpan { start: self.buffer_start, bytes: std::mem::take(&mut self.buffer) } } })
    }
    /// Consume this parser and recover all buffered source spans without allocation.
    /// Previously emitted frames belong to their caller; an opening boundary may overlap them.
    pub fn abort(self) -> MultipartRemainder {
        MultipartRemainder { basis: self.basis, reason: self.failure, next_offset: self.offset,
            spans: [MultipartSpan { start: 0, bytes: self.preamble },
                MultipartSpan { start: self.opening_range[0], bytes: self.opening },
                MultipartSpan { start: self.headers_start, bytes: self.headers },
                MultipartSpan { start: self.buffer_start, bytes: self.buffer }] }
    }
    fn active(&self, consumed: usize) -> Result<(), MultipartFailure> {
        let error = if self.phase == Phase::Closed { Some(MultipartError::Closed) }
            else if self.failure.is_some() { Some(MultipartError::Poisoned) } else { None };
        match error { Some(error) => Err(MultipartFailure { error, consumed, next_offset: self.offset }), None => Ok(()) }
    }
    fn fail(&mut self, error: MultipartError, consumed: usize) -> MultipartFailure {
        if self.failure.is_none() { self.failure = Some(error); }
        MultipartFailure { error, consumed, next_offset: self.offset }
    }
}
fn copy(bytes: &[u8]) -> Result<Vec<u8>, MultipartError> {
    let mut out = Vec::new(); out.try_reserve_exact(bytes.len()).map_err(|_| MultipartError::Limit)?;
    out.extend_from_slice(bytes); Ok(out)
}
fn token(b: u8) -> bool { b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b) }
fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|b| !b" \t".contains(b)).unwrap_or(bytes.len());
    let end = bytes.iter().rposition(|b| !b" \t".contains(b)).map_or(start, |i| i+1);
    &bytes[start..end]
}
fn parse_content_type(value: &str, budget: &mut DecodeBudget<'_>) -> Result<Vec<u8>, MultipartError> {
    if value.len() > 256 || !value.is_ascii() || value.bytes().any(|b| b < 32 && b != 9 || b == 127) {
        return Err(MultipartError::Configuration);
    }
    budget.charge(value.len() as u64 + 256)?;
    let (media, parameter) = value.split_once(';').ok_or(MultipartError::Configuration)?;
    if !trim(media.as_bytes()).eq_ignore_ascii_case(b"multipart/x-mixed-replace") {
        return Err(MultipartError::Configuration);
    }
    let (name, val) = parameter.split_once('=').ok_or(MultipartError::Configuration)?;
    if !trim(name.as_bytes()).eq_ignore_ascii_case(b"boundary") { return Err(MultipartError::Configuration); }
    let val = trim(val.as_bytes());
    let boundary = if val.starts_with(b"\"") {
        if val.len() < 2 || !val.ends_with(b"\"") { return Err(MultipartError::Configuration); }
        &val[1..val.len()-1]
    } else {
        if !val.iter().all(|&b| token(b)) { return Err(MultipartError::Configuration); }
        val
    };
    if boundary.is_empty() || boundary.len() > 70 || boundary.last() == Some(&b' ')
        || boundary.iter().any(|b| !b.is_ascii_alphanumeric() && !b"'()+_,-./:=? ".contains(b)) {
        return Err(MultipartError::Configuration);
    }
    copy(boundary)
}
// RFC 2046 forbids a boundary value as a prefix inside a body line. A matching
// prefix with unsupported tail is refused instead of giving a different parser a
// competing interpretation. Up to 64 bytes of transport padding are admitted.
fn boundary_line(line: &[u8], boundary: &[u8]) -> Result<Option<bool>, MultipartError> {
    if !line.starts_with(b"--") || !line[2..].starts_with(boundary) { return Ok(None); }
    let mut tail = &line[2+boundary.len()..];
    let closed = tail.starts_with(b"--");
    if closed { tail = &tail[2..]; }
    if tail.len() > 64 || tail.iter().any(|b| !b" \t".contains(b)) { return Err(MultipartError::Malformed); }
    Ok(Some(closed))
}
fn parse_headers(bytes: &[u8], limit: usize) -> Result<Option<usize>, MultipartError> {
    let mut names: [&[u8]; 32] = [&[]; 32]; let mut count = 0;
    let mut content_type = false; let mut length = None;
    for raw in bytes.split(|b| *b == b'\n') {
        if raw.is_empty() { continue; }
        let line = raw.strip_suffix(b"\r").ok_or(MultipartError::Malformed)?;
        if line.is_empty() { continue; }
        let colon = line.iter().position(|b| *b == b':').ok_or(MultipartError::Malformed)?;
        let name = &line[..colon]; let value = trim(&line[colon+1..]);
        if name.is_empty() || !name.iter().all(|&b| token(b))
            || value.iter().any(|&b| b < 32 && b != 9 || b > 126)
            || names[..count].iter().any(|prior| prior.eq_ignore_ascii_case(name)) {
            return Err(MultipartError::Malformed);
        }
        if count == names.len() { return Err(MultipartError::Limit); }
        names[count] = name; count += 1;
        if name.eq_ignore_ascii_case(b"Content-Type") {
            if !value.eq_ignore_ascii_case(b"image/jpeg") { return Err(MultipartError::Unsupported); }
            content_type = true;
        } else if name.eq_ignore_ascii_case(b"Content-Length") {
            if value.is_empty() || value.len() > 20 || !value.iter().all(u8::is_ascii_digit) {
                return Err(MultipartError::Malformed);
            }
            let mut n = 0_usize;
            for b in value { n = n.checked_mul(10).and_then(|n| n.checked_add(usize::from(*b-b'0'))).ok_or(MultipartError::Limit)?; }
            if n < 4 || n > limit { return Err(MultipartError::Limit); } length = Some(n);
        } else if name.eq_ignore_ascii_case(b"Content-Transfer-Encoding") {
            if !value.eq_ignore_ascii_case(b"binary") { return Err(MultipartError::Unsupported); }
        } else if name.eq_ignore_ascii_case(b"Content-Encoding") || name.eq_ignore_ascii_case(b"Transfer-Encoding") {
            return Err(MultipartError::Unsupported);
        }
    }
    if !content_type { return Err(MultipartError::Unsupported); }
    Ok(length)
}

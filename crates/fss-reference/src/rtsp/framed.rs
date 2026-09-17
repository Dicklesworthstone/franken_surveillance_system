#![forbid(unsafe_code)]
//! Bounded exact-message intake for authentication-aware RTSP owners.
//!
//! This layer locates a single strict CRLF frame, then requires the existing
//! RTSP parser to validate that EXACT frame. It never interprets a challenge,
//! guesses a transport, or resynchronizes after damage. Unlike public parsed
//! headers, retained wire can contain secrets; Debug always excludes its bytes.

use super::{RtspError, RtspEvent, RtspLimits, RtspParser};

/// Maximum chunk admitted by one feed. Poll before supplying the next chunk.
pub const MAX_WIRE_CHUNK: usize = 4096;
/// Maximum header block including its CRLF terminator.
pub const MAX_WIRE_HEADERS: usize = 65_536;
/// Maximum complete control-message body.
pub const MAX_WIRE_BODY: usize = 65_536;
/// A full control frame plus at most one chunk of lookahead.
pub const MAX_WIRE_BUFFER: usize = MAX_WIRE_HEADERS + MAX_WIRE_BODY + MAX_WIRE_CHUNK;
/// Fixed lifetime from the oldest retained byte, even for a complete queued frame.
pub const WIRE_LIFETIME_NS: u64 = 5_000_000_000;

/// Payload-free intake refusal. All retained original bytes survive until cancel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireIntakeError {
    /// Drain the previous feed before admitting another chunk; input was not consumed.
    Backpressure,
    /// Chunk, header, body, or total buffer bound exceeded.
    Limit,
    /// Bounded allocation failed.
    Allocation,
    /// Supplied owner time decreased.
    ClockReversed,
    /// Oldest retained byte reached its fixed residence deadline.
    Deadline,
    /// Missing, conflicting, signed, or malformed strict CRLF framing.
    Framing,
    /// Existing RTSP parser rejected the exactly framed message.
    Protocol(RtspError),
    /// EOF inside a header, body, or interleaved frame.
    Truncated,
    /// The owner already cancelled or marked EOF.
    Closed,
}
impl std::fmt::Display for WireIntakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RTSP wire intake refusal: {self:?}")
    }
}
impl std::error::Error for WireIntakeError {}

/// Original unprocessed TCP bytes transferred after cancellation/failure.
/// The caller must separately retain already delivered bytes as its custody policy requires.
pub struct RetainedRtspWire(Vec<u8>);
impl RetainedRtspWire {
    /// Explicit access to original bytes, which may include authentication material.
    pub fn expose(&self) -> &[u8] { &self.0 }
    /// Number of original bytes still held by this value.
    pub fn len(&self) -> usize { self.0.len() }
    /// Whether no original bytes remain.
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
}
impl std::fmt::Debug for RetainedRtspWire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedRtspWire").field("bytes", &self.len()).finish()
    }
}

/// One fully validated frame and its exact original wire representation.
/// No Clone or wire-bearing Debug implementation is provided.
pub struct RtspWireFrame {
    event: RtspEvent,
    wire: RetainedRtspWire,
    received_ns: u64,
}
impl RtspWireFrame {
    /// Existing parser output. Authentication headers remain redacted there.
    pub fn event(&self) -> &RtspEvent { &self.event }
    /// Original complete response/frame, including headers and any opaque body.
    /// Use only at an explicit authentication/source-custody boundary; do not log.
    pub fn expose_wire(&self) -> &[u8] { self.wire.expose() }
    /// Time the final byte was admitted, not processing time or camera capture time.
    pub fn received_ns(&self) -> u64 { self.received_ns }
    /// Transfer both representations without serializing a parsed message back to wire.
    pub fn into_parts(self) -> (RtspEvent, RetainedRtspWire, u64) {
        (self.event, self.wire, self.received_ns)
    }
}
impl std::fmt::Debug for RtspWireFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RtspWireFrame").field("bytes", &self.wire.len())
            .field("received_ns", &self.received_ns).finish()
    }
}

/// One-frame-at-a-time intake, with no unbounded parsed-event queue.
///
/// Call poll until it returns None between feeds. A partial frame may span many
/// feeds; once a frame completes, all lookahead is from the LAST admitted chunk.
/// This invariant preserves original completion times and deadlines even when
/// multiple messages share a chunk. CRLF is required; bare LF, folded fields,
/// duplicate Content-Length, and leading empty lines are deliberately refused.
#[derive(Default)]
pub struct RtspWireIntake {
    buffer: Vec<u8>,
    expected: Option<usize>,
    last_ns: u64,
    last_input_ns: u64,
    deadline_ns: Option<u64>,
    needs_poll: bool,
    eof: bool,
    closed: bool,
    failure: Option<WireIntakeError>,
}
impl std::fmt::Debug for RtspWireIntake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RtspWireIntake").field("bytes", &self.buffer.len())
            .field("deadline_ns", &self.deadline_ns).field("eof", &self.eof)
            .field("closed", &self.closed).finish_non_exhaustive()
    }
}
impl RtspWireIntake {
    /// Construct a quiescent owner without performing I/O.
    pub fn new() -> Self { Self::default() }
    /// Exact bytes retained, including at most one chunk of lookahead.
    pub fn buffered_bytes(&self) -> usize { self.buffer.len() }
    /// The fixed oldest-byte deadline, regardless of whether poll was delayed.
    pub fn deadline_ns(&self) -> Option<u64> { self.deadline_ns }
    /// Ready work wakes immediately; partial messages retain their fixed deadline.
    pub fn next_wake_ns(&self) -> Option<u64> {
        if self.closed || self.failure.is_some() { None }
        else if self.needs_poll || self.eof && !self.buffer.is_empty() { Some(self.last_ns) }
        else { self.deadline_ns }
    }
    /// Whether EOF drained to an exact message boundary, without a framing failure.
    pub fn is_ended(&self) -> bool { self.eof && self.buffer.is_empty() && self.failure.is_none() }
    /// Borrow/copy one bounded chunk. Every refusal consumes NONE of this chunk
    /// and leaves the accepted byte buffer and clock unchanged.
    pub fn ingest(&mut self, incoming: &[u8], now_ns: u64) -> Result<(), WireIntakeError> {
        self.check_time(now_ns)?;
        if self.closed || self.eof || self.failure.is_some() { return Err(WireIntakeError::Closed); }
        if self.deadline_ns.is_some_and(|at| now_ns >= at) { return Err(WireIntakeError::Deadline); }
        if self.needs_poll { return Err(WireIntakeError::Backpressure); }
        if incoming.len() > MAX_WIRE_CHUNK || incoming.len() > MAX_WIRE_BUFFER.saturating_sub(self.buffer.len()) {
            return Err(WireIntakeError::Limit);
        }
        let deadline = now_ns.checked_add(WIRE_LIFETIME_NS).ok_or(WireIntakeError::Deadline)?;
        self.buffer.try_reserve_exact(incoming.len()).map_err(|_| WireIntakeError::Allocation)?;
        if !incoming.is_empty() {
            self.buffer.extend_from_slice(incoming);
            self.deadline_ns = self.deadline_ns.or(Some(deadline));
            self.last_input_ns = now_ns;
            self.needs_poll = true;
        }
        self.last_ns = now_ns;
        Ok(())
    }
    /// Validate and transfer one exact frame. A malformed suffix is reported only
    /// after every preceding valid frame has been returned; no resynchronization occurs.
    pub fn poll(&mut self, now_ns: u64) -> Result<Option<RtspWireFrame>, WireIntakeError> {
        self.check_time(now_ns)?;
        if let Some(error) = &self.failure { return Err(error.clone()); }
        if self.closed { return Err(WireIntakeError::Closed); }
        self.last_ns = now_ns;
        if self.deadline_ns.is_some_and(|at| now_ns >= at) { return self.fail(WireIntakeError::Deadline); }
        if self.buffer.is_empty() { self.needs_poll = false; return Ok(None); }
        if self.expected.is_none() {
            match frame_length(&self.buffer) {
                Ok(length) => self.expected = length,
                Err(error) => return self.fail(error),
            }
        }
        let Some(length) = self.expected.filter(|n| *n <= self.buffer.len()) else {
            self.needs_poll = false;
            return if self.eof { self.fail(WireIntakeError::Truncated) } else { Ok(None) };
        };
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|_| WireIntakeError::Allocation)?;
        let mut parser = RtspParser::with_limits(RtspLimits { max_line_bytes: 2048,
            max_headers: 32, max_body_bytes: MAX_WIRE_BODY, max_interleaved_bytes: 65_535 });
        let mut events = match parser.feed(&self.buffer[..length]) {
            Ok(events) => events,
            Err(error) => return self.fail(WireIntakeError::Protocol(error)),
        };
        if events.len() != 1 || parser.buffered_bytes() != 0 || !matches!(parser.feed(&[]), Ok(e) if e.is_empty()) {
            return self.fail(WireIntakeError::Framing);
        }
        let Some(event) = events.pop() else { return self.fail(WireIntakeError::Framing); };
        bytes.extend_from_slice(&self.buffer[..length]);
        self.buffer.drain(..length);
        self.expected = None;
        self.needs_poll = !self.buffer.is_empty();
        self.deadline_ns = if self.buffer.is_empty() { None }
            else { self.last_input_ns.checked_add(WIRE_LIFETIME_NS) };
        Ok(Some(RtspWireFrame { event, wire: RetainedRtspWire(bytes), received_ns: self.last_input_ns }))
    }
    /// Mark EOF; fully framed input still drains, an incomplete suffix never becomes success.
    pub fn finish(&mut self) { self.eof = true; }
    /// Stop and transfer ALL unconsumed original bytes, including a failed challenge.
    pub fn cancel(&mut self) -> RetainedRtspWire {
        self.closed = true;
        self.expected = None; self.deadline_ns = None; self.needs_poll = false;
        RetainedRtspWire(std::mem::take(&mut self.buffer))
    }
    fn check_time(&self, now_ns: u64) -> Result<(), WireIntakeError> {
        if now_ns < self.last_ns { Err(WireIntakeError::ClockReversed) } else { Ok(()) }
    }
    fn fail<T>(&mut self, error: WireIntakeError) -> Result<T, WireIntakeError> {
        self.failure = Some(error.clone());
        Err(error)
    }
}

// Framing only: the old parser remains the semantic validator. Content-Length
// receives a deliberately narrower grammar so parser differentials cannot route
// body bytes into authentication headers or a second control response.
fn frame_length(bytes: &[u8]) -> Result<Option<usize>, WireIntakeError> {
    if bytes.first() == Some(&b'$') {
        return Ok((bytes.len() >= 4).then(|| 4 + usize::from(u16::from_be_bytes([bytes[2], bytes[3]]))));
    }
    let end = bytes.windows(4).position(|b| b == b"\r\n\r\n").map(|at| at + 4);
    let header = &bytes[..end.unwrap_or(bytes.len())];
    if header.len() > MAX_WIRE_HEADERS { return Err(WireIntakeError::Limit); }
    if header.first().is_some_and(|b| *b == b'\r' || *b == b'\n') { return Err(WireIntakeError::Framing); }
    for (i, byte) in header.iter().enumerate() {
        if *byte == 0 || *byte == b'\n' && (i == 0 || header[i - 1] != b'\r')
            || *byte == b'\r' && header.get(i + 1).is_some_and(|b| *b != b'\n') {
            return Err(WireIntakeError::Framing);
        }
    }
    let mut line_start = 0;
    for (i, byte) in header.iter().enumerate() {
        if *byte == b'\n' {
            if i.saturating_sub(line_start) > 2049 { return Err(WireIntakeError::Limit); }
            line_start = i + 1;
        }
    }
    if header.len() - line_start > 2049 { return Err(WireIntakeError::Limit); }
    let Some(end) = end else { return Ok(None); };
    let header = std::str::from_utf8(&bytes[..end - 4]).map_err(|_| WireIntakeError::Framing)?;
    let mut length = None;
    for (i, line) in header.split("\r\n").enumerate().skip(1) {
        if i > 32 { return Err(WireIntakeError::Limit); }
        if line.starts_with([' ', '\t']) { return Err(WireIntakeError::Framing); }
        let (name, value) = line.split_once(':').ok_or(WireIntakeError::Framing)?;
        if name.trim().eq_ignore_ascii_case("Content-Length") {
            let value = value.trim();
            if length.is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(WireIntakeError::Framing);
            }
            let size = value.parse::<usize>().map_err(|_| WireIntakeError::Limit)?;
            if size > MAX_WIRE_BODY { return Err(WireIntakeError::Limit); }
            length = Some(size);
        }
    }
    Ok(Some(end + length.unwrap_or(0)))
}

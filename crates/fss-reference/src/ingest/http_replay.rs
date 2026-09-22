#![forbid(unsafe_code)]
//! Cold, source-verified HTTP/MJPEG replay over an EXACT retained wire prefix.
//!
//! Uses the same HTTP and multipart parsers as native acquisition. There is no
//! network, replacement JPEG splitter, invented capture clock or implicit latest
//! head. Every loaded range is read back from the existing content-addressed store.
//! Complete frames backpressure the cursor until an exact, reverified transfer.
//!
//! Exhausting an archive is NOT observing socket EOF. Length/chunk-delimited HTTP
//! may finish from its original bytes; close-delimited or interrupted input stays
//! `PrefixExhausted`, with all parser remainders available through `retire`.

use fss_codec_mjpeg::DecodeBudget;
use fss_codec_mjpeg::http::{EntityData, HttpEnd, HttpError, HttpEvent, HttpLimits,
    HttpRemainder, HttpResponseStream, ResponseHead};
use fss_codec_mjpeg::http_mjpeg::{HttpJpegFrame, HttpMjpegEnd, HttpMjpegError,
    HttpMjpegRemainder, HttpMultipartStream};
use fss_codec_mjpeg::multipart::MultipartLimits;
use fss_geometry::{GeometryError, WorkBudget};
use fss_publication::{LocalRootPublisher, PublishCancellation, PublishCutPoint};

use super::http_archive::{HttpArchiveError, HttpWireArchive, HttpWirePin};

/// Independently selected parser, allocation and output bounds. Recorded metadata
/// cannot enlarge these values. Rechunking changes work, not source/frame identity.
#[derive(Clone, Copy, Debug)]
pub struct HttpReplayLimits {
    /// Existing HTTP header, framing and total-byte ceilings.
    pub http: HttpLimits,
    /// Existing MIME header, wrapper and complete-JPEG ceilings.
    pub multipart: MultipartLimits,
    /// At most 65536 original bytes in one storage read buffer.
    pub read_bytes: usize,
    /// At most this many complete frames; exhaustion is not clean termination.
    pub frames: u64,
    /// Complete JPEG-to-wire map bound; never a top-k selection of source spans.
    pub source_runs: usize,
}
impl Default for HttpReplayLimits {
    fn default() -> Self {
        Self { http: HttpLimits::default(), multipart: MultipartLimits::default(),
            read_bytes: 16384, frames: 100_000, source_runs: 65536 }
    }
}

/// One operation's explicitly authorized original-media access and owned budgets.
/// The probe must check current ORIGINAL-byte disclosure permission, cancellation
/// and deadline, including HTTP headers. A retention digest alone grants nothing.
pub struct HttpReplayAccess<'a, 'cx> {
    /// Existing exclusive filesystem owner; the replay cursor cannot mutate it.
    pub publisher: &'a LocalRootPublisher,
    /// Live read/disclosure policy adapter; no permissive default is provided here.
    pub cancellation: &'a dyn PublishCancellation,
    /// Caller-owned source-read, verification and orchestration work.
    pub work: &'a mut WorkBudget<'cx>,
    /// Caller-owned native HTTP/MIME parse work; never refilled internally.
    pub framing: &'a mut DecodeBudget<'cx>,
}

/// Native progress is separate from an incomplete pinned prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpReplayStep {
    /// Every required original root/metadata/byte was verified for the exact pin.
    PrefixVerified,
    /// A bounded original wire range was re-read; no parsing happened in this step.
    WireLoaded { /// Half-open offsets in the ORIGINAL HTTP response.
        range: [u64; 2] },
    /// One existing HTTP/MIME parser operation advanced.
    Advanced,
    /// A complete source-mapped part is held; no more source is read until transfer.
    FrameReady,
    /// Both HTTP and MIME finished, with explicit framing or verified original EOF.
    Complete,
    /// All pinned bytes were consumed, but no source EOF or complete HTTP was proved.
    /// This includes valid close-delimited captures; it is NOT absence of detections.
    PrefixExhausted,
}

/// Payload-free refusal. Source-read failures are retryable without advancing the
/// cursor. Parser failures are terminal because a native parser may consume a prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpReplayError {
    /// Invalid independently supplied bounds or an incompatible exact prefix.
    Configuration,
    /// Live original-byte access/cancellation/deadline probe refused.
    Cancelled,
    /// Caller work was exhausted/cancelled before completion.
    Work(GeometryError),
    /// Existing archive refused current source verification or read-back.
    Archive(HttpArchiveError),
    /// Existing HTTP parser refused; its consumed prefix remains accounted for.
    Http(HttpError),
    /// Existing MIME/source-map parser refused; its partial state remains owned.
    Multipart(HttpMjpegError),
    /// More pinned bytes follow a self-delimited response. Nothing is silently ignored.
    TrailingResponse,
    /// Independent frame ceiling reached; this is not EOF or a successful recording.
    FrameLimit,
    /// Requested ordinal/hash is not the held complete part.
    FrameMismatch,
    /// Internal parser/owner state is inconsistent; no state is reset or replayed.
    State,
}
impl From<GeometryError> for HttpReplayError {
    fn from(error: GeometryError) -> Self { Self::Work(error) }
}
impl From<HttpArchiveError> for HttpReplayError {
    fn from(error: HttpArchiveError) -> Self { Self::Archive(error) }
}
impl std::fmt::Display for HttpReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "archived HTTP replay refused: {self:?}")
    }
}
impl std::error::Error for HttpReplayError {}

/// Counts are replay progress over retained bytes, not live coverage or camera time.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HttpReplayPosition {
    /// Original prefix loaded from storage (including a still-unparsed buffer).
    pub loaded_bytes: u64,
    /// Original HTTP wire prefix accepted by the native parser.
    pub parsed_bytes: u64,
    /// Complete native MIME frames observed, including one still held.
    pub frames: u64,
    /// Complete frames explicitly transferred to a downstream owner.
    pub transferred_frames: u64,
}

/// Original buffered range, retained on failure. Debug never includes response bytes.
pub struct HttpReplayWire {
    /// Absolute start offset in the original response.
    pub start: u64,
    /// Unmodified original bytes, possibly including sensitive response headers.
    pub bytes: Vec<u8>,
    /// Prefix already offered to the native parser, even when that call failed.
    pub parsed: usize,
}
impl std::fmt::Debug for HttpReplayWire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpReplayWire").field("start", &self.start)
            .field("bytes", &self.bytes.len()).field("parsed", &self.parsed).finish()
    }
}

/// One bounded replay cursor, borrowing the immutable original-read inventory.
/// No mutable source/archive escape, network retry, implicit repair or authority token.
pub struct HttpWireReplay<'a> {
    archive: &'a HttpWireArchive,
    pin: HttpWirePin,
    limits: HttpReplayLimits,
    verified: bool,
    exhausted: bool,
    loaded: u64,
    frames: u64,
    transferred: u64,
    http: HttpResponseStream,
    multipart: Option<HttpMultipartStream>,
    head: Option<ResponseHead>,
    wire: Option<HttpReplayWire>,
    entity: Option<(EntityData, usize)>,
    frame: Option<HttpJpegFrame>,
    end: Option<HttpEnd>,
    complete: Option<HttpMjpegEnd>,
    failure: Option<HttpReplayError>,
}
impl<'a> HttpWireReplay<'a> {
    /// Pure construction. The first step verifies the EXACT independently retained
    /// pin against storage before any parsing. An empty inventory is not trusted.
    pub fn new(archive: &'a HttpWireArchive, expected: HttpWirePin, limits: HttpReplayLimits)
        -> Result<Self, HttpReplayError> {
        if archive.pin() != expected || !(1..=65536).contains(&limits.read_bytes)
            || !(1..=1_000_000).contains(&limits.frames)
            || !(1..=65536).contains(&limits.source_runs)
            || !(4..=16 * 1024 * 1024).contains(&limits.multipart.frame_bytes)
            || !(4..=16384).contains(&limits.multipart.header_bytes)
            || limits.multipart.wrapper_bytes > 65536 || expected.bytes > limits.http.wire_bytes {
            return Err(HttpReplayError::Configuration);
        }
        let http = HttpResponseStream::new(archive.scope().stream, limits.http).map_err(HttpReplayError::Http)?;
        Ok(Self { archive, pin: expected, limits, verified: false, exhausted: false,
            loaded: 0, frames: 0, transferred: 0, http, multipart: None, head: None,
            wire: None, entity: None, frame: None, end: None, complete: None, failure: None })
    }
    /// Exact historical prefix; never implicitly advanced to a newer archive head.
    pub fn pin(&self) -> HttpWirePin { self.pin }
    /// Accepted replay progress, including after a late cancellation or parser error.
    pub fn position(&self) -> HttpReplayPosition {
        HttpReplayPosition { loaded_bytes: self.loaded, parsed_bytes: self.http.next_offset(),
            frames: self.frames, transferred_frames: self.transferred }
    }
    /// First terminal parser/limit failure. Storage/cancellation refusal is not EOF.
    pub fn failure(&self) -> Option<HttpReplayError> { self.failure }
    /// Original complete response header, when observed; not safe for default logs.
    pub fn response_head(&self) -> Option<&ResponseHead> { self.head.as_ref() }
    /// Original complete mapped JPEG. No capture time is inferred from its ordinal.
    pub fn pending_frame(&self) -> Option<&HttpJpegFrame> { self.frame.as_ref() }
    /// Current original read and consumed prefix, including after terminal refusal.
    pub fn pending_wire(&self) -> Option<&HttpReplayWire> { self.wire.as_ref() }
    /// Both framing receipts after self-delimitation or verified original EOF.
    pub fn completion(&self) -> Option<&HttpMjpegEnd> { self.complete.as_ref() }

    /// At most one native parser operation OR bounded source read. A complete frame
    /// backpressures all reads. Every call, including waiting/terminal polling, checks
    /// current original-byte authority; no internal loop, sleep or budget refill.
    pub fn step(&mut self, mut access: HttpReplayAccess<'_, '_>) -> Result<HttpReplayStep, HttpReplayError> {
        probe(access.cancellation)?;
        access.work.charge(1)?;
        if let Some(error) = self.failure { return Err(error); }
        let result = self.advance(&mut access);
        if let Err(error @ (HttpReplayError::Http(_) | HttpReplayError::Multipart(_)
            | HttpReplayError::TrailingResponse | HttpReplayError::FrameLimit | HttpReplayError::State)) = result {
            self.failure = Some(error);
        }
        // Accepted input/output is already retained before this late refusal.
        probe(access.cancellation)?;
        access.work.charge(0)?;
        result
    }
    fn advance(&mut self, access: &mut HttpReplayAccess<'_, '_>) -> Result<HttpReplayStep, HttpReplayError> {
        if !self.verified {
            HttpWireArchive::load(access.publisher, self.archive.scope(), self.pin, self.archive.limits(),
                access.cancellation, access.work)?;
            self.verified = true;
            return Ok(HttpReplayStep::PrefixVerified);
        }
        if self.frame.is_some() { return Ok(HttpReplayStep::FrameReady); }
        if self.complete.is_some() { return Ok(HttpReplayStep::Complete); }
        if self.exhausted { return Ok(HttpReplayStep::PrefixExhausted); }
        if self.frames == self.limits.frames { return Err(HttpReplayError::FrameLimit); }
        if let Some((data, cursor)) = &mut self.entity {
            let parser = self.multipart.as_mut().ok_or(HttpReplayError::State)?;
            match parser.push(data, *cursor, access.framing) {
                Err(error) => { *cursor += error.consumed; return Err(HttpReplayError::Multipart(error.error)); }
                Ok(step) => {
                    *cursor += step.consumed;
                    if let Some(frame) = step.frame { self.frame = Some(frame); self.frames += 1; }
                    if *cursor == data.bytes().len() { self.entity = None; }
                }
            }
            return Ok(if self.frame.is_some() { HttpReplayStep::FrameReady } else { HttpReplayStep::Advanced });
        }
        if let Some(wire) = &mut self.wire && wire.parsed < wire.bytes.len() {
            if self.http.body_complete() { return Err(HttpReplayError::TrailingResponse); }
            let event = match self.http.push(wire.start + wire.parsed as u64, &wire.bytes[wire.parsed..], access.framing) {
                Err(error) => { wire.parsed += error.consumed; return Err(HttpReplayError::Http(error.error)); }
                Ok(step) => { wire.parsed += step.consumed; step.event }
            };
            match event {
                Some(HttpEvent::Head(head)) => {
                    self.head = Some(head);
                    self.multipart = Some(HttpMultipartStream::new(self.head.as_ref().ok_or(HttpReplayError::State)?,
                        self.limits.multipart, self.limits.source_runs, access.framing).map_err(HttpReplayError::Multipart)?);
                }
                Some(HttpEvent::Data(data)) => self.entity = Some((data, 0)),
                Some(HttpEvent::Control(_)) | None => {},
            }
            return Ok(HttpReplayStep::Advanced);
        }
        self.wire = None;
        if self.http.body_complete() {
            if self.loaded != self.pin.bytes { return Err(HttpReplayError::TrailingResponse); }
            let end = self.http.finish(access.framing).map_err(HttpReplayError::Http)?;
            self.end = Some(end);
            let mut complete = self.multipart.as_mut().ok_or(HttpReplayError::State)?
                .finish(end, access.framing).map_err(HttpReplayError::Multipart)?;
            self.frame = complete.final_frame.take();
            if self.frame.is_some() { self.frames += 1; }
            self.complete = Some(complete);
            return Ok(if self.frame.is_some() { HttpReplayStep::FrameReady } else { HttpReplayStep::Complete });
        }
        if self.loaded == self.pin.bytes {
            // Never call finish() here: an archive prefix is not an observed EOF.
            self.exhausted = true;
            return Ok(HttpReplayStep::PrefixExhausted);
        }
        let start = self.loaded;
        let end = start + (self.pin.bytes - start).min(self.limits.read_bytes as u64);
        let bytes = self.archive.read_range(access.publisher, [start, end], access.cancellation, access.work)?;
        self.wire = Some(HttpReplayWire { start, bytes, parsed: 0 });
        self.loaded = end;
        Ok(HttpReplayStep::WireLoaded { range: [start, end] })
    }

    /// Re-read and compare EVERY mapped JPEG byte before transfer. Mismatch,
    /// tombstones, corruption, insufficient work, or revoked disclosure leave the
    /// complete frame held; no alternate bytes or empty-scene result are returned.
    pub fn take_frame(&mut self, ordinal: u64, encoded_sha256: [u8; 32],
        access: HttpReplayAccess<'_, '_>) -> Result<HttpJpegFrame, HttpReplayError> {
        probe(access.cancellation)?;
        let frame = self.frame.as_ref().ok_or(HttpReplayError::FrameMismatch)?;
        if frame.part().receipt().ordinal != ordinal || frame.part().receipt().encoded_sha256 != encoded_sha256 {
            return Err(HttpReplayError::FrameMismatch);
        }
        self.archive.verify_frame(access.publisher, frame, access.cancellation, access.work)?;
        probe(access.cancellation)?;
        let frame = self.frame.take().ok_or(HttpReplayError::State)?;
        self.transferred += 1;
        Ok(frame)
    }
    /// Transfer all unfinished source/parser state, without I/O or another parser call.
    /// A partial prefix or failure never turns into successful completion on retirement.
    pub fn retire(self) -> HttpReplayRetirement {
        let position = self.position();
        HttpReplayRetirement { pin: self.pin, position, reason: self.failure, prefix_exhausted: self.exhausted,
            head: self.head, wire: self.wire, entity: self.entity, frame: self.frame,
            http: self.http.abort(), multipart: self.multipart.map(HttpMultipartStream::abort),
            end: self.end, complete: self.complete }
    }
}

/// Complete replay handoff. Source roots stay with the caller's original archive.
#[must_use]
pub struct HttpReplayRetirement {
    /// Exact source prefix, independently required for fresh replay after restart.
    pub pin: HttpWirePin,
    /// Last accepted source/frame accounting.
    pub position: HttpReplayPosition,
    /// First terminal refusal, if any.
    pub reason: Option<HttpReplayError>,
    /// The pinned prefix ended without proof of complete HTTP or original socket EOF.
    pub prefix_exhausted: bool,
    /// Original admitted response header.
    pub head: Option<ResponseHead>,
    /// Original bounded wire buffer, including its already-consumed prefix.
    pub wire: Option<HttpReplayWire>,
    /// Current entity and the prefix already consumed by native MIME parsing.
    pub entity: Option<(EntityData, usize)>,
    /// Complete original mapped JPEG not yet transferred.
    pub frame: Option<HttpJpegFrame>,
    /// Existing HTTP parser's original remainder and state.
    pub http: HttpRemainder,
    /// Existing MIME parser's original remainder and state.
    pub multipart: Option<HttpMjpegRemainder>,
    /// HTTP end already observed, even if later MIME finalization failed.
    pub end: Option<HttpEnd>,
    /// Both completed framing receipts, if actually established.
    pub complete: Option<HttpMjpegEnd>,
}
fn probe(cancellation: &dyn PublishCancellation) -> Result<(), HttpReplayError> {
    if cancellation.cancel_requested(PublishCutPoint::AfterChildrenVerified) {
        Err(HttpReplayError::Cancelled)
    } else { Ok(()) }
}

/// Source-verified archived JPEGs through the existing neural RGB and zone owners.
pub mod rgb;

/// Durable native termination records and explicitly witnessed cold finalization.
pub mod completion;

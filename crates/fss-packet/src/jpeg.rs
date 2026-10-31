#![forbid(unsafe_code)]
//! Bounded RFC 2435 baseline JPEG reconstruction from ordered RTP datagrams.
//!
//! This constructs a derived JPEG interchange stream; it does not authenticate or retain
//! the original packets and does not validate JPEG entropy. Original headers and copied
//! spans remain explicit. The pixel decoder must validate the entire completed image.

mod headers;
mod receiver;

pub use receiver::{
    JpegReceiveAdmission, JpegReceiveCancellation, JpegReceiveError, JpegReceivePoll, JpegReceiver,
};

use std::{fmt, ops::Range};

use crate::{RtpPacket, StreamKey};

/// Exact admitted reconstruction semantics, separate from a JPEG pixel decoder identity.
pub const JPEG_RECONSTRUCTION_PROFILE: &str = "fss.rtp_jpeg.rfc2435.whole_frame.v1";
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Independent bounds for one owner-scoped JPEG reconstruction stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JpegLimits {
    /// Complete derived JPEG bytes, including generated headers; at most 16 MiB.
    pub max_frame_bytes: usize,
    /// Datagrams contributing to one image, at most 4096.
    pub max_fragment_packets: usize,
    /// Unrenewable pending-frame lifetime, at most 60 seconds in caller-supplied nanoseconds.
    pub max_pending_age_ns: u64,
    /// Immutable explicitly supplied quantizer mappings retained for Q=128..254; at most 127.
    pub max_cached_quantizers: usize,
    /// Maximum width and height, in pixels; at most the RFC's 2040-pixel field bound.
    pub max_dimension: u16,
}

impl Default for JpegLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 8 * 1024 * 1024,
            max_fragment_packets: 4096,
            max_pending_age_ns: 2_000_000_000,
            max_cached_quantizers: 127,
            max_dimension: 2040,
        }
    }
}

/// Payload-free failure and incomplete-frame retirement vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JpegError {
    /// Invalid owner binding or bounds.
    Configuration,
    /// Wrong epoch, SSRC, payload type, or extended/raw sequence binding.
    StreamMismatch,
    /// This owner was cancelled or finished.
    Closed,
    /// Supplied monotonic time decreased.
    ClockReversed,
    /// Invalid header, inconsistent fragment offset, or forbidden scan marker.
    Malformed,
    /// Unsupported type, field/interlaced image, quantizer precision, or reserved Q value.
    Unsupported,
    /// Byte, fragment, dimension, quantizer-cache, or representable deadline bound exceeded.
    Limit,
    /// Fallible output reservation failed.
    Allocation,
    /// Ordered delivery lost a sequence position.
    Gap,
    /// A nonzero fragment offset has no intact initial fragment.
    MissingStart,
    /// The frame timestamp, dimensions, type, Q, or restart interval changed mid-frame.
    FragmentMismatch,
    /// A cached quantizer was requested before its definition was received.
    MissingQuantizers,
    /// A Q=128..254 mapping was redefined, contrary to its immutable stream contract.
    QuantizerConflict,
    /// A new first fragment replaced an incomplete image.
    Interrupted,
    /// The pending image's original lifetime expired.
    Deadline,
    /// The owner cancelled pending reconstruction.
    Cancelled,
    /// Input ended with an incomplete image.
    EndOfInput,
}

/// Explicit incomplete image retirement; no partial image is returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JpegDiscard {
    /// Exact owner ingress, generation, and asserted SSRC.
    pub key: StreamKey,
    /// Why the incomplete derivative was retired.
    pub reason: JpegError,
    /// First contributing extended sequence.
    pub first_sequence: u64,
    /// Last contributing extended sequence.
    pub last_sequence: u64,
    /// Retired derived bytes, including generated headers.
    pub byte_len: usize,
    /// Number of contributing packets.
    pub fragments: usize,
}

/// Refusal and any incomplete derivative retired by that operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JpegFailure {
    /// Stable category, without input bytes.
    pub reason: JpegError,
    /// Present exactly when this operation retired pending reconstruction.
    pub discarded: Option<JpegDiscard>,
}
impl fmt::Display for JpegFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RTP/JPEG reconstruction refusal: {:?}", self.reason)
    }
}
impl std::error::Error for JpegFailure {}

/// Exact copied original datagram bytes in the derived interchange image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JpegSourceSpan {
    /// Extended RTP sequence within the exact owner epoch, possibly a prior quantizer definition.
    pub sequence: u64,
    /// Original complete datagram range, excluding RTP padding.
    pub wire_range: Range<usize>,
    /// Equal-length byte-for-byte destination range in the derived JPEG.
    pub jpeg_range: Range<usize>,
}

/// Original interpreted JPEG header bytes, distinct from copied compressed image bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JpegHeaderSource {
    /// Extended RTP sequence in the same owner epoch.
    pub sequence: u64,
    /// Header range in the complete datagram, including any explicitly supplied tables.
    pub wire_range: Range<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Parameters {
    kind: u8,
    quality: u8,
    width: u16,
    height: u16,
    restart: u16,
}

/// Complete transport-reconstructed JPEG, requiring independent full pixel validation.
///
/// Generated headers are not original camera-file bytes. `source_spans` and
/// `generated_ranges` partition the output; `header_sources` records interpreted inputs.
#[derive(Eq, PartialEq)]
pub struct JpegFrame {
    key: StreamKey,
    timestamp: u32,
    parameters: Parameters,
    bytes: Vec<u8>,
    sources: Vec<JpegSourceSpan>,
    headers: Vec<JpegHeaderSource>,
    generated: Vec<Range<usize>>,
    scan_start: usize,
    scan_len: usize,
    first_sequence: u64,
    last_sequence: u64,
    fragments: usize,
    started_ns: u64,
}

impl fmt::Debug for JpegFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JpegFrame")
            .field("key", &self.key)
            .field("timestamp", &self.timestamp)
            .field("parameters", &self.parameters)
            .field("bytes", &self.bytes.len())
            .field("fragments", &self.fragments)
            .finish_non_exhaustive()
    }
}

impl JpegFrame {
    /// Exact complete derived interchange JPEG; never the original RTP source identity.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Original owner binding, not sender authentication.
    pub fn key(&self) -> StreamKey {
        self.key
    }
    /// Uninterpreted 90 kHz media timestamp, not a camera capture clock.
    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }
    /// Coded width and height from the complete frame's consistent RTP/JPEG headers.
    pub fn dimensions(&self) -> [u16; 2] {
        [self.parameters.width, self.parameters.height]
    }
    /// Admitted RFC type: 0/64 for 4:2:2 or 1/65 for 4:2:0.
    pub fn jpeg_type(&self) -> u8 {
        self.parameters.kind
    }
    /// Exact Q field; never a calibrated quality score.
    pub fn quality(&self) -> u8 {
        self.parameters.quality
    }
    /// Explicit nonzero restart interval, or None when restart markers are forbidden.
    pub fn restart_interval(&self) -> Option<u16> {
        (self.parameters.restart != 0).then_some(self.parameters.restart)
    }
    /// Complete copied-byte provenance, including earlier cached table definitions.
    pub fn source_spans(&self) -> &[JpegSourceSpan] {
        &self.sources
    }
    /// Complete interpreted-header dependency list in admitted packet order.
    pub fn header_sources(&self) -> &[JpegHeaderSource] {
        &self.headers
    }
    /// Output ranges generated from the registered profile and interpreted headers.
    pub fn generated_ranges(&self) -> &[Range<usize>] {
        &self.generated
    }
    /// Inclusive first and last packet sequence positions; table dependencies may predate these.
    pub fn sequence_interval(&self) -> [u64; 2] {
        [self.first_sequence, self.last_sequence]
    }
    /// Number of current-frame contributing packets, including no cached-table definitions.
    pub fn fragments(&self) -> usize {
        self.fragments
    }
}

/// Progress after one ordered packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JpegStatus {
    /// One complete derived JPEG is available; entropy is not yet validated.
    Complete,
    /// An incomplete bounded image is retained.
    FragmentPending,
    /// Duplicate or late extended sequence was not appended again.
    IgnoredNonIncreasing,
}

/// Atomic reconstruction result with explicit prior-frame retirement.
#[derive(Debug, Eq, PartialEq)]
pub struct JpegOutput {
    /// Complete, pending, or ignored progress.
    pub status: JpegStatus,
    /// At most one complete JPEG; malformed packets never return a successful prefix.
    pub frame: Option<Box<JpegFrame>>,
    /// Sequence gap observed before this packet, independent of incomplete state.
    pub gap_before: bool,
    /// Prior incomplete image retired by this operation, if any.
    pub discarded: Option<JpegDiscard>,
}

#[derive(Clone)]
struct Quantizers {
    bytes: [u8; 128],
    source: Option<QuantizerSource>,
}

#[derive(Clone, Copy)]
struct QuantizerSource {
    sequence: u64,
    header_start: usize,
    table_start: usize,
}

/// Single-owner RFC 2435 reassembler over increasing, sequence-validated packets.
///
/// Admits progressive-frame baseline JPEG types 0/1/64/65, standard Huffman tables,
/// Q=1..99, and exactly two 8-bit explicit quantizers for Q=128..255. Static explicit
/// mappings cannot be redefined; Q=255 requires fresh tables each frame. Restart hints
/// remain source metadata: only complete-frame decoding is permitted, never concealment.
pub struct JpegDepacketizer {
    key: StreamKey,
    payload_type: u8,
    limits: JpegLimits,
    last_sequence: Option<u64>,
    last_now_ns: u64,
    pending: Option<JpegFrame>,
    quantizers: Vec<(u8, Quantizers)>,
    closed: bool,
}

impl fmt::Debug for JpegDepacketizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JpegDepacketizer")
            .field("key", &self.key)
            .field("pending_bytes", &self.pending_bytes())
            .field("cached_quantizers", &self.quantizers.len())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl JpegDepacketizer {
    /// Validate all bounds before receiving source bytes; performs no I/O or authorization.
    pub fn new(key: StreamKey, payload_type: u8, limits: JpegLimits) -> Result<Self, JpegFailure> {
        if key.ingress == 0
            || key.generation == 0
            || payload_type > 127
            || !(1..=MAX_FRAME_BYTES).contains(&limits.max_frame_bytes)
            || !(1..=4096).contains(&limits.max_fragment_packets)
            || !(1..=60_000_000_000).contains(&limits.max_pending_age_ns)
            || limits.max_cached_quantizers > 127
            || !(1..=2040).contains(&limits.max_dimension)
        {
            return Err(failure(JpegError::Configuration));
        }
        Ok(Self {
            key,
            payload_type,
            limits,
            last_sequence: None,
            last_now_ns: 0,
            pending: None,
            quantizers: Vec::new(),
            closed: false,
        })
    }
    /// Incomplete derived-image residence; cached parameter definitions are counted separately.
    pub fn pending_bytes(&self) -> usize {
        self.pending.as_ref().map_or(0, |frame| frame.bytes.len())
    }
    /// Number of immutable Q=128..254 table definitions in this owner epoch.
    pub fn cached_quantizers(&self) -> usize {
        self.quantizers.len()
    }
    /// Original pending-frame expiration, never renewed by later fragments or duplicates.
    pub fn next_deadline_ns(&self) -> Option<u64> {
        self.pending
            .as_ref()
            .and_then(|frame| frame.started_ns.checked_add(self.limits.max_pending_age_ns))
    }
    /// Retire the incomplete image after an independently confirmed ordered-delivery gap.
    pub fn discard_gap(&mut self) -> Option<JpegDiscard> {
        self.discard(JpegError::Gap)
    }
    /// Process one ordered packet. Original datagrams always remain caller-owned.
    pub fn push(
        &mut self,
        key: StreamKey,
        sequence: u64,
        packet: RtpPacket<'_>,
        now_ns: u64,
    ) -> Result<JpegOutput, JpegFailure> {
        if key != self.key
            || packet.ssrc() != key.ssrc
            || packet.payload_type() != self.payload_type
            || packet.sequence() != sequence as u16
        {
            return Err(failure(JpegError::StreamMismatch));
        }
        if self.closed {
            return Err(failure(JpegError::Closed));
        }
        let mut discarded = self.expire(now_ns)?;
        if self.last_sequence.is_some_and(|last| sequence <= last) {
            return Ok(JpegOutput {
                status: JpegStatus::IgnoredNonIncreasing,
                frame: None,
                gap_before: false,
                discarded,
            });
        }
        let gap = self
            .last_sequence
            .is_some_and(|last| last.checked_add(1) != Some(sequence));
        if gap && discarded.is_none() {
            discarded = self.discard(JpegError::Gap);
        }
        self.last_sequence = Some(sequence);
        match self.consume(sequence, packet, now_ns, &mut discarded) {
            Ok(frame) => Ok(JpegOutput {
                status: if frame.is_some() {
                    JpegStatus::Complete
                } else {
                    JpegStatus::FragmentPending
                },
                frame: frame.map(Box::new),
                gap_before: gap,
                discarded,
            }),
            Err(reason) => {
                let remaining = self.discard(reason);
                Err(JpegFailure {
                    reason,
                    discarded: discarded.or(remaining),
                })
            }
        }
    }
    /// Expire a stalled image even when the source becomes silent.
    pub fn expire(&mut self, now_ns: u64) -> Result<Option<JpegDiscard>, JpegFailure> {
        if now_ns < self.last_now_ns {
            return Err(failure(JpegError::ClockReversed));
        }
        self.last_now_ns = now_ns;
        Ok(
            if self
                .pending
                .as_ref()
                .is_some_and(|f| now_ns - f.started_ns >= self.limits.max_pending_age_ns)
            {
                self.discard(JpegError::Deadline)
            } else {
                None
            },
        )
    }
    /// Permanently cancel this epoch and release every cached parameter definition.
    pub fn cancel(&mut self) -> Option<JpegDiscard> {
        self.closed = true;
        self.quantizers.clear();
        self.discard(JpegError::Cancelled)
    }
    /// Permanently finish after accepted packets drain; an incomplete image never becomes complete.
    pub fn finish(&mut self) -> Option<JpegDiscard> {
        self.closed = true;
        self.quantizers.clear();
        self.discard(JpegError::EndOfInput)
    }

    fn discard(&mut self, reason: JpegError) -> Option<JpegDiscard> {
        let frame = self.pending.take()?;
        Some(JpegDiscard {
            key: frame.key,
            reason,
            first_sequence: frame.first_sequence,
            last_sequence: frame.last_sequence,
            byte_len: frame.bytes.len(),
            fragments: frame.fragments,
        })
    }

    fn consume(
        &mut self,
        sequence: u64,
        packet: RtpPacket<'_>,
        now_ns: u64,
        discarded: &mut Option<JpegDiscard>,
    ) -> Result<Option<JpegFrame>, JpegError> {
        let payload = packet.payload();
        let header = headers::parse(payload, self.limits.max_dimension)?;
        let wire = packet.payload_range().start;
        if header.offset == 0 {
            if !packet.marker() {
                now_ns
                    .checked_add(self.limits.max_pending_age_ns)
                    .ok_or(JpegError::Limit)?;
            }
            let quantizers = self.tables(sequence, wire, payload, &header)?;
            let (bytes, table_ranges) = headers::build(header.parameters, &quantizers.bytes)?;
            if bytes.len() > self.limits.max_frame_bytes {
                return Err(JpegError::Limit);
            }
            let mut sources = Vec::new();
            let mut dependencies = Vec::new();
            if let Some(origin) = quantizers.source {
                reserve(&mut sources, 2, self.limits.max_fragment_packets + 2)?;
                for (i, jpeg_range) in table_ranges.into_iter().enumerate() {
                    sources.push(JpegSourceSpan {
                        sequence: origin.sequence,
                        wire_range: origin.table_start + i * 64..origin.table_start + (i + 1) * 64,
                        jpeg_range,
                    });
                }
                if origin.sequence != sequence {
                    reserve(&mut dependencies, 1, self.limits.max_fragment_packets + 1)?;
                    dependencies.push(JpegHeaderSource {
                        sequence: origin.sequence,
                        wire_range: origin.header_start..origin.table_start + 128,
                    });
                }
            }
            *discarded = discarded
                .take()
                .or_else(|| self.discard(JpegError::Interrupted));
            self.pending = Some(JpegFrame {
                key: self.key,
                timestamp: packet.timestamp(),
                parameters: header.parameters,
                scan_start: bytes.len(),
                bytes,
                sources,
                headers: dependencies,
                generated: Vec::new(),
                scan_len: 0,
                first_sequence: sequence,
                last_sequence: sequence,
                fragments: 0,
                started_ns: now_ns,
            });
        }
        let frame = self.pending.as_mut().ok_or(JpegError::MissingStart)?;
        if frame.timestamp != packet.timestamp() || frame.parameters != header.parameters {
            return Err(JpegError::FragmentMismatch);
        }
        if header.offset != frame.scan_len {
            return Err(JpegError::Malformed);
        }
        let scan = &payload[header.payload_start..];
        if scan.is_empty() {
            return Err(JpegError::Malformed);
        }
        let scan_len = frame
            .scan_len
            .checked_add(scan.len())
            .ok_or(JpegError::Limit)?;
        if scan_len > MAX_FRAME_BYTES {
            return Err(JpegError::Limit);
        }
        let begin = frame.bytes.len();
        let end = begin.checked_add(scan.len()).ok_or(JpegError::Limit)?;
        reserve(&mut frame.bytes, end, self.limits.max_frame_bytes)?;
        reserve(
            &mut frame.sources,
            frame.fragments + 3,
            self.limits.max_fragment_packets + 2,
        )?;
        let dependency_count = frame.headers.len() + 1;
        reserve(
            &mut frame.headers,
            dependency_count,
            self.limits.max_fragment_packets + 1,
        )?;
        if frame.fragments == self.limits.max_fragment_packets {
            return Err(JpegError::Limit);
        }
        frame.bytes.extend_from_slice(scan);
        frame.sources.push(JpegSourceSpan {
            sequence,
            wire_range: wire + header.payload_start..wire + payload.len(),
            jpeg_range: begin..end,
        });
        frame.headers.push(JpegHeaderSource {
            sequence,
            wire_range: wire..wire + header.payload_start,
        });
        frame.scan_len = scan_len;
        frame.fragments += 1;
        frame.last_sequence = sequence;
        if !packet.marker() {
            return Ok(None);
        }
        let has_eoi = headers::validate_scan(
            &frame.bytes[frame.scan_start..],
            frame.parameters.restart != 0,
        )?;
        if !has_eoi {
            let length = frame.bytes.len().checked_add(2).ok_or(JpegError::Limit)?;
            reserve(&mut frame.bytes, length, self.limits.max_frame_bytes)?;
            frame.bytes.extend_from_slice(&[0xff, 0xd9]);
        }
        // Complement the strictly ordered exact copied spans; never label generated headers
        // as original source bytes, even when a quantizer was reconstructed algorithmically.
        reserve(
            &mut frame.generated,
            frame.sources.len() + 1,
            self.limits.max_fragment_packets + 3,
        )?;
        let mut at = 0;
        for source in &frame.sources {
            if source.jpeg_range.start > at {
                frame.generated.push(at..source.jpeg_range.start);
            }
            at = source.jpeg_range.end;
        }
        if at < frame.bytes.len() {
            frame.generated.push(at..frame.bytes.len());
        }
        Ok(self.pending.take())
    }

    fn tables(
        &mut self,
        sequence: u64,
        wire: usize,
        payload: &[u8],
        header: &headers::Header,
    ) -> Result<Quantizers, JpegError> {
        let q = header.parameters.quality;
        if q < 128 {
            return Ok(Quantizers {
                bytes: headers::quantizers(q),
                source: None,
            });
        }
        let cached = self
            .quantizers
            .iter()
            .find(|(value, _)| *value == q)
            .map(|(_, t)| t);
        let Some(start) = header.quantizers else {
            return cached.cloned().ok_or(JpegError::MissingQuantizers);
        };
        let bytes: [u8; 128] = payload[start..start + 128]
            .try_into()
            .map_err(|_| JpegError::Malformed)?;
        if bytes.contains(&0) {
            return Err(JpegError::Malformed);
        }
        let tables = Quantizers {
            bytes,
            source: Some(QuantizerSource {
                sequence,
                header_start: wire,
                table_start: wire + start,
            }),
        };
        if let Some(previous) = cached {
            if previous.bytes != bytes {
                return Err(JpegError::QuantizerConflict);
            }
        } else if q != 255 {
            let count = self.quantizers.len() + 1;
            reserve(
                &mut self.quantizers,
                count,
                self.limits.max_cached_quantizers,
            )?;
            self.quantizers.push((q, tables.clone()));
        }
        Ok(tables)
    }
}

fn failure(reason: JpegError) -> JpegFailure {
    JpegFailure {
        reason,
        discarded: None,
    }
}

fn reserve<T>(values: &mut Vec<T>, needed: usize, limit: usize) -> Result<(), JpegError> {
    if needed > limit {
        return Err(JpegError::Limit);
    }
    if needed > values.len() {
        values
            .try_reserve_exact(needed - values.len())
            .map_err(|_| JpegError::Allocation)?;
    }
    Ok(())
}

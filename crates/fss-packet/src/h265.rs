//! Bounded RFC 7798 reconstruction in single-stream, no-DON transmission order.
//!
//! This module owns transport reconstruction only. It neither decodes HEVC nor
//! certifies picture completeness, parameter-set availability, or source custody.

use std::{fmt, ops::Range};

use crate::{RtpPacket, StreamKey};

/// Independent work and storage ceilings for one negotiated HEVC stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct H265Limits {
    /// Maximum NAL bytes, including its two-byte header, and total AP output bytes.
    /// Must be in 2..=16 MiB; aggregation cannot multiply this byte budget.
    pub max_nal_bytes: usize,
    /// Maximum NAL units in one aggregation packet, in 1..=256.
    pub max_packet_nals: usize,
    /// Maximum contributing FU packets per NAL, in 2..=4096.
    pub max_fragment_packets: usize,
    /// Maximum pending age in owner-supplied monotonic nanoseconds, in 1..=60 seconds.
    pub max_pending_age_ns: u64,
}

impl Default for H265Limits {
    fn default() -> Self {
        Self {
            max_nal_bytes: 8 * 1_024 * 1_024,
            max_packet_nals: 64,
            max_fragment_packets: 4_096,
            max_pending_age_ns: 2_000_000_000,
        }
    }
}

/// Payload-free refusal and incomplete-derivative retirement categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum H265Error {
    /// Invalid owner, payload type, SDP value, or resource ceiling.
    Configuration,
    /// Owner generation, SSRC, payload type, or extended/raw sequence mismatch.
    StreamMismatch,
    /// Input was supplied after cancellation or EOF finalization.
    Closed,
    /// Owner-supplied monotonic time moved backwards.
    ClockReversed,
    /// Invalid NAL, AP, or FU framing, header, or marker placement.
    Malformed,
    /// DON-based ordering, PACI, or a reserved packetization type is unsupported.
    Unsupported,
    /// The forbidden-zero bit reports corrupt source data.
    Corrupt,
    /// A byte, count, or representable-deadline ceiling was exceeded.
    Limit,
    /// A bounded allocation could not be reserved.
    Allocation,
    /// A delivery gap invalidated the pending FU chain.
    Gap,
    /// A continuation fragment has no intact start in this owner epoch.
    MissingStart,
    /// Timestamp, NAL type, layer, or temporal identity changed within a FU chain.
    FragmentMismatch,
    /// New input interrupted an unfinished NAL.
    Interrupted,
    /// Pending reconstruction reached its deadline.
    Deadline,
    /// Owner cancellation retired the pending derivative.
    Cancelled,
    /// End of input retired an incomplete derivative, without publishing it.
    EndOfInput,
}

/// Receipt for incomplete media that was never returned as a complete NAL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H265FragmentDiscard {
    /// Exact owner stream identity.
    pub key: StreamKey,
    /// Why reconstruction was retired; independently retained source bytes are unaffected.
    pub reason: H265Error,
    /// First contributing extended sequence.
    pub first_sequence: u64,
    /// Last contributing extended sequence.
    pub last_sequence: u64,
    /// Retired byte count, including the reconstructed two-byte NAL header.
    pub byte_len: usize,
    /// Number of contributing FU packets.
    pub fragments: usize,
}

/// Refusal and, when applicable, the sole pending derivative retired by this call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H265Failure {
    /// Stable reason, never containing source media or credentials.
    pub reason: H265Error,
    /// Explicit incomplete-chain retirement receipt.
    pub discarded: Option<H265FragmentDiscard>,
}

impl fmt::Display for H265Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "H.265 depacketization refusal: {:?}", self.reason)
    }
}

impl std::error::Error for H265Failure {}

/// Exact source-to-derived byte mapping, excluding RTP padding and AP length fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H265SourceSpan {
    /// Extended sequence of the original datagram in this stream epoch.
    pub sequence: u64,
    /// Copied range in the complete source datagram, not just its RTP payload.
    pub wire_range: Range<usize>,
    /// Destination range in the reconstructed NAL.
    pub nal_range: Range<usize>,
    /// FU payload-header and FU-header bytes that synthesize NAL bytes 0..2.
    /// None for single NAL and AP members, whose NAL headers are copied verbatim.
    pub fragment_header_range: Option<Range<usize>>,
}

/// A transport-reconstructed HEVC NAL, not a decoded frame or complete picture.
#[derive(Eq, PartialEq)]
pub struct H265NalUnit {
    key: StreamKey,
    timestamp: u32,
    bytes: Vec<u8>,
    sources: Vec<H265SourceSpan>,
    marker: bool,
    started_ns: u64,
    first_sequence: u64,
}

impl H265NalUnit {
    /// Exact NAL bytes, without adding an Annex-B prefix or interpreting its RBSP.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Six-bit HEVC NAL type; an IRAP type alone does not establish decodability.
    pub fn nal_type(&self) -> u8 {
        (self.bytes[0] >> 1) & 63
    }

    /// Six-bit layer identity, preserved rather than silently flattened to layer zero.
    pub fn layer_id(&self) -> u8 {
        layer_id(&self.bytes)
    }

    /// Nonzero three-bit temporal-id-plus-one field from the NAL header.
    pub fn temporal_id_plus_one(&self) -> u8 {
        self.bytes[1] & 7
    }

    /// Owner stream generation and SSRC.
    pub fn key(&self) -> StreamKey {
        self.key
    }

    /// Uninterpreted source RTP timestamp, not a capture-time assertion.
    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }

    /// Marker on the final contributing packet, or final AP member only.
    pub fn marker(&self) -> bool {
        self.marker
    }

    /// Exact copy spans and synthesized-header inputs.
    pub fn sources(&self) -> &[H265SourceSpan] {
        &self.sources
    }
}

impl fmt::Debug for H265NalUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("H265NalUnit")
            .field("key", &self.key)
            .field("timestamp", &self.timestamp)
            .field("nal_type", &self.nal_type())
            .field("layer_id", &self.layer_id())
            .field("temporal_id_plus_one", &self.temporal_id_plus_one())
            .field("byte_len", &self.bytes.len())
            .field("source_spans", &self.sources)
            .field("marker", &self.marker)
            .finish_non_exhaustive()
    }
}

/// Distinguishes emitted NALs from incomplete or deliberately ignored input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum H265Status {
    /// One or more complete transport NALs were emitted.
    Complete,
    /// A bounded FU chain is pending; no complete NAL was emitted.
    FragmentPending,
    /// Duplicate or late input was not appended or emitted again.
    IgnoredNonIncreasing,
}

/// Bounded packet result. Debug does not disclose original or reconstructed media.
#[derive(Debug, Eq, PartialEq)]
pub struct H265Output {
    /// Complete, pending, or ignored disposition.
    pub status: H265Status,
    /// Complete NALs only. A malformed AP never publishes a valid prefix.
    pub nals: Vec<H265NalUnit>,
    /// An increasing-sequence gap preceded this packet, even without a pending FU.
    pub gap_before: bool,
    /// Prior incomplete derivative retired by this operation, if any.
    pub discarded: Option<H265FragmentDiscard>,
}

/// Owner-driven RFC 7798 single-NAL/AP/FU receiver with explicit EOF and cancellation.
///
/// The caller supplies SRST negotiation with `sprop-max-don-diff = 0`, validates
/// extended sequences, retains source custody, and orders packets before `push`.
/// DONL/DOND ordering, cross-stream decoding order, and PACI are not implemented.
/// A loss or expiry permanently invalidates a fragment chain; late packets cannot
/// repair already-emitted gaps. All work is synchronous and performs no I/O.
pub struct H265Depacketizer {
    key: StreamKey,
    payload_type: u8,
    limits: H265Limits,
    last_sequence: Option<u64>,
    last_now_ns: u64,
    pending: Option<H265NalUnit>,
    closed: bool,
}

impl H265Depacketizer {
    /// Validate the exact owner, payload type, negotiated DON requirement, and budgets.
    /// Nonzero `sprop_max_don_diff` is refused, never guessed from packet bytes.
    pub fn new(
        key: StreamKey,
        payload_type: u8,
        sprop_max_don_diff: u16,
        limits: H265Limits,
    ) -> Result<Self, H265Failure> {
        if key.ingress == 0
            || key.generation == 0
            || payload_type > 127
            || sprop_max_don_diff > 32_767
            || !(2..=16 * 1_024 * 1_024).contains(&limits.max_nal_bytes)
            || !(1..=256).contains(&limits.max_packet_nals)
            || !(2..=4_096).contains(&limits.max_fragment_packets)
            || !(1..=60_000_000_000).contains(&limits.max_pending_age_ns)
        {
            return Err(failure(H265Error::Configuration));
        }
        if sprop_max_don_diff != 0 {
            return Err(failure(H265Error::Unsupported));
        }
        Ok(Self {
            key,
            payload_type,
            limits,
            last_sequence: None,
            last_now_ns: 0,
            pending: None,
            closed: false,
        })
    }

    /// Retained derivative bytes, excluding independently owned source custody.
    pub fn pending_bytes(&self) -> usize {
        self.pending.as_ref().map_or(0, |nal| nal.bytes.len())
    }

    /// Exact deadline the owner must arrange to poll, even without further network input.
    pub fn next_deadline_ns(&self) -> Option<u64> {
        self.pending
            .as_ref()
            .and_then(|nal| nal.started_ns.checked_add(self.limits.max_pending_age_ns))
    }

    /// Immediately invalidate pending reconstruction on an owner-confirmed delivery gap.
    pub fn discard_gap(&mut self) -> Option<H265FragmentDiscard> {
        self.discard(H265Error::Gap)
    }

    /// Consume one ordered packet bound to its caller-validated extended sequence.
    /// Wrong-owner and reversed-clock refusals leave pending state and sequence unchanged.
    pub fn push(
        &mut self,
        key: StreamKey,
        sequence: u64,
        packet: RtpPacket<'_>,
        now_ns: u64,
    ) -> Result<H265Output, H265Failure> {
        if key != self.key
            || packet.ssrc() != key.ssrc
            || packet.payload_type() != self.payload_type
            || packet.sequence() != sequence as u16
        {
            return Err(failure(H265Error::StreamMismatch));
        }
        if self.closed {
            return Err(failure(H265Error::Closed));
        }
        let mut discarded = self.expire(now_ns)?;
        if self.last_sequence.is_some_and(|last| sequence <= last) {
            return Ok(H265Output {
                status: H265Status::IgnoredNonIncreasing,
                nals: Vec::new(),
                gap_before: false,
                discarded,
            });
        }
        let gap = self
            .last_sequence
            .is_some_and(|last| last.checked_add(1) != Some(sequence));
        if gap && discarded.is_none() {
            discarded = self.discard(H265Error::Gap);
        }
        self.last_sequence = Some(sequence);
        match self.consume(sequence, packet, now_ns, &mut discarded) {
            Ok(mut output) => {
                output.gap_before = gap;
                output.discarded = discarded;
                Ok(output)
            }
            Err(reason) => {
                let remaining = self.discard(reason);
                Err(H265Failure {
                    reason,
                    discarded: discarded.or(remaining),
                })
            }
        }
    }

    /// Advance monotonic time and retire expired work without requiring a network packet.
    pub fn expire(&mut self, now_ns: u64) -> Result<Option<H265FragmentDiscard>, H265Failure> {
        if now_ns < self.last_now_ns {
            return Err(failure(H265Error::ClockReversed));
        }
        self.last_now_ns = now_ns;
        let expired = self
            .pending
            .as_ref()
            .is_some_and(|nal| now_ns - nal.started_ns >= self.limits.max_pending_age_ns);
        Ok(if expired {
            self.discard(H265Error::Deadline)
        } else {
            None
        })
    }

    /// Close permanently and account for incomplete reconstruction exactly once.
    pub fn cancel(&mut self) -> Option<H265FragmentDiscard> {
        self.closed = true;
        self.discard(H265Error::Cancelled)
    }

    /// Close at EOF, without presenting an unfinished FU chain as a complete NAL.
    pub fn finish(&mut self) -> Option<H265FragmentDiscard> {
        self.closed = true;
        self.discard(H265Error::EndOfInput)
    }

    fn discard(&mut self, reason: H265Error) -> Option<H265FragmentDiscard> {
        let nal = self.pending.take()?;
        Some(H265FragmentDiscard {
            key: nal.key,
            reason,
            first_sequence: nal.first_sequence,
            last_sequence: nal
                .sources
                .last()
                .map_or(nal.first_sequence, |span| span.sequence),
            byte_len: nal.bytes.len(),
            fragments: nal.sources.len(),
        })
    }

    fn consume(
        &mut self,
        sequence: u64,
        packet: RtpPacket<'_>,
        now_ns: u64,
        discarded: &mut Option<H265FragmentDiscard>,
    ) -> Result<H265Output, H265Error> {
        let payload = packet.payload();
        let kind = validate_header(payload)?;
        let mut nals = Vec::new();
        match kind {
            0..=47 => {
                reserve(&mut nals, 1, self.limits.max_packet_nals)?;
                let nal =
                    self.copy_nal(sequence, packet, 0..payload.len(), now_ns, packet.marker())?;
                *discarded = discarded
                    .take()
                    .or_else(|| self.discard(H265Error::Interrupted));
                nals.push(nal);
            }
            48 => {
                // Validate every member and the aggregate budget before allocating any output.
                let count = validate_ap(payload, self.limits)?;
                reserve(&mut nals, count, self.limits.max_packet_nals)?;
                let mut offset = 2;
                for index in 0..count {
                    let length =
                        usize::from(u16::from_be_bytes([payload[offset], payload[offset + 1]]));
                    offset += 2;
                    nals.push(self.copy_nal(
                        sequence,
                        packet,
                        offset..offset + length,
                        now_ns,
                        packet.marker() && index + 1 == count,
                    )?);
                    offset += length;
                }
                *discarded = discarded
                    .take()
                    .or_else(|| self.discard(H265Error::Interrupted));
            }
            49 => {
                // RFC 7798 forbids empty FU payloads, unlike RFC 6184.
                if payload.len() < 4 {
                    return Err(H265Error::Malformed);
                }
                let fu = payload[2];
                let start = fu & 0x80 != 0;
                let end = fu & 0x40 != 0;
                if (start && end) || (fu & 63) > 47 || (packet.marker() && !end) {
                    return Err(H265Error::Malformed);
                }
                let header = [(payload[0] & 0x81) | ((fu & 63) << 1), payload[1]];
                if start {
                    now_ns
                        .checked_add(self.limits.max_pending_age_ns)
                        .ok_or(H265Error::Limit)?;
                    let mut bytes = Vec::new();
                    reserve(&mut bytes, payload.len() - 1, self.limits.max_nal_bytes)?;
                    bytes.extend_from_slice(&header);
                    let mut sources = Vec::new();
                    reserve(&mut sources, 1, self.limits.max_fragment_packets)?;
                    *discarded = discarded
                        .take()
                        .or_else(|| self.discard(H265Error::Interrupted));
                    self.pending = Some(H265NalUnit {
                        key: self.key,
                        timestamp: packet.timestamp(),
                        bytes,
                        sources,
                        marker: false,
                        started_ns: now_ns,
                        first_sequence: sequence,
                    });
                }
                let nal = self.pending.as_mut().ok_or(H265Error::MissingStart)?;
                if nal.timestamp != packet.timestamp() || [nal.bytes[0], nal.bytes[1]] != header {
                    return Err(H265Error::FragmentMismatch);
                }
                let begin = nal.bytes.len();
                let needed = begin
                    .checked_add(payload.len() - 3)
                    .ok_or(H265Error::Limit)?;
                reserve(&mut nal.bytes, needed, self.limits.max_nal_bytes)?;
                let source_count = nal.sources.len() + 1;
                reserve(
                    &mut nal.sources,
                    source_count,
                    self.limits.max_fragment_packets,
                )?;
                let wire = packet.payload_range().start;
                nal.bytes.extend_from_slice(&payload[3..]);
                nal.sources.push(H265SourceSpan {
                    sequence,
                    wire_range: wire + 3..wire + payload.len(),
                    nal_range: begin..needed,
                    fragment_header_range: Some(wire..wire + 3),
                });
                if end {
                    nal.marker = packet.marker();
                    reserve(&mut nals, 1, self.limits.max_packet_nals)?;
                    nals.push(self.pending.take().ok_or(H265Error::MissingStart)?);
                }
            }
            _ => return Err(H265Error::Unsupported),
        }
        Ok(H265Output {
            status: if nals.is_empty() {
                H265Status::FragmentPending
            } else {
                H265Status::Complete
            },
            nals,
            gap_before: false,
            discarded: None,
        })
    }

    fn copy_nal(
        &self,
        sequence: u64,
        packet: RtpPacket<'_>,
        range: Range<usize>,
        now_ns: u64,
        marker: bool,
    ) -> Result<H265NalUnit, H265Error> {
        let mut bytes = Vec::new();
        reserve(&mut bytes, range.len(), self.limits.max_nal_bytes)?;
        bytes.extend_from_slice(&packet.payload()[range.clone()]);
        let mut sources = Vec::new();
        reserve(&mut sources, 1, self.limits.max_fragment_packets)?;
        let wire = packet.payload_range().start;
        sources.push(H265SourceSpan {
            sequence,
            wire_range: wire + range.start..wire + range.end,
            nal_range: 0..bytes.len(),
            fragment_header_range: None,
        });
        Ok(H265NalUnit {
            key: self.key,
            timestamp: packet.timestamp(),
            bytes,
            sources,
            marker,
            started_ns: now_ns,
            first_sequence: sequence,
        })
    }
}

fn failure(reason: H265Error) -> H265Failure {
    H265Failure {
        reason,
        discarded: None,
    }
}

fn reserve<T>(buffer: &mut Vec<T>, needed: usize, ceiling: usize) -> Result<(), H265Error> {
    if needed > ceiling {
        return Err(H265Error::Limit);
    }
    if needed > buffer.capacity() {
        let target = needed.saturating_mul(2).min(ceiling);
        buffer
            .try_reserve_exact(target - buffer.len())
            .map_err(|_| H265Error::Allocation)?;
    }
    Ok(())
}

fn layer_id(header: &[u8]) -> u8 {
    ((header[0] & 1) << 5) | (header[1] >> 3)
}

fn validate_header(bytes: &[u8]) -> Result<u8, H265Error> {
    if bytes.len() < 2 || bytes[1] & 7 == 0 {
        return Err(H265Error::Malformed);
    }
    if bytes[0] & 0x80 != 0 {
        return Err(H265Error::Corrupt);
    }
    Ok((bytes[0] >> 1) & 63)
}

fn validate_ap(payload: &[u8], limits: H265Limits) -> Result<usize, H265Error> {
    let mut offset = 2;
    let mut count = 0;
    let mut total_bytes = 0_usize;
    let mut min_layer = 63;
    let mut min_tid = 7;
    while offset < payload.len() {
        if count == limits.max_packet_nals {
            return Err(H265Error::Limit);
        }
        let pair = payload
            .get(offset..offset + 2)
            .ok_or(H265Error::Malformed)?;
        let length = usize::from(u16::from_be_bytes([pair[0], pair[1]]));
        offset += 2;
        if length < 2 {
            return Err(H265Error::Malformed);
        }
        total_bytes = total_bytes.checked_add(length).ok_or(H265Error::Limit)?;
        if total_bytes > limits.max_nal_bytes {
            return Err(H265Error::Limit);
        }
        let bytes = payload
            .get(offset..offset + length)
            .ok_or(H265Error::Malformed)?;
        if validate_header(bytes)? > 47 {
            return Err(H265Error::Malformed);
        }
        min_layer = min_layer.min(layer_id(bytes));
        min_tid = min_tid.min(bytes[1] & 7);
        count += 1;
        offset += length;
    }
    if count < 2 || layer_id(payload) != min_layer || payload[1] & 7 != min_tid {
        return Err(H265Error::Malformed);
    }
    Ok(count)
}

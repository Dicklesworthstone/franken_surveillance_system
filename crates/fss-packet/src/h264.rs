use std::{fmt, ops::Range};

use crate::{RtpPacket, StreamKey};

/// Explicit negotiated RFC 6184 packetization mode. Interleaved mode is unsupported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum H264Mode {
    /// Mode zero: only individual NAL units.
    SingleNal,
    /// Mode one: single NAL, STAP-A, and FU-A.
    NonInterleaved,
}

/// Hard bounds for one stream's pending reconstruction and packet output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct H264Limits {
    /// Maximum reconstructed NAL bytes, including its header, at most 16 MiB.
    pub max_nal_bytes: usize,
    /// Maximum NAL units in one STAP-A packet, at most 256.
    pub max_packet_nals: usize,
    /// Maximum FU packets contributing to one NAL, at most 4,096.
    pub max_fragment_packets: usize,
    /// Pending lifetime in supplied monotonic nanoseconds, at most 60 seconds.
    pub max_pending_age_ns: u64,
}

impl Default for H264Limits {
    fn default() -> Self {
        Self {
            max_nal_bytes: 8 * 1_024 * 1_024,
            max_packet_nals: 64,
            max_fragment_packets: 4_096,
            max_pending_age_ns: 2_000_000_000,
        }
    }
}

/// Stable reasons for refusing input or retiring incomplete derivative state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum H264Error {
    /// Invalid policy, generation, or payload type.
    Configuration,
    /// Wrong owner epoch, SSRC, payload type, or extended/raw sequence binding.
    StreamMismatch,
    /// Receiver has been cancelled or finished.
    Closed,
    /// Supplied monotonic clock moved backwards.
    ClockReversed,
    /// Invalid aggregation/fragment framing or nested packetization units.
    Malformed,
    /// Unnegotiated packetization mode or unsupported packetization unit.
    Unsupported,
    /// A forbidden bit reports corrupted source media.
    Corrupt,
    /// Reconstruction exceeded a byte/count budget or its representable deadline.
    Limit,
    /// A bounded allocation could not be reserved.
    Allocation,
    /// A missing sequence interrupted the pending fragment chain.
    Gap,
    /// Fragment arrived without an intact start.
    MissingStart,
    /// Timestamp or reconstructed NAL header changed within one fragment chain.
    FragmentMismatch,
    /// New NAL/start replaced an incomplete chain.
    Interrupted,
    /// Pending reconstruction reached its deadline.
    Deadline,
    /// Owner cancelled the derivative stream.
    Cancelled,
    /// Source ended before reconstruction completed.
    EndOfInput,
}

/// Payload-free receipt for an incomplete NAL that was never published as complete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FragmentDiscard {
    /// Exact owner stream epoch.
    pub key: StreamKey,
    /// Why the derivative was discarded; original packet custody is unaffected.
    pub reason: H264Error,
    /// First contributing extended sequence.
    pub first_sequence: u64,
    /// Last contributing extended sequence.
    pub last_sequence: u64,
    /// Reconstructed bytes retired, including the synthesized NAL header.
    pub byte_len: usize,
    /// Number of contributing FU packets, including empty payload fragments.
    pub fragments: usize,
}

/// Refusal plus the explicit retirement receipt for any affected pending derivative.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H264Failure {
    /// Stable input/refusal category.
    pub reason: H264Error,
    /// Incomplete state retired by this operation, when present.
    pub discarded: Option<FragmentDiscard>,
}

impl fmt::Display for H264Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "H.264 depacketization refusal: {:?}", self.reason)
    }
}

impl std::error::Error for H264Failure {}

/// Exact source-to-derived byte mapping, excluding packet padding and aggregation lengths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NalSourceSpan {
    /// Extended sequence of the retained source datagram in this owner epoch.
    pub sequence: u64,
    /// Copied bytes in the complete source datagram, not merely its RTP payload.
    pub wire_range: Range<usize>,
    /// Destination bytes in the reconstructed NAL.
    pub nal_range: Range<usize>,
    /// FU indicator/header source range; its semantics synthesize output byte zero.
    pub fragment_header_range: Option<Range<usize>>,
}

/// A complete transport-reconstructed NAL, not a decoded frame or complete access unit.
#[derive(Eq, PartialEq)]
pub struct NalUnit {
    key: StreamKey,
    timestamp: u32,
    bytes: Vec<u8>,
    sources: Vec<NalSourceSpan>,
    marker: bool,
    started_ns: u64,
    first_sequence: u64,
}

impl NalUnit {
    /// Reconstructed NAL bytes without an invented Annex-B start code.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// NAL type only; type five does not prove that required parameter sets are present.
    pub fn nal_type(&self) -> u8 {
        self.bytes[0] & 31
    }

    /// Original owner epoch and SSRC.
    pub fn key(&self) -> StreamKey {
        self.key
    }

    /// Uninterpreted source RTP timestamp.
    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }

    /// Sender marker on the final packet/NAL; not a completeness certificate for an access unit.
    pub fn marker(&self) -> bool {
        self.marker
    }

    /// Exact copy spans and any synthesized-header inputs.
    pub fn sources(&self) -> &[NalSourceSpan] {
        &self.sources
    }
}

impl fmt::Debug for NalUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NalUnit")
            .field("key", &self.key)
            .field("timestamp", &self.timestamp)
            .field("nal_type", &self.nal_type())
            .field("byte_len", &self.bytes.len())
            .field("source_spans", &self.sources)
            .field("marker", &self.marker)
            .finish_non_exhaustive()
    }
}

/// Successful processing status, separating complete output from retained or ignored input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum H264Status {
    /// One or more complete NAL units are returned.
    Complete,
    /// A bounded incomplete FU chain is retained; no NAL is returned.
    FragmentPending,
    /// Non-increasing extended sequence is not delivered again or appended out of order.
    IgnoredNonIncreasing,
}

/// Packet processing receipt. Debug intentionally cannot disclose media bytes.
#[derive(Debug, Eq, PartialEq)]
pub struct H264Output {
    /// Whether complete, pending, or deliberately ignored.
    pub status: H264Status,
    /// Complete NAL units only; an invalid STAP-A never returns a valid prefix.
    pub nals: Vec<NalUnit>,
    /// A sequence gap was observed before this packet, even when no fragment was pending.
    pub gap_before: bool,
    /// Prior incomplete derivative retired by this operation, when present.
    pub discarded: Option<FragmentDiscard>,
}

/// Bounded, owner-scoped mode-zero/one NAL reassembler with explicit drain/cancel receipts.
///
/// Supply sequence-validated packets in increasing extended-sequence order. This is not
/// a jitter buffer: a gap discards partial FU state, and a late packet cannot resurrect it.
/// Single/STAP NAL completion is not access-unit completeness or source continuity.
pub struct H264Depacketizer {
    key: StreamKey,
    payload_type: u8,
    mode: H264Mode,
    limits: H264Limits,
    last_sequence: Option<u64>,
    last_now_ns: u64,
    pending: Option<NalUnit>,
    closed: bool,
}

impl H264Depacketizer {
    /// Open a bounded derivative receiver; the caller separately owns source custody/authority.
    pub fn new(
        key: StreamKey,
        payload_type: u8,
        mode: H264Mode,
        limits: H264Limits,
    ) -> Result<Self, H264Failure> {
        if key.ingress == 0
            || key.generation == 0
            || payload_type > 127
            || !(1..=16 * 1_024 * 1_024).contains(&limits.max_nal_bytes)
            || !(1..=256).contains(&limits.max_packet_nals)
            || !(2..=4_096).contains(&limits.max_fragment_packets)
            || !(1..=60_000_000_000).contains(&limits.max_pending_age_ns)
        {
            return Err(H264Failure {
                reason: H264Error::Configuration,
                discarded: None,
            });
        }
        Ok(Self {
            key,
            payload_type,
            mode,
            limits,
            last_sequence: None,
            last_now_ns: 0,
            pending: None,
            closed: false,
        })
    }

    /// Current retained derivative bytes; never includes the independently owned source spool.
    pub fn pending_bytes(&self) -> usize {
        self.pending.as_ref().map_or(0, |nal| nal.bytes.len())
    }

    /// Earliest poll time for pending reconstruction, absent when nothing is retained.
    /// FU starts with an unrepresentable deadline are refused rather than retained forever.
    pub fn next_deadline_ns(&self) -> Option<u64> {
        self.pending.as_ref().and_then(|nal| {
            nal.started_ns.checked_add(self.limits.max_pending_age_ns)
        })
    }

    /// Retire an incomplete chain immediately on an owner-confirmed delivery gap.
    /// This does not admit a packet, advance sequence/time, or close the receiver.
    pub fn discard_gap(&mut self) -> Option<FragmentDiscard> {
        self.discard(H264Error::Gap)
    }

    /// Process one complete parsed RTP packet with its caller-validated extended sequence.
    pub fn push(
        &mut self,
        key: StreamKey,
        sequence: u64,
        packet: RtpPacket<'_>,
        now_ns: u64,
    ) -> Result<H264Output, H264Failure> {
        let failure = |reason| H264Failure {
            reason,
            discarded: None,
        };
        if key != self.key
            || packet.ssrc() != key.ssrc
            || packet.payload_type() != self.payload_type
            || packet.sequence() != sequence as u16
        {
            return Err(failure(H264Error::StreamMismatch));
        }
        if self.closed {
            return Err(failure(H264Error::Closed));
        }
        if now_ns < self.last_now_ns {
            return Err(failure(H264Error::ClockReversed));
        }
        let mut discarded = self.expire(now_ns)?;
        if self.last_sequence.is_some_and(|last| sequence <= last) {
            return Ok(H264Output {
                status: H264Status::IgnoredNonIncreasing,
                nals: Vec::new(),
                gap_before: false,
                discarded,
            });
        }
        let gap = self
            .last_sequence
            .is_some_and(|last| last.checked_add(1) != Some(sequence));
        if gap && discarded.is_none() {
            discarded = self.discard(H264Error::Gap);
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
                Err(H264Failure {
                    reason,
                    discarded: discarded.or(remaining),
                })
            }
        }
    }

    /// Retire expired pending work even when no more packets arrive; supplied time is monotonic.
    pub fn expire(&mut self, now_ns: u64) -> Result<Option<FragmentDiscard>, H264Failure> {
        if now_ns < self.last_now_ns {
            return Err(H264Failure {
                reason: H264Error::ClockReversed,
                discarded: None,
            });
        }
        self.last_now_ns = now_ns;
        let expired = self
            .pending
            .as_ref()
            .is_some_and(|nal| now_ns - nal.started_ns >= self.limits.max_pending_age_ns);
        Ok(if expired {
            self.discard(H264Error::Deadline)
        } else {
            None
        })
    }

    /// Cancel permanently and report the incomplete derivative rather than publishing it.
    pub fn cancel(&mut self) -> Option<FragmentDiscard> {
        self.closed = true;
        self.discard(H264Error::Cancelled)
    }

    /// Finish permanently at end of input; never flush an incomplete FU as a complete NAL.
    pub fn finish(&mut self) -> Option<FragmentDiscard> {
        self.closed = true;
        self.discard(H264Error::EndOfInput)
    }

    fn discard(&mut self, reason: H264Error) -> Option<FragmentDiscard> {
        let nal = self.pending.take()?;
        Some(FragmentDiscard {
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
        discarded: &mut Option<FragmentDiscard>,
    ) -> Result<H264Output, H264Error> {
        let payload = packet.payload();
        let header = *payload.first().ok_or(H264Error::Malformed)?;
        if header & 0x80 != 0 {
            return Err(H264Error::Corrupt);
        }
        let kind = header & 31;
        if !(1..=23).contains(&kind) && self.mode == H264Mode::SingleNal {
            return Err(H264Error::Unsupported);
        }
        let mut nals = Vec::new();
        match kind {
            1..=23 => {
                reserve(&mut nals, 1, self.limits.max_packet_nals)?;
                let nal =
                    self.copy_nal(sequence, packet, 0..payload.len(), now_ns, packet.marker())?;
                *discarded = discarded
                    .take()
                    .or_else(|| self.discard(H264Error::Interrupted));
                nals.push(nal);
            }
            24 => {
                let count = validate_stap(payload, self.limits)?;
                reserve(&mut nals, count, self.limits.max_packet_nals)?;
                let mut offset = 1;
                for index in 0..count {
                    let length =
                        usize::from(u16::from_be_bytes([payload[offset], payload[offset + 1]]));
                    offset += 2;
                    let nal = self.copy_nal(
                        sequence,
                        packet,
                        offset..offset + length,
                        now_ns,
                        packet.marker() && index + 1 == count,
                    )?;
                    nals.push(nal);
                    offset += length;
                }
                *discarded = discarded
                    .take()
                    .or_else(|| self.discard(H264Error::Interrupted));
            }
            28 => {
                let fu = *payload.get(1).ok_or(H264Error::Malformed)?;
                let start = fu & 0x80 != 0;
                let end = fu & 0x40 != 0;
                // RFC 6184 requires receivers to ignore the reserved bit. Empty FU payloads are legal.
                let nal_header = (header & 0x60) | (fu & 31);
                if (start && end) || !(1..=23).contains(&(fu & 31)) || (packet.marker() && !end) {
                    return Err(H264Error::Malformed);
                }
                if start {
                    // Every retained chain must have a representable timer wake.
                    now_ns
                        .checked_add(self.limits.max_pending_age_ns)
                        .ok_or(H264Error::Limit)?;
                    let mut bytes = Vec::new();
                    reserve(&mut bytes, payload.len() - 1, self.limits.max_nal_bytes)?;
                    bytes.push(nal_header);
                    let mut sources = Vec::new();
                    reserve(&mut sources, 1, self.limits.max_fragment_packets)?;
                    *discarded = discarded
                        .take()
                        .or_else(|| self.discard(H264Error::Interrupted));
                    self.pending = Some(NalUnit {
                        key: self.key,
                        timestamp: packet.timestamp(),
                        bytes,
                        sources,
                        marker: false,
                        started_ns: now_ns,
                        first_sequence: sequence,
                    });
                }
                let nal = self.pending.as_mut().ok_or(H264Error::MissingStart)?;
                if nal.timestamp != packet.timestamp() || nal.bytes[0] != nal_header {
                    return Err(H264Error::FragmentMismatch);
                }
                let begin = nal.bytes.len();
                let needed = begin
                    .checked_add(payload.len() - 2)
                    .ok_or(H264Error::Limit)?;
                reserve(&mut nal.bytes, needed, self.limits.max_nal_bytes)?;
                let source_count = nal.sources.len() + 1;
                reserve(
                    &mut nal.sources,
                    source_count,
                    self.limits.max_fragment_packets,
                )?;
                let wire = packet.payload_range().start;
                nal.bytes.extend_from_slice(&payload[2..]);
                nal.sources.push(NalSourceSpan {
                    sequence,
                    wire_range: wire + 2..wire + payload.len(),
                    nal_range: begin..needed,
                    fragment_header_range: Some(wire..wire + 2),
                });
                if end {
                    nal.marker = packet.marker();
                    reserve(&mut nals, 1, self.limits.max_packet_nals)?;
                    nals.push(self.pending.take().ok_or(H264Error::MissingStart)?);
                }
            }
            _ => return Err(H264Error::Unsupported),
        }
        Ok(H264Output {
            status: if nals.is_empty() {
                H264Status::FragmentPending
            } else {
                H264Status::Complete
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
    ) -> Result<NalUnit, H264Error> {
        let mut bytes = Vec::new();
        reserve(&mut bytes, range.len(), self.limits.max_nal_bytes)?;
        bytes.extend_from_slice(&packet.payload()[range.clone()]);
        let mut sources = Vec::new();
        reserve(&mut sources, 1, self.limits.max_fragment_packets)?;
        let wire = packet.payload_range().start;
        sources.push(NalSourceSpan {
            sequence,
            wire_range: wire + range.start..wire + range.end,
            nal_range: 0..bytes.len(),
            fragment_header_range: None,
        });
        Ok(NalUnit {
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

fn reserve<T>(buffer: &mut Vec<T>, needed: usize, ceiling: usize) -> Result<(), H264Error> {
    if needed > ceiling {
        return Err(H264Error::Limit);
    }
    if needed > buffer.capacity() {
        let target = needed.saturating_mul(2).min(ceiling);
        buffer
            .try_reserve_exact(target - buffer.len())
            .map_err(|_| H264Error::Allocation)?;
    }
    Ok(())
}

fn validate_stap(payload: &[u8], limits: H264Limits) -> Result<usize, H264Error> {
    let mut offset = 1;
    let mut count = 0;
    let mut nri = 0;
    while offset < payload.len() {
        if count == limits.max_packet_nals {
            return Err(H264Error::Limit);
        }
        let pair = payload
            .get(offset..offset + 2)
            .ok_or(H264Error::Malformed)?;
        let length = usize::from(u16::from_be_bytes([pair[0], pair[1]]));
        offset += 2;
        if length == 0 || length > limits.max_nal_bytes {
            return Err(if length == 0 {
                H264Error::Malformed
            } else {
                H264Error::Limit
            });
        }
        let bytes = payload
            .get(offset..offset + length)
            .ok_or(H264Error::Malformed)?;
        if bytes[0] & 0x80 != 0 {
            return Err(H264Error::Corrupt);
        }
        if !(1..=23).contains(&(bytes[0] & 31)) {
            return Err(H264Error::Malformed);
        }
        nri = nri.max(bytes[0] & 0x60);
        count += 1;
        offset += length;
    }
    if count == 0 || payload[0] & 0x60 != nri {
        return Err(H264Error::Malformed);
    }
    Ok(count)
}

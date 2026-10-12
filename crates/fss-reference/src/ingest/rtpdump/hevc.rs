#![forbid(unsafe_code)]
//! Recorded HEVC RTP through the native ordered RFC 7798 receiver.
//!
//! This reconstructs transport NALs, not decoded pixels or complete pictures.
//! Originals remain independently owned by the caller. No socket, guessed codec
//! configuration, sender-clock assertion, or effect authority is introduced.

use super::{
    RtpDumpError, RtpDumpKind, RtpDumpLimits, RtpDumpReader, RtpDumpRecord, replay::FileNalSource,
};
use crate::ReplayCx;
use fss_packet::{
    H265Limits, H265NalUnit, H265ReceiveAdmission, H265ReceiveCancellation, H265ReceiveError,
    H265ReceivePoll, H265Receiver, ReorderDisposition, ReorderLimits, RtcpCompound, RtcpMode,
    RtpPacket, StreamKey,
};

/// Explicit source binding and independent container, transport, and codec bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HevcDumpConfig {
    /// Owner-authorized ingress, immutable generation, and selected SSRC.
    pub key: StreamKey,
    /// Selected HEVC RTP payload mapping; never inferred from packet bytes.
    pub payload_type: u8,
    /// Negotiated SDP value. Only SRST without DON is supported; nonzero is refused.
    pub sprop_max_don_diff: u16,
    /// Original-file bounds, also bounding the number of retained source-map entries.
    pub dump: RtpDumpLimits,
    /// Original-datagram parsing, queue, and reordering limits.
    pub reorder: ReorderLimits,
    /// Independent NAL, aggregation, fragment-count, and reconstruction-age limits.
    pub reconstruction: H265Limits,
    /// Explicit RTCP validation mode, never broadened following a parse failure.
    pub rtcp: RtcpMode,
}

/// Payload-free failure; a failed derivative never destroys the caller's originals.
#[derive(Debug)]
pub enum HevcDumpError {
    /// Invalid container framing or a declared container ceiling was reached.
    Framing(RtpDumpError),
    /// Native receiver construction or progress was refused.
    Receiver(H265ReceiveError),
    /// Bounded metadata allocation failed.
    Allocation,
    /// A reconstructed span cannot be proven against its exact admitted original.
    SourceMap,
}
impl std::fmt::Display for HevcDumpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "recorded HEVC refusal: {self:?}")
    }
}
impl std::error::Error for HevcDumpError {}

/// One original-record admission. It does not assert picture validity or source custody.
#[derive(Debug)]
pub enum HevcDumpAdmission {
    /// Unmodified native admission, including probation, duplicate, and restart receipts.
    Rtp(H265ReceiveAdmission),
    /// Whole-compound RTCP validation, independent of video reconstruction.
    Rtcp(Result<(), fss_packet::PacketError>),
    /// Snaplen lost original bytes; all pending derivative state was retired.
    CapturedPrefix(H265ReceiveCancellation),
    /// Admission failed and fenced this derivative attempt.
    Refused {
        /// Typed admission or source-mapping failure.
        error: HevcDumpError,
        /// Pending originals and fragments retired by the failure.
        cancelled: H265ReceiveCancellation,
    },
    /// A prior failure or restart fenced this attempt. The original is still exposed.
    Fenced,
}

/// At most one original record or native receiver event per owner-driven step.
#[derive(Debug)]
pub enum HevcDumpStep<'a> {
    /// Exact original, including probation, duplicate, malformed, or fenced inputs.
    Record {
        /// Borrowed original-file record, exposed before corresponding receiver progress.
        source: RtpDumpRecord<'a>,
        /// Capture offset decreased relative to the preceding original record.
        offset_reversed: bool,
        /// Typed admission receipt for this original.
        admission: HevcDumpAdmission,
    },
    /// Native NAL output, source datagram, gap, codec refusal, or retirement unchanged.
    Progress(H265ReceivePoll),
    /// Container EOF, not receiver quiescence. Accepted datagrams must still drain.
    InputEnded,
    /// Malformed container termination is never converted to clean codec EOF.
    FramingRefused {
        /// Exact framing failure.
        error: RtpDumpError,
        /// All pending derivative work retired by the failure.
        cancelled: H265ReceiveCancellation,
    },
    /// Native progress failed; later original records remain inspectable.
    ReceiverRefused {
        /// Typed native receiver failure.
        error: H265ReceiveError,
        /// All pending derivative work retired by the failure.
        cancelled: H265ReceiveCancellation,
    },
    /// Owner cancellation retired the queue and fragment chain without NAL publication.
    Cancelled(H265ReceiveCancellation),
    /// Terminal: no further events or repeated retirement receipts.
    Exhausted,
}

struct Original<'a> {
    sequence: u64,
    record: RtpDumpRecord<'a>,
}

/// Bounded recorded HEVC reconstruction with byte-exact original-file provenance.
///
/// The capture offsets drive only a monotonic laboratory clock. Intermediate
/// reorder and fragment deadlines run before later arrivals, including arrivals
/// exactly at a deadline. Reversed offsets are reported, never used to reverse
/// receiver time. A truncated capture or admission failure fences derivatives but
/// continues original-record inspection. A restart needs a new owner generation.
/// Out-of-band VPS/SPS/PPS availability and subsequent picture validation remain
/// separate obligations; this adapter makes no parameter-set or decoding claim.
pub struct RecordedHevcReplay<'a> {
    input: &'a [u8],
    reader: RtpDumpReader<'a>,
    config: HevcDumpConfig,
    receiver: H265Receiver,
    originals: Vec<Original<'a>>,
    next: Option<RtpDumpRecord<'a>>,
    now_ns: u64,
    previous_offset: Option<u32>,
    input_ended: bool,
    fenced: bool,
    stopped: bool,
}
impl<'a> RecordedHevcReplay<'a> {
    /// Open one explicitly selected, negotiated owner epoch over a retained file.
    pub fn new(input: &'a [u8], config: HevcDumpConfig) -> Result<Self, HevcDumpError> {
        let reader = RtpDumpReader::new(input, config.dump).map_err(HevcDumpError::Framing)?;
        let receiver = H265Receiver::new(
            config.key,
            config.payload_type,
            config.sprop_max_don_diff,
            config.reorder,
            config.reconstruction,
        )
        .map_err(HevcDumpError::Receiver)?;
        let mut originals = Vec::new();
        originals
            .try_reserve_exact(config.dump.max_records)
            .map_err(|_| HevcDumpError::Allocation)?;
        Ok(Self {
            input,
            reader,
            config,
            receiver,
            originals,
            next: None,
            now_ns: 0,
            previous_offset: None,
            input_ended: false,
            fenced: false,
            stopped: false,
        })
    }

    /// Incomplete derivative bytes; caller-owned NALs and original custody are separate.
    pub fn retained_nal_bytes(&self) -> usize {
        self.receiver.pending_nal_bytes()
    }

    /// First admitted original for an extended sequence. Duplicates cannot remap it.
    pub fn source_record(&self, sequence: u64) -> Option<&RtpDumpRecord<'a>> {
        self.originals
            .binary_search_by_key(&sequence, |o| o.sequence)
            .ok()
            .map(|i| &self.originals[i].record)
    }

    /// Verify copied NAL bytes and synthesized two-byte FU headers against originals.
    /// File offsets cover the full source datagram, excluding RTP padding and AP lengths.
    pub fn map_nal(&self, nal: &H265NalUnit) -> Result<Vec<FileNalSource>, HevcDumpError> {
        if nal.key() != self.config.key {
            return Err(HevcDumpError::SourceMap);
        }
        let mut mapped = Vec::new();
        mapped
            .try_reserve_exact(nal.sources().len())
            .map_err(|_| HevcDumpError::Allocation)?;
        for span in nal.sources() {
            let record = self
                .source_record(span.sequence)
                .ok_or(HevcDumpError::SourceMap)?;
            let source = RtpPacket::parse(record.packet(), self.config.reorder.packet)
                .map_err(|_| HevcDumpError::SourceMap)?;
            let payload = source.payload_range();
            if source.timestamp() != nal.timestamp()
                || span.wire_range.start < payload.start
                || span.wire_range.end > payload.end
            {
                return Err(HevcDumpError::SourceMap);
            }
            let packet = record.packet_span();
            let translate = |range: &std::ops::Range<usize>| {
                if range.start > range.end || range.end > packet.len() {
                    Err(HevcDumpError::SourceMap)
                } else {
                    Ok(packet.start + range.start..packet.start + range.end)
                }
            };
            let wire = translate(&span.wire_range)?;
            let original = self
                .input
                .get(wire.clone())
                .ok_or(HevcDumpError::SourceMap)?;
            let derived = nal
                .bytes()
                .get(span.nal_range.clone())
                .ok_or(HevcDumpError::SourceMap)?;
            if original != derived {
                return Err(HevcDumpError::SourceMap);
            }
            let fragment_header = if let Some(range) = &span.fragment_header_range {
                if range.start < payload.start || range.end > payload.end {
                    return Err(HevcDumpError::SourceMap);
                }
                let range = translate(range)?;
                let h = self
                    .input
                    .get(range.clone())
                    .ok_or(HevcDumpError::SourceMap)?;
                if h.len() != 3 {
                    return Err(HevcDumpError::SourceMap);
                }
                let header = [(h[0] & 0x81) | ((h[2] & 63) << 1), h[1]];
                if nal.bytes().get(..2) != Some(header.as_slice()) {
                    return Err(HevcDumpError::SourceMap);
                }
                Some(range)
            } else {
                None
            };
            mapped.push(FileNalSource {
                record: record.index(),
                wire,
                nal: span.nal_range.clone(),
                fragment_header,
            });
        }
        Ok(mapped)
    }

    /// Advance one bounded event, honoring cancellation before any input or timer work.
    pub fn step(&mut self, cx: &ReplayCx) -> HevcDumpStep<'a> {
        if self.stopped {
            return HevcDumpStep::Exhausted;
        }
        if cx.checkpoint("rtpdump:hevc").is_err() {
            self.stopped = true;
            return HevcDumpStep::Cancelled(self.receiver.cancel());
        }
        if let Some(event) = self.progress() {
            return event;
        }
        if self.input_ended {
            self.stopped = true;
            return HevcDumpStep::Exhausted;
        }
        if self.next.is_none() {
            match self.reader.next_record() {
                Ok(Some(record)) => self.next = Some(record),
                Ok(None) => {
                    self.input_ended = true;
                    self.receiver.finish();
                    return HevcDumpStep::InputEnded;
                }
                Err(error) => {
                    self.stopped = true;
                    return HevcDumpStep::FramingRefused {
                        error,
                        cancelled: self.receiver.cancel(),
                    };
                }
            }
        }
        if let Some(record) = &self.next {
            let target = self.now_ns.max(u64::from(record.offset_ms()) * 1_000_000);
            while target > self.now_ns {
                self.now_ns = self
                    .receiver
                    .next_wake_ns()
                    .filter(|wake| *wake > self.now_ns)
                    .map_or(target, |wake| wake.min(target));
                if let Some(event) = self.progress() {
                    return event;
                }
            }
        }
        let Some(source) = self.next.take() else {
            self.stopped = true;
            return HevcDumpStep::Exhausted;
        };
        let offset_reversed = self
            .previous_offset
            .is_some_and(|old| source.offset_ms() < old);
        self.previous_offset = Some(source.offset_ms());
        let admission = if self.fenced {
            HevcDumpAdmission::Fenced
        } else {
            match source.kind() {
                RtpDumpKind::Rtcp => HevcDumpAdmission::Rtcp(
                    RtcpCompound::parse(
                        source.packet(),
                        self.config.reorder.packet,
                        self.config.rtcp,
                    )
                    .map(|_| ()),
                ),
                RtpDumpKind::CapturedPrefix => {
                    self.fenced = true;
                    HevcDumpAdmission::CapturedPrefix(self.receiver.cancel())
                }
                RtpDumpKind::Rtp => {
                    match self
                        .receiver
                        .ingest(self.config.key, source.packet(), self.now_ns)
                    {
                        Ok(receipt) => {
                            let transport = &receipt.transport;
                            if transport.disposition == ReorderDisposition::Buffered {
                                let entry = transport.sequence.extended_sequence.and_then(|seq| {
                                    self.originals
                                        .binary_search_by_key(&seq, |o| o.sequence)
                                        .err()
                                        .map(|i| (seq, i))
                                });
                                match entry {
                                    Some((sequence, i))
                                        if self.originals.len() < self.config.dump.max_records =>
                                    {
                                        self.originals.insert(
                                            i,
                                            Original {
                                                sequence,
                                                record: source.clone(),
                                            },
                                        );
                                        HevcDumpAdmission::Rtp(receipt)
                                    }
                                    _ => {
                                        self.fenced = true;
                                        HevcDumpAdmission::Refused {
                                            error: HevcDumpError::SourceMap,
                                            cancelled: self.receiver.cancel(),
                                        }
                                    }
                                }
                            } else {
                                if transport.disposition == ReorderDisposition::RestartRequired {
                                    self.fenced = true;
                                }
                                HevcDumpAdmission::Rtp(receipt)
                            }
                        }
                        Err(error) => {
                            self.fenced = true;
                            HevcDumpAdmission::Refused {
                                error: HevcDumpError::Receiver(error),
                                cancelled: self.receiver.cancel(),
                            }
                        }
                    }
                }
            }
        };
        HevcDumpStep::Record {
            source,
            offset_reversed,
            admission,
        }
    }

    fn progress(&mut self) -> Option<HevcDumpStep<'a>> {
        if self.fenced {
            return None;
        }
        match self.receiver.poll(self.now_ns) {
            Ok(H265ReceivePoll::Pending { .. }) => None,
            Ok(event) => {
                if matches!(&event, H265ReceivePoll::Ended { .. }) {
                    self.fenced = true;
                    if self.input_ended {
                        self.stopped = true;
                    }
                }
                Some(HevcDumpStep::Progress(event))
            }
            Err(error) => {
                self.fenced = true;
                Some(HevcDumpStep::ReceiverRefused {
                    error,
                    cancelled: self.receiver.cancel(),
                })
            }
        }
    }
}
impl std::fmt::Debug for RecordedHevcReplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordedHevcReplay")
            .field("records", &self.reader.records_read())
            .field("retained_nal_bytes", &self.retained_nal_bytes())
            .field("fenced", &self.fenced)
            .field("stopped", &self.stopped)
            .finish_non_exhaustive()
    }
}

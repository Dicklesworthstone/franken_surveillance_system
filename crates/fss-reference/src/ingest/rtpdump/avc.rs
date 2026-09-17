#![forbid(unsafe_code)]
//! Recorded RTP through the existing ordered AVC picture receiver. This is
//! derivative grouping, never picture decoding, live continuity or source custody.

use fss_packet::{H264Mode, NalUnit, ReorderDisposition, RtcpCompound, RtcpMode, StreamKey};
use fss_packet::avc::{AvcPps, AvcSps, AvcReceiveAdmission, AvcReceiveCancellation,
    AvcReceiveError, AvcReceiveLimits, AvcReceivePoll, AvcReceiver};
use crate::ReplayCx;
use super::{RtpDumpError, RtpDumpKind, RtpDumpLimits, RtpDumpReader, RtpDumpRecord,
    replay::FileNalSource};

/// Separate owner binding, framing and derivative budgets. Exact SPS/PPS are
/// supplied separately, and their source custody remains the caller's obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AvcDumpConfig {
    /// Fresh owner ingress, immutable stream generation and selected SSRC.
    pub key: StreamKey,
    /// Explicit H.264 payload mapping.
    pub payload_type: u8,
    /// Explicit RFC 6184 mode zero or one.
    pub mode: H264Mode,
    /// Original-file bounds, including the total source-map entry count.
    pub dump: RtpDumpLimits,
    /// Existing reorder, reconstruction, syntax and picture-assembly bounds.
    pub receiver: AvcReceiveLimits,
    /// RTCP mode; never broadened after a malformed compound.
    pub rtcp: RtcpMode,
}

/// Payload-free adapter refusal. Original bytes remain owned by the caller.
#[derive(Debug)]
pub enum AvcDumpError {
    /// The original recording cannot be framed under its declared bounds.
    Framing(RtpDumpError),
    /// The real receiver refused configuration or progress.
    Receiver(AvcReceiveError),
    /// The bounded source-map allocation could not be reserved.
    Allocation,
    /// A kernel span could not be proven against its exact admitted original.
    SourceMap,
}
impl std::fmt::Display for AvcDumpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "recorded AVC refusal: {self:?}") }
}
impl std::error::Error for AvcDumpError {}

/// Original record admission, not a decoded picture or continuity certificate.
#[derive(Debug)]
pub enum AvcDumpAdmission {
    /// Exact real-kernel result, including probation, duplicate and restart receipts.
    Rtp(AvcReceiveAdmission),
    /// Full compound validation result; no sender-clock truth is asserted.
    Rtcp(Result<(), fss_packet::PacketError>),
    /// Snaplen lost source bytes. All pending derivative layers are retired.
    CapturedPrefix(AvcReceiveCancellation),
    /// An admission error fenced this attempt; cancellation accounts for pending work.
    Refused { error: AvcDumpError, cancelled: AvcReceiveCancellation },
    /// A prior source/configuration failure or codec end stopped derivative admission.
    /// Original recording records continue to be surfaced without reinterpretation.
    Fenced,
}

/// Each step consumes at most one source record or returns one bounded receiver event.
#[derive(Debug)]
pub enum AvcDumpStep<'a> {
    /// Exact original record, including RTCP, probation, duplicates and refused inputs.
    Record { source: RtpDumpRecord<'a>, offset_reversed: bool, admission: AvcDumpAdmission },
    /// Existing receiver event unchanged, preserving picture boundaries and retirements.
    /// Picture source spans can be mapped with `RecordedAvcReplay::map_nal`.
    Progress(AvcReceivePoll),
    /// Container EOF was reached. Receiver drain/EOF pictures may follow; not quiescence yet.
    InputEnded,
    /// Malformed framing is not clean EOF; no unverified picture tail is manufactured.
    FramingRefused { error: RtpDumpError, cancelled: AvcReceiveCancellation },
    /// Receiver failure is explicit and fences derivatives, not original-record inspection.
    ReceiverRefused { error: AvcReceiveError, cancelled: AvcReceiveCancellation },
    /// Owner cancellation, including all queued packet/NAL/picture retirements.
    Cancelled(AvcReceiveCancellation),
    /// This attempt is terminal and has no further events.
    Exhausted,
}

struct Original<'a> { sequence: u64, record: RtpDumpRecord<'a> }

/// Bounded ordered recorded-media replay. The immutable original file is borrowed,
/// and every ingress record is exposed before any corresponding receiver progress.
///
/// Recorded offsets drive a laboratory timer only: decreasing offsets are reported,
/// and time never reverses. Receiver deadlines are polled BEFORE admitting later
/// input, so a late packet cannot rescue an expired fragment or picture. A capture
/// prefix or admission failure conservatively fences this derivative attempt;
/// subsequent originals are still returned. Reconnect requires a new owner epoch.
pub struct RecordedAvcReplay<'a> {
    input: &'a [u8],
    reader: RtpDumpReader<'a>,
    config: AvcDumpConfig,
    receiver: AvcReceiver,
    originals: Vec<Original<'a>>,
    next: Option<RtpDumpRecord<'a>>,
    now_ns: u64,
    previous_offset: Option<u32>,
    input_ended: bool,
    fenced: bool,
    stopped: bool,
}
impl<'a> RecordedAvcReplay<'a> {
    /// The exact parameter pair must come from retained, explicitly selected
    /// configuration evidence. This adapter never guesses SPS/PPS from malformed input.
    pub fn new(input: &'a [u8], config: AvcDumpConfig, parameters: (AvcSps, AvcPps)) -> Result<Self, AvcDumpError> {
        let reader = RtpDumpReader::new(input, config.dump).map_err(AvcDumpError::Framing)?;
        let receiver = AvcReceiver::new(config.key, config.payload_type, config.mode, config.receiver, parameters)
            .map_err(AvcDumpError::Receiver)?;
        let mut originals = Vec::new();
        originals.try_reserve_exact(config.dump.max_records).map_err(|_| AvcDumpError::Allocation)?;
        Ok(Self { input, reader, config, receiver, originals, next: None, now_ns: 0,
            previous_offset: None, input_ended: false, fenced: false, stopped: false })
    }
    /// Retained derivative bytes, excluding original capture custody and source-map metadata.
    pub fn retained_nal_bytes(&self) -> usize { self.receiver.retained_nal_bytes() }
    /// One original file record for an admitted extended sequence. The first
    /// admitted record wins; duplicates cannot rewrite provenance.
    pub fn source_record(&self, sequence: u64) -> Option<&RtpDumpRecord<'a>> {
        self.originals.binary_search_by_key(&sequence, |o| o.sequence).ok().map(|i| &self.originals[i].record)
    }
    /// Map and verify one emitted or refused NAL against exact original-file spans.
    /// The caller may retain these mappings before dropping this replay instance.
    pub fn map_nal(&self, nal: &NalUnit) -> Result<Vec<FileNalSource>, AvcDumpError> {
        if nal.key() != self.config.key { return Err(AvcDumpError::SourceMap); }
        let mut mapped = Vec::new();
        mapped.try_reserve_exact(nal.sources().len()).map_err(|_| AvcDumpError::Allocation)?;
        for span in nal.sources() {
            let record = self.source_record(span.sequence).ok_or(AvcDumpError::SourceMap)?;
            let packet = record.packet_span();
            let translate = |r: &std::ops::Range<usize>| {
                if r.start > r.end || r.end > packet.len() { Err(AvcDumpError::SourceMap) }
                else { Ok(packet.start + r.start..packet.start + r.end) }
            };
            let wire = translate(&span.wire_range)?;
            if self.input.get(wire.clone()) != nal.bytes().get(span.nal_range.clone()) {
                return Err(AvcDumpError::SourceMap);
            }
            let fragment_header = if let Some(range) = &span.fragment_header_range {
                let range = translate(range)?;
                let h = self.input.get(range.clone()).ok_or(AvcDumpError::SourceMap)?;
                if h.len() != 2 || nal.bytes().first().copied() != Some((h[0] & 0xe0) | (h[1] & 31)) {
                    return Err(AvcDumpError::SourceMap);
                }
                Some(range)
            } else { None };
            mapped.push(FileNalSource { record: record.index(), wire, nal: span.nal_range.clone(), fragment_header });
        }
        Ok(mapped)
    }
    /// Drive one bounded event. Caller retains the complete file independently of
    /// whether any packet, NAL or picture is admitted, fenced, refused or cancelled.
    pub fn step(&mut self, cx: &ReplayCx) -> AvcDumpStep<'a> {
        if self.stopped { return AvcDumpStep::Exhausted; }
        if cx.checkpoint("rtpdump:avc").is_err() {
            self.stopped = true;
            return AvcDumpStep::Cancelled(self.receiver.cancel());
        }
        if let Some(event) = self.progress() { return event; }
        if self.input_ended { self.stopped = true; return AvcDumpStep::Exhausted; }
        if self.next.is_none() {
            match self.reader.next_record() {
                Ok(Some(record)) => self.next = Some(record),
                Ok(None) => {
                    self.input_ended = true; self.receiver.finish();
                    return AvcDumpStep::InputEnded;
                }
                Err(error) => {
                    self.stopped = true;
                    return AvcDumpStep::FramingRefused { error, cancelled: self.receiver.cancel() };
                }
            }
        }
        // A receiver timeout may produce several bounded retirement events before
        // this still-borrowed source record is admitted. Do not consume it twice.
        if let Some(record) = &self.next {
            let target = self.now_ns.max(u64::from(record.offset_ms()) * 1_000_000);
            if target > self.now_ns {
                self.now_ns = target;
                if let Some(event) = self.progress() { return event; }
            }
        }
        let Some(source) = self.next.take() else { self.stopped = true; return AvcDumpStep::Exhausted; };
        let offset_reversed = self.previous_offset.is_some_and(|old| source.offset_ms() < old);
        self.previous_offset = Some(source.offset_ms());
        let admission = if self.fenced { AvcDumpAdmission::Fenced } else {
            match source.kind() {
                RtpDumpKind::Rtcp => AvcDumpAdmission::Rtcp(RtcpCompound::parse(source.packet(),
                    self.config.receiver.reorder.packet, self.config.rtcp).map(|_| ())),
                RtpDumpKind::CapturedPrefix => {
                    self.fenced = true; AvcDumpAdmission::CapturedPrefix(self.receiver.cancel())
                }
                RtpDumpKind::Rtp => match self.receiver.ingest(self.config.key, source.packet(), self.now_ns) {
                    Ok(receipt) => {
                        let transport = &receipt.transport.transport;
                        if transport.disposition == ReorderDisposition::Buffered {
                            match transport.sequence.extended_sequence.and_then(|seq|
                                self.originals.binary_search_by_key(&seq, |o| o.sequence).err().map(|i| (seq, i))) {
                                Some((sequence, i)) if self.originals.len() < self.config.dump.max_records => {
                                    self.originals.insert(i, Original { sequence, record: source.clone() });
                                    AvcDumpAdmission::Rtp(receipt)
                                }
                                _ => {
                                    self.fenced = true;
                                    AvcDumpAdmission::Refused { error: AvcDumpError::SourceMap, cancelled: self.receiver.cancel() }
                                }
                            }
                        } else {
                            if transport.disposition == ReorderDisposition::RestartRequired { self.fenced = true; }
                            AvcDumpAdmission::Rtp(receipt)
                        }
                    }
                    Err(error) => {
                        self.fenced = true;
                        AvcDumpAdmission::Refused { error: AvcDumpError::Receiver(error), cancelled: self.receiver.cancel() }
                    }
                },
            }
        };
        AvcDumpStep::Record { source, offset_reversed, admission }
    }
    fn progress(&mut self) -> Option<AvcDumpStep<'a>> {
        if self.fenced { return None; }
        match self.receiver.poll(self.now_ns) {
            Ok(AvcReceivePoll::Pending { .. }) => None,
            Ok(event) => {
                if matches!(&event, AvcReceivePoll::Ended { .. }) {
                    self.fenced = true;
                    if self.input_ended { self.stopped = true; }
                }
                Some(AvcDumpStep::Progress(event))
            }
            Err(error) => {
                self.fenced = true;
                Some(AvcDumpStep::ReceiverRefused { error, cancelled: self.receiver.cancel() })
            }
        }
    }
}
impl std::fmt::Debug for RecordedAvcReplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordedAvcReplay").field("records", &self.reader.records_read())
            .field("retained_nal_bytes", &self.retained_nal_bytes()).field("fenced", &self.fenced)
            .field("stopped", &self.stopped).finish_non_exhaustive()
    }
}

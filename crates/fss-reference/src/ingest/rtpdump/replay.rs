#![forbid(unsafe_code)]
//! Recorded original packets through the real sequence and H.264 kernels.

use std::ops::Range;
use fss_packet::{ContinuityError, FragmentDiscard, H264Depacketizer, H264Failure,
    H264Limits, H264Mode, H264Status, NalUnit, PacketError, PacketLimits,
    RtcpCompound, RtcpMode, RtpPacket, SequenceClass, SequenceObservation,
    SequenceStats, SequenceTracker, StreamKey};
use crate::adapter_replay::ReplayCx;
use super::{RtpDumpError, RtpDumpKind, RtpDumpLimits, RtpDumpReader, RtpDumpRecord};

/// Explicit binding supplied by the import owner. No payload/SSRC is guessed
/// from untrusted capture headers; source changes require a newly authorized scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtpReplayConfig {
    /// Owner-issued input binding and generation, plus expected SSRC.
    pub key: StreamKey,
    /// Explicit H.264 payload mapping.
    pub payload_type: u8,
    /// Explicit RFC 6184 packetization mode.
    pub mode: H264Mode,
    /// Container bounds, including maximum metadata entries retained for source mapping.
    pub dump: RtpDumpLimits,
    /// Packet parser bounds.
    pub packet: PacketLimits,
    /// Fragment reconstruction bounds.
    pub codec: H264Limits,
    /// Recorded RTCP interpretation. Reduced size is never guessed after failure.
    pub rtcp: RtcpMode,
}

impl RtpReplayConfig {
    /// Validate all owner/parser/reconstruction policies without reading or
    /// retaining source bytes. File entrypoints use this before opening input.
    pub fn validate(self) -> Result<(), RtpReplayError> {
        self.dump.validate().map_err(RtpReplayError::Dump)?;
        self.packet.validate().map_err(RtpReplayError::Packet)?;
        SequenceTracker::new(self.key, self.payload_type).map_err(RtpReplayError::Continuity)?;
        H264Depacketizer::new(self.key, self.payload_type, self.mode, self.codec)
            .map_err(RtpReplayError::Codec)?;
        Ok(())
    }
}

/// Exact original-file copy and synthesis inputs for one reconstructed NAL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileNalSource {
    /// Zero-based original record index, not an arrival-order replacement for RTP sequence.
    pub record: usize,
    /// Copied bytes in the ORIGINAL rtpdump file.
    pub wire: Range<usize>,
    /// Corresponding reconstructed NAL range.
    pub nal: Range<usize>,
    /// Original FU indicator/header when byte zero is synthesized, not copied.
    pub fragment_header: Option<Range<usize>>,
}

/// A transport-reconstructed NAL plus exact original-file provenance.
/// This is not a decoded picture, an access-unit certificate, or a source-custody receipt.
#[derive(Debug, Eq, PartialEq)]
pub struct ReplayedNal {
    /// Kernel-owned complete NAL, without invented Annex-B bytes.
    pub nal: NalUnit,
    /// Verified original-file offsets, retaining FU header synthesis separately.
    pub sources: Vec<FileNalSource>,
}

/// Packet outcome. Originals are returned with every outcome, including refusals.
#[derive(Debug)]
pub enum RtpRecordOutcome {
    /// Snaplen-truncated original is retained but never parsed as a full packet.
    CapturedPrefix,
    /// Validated RTCP compound; no sender time is promoted into capture truth.
    Rtcp,
    /// Packet parsing failed with its exact typed reason.
    PacketRefused(PacketError),
    /// Owner binding or sequence epoch refused admission; never silently restart.
    StreamRefused(ContinuityError),
    /// Sequence observation was not delivered (probation, duplicate, or restart requirement).
    SequenceOnly(SequenceObservation),
    /// H.264 syntax/reconstruction refused a sequence-validated packet.
    CodecRefused {
        /// Sequence accounting from the packet kernel for this refused packet.
        observation: SequenceObservation,
        /// The typed H.264 syntax or reconstruction refusal.
        failure: H264Failure,
    },
    /// Existing packet kernel's success, including explicit ignored out-of-order input.
    H264 {
        /// Original sequence accounting, not a camera-coverage claim.
        observation: SequenceObservation,
        /// Complete, fragment-pending, or ignored-nonincreasing status.
        status: H264Status,
        /// Complete mapped NALs only.
        nals: Vec<ReplayedNal>,
        /// Missing delivery before this packet; late input never erases this fact.
        gap_before: bool,
    },
}

/// One record's processing receipt, preserving access to its exact original bytes.
#[derive(Debug)]
pub struct ReplayedRecord<'a> {
    /// Unmodified container record, including RTCP and unadmitted originals.
    pub source: RtpDumpRecord<'a>,
    /// Recorded offset decreased; it was not treated as reversed owner receive time.
    pub offset_reversed: bool,
    /// Expiry checked BEFORE admitting this record, so a late final FU cannot escape it.
    pub expired: Option<FragmentDiscard>,
    /// Fragment retired by this record's gap, invalid packet, or codec event.
    pub discarded: Option<FragmentDiscard>,
    /// Exact typed processing result.
    pub outcome: RtpRecordOutcome,
}

/// One bounded progress result. A framing fault can never turn into a clean EOF.
#[derive(Debug)]
pub enum RtpReplayStep<'a> {
    /// One original source record and zero or more complete transport NALs.
    /// Boxed so the terminal and refusal variants stay small to construct and match.
    Record(Box<ReplayedRecord<'a>>),
    /// Framing failed after any previous successful records; unparsed suffix remains source.
    FramingRefused {
        /// The exact container framing failure; never coerced into a clean EOF.
        error: RtpDumpError,
        /// Fragment retired by the framing fault, if one was pending.
        discarded: Option<FragmentDiscard>,
    },
    /// Clean file EOF; an incomplete fragment is explicitly retired, never emitted as a NAL.
    Ended {
        /// Final sequence statistics over all admitted packets.
        stats: SequenceStats,
        /// Incomplete fragment retired at EOF, if one was pending.
        discarded: Option<FragmentDiscard>,
    },
    /// Owner cancellation. Caller still owns the entire source snapshot.
    Cancelled {
        /// Fragment retired by the cancellation, if one was pending.
        discarded: Option<FragmentDiscard>,
    },
    /// This attempt already returned a terminal state. It has not verified new input.
    Exhausted,
}

/// Failures of constructing or maintaining the replay adapter itself; input remains borrowed.
#[derive(Debug)]
pub enum RtpReplayError {
    /// Container/header/bound failure before processing.
    Dump(RtpDumpError),
    /// Invalid packet parser configuration.
    Packet(PacketError),
    /// Invalid explicit stream configuration.
    Continuity(ContinuityError),
    /// Invalid reconstruction configuration or impossible clock step.
    Codec(H264Failure),
    /// A bounded metadata/output allocation failed.
    Allocation,
    /// The kernel's source mappings could not be proven against the original file.
    SourceMap,
}
impl std::fmt::Display for RtpReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "rtpdump replay refusal: {self:?}") }
}
impl std::error::Error for RtpReplayError {}

struct AdmittedSource { sequence: u64, record: usize, packet: Range<usize> }

/// Incremental, bounded file replay. One call consumes at most one record.
///
/// Reordering is classified but not repaired: the existing depacketizer ignores
/// nonincreasing sequence input. The capture-offset clock is a LABORATORY timer:
/// max(recorded offsets so far) in nanoseconds. Neither it nor the file's header
/// timestamp becomes FSS receive time, camera capture time, DTS, or a continuity witness.
pub struct RtpDumpReplay<'a> {
    input: &'a [u8],
    reader: RtpDumpReader<'a>,
    config: RtpReplayConfig,
    sequence: SequenceTracker,
    codec: H264Depacketizer,
    admitted: Vec<AdmittedSource>,
    now_ns: u64,
    previous_offset: Option<u32>,
    stopped: bool,
}
impl<'a> RtpDumpReplay<'a> {
    /// Bind one recorded source epoch. Construction performs no I/O or source publication.
    pub fn new(input: &'a [u8], config: RtpReplayConfig) -> Result<Self, RtpReplayError> {
        let reader = RtpDumpReader::new(input, config.dump).map_err(RtpReplayError::Dump)?;
        config.packet.validate().map_err(RtpReplayError::Packet)?;
        let sequence = SequenceTracker::new(config.key, config.payload_type).map_err(RtpReplayError::Continuity)?;
        let codec = H264Depacketizer::new(config.key, config.payload_type, config.mode, config.codec)
            .map_err(RtpReplayError::Codec)?;
        // Reserve mapping metadata BEFORE consuming any input. Each admitted source
        // consumes exactly one entry, independent of NAL count or fragment length.
        let mut admitted = Vec::new();
        admitted.try_reserve_exact(config.dump.max_records).map_err(|_| RtpReplayError::Allocation)?;
        Ok(Self { input, reader, config, sequence, codec, admitted,
            now_ns: 0, previous_offset: None, stopped: false })
    }
    /// Current packet accounting. Missing positions remain provisional, never physical absence.
    pub fn stats(&self) -> SequenceStats { self.sequence.stats() }
    /// Retained incomplete derivative bytes, separate from caller-owned original custody.
    pub fn pending_bytes(&self) -> usize { self.codec.pending_bytes() }
    /// Complete source records consumed so far, including refused media.
    pub fn records_read(&self) -> usize { self.reader.records_read() }
    /// Process at most one recorded input with a real reference cancellation checkpoint.
    pub fn step(&mut self, cx: &ReplayCx) -> Result<RtpReplayStep<'a>, RtpReplayError> {
        if self.stopped { return Ok(RtpReplayStep::Exhausted); }
        cx.reach_stage("rtpdump:record");
        if cx.is_cancelled() {
            let discarded = self.cancel();
            cx.drain_and_finalize();
            return Ok(RtpReplayStep::Cancelled { discarded });
        }
        let result = self.advance();
        // Caller can still explicitly cancel to retrieve a pending fragment receipt.
        if result.is_err() { self.stopped = true; }
        result
    }
    /// Stop only this adapter and return the pending derivative receipt. No source is deleted.
    pub fn cancel(&mut self) -> Option<FragmentDiscard> {
        self.stopped = true;
        self.codec.cancel()
    }
    fn advance(&mut self) -> Result<RtpReplayStep<'a>, RtpReplayError> {
        let source = match self.reader.next_record() {
            Ok(Some(source)) => source,
            Ok(None) => {
                self.stopped = true;
                return Ok(RtpReplayStep::Ended { stats: self.sequence.stats(), discarded: self.codec.finish() });
            }
            Err(error) => {
                self.stopped = true;
                return Ok(RtpReplayStep::FramingRefused { error, discarded: self.codec.finish() });
            }
        };
        let offset_reversed = self.previous_offset.is_some_and(|prev| source.offset_ms() < prev);
        self.previous_offset = Some(source.offset_ms());
        self.now_ns = self.now_ns.max(u64::from(source.offset_ms()) * 1_000_000);
        let expired = self.codec.expire(self.now_ns).map_err(RtpReplayError::Codec)?;
        let mut discarded = None;
        let outcome = match source.kind() {
            RtpDumpKind::CapturedPrefix => {
                discarded = self.codec.discard_gap();
                RtpRecordOutcome::CapturedPrefix
            }
            RtpDumpKind::Rtcp => match RtcpCompound::parse(source.packet(), self.config.packet, self.config.rtcp) {
                Ok(_) => RtpRecordOutcome::Rtcp,
                Err(error) => RtpRecordOutcome::PacketRefused(error),
            },
            RtpDumpKind::Rtp => match RtpPacket::parse(source.packet(), self.config.packet) {
                Err(error) => { discarded = self.codec.discard_gap(); RtpRecordOutcome::PacketRefused(error) }
                Ok(packet) => match self.sequence.observe(self.config.key, packet) {
                    Err(error) => { discarded = self.codec.discard_gap(); RtpRecordOutcome::StreamRefused(error) }
                    Ok(observation) if !observation.is_unique() => {
                        if matches!(observation.class, SequenceClass::DiscontinuitySuspected | SequenceClass::RestartRequired) {
                            discarded = self.codec.discard_gap();
                        }
                        RtpRecordOutcome::SequenceOnly(observation)
                    }
                    Ok(observation) => {
                        let sequence = observation.extended_sequence.ok_or(RtpReplayError::SourceMap)?;
                        if matches!(observation.class, SequenceClass::Baseline | SequenceClass::Advanced) {
                            self.admitted.push(AdmittedSource { sequence, record: source.index(), packet: source.packet_span() });
                        }
                        match self.codec.push(self.config.key, sequence, packet, self.now_ns) {
                            Err(mut failure) => {
                                discarded = failure.discarded.take();
                                RtpRecordOutcome::CodecRefused { observation, failure }
                            }
                            Ok(output) => {
                                discarded = output.discarded;
                                let mut nals = Vec::new();
                                nals.try_reserve_exact(output.nals.len()).map_err(|_| RtpReplayError::Allocation)?;
                                for nal in output.nals { nals.push(self.map_nal(nal)?); }
                                RtpRecordOutcome::H264 { observation, status: output.status, nals, gap_before: output.gap_before }
                            }
                        }
                    }
                },
            },
        };
        Ok(RtpReplayStep::Record(Box::new(ReplayedRecord { source, offset_reversed, expired, discarded, outcome })))
    }
    fn map_nal(&self, nal: NalUnit) -> Result<ReplayedNal, RtpReplayError> {
        let mut sources = Vec::new();
        sources.try_reserve_exact(nal.sources().len()).map_err(|_| RtpReplayError::Allocation)?;
        for span in nal.sources() {
            let index = self.admitted.binary_search_by_key(&span.sequence, |s| s.sequence)
                .map_err(|_| RtpReplayError::SourceMap)?;
            let source = &self.admitted[index];
            let translate = |range: &Range<usize>| -> Result<Range<usize>, RtpReplayError> {
                if range.start > range.end || range.end > source.packet.len() { return Err(RtpReplayError::SourceMap); }
                Ok(source.packet.start + range.start..source.packet.start + range.end)
            };
            let wire = translate(&span.wire_range)?;
            let original = self.input.get(wire.clone()).ok_or(RtpReplayError::SourceMap)?;
            let reconstructed = nal.bytes().get(span.nal_range.clone()).ok_or(RtpReplayError::SourceMap)?;
            if original != reconstructed { return Err(RtpReplayError::SourceMap); }
            let fragment_header = match &span.fragment_header_range {
                Some(range) => {
                    let range = translate(range)?;
                    let header = self.input.get(range.clone()).ok_or(RtpReplayError::SourceMap)?;
                    if header.len() != 2 || nal.bytes().first().copied() != Some((header[0] & 0xe0) | (header[1] & 31)) {
                        return Err(RtpReplayError::SourceMap);
                    }
                    Some(range)
                }
                None => None,
            };
            sources.push(FileNalSource { record: source.record, wire, nal: span.nal_range.clone(), fragment_header });
        }
        Ok(ReplayedNal { nal, sources })
    }
}
impl std::fmt::Debug for RtpDumpReplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RtpDumpReplay").field("reader", &self.reader)
            .field("stats", &self.stats()).field("pending_bytes", &self.pending_bytes())
            .field("stopped", &self.stopped).finish_non_exhaustive()
    }
}

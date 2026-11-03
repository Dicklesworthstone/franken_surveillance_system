#![forbid(unsafe_code)]
//! One replay implementation for initial import and current retained-origin verification.

use super::*;
use crate::rtsp::datagram_reconstruction::jpeg::{
    DatagramJpegReplay, JpegReplayBounds, JpegReplayStep,
};
use fss_core::CanonicalEncoder;
use fss_packet::{
    ReorderDisposition, ReorderGapReason,
    jpeg::{JpegDiscard, JpegError, JpegReceiveError, JpegReceivePoll},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct FrameOrigin {
    pub encoded: ContentDigest,
    pub bytes: u64,
    pub gap_before: bool,
    pub provenance: ContentDigest,
    pub lineage: Vec<u8>,
}

pub(super) struct Reconstruction {
    pub interpretation: ContentDigest,
    pub media: Vec<u8>,
    pub frames: Vec<FrameOrigin>,
    pub diagnostics: Vec<u8>,
    pub accounting: JpegImportAccounting,
    pub terminal: JpegImportTerminal,
    pub steps: u64,
}

// Original custody traversal has its own caller budget. Excluding only work charged
// INSIDE that callback keeps the intrinsic codec/scheduler admission identical for
// a capture publisher and a destination with a different tombstone inventory.
struct MeasuredReader<'a> {
    inner: &'a mut dyn DatagramObjectReader,
    read_work: u64,
}
impl DatagramObjectReader for MeasuredReader<'_> {
    fn read_object(
        &mut self,
        digest: ContentDigest,
        maximum: usize,
        cancel: &dyn PublishCancellation,
        work: &mut WorkBudget<'_>,
    ) -> Result<Vec<u8>, DatagramArchiveError> {
        let before = work.used();
        let result = self.inner.read_object(digest, maximum, cancel, work);
        self.read_work += work.used() - before;
        result
    }
}

pub(super) fn reconstruct(
    prefix: &DetachedDatagramPrefix,
    request: &JpegImportRequest,
    reader: &mut dyn DatagramObjectReader,
    access: &dyn PublishCancellation,
    work: &mut WorkBudget<'_>,
) -> Result<Reconstruction, JpegImportError> {
    let start = work.used();
    let mut reader = MeasuredReader {
        inner: reader,
        read_work: 0,
    };
    let mut replay = DatagramJpegReplay::new_detached(
        prefix,
        request.replay,
        JpegReplayBounds {
            max_source_bytes: request.archive_limits.max_payload_bytes,
            max_steps: request.max_steps,
            // Real current deadline/cancellation is supplied by access at every boundary.
            // Zero is only a constant replay-storage coordinate, never camera/receive time.
            deadline_ns: u64::MAX,
        },
        0,
    )
    .map_err(source_error)?;
    let interpretation = replay.interpretation();
    let mut media = Vec::new();
    let mut frames = Vec::new();
    let mut diagnostics = Vec::new();
    let mut lineage_bytes = 0usize;
    let mut accounting = JpegImportAccounting::default();
    let mut pending_gap = false;
    for steps in 1..=request.max_steps {
        work.charge(0).map_err(source_error)?;
        let step = replay
            .step_detached(&mut reader, 0, access, work)
            .map_err(source_error)?;
        // The same intrinsic ceiling is mandatory at import and every later cold
        // verification. A larger caller allowance cannot publish an unreadable import.
        if work.used() - start - reader.read_work > MAX_REPLAY_WORK {
            return Err(JpegImportError::Limit("intrinsic cold replay work"));
        }
        let mut event = CanonicalEncoder::new();
        match step {
            JpegReplayStep::Rtp {
                source,
                admission,
                retired,
            } => {
                accounting.rtp_datagrams += 1;
                event.tag(0);
                event.u64(source.record().pin.datagrams);
                let tag = match admission.transport.disposition {
                    ReorderDisposition::Buffered => 0,
                    ReorderDisposition::NotAdmitted => {
                        pending_gap = true;
                        1
                    }
                    ReorderDisposition::Duplicate => 2,
                    ReorderDisposition::TooLate => {
                        pending_gap = true;
                        3
                    }
                    ReorderDisposition::RestartRequired => {
                        return Err(JpegImportError::Invalid("source restart"));
                    }
                };
                event.tag(tag);
                if retired.is_some() || admission.transport.discarded.is_some() {
                    return Err(JpegImportError::Invalid("source restart retirement"));
                }
                note_discard(
                    &mut event,
                    admission.discarded.as_ref(),
                    &mut accounting,
                    &mut pending_gap,
                );
            }
            JpegReplayStep::Rtcp { source, validation } => {
                accounting.rtcp_datagrams += 1;
                accounting.invalid_rtcp_datagrams += u64::from(validation.is_err());
                event.tag(1);
                event.u64(source.record().pin.datagrams);
                event.bool(validation.is_ok());
                event.u64(validation.unwrap_or(0) as u64);
            }
            JpegReplayStep::Media {
                replay_ns,
                event: media_event,
                provenance,
            } => {
                event.tag(2);
                event.u64(replay_ns);
                match media_event {
                    JpegReceivePoll::Packet {
                        source,
                        reconstruction,
                    } => {
                        accounting.ordered_packets += 1;
                        event.tag(0);
                        event.u64(source.sequence());
                        match reconstruction {
                            Ok(output) => {
                                event.bool(true);
                                note_discard(
                                    &mut event,
                                    output.discarded.as_ref(),
                                    &mut accounting,
                                    &mut pending_gap,
                                );
                                pending_gap |= output.gap_before;
                                event.bool(output.frame.is_some());
                                if let Some(frame) = output.frame {
                                    if frames.len() >= request.max_frames {
                                        return Err(JpegImportError::Limit("complete frames"));
                                    }
                                    let native = provenance
                                        .ok_or(JpegImportError::Invalid("missing frame lineage"))?;
                                    if native.source() != request.pin
                                        || native.interpretation() != interpretation
                                        || native.capture_clock().is_some()
                                    {
                                        return Err(JpegImportError::Invalid(
                                            "native frame source binding",
                                        ));
                                    }
                                    let lineage = native
                                        .canonical_bytes(&frame, work)
                                        .map_err(source_error)?;
                                    lineage_bytes = lineage_bytes
                                        .checked_add(lineage.len())
                                        .ok_or(JpegImportError::Limit("frame lineage"))?;
                                    let bytes = frame.bytes();
                                    if lineage_bytes > MAX_PROOF_BYTES / 2
                                        || media.len() as u64 + bytes.len() as u64
                                            > request.max_media_bytes
                                    {
                                        return Err(JpegImportError::Limit(
                                            "reconstructed bytes or lineage",
                                        ));
                                    }
                                    work.charge((bytes.len() + lineage.len()) as u64)
                                        .map_err(source_error)?;
                                    media
                                        .try_reserve(bytes.len())
                                        .map_err(|_| JpegImportError::Limit("media allocation"))?;
                                    media.extend_from_slice(bytes);
                                    event.digest(native.digest());
                                    event.bool(pending_gap);
                                    frames.push(FrameOrigin {
                                        encoded: native.encoded_digest(),
                                        bytes: bytes.len() as u64,
                                        gap_before: pending_gap,
                                        provenance: native.digest(),
                                        lineage,
                                    });
                                    pending_gap = false;
                                } else if provenance.is_some() {
                                    return Err(JpegImportError::Invalid("lineage without frame"));
                                }
                            }
                            Err(JpegReceiveError::Codec(failure)) => {
                                event.bool(false);
                                event.text(reason(failure.reason));
                                accounting.codec_refusals += 1;
                                pending_gap = true;
                                note_discard(
                                    &mut event,
                                    failure.discarded.as_ref(),
                                    &mut accounting,
                                    &mut pending_gap,
                                );
                            }
                            Err(_) => {
                                return Err(JpegImportError::Invalid("ordered packet refusal"));
                            }
                        }
                    }
                    JpegReceivePoll::Gap { gap, discarded } => {
                        accounting.gap_events += 1;
                        pending_gap = true;
                        event.tag(1);
                        event.u64(gap.first_sequence);
                        event.u64(gap.last_sequence);
                        event.text(match gap.reason {
                            ReorderGapReason::Deadline => "deadline",
                            ReorderGapReason::EndOfInput => "end_of_input",
                        });
                        note_discard(
                            &mut event,
                            discarded.as_ref(),
                            &mut accounting,
                            &mut pending_gap,
                        );
                    }
                    JpegReceivePoll::JpegDiscarded(discarded) => {
                        event.tag(2);
                        note_discard(
                            &mut event,
                            Some(&discarded),
                            &mut accounting,
                            &mut pending_gap,
                        );
                    }
                    JpegReceivePoll::Pending { wake_at_ns } => {
                        event.tag(3);
                        option_u64(&mut event, wake_at_ns);
                    }
                    JpegReceivePoll::Ended { .. } => {
                        return Err(JpegImportError::Invalid("native receiver ended"));
                    }
                }
            }
            JpegReplayStep::ClockAdvanced { replay_ns } => {
                event.tag(3);
                event.u64(replay_ns);
            }
            JpegReplayStep::PrefixExhausted {
                source,
                replay_ns,
                retired,
            } => {
                if source != request.pin || replay.observations_read() != request.pin.datagrams {
                    return Err(JpegImportError::Invalid("incomplete selected prefix"));
                }
                let terminal = JpegImportTerminal {
                    replay_ns,
                    queue_packets: retired.queue.packets,
                    queue_bytes: retired.queue.bytes,
                    queue_first_sequence: retired.queue.first_sequence,
                    queue_last_sequence: retired.queue.last_sequence,
                    gap_pending: pending_gap
                        || retired.queue.packets > 0
                        || retired.fragment.is_some(),
                    fragment: retired.fragment.as_ref().map(discard),
                };
                event.tag(4);
                event.u64(replay_ns);
                event.u64(terminal.queue_packets as u64);
                event.u64(terminal.queue_bytes as u64);
                option_u64(&mut event, terminal.queue_first_sequence);
                option_u64(&mut event, terminal.queue_last_sequence);
                event.bool(terminal.gap_pending);
                event.bool(retired.fragment.is_some());
                if let Some(value) = &retired.fragment {
                    encode_discard(&mut event, value);
                }
                append(&mut diagnostics, event)?;
                if frames.is_empty() {
                    return Err(JpegImportError::NoCompleteFrames);
                }
                work.charge(0).map_err(source_error)?;
                if work.used() - start - reader.read_work > MAX_REPLAY_WORK {
                    return Err(JpegImportError::Limit("intrinsic cold replay work"));
                }
                return Ok(Reconstruction {
                    interpretation,
                    media,
                    frames,
                    diagnostics,
                    accounting,
                    terminal,
                    steps,
                });
            }
            JpegReplayStep::InputRefused { .. } => {
                return Err(JpegImportError::Invalid("original input refused"));
            }
            JpegReplayStep::CodecEnded { .. } => {
                return Err(JpegImportError::Invalid("source epoch ended"));
            }
            JpegReplayStep::Ended => {
                return Err(JpegImportError::Invalid("repeated terminal replay"));
            }
        }
        append(&mut diagnostics, event)?;
        if work.used() - start - reader.read_work > MAX_REPLAY_WORK {
            return Err(JpegImportError::Limit("intrinsic cold replay work"));
        }
    }
    Err(JpegImportError::Limit("replay steps"))
}

fn append(bytes: &mut Vec<u8>, event: CanonicalEncoder) -> Result<(), JpegImportError> {
    let value = event.finish_checked()?;
    if bytes.len() + value.len() > MAX_PROOF_BYTES / 4 {
        return Err(JpegImportError::Limit("replay accounting"));
    }
    bytes
        .try_reserve(value.len())
        .map_err(|_| JpegImportError::Limit("accounting allocation"))?;
    bytes.extend_from_slice(&value);
    Ok(())
}
fn note_discard(
    e: &mut CanonicalEncoder,
    value: Option<&JpegDiscard>,
    a: &mut JpegImportAccounting,
    gap: &mut bool,
) {
    e.bool(value.is_some());
    if let Some(value) = value {
        a.fragment_discards += 1;
        *gap = true;
        encode_discard(e, value);
    }
}
fn encode_discard(e: &mut CanonicalEncoder, value: &JpegDiscard) {
    e.text(reason(value.reason));
    e.u64(value.first_sequence);
    e.u64(value.last_sequence);
    e.u64(value.byte_len as u64);
    e.u64(value.fragments as u64);
}
fn discard(value: &JpegDiscard) -> JpegImportDiscard {
    JpegImportDiscard {
        reason: reason(value.reason),
        first_sequence: value.first_sequence,
        last_sequence: value.last_sequence,
        bytes: value.byte_len,
        fragments: value.fragments,
    }
}
fn option_u64(e: &mut CanonicalEncoder, value: Option<u64>) {
    e.bool(value.is_some());
    if let Some(v) = value {
        e.u64(v);
    }
}
fn reason(value: JpegError) -> &'static str {
    match value {
        JpegError::Configuration => "configuration",
        JpegError::StreamMismatch => "stream_mismatch",
        JpegError::Closed => "closed",
        JpegError::ClockReversed => "clock_reversed",
        JpegError::Malformed => "malformed",
        JpegError::Unsupported => "unsupported",
        JpegError::Limit => "limit",
        JpegError::Allocation => "allocation",
        JpegError::Gap => "gap",
        JpegError::MissingStart => "missing_start",
        JpegError::FragmentMismatch => "fragment_mismatch",
        JpegError::MissingQuantizers => "missing_quantizers",
        JpegError::QuantizerConflict => "quantizer_conflict",
        JpegError::Interrupted => "interrupted",
        JpegError::Deadline => "deadline",
        JpegError::Cancelled => "cancelled",
        JpegError::EndOfInput => "end_of_input",
    }
}

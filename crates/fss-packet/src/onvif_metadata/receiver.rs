#![forbid(unsafe_code)]
//! The existing owner-bound RTP reorder model composed with ONVIF document reconstruction.

use std::fmt;

use super::{
    Assembler, OnvifMetadataDiscard, OnvifMetadataDiscardReason, OnvifMetadataError,
    OnvifMetadataFailure, OnvifMetadataLimits, OnvifMetadataOutput,
};
use crate::{
    ContinuityError, OrderedRtpPacket, QueueDiscard, ReorderAdmission, ReorderDisposition,
    ReorderError, ReorderGap, ReorderLimits, ReorderPoll, RtpReorderBuffer, SequenceStats,
    StreamKey,
};

/// Payload-free receiver refusal; terminal wire ambiguity explicitly accounts for retired state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OnvifMetadataReceiveError {
    /// Transactional transport refusal, with no queue/reconstruction mutation.
    Transport(ReorderError),
    /// Invalid reconstruction configuration or processing time.
    Reconstruction(OnvifMetadataFailure),
    /// Malformed framing or conflicting queued source closed this receiver.
    Invalidated {
        /// Exact transport reason; no untrusted bytes or text are printed.
        cause: ReorderError,
        /// Both derivative layers were retired; source custody remains the owner's.
        retired: OnvifMetadataReceiveCancellation,
    },
}
impl fmt::Display for OnvifMetadataReceiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ONVIF metadata receiver refusal: {self:?}")
    }
}
impl std::error::Error for OnvifMetadataReceiveError {}

/// Transport disposition and any incomplete document retired by a confirmed restart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnvifMetadataReceiveAdmission {
    /// Original sequence observation, delivery admission and queue retirement.
    pub transport: ReorderAdmission,
    /// Candidate retired when transport requires a new stream generation.
    pub discarded: Option<OnvifMetadataDiscard>,
}

/// One bounded unit of original-packet delivery and document reconstruction.
#[derive(Debug, Eq, PartialEq)]
pub enum OnvifMetadataReceivePoll {
    /// Original source remains available even when reconstruction refuses this packet.
    Packet {
        /// Exact admitted datagram with original owner receive time and extended sequence.
        source: OrderedRtpPacket,
        /// Synchronization/pending state or one complete marker-delimited document.
        reconstruction: Result<OnvifMetadataOutput, OnvifMetadataFailure>,
    },
    /// A delivery hole retires incomplete bytes and requires a new marker boundary.
    Gap {
        /// Exact missing delivery range; not a claim of physical absence.
        gap: ReorderGap,
        /// Any candidate interrupted by that delivery gap.
        discarded: Option<OnvifMetadataDiscard>,
    },
    /// A fixed document deadline expired without requiring another packet arrival.
    DocumentDiscarded(OnvifMetadataDiscard),
    /// Owner should wait for input or arrange the declared timer wake.
    Pending {
        /// Earliest queue/reconstruction deadline; absent when no timer work exists.
        wake_at_ns: Option<u64>,
    },
    /// Input is closed and drained; retirement is emitted only once.
    Ended {
        /// Trailing candidate without its closing marker, if one existed.
        discarded: Option<OnvifMetadataDiscard>,
    },
}

/// Explicit retirement of all receiver-owned derivatives on owner stop or invalidation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnvifMetadataReceiveCancellation {
    /// Queued original datagrams retired through the reorder owner's cancellation boundary.
    pub queue: QueueDiscard,
    /// Incomplete candidate and its precise invalidator, when present.
    pub document: Option<OnvifMetadataDiscard>,
    /// Why this receiver closed, also preserved when no candidate was pending.
    pub reason: OnvifMetadataDiscardReason,
}

/// Deterministic bounded receiver for one negotiated uncompressed ONVIF RTP stream.
///
/// This owner reuses the standard packet parser, sequence validation and reorder
/// buffer. Initial probation and an unknown partial document are never published.
/// After the first delivered marker, contiguous packets form the next document.
/// RTP timestamp changes never split or join documents. XML/schema validation is
/// separate: completed transport bytes are not yet vendor observations.
///
/// The adapter retains every original record independently, including malformed,
/// duplicate, probation and too-late packets. It can map each first `Buffered`
/// admission's extended sequence to its original record ordinal; document spans
/// and their preceding boundary use that same epoch-bound sequence namespace.
/// Poll after admissions and on timer wakes, including periods with no new input.
pub struct OnvifMetadataReceiver {
    reorder: RtpReorderBuffer,
    assembler: Assembler,
    last_now_ns: u64,
    ended: bool,
}
impl fmt::Debug for OnvifMetadataReceiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnvifMetadataReceiver")
            .field("reorder", &self.reorder)
            .field("pending_document_bytes", &self.pending_document_bytes())
            .field("last_now_ns", &self.last_now_ns)
            .field("ended", &self.ended)
            .finish_non_exhaustive()
    }
}
impl OnvifMetadataReceiver {
    /// Validate one owner stream and independent transport/document limits.
    /// The caller must independently select uncompressed `vnd.onvif.metadata/90000`.
    /// Compressed gzip/EXI encodings must not be admitted through this receiver.
    pub fn new(
        key: StreamKey,
        payload_type: u8,
        reorder_limits: ReorderLimits,
        metadata_limits: OnvifMetadataLimits,
    ) -> Result<Self, OnvifMetadataReceiveError> {
        let assembler = Assembler::new(key, payload_type, metadata_limits)
            .map_err(OnvifMetadataReceiveError::Reconstruction)?;
        let reorder = RtpReorderBuffer::new(key, payload_type, reorder_limits)
            .map_err(OnvifMetadataReceiveError::Transport)?;
        Ok(Self {
            reorder,
            assembler,
            last_now_ns: 0,
            ended: false,
        })
    }

    /// Queued original datagrams, excluding returned caller-owned output.
    pub fn queued_packets(&self) -> usize {
        self.reorder.queued_packets()
    }
    /// Queued wire bytes, independently bounded from document reconstruction.
    pub fn queued_bytes(&self) -> usize {
        self.reorder.queued_bytes()
    }
    /// Incomplete reconstructed payload bytes.
    pub fn pending_document_bytes(&self) -> usize {
        self.assembler.pending_bytes()
    }
    /// Transport sequence accounting; late recovery never retracts a finalized gap.
    pub fn stats(&self) -> SequenceStats {
        self.reorder.stats()
    }
    /// Earliest useful owner timer across queue and fixed reconstruction deadlines.
    pub fn next_wake_ns(&self) -> Option<u64> {
        if self.ended {
            return None;
        }
        let wake = match (
            self.reorder.next_wake_ns(),
            self.assembler.next_deadline_ns(),
        ) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        wake.map(|at| at.max(self.last_now_ns))
    }

    /// Admit a complete datagram whose receipt and processing time coincide.
    pub fn ingest(
        &mut self,
        key: StreamKey,
        wire: &[u8],
        now_ns: u64,
    ) -> Result<OnvifMetadataReceiveAdmission, OnvifMetadataReceiveError> {
        self.ingest_received(key, wire, now_ns, now_ns)
    }

    /// Admit exact source bytes with the original owner receipt time.
    ///
    /// Capacity, wrong-owner/payload and time refusals are transactional. Malformed
    /// RTP framing or a conflicting queued duplicate closes the receiver and retires
    /// both derivatives explicitly; no later packet can bridge that ambiguity.
    pub fn ingest_received(
        &mut self,
        key: StreamKey,
        wire: &[u8],
        received_ns: u64,
        now_ns: u64,
    ) -> Result<OnvifMetadataReceiveAdmission, OnvifMetadataReceiveError> {
        self.check_time(now_ns)?;
        let transport = match self.reorder.ingest_received(key, wire, received_ns, now_ns) {
            Ok(value) => value,
            Err(cause @ ReorderError::Packet(_)) => {
                let retired = self.invalidate(OnvifMetadataDiscardReason::InvalidPacket);
                return Err(OnvifMetadataReceiveError::Invalidated { cause, retired });
            }
            Err(cause @ ReorderError::ConflictingDuplicate) => {
                let retired = self.invalidate(OnvifMetadataDiscardReason::ConflictingPacket);
                return Err(OnvifMetadataReceiveError::Invalidated { cause, retired });
            }
            Err(error) => return Err(OnvifMetadataReceiveError::Transport(error)),
        };
        self.last_now_ns = now_ns;
        let discarded = if transport.disposition == ReorderDisposition::RestartRequired {
            self.ended = true;
            self.assembler
                .discard(OnvifMetadataDiscardReason::RestartRequired)
        } else {
            None
        };
        Ok(OnvifMetadataReceiveAdmission {
            transport,
            discarded,
        })
    }

    /// Perform one bounded progress step. Expiry is reported before consuming a
    /// queued packet, so the following poll can retain that exact original source.
    pub fn poll(
        &mut self,
        now_ns: u64,
    ) -> Result<OnvifMetadataReceivePoll, OnvifMetadataReceiveError> {
        self.check_time(now_ns)?;
        self.last_now_ns = now_ns;
        if self.ended {
            return Ok(OnvifMetadataReceivePoll::Ended { discarded: None });
        }
        if let Some(discarded) = self
            .assembler
            .expire(now_ns)
            .map_err(OnvifMetadataReceiveError::Reconstruction)?
        {
            return Ok(OnvifMetadataReceivePoll::DocumentDiscarded(discarded));
        }
        match self
            .reorder
            .poll(now_ns)
            .map_err(OnvifMetadataReceiveError::Transport)?
        {
            ReorderPoll::Packet(source) => {
                let reconstruction = match source.packet() {
                    Ok(packet) => self.assembler.push(
                        source.key(),
                        source.sequence(),
                        packet,
                        source.received_ns(),
                        now_ns,
                    ),
                    Err(error) => Err(OnvifMetadataFailure {
                        reason: OnvifMetadataError::Packet(error),
                        discarded: self
                            .assembler
                            .discard(OnvifMetadataDiscardReason::InvalidPacket),
                    }),
                };
                Ok(OnvifMetadataReceivePoll::Packet {
                    source,
                    reconstruction,
                })
            }
            ReorderPoll::Gap(gap) => Ok(OnvifMetadataReceivePoll::Gap {
                gap,
                discarded: self.assembler.gap(),
            }),
            ReorderPoll::Pending { .. } => Ok(OnvifMetadataReceivePoll::Pending {
                wake_at_ns: self.next_wake_ns(),
            }),
            ReorderPoll::Ended => {
                self.ended = true;
                Ok(OnvifMetadataReceivePoll::Ended {
                    discarded: self
                        .assembler
                        .discard(OnvifMetadataDiscardReason::EndOfInput),
                })
            }
        }
    }

    /// Stop admission and drain accepted datagrams before retiring an incomplete tail.
    pub fn finish(&mut self) {
        self.reorder.finish();
    }
    /// Immediately retire queue and incomplete document without publishing a candidate.
    pub fn cancel(&mut self) -> OnvifMetadataReceiveCancellation {
        self.invalidate(OnvifMetadataDiscardReason::Cancelled)
    }
    /// Retire the entire receiver after an owner-observed discontinuity such as a
    /// truncated capture record. A fresh receiver requires a new owner generation.
    pub fn invalidate(
        &mut self,
        reason: OnvifMetadataDiscardReason,
    ) -> OnvifMetadataReceiveCancellation {
        self.ended = true;
        OnvifMetadataReceiveCancellation {
            queue: self.reorder.cancel(),
            document: self.assembler.discard(reason),
            reason,
        }
    }
    /// Construct a fresh receiver only for the same ingress and strictly newer epoch.
    /// The old owner must separately drain/cancel this instance and retain its receipts.
    pub fn restart(
        &self,
        key: StreamKey,
        payload_type: u8,
        reorder_limits: ReorderLimits,
        metadata_limits: OnvifMetadataLimits,
    ) -> Result<Self, OnvifMetadataReceiveError> {
        let assembler = Assembler::new(key, payload_type, metadata_limits)
            .map_err(OnvifMetadataReceiveError::Reconstruction)?;
        let reorder = self
            .reorder
            .restart(key, payload_type, reorder_limits)
            .map_err(OnvifMetadataReceiveError::Transport)?;
        Ok(Self {
            reorder,
            assembler,
            last_now_ns: 0,
            ended: false,
        })
    }
    fn check_time(&self, now_ns: u64) -> Result<(), OnvifMetadataReceiveError> {
        if now_ns < self.last_now_ns {
            return Err(OnvifMetadataReceiveError::Transport(
                ReorderError::Continuity(ContinuityError::ClockReversed),
            ));
        }
        Ok(())
    }
}

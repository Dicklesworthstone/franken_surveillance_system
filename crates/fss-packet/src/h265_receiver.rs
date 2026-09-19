//! Ordered, source-preserving HEVC reception over the shared RTP sequence machinery.

use std::fmt;

use crate::{
    ContinuityError, H265Depacketizer, H265Failure, H265FragmentDiscard, H265Limits,
    H265Output, OrderedRtpPacket, PacketError, QueueDiscard, ReorderAdmission,
    ReorderDisposition, ReorderError, ReorderGap, ReorderLimits, ReorderPoll,
    RtpReorderBuffer, SequenceStats, StreamKey,
};

/// Payload-free receiver refusal; codec failures are returned with their source datagram.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum H265ReceiveError {
    /// Wire validation, owner binding, monotonic time, or queue admission refusal.
    Transport(ReorderError),
    /// HEVC reconstruction configuration or payload refusal.
    Codec(H265Failure),
    /// Defensive revalidation of an immutable admitted packet failed.
    Packet(PacketError),
}

impl fmt::Display for H265ReceiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "H.265 receiver refusal: {self:?}")
    }
}

impl std::error::Error for H265ReceiveError {}

/// Transport admission and any incomplete codec work retired by a confirmed restart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H265ReceiveAdmission {
    /// Original sequence observation, disposition, and queue retirement receipt.
    pub transport: ReorderAdmission,
    /// Pending fragment chain invalidated by a confirmed source restart.
    pub discarded: Option<H265FragmentDiscard>,
}

/// One bounded progress step, with media excluded from Debug output.
#[derive(Debug, Eq, PartialEq)]
pub enum H265ReceivePoll {
    /// An ordered original datagram, whether reconstruction succeeded or failed.
    Packet {
        /// Exact source bytes, including RTP header, extensions, and padding.
        source: OrderedRtpPacket,
        /// Complete NALs, pending state, or a payload-free reconstruction refusal.
        reconstruction: Result<H265Output, H265ReceiveError>,
    },
    /// Missing ordered-delivery positions, not a physical-observability assertion.
    Gap {
        /// Inclusive delivery gap and the evidence that ended waiting.
        gap: ReorderGap,
        /// Pending reconstruction invalidated immediately, reported exactly once.
        discarded: Option<H265FragmentDiscard>,
    },
    /// Reconstruction expired without consuming the next queued source datagram.
    FragmentDiscarded(H265FragmentDiscard),
    /// Owner must arrange the next deadline wake or supply more network input.
    Pending {
        /// Earliest transport/reconstruction wake, absent when no timer work exists.
        wake_at_ns: Option<u64>,
    },
    /// Both layers are quiescent; subsequent polls return no repeated retirement.
    Ended {
        /// Unfinished reconstruction retired after draining all accepted datagrams.
        discarded: Option<H265FragmentDiscard>,
    },
}

/// Separate accounting for queued originals and incomplete codec derivatives.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H265ReceiveCancellation {
    /// Datagrams retired without delivery; independent source custody is unaffected.
    pub queue: QueueDiscard,
    /// Incomplete reconstructed media retired without a complete-NAL claim.
    pub fragment: Option<H265FragmentDiscard>,
}

/// Owner-driven RTP-to-HEVC receiver with independent transport and codec budgets.
///
/// `ingest` only admits transport. Drive `poll` until pending and at timer wakes;
/// each step emits at most one datagram, gap, or retirement receipt. Source arrival
/// timestamps remain attached to originals, while reconstruction uses monotonic
/// delivery time. The owner retains authorization, source custody, and SRST/no-DON
/// negotiation. No worker, socket, clock, decoder, or picture validator is created.
pub struct H265Receiver {
    reorder: RtpReorderBuffer,
    depacketizer: H265Depacketizer,
    last_now_ns: u64,
    ended: bool,
}

impl fmt::Debug for H265Receiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("H265Receiver")
            .field("reorder", &self.reorder)
            .field("pending_nal_bytes", &self.depacketizer.pending_bytes())
            .field("last_now_ns", &self.last_now_ns)
            .field("ended", &self.ended)
            .finish_non_exhaustive()
    }
}

impl H265Receiver {
    /// Validate one owner epoch, payload type, negotiated DON requirement, and both budgets.
    pub fn new(
        key: StreamKey,
        payload_type: u8,
        sprop_max_don_diff: u16,
        reorder_limits: ReorderLimits,
        h265_limits: H265Limits,
    ) -> Result<Self, H265ReceiveError> {
        let depacketizer = H265Depacketizer::new(key, payload_type, sprop_max_don_diff, h265_limits)
            .map_err(H265ReceiveError::Codec)?;
        let reorder = RtpReorderBuffer::new(key, payload_type, reorder_limits)
            .map_err(H265ReceiveError::Transport)?;
        Ok(Self {
            reorder,
            depacketizer,
            last_now_ns: 0,
            ended: false,
        })
    }

    /// Number of queued source datagrams, excluding previously returned caller-owned output.
    pub fn queued_packets(&self) -> usize {
        self.reorder.queued_packets()
    }

    /// Queued wire bytes; this is not an original-source custody receipt.
    pub fn queued_bytes(&self) -> usize {
        self.reorder.queued_bytes()
    }

    /// Incomplete NAL bytes, bounded independently of the datagram queue.
    pub fn pending_nal_bytes(&self) -> usize {
        self.depacketizer.pending_bytes()
    }

    /// Sequence accounting; late recovery never retracts an emitted delivery gap.
    pub fn stats(&self) -> SequenceStats {
        self.reorder.stats()
    }

    /// Earliest useful poll time across both layers, absent after quiescence.
    pub fn next_wake_ns(&self) -> Option<u64> {
        if self.ended {
            return None;
        }
        let wake = match (
            self.reorder.next_wake_ns(),
            self.depacketizer.next_deadline_ns(),
        ) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        wake.map(|at| at.max(self.last_now_ns))
    }

    /// Admit transport without reconstruction. A capacity refusal is safe to drain and retry.
    /// A confirmed source restart closes this epoch and accounts for both retained layers.
    pub fn ingest(
        &mut self,
        key: StreamKey,
        wire: &[u8],
        now_ns: u64,
    ) -> Result<H265ReceiveAdmission, H265ReceiveError> {
        self.check_time(now_ns)?;
        let transport = self
            .reorder
            .ingest(key, wire, now_ns)
            .map_err(H265ReceiveError::Transport)?;
        self.last_now_ns = now_ns;
        let discarded = if transport.disposition == ReorderDisposition::RestartRequired {
            let discarded = self.depacketizer.discard_gap();
            let _ = self.depacketizer.finish();
            self.ended = true;
            discarded
        } else {
            None
        };
        Ok(H265ReceiveAdmission {
            transport,
            discarded,
        })
    }

    /// Perform at most one bounded progress step. Expiry is reported before consuming
    /// another source packet, so no refusal path silently loses the next original.
    pub fn poll(&mut self, now_ns: u64) -> Result<H265ReceivePoll, H265ReceiveError> {
        self.check_time(now_ns)?;
        self.last_now_ns = now_ns;
        if self.ended {
            return Ok(H265ReceivePoll::Ended { discarded: None });
        }
        if let Some(discarded) = self
            .depacketizer
            .expire(now_ns)
            .map_err(H265ReceiveError::Codec)?
        {
            return Ok(H265ReceivePoll::FragmentDiscarded(discarded));
        }
        match self
            .reorder
            .poll(now_ns)
            .map_err(H265ReceiveError::Transport)?
        {
            ReorderPoll::Packet(source) => {
                let reconstruction = match source.packet() {
                    Ok(packet) => self
                        .depacketizer
                        // Reordered arrival times can reverse; delivery time cannot.
                        .push(source.key(), source.sequence(), packet, now_ns)
                        .map_err(H265ReceiveError::Codec),
                    Err(error) => Err(H265ReceiveError::Packet(error)),
                };
                Ok(H265ReceivePoll::Packet {
                    source,
                    reconstruction,
                })
            }
            ReorderPoll::Gap(gap) => Ok(H265ReceivePoll::Gap {
                gap,
                discarded: self.depacketizer.discard_gap(),
            }),
            ReorderPoll::Pending { .. } => Ok(H265ReceivePoll::Pending {
                wake_at_ns: self.next_wake_ns(),
            }),
            ReorderPoll::Ended => {
                self.ended = true;
                Ok(H265ReceivePoll::Ended {
                    discarded: self.depacketizer.finish(),
                })
            }
        }
    }

    /// End admission; accepted datagrams drain before incomplete codec EOF retirement.
    pub fn finish(&mut self) {
        self.reorder.finish();
    }

    /// Immediately retire both layers without returning any completed media.
    pub fn cancel(&mut self) -> H265ReceiveCancellation {
        self.ended = true;
        H265ReceiveCancellation {
            queue: self.reorder.cancel(),
            fragment: self.depacketizer.cancel(),
        }
    }

    /// Create a strictly newer epoch of the same ingress, without mutating this instance.
    /// The owner must separately drain or cancel the old receiver and retain its receipts.
    pub fn restart(
        &self,
        key: StreamKey,
        payload_type: u8,
        sprop_max_don_diff: u16,
        reorder_limits: ReorderLimits,
        h265_limits: H265Limits,
    ) -> Result<Self, H265ReceiveError> {
        let depacketizer = H265Depacketizer::new(key, payload_type, sprop_max_don_diff, h265_limits)
            .map_err(H265ReceiveError::Codec)?;
        let reorder = self
            .reorder
            .restart(key, payload_type, reorder_limits)
            .map_err(H265ReceiveError::Transport)?;
        Ok(Self {
            reorder,
            depacketizer,
            last_now_ns: 0,
            ended: false,
        })
    }

    fn check_time(&self, now_ns: u64) -> Result<(), H265ReceiveError> {
        if now_ns < self.last_now_ns {
            return Err(H265ReceiveError::Transport(ReorderError::Continuity(
                ContinuityError::ClockReversed,
            )));
        }
        Ok(())
    }
}

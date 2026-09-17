use std::fmt;

use crate::{
    ContinuityError, FragmentDiscard, H264Depacketizer, H264Failure, H264Limits, H264Mode,
    H264Output, OrderedRtpPacket, PacketError, QueueDiscard, ReorderAdmission, ReorderDisposition,
    ReorderError, ReorderGap, ReorderLimits, ReorderPoll, RtpReorderBuffer, SequenceStats,
    StreamKey,
};

/// Payload-free receiver failure. Codec refusal is attached to its original datagram.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum H264ReceiveError {
    /// Wire admission, ownership, time, queue capacity, or sequence refusal.
    Transport(ReorderError),
    /// Reconstruction configuration or H.264 payload refusal.
    Codec(H264Failure),
    /// Defensive revalidation of an immutable admitted datagram failed.
    Packet(PacketError),
}

impl fmt::Display for H264ReceiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "H.264 receiver refusal: {self:?}")
    }
}

impl std::error::Error for H264ReceiveError {}

/// Transport admission and any incomplete codec state retired by a confirmed restart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H264ReceiveAdmission {
    /// The sequence observation, queue disposition, and queue retirement receipt.
    pub transport: ReorderAdmission,
    /// Pending reconstruction retired on restart, attributed to a delivery gap.
    pub discarded: Option<FragmentDiscard>,
}

/// Bounded receiver progress. Debug excludes both original and reconstructed media bytes.
#[derive(Debug, Eq, PartialEq)]
pub enum H264ReceivePoll {
    /// One ordered source datagram and its reconstruction result, including codec refusals.
    Packet {
        /// Exact immutable source bytes survive successful and failed reconstruction alike.
        source: OrderedRtpPacket,
        /// Complete NALs, bounded pending state, or an explicit payload refusal.
        reconstruction: Result<H264Output, H264ReceiveError>,
    },
    /// Missing ordered-delivery positions, with immediate incomplete-chain retirement.
    Gap {
        /// Exact delivery gap, not proof of physical absence or capture failure.
        gap: ReorderGap,
        /// Any FU chain invalidated by this gap, reported exactly once.
        discarded: Option<FragmentDiscard>,
    },
    /// Reconstruction expired without needing a subsequent network packet.
    FragmentDiscarded(FragmentDiscard),
    /// The owner must arrange the next wake or supply more network input.
    Pending {
        /// Earliest transport or reconstruction deadline, absent when there is no timer work.
        wake_at_ns: Option<u64>,
    },
    /// Both layers are quiescent; repeated polls never repeat the retirement receipt.
    Ended {
        /// Incomplete reconstruction retired after all accepted source packets were drained.
        discarded: Option<FragmentDiscard>,
    },
}

/// Cancellation accounts for independently retained transport and codec derivatives.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H264ReceiveCancellation {
    /// Queued datagrams retired without delivery; original custody remains the owner's.
    pub queue: QueueDiscard,
    /// Incomplete reconstructed bytes retired without publishing a complete NAL.
    pub fragment: Option<FragmentDiscard>,
}

/// Owner-driven RTP-to-H.264 receiver with bounded reordering and reconstruction.
///
/// The owner independently retains source custody, supplies negotiated bindings, and
/// drives `poll` until pending, including timer wakes without network input. Ingest
/// only admits transport; codec work occurs in bounded, ordered poll steps. This is
/// not an RTSP client, decoder, access-unit validator, or authorization mechanism.
pub struct H264Receiver {
    reorder: RtpReorderBuffer,
    depacketizer: H264Depacketizer,
    last_now_ns: u64,
    ended: bool,
}

impl fmt::Debug for H264Receiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("H264Receiver")
            .field("reorder", &self.reorder)
            .field("pending_nal_bytes", &self.depacketizer.pending_bytes())
            .field("last_now_ns", &self.last_now_ns)
            .field("ended", &self.ended)
            .finish_non_exhaustive()
    }
}

impl H264Receiver {
    /// Validate separate transport and codec budgets for one negotiated owner stream.
    pub fn new(
        key: StreamKey,
        payload_type: u8,
        mode: H264Mode,
        reorder_limits: ReorderLimits,
        h264_limits: H264Limits,
    ) -> Result<Self, H264ReceiveError> {
        let depacketizer = H264Depacketizer::new(key, payload_type, mode, h264_limits)
            .map_err(H264ReceiveError::Codec)?;
        let reorder = RtpReorderBuffer::new(key, payload_type, reorder_limits)
            .map_err(H264ReceiveError::Transport)?;
        Ok(Self {
            reorder,
            depacketizer,
            last_now_ns: 0,
            ended: false,
        })
    }

    /// Queued original datagrams, excluding already delivered caller-owned output.
    pub fn queued_packets(&self) -> usize {
        self.reorder.queued_packets()
    }

    /// Total queued wire bytes; source custody is independent of this derivative budget.
    pub fn queued_bytes(&self) -> usize {
        self.reorder.queued_bytes()
    }

    /// Incomplete reconstructed NAL bytes, bounded independently of the datagram queue.
    pub fn pending_nal_bytes(&self) -> usize {
        self.depacketizer.pending_bytes()
    }

    /// Transport statistics do not retract emitted delivery gaps on late recovery.
    pub fn stats(&self) -> SequenceStats {
        self.reorder.stats()
    }

    /// Earliest useful poll time across both layers; quiescent receivers need no wake.
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

    /// Admit one datagram without decoding it. Failed admission is safe to drain and retry.
    /// Call `poll` after successful admission and at timer wakes, even during duplicate traffic.
    pub fn ingest(
        &mut self,
        key: StreamKey,
        wire: &[u8],
        now_ns: u64,
    ) -> Result<H264ReceiveAdmission, H264ReceiveError> {
        self.check_time(now_ns)?;
        let transport = self
            .reorder
            .ingest(key, wire, now_ns)
            .map_err(H264ReceiveError::Transport)?;
        self.last_now_ns = now_ns;
        let discarded = if transport.disposition == ReorderDisposition::RestartRequired {
            // The transport epoch is closed; no old NAL may cross into a new generation.
            let discarded = self.depacketizer.discard_gap();
            // discard_gap has already removed the sole pending chain.
            let _ = self.depacketizer.finish();
            self.ended = true;
            discarded
        } else {
            None
        };
        Ok(H264ReceiveAdmission {
            transport,
            discarded,
        })
    }

    /// Perform at most one progress step. Expired reconstruction is reported before
    /// consuming another source packet, so no error path can silently lose that packet.
    pub fn poll(&mut self, now_ns: u64) -> Result<H264ReceivePoll, H264ReceiveError> {
        self.check_time(now_ns)?;
        self.last_now_ns = now_ns;
        if self.ended {
            return Ok(H264ReceivePoll::Ended { discarded: None });
        }
        if let Some(discarded) = self
            .depacketizer
            .expire(now_ns)
            .map_err(H264ReceiveError::Codec)?
        {
            return Ok(H264ReceivePoll::FragmentDiscarded(discarded));
        }
        match self
            .reorder
            .poll(now_ns)
            .map_err(H264ReceiveError::Transport)?
        {
            ReorderPoll::Packet(source) => {
                let reconstruction = match source.packet() {
                    Ok(packet) => self
                        .depacketizer
                        // Arrival times can reverse after reordering. Reconstruction uses
                        // the monotonic delivery time; the source retains its arrival time.
                        .push(source.key(), source.sequence(), packet, now_ns)
                        .map_err(H264ReceiveError::Codec),
                    Err(error) => Err(H264ReceiveError::Packet(error)),
                };
                Ok(H264ReceivePoll::Packet {
                    source,
                    reconstruction,
                })
            }
            ReorderPoll::Gap(gap) => Ok(H264ReceivePoll::Gap {
                gap,
                discarded: self.depacketizer.discard_gap(),
            }),
            ReorderPoll::Pending { .. } => Ok(H264ReceivePoll::Pending {
                wake_at_ns: self.next_wake_ns(),
            }),
            ReorderPoll::Ended => {
                self.ended = true;
                Ok(H264ReceivePoll::Ended {
                    discarded: self.depacketizer.finish(),
                })
            }
        }
    }

    /// Stop transport admission. Accepted datagrams drain before codec EOF finalization.
    pub fn finish(&mut self) {
        self.reorder.finish();
    }

    /// Immediately retire both derivative layers with separate receipts and no NAL output.
    pub fn cancel(&mut self) -> H264ReceiveCancellation {
        self.ended = true;
        H264ReceiveCancellation {
            queue: self.reorder.cancel(),
            fragment: self.depacketizer.cancel(),
        }
    }

    /// Open a strictly newer epoch for the same ingress without mutating this receiver.
    /// The owner must separately drain or cancel the old instance and retain its receipts.
    pub fn restart(
        &self,
        key: StreamKey,
        payload_type: u8,
        mode: H264Mode,
        reorder_limits: ReorderLimits,
        h264_limits: H264Limits,
    ) -> Result<Self, H264ReceiveError> {
        let depacketizer = H264Depacketizer::new(key, payload_type, mode, h264_limits)
            .map_err(H264ReceiveError::Codec)?;
        let reorder = self
            .reorder
            .restart(key, payload_type, reorder_limits)
            .map_err(H264ReceiveError::Transport)?;
        Ok(Self {
            reorder,
            depacketizer,
            last_now_ns: 0,
            ended: false,
        })
    }

    fn check_time(&self, now_ns: u64) -> Result<(), H264ReceiveError> {
        if now_ns < self.last_now_ns {
            return Err(H264ReceiveError::Transport(ReorderError::Continuity(
                ContinuityError::ClockReversed,
            )));
        }
        Ok(())
    }
}

#![forbid(unsafe_code)]
//! Ordered RTP reception composed with the native RFC 2435 JPEG reconstructor.

use super::{JpegDepacketizer, JpegDiscard, JpegFailure, JpegLimits, JpegOutput};
use std::fmt;

use crate::{
    ContinuityError, OrderedRtpPacket, PacketError, QueueDiscard, ReorderAdmission,
    ReorderDisposition, ReorderError, ReorderGap, ReorderLimits, ReorderPoll, RtpReorderBuffer,
    SequenceStats, StreamKey,
};

/// Payload-free receiver failure. Codec refusal is attached to its original datagram.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JpegReceiveError {
    /// Wire admission, ownership, time, queue capacity, or sequence refusal.
    Transport(ReorderError),
    /// Reconstruction configuration or RTP/JPEG payload refusal.
    Codec(JpegFailure),
    /// Defensive revalidation of an immutable admitted datagram failed.
    Packet(PacketError),
}

impl fmt::Display for JpegReceiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RTP/JPEG receiver refusal: {self:?}")
    }
}

impl std::error::Error for JpegReceiveError {}

/// Transport admission and any incomplete image state retired by a confirmed restart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JpegReceiveAdmission {
    /// The sequence observation, queue disposition, and queue retirement receipt.
    pub transport: ReorderAdmission,
    /// Pending reconstruction retired on restart, attributed to a delivery gap.
    pub discarded: Option<JpegDiscard>,
}

/// Bounded receiver progress. Debug excludes both original and reconstructed media bytes.
#[derive(Debug, Eq, PartialEq)]
pub enum JpegReceivePoll {
    /// One ordered source datagram and its reconstruction result, including codec refusals.
    Packet {
        /// Exact immutable source bytes survive successful and failed reconstruction alike.
        source: OrderedRtpPacket,
        /// Complete images, bounded pending state, or an explicit payload refusal.
        reconstruction: Result<JpegOutput, JpegReceiveError>,
    },
    /// Missing ordered-delivery positions, with immediate incomplete-chain retirement.
    Gap {
        /// Exact delivery gap, not proof of physical absence or capture failure.
        gap: ReorderGap,
        /// Any image invalidated by this gap, reported exactly once.
        discarded: Option<JpegDiscard>,
    },
    /// Reconstruction expired without needing a subsequent network packet.
    JpegDiscarded(JpegDiscard),
    /// The owner must arrange the next wake or supply more network input.
    Pending {
        /// Earliest transport or reconstruction deadline, absent when there is no timer work.
        wake_at_ns: Option<u64>,
    },
    /// Both layers are quiescent; repeated polls never repeat the retirement receipt.
    Ended {
        /// Incomplete reconstruction retired after all accepted source packets were drained.
        discarded: Option<JpegDiscard>,
    },
}

/// Cancellation accounts for independently retained transport and codec derivatives.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JpegReceiveCancellation {
    /// Queued datagrams retired without delivery; original custody remains the owner's.
    pub queue: QueueDiscard,
    /// Incomplete reconstructed bytes retired without publishing a complete image.
    pub fragment: Option<JpegDiscard>,
}

/// Owner-driven RTP-to-RTP/JPEG receiver with bounded reordering and reconstruction.
///
/// The owner independently retains source custody, supplies negotiated bindings, and
/// drives `poll` until pending, including timer wakes without network input. Ingest
/// only admits transport; codec work occurs in bounded, ordered poll steps. This is
/// not an RTSP client, decoder, access-unit validator, or authorization mechanism.
pub struct JpegReceiver {
    reorder: RtpReorderBuffer,
    depacketizer: JpegDepacketizer,
    last_now_ns: u64,
    ended: bool,
}

impl fmt::Debug for JpegReceiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JpegReceiver")
            .field("reorder", &self.reorder)
            .field("pending_frame_bytes", &self.depacketizer.pending_bytes())
            .field("last_now_ns", &self.last_now_ns)
            .field("ended", &self.ended)
            .finish_non_exhaustive()
    }
}

impl JpegReceiver {
    /// Validate separate transport and codec budgets for one negotiated owner stream.
    pub fn new(
        key: StreamKey,
        payload_type: u8,
        reorder_limits: ReorderLimits,
        jpeg_limits: JpegLimits,
    ) -> Result<Self, JpegReceiveError> {
        let depacketizer = JpegDepacketizer::new(key, payload_type, jpeg_limits)
            .map_err(JpegReceiveError::Codec)?;
        let reorder = RtpReorderBuffer::new(key, payload_type, reorder_limits)
            .map_err(JpegReceiveError::Transport)?;
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

    /// Incomplete reconstructed image bytes, bounded independently of the datagram queue.
    pub fn pending_frame_bytes(&self) -> usize {
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
    ) -> Result<JpegReceiveAdmission, JpegReceiveError> {
        self.ingest_received(key, wire, now_ns, now_ns)
    }

    /// Admit exact source bytes with their original receipt time after bounded delay.
    /// Queue and reconstruction deadlines use `now_ns`, independently of custody time.
    pub fn ingest_received(
        &mut self,
        key: StreamKey,
        wire: &[u8],
        received_ns: u64,
        now_ns: u64,
    ) -> Result<JpegReceiveAdmission, JpegReceiveError> {
        self.check_time(now_ns)?;
        let transport = self
            .reorder
            .ingest_received(key, wire, received_ns, now_ns)
            .map_err(JpegReceiveError::Transport)?;
        self.last_now_ns = now_ns;
        let discarded = if transport.disposition == ReorderDisposition::RestartRequired {
            // The transport epoch is closed; no old image may cross into a new generation.
            let discarded = self.depacketizer.discard_gap();
            // discard_gap has already removed the sole pending chain.
            let _ = self.depacketizer.finish();
            self.ended = true;
            discarded
        } else {
            None
        };
        Ok(JpegReceiveAdmission {
            transport,
            discarded,
        })
    }

    /// Perform at most one progress step. Expired reconstruction is reported before
    /// consuming another source packet, so no error path can silently lose that packet.
    pub fn poll(&mut self, now_ns: u64) -> Result<JpegReceivePoll, JpegReceiveError> {
        self.check_time(now_ns)?;
        self.last_now_ns = now_ns;
        if self.ended {
            return Ok(JpegReceivePoll::Ended { discarded: None });
        }
        if let Some(discarded) = self
            .depacketizer
            .expire(now_ns)
            .map_err(JpegReceiveError::Codec)?
        {
            return Ok(JpegReceivePoll::JpegDiscarded(discarded));
        }
        match self
            .reorder
            .poll(now_ns)
            .map_err(JpegReceiveError::Transport)?
        {
            ReorderPoll::Packet(source) => {
                let reconstruction = match source.packet() {
                    Ok(packet) => self
                        .depacketizer
                        // Arrival times can reverse after reordering. Reconstruction uses
                        // the monotonic delivery time; the source retains its arrival time.
                        .push(source.key(), source.sequence(), packet, now_ns)
                        .map_err(JpegReceiveError::Codec),
                    Err(error) => Err(JpegReceiveError::Packet(error)),
                };
                Ok(JpegReceivePoll::Packet {
                    source,
                    reconstruction,
                })
            }
            ReorderPoll::Gap(gap) => Ok(JpegReceivePoll::Gap {
                gap,
                discarded: self.depacketizer.discard_gap(),
            }),
            ReorderPoll::Pending { .. } => Ok(JpegReceivePoll::Pending {
                wake_at_ns: self.next_wake_ns(),
            }),
            ReorderPoll::Ended => {
                self.ended = true;
                Ok(JpegReceivePoll::Ended {
                    discarded: self.depacketizer.finish(),
                })
            }
        }
    }

    /// Stop transport admission. Accepted datagrams drain before codec EOF finalization.
    pub fn finish(&mut self) {
        self.reorder.finish();
    }

    /// Immediately retire both derivative layers with separate receipts and no image output.
    pub fn cancel(&mut self) -> JpegReceiveCancellation {
        self.ended = true;
        JpegReceiveCancellation {
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
        reorder_limits: ReorderLimits,
        jpeg_limits: JpegLimits,
    ) -> Result<Self, JpegReceiveError> {
        let depacketizer = JpegDepacketizer::new(key, payload_type, jpeg_limits)
            .map_err(JpegReceiveError::Codec)?;
        let reorder = self
            .reorder
            .restart(key, payload_type, reorder_limits)
            .map_err(JpegReceiveError::Transport)?;
        Ok(Self {
            reorder,
            depacketizer,
            last_now_ns: 0,
            ended: false,
        })
    }

    fn check_time(&self, now_ns: u64) -> Result<(), JpegReceiveError> {
        if now_ns < self.last_now_ns {
            return Err(JpegReceiveError::Transport(ReorderError::Continuity(
                ContinuityError::ClockReversed,
            )));
        }
        Ok(())
    }
}

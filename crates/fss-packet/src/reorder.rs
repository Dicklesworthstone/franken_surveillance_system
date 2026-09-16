use std::fmt;

use crate::{
    ContinuityError, PacketError, PacketLimits, RtpPacket, SequenceClass, SequenceObservation,
    SequenceStats, SequenceTracker, StreamKey,
};

/// Bounds for ordered delivery, independent of original-source retention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReorderLimits {
    /// Wire parsing limits, applied before sequence admission or copying.
    pub packet: PacketLimits,
    /// At most 128 queued datagrams, matching the sequence recovery window.
    pub max_packets: usize,
    /// Maximum sum of queued wire lengths, at most 16 MiB.
    pub max_bytes: usize,
    /// Maximum wait for a hole, in supplied monotonic nanoseconds (1..=60 seconds).
    pub max_delay_ns: u64,
}

impl Default for ReorderLimits {
    fn default() -> Self {
        Self {
            packet: PacketLimits::default(),
            max_packets: 128,
            max_bytes: 8 * 1_024 * 1_024,
            max_delay_ns: 100_000_000,
        }
    }
}

/// Payload-free refusal. Every failed admission leaves sequence and queue state unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReorderError {
    /// The reorder policy exceeds implementation bounds.
    Configuration,
    /// Wire validation failed before sequence admission.
    Packet(PacketError),
    /// Owner, sequence, time, or arithmetic validation failed.
    Continuity(ContinuityError),
    /// Admission has ended through finish, cancellation, or source restart.
    Closed,
    /// Drain the bounded packet queue before retrying this unconsumed input.
    PacketCapacity,
    /// Queued wire bytes would exceed the independent byte ceiling.
    ByteCapacity,
    /// A bounded allocation could not be reserved.
    Allocation,
    /// A still-buffered sequence was retransmitted with different original bytes.
    ConflictingDuplicate,
}

impl fmt::Display for ReorderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RTP reorder refusal: {self:?}")
    }
}

impl std::error::Error for ReorderError {}

/// A validated datagram released in extended-sequence order. Debug never prints wire bytes.
#[derive(Eq, PartialEq)]
pub struct OrderedRtpPacket {
    key: StreamKey,
    sequence: u64,
    received_ns: u64,
    bytes: Vec<u8>,
    limits: PacketLimits,
}

impl OrderedRtpPacket {
    /// Owner binding of the admitted datagram.
    pub fn key(&self) -> StreamKey {
        self.key
    }

    /// Validated, unwrapped sequence number in this owner epoch.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Time supplied at receiver admission, not a claimed camera capture time.
    pub fn received_ns(&self) -> u64 {
        self.received_ns
    }

    /// Exact original datagram, including headers, extensions, and padding.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrow the validated packet using the same wire limits as admission.
    pub fn packet(&self) -> Result<RtpPacket<'_>, PacketError> {
        RtpPacket::parse(&self.bytes, self.limits)
    }
}

impl fmt::Debug for OrderedRtpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrderedRtpPacket")
            .field("key", &self.key)
            .field("sequence", &self.sequence)
            .field("received_ns", &self.received_ns)
            .field("byte_len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Admission is separate from ordered delivery and from source custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReorderDisposition {
    /// Exact wire bytes are queued for ordered delivery.
    Buffered,
    /// Probation, before-baseline input, or an unconfirmed discontinuity.
    NotAdmitted,
    /// This sequence was already admitted and is not queued a second time.
    Duplicate,
    /// Transport recovered the position, but ordered delivery already retired the hole.
    TooLate,
    /// Confirmed source restart; old queued derivatives were retired and input is closed.
    RestartRequired,
}

/// Why queued derivatives were retired without ordered delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueDiscardReason {
    /// The owner requested immediate cancellation.
    Cancelled,
    /// Two discontinuous packets confirmed that a new stream epoch is required.
    RestartRequired,
}

/// A retirement summary, not a claim that every position between the bounds was present.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueDiscard {
    /// Owner epoch whose queued derivatives were retired.
    pub key: StreamKey,
    /// Cancellation or confirmed restart; never successful delivery.
    pub reason: QueueDiscardReason,
    /// Number of actually queued datagrams discarded.
    pub packets: usize,
    /// Sum of discarded wire lengths.
    pub bytes: usize,
    /// Lowest queued sequence, absent for an empty queue.
    pub first_sequence: Option<u64>,
    /// Highest queued sequence, absent for an empty queue.
    pub last_sequence: Option<u64>,
}

/// Transport accounting, admission disposition, and any queue retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReorderAdmission {
    /// Observation from the owner-bound transport sequence tracker.
    pub sequence: SequenceObservation,
    /// Whether ordered delivery accepted this datagram.
    pub disposition: ReorderDisposition,
    /// Present when a confirmed restart retired the prior queue.
    pub discarded: Option<QueueDiscard>,
}

/// Evidence that ended the wait for missing delivery positions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReorderGapReason {
    /// The oldest buffered witness reached its bounded wait deadline.
    Deadline,
    /// The owner closed input, so missing positions can no longer be filled.
    EndOfInput,
}

/// An exact inclusive range retired from ordered delivery, not certified network loss.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReorderGap {
    /// Exact owner epoch for this delivery discontinuity.
    pub key: StreamKey,
    /// First missing position, inclusive.
    pub first_sequence: u64,
    /// Last missing position, inclusive; no missing tail is invented.
    pub last_sequence: u64,
    /// Why waiting ended without these positions.
    pub reason: ReorderGapReason,
}

/// Each poll releases at most one datagram or one compact gap; output cannot grow unboundedly.
#[derive(Debug, Eq, PartialEq)]
pub enum ReorderPoll {
    /// One original datagram in strictly increasing extended-sequence order.
    Packet(OrderedRtpPacket),
    /// Missing positions retired before releasing the next datagram.
    Gap(ReorderGap),
    /// No output is ready; the owner must arrange the next wake.
    Pending {
        /// Earliest hole deadline, absent when only new input can make progress.
        wake_at_ns: Option<u64>,
    },
    /// Closed and drained; no accepted packet remains owned by this buffer.
    Ended,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Open,
    Draining,
    Closed,
}

/// Bounded deterministic jitter buffer over the existing owner-bound sequence tracker.
///
/// The owner supplies time, drives `poll` at the returned deadline even without traffic,
/// and retains original source custody independently. A full queue refuses admission
/// transactionally: drain/retry does not turn the refused packet into a duplicate.
/// No socket, clock, worker, authentication, or coverage certificate is created here.
pub struct RtpReorderBuffer {
    key: StreamKey,
    limits: ReorderLimits,
    tracker: SequenceTracker,
    queue: Vec<OrderedRtpPacket>,
    bytes: usize,
    next_sequence: Option<u64>,
    last_now_ns: u64,
    phase: Phase,
}

impl fmt::Debug for RtpReorderBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtpReorderBuffer")
            .field("key", &self.key)
            .field("limits", &self.limits)
            .field("queued_packets", &self.queue.len())
            .field("queued_bytes", &self.bytes)
            .field("next_sequence", &self.next_sequence)
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl RtpReorderBuffer {
    /// Allocate a bounded queue without admitting or authenticating any packet.
    pub fn new(
        key: StreamKey,
        payload_type: u8,
        limits: ReorderLimits,
    ) -> Result<Self, ReorderError> {
        limits.packet.validate().map_err(ReorderError::Packet)?;
        if !(1..=128).contains(&limits.max_packets)
            || !(12..=16 * 1_024 * 1_024).contains(&limits.max_bytes)
            || !(1..=60_000_000_000).contains(&limits.max_delay_ns)
        {
            return Err(ReorderError::Configuration);
        }
        let tracker = SequenceTracker::new(key, payload_type).map_err(ReorderError::Continuity)?;
        let mut queue = Vec::new();
        queue
            .try_reserve_exact(limits.max_packets)
            .map_err(|_| ReorderError::Allocation)?;
        Ok(Self {
            key,
            limits,
            tracker,
            queue,
            bytes: 0,
            next_sequence: None,
            last_now_ns: 0,
            phase: Phase::Open,
        })
    }

    /// Number of datagrams currently retained for ordered delivery.
    pub fn queued_packets(&self) -> usize {
        self.queue.len()
    }

    /// Sum of currently queued original wire lengths.
    pub fn queued_bytes(&self) -> usize {
        self.bytes
    }

    /// Transport accounting can recover a packet after its delivery gap was finalized.
    /// Consequently these statistics must not replace emitted delivery-gap receipts.
    pub fn stats(&self) -> SequenceStats {
        self.tracker.stats()
    }

    /// Earliest useful poll time. Ready output (including EOF) uses the last supplied time.
    pub fn next_wake_ns(&self) -> Option<u64> {
        if self.phase != Phase::Open {
            return Some(self.last_now_ns);
        }
        let first = self.queue.first()?;
        if Some(first.sequence) == self.next_sequence {
            return Some(self.last_now_ns);
        }
        self.queue
            .iter()
            .map(|packet| packet.received_ns)
            .min()?
            .checked_add(self.limits.max_delay_ns)
    }

    /// Validate and copy one complete datagram. Borrowed input always remains with the caller.
    pub fn ingest(
        &mut self,
        key: StreamKey,
        wire: &[u8],
        now_ns: u64,
    ) -> Result<ReorderAdmission, ReorderError> {
        if key != self.key {
            return Err(ReorderError::Continuity(ContinuityError::StreamMismatch));
        }
        if self.phase != Phase::Open {
            return Err(ReorderError::Closed);
        }
        self.check_time(now_ns)?;
        let packet = RtpPacket::parse(wire, self.limits.packet).map_err(ReorderError::Packet)?;
        let mut tracker = self.tracker.clone();
        let sequence = tracker
            .observe(key, packet)
            .map_err(ReorderError::Continuity)?;
        let mut discarded = None;
        let disposition = if sequence.is_unique() {
            let extended = sequence
                .extended_sequence
                .ok_or(ReorderError::Continuity(ContinuityError::Exhausted))?;
            if self.next_sequence.is_some_and(|next| extended < next) {
                ReorderDisposition::TooLate
            } else {
                // Reserve every resource before committing sequence admission or queue mutation.
                if self.queue.len() == self.limits.max_packets {
                    return Err(ReorderError::PacketCapacity);
                }
                let bytes = self
                    .bytes
                    .checked_add(wire.len())
                    .filter(|total| *total <= self.limits.max_bytes)
                    .ok_or(ReorderError::ByteCapacity)?;
                if extended == u64::MAX || now_ns.checked_add(self.limits.max_delay_ns).is_none() {
                    return Err(ReorderError::Continuity(ContinuityError::Exhausted));
                }
                let mut owned = Vec::new();
                owned
                    .try_reserve_exact(wire.len())
                    .map_err(|_| ReorderError::Allocation)?;
                owned.extend_from_slice(wire);
                let index = self.queue.partition_point(|queued| queued.sequence < extended);
                self.queue.insert(
                    index,
                    OrderedRtpPacket {
                        key,
                        sequence: extended,
                        received_ns: now_ns,
                        bytes: owned,
                        limits: self.limits.packet,
                    },
                );
                self.bytes = bytes;
                if self.next_sequence.is_none() {
                    self.next_sequence = Some(extended);
                }
                ReorderDisposition::Buffered
            }
        } else if sequence.class == SequenceClass::Duplicate {
            if self.queue.iter().any(|queued| {
                Some(queued.sequence) == sequence.extended_sequence && queued.bytes.as_slice() != wire
            }) {
                return Err(ReorderError::ConflictingDuplicate);
            }
            ReorderDisposition::Duplicate
        } else if sequence.class == SequenceClass::RestartRequired {
            discarded = Some(self.retire(QueueDiscardReason::RestartRequired));
            self.phase = Phase::Closed;
            ReorderDisposition::RestartRequired
        } else {
            ReorderDisposition::NotAdmitted
        };
        self.tracker = tracker;
        self.last_now_ns = now_ns;
        Ok(ReorderAdmission {
            sequence,
            disposition,
            discarded,
        })
    }

    /// Release ordered output. A hole's deadline is anchored to the oldest queued witness,
    /// not the most recent arrival, duplicate, or lower-sequence recovery.
    pub fn poll(&mut self, now_ns: u64) -> Result<ReorderPoll, ReorderError> {
        self.check_time(now_ns)?;
        self.last_now_ns = now_ns;
        let Some(first) = self.queue.first() else {
            if self.phase != Phase::Open {
                self.phase = Phase::Closed;
                return Ok(ReorderPoll::Ended);
            }
            return Ok(ReorderPoll::Pending { wake_at_ns: None });
        };
        let next = self.next_sequence.unwrap_or(first.sequence);
        if first.sequence == next {
            let packet = self.queue.remove(0);
            self.bytes -= packet.bytes.len();
            // Ingest rejects MAX, so a delivered sequence always has a representable successor.
            self.next_sequence = Some(packet.sequence + 1);
            return Ok(ReorderPoll::Packet(packet));
        }
        let deadline = self.next_wake_ns();
        if self.phase == Phase::Draining || deadline.is_some_and(|at| now_ns >= at) {
            let gap = ReorderGap {
                key: self.key,
                first_sequence: next,
                last_sequence: first.sequence - 1,
                reason: if self.phase == Phase::Draining {
                    ReorderGapReason::EndOfInput
                } else {
                    ReorderGapReason::Deadline
                },
            };
            self.next_sequence = Some(first.sequence);
            return Ok(ReorderPoll::Gap(gap));
        }
        Ok(ReorderPoll::Pending {
            wake_at_ns: deadline,
        })
    }

    /// Stop admission and drain already accepted packets with explicit intervening gaps.
    /// No missing tail is invented after the highest accepted sequence.
    pub fn finish(&mut self) {
        if self.phase == Phase::Open {
            self.phase = Phase::Draining;
        }
    }

    /// Stop admission and discard queued derivatives, preserving a payload-free receipt.
    pub fn cancel(&mut self) -> QueueDiscard {
        self.phase = Phase::Closed;
        self.retire(QueueDiscardReason::Cancelled)
    }

    /// Open a clean sequence space only for the same ingress and a strictly newer owner epoch.
    /// The owner must separately finish/drain or cancel the old buffer and retain its receipts.
    pub fn restart(
        &self,
        key: StreamKey,
        payload_type: u8,
        limits: ReorderLimits,
    ) -> Result<Self, ReorderError> {
        self.tracker
            .restart(key, payload_type)
            .map_err(ReorderError::Continuity)?;
        Self::new(key, payload_type, limits)
    }

    fn check_time(&self, now_ns: u64) -> Result<(), ReorderError> {
        if now_ns < self.last_now_ns {
            return Err(ReorderError::Continuity(ContinuityError::ClockReversed));
        }
        Ok(())
    }

    fn retire(&mut self, reason: QueueDiscardReason) -> QueueDiscard {
        let receipt = QueueDiscard {
            key: self.key,
            reason,
            packets: self.queue.len(),
            bytes: self.bytes,
            first_sequence: self.queue.first().map(|packet| packet.sequence),
            last_sequence: self.queue.last().map(|packet| packet.sequence),
        };
        self.queue.clear();
        self.bytes = 0;
        receipt
    }
}

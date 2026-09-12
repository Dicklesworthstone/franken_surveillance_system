#![forbid(unsafe_code)]
//! Deterministic packet fault injection with typed evidence and bounded buffers (FSS-015).
//!
//! Provides deterministic fault injection over packet streams (loss, duplication, bounded
//! reordering, and certified coverage gaps). Downstream systems can reliably distinguish
//! intentional injected gaps from unobserved absences using typed [`InjectedGapWitness`]
//! evidence, upholding INV-003 and INV-011.
//!
//! # Invariants
//! - **Bit-identical replay**: Identical seeds and input sequences produce identical output streams.
//! - **Typed evidence**: Every injected fault is explicitly recorded with audit metadata.
//! - **Bounded state**: All reorder buffers, duplicate limits, and schedule capacities are strictly bounded.
//! - **Explicit authority & zero ambient state**: No wall-clock time, no thread-local singletons, no defaults.

use std::collections::BTreeMap;
use std::fmt;

use fss_core::{CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest, SensorId};

/// Maximum reorder window size (maximum packet delay in steps).
pub const MAX_REORDER_WINDOW: usize = 64;

/// Maximum duplicate copies generated per packet.
pub const MAX_DUPLICATE_COPIES: u32 = 8;

/// Maximum total buffered packets in injector queue.
pub const MAX_BUFFER_CAPACITY: usize = 256;

/// Maximum pre-configured explicit schedule rules.
pub const MAX_SCHEDULE_RULES: usize = 4_096;

/// Maximum sequence count spanned by one injected coverage gap.
pub const MAX_GAP_LENGTH: u64 = 65_536;

/// Trait representing any sequenced packet that can be processed by [`PacketFaultInjector`].
///
/// Implemented by [`crate::SourcePacket`] and compatible with 7.2 encoded-camera fixtures.
pub trait SequencedPacket: Clone {
    /// Monotonic 1-based source sequence number.
    fn sequence(&self) -> u64;

    /// Sensor identifier responsible for the packet.
    fn sensor_id(&self) -> &SensorId;

    /// Optional conservative capture interval.
    fn capture_interval(&self) -> Option<CaptureInterval> {
        None
    }

    /// Optional content digest of packet payload.
    fn content_digest(&self) -> Option<ContentDigest> {
        None
    }
}

impl SequencedPacket for crate::SourcePacket {
    fn sequence(&self) -> u64 {
        self.sequence
    }

    fn sensor_id(&self) -> &SensorId {
        &self.sensor_id
    }

    fn capture_interval(&self) -> Option<CaptureInterval> {
        Some(self.capture)
    }

    fn content_digest(&self) -> Option<ContentDigest> {
        Some(self.digest)
    }
}

/// Errors returned by the packet fault injection subsystem.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PacketFaultError {
    /// Reorder window size exceeds [`MAX_REORDER_WINDOW`].
    ReorderWindowExceedsBound {
        /// Requested window size.
        requested: usize,
        /// Maximum allowed window size.
        max: usize,
    },
    /// Duplicate copies request exceeds [`MAX_DUPLICATE_COPIES`].
    DuplicateCopiesExceedsBound {
        /// Requested duplicate copies.
        requested: u32,
        /// Maximum allowed duplicate copies.
        max: u32,
    },
    /// Buffer capacity configuration exceeds [`MAX_BUFFER_CAPACITY`].
    BufferCapacityExceedsBound {
        /// Requested buffer capacity.
        requested: usize,
        /// Maximum allowed buffer capacity.
        max: usize,
    },
    /// Runtime reorder buffer capacity would be exceeded by this packet.
    BufferCapacityExceeded {
        /// Current buffered count.
        current: usize,
        /// Configured maximum capacity.
        capacity: usize,
    },
    /// Explicit schedule rules count exceeds [`MAX_SCHEDULE_RULES`].
    ScheduleCapacityExceeded {
        /// Current rules count.
        current: usize,
        /// Maximum allowed rules.
        max: usize,
    },
    /// Injected gap sequence count exceeds [`MAX_GAP_LENGTH`].
    GapLengthExceedsBound {
        /// Requested gap sequence count.
        requested: u64,
        /// Maximum allowed gap count.
        max: u64,
    },
    /// Injected gap range is inverted or zero.
    InvalidSequenceRange {
        /// Start sequence.
        start: u64,
        /// End sequence.
        end: u64,
    },
    /// Fault rate in parts-per-million exceeds 1_000_000.
    InvalidPpmRate {
        /// Rate provided.
        rate_ppm: u32,
    },
    /// Sequence number 0 is disallowed; sequence numbers must be 1-based monotone.
    ZeroSequenceDisallowed,
    /// Arithmetic overflow in step or index tracking.
    ArithmeticOverflow,
}

impl fmt::Display for PacketFaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReorderWindowExceedsBound { requested, max } => {
                write!(f, "reorder window {requested} exceeds maximum bound {max}")
            }
            Self::DuplicateCopiesExceedsBound { requested, max } => {
                write!(
                    f,
                    "duplicate copies {requested} exceeds maximum bound {max}"
                )
            }
            Self::BufferCapacityExceedsBound { requested, max } => {
                write!(
                    f,
                    "configured buffer capacity {requested} exceeds maximum bound {max}"
                )
            }
            Self::BufferCapacityExceeded { current, capacity } => {
                write!(
                    f,
                    "runtime buffer capacity exceeded (current: {current}, limit: {capacity})"
                )
            }
            Self::ScheduleCapacityExceeded { current, max } => {
                write!(
                    f,
                    "schedule rules count {current} exceeds maximum bound {max}"
                )
            }
            Self::GapLengthExceedsBound { requested, max } => {
                write!(f, "gap length {requested} exceeds maximum bound {max}")
            }
            Self::InvalidSequenceRange { start, end } => {
                write!(f, "invalid sequence range [{start}..={end}]")
            }
            Self::InvalidPpmRate { rate_ppm } => {
                write!(f, "invalid rate {rate_ppm} ppm (> 1_000_000)")
            }
            Self::ZeroSequenceDisallowed => {
                write!(f, "packet sequence 0 is disallowed (must be 1-based)")
            }
            Self::ArithmeticOverflow => {
                write!(f, "arithmetic overflow in packet fault injector")
            }
        }
    }
}

impl std::error::Error for PacketFaultError {}

/// Deterministic, zero-ambient-state pseudorandom generator.
///
/// Guaranteed never to degenerate into the zero fixed-point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeterministicFaultPrng {
    seed: u64,
    state: u64,
    draw_count: u64,
}

impl DeterministicFaultPrng {
    /// Constructs a deterministic PRNG anchored at `seed`.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        let mut state = if seed == 0 {
            0xd1b5_4a32_d192_ed03_u64
        } else {
            seed ^ 0x9e37_79b9_7f4a_7c15_u64
        };
        if state == 0 {
            state = 0xd1b5_4a32_d192_ed03_u64;
        }
        Self {
            seed,
            state,
            draw_count: 0,
        }
    }

    /// Advances the PRNG state and returns the next pseudo-random `u64`.
    pub fn next_u64(&mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.draw_count = self.draw_count.saturating_add(1);
        self.state
    }

    /// Returns a pseudo-random integer in `[0, bound)`.
    pub fn next_bounded(&mut self, bound: u64) -> u64 {
        if bound <= 1 {
            0
        } else {
            self.next_u64() % bound
        }
    }

    /// Evaluates whether an event occurs according to parts-per-million probability.
    pub fn check_rate_ppm(&mut self, rate_ppm: u32) -> bool {
        if rate_ppm == 0 {
            false
        } else if rate_ppm >= 1_000_000 {
            true
        } else {
            self.next_bounded(1_000_000) < u64::from(rate_ppm)
        }
    }

    /// Returns the initial seed.
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Returns the number of pseudo-random samples drawn.
    #[must_use]
    pub const fn draw_count(&self) -> u64 {
        self.draw_count
    }
}

/// Explicit schedule rule applied to one specific sequence number.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FaultRule {
    /// Drop this sequence packet entirely.
    Drop {
        /// Reason for drop.
        reason: String,
    },
    /// Duplicate this sequence packet by generating `copies` additional duplicates.
    Duplicate {
        /// Number of extra duplicate copies (1..=MAX_DUPLICATE_COPIES).
        copies: u32,
    },
    /// Delay this packet by `delay_steps` before releasing to downstream.
    Reorder {
        /// Steps to hold this packet in the reorder buffer.
        delay_steps: usize,
    },
}

/// Pre-scheduled coverage gap across an explicit sequence range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduledGap {
    /// First sequence of gap (inclusive).
    pub start_sequence: u64,
    /// Last sequence of gap (inclusive).
    pub end_sequence: u64,
    /// Reason explaining why the coverage gap exists.
    pub reason: String,
}

/// Stochastic profile for pseudo-random fault generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StochasticFaultProfile {
    /// Loss probability in parts per million (0..=1_000_000).
    pub loss_rate_ppm: u32,
    /// Duplication probability in parts per million.
    pub duplication_rate_ppm: u32,
    /// Maximum duplicates generated when a duplicate event fires (1..=MAX_DUPLICATE_COPIES).
    pub max_duplicates: u32,
    /// Reordering probability in parts per million.
    pub reorder_rate_ppm: u32,
    /// Maximum reorder delay steps (1..=reorder_window).
    pub max_reorder_delay: usize,
}

impl StochasticFaultProfile {
    /// Constructs a validated stochastic fault profile.
    pub fn new(
        loss_rate_ppm: u32,
        duplication_rate_ppm: u32,
        max_duplicates: u32,
        reorder_rate_ppm: u32,
        max_reorder_delay: usize,
    ) -> Result<Self, PacketFaultError> {
        let profile = Self {
            loss_rate_ppm,
            duplication_rate_ppm,
            max_duplicates,
            reorder_rate_ppm,
            max_reorder_delay,
        };
        profile.validate(MAX_REORDER_WINDOW)?;
        Ok(profile)
    }

    /// Validates profile parameters against bounds.
    pub fn validate(&self, max_allowed_window: usize) -> Result<(), PacketFaultError> {
        if self.loss_rate_ppm > 1_000_000 {
            return Err(PacketFaultError::InvalidPpmRate {
                rate_ppm: self.loss_rate_ppm,
            });
        }
        if self.duplication_rate_ppm > 1_000_000 {
            return Err(PacketFaultError::InvalidPpmRate {
                rate_ppm: self.duplication_rate_ppm,
            });
        }
        if self.reorder_rate_ppm > 1_000_000 {
            return Err(PacketFaultError::InvalidPpmRate {
                rate_ppm: self.reorder_rate_ppm,
            });
        }
        if self.max_duplicates > MAX_DUPLICATE_COPIES {
            return Err(PacketFaultError::DuplicateCopiesExceedsBound {
                requested: self.max_duplicates,
                max: MAX_DUPLICATE_COPIES,
            });
        }
        if self.max_reorder_delay > max_allowed_window {
            return Err(PacketFaultError::ReorderWindowExceedsBound {
                requested: self.max_reorder_delay,
                max: max_allowed_window,
            });
        }
        Ok(())
    }
}

/// Explicit configuration and schedule for packet fault injection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketFaultSchedule {
    seed: u64,
    reorder_window: usize,
    buffer_capacity: usize,
    explicit_rules: BTreeMap<u64, FaultRule>,
    explicit_gaps: Vec<ScheduledGap>,
    stochastic_profile: Option<StochasticFaultProfile>,
}

impl PacketFaultSchedule {
    /// Constructs a validated fault schedule with explicit bounds.
    pub fn new(
        seed: u64,
        reorder_window: usize,
        buffer_capacity: usize,
    ) -> Result<Self, PacketFaultError> {
        if reorder_window > MAX_REORDER_WINDOW {
            return Err(PacketFaultError::ReorderWindowExceedsBound {
                requested: reorder_window,
                max: MAX_REORDER_WINDOW,
            });
        }
        if buffer_capacity > MAX_BUFFER_CAPACITY {
            return Err(PacketFaultError::BufferCapacityExceedsBound {
                requested: buffer_capacity,
                max: MAX_BUFFER_CAPACITY,
            });
        }
        Ok(Self {
            seed,
            reorder_window,
            buffer_capacity,
            explicit_rules: BTreeMap::new(),
            explicit_gaps: Vec::new(),
            stochastic_profile: None,
        })
    }

    /// Convenience constructor with default maximum buffer capacity.
    pub fn with_deterministic_rules(
        seed: u64,
        reorder_window: usize,
    ) -> Result<Self, PacketFaultError> {
        Self::new(seed, reorder_window, MAX_BUFFER_CAPACITY)
    }

    /// Returns the schedule seed.
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Returns the configured reorder window.
    #[must_use]
    pub const fn reorder_window(&self) -> usize {
        self.reorder_window
    }

    /// Returns the configured buffer capacity.
    #[must_use]
    pub const fn buffer_capacity(&self) -> usize {
        self.buffer_capacity
    }

    /// Adds an explicit packet drop rule.
    pub fn add_drop_rule(
        &mut self,
        sequence: u64,
        reason: impl Into<String>,
    ) -> Result<(), PacketFaultError> {
        if sequence == 0 {
            return Err(PacketFaultError::ZeroSequenceDisallowed);
        }
        if self.explicit_rules.len() >= MAX_SCHEDULE_RULES {
            return Err(PacketFaultError::ScheduleCapacityExceeded {
                current: self.explicit_rules.len(),
                max: MAX_SCHEDULE_RULES,
            });
        }
        self.explicit_rules.insert(
            sequence,
            FaultRule::Drop {
                reason: reason.into(),
            },
        );
        Ok(())
    }

    /// Adds an explicit packet duplication rule.
    pub fn add_duplicate_rule(
        &mut self,
        sequence: u64,
        copies: u32,
    ) -> Result<(), PacketFaultError> {
        if sequence == 0 {
            return Err(PacketFaultError::ZeroSequenceDisallowed);
        }
        if copies == 0 || copies > MAX_DUPLICATE_COPIES {
            return Err(PacketFaultError::DuplicateCopiesExceedsBound {
                requested: copies,
                max: MAX_DUPLICATE_COPIES,
            });
        }
        if self.explicit_rules.len() >= MAX_SCHEDULE_RULES {
            return Err(PacketFaultError::ScheduleCapacityExceeded {
                current: self.explicit_rules.len(),
                max: MAX_SCHEDULE_RULES,
            });
        }
        self.explicit_rules
            .insert(sequence, FaultRule::Duplicate { copies });
        Ok(())
    }

    /// Adds an explicit packet reordering rule.
    pub fn add_reorder_rule(
        &mut self,
        sequence: u64,
        delay_steps: usize,
    ) -> Result<(), PacketFaultError> {
        if sequence == 0 {
            return Err(PacketFaultError::ZeroSequenceDisallowed);
        }
        if delay_steps == 0 || delay_steps > self.reorder_window {
            return Err(PacketFaultError::ReorderWindowExceedsBound {
                requested: delay_steps,
                max: self.reorder_window,
            });
        }
        if self.explicit_rules.len() >= MAX_SCHEDULE_RULES {
            return Err(PacketFaultError::ScheduleCapacityExceeded {
                current: self.explicit_rules.len(),
                max: MAX_SCHEDULE_RULES,
            });
        }
        self.explicit_rules
            .insert(sequence, FaultRule::Reorder { delay_steps });
        Ok(())
    }

    /// Adds a scheduled coverage gap across sequence range `[start_sequence..=end_sequence]`.
    pub fn add_gap(
        &mut self,
        start_sequence: u64,
        end_sequence: u64,
        reason: impl Into<String>,
    ) -> Result<(), PacketFaultError> {
        if start_sequence == 0 || end_sequence == 0 || start_sequence > end_sequence {
            return Err(PacketFaultError::InvalidSequenceRange {
                start: start_sequence,
                end: end_sequence,
            });
        }
        let length = end_sequence - start_sequence + 1;
        if length > MAX_GAP_LENGTH {
            return Err(PacketFaultError::GapLengthExceedsBound {
                requested: length,
                max: MAX_GAP_LENGTH,
            });
        }
        if self.explicit_gaps.len() >= MAX_SCHEDULE_RULES {
            return Err(PacketFaultError::ScheduleCapacityExceeded {
                current: self.explicit_gaps.len(),
                max: MAX_SCHEDULE_RULES,
            });
        }
        self.explicit_gaps.push(ScheduledGap {
            start_sequence,
            end_sequence,
            reason: reason.into(),
        });
        Ok(())
    }

    /// Sets an optional stochastic fault profile.
    pub fn set_stochastic_profile(
        &mut self,
        profile: StochasticFaultProfile,
    ) -> Result<(), PacketFaultError> {
        profile.validate(self.reorder_window)?;
        self.stochastic_profile = Some(profile);
        Ok(())
    }
}

/// Explicit witness object certifying an injected sensor coverage gap.
///
/// Ensures downstream cognition can distinguish artificial test omissions from real absence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InjectedGapWitness {
    /// Sensor affected by the gap.
    pub sensor_id: SensorId,
    /// First sequence in the gap (inclusive).
    pub start_sequence: u64,
    /// Last sequence in the gap (inclusive).
    pub end_sequence: u64,
    /// Optional capture interval of the gap.
    pub interval: Option<CaptureInterval>,
    /// Explicit reason for the gap.
    pub reason: String,
    /// Deterministic seed that configured the injection.
    pub schedule_seed: u64,
    /// Canonical content digest of this witness object.
    pub witness_digest: ContentDigest,
}

impl InjectedGapWitness {
    /// Constructs a validated gap witness with its canonical content digest.
    pub fn new(
        sensor_id: SensorId,
        start_sequence: u64,
        end_sequence: u64,
        interval: Option<CaptureInterval>,
        reason: impl Into<String>,
        schedule_seed: u64,
    ) -> Result<Self, PacketFaultError> {
        if start_sequence == 0 || end_sequence == 0 || start_sequence > end_sequence {
            return Err(PacketFaultError::InvalidSequenceRange {
                start: start_sequence,
                end: end_sequence,
            });
        }
        let length = end_sequence - start_sequence + 1;
        if length > MAX_GAP_LENGTH {
            return Err(PacketFaultError::GapLengthExceedsBound {
                requested: length,
                max: MAX_GAP_LENGTH,
            });
        }
        let reason_str = reason.into();
        let witness_digest = Self::compute_digest(
            &sensor_id,
            start_sequence,
            end_sequence,
            interval,
            &reason_str,
            schedule_seed,
        );
        Ok(Self {
            sensor_id,
            start_sequence,
            end_sequence,
            interval,
            reason: reason_str,
            schedule_seed,
            witness_digest,
        })
    }

    fn compute_digest(
        sensor_id: &SensorId,
        start_sequence: u64,
        end_sequence: u64,
        interval: Option<CaptureInterval>,
        reason: &str,
        schedule_seed: u64,
    ) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.injected_gap_witness.v1");
        sensor_id.encode_canonical(&mut encoder);
        encoder.u64(start_sequence);
        encoder.u64(end_sequence);
        match interval {
            Some(iv) => {
                encoder.bool(true);
                iv.encode_canonical(&mut encoder);
            }
            None => {
                encoder.bool(false);
            }
        }
        encoder.text(reason);
        encoder.u64(schedule_seed);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Number of sequences in this gap.
    #[must_use]
    pub const fn packet_count(&self) -> u64 {
        self.end_sequence - self.start_sequence + 1
    }

    /// Returns whether `sequence` falls within this gap.
    #[must_use]
    pub const fn contains_sequence(&self, sequence: u64) -> bool {
        sequence >= self.start_sequence && sequence <= self.end_sequence
    }
}

impl CanonicalEncode for InjectedGapWitness {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text("fss.injected_gap_witness.v1");
        self.sensor_id.encode_canonical(encoder);
        encoder.u64(self.start_sequence);
        encoder.u64(self.end_sequence);
        match &self.interval {
            Some(iv) => {
                encoder.bool(true);
                iv.encode_canonical(encoder);
            }
            None => {
                encoder.bool(false);
            }
        }
        encoder.text(&self.reason);
        encoder.u64(self.schedule_seed);
    }
}

/// Typed evidence of an injected packet fault.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InjectedFaultEvidence {
    /// Packet loss.
    Loss {
        /// Omitted sequence.
        sequence: u64,
        /// Sensor id.
        sensor_id: SensorId,
        /// Reason for drop.
        reason: String,
    },
    /// Duplication.
    Duplication {
        /// Sequence duplicated.
        sequence: u64,
        /// Sensor id.
        sensor_id: SensorId,
        /// 1-based index of this duplicate copy (1..=total_copies).
        copy_index: u32,
        /// Total extra copies generated.
        total_copies: u32,
    },
    /// Reorder.
    Reorder {
        /// Sequence reordered.
        sequence: u64,
        /// Sensor id.
        sensor_id: SensorId,
        /// Steps held in buffer.
        delay_steps: usize,
        /// Delivery index when emitted.
        emitted_at_delivery_index: u64,
    },
    /// Injected gap witness.
    Gap(InjectedGapWitness),
}

/// One output emitted by [`PacketFaultInjector`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FaultStreamItem<P> {
    /// A packet delivered to downstream.
    Packet {
        /// Payload packet.
        packet: P,
        /// Monotonic 1-based delivery index.
        delivery_index: u64,
        /// Whether this packet is a duplicate copy.
        is_duplicate: bool,
    },
    /// A typed injected coverage gap witness certifying intentional omission.
    InjectedGap(InjectedGapWitness),
}

impl<P> FaultStreamItem<P> {
    /// Returns a reference to the inner packet if this is a packet delivery.
    pub fn as_packet(&self) -> Option<&P> {
        match self {
            Self::Packet { packet, .. } => Some(packet),
            Self::InjectedGap(_) => None,
        }
    }

    /// Returns true if this is an injected coverage gap witness.
    #[must_use]
    pub const fn is_injected_gap(&self) -> bool {
        matches!(self, Self::InjectedGap(_))
    }
}

/// Complete audit journal of all faults injected across a stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultInjectionJournal {
    /// Deterministic seed that configured the injector.
    pub schedule_seed: u64,
    /// Total input packets provided.
    pub total_input_packets: u64,
    /// Total delivered packet copies (including duplicates).
    pub total_delivered_packets: u64,
    /// Total stream items emitted (delivered packets + gap witnesses).
    pub total_emitted_items: u64,
    /// Chronological log of typed fault evidence.
    pub fault_evidence: Vec<InjectedFaultEvidence>,
    /// Summary of lost sequences.
    pub lost_sequences: Vec<u64>,
    /// Summary of duplicated sequences.
    pub duplicated_sequences: Vec<u64>,
    /// Summary of reordered sequences.
    pub reordered_sequences: Vec<u64>,
    /// Summary of gap witnesses.
    pub gap_witnesses: Vec<InjectedGapWitness>,
    /// Canonical content digest of this journal.
    pub journal_digest: ContentDigest,
}

impl FaultInjectionJournal {
    /// Computes the canonical content digest of this journal.
    #[must_use]
    pub fn compute_digest(
        schedule_seed: u64,
        total_input: u64,
        total_delivered: u64,
        lost: &[u64],
        duplicated: &[u64],
        reordered: &[u64],
        gaps: &[InjectedGapWitness],
    ) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.packet_fault_journal.v1");
        encoder.u64(schedule_seed);
        encoder.u64(total_input);
        encoder.u64(total_delivered);
        encoder.u64(lost.len() as u64);
        for s in lost {
            encoder.u64(*s);
        }
        encoder.u64(duplicated.len() as u64);
        for s in duplicated {
            encoder.u64(*s);
        }
        encoder.u64(reordered.len() as u64);
        for s in reordered {
            encoder.u64(*s);
        }
        encoder.u64(gaps.len() as u64);
        for g in gaps {
            g.encode_canonical(&mut encoder);
        }
        ContentDigest::sha256(&encoder.finish())
    }
}

impl CanonicalEncode for FaultInjectionJournal {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text("fss.packet_fault_journal.v1");
        encoder.u64(self.schedule_seed);
        encoder.u64(self.total_input_packets);
        encoder.u64(self.total_delivered_packets);
        encoder.u64(self.lost_sequences.len() as u64);
        for s in &self.lost_sequences {
            encoder.u64(*s);
        }
        encoder.u64(self.duplicated_sequences.len() as u64);
        for s in &self.duplicated_sequences {
            encoder.u64(*s);
        }
        encoder.u64(self.reordered_sequences.len() as u64);
        for s in &self.reordered_sequences {
            encoder.u64(*s);
        }
        encoder.u64(self.gap_witnesses.len() as u64);
        for g in &self.gap_witnesses {
            g.encode_canonical(encoder);
        }
    }
}

#[derive(Clone, Debug)]
struct DelayedItem<P> {
    packet: P,
    sequence: u64,
    remaining_delay: usize,
}

/// Deterministic, bounded packet fault injector.
///
/// Implements seeded loss, reordering within a bounded window, duplication, and
/// certified coverage gaps over any [`SequencedPacket`] stream.
#[derive(Clone, Debug)]
pub struct PacketFaultInjector<P> {
    schedule: PacketFaultSchedule,
    prng: DeterministicFaultPrng,
    delivery_counter: u64,
    reorder_buffer: Vec<DelayedItem<P>>,
    fault_evidence: Vec<InjectedFaultEvidence>,
    lost_sequences: Vec<u64>,
    duplicated_sequences: Vec<u64>,
    reordered_sequences: Vec<u64>,
    gap_witnesses: Vec<InjectedGapWitness>,
    total_input_packets: u64,
    total_delivered_packets: u64,
    total_emitted_items: u64,
    emitted_gap_starts: Vec<u64>,
}

impl<P: SequencedPacket> PacketFaultInjector<P> {
    /// Constructs a new injector driven by `schedule`.
    #[must_use]
    pub fn new(schedule: PacketFaultSchedule) -> Self {
        let prng = DeterministicFaultPrng::new(schedule.seed);
        Self {
            schedule,
            prng,
            delivery_counter: 0,
            reorder_buffer: Vec::new(),
            fault_evidence: Vec::new(),
            lost_sequences: Vec::new(),
            duplicated_sequences: Vec::new(),
            reordered_sequences: Vec::new(),
            gap_witnesses: Vec::new(),
            total_input_packets: 0,
            total_delivered_packets: 0,
            total_emitted_items: 0,
            emitted_gap_starts: Vec::new(),
        }
    }

    /// Returns the current number of packets in the reorder buffer.
    #[must_use]
    pub fn buffered_packet_count(&self) -> usize {
        self.reorder_buffer.len()
    }

    /// Pushes one packet into the injector and returns items ready for immediate emission.
    pub fn push(&mut self, packet: P) -> Result<Vec<FaultStreamItem<P>>, PacketFaultError> {
        let sequence = packet.sequence();
        if sequence == 0 {
            return Err(PacketFaultError::ZeroSequenceDisallowed);
        }

        self.total_input_packets = self
            .total_input_packets
            .checked_add(1)
            .ok_or(PacketFaultError::ArithmeticOverflow)?;

        let mut emitted = Vec::new();

        // 1. Check if sequence is part of a scheduled gap
        if let Some(gap) = self
            .schedule
            .explicit_gaps
            .iter()
            .find(|g| sequence >= g.start_sequence && sequence <= g.end_sequence)
        {
            // If this is the start of the gap, emit the typed InjectedGapWitness
            if !self.emitted_gap_starts.contains(&gap.start_sequence) {
                self.emitted_gap_starts.push(gap.start_sequence);
                let witness = InjectedGapWitness::new(
                    packet.sensor_id().clone(),
                    gap.start_sequence,
                    gap.end_sequence,
                    packet.capture_interval(),
                    gap.reason.clone(),
                    self.schedule.seed,
                )?;
                self.gap_witnesses.push(witness.clone());
                self.fault_evidence
                    .push(InjectedFaultEvidence::Gap(witness.clone()));
                self.total_emitted_items = self
                    .total_emitted_items
                    .checked_add(1)
                    .ok_or(PacketFaultError::ArithmeticOverflow)?;
                emitted.push(FaultStreamItem::InjectedGap(witness));
            }
            // Packet in gap is dropped/suppressed
            self.lost_sequences.push(sequence);
            return Ok(emitted);
        }

        // 2. Decrement countdown on currently delayed packets and collect those ready
        let mut still_delayed = Vec::new();
        let mut ready_from_delay = Vec::new();

        for mut delayed in self.reorder_buffer.drain(..) {
            delayed.remaining_delay = delayed.remaining_delay.saturating_sub(1);
            if delayed.remaining_delay == 0 {
                ready_from_delay.push(delayed);
            } else {
                still_delayed.push(delayed);
            }
        }
        self.reorder_buffer = still_delayed;

        // 3. Determine fault rule for this incoming packet
        let rule = if let Some(r) = self.schedule.explicit_rules.get(&sequence) {
            Some(r.clone())
        } else if let Some(profile) = &self.schedule.stochastic_profile {
            if self.prng.check_rate_ppm(profile.loss_rate_ppm) {
                Some(FaultRule::Drop {
                    reason: "stochastic_loss".to_owned(),
                })
            } else if profile.duplication_rate_ppm > 0
                && profile.max_duplicates > 0
                && self.prng.check_rate_ppm(profile.duplication_rate_ppm)
            {
                let count = (self.prng.next_bounded(u64::from(profile.max_duplicates)) as u32) + 1;
                Some(FaultRule::Duplicate { copies: count })
            } else if profile.reorder_rate_ppm > 0
                && profile.max_reorder_delay > 0
                && self.prng.check_rate_ppm(profile.reorder_rate_ppm)
            {
                let delay = (self.prng.next_bounded(profile.max_reorder_delay as u64) as usize) + 1;
                Some(FaultRule::Reorder { delay_steps: delay })
            } else {
                None
            }
        } else {
            None
        };

        // 4. Execute rule on incoming packet
        match rule {
            Some(FaultRule::Drop { reason }) => {
                self.lost_sequences.push(sequence);
                self.fault_evidence.push(InjectedFaultEvidence::Loss {
                    sequence,
                    sensor_id: packet.sensor_id().clone(),
                    reason,
                });
            }
            Some(FaultRule::Reorder { delay_steps }) => {
                if self.reorder_buffer.len() >= self.schedule.buffer_capacity {
                    return Err(PacketFaultError::BufferCapacityExceeded {
                        current: self.reorder_buffer.len(),
                        capacity: self.schedule.buffer_capacity,
                    });
                }
                self.reordered_sequences.push(sequence);
                self.reorder_buffer.push(DelayedItem {
                    packet,
                    sequence,
                    remaining_delay: delay_steps,
                });
            }
            Some(FaultRule::Duplicate { copies }) => {
                // Emit original
                self.delivery_counter = self
                    .delivery_counter
                    .checked_add(1)
                    .ok_or(PacketFaultError::ArithmeticOverflow)?;
                self.total_delivered_packets = self
                    .total_delivered_packets
                    .checked_add(1)
                    .ok_or(PacketFaultError::ArithmeticOverflow)?;
                self.total_emitted_items = self
                    .total_emitted_items
                    .checked_add(1)
                    .ok_or(PacketFaultError::ArithmeticOverflow)?;
                emitted.push(FaultStreamItem::Packet {
                    packet: packet.clone(),
                    delivery_index: self.delivery_counter,
                    is_duplicate: false,
                });

                // Emit duplicates
                self.duplicated_sequences.push(sequence);
                for c in 1..=copies {
                    self.delivery_counter = self
                        .delivery_counter
                        .checked_add(1)
                        .ok_or(PacketFaultError::ArithmeticOverflow)?;
                    self.total_delivered_packets = self
                        .total_delivered_packets
                        .checked_add(1)
                        .ok_or(PacketFaultError::ArithmeticOverflow)?;
                    self.total_emitted_items = self
                        .total_emitted_items
                        .checked_add(1)
                        .ok_or(PacketFaultError::ArithmeticOverflow)?;
                    self.fault_evidence
                        .push(InjectedFaultEvidence::Duplication {
                            sequence,
                            sensor_id: packet.sensor_id().clone(),
                            copy_index: c,
                            total_copies: copies,
                        });
                    emitted.push(FaultStreamItem::Packet {
                        packet: packet.clone(),
                        delivery_index: self.delivery_counter,
                        is_duplicate: true,
                    });
                }
            }
            None => {
                // Normal delivery
                self.delivery_counter = self
                    .delivery_counter
                    .checked_add(1)
                    .ok_or(PacketFaultError::ArithmeticOverflow)?;
                self.total_delivered_packets = self
                    .total_delivered_packets
                    .checked_add(1)
                    .ok_or(PacketFaultError::ArithmeticOverflow)?;
                self.total_emitted_items = self
                    .total_emitted_items
                    .checked_add(1)
                    .ok_or(PacketFaultError::ArithmeticOverflow)?;
                emitted.push(FaultStreamItem::Packet {
                    packet,
                    delivery_index: self.delivery_counter,
                    is_duplicate: false,
                });
            }
        }

        // 5. Emit items released from delay buffer
        for delayed in ready_from_delay {
            self.delivery_counter = self
                .delivery_counter
                .checked_add(1)
                .ok_or(PacketFaultError::ArithmeticOverflow)?;
            self.total_delivered_packets = self
                .total_delivered_packets
                .checked_add(1)
                .ok_or(PacketFaultError::ArithmeticOverflow)?;
            self.total_emitted_items = self
                .total_emitted_items
                .checked_add(1)
                .ok_or(PacketFaultError::ArithmeticOverflow)?;
            self.fault_evidence.push(InjectedFaultEvidence::Reorder {
                sequence: delayed.sequence,
                sensor_id: delayed.packet.sensor_id().clone(),
                delay_steps: 0,
                emitted_at_delivery_index: self.delivery_counter,
            });
            emitted.push(FaultStreamItem::Packet {
                packet: delayed.packet,
                delivery_index: self.delivery_counter,
                is_duplicate: false,
            });
        }

        Ok(emitted)
    }

    /// Drains any remaining delayed packets at stream termination.
    pub fn drain(&mut self) -> Result<Vec<FaultStreamItem<P>>, PacketFaultError> {
        let mut drained = Vec::new();
        for delayed in self.reorder_buffer.drain(..) {
            self.delivery_counter = self
                .delivery_counter
                .checked_add(1)
                .ok_or(PacketFaultError::ArithmeticOverflow)?;
            self.total_delivered_packets = self
                .total_delivered_packets
                .checked_add(1)
                .ok_or(PacketFaultError::ArithmeticOverflow)?;
            self.total_emitted_items = self
                .total_emitted_items
                .checked_add(1)
                .ok_or(PacketFaultError::ArithmeticOverflow)?;
            self.fault_evidence.push(InjectedFaultEvidence::Reorder {
                sequence: delayed.sequence,
                sensor_id: delayed.packet.sensor_id().clone(),
                delay_steps: 0,
                emitted_at_delivery_index: self.delivery_counter,
            });
            drained.push(FaultStreamItem::Packet {
                packet: delayed.packet,
                delivery_index: self.delivery_counter,
                is_duplicate: false,
            });
        }
        Ok(drained)
    }

    /// Finalizes stream processing, flushing remaining packets and compiling the journal.
    pub fn finish(
        mut self,
    ) -> Result<(Vec<FaultStreamItem<P>>, FaultInjectionJournal), PacketFaultError> {
        let flushed = self.drain()?;
        let journal_digest = FaultInjectionJournal::compute_digest(
            self.schedule.seed,
            self.total_input_packets,
            self.total_delivered_packets,
            &self.lost_sequences,
            &self.duplicated_sequences,
            &self.reordered_sequences,
            &self.gap_witnesses,
        );

        let journal = FaultInjectionJournal {
            schedule_seed: self.schedule.seed,
            total_input_packets: self.total_input_packets,
            total_delivered_packets: self.total_delivered_packets,
            total_emitted_items: self.total_emitted_items,
            fault_evidence: self.fault_evidence,
            lost_sequences: self.lost_sequences,
            duplicated_sequences: self.duplicated_sequences,
            reordered_sequences: self.reordered_sequences,
            gap_witnesses: self.gap_witnesses,
            journal_digest,
        };

        Ok((flushed, journal))
    }
}

/// Helper executing deterministic fault injection over a stream of packets.
///
/// Returns all emitted stream items (delivered packets and gap witnesses) and the final journal.
pub fn inject_stream<P: SequencedPacket>(
    packets: Vec<P>,
    schedule: PacketFaultSchedule,
) -> Result<(Vec<FaultStreamItem<P>>, FaultInjectionJournal), PacketFaultError> {
    let mut injector = PacketFaultInjector::new(schedule);
    let mut stream_items = Vec::new();

    for packet in packets {
        let ready = injector.push(packet)?;
        stream_items.extend(ready);
    }

    let (flushed, journal) = injector.finish()?;
    stream_items.extend(flushed);

    Ok((stream_items, journal))
}

/// Helper executing deterministic fault injection and returning only delivered packets.
pub fn inject_packets<P: SequencedPacket>(
    packets: Vec<P>,
    schedule: PacketFaultSchedule,
) -> Result<(Vec<P>, FaultInjectionJournal), PacketFaultError> {
    let (items, journal) = inject_stream(packets, schedule)?;
    let delivered = items
        .into_iter()
        .filter_map(|item| match item {
            FaultStreamItem::Packet { packet, .. } => Some(packet),
            FaultStreamItem::InjectedGap(_) => None,
        })
        .collect();
    Ok((delivered, journal))
}

use std::fmt;

use crate::RtpPacket;

/// Owner-assigned stream epoch plus the negotiated SSRC; not sender authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamKey {
    /// Nonzero epoch. A reconnect, source restart, or clock reset requires a new epoch.
    pub generation: u64,
    /// Negotiated synchronization source, including zero when legitimately negotiated.
    pub ssrc: u32,
}

/// Payload-free continuity, ownership, and timing refusals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContinuityError {
    /// Invalid negotiated clock, payload type, or generation.
    Configuration,
    /// Packet or caller belongs to another stream epoch or SSRC.
    StreamMismatch,
    /// Payload type differs from the negotiated configuration.
    PayloadType,
    /// Caller must create a strictly newer stream generation.
    GenerationRequired,
    /// Sequence/counter arithmetic has reached its representable boundary.
    Exhausted,
    /// A supplied monotonic time moved backwards.
    ClockReversed,
    /// A timestamp difference cannot be unambiguously unwrapped.
    ClockAmbiguous,
    /// No sender report has been received for this epoch.
    NoSenderReport,
}

impl fmt::Display for ContinuityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "packet continuity refusal: {self:?}")
    }
}

impl std::error::Error for ContinuityError {}

/// Sequence disposition within a fixed 128-packet duplicate/reordering window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SequenceClass {
    /// Waiting for two sequential packets; this packet is not admitted to decoding.
    Probation,
    /// Second sequential packet establishes the accounting baseline.
    Baseline,
    /// New highest sequence, possibly exposing provisional gaps.
    Advanced,
    /// Previously missing packet recovered inside the retained window.
    Reordered,
    /// Already observed sequence; do not deliver it again to a decoder.
    Duplicate,
    /// A packet preceding the admitted baseline cannot improve its coverage.
    BeforeBaseline,
    /// Large jump or old packet: no new sequence/continuity is admitted.
    DiscontinuitySuspected,
    /// Consecutive discontinuous packets require an explicit new stream epoch.
    RestartRequired,
}

/// Accounting distinguishes transport duplicates from unique evidence and missing packets.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SequenceStats {
    /// Expected sequence positions since the admitted baseline, inclusive.
    pub expected: u64,
    /// Accepted arrivals, including duplicates, excluding probation/refusals.
    pub received: u64,
    /// Distinct accepted positions, never incremented by a duplicate.
    pub unique: u64,
    /// Expected minus unique; late recovery may reduce this, duplicates cannot.
    pub missing: u64,
}

/// A bounded sequence observation, not a coverage or decodability certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SequenceObservation {
    /// Disposition that controls admission and safe retry.
    pub class: SequenceClass,
    /// Unwrapped sequence only when mapped into the admitted epoch.
    pub extended_sequence: Option<u64>,
    /// Accounting after this observation.
    pub stats: SequenceStats,
}

impl SequenceObservation {
    /// Whether this is a new, sequence-validated packet rather than a duplicate or refusal.
    pub fn is_unique(self) -> bool {
        matches!(self.class, SequenceClass::Baseline | SequenceClass::Advanced | SequenceClass::Reordered)
    }
}

/// Allocation-free RTP sequence validation, wrap tracking, and duplicate suppression.
///
/// Uses two sequential packets for probation and a forward dropout bound of 3,000,
/// following RFC 3550 A.1. Unlike that sample, a confirmed restart is never silently
/// merged into the old generation. Reordering is retained for exactly 128 positions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SequenceTracker {
    key: StreamKey,
    payload_type: u8,
    probation: Option<u16>,
    base: Option<u64>,
    highest: u64,
    seen: u128,
    bad_next: Option<u16>,
    restart_required: bool,
    stats: SequenceStats,
}

impl SequenceTracker {
    /// Start a new owner-bound sequence epoch without trusting the first packet.
    pub fn new(key: StreamKey, payload_type: u8) -> Result<Self, ContinuityError> {
        if key.generation == 0 || payload_type > 127 {
            return Err(ContinuityError::Configuration);
        }
        Ok(Self {
            key,
            payload_type,
            probation: None,
            base: None,
            highest: 0,
            seen: 0,
            bad_next: None,
            restart_required: false,
            stats: SequenceStats::default(),
        })
    }

    /// Current accounting; missing is provisional, never evidence of physical absence.
    pub fn stats(&self) -> SequenceStats {
        self.stats
    }

    /// Validate ownership before any mutation, then classify a complete parsed packet.
    pub fn observe(
        &mut self,
        key: StreamKey,
        packet: RtpPacket<'_>,
    ) -> Result<SequenceObservation, ContinuityError> {
        if key != self.key || packet.ssrc() != self.key.ssrc {
            return Err(ContinuityError::StreamMismatch);
        }
        if packet.payload_type() != self.payload_type {
            return Err(ContinuityError::PayloadType);
        }
        // The state is small and fixed-size: arithmetic refusal cannot partially advance it.
        let mut next = self.clone();
        let observation = next.advance(packet.sequence())?;
        *self = next;
        Ok(observation)
    }

    /// Reopen with a strictly newer owner epoch, preserving no old continuity claims.
    pub fn restart(&self, key: StreamKey, payload_type: u8) -> Result<Self, ContinuityError> {
        if key.generation <= self.key.generation {
            return Err(ContinuityError::GenerationRequired);
        }
        Self::new(key, payload_type)
    }

    fn observation(&self, class: SequenceClass, sequence: Option<u64>) -> SequenceObservation {
        SequenceObservation { class, extended_sequence: sequence, stats: self.stats }
    }

    fn advance(&mut self, sequence: u16) -> Result<SequenceObservation, ContinuityError> {
        if self.restart_required {
            return Ok(self.observation(SequenceClass::RestartRequired, None));
        }
        let Some(base) = self.base else {
            if self.probation.map(|last| last.wrapping_add(1)) != Some(sequence) {
                self.probation = Some(sequence);
                return Ok(self.observation(SequenceClass::Probation, None));
            }
            let extended = u64::from(sequence);
            self.base = Some(extended);
            self.highest = extended;
            self.seen = 1;
            self.stats = SequenceStats { expected: 1, received: 1, unique: 1, missing: 0 };
            return Ok(self.observation(SequenceClass::Baseline, Some(extended)));
        };
        let forward = sequence.wrapping_sub(self.highest as u16);
        let (class, extended) = if forward != 0 && forward < 3_000 {
            let extended = self.highest.checked_add(u64::from(forward)).ok_or(ContinuityError::Exhausted)?;
            self.seen = if forward >= 128 { 1 } else { (self.seen << forward) | 1 };
            self.highest = extended;
            self.bad_next = None;
            (SequenceClass::Advanced, extended)
        } else if forward == 0 || forward > u16::MAX - 127 {
            let behind = (self.highest as u16).wrapping_sub(sequence);
            let Some(extended) = self.highest.checked_sub(u64::from(behind)) else {
                return Ok(self.observation(SequenceClass::BeforeBaseline, None));
            };
            if extended < base {
                return Ok(self.observation(SequenceClass::BeforeBaseline, None));
            }
            let mask = 1_u128 << behind;
            let class = if self.seen & mask != 0 { SequenceClass::Duplicate } else { SequenceClass::Reordered };
            self.seen |= mask;
            self.bad_next = None;
            (class, extended)
        } else {
            if self.bad_next == Some(sequence) {
                self.restart_required = true;
                return Ok(self.observation(SequenceClass::RestartRequired, None));
            }
            self.bad_next = Some(sequence.wrapping_add(1));
            return Ok(self.observation(SequenceClass::DiscontinuitySuspected, None));
        };
        self.stats.expected = self.highest.checked_sub(base).and_then(|n| n.checked_add(1)).ok_or(ContinuityError::Exhausted)?;
        self.stats.received = self.stats.received.checked_add(1).ok_or(ContinuityError::Exhausted)?;
        if class != SequenceClass::Duplicate {
            self.stats.unique = self.stats.unique.checked_add(1).ok_or(ContinuityError::Exhausted)?;
        }
        self.stats.missing = self.stats.expected - self.stats.unique;
        Ok(self.observation(class, Some(extended)))
    }
}

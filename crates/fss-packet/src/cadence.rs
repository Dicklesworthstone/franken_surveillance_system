#![forbid(unsafe_code)]
//! Explicit fixed-cadence timing for decoding-order pictures with reordered RTP timestamps.
//!
//! This is a caller-declared media clock, not clock recovery, decoder conformance,
//! physical capture time, or source-continuity evidence. Supply only complete pictures
//! in the original receiver's decoding order. Packet loss remains the receiver's job.

use crate::StreamKey;

/// Maximum admitted distance between decoding and presentation positions.
pub const MAX_CADENCE_REORDER: u8 = 16;

/// One declared sample interval. Startup timing must be discarded with non-IDR pictures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CadenceTiming {
    /// Relative monotonically increasing decoding time in the declared media ticks.
    pub decode_time: u64,
    /// Caller-selected fixed positive duration.
    pub duration: u32,
    /// Signed presentation-minus-decode offset; negative values are preserved.
    pub composition_offset: i32,
    /// False before the first IDR. Such a picture is not admitted to a recording.
    pub anchored: bool,
}

/// Payload-free, atomic refusal. No error advances the clock or consumes a position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CadenceError {
    /// Duration or reorder distance is outside the supported explicit policy.
    Configuration,
    /// Invalid or changed source epoch.
    Stream,
    /// RTP does not lie on the declared fixed-duration lattice.
    OffCadence,
    /// A timestamp is too far from the next decoding position or precedes the IDR.
    ReorderBound,
    /// A presentation position has already been admitted.
    Duplicate,
    /// An unfilled presentation position can no longer arrive within the bound.
    MissingPosition,
    /// An IDR crosses an unfinished prefix or does not start the next display position.
    OpenGroup,
    /// A declared decoding/presentation interval or position cannot be represented.
    Exhausted,
    /// Normal completion requires an IDR and no unresolved presentation positions.
    Incomplete,
}
impl std::fmt::Display for CadenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "declared RTP cadence refused: {self:?}")
    }
}
impl std::error::Error for CadenceError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Anchor {
    timestamp: u32,
    pictures: u64,
    first_missing: u64,
    // Bit i denotes an admitted presentation position first_missing + i.
    // At most 2 * MAX_CADENCE_REORDER + 1 positions can be live.
    seen: u64,
}

/// Allocation-free bounded permutation checker and relative media-timing calculator.
///
/// DTS advances by the declared duration; RTP checks the corresponding presentation
/// lattice within an explicit reorder distance. No sorting of source pictures occurs.
/// A fixed bitmap catches repeated timestamps and positions missing beyond that distance.
/// The first IDR anchors the lattice; earlier pictures receive monotonic placeholder DTS
/// only for the collector's existing `AwaitingIdr` path. They do not establish an anchor.
/// Subsequent IDRs must begin a closed presentation prefix. Open GOPs are unsupported.
///
/// State survives local recording-window cuts. A changed source key requires a new clock.
/// Call `finish` before declaring a normally completed capture; it never fills missing slots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReorderedRtpClock {
    duration: u32,
    depth: u8,
    key: Option<StreamKey>,
    next_decode_time: u64,
    anchor: Option<Anchor>,
}
impl ReorderedRtpClock {
    /// Pure policy admission. A 90 kHz time scale must be bound independently by the owner.
    pub fn new(duration: u32, max_reorder_pictures: u8) -> Result<Self, CadenceError> {
        if !(1..=90_000).contains(&duration)
            || !(1..=MAX_CADENCE_REORDER).contains(&max_reorder_pictures)
        {
            return Err(CadenceError::Configuration);
        }
        Ok(Self {
            duration,
            depth: max_reorder_pictures,
            key: None,
            next_decode_time: 0,
            anchor: None,
        })
    }

    /// Whether all anchored pictures form a closed presentation prefix, not scene coverage.
    pub fn prefix_complete(&self) -> bool {
        self.anchor
            .is_some_and(|a| a.first_missing == a.pictures && a.seen == 0)
    }

    /// Check a requested final boundary without mutating state or fabricating missing pictures.
    pub fn finish(&self) -> Result<(), CadenceError> {
        if self.prefix_complete() {
            Ok(())
        } else {
            Err(CadenceError::Incomplete)
        }
    }

    /// Time one actual complete picture. `idr` comes from the owning native picture parser.
    ///
    /// Call once per picture; a repeated timing reply is not a second observation. A failed
    /// downstream collection must stop/reconcile, not call this method again to retry timing.
    /// Every local refusal is atomic and leaves even first-source admission unchanged.
    pub fn observe(
        &mut self,
        key: StreamKey,
        timestamp: u32,
        idr: bool,
    ) -> Result<CadenceTiming, CadenceError> {
        if key.ingress == 0 || key.generation == 0 || self.key.is_some_and(|k| k != key) {
            return Err(CadenceError::Stream);
        }
        let decode_time = self.next_decode_time;
        let next_decode_time = decode_time
            .checked_add(u64::from(self.duration))
            .ok_or(CadenceError::Exhausted)?;
        let mut anchor = self.anchor.or_else(|| {
            idr.then_some(Anchor {
                timestamp,
                pictures: 0,
                first_missing: 0,
                seen: 0,
            })
        });
        let offset = if let Some(a) = &mut anchor {
            // Calculate modulo 2^32 deliberately; elapsed media time itself remains u64.
            let expected = a
                .timestamp
                .wrapping_add((a.pictures as u32).wrapping_mul(self.duration));
            let delta = i64::from(timestamp.wrapping_sub(expected) as i32);
            if delta.unsigned_abs() > u64::from(self.depth) * u64::from(self.duration) {
                return Err(CadenceError::ReorderBound);
            }
            if delta % i64::from(self.duration) != 0 {
                return Err(CadenceError::OffCadence);
            }
            let position = a
                .pictures
                .checked_add_signed(delta / i64::from(self.duration))
                .ok_or(CadenceError::ReorderBound)?;
            if idr && (position != a.pictures || a.first_missing != a.pictures || a.seen != 0) {
                return Err(CadenceError::OpenGroup);
            }
            let bit = position
                .checked_sub(a.first_missing)
                .ok_or(CadenceError::Duplicate)?;
            if bit >= 64 {
                return Err(CadenceError::ReorderBound);
            }
            let mask = 1_u64 << bit;
            if a.seen & mask != 0 {
                return Err(CadenceError::Duplicate);
            }
            a.seen |= mask;
            while a.seen & 1 != 0 {
                a.seen >>= 1;
                a.first_missing = a
                    .first_missing
                    .checked_add(1)
                    .ok_or(CadenceError::Exhausted)?;
            }
            a.pictures = a.pictures.checked_add(1).ok_or(CadenceError::Exhausted)?;
            if a.first_missing < a.pictures.saturating_sub(u64::from(self.depth)) {
                return Err(CadenceError::MissingPosition);
            }
            let presentation = decode_time
                .checked_add_signed(delta)
                .ok_or(CadenceError::Exhausted)?;
            presentation
                .checked_add(u64::from(self.duration))
                .ok_or(CadenceError::Exhausted)?;
            i32::try_from(delta).map_err(|_| CadenceError::Exhausted)?
        } else {
            0
        };
        self.key = Some(key);
        self.next_decode_time = next_decode_time;
        self.anchor = anchor;
        Ok(CadenceTiming {
            decode_time,
            duration: self.duration,
            composition_offset: offset,
            anchored: anchor.is_some(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type Test = Result<(), CadenceError>;
    const KEY: StreamKey = StreamKey {
        ingress: 1,
        generation: 1,
        ssrc: 7,
    };
    const D: u32 = 3_600;

    #[test]
    fn signed_offsets_preserve_a_closed_reordered_gop() -> Test {
        let mut clock = ReorderedRtpClock::new(D, 2)?;
        for (n, p) in [0_u32, 3, 1, 2, 6, 4, 5].into_iter().enumerate() {
            let t = clock.observe(KEY, 80_000 + p * D, n == 0)?;
            assert_eq!(t.decode_time, n as u64 * u64::from(D));
            assert_eq!(t.composition_offset, (p as i32 - n as i32) * D as i32);
            assert!(t.anchored);
            assert_eq!(clock.prefix_complete(), [0, 3, 6].contains(&n));
        }
        clock.finish()
    }

    #[test]
    fn wraps_rtp_without_wrapping_the_relative_timeline() -> Test {
        for origin in [0, 1, u32::MAX - 1, 0x8000_0000] {
            let mut clock = ReorderedRtpClock::new(D, 2)?;
            for (n, p) in [0_u32, 3, 1, 2].into_iter().enumerate() {
                let t = clock.observe(KEY, origin.wrapping_add(p * D), n == 0)?;
                assert_eq!(
                    t.decode_time
                        .checked_add_signed(i64::from(t.composition_offset)),
                    Some(u64::from(p * D))
                );
            }
            clock.finish()?;
        }
        Ok(())
    }

    #[test]
    fn duplicates_include_retired_and_still_pending_presentation_positions() -> Test {
        let mut clock = ReorderedRtpClock::new(D, 2)?;
        clock.observe(KEY, 0, true)?;
        clock.observe(KEY, 3 * D, false)?;
        for stamp in [0, 3 * D] {
            let before = clock;
            assert_eq!(
                clock.observe(KEY, stamp, false),
                Err(CadenceError::Duplicate)
            );
            assert_eq!(clock, before);
        }
        clock.observe(KEY, D, false)?;
        clock.observe(KEY, 2 * D, false)?;
        clock.finish()
    }

    #[test]
    fn a_missing_position_cannot_hide_behind_continually_advancing_timestamps() -> Test {
        let mut clock = ReorderedRtpClock::new(D, 2)?;
        for (n, p) in [0, 3, 4].into_iter().enumerate() {
            clock.observe(KEY, p * D, n == 0)?;
        }
        let before = clock;
        assert_eq!(
            clock.observe(KEY, 5 * D, false),
            Err(CadenceError::MissingPosition)
        );
        assert_eq!(clock, before);
        clock.observe(KEY, D, false)?;
        clock.observe(KEY, 2 * D, false)?;
        clock.finish()
    }

    #[test]
    fn drift_far_jumps_and_ambiguous_half_cycles_refuse_atomically() -> Test {
        let mut clock = ReorderedRtpClock::new(D, 2)?;
        clock.observe(KEY, 0, true)?;
        for stamp in [D + 1, D - 1, 4 * D, 0x8000_0000, u32::MAX] {
            let before = clock;
            assert!(clock.observe(KEY, stamp, false).is_err());
            assert_eq!(clock, before);
        }
        clock.observe(KEY, D, false)?;
        clock.finish()
    }

    #[test]
    fn unobserved_pre_idr_startup_does_not_guess_a_presentation_origin() -> Test {
        let mut clock = ReorderedRtpClock::new(D, 2)?;
        assert_eq!(clock.finish(), Err(CadenceError::Incomplete));
        for n in 0..4 {
            let t = clock.observe(KEY, u32::MAX - n, false)?;
            assert!(!t.anchored);
            assert_eq!(t.decode_time, u64::from(n * D));
            assert!(!clock.prefix_complete());
        }
        for (n, p) in [0, 3, 1, 2].into_iter().enumerate() {
            let t = clock.observe(KEY, 20_000 + p * D, n == 0)?;
            assert_eq!(t.decode_time, (n as u64 + 4) * u64::from(D));
        }
        clock.finish()
    }

    #[test]
    fn idr_cannot_erase_pending_positions_or_reset_the_clock() -> Test {
        let mut clock = ReorderedRtpClock::new(D, 2)?;
        clock.observe(KEY, 0, true)?;
        clock.observe(KEY, 3 * D, false)?;
        let before = clock;
        assert_eq!(
            clock.observe(KEY, 2 * D, true),
            Err(CadenceError::OpenGroup)
        );
        assert_eq!(clock, before);
        clock.observe(KEY, D, false)?;
        clock.observe(KEY, 2 * D, false)?;
        let t = clock.observe(KEY, 4 * D, true)?;
        assert_eq!(t.decode_time, u64::from(4 * D));
        clock.finish()
    }

    #[test]
    fn changed_source_needs_a_new_clock_even_before_first_idr() -> Test {
        let mut clock = ReorderedRtpClock::new(D, 2)?;
        clock.observe(KEY, 0, false)?;
        for key in [
            StreamKey {
                generation: 2,
                ..KEY
            },
            StreamKey { ingress: 2, ..KEY },
            StreamKey { ssrc: 8, ..KEY },
        ] {
            let before = clock;
            assert_eq!(clock.observe(key, D, true), Err(CadenceError::Stream));
            assert_eq!(clock, before);
        }
        Ok(())
    }

    #[test]
    fn unfinished_prefix_never_becomes_success_at_a_requested_cut() -> Test {
        let mut clock = ReorderedRtpClock::new(D, 2)?;
        clock.observe(KEY, 0, true)?;
        clock.observe(KEY, 3 * D, false)?;
        assert_eq!(clock.finish(), Err(CadenceError::Incomplete));
        clock.observe(KEY, D, false)?;
        assert_eq!(clock.finish(), Err(CadenceError::Incomplete));
        clock.observe(KEY, 2 * D, false)?;
        clock.finish()
    }

    #[test]
    fn exhausted_intervals_refuse_before_source_or_position_mutation() -> Test {
        let mut clock = ReorderedRtpClock::new(D, 2)?;
        clock.next_decode_time = u64::MAX - u64::from(D);
        clock.observe(KEY, 0, true)?;
        let before = clock;
        assert_eq!(clock.observe(KEY, D, false), Err(CadenceError::Exhausted));
        assert_eq!(clock, before);
        // A future PTS end can overflow even when the whole DTS interval still fits.
        let mut clock = ReorderedRtpClock::new(D, 2)?;
        clock.next_decode_time = u64::MAX - u64::from(3 * D);
        clock.observe(KEY, 0, true)?;
        let before = clock;
        assert_eq!(
            clock.observe(KEY, 3 * D, false),
            Err(CadenceError::Exhausted)
        );
        assert_eq!(clock, before);
        Ok(())
    }

    #[test]
    fn invalid_policies_and_invalid_source_do_not_pin_an_origin() -> Test {
        for (d, r) in [(0, 1), (90_001, 1), (1, 0), (1, 17)] {
            assert_eq!(
                ReorderedRtpClock::new(d, r),
                Err(CadenceError::Configuration)
            );
        }
        let mut clock = ReorderedRtpClock::new(D, 2)?;
        let before = clock;
        assert_eq!(
            clock.observe(StreamKey { ingress: 0, ..KEY }, 0, true),
            Err(CadenceError::Stream)
        );
        assert_eq!(clock, before);
        Ok(())
    }

    #[test]
    fn every_bounded_permutation_matches_the_simple_position_oracle() -> Test {
        fn visit(order: &mut [u32], at: usize) -> Test {
            if at == order.len() {
                let required = order
                    .iter()
                    .enumerate()
                    .map(|(n, p)| (i64::from(*p) - n as i64).unsigned_abs())
                    .max()
                    .unwrap_or(0);
                for depth in 1..=4 {
                    let mut clock = ReorderedRtpClock::new(D, depth)?;
                    let mut accepted = true;
                    for (n, p) in order.iter().enumerate() {
                        match clock.observe(KEY, p * D, n == 0) {
                            Ok(t) => {
                                assert_eq!(t.composition_offset, (*p as i32 - n as i32) * D as i32)
                            }
                            Err(_) => {
                                accepted = false;
                                break;
                            }
                        }
                    }
                    assert_eq!(accepted, required <= u64::from(depth));
                    if accepted {
                        clock.finish()?;
                    }
                }
            } else {
                for next in at..order.len() {
                    order.swap(at, next);
                    visit(order, at + 1)?;
                    order.swap(at, next);
                }
            }
            Ok(())
        }
        visit(&mut [0, 1, 2, 3, 4, 5, 6, 7], 1)
    }
}

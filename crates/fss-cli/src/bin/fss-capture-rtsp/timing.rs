#![forbid(unsafe_code)]
//! Explicit operator-declared media cadence for the bounded RTSP capture command.
//!
//! The caller must bind the 90 kHz time scale, positive frame duration, and timing
//! evidence into its recording plan. RTP timestamps only check that declaration;
//! they never establish a wall clock, capture interval, or decoder reorder model.

use fss_packet::{StreamKey, cadence::ReorderedRtpClock};
use fss_reference::rtsp::hevc_recording_capture::HevcPictureTimingRequest;
use fss_reference::rtsp::recording::hevc::HevcRecordingTiming;
use fss_reference::rtsp::recording_capture::PictureTimingRequest;
use fss_reference::rtsp::recording_collector::RecordingTiming;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreviousPicture {
    key: StreamKey,
    rtp_timestamp: u32,
    next_decode_time: u64,
}

/// A relative fixed-duration timeline; reordering requires explicit plan admission.
///
/// Every completed picture consumes one declared duration, including pictures
/// skipped while awaiting the first IDR. The first observed picture starts at
/// zero; an arbitrary source RTP origin never becomes a physical capture time.
/// Legacy mode refuses presentation reordering. Opt-in mode uses the shared bounded
/// presentation-position checker without sorting source pictures or inventing samples.
#[derive(Debug)]
pub(super) struct FixedTiming {
    frame_duration: u32,
    previous: Option<PreviousPicture>,
    reordered: Option<ReorderedRtpClock>,
}

impl FixedTiming {
    /// Accept a positive duration expressed in the caller's fixed 90 kHz clock.
    pub(super) fn new(frame_duration: u32) -> Result<Self, &'static str> {
        if frame_duration == 0 {
            return Err("frame duration ticks must be positive");
        }
        Ok(Self {
            frame_duration,
            previous: None,
            reordered: None,
        })
    }

    /// Only a separately approved nonzero bound enables reordered presentation.
    pub(super) fn with_reorder(frame_duration: u32, depth: u8) -> Result<Self, &'static str> {
        let mut timing = Self::new(frame_duration)?;
        if depth != 0 {
            timing.reordered = Some(
                ReorderedRtpClock::new(frame_duration, depth)
                    .map_err(|_| "invalid declared picture reordering policy")?,
            );
        }
        Ok(timing)
    }

    /// Normal completion cannot discard an unresolved display position as an observed picture.
    /// Legacy mode adds no new completion restriction or changes to existing approvals.
    pub(super) fn finish(&self) -> Result<(), &'static str> {
        if let Some(clock) = &self.reordered {
            clock
                .finish()
                .map_err(|_| "declared presentation prefix is incomplete")?;
        }
        Ok(())
    }

    fn observe_picture(
        &mut self,
        key: StreamKey,
        rtp_timestamp: u32,
        idr: bool,
    ) -> Result<RecordingTiming, &'static str> {
        if let Some(clock) = &mut self.reordered {
            let t = clock
                .observe(key, rtp_timestamp, idr)
                .map_err(|_| "RTP picture violates the declared bounded presentation cadence")?;
            return Ok(RecordingTiming {
                decode_time: t.decode_time,
                duration: t.duration,
                composition_offset: t.composition_offset,
            });
        }
        self.observe_source(key, rtp_timestamp)
    }

    /// Validate and time one newly consumed request, without changing state on refusal.
    ///
    /// Call exactly once before supplying timing for this picture. Polling the
    /// same held request again is not a new picture and does not advance time.
    /// A failed timing admission must stop or reconcile the capture; this helper
    /// cannot establish whether the caller's collector consumed that admission.
    pub(super) fn observe(
        &mut self,
        request: PictureTimingRequest,
    ) -> Result<RecordingTiming, &'static str> {
        self.observe_picture(request.key, request.rtp_timestamp, request.idr)
    }

    pub(super) fn observe_hevc(
        &mut self,
        request: HevcPictureTimingRequest,
    ) -> Result<HevcRecordingTiming, &'static str> {
        let timing = self.observe_picture(request.key, request.rtp_timestamp, request.idr)?;
        Ok(HevcRecordingTiming {
            decode_time: timing.decode_time,
            duration: timing.duration,
            composition_offset: timing.composition_offset,
        })
    }

    fn observe_source(
        &mut self,
        key: StreamKey,
        rtp_timestamp: u32,
    ) -> Result<RecordingTiming, &'static str> {
        if key.ingress == 0 || key.generation == 0 {
            return Err("picture has an invalid stream identity");
        }
        let decode_time = if let Some(previous) = self.previous {
            if key != previous.key {
                return Err("picture stream changed; a new capture generation is required");
            }
            if rtp_timestamp != previous.rtp_timestamp.wrapping_add(self.frame_duration) {
                return Err(
                    "RTP timestamps do not match the declared fixed cadence; gaps and reordered pictures are unsupported",
                );
            }
            previous.next_decode_time
        } else {
            0
        };
        // The whole sample interval must fit, even if its start remains representable.
        let next_decode_time = decode_time
            .checked_add(u64::from(self.frame_duration))
            .ok_or("declared media timeline exceeds its u64 tick bound")?;
        let timing = RecordingTiming {
            decode_time,
            duration: self.frame_duration,
            composition_offset: 0,
        };
        self.previous = Some(PreviousPicture {
            key,
            rtp_timestamp,
            next_decode_time,
        });
        Ok(timing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_packet::avc::AvcBoundary;

    const DURATION: u32 = 3_000;

    fn picture(rtp_timestamp: u32) -> PictureTimingRequest {
        PictureTimingRequest {
            key: StreamKey {
                ingress: 1,
                generation: 1,
                ssrc: 42,
            },
            rtp_timestamp,
            frame_num: 0,
            idr: true,
            boundary: AvcBoundary::RtpMarker,
            bytes: 1,
        }
    }

    #[test]
    fn zero_duration_is_refused() {
        assert!(FixedTiming::new(0).is_err());
    }

    #[test]
    fn arbitrary_rtp_origin_starts_a_relative_timeline() -> Result<(), &'static str> {
        let mut timing = FixedTiming::new(DURATION)?;
        assert_eq!(
            timing.observe(picture(2_000_000_000))?,
            RecordingTiming {
                decode_time: 0,
                duration: DURATION,
                composition_offset: 0,
            }
        );
        for index in 1..=3 {
            assert_eq!(
                timing
                    .observe(picture(2_000_000_000 + index * DURATION))?
                    .decode_time,
                u64::from(index * DURATION)
            );
        }
        Ok(())
    }

    #[test]
    fn source_timestamp_rollover_keeps_decode_time_contiguous() -> Result<(), &'static str> {
        let mut timing = FixedTiming::new(DURATION)?;
        let origin = u32::MAX - 1_000;
        assert_eq!(timing.observe(picture(origin))?.decode_time, 0);
        assert_eq!(timing.observe(picture(1_999))?.decode_time, 3_000);
        assert_eq!(timing.observe(picture(4_999))?.decode_time, 6_000);
        Ok(())
    }

    #[test]
    fn duplicate_reordered_gap_and_drifting_timestamps_do_not_advance_state()
    -> Result<(), &'static str> {
        for timestamp in [100_000, 97_000, 106_000, 102_999, 103_001, 2_147_583_648] {
            let mut timing = FixedTiming::new(DURATION)?;
            timing.observe(picture(100_000))?;
            let before = timing.previous;
            assert!(timing.observe(picture(timestamp)).is_err());
            assert_eq!(timing.previous, before);
            assert_eq!(timing.observe(picture(103_000))?.decode_time, 3_000);
        }
        Ok(())
    }

    #[test]
    fn missing_picture_across_timestamp_rollover_is_not_hidden() -> Result<(), &'static str> {
        let mut timing = FixedTiming::new(DURATION)?;
        timing.observe(picture(u32::MAX - 1_000))?;
        let before = timing.previous;
        assert!(timing.observe(picture(4_999)).is_err());
        assert_eq!(timing.previous, before);
        assert_eq!(timing.observe(picture(1_999))?.decode_time, 3_000);
        Ok(())
    }

    #[test]
    fn skipped_non_idr_startup_and_frame_number_wrap_keep_the_same_clock()
    -> Result<(), &'static str> {
        let mut timing = FixedTiming::new(DURATION)?;
        let mut startup = picture(45_000);
        startup.idr = false;
        startup.frame_num = u16::MAX;
        assert_eq!(timing.observe(startup)?.decode_time, 0);
        let idr = timing.observe(picture(48_000))?;
        assert_eq!(idr.decode_time, 3_000);
        assert_eq!(idr.composition_offset, 0);
        Ok(())
    }

    #[test]
    fn changed_receiver_identity_requires_a_new_timeline() -> Result<(), &'static str> {
        let mut timing = FixedTiming::new(DURATION)?;
        timing.observe(picture(0))?;
        let before = timing.previous;
        let original = picture(DURATION);
        for key in [
            StreamKey {
                ingress: 2,
                ..original.key
            },
            StreamKey {
                generation: 2,
                ..original.key
            },
            StreamKey {
                ssrc: 43,
                ..original.key
            },
        ] {
            assert!(
                timing
                    .observe(PictureTimingRequest { key, ..original })
                    .is_err()
            );
            assert_eq!(timing.previous, before);
        }
        assert_eq!(timing.observe(original)?.decode_time, 3_000);
        Ok(())
    }

    #[test]
    fn invalid_initial_identity_does_not_choose_an_origin() -> Result<(), &'static str> {
        let mut timing = FixedTiming::new(DURATION)?;
        for key in [
            StreamKey {
                ingress: 0,
                ..picture(0).key
            },
            StreamKey {
                generation: 0,
                ..picture(0).key
            },
        ] {
            assert!(
                timing
                    .observe(PictureTimingRequest {
                        key,
                        ..picture(123_456)
                    })
                    .is_err()
            );
            assert!(timing.previous.is_none());
        }
        assert_eq!(timing.observe(picture(654_321))?.decode_time, 0);
        Ok(())
    }

    #[test]
    fn sample_end_overflow_is_refused_even_when_decode_time_fits() -> Result<(), &'static str> {
        let mut timing = FixedTiming::new(DURATION)?;
        timing.previous = Some(PreviousPicture {
            key: picture(0).key,
            rtp_timestamp: 0,
            next_decode_time: u64::MAX - u64::from(DURATION) + 1,
        });
        let before = timing.previous;
        assert!(timing.observe(picture(DURATION)).is_err());
        assert_eq!(timing.previous, before);
        Ok(())
    }

    #[test]
    fn last_representable_sample_is_accepted_then_exhaustion_is_atomic() -> Result<(), &'static str>
    {
        let mut timing = FixedTiming::new(DURATION)?;
        timing.previous = Some(PreviousPicture {
            key: picture(0).key,
            rtp_timestamp: 0,
            next_decode_time: u64::MAX - u64::from(DURATION),
        });
        assert_eq!(
            timing.observe(picture(DURATION))?.decode_time,
            u64::MAX - u64::from(DURATION)
        );
        let before = timing.previous;
        assert!(timing.observe(picture(DURATION * 2)).is_err());
        assert_eq!(timing.previous, before);
        Ok(())
    }

    #[test]
    fn zero_reorder_preserves_legacy_timing_and_finish_behavior() -> Result<(), &'static str> {
        let mut legacy = FixedTiming::new(DURATION)?;
        let mut explicit = FixedTiming::with_reorder(DURATION, 0)?;
        explicit.finish()?;
        for n in 0..8 {
            let p = picture(9_000 + n * DURATION);
            assert_eq!(legacy.observe(p)?, explicit.observe(p)?);
        }
        explicit.finish()
    }

    #[test]
    fn both_native_request_types_use_identical_signed_presentation_mapping()
    -> Result<(), &'static str> {
        let mut avc = FixedTiming::with_reorder(DURATION, 2)?;
        let mut hevc = FixedTiming::with_reorder(DURATION, 2)?;
        for (n, position) in [0, 3, 1, 2].into_iter().enumerate() {
            let mut p = picture(9_000 + position * DURATION);
            p.idr = n == 0;
            let a = avc.observe(p)?;
            let h = hevc.observe_hevc(HevcPictureTimingRequest {
                key: p.key,
                rtp_timestamp: p.rtp_timestamp,
                idr: p.idr,
                boundary: fss_packet::hevc::HevcBoundary::NextFirstSlice,
                bytes: 1,
            })?;
            assert_eq!(a.decode_time, h.decode_time);
            assert_eq!(a.composition_offset, h.composition_offset);
            assert_eq!(
                a.composition_offset,
                (position as i32 - n as i32) * DURATION as i32
            );
            if n == 1 || n == 2 {
                assert!(avc.finish().is_err());
                assert!(hevc.finish().is_err());
            }
        }
        avc.finish()?;
        hevc.finish()
    }

    #[test]
    fn pre_idr_reordering_never_pins_an_origin_and_refusal_keeps_the_next_slot()
    -> Result<(), &'static str> {
        let mut clock = FixedTiming::with_reorder(DURATION, 2)?;
        let mut p = picture(99_000);
        p.idr = false;
        clock.observe(p)?;
        p.rtp_timestamp = 1;
        clock.observe(p)?;
        assert!(clock.finish().is_err());
        p.idr = true;
        p.rtp_timestamp = u32::MAX - 2;
        assert_eq!(clock.observe(p)?.decode_time, 2 * u64::from(DURATION));
        p.idr = false;
        p.rtp_timestamp = p.rtp_timestamp.wrapping_add(DURATION + 1);
        let before = clock.reordered;
        assert!(clock.observe(p).is_err());
        assert_eq!(clock.reordered, before);
        p.rtp_timestamp = p.rtp_timestamp.wrapping_sub(1);
        assert_eq!(clock.observe(p)?.decode_time, 3 * u64::from(DURATION));
        clock.finish()
    }
}

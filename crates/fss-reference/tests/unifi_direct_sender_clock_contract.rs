#![forbid(unsafe_code)]
//! Sender-clock hypotheses do not establish physical A/V synchronization.

use fss_reference::unifi_direct::av_recording::{Error, SenderClockOrigin, sender_clock_origin};

#[test]
fn maps_positive_and_negative_sender_offsets_without_resetting_video_epoch() {
    assert_eq!(
        sender_clock_origin(10_000, 10_010, 16_000, 2_000),
        Ok(SenderClockOrigin {
            audio_ticks: 160_160,
            audio_minus_video_ms: 10,
            fractional_tick_thousandths: 0,
        })
    );
    assert_eq!(
        sender_clock_origin(10_000, 9_900, 16_000, 2_000)
            .map(|x| (x.audio_ticks, x.audio_minus_video_ms)),
        Ok((158_400, -100))
    );
}

#[test]
fn unwraps_audio_on_each_side_of_a_sender_timestamp_wrap() {
    assert_eq!(
        sender_clock_origin(0xffff_fff0, 0x10, 16_000, 100)
            .map(|x| (x.audio_ticks, x.audio_minus_video_ms)),
        Ok((0x1_0000_0010_u64 * 16, 32))
    );
    assert_eq!(
        sender_clock_origin(0x1_0000_0010, 0xffff_fff0, 16_000, 100)
            .map(|x| (x.audio_ticks, x.audio_minus_video_ms)),
        Ok((0xffff_fff0_u64 * 16, -32))
    );
}

#[test]
fn records_fractional_tick_remainder_without_rounding_up() -> Result<(), Error> {
    let origin = sender_clock_origin(1_001, 1_001, 44_100, 0)?;
    assert_eq!(origin.audio_ticks, 44_144);
    assert_eq!(origin.fractional_tick_thousandths, 100);
    Ok(())
}

#[test]
fn refuses_ambiguous_or_out_of_range_origins() {
    assert_eq!(
        sender_clock_origin(0, 0x8000_0000, 16_000, 2_000),
        Err(Error::Alignment)
    );
    assert_eq!(
        sender_clock_origin(10_000, 12_001, 16_000, 2_000),
        Err(Error::Alignment)
    );
    assert_eq!(
        sender_clock_origin(0, 0xffff_ffff, 16_000, 2_000),
        Err(Error::Alignment)
    );
    assert_eq!(sender_clock_origin(1, 1, 0, 2_000), Err(Error::Alignment));
    assert_eq!(
        sender_clock_origin(1, 1, 16_000, 1 << 31),
        Err(Error::Alignment)
    );
    assert_eq!(
        sender_clock_origin(u64::MAX, u32::MAX, u32::MAX, 0),
        Err(Error::Alignment)
    );
}

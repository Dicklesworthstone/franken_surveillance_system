#![forbid(unsafe_code)]
//! Sample-clock and sender-timestamp reconciliation, without media decoding.

use fss_packet::extended_flv::{
    aac::Configuration,
    aac_clock::{Clock, Error},
};

type Test = Result<(), Box<dyn std::error::Error>>;

#[test]
fn sample_clock_tracks_16khz_sender_across_timestamp_wrap() -> Test {
    let config = Configuration::parse_explicit(&[0x14, 0x08])?;
    let mut clock = Clock::new(&config, 7_000, 1, 4)?;
    let first = clock.observe(u32::MAX - 31)?;
    let second = clock.observe(32)?;
    let third = clock.observe(96)?;
    assert_eq!(
        (first.decode_ticks, first.duration_ticks, first.elapsed_ms),
        (7_000, 1024, 0)
    );
    assert_eq!((second.decode_ticks, second.elapsed_ms), (8_024, 64));
    assert_eq!((third.decode_ticks, third.elapsed_ms), (9_048, 128));
    Ok(())
}

#[test]
fn fractional_milliseconds_do_not_accumulate_rounding_error() -> Test {
    let config = Configuration::parse_explicit(&[0x12, 0x10])?;
    assert_eq!(config.sample_rate(), 44_100);
    let mut clock = Clock::new(&config, 0, 1, 1_000)?;
    for i in 0..1_000u64 {
        let timestamp = 123 + ((i * 1024 * 1000) / 44_100) as u32;
        let sample = clock.observe(timestamp)?;
        assert_eq!(sample.decode_ticks, i * 1024);
    }
    assert_eq!(clock.observe(24_000), Err(Error::Limit));
    Ok(())
}

#[test]
fn duplicates_reversal_and_missing_frame_do_not_advance_the_clock() -> Test {
    let config = Configuration::parse_explicit(&[0x14, 0x08])?;
    let mut clock = Clock::new(&config, 0, 1, 3)?;
    clock.observe(100)?;
    assert_eq!(clock.observe(100), Err(Error::Timeline));
    assert_eq!(clock.observe(99), Err(Error::Timeline));
    assert_eq!(clock.observe(228), Err(Error::Timeline));
    assert_eq!(clock.observe(164)?.decode_ticks, 1024);
    assert_eq!(clock.observe(228)?.decode_ticks, 2048);
    Ok(())
}

#[test]
fn rejects_unbounded_or_ambiguous_clock_policies() -> Test {
    let config = Configuration::parse_explicit(&[0x14, 0x08])?;
    assert!(matches!(
        Clock::new(&config, 0, 32, 1),
        Err(Error::Configuration)
    ));
    assert!(matches!(
        Clock::new(&config, 0, 1, 0),
        Err(Error::Configuration)
    ));
    assert!(matches!(
        Clock::new(&config, 0, 1, 16_000_001),
        Err(Error::Configuration)
    ));
    assert!(matches!(
        Clock::new(&config, u64::MAX, 1, 1),
        Err(Error::Configuration)
    ));
    Ok(())
}

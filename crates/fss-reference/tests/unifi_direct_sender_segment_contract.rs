#![forbid(unsafe_code)]
//! Sender-clock mapping from original records in a synthetic completed segment.

use fss_container::{Mp4Limits, flv_av, flv_avc::SourceKey};
use fss_packet::extended_flv::{
    Limits as FlvLimits, aac,
    stream::{Framer, Next},
};
use fss_reference::unifi_direct::{
    av_recording,
    recording::{self, Push, Recorder},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const BASELINE: &[u8] = include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264");

fn tag(kind: u8, timestamp: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut out = vec![
        kind,
        (n >> 16) as u8,
        (n >> 8) as u8,
        n as u8,
        (timestamp >> 16) as u8,
        (timestamp >> 8) as u8,
        timestamp as u8,
        (timestamp >> 24) as u8,
        0,
        0,
        0,
    ];
    out.extend_from_slice(payload);
    out.extend_from_slice(&(11_u32 + n as u32).to_be_bytes());
    out
}

fn first_segment(
    start: u32,
    include_audio: bool,
    audio_skew: u32,
    config: &aac::Configuration<'_>,
) -> Result<(recording::Segment, flv_av::Initialization), Box<dyn std::error::Error>> {
    let nals: Vec<_> = fss_codec_h264::annex_b_nal_units(BASELINE).collect();
    let sps = nals.iter().copied().find(|n| n[0] & 31 == 7).ok_or("SPS")?;
    let pps = nals.iter().copied().find(|n| n[0] & 31 == 8).ok_or("PPS")?;
    let pictures: Vec<_> = nals
        .into_iter()
        .filter(|n| matches!(n[0] & 31, 1 | 5))
        .collect();
    if pictures.len() != 4 || pictures[0][0] & 31 != 5 {
        return Err("fixture picture layout".into());
    }
    let mut avc = vec![0x17, 0, 0, 0, 0, 1, sps[1], sps[2], sps[3], 0xff, 0xe1];
    avc.extend_from_slice(&u16::try_from(sps.len())?.to_be_bytes());
    avc.extend_from_slice(sps);
    avc.push(1);
    avc.extend_from_slice(&u16::try_from(pps.len())?.to_be_bytes());
    avc.extend_from_slice(pps);
    let mut wire = b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    wire.extend(tag(9, start, &avc));
    for i in 0..7_u32 {
        if include_audio {
            wire.extend(tag(
                8,
                start.wrapping_add(i * 64).wrapping_add(audio_skew),
                &[0xaf, 1, 2],
            ));
        }
        let nal = pictures[i as usize % 3];
        let mut data = vec![0x17, 1, 0, 0, 0];
        data.extend_from_slice(&u32::try_from(nal.len())?.to_be_bytes());
        data.extend_from_slice(nal);
        wire.extend(tag(9, start.wrapping_add(i * 40), &data));
    }
    let mut framer = Framer::new(FlvLimits::default(), 1024 * 1024)?;
    framer.append(0, &wire)?;
    let mut recorder = Recorder::new(
        SourceKey {
            connection: 1,
            generation: 1,
        },
        recording::Limits::default(),
    )?;
    while let Next::Record(record) = framer.take()? {
        if let Push::Segment(segment) = recorder.push(record).map_err(|r| r.reason)? {
            let init = recorder
                .av_initialization(config)?
                .ok_or("A/V initialization")?;
            return Ok((segment, init));
        }
    }
    Err("no complete segment".into())
}

#[test]
fn source_segment_origin_is_used_by_the_muxer() -> TestResult {
    let config = aac::Configuration::parse_explicit(&[0x14, 0x08])?;
    let (segment, init) = first_segment(10_000, true, 0, &config)?;
    let origin = av_recording::segment_sender_clock_origin(&segment, &config, 2_000)?;
    assert_eq!(
        (origin.audio_minus_video_ms, origin.audio_ticks),
        (64, 161_024)
    );
    let mut muxer = av_recording::Muxer::new(
        &init,
        &config,
        origin.audio_ticks,
        0,
        32,
        32,
        Mp4Limits::default(),
    )?;
    let fragment = muxer.fragment(&init, &segment)?;
    assert_eq!(fragment.audio()[0].decode_ticks, 161_024);
    assert_eq!(segment.fragment().samples()[0].decode_time_ms, 10_000);
    flv_av::verify_archived_fragment(
        segment.fragment().bytes(),
        fragment.bytes(),
        fragment.audio(),
        Mp4Limits::default(),
    )?;
    Ok(())
}

#[test]
fn segment_origin_handles_wrap_and_refuses_missing_or_distant_audio() -> TestResult {
    let config = aac::Configuration::parse_explicit(&[0x14, 0x08])?;
    let (wrapped, _) = first_segment(u32::MAX - 50, true, 0, &config)?;
    let origin = av_recording::segment_sender_clock_origin(&wrapped, &config, 2_000)?;
    assert_eq!(origin.audio_minus_video_ms, 64);
    assert_eq!(origin.audio_ticks, (u64::from(u32::MAX) - 50 + 64) * 16);
    let (missing, _) = first_segment(10_000, false, 0, &config)?;
    assert_eq!(
        av_recording::segment_sender_clock_origin(&missing, &config, 2_000),
        Err(av_recording::Error::NoAudio)
    );
    let (distant, _) = first_segment(10_000, true, 5_000, &config)?;
    assert_eq!(
        av_recording::segment_sender_clock_origin(&distant, &config, 2_000),
        Err(av_recording::Error::Alignment)
    );
    Ok(())
}

#[cfg(unix)]
#[test]
#[ignore = "explicit synthetic output path required for independent MP4 probe"]
fn emit_synthetic_sender_clock_mp4_for_independent_probe() -> TestResult {
    use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt, path::PathBuf};

    let path =
        PathBuf::from(std::env::var_os("FSS_SYNTHETIC_MP4_OUTPUT").ok_or("missing output path")?);
    if !path.is_absolute() {
        return Err("output path must be absolute".into());
    }
    let config = aac::Configuration::parse_explicit(&[0x14, 0x08])?;
    let (segment, init) = first_segment(10_000, true, 0, &config)?;
    let origin = av_recording::segment_sender_clock_origin(&segment, &config, 2_000)?;
    let mut muxer = av_recording::Muxer::new(
        &init,
        &config,
        origin.audio_ticks,
        0,
        32,
        32,
        Mp4Limits::default(),
    )?;
    let fragment = muxer.fragment(&init, &segment)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(init.bytes())?;
    file.write_all(fragment.bytes())?;
    file.sync_all()?;
    Ok(())
}

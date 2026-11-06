#![forbid(unsafe_code)]
//! FLV-to-MP4 byte provenance, timeline and refusal contracts.
#[allow(dead_code)]
mod common;

use common::{BASELINE, Error, KEY, groups};
use fss_container::{
    Mp4Error, Mp4Limits,
    demux::{AvcMp4, DemuxLimits},
    flv_avc::{Muxer, SourceKey, TimedSample},
};
use fss_packet::{
    avc::AvcPictureGroup,
    extended_flv::{
        Limits,
        stream::{Framer, Next, SourceRecord},
    },
};

type TestResult = Result<(), Error>;
const SOURCE: SourceKey = SourceKey {
    connection: 7,
    generation: 1,
};

fn tag(kind: u8, timestamp: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut wire = vec![
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
    wire.extend_from_slice(payload);
    wire.extend_from_slice(&(11_u32 + n as u32).to_be_bytes());
    wire
}

fn fixture() -> Result<(Vec<u8>, Vec<SourceRecord>), Error> {
    fixture_with_audio_step(40)
}

fn fixture_with_audio_step(audio_step: u32) -> Result<(Vec<u8>, Vec<SourceRecord>), Error> {
    fixture_with_audio(audio_step, &[2])
}

fn fixture_with_audio(
    audio_step: u32,
    audio_body: &[u8],
) -> Result<(Vec<u8>, Vec<SourceRecord>), Error> {
    fixture_with_audio_count(audio_step, audio_body, None)
}

fn fixture_with_audio_count(
    audio_step: u32,
    audio_body: &[u8],
    count: Option<usize>,
) -> Result<(Vec<u8>, Vec<SourceRecord>), Error> {
    let pictures = groups(BASELINE, KEY, true, false)?;
    assert!(pictures.len() >= 4);
    let sps = pictures[0].sps().nal_bytes();
    let pps = pictures[0].pps().nal_bytes();
    let mut configuration = vec![0x17, 0, 0, 0, 0, 1, sps[1], sps[2], sps[3], 0xff, 0xe1];
    configuration.extend_from_slice(&u16::try_from(sps.len())?.to_be_bytes());
    configuration.extend_from_slice(sps);
    configuration.push(1);
    configuration.extend_from_slice(&u16::try_from(pps.len())?.to_be_bytes());
    configuration.extend_from_slice(pps);
    let mut wire = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    wire.extend(tag(9, 0, &configuration));
    for (index, picture) in pictures
        .iter()
        .cycle()
        .take(count.unwrap_or(pictures.len()))
        .enumerate()
    {
        let mut audio = vec![0xaf, 1];
        audio.extend_from_slice(audio_body);
        wire.extend(tag(8, index as u32 * audio_step, &audio));
        wire.extend([0x77; 3]);
        wire.extend(video(picture, index as u32 * 40));
    }
    let mut framer = Framer::new(Limits::default(), 1024 * 1024)?;
    framer.append(0, &wire)?;
    let mut records = Vec::new();
    while let Next::Record(record) = framer.take()? {
        records.push(record);
    }
    Ok((wire, records))
}

fn video(picture: &AvcPictureGroup, timestamp: u32) -> Vec<u8> {
    let mut payload = vec![0x17, 1, 0, 0, 0];
    for nal in picture
        .nals()
        .iter()
        .filter(|nal| !matches!(nal.nal_type(), 7 | 8))
    {
        payload.extend_from_slice(&(nal.bytes().len() as u32).to_be_bytes());
        payload.extend_from_slice(nal.bytes());
    }
    tag(9, timestamp, &payload)
}

#[test]
fn source_mapped_fragments_round_trip_through_independent_demux() -> TestResult {
    let (wire, records) = fixture()?;
    assert_eq!(records.len(), 10);
    let mut mux = Muxer::new(SOURCE, &records[1], Mp4Limits::default())?;
    let config_sources = mux.configuration_sources();
    assert_eq!(
        &wire[config_sources[0].start as usize..config_sources[0].end as usize],
        &mux.initialization().bytes()[mux.initialization().sps_range()]
    );
    assert_eq!(
        &wire[config_sources[1].start as usize..config_sources[1].end as usize],
        &mux.initialization().bytes()[mux.initialization().pps_range()]
    );
    let samples = [
        TimedSample {
            record: &records[3],
            decode_time_ms: 0,
            duration_ms: 40,
        },
        TimedSample {
            record: &records[5],
            decode_time_ms: 40,
            duration_ms: 40,
        },
        TimedSample {
            record: &records[7],
            decode_time_ms: 80,
            duration_ms: 40,
        },
    ];
    let coverage: Vec<_> = records[2..=9].iter().collect();
    let fragment = mux.fragment(&samples, &records[9], &coverage)?;
    assert_eq!(fragment.sequence(), 1);
    assert_eq!(fragment.key(), SOURCE);
    assert_eq!(fragment.samples().len(), 3);
    for mapping in fragment.nals() {
        assert_eq!(
            &wire[mapping.source.start as usize..mapping.source.end as usize],
            &fragment.bytes()[mapping.target.clone()]
        );
    }
    let mut file = mux.initialization().bytes().to_vec();
    let offset = file.len();
    file.extend_from_slice(fragment.bytes());
    let parsed = AvcMp4::parse(&file, None, DemuxLimits::default())?;
    assert_eq!(parsed.samples().len(), 3);
    for (sample, output) in parsed.samples().iter().zip(fragment.samples()) {
        assert_eq!(
            sample.source,
            offset + output.target.start..offset + output.target.end
        );
        assert_eq!(sample.decode_time, output.decode_time_ms);
        assert_eq!(sample.duration, output.duration_ms);
        assert_eq!(sample.contains_idr, output.idr);
    }
    let extracted = parsed.annex_b(0, 3)?;
    let mut derived_decoder =
        fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
    let mut derived_frames = derived_decoder.decode_annex_b(extracted.bytes())?;
    derived_frames.extend(derived_decoder.finish()?);
    let mut original_decoder =
        fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
    let mut original_frames = original_decoder.decode_annex_b(BASELINE)?;
    original_frames.extend(original_decoder.finish()?);
    assert_eq!(derived_frames.len(), 3);
    assert!(original_frames.len() >= 3);
    for (derived, original) in derived_frames.iter().zip(&original_frames) {
        assert_eq!(
            (derived.width(), derived.height()),
            (original.width(), original.height())
        );
        assert_eq!(derived.i420_sha256(), original.i420_sha256());
    }
    assert_eq!(mux.next_sequence(), Some(2));
    Ok(())
}

#[test]
fn av_fragment_keeps_video_and_audio_source_mappings() -> TestResult {
    use fss_container::flv_av::{self, TimedAudio};
    use fss_packet::extended_flv::{aac, aac_adts, aac_clock};

    let (wire, records) = fixture_with_audio_step(64)?;
    let mut video = Muxer::new(SOURCE, &records[1], Mp4Limits::default())?;
    let config_bytes = [0x14, 0x08];
    let audio_config = aac::Configuration::parse_explicit(&config_bytes)?;
    let init = video.av_initialization(&audio_config)?;
    assert_eq!(
        &init.bytes()[init.audio_configuration_range()],
        &config_bytes
    );
    assert_eq!(
        &wire[video.configuration_sources()[0].start as usize
            ..video.configuration_sources()[0].end as usize],
        &init.bytes()[init.sps_range()]
    );
    let video_samples = [
        TimedSample {
            record: &records[3],
            decode_time_ms: 0,
            duration_ms: 40,
        },
        TimedSample {
            record: &records[5],
            decode_time_ms: 40,
            duration_ms: 40,
        },
        TimedSample {
            record: &records[7],
            decode_time_ms: 80,
            duration_ms: 40,
        },
    ];
    let coverage: Vec<_> = records[2..=9].iter().collect();
    let video_fragment = video.fragment(&video_samples, &records[9], &coverage)?;
    let frame = aac_adts::source_frame(
        &audio_config,
        &records[2],
        Limits::default(),
        aac::Limits::default(),
    )?
    .ok_or("missing audio")?;
    let second = aac_adts::source_frame(
        &audio_config,
        &records[4],
        Limits::default(),
        aac::Limits::default(),
    )?
    .ok_or("missing second audio")?;
    let mut clock = aac_clock::Clock::new(&audio_config, 0, 1, 2)?;
    let audio = [
        TimedAudio {
            frame: &frame,
            time: clock.observe(frame.timestamp_ms())?,
        },
        TimedAudio {
            frame: &second,
            time: clock.observe(second.timestamp_ms())?,
        },
    ];
    let combined = flv_av::fragment(
        &init,
        &video_fragment,
        &audio_config,
        &audio,
        Mp4Limits::default(),
    )?;
    assert_eq!(combined.audio().len(), 2);
    for mapping in video_fragment.nals() {
        let shifted = mapping.target.start + combined.video_target_shift()
            ..mapping.target.end + combined.video_target_shift();
        assert_eq!(
            &wire[mapping.source.start as usize..mapping.source.end as usize],
            &combined.bytes()[shifted]
        );
    }
    for mapping in combined.audio() {
        assert_eq!(
            &wire[mapping.source.start as usize..mapping.source.end as usize],
            &combined.bytes()[mapping.target.clone()]
        );
    }
    let mut file = init.bytes().to_vec();
    file.extend_from_slice(combined.bytes());
    let parsed = AvcMp4::parse(&file, None, DemuxLimits::default())?;
    assert_eq!(parsed.samples().len(), 3);
    assert_eq!(parsed.samples()[0].decode_time, 0);

    let other_bytes = [0x11, 0x88];
    let wrong = aac::Configuration::parse_explicit(&other_bytes)?;
    assert!(matches!(
        flv_av::fragment(&init, &video_fragment, &wrong, &audio, Mp4Limits::default()),
        Err(Mp4Error::ParameterSet)
    ));
    let other_key = SourceKey {
        connection: SOURCE.connection + 1,
        generation: SOURCE.generation,
    };
    let other_init = Muxer::new(other_key, &records[1], Mp4Limits::default())?
        .av_initialization(&audio_config)?;
    assert!(matches!(
        flv_av::fragment(
            &other_init,
            &video_fragment,
            &audio_config,
            &audio,
            Mp4Limits::default()
        ),
        Err(Mp4Error::StreamMismatch)
    ));
    assert!(matches!(
        flv_av::fragment(
            &init,
            &video_fragment,
            &audio_config,
            &[],
            Mp4Limits::default()
        ),
        Err(Mp4Error::Limit)
    ));
    let tight = Mp4Limits {
        max_samples: 1,
        ..Mp4Limits::default()
    };
    assert!(matches!(
        flv_av::fragment(&init, &video_fragment, &audio_config, &audio[..1], tight),
        Err(Mp4Error::Limit)
    ));
    let bad_time = fss_packet::extended_flv::aac_clock::SampleTime {
        decode_ticks: audio[1].time.decode_ticks + 1,
        ..audio[1].time
    };
    let discontinuous = [
        TimedAudio {
            frame: &frame,
            time: audio[0].time,
        },
        TimedAudio {
            frame: &second,
            time: bad_time,
        },
    ];
    assert!(matches!(
        flv_av::fragment(
            &init,
            &video_fragment,
            &audio_config,
            &discontinuous,
            Mp4Limits::default()
        ),
        Err(Mp4Error::Timeline)
    ));
    let bad_elapsed = fss_packet::extended_flv::aac_clock::SampleTime {
        elapsed_ms: audio[1].time.elapsed_ms + 1,
        ..audio[1].time
    };
    let inconsistent = [
        TimedAudio {
            frame: &frame,
            time: audio[0].time,
        },
        TimedAudio {
            frame: &second,
            time: bad_elapsed,
        },
    ];
    assert!(matches!(
        flv_av::fragment(
            &init,
            &video_fragment,
            &audio_config,
            &inconsistent,
            Mp4Limits::default()
        ),
        Err(Mp4Error::Timeline)
    ));
    Ok(())
}

#[test]
fn av_session_preserves_cross_fragment_sequence_and_audio_clock() -> TestResult {
    use fss_container::flv_av::{self, TimedAudio};
    use fss_packet::extended_flv::{aac, aac_adts, aac_clock};

    let (_, records) = fixture_with_audio_count(64, &[2], Some(9))?;
    assert_eq!(records.len(), 20);
    let config_bytes = [0x14, 0x08];
    let config = aac::Configuration::parse_explicit(&config_bytes)?;
    let mut video_mux = Muxer::new(SOURCE, &records[1], Mp4Limits::default())?;
    let init = video_mux.av_initialization(&config)?;
    let first_video: Vec<_> = (0..4)
        .map(|i| TimedSample {
            record: &records[3 + 2 * i],
            decode_time_ms: i as u64 * 40,
            duration_ms: 40,
        })
        .collect();
    let second_video: Vec<_> = (4..8)
        .map(|i| TimedSample {
            record: &records[3 + 2 * i],
            decode_time_ms: i as u64 * 40,
            duration_ms: 40,
        })
        .collect();
    let first_coverage: Vec<_> = records[2..=11].iter().collect();
    let second_coverage: Vec<_> = records[10..=19].iter().collect();
    let first_video = video_mux.fragment(&first_video, &records[11], &first_coverage)?;
    let second_video = video_mux.fragment(&second_video, &records[19], &second_coverage)?;
    let mut frames = Vec::new();
    for i in 0..8 {
        frames.push(
            aac_adts::source_frame(
                &config,
                &records[2 + 2 * i],
                Limits::default(),
                aac::Limits::default(),
            )?
            .ok_or("missing audio")?,
        );
    }
    let mut clock = aac_clock::Clock::new(&config, 0, 1, 8)?;
    let mut times = Vec::new();
    for frame in &frames {
        times.push(clock.observe(frame.timestamp_ms())?);
    }
    let first_audio: Vec<_> = (0..4)
        .map(|i| TimedAudio {
            frame: &frames[i],
            time: times[i],
        })
        .collect();
    let second_audio: Vec<_> = (4..8)
        .map(|i| TimedAudio {
            frame: &frames[i],
            time: times[i],
        })
        .collect();
    let mut session = flv_av::Session::new(&init)?;
    let first = session.fragment(
        &init,
        &first_video,
        &config,
        &first_audio,
        Mp4Limits::default(),
    )?;
    assert_eq!(first.audio().len(), 4);
    assert!(matches!(
        session.fragment(
            &init,
            &first_video,
            &config,
            &first_audio,
            Mp4Limits::default()
        ),
        Err(Mp4Error::SourceOrder)
    ));
    let wrong = [TimedAudio {
        frame: &frames[4],
        time: aac_clock::SampleTime {
            decode_ticks: times[4].decode_ticks + 1,
            ..times[4]
        },
    }];
    assert!(matches!(
        session.fragment(&init, &second_video, &config, &wrong, Mp4Limits::default()),
        Err(Mp4Error::Timeline)
    ));
    let second = session.fragment(
        &init,
        &second_video,
        &config,
        &second_audio,
        Mp4Limits::default(),
    )?;
    assert_eq!(second.video().sequence(), 2);
    assert_eq!(second.audio().len(), 4);
    Ok(())
}

#[cfg(unix)]
#[test]
#[ignore = "requires a caller-supplied synthetic AAC body and a new private output path"]
fn synthetic_av_for_external_decoder() -> TestResult {
    use fss_container::flv_av::{self, TimedAudio};
    use fss_packet::extended_flv::{aac, aac_adts, aac_clock};
    use std::io::{Read, Write};
    use std::os::unix::fs::OpenOptionsExt;

    let input = std::env::var_os("FSS_SYNTHETIC_AAC_BODY").ok_or("missing synthetic audio path")?;
    let output = std::env::var_os("FSS_SYNTHETIC_AV_OUTPUT").ok_or("missing output path")?;
    let mut body = Vec::new();
    std::fs::File::open(input)?
        .take(8185)
        .read_to_end(&mut body)?;
    if body.is_empty() || body.len() > 8184 {
        return Err("invalid synthetic audio length".into());
    }
    let (_, records) = fixture_with_audio(64, &body)?;
    let mut video = Muxer::new(SOURCE, &records[1], Mp4Limits::default())?;
    let config_bytes = [0x14, 0x08];
    let config = aac::Configuration::parse_explicit(&config_bytes)?;
    let init = video.av_initialization(&config)?;
    let videos = [
        TimedSample {
            record: &records[3],
            decode_time_ms: 0,
            duration_ms: 40,
        },
        TimedSample {
            record: &records[5],
            decode_time_ms: 40,
            duration_ms: 40,
        },
        TimedSample {
            record: &records[7],
            decode_time_ms: 80,
            duration_ms: 40,
        },
    ];
    let source: Vec<_> = records[2..=9].iter().collect();
    let video = video.fragment(&videos, &records[9], &source)?;
    let first = aac_adts::source_frame(
        &config,
        &records[2],
        Limits::default(),
        aac::Limits::default(),
    )?
    .ok_or("missing audio")?;
    let second = aac_adts::source_frame(
        &config,
        &records[4],
        Limits::default(),
        aac::Limits::default(),
    )?
    .ok_or("missing audio")?;
    let mut clock = aac_clock::Clock::new(&config, 0, 1, 2)?;
    let audio = [
        TimedAudio {
            frame: &first,
            time: clock.observe(first.timestamp_ms())?,
        },
        TimedAudio {
            frame: &second,
            time: clock.observe(second.timestamp_ms())?,
        },
    ];
    let av = flv_av::fragment(&init, &video, &config, &audio, Mp4Limits::default())?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)?;
    file.write_all(init.bytes())?;
    file.write_all(av.bytes())?;
    file.flush()?;
    Ok(())
}

#[test]
fn omitted_audio_or_video_bad_timing_and_wrong_source_preserve_cursor() -> TestResult {
    let (_, records) = fixture()?;
    let mut mux = Muxer::new(SOURCE, &records[1], Mp4Limits::default())?;
    let first = TimedSample {
        record: &records[3],
        decode_time_ms: 0,
        duration_ms: 40,
    };
    let coverage: Vec<_> = records[2..=5].iter().collect();
    assert_eq!(
        mux.fragment(&[first], &records[5], &[&records[3], &records[5]]),
        Err(Mp4Error::SourceOrder)
    );
    let skipped = TimedSample {
        record: &records[5],
        decode_time_ms: 40,
        duration_ms: 40,
    };
    assert_eq!(
        mux.fragment(
            &[skipped],
            &records[7],
            &records[2..=7].iter().collect::<Vec<_>>()
        ),
        Err(Mp4Error::UnverifiedPicture)
    );
    let bad_timing = TimedSample {
        duration_ms: 41,
        ..first
    };
    assert_eq!(
        mux.fragment(&[bad_timing], &records[5], &coverage),
        Err(Mp4Error::Timeline)
    );
    assert_eq!(mux.next_sequence(), Some(1));
    assert_eq!(
        mux.fragment(&[first], &records[5], &coverage)?.sequence(),
        1
    );
    Ok(())
}

#[test]
fn limits_and_epoch_refusal_are_transactional() -> TestResult {
    let (_, records) = fixture()?;
    assert!(matches!(
        Muxer::new(
            SourceKey {
                connection: 0,
                generation: 1
            },
            &records[1],
            Mp4Limits::default()
        ),
        Err(Mp4Error::Configuration)
    ));
    let mut mux = Muxer::new(
        SOURCE,
        &records[1],
        Mp4Limits {
            max_fragment_bytes: 8,
            ..Mp4Limits::default()
        },
    )?;
    let first = TimedSample {
        record: &records[3],
        decode_time_ms: 0,
        duration_ms: 40,
    };
    let coverage: Vec<_> = records[2..=5].iter().collect();
    assert_eq!(
        mux.fragment(&[first], &records[5], &coverage),
        Err(Mp4Error::Limit)
    );
    assert_eq!(mux.next_sequence(), Some(1));
    Ok(())
}

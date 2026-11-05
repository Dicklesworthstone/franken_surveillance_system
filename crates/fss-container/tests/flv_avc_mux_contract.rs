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
    for (index, picture) in pictures.iter().enumerate() {
        wire.extend(tag(8, index as u32 * 40, &[0xaf, 1, 2]));
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

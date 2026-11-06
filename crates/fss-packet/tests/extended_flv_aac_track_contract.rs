#![forbid(unsafe_code)]
//! AAC source spans, configuration epochs, and failure fencing.

use fss_packet::extended_flv::{
    Limits, aac, aac_adts,
    aac_track::{Error, Observation, Track},
    stream::{Framer, Next, SearchMode, SourceRecord},
};
use std::io::Read;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const HEADER: &[u8] = b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00";

fn tag(kind: u8, timestamp: u32, payload: &[u8]) -> Vec<u8> {
    let size = payload.len();
    let mut output = vec![
        kind,
        (size >> 16) as u8,
        (size >> 8) as u8,
        size as u8,
        (timestamp >> 16) as u8,
        (timestamp >> 8) as u8,
        timestamp as u8,
        (timestamp >> 24) as u8,
        0,
        0,
        0,
    ];
    output.extend_from_slice(payload);
    output.extend_from_slice(&(11_u32 + size as u32).to_be_bytes());
    output
}

fn records(wire: &[u8]) -> TestResultRecords {
    let mut framer = Framer::new(Limits::default(), 4096)?;
    framer.append(0, wire)?;
    let mut records = Vec::new();
    while let Next::Record(record) = framer.take()? {
        records.push(record);
    }
    Ok(records)
}
type TestResultRecords = Result<Vec<SourceRecord>, Box<dyn std::error::Error>>;

fn selected<'a>(wire: &'a [u8], span: &std::ops::Range<u64>) -> &'a [u8] {
    &wire[span.start as usize..span.end as usize]
}

#[test]
fn configuration_and_sample_keep_connection_relative_source_spans() -> TestResult {
    let mut wire = HEADER.to_vec();
    wire.extend(tag(8, 0, &[0xaf, 0, 0x14, 0x08]));
    wire.extend([0x77; 3]);
    wire.extend(tag(9, 1, &[0x17, 1]));
    wire.extend(tag(8, 64, &[0xaf, 1, 0xde, 0xad]));
    let records = records(&wire)?;
    assert_eq!(records.len(), 4);
    let mut track = Track::new(Limits::default(), aac::Limits::default());
    assert_eq!(track.observe(&records[0])?, Observation::Header);
    let Observation::Configuration {
        epoch,
        provisional,
        tag: config_tag,
        configuration,
        sample_rate,
        channels,
        frame_samples,
    } = track.observe(&records[1])?
    else {
        return Err("configuration missing".into());
    };
    assert_eq!(
        (epoch, provisional, sample_rate, channels, frame_samples),
        (1, false, 16_000, 1, 1024)
    );
    assert_eq!(
        selected(&wire, &config_tag),
        tag(8, 0, &[0xaf, 0, 0x14, 0x08])
    );
    assert_eq!(selected(&wire, &configuration), &[0x14, 0x08]);
    assert_eq!(track.observe(&records[2])?, Observation::Other);
    let Observation::Sample {
        epoch,
        provisional,
        timestamp_ms,
        tag: sample_tag,
        body,
    } = track.observe(&records[3])?
    else {
        return Err("sample missing".into());
    };
    assert_eq!((epoch, provisional, timestamp_ms), (1, false, 64));
    assert_eq!(
        selected(&wire, &sample_tag),
        tag(8, 64, &[0xaf, 1, 0xde, 0xad])
    );
    assert_eq!(selected(&wire, &body), &[0xde, 0xad]);
    Ok(())
}

#[test]
fn raw_before_configuration_stays_unconfigured_and_changes_create_epochs() -> TestResult {
    let mut wire = HEADER.to_vec();
    wire.extend(tag(8, 1, &[0xaf, 1, 0x21]));
    wire.extend(tag(8, 2, &[0xaf, 0, 0x14, 0x08]));
    wire.extend(tag(8, 3, &[0xaf, 1, 0x22]));
    wire.extend(tag(8, 4, &[0xaf, 0, 0x14, 0x0c]));
    wire.extend(tag(8, 5, &[0xaf, 1, 0x23]));
    let records = records(&wire)?;
    let mut track = Track::new(Limits::default(), aac::Limits::default());
    assert_eq!(track.observe(&records[0])?, Observation::Header);
    assert!(matches!(
        track.observe(&records[1])?,
        Observation::UnconfiguredSample {
            timestamp_ms: 1,
            ..
        }
    ));
    assert!(matches!(
        track.observe(&records[2])?,
        Observation::Configuration {
            epoch: 1,
            frame_samples: 1024,
            ..
        }
    ));
    assert!(matches!(
        track.observe(&records[3])?,
        Observation::Sample {
            epoch: 1,
            timestamp_ms: 3,
            ..
        }
    ));
    assert!(matches!(
        track.observe(&records[4])?,
        Observation::Configuration {
            epoch: 2,
            frame_samples: 960,
            ..
        }
    ));
    assert!(matches!(
        track.observe(&records[5])?,
        Observation::Sample {
            epoch: 2,
            timestamp_ms: 5,
            ..
        }
    ));
    Ok(())
}

#[test]
fn unsupported_audio_and_discontinuity_fence_without_losing_source() -> TestResult {
    let mut wire = HEADER.to_vec();
    wire.extend(tag(8, 0, &[0xaf, 0, 0x14, 0x08]));
    wire.extend(tag(8, 2, &[0xaf, 0, 0x14, 0x09]));
    wire.extend(tag(8, 3, &[0xaf, 1, 0x22]));
    let records = records(&wire)?;
    let mut track = Track::new(Limits::default(), aac::Limits::default());
    track.observe(&records[0])?;
    track.observe(&records[1])?;
    assert_eq!(
        track.observe(&records[2]),
        Err(Error::Aac(aac::Error::UnsupportedGaFlags))
    );
    assert_eq!(track.observe(&records[3]), Err(Error::Fenced));
    let start = records[2].offset() as usize;
    assert_eq!(
        &wire[start..start + records[2].bytes().len()],
        records[2].bytes()
    );
    let mut missing = Track::new(Limits::default(), aac::Limits::default());
    assert_eq!(missing.observe(&records[1]), Err(Error::Discontinuity));
    assert_eq!(missing.observe(&records[0]), Err(Error::Fenced));
    Ok(())
}

#[test]
fn vendor_audio_kind_is_explicitly_unsupported() -> TestResult {
    let mut wire = HEADER.to_vec();
    wire.extend(tag(10, 1, &[0xcf, 0, 3, 0]));
    let records = records(&wire)?;
    let mut track = Track::new(Limits::default(), aac::Limits::default());
    assert_eq!(track.observe(&records[0])?, Observation::Header);
    assert_eq!(track.observe(&records[1]), Err(Error::UnsupportedAudioKind));
    assert_eq!(track.observe(&records[1]), Err(Error::Fenced));
    Ok(())
}

#[test]
fn source_adts_frame_borrows_exact_bytes_and_refuses_configuration_changes() -> TestResult {
    let mut wire = HEADER.to_vec();
    wire.extend(tag(9, 1, &[0x17, 1]));
    wire.extend([0x77; 3]);
    wire.extend(tag(8, 64, &[0xaf, 1, 0xde, 0xad]));
    wire.extend(tag(9, 65, &[0x17, 1]));
    wire.extend(tag(8, 66, &[0xaf, 0, 0x14, 0x08]));
    wire.extend(tag(10, 67, &[0xcf, 0, 3, 0]));
    let records = records(&wire)?;
    assert_eq!(records.len(), 6);
    let config_bytes = [0x14, 0x08];
    let config = aac::Configuration::parse_explicit(&config_bytes)?;
    let read = |index| {
        aac_adts::source_frame(
            &config,
            &records[index],
            Limits::default(),
            aac::Limits::default(),
        )
    };
    assert!(read(0)?.is_none());
    assert!(read(1)?.is_none());
    let frame = read(2)?.ok_or("audio frame missing")?;
    assert_eq!(frame.header(), &[0xff, 0xf1, 0x60, 0x40, 0x01, 0x3f, 0xfc]);
    assert_eq!(frame.body(), &[0xde, 0xad]);
    assert_eq!(selected(&wire, &frame.body_range()), frame.body());
    assert_eq!(frame.timestamp_ms(), 64);
    assert!(!frame.provisional());
    assert!(!format!("{frame:?}").contains("de, ad"));
    assert!(read(3)?.is_none());
    assert!(matches!(
        read(4),
        Err(aac_adts::SourceError::ConfigurationObserved)
    ));
    assert!(matches!(
        read(5),
        Err(aac_adts::SourceError::UnsupportedAudioKind)
    ));
    Ok(())
}

#[test]
fn provisional_configuration_taints_dependent_audio() -> TestResult {
    let limits = Limits {
        max_payload: 256,
        max_trailer: 256,
        ..Limits::default()
    };
    let mut framer = Framer::with_mode(limits, 512, SearchMode::Provisional)?;
    let mut track = Track::new(limits, aac::Limits::default());
    framer.append(0, HEADER)?;
    let Next::Record(header) = framer.take()? else {
        return Err("header".into());
    };
    track.observe(&header)?;
    framer.append(framer.next_offset(), &tag(18, 0, b"metadata"))?;
    let Next::Record(first) = framer.take()? else {
        return Err("first".into());
    };
    assert_eq!(track.observe(&first)?, Observation::Other);
    let config = tag(8, 0, &[0xaf, 0, 0x14, 0x08]);
    let mut payload = config.clone();
    payload.resize(200, 0x77);
    let outer = tag(9, 1, &payload);
    framer.append(framer.next_offset(), &outer[..11 + config.len()])?;
    let Next::Record(candidate) = framer.take()? else {
        return Err("candidate".into());
    };
    assert!(matches!(
        track.observe(&candidate)?,
        Observation::Configuration {
            provisional: true,
            ..
        }
    ));
    framer.append(framer.next_offset(), &tag(8, 4, &[0xaf, 1, 0x44]))?;
    let Next::Record(sample) = framer.take()? else {
        return Err("sample".into());
    };
    assert!(matches!(
        track.observe(&sample)?,
        Observation::Sample {
            provisional: true,
            ..
        }
    ));
    let explicit = aac::Configuration::parse_explicit(&[0x14, 0x08])?;
    let derived = aac_adts::source_frame(&explicit, &sample, limits, aac::Limits::default())?
        .ok_or("provisional frame missing")?;
    assert!(derived.provisional());
    assert_eq!(derived.body(), &[0x44]);
    Ok(())
}

#[test]
#[ignore = "requires an explicitly authorized, bounded audio capture on stdin"]
fn owner_camera_audio_track_replay() -> TestResult {
    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut input)?;
    if input.len() > 8 * 1024 * 1024 || !input.starts_with(b"FLV\x01") {
        return Err("invalid bounded laboratory input".into());
    }
    let limits = Limits::default();
    let mut framer = Framer::with_mode(limits, 8 * 1024 * 1024, SearchMode::StructuredTrailer16)?;
    let mut track = Track::new(limits, aac::Limits::default());
    framer.append(0, &input)?;
    let (mut records, mut configurations, mut configured, mut unconfigured, mut provisional) =
        (0usize, 0usize, 0usize, 0usize, 0usize);
    while let Next::Record(record) = framer.take()? {
        records += 1;
        if records > 10_000 {
            return Err("laboratory record limit".into());
        }
        let offset = usize::try_from(record.offset())?;
        let end = offset
            .checked_add(record.bytes().len())
            .ok_or("offset overflow")?;
        if input.get(offset..end) != Some(record.bytes()) {
            return Err("source record mismatch".into());
        }
        match track.observe(&record)? {
            Observation::Header | Observation::Other => (),
            Observation::Configuration {
                provisional: uncertain,
                configuration,
                ..
            } => {
                if input
                    .get(usize::try_from(configuration.start)?..usize::try_from(configuration.end)?)
                    .is_none()
                {
                    return Err("configuration source span".into());
                }
                configurations += 1;
                provisional += usize::from(uncertain);
            }
            Observation::Sample {
                provisional: uncertain,
                body,
                ..
            } => {
                if input
                    .get(usize::try_from(body.start)?..usize::try_from(body.end)?)
                    .is_none_or(<[u8]>::is_empty)
                {
                    return Err("sample source span".into());
                }
                configured += 1;
                provisional += usize::from(uncertain);
            }
            Observation::UnconfiguredSample {
                provisional: uncertain,
                body,
                ..
            } => {
                if input
                    .get(usize::try_from(body.start)?..usize::try_from(body.end)?)
                    .is_none_or(<[u8]>::is_empty)
                {
                    return Err("unconfigured source span".into());
                }
                unconfigured += 1;
                provisional += usize::from(uncertain);
            }
        }
    }
    let remainder = framer.retire();
    if input.get(usize::try_from(remainder.offset)?..) != Some(remainder.bytes()) {
        return Err("unparsed tail mismatch".into());
    }
    if configured + unconfigured == 0 || (configurations == 0 && configured != 0) {
        return Err("audio or configuration accounting failed".into());
    }
    println!(
        "aac_configurations={configurations} configured_samples={configured} unconfigured_samples={unconfigured} provisional_observations={provisional} records={records} tail_bytes={} source=caller_supplied frame_decode=not_attempted authentication=unverified media_saved=no",
        remainder.bytes().len()
    );
    Ok(())
}

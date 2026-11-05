#![forbid(unsafe_code)]
//! Source-span, epoch and failure contracts for direct-UniFi AVC tracks.

use fss_packet::extended_flv::{
    Limits, avc,
    stream::{Framer, Next, SearchMode, SourceRecord},
    track::{Error, Observation, Track},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const HEADER: &[u8] = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00";

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
fn config() -> Vec<u8> {
    tag(
        9,
        0,
        &[
            0x17, 0, 0, 0, 0, 1, 100, 0, 31, 0xff, 0xe1, 0, 3, 0x67, 0x64, 0x1f, 1, 0, 2, 0x68,
            0xaa,
        ],
    )
}
fn sample(time: u32) -> Vec<u8> {
    tag(
        9,
        time,
        &[
            0x17, 1, 0xff, 0xff, 0xfe, 0, 0, 0, 2, 0x65, 0x42, 0, 0, 0, 2, 0x41, 0x33,
        ],
    )
}
fn records(wire: &[u8]) -> Result<Vec<SourceRecord>, Box<dyn std::error::Error>> {
    let mut f = Framer::new(Limits::default(), 4096)?;
    f.append(0, wire)?;
    let mut out = Vec::new();
    while let Next::Record(record) = f.take()? {
        out.push(record);
    }
    Ok(out)
}
fn selected<'a>(wire: &'a [u8], span: &std::ops::Range<u64>) -> &'a [u8] {
    &wire[span.start as usize..span.end as usize]
}

#[test]
fn epochs_and_nals_keep_exact_connection_relative_source_spans() -> TestResult {
    let mut wire = HEADER.to_vec();
    wire.extend(config());
    wire.extend([0x77; 3]);
    wire.extend(sample(40));
    wire.extend(config());
    wire.extend(sample(80));
    let r = records(&wire)?;
    assert_eq!(r.len(), 5);
    let mut track = Track::new(Limits::default(), avc::Limits::default());
    assert_eq!(track.observe(&r[0])?, Observation::Header);
    let Observation::Configuration {
        epoch,
        provisional,
        tag,
        parameter_sets,
    } = track.observe(&r[1])?
    else {
        return Err("missing configuration".into());
    };
    assert_eq!(epoch, 1);
    assert!(!provisional);
    assert_eq!(selected(&wire, &tag), config());
    assert_eq!(selected(&wire, &parameter_sets[0]), &[0x67, 0x64, 0x1f]);
    assert_eq!(selected(&wire, &parameter_sets[1]), &[0x68, 0xaa]);
    let Observation::Sample {
        epoch,
        provisional,
        timestamp_ms,
        composition_offset_ms,
        frame_type,
        contains_idr_nal_type,
        nals,
    } = track.observe(&r[2])?
    else {
        return Err("missing sample".into());
    };
    assert_eq!(
        (
            epoch,
            provisional,
            timestamp_ms,
            composition_offset_ms,
            frame_type,
            contains_idr_nal_type
        ),
        (1, false, 40, -2, 1, true)
    );
    assert_eq!(selected(&wire, &nals[0]), &[0x65, 0x42]);
    assert_eq!(selected(&wire, &nals[1]), &[0x41, 0x33]);
    assert!(matches!(
        track.observe(&r[3])?,
        Observation::Configuration { epoch: 2, .. }
    ));
    assert!(matches!(
        track.observe(&r[4])?,
        Observation::Sample {
            epoch: 2,
            timestamp_ms: 80,
            ..
        }
    ));
    Ok(())
}

#[test]
fn midstream_sample_and_end_of_sequence_do_not_invent_configuration() -> TestResult {
    let mut wire = HEADER.to_vec();
    wire.extend(sample(10));
    wire.extend(config());
    wire.extend(tag(9, 20, &[0x17, 2, 0, 0, 0]));
    wire.extend(sample(30));
    let r = records(&wire)?;
    let mut t = Track::new(Limits::default(), avc::Limits::default());
    assert_eq!(t.observe(&r[0])?, Observation::Header);
    assert!(matches!(
        t.observe(&r[1])?,
        Observation::UnconfiguredSample {
            timestamp_ms: 10,
            ..
        }
    ));
    assert!(matches!(
        t.observe(&r[2])?,
        Observation::Configuration { epoch: 1, .. }
    ));
    assert_eq!(t.observe(&r[3])?, Observation::EndOfSequence);
    assert!(matches!(
        t.observe(&r[4])?,
        Observation::UnconfiguredSample {
            timestamp_ms: 30,
            ..
        }
    ));
    Ok(())
}

#[test]
fn discontinuity_and_malformed_video_fence_the_track_without_discarding_source() -> TestResult {
    let mut wire = HEADER.to_vec();
    wire.extend(config());
    wire.extend(tag(9, 5, &[0x17, 1, 0, 0, 0, 0, 0, 0, 9, 0x65]));
    wire.extend(sample(6));
    let r = records(&wire)?;
    let mut t = Track::new(Limits::default(), avc::Limits::default());
    assert_eq!(t.observe(&r[0])?, Observation::Header);
    t.observe(&r[1])?;
    assert_eq!(
        t.observe(&r[2]),
        Err(Error::Avc(avc::Error::InvalidNalUnits))
    );
    assert_eq!(t.observe(&r[3]), Err(Error::Fenced));
    assert_eq!(
        &wire[r[2].offset() as usize..r[2].offset() as usize + r[2].bytes().len()],
        r[2].bytes()
    );
    let mut missing = Track::new(Limits::default(), avc::Limits::default());
    assert_eq!(missing.observe(&r[1]), Err(Error::Discontinuity));
    assert_eq!(missing.observe(&r[0]), Err(Error::Fenced));
    Ok(())
}

#[test]
fn provisional_configuration_taints_subsequent_samples() -> TestResult {
    let limits = Limits {
        max_payload: 256,
        max_trailer: 256,
        ..Limits::default()
    };
    let mut f = Framer::with_mode(limits, 512, SearchMode::Provisional)?;
    let mut t = Track::new(limits, avc::Limits::default());
    f.append(0, HEADER)?;
    let Next::Record(h) = f.take()? else {
        return Err("header".into());
    };
    t.observe(&h)?;
    let nonvideo = tag(18, 0, b"metadata");
    f.append(f.next_offset(), &nonvideo)?;
    let Next::Record(first) = f.take()? else {
        return Err("first".into());
    };
    assert_eq!(t.observe(&first)?, Observation::Other);
    let cfg = config();
    let mut payload = cfg.clone();
    payload.resize(200, 0x77);
    let outer = tag(9, 1, &payload);
    f.append(f.next_offset(), &outer[..11 + cfg.len()])?;
    let Next::Record(c) = f.take()? else {
        return Err("candidate".into());
    };
    assert!(matches!(
        t.observe(&c)?,
        Observation::Configuration {
            provisional: true,
            ..
        }
    ));
    f.append(f.next_offset(), &sample(4))?;
    let Next::Record(s) = f.take()? else {
        return Err("sample".into());
    };
    assert!(matches!(
        t.observe(&s)?,
        Observation::Sample {
            provisional: true,
            ..
        }
    ));
    Ok(())
}

#![forbid(unsafe_code)]
//! Incremental FLV framing, exact byte retention, and offset contracts.

use fss_packet::extended_flv::{
    Limits, Parse, Tag, avc,
    stream::{Error, Framer, Next, Phase, RecordKind, SearchMode},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

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

#[test]
fn chunk_boundaries_preserve_header_trailers_tag_offsets_and_avc_bytes() -> TestResult {
    let header = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00";
    let configuration = tag(
        9,
        0,
        &[
            0x17, 0, 0, 0, 0, 1, 100, 0, 31, 0xff, 0xe1, 0, 3, 0x67, 0x64, 0x1f, 1, 0, 2, 0x68,
            0xaa,
        ],
    );
    let picture = tag(9, 40, &[0x17, 1, 0, 0, 0, 0, 0, 0, 2, 0x65, 0x42]);
    let trailer = [0x77_u8; 5];
    let tail = [0x77_u8; 3];
    let mut wire = header.to_vec();
    wire.extend_from_slice(&configuration);
    wire.extend_from_slice(&trailer);
    wire.extend_from_slice(&picture);
    wire.extend_from_slice(&tail);
    for width in [1, 2, 3, 7, 16, 31] {
        let mut framer = Framer::new(Limits::default(), 64)?;
        let mut records = Vec::new();
        for chunk in wire.chunks(width) {
            framer.append(framer.next_offset(), chunk)?;
            while let Next::Record(record) = framer.take()? {
                records.push(record);
            }
        }
        assert_eq!(records.len(), 3, "width {width}");
        assert_eq!(records[0].kind(), RecordKind::Header);
        assert_eq!(records[0].offset(), 0);
        assert_eq!(records[0].bytes(), header);
        assert_eq!(records[1].offset(), header.len() as u64);
        assert_eq!(records[1].bytes(), configuration);
        assert_eq!(
            records[2].offset(),
            (header.len() + configuration.len()) as u64
        );
        assert!(matches!(
            records[2].kind(),
            RecordKind::Candidate {
                trailer_bytes: 5,
                tag_kind: 9,
                timestamp_ms: 40,
                earlier_incomplete: false,
                provisional: false,
            }
        ));
        assert_eq!(&records[2].bytes()[..5], trailer);
        assert_eq!(
            &records[2].bytes()[records[2].tag_range().ok_or("tag range")?],
            picture
        );
        let Parse::Complete(config_tag) = Tag::parse(records[1].bytes(), Limits::default())? else {
            return Err("configuration missing".into());
        };
        let configuration_view =
            avc::VideoTag::parse(config_tag)?.configuration(avc::Limits::default())?;
        let range = records[2].tag_range().ok_or("tag range")?;
        let Parse::Complete(video_tag) =
            Tag::parse(&records[2].bytes()[range.clone()], Limits::default())?
        else {
            return Err("picture missing".into());
        };
        let sample = avc::VideoTag::parse(video_tag)?
            .nal_units(&configuration_view, avc::Limits::default())?;
        let nal = sample.iter().next().ok_or("NAL missing")?;
        let stream_offset = records[2].offset() as usize + range.start + nal.range().start;
        assert_eq!(
            &wire[stream_offset..stream_offset + nal.bytes().len()],
            nal.bytes()
        );
        assert_eq!(nal.bytes(), &[0x65, 0x42]);
        let remainder = framer.retire();
        assert_eq!(remainder.phase, Phase::Successor);
        assert_eq!(remainder.offset as usize, wire.len() - tail.len());
        assert_eq!(remainder.bytes(), tail);
        let mut reassembled = Vec::new();
        for record in &records {
            reassembled.extend_from_slice(record.bytes());
        }
        reassembled.extend_from_slice(remainder.bytes());
        assert_eq!(reassembled, wire);
    }
    Ok(())
}

#[test]
fn earlier_incomplete_candidate_is_not_skipped_when_chunked() -> TestResult {
    let limits = Limits {
        max_payload: 64,
        max_trailer: 64,
        ..Limits::default()
    };
    let mut framer = Framer::new(limits, 128)?;
    let mut first = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    first.extend_from_slice(&tag(9, 0, b"first"));
    framer.append(0, &first)?;
    assert!(matches!(framer.take()?, Next::Record(_)));
    assert!(matches!(framer.take()?, Next::Record(_)));
    let embedded = tag(8, 1, b"fake");
    let mut payload = embedded.clone();
    payload.resize(40, 0x77);
    let outer = tag(9, 2, &payload);
    let cut = 11 + embedded.len();
    framer.append(framer.next_offset(), &outer[..cut])?;
    assert_eq!(framer.take()?, Next::NeedMore);
    framer.append(framer.next_offset(), &outer[cut..])?;
    let Next::Record(record) = framer.take()? else {
        return Err("candidate missing".into());
    };
    assert_eq!(record.bytes(), outer);
    assert!(matches!(
        record.kind(),
        RecordKind::Candidate {
            trailer_bytes: 0,
            tag_kind: 9,
            timestamp_ms: 2,
            earlier_incomplete: false,
            provisional: false,
        }
    ));
    Ok(())
}

#[test]
fn refused_offsets_capacity_and_invalid_tags_never_discard_source() -> TestResult {
    let mut framer = Framer::new(Limits::default(), 13)?;
    assert_eq!(framer.append(1, b"bad"), Err(Error::OffsetMismatch));
    assert_eq!(framer.append(0, &[0x77; 14]), Err(Error::BufferLimit));
    assert_eq!(framer.next_offset(), 0);
    let header = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00";
    framer.append(0, header)?;
    assert!(matches!(framer.take()?, Next::Record(_)));
    framer.append(13, b"PRIVATE")?;
    assert!(matches!(framer.take(), Err(Error::Parse(_))));
    assert!(!format!("{framer:?}").contains("PRIVATE"));
    let rest = framer.retire();
    assert_eq!(rest.offset, 13);
    assert_eq!(rest.bytes(), b"PRIVATE");
    assert!(!format!("{rest:?}").contains("PRIVATE"));
    Ok(())
}

#[test]
fn provisional_search_marks_skipped_and_all_later_boundaries() -> TestResult {
    let limits = Limits {
        max_payload: 64,
        max_trailer: 64,
        ..Limits::default()
    };
    let mut framer = Framer::with_mode(limits, 128, SearchMode::Provisional)?;
    let mut initial = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    initial.extend_from_slice(&tag(9, 0, b"first"));
    framer.append(0, &initial)?;
    assert!(matches!(framer.take()?, Next::Record(_)));
    assert!(matches!(framer.take()?, Next::Record(_)));
    let embedded = tag(8, 1, b"audio");
    let mut payload = embedded.clone();
    payload.resize(40, 0x77);
    let outer = tag(9, 2, &payload);
    let cut = 11 + embedded.len();
    framer.append(framer.next_offset(), &outer[..cut])?;
    let Next::Record(first) = framer.take()? else {
        return Err("provisional candidate missing".into());
    };
    assert!(matches!(
        first.kind(),
        RecordKind::Candidate {
            trailer_bytes: 11,
            earlier_incomplete: true,
            provisional: true,
            ..
        }
    ));
    let next = tag(9, 3, b"video");
    framer.append(framer.next_offset(), &next)?;
    let Next::Record(second) = framer.take()? else {
        return Err("later candidate missing".into());
    };
    assert!(matches!(
        second.kind(),
        RecordKind::Candidate {
            trailer_bytes: 0,
            earlier_incomplete: false,
            provisional: true,
            ..
        }
    ));
    assert!(framer.retire().provisional);
    Ok(())
}

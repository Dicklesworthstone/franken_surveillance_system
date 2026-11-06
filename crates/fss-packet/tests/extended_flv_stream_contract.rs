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
                policy: SearchMode::Conservative,
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
            policy: SearchMode::Conservative,
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

#[test]
fn explicit_structured_trailer_ignores_embedded_false_header_and_keeps_source() -> TestResult {
    let mut initial = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    initial.extend_from_slice(&tag(9, 0, b"first"));
    // A plausible incomplete tag header lies inside a 16-byte zero-padded trailer.
    let trailer = [9, 3, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4];
    let successor = tag(8, 40, b"audio");
    let mut rest = trailer.to_vec();
    rest.extend_from_slice(&successor);
    for cut in 0..=rest.len() {
        let mut framer =
            Framer::with_mode(Limits::default(), 1024, SearchMode::StructuredTrailer16)?;
        framer.append(0, &initial)?;
        assert!(matches!(framer.take()?, Next::Record(_)));
        assert!(matches!(framer.take()?, Next::Record(_)));
        framer.append(framer.next_offset(), &rest[..cut])?;
        if cut < rest.len() {
            assert_eq!(framer.take()?, Next::NeedMore);
            framer.append(framer.next_offset(), &rest[cut..])?;
        }
        let Next::Record(record) = framer.take()? else {
            return Err("missing structured record".into());
        };
        assert!(matches!(
            record.kind(),
            RecordKind::Candidate {
                trailer_bytes: 16,
                tag_kind: 8,
                timestamp_ms: 40,
                earlier_incomplete: false,
                provisional: false,
                policy: SearchMode::StructuredTrailer16,
            }
        ));
        assert_eq!(record.bytes(), rest);
    }
    let mut conservative = Framer::new(Limits::default(), 1024)?;
    conservative.append(0, &initial)?;
    conservative.take()?;
    conservative.take()?;
    conservative.append(conservative.next_offset(), &rest)?;
    assert_eq!(conservative.take()?, Next::NeedMore);
    Ok(())
}

#[test]
fn structured_trailer_mismatch_is_fenced_without_discarding_bytes() -> TestResult {
    let mut initial = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    initial.extend_from_slice(&tag(9, 0, b"first"));
    let mut source = vec![0; 16];
    source[7] = 1;
    source.extend_from_slice(&tag(8, 40, b"audio"));
    let mut framer = Framer::with_mode(Limits::default(), 1024, SearchMode::StructuredTrailer16)?;
    framer.append(0, &initial)?;
    framer.take()?;
    framer.take()?;
    framer.append(framer.next_offset(), &source)?;
    assert_eq!(framer.take(), Err(Error::TrailerPolicyMismatch));
    let remainder = framer.retire();
    assert_eq!(remainder.bytes(), source);
    let mut wrong_stream = vec![0; 16];
    let mut successor = tag(8, 40, b"audio");
    successor[8] = 1;
    wrong_stream.extend_from_slice(&successor);
    let mut framer = Framer::with_mode(Limits::default(), 1024, SearchMode::StructuredTrailer16)?;
    framer.append(0, &initial)?;
    framer.take()?;
    framer.take()?;
    framer.append(framer.next_offset(), &wrong_stream)?;
    assert_eq!(framer.take(), Err(Error::TrailerPolicyMismatch));
    assert_eq!(framer.retire().bytes(), wrong_stream);
    let tight = Limits {
        max_trailer: 15,
        ..Limits::default()
    };
    assert!(matches!(
        Framer::with_mode(tight, 1024, SearchMode::StructuredTrailer16),
        Err(Error::Configuration)
    ));
    Ok(())
}

#[test]
fn av_flag_trailer_policy_binds_preceding_tag_and_preserves_source() -> TestResult {
    let mut initial = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    initial.extend_from_slice(&tag(9, 0, b"video"));
    let mut first = vec![0; 16];
    first[11] = 1;
    first.extend_from_slice(&tag(8, 40, b"audio"));
    let mut second = vec![0; 16];
    second.extend_from_slice(&tag(9, 80, b"video"));
    let mut input = first.clone();
    input.extend_from_slice(&second);
    for cut in 0..=input.len() {
        let mut framer = Framer::with_mode(
            Limits::default(),
            1024,
            SearchMode::StructuredTrailer16AvFlag,
        )?;
        framer.append(0, &initial)?;
        framer.take()?;
        framer.take()?;
        framer.append(framer.next_offset(), &input[..cut])?;
        let one = framer.take()?;
        let first_record = match one {
            Next::Record(record) => record,
            Next::NeedMore => {
                framer.append(framer.next_offset(), &input[cut..])?;
                let Next::Record(record) = framer.take()? else {
                    return Err("missing first AV flag record".into());
                };
                record
            }
        };
        assert_eq!(first_record.bytes(), first);
        assert!(matches!(
            first_record.kind(),
            RecordKind::Candidate {
                policy: SearchMode::StructuredTrailer16AvFlag,
                provisional: false,
                ..
            }
        ));
        if cut >= first.len() {
            framer.append(framer.next_offset(), &input[cut..])?;
        }
        let Next::Record(second_record) = framer.take()? else {
            return Err("missing second AV flag record".into());
        };
        assert_eq!(second_record.bytes(), second);
    }
    for corrupt in [4, 7, 10, 11] {
        let mut source = first.clone();
        source[corrupt] ^= 1;
        let mut framer = Framer::with_mode(
            Limits::default(),
            1024,
            SearchMode::StructuredTrailer16AvFlag,
        )?;
        framer.append(0, &initial)?;
        framer.take()?;
        framer.take()?;
        framer.append(framer.next_offset(), &source)?;
        assert_eq!(framer.take(), Err(Error::TrailerPolicyMismatch));
        assert_eq!(framer.retire().bytes(), source);
    }
    let mut wrong_after_audio = second.clone();
    wrong_after_audio[11] = 1;
    let mut framer = Framer::with_mode(
        Limits::default(),
        1024,
        SearchMode::StructuredTrailer16AvFlag,
    )?;
    framer.append(0, &initial)?;
    framer.take()?;
    framer.take()?;
    framer.append(framer.next_offset(), &first)?;
    assert!(matches!(framer.take()?, Next::Record(_)));
    framer.append(framer.next_offset(), &wrong_after_audio)?;
    assert_eq!(framer.take(), Err(Error::TrailerPolicyMismatch));
    assert_eq!(framer.retire().bytes(), wrong_after_audio);
    let mut metadata = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    metadata.extend_from_slice(&tag(18, 0, b"metadata"));
    let mut metadata_framer = Framer::with_mode(
        Limits::default(),
        1024,
        SearchMode::StructuredTrailer16AvFlag,
    )?;
    metadata_framer.append(0, &metadata)?;
    metadata_framer.take()?;
    metadata_framer.take()?;
    metadata_framer.append(metadata_framer.next_offset(), &first)?;
    let Next::Record(metadata_successor) = metadata_framer.take()? else {
        return Err("missing successor after metadata".into());
    };
    assert_eq!(metadata_successor.bytes(), first);
    let mut unsupported = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    unsupported.extend_from_slice(&tag(10, 0, b"vendor audio"));
    let mut framer = Framer::with_mode(
        Limits::default(),
        1024,
        SearchMode::StructuredTrailer16AvFlag,
    )?;
    framer.append(0, &unsupported)?;
    framer.take()?;
    framer.take()?;
    framer.append(framer.next_offset(), &first)?;
    assert_eq!(framer.take(), Err(Error::TrailerPolicyMismatch));
    assert_eq!(framer.retire().bytes(), first);
    Ok(())
}

#[test]
fn framing_policy_evidence_ids_remain_stable_and_reject_unknown() {
    let policies = [
        SearchMode::Conservative,
        SearchMode::Provisional,
        SearchMode::StructuredTrailer16,
        SearchMode::StructuredTrailer16AvFlag,
    ];
    for (id, policy) in policies.into_iter().enumerate() {
        assert_eq!(policy.evidence_id(), id as u8);
        assert_eq!(SearchMode::from_evidence_id(id as u8), Some(policy));
    }
    assert_eq!(SearchMode::from_evidence_id(4), None);
    assert_eq!(SearchMode::from_evidence_id(u8::MAX), None);
}

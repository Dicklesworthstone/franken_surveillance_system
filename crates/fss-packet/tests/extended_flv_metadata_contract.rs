#![forbid(unsafe_code)]
//! Bounded AMF0 metadata claims are untrusted and retain source ownership.

use fss_packet::extended_flv::{
    self, Limits, Parse, Tag, metadata,
    stream::{Framer, NameProbe, NameProbeError, NameProbeOwner, Next, RecordKind, SearchMode},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn short(value: &str) -> Vec<u8> {
    let mut bytes = (value.len() as u16).to_be_bytes().to_vec();
    bytes.extend_from_slice(value.as_bytes());
    bytes
}

fn event(name: &str, object_marker: u8) -> Vec<u8> {
    let mut bytes = vec![2];
    bytes.extend(short(name));
    bytes.push(object_marker);
    if object_marker == 8 {
        bytes.extend(3_u32.to_be_bytes());
    }
    bytes
}

fn property_string(payload: &mut Vec<u8>, key: &str, value: &str) {
    payload.extend(short(key));
    payload.push(2);
    payload.extend(short(value));
}

fn finish(payload: &mut Vec<u8>) {
    payload.extend([0, 0, 9]);
}

fn wire(kind: u8, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut bytes = vec![
        kind,
        (n >> 16) as u8,
        (n >> 8) as u8,
        n as u8,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    bytes.extend(payload);
    bytes.extend((11_u32 + n as u32).to_be_bytes());
    bytes
}

fn parse_payload(payload: &[u8]) -> Result<(String, Option<String>), metadata::Error> {
    let input = wire(18, payload);
    let Parse::Complete(tag) = Tag::parse(&input, Limits::default()).expect("valid FLV wrapper")
    else {
        panic!("complete FLV wrapper");
    };
    let result = metadata::parse(tag)?;
    Ok((
        result.event().to_owned(),
        result.stream_name().map(str::to_owned),
    ))
}

#[test]
fn accepts_borrowed_stream_claim_and_redacts_debug() -> TestResult {
    let mut payload = event("event1", 3);
    property_string(&mut payload, "streamName", "0123456789abcdef");
    payload.extend(short("width"));
    payload.push(0);
    payload.extend(2688_f64.to_be_bytes());
    finish(&mut payload);
    let input = wire(18, &payload);
    let Parse::Complete(tag) = Tag::parse(&input, Limits::default())? else {
        return Err("missing tag".into());
    };
    let claim = metadata::parse(tag)?;
    assert_eq!(claim.event(), "event1");
    assert_eq!(claim.stream_name(), Some("0123456789abcdef"));
    assert!(!format!("{claim:?}").contains("0123456789abcdef"));
    assert_eq!(tag.wire_bytes(), input);
    Ok(())
}

#[test]
fn accepts_ecma_object_and_set_data_frame_wrapper() -> TestResult {
    let mut payload = vec![2];
    payload.extend(short("@setDataFrame"));
    payload.extend(event("onMetaData", 8));
    property_string(&mut payload, "streamName", "sample");
    finish(&mut payload);
    assert_eq!(
        parse_payload(&payload)?,
        ("onMetaData".into(), Some("sample".into()))
    );
    Ok(())
}

#[test]
fn nested_names_do_not_bind_and_duplicate_top_level_names_refuse() -> TestResult {
    let mut payload = event("event1", 3);
    payload.extend(short("nested"));
    payload.push(3);
    property_string(&mut payload, "streamName", "nested-only");
    finish(&mut payload);
    finish(&mut payload);
    assert_eq!(parse_payload(&payload)?, ("event1".into(), None));
    let mut duplicate = event("event1", 3);
    property_string(&mut duplicate, "streamName", "first");
    property_string(&mut duplicate, "streamName", "second");
    finish(&mut duplicate);
    assert_eq!(
        parse_payload(&duplicate),
        Err(metadata::Error::DuplicateStreamName)
    );
    Ok(())
}

#[test]
fn incomplete_invalid_and_unsupported_values_never_yield_partial_claim() -> TestResult {
    let mut valid = event("event1", 3);
    property_string(&mut valid, "streamName", "sample");
    finish(&mut valid);
    for cut in 0..valid.len() {
        assert!(parse_payload(&valid[..cut]).is_err(), "accepted cut {cut}");
    }
    let mut trailing = valid.clone();
    trailing.push(0);
    assert_eq!(parse_payload(&trailing), Err(metadata::Error::Invalid));
    let mut unknown = event("event1", 3);
    property_string(&mut unknown, "streamName", "sample");
    unknown.extend(short("unknown"));
    unknown.push(0x11);
    finish(&mut unknown);
    assert_eq!(parse_payload(&unknown), Err(metadata::Error::Unsupported));
    let mut wrong = event("event1", 3);
    wrong.extend(short("streamName"));
    wrong.push(5);
    finish(&mut wrong);
    assert_eq!(
        parse_payload(&wrong),
        Err(metadata::Error::InvalidStreamName)
    );
    Ok(())
}

#[test]
fn bounds_nesting_and_only_accepts_script_tags() -> TestResult {
    let mut payload = event("event1", 3);
    for _ in 0..9 {
        payload.extend(short("nested"));
        payload.push(3);
    }
    for _ in 0..10 {
        finish(&mut payload);
    }
    assert_eq!(parse_payload(&payload), Err(metadata::Error::Limit));
    let input = wire(9, b"not a script");
    let Parse::Complete(tag) = Tag::parse(&input, Limits::default())? else {
        return Err("missing tag".into());
    };
    assert_eq!(metadata::parse(tag), Err(metadata::Error::NotScript));
    assert!(matches!(
        Tag::parse(&[], extended_flv::Limits::default())?,
        Parse::NeedMore
    ));
    Ok(())
}

#[test]
fn refuses_excess_fields_strings_and_adversarial_array_lengths() {
    let mut many = event("event1", 3);
    for _ in 0..1025 {
        many.extend(short("x"));
        many.push(5);
    }
    finish(&mut many);
    assert_eq!(parse_payload(&many), Err(metadata::Error::Limit));

    let mut long = event("event1", 3);
    long.extend(short("value"));
    long.push(2);
    long.extend((16_385_u16).to_be_bytes());
    long.resize(long.len() + 16_385, b'x');
    finish(&mut long);
    assert_eq!(parse_payload(&long), Err(metadata::Error::Limit));

    let mut array = event("event1", 3);
    array.extend(short("array"));
    array.push(10);
    array.extend(u32::MAX.to_be_bytes());
    finish(&mut array);
    assert_eq!(parse_payload(&array), Err(metadata::Error::Limit));
}

#[test]
fn rejects_invalid_text_without_disclosing_a_prior_name() {
    let mut payload = event("event1", 3);
    property_string(&mut payload, "streamName", "private-value");
    payload.extend(short("other"));
    payload.extend([2, 0, 1, 0xff]);
    finish(&mut payload);
    assert_eq!(parse_payload(&payload), Err(metadata::Error::InvalidUtf8));
}

#[test]
fn source_record_keeps_trailers_and_refuses_provisional_metadata() -> TestResult {
    let mut metadata_payload = event("event1", 3);
    property_string(&mut metadata_payload, "streamName", "sample");
    finish(&mut metadata_payload);
    let script_tag = wire(18, &metadata_payload);
    let mut prefix = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    prefix.extend(wire(9, b"video"));

    let mut safe = Framer::new(Limits::default(), 1024 * 1024)?;
    safe.append(0, &prefix)?;
    safe.take()?;
    safe.take()?;
    let mut source = vec![0x77; 16];
    source.extend(&script_tag);
    safe.append(safe.next_offset(), &source)?;
    let Next::Record(record) = safe.take()? else {
        return Err("metadata record unavailable".into());
    };
    assert_eq!(record.bytes(), source);
    assert_eq!(
        metadata::parse_record(&record)?.stream_name(),
        Some("sample")
    );
    assert_eq!(record.bytes(), source);

    let mut provisional =
        Framer::with_mode(Limits::default(), 1024 * 1024, SearchMode::Provisional)?;
    provisional.append(0, &prefix)?;
    provisional.take()?;
    provisional.take()?;
    let mut ambiguous = vec![0; 16];
    ambiguous[15] = 8;
    ambiguous.extend(&script_tag);
    provisional.append(provisional.next_offset(), &ambiguous)?;
    let Next::Record(record) = provisional.take()? else {
        return Err("provisional record unavailable".into());
    };
    assert!(matches!(
        record.kind(),
        RecordKind::Candidate {
            provisional: true,
            ..
        }
    ));
    assert_eq!(
        metadata::parse_record(&record),
        Err(metadata::Error::Provisional)
    );
    assert_eq!(record.bytes(), ambiguous);
    Ok(())
}

#[test]
fn startup_name_probe_retains_bytes_across_every_chunk_boundary() -> TestResult {
    let mut earlier = event("other", 3);
    property_string(&mut earlier, "streamName", "ffffffffffffffff");
    finish(&mut earlier);
    let mut target = event("event1", 3);
    property_string(&mut target, "streamName", "0123456789abcdef");
    finish(&mut target);
    let mut source = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    source.extend(wire(9, b"video"));
    source.extend([0; 16]);
    source.extend(wire(18, &earlier));
    source.extend([0; 16]);
    source.extend(wire(18, &target));

    let mut framer = Framer::with_mode(Limits::default(), 4096, SearchMode::StructuredTrailer16)?;
    let mut work = 10_000_000;
    for (index, byte) in source.iter().enumerate() {
        framer.append(framer.next_offset(), &[*byte])?;
        let observation =
            framer.inspect_initial_name("event1", "0123456789abcdef", 4096, 4, &mut work)?;
        if index + 1 < source.len() {
            assert_eq!(observation, NameProbe::NeedMore);
        } else {
            assert_eq!(observation, NameProbe::Matched { tag_index: 2 });
        }
        assert_eq!(framer.next_offset(), (index + 1) as u64);
    }
    assert_eq!(
        framer.inspect_initial_name("event1", "1111111111111111", 4096, 4, &mut work)?,
        NameProbe::Mismatched { tag_index: 2 }
    );
    assert_eq!(
        framer.inspect_initial_name("event1", "0123456789abcdef", 4096, 2, &mut work)?,
        NameProbe::LimitReached { tags_scanned: 2 }
    );
    assert_eq!(
        framer.inspect_initial_name("event1", "0123456789abcdef", 13, 4, &mut work)?,
        NameProbe::LimitReached { tags_scanned: 0 }
    );
    assert_eq!(
        framer.inspect_initial_name("event1", "INVALID", 4096, 4, &mut work),
        Err(NameProbeError::Configuration)
    );

    let mut retained = Vec::new();
    for _ in 0..4 {
        let Next::Record(record) = framer.take()? else {
            return Err("missing retained record".into());
        };
        retained.extend_from_slice(record.bytes());
    }
    assert_eq!(retained, source);
    assert_eq!(
        framer.inspect_initial_name("event1", "0123456789abcdef", 4096, 4, &mut work),
        Err(NameProbeError::Configuration)
    );
    Ok(())
}

#[test]
fn startup_name_probe_refuses_ambiguous_boundaries_and_exhausted_work() -> TestResult {
    let mut payload = event("event1", 3);
    property_string(&mut payload, "streamName", "0123456789abcdef");
    finish(&mut payload);
    let mut initial = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    initial.extend(wire(9, b"video"));
    let mut ambiguous = vec![0; 16];
    ambiguous[15] = 8;
    ambiguous.extend(wire(18, &payload));
    let mut framer = Framer::with_mode(Limits::default(), 1024 * 1024, SearchMode::Provisional)?;
    framer.append(0, &initial)?;
    framer.append(framer.next_offset(), &ambiguous)?;
    let original_offset = framer.next_offset();
    let mut work = 10_000_000;
    assert_eq!(
        framer.inspect_initial_name("event1", "0123456789abcdef", 4096, 2, &mut work),
        Err(NameProbeError::Provisional)
    );
    let mut no_work = 0;
    assert_eq!(
        framer.inspect_initial_name("event1", "0123456789abcdef", 4096, 2, &mut no_work),
        Err(NameProbeError::WorkLimit)
    );
    assert_eq!(framer.next_offset(), original_offset);
    let tail = framer.retire();
    let mut source = initial;
    source.extend(ambiguous);
    assert_eq!(tail.bytes(), source);
    Ok(())
}

#[test]
fn startup_name_probe_refuses_unsupported_metadata_and_wrong_first_stream_id() -> TestResult {
    let mut payload = event("event1", 3);
    payload.extend(short("unrecognized"));
    payload.push(0x11);
    finish(&mut payload);
    let header = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00";
    let mut framer = Framer::new(Limits::default(), 4096)?;
    framer.append(0, header)?;
    framer.append(framer.next_offset(), &wire(18, &payload))?;
    let mut work = 1_000_000;
    assert_eq!(
        framer.inspect_initial_name("event1", "0123456789abcdef", 4096, 2, &mut work),
        Err(NameProbeError::Metadata(metadata::Error::Unsupported))
    );

    let mut wrong_id = wire(9, b"video");
    wrong_id[8] = 1;
    let mut framer = Framer::with_mode(Limits::default(), 4096, SearchMode::ZeroStreamId)?;
    framer.append(0, header)?;
    framer.append(framer.next_offset(), &wrong_id)?;
    assert_eq!(
        framer.inspect_initial_name("event1", "0123456789abcdef", 4096, 2, &mut work),
        Err(NameProbeError::Framing(
            extended_flv::stream::Error::StreamIdMismatch
        ))
    );
    Ok(())
}

#[test]
fn startup_name_owner_keeps_immutable_expectations_and_cumulative_work() -> TestResult {
    let mut framer = Framer::new(Limits::default(), 4096)?;
    let mut probe = NameProbeOwner::new("event1", "0123456789abcdef", 4096, 4, 100_000)?;
    let initial = probe.work_remaining();
    assert_eq!(probe.inspect(&framer)?, NameProbe::NeedMore);
    assert!(probe.work_remaining() < initial);
    assert!(!format!("{probe:?}").contains("0123456789abcdef"));
    let mut payload = event("event1", 3);
    property_string(&mut payload, "streamName", "0123456789abcdef");
    finish(&mut payload);
    let mut source = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    source.extend(wire(18, &payload));
    framer.append(0, &source)?;
    assert_eq!(probe.inspect(&framer)?, NameProbe::Matched { tag_index: 0 });
    assert!(NameProbeOwner::new("event1", "0123456789abcdef", 4096, 4, 0).is_err());
    Ok(())
}

/// Bounded, private camera metadata supplied over stdin by an owner-run
/// laboratory harness. No payload or untrusted strings are printed.
#[test]
#[ignore = "requires owner-supplied private metadata"]
fn private_camera_metadata_batch() -> TestResult {
    use std::io::Read;

    const MAX_BATCH: u64 = 2 * 1024 * 1024;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_BATCH + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BATCH {
        return Err("metadata batch bound".into());
    }
    let mut offset = 0_usize;
    let (mut total, mut accepted, mut names, mut unsupported) =
        (0_usize, 0_usize, 0_usize, 0_usize);
    while offset < bytes.len() {
        let header = bytes
            .get(offset..offset + 4)
            .ok_or("truncated batch length")?;
        let length = u32::from_be_bytes(header.try_into()?) as usize;
        offset += 4;
        let end = offset.checked_add(length).ok_or("batch length overflow")?;
        let source = bytes.get(offset..end).ok_or("truncated batch tag")?;
        let Parse::Complete(tag) = Tag::parse(source, Limits::default())? else {
            return Err("incomplete batch tag".into());
        };
        if tag.kind() != 18 || tag.wire_bytes().len() != source.len() {
            return Err("invalid batch tag".into());
        }
        total += 1;
        if total > 512 {
            return Err("metadata tag count bound".into());
        }
        match metadata::parse(tag) {
            Ok(claim) => {
                accepted += 1;
                names += usize::from(claim.stream_name().is_some());
            }
            Err(metadata::Error::Unsupported) => unsupported += 1,
            Err(_) => (),
        }
        offset = end;
    }
    if total == 0 || accepted == 0 {
        return Err("no metadata claims decoded".into());
    }
    println!(
        "private_metadata candidates={total} accepted={accepted} with_stream_name={names} unsupported={unsupported} source_retained=no identity=unverified"
    );
    Ok(())
}

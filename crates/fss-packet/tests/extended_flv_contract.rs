#![forbid(unsafe_code)]
//! Synthetic source-preservation and adversarial extended-FLV boundary checks.

use fss_packet::extended_flv::{
    Error, Header, Limits, Parse, Tag, find_next, find_next_provisional,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn header() -> Vec<u8> {
    b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec()
}

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
fn source_header_and_tag_are_preserved_without_interpreting_timing() -> TestResult {
    let raw = header();
    let Parse::Complete(h) = Header::parse(&raw, Limits::default())? else {
        return Err("missing header".into());
    };
    assert_eq!(h.wire_bytes(), raw);
    assert_eq!(h.flags(), 1);
    assert_eq!(h.data_offset(), 9);
    let wire = tag(9, 0xf123_4567, &[0x17, 1, 2, 3]);
    let Parse::Complete(parsed) = Tag::parse(&wire, Limits::default())? else {
        return Err("missing tag".into());
    };
    assert_eq!(parsed.wire_bytes(), wire);
    assert_eq!(parsed.payload(), &[0x17, 1, 2, 3]);
    assert_eq!(parsed.payload_range(), 11..15);
    assert_eq!(parsed.timestamp_ms(), 0xf123_4567);
    for cut in 0..raw.len() {
        assert_eq!(
            Header::parse(&raw[..cut], Limits::default())?,
            Parse::NeedMore
        );
    }
    for cut in 0..wire.len() {
        assert_eq!(
            Tag::parse(&wire[..cut], Limits::default())?,
            Parse::NeedMore
        );
    }
    Ok(())
}

#[test]
fn variable_trailers_and_chunk_cuts_preserve_original_source() -> TestResult {
    for trailer_len in [0, 1, 16, 257, 784, 1024] {
        let limits = Limits {
            max_trailer: 1024,
            ..Limits::default()
        };
        let next = tag(10, 20, b"\xcf\x00\x03\x00");
        let trailer = vec![0x77; trailer_len];
        let mut input = trailer.clone();
        input.extend_from_slice(&next);
        for cut in 0..input.len() {
            assert_eq!(find_next(&input[..cut], limits)?, Parse::NeedMore);
        }
        let Parse::Complete(found) = find_next(&input, limits)? else {
            return Err("missing candidate".into());
        };
        assert_eq!(found.trailer, trailer);
        assert_eq!(found.tag.wire_bytes(), next);
        assert_eq!(found.tag.kind(), 10);
    }
    Ok(())
}

#[test]
fn incomplete_earlier_candidate_is_not_silently_skipped() -> TestResult {
    let limits = Limits {
        max_payload: 64,
        max_trailer: 64,
        ..Limits::default()
    };
    let mut input = vec![9, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0];
    let actual = tag(8, 42, b"audio");
    input.extend_from_slice(&actual);
    assert_eq!(find_next(&input, limits)?, Parse::NeedMore);
    let Parse::Complete(provisional) = find_next_provisional(&input, limits)? else {
        return Err("missing provisional candidate".into());
    };
    assert_eq!(provisional.trailer.len(), 11);
    assert!(provisional.earlier_incomplete);
    input.resize(55, 0x77); // complete earlier candidate, whose back-reference is invalid
    let Parse::Complete(found) = find_next(&input, limits)? else {
        return Err("missing candidate".into());
    };
    assert_eq!(found.trailer.len(), 11);
    assert_eq!(found.tag.wire_bytes(), actual);
    assert!(!found.earlier_incomplete);
    Ok(())
}

#[test]
fn provisional_candidate_can_change_when_the_earlier_tag_finishes() -> TestResult {
    let limits = Limits {
        max_payload: 64,
        max_trailer: 64,
        ..Limits::default()
    };
    let embedded = tag(8, 42, b"audio");
    let mut payload = embedded.clone();
    payload.resize(40, 0x77);
    let outer = tag(9, 0, &payload);
    let prefix = &outer[..11 + embedded.len()];
    let Parse::Complete(provisional) = find_next_provisional(prefix, limits)? else {
        return Err("missing provisional candidate".into());
    };
    assert_eq!(provisional.trailer.len(), 11);
    assert!(provisional.earlier_incomplete);
    assert_eq!(find_next(prefix, limits)?, Parse::NeedMore);
    let Parse::Complete(stable) = find_next(&outer, limits)? else {
        return Err("missing earlier completed candidate".into());
    };
    assert!(stable.trailer.is_empty());
    assert_eq!(stable.tag.wire_bytes(), outer);
    Ok(())
}

#[test]
fn malformed_lengths_backrefs_and_search_bounds_are_explicit() -> TestResult {
    let limits = Limits {
        max_payload: 3,
        max_trailer: 2,
        ..Limits::default()
    };
    let big = tag(9, 0, b"four");
    assert_eq!(Tag::parse(&big, limits), Err(Error::PayloadLimit));
    let mut broken = tag(9, 0, b"abc");
    let last = broken.len() - 1;
    broken[last] ^= 1;
    assert_eq!(Tag::parse(&broken, limits), Err(Error::PreviousTagSize));
    assert_eq!(find_next(&[0x77, 0x77], limits)?, Parse::NeedMore);
    assert_eq!(
        find_next(&[0x77, 0x77, 0x77], limits),
        Err(Error::NoCandidate)
    );
    let mut invalid_header = header();
    invalid_header[12] = 1;
    assert_eq!(
        Header::parse(&invalid_header, limits),
        Err(Error::InvalidHeader)
    );
    assert_eq!(
        Tag::parse(
            &[9],
            Limits {
                max_payload: 4 * 1024 * 1024 + 1,
                ..limits
            }
        ),
        Err(Error::InvalidLimits)
    );
    Ok(())
}

#[test]
fn structural_match_is_only_a_candidate_and_debug_never_prints_payload() -> TestResult {
    let fake = tag(18, 1, b"PRIVATE_TRAILER_BYTES");
    let real = tag(9, 2, b"PRIVATE_MEDIA_BYTES");
    let mut input = fake.clone();
    input.extend_from_slice(&real);
    let Parse::Complete(found) = find_next(&input, Limits::default())? else {
        return Err("missing candidate".into());
    };
    assert_eq!(found.tag.wire_bytes(), fake);
    assert!(!format!("{found:?}").contains("PRIVATE"));
    assert!(!format!("{:?}", found.tag).contains("PRIVATE"));
    Ok(())
}

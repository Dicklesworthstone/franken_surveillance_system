#![forbid(unsafe_code)]
//! HTTP chunked-transfer contracts: control overhead retention, limits, and hostile inputs.
use fss_codec_mjpeg::http::*;
use fss_codec_mjpeg::stream::StreamBasis;
use fss_codec_mjpeg::{DecodeBudget, DecodeError};
use fss_core::ContentDigest;
use std::error::Error;
use std::sync::atomic::AtomicBool;
type Test = Result<(), Box<dyn Error>>;
fn basis() -> StreamBasis {
    StreamBasis {
        source: [9; 32],
        generation: 4,
    }
}
fn parser() -> Result<HttpResponseStream, HttpError> {
    HttpResponseStream::new(basis(), HttpLimits::default())
}
fn header(extra: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=frame\r\n{extra}\r\n"
    )
    .into_bytes()
}
struct Run {
    entity: Vec<u8>,
    wire: Vec<u8>,
    mappings: Vec<EntityMapping>,
    end: HttpEnd,
    events: usize,
}
fn replay(bytes: &[u8], split: usize) -> Result<Run, Box<dyn Error>> {
    let mut p = parser()?;
    let mut budget = DecodeBudget::new(100_000_000);
    let mut entity = Vec::new();
    let mut wire = Vec::new();
    let mut mappings = Vec::new();
    let mut events = 0;
    for chunk in bytes.chunks(split) {
        let mut at = 0;
        while at < chunk.len() {
            let step = p.push(p.next_offset(), &chunk[at..], &mut budget)?;
            assert!(step.consumed > 0);
            at += step.consumed;
            if let Some(event) = step.event {
                events += 1;
                let raw = match &event {
                    HttpEvent::Head(h) => {
                        assert_eq!(
                            h.content_type(),
                            "multipart/x-mixed-replace; boundary=frame"
                        );
                        h.raw()
                    }
                    HttpEvent::Control(c) => &c.raw,
                    HttpEvent::Data(d) => {
                        assert_eq!(d.mapping().entity_range[0], entity.len() as u64);
                        assert_eq!(d.mapping().sha256, ContentDigest::sha256(d.bytes()).bytes());
                        assert_ne!(d.mapping().head.wire, d.mapping().head.entity);
                        entity.extend_from_slice(d.bytes());
                        mappings.push(d.mapping());
                        d.raw()
                    }
                };
                assert_eq!(raw.range()[0], wire.len() as u64);
                wire.extend_from_slice(raw.bytes());
            }
        }
    }
    let end = p.finish(&mut budget)?;
    assert_eq!(wire, bytes);
    Ok(Run {
        entity,
        wire,
        mappings,
        end,
        events,
    })
}
#[test]
fn fixed_length_has_exact_source_maps_at_every_fragment_size() -> Test {
    let mut bytes = header("Content-Length: 9\r\n");
    bytes.extend_from_slice(b"abc\0de\r\nf");
    for size in 1..=bytes.len() {
        let r = replay(&bytes, size)?;
        assert_eq!(r.entity, b"abc\0de\r\nf");
        assert_eq!(r.end.termination, HttpTermination::ExplicitFraming);
        assert_eq!(r.end.entity_bytes, 9);
        assert_eq!(r.end.wire_bytes, bytes.len() as u64);
        assert_eq!(r.end.chunks, 0);
        for m in r.mappings {
            assert_eq!(m.chunk, None);
            assert_eq!(
                &bytes[m.wire_range[0] as usize..m.wire_range[1] as usize],
                &r.entity[m.entity_range[0] as usize..m.entity_range[1] as usize]
            );
        }
    }
    Ok(())
}
#[test]
fn chunked_fragments_extensions_trailers_and_all_two_way_splits() -> Test {
    let mut bytes = header("Transfer-Encoding: ChUnKeD\r\nTrailer: X-Checksum\r\n");
    bytes.extend_from_slice(b"3;tag=abc;quoted=\"semi;\\\"quote\"\r\nabc\r\n4 \t; name = token\r\ndefg\r\n0;end\r\nX-Checksum: retained\r\n\r\n");
    for size in 1..=bytes.len() {
        let r = replay(&bytes, size)?;
        assert_eq!(r.entity, b"abcdefg");
        assert_eq!(r.end.chunks, 2);
        assert!(r.events >= 9);
        assert_eq!(r.end.termination, HttpTermination::ExplicitFraming);
    }
    for split in 0..=bytes.len() {
        let mut p = parser()?;
        let mut b = DecodeBudget::new(100_000);
        let mut out = Vec::new();
        for input in [&bytes[..split], &bytes[split..]] {
            let mut n = 0;
            while n < input.len() {
                let s = p.push(p.next_offset(), &input[n..], &mut b)?;
                n += s.consumed;
                if let Some(HttpEvent::Data(d)) = s.event {
                    out.extend_from_slice(d.bytes());
                }
            }
        }
        assert_eq!(out, b"abcdefg");
        p.finish(&mut b)?;
    }
    Ok(())
}
#[test]
fn close_delimited_eof_is_not_explicit_length_completion() -> Test {
    let mut bytes = header("");
    bytes.extend_from_slice(b"image-like-body");
    let r = replay(&bytes, 3)?;
    assert_eq!(r.end.termination, HttpTermination::CloseDelimitedEof);
    assert_eq!(r.entity, b"image-like-body");
    assert_eq!(r.wire, bytes);
    Ok(())
}
#[test]
fn conflicting_and_unsupported_framing_is_rejected_before_entity_bytes() -> Test {
    for extra in [
        "Content-Length: 1\r\nContent-Length: 1\r\n",
        "Content-Length: 1, 1\r\n",
        "Content-Length: +1\r\n",
        "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n",
        "Transfer-Encoding: gzip, chunked\r\n",
        "Transfer-Encoding: chunked;foo=bar\r\n",
        "Content-Encoding: gzip\r\n",
        "Content-Type: image/jpeg\r\n",
        " Connection: close\r\n",
        "Content-Length : 4\r\n",
        "Connection: content-length\r\n",
        "Trailer: content-type\r\n",
    ] {
        let mut p = parser()?;
        let mut b = DecodeBudget::new(100_000);
        let err = p
            .push(0, &header(extra), &mut b)
            .err()
            .ok_or("accepted malformed header")?;
        assert_eq!(p.entity_offset(), 0);
        assert_eq!(err.next_offset, err.consumed as u64);
        assert!(p.failure().is_some());
    }
    Ok(())
}
#[test]
fn status_refusals_do_not_follow_redirects_or_authenticate() -> Test {
    for status in [101, 103, 204, 301, 401, 407, 500] {
        let bytes =
            format!("HTTP/1.1 {status} reason\r\nLocation: https://example.invalid/\r\n\r\n");
        let mut p = parser()?;
        let err = p
            .push(0, bytes.as_bytes(), &mut DecodeBudget::new(10000))
            .err()
            .ok_or("accepted status")?;
        assert_eq!(err.error, HttpError::Status(status));
    }
    Ok(())
}
#[test]
fn strict_crlf_and_field_syntax_fail_with_recoverable_source() -> Test {
    for bytes in [
        b"HTTP/1.1 200 OK\n".as_slice(),
        b"HTTP/1.1 200 OK\rX",
        b"HTTP/1.1 200 OK\r\nX:\0oops\r\n\r\n",
    ] {
        let mut p = parser()?;
        let e = p
            .push(0, bytes, &mut DecodeBudget::new(10000))
            .err()
            .ok_or("accepted bad syntax")?;
        let saved = p.abort();
        assert_eq!(saved.pending.bytes(), &bytes[..e.consumed]);
        assert_eq!(saved.pending.range(), [0, e.next_offset]);
    }
    Ok(())
}
#[test]
fn explicit_response_stops_before_next_message() -> Test {
    let h = header("Content-Length: 3\r\n");
    let mut bytes = h.clone();
    bytes.extend_from_slice(b"abcHTTP/1.1 200 NEXT");
    let mut p = parser()?;
    let mut b = DecodeBudget::new(10000);
    assert_eq!(p.push(0, &bytes, &mut b)?.consumed, h.len());
    let step = p.push(p.next_offset(), &bytes[h.len()..], &mut b)?;
    assert_eq!(step.consumed, 3);
    assert!(p.body_complete());
    assert_eq!(p.finish(&mut b)?.wire_bytes, (h.len() + 3) as u64);
    Ok(())
}
#[test]
fn every_explicit_truncation_refuses_whole_response_success() -> Test {
    let mut bytes = header("Transfer-Encoding: chunked\r\n");
    bytes.extend_from_slice(b"3\r\nabc\r\n0\r\nX-End: yes\r\n\r\n");
    for end in 0..bytes.len() {
        let mut p = parser()?;
        let mut b = DecodeBudget::new(10000);
        let mut offset = 0;
        while offset < end {
            let step = p.push(offset as u64, &bytes[offset..end], &mut b)?;
            offset += step.consumed;
        }
        assert_eq!(p.finish(&mut b), Err(HttpError::Truncated));
        assert_eq!(p.abort().next_offset, end as u64);
    }
    Ok(())
}
#[test]
fn malformed_chunk_extensions_delimiters_and_trailer_overrides_fail() -> Test {
    for body in [
        "+1\r\n",
        "0x1\r\n",
        "1;\r\n",
        "1;x=\r\n",
        "1;x=\"bad\r\n",
        "10000000000000000\r\n",
        "1\r\naXX",
        "0\r\nContent-Type: image/jpeg\r\n\r\n",
        "0\r\nX-A: 1\r\nx-a: 2\r\n\r\n",
        "0\r\n folded\r\n\r\n",
    ] {
        let mut p = parser()?;
        let mut b = DecodeBudget::new(100000);
        p.push(0, &header("Transfer-Encoding: chunked\r\n"), &mut b)?;
        let mut n = 0;
        let mut failed = false;
        while n < body.len() {
            match p.push(p.next_offset(), &body.as_bytes()[n..], &mut b) {
                Ok(s) => {
                    n += s.consumed;
                }
                Err(_) => {
                    failed = true;
                    break;
                }
            }
        }
        assert!(failed, "accepted {body:?}");
        assert!(p.failure().is_some());
    }
    Ok(())
}
#[test]
fn cancellation_and_offset_errors_latch_without_losing_pending_bytes() -> Test {
    let mut p = parser()?;
    p.push(0, b"HTTP/1.1", &mut DecodeBudget::new(1000))?;
    let stop = AtomicBool::new(true);
    let err = p
        .push(
            8,
            b" 200 OK\r\n",
            &mut DecodeBudget::cancellable(1000, &stop),
        )
        .err()
        .ok_or("ignored cancel")?;
    assert_eq!(err.consumed, 0);
    assert_eq!(err.error, HttpError::Work(DecodeError::Cancelled));
    assert_eq!(p.abort().pending.bytes(), b"HTTP/1.1");
    let mut p = parser()?;
    assert_eq!(
        p.push(1, b"H", &mut DecodeBudget::new(1000))
            .err()
            .ok_or("ignored gap")?
            .error,
        HttpError::Offset
    );
    assert_eq!(
        p.push(0, b"H", &mut DecodeBudget::new(1000))
            .err()
            .ok_or("resumed")?
            .error,
        HttpError::Poisoned
    );
    Ok(())
}
#[test]
fn complete_bounds_and_budget_failure_do_not_publish_a_partial_event() -> Test {
    let limits = HttpLimits {
        entity_bytes: 2,
        ..HttpLimits::default()
    };
    let mut p = HttpResponseStream::new(basis(), limits)?;
    assert_eq!(
        p.push(
            0,
            &header("Content-Length: 3\r\n"),
            &mut DecodeBudget::new(10000)
        )
        .err()
        .ok_or("ignored limit")?
        .error,
        HttpError::Limit
    );
    let mut p = parser()?;
    let h = header("Content-Length: 3\r\n");
    p.push(0, &h, &mut DecodeBudget::new(10000))?;
    let fail = p
        .push(p.next_offset(), b"abc", &mut DecodeBudget::new(8))
        .err()
        .ok_or("ignored budget")?;
    assert_eq!(fail.consumed, 0);
    assert_eq!(p.entity_offset(), 0);
    assert_eq!(p.next_offset(), h.len() as u64);
    Ok(())
}
#[test]
fn zero_length_needs_no_phantom_body_and_http10_chunking_refuses() -> Test {
    let h = header("Content-Length: 0\r\n");
    let r = replay(&h, 1)?;
    assert_eq!(r.entity.len(), 0);
    assert_eq!(r.events, 1);
    let bytes = String::from_utf8(header("Transfer-Encoding: chunked\r\n"))?
        .replace("HTTP/1.1", "HTTP/1.0");
    assert_eq!(
        parser()?
            .push(0, bytes.as_bytes(), &mut DecodeBudget::new(10000))
            .err()
            .ok_or("accepted HTTP10 chunking")?
            .error,
        HttpError::Malformed
    );
    Ok(())
}
#[test]
fn derived_entity_identity_matches_independent_golden_and_large_lengths_do_not_truncate() -> Test {
    let r = replay(
        &[header("Content-Length: 3\r\n"), b"abc".to_vec()].concat(),
        1000,
    )?;
    let digest = r
        .end
        .head
        .entity
        .source
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(
        digest,
        "a6b6286b519c5c47cace4e089bbbd2076c8bcea304d8685bbc5bb1c3b54c6040"
    );
    let mut p = parser()?;
    let mut b = DecodeBudget::new(10000);
    let h = header("Content-Length: 4294967297\r\n");
    p.push(0, &h, &mut b)?;
    assert_eq!(p.push(p.next_offset(), b"a", &mut b)?.consumed, 1);
    assert!(!p.body_complete());
    assert_eq!(p.finish(&mut b), Err(HttpError::Truncated));
    Ok(())
}

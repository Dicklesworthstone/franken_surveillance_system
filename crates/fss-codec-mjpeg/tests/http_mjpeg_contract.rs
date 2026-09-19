#![forbid(unsafe_code)]
//! HTTP MJPEG contracts: multipart framing over chunked HTTP with bounded decode budgets.
use fss_codec_mjpeg::http::*;
use fss_codec_mjpeg::http_mjpeg::*;
use fss_codec_mjpeg::multipart::{MultipartError, MultipartLimits};
use fss_codec_mjpeg::stream::StreamBasis;
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits};
use std::error::Error;
use std::sync::atomic::AtomicBool;
type Test = Result<(), Box<dyn Error>>;
const JPEG: &[u8] = include_bytes!("fixtures/gray.jpg");
fn basis() -> StreamBasis {
    StreamBasis {
        source: [5; 32],
        generation: 1,
    }
}
fn entity(count: usize, crlf: bool) -> Vec<u8> {
    let mut bytes = b"--f\r\n".to_vec();
    for i in 0..count {
        bytes.extend_from_slice(b"Content-Type: image/jpeg\r\n\r\n");
        bytes.extend_from_slice(JPEG);
        bytes.extend_from_slice(if i + 1 == count {
            b"\r\n--f--"
        } else {
            b"\r\n--f\r\n"
        });
    }
    if crlf {
        bytes.extend_from_slice(b"\r\n");
    }
    bytes
}
fn response(body: &[u8], mode: u8, chunk: usize) -> Vec<u8> {
    let mut bytes =
        b"HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=f\r\n".to_vec();
    if mode == 0 {
        bytes.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        bytes.extend_from_slice(body);
    } else if mode == 1 {
        bytes.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
        for part in body.chunks(chunk) {
            bytes.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
            bytes.extend_from_slice(part);
            bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(b"0\r\nX-Check: opaque\r\n\r\n");
    } else {
        bytes.extend_from_slice(b"\r\n");
        bytes.extend_from_slice(body);
    }
    bytes
}
fn drive(wire: &[u8], split: usize) -> Result<(Vec<HttpJpegFrame>, HttpMjpegEnd), Box<dyn Error>> {
    let mut http = HttpResponseStream::new(basis(), HttpLimits::default())?;
    let mut consumer = None;
    let mut frames = Vec::new();
    let mut budget = DecodeBudget::new(100_000_000);
    for fragment in wire.chunks(split) {
        let mut pos = 0;
        while pos < fragment.len() {
            let step = http.push(http.next_offset(), &fragment[pos..], &mut budget)?;
            assert!(step.consumed > 0);
            pos += step.consumed;
            match step.event {
                Some(HttpEvent::Head(head)) => {
                    consumer = Some(HttpMultipartStream::new(
                        &head,
                        MultipartLimits::default(),
                        65536,
                        &mut budget,
                    )?)
                }
                Some(HttpEvent::Data(data)) => {
                    let p = consumer.as_mut().ok_or("no MIME consumer")?;
                    let mut used = 0;
                    while used < data.bytes().len() {
                        let s = p.push(&data, used, &mut budget)?;
                        assert!(s.consumed > 0);
                        used += s.consumed;
                        if let Some(frame) = s.frame {
                            frames.push(frame);
                        }
                    }
                }
                _ => (),
            }
        }
    }
    let mut end = consumer
        .as_mut()
        .ok_or("no header")?
        .finish(http.finish(&mut budget)?, &mut budget)?;
    if let Some(frame) = end.final_frame.take() {
        frames.push(frame);
    }
    Ok((frames, end))
}
fn check_frame(wire: &[u8], frame: &HttpJpegFrame) -> Test {
    assert_eq!(frame.part().bytes(), JPEG);
    let mut rebuilt = Vec::new();
    let mut offset = 0;
    for span in frame.source_spans() {
        assert_eq!(span.jpeg_range[0], offset);
        assert!(span.jpeg_range[1] > offset);
        assert_eq!(
            span.wire_range[1] - span.wire_range[0],
            span.jpeg_range[1] - span.jpeg_range[0]
        );
        rebuilt.extend_from_slice(&wire[span.wire_range[0] as usize..span.wire_range[1] as usize]);
        offset = span.jpeg_range[1];
    }
    assert_eq!(rebuilt, JPEG);
    assert_eq!(offset, JPEG.len() as u64);
    let decoded = frame.decode(
        ComponentInterpretation::Grayscale,
        DecodeLimits::default(),
        &mut DecodeBudget::new(1_000_000),
    )?;
    let expected = include_bytes!("fixtures/gray.gray");
    assert_eq!(decoded.dimensions(), [17, 13]);
    assert!(
        decoded
            .pixels()
            .iter()
            .zip(expected)
            .all(|(a, b)| a.abs_diff(*b) <= 1)
    );
    Ok(())
}
#[test]
fn three_http_modes_reach_native_jpeg_with_exact_wire_maps() -> Test {
    for mode in 0..3 {
        for part_size in [1, 17, 113, 4096] {
            let wire = response(&entity(2, true), mode, part_size);
            let (frames, end) = drive(&wire, 7)?;
            assert_eq!(frames.len(), 2);
            assert_eq!(end.http.entity_bytes, end.multipart.bytes);
            assert_eq!(end.multipart.frames, 2);
            assert_eq!(
                end.http.termination,
                if mode == 2 {
                    HttpTermination::CloseDelimitedEof
                } else {
                    HttpTermination::ExplicitFraming
                }
            );
            for frame in &frames {
                check_frame(&wire, frame)?;
            }
        }
    }
    Ok(())
}
#[test]
fn all_wire_fragment_sizes_preserve_frame_and_mapping_results() -> Test {
    let wire = response(&entity(1, true), 1, 43);
    for split in 1..=wire.len() {
        let (frames, _) = drive(&wire, split)?;
        assert_eq!(frames.len(), 1);
        check_frame(&wire, &frames[0])?;
    }
    Ok(())
}
#[test]
fn final_mime_delimiter_without_crlf_is_completed_only_at_http_end() -> Test {
    for mode in 0..3 {
        let wire = response(&entity(1, false), mode, 7);
        let (frames, end) = drive(&wire, 3)?;
        assert_eq!(frames.len(), 1);
        assert_eq!(end.multipart.frames, 1);
        check_frame(&wire, &frames[0])?;
    }
    Ok(())
}
#[test]
fn multiple_mime_frames_in_one_http_data_event_do_not_drop_suffix() -> Test {
    let wire = response(&entity(3, true), 0, 1);
    let (frames, _) = drive(&wire, wire.len())?;
    assert_eq!(frames.len(), 3);
    for (i, frame) in frames.iter().enumerate() {
        assert_eq!(frame.part().receipt().ordinal, i as u64 + 1);
        check_frame(&wire, frame)?;
    }
    Ok(())
}
fn head_and_data(body: &[u8]) -> Result<(ResponseHead, EntityData), Box<dyn Error>> {
    let wire = response(body, 0, 1);
    let mut http = HttpResponseStream::new(basis(), HttpLimits::default())?;
    let mut budget = DecodeBudget::new(1_000_000);
    let head = http.push(0, &wire, &mut budget)?;
    let data = http.push(http.next_offset(), &wire[head.consumed..], &mut budget)?;
    match (head.event, data.event) {
        (Some(HttpEvent::Head(h)), Some(HttpEvent::Data(d))) => Ok((h, d)),
        _ => Err("missing events".into()),
    }
}
#[test]
fn repeated_or_skipped_entity_bytes_poison_consumer() -> Test {
    let (head, data) = head_and_data(&entity(1, true))?;
    let mut b = DecodeBudget::new(1_000_000);
    let mut p = HttpMultipartStream::new(&head, MultipartLimits::default(), 4096, &mut b)?;
    assert_eq!(
        p.push(&data, 1, &mut b).err().ok_or("accepted gap")?.error,
        HttpMjpegError::BasisMismatch
    );
    assert_eq!(
        p.push(&data, 0, &mut b).err().ok_or("resumed")?.error,
        HttpMjpegError::Poisoned
    );
    let mut p = HttpMultipartStream::new(&head, MultipartLimits::default(), 4096, &mut b)?;
    p.push(&data, 0, &mut b)?;
    assert_eq!(
        p.push(&data, 0, &mut b)
            .err()
            .ok_or("accepted replay")?
            .error,
        HttpMjpegError::BasisMismatch
    );
    Ok(())
}
#[test]
fn missing_http_or_mime_termination_cannot_become_complete() -> Test {
    let body = entity(1, true);
    let wire = response(&body, 1, 100);
    for remove in 1..=5 {
        assert!(drive(&wire[..wire.len() - remove], 17).is_err());
    }
    let short = &body[..body.len() - 9];
    let wire = response(short, 0, 1);
    assert!(drive(&wire, 11).is_err());
    Ok(())
}
#[test]
fn cancellation_and_mapping_limit_retain_original_data_and_pending_parts() -> Test {
    let (head, data) = head_and_data(&entity(1, true))?;
    let mut b = DecodeBudget::new(1_000_000);
    let mut p = HttpMultipartStream::new(&head, MultipartLimits::default(), 4096, &mut b)?;
    let stop = AtomicBool::new(true);
    assert_eq!(
        p.push(&data, 0, &mut DecodeBudget::cancellable(100000, &stop))
            .err()
            .ok_or("ignored cancel")?
            .consumed,
        0
    );
    assert!(p.abort().pending_frame.is_none());
    assert_eq!(data.bytes(), entity(1, true));
    let mut p = HttpMultipartStream::new(&head, MultipartLimits::default(), 4096, &mut b)?;
    let before = b.used();
    assert!(p.push(&data, 0, &mut b)?.frame.is_some());
    let used = b.used() - before;
    let mut p = HttpMultipartStream::new(&head, MultipartLimits::default(), 4096, &mut b)?;
    let error = p
        .push(&data, 0, &mut DecodeBudget::new(used - 1))
        .err()
        .ok_or("ignored publication budget")?;
    assert_eq!(error.consumed, data.bytes().len());
    assert_eq!(
        p.abort()
            .pending_frame
            .ok_or("lost complete frame")?
            .bytes(),
        JPEG
    );
    Ok(())
}
#[test]
fn chunk_map_overflow_fails_instead_of_truncating_source_lineage() -> Test {
    let wire = response(&entity(1, true), 1, 7);
    let mut h = HttpResponseStream::new(basis(), HttpLimits::default())?;
    let mut p = None;
    let mut b = DecodeBudget::new(1_000_000);
    let mut failed = false;
    while (h.next_offset() as usize) < wire.len() {
        let s = h.push(h.next_offset(), &wire[h.next_offset() as usize..], &mut b)?;
        match s.event {
            Some(HttpEvent::Head(head)) => {
                p = Some(HttpMultipartStream::new(
                    &head,
                    MultipartLimits::default(),
                    1,
                    &mut b,
                )?)
            }
            Some(HttpEvent::Data(data)) => {
                if let Err(e) = p.as_mut().ok_or("head")?.push(&data, 0, &mut b) {
                    assert_eq!(e.error, HttpMjpegError::Limit);
                    assert_eq!(e.consumed, 0);
                    failed = true;
                    break;
                }
            }
            _ => (),
        }
    }
    assert!(failed);
    let saved = p.ok_or("consumer")?.abort();
    assert_eq!(saved.runs.len(), 1);
    Ok(())
}
#[test]
fn non_multipart_and_wrong_response_data_are_not_admitted() -> Test {
    let (head, data) = head_and_data(&entity(1, true))?;
    let mut b = DecodeBudget::new(1_000_000);
    let other = b"HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\n\r\n";
    let mut h = HttpResponseStream::new(basis(), HttpLimits::default())?;
    if let Some(HttpEvent::Head(bad)) = h.push(0, other, &mut b)?.event {
        assert!(matches!(
            HttpMultipartStream::new(&bad, MultipartLimits::default(), 10, &mut b),
            Err(HttpMjpegError::Multipart(MultipartError::Configuration))
        ));
    } else {
        return Err("header absent".into());
    }
    let mut h = HttpResponseStream::new(
        StreamBasis {
            generation: 2,
            ..basis()
        },
        HttpLimits::default(),
    )?;
    let wire = response(&entity(1, true), 0, 1);
    let hs = h.push(0, &wire, &mut b)?;
    if let Some(HttpEvent::Head(other)) = hs.event {
        let mut p = HttpMultipartStream::new(&other, MultipartLimits::default(), 10, &mut b)?;
        assert_eq!(
            p.push(&data, 0, &mut b)
                .err()
                .ok_or("accepted different source")?
                .error,
            HttpMjpegError::BasisMismatch
        );
    } else {
        return Err("header absent".into());
    }
    assert_ne!(head.identity().entity.source, [0; 32]);
    Ok(())
}

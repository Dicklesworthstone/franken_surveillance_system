#![forbid(unsafe_code)]
use fss_reference::rtsp::{RtspEvent, framed::*};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn response(cseq: u32, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\nWWW-Authenticate: Digest realm=\"PRIVATE-REALM\", nonce=\"PRIVATE-NONCE\"\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    bytes.extend_from_slice(body); bytes
}
#[test]
fn every_split_preserves_the_exact_challenge_and_opaque_body() -> TestResult {
    let bytes = response(1, b"$\0\0\x04RTSP/1.0 200 fake\r\n\r\n");
    for cut in 0..=bytes.len() {
        let mut input = RtspWireIntake::new();
        input.ingest(&bytes[..cut], 1)?;
        let first = input.poll(1)?;
        input.ingest(&bytes[cut..], 2)?;
        let frame = first.or(input.poll(2)?).ok_or("frame missing")?;
        assert_eq!(frame.expose_wire(), bytes);
        assert!(matches!(frame.event(), RtspEvent::AuthRequired { response, .. } if response.status_code == 401));
        assert!(input.poll(2)?.is_none());
        assert_eq!(input.buffered_bytes(), 0);
    }
    Ok(())
}
#[test]
fn mixed_frames_are_delivered_in_wire_order_without_a_batch_queue() -> TestResult {
    let first = response(1, b"body");
    let packet = b"$\x02\0\x08\x80\xc9\0\x01\0\0\0\x07";
    let second = b"RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n";
    let bytes = [first.as_slice(), packet, second].concat();
    let mut input = RtspWireIntake::new(); input.ingest(&bytes, 5)?;
    for expected in [first.as_slice(), packet, second] {
        let frame = input.poll(10)?.ok_or("frame")?;
        assert_eq!(frame.expose_wire(), expected); assert_eq!(frame.received_ns(), 5);
    }
    assert!(input.poll(10)?.is_none());
    Ok(())
}
#[test]
fn incomplete_binary_payload_cannot_be_reinterpreted_as_a_challenge() -> TestResult {
    let challenge = response(1, b"");
    let mut wire = vec![b'$', 0]; wire.extend_from_slice(&(challenge.len() as u16).to_be_bytes());
    wire.extend_from_slice(&challenge);
    let mut input = RtspWireIntake::new();
    for chunk in wire.chunks(3) { input.ingest(chunk, 1)?; if let Some(frame) = input.poll(1)? {
        assert!(matches!(frame.event(), RtspEvent::Interleaved { span, .. } if *span == challenge));
        assert_eq!(frame.expose_wire(), wire);
    } }
    input.finish(); assert!(input.poll(1)?.is_none()); assert!(input.is_ended());
    Ok(())
}
#[test]
fn intake_backpressure_does_not_consume_input_or_advance_time() -> TestResult {
    let bytes = response(1, b""); let mut input = RtspWireIntake::new();
    input.ingest(&bytes, 1)?;
    assert_eq!(input.ingest(b"not admitted", 100), Err(WireIntakeError::Backpressure));
    assert_eq!(input.buffered_bytes(), bytes.len());
    assert_eq!(input.poll(2)?.ok_or("frame")?.expose_wire(), bytes);
    assert!(input.poll(2)?.is_none());
    Ok(())
}
#[test]
fn deadline_is_checked_before_a_late_final_byte_can_clear_it() -> TestResult {
    let bytes = response(1, b""); let mut input = RtspWireIntake::new();
    input.ingest(&bytes[..bytes.len()-1], 0)?; assert!(input.poll(0)?.is_none());
    assert_eq!(input.ingest(&bytes[bytes.len()-1..], WIRE_LIFETIME_NS), Err(WireIntakeError::Deadline));
    assert!(matches!(input.poll(WIRE_LIFETIME_NS), Err(WireIntakeError::Deadline)));
    assert_eq!(input.cancel().expose(), &bytes[..bytes.len()-1]);
    Ok(())
}
#[test]
fn lookahead_uses_original_admission_time_not_processing_time() -> TestResult {
    let a = response(1, b""); let b = response(2, b"");
    let mut input = RtspWireIntake::new(); input.ingest(&a[..10], 1)?; assert!(input.poll(1)?.is_none());
    input.ingest(&[&a[10..], &b[..10]].concat(), 5)?;
    assert!(input.poll(100)?.is_some()); assert!(input.poll(100)?.is_none());
    assert_eq!(input.deadline_ns(), Some(5 + WIRE_LIFETIME_NS));
    assert!(matches!(input.poll(5 + WIRE_LIFETIME_NS), Err(WireIntakeError::Deadline)));
    assert_eq!(input.cancel().expose(), &b[..10]);
    Ok(())
}
#[test]
fn valid_prefix_survives_but_malformed_suffix_never_resynchronizes() -> TestResult {
    let valid = response(1, b""); let bad = b"RTSP/2.0 200 NO\r\nCSeq: 2\r\n\r\n";
    let mut input = RtspWireIntake::new(); input.ingest(&[valid.as_slice(), bad, valid.as_slice()].concat(), 1)?;
    assert_eq!(input.poll(1)?.ok_or("prefix")?.expose_wire(), valid);
    assert!(matches!(input.poll(1), Err(WireIntakeError::Protocol(_))));
    assert!(input.poll(1).is_err());
    assert_eq!(input.cancel().expose(), [bad.as_slice(), valid.as_slice()].concat());
    Ok(())
}
#[test]
fn conflicting_duplicate_signed_and_folded_lengths_are_refused() -> TestResult {
    for header in ["Content-Length: 0\r\nContent-Length: 0", "Content-Length: +0",
        "Content-Length: 0\r\nContent-Length: 1", " Content-Length: 0", "Content-Length: 0\r\n 1"] {
        let bytes = format!("RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\n{header}\r\n\r\n").into_bytes();
        let mut input = RtspWireIntake::new(); input.ingest(&bytes, 1)?;
        assert!(input.poll(1).is_err()); assert_eq!(input.cancel().expose(), bytes);
    }
    Ok(())
}
#[test]
fn every_nonboundary_eof_is_explicitly_truncated() -> TestResult {
    let bytes = response(1, b"body");
    for cut in 1..bytes.len() {
        let mut input = RtspWireIntake::new(); input.ingest(&bytes[..cut], 1)?; input.finish();
        assert!(matches!(input.poll(1), Err(WireIntakeError::Truncated)));
        assert!(!input.is_ended()); assert_eq!(input.cancel().expose(), &bytes[..cut]);
    }
    Ok(())
}
#[test]
fn debug_and_budget_errors_never_contain_retained_authentication_text() -> TestResult {
    let bytes = response(1, b"PRIVATE-BODY"); let mut input = RtspWireIntake::new();
    input.ingest(&bytes, 1)?; assert!(!format!("{input:?}").contains("PRIVATE"));
    let frame = input.poll(1)?.ok_or("frame")?;
    assert!(!format!("{frame:?}").contains("PRIVATE"));
    let (_, retained, _) = frame.into_parts(); assert!(!format!("{retained:?}").contains("PRIVATE"));
    assert_eq!(input.ingest(&vec![b'x'; MAX_WIRE_CHUNK + 1], 2), Err(WireIntakeError::Limit));
    assert_eq!(input.buffered_bytes(), 0);
    let too_big = b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nContent-Length: 65537\r\n\r\n";
    input.ingest(too_big, 2)?; assert!(matches!(input.poll(2), Err(WireIntakeError::Limit)));
    Ok(())
}

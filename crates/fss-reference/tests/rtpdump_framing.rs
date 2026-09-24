#![forbid(unsafe_code)]
//! rtpdump framing: exact offsets, exact-prefix cuts, no resynchronization, and independent limits.
use fss_reference::ingest::rtpdump::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn header() -> Vec<u8> {
    let mut bytes = b"#!rtpplay1.0 0.0.0.0/0\n".to_vec();
    bytes.extend_from_slice(&[0; 16]);
    bytes
}
fn record(bytes: &mut Vec<u8>, payload: &[u8], original: u16) {
    bytes.extend_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
    bytes.extend_from_slice(&original.to_be_bytes());
    bytes.extend_from_slice(&7u32.to_be_bytes());
    bytes.extend_from_slice(payload);
}

#[test]
fn exact_offsets_and_kind_do_not_guess_packet_validity() -> TestResult {
    let mut bytes = header();
    record(&mut bytes, &[0x80, 96, 0], 50);
    record(&mut bytes, &[0x80, 201, 0, 1, 0, 0, 0, 7], 0);
    record(&mut bytes, &[0x80; 12], 12);
    let mut reader = RtpDumpReader::new(&bytes, RtpDumpLimits::default())?;
    assert_eq!(reader.header_span(), 0..header().len());
    for (index, kind) in [
        RtpDumpKind::CapturedPrefix,
        RtpDumpKind::Rtcp,
        RtpDumpKind::Rtp,
    ]
    .into_iter()
    .enumerate()
    {
        let item = reader.next_record()?.ok_or("record missing")?;
        assert_eq!(item.index(), index);
        assert_eq!(item.kind(), kind);
        assert_eq!(item.packet(), &bytes[item.packet_span()]);
        assert_eq!(item.offset_ms(), 7);
    }
    assert!(reader.next_record()?.is_none());
    assert_eq!(reader.consumed_bytes(), bytes.len());
    Ok(())
}

#[test]
fn every_cut_is_exact_prefix_or_explicit_failure() {
    let mut bytes = header();
    record(&mut bytes, &[0x80; 12], 12);
    let boundary = bytes.len();
    record(&mut bytes, &[0x80; 12], 12);
    for cut in 0..=bytes.len() {
        match RtpDumpReader::new(&bytes[..cut], RtpDumpLimits::default()) {
            Err(_) => assert!(cut < header().len()),
            Ok(mut reader) => loop {
                match reader.next_record() {
                    Ok(Some(item)) => assert!(item.span().end <= cut),
                    Ok(None) => {
                        assert!([header().len(), boundary, bytes.len()].contains(&cut));
                        break;
                    }
                    Err(error) => {
                        assert_eq!(error.span.end, cut);
                        assert_eq!(
                            reader.next_record().err().map(|e| e.fault),
                            Some(RtpDumpFault::Stopped)
                        );
                        break;
                    }
                }
            },
        }
    }
}

#[test]
fn malformed_record_never_resynchronizes() -> TestResult {
    let mut bytes = header();
    bytes.extend_from_slice(&[0, 7, 0, 12, 0, 0, 0, 0]);
    record(&mut bytes, &[0x80; 12], 12);
    let mut reader = RtpDumpReader::new(&bytes, RtpDumpLimits::default())?;
    assert_eq!(
        reader.next_record().err().map(|e| e.fault),
        Some(RtpDumpFault::RecordLength)
    );
    assert_eq!(reader.records_read(), 0);
    assert_eq!(reader.consumed_bytes(), header().len());
    assert_eq!(
        reader.next_record().err().map(|e| e.fault),
        Some(RtpDumpFault::Stopped)
    );
    Ok(())
}

#[test]
fn independent_limits_and_redaction() -> TestResult {
    let mut bytes = b"#!rtpplay1.0 PRIVATE-ENDPOINT/55\n".to_vec();
    bytes.extend_from_slice(&[0; 16]);
    record(&mut bytes, b"PRIVATE-PAYLOAD", 15);
    let mut reader = RtpDumpReader::new(&bytes, RtpDumpLimits::default())?;
    let item = reader.next_record()?;
    assert!(!format!("{reader:?} {item:?}").contains("PRIVATE"));
    assert!(
        RtpDumpReader::new(
            &bytes,
            RtpDumpLimits {
                max_input_bytes: bytes.len() - 1,
                ..RtpDumpLimits::default()
            }
        )
        .is_err()
    );
    let mut reader = RtpDumpReader::new(
        &bytes,
        RtpDumpLimits {
            max_packet_bytes: 13,
            ..RtpDumpLimits::default()
        },
    )?;
    assert_eq!(
        reader.next_record().err().map(|e| e.fault),
        Some(RtpDumpFault::Limit)
    );
    Ok(())
}

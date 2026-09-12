#![forbid(unsafe_code)]
//! Cross-ingress isolation, unavailable clocks, and state-retirement regression cases.

use fss_packet::{
    ContinuityError, H264Depacketizer, H264Error, H264Limits, H264Mode, NtpTimestamp,
    PacketLimits, RtpPacket, SenderReport, SenderReportClock, SequenceTracker, StreamKey,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const KEY: StreamKey = StreamKey { ingress: 1, generation: 1, ssrc: 7 };

#[test]
fn identical_wire_ssrc_and_epoch_cannot_cross_logical_ingress() -> TestResult {
    let other = StreamKey { ingress: 2, ..KEY };
    let mut sequence = SequenceTracker::new(KEY, 96)?;
    let before = sequence.clone();
    let bytes = [0x80, 96, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7, 0x7c, 0x85, 1];
    let packet = RtpPacket::parse(&bytes, PacketLimits::default())?;
    assert_eq!(sequence.observe(other, packet), Err(ContinuityError::StreamMismatch));
    assert_eq!(sequence, before);
    let newer_other = StreamKey { generation: 2, ..other };
    assert_eq!(sequence.restart(newer_other, 96), Err(ContinuityError::StreamMismatch));
    let mut media = H264Depacketizer::new(KEY, 96, H264Mode::NonInterleaved, H264Limits::default())?;
    media.push(KEY, 1, packet, 0)?;
    let end = [0x80, 224, 0, 2, 0, 0, 0, 0, 0, 0, 0, 7, 0x7c, 0x45, 2];
    let packet = RtpPacket::parse(&end, PacketLimits::default())?;
    let failure = media.push(other, 2, packet, 1).err().ok_or("foreign ingress accepted")?;
    assert_eq!(failure.reason, H264Error::StreamMismatch);
    assert!(failure.discarded.is_none());
    assert_eq!(media.pending_bytes(), 2);
    assert_eq!(media.push(KEY, 2, packet, 1)?.nals[0].bytes(), [0x65, 1, 2]);
    Ok(())
}

#[test]
fn unavailable_sender_clock_and_cross_ingress_estimates_are_not_capture_time() -> TestResult {
    let mut report = SenderReport {
        ssrc: 7,
        ntp: NtpTimestamp { seconds: 0, fraction: 0 },
        rtp_timestamp: 0,
        packet_count: 0,
        octet_count: 0,
    };
    assert_eq!(SenderReportClock::new(KEY, 90_000, report, 0, 0, 90_000), Err(ContinuityError::NoSenderReport));
    report.ntp.seconds = 1;
    let clock = SenderReportClock::new(KEY, 90_000, report, 0, 0, 90_000)?;
    let other = StreamKey { ingress: 2, ..KEY };
    assert_eq!(clock.estimate(other, 0), Err(ContinuityError::StreamMismatch));
    Ok(())
}

#[test]
fn contradictory_or_unbounded_limits_refuse_before_allocating() -> TestResult {
    let zero = StreamKey { ingress: 0, ..KEY };
    assert_eq!(SequenceTracker::new(zero, 96), Err(ContinuityError::Configuration));
    assert!(H264Depacketizer::new(zero, 96, H264Mode::NonInterleaved, H264Limits::default()).is_err());
    for limits in [
        H264Limits { max_nal_bytes: 0, ..H264Limits::default() },
        H264Limits { max_nal_bytes: usize::MAX, ..H264Limits::default() },
        H264Limits { max_packet_nals: 257, ..H264Limits::default() },
        H264Limits { max_fragment_packets: 1, ..H264Limits::default() },
        H264Limits { max_pending_age_ns: u64::MAX, ..H264Limits::default() },
    ] {
        assert!(H264Depacketizer::new(KEY, 96, H264Mode::NonInterleaved, limits).is_err());
    }
    Ok(())
}

#[test]
fn replacement_start_retires_old_chain_without_mixing_payloads() -> TestResult {
    let mut media = H264Depacketizer::new(KEY, 96, H264Mode::NonInterleaved, H264Limits::default())?;
    for (sequence, marker, payload) in [
        (1_u16, false, [0x7c, 0x85, 10]),
        (2, false, [0x7c, 0x85, 20]),
        (3, true, [0x7c, 0x45, 30]),
    ] {
        let mut bytes = vec![0x80, 96 | if marker { 128 } else { 0 }];
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 7]);
        bytes.extend_from_slice(&payload);
        let output = media.push(KEY, u64::from(sequence), RtpPacket::parse(&bytes, PacketLimits::default())?, u64::from(sequence))?;
        if sequence == 2 {
            let discard = output.discarded.ok_or("old chain lacked retirement receipt")?;
            assert_eq!(discard.reason, H264Error::Interrupted);
            assert_eq!(discard.first_sequence, 1);
            assert_eq!(discard.byte_len, 2);
            assert!(output.nals.is_empty());
        }
        if sequence == 3 {
            assert_eq!(output.nals[0].bytes(), [0x65, 20, 30]);
            assert_eq!(output.nals[0].sources()[0].sequence, 2);
        }
    }
    Ok(())
}

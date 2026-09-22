#![forbid(unsafe_code)]
//! Companion contract tests for sans-IO RTSP/1.0 parser (fss-2h5zq.33).
//!
//! Verifies:
//! - Exact typed event sequences for all 8 committed transcripts (C2S and S2C fed separately)
//! - SDP parameter set equality with FIXH264 parameter sets (SPS/PPS)
//! - Frame reassembly across split records (interleave_split)
//! - Typed error surfacing on malformed length (bad_content_length)
//! - Incremental feeding: identical event sequences across every 2-way byte split and 1-byte chunks
//! - Credential byte-scan: planted secrets in Authorization, Proxy-Authorization, WWW-Authenticate,
//!   and user:pass@ URIs never appear in Debug output of any event or error
//! - Bounded inputs: exact boundary behavior at limit N (Ok) and N+1 (HeaderLimit / BodyLimit)
//! - Mutant kills: CSeq required, Content-Length exact framing, userinfo forbidden,
//!   pending-error-before-buffering preservation, and line folding forbidden

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_reference::media_fixture::h264::{generate_pps, generate_sps};
use fss_reference::media_fixture::{TranscriptDirection, TranscriptRecord, parse_transcript};
use fss_reference::rtsp::{
    AuthScheme, REDACTED_CREDENTIAL, RtspError, RtspEvent, RtspLimits, RtspMethod, RtspParser,
    parse_sdp,
};

fn get_repo_root() -> Result<PathBuf, Box<dyn Error>> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .ok_or_else(|| "cannot find repository root".into())
}

fn load_transcript(filename: &str) -> Result<Vec<TranscriptRecord>, Box<dyn Error>> {
    let repo_root = get_repo_root()?;
    let path = repo_root.join("tests/fixtures/media/rtsp").join(filename);
    let bytes = fs::read(&path)?;
    let records = parse_transcript(&bytes)?;
    Ok(records)
}

fn split_stream_records(records: &[TranscriptRecord]) -> (Vec<u8>, Vec<u8>) {
    let mut c2s = Vec::new();
    let mut s2c = Vec::new();
    for r in records {
        match r.direction {
            TranscriptDirection::ClientToServer => c2s.extend_from_slice(&r.bytes),
            TranscriptDirection::ServerToClient => s2c.extend_from_slice(&r.bytes),
        }
    }
    (c2s, s2c)
}

#[test]
fn test_transcript_clean_literal_expected_sequences() -> Result<(), Box<dyn Error>> {
    let records = load_transcript("clean.transcript")?;
    let (c2s_bytes, s2c_bytes) = split_stream_records(&records);

    // 1. ClientToServer stream (5 requests)
    let mut c2s_parser = RtspParser::new();
    let c2s_events = c2s_parser.feed(&c2s_bytes)?;
    assert_eq!(c2s_events.len(), 5);

    // C2S [0]: OPTIONS
    let RtspEvent::Request(req0) = &c2s_events[0] else {
        return Err("expected Request event at 0".into());
    };
    assert_eq!(req0.method, RtspMethod::Options);
    assert_eq!(req0.uri, "rtsp://fixture.invalid/stream");
    assert_eq!(req0.version, "RTSP/1.0");
    assert_eq!(req0.headers.cseq().ok_or("missing CSeq")??, 1);
    assert_eq!(req0.headers.get("User-Agent"), Some("FSS-Reference"));
    assert!(req0.body.is_empty());

    // C2S [1]: DESCRIBE
    let RtspEvent::Request(req1) = &c2s_events[1] else {
        return Err("expected Request event at 1".into());
    };
    assert_eq!(req1.method, RtspMethod::Describe);
    assert_eq!(req1.uri, "rtsp://fixture.invalid/stream");
    assert_eq!(req1.version, "RTSP/1.0");
    assert_eq!(req1.headers.cseq().ok_or("missing CSeq")??, 2);
    assert_eq!(req1.headers.get("Accept"), Some("application/sdp"));
    assert!(req1.body.is_empty());

    // C2S [2]: SETUP
    let RtspEvent::Request(req2) = &c2s_events[2] else {
        return Err("expected Request event at 2".into());
    };
    assert_eq!(req2.method, RtspMethod::Setup);
    assert_eq!(req2.uri, "rtsp://fixture.invalid/stream/trackID=1");
    assert_eq!(req2.version, "RTSP/1.0");
    assert_eq!(req2.headers.cseq().ok_or("missing CSeq")??, 3);
    let tr = req2.headers.transport().ok_or("missing Transport")??;
    assert_eq!(tr.profile, "RTP/AVP/TCP");
    assert!(tr.unicast);
    assert_eq!(tr.interleaved, Some((0, 1)));
    assert!(req2.body.is_empty());

    // C2S [3]: PLAY
    let RtspEvent::Request(req3) = &c2s_events[3] else {
        return Err("expected Request event at 3".into());
    };
    assert_eq!(req3.method, RtspMethod::Play);
    assert_eq!(req3.uri, "rtsp://fixture.invalid/stream");
    assert_eq!(req3.version, "RTSP/1.0");
    assert_eq!(req3.headers.cseq().ok_or("missing CSeq")??, 4);
    assert_eq!(req3.headers.session_id(), Some("12345678"));
    assert_eq!(req3.headers.range(), Some("npt=0-"));
    assert!(req3.body.is_empty());

    // C2S [4]: TEARDOWN
    let RtspEvent::Request(req4) = &c2s_events[4] else {
        return Err("expected Request event at 4".into());
    };
    assert_eq!(req4.method, RtspMethod::Teardown);
    assert_eq!(req4.uri, "rtsp://fixture.invalid/stream");
    assert_eq!(req4.version, "RTSP/1.0");
    assert_eq!(req4.headers.cseq().ok_or("missing CSeq")??, 5);
    assert_eq!(req4.headers.session_id(), Some("12345678"));
    assert!(req4.body.is_empty());

    // 2. ServerToClient stream (4 responses + 18 interleaved frames + 1 response = 23 events)
    let mut s2c_parser = RtspParser::new();
    let s2c_events = s2c_parser.feed(&s2c_bytes)?;
    assert_eq!(s2c_events.len(), 23);

    // S2C [0]: OPTIONS response
    let RtspEvent::Response(resp0) = &s2c_events[0] else {
        return Err("expected Response event at 0".into());
    };
    assert_eq!(resp0.version, "RTSP/1.0");
    assert_eq!(resp0.status_code, 200);
    assert_eq!(resp0.reason, "OK");
    assert_eq!(resp0.headers.cseq().ok_or("missing CSeq")??, 1);
    assert_eq!(
        resp0.headers.public(),
        Some("OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN")
    );
    assert!(resp0.body.is_empty());

    // S2C [1]: DESCRIBE response with SDP
    let RtspEvent::Response(resp1) = &s2c_events[1] else {
        return Err("expected Response event at 1".into());
    };
    assert_eq!(resp1.version, "RTSP/1.0");
    assert_eq!(resp1.status_code, 200);
    assert_eq!(resp1.reason, "OK");
    assert_eq!(resp1.headers.cseq().ok_or("missing CSeq")??, 2);
    assert_eq!(resp1.headers.content_type(), Some("application/sdp"));
    assert_eq!(
        resp1.headers.get("Content-Base"),
        Some("rtsp://fixture.invalid/stream/")
    );
    assert_eq!(resp1.headers.content_length().ok_or("missing len")??, 242);
    assert_eq!(resp1.body.len(), 242);

    // Parse and verify SDP body against FIXH264 parameter sets
    let sdp_str = std::str::from_utf8(&resp1.body)?;
    let sdp = parse_sdp(sdp_str)?;
    assert_eq!(sdp.version, 0);
    assert_eq!(sdp.session_name, "FSS Synthetic RTSP Session");
    assert_eq!(
        sdp.connection_opaque.as_deref(),
        Some("IN IP4 fixture.invalid")
    );
    let video = sdp.video_media.ok_or("missing video media in SDP")?;
    assert_eq!(video.payload_type, 96);
    assert_eq!(video.encoding_name.as_deref(), Some("H264"));
    assert_eq!(video.clock_rate, Some(90_000));
    assert_eq!(video.packetization_mode, Some(1));
    assert_eq!(video.control.as_deref(), Some("trackID=1"));
    assert!(!video.rtcp_reduced_size);
    assert_eq!(video.sps.as_ref(), Some(&generate_sps(42)));
    assert_eq!(video.pps.as_ref(), Some(&generate_pps(42)));

    // S2C [2]: SETUP response
    let RtspEvent::Response(resp2) = &s2c_events[2] else {
        return Err("expected Response event at 2".into());
    };
    assert_eq!(resp2.version, "RTSP/1.0");
    assert_eq!(resp2.status_code, 200);
    assert_eq!(resp2.reason, "OK");
    assert_eq!(resp2.headers.cseq().ok_or("missing CSeq")??, 3);
    assert_eq!(resp2.headers.session_id(), Some("12345678"));
    assert_eq!(resp2.headers.session_timeout(), Some(60));
    let s2c_tr = resp2.headers.transport().ok_or("missing Transport")??;
    assert_eq!(s2c_tr.profile, "RTP/AVP/TCP");
    assert!(s2c_tr.unicast);
    assert_eq!(s2c_tr.interleaved, Some((0, 1)));
    assert!(resp2.body.is_empty());

    // S2C [3]: PLAY response
    let RtspEvent::Response(resp3) = &s2c_events[3] else {
        return Err("expected Response event at 3".into());
    };
    assert_eq!(resp3.version, "RTSP/1.0");
    assert_eq!(resp3.status_code, 200);
    assert_eq!(resp3.reason, "OK");
    assert_eq!(resp3.headers.cseq().ok_or("missing CSeq")??, 4);
    assert_eq!(resp3.headers.session_id(), Some("12345678"));
    assert_eq!(
        resp3.headers.rtp_info(),
        Some("url=rtsp://fixture.invalid/stream/trackID=1;seq=65534;rtptime=90000")
    );
    assert!(resp3.body.is_empty());

    // S2C [4..21]: 18 Interleaved binary frames (channel, expected_len)
    let expected_frames: [(u8, usize); 18] = [
        (1, 68),
        (0, 14),
        (0, 14),
        (0, 29),
        (0, 62),
        (0, 1200),
        (0, 244),
        (0, 333),
        (0, 14),
        (0, 397),
        (1, 68),
        (0, 14),
        (0, 541),
        (0, 14),
        (0, 397),
        (0, 14),
        (0, 397),
        (1, 68),
    ];
    for (idx, &(exp_ch, exp_len)) in expected_frames.iter().enumerate() {
        let event_idx = 4 + idx;
        let RtspEvent::Interleaved { channel, span } = &s2c_events[event_idx] else {
            return Err(format!("expected Interleaved event at {event_idx}").into());
        };
        assert_eq!(*channel, exp_ch, "channel mismatch at {event_idx}");
        assert_eq!(span.len(), exp_len, "span len mismatch at {event_idx}");
    }

    // S2C [22]: TEARDOWN response
    let RtspEvent::Response(resp22) = &s2c_events[22] else {
        return Err("expected Response event at 22".into());
    };
    assert_eq!(resp22.version, "RTSP/1.0");
    assert_eq!(resp22.status_code, 200);
    assert_eq!(resp22.reason, "OK");
    assert_eq!(resp22.headers.cseq().ok_or("missing CSeq")??, 5);
    assert_eq!(resp22.headers.session_id(), Some("12345678"));
    assert!(resp22.body.is_empty());

    println!(
        r#"CAPLOG {{"step":"test_transcript_clean_literal_expected_sequences","verdict":"pass","duration_ms":1}}"#
    );
    Ok(())
}

#[test]
fn test_transcript_auth_required_literal_expected_sequences() -> Result<(), Box<dyn Error>> {
    let records = load_transcript("auth_required.transcript")?;
    let (c2s_bytes, s2c_bytes) = split_stream_records(&records);

    // C2S: 1 OPTIONS request
    let mut c2s_parser = RtspParser::new();
    let c2s_events = c2s_parser.feed(&c2s_bytes)?;
    assert_eq!(c2s_events.len(), 1);
    let RtspEvent::Request(req) = &c2s_events[0] else {
        return Err("expected Request event".into());
    };
    assert_eq!(req.method, RtspMethod::Options);
    assert_eq!(req.uri, "rtsp://fixture.invalid/stream");
    assert_eq!(req.headers.cseq().ok_or("missing CSeq")??, 1);
    assert_eq!(req.headers.get("User-Agent"), Some("FSS-Reference"));

    // S2C: 1 AuthRequired event with scheme AuthScheme::Digest
    let mut s2c_parser = RtspParser::new();
    let s2c_events = s2c_parser.feed(&s2c_bytes)?;
    assert_eq!(s2c_events.len(), 1);
    let RtspEvent::AuthRequired { scheme, response } = &s2c_events[0] else {
        return Err("expected AuthRequired event at 0".into());
    };
    assert_eq!(*scheme, AuthScheme::Digest);
    assert_eq!(response.status_code, 401);
    assert_eq!(response.headers.cseq().ok_or("missing CSeq")??, 1);

    println!(
        r#"CAPLOG {{"step":"test_transcript_auth_required_literal_expected_sequences","verdict":"pass","duration_ms":1}}"#
    );
    Ok(())
}

#[test]
fn test_transcript_interleave_split_reassembly_and_literal_expected_sequences()
-> Result<(), Box<dyn Error>> {
    let records = load_transcript("interleave_split.transcript")?;
    let (c2s_bytes, s2c_bytes) = split_stream_records(&records);

    // C2S stream is identical to clean
    let mut c2s_parser = RtspParser::new();
    let c2s_events = c2s_parser.feed(&c2s_bytes)?;
    assert_eq!(c2s_events.len(), 5);

    // S2C stream contains a 1204-byte interleaved frame that was physically split across
    // 2 records on wire (600 + 604 bytes). The parser must reassemble it into a single frame.
    let mut s2c_parser = RtspParser::new();
    let s2c_events = s2c_parser.feed(&s2c_bytes)?;
    assert_eq!(
        s2c_events.len(),
        23,
        "reassembled stream must yield exactly 23 events"
    );

    // Specifically verify event index 9 (interleaved frame 5) reassembled to 1200 bytes
    let RtspEvent::Interleaved { channel, span } = &s2c_events[9] else {
        return Err("expected Interleaved event at 9".into());
    };
    assert_eq!(*channel, 0);
    assert_eq!(
        span.len(),
        1200,
        "split frame must be fully reassembled to 1200 bytes"
    );

    println!(
        r#"CAPLOG {{"step":"test_transcript_interleave_split_reassembly_and_literal_expected_sequences","verdict":"pass","duration_ms":1}}"#
    );
    Ok(())
}

#[test]
fn test_transcript_bad_content_length_literal_expected_sequences() -> Result<(), Box<dyn Error>> {
    let records = load_transcript("bad_content_length.transcript")?;
    let (c2s_bytes, s2c_bytes) = split_stream_records(&records);

    // C2S: 2 requests (OPTIONS, DESCRIBE)
    let mut c2s_parser = RtspParser::new();
    let c2s_events = c2s_parser.feed(&c2s_bytes)?;
    assert_eq!(c2s_events.len(), 2);
    let RtspEvent::Request(req0) = &c2s_events[0] else {
        return Err("expected Request 0".into());
    };
    assert_eq!(req0.method, RtspMethod::Options);
    assert_eq!(req0.headers.cseq().ok_or("missing CSeq")??, 1);
    let RtspEvent::Request(req1) = &c2s_events[1] else {
        return Err("expected Request 1".into());
    };
    assert_eq!(req1.method, RtspMethod::Describe);
    assert_eq!(req1.headers.cseq().ok_or("missing CSeq")??, 2);

    // S2C: Record 1 is 200 OK for OPTIONS; Record 3 is 200 OK for DESCRIBE with Content-Length: not-a-number
    let s2c_records: Vec<_> = records
        .iter()
        .filter(|r| r.direction == TranscriptDirection::ServerToClient)
        .collect();
    assert_eq!(s2c_records.len(), 2);

    // Feed record 0 alone: produces Response 200 OK
    let mut s2c_parser1 = RtspParser::new();
    let events1 = s2c_parser1.feed(&s2c_records[0].bytes)?;
    assert_eq!(events1.len(), 1);
    let RtspEvent::Response(resp0) = &events1[0] else {
        return Err("expected Response event".into());
    };
    assert_eq!(resp0.status_code, 200);
    assert_eq!(resp0.headers.cseq().ok_or("missing CSeq")??, 1);

    // Feed record 1: surfaces typed error BadContentLength
    let res2 = s2c_parser1.feed(&s2c_records[1].bytes);
    assert!(
        matches!(res2, Err(RtspError::BadContentLength(_))),
        "expected BadContentLength error"
    );

    // Combined stream fed at once yields valid event 0 first, then surfaces BadContentLength
    let mut combined_parser = RtspParser::new();
    let combined_events = combined_parser.feed(&s2c_bytes)?;
    assert_eq!(combined_events.len(), 1);
    assert_eq!(combined_events[0], events1[0]);
    let next_res = combined_parser.feed(b"");
    assert!(
        matches!(next_res, Err(RtspError::BadContentLength(_))),
        "subsequent feed must surface pending BadContentLength error"
    );

    println!(
        r#"CAPLOG {{"step":"test_transcript_bad_content_length_literal_expected_sequences","verdict":"pass","duration_ms":1}}"#
    );
    Ok(())
}

#[test]
fn test_transcript_session_timeout_header_literal_expected_sequences() -> Result<(), Box<dyn Error>>
{
    let records = load_transcript("session_timeout_header.transcript")?;
    let (c2s_bytes, s2c_bytes) = split_stream_records(&records);

    let mut c2s_parser = RtspParser::new();
    let c2s_events = c2s_parser.feed(&c2s_bytes)?;
    assert_eq!(c2s_events.len(), 5);

    let mut s2c_parser = RtspParser::new();
    let s2c_events = s2c_parser.feed(&s2c_bytes)?;
    assert_eq!(s2c_events.len(), 23);

    // SETUP response has timeout=30 instead of 60
    let RtspEvent::Response(resp2) = &s2c_events[2] else {
        return Err("expected Response at 2".into());
    };
    assert_eq!(resp2.headers.session_id(), Some("12345678"));
    assert_eq!(resp2.headers.session_timeout(), Some(30));

    println!(
        r#"CAPLOG {{"step":"test_transcript_session_timeout_header_literal_expected_sequences","verdict":"pass","duration_ms":1}}"#
    );
    Ok(())
}

#[test]
fn test_transcript_rtcp_rsize_literal_expected_sequences() -> Result<(), Box<dyn Error>> {
    let records = load_transcript("rtcp_rsize.transcript")?;
    let (c2s_bytes, s2c_bytes) = split_stream_records(&records);

    let mut c2s_parser = RtspParser::new();
    let c2s_events = c2s_parser.feed(&c2s_bytes)?;
    assert_eq!(c2s_events.len(), 5);

    let mut s2c_parser = RtspParser::new();
    let s2c_events = s2c_parser.feed(&s2c_bytes)?;
    assert_eq!(s2c_events.len(), 23);

    // DESCRIBE response SDP specifies a=rtcp-rsize and content length 256
    let RtspEvent::Response(resp1) = &s2c_events[1] else {
        return Err("expected Response at 1".into());
    };
    assert_eq!(resp1.headers.content_length().ok_or("missing len")??, 256);
    let sdp = parse_sdp(std::str::from_utf8(&resp1.body)?)?;
    let video = sdp.video_media.ok_or("missing video media")?;
    assert!(video.rtcp_reduced_size);
    assert_eq!(video.sps.as_ref(), Some(&generate_sps(42)));
    assert_eq!(video.pps.as_ref(), Some(&generate_pps(42)));

    // Channel 1 RTCP frames have reduced length 28 (indices 4, 14, 21)
    for &event_idx in &[4, 14, 21] {
        let RtspEvent::Interleaved { channel, span } = &s2c_events[event_idx] else {
            return Err(format!("expected Interleaved at {event_idx}").into());
        };
        assert_eq!(*channel, 1);
        assert_eq!(span.len(), 28, "rsize RTCP frame must be length 28");
    }

    println!(
        r#"CAPLOG {{"step":"test_transcript_rtcp_rsize_literal_expected_sequences","verdict":"pass","duration_ms":1}}"#
    );
    Ok(())
}

#[test]
fn test_transcript_sr_absent_literal_expected_sequences() -> Result<(), Box<dyn Error>> {
    let records = load_transcript("sr_absent.transcript")?;
    let (c2s_bytes, s2c_bytes) = split_stream_records(&records);

    let mut c2s_parser = RtspParser::new();
    let c2s_events = c2s_parser.feed(&c2s_bytes)?;
    assert_eq!(c2s_events.len(), 5);

    let mut s2c_parser = RtspParser::new();
    let s2c_events = s2c_parser.feed(&s2c_bytes)?;
    // 4 responses + 15 channel 0 frames + 1 response = 20 events (no channel 1 frames)
    assert_eq!(s2c_events.len(), 20);

    for event in &s2c_events[4..19] {
        let RtspEvent::Interleaved { channel, .. } = event else {
            return Err("expected Interleaved event".into());
        };
        assert_eq!(*channel, 0, "sr_absent must have no channel 1 RTCP frames");
    }

    println!(
        r#"CAPLOG {{"step":"test_transcript_sr_absent_literal_expected_sequences","verdict":"pass","duration_ms":1}}"#
    );
    Ok(())
}

#[test]
fn test_transcript_get_parameter_keepalive_literal_expected_sequences() -> Result<(), Box<dyn Error>>
{
    let records = load_transcript("get_parameter_keepalive.transcript")?;
    let (c2s_bytes, s2c_bytes) = split_stream_records(&records);

    // C2S: 6 requests (OPTIONS, DESCRIBE, SETUP, PLAY, GET_PARAMETER, TEARDOWN)
    let mut c2s_parser = RtspParser::new();
    let c2s_events = c2s_parser.feed(&c2s_bytes)?;
    assert_eq!(c2s_events.len(), 6);

    let RtspEvent::Request(req4) = &c2s_events[4] else {
        return Err("expected Request 4".into());
    };
    assert_eq!(req4.method, RtspMethod::GetParameter);
    assert_eq!(req4.headers.cseq().ok_or("missing CSeq")??, 5);
    assert_eq!(req4.headers.session_id(), Some("12345678"));

    let RtspEvent::Request(req5) = &c2s_events[5] else {
        return Err("expected Request 5".into());
    };
    assert_eq!(req5.method, RtspMethod::Teardown);
    assert_eq!(req5.headers.cseq().ok_or("missing CSeq")??, 6);
    assert_eq!(req5.headers.session_id(), Some("12345678"));

    // S2C: 24 events (4 responses + 18 interleaved frames + GET_PARAMETER resp + TEARDOWN resp)
    let mut s2c_parser = RtspParser::new();
    let s2c_events = s2c_parser.feed(&s2c_bytes)?;
    assert_eq!(s2c_events.len(), 24);

    let RtspEvent::Response(resp22) = &s2c_events[22] else {
        return Err("expected Response at 22".into());
    };
    assert_eq!(resp22.status_code, 200);
    assert_eq!(resp22.headers.cseq().ok_or("missing CSeq")??, 5);
    assert_eq!(resp22.headers.session_id(), Some("12345678"));

    let RtspEvent::Response(resp23) = &s2c_events[23] else {
        return Err("expected Response at 23".into());
    };
    assert_eq!(resp23.status_code, 200);
    assert_eq!(resp23.headers.cseq().ok_or("missing CSeq")??, 6);
    assert_eq!(resp23.headers.session_id(), Some("12345678"));

    println!(
        r#"CAPLOG {{"step":"test_transcript_get_parameter_keepalive_literal_expected_sequences","verdict":"pass","duration_ms":1}}"#
    );
    Ok(())
}

#[test]
fn test_incremental_feeding_all_byte_splits_and_single_byte_chunks() -> Result<(), Box<dyn Error>> {
    let valid_variants = [
        "clean.transcript",
        "auth_required.transcript",
        "interleave_split.transcript",
        "session_timeout_header.transcript",
        "rtcp_rsize.transcript",
        "sr_absent.transcript",
        "get_parameter_keepalive.transcript",
    ];

    for name in valid_variants {
        let records = load_transcript(name)?;
        let (c2s, s2c) = split_stream_records(&records);

        for (stream_name, stream) in [("C2S", &c2s), ("S2C", &s2c)] {
            if stream.is_empty() {
                continue;
            }
            let mut ref_parser = RtspParser::new();
            let ref_events = ref_parser.feed(stream)?;

            // 1. Every 2-way byte split: [..split_pos] and [split_pos..]
            for split_pos in 0..=stream.len() {
                let mut split_parser = RtspParser::new();
                let mut split_events = split_parser.feed(&stream[..split_pos])?;
                split_events.extend(split_parser.feed(&stream[split_pos..])?);
                assert_eq!(
                    split_events, ref_events,
                    "2-way byte split at {split_pos} mismatch for {name} {stream_name}"
                );
            }

            // 2. 1-byte chunks
            let mut byte_parser = RtspParser::new();
            let mut byte_events = Vec::new();
            for &b in stream.iter() {
                byte_events.extend(byte_parser.feed(&[b])?);
            }
            assert_eq!(
                byte_events, ref_events,
                "1-byte chunks mismatch for {name} {stream_name}"
            );
        }
    }

    // bad_content_length: test every 2-way split and 1-byte chunking surfaces BadContentLength
    let bcl_records = load_transcript("bad_content_length.transcript")?;
    let (_c2s, bcl_s2c) = split_stream_records(&bcl_records);

    for split_pos in 0..=bcl_s2c.len() {
        let mut split_parser = RtspParser::new();
        let mut err = None;
        match split_parser.feed(&bcl_s2c[..split_pos]) {
            Ok(_) => match split_parser.feed(&bcl_s2c[split_pos..]) {
                Ok(_) => {
                    if let Err(e) = split_parser.feed(b"") {
                        err = Some(e);
                    }
                }
                Err(e) => err = Some(e),
            },
            Err(e) => err = Some(e),
        }
        let Some(err) = err else {
            return Err(format!("split at {split_pos} failed to surface any error").into());
        };
        assert!(
            matches!(err, RtspError::BadContentLength(_)),
            "split at {split_pos} yielded unexpected error: {err:?}"
        );
    }

    let mut byte_parser = RtspParser::new();
    let mut surfaced_error = false;
    for &b in bcl_s2c.iter() {
        match byte_parser.feed(&[b]) {
            Ok(_) => {}
            Err(RtspError::BadContentLength(_)) => {
                surfaced_error = true;
                break;
            }
            Err(other) => return Err(format!("unexpected error: {other:?}").into()),
        }
    }
    if !surfaced_error {
        if let Err(RtspError::BadContentLength(_)) = byte_parser.feed(b"") {
            surfaced_error = true;
        }
    }
    assert!(
        surfaced_error,
        "1-byte chunks failed to surface BadContentLength"
    );

    println!(
        r#"CAPLOG {{"step":"test_incremental_feeding_all_byte_splits_and_single_byte_chunks","verdict":"pass","duration_ms":1}}"#
    );
    Ok(())
}

#[test]
fn test_credential_byte_scan_debug_and_error_output() -> Result<(), Box<dyn Error>> {
    const SECRET_AUTH_BEARER: &str = "supersecret_bearer_token_xyz_98765";
    const SECRET_PROXY_AUTH: &str = "supersecret_proxy_auth_token_77777";
    const SECRET_WWW_AUTH_NONCE: &str = "supersecret_nonce_abcdef_112233";
    const SECRET_USERINFO_PASS: &str = "supersecret_userinfo_pass_99999";

    // 1. Authorization header: redacted in headers and Debug output
    let wire_auth = format!(
        "OPTIONS rtsp://fixture.invalid/stream RTSP/1.0\r\n\
         CSeq: 1\r\n\
         Authorization: Bearer {SECRET_AUTH_BEARER}\r\n\r\n"
    );
    let mut parser = RtspParser::new();
    let events = parser.feed(wire_auth.as_bytes())?;
    assert_eq!(events.len(), 1);
    let debug_output = format!("{:?}", events[0]);
    assert!(
        !debug_output.contains(SECRET_AUTH_BEARER),
        "Authorization secret leaked in Debug representation"
    );
    if let RtspEvent::Request(req) = &events[0] {
        assert_eq!(req.headers.get("Authorization"), Some(REDACTED_CREDENTIAL));
    } else {
        return Err("expected Request event".into());
    }

    // 2. Proxy-Authorization header: redacted in headers and Debug output
    let wire_proxy = format!(
        "OPTIONS rtsp://fixture.invalid/stream RTSP/1.0\r\n\
         CSeq: 1\r\n\
         Proxy-Authorization: Basic {SECRET_PROXY_AUTH}\r\n\r\n"
    );
    let mut parser = RtspParser::new();
    let events = parser.feed(wire_proxy.as_bytes())?;
    assert_eq!(events.len(), 1);
    let debug_output = format!("{:?}", events[0]);
    assert!(
        !debug_output.contains(SECRET_PROXY_AUTH),
        "Proxy-Authorization secret leaked in Debug representation"
    );
    if let RtspEvent::Request(req) = &events[0] {
        assert_eq!(
            req.headers.get("Proxy-Authorization"),
            Some(REDACTED_CREDENTIAL)
        );
    } else {
        return Err("expected Request event".into());
    }

    // 3. WWW-Authenticate on 401 response: parameters discarded, only scheme emitted
    let wire_401 = format!(
        "RTSP/1.0 401 Unauthorized\r\n\
         CSeq: 1\r\n\
         WWW-Authenticate: Digest realm=\"fixture.invalid\", nonce=\"{SECRET_WWW_AUTH_NONCE}\"\r\n\r\n"
    );
    let mut parser = RtspParser::new();
    let events = parser.feed(wire_401.as_bytes())?;
    assert_eq!(events.len(), 1);
    let debug_output = format!("{:?}", events[0]);
    assert!(
        !debug_output.contains(SECRET_WWW_AUTH_NONCE),
        "WWW-Authenticate nonce secret leaked in 401 Debug representation"
    );
    let RtspEvent::AuthRequired { scheme, response } = &events[0] else {
        return Err("expected AuthRequired event".into());
    };
    assert_eq!(*scheme, AuthScheme::Digest);
    assert_eq!(response.status_code, 401);
    assert_eq!(response.headers.cseq().ok_or("missing CSeq")??, 1);

    // 4. WWW-Authenticate on 200 OK response: stripped from headers and Debug
    let wire_200 = format!(
        "RTSP/1.0 200 OK\r\n\
         CSeq: 1\r\n\
         WWW-Authenticate: Basic nonce=\"{SECRET_WWW_AUTH_NONCE}\"\r\n\r\n"
    );
    let mut parser = RtspParser::new();
    let events = parser.feed(wire_200.as_bytes())?;
    assert_eq!(events.len(), 1);
    let debug_output = format!("{:?}", events[0]);
    assert!(
        !debug_output.contains(SECRET_WWW_AUTH_NONCE),
        "WWW-Authenticate secret leaked in 200 Debug representation"
    );
    if let RtspEvent::Response(resp) = &events[0] {
        assert_eq!(resp.headers.get("WWW-Authenticate"), None);
    } else {
        return Err("expected Response event".into());
    }

    // 5. Userinfo in Request URI: rejected with UserinfoNotPermitted, error Debug does not echo credentials
    let wire_userinfo_req = format!(
        "OPTIONS rtsp://admin:{SECRET_USERINFO_PASS}@fixture.invalid/live RTSP/1.0\r\n\
         CSeq: 1\r\n\r\n"
    );
    let mut parser = RtspParser::new();
    let res = parser.feed(wire_userinfo_req.as_bytes());
    assert!(matches!(res, Err(RtspError::UserinfoNotPermitted(_))));
    let err = res.err().ok_or("expected error")?;
    let err_debug = format!("{err:?}");
    assert!(
        !err_debug.contains(SECRET_USERINFO_PASS),
        "userinfo secret leaked in error Debug output"
    );

    // 6. Userinfo in header URI: rejected with UserinfoNotPermitted, error Debug does not echo credentials
    let wire_userinfo_hdr = format!(
        "RTSP/1.0 200 OK\r\n\
         CSeq: 1\r\n\
         Content-Base: rtsp://user:{SECRET_USERINFO_PASS}@fixture.invalid/live/\r\n\r\n"
    );
    let mut parser = RtspParser::new();
    let res = parser.feed(wire_userinfo_hdr.as_bytes());
    assert!(matches!(res, Err(RtspError::UserinfoNotPermitted(_))));
    let err = res.err().ok_or("expected error")?;
    let err_debug = format!("{err:?}");
    assert!(
        !err_debug.contains(SECRET_USERINFO_PASS),
        "userinfo header secret leaked in error Debug output"
    );

    println!(
        r#"CAPLOG {{"step":"test_credential_byte_scan_debug_and_error_output","verdict":"pass","duration_ms":1}}"#
    );
    Ok(())
}

#[test]
fn test_bounded_inputs_limits_n_and_n_plus_one() -> Result<(), Box<dyn Error>> {
    // 1. Header line limit: N is Ok, N+1 returns HeaderLimit
    let limit_line = 60;
    let limits_line = RtspLimits {
        max_line_bytes: limit_line,
        ..RtspLimits::default()
    };
    // "X-Custom: " is 10 bytes; 50 'a's makes exactly 60 bytes.
    let val_n = "a".repeat(limit_line - 10);
    let wire_line_n = format!(
        "OPTIONS rtsp://fixture.invalid/stream RTSP/1.0\r\n\
         CSeq: 1\r\n\
         X-Custom: {val_n}\r\n\r\n"
    );
    let mut parser_ln = RtspParser::with_limits(limits_line);
    let events_ln = parser_ln.feed(wire_line_n.as_bytes())?;
    assert_eq!(events_ln.len(), 1);

    let val_n1 = "a".repeat(limit_line - 10 + 1);
    let wire_line_n1 = format!(
        "OPTIONS rtsp://fixture.invalid/stream RTSP/1.0\r\n\
         CSeq: 1\r\n\
         X-Custom: {val_n1}\r\n\r\n"
    );
    let mut parser_ln1 = RtspParser::with_limits(limits_line);
    let res_ln1 = parser_ln1.feed(wire_line_n1.as_bytes());
    assert!(
        matches!(res_ln1, Err(RtspError::HeaderLimit(_))),
        "line of length N+1 must return HeaderLimit"
    );

    // 2. Header count limit: N headers is Ok, N+1 headers returns HeaderLimit
    let limit_headers = 3;
    let limits_h = RtspLimits {
        max_headers: limit_headers,
        ..RtspLimits::default()
    };
    let wire_hdr_n = b"OPTIONS rtsp://fixture.invalid/stream RTSP/1.0\r\n\
                       CSeq: 1\r\n\
                       X-H1: v1\r\n\
                       X-H2: v2\r\n\r\n";
    let mut parser_hn = RtspParser::with_limits(limits_h);
    let events_hn = parser_hn.feed(wire_hdr_n)?;
    assert_eq!(events_hn.len(), 1);

    let wire_hdr_n1 = b"OPTIONS rtsp://fixture.invalid/stream RTSP/1.0\r\n\
                        CSeq: 1\r\n\
                        X-H1: v1\r\n\
                        X-H2: v2\r\n\
                        X-H3: v3\r\n\r\n";
    let mut parser_hn1 = RtspParser::with_limits(limits_h);
    let res_hn1 = parser_hn1.feed(wire_hdr_n1);
    assert!(
        matches!(res_hn1, Err(RtspError::HeaderLimit(_))),
        "header count N+1 must return HeaderLimit"
    );

    // 3. Body length limit: N bytes is Ok, N+1 bytes returns BodyLimit
    let limit_body = 25;
    let limits_b = RtspLimits {
        max_body_bytes: limit_body,
        ..RtspLimits::default()
    };
    let body_n = "b".repeat(limit_body);
    let wire_body_n = format!(
        "RTSP/1.0 200 OK\r\n\
         CSeq: 1\r\n\
         Content-Length: {limit_body}\r\n\r\n\
         {body_n}"
    );
    let mut parser_bn = RtspParser::with_limits(limits_b);
    let events_bn = parser_bn.feed(wire_body_n.as_bytes())?;
    assert_eq!(events_bn.len(), 1);

    let body_n1 = "b".repeat(limit_body + 1);
    let wire_body_n1 = format!(
        "RTSP/1.0 200 OK\r\n\
         CSeq: 1\r\n\
         Content-Length: {}\r\n\r\n\
         {}",
        limit_body + 1,
        body_n1
    );
    let mut parser_bn1 = RtspParser::with_limits(limits_b);
    let res_bn1 = parser_bn1.feed(wire_body_n1.as_bytes());
    assert!(
        matches!(res_bn1, Err(RtspError::BodyLimit(_))),
        "body length N+1 must return BodyLimit"
    );

    println!(
        r#"CAPLOG {{"step":"test_bounded_inputs_limits_n_and_n_plus_one","verdict":"pass","duration_ms":1}}"#
    );
    Ok(())
}

#[test]
fn test_mutant_kills_companion_contract_alone() -> Result<(), Box<dyn Error>> {
    // Mutant 1: CSeq check off
    let wire_m1_req = b"OPTIONS rtsp://fixture.invalid/stream RTSP/1.0\r\n\
                        User-Agent: FSS\r\n\r\n";
    let mut p1 = RtspParser::new();
    assert_eq!(
        p1.feed(wire_m1_req),
        Err(RtspError::MissingCSeq),
        "must reject request missing CSeq with MissingCSeq"
    );

    let wire_m1_resp = b"RTSP/1.0 200 OK\r\n\
                         Server: FSS\r\n\r\n";
    let mut p1_resp = RtspParser::new();
    assert_eq!(
        p1_resp.feed(wire_m1_resp),
        Err(RtspError::MissingCSeq),
        "must reject response missing CSeq with MissingCSeq"
    );

    // Mutant 2: Content-Length off by one
    // Exact slice framing: 5 bytes of body must leave exactly 0 unconsumed bytes before next request
    let wire_m2 = b"RTSP/1.0 200 OK\r\n\
                    CSeq: 1\r\n\
                    Content-Length: 5\r\n\r\n\
                    12345\
                    OPTIONS rtsp://fixture.invalid/stream RTSP/1.0\r\n\
                    CSeq: 2\r\n\r\n";
    let mut p2 = RtspParser::new();
    let events_m2 = p2.feed(wire_m2)?;
    assert_eq!(events_m2.len(), 2);
    let RtspEvent::Response(resp) = &events_m2[0] else {
        return Err("expected Response at 0".into());
    };
    assert_eq!(resp.body, b"12345");
    assert_eq!(resp.body.len(), 5);
    let RtspEvent::Request(req) = &events_m2[1] else {
        return Err("expected Request at 1".into());
    };
    assert_eq!(req.method, RtspMethod::Options);
    assert_eq!(req.headers.cseq().ok_or("missing CSeq")??, 2);
    assert_eq!(p2.buffered_bytes(), 0);

    // Mutant 3: Userinfo check off
    let wire_m3_req = b"OPTIONS rtsp://user:pass@fixture.invalid/stream RTSP/1.0\r\n\
                        CSeq: 1\r\n\r\n";
    let mut p3 = RtspParser::new();
    assert!(
        matches!(
            p3.feed(wire_m3_req),
            Err(RtspError::UserinfoNotPermitted(_))
        ),
        "must reject URI with userinfo"
    );

    let wire_m3_hdr = b"RTSP/1.0 200 OK\r\n\
                        CSeq: 1\r\n\
                        Content-Base: rtsp://user:pass@fixture.invalid/stream/\r\n\r\n";
    let mut p3_hdr = RtspParser::new();
    assert!(
        matches!(
            p3_hdr.feed(wire_m3_hdr),
            Err(RtspError::UserinfoNotPermitted(_))
        ),
        "must reject header URI with userinfo"
    );

    // Mutant 4: Pending-error-before-buffering order restored
    // Feed 1: Valid request + trailing unparseable garbage. Returns Ok([event1]), pending_error set.
    let wire_m4_chunk1 = b"OPTIONS rtsp://fixture.invalid/stream RTSP/1.0\r\n\
                           CSeq: 1\r\n\r\n\
                           GARBAGE_NO_DELIMITER\r\n\r\n";
    // Feed 2: Valid second request. Feed must append chunk2 to buffer BEFORE returning pending error.
    let wire_m4_chunk2 = b"OPTIONS rtsp://fixture.invalid/stream RTSP/1.0\r\n\
                           CSeq: 2\r\n\r\n";
    let mut p4 = RtspParser::new();
    let events1 = p4.feed(wire_m4_chunk1)?;
    assert_eq!(events1.len(), 1);
    let res2 = p4.feed(wire_m4_chunk2);
    assert!(matches!(res2, Err(RtspError::MalformedStartLine(_))));
    // Feed 3: Empty chunk. If chunk2 was properly buffered in Feed 2, it is parsed now!
    let events3 = p4.feed(b"")?;
    assert_eq!(
        events3.len(),
        1,
        "buffered chunk2 must not be dropped when surfacing pending error"
    );
    let RtspEvent::Request(req2) = &events3[0] else {
        return Err("expected Request from buffered chunk2".into());
    };
    assert_eq!(req2.headers.cseq().ok_or("missing CSeq")??, 2);

    // Mutant 5: Line folding accepted
    let wire_m5 = b"OPTIONS rtsp://fixture.invalid/stream RTSP/1.0\r\n\
                    CSeq: 1\r\n \
                    Folded-Header: val\r\n\r\n";
    let mut p5 = RtspParser::new();
    assert_eq!(
        p5.feed(wire_m5),
        Err(RtspError::LineFoldingNotPermitted),
        "must reject line folding with LineFoldingNotPermitted"
    );

    println!(
        r#"CAPLOG {{"step":"test_mutant_kills_companion_contract_alone","verdict":"pass","duration_ms":1}}"#
    );
    Ok(())
}

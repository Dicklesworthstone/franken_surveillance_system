#![forbid(unsafe_code)]
//! Contract tests for sans-IO RTSP/1.0 message parser and SDP parser (fss-2h5zq.32).

use std::error::Error;

use fss_reference::rtsp::{
    DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_HEADERS, DEFAULT_MAX_INTERLEAVED_BYTES,
    DEFAULT_MAX_LINE_BYTES, MAX_SDP_LINE_BYTES, REDACTED_CREDENTIAL, RtspError, RtspEvent,
    RtspHeaders, RtspLimits, RtspMethod, RtspParser, SdpError, decode_base64, parse_sdp,
};

#[test]
fn test_rtsp_limits_and_constants() {
    let limits = RtspLimits::default();
    assert_eq!(limits.max_line_bytes, DEFAULT_MAX_LINE_BYTES);
    assert_eq!(limits.max_headers, DEFAULT_MAX_HEADERS);
    assert_eq!(limits.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
    assert_eq!(limits.max_interleaved_bytes, DEFAULT_MAX_INTERLEAVED_BYTES);
}

#[test]
fn test_rtsp_request_options() -> Result<(), Box<dyn Error>> {
    let mut parser = RtspParser::new();
    let wire = b"OPTIONS rtsp://127.0.0.1:8554/live RTSP/1.0\r\n\
                 CSeq: 1\r\n\
                 User-Agent: FSS-Reference\r\n\r\n";

    let events = parser.feed(wire)?;
    assert_eq!(events.len(), 1);

    let RtspEvent::Request(req) = &events[0] else {
        return Err(format!("expected Request event, got {:?}", events[0]).into());
    };
    assert_eq!(req.method, RtspMethod::Options);
    assert_eq!(req.method.as_str(), "OPTIONS");
    assert_eq!(req.uri, "rtsp://127.0.0.1:8554/live");
    assert_eq!(req.version, "RTSP/1.0");
    assert_eq!(req.headers.cseq().ok_or("CSeq missing")??, 1);
    assert_eq!(req.headers.get("User-Agent"), Some("FSS-Reference"));
    assert!(req.body.is_empty());
    Ok(())
}

#[test]
fn test_rtsp_response_options() -> Result<(), Box<dyn Error>> {
    let mut parser = RtspParser::new();
    let wire = b"RTSP/1.0 200 OK\r\n\
                 CSeq: 1\r\n\
                 Public: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN, GET_PARAMETER\r\n\r\n";

    let events = parser.feed(wire)?;
    assert_eq!(events.len(), 1);

    let RtspEvent::Response(resp) = &events[0] else {
        return Err(format!("expected Response event, got {:?}", events[0]).into());
    };
    assert_eq!(resp.version, "RTSP/1.0");
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.reason, "OK");
    assert_eq!(resp.headers.cseq().ok_or("CSeq missing")??, 1);
    assert_eq!(
        resp.headers.public(),
        Some("OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN, GET_PARAMETER")
    );
    assert!(resp.body.is_empty());
    Ok(())
}

#[test]
fn test_rtsp_request_describe() -> Result<(), Box<dyn Error>> {
    let mut parser = RtspParser::new();
    let wire = b"DESCRIBE rtsp://127.0.0.1:8554/live RTSP/1.0\r\n\
                 CSeq: 2\r\n\
                 Accept: application/sdp\r\n\r\n";

    let events = parser.feed(wire)?;
    assert_eq!(events.len(), 1);

    let RtspEvent::Request(req) = &events[0] else {
        return Err(format!("expected Request event, got {:?}", events[0]).into());
    };
    assert_eq!(req.method, RtspMethod::Describe);
    assert_eq!(req.headers.cseq().ok_or("CSeq missing")??, 2);
    assert_eq!(req.headers.get("Accept"), Some("application/sdp"));
    Ok(())
}

#[test]
fn test_rtsp_response_describe_with_sdp_body() -> Result<(), Box<dyn Error>> {
    let mut parser = RtspParser::new();
    let sdp_body = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=Test\r\nm=video 0 RTP/AVP 96\r\n";
    let wire = format!(
        "RTSP/1.0 200 OK\r\n\
         CSeq: 2\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n{}",
        sdp_body.len(),
        sdp_body
    );

    let events = parser.feed(wire.as_bytes())?;
    assert_eq!(events.len(), 1);

    let RtspEvent::Response(resp) = &events[0] else {
        return Err(format!("expected Response event, got {:?}", events[0]).into());
    };
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.headers.content_type(), Some("application/sdp"));
    assert_eq!(
        resp.headers.content_length().ok_or("len missing")??,
        sdp_body.len()
    );
    assert_eq!(resp.body, sdp_body.as_bytes());
    Ok(())
}

#[test]
fn test_rtsp_request_setup() -> Result<(), Box<dyn Error>> {
    let mut parser = RtspParser::new();
    let wire = b"SETUP rtsp://127.0.0.1:8554/live/trackID=0 RTSP/1.0\r\n\
                 CSeq: 3\r\n\
                 Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n";

    let events = parser.feed(wire)?;
    assert_eq!(events.len(), 1);

    let RtspEvent::Request(req) = &events[0] else {
        return Err(format!("expected Request event, got {:?}", events[0]).into());
    };
    assert_eq!(req.method, RtspMethod::Setup);
    let transport = req.headers.transport().ok_or("Transport missing")??;
    assert_eq!(transport.profile, "RTP/AVP/TCP");
    assert!(transport.unicast);
    assert_eq!(transport.interleaved, Some((0, 1)));
    assert_eq!(transport.client_port, None);
    Ok(())
}

#[test]
fn test_rtsp_response_setup() -> Result<(), Box<dyn Error>> {
    let mut parser = RtspParser::new();
    let wire = b"RTSP/1.0 200 OK\r\n\
                 CSeq: 3\r\n\
                 Session: 47112344;timeout=60\r\n\
                 Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n";

    let events = parser.feed(wire)?;
    assert_eq!(events.len(), 1);

    let RtspEvent::Response(resp) = &events[0] else {
        return Err(format!("expected Response event, got {:?}", events[0]).into());
    };
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.headers.session_id(), Some("47112344"));
    assert_eq!(resp.headers.session_timeout(), Some(60));
    let transport = resp.headers.transport().ok_or("Transport missing")??;
    assert_eq!(transport.profile, "RTP/AVP/TCP");
    assert!(transport.unicast);
    assert_eq!(transport.interleaved, Some((0, 1)));
    Ok(())
}

#[test]
fn test_rtsp_request_and_response_play() -> Result<(), Box<dyn Error>> {
    let mut parser = RtspParser::new();
    let req_wire = b"PLAY rtsp://127.0.0.1:8554/live RTSP/1.0\r\n\
                     CSeq: 4\r\n\
                     Session: 47112344\r\n\
                     Range: npt=0.000-\r\n\r\n";

    let events = parser.feed(req_wire)?;
    assert_eq!(events.len(), 1);
    let RtspEvent::Request(req) = &events[0] else {
        return Err(format!("expected Request event, got {:?}", events[0]).into());
    };
    assert_eq!(req.method, RtspMethod::Play);
    assert_eq!(req.headers.range(), Some("npt=0.000-"));
    assert_eq!(req.headers.session_id(), Some("47112344"));

    let resp_wire = b"RTSP/1.0 200 OK\r\n\
                      CSeq: 4\r\n\
                      Session: 47112344\r\n\
                      Range: npt=0.000-\r\n\
                      RTP-Info: url=rtsp://127.0.0.1:8554/live/trackID=0;seq=100;rtptime=900000\r\n\r\n";

    let events = parser.feed(resp_wire)?;
    assert_eq!(events.len(), 1);
    let RtspEvent::Response(resp) = &events[0] else {
        return Err(format!("expected Response event, got {:?}", events[0]).into());
    };
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.headers.range(), Some("npt=0.000-"));
    assert_eq!(
        resp.headers.rtp_info(),
        Some("url=rtsp://127.0.0.1:8554/live/trackID=0;seq=100;rtptime=900000")
    );
    Ok(())
}

#[test]
fn test_rtsp_request_and_response_pause() -> Result<(), Box<dyn Error>> {
    let mut parser = RtspParser::new();
    let req_wire = b"PAUSE rtsp://127.0.0.1:8554/live RTSP/1.0\r\n\
                     CSeq: 5\r\n\
                     Session: 47112344\r\n\r\n";

    let events = parser.feed(req_wire)?;
    assert_eq!(events.len(), 1);
    let RtspEvent::Request(req) = &events[0] else {
        return Err(format!("expected Request event, got {:?}", events[0]).into());
    };
    assert_eq!(req.method, RtspMethod::Pause);
    assert_eq!(req.headers.session_id(), Some("47112344"));

    let resp_wire = b"RTSP/1.0 200 OK\r\n\
                      CSeq: 5\r\n\
                      Session: 47112344\r\n\r\n";
    let events = parser.feed(resp_wire)?;
    assert_eq!(events.len(), 1);
    let RtspEvent::Response(resp) = &events[0] else {
        return Err(format!("expected Response event, got {:?}", events[0]).into());
    };
    assert_eq!(resp.version, "RTSP/1.0");
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.reason, "OK");
    assert_eq!(resp.headers.cseq().ok_or("CSeq missing")??, 5);
    assert_eq!(resp.headers.session_id(), Some("47112344"));
    assert!(resp.body.is_empty());
    Ok(())
}

#[test]
fn test_rtsp_request_and_response_teardown() -> Result<(), Box<dyn Error>> {
    let mut parser = RtspParser::new();
    let req_wire = b"TEARDOWN rtsp://127.0.0.1:8554/live RTSP/1.0\r\n\
                     CSeq: 6\r\n\
                     Session: 47112344\r\n\r\n";

    let events = parser.feed(req_wire)?;
    assert_eq!(events.len(), 1);
    let RtspEvent::Request(req) = &events[0] else {
        return Err(format!("expected Request event, got {:?}", events[0]).into());
    };
    assert_eq!(req.method, RtspMethod::Teardown);
    assert_eq!(req.headers.session_id(), Some("47112344"));

    let resp_wire = b"RTSP/1.0 200 OK\r\n\
                      CSeq: 6\r\n\
                      Session: 47112344\r\n\r\n";
    let events = parser.feed(resp_wire)?;
    assert_eq!(events.len(), 1);
    let RtspEvent::Response(resp) = &events[0] else {
        return Err(format!("expected Response event, got {:?}", events[0]).into());
    };
    assert_eq!(resp.version, "RTSP/1.0");
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.reason, "OK");
    assert_eq!(resp.headers.cseq().ok_or("CSeq missing")??, 6);
    assert_eq!(resp.headers.session_id(), Some("47112344"));
    assert!(resp.body.is_empty());
    Ok(())
}

#[test]
fn test_rtsp_request_and_response_get_parameter_keepalive() -> Result<(), Box<dyn Error>> {
    let mut parser = RtspParser::new();
    let req_wire = b"GET_PARAMETER rtsp://127.0.0.1:8554/live RTSP/1.0\r\n\
                     CSeq: 7\r\n\
                     Session: 47112344\r\n\r\n";

    let events = parser.feed(req_wire)?;
    assert_eq!(events.len(), 1);
    let RtspEvent::Request(req) = &events[0] else {
        return Err(format!("expected Request event, got {:?}", events[0]).into());
    };
    assert_eq!(req.method, RtspMethod::GetParameter);
    assert_eq!(req.headers.session_id(), Some("47112344"));

    let resp_wire = b"RTSP/1.0 200 OK\r\n\
                      CSeq: 7\r\n\
                      Session: 47112344\r\n\r\n";
    let events = parser.feed(resp_wire)?;
    assert_eq!(events.len(), 1);
    let RtspEvent::Response(resp) = &events[0] else {
        return Err(format!("expected Response event, got {:?}", events[0]).into());
    };
    assert_eq!(resp.version, "RTSP/1.0");
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.reason, "OK");
    assert_eq!(resp.headers.cseq().ok_or("CSeq missing")??, 7);
    assert_eq!(resp.headers.session_id(), Some("47112344"));
    assert!(resp.body.is_empty());
    Ok(())
}

#[test]
fn test_rtsp_unsupported_methods_typed_refusals() {
    let mut parser = RtspParser::new();

    for method in ["ANNOUNCE", "RECORD", "REDIRECT", "SET_PARAMETER"] {
        let wire = format!("{method} rtsp://127.0.0.1:8554/live RTSP/1.0\r\nCSeq: 8\r\n\r\n");
        let result = parser.feed(wire.as_bytes());
        assert_eq!(
            result,
            Err(RtspError::Unsupported {
                method: method.to_string()
            }),
            "method {method} should yield typed Unsupported refusal"
        );
    }
}

#[test]
fn test_rtsp_auth_required_401_digest() -> Result<(), Box<dyn Error>> {
    let mut parser = RtspParser::new();
    let wire = b"RTSP/1.0 401 Unauthorized\r\n\
                 CSeq: 1\r\n\
                 WWW-Authenticate: Digest realm=\"AXIS_00408C\", nonce=\"0001abcd\", stale=\"FALSE\"\r\n\r\n";

    let events = parser.feed(wire)?;
    assert_eq!(events.len(), 1);

    let RtspEvent::AuthRequired { scheme } = &events[0] else {
        return Err(format!("expected AuthRequired event, got {:?}", events[0]).into());
    };
    assert_eq!(scheme, "Digest");
    // Challenge parameters (realm, nonce, etc.) are NOT stored.
    Ok(())
}

#[test]
fn test_rtsp_auth_required_401_basic() -> Result<(), Box<dyn Error>> {
    let mut parser = RtspParser::new();
    let wire = b"RTSP/1.0 401 Unauthorized\r\n\
                 CSeq: 2\r\n\
                 WWW-Authenticate: Basic realm=\"camera_access\"\r\n\r\n";

    let events = parser.feed(wire)?;
    assert_eq!(events.len(), 1);

    let RtspEvent::AuthRequired { scheme } = &events[0] else {
        return Err(format!("expected AuthRequired event, got {:?}", events[0]).into());
    };
    assert_eq!(scheme, "Basic");
    Ok(())
}

#[test]
fn test_interleaved_frame_single_feed() -> Result<(), Box<dyn Error>> {
    let mut parser = RtspParser::new();
    // Interleaved frame: '$' (0x24), channel 0, len 6, payload [10, 20, 30, 40, 50, 60]
    let wire = [b'$', 0x00, 0x00, 0x06, 10, 20, 30, 40, 50, 60];

    let events = parser.feed(&wire)?;
    assert_eq!(events.len(), 1);

    let RtspEvent::Interleaved { channel, span } = &events[0] else {
        return Err(format!("expected Interleaved event, got {:?}", events[0]).into());
    };
    assert_eq!(*channel, 0);
    assert_eq!(span, &[10, 20, 30, 40, 50, 60]);
    Ok(())
}

#[test]
fn test_interleaved_frame_split_across_feeds() -> Result<(), Box<dyn Error>> {
    let mut parser = RtspParser::new();
    // Interleaved frame: '$', channel 1, len 8, payload [1, 2, 3, 4, 5, 6, 7, 8]
    let chunk1 = [b'$', 0x01, 0x00]; // incomplete header
    let chunk2 = [0x08, 1, 2, 3]; // header completed, partial payload
    let chunk3 = [4, 5]; // partial payload
    let chunk4 = [6, 7, 8]; // payload completed

    let e1 = parser.feed(&chunk1)?;
    assert!(e1.is_empty(), "incomplete frame produces no events");

    let e2 = parser.feed(&chunk2)?;
    assert!(e2.is_empty(), "incomplete frame produces no events");

    let e3 = parser.feed(&chunk3)?;
    assert!(e3.is_empty(), "incomplete frame produces no events");

    let e4 = parser.feed(&chunk4)?;
    assert_eq!(e4.len(), 1);

    let RtspEvent::Interleaved { channel, span } = &e4[0] else {
        return Err(format!("expected Interleaved event, got {:?}", e4[0]).into());
    };
    assert_eq!(*channel, 1);
    assert_eq!(span, &[1, 2, 3, 4, 5, 6, 7, 8]);
    Ok(())
}

#[test]
fn test_incremental_split_at_every_byte() -> Result<(), Box<dyn Error>> {
    let mut parser = RtspParser::new();
    let wire = b"RTSP/1.0 200 OK\r\nCSeq: 9\r\nContent-Length: 4\r\n\r\nTEST";

    let mut all_events = Vec::new();
    for &byte in wire {
        let events = parser.feed(&[byte])?;
        all_events.extend(events);
    }

    assert_eq!(all_events.len(), 1);
    let RtspEvent::Response(resp) = &all_events[0] else {
        return Err(format!("expected Response, got {:?}", all_events[0]).into());
    };
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.body, b"TEST");
    Ok(())
}

#[test]
fn test_bad_content_length_errors() {
    let mut parser1 = RtspParser::new();
    let wire_neg = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: -5\r\n\r\n";
    assert!(matches!(
        parser1.feed(wire_neg),
        Err(RtspError::BadContentLength(_))
    ));

    let mut parser2 = RtspParser::new();
    let wire_alpha = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: abc\r\n\r\n";
    assert!(matches!(
        parser2.feed(wire_alpha),
        Err(RtspError::BadContentLength(_))
    ));
}

#[test]
fn test_bad_interleaved_length_limit() {
    let limits = RtspLimits {
        max_interleaved_bytes: 100,
        ..RtspLimits::default()
    };
    let mut parser = RtspParser::with_limits(limits);

    // Frame with length 200 > limit 100
    let wire = [b'$', 0x00, 0x00, 0xC8, 0x00, 0x00];
    assert!(matches!(
        parser.feed(&wire),
        Err(RtspError::BadInterleavedLength(_))
    ));
}

#[test]
fn test_body_limit_exceeded() {
    let limits = RtspLimits {
        max_body_bytes: 50,
        ..RtspLimits::default()
    };
    let mut parser = RtspParser::with_limits(limits);

    let wire = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 100\r\n\r\n";
    assert!(matches!(parser.feed(wire), Err(RtspError::BodyLimit(_))));
}

#[test]
fn test_header_count_limit_exceeded() {
    let limits = RtspLimits {
        max_headers: 3,
        ..RtspLimits::default()
    };
    let mut parser = RtspParser::with_limits(limits);

    let wire = b"RTSP/1.0 200 OK\r\n\
                 H1: 1\r\n\
                 H2: 2\r\n\
                 H3: 3\r\n\
                 H4: 4\r\n\r\n";
    assert!(matches!(parser.feed(wire), Err(RtspError::HeaderLimit(_))));
}

#[test]
fn test_header_line_length_limit_exceeded() {
    let limits = RtspLimits {
        max_line_bytes: 30,
        ..RtspLimits::default()
    };
    let mut parser = RtspParser::with_limits(limits);

    let wire = b"RTSP/1.0 200 OK\r\n\
                 Super-Long-Header-Name-That-Exceeds-Limits: value\r\n\r\n";
    assert!(matches!(parser.feed(wire), Err(RtspError::HeaderLimit(_))));
}

#[test]
fn test_bad_transport_parsing() {
    let mut headers = RtspHeaders::new();
    headers.insert("Transport", "RTP/AVP/TCP;unicast;interleaved=bad-channel");
    assert!(matches!(
        headers.transport(),
        Some(Err(RtspError::BadTransport(_)))
    ));

    let mut headers2 = RtspHeaders::new();
    headers2.insert("Transport", "RTP/AVP;client_port=notaport-5001");
    assert!(matches!(
        headers2.transport(),
        Some(Err(RtspError::BadTransport(_)))
    ));
}

#[test]
fn test_first_party_base64_decoder() -> Result<(), Box<dyn Error>> {
    // Standard test vectors
    assert_eq!(decode_base64("")?, Vec::<u8>::new());
    assert_eq!(decode_base64("Zg==")?, b"f");
    assert_eq!(decode_base64("Zm8=")?, b"fo");
    assert_eq!(decode_base64("Zm9v")?, b"foo");
    assert_eq!(decode_base64("Zm9vYg==")?, b"foob");
    assert_eq!(decode_base64("Zm9vYmE=")?, b"fooba");
    assert_eq!(decode_base64("Zm9vYmFy")?, b"foobar");

    // Real H.264 SPS & PPS parameter sets
    let sps_b64 = "Z0LgH9oBQBbsBEAAAAMAQAAAwDw8WLg=";
    let pps_b64 = "aM48gA==";
    let sps = decode_base64(sps_b64)?;
    let pps = decode_base64(pps_b64)?;

    // Check expected NAL unit header types:
    // SPS nal_unit_type = 7 (first byte & 0x1F = 7; 103 & 0x1F = 7)
    assert_eq!(sps[0] & 0x1F, 7);
    // PPS nal_unit_type = 8 (first byte & 0x1F = 8; 104 & 0x1F = 8)
    assert_eq!(pps[0] & 0x1F, 8);

    // Errors
    assert!(matches!(
        decode_base64("bad_len"),
        Err(SdpError::BadBase64(_))
    ));
    assert!(matches!(
        decode_base64("Zg==extra"),
        Err(SdpError::BadBase64(_))
    ));
    assert!(matches!(decode_base64("===="), Err(SdpError::BadBase64(_))));
    assert!(matches!(decode_base64("Z!o="), Err(SdpError::BadBase64(_))));
    // Non-zero padding bits
    assert!(matches!(decode_base64("Zh=="), Err(SdpError::BadBase64(_))));
    Ok(())
}

#[test]
fn test_hand_built_sdp_with_h264_and_rtcp_rsize() -> Result<(), Box<dyn Error>> {
    let sdp_text = "v=0\r\n\
                    o=- 1609459200 1609459200 IN IP4 127.0.0.1\r\n\
                    s=H.264 Video Stream\r\n\
                    c=IN IP4 0.0.0.0\r\n\
                    t=0 0\r\n\
                    a=control:*\r\n\
                    m=video 0 RTP/AVP 96\r\n\
                    a=rtpmap:96 H264/90000\r\n\
                    a=fmtp:96 packetization-mode=1;profile-level-id=42e01f;sprop-parameter-sets=Z0LgH9oBQBbsBEAAAAMAQAAAwDw8WLg=,aM48gA==\r\n\
                    a=control:trackID=0\r\n\
                    a=rtcp-rsize\r\n\
                    m=audio 0 RTP/AVP 97\r\n\
                    a=rtpmap:97 PCMU/8000\r\n\
                    a=control:trackID=1\r\n";

    let session = parse_sdp(sdp_text)?;
    assert_eq!(session.version, 0);
    assert_eq!(session.session_name, "H.264 Video Stream");
    assert_eq!(session.session_control, Some("*".to_string()));

    // Video media assertions
    let video = session
        .video()
        .ok_or("video media section must be present")?;
    assert_eq!(video.media_type, "video");
    assert_eq!(video.port, 0);
    assert_eq!(video.proto, "RTP/AVP");
    assert_eq!(video.payload_type, 96);
    assert_eq!(video.encoding_name.as_deref(), Some("H264"));
    assert_eq!(video.clock_rate, Some(90000));
    assert_eq!(video.packetization_mode, Some(1));
    assert_eq!(video.profile_level_id, Some("42e01f".to_string()));
    assert_eq!(video.control, Some("trackID=0".to_string()));

    // Reduced-size RTCP signaled via a=rtcp-rsize
    assert!(video.rtcp_reduced_size);

    // SPS / PPS parameter sets decoded from base64
    let sps = video.sps.as_ref().ok_or("SPS must be present")?;
    let pps = video.pps.as_ref().ok_or("PPS must be present")?;
    assert_eq!(sps[0] & 0x1F, 7); // NAL type 7 (SPS)
    assert_eq!(pps[0] & 0x1F, 8); // NAL type 8 (PPS)
    assert_eq!(video.sprop_parameter_sets.len(), 2);

    // Audio media recorded and ignored per GOAL-009 privacy rules
    assert_eq!(session.audio().len(), 1);
    assert_eq!(session.audio()[0].media_type, "audio");
    assert_eq!(session.audio()[0].payload_type, 97);
    assert_eq!(session.audio()[0].encoding_name.as_deref(), Some("PCMU"));
    assert_eq!(session.audio()[0].clock_rate, Some(8000));
    Ok(())
}

#[test]
fn test_sdp_without_rtcp_rsize_yields_false() -> Result<(), Box<dyn Error>> {
    let sdp_text = "v=0\r\n\
                    o=- 1234 1234 IN IP4 127.0.0.1\r\n\
                    s=Test Stream\r\n\
                    m=video 0 RTP/AVP 96\r\n\
                    a=rtpmap:96 H264/90000\r\n\
                    a=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0LgH9oBQBbsBEAAAAMAQAAAwDw8WLg=,aM48gA==\r\n";

    let session = parse_sdp(sdp_text)?;
    let video = session.video().ok_or("video section")?;
    assert!(
        !video.rtcp_reduced_size,
        "without a=rtcp-rsize, rtcp_reduced_size must be false"
    );
    Ok(())
}

#[test]
fn test_sdp_malformed_errors() {
    // Missing v=0
    assert_eq!(
        parse_sdp("s=Test\r\no=- 0 0 IN IP4 127.0.0.1\r\nm=video 0 RTP/AVP 96\r\n"),
        Err(SdpError::MissingVersion)
    );

    // Missing o=
    assert_eq!(
        parse_sdp("v=0\r\ns=Test\r\nm=video 0 RTP/AVP 96\r\n"),
        Err(SdpError::MissingOrigin)
    );

    // Missing s=
    assert_eq!(
        parse_sdp("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\nm=video 0 RTP/AVP 96\r\n"),
        Err(SdpError::MissingSessionName)
    );

    // Missing m=
    assert_eq!(
        parse_sdp("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=Test\r\n"),
        Err(SdpError::MissingMedia)
    );
}

fn scan_file_for_forbidden(path: &std::path::Path) -> Result<(), Box<dyn Error>> {
    let content = std::fs::read_to_string(path)?;
    assert!(
        !content.contains("Authorization:"),
        "source file {path:?} must not contain 'Authorization:' builder code"
    );
    assert!(
        !content.contains("Authorization"),
        "source file {path:?} must not handle Authorization headers"
    );
    Ok(())
}

fn scan_dir_recursive(dir: &std::path::Path) -> Result<(), Box<dyn Error>> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            scan_dir_recursive(&path)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            scan_file_for_forbidden(&path)?;
        }
    }
    Ok(())
}

#[test]
fn test_no_authorization_header_builder_in_crate_source() -> Result<(), Box<dyn Error>> {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let rtsp_rs = manifest_dir.join("src").join("rtsp.rs");
    if rtsp_rs.exists() {
        scan_file_for_forbidden(&rtsp_rs)?;
    }
    let rtsp_dir = manifest_dir.join("src").join("rtsp");
    scan_dir_recursive(&rtsp_dir)?;
    Ok(())
}

#[test]
fn test_bare_lf_with_body_kills_mutant_2() -> Result<(), Box<dyn Error>> {
    let mut parser = RtspParser::new();
    let wire = b"RTSP/1.0 200 OK\nCSeq: 1\nContent-Length: 4\n\nBODY";
    let events = parser.feed(wire)?;
    assert_eq!(events.len(), 1);
    let RtspEvent::Response(resp) = &events[0] else {
        return Err(format!("expected Response, got {:?}", events[0]).into());
    };
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.headers.cseq().ok_or("missing CSeq")??, 1);
    assert_eq!(resp.body, b"BODY");
    assert_eq!(parser.buffered_bytes(), 0);
    Ok(())
}

#[test]
fn test_bad_cseq_string_kills_mutant_4() {
    let mut parser = RtspParser::new();
    let wire = b"RTSP/1.0 200 OK\r\nCSeq: abc\r\n\r\n";
    let res = parser.feed(wire);
    assert!(matches!(res, Err(RtspError::BadCSeq(_))));

    let mut headers = RtspHeaders::new();
    headers.insert("CSeq", "abc");
    assert!(matches!(headers.cseq(), Some(Err(RtspError::BadCSeq(_)))));
}

#[test]
fn test_audio_rtcp_rsize_isolated_kills_mutant_7() -> Result<(), Box<dyn Error>> {
    let sdp_text = "v=0\r\n\
                    o=- 1 1 IN IP4 127.0.0.1\r\ns=Test\r\nt=0 0\r\n\
                    m=video 0 RTP/AVP 96\r\n\
                    a=rtpmap:96 H264/90000\r\n\
                    a=rtcp-rsize\r\n\
                    m=audio 0 RTP/AVP 0\r\n";
    let session = parse_sdp(sdp_text)?;
    assert_eq!(session.media.len(), 2);
    let video = session.video().ok_or("missing video")?;
    assert!(video.rtcp_reduced_size, "video must have rtcp-rsize");
    let audio = &session.audio()[0];
    assert!(
        !audio.rtcp_reduced_size,
        "audio must NOT have rtcp-rsize when only video declared it"
    );
    Ok(())
}

#[test]
fn test_credentials_redacted_p19a() -> Result<(), Box<dyn Error>> {
    let wire = b"DESCRIBE rtsp://127.0.0.1/x RTSP/1.0\r\n\
                 CSeq: 2\r\n\
                 Authorization: Basic dXNlcjpwYXNz\r\n\
                 Proxy-Authorization: Digest username=\"admin\"\r\n\r\n";
    let mut parser = RtspParser::new();
    let events = parser.feed(wire)?;
    assert_eq!(events.len(), 1);
    let RtspEvent::Request(req) = &events[0] else {
        return Err(format!("expected Request, got {:?}", events[0]).into());
    };
    assert_eq!(req.headers.get("authorization"), Some(REDACTED_CREDENTIAL));
    assert_eq!(
        req.headers.get("proxy-authorization"),
        Some(REDACTED_CREDENTIAL)
    );
    let dbg = format!("{:?}", req.headers);
    assert!(!dbg.contains("dXNlcjpwYXNz"));
    assert!(!dbg.contains("admin"));
    Ok(())
}

#[test]
fn test_userinfo_in_uri_refused_p19b() {
    let wire = b"DESCRIBE rtsp://user:secretpw@127.0.0.1/x RTSP/1.0\r\nCSeq: 2\r\n\r\n";
    let mut parser = RtspParser::new();
    let res = parser.feed(wire);
    assert!(matches!(res, Err(RtspError::UserinfoNotPermitted(_))));
}

#[test]
fn test_auth_challenge_variants_p20a_p20b() -> Result<(), Box<dyn Error>> {
    // 407 Proxy-Authenticate
    let wire_407 = b"RTSP/1.0 407 Proxy Authentication Required\r\n\
                     CSeq: 1\r\n\
                     Proxy-Authenticate: Digest realm=\"r\", nonce=\"n0nce\"\r\n\r\n";
    let mut parser = RtspParser::new();
    let events = parser.feed(wire_407)?;
    assert_eq!(events.len(), 1);
    assert!(matches!(&events[0], RtspEvent::AuthRequired { scheme } if scheme == "Digest"));
    let dbg = format!("{events:?}");
    assert!(!dbg.contains("n0nce"));
    assert!(!dbg.contains("realm"));

    // 200 with WWW-Authenticate
    let wire_200 = b"RTSP/1.0 200 OK\r\n\
                     CSeq: 1\r\n\
                     WWW-Authenticate: Basic realm=\"secret\"\r\n\r\n";
    let mut parser2 = RtspParser::new();
    let events2 = parser2.feed(wire_200)?;
    assert_eq!(events2.len(), 1);
    assert!(matches!(&events2[0], RtspEvent::AuthRequired { scheme } if scheme == "Basic"));
    let dbg2 = format!("{events2:?}");
    assert!(!dbg2.contains("secret"));
    Ok(())
}

#[test]
fn test_schemeless_auth_challenge_p20d() -> Result<(), Box<dyn Error>> {
    let wire = b"RTSP/1.0 401 Unauthorized\r\n\
                 CSeq: 1\r\n\
                 WWW-Authenticate: nonce=\"s3cretnonce\"\r\n\r\n";
    let mut parser = RtspParser::new();
    let events = parser.feed(wire)?;
    assert_eq!(events.len(), 1);
    let RtspEvent::Response(resp) = &events[0] else {
        return Err(format!("expected Response, got {:?}", events[0]).into());
    };
    assert_eq!(resp.status_code, 401);
    assert_eq!(resp.headers.get("www-authenticate"), None);
    let dbg = format!("{events:?}");
    assert!(!dbg.contains("s3cretnonce"));
    Ok(())
}

#[test]
fn test_events_preserved_before_error_and_error_not_sticky_p14_p15() -> Result<(), Box<dyn Error>> {
    let mut parser = RtspParser::new();
    let wire = b"OPTIONS rtsp://127.0.0.1/live RTSP/1.0\r\nCSeq: 1\r\n\r\n\
                 ANNOUNCE rtsp://127.0.0.1/live RTSP/1.0\r\nCSeq: 2\r\n\r\n";
    let events = parser.feed(wire)?;
    assert_eq!(events.len(), 1);
    assert!(matches!(&events[0], RtspEvent::Request(r) if r.method == RtspMethod::Options));

    let res = parser.feed(b"");
    assert!(matches!(res, Err(RtspError::Unsupported { .. })));

    let wire_valid = b"RTSP/1.0 200 OK\r\nCSeq: 3\r\n\r\n";
    let events2 = parser.feed(wire_valid)?;
    assert_eq!(events2.len(), 1);
    assert!(matches!(&events2[0], RtspEvent::Response(r) if r.status_code == 200));
    Ok(())
}

#[test]
fn test_missing_cseq_refused() {
    let mut parser = RtspParser::new();
    let wire = b"RTSP/1.0 200 OK\r\n\r\n";
    assert!(matches!(parser.feed(wire), Err(RtspError::MissingCSeq)));
}

#[test]
fn test_duplicate_cseq_refused() {
    let mut parser = RtspParser::new();
    let wire = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nCSeq: 2\r\n\r\n";
    assert!(matches!(
        parser.feed(wire),
        Err(RtspError::DuplicateCSeq(_))
    ));
}

#[test]
fn test_duplicate_content_length_refused() {
    let mut parser = RtspParser::new();
    let wire = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 4\r\nContent-Length: 0\r\n\r\n";
    assert!(matches!(
        parser.feed(wire),
        Err(RtspError::DuplicateContentLength(_))
    ));
}

#[test]
fn test_line_folding_does_not_inject_headers() -> Result<(), Box<dyn Error>> {
    let wire = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nX-Custom: part1\r\n Injected: value\r\n\r\n";
    let mut parser = RtspParser::new();
    let events = parser.feed(wire)?;
    assert_eq!(events.len(), 1);
    let RtspEvent::Response(resp) = &events[0] else {
        return Err(format!("expected Response, got {:?}", events[0]).into());
    };
    assert_eq!(resp.headers.get("Injected"), None);
    assert_eq!(resp.headers.get("X-Custom"), Some("part1 Injected: value"));
    Ok(())
}

#[test]
fn test_unsupported_version_refused() {
    let mut parser = RtspParser::new();
    let wire = b"RTSP/2.0 200 OK\r\nCSeq: 1\r\n\r\n";
    assert!(matches!(
        parser.feed(wire),
        Err(RtspError::UnsupportedVersion(_))
    ));

    let mut parser2 = RtspParser::new();
    let wire2 = b"OPTIONS * RTSP/2.0\r\nCSeq: 1\r\n\r\n";
    assert!(matches!(
        parser2.feed(wire2),
        Err(RtspError::UnsupportedVersion(_))
    ));
}

#[test]
fn test_nul_byte_refused() {
    let mut p1 = RtspParser::new();
    assert!(matches!(
        p1.feed(b"OPTIONS rtsp://h\x00/x RTSP/1.0\r\nCSeq: 1\r\n\r\n"),
        Err(RtspError::NulByte(_))
    ));

    let mut p2 = RtspParser::new();
    assert!(matches!(
        p2.feed(b"RTSP/1.0 200 OK\r\nCS\x00eq: 1\r\n\r\n"),
        Err(RtspError::NulByte(_))
    ));

    let mut p3 = RtspParser::new();
    assert!(matches!(
        p3.feed(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nX-Val: a\x00b\r\n\r\n"),
        Err(RtspError::NulByte(_))
    ));
}

#[test]
fn test_sdp_defaults_rfc3551() -> Result<(), Box<dyn Error>> {
    let sdp_text = "v=0\r\n\
                    o=- 1 1 IN IP4 127.0.0.1\r\ns=Test\r\nt=0 0\r\n\
                    m=audio 0 RTP/AVP 0\r\n\
                    m=video 0 RTP/AVP 96\r\n";
    let session = parse_sdp(sdp_text)?;
    assert_eq!(session.media.len(), 2);
    // PT 0 static default per RFC 3551 Table 4: PCMU / 8000
    assert_eq!(session.media[0].payload_type, 0);
    assert_eq!(session.media[0].encoding_name.as_deref(), Some("PCMU"));
    assert_eq!(session.media[0].clock_rate, Some(8000));

    // PT 96 dynamic without rtpmap: None / None
    assert_eq!(session.media[1].payload_type, 96);
    assert_eq!(session.media[1].encoding_name, None);
    assert_eq!(session.media[1].clock_rate, None);
    Ok(())
}

#[test]
fn test_sdp_line_length_bound() {
    let big_line = "a=".to_string() + &"x".repeat(MAX_SDP_LINE_BYTES + 1);
    let sdp_text = format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=Test\r\nt=0 0\r\n{big_line}\r\nm=video 0 RTP/AVP 96\r\n"
    );
    assert!(matches!(parse_sdp(&sdp_text), Err(SdpError::Limit(_))));
}

#[test]
fn test_sdp_invalid_fmtp_and_pt() {
    let sdp_bad_pm = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=Test\r\nt=0 0\r\n\
                      m=video 0 RTP/AVP 96\r\n\
                      a=fmtp:96 packetization-mode=9\r\n";
    assert!(matches!(parse_sdp(sdp_bad_pm), Err(SdpError::Malformed(_))));

    let sdp_bad_pt = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=Test\r\nt=0 0\r\n\
                      m=video 0 RTP/AVP 200\r\n";
    assert!(matches!(parse_sdp(sdp_bad_pt), Err(SdpError::Malformed(_))));
}

#[test]
fn test_transport_case_insensitivity_and_alternatives() -> Result<(), Box<dyn Error>> {
    let mut h = RtspHeaders::new();
    h.insert("Transport", "RTP/AVP/TCP;unicast;Interleaved=0-1");
    let t = h.transport().ok_or("missing transport")??;
    assert_eq!(t.interleaved, Some((0, 1)));

    let mut h2 = RtspHeaders::new();
    h2.insert(
        "Transport",
        "RTP/AVP/TCP;unicast;interleaved=2-3,RTP/AVP;unicast;client_port=5000-5001",
    );
    let t2 = h2.transport().ok_or("missing transport")??;
    assert_eq!(t2.interleaved, Some((2, 3)));

    let mut h3 = RtspHeaders::new();
    h3.insert("Transport", "RTP/AVP/TCP;unicast;interleaved=255");
    assert!(matches!(
        h3.transport(),
        Some(Err(RtspError::BadTransport(_)))
    ));

    let mut h4 = RtspHeaders::new();
    h4.insert("Transport", "RTP/AVP;unicast;client_port=65535");
    assert!(matches!(
        h4.transport(),
        Some(Err(RtspError::BadTransport(_)))
    ));
    Ok(())
}

#[test]
fn test_session_level_rtcp_rsize_inherited() -> Result<(), Box<dyn Error>> {
    let sdp_text = "v=0\r\n\
                    o=- 1 1 IN IP4 127.0.0.1\r\ns=Test\r\nt=0 0\r\n\
                    a=rtcp-rsize\r\n\
                    m=video 0 RTP/AVP 96\r\n";
    let session = parse_sdp(sdp_text)?;
    assert!(session.media[0].rtcp_reduced_size);
    Ok(())
}

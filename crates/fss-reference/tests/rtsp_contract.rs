#![forbid(unsafe_code)]
//! Contract tests for sans-IO RTSP/1.0 message parser and SDP parser (fss-2h5zq.32).

use std::error::Error;

use fss_reference::rtsp::{
    AuthScheme, Base64Fault, ContentLengthConflict, DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_HEADERS,
    DEFAULT_MAX_INTERLEAVED_BYTES, DEFAULT_MAX_LINE_BYTES, DuplicateHeader, HeaderLimitFault,
    HeaderValueFault, LengthLimit, MAX_SDP_LINE_BYTES, NumericFault, PoisonCause,
    REDACTED_CREDENTIAL, RtspError, RtspEvent, RtspHeaders, RtspLimits, RtspMethod, RtspParser,
    SdpControlLevel, SdpError, StartLineFault, TransportFault, UnsupportedMethod, UserinfoSite,
    Utf8Fault, decode_base64, parse_sdp, parse_sdp_bytes,
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

    for (token, method) in [
        ("ANNOUNCE", UnsupportedMethod::Announce),
        ("RECORD", UnsupportedMethod::Record),
        ("REDIRECT", UnsupportedMethod::Redirect),
        ("SET_PARAMETER", UnsupportedMethod::SetParameter),
    ] {
        let wire = format!("{token} rtsp://127.0.0.1:8554/live RTSP/1.0\r\nCSeq: 8\r\n\r\n");
        let result = parser.feed(wire.as_bytes());
        assert_eq!(method.as_str(), token);
        assert_eq!(
            result,
            Err(RtspError::Unsupported { method }),
            "method {token} should yield typed Unsupported refusal"
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

    let RtspEvent::AuthRequired { scheme, response } = &events[0] else {
        return Err(format!("expected AuthRequired event, got {:?}", events[0]).into());
    };
    assert_eq!(*scheme, AuthScheme::Digest);
    assert_eq!(response.status_code, 401);
    assert_eq!(response.headers.cseq().ok_or("CSeq missing")??, 1);
    assert_eq!(response.auth_challenge, Some(AuthScheme::Digest));
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

    let RtspEvent::AuthRequired { scheme, response } = &events[0] else {
        return Err(format!("expected AuthRequired event, got {:?}", events[0]).into());
    };
    assert_eq!(*scheme, AuthScheme::Basic);
    assert_eq!(response.status_code, 401);
    assert_eq!(response.headers.cseq().ok_or("CSeq missing")??, 2);
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
    let wire1 = b"DESCRIBE rtsp://user:secretpw@127.0.0.1/x RTSP/1.0\r\nCSeq: 2\r\n\r\n";
    let mut parser1 = RtspParser::new();
    let res1 = parser1.feed(wire1);
    assert!(matches!(res1, Err(RtspError::UserinfoNotPermitted(_))));

    let wire2 = b"DESCRIBE //user:secretpw@127.0.0.1/x RTSP/1.0\r\nCSeq: 2\r\n\r\n";
    let mut parser2 = RtspParser::new();
    let res2 = parser2.feed(wire2);
    assert!(matches!(res2, Err(RtspError::UserinfoNotPermitted(_))));
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
    assert!(matches!(
        &events[0],
        RtspEvent::AuthRequired { scheme: AuthScheme::Digest, response } if response.status_code == 407
    ));
    let dbg = format!("{events:?}");
    assert!(!dbg.contains("n0nce"));
    assert!(!dbg.contains("realm"));

    // 200 with WWW-Authenticate must preserve 200 Response and surface auth_challenge
    let wire_200 = b"RTSP/1.0 200 OK\r\n\
                     CSeq: 1\r\n\
                     WWW-Authenticate: Basic realm=\"secret\"\r\n\r\n";
    let mut parser2 = RtspParser::new();
    let events2 = parser2.feed(wire_200)?;
    assert_eq!(events2.len(), 1);
    let RtspEvent::Response(resp2) = &events2[0] else {
        return Err(format!("expected Response, got {:?}", events2[0]).into());
    };
    assert_eq!(resp2.status_code, 200);
    assert_eq!(resp2.auth_challenge, Some(AuthScheme::Basic));
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
fn test_line_folding_does_not_inject_headers() {
    let wire = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nX-Custom: part1\r\n Injected: value\r\n\r\n";
    let mut parser = RtspParser::new();
    let res = parser.feed(wire);
    assert_eq!(res, Err(RtspError::LineFoldingNotPermitted));
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

    let mut h5 = RtspHeaders::new();
    h5.insert("Transport", "RTP/AVP;unicast;Client_Port=5000-5001");
    let t5 = h5.transport().ok_or("missing transport")??;
    assert_eq!(t5.client_port, Some((5000, 5001)));

    let mut h6 = RtspHeaders::new();
    h6.insert(
        "Transport",
        "RTP/AVP/TCP;interleaved=300,RTP/AVP/TCP;interleaved=2-3",
    );
    let t6 = h6.transport().ok_or("missing transport")??;
    assert_eq!(t6.interleaved, Some((2, 3)));
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

#[test]
fn test_bare_lf_no_body_and_one_byte_body_kills_m21() -> Result<(), Box<dyn Error>> {
    // Bare LF with no body (exact round-1 stall condition)
    let mut p1 = RtspParser::new();
    let ev1 = p1.feed(b"RTSP/1.0 200 OK\nCSeq: 1\n\n")?;
    assert_eq!(ev1.len(), 1);
    assert_eq!(p1.buffered_bytes(), 0);

    // Bare LF with 1-byte body
    let mut p2 = RtspParser::new();
    let ev2 = p2.feed(b"RTSP/1.0 200 OK\nCSeq: 1\nContent-Length: 1\n\nX")?;
    assert_eq!(ev2.len(), 1);
    assert_eq!(p2.buffered_bytes(), 0);

    // Bare LF with 0-length declared body
    let mut p3 = RtspParser::new();
    let ev3 = p3.feed(b"RTSP/1.0 200 OK\nCSeq: 1\nContent-Length: 0\n\n")?;
    assert_eq!(ev3.len(), 1);
    assert_eq!(p3.buffered_bytes(), 0);
    Ok(())
}

#[test]
fn test_request_bad_cseq_and_missing_cseq_kills_m41_m43() {
    let mut p1 = RtspParser::new();
    let res1 = p1.feed(b"OPTIONS rtsp://127.0.0.1/live RTSP/1.0\r\nCSeq: abc\r\n\r\n");
    assert!(matches!(res1, Err(RtspError::BadCSeq(_))));

    let mut p2 = RtspParser::new();
    let res2 = p2.feed(b"OPTIONS rtsp://127.0.0.1/live RTSP/1.0\r\n\r\n");
    assert!(matches!(res2, Err(RtspError::MissingCSeq)));
}

#[test]
fn test_scheme_token_charset_kills_m151() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        fss_reference::rtsp::message::extract_auth_scheme("Dig(est"),
        None
    );
    assert_eq!(
        fss_reference::rtsp::message::extract_auth_scheme("Digest/1"),
        None
    );
    assert_eq!(
        fss_reference::rtsp::message::extract_auth_scheme("Digest@host"),
        None
    );

    let mut parser = RtspParser::new();
    let wire =
        b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Dig(est nonce=\"x\"\r\n\r\n";
    let events = parser.feed(wire)?;
    assert_eq!(events.len(), 1);
    let RtspEvent::Response(resp) = &events[0] else {
        return Err(format!("expected Response, got {:?}", events[0]).into());
    };
    assert_eq!(resp.status_code, 401);
    assert_eq!(resp.auth_challenge, None);
    Ok(())
}

#[test]
fn test_sdp_pt_above_127_in_rtpmap_and_fmtp_kills_m281() {
    let sdp_bad_rtpmap = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=Test\r\nt=0 0\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:200 H264/90000\r\n";
    assert!(matches!(
        parse_sdp(sdp_bad_rtpmap),
        Err(SdpError::Malformed(_))
    ));

    let sdp_bad_fmtp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=Test\r\nt=0 0\r\nm=video 0 RTP/AVP 96\r\na=fmtp:200 packetization-mode=1\r\n";
    assert!(matches!(
        parse_sdp(sdp_bad_fmtp),
        Err(SdpError::Malformed(_))
    ));
}

#[test]
fn test_pending_error_preserves_incoming_chunk_and_resumes() -> Result<(), Box<dyn Error>> {
    let mut parser = RtspParser::new();
    let wire1 = b"OPTIONS rtsp://h RTSP/1.0\r\nCSeq: 1\r\n\r\nANNOUNCE rtsp://h RTSP/1.0\r\nCSeq: 2\r\n\r\n";
    let ev1 = parser.feed(wire1)?;
    assert_eq!(ev1.len(), 1);
    assert!(matches!(&ev1[0], RtspEvent::Request(r) if r.method == RtspMethod::Options));

    // Next feed delivers valid 200 OK. It surfaces pending error for ANNOUNCE, but buffers the 200 OK!
    let wire2 = b"RTSP/1.0 200 OK\r\nCSeq: 3\r\n\r\n";
    let res2 = parser.feed(wire2);
    assert!(matches!(res2, Err(RtspError::Unsupported { .. })));

    // Next feed with empty slice processes the buffered 200 OK!
    let ev3 = parser.feed(b"")?;
    assert_eq!(ev3.len(), 1);
    let RtspEvent::Response(r) = &ev3[0] else {
        return Err(format!("expected Response, got {:?}", ev3[0]).into());
    };
    assert_eq!(r.status_code, 200);
    assert_eq!(r.headers.cseq().ok_or("missing CSeq")??, 3);
    Ok(())
}

#[test]
fn test_duplicate_cseq_with_body_discards_body_and_resumes() -> Result<(), Box<dyn Error>> {
    let mut parser = RtspParser::new();
    let wire_dup = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nCSeq: 2\r\nContent-Length: 5\r\n\r\nhello";
    let res = parser.feed(wire_dup);
    assert!(matches!(res, Err(RtspError::DuplicateCSeq(_))));
    assert_eq!(parser.buffered_bytes(), 0);

    let wire_valid = b"RTSP/1.0 200 OK\r\nCSeq: 3\r\n\r\n";
    let ev = parser.feed(wire_valid)?;
    assert_eq!(ev.len(), 1);
    let RtspEvent::Response(r) = &ev[0] else {
        return Err(format!("expected Response, got {:?}", ev[0]).into());
    };
    assert_eq!(r.status_code, 200);
    assert_eq!(r.headers.cseq().ok_or("missing CSeq")??, 3);
    Ok(())
}

#[test]
fn test_credential_byte_scan() {
    fn scan(ev: &Result<Vec<RtspEvent>, RtspError>) -> Vec<u8> {
        let mut out: Vec<u8> = format!("{ev:?}").into_bytes();
        if let Ok(v) = ev {
            for e in v {
                match e {
                    RtspEvent::Request(r) => {
                        out.extend_from_slice(r.uri.as_bytes());
                        out.extend_from_slice(r.version.as_bytes());
                        for h in r.headers.iter() {
                            out.extend_from_slice(h.name.as_bytes());
                            out.extend_from_slice(h.value.as_bytes());
                        }
                        out.extend_from_slice(&r.body);
                    }
                    RtspEvent::Response(r) => {
                        out.extend_from_slice(r.reason.as_bytes());
                        for h in r.headers.iter() {
                            out.extend_from_slice(h.name.as_bytes());
                            out.extend_from_slice(h.value.as_bytes());
                        }
                        out.extend_from_slice(&r.body);
                    }
                    RtspEvent::AuthRequired { response, .. } => {
                        out.extend_from_slice(response.reason.as_bytes());
                        for h in response.headers.iter() {
                            out.extend_from_slice(h.name.as_bytes());
                            out.extend_from_slice(h.value.as_bytes());
                        }
                        out.extend_from_slice(&response.body);
                    }
                    RtspEvent::Interleaved { span, .. } => out.extend_from_slice(span),
                }
            }
        } else if let Err(e) = ev {
            out.extend_from_slice(e.to_string().as_bytes());
        }
        out
    }

    let vectors: &[(&str, &[u8], &[&str])] = &[
        (
            "c01 Authorization Basic",
            b"DESCRIBE rtsp://h/x RTSP/1.0\r\nCSeq: 2\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n",
            &["dXNlcjpwYXNz"],
        ),
        (
            "c02 Proxy-Authorization",
            b"DESCRIBE rtsp://h/x RTSP/1.0\r\nCSeq: 2\r\nProxy-Authorization: Digest username=\"ADMINU\", response=\"RESPSECRET\"\r\n\r\n",
            &["ADMINU", "RESPSECRET"],
        ),
        (
            "c03 userinfo URI",
            b"DESCRIBE rtsp://admin:SECRETPW@h/x RTSP/1.0\r\nCSeq: 2\r\n\r\n",
            &["SECRETPW", "admin"],
        ),
        (
            "c04 401 Digest",
            b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Digest realm=\"REALMX\", nonce=\"N0NCE1\"\r\n\r\n",
            &["REALMX", "N0NCE1"],
        ),
        (
            "c05 407 Proxy-Authenticate",
            b"RTSP/1.0 407 Proxy Authentication Required\r\nCSeq: 1\r\nProxy-Authenticate: Digest realm=\"REALMP\", nonce=\"N0NCEP\"\r\n\r\n",
            &["REALMP", "N0NCEP"],
        ),
        (
            "c06 200 + WWW-Authenticate + body",
            b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nWWW-Authenticate: Basic realm=\"REALM2\"\r\nContent-Length: 7\r\n\r\nBODYSDP",
            &["REALM2"],
        ),
        (
            "c07 folded Authorization",
            b"DESCRIBE rtsp://h/x RTSP/1.0\r\nCSeq: 2\r\nAuthorization: Digest username=\"u\",\r\n response=\"FOLDSECRET\"\r\n\r\n",
            &["FOLDSECRET"],
        ),
        (
            "c08 folded WWW-Authenticate after CSeq",
            b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Digest realm=\"r\",\r\n nonce=\"FOLDNONCE\"\r\n\r\n",
            &["FOLDNONCE"],
        ),
        (
            "c09 folded WWW-Authenticate after X-A",
            b"DESCRIBE rtsp://h/x RTSP/1.0\r\nCSeq: 2\r\nX-A: a\r\nWWW-Authenticate: Digest realm=\"r\",\r\n nonce=\"REQFOLD\"\r\n\r\n",
            &["REQFOLD"],
        ),
        (
            "c10 folded WWW-Authenticate after Session",
            b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nSession: 1234\r\nWWW-Authenticate:\r\n Digest nonce=\"SLFOLD\"\r\n\r\n",
            &["SLFOLD"],
        ),
        (
            "c11 Authorization line without colon",
            b"DESCRIBE rtsp://h/x RTSP/1.0\r\nCSeq: 2\r\nAuthorization Basic dXNlcjpwYXNz\r\n\r\n",
            &["dXNlcjpwYXNz"],
        ),
        (
            "c12 Content-Base with userinfo",
            b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Base: rtsp://admin:SECRETCB@h/\r\n\r\n",
            &["SECRETCB"],
        ),
        (
            "c13 userinfo URI after valid msg",
            b"OPTIONS rtsp://h RTSP/1.0\r\nCSeq: 1\r\n\r\nDESCRIBE rtsp://admin:SECRETPEND@h/x RTSP/1.0\r\nCSeq: 2\r\n\r\n",
            &["SECRETPEND"],
        ),
        (
            "c14 network-path URI //user:pw@h",
            b"DESCRIBE //admin:SECRETNP@h/x RTSP/1.0\r\nCSeq: 2\r\n\r\n",
            &["SECRETNP"],
        ),
        (
            "c15 Authorization name with trailing ws",
            b"DESCRIBE rtsp://h/x RTSP/1.0\r\nCSeq: 2\r\nAuthorization \t: Basic SECRETWS\r\n\r\n",
            &["SECRETWS"],
        ),
        (
            "c16 folded Proxy-Authorization",
            b"DESCRIBE rtsp://h/x RTSP/1.0\r\nCSeq: 2\r\nProxy-Authorization: Basic\r\n\tSECRETPF\r\n\r\n",
            &["SECRETPF"],
        ),
        (
            "c17 WWW-Authenticate on a request",
            b"DESCRIBE rtsp://h/x RTSP/1.0\r\nCSeq: 2\r\nWWW-Authenticate: Digest nonce=\"REQNONCE\"\r\n\r\n",
            &["REQNONCE"],
        ),
        (
            "c18 two challenges, first invalid scheme",
            b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: \"x\" nonce=\"TWO1\"\r\nWWW-Authenticate: Basic realm=\"TWO2\"\r\n\r\n",
            &["TWO1", "TWO2"],
        ),
        (
            "c19 scheme Dig(est",
            b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Dig(est nonce=\"PAREN\"\r\n\r\n",
            &["PAREN", "Dig("],
        ),
        (
            "c20 scheme Digest, comma",
            b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Digest, nonce=\"COMMA\"\r\n\r\n",
            &["COMMA"],
        ),
        (
            "c21 start line 'Authorization Basic <b64>'",
            b"Authorization Basic dXNlcjpwYXNz\r\nCSeq: 1\r\n\r\n",
            &["dXNlcjpwYXNz"],
        ),
        (
            "c22 start line 'Authorization: Basic <b64>'",
            b"Authorization: Basic dXNlcjpwYXNz\r\nCSeq: 1\r\n\r\n",
            &["dXNlcjpwYXNz"],
        ),
        (
            "c23 secret as method",
            b"dXNlcjpwYXNz rtsp://h/x RTSP/1.0\r\nCSeq: 1\r\n\r\n",
            &["dXNlcjpwYXNz"],
        ),
        (
            "c24 secret as status code",
            b"RTSP/1.0 dXNlcjpwYXNz OK\r\nCSeq: 1\r\n\r\n",
            &["dXNlcjpwYXNz"],
        ),
        (
            "c25 secret as response version",
            b"RTSP/dXNlcjpwYXNz 200 OK\r\nCSeq: 1\r\n\r\n",
            &["dXNlcjpwYXNz"],
        ),
        (
            "c26 secret as request version",
            b"OPTIONS rtsp://h/x RTSP/dXNlcjpwYXNz\r\nCSeq: 1\r\n\r\n",
            &["dXNlcjpwYXNz"],
        ),
        (
            "c27 secret as response CSeq",
            b"RTSP/1.0 200 OK\r\nCSeq: Basic dXNlcjpwYXNz\r\n\r\n",
            &["dXNlcjpwYXNz"],
        ),
        (
            "c28 secret as request CSeq",
            b"OPTIONS rtsp://h/x RTSP/1.0\r\nCSeq: dXNlcjpwYXNz\r\n\r\n",
            &["dXNlcjpwYXNz"],
        ),
        (
            "c29 secret as duplicate CSeq",
            b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nCSeq: dXNlcjpwYXNz\r\n\r\n",
            &["dXNlcjpwYXNz"],
        ),
        (
            "c30 secret as Content-Length",
            b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: dXNlcjpwYXNz\r\n\r\n",
            &["dXNlcjpwYXNz"],
        ),
        (
            "c31 secret as Transport client_port",
            b"RTSP/1.0 200 OK\r\nCSeq: 3\r\nTransport: RTP/AVP;unicast;client_port=dXNlcjpwYXNz\r\n\r\n",
            &["dXNlcjpwYXNz"],
        ),
        (
            "c32 secret as Transport interleaved channel",
            b"SETUP rtsp://h/x RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP/TCP;unicast;interleaved=dXNlcjpwYXNz\r\n\r\n",
            &["dXNlcjpwYXNz"],
        ),
        (
            "c33 Location userinfo",
            b"RTSP/1.0 302 Found\r\nCSeq: 1\r\nLocation: rtsp://admin:SECRETLOC@h/\r\n\r\n",
            &["SECRETLOC"],
        ),
        (
            "c34 RTP-Info second url userinfo",
            b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nRTP-Info: url=rtsp://h/t0;seq=1,url=rtsp://admin:SECRETRI@h/t1;seq=2\r\n\r\n",
            &["SECRETRI"],
        ),
        (
            "c35 Content-Location userinfo",
            b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Location: rtsp://admin:SECRETCL@h/\r\n\r\n",
            &["SECRETCL"],
        ),
        (
            "c36 invalid UTF-8 beside the secret",
            b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nX: \xff dXNlcjpwYXNz\r\n\r\n",
            &["dXNlcjpwYXNz"],
        ),
        (
            "c37 401 bare-token challenge",
            b"RTSP/1.0 401 Unauthorized\r\nCSeq: 6\r\nWWW-Authenticate: dXNlcjpwYXNz\r\n\r\n",
            &["dXNlcjpwYXNz"],
        ),
        (
            "c38 200 bare-token challenge",
            b"RTSP/1.0 200 OK\r\nCSeq: 5\r\nWWW-Authenticate: dXNlcjpwYXNz\r\n\r\n",
            &["dXNlcjpwYXNz"],
        ),
        (
            "c39 overflowing Content-Length then a smuggled request carrying the secret",
            b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 99999999999999999999999\r\n\r\nOPTIONS rtsp://h/dXNlcjpwYXNz RTSP/1.0\r\nCSeq: 9\r\n\r\n",
            &["dXNlcjpwYXNz"],
        ),
        (
            "c40 conflicting Content-Length then a smuggled request carrying the secret",
            b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 0\r\nContent-Length: 51\r\n\r\nOPTIONS rtsp://h/dXNlcjpwYXNz RTSP/1.0\r\nCSeq: 9\r\n\r\n",
            &["dXNlcjpwYXNz"],
        ),
        (
            "c41 invalid UTF-8 header block whose body smuggles a request carrying the secret",
            b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nX: \xff\r\nContent-Length: 51\r\n\r\nOPTIONS rtsp://h/dXNlcjpwYXNz RTSP/1.0\r\nCSeq: 9\r\n\r\n",
            &["dXNlcjpwYXNz"],
        ),
    ];

    for (id, wire, secrets) in vectors {
        let mut hay = Vec::new();
        let mut p = RtspParser::new();
        let r1 = p.feed(wire);
        hay.extend(scan(&r1));
        for _ in 0..3 {
            let r = p.feed(b"");
            hay.extend(scan(&r));
        }
        let mut p2 = RtspParser::new();
        for b in *wire {
            let r = p2.feed(std::slice::from_ref(b));
            hay.extend(scan(&r));
        }
        for _ in 0..3 {
            let r = p2.feed(b"");
            hay.extend(scan(&r));
        }
        for s in *secrets {
            let pat = s.as_bytes();
            let leaked = hay.windows(pat.len()).any(|w| w == pat);
            assert!(
                !leaked,
                "Vector '{id}' leaked planted secret '{s}' into parser output or error text"
            );
        }
    }
}

// ---- Round 4 (fss-2h5zq.32): typed errors, userinfo everywhere, framing poison, challenge
// marker, tab folding. ----

const SMUGGLED: &[u8] = b"OPTIONS rtsp://h/SMUGGLED RTSP/1.0\r\nCSeq: 9\r\n\r\n";
const VALID_200: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n";

fn assert_not_smuggled(id: &str, res: &Result<Vec<RtspEvent>, RtspError>) {
    let text = format!("{res:?}");
    assert!(
        !text.contains("SMUGGLED"),
        "{id}: bytes after a lost boundary surfaced as a message: {text}"
    );
}

fn single_response_cseq(events: &[RtspEvent]) -> Result<u32, Box<dyn Error>> {
    let [RtspEvent::Response(resp)] = events else {
        return Err(format!("expected exactly one Response, got {events:?}").into());
    };
    Ok(resp.headers.cseq().ok_or("missing CSeq")??)
}

#[test]
fn test_error_values_carry_no_input_text() {
    let secret = "dXNlcjpwYXNz";
    let mut rendered = Vec::new();

    let method = RtspMethod::parse_token(secret);
    assert_eq!(
        method,
        Err(RtspError::MalformedStartLine(
            StartLineFault::UnknownMethod { token_len: 12 }
        ))
    );
    rendered.push(format!("{method:?}"));

    let mut h = RtspHeaders::new();
    h.insert("CSeq", secret);
    h.insert("Content-Length", secret);
    h.insert("Transport", format!("RTP/AVP;unicast;client_port={secret}"));
    let cseq = h.cseq();
    assert_eq!(
        cseq,
        Some(Err(RtspError::BadCSeq(HeaderValueFault {
            kind: NumericFault::NotAnInteger,
            value_len: 12,
        })))
    );
    let content_length = h.content_length();
    assert_eq!(
        content_length,
        Some(Err(RtspError::BadContentLength(HeaderValueFault {
            kind: NumericFault::NotAnInteger,
            value_len: 12,
        })))
    );
    let transport = h.transport();
    assert_eq!(
        transport,
        Some(Err(RtspError::BadTransport(TransportFault::InvalidPort {
            value_len: 12
        })))
    );
    rendered.push(format!("{cseq:?}{content_length:?}{transport:?}"));

    let mut h2 = RtspHeaders::new();
    h2.insert(
        "Transport",
        format!("RTP/AVP/TCP;unicast;interleaved=0-{secret}"),
    );
    let transport2 = h2.transport();
    assert_eq!(
        transport2,
        Some(Err(RtspError::BadTransport(
            TransportFault::InvalidChannel { value_len: 12 }
        )))
    );
    rendered.push(format!("{transport2:?}"));

    assert_eq!(
        fss_reference::rtsp::message::extract_auth_scheme(secret),
        Some(AuthScheme::Other)
    );

    let errors = [
        RtspError::MalformedStartLine(StartLineFault::UnknownMethod { token_len: 12 }),
        RtspError::BadCSeq(HeaderValueFault {
            kind: NumericFault::Overflow,
            value_len: 12,
        }),
        RtspError::Poisoned(PoisonCause::AmbiguousContentLength),
        RtspError::Unsupported {
            method: UnsupportedMethod::SetParameter,
        },
    ];
    for err in errors {
        rendered.push(format!("{err:?} {err}"));
    }
    for text in &rendered {
        assert!(!text.contains(secret), "error text echoed input: {text}");
    }
}

#[test]
fn test_error_offsets_and_lengths_are_exact() -> Result<(), Box<dyn Error>> {
    let mut p = RtspParser::new();
    // "RTSP/1.0 200 OK\r\n" is 17 bytes, "CSeq: 1\r\n" is 9: the duplicate starts at 26.
    assert_eq!(
        p.feed(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nCSeq: 2\r\n\r\n"),
        Err(RtspError::DuplicateCSeq(DuplicateHeader { offset: 26 }))
    );
    assert_eq!(
        RtspParser::new().feed(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nNoColonHere\r\n\r\n"),
        Err(RtspError::MalformedStartLine(
            StartLineFault::HeaderMissingColon { offset: 26 }
        ))
    );
    assert_eq!(
        RtspParser::new().feed(b"RTSP/1.0 abc OK\r\nCSeq: 1\r\n\r\n"),
        Err(RtspError::MalformedStartLine(
            StartLineFault::InvalidStatusCode { token_len: 3 }
        ))
    );
    assert_eq!(
        decode_base64("dXNl!3Bh"),
        Err(SdpError::BadBase64(Base64Fault::InvalidCharacter {
            offset: 4
        }))
    );
    assert_eq!(
        decode_base64("abc"),
        Err(SdpError::BadBase64(Base64Fault::LengthNotMultipleOf4 {
            len: 3
        }))
    );
    Ok(())
}

#[test]
fn test_sdp_credential_byte_scan() {
    let secret = "dXNlcjpwYXNz";
    let head = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=S\r\nt=0 0\r\n";
    let long = format!("a=x{secret}{}", "x".repeat(MAX_SDP_LINE_BYTES));
    let cases = [
        (
            "s01 version",
            format!("v={secret}\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=S\r\nm=video 0 RTP/AVP 96\r\n"),
        ),
        (
            "s02 line without '='",
            format!("{head}{secret}\r\nm=video 0 RTP/AVP 96\r\n"),
        ),
        (
            "s03 m= port",
            format!("{head}m=video {secret} RTP/AVP 96\r\n"),
        ),
        (
            "s04 m= payload format",
            format!("{head}m=video 0 RTP/AVP {secret}\r\n"),
        ),
        (
            "s05 rtpmap payload type",
            format!("{head}m=video 0 RTP/AVP 96\r\na=rtpmap:{secret} H264/90000\r\n"),
        ),
        (
            "s06 rtpmap clock rate",
            format!("{head}m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/{secret}\r\n"),
        ),
        (
            "s07 fmtp payload type",
            format!("{head}m=video 0 RTP/AVP 96\r\na=fmtp:{secret} packetization-mode=1\r\n"),
        ),
        (
            "s08 packetization-mode",
            format!("{head}m=video 0 RTP/AVP 96\r\na=fmtp:96 packetization-mode={secret}\r\n"),
        ),
        (
            "s09 sprop-parameter-sets",
            format!(
                "{head}m=video 0 RTP/AVP 96\r\na=fmtp:96 sprop-parameter-sets={secret}$AAA\r\n"
            ),
        ),
        (
            "s10 session a=control userinfo",
            format!("{head}a=control:rtsp://admin:{secret}@h/\r\nm=video 0 RTP/AVP 96\r\n"),
        ),
        (
            "s11 media a=control userinfo",
            format!("{head}m=video 0 RTP/AVP 96\r\na=control:rtsp://admin:{secret}@h/t\r\n"),
        ),
        (
            "s12 over-long line",
            format!("{head}{long}\r\nm=video 0 RTP/AVP 96\r\n"),
        ),
    ];
    for (id, sdp) in &cases {
        let res = parse_sdp(sdp);
        assert!(res.is_err(), "{id} must be refused, got {res:?}");
        let text = match &res {
            Ok(session) => format!("{session:?}"),
            Err(err) => format!("{err:?} {err}"),
        };
        assert!(
            !text.contains(secret),
            "{id} leaked the planted secret: {text}"
        );
    }

    let mut bytes = format!("{head}m=video 0 RTP/AVP 96\r\na=x:").into_bytes();
    bytes.push(0xff);
    bytes.extend_from_slice(secret.as_bytes());
    let res = parse_sdp_bytes(&bytes);
    assert!(matches!(res, Err(SdpError::Utf8(_))));
    assert!(!format!("{res:?}").contains(secret));
}

#[test]
fn test_userinfo_refused_in_every_uri_header_and_sdp_control() -> Result<(), Box<dyn Error>> {
    // u01: Location
    assert_eq!(
        RtspParser::new()
            .feed(b"RTSP/1.0 302 Found\r\nCSeq: 1\r\nLocation: rtsp://admin:SECRETLOC@h/\r\n\r\n"),
        Err(RtspError::UserinfoNotPermitted(UserinfoSite::Location))
    );
    // u02: RTP-Info url=, first and later entries, and a comma inside the userinfo
    assert_eq!(
        RtspParser::new().feed(
            b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nRTP-Info: url=rtsp://admin:SECRETRI@h/t1;seq=1\r\n\r\n"
        ),
        Err(RtspError::UserinfoNotPermitted(UserinfoSite::RtpInfo {
            entry: 0
        }))
    );
    assert_eq!(
        RtspParser::new().feed(
            b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nRTP-Info: url=rtsp://h/t0;seq=1, URL=rtsp://u:p@h/t1;seq=2\r\n\r\n"
        ),
        Err(RtspError::UserinfoNotPermitted(UserinfoSite::RtpInfo {
            entry: 1
        }))
    );
    assert_eq!(
        RtspParser::new()
            .feed(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nRTP-Info: url=rtsp://a,b:p@h/t1;seq=1\r\n\r\n"),
        Err(RtspError::UserinfoNotPermitted(UserinfoSite::RtpInfo {
            entry: 0
        }))
    );
    // Content-Location (kills M73) and Content-Base
    assert_eq!(
        RtspParser::new().feed(
            b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Location: rtsp://admin:SECRETCL@h/\r\n\r\n"
        ),
        Err(RtspError::UserinfoNotPermitted(
            UserinfoSite::ContentLocation
        ))
    );
    assert_eq!(
        RtspParser::new()
            .feed(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Base: //admin:pw@h/\r\n\r\n"),
        Err(RtspError::UserinfoNotPermitted(UserinfoSite::ContentBase))
    );

    // u05: SDP a=control at session and media level
    let head = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=S\r\nt=0 0\r\n";
    let session_ctl =
        format!("{head}a=control:rtsp://admin:SECRETSDP@h/\r\nm=video 0 RTP/AVP 96\r\n");
    assert_eq!(
        parse_sdp(&session_ctl),
        Err(SdpError::UserinfoNotPermitted(SdpControlLevel::Session {
            offset: head.len()
        }))
    );
    let m_line = "m=video 0 RTP/AVP 96\r\n";
    let media_ctl = format!("{head}{m_line}a=control:rtsp://admin:SECRETSDPM@h/t\r\n");
    assert_eq!(
        parse_sdp(&media_ctl),
        Err(SdpError::UserinfoNotPermitted(SdpControlLevel::Media {
            index: 0,
            offset: head.len() + m_line.len()
        }))
    );

    // A query-only '@' is not userinfo and is accepted everywhere (kills M71).
    let ev = RtspParser::new().feed(b"OPTIONS rtsp://h?x=a@b RTSP/1.0\r\nCSeq: 1\r\n\r\n")?;
    let [RtspEvent::Request(req)] = ev.as_slice() else {
        return Err(format!("expected one Request, got {ev:?}").into());
    };
    assert_eq!(req.uri, "rtsp://h?x=a@b");
    let ev = RtspParser::new().feed(
        b"RTSP/1.0 302 Found\r\nCSeq: 1\r\nLocation: rtsp://h?next=a@b\r\nRTP-Info: url=rtsp://h?q=a@b;seq=1\r\n\r\n",
    )?;
    let [RtspEvent::Response(resp)] = ev.as_slice() else {
        return Err(format!("expected one Response, got {ev:?}").into());
    };
    assert_eq!(resp.headers.get("Location"), Some("rtsp://h?next=a@b"));
    assert_eq!(resp.headers.rtp_info(), Some("url=rtsp://h?q=a@b;seq=1"));
    let sdp_query = format!("{head}a=control:rtsp://h?x=a@b\r\n{m_line}a=control:trackID=0\r\n");
    let session = parse_sdp(&sdp_query)?;
    assert_eq!(session.session_control.as_deref(), Some("rtsp://h?x=a@b"));
    assert_eq!(session.media[0].control.as_deref(), Some("trackID=0"));
    Ok(())
}

#[test]
fn test_tab_folded_continuation_refused_kills_m201() {
    let crlf = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nX-Custom: part1\r\n\tInjected: value\r\n\r\n";
    assert_eq!(
        RtspParser::new().feed(crlf),
        Err(RtspError::LineFoldingNotPermitted)
    );
    let bare_lf = b"RTSP/1.0 200 OK\nCSeq: 1\nX: a\n\tSession: evil\n\n";
    assert_eq!(
        RtspParser::new().feed(bare_lf),
        Err(RtspError::LineFoldingNotPermitted)
    );
}

#[test]
fn test_invalid_transport_refused_at_message_level() -> Result<(), Box<dyn Error>> {
    let mut p = RtspParser::new();
    let mut wire =
        b"SETUP rtsp://h/x RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP/TCP;interleaved=300\r\n\r\n"
            .to_vec();
    wire.extend_from_slice(VALID_200);
    assert_eq!(
        p.feed(&wire),
        Err(RtspError::BadTransport(TransportFault::InvalidChannel {
            value_len: 3
        }))
    );
    // Message-level error: the refused message was framed, the next one parses.
    assert_eq!(single_response_cseq(&p.feed(b"")?)?, 2);
    Ok(())
}

#[test]
fn test_utf8_header_error_poisons_until_reset_b01() -> Result<(), Box<dyn Error>> {
    let mut wire = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nX: \xff\r\n".to_vec();
    wire.extend_from_slice(format!("Content-Length: {}\r\n\r\n", SMUGGLED.len()).as_bytes());
    wire.extend_from_slice(SMUGGLED);
    let mut p = RtspParser::new();
    assert_eq!(
        p.feed(&wire),
        Err(RtspError::Utf8(Utf8Fault {
            valid_up_to: 29,
            error_len: Some(1)
        }))
    );
    assert_eq!(p.buffered_bytes(), 0);
    assert_eq!(p.poisoned(), Some(PoisonCause::InvalidUtf8Headers));
    for _ in 0..3 {
        let res = p.feed(VALID_200);
        assert_not_smuggled("b01", &res);
        assert_eq!(
            res,
            Err(RtspError::Poisoned(PoisonCause::InvalidUtf8Headers))
        );
        assert_eq!(p.buffered_bytes(), 0);
    }
    p.reset();
    assert_eq!(p.poisoned(), None);
    assert_eq!(single_response_cseq(&p.feed(VALID_200)?)?, 2);
    Ok(())
}

#[test]
fn test_oversize_interleaved_frame_discarded_exactly_b02() -> Result<(), Box<dyn Error>> {
    let limits = RtspLimits {
        max_interleaved_bytes: 16,
        ..RtspLimits::default()
    };
    let declared = u16::try_from(SMUGGLED.len())?;
    let mut frame = vec![b'$', 0];
    frame.extend_from_slice(&declared.to_be_bytes());
    frame.extend_from_slice(SMUGGLED);

    let mut p = RtspParser::with_limits(limits);
    let res = p.feed(&frame);
    assert_eq!(
        res,
        Err(RtspError::BadInterleavedLength(LengthLimit {
            declared: SMUGGLED.len(),
            limit: 16
        }))
    );
    assert_eq!(p.buffered_bytes(), 0);
    let res = p.feed(b"");
    assert_not_smuggled("b02", &res);
    assert_eq!(res?, Vec::new());
    assert_eq!(p.poisoned(), None);
    assert_eq!(single_response_cseq(&p.feed(VALID_200)?)?, 2);

    // The same frame split across feeds: the payload tail is discarded, the next message parses.
    let mut p2 = RtspParser::with_limits(limits);
    let (head, tail) = frame.split_at(14);
    assert!(matches!(
        p2.feed(head),
        Err(RtspError::BadInterleavedLength(_))
    ));
    let mut rest = tail.to_vec();
    rest.extend_from_slice(VALID_200);
    let res = p2.feed(&rest);
    assert_not_smuggled("b02 split", &res);
    assert_eq!(single_response_cseq(&res?)?, 2);
    Ok(())
}

#[test]
fn test_ambiguous_content_length_poisons_b03_b04_b05() -> Result<(), Box<dyn Error>> {
    let n = SMUGGLED.len();
    let cases = [
        (
            "b03 conflicting Content-Length",
            format!(
                "RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 0\r\nContent-Length: {n}\r\n\r\n"
            ),
            RtspError::DuplicateContentLength(ContentLengthConflict {
                first: 0,
                second: n,
                offset: 45,
            }),
        ),
        (
            "b04 signed Content-Length",
            format!("RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: +{n}\r\n\r\n"),
            RtspError::BadContentLength(HeaderValueFault {
                kind: NumericFault::Signed,
                value_len: 3,
            }),
        ),
        (
            "b05 overflowing Content-Length",
            "RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 99999999999999999999999\r\n\r\n"
                .to_string(),
            RtspError::BadContentLength(HeaderValueFault {
                kind: NumericFault::Overflow,
                value_len: 23,
            }),
        ),
        (
            "folded Content-Length",
            format!("RTSP/1.0 200 OK\r\nCSeq: 1\r\nX: a\r\n Content-Length: {n}\r\n\r\n"),
            RtspError::LineFoldingNotPermitted,
        ),
    ];
    for (id, head, expected) in cases {
        let mut wire = head.into_bytes();
        wire.extend_from_slice(SMUGGLED);
        let mut p = RtspParser::new();
        assert_eq!(p.feed(&wire), Err(expected), "{id}");
        assert_eq!(p.buffered_bytes(), 0, "{id}");
        assert_eq!(
            p.poisoned(),
            Some(PoisonCause::AmbiguousContentLength),
            "{id}"
        );
        for _ in 0..3 {
            let res = p.feed(VALID_200);
            assert_not_smuggled(id, &res);
            assert_eq!(
                res,
                Err(RtspError::Poisoned(PoisonCause::AmbiguousContentLength)),
                "{id}"
            );
        }
        p.reset();
        assert_eq!(single_response_cseq(&p.feed(VALID_200)?)?, 2, "{id}");
    }

    // A poisoning error after an earlier event: the event first, then the error, then poison.
    let mut wire = b"OPTIONS rtsp://h RTSP/1.0\r\nCSeq: 1\r\n\r\n".to_vec();
    wire.extend_from_slice(
        format!("RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Length: 0\r\nContent-Length: {n}\r\n\r\n")
            .as_bytes(),
    );
    wire.extend_from_slice(SMUGGLED);
    let mut p = RtspParser::new();
    let first = p.feed(&wire)?;
    assert!(matches!(first.as_slice(), [RtspEvent::Request(r)] if r.method == RtspMethod::Options));
    let second = p.feed(VALID_200);
    assert!(matches!(second, Err(RtspError::DuplicateContentLength(_))));
    let third = p.feed(VALID_200);
    assert_not_smuggled("pending poison", &third);
    assert_eq!(
        third,
        Err(RtspError::Poisoned(PoisonCause::AmbiguousContentLength))
    );
    Ok(())
}

#[test]
fn test_body_limit_poisons_instead_of_black_hole_b06() -> Result<(), Box<dyn Error>> {
    let mut p = RtspParser::new();
    let huge = format!(
        "RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: {}\r\n\r\n",
        usize::MAX
    );
    assert_eq!(
        p.feed(huge.as_bytes()),
        Err(RtspError::BodyLimit(LengthLimit {
            declared: usize::MAX,
            limit: DEFAULT_MAX_BODY_BYTES
        }))
    );
    for cseq in 2..5 {
        let later = format!("RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n\r\n");
        assert_eq!(
            p.feed(later.as_bytes()),
            Err(RtspError::Poisoned(PoisonCause::BodyLimit)),
            "later traffic must be refused loudly, never swallowed as Ok([])"
        );
    }
    assert_eq!(p.buffered_bytes(), 0);
    p.reset();
    assert_eq!(single_response_cseq(&p.feed(VALID_200)?)?, 2);
    Ok(())
}

#[test]
fn test_body_limit_then_valid_message_after_reset_kills_m82_m83_m84() -> Result<(), Box<dyn Error>>
{
    let limits = RtspLimits {
        max_body_bytes: 8,
        ..RtspLimits::default()
    };
    let mut wire = format!(
        "RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: {}\r\n\r\n",
        SMUGGLED.len()
    )
    .into_bytes();
    wire.extend_from_slice(SMUGGLED);
    let mut p = RtspParser::with_limits(limits);
    assert_eq!(
        p.feed(&wire),
        Err(RtspError::BodyLimit(LengthLimit {
            declared: SMUGGLED.len(),
            limit: 8
        }))
    );
    let res = p.feed(b"");
    assert_not_smuggled("body limit", &res);
    assert_eq!(res, Err(RtspError::Poisoned(PoisonCause::BodyLimit)));
    p.reset();
    assert_eq!(single_response_cseq(&p.feed(VALID_200)?)?, 2);

    // A header error whose single declared length is above the body limit also poisons.
    let mut p2 = RtspParser::with_limits(limits);
    assert!(matches!(
        p2.feed(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nCSeq: 2\r\nContent-Length: 100\r\n\r\n"),
        Err(RtspError::DuplicateCSeq(_))
    ));
    assert_eq!(p2.poisoned(), Some(PoisonCause::BodyLimit));
    assert_eq!(
        p2.feed(VALID_200),
        Err(RtspError::Poisoned(PoisonCause::BodyLimit))
    );
    Ok(())
}

#[test]
fn test_header_error_partial_body_discard_across_feeds() -> Result<(), Box<dyn Error>> {
    let n = SMUGGLED.len();
    let mut first = format!("RTSP/1.0 200 OK\r\nCSeq: 2\r\nCSeq: 3\r\nContent-Length: {n}\r\n\r\n")
        .into_bytes();
    first.extend_from_slice(&SMUGGLED[..10]);
    let mut p = RtspParser::new();
    assert_eq!(
        p.feed(&first),
        Err(RtspError::DuplicateCSeq(DuplicateHeader { offset: 26 }))
    );
    assert_eq!(p.buffered_bytes(), 0);
    assert_eq!(p.poisoned(), None);
    // Still inside the declared body: discarded, nothing surfaces.
    assert_eq!(p.feed(&SMUGGLED[10..20])?, Vec::new());
    assert_eq!(p.buffered_bytes(), 0);
    let mut rest = SMUGGLED[20..].to_vec();
    rest.extend_from_slice(b"RTSP/1.0 200 OK\r\nCSeq: 4\r\n\r\n");
    let res = p.feed(&rest);
    assert_not_smuggled("partial discard", &res);
    assert_eq!(single_response_cseq(&res?)?, 4);
    assert_eq!(p.buffered_bytes(), 0);

    // Same discard when the header error is pending behind an earlier event (probe b07).
    let mut p2 = RtspParser::new();
    let mut wire = b"OPTIONS rtsp://h RTSP/1.0\r\nCSeq: 1\r\n\r\n".to_vec();
    wire.extend_from_slice(
        b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nCSeq: 3\r\nContent-Length: 10\r\n\r\nabc",
    );
    let ev = p2.feed(&wire)?;
    assert!(matches!(ev.as_slice(), [RtspEvent::Request(_)]));
    assert_eq!(p2.buffered_bytes(), 0);
    assert!(matches!(
        p2.feed(b"defghijRTSP/1.0 200 OK\r\nCSeq: 4\r\n\r\n"),
        Err(RtspError::DuplicateCSeq(_))
    ));
    assert_eq!(single_response_cseq(&p2.feed(b"")?)?, 4);
    assert_eq!(p2.feed(b"")?, Vec::new());
    Ok(())
}

#[test]
fn test_unterminated_header_block_poisons() -> Result<(), Box<dyn Error>> {
    let limits = RtspLimits {
        max_line_bytes: 16,
        max_headers: 2,
        ..RtspLimits::default()
    };
    let mut p = RtspParser::with_limits(limits);
    let junk = [b'A'; 40];
    assert_eq!(
        p.feed(&junk),
        Err(RtspError::HeaderLimit(
            HeaderLimitFault::UnterminatedHeaderBlock {
                buffered: 40,
                limit: 32
            }
        ))
    );
    assert_eq!(
        p.feed(VALID_200),
        Err(RtspError::Poisoned(PoisonCause::UnterminatedHeaderBlock))
    );
    p.reset();
    assert_eq!(single_response_cseq(&p.feed(VALID_200)?)?, 2);
    Ok(())
}

#[test]
fn test_challenge_marker_keeps_status_cseq_session_and_body() -> Result<(), Box<dyn Error>> {
    // a01: a challenged 200 keeps status, CSeq, Session and body (kills M92, M93).
    let ev = RtspParser::new().feed(
        b"RTSP/1.0 200 OK\r\nCSeq: 5\r\nSession: 99;timeout=60\r\nWWW-Authenticate: Basic realm=\"R\"\r\nContent-Length: 4\r\n\r\nv=0\n",
    )?;
    let [RtspEvent::Response(resp)] = ev.as_slice() else {
        return Err(format!("expected one Response, got {ev:?}").into());
    };
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.headers.cseq().ok_or("missing CSeq")??, 5);
    assert_eq!(resp.headers.session_id(), Some("99"));
    assert_eq!(resp.headers.session_timeout(), Some(60));
    assert_eq!(resp.body, b"v=0\n");
    assert_eq!(resp.auth_challenge, Some(AuthScheme::Basic));
    assert_eq!(resp.headers.get("WWW-Authenticate"), None);

    // a03: a 401 keeps status, CSeq, Session and body inside AuthRequired.
    let ev = RtspParser::new().feed(
        b"RTSP/1.0 401 Unauthorized\r\nCSeq: 6\r\nSession: 77\r\nWWW-Authenticate: Digest realm=\"R\", nonce=\"NONCE401\"\r\nContent-Length: 2\r\n\r\nhi",
    )?;
    let [RtspEvent::AuthRequired { scheme, response }] = ev.as_slice() else {
        return Err(format!("expected one AuthRequired, got {ev:?}").into());
    };
    assert_eq!(*scheme, AuthScheme::Digest);
    assert_eq!(response.status_code, 401);
    assert_eq!(response.reason, "Unauthorized");
    assert_eq!(response.headers.cseq().ok_or("missing CSeq")??, 6);
    assert_eq!(response.headers.session_id(), Some("77"));
    assert_eq!(response.body, b"hi");
    assert_eq!(response.auth_challenge, Some(AuthScheme::Digest));
    assert!(!format!("{ev:?}").contains("NONCE401"));

    // a04: 200 + Proxy-Authenticate; case-insensitive scheme.
    let ev = RtspParser::new()
        .feed(b"RTSP/1.0 200 OK\r\nCSeq: 5\r\nProxy-Authenticate: dIgEsT nonce=\"N\"\r\n\r\n")?;
    assert!(
        matches!(ev.as_slice(), [RtspEvent::Response(r)] if r.auth_challenge == Some(AuthScheme::Digest))
    );

    // a02 / a06 / a07: other scheme tokens become a typed marker, never the token.
    for (id, wire, status) in [
        (
            "a02",
            &b"RTSP/1.0 200 OK\r\nCSeq: 5\r\nWWW-Authenticate: dXNlcjpwYXNz\r\n\r\n"[..],
            200,
        ),
        (
            "a06",
            b"RTSP/1.0 401 Unauthorized\r\nCSeq: 6\r\nWWW-Authenticate: dXNlcjpwYXNz\r\n\r\n",
            401,
        ),
        (
            "a07",
            b"RTSP/1.0 200 OK\r\nCSeq: 5\r\nWWW-Authenticate: Bearer\r\n\r\n",
            200,
        ),
    ] {
        let ev = RtspParser::new().feed(wire)?;
        assert!(!format!("{ev:?}").contains("dXNlcjpwYXNz"), "{id}");
        let resp = match ev.as_slice() {
            [RtspEvent::Response(r)] => r,
            [RtspEvent::AuthRequired { scheme, response }] => {
                assert_eq!(*scheme, AuthScheme::Other, "{id}");
                response
            }
            other => return Err(format!("{id}: unexpected events {other:?}").into()),
        };
        assert_eq!(resp.status_code, status, "{id}");
        assert_eq!(resp.auth_challenge, Some(AuthScheme::Other), "{id}");
    }
    Ok(())
}

#[test]
fn test_folded_continuation_after_content_length_poisons_b15b() -> Result<(), Box<dyn Error>> {
    let mut wire = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 4\r\n 7\r\n\r\nXXXX".to_vec();
    wire.extend_from_slice(SMUGGLED);

    let mut p = RtspParser::new();
    assert_eq!(p.feed(&wire), Err(RtspError::LineFoldingNotPermitted));
    assert_eq!(p.buffered_bytes(), 0);
    assert_eq!(p.poisoned(), Some(PoisonCause::AmbiguousContentLength));
    for _ in 0..3 {
        let res = p.feed(b"");
        assert_not_smuggled("b15b", &res);
        assert_eq!(
            res,
            Err(RtspError::Poisoned(PoisonCause::AmbiguousContentLength))
        );
    }
    let res = p.feed(VALID_200);
    assert_not_smuggled("b15b valid after poison", &res);
    assert_eq!(
        res,
        Err(RtspError::Poisoned(PoisonCause::AmbiguousContentLength))
    );
    p.reset();
    assert_eq!(single_response_cseq(&p.feed(VALID_200)?)?, 2);

    // Byte-at-a-time and with a tab continuation: the smuggled request never surfaces.
    let mut tab_wire =
        b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 4\r\n\t7\r\n\r\nXXXX".to_vec();
    tab_wire.extend_from_slice(SMUGGLED);
    for (id, w) in [("b15b bytewise", &wire), ("b15b tab bytewise", &tab_wire)] {
        let mut p2 = RtspParser::new();
        for b in w {
            let res = p2.feed(std::slice::from_ref(b));
            assert_not_smuggled(id, &res);
        }
        assert_eq!(
            p2.poisoned(),
            Some(PoisonCause::AmbiguousContentLength),
            "{id}"
        );
    }
    Ok(())
}

/// fss-0i0ue: the non-standard `\n\r\n` header terminator is deliberately not recognized.
/// The parser keeps waiting for a canonical `\r\n\r\n` or bare `\n\n`; once the buffered
/// header block exceeds the configured line/headers budget the session poisons with the
/// typed unterminated-header-block fault. This documents the refusal — recognizing `\n\r\n`
/// needs an owner decision backed by real device captures (file-ingest-first).
#[test]
fn lf_crlf_terminator_is_not_recognized_and_poisons_unterminated_fss_0i0ue()
-> Result<(), Box<dyn Error>> {
    // Deliberately tiny header budget so the poison fires within a few bytes.
    let limits = RtspLimits {
        max_line_bytes: 32,
        max_headers: 2,
        max_body_bytes: 256,
        max_interleaved_bytes: 256,
    };
    let mut parser = RtspParser::with_limits(limits);

    // Below the header budget: the partial terminator must simply wait (no events, no error).
    let waiting = b"RTSP/1.0 200 OK\r\nCSeq: 1\n\r\n";
    let events = parser.feed(&waiting[..waiting.len() - 1])?;
    assert!(
        events.is_empty(),
        "partial terminator must wait: {events:?}"
    );

    // Exceeding the header budget without a recognized terminator poisons the session.
    let flooded = b"RTSP/1.0 200 OK\r\nCSeq: 1\n\r\n" // begins with the non-standard terminator
        .iter()
        .copied()
        .chain(std::iter::repeat_n(b'x', 256))
        .collect::<Vec<u8>>();
    let poisoned = parser.feed(&flooded);
    assert!(
        poisoned.is_err(),
        "the unterminated header block must poison: {poisoned:?}"
    );
    let Err(err) = poisoned else {
        return Err("the unterminated header block must poison".into());
    };
    let err = err.to_string();
    assert!(
        err.contains("unterminated") || err.contains("header"),
        "expected the unterminated-header fault, got: {err}"
    );
    Ok(())
}

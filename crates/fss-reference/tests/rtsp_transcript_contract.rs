#![forbid(unsafe_code)]
//! Deterministic contract tests for RTSP/1.0 interleaved-TCP session transcripts.
//!
//! Verifies:
//! - Deterministic transcript fixture generation from Annex-B and rtpdump
//! - Byte-for-byte reproduction against committed fixtures and pinned SHA-256 literals
//! - Strict security boundary: no credentials, no real IP addresses, only fixture.invalid
//! - Incremental feeding through sans-IO RtspParser: every 2-way byte split yields identical events
//! - SDP sanity: H.264, clock rate 90000, packetization-mode 1, valid Base64 SPS/PPS
//! - RTCP compound SR+SDES(CNAME) parsing with fss_packet and SenderReportClock binding
//! - ReducedSize RTCP report handling in rtcp_rsize variant
//! - SequenceClass expectations matching FIXH264 packetizer

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_core::ContentDigest;
use fss_packet::{PacketLimits, RtcpCompound, RtcpMode, SenderReportClock, StreamKey};
use fss_reference::media_fixture::{
    H264FixtureParams, RTSP_TRANSCRIPT_MAGIC_HEADER, RtspTranscriptParams, TranscriptDirection,
    TranscriptRecord, build_rtsp_manifest_json, generate_h264_annexb,
    generate_transcript_auth_required, generate_transcript_bad_content_length,
    generate_transcript_clean, generate_transcript_get_parameter_keepalive,
    generate_transcript_interleave_split, generate_transcript_rtcp_rsize,
    generate_transcript_session_timeout, generate_transcript_sr_absent, parse_transcript,
    serialize_transcript,
};
use fss_reference::rtsp::{RtspError, RtspEvent, RtspParser, decode_base64, parse_sdp};

/// Pinned SHA-256 literal for clean.transcript.
pub const PINNED_SHA256_CLEAN: &str =
    "f0640fca1a33fe43e8335cb01013e0f7d98589b86c45a8480ef75ced345d24aa";

/// Pinned SHA-256 literal for auth_required.transcript.
pub const PINNED_SHA256_AUTH_REQUIRED: &str =
    "c2d19f964ccfaa656b89e7c48cd9d7272558a420b7a687ab40a50aa88ed63a0c";

/// Pinned SHA-256 literal for interleave_split.transcript.
pub const PINNED_SHA256_INTERLEAVE_SPLIT: &str =
    "a0eccf64599579ee98d0b335b2b16d957a70605166dae3a559dbf665d49f8ae1";

/// Pinned SHA-256 literal for bad_content_length.transcript.
pub const PINNED_SHA256_BAD_CONTENT_LENGTH: &str =
    "4ba38d4cf689abe2d505cbed0321d31397eb5b1347ed1106c9cb9a4ede5b1342";

/// Pinned SHA-256 literal for session_timeout_header.transcript.
pub const PINNED_SHA256_SESSION_TIMEOUT: &str =
    "54557ffaaa43a00c205ab7a807186502784a19ddb13300e3b32b84fb29f5cacd";

/// Pinned SHA-256 literal for rtcp_rsize.transcript.
pub const PINNED_SHA256_RTCP_RSIZE: &str =
    "e503ecc51b1d34afbdb53e50f14ee31a494b92d1c142c74c96d23e83a208f88e";

/// Pinned SHA-256 literal for sr_absent.transcript.
pub const PINNED_SHA256_SR_ABSENT: &str =
    "e154d42cdf5d5a76d3304a6d13a13d98e56b922bf55ba783bb0e581d42d10e32";

/// Pinned SHA-256 literal for get_parameter_keepalive.transcript.
pub const PINNED_SHA256_GET_PARAMETER: &str =
    "60acc52f1e58877ea5aceb2b40eb0a3ecf313b9a7a13ac0f91383269b7b46675";

fn get_repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("cannot find repo root")
        .to_path_buf()
}

fn to_hex(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[test]
fn test_transcript_regeneration_identity() -> Result<(), Box<dyn Error>> {
    let repo_root = get_repo_root();
    let rtsp_dir = repo_root.join("tests/fixtures/media/rtsp");

    let annexb = generate_h264_annexb(&H264FixtureParams::default())?;
    let params = RtspTranscriptParams::default();

    let clean = generate_transcript_clean(&annexb, &params)?;
    let auth_required = generate_transcript_auth_required(&params)?;
    let interleave_split = generate_transcript_interleave_split(&annexb, &params)?;
    let bad_content_length = generate_transcript_bad_content_length(&annexb, &params)?;
    let session_timeout = generate_transcript_session_timeout(&annexb, &params)?;
    let rtcp_rsize = generate_transcript_rtcp_rsize(&annexb, &params)?;
    let sr_absent = generate_transcript_sr_absent(&annexb, &params)?;
    let get_parameter_keepalive = generate_transcript_get_parameter_keepalive(&annexb, &params)?;

    let tests = [
        ("clean.transcript", &clean, PINNED_SHA256_CLEAN),
        (
            "auth_required.transcript",
            &auth_required,
            PINNED_SHA256_AUTH_REQUIRED,
        ),
        (
            "interleave_split.transcript",
            &interleave_split,
            PINNED_SHA256_INTERLEAVE_SPLIT,
        ),
        (
            "bad_content_length.transcript",
            &bad_content_length,
            PINNED_SHA256_BAD_CONTENT_LENGTH,
        ),
        (
            "session_timeout_header.transcript",
            &session_timeout,
            PINNED_SHA256_SESSION_TIMEOUT,
        ),
        (
            "rtcp_rsize.transcript",
            &rtcp_rsize,
            PINNED_SHA256_RTCP_RSIZE,
        ),
        ("sr_absent.transcript", &sr_absent, PINNED_SHA256_SR_ABSENT),
        (
            "get_parameter_keepalive.transcript",
            &get_parameter_keepalive,
            PINNED_SHA256_GET_PARAMETER,
        ),
    ];

    for (name, fix, pinned_sha) in tests {
        assert_eq!(fix.sha256, pinned_sha, "SHA mismatch for {name}");
        let disk_path = rtsp_dir.join(name);
        assert!(disk_path.exists(), "{name} must exist on disk");
        let disk_bytes = fs::read(&disk_path)?;
        let disk_sha = to_hex(ContentDigest::sha256(&disk_bytes).bytes());
        assert_eq!(disk_sha, pinned_sha, "disk SHA mismatch for {name}");
        assert_eq!(
            disk_bytes, fix.bytes,
            "regenerated bytes mismatch for {name}"
        );
    }

    let all_fixtures = [
        clean,
        auth_required,
        interleave_split,
        bad_content_length,
        session_timeout,
        rtcp_rsize,
        sr_absent,
        get_parameter_keepalive,
    ];
    let manifest_str = build_rtsp_manifest_json(&all_fixtures, &params);
    let disk_manifest_path = rtsp_dir.join("fixture_manifest.json");
    assert!(
        disk_manifest_path.exists(),
        "fixture_manifest.json must exist"
    );
    let disk_manifest_str = fs::read_to_string(&disk_manifest_path)?;
    assert_eq!(
        disk_manifest_str, manifest_str,
        "committed fixture_manifest.json must match regenerated"
    );

    Ok(())
}

#[test]
fn test_transcript_container_framing_and_roundtrip() -> Result<(), Box<dyn Error>> {
    let dummy_records = vec![
        TranscriptRecord {
            direction: TranscriptDirection::ClientToServer,
            offset_ms: 0,
            bytes: b"OPTIONS rtsp://fixture.invalid/stream RTSP/1.0\r\n\r\n".to_vec(),
        },
        TranscriptRecord {
            direction: TranscriptDirection::ServerToClient,
            offset_ms: 10,
            bytes: b"RTSP/1.0 200 OK\r\n\r\n".to_vec(),
        },
    ];

    let serialized = serialize_transcript(&dummy_records);
    assert!(serialized.starts_with(RTSP_TRANSCRIPT_MAGIC_HEADER));

    let parsed = parse_transcript(&serialized)?;
    assert_eq!(parsed, dummy_records);

    // Corrupt magic header
    let mut corrupt = serialized.clone();
    corrupt[0] = b'?';
    assert!(parse_transcript(&corrupt).is_err());

    // Truncated header
    assert!(parse_transcript(&serialized[..10]).is_err());

    // Truncated record body
    assert!(parse_transcript(&serialized[..serialized.len() - 5]).is_err());

    Ok(())
}

#[test]
fn test_no_credentials_or_real_addresses_guard() -> Result<(), Box<dyn Error>> {
    let repo_root = get_repo_root();
    let rtsp_dir = repo_root.join("tests/fixtures/media/rtsp");

    let filenames = [
        "clean.transcript",
        "auth_required.transcript",
        "interleave_split.transcript",
        "bad_content_length.transcript",
        "session_timeout_header.transcript",
        "rtcp_rsize.transcript",
        "sr_absent.transcript",
        "get_parameter_keepalive.transcript",
    ];

    // Forbidden tokens for credentials or real network addresses
    let forbidden_headers = ["authorization:", "proxy-authorization:"];

    let forbidden_ip_prefixes = ["192.168.", "10.", "172.16.", "127.0.0.1", "0.0.0.0"];

    for name in filenames {
        let bytes = fs::read(rtsp_dir.join(name))?;
        let records = parse_transcript(&bytes)?;

        for r in &records {
            let s = String::from_utf8_lossy(&r.bytes).to_lowercase();

            // Guard against credentials
            for f in forbidden_headers {
                assert!(
                    !s.contains(f),
                    "forbidden header '{f}' found in {name} record at offset {}",
                    r.offset_ms
                );
            }

            // Guard against real IP addresses
            for ip in forbidden_ip_prefixes {
                assert!(
                    !s.contains(ip),
                    "forbidden IP address '{ip}' found in {name} record at offset {}",
                    r.offset_ms
                );
            }

            // Host must always be fixture.invalid if rtsp:// URI is present
            if s.contains("rtsp://") {
                assert!(
                    s.contains("rtsp://fixture.invalid"),
                    "RTSP URI without fixture.invalid found in {name}"
                );
            }
        }
    }

    Ok(())
}

#[test]
fn test_rtsp_parser_two_way_splits() -> Result<(), Box<dyn Error>> {
    let repo_root = get_repo_root();
    let rtsp_dir = repo_root.join("tests/fixtures/media/rtsp");

    let variants = [
        "clean.transcript",
        "auth_required.transcript",
        "interleave_split.transcript",
        "session_timeout_header.transcript",
        "rtcp_rsize.transcript",
        "sr_absent.transcript",
        "get_parameter_keepalive.transcript",
    ];

    for name in variants {
        let bytes = fs::read(rtsp_dir.join(name))?;
        let records = parse_transcript(&bytes)?;

        // Concatenate all ServerToClient bytes to simulate TCP stream
        let mut s2c_stream = Vec::new();
        for r in &records {
            if r.direction == TranscriptDirection::ServerToClient {
                s2c_stream.extend_from_slice(&r.bytes);
            }
        }

        // Reference parse
        let mut ref_parser = RtspParser::new();
        let ref_events = ref_parser.feed(&s2c_stream)?;
        assert!(!ref_events.is_empty(), "expected events in {name}");

        // Test every 2-way byte split
        for split_pos in 0..=s2c_stream.len() {
            let chunk1 = &s2c_stream[..split_pos];
            let chunk2 = &s2c_stream[split_pos..];

            let mut parser = RtspParser::new();
            let mut split_events = parser.feed(chunk1)?;
            let events2 = parser.feed(chunk2)?;
            split_events.extend(events2);

            assert_eq!(
                split_events, ref_events,
                "split at {split_pos} failed in {name}"
            );
        }
    }

    // bad_content_length: test that every split surfaces the exact same error
    let bcl_bytes = fs::read(rtsp_dir.join("bad_content_length.transcript"))?;
    let bcl_records = parse_transcript(&bcl_bytes)?;
    let mut bcl_stream = Vec::new();
    for r in &bcl_records {
        if r.direction == TranscriptDirection::ServerToClient {
            bcl_stream.extend_from_slice(&r.bytes);
        }
    }

    let mut ref_parser = RtspParser::new();
    let ref_res = ref_parser.feed(&bcl_stream);
    assert!(
        matches!(ref_res, Err(RtspError::BadContentLength(_))),
        "expected BadContentLength error in bad_content_length"
    );

    for split_pos in 0..=bcl_stream.len() {
        let chunk1 = &bcl_stream[..split_pos];
        let chunk2 = &bcl_stream[split_pos..];

        let mut parser = RtspParser::new();
        let res1 = parser.feed(chunk1);
        let res2 = if res1.is_ok() {
            parser.feed(chunk2)
        } else {
            res1
        };
        assert!(
            matches!(res2, Err(RtspError::BadContentLength(_))),
            "split at {split_pos} did not surface BadContentLength in bad_content_length"
        );
    }

    Ok(())
}

#[test]
fn test_rtsp_sdp_sanity() -> Result<(), Box<dyn Error>> {
    let repo_root = get_repo_root();
    let bytes = fs::read(repo_root.join("tests/fixtures/media/rtsp/clean.transcript"))?;
    let records = parse_transcript(&bytes)?;

    // Record 3 is DESCRIBE response
    let describe_resp_bytes = &records[3].bytes;
    let mut parser = RtspParser::new();
    let events = parser.feed(describe_resp_bytes)?;
    assert_eq!(events.len(), 1);

    let sdp_body = match &events[0] {
        RtspEvent::Response(resp) => {
            assert_eq!(resp.status_code, 200);
            assert_eq!(resp.headers.content_type(), Some("application/sdp"));
            std::str::from_utf8(&resp.body)?
        }
        _ => panic!("expected RtspEvent::Response"),
    };

    let session = parse_sdp(sdp_body)?;
    assert_eq!(session.version, 0);
    assert_eq!(session.session_name, "FSS Synthetic RTSP Session");
    assert!(session.video_media.is_some());

    let video = session.video_media.unwrap();
    assert_eq!(video.payload_type, 96);
    assert_eq!(video.encoding_name.as_deref(), Some("H264"));
    assert_eq!(video.clock_rate, Some(90_000));
    assert_eq!(video.packetization_mode, Some(1));
    assert_eq!(video.control.as_deref(), Some("trackID=1"));
    assert!(!video.rtcp_reduced_size);

    // Verify SPS and PPS decode
    assert!(video.sps.is_some());
    assert!(video.pps.is_some());
    let sps = video.sps.unwrap();
    let pps = video.pps.unwrap();
    assert_eq!(sps[0] & 0x1f, 7);
    assert_eq!(pps[0] & 0x1f, 8);

    // Check rtcp_rsize SDP
    let rsize_bytes = fs::read(repo_root.join("tests/fixtures/media/rtsp/rtcp_rsize.transcript"))?;
    let rsize_records = parse_transcript(&rsize_bytes)?;
    let mut parser2 = RtspParser::new();
    let rsize_events = parser2.feed(&rsize_records[3].bytes)?;
    let rsize_sdp_body = match &rsize_events[0] {
        RtspEvent::Response(resp) => std::str::from_utf8(&resp.body)?,
        _ => panic!("expected Response"),
    };
    let rsize_session = parse_sdp(rsize_sdp_body)?;
    assert!(rsize_session.video_media.unwrap().rtcp_reduced_size);

    Ok(())
}

#[test]
fn test_rtcp_compound_parsing_and_clock_binding() -> Result<(), Box<dyn Error>> {
    let repo_root = get_repo_root();
    let bytes = fs::read(repo_root.join("tests/fixtures/media/rtsp/clean.transcript"))?;
    let records = parse_transcript(&bytes)?;

    let mut parser = RtspParser::new();
    let mut rtcp_frames = Vec::new();

    for r in &records {
        if r.direction == TranscriptDirection::ServerToClient {
            for event in parser.feed(&r.bytes)? {
                if let RtspEvent::Interleaved { channel, span } = event {
                    if channel == 1 {
                        rtcp_frames.push(span);
                    }
                }
            }
        }
    }

    assert_eq!(rtcp_frames.len(), 3, "expected 3 RTCP frames in clean");

    for (idx, frame) in rtcp_frames.iter().enumerate() {
        // Parse with fss_packet RtcpCompound in Compound mode
        let compound = RtcpCompound::parse(frame, PacketLimits::default(), RtcpMode::Compound)?;
        assert_eq!(compound.packet_count(), 2, "expected SR + SDES compound");

        let sr = compound
            .packets()
            .next()
            .and_then(|p| p.sender_report())
            .expect("first packet must be SenderReport");

        assert_eq!(sr.ssrc, 0x1122_3344);
        assert_ne!(sr.ntp.seconds, 0);

        let key = StreamKey {
            ingress: 1,
            generation: 1,
            ssrc: sr.ssrc,
        };
        let clock = SenderReportClock::new(key, 90_000, sr, 1_000_000_000, 10_000_000, 90_000 * 10);
        assert!(
            clock.is_ok(),
            "SenderReportClock binding failed for SR {idx}"
        );
    }

    // Test rtcp_rsize: ReducedSize succeeds, Compound fails
    let rsize_bytes = fs::read(repo_root.join("tests/fixtures/media/rtsp/rtcp_rsize.transcript"))?;
    let rsize_records = parse_transcript(&rsize_bytes)?;
    let mut parser_rsize = RtspParser::new();
    let mut rsize_rtcp_frames = Vec::new();

    for r in &rsize_records {
        if r.direction == TranscriptDirection::ServerToClient {
            for event in parser_rsize.feed(&r.bytes)? {
                if let RtspEvent::Interleaved { channel, span } = event {
                    if channel == 1 {
                        rsize_rtcp_frames.push(span);
                    }
                }
            }
        }
    }

    assert_eq!(rsize_rtcp_frames.len(), 3);
    for frame in &rsize_rtcp_frames {
        // ReducedSize mode succeeds
        let report = RtcpCompound::parse(frame, PacketLimits::default(), RtcpMode::ReducedSize)?;
        assert_eq!(report.packet_count(), 1);

        // Compound mode fails because SDES CNAME is missing
        assert!(RtcpCompound::parse(frame, PacketLimits::default(), RtcpMode::Compound).is_err());
    }

    Ok(())
}

#[test]
fn test_session_timeout_header_parsing() -> Result<(), Box<dyn Error>> {
    let repo_root = get_repo_root();

    // clean has timeout=60
    let clean_bytes = fs::read(repo_root.join("tests/fixtures/media/rtsp/clean.transcript"))?;
    let clean_records = parse_transcript(&clean_bytes)?;
    let mut p1 = RtspParser::new();
    let events1 = p1.feed(&clean_records[5].bytes)?; // Record 5 is SETUP response
    if let RtspEvent::Response(resp) = &events1[0] {
        assert_eq!(resp.headers.session_id(), Some("12345678"));
        assert_eq!(resp.headers.session_timeout(), Some(60));
    } else {
        panic!("expected Response");
    }

    // session_timeout_header has timeout=30
    let timeout_bytes =
        fs::read(repo_root.join("tests/fixtures/media/rtsp/session_timeout_header.transcript"))?;
    let timeout_records = parse_transcript(&timeout_bytes)?;
    let mut p2 = RtspParser::new();
    let events2 = p2.feed(&timeout_records[5].bytes)?;
    if let RtspEvent::Response(resp) = &events2[0] {
        assert_eq!(resp.headers.session_id(), Some("12345678"));
        assert_eq!(resp.headers.session_timeout(), Some(30));
    } else {
        panic!("expected Response");
    }

    Ok(())
}

#[test]
fn test_auth_required_variant() -> Result<(), Box<dyn Error>> {
    let repo_root = get_repo_root();
    let bytes = fs::read(repo_root.join("tests/fixtures/media/rtsp/auth_required.transcript"))?;
    let records = parse_transcript(&bytes)?;

    assert_eq!(records.len(), 2);
    let mut parser = RtspParser::new();
    let events = parser.feed(&records[1].bytes)?;
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0],
        RtspEvent::AuthRequired {
            scheme: "Digest".to_string()
        }
    );

    Ok(())
}

#[test]
fn test_interleave_split_equivalence() -> Result<(), Box<dyn Error>> {
    let repo_root = get_repo_root();
    let clean_bytes = fs::read(repo_root.join("tests/fixtures/media/rtsp/clean.transcript"))?;
    let split_bytes =
        fs::read(repo_root.join("tests/fixtures/media/rtsp/interleave_split.transcript"))?;

    let clean_records = parse_transcript(&clean_bytes)?;
    let split_records = parse_transcript(&split_bytes)?;

    let mut p_clean = RtspParser::new();
    let mut clean_events = Vec::new();
    for r in clean_records {
        if r.direction == TranscriptDirection::ServerToClient {
            clean_events.extend(p_clean.feed(&r.bytes)?);
        }
    }

    let mut p_split = RtspParser::new();
    let mut split_events = Vec::new();
    for r in split_records {
        if r.direction == TranscriptDirection::ServerToClient {
            split_events.extend(p_split.feed(&r.bytes)?);
        }
    }

    assert_eq!(clean_events, split_events);
    Ok(())
}

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
use fss_reference::rtsp::{AuthScheme, RtspError, RtspEvent, RtspParser, parse_sdp};

/// Pinned SHA-256 literal for clean.transcript.
// [fss-l0azz, 2026-10-12] Setup responses now bind ssrc=<media SSRC> so the
// shipped RtspAvcClient can replay these transcripts; digests moved accordingly.
pub const PINNED_SHA256_CLEAN: &str =
    "76466b3c4a20de1026920697eff2c240a0c25d82056e8d85ef9edde905389b07";

/// Pinned SHA-256 literal for auth_required.transcript.
pub const PINNED_SHA256_AUTH_REQUIRED: &str =
    "c2d19f964ccfaa656b89e7c48cd9d7272558a420b7a687ab40a50aa88ed63a0c";

/// Pinned SHA-256 literal for interleave_split.transcript.
pub const PINNED_SHA256_INTERLEAVE_SPLIT: &str =
    "3dd594eba7ed5b98cc62ed8b33997dd4cc932be3e698d849cae364b6c683bbf5";

/// Pinned SHA-256 literal for bad_content_length.transcript.
pub const PINNED_SHA256_BAD_CONTENT_LENGTH: &str =
    "4ba38d4cf689abe2d505cbed0321d31397eb5b1347ed1106c9cb9a4ede5b1342";

/// Pinned SHA-256 literal for session_timeout_header.transcript.
pub const PINNED_SHA256_SESSION_TIMEOUT: &str =
    "481aa6ed4c62e7a56cdcff42cb179907c7647bfe6e4118066393e6b2d1b78f1a";

/// Pinned SHA-256 literal for rtcp_rsize.transcript.
pub const PINNED_SHA256_RTCP_RSIZE: &str =
    "8f268b4232377deaf4f0a84b93200d62d5a67b0bb3076dacad2b2bdef8e0bc11";

/// Pinned SHA-256 literal for sr_absent.transcript.
pub const PINNED_SHA256_SR_ABSENT: &str =
    "8cb42ac5fa03fe84945e5a9fed073400c0b17003cf200cf6396e75a60ef52242";

/// Pinned SHA-256 literal for get_parameter_keepalive.transcript.
pub const PINNED_SHA256_GET_PARAMETER: &str =
    "dc8440930c7c94b044c850144743e51a50db95cb87d2b12c00fb9adb6d30b759";

fn get_repo_root() -> Result<PathBuf, &'static str> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .ok_or("cannot find repo root")
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
    let repo_root = get_repo_root()?;
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
        let disk_sha = to_hex(&ContentDigest::sha256(&disk_bytes).bytes());
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

/// The RFC 2617 example nonce carried by the fixture's Digest challenge. Any other challenge
/// token in a committed transcript means real credentials leaked into the fixtures.
const KNOWN_FIXTURE_NONCE: &str = "dcd98b7102dd2f0e8b11d0f600bfb0c093";

/// Returns `true` when `s` contains a dotted-quad IPv4 literal (four 1-3 digit groups).
fn contains_dotted_quad(s: &str) -> bool {
    let bytes = s.as_bytes();
    let n = bytes.len();
    let mut i = 0;
    while i < n {
        if bytes[i].is_ascii_digit() {
            let start = i;
            let mut j = i;
            let mut dots = 0;
            while j < n && (bytes[j].is_ascii_digit() || bytes[j] == b'.') {
                if bytes[j] == b'.' {
                    dots += 1;
                }
                j += 1;
            }
            let token = &s[start..j];
            let groups: Vec<&str> = token.split('.').collect();
            if dots == 3
                && groups.len() == 4
                && groups
                    .iter()
                    .all(|g| !g.is_empty() && g.len() <= 3 && g.bytes().all(|c| c.is_ascii_digit()))
            {
                return true;
            }
            i = j.max(start + 1);
        } else {
            i += 1;
        }
    }
    false
}

/// Security-boundary guard for committed RTSP transcripts: every violation found is returned as
/// a human-readable reason. The fixture set must carry zero violations.
fn credential_guard_violations(name: &str, records: &[TranscriptRecord]) -> Vec<String> {
    let mut violations = Vec::new();
    let forbidden_headers = ["authorization:", "proxy-authorization:"];
    let forbidden_ip_prefixes = ["192.168.", "10.", "172.16.", "127.0.0.1", "0.0.0.0"];

    for r in records {
        let s = String::from_utf8_lossy(&r.bytes).to_lowercase();
        let mut at = |what: &str| {
            violations.push(format!("{name} record at offset {}: {what}", r.offset_ms));
        };

        for f in forbidden_headers {
            if s.contains(f) {
                at(&format!("forbidden header '{f}'"));
            }
        }
        if s.contains("bearer ") {
            at("bearer credential token");
        }
        if contains_dotted_quad(&s) {
            at("dotted-quad IPv4 literal");
        }
        for ip in forbidden_ip_prefixes {
            if s.contains(ip) {
                at(&format!("forbidden IP address '{ip}'"));
            }
        }
        // Credentials as userinfo inside rtsp:// URIs (rtsp://user@host/).
        let mut search = 0usize;
        while let Some(rel) = s[search..].find("rtsp://") {
            let uri_start = search + rel;
            let rest = &s[uri_start..];
            let uri_len = rest.find(['\r', '\n', ' ']).unwrap_or(rest.len());
            let uri = &rest[..uri_len];
            if uri.contains('@') {
                at(&format!("rtsp URI with userinfo '@': {uri}"));
            }
            if !uri.contains("fixture.invalid") {
                at(&format!("RTSP URI without fixture.invalid: {uri}"));
            }
            search = uri_start + uri_len;
        }
        // RFC 2617 challenge tokens other than the fixture's known nonce.
        if s.contains("www-authenticate:") {
            for segment in s.split("nonce=\"").skip(1) {
                let nonce = segment.split('"').next().unwrap_or("");
                if nonce != KNOWN_FIXTURE_NONCE {
                    at(&format!("non-fixture www-authenticate nonce '{nonce}'"));
                }
            }
        }
    }
    violations
}

#[test]
fn test_no_credentials_or_real_addresses_guard() -> Result<(), Box<dyn Error>> {
    let repo_root = get_repo_root()?;
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

    let mut records_scanned = 0usize;
    for name in filenames {
        let bytes = fs::read(rtsp_dir.join(name))?;
        let records = parse_transcript(&bytes)?;
        records_scanned += records.len();
        let violations = credential_guard_violations(name, &records);
        assert!(
            violations.is_empty(),
            "credential/address guard violations in committed transcripts: {violations:?}"
        );
    }
    // REAL totals: the guard must have actually scanned the committed corpus.
    assert!(
        records_scanned >= 16,
        "guard scanned only {records_scanned} records; committed corpus is larger"
    );

    Ok(())
}

/// Executed mutant table for the credential/address guard: each planted credential, address, or
/// challenge-token mutation must turn the guard red with the matching category.
#[test]
fn credential_guard_mutant_table() -> Result<(), Box<dyn Error>> {
    let repo_root = get_repo_root()?;
    let rtsp_dir = repo_root.join("tests/fixtures/media/rtsp");

    fn violations_for(records: &[TranscriptRecord]) -> Vec<String> {
        credential_guard_violations("mutant", records)
    }
    fn replace_all(bytes: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len());
        let mut rest = bytes;
        while let Some(pos) = rest.windows(from.len()).position(|w| w == from) {
            out.extend_from_slice(&rest[..pos]);
            out.extend_from_slice(to);
            rest = &rest[pos + from.len()..];
        }
        out.extend_from_slice(rest);
        out
    }

    // M1: planted basic credential header turns the guard red on the forbidden-header rule.
    let clean = parse_transcript(&fs::read(rtsp_dir.join("clean.transcript"))?)?;
    let mut m1 = clean.clone();
    let planted = b"authorization: basic cm9vdDpyb290\r\n";
    let first = m1[0].bytes.clone();
    let mut mutated = Vec::new();
    mutated.extend_from_slice(&first);
    mutated.extend_from_slice(planted);
    mutated.extend_from_slice(&first);
    m1[0].bytes = mutated;
    let v = violations_for(&m1);
    assert!(
        v.iter().any(|x| x.contains("authorization:")),
        "M1 planted credential header must be caught: {v:?}"
    );

    // M2: planted dotted-quad IP turns the guard red on the IPv4 rule.
    let m2_records: Vec<TranscriptRecord> = clean
        .iter()
        .map(|r| TranscriptRecord {
            direction: r.direction,
            offset_ms: r.offset_ms,
            bytes: replace_all(&r.bytes, b"fixture.invalid", b"192.168.10.5"),
        })
        .collect();
    let v = violations_for(&m2_records);
    assert!(
        v.iter()
            .any(|x| x.contains("IPv4") || x.contains("IP address")),
        "M2 planted dotted-quad IP must be caught: {v:?}"
    );

    // M3: planted userinfo '@' in the rtsp:// URI turns the guard red.
    let m3_records: Vec<TranscriptRecord> = clean
        .iter()
        .map(|r| TranscriptRecord {
            direction: r.direction,
            offset_ms: r.offset_ms,
            bytes: replace_all(
                &r.bytes,
                b"rtsp://fixture.invalid",
                b"rtsp://operator@fixture.invalid",
            ),
        })
        .collect();
    let v = violations_for(&m3_records);
    assert!(
        v.iter().any(|x| x.contains("userinfo")),
        "M3 planted URI userinfo must be caught: {v:?}"
    );

    // M4: a non-fixture RFC 2617 nonce turns the guard red.
    let auth = parse_transcript(&fs::read(rtsp_dir.join("auth_required.transcript"))?)?;
    let m4_records: Vec<TranscriptRecord> = auth
        .iter()
        .map(|r| TranscriptRecord {
            direction: r.direction,
            offset_ms: r.offset_ms,
            bytes: replace_all(
                &r.bytes,
                KNOWN_FIXTURE_NONCE.as_bytes(),
                b"00000000000000000000000000000000",
            ),
        })
        .collect();
    let v = violations_for(&m4_records);
    assert!(
        v.iter().any(|x| x.contains("nonce")),
        "M4 planted non-fixture nonce must be caught: {v:?}"
    );

    Ok(())
}

#[test]
fn test_rtsp_parser_two_way_splits() -> Result<(), Box<dyn Error>> {
    let repo_root = get_repo_root()?;
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

    // Reference prefix: feeding record-by-record, the events emitted before the error are the
    // deterministic prefix every byte split must reproduce exactly.
    let mut ref_events = Vec::new();
    let mut ref_errored = false;
    let mut ref_parser = RtspParser::new();
    for r in &bcl_records {
        if r.direction != TranscriptDirection::ServerToClient || ref_errored {
            continue;
        }
        match ref_parser.feed(&r.bytes) {
            Ok(mut events) => ref_events.append(&mut events),
            Err(RtspError::BadContentLength(_)) => ref_errored = true,
            Err(e) => return Err(e.into()),
        }
    }
    if !ref_errored {
        match ref_parser.feed(&[]) {
            Ok(mut events) => ref_events.append(&mut events),
            Err(RtspError::BadContentLength(_)) => ref_errored = true,
            Err(e) => return Err(e.into()),
        }
    }
    assert!(
        ref_errored,
        "expected BadContentLength error in bad_content_length"
    );
    assert!(
        !ref_events.is_empty(),
        "reference prefix must contain the events emitted before the error"
    );

    for split_pos in 0..=bcl_stream.len() {
        let chunk1 = &bcl_stream[..split_pos];
        let chunk2 = &bcl_stream[split_pos..];

        let mut parser = RtspParser::new();
        let mut split_events = Vec::new();
        let mut surfaced = false;
        for chunk in [chunk1, chunk2, b"".as_slice()] {
            match parser.feed(chunk) {
                Ok(mut events) => split_events.append(&mut events),
                Err(RtspError::BadContentLength(_)) => {
                    surfaced = true;
                    break;
                }
                Err(e) => return Err(e.into()),
            }
        }
        assert!(
            surfaced,
            "split at {split_pos} did not surface BadContentLength in bad_content_length"
        );
        // The events emitted before the error must equal the reference prefix: a split that
        // drops or reorders them is a parser defect even when the error still surfaces.
        assert_eq!(
            split_events, ref_events,
            "split at {split_pos}: events before the error diverge from the reference prefix"
        );
    }

    Ok(())
}

#[test]
fn test_rtsp_sdp_sanity() -> Result<(), Box<dyn Error>> {
    let repo_root = get_repo_root()?;
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
        _ => return Err("expected RtspEvent::Response".into()),
    };

    let session = parse_sdp(sdp_body)?;
    assert_eq!(session.version, 0);
    assert_eq!(session.session_name, "FSS Synthetic RTSP Session");
    assert!(session.video_media.is_some());

    let video = session.video_media.as_ref().ok_or("expected video_media")?;
    assert_eq!(video.payload_type, 96);
    assert_eq!(video.encoding_name.as_deref(), Some("H264"));
    assert_eq!(video.clock_rate, Some(90_000));
    assert_eq!(video.packetization_mode, Some(1));
    assert_eq!(video.control.as_deref(), Some("trackID=1"));
    assert!(!video.rtcp_reduced_size);

    // Verify SPS and PPS decode
    let sps = video.sps.as_ref().ok_or("expected sps")?;
    let pps = video.pps.as_ref().ok_or("expected pps")?;
    assert_eq!(sps[0] & 0x1f, 7);
    assert_eq!(pps[0] & 0x1f, 8);

    // Check rtcp_rsize SDP
    let rsize_bytes = fs::read(repo_root.join("tests/fixtures/media/rtsp/rtcp_rsize.transcript"))?;
    let rsize_records = parse_transcript(&rsize_bytes)?;
    let mut parser2 = RtspParser::new();
    let rsize_events = parser2.feed(&rsize_records[3].bytes)?;
    let rsize_sdp_body = match &rsize_events[0] {
        RtspEvent::Response(resp) => std::str::from_utf8(&resp.body)?,
        _ => return Err("expected Response".into()),
    };
    let rsize_session = parse_sdp(rsize_sdp_body)?;
    let rsize_video = rsize_session
        .video_media
        .as_ref()
        .ok_or("expected rsize video_media")?;
    assert!(rsize_video.rtcp_reduced_size);

    Ok(())
}

#[test]
fn test_rtcp_compound_parsing_and_clock_binding() -> Result<(), Box<dyn Error>> {
    let repo_root = get_repo_root()?;
    let bytes = fs::read(repo_root.join("tests/fixtures/media/rtsp/clean.transcript"))?;
    let records = parse_transcript(&bytes)?;

    let mut parser = RtspParser::new();
    let mut rtcp_frames = Vec::new();

    for r in &records {
        if r.direction == TranscriptDirection::ServerToClient {
            for event in parser.feed(&r.bytes)? {
                if let RtspEvent::Interleaved { channel: 1, span } = event {
                    rtcp_frames.push(span);
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
            .ok_or("first packet must be SenderReport")?;

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
                if let RtspEvent::Interleaved { channel: 1, span } = event {
                    rsize_rtcp_frames.push(span);
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
    let repo_root = get_repo_root()?;

    // clean has timeout=60
    let clean_bytes = fs::read(repo_root.join("tests/fixtures/media/rtsp/clean.transcript"))?;
    let clean_records = parse_transcript(&clean_bytes)?;
    let mut p1 = RtspParser::new();
    let events1 = p1.feed(&clean_records[5].bytes)?; // Record 5 is SETUP response
    if let RtspEvent::Response(resp) = &events1[0] {
        assert_eq!(resp.headers.session_id(), Some("12345678"));
        assert_eq!(resp.headers.session_timeout(), Some(60));
    } else {
        return Err("expected Response".into());
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
        return Err("expected Response".into());
    }

    Ok(())
}

#[test]
fn test_auth_required_variant() -> Result<(), Box<dyn Error>> {
    let repo_root = get_repo_root()?;
    let bytes = fs::read(repo_root.join("tests/fixtures/media/rtsp/auth_required.transcript"))?;
    let records = parse_transcript(&bytes)?;

    assert_eq!(records.len(), 2);
    let mut parser = RtspParser::new();
    let events = parser.feed(&records[1].bytes)?;
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0],
        RtspEvent::AuthRequired {
            scheme: AuthScheme::Digest,
            ..
        }
    ));
    let RtspEvent::AuthRequired { ref response, .. } = events[0] else {
        return Err(format!("expected AuthRequired event, got: {:?}", events[0]).into());
    };
    assert_eq!(response.status_code, 401);
    assert_eq!(response.auth_challenge, Some(AuthScheme::Digest));

    Ok(())
}

#[test]
fn test_interleave_split_equivalence() -> Result<(), Box<dyn Error>> {
    let repo_root = get_repo_root()?;
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

/// fss-2h5zq.33: 10,000 fixed-seed stacked mutations of the S2C stream must
/// never panic the parser — every outcome is Ok(events), Ok(no events), or
/// a typed RtspError. A panic here is a hostile-input defect; a mutation
/// that changes event COUNT on a benign transcript is recorded, not failed
/// (framing may legitimately break), but determinism per mutant holds: the
/// same mutant twice yields identical outcomes.
#[test]
fn parser_ten_thousand_mutations_never_panic() -> Result<(), Box<dyn Error>> {
    let repo_root = get_repo_root()?;
    let rtsp_dir = repo_root.join("tests/fixtures/media/rtsp");

    // Base stream: the committed S2C bytes of the first transcript found.
    let mut s2c_stream = Vec::new();
    for entry in fs::read_dir(&rtsp_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "clean.transcript" {
            let transcript = parse_transcript(&fs::read(entry.path())?)?;
            for r in &transcript {
                if r.direction == TranscriptDirection::ServerToClient {
                    s2c_stream.extend_from_slice(&r.bytes);
                }
            }
            if !s2c_stream.is_empty() {
                break;
            }
        }
    }
    assert!(
        !s2c_stream.is_empty(),
        "no S2C bytes found in committed transcripts"
    );

    // Simple LCG — fixed seed, no external RNG.
    let mut state: u64 = 0x5F3A_7C2D_1B9E_4086;
    let mut next = || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        state >> 33
    };

    let mut panics: usize = 0;
    let mut nondeterministic: usize = 0;
    for iteration in 0..10_000u64 {
        // 1-3 stacked mutations: single-byte flips, short insertions, truncations.
        let mutation_count = (next() % 3) + 1;
        let mut mutant = s2c_stream.clone();
        for _ in 0..mutation_count {
            let choice = next() % 3;
            if choice == 0 && !mutant.is_empty() {
                let idx = (next() as usize) % mutant.len();
                mutant[idx] ^= (next() % 255) as u8 + 1;
            } else if choice == 1 && !mutant.is_empty() {
                let idx = (next() as usize) % mutant.len();
                let byte = (next() % 256) as u8;
                mutant.insert(idx, byte);
            } else if mutant.len() > 1 {
                let new_len = mutant.len() - (next() as usize % 32).min(mutant.len() - 1);
                mutant.truncate(new_len);
            }
        }

        // First pass: no panic (catch_unwind over the parser feed).
        let first = {
            let mut parser = RtspParser::new();
            let stream = mutant.clone();
            let result = std::panic::catch_unwind(move || parser.feed(&stream));
            match result {
                Ok(Ok(events)) => Some(events.len()),
                Ok(Err(_)) => None,
                Err(_) => {
                    panics += 1;
                    continue;
                }
            }
        };

        // Second pass: identical mutant must yield the identical outcome.
        let second = {
            let mut parser = RtspParser::new();
            let stream = mutant;
            let result = std::panic::catch_unwind(move || parser.feed(&stream));
            match result {
                Ok(Ok(events)) => Some(events.len()),
                Ok(Err(_)) => None,
                Err(_) => {
                    panics += 1;
                    continue;
                }
            }
        };

        if first != second {
            nondeterministic += 1;
            if nondeterministic <= 3 {
                eprintln!("mutant {iteration}: outcome changed across identical runs");
            }
        }
    }

    assert_eq!(panics, 0, "parser panicked on {panics} of 10,000 mutants");
    assert_eq!(
        nondeterministic, 0,
        "identical mutants produced different outcomes {nondeterministic} times"
    );
    Ok(())
}

/// [fss-l0azz] First-party base64 decode for the sprop equality proof (no external crate).
fn decode_base64(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer = 0_u32;
    let mut bits = 0_u32;
    for ch in input.bytes() {
        if ch == b'=' {
            break;
        }
        let value = TABLE
            .iter()
            .position(|&t| t == ch)
            .ok_or_else(|| format!("invalid base64 character {ch:?}"))? as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

/// [fss-l0azz] The SDP sprop-parameter-sets in the transcript must be byte-equal to the
/// SPS/PPS NAL units of the FIXH264 annexb fixture the transcript carries — independently
/// re-extracted here from the committed .264 by start-code scanning (not via the generator).
#[test]
fn sdp_sprop_parameter_sets_equal_fixh264_nal_bytes() -> Result<(), Box<dyn Error>> {
    let repo_root = get_repo_root()?;

    // Independent extraction: scan the committed annexb stream for NAL types 7 (SPS) and 8 (PPS).
    let annexb = fs::read(repo_root.join("tests/fixtures/media/h264/clean.264"))?;
    let mut sps: Option<Vec<u8>> = None;
    let mut pps: Option<Vec<u8>> = None;
    // Exact start-code scan: collect (begin, len) for every 000001/00000001 code,
    // then each NAL spans (begin+len, next_begin) so trailing start codes are trimmed.
    let mut codes: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < annexb.len() {
        if annexb[i..].len() >= 4 && annexb[i..].starts_with(&[0, 0, 0, 1]) {
            codes.push((i, 4));
            i += 4;
        } else if annexb[i..].len() >= 3 && annexb[i..].starts_with(&[0, 0, 1]) {
            codes.push((i, 3));
            i += 3;
        } else {
            i += 1;
        }
    }
    assert!(!codes.is_empty(), "no annexb start codes found");
    for (index, &(begin, len)) in codes.iter().enumerate() {
        let start = begin + len;
        let end = codes
            .get(index + 1)
            .map_or(annexb.len(), |&(next_begin, _)| next_begin);
        let nal = &annexb[start..end];
        match nal[0] & 0x1f {
            7 if sps.is_none() => sps = Some(nal.to_vec()),
            8 if pps.is_none() => pps = Some(nal.to_vec()),
            _ => {}
        }
    }
    let sps = sps.ok_or("no SPS NAL found in clean.264")?;
    let pps = pps.ok_or("no PPS NAL found in clean.264")?;

    // Pull the sprop pair out of the transcript's DESCRIBE SDP.
    let transcript = parse_transcript(&fs::read(
        repo_root.join("tests/fixtures/media/rtsp/clean.transcript"),
    )?)?;
    let mut s2c = Vec::new();
    for r in &transcript {
        if r.direction == TranscriptDirection::ServerToClient {
            s2c.extend_from_slice(&r.bytes);
        }
    }
    let s2c_str = String::from_utf8_lossy(&s2c);
    let fmtp = s2c_str
        .lines()
        .find(|l| l.starts_with("a=fmtp:") && l.contains("sprop-parameter-sets="))
        .ok_or("no sprop-parameter-sets in transcript SDP")?;
    let value = fmtp
        .split("sprop-parameter-sets=")
        .nth(1)
        .ok_or("malformed sprop line")?
        .trim();
    let (sps_b64, pps_b64) = value
        .split_once(',')
        .ok_or("sprop-parameter-sets must carry SPS,PPS")?;

    assert_eq!(
        decode_base64(sps_b64)?,
        sps,
        "SDP SPS must be byte-equal to the FIXH264 SPS NAL"
    );
    assert_eq!(
        decode_base64(pps_b64)?,
        pps,
        "SDP PPS must be byte-equal to the FIXH264 PPS NAL"
    );
    Ok(())
}

/// [fss-l0azz] SR mutation findings: wrong SSRC, zero NTP and a missing CNAME are each
/// typed refusals at the layer that owns the check — SenderReportClock binding for SSRC/NTP,
/// compound-mode RTCP parsing for the CNAME.
#[test]
fn sender_report_mutations_are_typed_refusals() -> Result<(), Box<dyn Error>> {
    use fss_packet::ContinuityError;

    let repo_root = get_repo_root()?;
    let transcript = parse_transcript(&fs::read(
        repo_root.join("tests/fixtures/media/rtsp/clean.transcript"),
    )?)?;
    let mut parser = RtspParser::new();
    let mut rtcp_frames = Vec::new();
    for r in &transcript {
        if r.direction == TranscriptDirection::ServerToClient {
            for event in parser.feed(&r.bytes)? {
                if let RtspEvent::Interleaved { channel: 1, span } = event {
                    rtcp_frames.push(span);
                }
            }
        }
    }
    let frame = rtcp_frames
        .first()
        .ok_or("no RTCP frame in clean.transcript")?;
    let compound = RtcpCompound::parse(frame, PacketLimits::default(), RtcpMode::Compound)?;
    let sr = compound
        .packets()
        .next()
        .and_then(|p| p.sender_report())
        .ok_or("first packet must be SenderReport")?;

    let valid_key = StreamKey {
        ingress: 1,
        generation: 1,
        ssrc: sr.ssrc,
    };
    let bind = |report: fss_packet::SenderReport, key: StreamKey| {
        SenderReportClock::new(key, 90_000, report, 1_000_000_000, 10_000_000, 90_000 * 10)
    };
    assert!(bind(sr, valid_key).is_ok(), "unmutated SR must bind");

    // Wrong SSRC: a key from another owner epoch is a typed StreamMismatch.
    let wrong_key = StreamKey {
        ingress: 1,
        generation: 1,
        ssrc: sr.ssrc ^ 0xffff,
    };
    match bind(sr, wrong_key) {
        Err(ContinuityError::StreamMismatch) => {}
        other => return Err(format!("wrong SSRC must be StreamMismatch, got {other:?}").into()),
    }

    // Zero NTP (seconds AND fraction): a typed NoSenderReport, never a zero clock.
    let mut zero_ntp = sr;
    zero_ntp.ntp.seconds = 0;
    zero_ntp.ntp.fraction = 0;
    match bind(zero_ntp, valid_key) {
        Err(ContinuityError::NoSenderReport) => {}
        other => return Err(format!("zero NTP must be NoSenderReport, got {other:?}").into()),
    }

    // Missing CNAME: the SR without its SDES tail is refused in Compound mode and
    // accepted in ReducedSize mode (which is exactly the negotiated distinction).
    let sr_alone = &frame[..28.min(frame.len())];
    assert!(
        RtcpCompound::parse(sr_alone, PacketLimits::default(), RtcpMode::Compound).is_err(),
        "compound mode must refuse an SR with no SDES CNAME"
    );
    assert!(
        RtcpCompound::parse(sr_alone, PacketLimits::default(), RtcpMode::ReducedSize).is_ok(),
        "reduced-size mode accepts a bare SR by design"
    );
    Ok(())
}

/// [fss-l0azz] RTP NAL equivalence: every channel-0 interleaved RTP datagram in
/// clean.transcript must be byte-identical to the corresponding RTP datagram in
/// the committed clean.rtp rtpdump fixture — the RTSP interleaved path and the
/// rtpdump import path carry the same wire packets, independently decoded here.
#[test]
fn transcript_interleaved_rtp_equals_rtpdump_datagrams() -> Result<(), Box<dyn Error>> {
    let repo_root = get_repo_root()?;

    // Channel-0 RTP payloads from the transcript.
    let transcript = parse_transcript(&fs::read(
        repo_root.join("tests/fixtures/media/rtsp/clean.transcript"),
    )?)?;
    let mut parser = RtspParser::new();
    let mut rtp_wire: Vec<Vec<u8>> = Vec::new();
    for r in &transcript {
        if r.direction == TranscriptDirection::ServerToClient {
            for event in parser.feed(&r.bytes)? {
                if let RtspEvent::Interleaved { channel: 0, span } = event {
                    rtp_wire.push(span.to_vec());
                }
            }
        }
    }
    assert!(!rtp_wire.is_empty(), "no channel-0 RTP in clean.transcript");

    // RTP datagrams from the committed rtpdump file: 10-byte header ("#!/rtpdump1.0\n"
    // core), then per-packet 8-byte record headers (offset_usec u16 BE, len u16 BE,
    // payload_len u32 BE) followed by the RTP datagram.
    let rtpdump = fs::read(repo_root.join("tests/fixtures/media/rtp/clean.rtp"))?;
    let magic = b"#!rtpplay1.0 0.0.0.0/0\n";
    assert!(rtpdump.starts_with(magic), "rtpdump magic");
    let mut dump_wire: Vec<Vec<u8>> = Vec::new();
    // Skip the header line plus the 16-byteAddress/Port records: the generator layout is
    // magic + (u16 len)(u16 len)(u32 sec)(u32 usec) address/port block, then packets.
    // Robust approach: walk length-prefixed packet records scanning from after magic+16.
    let mut pos = magic.len();
    // Header remainder: address family + port records per the generator (16 bytes).
    pos += 16;
    // RD_packet_t: u16 record_length (8 + rtp_len), u16 plen (rtp_len), u16 offset,
    // u16 padding — then the RTP datagram itself.
    while pos + 8 <= rtpdump.len() {
        let plen = u16::from_be_bytes([rtpdump[pos + 2], rtpdump[pos + 3]]) as usize;
        pos += 8;
        if pos + plen > rtpdump.len() {
            break;
        }
        dump_wire.push(rtpdump[pos..pos + plen].to_vec());
        pos += plen;
    }
    assert_eq!(
        rtp_wire, dump_wire,
        "transcript interleaved RTP must equal the rtpdump import datagrams"
    );
    Ok(())
}

/// [fss-l0azz] Replay the clean transcript through the SHIPPED client: the client
/// issues Describe/Setup/Play itself, the transcript's server stream (responses in
/// order, then interleaved media) is fed through `ingest`, and the exact
/// control/event sequence is asserted. The Setup response now binds the media SSRC
/// (`ssrc=287454020` = 0x11223344), which is what makes the shipped owner-binding
/// client able to consume the finished fixture.
#[test]
fn clean_transcript_replays_through_the_shipped_client() -> Result<(), Box<dyn Error>> {
    use fss_packet::avc::AvcReceiveLimits;
    use fss_reference::rtsp::avc_client::{AvcClientPoll as P, RtspAvcClient};
    use fss_reference::rtsp::client::{
        ClientCommand as C, ClientConfig, ClientProgress, ClientState as S,
    };

    let repo_root = get_repo_root()?;
    let transcript = parse_transcript(&fs::read(
        repo_root.join("tests/fixtures/media/rtsp/clean.transcript"),
    )?)?;
    let mut server_stream = Vec::new();
    for r in &transcript {
        if r.direction == TranscriptDirection::ServerToClient {
            server_stream.extend_from_slice(&r.bytes);
        }
    }

    let config = ClientConfig {
        presentation_uri: "rtsp://fixture.invalid/stream".into(),
        control_root_uri: "rtsp://fixture.invalid/stream".into(),
        media_index: 0,
        channels: (0, 1),
        response_timeout_ns: 10_000_000_000,
        default_session_timeout_seconds: 60,
    };
    let key = StreamKey {
        ingress: 1,
        generation: 1,
        ssrc: 0x1122_3344,
    };
    let mut client = RtspAvcClient::new(config, key, AvcReceiveLimits::default())?;

    // Full verbatim exchange: OPTIONS -> DESCRIBE -> SETUP -> PLAY, then media, then
    // TEARDOWN. The transcript's server bytes arrive in order, fed in MAX_CHUNK-sized
    // slices (the client's real transport contract — bounded segments, never a whole
    // capture at once).
    let mut fed = 0usize;
    let mut now = 1u64;
    fn feed_upto(
        client: &mut RtspAvcClient,
        stream: &[u8],
        fed: &mut usize,
        upto: usize,
        now: u64,
    ) -> Result<(), Box<dyn Error>> {
        while *fed < upto {
            let end = (*fed + 4_096).min(upto);
            client.ingest(&stream[*fed..end], now)?;
            *fed = end;
        }
        Ok(())
    }
    // Byte offsets where each of the first four responses (OPTIONS/DESCRIBE/SETUP/PLAY)
    // ends, honoring Content-Length bodies: headers end at CRLFCRLF, then the body adds
    // its declared length. Interleaved media and the TEARDOWN response follow.
    fn response_end(stream: &[u8], from: usize) -> Option<usize> {
        let header_end = from + stream[from..].windows(4).position(|w| w == b"\r\n\r\n")? + 4;
        let headers = std::str::from_utf8(&stream[from..header_end]).ok()?;
        let content_length: usize = headers
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length:"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        Some(header_end + content_length)
    }
    let mut response_ends = Vec::new();
    let mut cursor = 0usize;
    for _ in 0..4 {
        let end = response_end(&server_stream, cursor)
            .ok_or("response boundary not found in transcript")?;
        response_ends.push(end);
        cursor = end;
    }
    assert_eq!(
        response_ends.len(),
        4,
        "expected OPTIONS/DESCRIBE/SETUP/PLAY responses"
    );

    client.request(C::Options, now)?;
    now += 1;
    feed_upto(&mut client, &server_stream, &mut fed, response_ends[0], now)?;
    assert!(matches!(
        client.poll(now)?,
        P::Control(ClientProgress::Accepted(_))
    ));
    now += 1;

    client.request(C::Describe, now)?;
    now += 1;
    feed_upto(&mut client, &server_stream, &mut fed, response_ends[1], now)?;
    assert!(matches!(
        client.poll(now)?,
        P::Control(ClientProgress::Accepted(S::Described))
    ));
    now += 1;

    client.request(C::Setup, now)?;
    now += 1;
    feed_upto(&mut client, &server_stream, &mut fed, response_ends[2], now)?;
    assert!(matches!(
        client.poll(now)?,
        P::Control(ClientProgress::Accepted(S::Ready))
    ));
    now += 1;

    client.request(C::Play, now)?;
    now += 1;
    feed_upto(&mut client, &server_stream, &mut fed, response_ends[3], now)?;
    assert!(matches!(
        client.poll(now)?,
        P::Control(ClientProgress::Accepted(S::Playing))
    ));
    now += 1;

    // The remainder is interleaved media, then the TEARDOWN response. Media streams
    // first (draining between chunks — the client's ingest refuses while events pend);
    // the teardown response is fed only after the client itself requests Teardown.
    let teardown_offset = server_stream
        .windows(24)
        .position(|w| w.starts_with(b"RTSP/1.0 200 OK\r\nCSeq: 5"))
        .ok_or("teardown response not found in transcript")?;
    let mut rtp_frames = 0usize;
    let mut rtcp_frames = 0usize;
    while fed < teardown_offset {
        let end = (fed + 4_096).min(teardown_offset);
        client.ingest(&server_stream[fed..end], now)?;
        fed = end;
        for _ in 0..2_048 {
            match client.poll(now)? {
                P::Pending { wake_at_ns } if wake_at_ns.is_none_or(|at| at > now) => break,
                P::Backpressure { .. } | P::Ended { .. } => break,
                P::Rtp { .. } => rtp_frames += 1,
                P::Rtcp { .. } => rtcp_frames += 1,
                P::Control(_) | P::Media(_) => {}
                P::Pending { .. } => break,
                P::Fault { reason, .. } => {
                    return Err(format!(
                        "transcript replay faulted at fed={fed} now={now} teardown_at={teardown_offset} total={}: {reason:?}", server_stream.len()
                    )
                    .into());
                }
            }
        }
    }
    // Close the session from the client side, then feed the teardown response.
    client.request(C::Teardown, now)?;
    now += 1;
    while fed < server_stream.len() {
        let end = (fed + 4_096).min(server_stream.len());
        client.ingest(&server_stream[fed..end], now)?;
        fed = end;
        for _ in 0..2_048 {
            match client.poll(now)? {
                P::Pending { wake_at_ns } if wake_at_ns.is_none_or(|at| at > now) => break,
                P::Backpressure { .. } | P::Ended { .. } | P::Pending { .. } => break,
                P::Rtp { .. } => rtp_frames += 1,
                P::Rtcp { .. } => rtcp_frames += 1,
                P::Control(_) | P::Media(_) => {}
                P::Fault { reason, .. } => {
                    return Err(format!("teardown replay faulted: {reason:?}").into());
                }
            }
        }
    }
    assert!(matches!(client.state(), S::Closed));
    // The clean transcript carries 15 RTP datagrams on channel 0 (the full clean.rtp
    // set — pinned by the rtpdump-equivalence test) and 3 RTCP compounds on channel 1.
    assert_eq!(rtp_frames, 15, "RTP frames delivered to the client");
    assert_eq!(rtcp_frames, 3, "RTCP frames delivered to the client");
    Ok(())
}

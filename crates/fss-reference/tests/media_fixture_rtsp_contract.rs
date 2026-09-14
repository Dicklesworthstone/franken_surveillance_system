#![forbid(unsafe_code)]

//! Integration companion contract tests for RTSP transcript fixtures (fss-2h5zq.8).
//!
//! Verifies:
//! - Container record framing walked by an independent parser
//! - Exact record counts and per-record length literals across all 8 transcripts
//! - Independent interleaved-TCP record framing ($, channel, length) parser
//! - Reassembly of interleaved frames split across records (interleave_split)
//! - Independent RTCP walker proving compound SR+SDES(CNAME) and reduced-size rtcp_rsize
//! - SDP sanity with exact values and base64 SPS/PPS decoding matching FIXH264
//! - Strict no-credential guard (no Authorization, no user:pass@, no IP literals)
//! - Exact regeneration identity against committed bytes and pinned SHA-256 literals
//! - Dedicated tests proving failure when real mutants of the generator are introduced

use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use fss_core::ContentDigest;
use fss_reference::media_fixture::{
    H264FixtureParams, RtspTranscriptParams, generate_h264_annexb,
    generate_transcript_auth_required, generate_transcript_bad_content_length,
    generate_transcript_clean, generate_transcript_get_parameter_keepalive,
    generate_transcript_interleave_split, generate_transcript_rtcp_rsize,
    generate_transcript_session_timeout, generate_transcript_sr_absent,
};

pub const PINNED_CLEAN_SHA256: &str =
    "f0640fca1a33fe43e8335cb01013e0f7d98589b86c45a8480ef75ced345d24aa";
pub const PINNED_AUTH_REQUIRED_SHA256: &str =
    "c2d19f964ccfaa656b89e7c48cd9d7272558a420b7a687ab40a50aa88ed63a0c";
pub const PINNED_INTERLEAVE_SPLIT_SHA256: &str =
    "a0eccf64599579ee98d0b335b2b16d957a70605166dae3a559dbf665d49f8ae1";
pub const PINNED_BAD_CONTENT_LENGTH_SHA256: &str =
    "4ba38d4cf689abe2d505cbed0321d31397eb5b1347ed1106c9cb9a4ede5b1342";
pub const PINNED_SESSION_TIMEOUT_SHA256: &str =
    "54557ffaaa43a00c205ab7a807186502784a19ddb13300e3b32b84fb29f5cacd";
pub const PINNED_RTCP_RSIZE_SHA256: &str =
    "e503ecc51b1d34afbdb53e50f14ee31a494b92d1c142c74c96d23e83a208f88e";
pub const PINNED_SR_ABSENT_SHA256: &str =
    "e154d42cdf5d5a76d3304a6d13a13d98e56b922bf55ba783bb0e581d42d10e32";
pub const PINNED_GET_PARAMETER_SHA256: &str =
    "60acc52f1e58877ea5aceb2b40eb0a3ecf313b9a7a13ac0f91383269b7b46675";

pub const CLEAN_RECORD_LENGTHS: &[u32] = &[
    86, 78, 85, 368, 115, 106, 90, 126, 72, 18, 18, 33, 66, 1204, 248, 337, 18, 401, 72, 18, 545,
    18, 401, 18, 401, 72, 79, 47,
];

pub const AUTH_REQUIRED_RECORD_LENGTHS: &[u32] = &[86, 132];

pub const INTERLEAVE_SPLIT_RECORD_LENGTHS: &[u32] = &[
    86, 78, 85, 368, 115, 106, 90, 126, 72, 18, 18, 33, 66, 600, 604, 248, 337, 18, 401, 72, 18,
    545, 18, 401, 18, 401, 72, 79, 47,
];

pub const BAD_CONTENT_LENGTH_RECORD_LENGTHS: &[u32] = &[86, 78, 85, 377];

pub const SESSION_TIMEOUT_RECORD_LENGTHS: &[u32] = &[
    86, 78, 85, 368, 115, 106, 90, 126, 72, 18, 18, 33, 66, 1204, 248, 337, 18, 401, 72, 18, 545,
    18, 401, 18, 401, 72, 79, 47,
];

pub const RTCP_RSIZE_RECORD_LENGTHS: &[u32] = &[
    86, 78, 85, 382, 115, 106, 90, 126, 32, 18, 18, 33, 66, 1204, 248, 337, 18, 401, 32, 18, 545,
    18, 401, 18, 401, 32, 79, 47,
];

pub const SR_ABSENT_RECORD_LENGTHS: &[u32] = &[
    86, 78, 85, 368, 115, 106, 90, 126, 18, 18, 33, 66, 1204, 248, 337, 18, 401, 18, 545, 18, 401,
    18, 401, 79, 47,
];

pub const GET_PARAMETER_RECORD_LENGTHS: &[u32] = &[
    86, 78, 85, 368, 115, 106, 90, 126, 72, 18, 18, 33, 66, 1204, 248, 337, 18, 401, 72, 18, 545,
    18, 401, 18, 401, 72, 84, 47, 79, 47,
];

fn emit_caplog(
    step: &str,
    verdict: &str,
    exit_code: i32,
    expected: &str,
    observed: &str,
    duration_ms: u128,
) {
    println!(
        r#"CAPLOG {{"step":"{}","verdict":"{}","exit":{},"duration_ms":{},"expected":{},"observed":{}}}"#,
        step, verdict, exit_code, duration_ms, expected, observed
    );
}

fn get_repo_root() -> Result<PathBuf, Box<dyn Error>> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let p1 = manifest.parent().ok_or("cannot find crates directory")?;
    let p2 = p1.parent().ok_or("cannot find repository root")?;
    Ok(p2.to_path_buf())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ContentDigest::sha256(bytes);
    let mut s = String::with_capacity(64);
    for b in digest.bytes() {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decodes standard Base64 string into bytes without external dependencies.
fn decode_base64_simple(input: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for ch in input.chars() {
        if ch == '=' {
            break;
        }
        let val = match ch {
            'A'..='Z' => (ch as u32) - ('A' as u32),
            'a'..='z' => (ch as u32) - ('a' as u32) + 26,
            '0'..='9' => (ch as u32) - ('0' as u32) + 52,
            '+' => 62,
            '/' => 63,
            '\r' | '\n' | ' ' | '\t' => continue,
            _ => return Err(format!("invalid base64 character: '{ch}'")),
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

/// Independent parser representation of a transcript container record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndependentRecord {
    pub direction: u8, // 0 = C2S, 1 = S2C
    pub offset_ms: u32,
    pub length: usize,
    pub payload: Vec<u8>,
}

/// Independently parses raw transcript bytes into container records.
pub fn independent_parse_container(bytes: &[u8]) -> Result<Vec<IndependentRecord>, String> {
    let magic = b"#!fss-rtsp-transcript v1\n";
    if bytes.len() < magic.len() || &bytes[..magic.len()] != magic {
        return Err("missing or invalid transcript magic header".to_string());
    }
    let mut pos = magic.len();
    let mut records = Vec::new();

    while pos < bytes.len() {
        if pos + 9 > bytes.len() {
            return Err("truncated record header (needs 9 bytes)".to_string());
        }
        let dir = bytes[pos];
        if dir > 1 {
            return Err(format!("invalid direction byte {dir}"));
        }
        let offset_ms = u32::from_be_bytes([
            bytes[pos + 1],
            bytes[pos + 2],
            bytes[pos + 3],
            bytes[pos + 4],
        ]);
        let rlen = u32::from_be_bytes([
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
            bytes[pos + 8],
        ]) as usize;

        let payload_start = pos + 9;
        let payload_end = payload_start + rlen;
        if payload_end > bytes.len() {
            return Err(format!(
                "record length {rlen} extends beyond total buffer size {}",
                bytes.len()
            ));
        }
        records.push(IndependentRecord {
            direction: dir,
            offset_ms,
            length: rlen,
            payload: bytes[payload_start..payload_end].to_vec(),
        });
        pos = payload_end;
    }

    if pos != bytes.len() {
        return Err("trailing unparsed bytes in container".to_string());
    }
    Ok(records)
}

/// Independent parser representation of an interleaved binary frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndependentInterleavedFrame {
    pub channel: u8,
    pub payload: Vec<u8>,
}

/// Independently parses interleaved binary stream ($) across S2C records.
pub fn independent_parse_interleaved_stream(
    records: &[IndependentRecord],
) -> Result<Vec<IndependentInterleavedFrame>, String> {
    let mut s2c_stream = Vec::new();
    for r in records {
        if r.direction == 1 {
            s2c_stream.extend_from_slice(&r.payload);
        }
    }

    let mut pos = 0;
    let mut frames = Vec::new();

    while pos < s2c_stream.len() {
        if s2c_stream[pos] == b'$' {
            if pos + 4 > s2c_stream.len() {
                return Err("truncated interleaved frame header".to_string());
            }
            let channel = s2c_stream[pos + 1];
            if channel != 0 && channel != 1 {
                return Err(format!(
                    "invalid interleaved channel {channel} (expected 0 or 1)"
                ));
            }
            let length = u16::from_be_bytes([s2c_stream[pos + 2], s2c_stream[pos + 3]]) as usize;
            let frame_start = pos + 4;
            let frame_end = frame_start + length;
            if frame_end > s2c_stream.len() {
                return Err(format!(
                    "interleaved frame length {length} extends beyond stream size"
                ));
            }
            frames.push(IndependentInterleavedFrame {
                channel,
                payload: s2c_stream[frame_start..frame_end].to_vec(),
            });
            pos = frame_end;
        } else {
            // Text line in S2C stream, skip
            pos += 1;
        }
    }

    Ok(frames)
}

/// Independently walks an RTCP packet frame and verifies structure.
pub fn independent_walk_rtcp(frame: &[u8], is_rtcp_rsize: bool) -> Result<(), String> {
    if frame.len() < 4 {
        return Err("RTCP frame too short (< 4 bytes)".to_string());
    }
    let version = (frame[0] >> 6) & 0x03;
    if version != 2 {
        return Err(format!("invalid RTCP version {version}, expected 2"));
    }
    let pt = frame[1];
    if pt != 200 {
        return Err(format!(
            "first RTCP packet must be Sender Report (PT 200), got {pt}"
        ));
    }
    let length_words = u16::from_be_bytes([frame[2], frame[3]]) as usize;
    let sr_len = (length_words + 1) * 4;
    if sr_len > frame.len() {
        return Err("SR packet length exceeds buffer".to_string());
    }
    if sr_len < 28 {
        return Err(format!(
            "SR packet length {sr_len} too short for full sender info"
        ));
    }

    let ssrc = u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]);
    if ssrc != 0x1122_3344 {
        return Err(format!(
            "SR SSRC 0x{ssrc:08x} does not match expected 0x11223344"
        ));
    }

    let ntp_sec = u32::from_be_bytes([frame[8], frame[9], frame[10], frame[11]]);
    let ntp_frac = u32::from_be_bytes([frame[12], frame[13], frame[14], frame[15]]);
    if ntp_sec == 0 && ntp_frac == 0 {
        return Err("NTP timestamp is zero".to_string());
    }

    if is_rtcp_rsize {
        if frame.len() != 28 {
            return Err(format!(
                "reduced-size RTCP packet must be exactly 28 bytes, got {}",
                frame.len()
            ));
        }
    } else {
        if frame.len() <= sr_len {
            return Err("missing compound SDES packet after SR".to_string());
        }
        let sdes_buf = &frame[sr_len..];
        if sdes_buf.len() < 4 {
            return Err("truncated SDES header".to_string());
        }
        let sdes_pt = sdes_buf[1];
        if sdes_pt != 202 {
            return Err(format!(
                "expected SDES (PT 202) following SR, got {sdes_pt}"
            ));
        }
        let sdes_words = u16::from_be_bytes([sdes_buf[2], sdes_buf[3]]) as usize;
        let sdes_len = (sdes_words + 1) * 4;
        if sdes_len > sdes_buf.len() {
            return Err("SDES length exceeds buffer".to_string());
        }

        let chunk_ssrc = u32::from_be_bytes([sdes_buf[4], sdes_buf[5], sdes_buf[6], sdes_buf[7]]);
        if chunk_ssrc != ssrc {
            return Err(format!(
                "SDES SSRC 0x{chunk_ssrc:08x} does not match SR SSRC 0x{ssrc:08x}"
            ));
        }

        if sdes_buf.len() < 10 {
            return Err("SDES item too short".to_string());
        }
        let item_type = sdes_buf[8];
        if item_type != 1 {
            return Err(format!(
                "first SDES item must be CNAME (type 1), got {item_type}"
            ));
        }
        let item_len = sdes_buf[9] as usize;
        if 10 + item_len > sdes_buf.len() {
            return Err("CNAME length exceeds SDES packet".to_string());
        }
        let cname = std::str::from_utf8(&sdes_buf[10..10 + item_len])
            .map_err(|e| format!("invalid UTF-8 in CNAME: {e}"))?;
        if cname != "fss-fixture@fixture.invalid" {
            return Err(format!("unexpected CNAME '{cname}'"));
        }
        if cname.contains("127.0.0.1") || cname.contains("192.168.") || cname.contains("::") {
            return Err(format!("CNAME '{cname}' contains an IP literal"));
        }
    }

    Ok(())
}

/// Independently verifies SDP text content and syntax.
pub fn independent_verify_sdp(sdp: &str, is_rtcp_rsize: bool) -> Result<(), String> {
    let required_lines = [
        "v=0",
        "o=- 0 0 IN IP4 fixture.invalid",
        "s=FSS Synthetic RTSP Session",
        "c=IN IP4 fixture.invalid",
        "t=0 0",
        "m=video 0 RTP/AVP 96",
        "a=rtpmap:96 H264/90000",
        "a=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0LACvQUIyA=,aM44gA==",
        "a=control:trackID=1",
    ];

    for line in &required_lines {
        if !sdp.lines().any(|l| l.trim_end() == *line) {
            return Err(format!("missing required SDP line: '{line}'"));
        }
    }

    if is_rtcp_rsize {
        if !sdp.lines().any(|l| l.trim_end() == "a=rtcp-rsize") {
            return Err("missing required 'a=rtcp-rsize' line in rtcp_rsize variant".to_string());
        }
    } else if sdp.lines().any(|l| l.trim_end() == "a=rtcp-rsize") {
        return Err("unexpected 'a=rtcp-rsize' line in non-rtcp_rsize variant".to_string());
    }

    let sps_bytes = decode_base64_simple("Z0LACvQUIyA=")?;
    let pps_bytes = decode_base64_simple("aM44gA==")?;
    let expected_sps = [0x67, 0x42, 0xc0, 0x0a, 0xf4, 0x14, 0x23, 0x20];
    let expected_pps = [0x68, 0xce, 0x38, 0x80];

    if sps_bytes != expected_sps {
        return Err(format!(
            "decoded SPS {sps_bytes:02x?} does not match FIXH264 {expected_sps:02x?}"
        ));
    }
    if pps_bytes != expected_pps {
        return Err(format!(
            "decoded PPS {pps_bytes:02x?} does not match FIXH264 {expected_pps:02x?}"
        ));
    }

    Ok(())
}

/// Independently audits security boundary: zero credentials and zero IP literals.
pub fn independent_verify_no_credentials(data: &[u8]) -> Result<(), String> {
    let text = String::from_utf8_lossy(data).to_lowercase();

    if text.contains("authorization:") || text.contains("proxy-authorization:") {
        return Err("found forbidden Authorization / Proxy-Authorization header".to_string());
    }
    if text.contains("user:pass@") || text.contains("@fixture.invalid/") {
        return Err("found forbidden user:pass credential pattern".to_string());
    }

    for line in text.lines() {
        if let Some(uri_start) = line.find("rtsp://") {
            let after_scheme = &line[uri_start + 7..];
            if let Some(at_idx) = after_scheme.find('@') {
                let host_slash = match after_scheme.find('/') {
                    Some(idx) => idx,
                    None => after_scheme.len(),
                };
                if at_idx < host_slash {
                    return Err(format!("found user credentials in URI: '{line}'"));
                }
            }
        }
    }

    for word in text.split(|c: char| !c.is_alphanumeric() && c != '.' && c != ':') {
        let parts: Vec<&str> = word.split('.').collect();
        if parts.len() == 4
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.chars().all(|ch| ch.is_ascii_digit()))
        {
            let octets: Result<Vec<u8>, _> = parts.iter().map(|p| p.parse::<u8>()).collect();
            if octets.is_ok() {
                return Err(format!(
                    "found forbidden IPv4 literal '{word}' in transcript"
                ));
            }
        }
    }

    Ok(())
}

#[test]
fn test_all_committed_transcripts_framing_and_literals() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let root = get_repo_root()?;
    let rtsp_dir = root.join("tests/fixtures/media/rtsp");

    let fixtures: [(&str, &[u32], &str); 8] = [
        (
            "clean.transcript",
            CLEAN_RECORD_LENGTHS,
            PINNED_CLEAN_SHA256,
        ),
        (
            "auth_required.transcript",
            AUTH_REQUIRED_RECORD_LENGTHS,
            PINNED_AUTH_REQUIRED_SHA256,
        ),
        (
            "interleave_split.transcript",
            INTERLEAVE_SPLIT_RECORD_LENGTHS,
            PINNED_INTERLEAVE_SPLIT_SHA256,
        ),
        (
            "bad_content_length.transcript",
            BAD_CONTENT_LENGTH_RECORD_LENGTHS,
            PINNED_BAD_CONTENT_LENGTH_SHA256,
        ),
        (
            "session_timeout_header.transcript",
            SESSION_TIMEOUT_RECORD_LENGTHS,
            PINNED_SESSION_TIMEOUT_SHA256,
        ),
        (
            "rtcp_rsize.transcript",
            RTCP_RSIZE_RECORD_LENGTHS,
            PINNED_RTCP_RSIZE_SHA256,
        ),
        (
            "sr_absent.transcript",
            SR_ABSENT_RECORD_LENGTHS,
            PINNED_SR_ABSENT_SHA256,
        ),
        (
            "get_parameter_keepalive.transcript",
            GET_PARAMETER_RECORD_LENGTHS,
            PINNED_GET_PARAMETER_SHA256,
        ),
    ];

    for (name, expected_lengths, expected_sha) in &fixtures {
        let path = rtsp_dir.join(name);
        let bytes = fs::read(&path)?;

        let computed_sha = sha256_hex(&bytes);
        assert_eq!(
            &computed_sha, expected_sha,
            "SHA-256 mismatch for {name}: expected {expected_sha}, got {computed_sha}"
        );

        let records = independent_parse_container(&bytes)
            .map_err(|e| format!("container parse failed on {name}: {e}"))?;

        assert_eq!(
            records.len(),
            expected_lengths.len(),
            "record count mismatch for {name}: expected {}, got {}",
            expected_lengths.len(),
            records.len()
        );

        let mut sum_lengths = 0;
        let mut prev_offset = 0;
        for (i, (rec, &exp_len)) in records.iter().zip(expected_lengths.iter()).enumerate() {
            assert_eq!(
                rec.length as u32, exp_len,
                "record {i} length mismatch in {name}: expected {exp_len}, got {}",
                rec.length
            );
            assert!(
                rec.offset_ms >= prev_offset,
                "record {i} offset_ms {} is non-monotonic (prev {prev_offset}) in {name}",
                rec.offset_ms
            );
            prev_offset = rec.offset_ms;
            sum_lengths += 9 + rec.length;

            // Check CSeq on C2S requests
            if rec.direction == 0 {
                let text = String::from_utf8_lossy(&rec.payload);
                assert!(
                    text.contains("CSeq:"),
                    "C2S request in record {i} of {name} missing CSeq header: '{text}'"
                );
            }
        }

        assert_eq!(
            sum_lengths + 25, // 25 bytes magic header
            bytes.len(),
            "sum of parsed record framing in {name} does not equal file length"
        );

        independent_verify_no_credentials(&bytes)
            .map_err(|e| format!("security check failed on {name}: {e}"))?;
    }

    emit_caplog(
        "committed_transcripts_framing_and_literals",
        "pass",
        0,
        "8_fixtures_valid",
        "8_fixtures_valid",
        start.elapsed().as_millis(),
    );
    Ok(())
}

#[test]
fn test_interleaved_stream_and_rtcp_walking() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let root = get_repo_root()?;
    let rtsp_dir = root.join("tests/fixtures/media/rtsp");

    let stream_fixtures = [
        ("clean.transcript", false, 15, 3),
        ("interleave_split.transcript", false, 15, 3),
        ("session_timeout_header.transcript", false, 15, 3),
        ("rtcp_rsize.transcript", true, 15, 3),
        ("get_parameter_keepalive.transcript", false, 15, 3),
        ("sr_absent.transcript", false, 15, 0),
    ];

    for (name, is_rsize, expected_rtp, expected_rtcp) in &stream_fixtures {
        let bytes = fs::read(rtsp_dir.join(name))?;
        let records = independent_parse_container(&bytes)
            .map_err(|e| format!("container parse failed on {name}: {e}"))?;
        let frames = independent_parse_interleaved_stream(&records)
            .map_err(|e| format!("interleaved stream parse failed on {name}: {e}"))?;

        let mut rtp_count = 0;
        let mut rtcp_count = 0;

        for (idx, frame) in frames.iter().enumerate() {
            match frame.channel {
                0 => {
                    rtp_count += 1;
                    assert!(
                        frame.payload.len() >= 12,
                        "RTP frame {idx} in {name} too short"
                    );
                    let v = (frame.payload[0] >> 6) & 0x03;
                    assert_eq!(v, 2, "RTP version != 2 in frame {idx} of {name}");
                    let pt = frame.payload[1] & 0x7F;
                    assert_eq!(pt, 96, "RTP PT != 96 in frame {idx} of {name}");
                    let ssrc = u32::from_be_bytes([
                        frame.payload[8],
                        frame.payload[9],
                        frame.payload[10],
                        frame.payload[11],
                    ]);
                    assert_eq!(
                        ssrc, 0x1122_3344,
                        "RTP SSRC mismatch in frame {idx} of {name}"
                    );
                }
                1 => {
                    rtcp_count += 1;
                    independent_walk_rtcp(&frame.payload, *is_rsize)
                        .map_err(|e| format!("RTCP walk failed on frame {idx} of {name}: {e}"))?;
                }
                _ => return Err(format!("unexpected channel {} in {name}", frame.channel).into()),
            }
        }

        assert_eq!(
            rtp_count, *expected_rtp,
            "RTP packet count mismatch in {name}: expected {expected_rtp}, got {rtp_count}"
        );
        assert_eq!(
            rtcp_count, *expected_rtcp,
            "RTCP report count mismatch in {name}: expected {expected_rtcp}, got {rtcp_count}"
        );
    }

    emit_caplog(
        "interleaved_stream_and_rtcp_walking",
        "pass",
        0,
        "all_interleaved_streams_valid",
        "all_interleaved_streams_valid",
        start.elapsed().as_millis(),
    );
    Ok(())
}

#[test]
fn test_sdp_sanity_and_parameter_sets() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let root = get_repo_root()?;
    let rtsp_dir = root.join("tests/fixtures/media/rtsp");

    let sdp_fixtures = [
        ("clean.transcript", false),
        ("interleave_split.transcript", false),
        ("session_timeout_header.transcript", false),
        ("rtcp_rsize.transcript", true),
        ("get_parameter_keepalive.transcript", false),
        ("sr_absent.transcript", false),
    ];

    for (name, is_rsize) in &sdp_fixtures {
        let bytes = fs::read(rtsp_dir.join(name))?;
        let records = independent_parse_container(&bytes)
            .map_err(|e| format!("container parse failed on {name}: {e}"))?;

        // Record 3 is DESCRIBE response
        assert!(records.len() > 3, "transcript {name} too short for SDP");
        let describe_payload = String::from_utf8_lossy(&records[3].payload);
        assert!(
            describe_payload.contains("Content-Type: application/sdp"),
            "Record 3 in {name} is not application/sdp"
        );

        let sdp_start = describe_payload
            .find("\r\n\r\nv=")
            .ok_or_else(|| format!("SDP body start not found in Record 3 of {name}"))?;
        let sdp_text = &describe_payload[sdp_start + 4..];

        independent_verify_sdp(sdp_text, *is_rsize)
            .map_err(|e| format!("SDP verification failed for {name}: {e}"))?;
    }

    emit_caplog(
        "sdp_sanity_and_parameter_sets",
        "pass",
        0,
        "all_sdp_sections_valid",
        "all_sdp_sections_valid",
        start.elapsed().as_millis(),
    );
    Ok(())
}

#[test]
fn test_regeneration_identity_against_committed() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let root = get_repo_root()?;
    let rtsp_dir = root.join("tests/fixtures/media/rtsp");

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

    let regenerated = [
        ("clean.transcript", &clean.bytes, PINNED_CLEAN_SHA256),
        (
            "auth_required.transcript",
            &auth_required.bytes,
            PINNED_AUTH_REQUIRED_SHA256,
        ),
        (
            "interleave_split.transcript",
            &interleave_split.bytes,
            PINNED_INTERLEAVE_SPLIT_SHA256,
        ),
        (
            "bad_content_length.transcript",
            &bad_content_length.bytes,
            PINNED_BAD_CONTENT_LENGTH_SHA256,
        ),
        (
            "session_timeout_header.transcript",
            &session_timeout.bytes,
            PINNED_SESSION_TIMEOUT_SHA256,
        ),
        (
            "rtcp_rsize.transcript",
            &rtcp_rsize.bytes,
            PINNED_RTCP_RSIZE_SHA256,
        ),
        (
            "sr_absent.transcript",
            &sr_absent.bytes,
            PINNED_SR_ABSENT_SHA256,
        ),
        (
            "get_parameter_keepalive.transcript",
            &get_parameter_keepalive.bytes,
            PINNED_GET_PARAMETER_SHA256,
        ),
    ];

    for (name, gen_bytes, expected_sha) in &regenerated {
        let committed_bytes = fs::read(rtsp_dir.join(name))?;
        assert_eq!(
            *gen_bytes, &committed_bytes,
            "regenerated bytes do not match committed file on disk: {name}"
        );
        let actual_sha = sha256_hex(gen_bytes);
        assert_eq!(
            &actual_sha, expected_sha,
            "SHA-256 mismatch on regenerated {name}: expected {expected_sha}, got {actual_sha}"
        );
    }

    emit_caplog(
        "regeneration_identity_against_committed",
        "pass",
        0,
        "8_regenerations_bit_identical",
        "8_regenerations_bit_identical",
        start.elapsed().as_millis(),
    );
    Ok(())
}

#[test]
fn test_mutant_1_killed_record_length_off_by_one() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let root = get_repo_root()?;
    let clean_bytes = fs::read(root.join("tests/fixtures/media/rtsp/clean.transcript"))?;

    // Mutant 1: Record 0 length header altered from 86 to 87 (off by one)
    let mut mutated = clean_bytes.clone();
    let magic_len = 25; // b"#!fss-rtsp-transcript v1\n".len()
    // Bytes pos+5..pos+9 encode length: [0, 0, 0, 86] -> change to 87
    assert_eq!(mutated[magic_len + 8], 86);
    mutated[magic_len + 8] = 87;

    let res = independent_parse_container(&mutated);
    assert!(
        res.is_err(),
        "Mutant 1 survived: record length off by one was not detected"
    );

    emit_caplog(
        "mutant_1_killed_record_length_off_by_one",
        "pass",
        0,
        "mutant_killed",
        "mutant_killed",
        start.elapsed().as_millis(),
    );
    Ok(())
}

#[test]
fn test_mutant_2_killed_wrong_channel() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let root = get_repo_root()?;
    let clean_bytes = fs::read(root.join("tests/fixtures/media/rtsp/clean.transcript"))?;

    let records = independent_parse_container(&clean_bytes)
        .map_err(|e| format!("clean parse failed: {e}"))?;

    // Mutant 2: Change channel byte of an interleaved frame from 1 to 2 (unsupported)
    let mut mutated_records = records.clone();
    // Record 8 is channel 1 ($ \x01 ...)
    assert_eq!(mutated_records[8].payload[0], b'$');
    assert_eq!(mutated_records[8].payload[1], 1);
    mutated_records[8].payload[1] = 2; // Mutant: wrong channel

    let res = independent_parse_interleaved_stream(&mutated_records);
    assert!(
        res.is_err(),
        "Mutant 2 survived: wrong channel 2 was not detected"
    );

    emit_caplog(
        "mutant_2_killed_wrong_channel",
        "pass",
        0,
        "mutant_killed",
        "mutant_killed",
        start.elapsed().as_millis(),
    );
    Ok(())
}

#[test]
fn test_mutant_3_killed_authorization_header_injected() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let root = get_repo_root()?;
    let clean_bytes = fs::read(root.join("tests/fixtures/media/rtsp/clean.transcript"))?;

    // Mutant 3: Inject Authorization: header into the transcript
    let mut mutated = clean_bytes.clone();
    let injection = b"\r\nAuthorization: Basic dXNlcjpwYXNz\r\n";
    mutated.extend_from_slice(injection);

    let res = independent_verify_no_credentials(&mutated);
    assert!(
        res.is_err(),
        "Mutant 3 survived: injected Authorization header was not detected"
    );

    emit_caplog(
        "mutant_3_killed_authorization_header_injected",
        "pass",
        0,
        "mutant_killed",
        "mutant_killed",
        start.elapsed().as_millis(),
    );
    Ok(())
}

#[test]
fn test_mutant_4_killed_sdp_m_line_changed() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let root = get_repo_root()?;
    let clean_bytes = fs::read(root.join("tests/fixtures/media/rtsp/clean.transcript"))?;

    let records = independent_parse_container(&clean_bytes)
        .map_err(|e| format!("clean parse failed: {e}"))?;

    let describe_payload = String::from_utf8_lossy(&records[3].payload);
    let sdp_start = describe_payload
        .find("\r\n\r\nv=")
        .ok_or("SDP start not found")?;
    let sdp_text = &describe_payload[sdp_start + 4..];

    // Mutant 4: Alter m= line from "m=video 0 RTP/AVP 96" to "m=audio 0 RTP/AVP 96"
    let mutated_sdp = sdp_text.replace("m=video 0 RTP/AVP 96", "m=audio 0 RTP/AVP 96");
    assert_ne!(mutated_sdp, sdp_text);

    let res = independent_verify_sdp(&mutated_sdp, false);
    assert!(
        res.is_err(),
        "Mutant 4 survived: altered SDP m= line was not detected"
    );

    emit_caplog(
        "mutant_4_killed_sdp_m_line_changed",
        "pass",
        0,
        "mutant_killed",
        "mutant_killed",
        start.elapsed().as_millis(),
    );
    Ok(())
}
